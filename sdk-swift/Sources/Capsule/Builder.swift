// CapsuleBuilder — general-purpose, mirrors sdk/src/builder.js.
//
// Host apps construct a builder, set program.md / agents.md, append
// chain events with full control over actor/kind/action/target/payload,
// optionally add skills and arbitrary payload files, then seal to bytes.
//
// No domain knowledge is baked in. The medical-journal example layers
// its lane mapping (symptom → observation/logged_symptom etc.) on top.

import Foundation

public final class CapsuleBuilder {
    public struct Originator {
        public let keyPair: Ed25519KeyPair
        public let label: String
        public init(keyPair: Ed25519KeyPair, label: String = "") {
            self.keyPair = keyPair; self.label = label
        }
    }

    public struct Participant {
        public let actorId: String
        public let role: String
        public let label: String
        public init(actorId: String, role: String, label: String) {
            self.actorId = actorId; self.role = role; self.label = label
        }
    }

    public struct PayloadFile {
        public let path: String
        public let bytes: Data
        public init(path: String, bytes: Data) {
            precondition(path.hasPrefix("payload/"),
                         "payload path must start with 'payload/': \(path)")
            self.path = path; self.bytes = bytes
        }
    }

    public struct BuildResult {
        public let bytes: Data
        public let capsuleId: String
        public let firstEventHash: String
        public let entryHash: String
        public let manifestHash: String
        public let contentIndexHash: String
        public let originatorPublicKey: String
        public let signedAt: String
        public let fileCount: Int
        public let byteCount: Int
    }

    private let originator: Originator
    private var participants: [Participant] = []
    private var programMd: String = "# Program\n"
    private var agentsMd: String? = nil
    private var bareEvents: [BareEvent] = []
    private var skills: [String: (json: Data?, markdown: String?, signed: Bool)] = [:]
    private var payload: [String: Data] = [:]
    private var createdAt: String

    public init(originator: Originator, createdAt: String? = nil) {
        self.originator = originator
        self.createdAt = createdAt ?? Self.isoNow()
    }

    @discardableResult
    public func setProgram(_ md: String) -> CapsuleBuilder {
        self.programMd = md; return self
    }

    @discardableResult
    public func setAgents(_ md: String) -> CapsuleBuilder {
        self.agentsMd = md; return self
    }

    @discardableResult
    public func setParticipants(_ ps: [Participant]) -> CapsuleBuilder {
        self.participants = ps; return self
    }

    /// Append a chain event. The seq, event_id, prev_hash, and hash are
    /// computed at seal time.
    @discardableResult
    public func appendEvent(
        actor: String, kind: String, action: String, target: String,
        timestamp: String? = nil,
        payload: JCSValue = .object([]),
        untrustedPayloadFields: [String] = []
    ) -> CapsuleBuilder {
        bareEvents.append(BareEvent(
            actor: actor, kind: kind, action: action, target: target,
            timestamp: timestamp ?? createdAt,
            payload: payload,
            untrustedPayloadFields: untrustedPayloadFields
        ))
        return self
    }

    /// Add a Capsule skill (skills/<id>/skill.json + SKILL.md).
    @discardableResult
    public func addSkill(id: String, json: Data?, markdown: String?, signed: Bool = false)
        -> CapsuleBuilder
    {
        precondition(id.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil,
                     "invalid skill id: \(id)")
        precondition(id != "decryption",
                     "'decryption' is reserved for encryption metadata; not a skill")
        skills[id] = (json, markdown, signed)
        return self
    }

    /// Add an arbitrary file under `payload/...`.
    @discardableResult
    public func addPayload(_ file: PayloadFile) -> CapsuleBuilder {
        payload[file.path] = file.bytes
        return self
    }

    /// Build, sign, and emit the sealed capsule bytes. The originator is
    /// the sole signer in v0; multi-signer is exposed via lower-level
    /// envelope APIs for hosts that need it.
    public func seal(signedAt: String? = nil) throws -> BuildResult {
        let sealedAt = signedAt ?? Self.isoNow()
        let parts = try buildInnerParts(sealedAt: sealedAt)
        let contentIndex = Manifest.buildContentIndex(parts.innerFiles)
        let manifest = Manifest.build(
            originator: .init(publicKeyHex: originator.keyPair.publicKeyHex,
                              label: originator.label),
            participants: participants.map {
                .init(actorId: $0.actorId, role: $0.role, label: $0.label)
            },
            contentIndex: contentIndex,
            firstEventHash: parts.firstHash,
            skillTrust: parts.skillTrust,
            createdAt: createdAt,
            capsuleId: parts.capsuleId
        )
        let mfHash = Manifest.hash(manifest)

        var envelope = Envelope.build(
            capsuleId: parts.capsuleId,
            firstEventHash: parts.firstHash,
            entryHash: parts.entryHash,
            manifestHash: mfHash,
            contentIndexHash: contentIndex.indexHash,
            cipher: "none",
            signedAt: sealedAt
        )
        try Envelope.sign(&envelope, signers: [
            .init(role: "originator", keyPair: originator.keyPair)
        ])

        var allFiles = parts.innerFiles
        allFiles.append(("manifest.json", Manifest.bytes(manifest)))
        allFiles.append(("provenance/envelope.json", JCS.bytes(envelope)))
        let zipBytes = CapsuleZip.pack(allFiles.map { ($0.0, $0.1) })

        return BuildResult(
            bytes: zipBytes,
            capsuleId: parts.capsuleId,
            firstEventHash: parts.firstHash,
            entryHash: parts.entryHash,
            manifestHash: mfHash,
            contentIndexHash: contentIndex.indexHash,
            originatorPublicKey: originator.keyPair.publicKeyHex,
            signedAt: sealedAt,
            fileCount: allFiles.count,
            byteCount: zipBytes.count
        )
    }

    /// Recipient for the multi-recipient encrypted seal path. Each recipient
    /// supplies a 32-byte X25519 raw public key; the builder generates an
    /// ephemeral X25519 keypair per recipient and HKDFs a wrap key.
    public struct Recipient {
        public let publicKey: Data
        public init(publicKey: Data) {
            precondition(publicKey.count == 32, "recipient X25519 pubkey must be 32 bytes")
            self.publicKey = publicKey
        }
    }

    /// Encrypted-capsule seal. Mirrors `sdk-js/src/builder.js`'s `seal()`
    /// when `recipients` is non-empty. Behavior with an empty recipient
    /// list is identical to the plain `seal(signedAt:)` overload.
    ///
    /// Result shape:
    ///   `bytes`             — outer zip (manifest.json + content.enc +
    ///                         skills/decryption/decryption.json + envelope)
    ///   `manifestHash`      — outer manifest hash
    ///   `contentIndexHash`  — outer content-index hash (covers only the
    ///                         decryption metadata file)
    ///   Other fields are shared with the inner capsule (same id,
    ///   first_event_hash, entry_hash, originator).
    public func seal(signedAt: String? = nil, recipients: [Recipient]) throws -> BuildResult {
        if recipients.isEmpty {
            return try seal(signedAt: signedAt)
        }
        let sealedAt = signedAt ?? Self.isoNow()

        // 1) Build inner files + chain anchors + originator/capsule id once.
        let parts = try buildInnerParts(sealedAt: sealedAt)

        // 2) Build the inner manifest + envelope. The inner package is what
        // recipients receive after decryption — a fully-formed plain
        // capsule that an L3 verifier can verify in isolation.
        let innerContentIndex = Manifest.buildContentIndex(parts.innerFiles)
        let innerManifest = Manifest.build(
            originator: .init(publicKeyHex: originator.keyPair.publicKeyHex,
                              label: originator.label),
            participants: participants.map {
                .init(actorId: $0.actorId, role: $0.role, label: $0.label)
            },
            contentIndex: innerContentIndex,
            firstEventHash: parts.firstHash,
            skillTrust: parts.skillTrust,
            encryption: .null,
            createdAt: createdAt,
            capsuleId: parts.capsuleId
        )
        let innerMfHash = Manifest.hash(innerManifest)
        var innerEnvelope = Envelope.build(
            capsuleId: parts.capsuleId,
            firstEventHash: parts.firstHash,
            entryHash: parts.entryHash,
            manifestHash: innerMfHash,
            contentIndexHash: innerContentIndex.indexHash,
            cipher: "none",
            signedAt: sealedAt
        )
        try Envelope.sign(&innerEnvelope, signers: [
            .init(role: "originator", keyPair: originator.keyPair)
        ])

        var innerAllFiles = parts.innerFiles
        innerAllFiles.append(("manifest.json", Manifest.bytes(innerManifest)))
        innerAllFiles.append(("provenance/envelope.json", JCS.bytes(innerEnvelope)))
        let innerZipBytes = CapsuleZip.pack(innerAllFiles)

        // 3) Encrypt the inner zip.
        //
        // AAD uses only static envelope fields available pre-decrypt
        // (no outer manifest_hash — that depends on encrypted_blob_hash, which
        //  depends on this encryption step).
        //
        // spec/envelope.md lists manifest_hash in the AAD object; the JS
        // reference SDK omits it knowingly, and the Python SDK matches JS.
        // We match the JS reference (the cross-SDK source of truth) so a
        // capsule sealed in Swift decrypts under JS and vice versa.
        let contentKey = Random.key32()
        let contentNonce = Random.nonce12()
        let aad = JCS.bytes(.object([
            ("version", .string("0.6")),
            ("capsule_id", .string(parts.capsuleId)),
            ("first_event_hash", .string(parts.firstHash)),
            ("originator_public_key", .string(originator.keyPair.publicKeyHex)),
            ("cipher", .string("ChaCha20-Poly1305")),
        ]))
        let contentEnc = try ChaCha20Poly1305.encrypt(
            key: contentKey, nonce: contentNonce, aad: aad, plaintext: innerZipBytes
        )
        let encryptedBlobHash = Hash.sha256Hex(contentEnc)

        // 4) Per-recipient key bundles. Ephemeral X25519 + HKDF-SHA256
        // (salt = recipient pubkey) → 32-byte wrap key; wrap the content
        // key with ChaCha20-Poly1305 over empty AAD.
        var keyBundles: [JCSValue] = []
        for r in recipients {
            let eph = X25519KeyPair.generate()
            let shared = try eph.dh(peerPublicKey: r.publicKey)
            let wrapKey = HKDF.sha256(
                ikm: shared,
                salt: r.publicKey,
                info: Data("capsule-key-wrap-v0.6".utf8),
                length: 32
            )
            let wrapNonce = Random.nonce12()
            let wrappedKey = try ChaCha20Poly1305.encrypt(
                key: wrapKey, nonce: wrapNonce, aad: Data(), plaintext: contentKey
            )
            keyBundles.append(.object([
                ("recipient_public_key", .string(Bytes.toHex(r.publicKey))),
                ("ephemeral_public_key", .string(eph.publicKeyHex)),
                ("wrap_nonce", .string(Bytes.toHex(wrapNonce))),
                ("wrapped_key", .string(Bytes.toHex(wrappedKey))),
            ]))
        }
        let decryptionMeta = JCSValue.object([
            ("cipher", .string("ChaCha20-Poly1305")),
            ("content_nonce", .string(Bytes.toHex(contentNonce))),
            ("key_bundles", .array(keyBundles)),
        ])
        let decryptionMetaBytes = JCS.bytes(decryptionMeta)

        // 5) Outer manifest + envelope. The outer content_index covers
        // only skills/decryption/decryption.json — manifest.json,
        // provenance/envelope.json, and content.enc are excluded from the
        // index by `buildContentIndex` (see spec/manifest.md).
        let outerSidecars: [(String, Data)] = [
            ("skills/decryption/decryption.json", decryptionMetaBytes),
            ("content.enc", contentEnc),
        ]
        let outerContentIndex = Manifest.buildContentIndex(outerSidecars)
        let outerManifest = Manifest.build(
            originator: .init(publicKeyHex: originator.keyPair.publicKeyHex,
                              label: originator.label),
            participants: participants.map {
                .init(actorId: $0.actorId, role: $0.role, label: $0.label)
            },
            contentIndex: outerContentIndex,
            firstEventHash: parts.firstHash,
            skillTrust: [], // decryption metadata is not a skill
            encryption: .object([
                ("metadata_path", .string("skills/decryption/decryption.json")),
                ("cipher", .string("ChaCha20-Poly1305")),
            ]),
            createdAt: createdAt,
            capsuleId: parts.capsuleId
        )
        let outerMfHash = Manifest.hash(outerManifest)

        var outerEnvelope = Envelope.build(
            capsuleId: parts.capsuleId,
            firstEventHash: parts.firstHash,
            entryHash: parts.entryHash,
            manifestHash: outerMfHash,
            contentIndexHash: outerContentIndex.indexHash,
            encryptedBlobHash: encryptedBlobHash,
            cipher: "ChaCha20-Poly1305",
            signedAt: sealedAt
        )
        try Envelope.sign(&outerEnvelope, signers: [
            .init(role: "originator", keyPair: originator.keyPair)
        ])

        // 6) Pack the outer zip.
        var outerAllFiles = outerSidecars
        outerAllFiles.append(("manifest.json", Manifest.bytes(outerManifest)))
        outerAllFiles.append(("provenance/envelope.json", JCS.bytes(outerEnvelope)))
        let outerZipBytes = CapsuleZip.pack(outerAllFiles)

        return BuildResult(
            bytes: outerZipBytes,
            capsuleId: parts.capsuleId,
            firstEventHash: parts.firstHash,
            entryHash: parts.entryHash,
            manifestHash: outerMfHash,
            contentIndexHash: outerContentIndex.indexHash,
            originatorPublicKey: originator.keyPair.publicKeyHex,
            signedAt: sealedAt,
            fileCount: outerAllFiles.count,
            byteCount: outerZipBytes.count
        )
    }

    public static func isoNow() -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f.string(from: Date())
    }

    // MARK: - Inner-build helper

    /// Shared pre-manifest construction used by both `seal()` overloads.
    /// Builds the chain, computes the capsule id, and assembles the
    /// non-manifest/non-envelope file list that lives inside the (inner)
    /// capsule.
    private struct InnerParts {
        let innerFiles: [(String, Data)]
        let capsuleId: String
        let firstHash: String
        let entryHash: String
        let skillTrust: [(String, String)]
    }

    private func buildInnerParts(sealedAt: String) throws -> InnerParts {
        var bare = bareEvents
        if bare.isEmpty {
            bare.append(BareEvent(
                actor: "system:host", kind: "observation",
                action: "session_ended", target: "capsule",
                timestamp: sealedAt,
                payload: .object([("note", .string("host emitted backstop event before seal"))]),
                untrustedPayloadFields: []
            ))
        }
        let events = Chain.build(bare)
        guard let firstHash = events.first?.hash, let entryHash = events.last?.hash else {
            throw CapsuleError.malformed("empty chain after build")
        }
        let eventsJsonl = Chain.eventsToJsonl(events)

        var innerFiles: [(String, Data)] = [
            ("program.md", Data(programMd.utf8)),
            ("chain/events.jsonl", eventsJsonl),
        ]
        if let agents = agentsMd {
            innerFiles.append(("agents.md", Data(agents.utf8)))
        }
        var skillTrust: [(String, String)] = []
        for (id, s) in skills {
            if let json = s.json {
                innerFiles.append(("skills/\(id)/skill.json", json))
            }
            if let md = s.markdown {
                innerFiles.append(("skills/\(id)/SKILL.md", Data(md.utf8)))
            }
            skillTrust.append((id, s.signed ? "signed" : "unsigned"))
        }
        for (path, bytes) in payload {
            innerFiles.append((path, bytes))
        }
        let capsuleId = Manifest.computeCapsuleId(
            originatorPub: originator.keyPair.publicKeyBytes,
            firstEventHashHex: firstHash
        )
        return InnerParts(
            innerFiles: innerFiles,
            capsuleId: capsuleId,
            firstHash: firstHash,
            entryHash: entryHash,
            skillTrust: skillTrust
        )
    }
}

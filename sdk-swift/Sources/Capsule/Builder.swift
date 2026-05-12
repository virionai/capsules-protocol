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
        let contentIndex = Manifest.buildContentIndex(innerFiles)
        let manifest = Manifest.build(
            originator: .init(publicKeyHex: originator.keyPair.publicKeyHex,
                              label: originator.label),
            participants: participants.map {
                .init(actorId: $0.actorId, role: $0.role, label: $0.label)
            },
            contentIndex: contentIndex,
            firstEventHash: firstHash,
            skillTrust: skillTrust,
            createdAt: createdAt,
            capsuleId: capsuleId
        )
        let mfHash = Manifest.hash(manifest)

        var envelope = Envelope.build(
            capsuleId: capsuleId,
            firstEventHash: firstHash,
            entryHash: entryHash,
            manifestHash: mfHash,
            contentIndexHash: contentIndex.indexHash,
            cipher: "none",
            signedAt: sealedAt
        )
        try Envelope.sign(&envelope, signers: [
            .init(role: "originator", keyPair: originator.keyPair)
        ])

        var allFiles = innerFiles
        allFiles.append(("manifest.json", Manifest.bytes(manifest)))
        allFiles.append(("provenance/envelope.json", JCS.bytes(envelope)))
        let zipBytes = CapsuleZip.pack(allFiles.map { ($0.0, $0.1) })

        return BuildResult(
            bytes: zipBytes,
            capsuleId: capsuleId,
            firstEventHash: firstHash,
            entryHash: entryHash,
            manifestHash: mfHash,
            contentIndexHash: contentIndex.indexHash,
            originatorPublicKey: originator.keyPair.publicKeyHex,
            signedAt: sealedAt,
            fileCount: allFiles.count,
            byteCount: zipBytes.count
        )
    }

    public static func isoNow() -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f.string(from: Date())
    }
}

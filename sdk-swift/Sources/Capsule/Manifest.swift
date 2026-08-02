// Manifest construction + capsule_id derivation.

import Foundation

public enum Manifest {
    /// Excluded from content_index.files by structural necessity, for every
    /// capsule regardless of profile:
    ///   - manifest.json: the index lives inside it (would be circular)
    ///   - provenance/envelope.json: it commits to the index hash (circular)
    public static let STRUCTURAL_EXCLUDED: Set<String> = [
        "manifest.json",
        "provenance/envelope.json",
    ]

    /// `content.enc` is excluded from the content index ONLY for encrypted
    /// capsules, where it is bound separately by
    /// `envelope.encrypted_blob_hash`. In a plain capsule (`cipher: "none"`)
    /// a `content.enc` entry MUST be indexed like any other file, so a signed
    /// plain capsule cannot carry an unaccounted-for blob past verification
    /// (spec/manifest.md).
    public static let CONTENT_INDEX_EXCLUDED: Set<String> =
        STRUCTURAL_EXCLUDED.union(["content.enc"])

    /// Choose the content-index exclusion set for the capsule's profile.
    /// `encrypted` must be derived from the SIGNED `envelope.cipher`, never
    /// from the presence of a `content.enc` file.
    public static func contentIndexExclusions(_ encrypted: Bool) -> Set<String> {
        encrypted ? CONTENT_INDEX_EXCLUDED : STRUCTURAL_EXCLUDED
    }

    public static let ID_DOMAIN = Data("capsule-id-v0.6\0".utf8)

    /// SHA-256("capsule-id-v0.6\0" || originator_pub || first_event_hash_raw).
    public static func computeCapsuleId(originatorPub: Data, firstEventHashHex: String) -> String {
        precondition(originatorPub.count == 32, "originator pubkey must be 32 bytes")
        precondition(firstEventHashHex.count == 64, "first_event_hash must be 64-hex")
        let firstRaw = Bytes.fromHex(firstEventHashHex)
        let h = Hash.sha256(Bytes.concat(ID_DOMAIN, originatorPub, firstRaw))
        return Bytes.toHex(h)
    }

    public struct ContentIndex {
        public let files: [(path: String, sha256: String)]
        public let indexHash: String
    }

    /// Builds content_index over a sorted list of (path, bytes), skipping
    /// `excluded`. The default is the structural-only set; callers building
    /// or verifying an ENCRYPTED capsule pass
    /// `Manifest.contentIndexExclusions(true)`.
    public static func buildContentIndex(
        _ files: [(path: String, data: Data)],
        excluded: Set<String> = Manifest.STRUCTURAL_EXCLUDED
    ) throws -> ContentIndex {
        var entries: [(path: String, sha256: String)] = []
        for (path, data) in files where !excluded.contains(path) {
            entries.append((path, Hash.sha256Hex(data)))
        }
        // content_index.files is a JSON array, so this order is inside the
        // bytes indexHash covers. Same UTF-16 comparator JCS uses for
        // object members — Swift's `String <` is not that order.
        entries.sort { JCS.utf16Less($0.path, $1.path) }
        let arr = JCSValue.array(entries.map { (p, h) in
            .object([("path", .string(p)), ("sha256", .string(h))])
        })
        let indexHash = Hash.sha256Hex(try JCS.bytes(arr))
        return ContentIndex(files: entries, indexHash: indexHash)
    }

    public struct Originator {
        public let publicKeyHex: String
        public let label: String
        public init(publicKeyHex: String, label: String) {
            self.publicKeyHex = publicKeyHex; self.label = label
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

    /// One member of `manifest.signer_commitment`: the exact seal-time
    /// signer set, sorted ascending by (publicKeyHex, role). Bound into
    /// every envelope signature via manifest_hash (spec/manifest.md).
    public struct SignerCommitmentMember {
        public let role: String
        public let publicKeyHex: String
        public init(role: String, publicKeyHex: String) {
            self.role = role; self.publicKeyHex = publicKeyHex
        }
    }

    /// Build a well-formed signer_commitment from seal-time members:
    /// sorts ascending by (public_key, role) and traps on duplicate
    /// (role, public_key) pairs — the same key under different roles is
    /// permitted as distinct members.
    public static func buildSignerCommitment(
        _ members: [SignerCommitmentMember]
    ) -> [SignerCommitmentMember] {
        let sorted = members
            .map { SignerCommitmentMember(role: $0.role, publicKeyHex: $0.publicKeyHex.lowercased()) }
            .sorted {
                $0.publicKeyHex != $1.publicKeyHex
                    ? $0.publicKeyHex < $1.publicKeyHex
                    : $0.role < $1.role
            }
        for i in 1..<max(sorted.count, 1) where i < sorted.count {
            precondition(
                sorted[i - 1].publicKeyHex != sorted[i].publicKeyHex
                    || sorted[i - 1].role != sorted[i].role,
                "duplicate signer (role=\(sorted[i].role), public_key=\(sorted[i].publicKeyHex))"
            )
        }
        return sorted
    }

    /// Returns the manifest as a JCSValue (with `id` populated). The caller
    /// embeds this into the capsule and uses `manifestHash()` to get the
    /// hash that lands in the envelope.
    ///
    /// `signerCommitment` is the exact seal-time signer set. Pass the
    /// members through `buildSignerCommitment` first; an empty list omits
    /// the manifest member entirely (templates and other unsigned tiers
    /// legitimately omit it — but a capsule sealed by this SDK always
    /// carries it). JCS sorts keys at serialization time, so the member's
    /// position in the pair list is irrelevant to the canonical bytes.
    public static func build(
        originator: Originator,
        participants: [Participant],
        contentIndex: ContentIndex,
        firstEventHash: String,
        skillTrust: [(String, String)] = [],
        encryption: JCSValue = .null,
        signerCommitment: [SignerCommitmentMember] = [],
        createdAt: String,
        capsuleId: String
    ) -> JCSValue {
        var pairs: [(String, JCSValue)] = commonPairs(
            originator: originator,
            participants: participants,
            contentIndex: contentIndex,
            firstEventHash: firstEventHash,
            skillTrust: skillTrust,
            encryption: encryption,
            createdAt: createdAt,
            capsuleId: capsuleId
        )
        if !signerCommitment.isEmpty {
            pairs.append(("signer_commitment", .array(signerCommitment.map { m in
                .object([("role", .string(m.role)), ("public_key", .string(m.publicKeyHex))])
            })))
        }
        return .object(pairs)
    }

    private static func commonPairs(
        originator: Originator,
        participants: [Participant],
        contentIndex: ContentIndex,
        firstEventHash: String,
        skillTrust: [(String, String)],
        encryption: JCSValue,
        createdAt: String,
        capsuleId: String
    ) -> [(String, JCSValue)] {
        [
            ("format", .object([
                ("version", .string("0.6")),
                ("container", .string("zip")),
                ("canonicalization", .string("JCS-RFC8785")),
                ("hash_algorithm", .string("SHA-256")),
            ])),
            ("id", .string(capsuleId)),
            ("originator", .object([
                ("public_key", .string(originator.publicKeyHex)),
                ("label", .string(originator.label)),
            ])),
            ("participants", .array(participants.map { p in
                .object([
                    ("actor_id", .string(p.actorId)),
                    ("role", .string(p.role)),
                    ("label", .string(p.label)),
                ])
            })),
            ("first_event_hash", .string(firstEventHash)),
            ("content_index", .object([
                ("files", .array(contentIndex.files.map {
                    .object([("path", .string($0.path)), ("sha256", .string($0.sha256))])
                })),
                ("index_hash", .string(contentIndex.indexHash)),
            ])),
            ("skill_trust", .object(skillTrust.map { ($0.0, .string($0.1)) })),
            ("encryption", encryption),
            ("created_at", .string(createdAt)),
        ]
    }

    public static func hash(_ manifest: JCSValue) throws -> String {
        Hash.sha256Hex(try JCS.bytes(manifest))
    }

    public static func bytes(_ manifest: JCSValue) throws -> Data {
        try JCS.bytes(manifest)
    }
}

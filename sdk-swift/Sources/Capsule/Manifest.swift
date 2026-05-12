// Manifest construction + capsule_id derivation.

import Foundation

public enum Manifest {
    /// Excluded from content_index.files (see manifest.md).
    public static let CONTENT_INDEX_EXCLUDED: Set<String> = [
        "manifest.json",
        "provenance/envelope.json",
        "content.enc",
    ]

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

    /// Builds content_index over a sorted list of (path, bytes), excluding
    /// the three reserved files.
    public static func buildContentIndex(_ files: [(path: String, data: Data)]) -> ContentIndex {
        var entries: [(path: String, sha256: String)] = []
        for (path, data) in files where !CONTENT_INDEX_EXCLUDED.contains(path) {
            entries.append((path, Hash.sha256Hex(data)))
        }
        entries.sort { $0.path < $1.path }
        let arr = JCSValue.array(entries.map { (p, h) in
            .object([("path", .string(p)), ("sha256", .string(h))])
        })
        let indexHash = Hash.sha256Hex(JCS.bytes(arr))
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

    /// Returns the manifest as a JCSValue (with `id` populated). The caller
    /// embeds this into the capsule and uses `manifestHash()` to get the
    /// hash that lands in the envelope.
    public static func build(
        originator: Originator,
        participants: [Participant],
        contentIndex: ContentIndex,
        firstEventHash: String,
        skillTrust: [(String, String)] = [],
        encryption: JCSValue = .null,
        createdAt: String,
        capsuleId: String
    ) -> JCSValue {
        .object([
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
        ])
    }

    public static func hash(_ manifest: JCSValue) -> String {
        Hash.sha256Hex(JCS.bytes(manifest))
    }

    public static func bytes(_ manifest: JCSValue) -> Data {
        JCS.bytes(manifest)
    }
}

// Append-only signed event chain. Mirrors chain.js: prev_hash + JCS(event)
// over raw bytes (no hex strings as inputs).

import Foundation

public struct BareEvent {
    public let actor: String
    public let kind: String
    public let action: String
    public let target: String
    public let timestamp: String        // ISO 8601 UTC, no fractional seconds
    public let payload: JCSValue        // .object
    public let untrustedPayloadFields: [String]

    public init(
        actor: String, kind: String, action: String, target: String,
        timestamp: String, payload: JCSValue, untrustedPayloadFields: [String] = []
    ) {
        self.actor = actor
        self.kind = kind
        self.action = action
        self.target = target
        self.timestamp = timestamp
        self.payload = payload
        self.untrustedPayloadFields = untrustedPayloadFields
    }
}

/// A built (sealed) event with hashes assigned.
public struct BuiltEvent {
    public let seq: Int
    public let event_id: String
    public let actor: String
    public let kind: String
    public let action: String
    public let target: String
    public let timestamp: String
    public let payload: JCSValue
    public let untrustedPayloadFields: [String]
    public let prev_hash: String
    public let hash: String
    /// The bytes written to chain/events.jsonl for this event.
    public let jsonLine: Data

    public func toJCSWithoutHash() -> JCSValue {
        .object([
            ("seq", .integer(Int64(seq))),
            ("event_id", .string(event_id)),
            ("actor", .string(actor)),
            ("kind", .string(kind)),
            ("action", .string(action)),
            ("target", .string(target)),
            ("timestamp", .string(timestamp)),
            ("payload", payload),
            ("untrusted_payload_fields", .array(untrustedPayloadFields.map { .string($0) })),
            ("prev_hash", .string(prev_hash)),
        ])
    }
}

public enum Chain {
    static let GENESIS_PREV = Data(repeating: 0, count: 32)

    /// The closed `kind` enum from spec/chain.md "Field rules". Readers
    /// reject unknown kinds and the builder refuses to append them — in
    /// every tier, because a custom kind is not a weaker claim, it is
    /// unreadable to the foreign LLM reader the format serves.
    public static let EVENT_KINDS = [
        "decision", "observation", "mutation", "session", "checkpoint",
    ]

    /// The one actor a chain event may always name without a matching
    /// manifest participant — backstop events emitted by the host runtime.
    public static let HOST_ACTOR = "system:host"

    /// True when `kind` is one of the five values spec/chain.md allows.
    public static func isValidEventKind(_ kind: String) -> Bool {
        EVENT_KINDS.contains(kind)
    }

    /// The CLOSED actor-id namespace set from spec/manifest.md "Field
    /// rules": `participants[].actor_id` must match `human:<id>`,
    /// `ai:<id>`, `system:<id>`, or `capsule:<id>` with a non-empty `<id>`.
    public static let ACTOR_NAMESPACES = ["human", "ai", "system", "capsule"]

    /// True when `actorId` is `<namespace>:<id>` with a known namespace
    /// and non-empty id. Case-sensitive; no surrounding whitespace.
    /// Pinned by the chain-rules/invalid-actor-namespace vector.
    public static func isValidActorId(_ actorId: String) -> Bool {
        guard let sep = actorId.firstIndex(of: ":") else { return false }
        let namespace = String(actorId[..<sep])
        let id = actorId[actorId.index(after: sep)...]
        return ACTOR_NAMESPACES.contains(namespace) && !id.isEmpty
    }

    /// The normative `untrusted_payload_fields` path grammar from
    /// spec/chain.md "Untrusted content":
    ///
    ///     path    = "payload" 1*( "." segment )
    ///     segment = 1*( ALPHA / DIGIT / "_" / "-" )
    ///
    /// A marking outside the grammar has no defined resolution — a host
    /// cannot tell which payload member the author marked untrusted — so
    /// writers refuse to emit it and verifiers reject it fail-closed
    /// (vector chain-rules/invalid-untrusted-path).
    public static func isValidUntrustedPayloadPath(_ path: String) -> Bool {
        let segments = path.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count >= 2, segments[0] == "payload" else { return false }
        for seg in segments.dropFirst() {
            if seg.isEmpty { return false }
            for scalar in seg.unicodeScalars {
                switch scalar {
                case "0"..."9", "a"..."z", "A"..."Z", "_", "-":
                    continue
                default:
                    return false
                }
            }
        }
        return true
    }

    /// Render a string the way Rust's `{:?}` renders a `String` (and JS's
    /// `JSON.stringify` a plain-ASCII one), so all five lanes emit
    /// byte-identical verifier messages. `nil` renders as `null` (a
    /// missing field).
    public static func debugQuoted(_ s: String?) -> String {
        guard let s else { return "null" }
        var out = "\""
        for ch in s.unicodeScalars {
            switch ch {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            default: out.unicodeScalars.append(ch)
            }
        }
        return out + "\""
    }

    public static func build(_ bare: [BareEvent]) throws -> [BuiltEvent] {
        var prev = GENESIS_PREV
        var out: [BuiltEvent] = []
        for (i, b) in bare.enumerated() {
            let seq = i + 1
            let eventId = "evt_" + String(format: "%03d", seq)
            let prevHex = Bytes.toHex(prev)
            // Default: mark common narrative fields untrusted unless the
            // caller already populated the list. (We trust caller in this
            // port — log sites in the app fill the list explicitly.)
            let unsealed = JCSValue.object([
                ("seq", .integer(Int64(seq))),
                ("event_id", .string(eventId)),
                ("actor", .string(b.actor)),
                ("kind", .string(b.kind)),
                ("action", .string(b.action)),
                ("target", .string(b.target)),
                ("timestamp", .string(b.timestamp)),
                ("payload", b.payload),
                ("untrusted_payload_fields", .array(b.untrustedPayloadFields.map { .string($0) })),
                ("prev_hash", .string(prevHex)),
            ])
            let canonical = try JCS.bytes(unsealed)
            let hashBytes = Hash.sha256(Bytes.concat(prev, canonical))
            let hashHex = Bytes.toHex(hashBytes)
            // Build JSONL line — exact key order matching reader expectations.
            // Order: seq, event_id, actor, kind, action, target, timestamp,
            // payload, untrusted_payload_fields, prev_hash, hash.
            let withHash = JCSValue.object([
                ("seq", .integer(Int64(seq))),
                ("event_id", .string(eventId)),
                ("actor", .string(b.actor)),
                ("kind", .string(b.kind)),
                ("action", .string(b.action)),
                ("target", .string(b.target)),
                ("timestamp", .string(b.timestamp)),
                ("payload", b.payload),
                ("untrusted_payload_fields", .array(b.untrustedPayloadFields.map { .string($0) })),
                ("prev_hash", .string(prevHex)),
                ("hash", .string(hashHex)),
            ])
            // For the on-disk JSONL we use canonical bytes (works for any
            // reader; deterministic).
            let line = try JCS.bytes(withHash)
            out.append(BuiltEvent(
                seq: seq,
                event_id: eventId,
                actor: b.actor,
                kind: b.kind,
                action: b.action,
                target: b.target,
                timestamp: b.timestamp,
                payload: b.payload,
                untrustedPayloadFields: b.untrustedPayloadFields,
                prev_hash: prevHex,
                hash: hashHex,
                jsonLine: line
            ))
            prev = hashBytes
        }
        return out
    }

    public static func eventsToJsonl(_ events: [BuiltEvent]) -> Data {
        var out = Data()
        for e in events {
            out.append(e.jsonLine)
            out.append(0x0A) // newline
        }
        return out
    }
}

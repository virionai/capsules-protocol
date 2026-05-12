// CapsuleReader — open a sealed plain capsule, parse manifest/envelope/
// chain/program.md/agents.md, and surface its files map. Verification
// lives in CapsuleVerifier; reader is just structured access.

import Foundation

public struct ParsedCapsule {
    public let manifest: JCSValue
    public let envelope: JCSValue
    public let events: [JCSValue]
    public let programMd: String
    public let agentsMd: String?
    public let files: [String: Data]

    public init(manifest: JCSValue, envelope: JCSValue, events: [JCSValue],
                programMd: String, agentsMd: String?, files: [String: Data]) {
        self.manifest = manifest; self.envelope = envelope; self.events = events
        self.programMd = programMd; self.agentsMd = agentsMd; self.files = files
    }
}

public struct VerifyCheck {
    public let name: String
    public let ok: Bool
    public let detail: String
    public init(name: String, ok: Bool, detail: String = "") {
        self.name = name; self.ok = ok; self.detail = detail
    }
}

public struct VerifyResult {
    public let ok: Bool
    public let checks: [VerifyCheck]
    public init(ok: Bool, checks: [VerifyCheck]) {
        self.ok = ok; self.checks = checks
    }
}

public enum CapsuleReader {

    /// Parse a sealed capsule's bytes. Encrypted capsules are out of scope
    /// for v0; throws `CapsuleError.malformed` on detection.
    public static func parse(_ bytes: Data) throws -> ParsedCapsule {
        let entries = try CapsuleZip.unpack(bytes)
        var files = [String: Data]()
        for (path, data) in entries { files[path] = data }

        guard let mfBytes = files["manifest.json"] else {
            throw CapsuleError.malformed("missing manifest.json")
        }
        guard let envBytes = files["provenance/envelope.json"] else {
            throw CapsuleError.malformed("missing provenance/envelope.json")
        }
        guard let evBytes = files["chain/events.jsonl"] else {
            throw CapsuleError.malformed("missing chain/events.jsonl")
        }
        guard let progBytes = files["program.md"] else {
            throw CapsuleError.malformed("missing program.md")
        }

        let manifest = try parseJSON(mfBytes)
        let envelope = try parseJSON(envBytes)
        var events: [JCSValue] = []
        for raw in evBytes.split(separator: 0x0A) where !raw.isEmpty {
            events.append(try parseJSON(Data(raw)))
        }
        let programMd = String(decoding: progBytes, as: UTF8.self)
        let agentsMd = files["agents.md"].map { String(decoding: $0, as: UTF8.self) }

        if case .object(let pairs) = manifest,
           let enc = pairs.first(where: { $0.0 == "encryption" }), enc.1 != .null {
            throw CapsuleError.malformed("encrypted capsule; v0 reader supports plain only")
        }
        return ParsedCapsule(
            manifest: manifest, envelope: envelope, events: events,
            programMd: programMd, agentsMd: agentsMd, files: files
        )
    }

    /// Verify chain hash linkage. Independent of envelope sigs.
    public static func verifyChain(_ events: [JCSValue]) -> Bool {
        var prev = Chain.GENESIS_PREV
        for (i, e) in events.enumerated() {
            guard case .object(let pairs) = e else { return false }
            var withoutHash: [(String, JCSValue)] = []
            var stored: String?
            for (k, v) in pairs {
                if k == "hash", case .string(let s) = v { stored = s }
                else { withoutHash.append((k, v)) }
            }
            guard let storedHash = stored,
                  let prevHash = pairs.first(where: { $0.0 == "prev_hash" }),
                  case .string(let prevHex) = prevHash.1
            else { return false }
            if i == 0 && prevHex != Bytes.toHex(Chain.GENESIS_PREV) { return false }
            if i > 0 && prevHex != Bytes.toHex(prev) { return false }
            let canonical = JCS.bytes(.object(withoutHash))
            let h = Hash.sha256(Bytes.concat(prev, canonical))
            if Bytes.toHex(h) != storedHash { return false }
            prev = h
        }
        return true
    }

    static func parseJSON(_ data: Data) throws -> JCSValue {
        let any = try JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed)
        return convert(any)
    }

    static func convert(_ any: Any) -> JCSValue {
        if any is NSNull { return .null }
        if let n = any as? NSNumber {
            if String(cString: n.objCType) == "c" { return .bool(n.boolValue) }
            if CFNumberIsFloatType(n) { return .decimal(n.doubleValue) }
            return .integer(n.int64Value)
        }
        if let s = any as? String { return .string(s) }
        if let arr = any as? [Any] { return .array(arr.map(convert)) }
        if let dict = any as? [String: Any] {
            return .object(dict.map { ($0.key, convert($0.value)) })
        }
        return .null
    }
}


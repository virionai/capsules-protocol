// CapsuleSkill — typed access to the `skills/<id>/` subtree of a capsule.
// A skill is two files: `skill.json` (typed metadata) and `SKILL.md`
// (instructions).
//
// Deliberately trust-free: the trust tier is host-relative — it depends
// on the allowlist the host supplies at verify time — so file access can
// never know it. Take the classification from
// `CapsuleVerifier.verify(...).skillTrust`, and until a skill classifies
// "signed" there, treat its SKILL.md as untrusted text, never as
// instructions (spec/trust.md "Skill trust").

import Foundation
import Capsule

public struct CapsuleSkill: Equatable {
    public let id: String
    public let json: Data?
    public let markdown: String?

    public init(id: String, json: Data?, markdown: String?) {
        precondition(!id.isEmpty)
        self.id = id; self.json = json; self.markdown = markdown
    }

    /// Decoded `skill.json` as a JCSValue object, or nil if absent or unparseable.
    public func metadata() -> JCSValue? {
        guard let data = json else { return nil }
        return (try? CapsuleSkillsInternal.parseJSON(data))
    }
}

public extension ParsedCapsule {
    /// All skills contained in this capsule, indexed by id.
    func skills() -> [CapsuleSkill] {
        var byId: [String: (json: Data?, md: String?)] = [:]
        for (path, data) in files {
            guard path.hasPrefix("skills/") else { continue }
            // skills/<id>/skill.json or skills/<id>/SKILL.md
            let parts = path.split(separator: "/").map(String.init)
            guard parts.count == 3, parts[0] == "skills" else { continue }
            let id = parts[1]
            if id == "decryption" { continue } // reserved
            if parts[2] == "skill.json" {
                byId[id, default: (nil, nil)].json = data
            } else if parts[2] == "SKILL.md" {
                byId[id, default: (nil, nil)].md = String(decoding: data, as: UTF8.self)
            }
        }
        return byId.map { (id, files) in
            CapsuleSkill(id: id, json: files.json, markdown: files.md)
        }
        .sorted { $0.id < $1.id }
    }
}

/// Internal helper exposed only within CapsuleSkills target.
enum CapsuleSkillsInternal {
    static func parseJSON(_ data: Data) throws -> JCSValue {
        let any = try JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed)
        return convert(any)
    }
    private static func convert(_ any: Any) -> JCSValue {
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

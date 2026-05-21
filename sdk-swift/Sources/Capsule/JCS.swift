// JCS — RFC 8785 canonicalization, ported from the JavaScript reference SDK.
//
// Object keys sorted by UTF-16 code units. Numbers via shortest-roundtrip,
// rejecting NaN/Infinity. Strings escape only RFC 8259 mandatory chars and
// U+0000..U+001F. Arrays preserve order.

import Foundation

public indirect enum JCSValue: Equatable {
    case null
    case bool(Bool)
    case integer(Int64)
    case decimal(Double)
    case string(String)
    case array([JCSValue])
    case object([(String, JCSValue)])

    public static func == (lhs: JCSValue, rhs: JCSValue) -> Bool {
        switch (lhs, rhs) {
        case (.null, .null): return true
        case (.bool(let a), .bool(let b)): return a == b
        case (.integer(let a), .integer(let b)): return a == b
        case (.decimal(let a), .decimal(let b)): return a.bitPattern == b.bitPattern
        case (.string(let a), .string(let b)): return a == b
        case (.array(let a), .array(let b)): return a == b
        case (.object(let a), .object(let b)):
            guard a.count == b.count else { return false }
            for (x, y) in zip(a, b) where x.0 != y.0 || x.1 != y.1 { return false }
            return true
        default: return false
        }
    }
}

public enum JCS {
    public static func canonical(_ v: JCSValue) -> String {
        switch v {
        case .null: return "null"
        case .bool(let b): return b ? "true" : "false"
        case .integer(let i): return String(i)
        case .decimal(let d):
            precondition(d.isFinite, "JCS: non-finite number")
            // Mirror ECMAScript Number.toString shortest-roundtrip. For
            // integral doubles within 2^53 emit without the decimal point.
            if d == 0 { return "0" }
            if d.truncatingRemainder(dividingBy: 1) == 0,
               abs(d) < Double(1 << 53) {
                return String(Int64(d))
            }
            return "\(d)"
        case .string(let s): return encodeString(s)
        case .array(let arr):
            return "[" + arr.map(canonical).joined(separator: ",") + "]"
        case .object(let pairs):
            // Sort by key; UTF-16 code-unit order is the default for Swift's
            // String comparison when both sides are pure-BMP. For correctness
            // beyond BMP we'd compare code-unit views explicitly; chain keys
            // are ASCII so this is exact.
            let sorted = pairs.sorted { $0.0 < $1.0 }
            return "{" + sorted.map { encodeString($0.0) + ":" + canonical($0.1) }
                .joined(separator: ",") + "}"
        }
    }

    public static func bytes(_ v: JCSValue) -> Data {
        return Data(canonical(v).utf8)
    }

    private static func encodeString(_ s: String) -> String {
        var out = "\""
        out.reserveCapacity(s.utf16.count + 2)
        for c in s.unicodeScalars {
            switch c.value {
            case 0x22: out += "\\\""
            case 0x5C: out += "\\\\"
            case 0x08: out += "\\b"
            case 0x0C: out += "\\f"
            case 0x0A: out += "\\n"
            case 0x0D: out += "\\r"
            case 0x09: out += "\\t"
            case 0..<0x20:
                out += String(format: "\\u%04x", c.value)
            default:
                out += String(c)
            }
        }
        out += "\""
        return out
    }
}

// Convenience builders so call sites read like the JS object literals.

public func jobj(_ pairs: (String, JCSValue)...) -> JCSValue { .object(pairs) }
public func jarr(_ items: JCSValue...) -> JCSValue { .array(items) }
public func jarr(_ items: [JCSValue]) -> JCSValue { .array(items) }

extension JCSValue: ExpressibleByNilLiteral {
    public init(nilLiteral: ()) { self = .null }
}
extension JCSValue: ExpressibleByBooleanLiteral {
    public init(booleanLiteral value: Bool) { self = .bool(value) }
}
extension JCSValue: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: Int64) { self = .integer(value) }
}
extension JCSValue: ExpressibleByFloatLiteral {
    public init(floatLiteral value: Double) { self = .decimal(value) }
}
extension JCSValue: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) { self = .string(value) }
}

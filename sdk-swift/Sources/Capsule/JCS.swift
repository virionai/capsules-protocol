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
        case .integer(let i):
            precondition(
                i.magnitude <= (UInt64(1) << 53) - 1,
                "JCS: integer outside IEEE-754 exact range (|n| > 2^53 - 1); "
                    + "not representable identically across implementations"
            )
            return String(i)
        case .decimal(let d):
            precondition(d.isFinite, "JCS: non-finite number")
            return serializeNumber(d)
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

    /// RFC 8785 §3.2.2.3: serialize per ECMAScript Number::toString
    /// (ECMA-262 §7.1.12.1).
    ///
    /// Swift's `"\(d)"` already yields the shortest digit string that
    /// round-trips (the same digits ECMAScript selects), but lays it
    /// out with Swift's own rules for where scientific notation begins
    /// (e.g. `1.5e-05` where ECMAScript emits `0.000015`). This
    /// re-lays those digits out with ECMAScript's thresholds: plain
    /// decimal for 10^-6 ≤ |x| < 10^21, exponent notation outside,
    /// lowercase `e`, explicit `+`, no zero-padded exponent.
    internal static func serializeNumber(_ v: Double) -> String {
        if v == 0 { return "0" } // covers -0.0: JCS serializes negative zero as "0"

        var s = "\(v)"
        var negative = false
        if s.hasPrefix("-") {
            negative = true
            s.removeFirst()
        }

        var mantissa = s
        var exponent = 0
        if let eIndex = s.firstIndex(of: "e") {
            mantissa = String(s[..<eIndex])
            exponent = Int(s[s.index(after: eIndex)...]) ?? 0
        }
        let parts = mantissa.split(
            separator: ".", maxSplits: 1, omittingEmptySubsequences: false)
        let intPart = String(parts[0])
        let fracPart = parts.count > 1 ? String(parts[1]) : ""

        // digits = shortest significant digits; n such that
        // value == 0.digits × 10^n
        let strippedInt = intPart.drop(while: { $0 == "0" })
        var n: Int
        if !strippedInt.isEmpty {
            n = strippedInt.count
        } else {
            n = -fracPart.prefix(while: { $0 == "0" }).count
        }
        n += exponent
        var digits = String((intPart + fracPart).drop(while: { $0 == "0" }))
        while digits.hasSuffix("0") { digits.removeLast() }
        let k = digits.count

        let out: String
        if k <= n && n <= 21 {
            out = digits + String(repeating: "0", count: n - k)
        } else if 0 < n && n <= 21 {
            let point = digits.index(digits.startIndex, offsetBy: n)
            out = String(digits[..<point]) + "." + String(digits[point...])
        } else if -6 < n && n <= 0 {
            out = "0." + String(repeating: "0", count: -n) + digits
        } else {
            let e = n - 1
            let head = k > 1
                ? String(digits.first!) + "." + String(digits.dropFirst())
                : digits
            out = head + "e" + (e >= 0 ? "+" : "-") + String(abs(e))
        }
        return negative ? "-" + out : out
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

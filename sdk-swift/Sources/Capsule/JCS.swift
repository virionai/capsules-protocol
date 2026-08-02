// JCS — RFC 8785 canonicalization, ported from the JavaScript reference SDK.
//
// Object keys sorted by UTF-16 code units (JCS.utf16Less, NOT Swift's
// `String <`). Numbers via shortest-roundtrip,
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
    /// Canonicalize a value to its JCS string.
    ///
    /// Throws `CapsuleError.malformed` (never traps) on values that have
    /// no interoperable canonical form: integers outside ±(2^53 − 1) and
    /// non-finite doubles. These are reachable from
    /// `CapsuleVerifier.verify` on attacker-controlled manifest, envelope,
    /// and chain bytes, so a `precondition` here would let a crafted
    /// capsule kill the host process — matching sdk-py's `ValueError`
    /// and sdk-kotlin's `IllegalArgumentException`, both catchable.
    public static func canonical(_ v: JCSValue) throws -> String {
        switch v {
        case .null: return "null"
        case .bool(let b): return b ? "true" : "false"
        case .integer(let i):
            guard i.magnitude <= (UInt64(1) << 53) - 1 else {
                throw CapsuleError.malformed(
                    "JCS: integer outside IEEE-754 exact range (|n| > 2^53 - 1); "
                        + "not representable identically across implementations"
                )
            }
            return String(i)
        case .decimal(let d):
            guard d.isFinite else {
                throw CapsuleError.malformed("JCS: non-finite number")
            }
            // I-JSON acceptance boundary (spec/canonicalization.md), the
            // double half of the `.integer` guard above: an integral double
            // below 1e21 serializes as a *plain integer literal*, so the same
            // ±(2^53 - 1) limit applies to it. Without this, 1e19 laid out as
            // 10000000000000000000 and no native-integer parser read it back
            // the same. Carried here as well as in `assertAcceptable` so no
            // canonicalization path can bypass the rule.
            guard isAcceptableDouble(d) else {
                throw CapsuleError.malformed(outOfExactRange("(number)"))
            }
            return serializeNumber(d)
        case .string(let s): return encodeString(s)
        case .array(let arr):
            return "[" + (try arr.map(canonical).joined(separator: ",")) + "]"
        case .object(let pairs):
            // RFC 8785 §3.2.3: members sort on their UTF-16 code-unit
            // sequences. Swift's `String <` compares normalized Unicode
            // scalars and disagrees twice over: a supplementary-plane key
            // (U+10000+, lead surrogate 0xD800..0xDBFF) sorts BELOW
            // U+E000..U+FFFF in UTF-16 but above it by scalar value, and
            // canonically equivalent keys ("e" + U+0301 vs U+00E9) compare
            // EQUAL, leaving their relative order to the sort's unspecified
            // stability. Pinned by spec/vectors/jcs-key-order.json.
            let sorted = pairs.sorted { utf16Less($0.0, $1.0) }
            return "{" + (try sorted.map { try encodeString($0.0) + ":" + canonical($0.1) }
                .joined(separator: ",")) + "}"
        }
    }

    public static func bytes(_ v: JCSValue) throws -> Data {
        return Data(try canonical(v).utf8)
    }

    /// Largest integer exactly representable as an IEEE-754 binary64: 2^53 - 1.
    public static let maxSafeInteger: Int64 = (1 << 53) - 1

    /// Smallest magnitude whose ECMAScript `Number::toString` form uses
    /// exponent notation. Below it an integral double serializes as a plain
    /// integer literal; at or above it the token carries an `e`.
    private static let plainIntegerCeiling = 1e21

    /// Enforce the I-JSON acceptance boundary from `spec/canonicalization.md`.
    ///
    /// Swift `String` is a sequence of Unicode scalars and `JSONSerialization`
    /// refuses lone-surrogate escapes at parse time, so only the number rule
    /// needs enforcing here: a number whose canonical token is a *plain
    /// integer literal* must satisfy |n| <= 2^53 - 1. Values at or above
    /// 1e21 serialize in exponent form, which round-trips through every
    /// lane's double path, and are accepted.
    ///
    /// `canonical` carries the same rule as a last-resort backstop; this is
    /// the walking gate that names the offending path, so a builder or reader
    /// rejection tells the caller *which* value it was.
    public static func assertAcceptable(_ v: JCSValue, path: String = "$") throws {
        switch v {
        case .null, .bool, .string:
            return
        case .integer(let i):
            if i.magnitude > UInt64(maxSafeInteger) {
                throw CapsuleError.malformed(outOfExactRange(path))
            }
        case .decimal(let d):
            if !d.isFinite {
                throw CapsuleError.malformed("JCS: non-finite number at \(path)")
            }
            if !isAcceptableDouble(d) {
                throw CapsuleError.malformed(outOfExactRange(path))
            }
        case .array(let items):
            for (i, item) in items.enumerated() {
                try assertAcceptable(item, path: "\(path)[\(i)]")
            }
        case .object(let pairs):
            for (key, value) in pairs {
                try assertAcceptable(value, path: "\(path).\(key)")
            }
        }
    }

    /// `false` when `d` is integral, beyond ±(2^53 - 1), and below 1e21 —
    /// i.e. exactly when its canonical token is an unsafe plain integer
    /// literal. Non-finite values are handled by the callers.
    private static func isAcceptableDouble(_ d: Double) -> Bool {
        let magnitude = abs(d)
        let integral = d == d.rounded(.towardZero)
        return !(integral
            && magnitude > Double(maxSafeInteger)
            && magnitude < plainIntegerCeiling)
    }

    private static func outOfExactRange(_ path: String) -> String {
        "JCS: integer outside IEEE-754 exact range (|n| > 2^53 - 1) at \(path); "
            + "not representable identically across implementations"
    }

    /// Strict UTF-16 code-unit ordering, per RFC 8785 §3.2.3.
    ///
    /// `String.UTF16View.Element` is `UInt16`, so a lexicographic
    /// comparison of the two views is a comparison of code-unit sequences —
    /// exactly what the spec asks for, with no normalization and no
    /// collation. Also the comparator for content-index entry order
    /// (`Manifest.buildContentIndex`) and ZIP entry order
    /// (`CapsuleZip.pack`), both of which must agree with the JS reference
    /// lane, where `a < b` on a JS string already IS UTF-16 order.
    internal static func utf16Less(_ a: String, _ b: String) -> Bool {
        return a.utf16.lexicographicallyPrecedes(b.utf16)
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

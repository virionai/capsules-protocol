//! JSON Canonicalization Scheme (JCS, RFC 8785).
//!
//! This module produces canonical JSON byte sequences that must be
//! byte-identical to the JS reference SDK's `canonicalize` npm package
//! (`sdk-js/src/canonical.js`). Identical output is required because the
//! verifier hashes these bytes and any divergence breaks signature checks.
//!
//! Implementation: thin wrapper over the `serde_jcs` crate. Every required
//! oracle case in `tests` below has been verified to match the JS output
//! byte-for-byte, including the cases where naive Rust formatters would
//! diverge from JS:
//!
//! - `1e21` → `1e+21` (JS `Number.prototype.toString` inserts `+`; `serde_jcs`
//!   uses `ryu-js` which mirrors that behavior)
//! - `-0` → `0` (negative zero collapses)
//! - control characters → lowercase `\u00XX` (RFC 8259 + JCS)
//! - object keys sorted by code-unit order (ASCII-only keys in our use case
//!   make this equivalent to `&str` byte order; documented for posterity)
//!
//! If `serde_jcs` ever diverges from the JS oracle, replace the body of
//! [`jcs`] with an inline canonicalizer; the public API and tests stay put.

use serde_json::Value;

/// Canonicalize `value` per RFC 8785 (JCS) and return UTF-8 bytes.
///
/// Object keys are sorted in UTF-16 code-unit order. For ASCII-only keys —
/// which covers all manifest, envelope, and chain-record keys in the v0.6
/// capsule format — this coincides with the byte order of UTF-8 strings. If
/// the schema ever introduces keys containing supplementary (non-BMP)
/// characters, the underlying `serde_jcs` crate already handles UTF-16
/// ordering correctly.
///
/// Panics if `value` contains a non-finite number (NaN or ±Infinity), which
/// `serde_json::Value` cannot represent in the first place, so this is a
/// theoretical concern. In practice all inputs to this function come from
/// parsed JSON, which excludes those by construction.
pub fn jcs(value: &Value) -> Vec<u8> {
    // serde_jcs serializes any Serialize value; for serde_json::Value the
    // result is JCS-canonical JSON. The intermediate String is guaranteed to
    // be valid UTF-8 (it's a Rust `String`), so we just take its bytes.
    serde_jcs::to_string(value)
        .expect("serde_jcs cannot fail on a serde_json::Value")
        .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256_hex;
    use serde_json::{json, Value};

    /// Helper: run `jcs` and assert the output matches `expected_bytes`.
    fn assert_jcs(value: Value, expected: &[u8]) {
        let got = jcs(&value);
        assert_eq!(
            got, expected,
            "JCS mismatch\n  got:      {:?}\n  expected: {:?}",
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(expected)
        );
    }

    #[test]
    fn oracle_null() {
        assert_jcs(Value::Null, b"null");
    }

    #[test]
    fn oracle_object_key_sorting() {
        assert_jcs(json!({"b": 1, "a": 2}), br#"{"a":2,"b":1}"#);
    }

    #[test]
    fn oracle_integer() {
        assert_jcs(json!(7), b"7");
    }

    #[test]
    fn oracle_decimal() {
        assert_jcs(json!(7.5), b"7.5");
    }

    #[test]
    fn oracle_negative_zero() {
        // `-0` parses as a Number; JCS collapses it to `0`.
        let v: Value = serde_json::from_str("-0").expect("valid json");
        assert_jcs(v, b"0");
    }

    #[test]
    fn oracle_large_exponent() {
        // 1e21 must serialize with a `+` in the exponent: `1e+21`.
        let v: Value = serde_json::from_str("1e21").expect("valid json");
        assert_jcs(v, b"1e+21");
    }

    #[test]
    fn oracle_zero() {
        assert_jcs(json!(0), b"0");
    }

    #[test]
    fn oracle_empty_string() {
        assert_jcs(json!(""), br#""""#);
    }

    #[test]
    fn oracle_simple_string() {
        assert_jcs(json!("a"), br#""a""#);
    }

    #[test]
    fn oracle_special_string_escapes() {
        // Five-char string: `"`, `\`, LF, `/`, `é`. The forward slash is NOT
        // escaped; the others get their RFC 8259 short escapes; `é` passes
        // through as UTF-8.
        let s = "\"\\\n/é";
        let expected: &[u8] = b"\"\\\"\\\\\\n/\xc3\xa9\"";
        assert_jcs(Value::String(s.to_string()), expected);
    }

    #[test]
    fn oracle_manifest_format_block() {
        // Real-world example: the `format` block from a v0.6 manifest. Object
        // keys must end up alphabetized.
        let input = json!({
            "format": {
                "version": "0.6",
                "container": "zip",
                "canonicalization": "JCS-RFC8785",
                "hash_algorithm": "SHA-256"
            }
        });
        let expected = br#"{"format":{"canonicalization":"JCS-RFC8785","container":"zip","hash_algorithm":"SHA-256","version":"0.6"}}"#;
        assert_jcs(input, expected);
    }

    #[test]
    fn oracle_nested_with_arrays_and_primitives() {
        let input = json!({
            "a": [1, 2, 3],
            "b": {"c": false, "d": true, "e": null}
        });
        let expected = br#"{"a":[1,2,3],"b":{"c":false,"d":true,"e":null}}"#;
        assert_jcs(input, expected);
    }

    #[test]
    fn oracle_empty_array() {
        assert_jcs(json!([]), b"[]");
    }

    #[test]
    fn oracle_empty_object() {
        assert_jcs(json!({}), b"{}");
    }

    #[test]
    fn oracle_negative_decimal() {
        assert_jcs(json!(-1.5), b"-1.5");
    }

    #[test]
    fn oracle_negative_exponent() {
        let v: Value = serde_json::from_str("1.5e-10").expect("valid json");
        assert_jcs(v, b"1.5e-10");
    }

    #[test]
    fn oracle_control_char_soh_lowercase_hex() {
        // U+0001 (SOH) must escape to `` with lowercase hex digits.
        // Total output is 8 bytes: `"`, `\`, `u`, `0`, `0`, `0`, `1`, `"`.
        let input = Value::String("\u{0001}".to_string());
        let expected: &[u8] = b"\"\\u0001\"";
        assert_eq!(expected.len(), 8);
        assert_jcs(input, expected);
    }

    #[test]
    fn ascii_input_yields_valid_utf8_string() {
        // Sanity: for ASCII-only input the bytes round-trip through
        // String::from_utf8 and equal the input characters of the canonical
        // form (i.e., we're returning UTF-8 bytes, not some other encoding).
        let bytes = jcs(&json!({"a": 1, "b": "hello", "c": [true, false, null]}));
        let s = String::from_utf8(bytes).expect("ASCII-only output must be valid UTF-8");
        assert_eq!(s, r#"{"a":1,"b":"hello","c":[true,false,null]}"#);
        // And every byte is < 0x80, the ASCII range.
        assert!(s.bytes().all(|b| b < 0x80));
    }

    #[test]
    fn deterministic_sha256_of_canonical_form() {
        // Cross-check with the Task 1 crypto helper: hashing the canonical
        // bytes is deterministic across invocations, regardless of the input
        // map's insertion order.
        let a = sha256_hex(&jcs(&json!({"a": 1, "b": 2})));
        let b = sha256_hex(&jcs(&json!({"b": 2, "a": 1})));
        assert_eq!(a, b, "key order in source map must not affect hash");

        let again = sha256_hex(&jcs(&json!({"a": 1, "b": 2})));
        assert_eq!(a, again, "JCS + SHA-256 must be deterministic");

        // The exact value isn't part of any spec we're verifying; we only
        // care that it's stable. Pin it so accidental future changes to the
        // canonicalizer surface as a test failure rather than a silent break.
        assert_eq!(
            a,
            "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
        );
    }
}

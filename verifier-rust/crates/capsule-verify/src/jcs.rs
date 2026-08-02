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
//! - object keys sorted by UTF-16 code-unit order. This is NOT `&str` byte
//!   order: Rust's `str: Ord` is UTF-8 byte order == code-point order, and
//!   the two disagree once a supplementary key (>= U+10000) meets a key in
//!   U+E000..U+FFFF. `serde_jcs` 0.2.0 wraps keys in a `Utf16Key` whose
//!   `Ord` compares `Vec<u16>` built by `encode_utf16()` (lib.rs:100-134),
//!   which is correct; pinned by `spec_registry::jcs_key_order_registry`.
//!
//! If `serde_jcs` ever diverges from the JS oracle, replace the body of
//! [`jcs`] with an inline canonicalizer; the public API and tests stay put.

use serde_json::Value;

/// Canonicalize `value` per RFC 8785 (JCS) and return UTF-8 bytes.
///
/// Object keys are sorted in UTF-16 code-unit order (RFC 8785 §3.2.3). All
/// v0.6 manifest, envelope, and chain-record keys are ASCII, where that
/// coincides with UTF-8 byte order — but the guarantee does not rest on
/// that: `serde_jcs` compares `Vec<u16>` from `encode_utf16()`, so
/// supplementary-plane keys are ordered correctly too. Do not swap in a
/// canonicalizer that sorts `&str` directly: that is code-point order, and
/// it disagrees with UTF-16 whenever a key >= U+10000 meets a key in
/// U+E000..U+FFFF.
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

/// Largest integer exactly representable as an IEEE-754 binary64: 2^53 - 1.
const MAX_SAFE_INTEGER: i128 = (1i128 << 53) - 1;

/// Smallest magnitude whose ECMAScript `Number::toString` form uses exponent
/// notation. Below it an integral double serializes as a plain integer
/// literal; at or above it the token carries an `e`.
const PLAIN_INTEGER_CEILING: f64 = 1e21;

/// Enforce the I-JSON acceptance boundary from `spec/canonicalization.md`.
///
/// RFC 8785 canonicalization is only defined over I-JSON (RFC 7493) input.
/// This verifier's strings are Rust `String`s, which cannot hold unpaired
/// surrogates (`serde_json` rejects lone-surrogate escapes at parse time), so
/// only the number rule needs enforcing here: a number whose canonical token
/// is a *plain integer literal* must satisfy |n| <= 2^53 - 1.
///
/// Returns `Err(message)` naming the offending path, or `Ok(())`.
pub fn check_ijson(value: &Value) -> Result<(), String> {
    check_ijson_at(value, "$")
}

fn check_ijson_at(value: &Value, path: &str) -> Result<(), String> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(n) => check_number(n, path),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                check_ijson_at(item, &format!("{path}[{i}]"))?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (k, v) in map {
                check_ijson_at(v, &format!("{path}.{k}"))?;
            }
            Ok(())
        }
    }
}

fn out_of_range(path: &str) -> String {
    format!(
        "JCS: integer outside IEEE-754 exact range (|n| > 2^53 - 1) at {path}; \
         not representable identically across implementations"
    )
}

fn check_number(n: &serde_json::Number, path: &str) -> Result<(), String> {
    if let Some(u) = n.as_u64() {
        return if i128::from(u) > MAX_SAFE_INTEGER {
            Err(out_of_range(path))
        } else {
            Ok(())
        };
    }
    if let Some(i) = n.as_i64() {
        return if i128::from(i).abs() > MAX_SAFE_INTEGER {
            Err(out_of_range(path))
        } else {
            Ok(())
        };
    }
    let f = n
        .as_f64()
        .ok_or_else(|| format!("JCS: non-finite number at {path}"))?;
    if !f.is_finite() {
        return Err(format!("JCS: non-finite number at {path}"));
    }
    let magnitude = f.abs();
    if f.fract() == 0.0 && magnitude > MAX_SAFE_INTEGER as f64 && magnitude < PLAIN_INTEGER_CEILING
    {
        return Err(out_of_range(path));
    }
    Ok(())
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
    fn check_ijson_rejects_plain_integer_literal_out_of_range() {
        // A 20-digit integer literal: serde_json parses it as u64, serde_jcs
        // would happily echo it, and a JS reader would round it. Refuse.
        let v: Value = serde_json::from_str(r#"{"payload":{"ts":10000000000000000000}}"#)
            .expect("valid json");
        let err = check_ijson(&v).expect_err("must be rejected");
        assert!(
            err.contains("integer outside IEEE-754 exact range"),
            "unexpected message: {err}"
        );
        assert!(
            err.contains("$.payload.ts"),
            "message must name the path: {err}"
        );
    }

    #[test]
    fn check_ijson_rejects_exponent_input_that_serializes_as_plain_integer() {
        // `1e19` arrives as an f64 but Number::toString lays it out as
        // 10000000000000000000 - the same unsafe plain literal.
        let v: Value = serde_json::from_str("[1e19]").expect("valid json");
        assert!(check_ijson(&v).is_err());
        assert_eq!(String::from_utf8(jcs(&v)).unwrap(), "[10000000000000000000]");
    }

    #[test]
    fn check_ijson_accepts_max_safe_and_exponent_form() {
        let safe: Value = serde_json::from_str("9007199254740991").expect("valid json");
        assert!(check_ijson(&safe).is_ok());
        // 1e21 and above serialize in exponent form, which round-trips
        // through every lane's double path.
        let big: Value = serde_json::from_str("1e21").expect("valid json");
        assert!(check_ijson(&big).is_ok());
        assert_eq!(String::from_utf8(jcs(&big)).unwrap(), "1e+21");
    }

    #[test]
    fn serde_json_rejects_lone_surrogate_escape_at_parse() {
        // The string half of the acceptance boundary is enforced by the
        // parser in this lane: Rust `String` cannot hold a lone surrogate.
        assert!(
            serde_json::from_str::<Value>(r#"{"s":"x\ud83dy"}"#).is_err(),
            "an unpaired high surrogate escape must not parse"
        );
        assert!(
            serde_json::from_str::<Value>(r#"{"s":"x\udc00"}"#).is_err(),
            "an unpaired low surrogate escape must not parse"
        );
        // The well-formed pair is accepted and yields one astral scalar.
        let ok: Value = serde_json::from_str(r#"{"s":"x🙂"}"#).expect("valid pair");
        assert_eq!(String::from_utf8(jcs(&ok)).unwrap().chars().count(), 10);
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

#[cfg(test)]
mod vector_tests {
    use super::jcs;
    use serde_json::Value;

    /// Vector-driven check against the normative JCS number vectors in
    /// spec/vectors/jcs-numbers.json (Node JSON.stringify is the oracle).
    /// Inputs are IEEE-754 bit patterns so no JSON parser sits between
    /// the vector and the value under test.
    #[test]
    fn numbers_match_spec_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../spec/vectors/jcs-numbers.json"
        );
        let doc: Value = serde_json::from_str(
            &std::fs::read_to_string(path).expect("read spec/vectors/jcs-numbers.json"),
        )
        .expect("parse jcs-numbers.json");
        let vectors = doc["vectors"].as_array().expect("vectors array");
        assert!(!vectors.is_empty(), "vector file is empty");
        for entry in vectors {
            let hex = entry["ieee_hex"].as_str().expect("ieee_hex");
            let expected = entry["expected"].as_str().expect("expected");
            let bits = u64::from_str_radix(hex, 16).expect("hex bits");
            let value = f64::from_bits(bits);
            let num = serde_json::Number::from_f64(value)
                .expect("vectors contain only finite doubles");
            if entry["accepted"] == Value::Bool(false) {
                // Outside the I-JSON acceptance boundary
                // (spec/canonicalization.md): `expected` documents the
                // Number::toString layout, but the value must be refused.
                assert!(
                    super::check_ijson(&Value::Number(num)).is_err(),
                    "bits {hex} (would serialize as {expected}) must be rejected"
                );
                continue;
            }
            let got = String::from_utf8(jcs(&Value::Number(num))).expect("utf8");
            assert_eq!(got, expected, "bits {hex}");
        }
    }
}

#![cfg(test)]

use std::collections::BTreeMap;
use std::io::{Cursor, Write};
use std::path::PathBuf;

use zip::write::{SimpleFileOptions, ZipWriter};
use zip::CompressionMethod;

use crate::zip_reader::unpack_zip;

/// Resolve a capsule fixture by name under `spec/vectors/tamper-detection/output`.
/// Panics with a clear message if the fixture is missing — this only fires
/// from tests, so the panic surfaces as a test failure with enough context
/// for a reader to know how to regenerate.
fn fixture_path(name: &str) -> PathBuf {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .join("..")
        .join("..")
        .join("..")
        .join("spec/vectors/tamper-detection/output")
        .join(name)
        .canonicalize()
        .unwrap_or_else(|_| {
            panic!(
                "fixture {name:?} missing; populate spec/vectors before running parity tests"
            )
        })
}

/// Returns the absolute path to the JS-produced clean capsule fixture.
/// Panics with a useful message if the fixture is missing.
pub fn clean_capsule_path() -> PathBuf {
    fixture_path("clean.capsule")
}

/// Reads `clean.capsule` into memory.
pub fn clean_capsule_bytes() -> Vec<u8> {
    std::fs::read(clean_capsule_path()).expect("read clean.capsule")
}

/// Reads a tamper-detection fixture (e.g. `tampered-payload.capsule`,
/// `tampered-chain.capsule`, `tampered-envelope.capsule`,
/// `tampered-blob.capsule`, `clean-encrypted.capsule`) into memory.
pub fn tampered_capsule_bytes(name: &str) -> Vec<u8> {
    std::fs::read(fixture_path(name)).unwrap_or_else(|e| {
        panic!("read fixture {name:?} failed: {e}");
    })
}

/// Reads the recipient's X25519 32-byte secret from
/// `spec/vectors/tamper-detection/output/keys.json` (the same fixture the JS
/// reference SDK uses to build `clean-encrypted.capsule`). Used by the
/// decryption tests to round-trip an encrypted capsule end-to-end.
pub fn recipient_x25519_private_key() -> [u8; 32] {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = crate_dir
        .join("..")
        .join("..")
        .join("..")
        .join("spec/vectors/tamper-detection/output/keys.json")
        .canonicalize()
        .expect(
            "keys.json missing; populate spec/vectors before running parity tests",
        );
    let bytes = std::fs::read(&path).expect("read keys.json");
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).expect("keys.json is valid JSON");
    let hex_str = v
        .pointer("/recipient/privateKey")
        .and_then(|x| x.as_str())
        .expect("keys.json contains recipient.privateKey");
    let raw = crate::crypto::hex_to_bytes(hex_str)
        .expect("recipient.privateKey is strict lowercase hex");
    raw.try_into()
        .expect("recipient.privateKey is exactly 32 bytes")
}

/// Read a base capsule fixture, mutate its `provenance/envelope.json` in
/// place, and re-pack the modified file set as a STORED-only ZIP. Used by
/// the synthesized-fixture tests that need to exercise rejection paths
/// (unsupported cipher, illegal cipher/blob combinations) without
/// depending on a fresh JS-side build.
///
/// The `mutate` callback receives the parsed envelope as a mutable
/// `serde_json::Value` so callers can flip individual fields without
/// re-stating the whole envelope. Every other file in the original ZIP is
/// copied through unchanged. The resulting capsule is *not* re-signed —
/// signature verification will fail — so callers should only assert on the
/// errors they care about (e.g. `Encryption`-category messages).
pub fn synthesize_capsule_with_envelope_mutation(
    base: &str,
    mutate: impl FnOnce(&mut serde_json::Value),
) -> Vec<u8> {
    let bytes = tampered_capsule_bytes(base);
    let files: BTreeMap<String, Vec<u8>> =
        unpack_zip(&bytes).expect("base fixture must unzip");

    let envelope_bytes = files
        .get("provenance/envelope.json")
        .expect("base fixture must contain provenance/envelope.json")
        .clone();
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&envelope_bytes).expect("envelope.json must parse");
    mutate(&mut envelope);
    let new_envelope_bytes =
        serde_json::to_vec(&envelope).expect("mutated envelope must reserialize");

    let buf = Cursor::new(Vec::<u8>::new());
    let mut zw = ZipWriter::new(buf);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (path, content) in &files {
        zw.start_file(path, opts).expect("zip start_file");
        let payload = if path == "provenance/envelope.json" {
            &new_envelope_bytes
        } else {
            content
        };
        zw.write_all(payload).expect("zip write_all");
    }
    zw.finish().expect("zip finish").into_inner()
}

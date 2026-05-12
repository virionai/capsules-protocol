# Rust Verifier v0.3 — L3 Decryption + Inner Chain Walk

**Status:** approved, ready to execute
**Builds on:** v0.1 (`2026-05-08-rust-verifier-plan.md`) + v0.2 (`2026-05-08-rust-verifier-v0.2-l2-encrypted-plan.md`)
**Capsule format:** v0.6 (no schema changes)
**Output:** Modifications to `new-design/verifier-rust/`. New `decrypt.rs` module + `--decryption-key` CLI flag.

## Goal

When the user supplies the recipient's 32-byte X25519 secret key, the Rust verifier should:

1. Locate the matching `key_bundle` in `skills/decryption/decryption.json`.
2. Derive the content key via X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305 unwrap.
3. Decrypt `content.enc` with the content key + AAD over JCS-canonical static envelope fields.
4. Parse the inner ZIP exactly as a plain capsule.
5. Run the existing chain walk on the inner chain.
6. Cross-check inner manifest/envelope anchors against the OUTER envelope (capsule_id, first_event_hash, entry_hash).
7. Report `level = "L3"` when this succeeds; `chain.note` is `None` (the chain was actually verified, not deferred).

Without a key, v0.2's L2 behavior is unchanged. The flag is opt-in and orthogonal.

After v0.3:

| Fixture | No key (L2) | With recipient key (L3) |
|---|---|---|
| `clean.capsule` | PASS | (key ignored — plain) |
| `tampered-payload.capsule` | FAIL @ content_index | (same — plain) |
| `tampered-chain.capsule` | FAIL | (same — plain) |
| `tampered-envelope.capsule` | FAIL @ envelope_signature | (same — plain) |
| `clean-encrypted.capsule` | PASS @ L2 (chain deferred) | **PASS @ L3 (chain fully verified)** |
| `tampered-blob.capsule` | FAIL @ encryption_state | FAIL @ decryption (auth tag mismatch) |

## Why now

The v0.2 final review identified L3 as the natural next deliverable. v0.2 closed the L2 gap; v0.3 closes the verification stack entirely. After v0.3, the moat claim moves from "two implementations at L2 (plain + encrypted-outer)" to "two implementations at every verification tier the spec defines" — which is the strongest framing for the Kaggle launch.

## Spec authority

- `spec/envelope.md` — "Encryption" and "L2 / L3" sections.
- `sdk/src/builder.js` lines 228-280 — the canonical encrypted construction (AAD shape, HKDF parameters, key-bundle layout). The Rust verifier must mirror these *exactly*.

### AAD shape (CRITICAL — matches the impl, not the spec text)

```json
{
  "version":               "0.6",
  "capsule_id":            "<hex>",
  "first_event_hash":      "<hex>",
  "originator_public_key": "<hex>",
  "cipher":                "ChaCha20-Poly1305"
}
```

JCS-canonicalize and use as AAD for the content blob's ChaCha20-Poly1305 decrypt. **No `manifest_hash` field**, despite what the spec text in `envelope.md` shows — the JS reference omits it (the comment explains why: it would create a circular dependency since `manifest_hash` depends on `content_index_hash` which depends on `encrypted_blob_hash` which depends on this encryption step). Mirror the impl.

### Key wrap

```
shared    = X25519(recipient_priv, ephemeral_pub_from_bundle)
wrap_key  = HKDF-SHA256(ikm = shared, salt = recipient_pubkey, info = utf8("capsule-key-wrap-v0.6"), length = 32)
content_key = ChaCha20-Poly1305-Decrypt(wrap_key, wrap_nonce, AAD = empty, wrapped_key)
```

Notes:
- Salt is the *recipient's* public key (not the ephemeral). Mirror exactly.
- AAD for the key-wrap step is empty (the JS uses `Buffer.alloc(0)`).
- All inputs to ECDH and ChaCha are raw bytes; no hex strings as crypto inputs.

### Inner ZIP

After `content.enc` decrypts to plaintext bytes, those bytes are a normal Capsule v0.6 plain-shape ZIP. Reuse `unpack_zip` and the existing schemas/chain walk. The inner ZIP contains its own `manifest.json`, `provenance/envelope.json`, `chain/events.jsonl`, etc.

### L3 cross-checks

Per `spec/envelope.md` and `sdk/src/verifier.js` lines 178-192:

```
inner.capsule_id == outer.capsule_id
inner.first_event_hash == outer.first_event_hash
inner.entry_hash == outer.entry_hash
```

If any mismatch, push to top-level errors with category `ChainAnchor` (the inner-vs-outer linkage is exactly the kind of cross-anchor mismatch ChainAnchor covers).

The inner envelope's *signatures* are also part of L3, but for v0.3 we follow the JS reference: report inner signers separately if they exist, but don't fail L3 over inner signature mismatches alone (those become a downstream concern). For simplicity, if the inner envelope has any signers, run signature verification on them with the same code path used for outer signatures, and surface results in a new `inner_envelope: Option<EnvelopeCheck>` field on `VerifyResult`. If this complicates scope, drop it and document — outer signatures plus L3 cross-checks are enough.

## Crate selection

| Crate | Purpose | Notes |
|---|---|---|
| `chacha20poly1305 = "0.10"` | AEAD decrypt | RustCrypto, audited, single-crate |
| `x25519-dalek = "2"` | X25519 ECDH | RustCrypto, audited |
| `hkdf = "0.12"` | HKDF-SHA256 | RustCrypto, audited |

All three are pure Rust, single-crate offerings. No vendoring required.

`x25519-dalek` v2 has a slightly fussy API (StaticSecret vs ReusableSecret); the implementer should pick whichever matches the use case (we hold the secret in memory for the decrypt session — `StaticSecret` is appropriate).

## Tasks

### Task 1 — `decrypt.rs` module

**Goal:** End-to-end `decrypt_inner_zip` that takes outer envelope + outer manifest + outer files map + recipient X25519 private key (32 bytes raw) and returns the inner ZIP bytes. Plus crypto wrappers + tests.

**Files:**
- `verifier-rust/Cargo.toml` (workspace deps: `chacha20poly1305`, `x25519-dalek`, `hkdf`)
- `verifier-rust/crates/capsule-verify/Cargo.toml` (wire deps in)
- `verifier-rust/crates/capsule-verify/src/decrypt.rs` (new)
- `verifier-rust/crates/capsule-verify/src/lib.rs` (declare + re-export new module)

**Public surface:**

```rust
pub fn decrypt_inner_zip(
    envelope: &Envelope,
    manifest: &Manifest,
    files: &BTreeMap<String, Vec<u8>>,
    recipient_private_key: &[u8; 32],
) -> Result<Vec<u8>, DecryptError>;

pub enum DecryptError {
    NotEncrypted,                              // no content.enc
    DecryptionMetadataMissing,                 // skills/decryption/decryption.json absent
    DecryptionMetadataInvalid(String),         // JSON parse / shape error
    NoMatchingRecipient,                       // none of the bundles' recipient_public_key matches the priv key's pubkey
    KeyUnwrapFailed,                           // ChaCha20-Poly1305 auth failure on wrapped_key
    ContentDecryptFailed,                      // ChaCha20-Poly1305 auth failure on content.enc
    Hex(String),                               // bad hex in metadata
    Crypto(String),                            // catch-all for ECDH/HKDF errors
}
```

`DecryptError` derives `Debug` + `thiserror::Error` with informative messages.

**Internal helpers (not pub, but unit-testable):**

```rust
fn x25519_pubkey_from_secret(secret: &[u8; 32]) -> [u8; 32];
fn x25519_dh(secret: &[u8; 32], peer_pub: &[u8; 32]) -> [u8; 32];
fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8>;
fn chacha20_poly1305_decrypt(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ()>;
fn build_aad(envelope: &Envelope, manifest: &Manifest) -> Vec<u8>;  // JCS over the 5-field aadObj
fn select_key_bundle<'a>(bundles: &'a [KeyBundle], my_pubkey_hex: &str) -> Option<&'a KeyBundle>;
```

**Decryption.json shape (parse with serde):**

```rust
#[derive(Debug, Deserialize)]
pub struct DecryptionMetadata {
    pub cipher: String,
    pub content_nonce: String,           // 24-hex
    pub key_bundles: Vec<KeyBundle>,
}

#[derive(Debug, Deserialize)]
pub struct KeyBundle {
    pub recipient_public_key: String,    // 64-hex (X25519)
    pub ephemeral_public_key: String,    // 64-hex
    pub wrap_nonce: String,              // 24-hex
    pub wrapped_key: String,             // hex (typically 96 chars: 32 bytes plaintext + 16 bytes tag → ~96 hex)
}
```

Place these structs in `decrypt.rs` (they're decryption-specific, not general schemas).

**Algorithm:**

```
1. Verify cipher == "ChaCha20-Poly1305" (otherwise NotEncrypted variant if cipher == "none", else KeyUnwrapFailed-equivalent error).
2. Read content.enc bytes from files.
3. Read & parse skills/decryption/decryption.json.
4. Compute my_pubkey = x25519_pubkey_from_secret(recipient_private_key); convert to hex.
5. Find the bundle where bundle.recipient_public_key == my_pubkey_hex. If none, return NoMatchingRecipient.
6. shared = x25519_dh(recipient_private_key, hex_to_bytes(bundle.ephemeral_public_key)).
7. wrap_key = hkdf_sha256(ikm=shared, salt=recipient_pubkey_raw, info="capsule-key-wrap-v0.6", length=32).
8. content_key = chacha20_poly1305_decrypt(wrap_key, hex_to_bytes(wrap_nonce), aad=&[], hex_to_bytes(wrapped_key)). Maps to KeyUnwrapFailed.
9. aad = build_aad(envelope, manifest).
10. inner_zip = chacha20_poly1305_decrypt(content_key, hex_to_bytes(envelope...content_nonce... wait, actually content_nonce is on decryption_meta, not envelope), aad, content_enc_bytes). Maps to ContentDecryptFailed.
11. Return inner_zip.
```

(The content_nonce lives on `DecryptionMetadata`, not on the envelope. Verify against the JS impl in builder.js.)

**Tests in `decrypt.rs`:**

1. **`hkdf_known_vector`** — RFC 5869 Test Case 1 (sha256). IKM = 22 bytes 0x0b, salt = 13 bytes 0x00..0x0c, info = 10 bytes 0xf0..0xf9, length = 42. Expected OKM matches the spec.

2. **`x25519_known_vector`** — RFC 7748 §6.1 test vector. Alice's private d75a98... derives expected pubkey.

3. **`chacha20poly1305_known_vector`** — RFC 8439 §2.8.2 test vector. Encrypt + decrypt round-trip on the standard "Ladies and Gentlemen" plaintext with known key/nonce/aad.

4. **`decrypts_clean_encrypted_capsule`** — full integration test:
   - Load `clean-encrypted.capsule` via `clean_encrypted_capsule_bytes()` (add helper to test_support if not present).
   - Load `keys.json`, parse `recipient.privateKey` as 32 bytes raw.
   - Open outer ZIP via `unpack_zip`.
   - Parse outer manifest + envelope.
   - Call `decrypt_inner_zip(envelope, manifest, files, &recipient_secret)`.
   - Assert result is Ok and the bytes start with the ZIP local-file-header magic `0x50, 0x4b, 0x03, 0x04`.
   - Open the inner ZIP via `unpack_zip` and confirm it contains `manifest.json`, `chain/events.jsonl`, `provenance/envelope.json` (the inner shape).

5. **`tampered_blob_fails_decryption`** — load tampered-blob.capsule + recipient key, expect `Err(ContentDecryptFailed)`.

6. **`wrong_key_returns_no_matching_recipient`** — load clean-encrypted with a fresh random X25519 private (whose pubkey isn't in the bundles). Expect `NoMatchingRecipient`.

7. **`build_aad_matches_jcs_oracle`** — capture the AAD bytes from the JS reference for `clean-encrypted.capsule`'s envelope+manifest, paste in as a hex literal, assert `build_aad(...)` returns the same bytes. Belt-and-suspenders check that the JCS over `{version, capsule_id, first_event_hash, originator_public_key, cipher}` matches what the producer used.

   To capture the oracle: `node -e "import('canonicalize').then(({default: c}) => process.stdout.write(c({version:'0.6', capsule_id:'<id>', first_event_hash:'<feh>', originator_public_key:'<pk>', cipher:'ChaCha20-Poly1305'})))"` from the SDK directory. Paste the hex into the test.

**Out of scope for Task 1:**

- Verifier integration (Task 2).
- CLI flag (Task 3).

### Task 2 — L3 verifier integration

**Goal:** When `VerifyOptions.recipient_private_key.is_some()` AND the capsule is encrypted, run L3 path. Update `VerifyResult.level` to `"L3"` and remove the chain skip note.

**Files:**
- `verifier-rust/crates/capsule-verify/src/verifier.rs`

**Changes to `VerifyOptions`:**

```rust
pub struct VerifyOptions {
    pub allowlist: Vec<String>,
    pub recipient_private_key: Option<[u8; 32]>,    // NEW — if Some, attempt L3 on encrypted capsules
}
```

**Changes to verification flow:**

After v0.2's L2 encrypted-blob hash check, if `is_encrypted == true && options.recipient_private_key.is_some()`:

```
1. Call decrypt_inner_zip(outer_envelope, outer_manifest, outer_files, recipient_priv).
   - On error, push top-level error (category Encryption, message includes the DecryptError).
   - Return early after assemble_result so we don't try to walk a chain that doesn't exist.

2. Open the inner ZIP via unpack_zip.
3. Parse inner manifest + envelope + chain (using the existing schemas + chain walk helpers).
4. Run chain walk on the inner chain (not deferred this time):
   - Replace chain.ok = true / note=Some with the result of the actual walk.
   - chain.event_count = inner events.len().
5. Cross-check inner against outer:
   - inner.manifest.id == outer.envelope.capsule_id → if mismatch, ChainAnchor error.
   - inner.envelope.first_event_hash == outer.envelope.first_event_hash → ChainAnchor.
   - inner.envelope.entry_hash == outer.envelope.entry_hash → ChainAnchor.
6. Set result.level = "L3".
7. (Optional, see plan note above) Verify inner envelope signatures, surface as a separate `inner_envelope` field if scope allows.
```

**`VerifyResult` additions:**

If you implement the optional inner-envelope signature verification, add:
```rust
pub inner_envelope: Option<EnvelopeCheck>,
```

Otherwise skip; v0.3 ships without inner-envelope sig verification.

**Tests (verifier.rs):**

1. `encrypted_clean_capsule_passes_l3_with_recipient_key` — load clean-encrypted + keys.json, run with `recipient_private_key: Some(recipient_secret)`, assert:
   - `result.ok == true`
   - `result.level == "L3"`
   - `result.chain.ok == true && result.chain.note.is_none()` (chain actually walked, not deferred)
   - `result.chain.event_count >= 1`
   - `result.errors.is_empty()`

2. `encrypted_clean_capsule_falls_back_to_l2_without_key` — same fixture, no recipient key, assert v0.2 behavior:
   - `result.ok == true`
   - `result.level == "L2"`
   - `result.chain.note.is_some()`

3. `tampered_blob_l3_decryption_fails` — tampered-blob + recipient key, assert:
   - `result.ok == false`
   - At least one error mentions decryption / auth (the DecryptError surfaced as a string)
   - `result.level` is `"L2"` or whatever level was reached before the decryption failure

4. `wrong_recipient_key_l3_fails_no_match` — clean-encrypted + a fresh random X25519 secret, assert NoMatchingRecipient surfaces.

### Task 3 — CLI `--decryption-key` flag + integration tests + README

**Goal:** Wire L3 into the CLI; add an integration test in `tests/parity_against_js_sdk.rs`; refresh the README with v0.3 status + transcript.

**Files:**
- `verifier-rust/crates/capsule-verify-cli/src/main.rs`
- `verifier-rust/tests/parity_against_js_sdk.rs`
- `verifier-rust/README.md`

**CLI flag:**

```
capsule-verify verify <FILE> --decryption-key <KEY>
```

`<KEY>` accepts either:
- A 64-character lowercase hex string (the recipient's X25519 private key), OR
- A path to a file containing 32 raw bytes OR a 64-char hex string OR base64.

For the v0.3 PoC, accept a hex string only (matches keys.json directly). If the value looks like a filesystem path that exists, read it and try to parse the contents as hex first, then base64. Keep parsing tolerant; reject only if neither shape matches.

If the flag is provided but the value can't be parsed as a 32-byte key, exit 2 with a clear error.

If the flag is provided but the capsule is plain (no `content.enc`), the flag is silently ignored — just verify normally.

**Plain-output rendering update:**

When `result.level == "L3"`, the chain check line shows `[✓] chain` with no skip note (because the walk actually happened). When `result.level == "L2"` and the capsule is encrypted, current "deferred to L3" rendering is unchanged.

A new line in the header card: `Level:                  L3` instead of `L2` when L3 was reached. (The level field is already in `VerifyResult`; just ensure the renderer surfaces it.)

**Integration test:**

```rust
#[test]
fn encrypted_clean_capsule_passes_l3() {
    let bytes = read_fixture("clean-encrypted.capsule");
    let keys: serde_json::Value = serde_json::from_slice(&read_fixture("keys.json")).unwrap();
    let recipient_secret_hex = keys.pointer("/recipient/privateKey").and_then(|v| v.as_str()).expect("recipient.privateKey");
    let recipient_secret: [u8; 32] = hex_to_bytes(recipient_secret_hex).unwrap().try_into().unwrap();

    let result = verify_capsule(&bytes, &VerifyOptions {
        allowlist: vec![],
        recipient_private_key: Some(recipient_secret),
    });
    assert!(result.ok, "expected L3 PASS, got: {:?}", result.errors);
    assert_eq!(result.level, "L3");
    assert!(result.chain.ok);
    assert!(result.chain.note.is_none(), "chain note should clear at L3");
    assert!(result.chain.event_count >= 1);
}
```

**README updates:**

- Add v0.3 to "What's new" section.
- Update the outcome table to include the L3 column.
- Add a transcript section showing CLI output for `cargo run -p capsule-verify-cli -- verify clean-encrypted.capsule --decryption-key <hex>` (with full L3 chain walk).
- Update "What it does NOT do (yet)" — drop L3 as parking lot; keep capsule-building, FFI/WASM.
- Bump test count if mentioned.

**Verification:**

```sh
. "$HOME/.cargo/env"
cd /Users/complex/repo/virion/capsule/new-design/verifier-rust
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

# CLI smoke
KEY=$(jq -r '.recipient.privateKey' ../examples/tamper-detection/output/keys.json)
cargo run -p capsule-verify-cli -- verify ../examples/tamper-detection/output/clean-encrypted.capsule --decryption-key "$KEY"   # PASS @ L3
cargo run -p capsule-verify-cli -- verify ../examples/tamper-detection/output/clean-encrypted.capsule                          # PASS @ L2 (unchanged)
cargo run -p capsule-verify-cli -- verify ../examples/tamper-detection/output/tampered-blob.capsule --decryption-key "$KEY"    # FAIL @ decryption
```

## Out of scope for v0.3

- **Inner envelope signature verification.** v0.3 verifies the OUTER envelope and the inner chain. Inner signatures are a v0.4 deliverable if there's appetite.
- **Multi-recipient streaming decryption.** v0.3 picks the first matching bundle. If the capsule has multiple recipients and our key matches more than one (unusual), the first match wins.
- **Capsule building / signing.** Still verifier-only.
- **WASM / FFI target.** Still future.
- **Encrypted key bundle key rotation.** No revocation handling.
- **Performance.** Microseconds-per-capsule even with crypto.

## Risks

| # | Risk | Mitigation |
|---|---|---|
| 1 | AAD shape mismatches the JS impl (e.g. extra/missing field) | Task 1 includes `build_aad_matches_jcs_oracle` test that pins the exact bytes captured from the JS reference. |
| 2 | `x25519-dalek` v2 API surface changed; clamping/serialization mismatch | Use `StaticSecret::from(bytes)` and `PublicKey::from(secret)`. Confirm via `x25519_known_vector` test using RFC 7748 vectors. |
| 3 | `chacha20poly1305` crate API differs between versions | Pin `chacha20poly1305 = "0.10"`; the API has been stable since 0.9. |
| 4 | HKDF salt / info bytes mismatched | Use `salt = recipient_pubkey_raw` (32 bytes), `info = b"capsule-key-wrap-v0.6"` (utf8 bytes). Test against a known derivation if possible. |
| 5 | Inner ZIP content_index excluded set differs from outer | Same set: `{manifest.json, provenance/envelope.json, content.enc}`. The inner ZIP shouldn't have `content.enc`, but the predicate is still safe. |
| 6 | `--decryption-key` flag accepts a 64-byte Ed25519 private accidentally | Validate length is 32 bytes after hex-decode. The error path should suggest "this looks like an Ed25519 key, not X25519". |

## Test oracle (post-v0.3)

```
Without --decryption-key (L2 behavior):
  ✓  clean.capsule                  PASS @ L2
  ✓  tampered-payload.capsule       FAIL @ content_index
  ✓  tampered-chain.capsule         FAIL @ content_index + chain
  ✓  tampered-envelope.capsule      FAIL @ envelope_signature
  ✓  clean-encrypted.capsule        PASS @ L2 (chain deferred)
  ✓  tampered-blob.capsule          FAIL @ encryption_state

With --decryption-key (L3 where applicable):
  ✓  clean.capsule                  PASS @ L2 (key ignored — plain)
  ✓  tampered-payload.capsule       FAIL @ content_index
  ✓  tampered-chain.capsule         FAIL @ content_index + chain
  ✓  tampered-envelope.capsule      FAIL @ envelope_signature
  ✓  clean-encrypted.capsule        PASS @ L3 (chain fully verified, anchors cross-checked)
  ✓  tampered-blob.capsule          FAIL @ decryption (auth tag mismatch)
```

When this passes, the Rust verifier covers every verification tier the spec defines, and the launch claim becomes "Capsule has two implementations at every verification tier."

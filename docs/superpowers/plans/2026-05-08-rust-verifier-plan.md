# Rust Verifier — Implementation Plan

**Status:** approved, ready to execute
**Target:** Second independent implementation of Capsule v0.6 verification, byte-compatible with the JS reference SDK against signed test vectors. Strengthens the launch moat for the 2026-05-18 Kaggle submission.
**Capsule format:** v0.6 (no schema changes)
**Output:** `new-design/verifier-rust/` — a Cargo workspace with a verifier library + CLI.

## Goal

Stand up a self-contained Rust verifier that opens a `.capsule` produced by the JS reference SDK and reports per-check pass/fail, byte-compatible with `sdk/src/verifier.js::verifyCapsule()`. Specifically:

- Verify deterministic ZIP container parses safely.
- Verify `manifest.id` derives from `SHA-256("capsule-id-v0.6\x00" || originator_pubkey || first_event_hash)`.
- Verify `envelope.manifest_hash` matches recomputed JCS-canonical manifest hash.
- Verify `envelope.content_index_hash` matches recomputed JCS-canonical hash of `manifest.content_index.files`.
- Verify per-file SHA-256 in `content_index.files` matches stored bytes.
- Verify chain integrity: `event.hash == SHA-256(prev_raw || JCS(event_minus_hash))`, `prev_hash` linkage, monotonic `seq`, genesis prev = 32 zero bytes.
- Verify each `signers[]` entry: `Ed25519.verify(pubkey, "capsule-provenance-v0.6:" + role + "\x00" || JCS(envelope_minus_signers), signature)`.
- Optional allowlist: signer trusted iff pubkey appears in caller-supplied set.

The verifier is **plain-capsule only** (encrypted capsules are out of scope for v0.1; the encrypted branch is parking-lot for the Rust impl until the JS SDK's encryption API stabilizes for cross-impl test vectors).

## Why now (moat motivation)

A second implementation of the verifier — written by a different person in a different language against the spec and signed test vectors — is the strongest single signal we can include in the Kaggle writeup that Capsule is a *format*, not a JS library. Moves the project from "interesting tool" to "format with two implementations." Cited as the priority moat-strengthener in the 2026-05-08 launch analysis.

## Approach

- Workspace with one library crate (`capsule-verify`) and one binary crate (`capsule-verify-cli`).
- Vetted upstream crates for crypto + JSON. No hand-rolled crypto.
- Test oracle: the JS SDK's `examples/tamper-detection/` example produces five capsules (one clean, four tampered, each in a distinct way). The Rust verifier must:
  - PASS on `clean.capsule`
  - FAIL on each tampered variant at the spec-named check
- Integration tests shell out to `npm` to produce the fixtures, then run the Rust verifier and assert outcomes.

## Crate selection

| Crate | Purpose | Notes |
|---|---|---|
| `serde`, `serde_json` | JSON parsing | universal Rust choice |
| `serde_jcs` (or hand-rolled) | RFC 8785 canonicalization | prefer `serde_jcs` if it round-trips against JS reference; fall back to inline impl if not |
| `sha2` | SHA-256 | RustCrypto, audited |
| `ed25519-dalek` | Ed25519 verify | RustCrypto, audited |
| `zip` | ZIP container reader | standard Rust ZIP crate |
| `hex` | hex codecs | tiny |
| `clap` | CLI arg parsing | for the binary |
| `anyhow`, `thiserror` | error handling | standard split |

No `tokio`/`async`. Verification is pure CPU + IO; sync is fine.

## File layout

```
new-design/verifier-rust/
├── Cargo.toml                    workspace manifest
├── README.md                     build, run, what's verified
├── crates/
│   ├── capsule-verify/           library crate
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs            re-exports
│   │       ├── jcs.rs            RFC 8785 canonicalization (or thin wrapper)
│   │       ├── crypto.rs         sha256 + ed25519 verify wrappers
│   │       ├── zip_reader.rs     deterministic STORED reader + safety checks
│   │       ├── schemas.rs        Manifest, Envelope, ChainEvent serde structs
│   │       ├── chain.rs          chain hash walk + verification
│   │       ├── envelope.rs       canonical payload + signature verify
│   │       └── verifier.rs       top-level verify_capsule() + VerifyResult
│   └── capsule-verify-cli/       binary crate
│       ├── Cargo.toml
│       └── src/main.rs           clap CLI: capsule-verify <file>
└── tests/
    └── parity_against_js_sdk.rs  integration test vs tamper-detection fixtures
```

## Tasks

Each task is independently dispatchable. Each implementer subagent should follow TDD where practical.

### Task 1 — Scaffold workspace + crypto/hex helpers

**Goal:** Cargo workspace builds cleanly with a hello-world test in each crate. Basic crypto and hex helpers exist with passing unit tests.

**Files:**
- `verifier-rust/Cargo.toml` (workspace)
- `verifier-rust/crates/capsule-verify/Cargo.toml`
- `verifier-rust/crates/capsule-verify/src/lib.rs`
- `verifier-rust/crates/capsule-verify/src/crypto.rs`
- `verifier-rust/crates/capsule-verify-cli/Cargo.toml`
- `verifier-rust/crates/capsule-verify-cli/src/main.rs`

**Spec refs:** none for scaffolding. Crypto helpers must mirror `sdk/src/canonical.js` (sha256, hex) and `sdk/src/crypto.js` (ed25519Verify with raw 32-byte public key + 64-byte signature inputs).

**Deps:** `sha2`, `ed25519-dalek`, `hex`, `anyhow`, `thiserror`. CLI gets `clap`.

**Tests:**
- `crypto::sha256(b"abc")` matches the well-known SHA-256 vector `ba7816...f20015ad`.
- `crypto::ed25519_verify` round-trips a known signature pair (use any RFC 8032 test vector).
- `hex_to_bytes` / `bytes_to_hex` round-trip.

**Constraint:** the binary must run `cargo run -- --help` and print usage even before later tasks land.

### Task 2 — JCS RFC 8785 canonicalization

**Goal:** Produce byte-identical canonical JSON to the JS reference SDK's `canonical.js` (which uses the npm `canonicalize` package).

**Files:**
- `verifier-rust/crates/capsule-verify/src/jcs.rs`

**Spec refs:** `spec/manifest.md` ("JCS-RFC8785"), `spec/chain.md` ("JCS(event without 'hash')"), `spec/envelope.md` ("JCS-canonical bytes of envelope minus signers"). The authoritative spec is RFC 8785.

**Deps:** Try `serde_jcs` first; if it round-trips against the oracles below, use it. If not, write inline.

**Tests:** Each must canonicalize to the *byte-for-byte* output the JS impl produces. Capture oracle bytes by running this Node one-liner and pasting them into a test fixture:

```js
import canonicalize from "canonicalize";
process.stdout.write(canonicalize(<value>));
```

Required oracles:
1. `null` → `"null"`
2. `{"b":1,"a":2}` → `'{"a":2,"b":1}'` (sorted keys)
3. Number serialization: `7`, `7.5`, `-0`, `1e21`, `0` — match ECMAScript Number.toString.
4. String escaping: a string containing `"`, `\`, `\n`, control `\x01`, `/` (slash NOT escaped), and non-ASCII `é` (passed through).
5. Nested `{"format":{"version":"0.6","container":"zip","canonicalization":"JCS-RFC8785","hash_algorithm":"SHA-256"}}` (mirrors a manifest fragment).

**Constraint:** API is `pub fn jcs(value: &serde_json::Value) -> Vec<u8>`.

### Task 3 — Deterministic STORED ZIP reader with safety checks

**Goal:** Open a `.capsule` byte slice, return `BTreeMap<String, Vec<u8>>` (path → bytes), enforcing the spec's safety rules.

**Files:**
- `verifier-rust/crates/capsule-verify/src/zip_reader.rs`

**Spec refs:** `spec/format.md` "Container properties" (sorted paths, fixed timestamps, STORED, ZIP-slip rejection, file-count and size limits 10,000 / 1 GiB).

**Deps:** `zip` crate.

**Rejections (each returns a typed error):**
- entry uses anything other than STORED compression
- path is empty, contains `\0`, is absolute (`/foo` or `C:\foo`), or has a `..` segment
- path is a symlink or directory entry
- entry count > 10,000
- total uncompressed size > 1 GiB

**Tests:**
- Open `examples/tamper-detection/output/clean.capsule` (after running its build): assert it parses, has the expected file set (`manifest.json`, `program.md`, `agents.md`, `chain/events.jsonl`, `provenance/envelope.json`).
- Synthetic ZIP with `..` in a path → rejected.
- Synthetic ZIP with absolute path → rejected.
- Synthetic ZIP with DEFLATE compression → rejected.

**Constraint:** API is `pub fn unpack_zip(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, ZipError>`. Use `BTreeMap` so paths are sorted on iteration (matches JS reference behavior).

### Task 4 — Schemas (Manifest, Envelope, ChainEvent)

**Goal:** serde-deserializable structs that round-trip the JSON written by the JS SDK.

**Files:**
- `verifier-rust/crates/capsule-verify/src/schemas.rs`

**Spec refs:** `spec/manifest.md`, `spec/envelope.md`, `spec/chain.md`.

**Deps:** `serde`, `serde_json`.

**Required structs:**
- `FormatBlock { version, container, canonicalization, hash_algorithm }`
- `Originator { public_key: String /*hex*/, label: String }`
- `Participant { actor_id, role, label }`
- `ContentIndexEntry { path: String, sha256: String /*hex*/ }`
- `ContentIndex { files: Vec<ContentIndexEntry>, index_hash: String }`
- `Encryption { metadata_path: String, cipher: String }` (Optional, may be `null`)
- `Manifest { format, id, originator, participants, first_event_hash, content_index, skill_trust: HashMap<String,String>, encryption: Option<Encryption>, created_at }`
- `Signer { role, public_key: String, signature: String }`
- `Envelope { version, capsule_id, first_event_hash, entry_hash, manifest_hash, content_index_hash, encrypted_blob_hash: Option<String>, cipher, signed_at, signers: Vec<Signer> }`
- `ChainEvent { seq: u64, event_id, actor, kind, action, target, timestamp, payload: serde_json::Value, untrusted_payload_fields: Vec<String>, prev_hash: String, hash: String }`

**Tests:**
- Round-trip parse + re-serialize a captured `manifest.json` and `envelope.json` from a JS-produced clean capsule.
- Parse `chain/events.jsonl` line-by-line.

### Task 5 — Verifier core

**Goal:** Top-level `verify_capsule(bytes: &[u8], options: VerifyOptions) -> VerifyResult` that performs every check the JS SDK's `verifier.js` performs, in the same order, with the same names.

**Files:**
- `verifier-rust/crates/capsule-verify/src/chain.rs` — chain walk
- `verifier-rust/crates/capsule-verify/src/envelope.rs` — canonical payload + signing input + per-signer verify
- `verifier-rust/crates/capsule-verify/src/verifier.rs` — orchestrator, returns structured result
- `verifier-rust/crates/capsule-verify/src/lib.rs` — re-exports

**Spec refs:** `spec/chain.md`, `spec/envelope.md`, `spec/manifest.md` (capsule_id derivation), `sdk/src/verifier.js` for ordering and check names.

**Deps:** all earlier tasks.

**Required behavior (mirror JS verifier exactly):**
1. Reject if `manifest.format.version != "0.6"` or `envelope.version != "0.6"`.
2. Recompute `capsule_id = SHA-256("capsule-id-v0.6\x00" || originator_pubkey_raw_bytes || first_event_hash_raw_bytes)`. Match against `manifest.id` AND `envelope.capsule_id`.
3. Recompute `manifest_hash = SHA-256(JCS(manifest))`. Match against `envelope.manifest_hash`.
4. Recompute content_index from stored files (excluding `manifest.json`, `provenance/envelope.json`, `content.enc`). Each file's SHA-256 must match its `content_index.files` entry. `content_index.index_hash` must equal `SHA-256(JCS(content_index.files))` AND `envelope.content_index_hash`. Per-file mismatch reported individually.
5. For plain capsules (no `content.enc`): `envelope.encrypted_blob_hash` must be null AND `envelope.cipher` must be `"none"`. (Encrypted branch out of scope.)
6. Walk `chain/events.jsonl`: for each event, recompute `hash = SHA-256(prev_raw || JCS(event_without_hash))`. Confirm `prev_hash` matches the previous event's `hash`. Confirm `seq` is monotonic from 1. Confirm event 1's `prev_hash` is 32 zero bytes (hex `000…0`). Confirm `actor` is in manifest.participants OR equals `system:host`.
7. Confirm `events[0].hash == envelope.first_event_hash` and `events[last].hash == envelope.entry_hash`.
8. For each signer, reconstruct `signing_input = utf8("capsule-provenance-v0.6:" + role + "\x00") || JCS(envelope_minus_signers)`. Verify `Ed25519.verify(signer.public_key_raw, signing_input, signer.signature_raw)`.
9. If `options.allowlist` non-empty, mark each signer `trusted` iff its public key appears.

**`VerifyResult` shape:**
```rust
pub struct VerifyResult {
    pub ok: bool,
    pub level: &'static str,                         // "L2" only in v0.1
    pub errors: Vec<String>,
    pub chain: ChainCheck,
    pub content_index: ContentIndexCheck,
    pub envelope: EnvelopeCheck,
    pub trusted_signer_count: usize,
    pub notes: Vec<String>,
}
```
(Mirror the JS shape so cross-impl diffing is easy.)

**Tests:**
- Unit test each check function independently against synthetic inputs.
- Reject capsule with wrong `format.version`.
- Reject capsule with mutated `manifest.id`.
- Reject capsule whose chain has a flipped byte in event N's payload.
- Reject capsule whose envelope.signers[0].signature is corrupted.

### Task 6 — CLI binary + integration test against JS SDK fixtures

**Goal:** `cargo run -p capsule-verify-cli -- verify <file.capsule>` prints a human-readable report and exits 0 on PASS / 1 on FAIL. An integration test runs against the JS SDK's tamper-detection fixtures.

**Files:**
- `verifier-rust/crates/capsule-verify-cli/src/main.rs`
- `verifier-rust/tests/parity_against_js_sdk.rs`
- `verifier-rust/tests/fixtures/.gitignore` (keep dir, ignore generated capsules)

**Spec refs:** `examples/tamper-detection/README.md` for what each variant tampers and where verification should fail.

**Deps:** all earlier tasks.

**CLI:**
```
capsule-verify verify <FILE>          # default action; checks plain capsule
capsule-verify verify <FILE> --allowlist <HEX_PUBKEY>...  # trust check
```
Output is one line per check with `[✓]` or `[✗]` prefix, plus a final `PASS` / `FAIL` line. JSON output via `--json`.

**Integration test (`parity_against_js_sdk.rs`):**

The test must, in `#[test]`:
1. Resolve the JS SDK + tamper-detection example paths via env or relative `CARGO_MANIFEST_DIR`.
2. Shell out to run `npm install && npm run build` in `examples/tamper-detection/` (or assume already run if `output/clean.capsule` exists). Skip with `#[ignore]` if Node is not available.
3. Open each of `clean.capsule`, `tampered-payload.capsule`, `tampered-chain.capsule`, `tampered-envelope.capsule`, `tampered-blob.capsule`.
4. Assert outcomes:
   - `clean.capsule`: `result.ok == true`
   - `tampered-payload.capsule`: `result.ok == false`, error contains `content_index`
   - `tampered-chain.capsule`: `result.ok == false`, error in `chain` or `content_index`
   - `tampered-envelope.capsule`: `result.ok == false`, an envelope signer marked invalid
   - `tampered-blob.capsule`: this is the encrypted variant — Rust verifier (plain only) should reject with a clear error indicating the capsule is encrypted, not silently pass. Test asserts the rejection message.

### Task 7 — README + ergonomics

**Goal:** `verifier-rust/README.md` explains build, test, run, what's verified, what's *not* (plain only, no encryption, no decrypt). Include a copy-pasteable transcript showing all five tamper-detection outcomes.

**Files:**
- `verifier-rust/README.md`

**No tests required.**

## Test oracle

The JS SDK's tamper-detection example is the cross-impl test oracle. After Task 6, running the parity integration test should produce, in transcript:

```
✓  clean.capsule                  PASS
✓  tampered-payload.capsule       FAIL @ content_index
✓  tampered-chain.capsule         FAIL @ chain or content_index
✓  tampered-envelope.capsule      FAIL @ envelope signature
✓  tampered-blob.capsule          REJECTED (encrypted; out of scope)
```

When this passes, the Rust verifier is byte-compatible with the JS reference SDK on the spec's existing test corpus, and the Kaggle writeup can claim "Capsule has two independent implementations."

## Out of scope

- **Encrypted capsules / decryption.** L3 verification and ChaCha20-Poly1305 are deferred. The Rust verifier surfaces "encrypted, out of scope" cleanly.
- **Capsule building / signing.** This is a *verifier*. Issuing capsules from Rust is a separate future deliverable.
- **C FFI / WASM target.** Pure-Rust library + binary only.
- **Performance work.** Correctness first; profiling later if needed.

## Risks

| # | Risk | Mitigation |
|---|---|---|
| 1 | `serde_jcs` doesn't byte-match JS `canonicalize` for some edge case | Task 2 includes byte-for-byte oracle tests; if `serde_jcs` fails any, fall back to a small inline impl modeled on the JS one. |
| 2 | `ed25519-dalek` strict verification rejects a signature the JS impl accepts (or vice versa) | Use `ed25519_dalek::Verifier` with default verification; JS uses Node's WebCrypto / OpenSSL which is also strict. Add a regression test capturing a JS-produced signature byte-for-byte. |
| 3 | `zip` crate accepts edge-case malformed ZIPs the JS reader rejects | Acceptable so long as the safety predicates we apply (path/compression/size checks) catch them. Document the divergence if it appears. |
| 4 | Integration test relies on Node being installed | Mark `#[ignore]` if `node` not found; provide explicit `cargo test --ignored` instructions in README. |

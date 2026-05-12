# Rust Verifier v0.2 — L2 Encrypted-Outer Verification

**Status:** approved, ready to execute
**Builds on:** [`2026-05-08-rust-verifier-plan.md`](./2026-05-08-rust-verifier-plan.md) (v0.1, shipped)
**Capsule format:** v0.6 (no schema changes)
**Output:** Modifications to `new-design/verifier-rust/`. No new top-level deliverable; existing crates evolve.

## Goal

Stop short-circuiting on encrypted capsules. The Rust verifier should perform the full L2 envelope-only verification on encrypted-outer capsules, identical in coverage to what the JS SDK's `verifyCapsule` does at L2. After v0.2:

| Fixture | Outcome |
|---|---|
| `clean.capsule` | PASS (unchanged) |
| `tampered-payload.capsule` | FAIL @ content_index (unchanged) |
| `tampered-chain.capsule` | FAIL @ content_index + chain (unchanged) |
| `tampered-envelope.capsule` | FAIL @ envelope_signature (unchanged) |
| `clean-encrypted.capsule` | **PASS @ L2** (was: FAIL "out of scope") |
| `tampered-blob.capsule` | **FAIL @ encryption_state (encrypted_blob_hash mismatch)** (was: FAIL "out of scope") |

Plus two ride-along follow-ups from the v0.1 final review:
- Cipher whitelist (envelope.cipher must be in `{none, ChaCha20-Poly1305}`; `AES-256-GCM` etc. rejected explicitly).
- A synthetic regression test exercising `TopErrorCategory::ChainAnchor` (currently defensive, not exercised by the existing fixture suite).

## Why now

The v0.1 final review identified L2-encrypted as the single highest-leverage v0.2 deliverable. Today the Rust impl only verifies plain capsules; the JS reference handles both at L2. Closing this gap means the Rust verifier covers the same verification tier the reference implementation covers — strengthening the launch claim "Capsule has two implementations" from "two plain-capsule implementations" to "two implementations at the L2 tier the spec defines."

## Approach

The encrypted-outer L2 verification only needs:
1. Manifest hash (existing — works on any manifest).
2. Content index (existing — already excludes `content.enc` from the index per spec).
3. Envelope signature (existing — works on any envelope).
4. **NEW:** SHA-256 of `content.enc` matches `envelope.encrypted_blob_hash`.
5. Chain check is *skipped* (the chain is encrypted; verified at L3 with the recipient's key).

Spec citation: `spec/envelope.md` "L2 / L3" section.

The skip needs to be a first-class state, not an error. Today the encrypted path sets `chain.ok = false` with message "chain check skipped (encrypted outer)" — this renders as `[✗] chain` which is misleading. The JS reference returns `chain = { ok: true, errors: [], note: "deferred to L3 (encrypted outer)" }`. Mirror that: add `note: Option<String>` to `ChainCheck` and set `ok = true` for the deferred case.

## Tasks

### Task 1 — Cipher whitelist + encrypted-blob hash check + chain-skip semantics

**Goal:** The bulk of v0.2 in one focused task. Drop the wholesale encrypted rejection; replace with the actual L2 checks.

**Files:**
- `crates/capsule-verify/src/verifier.rs` (encryption_state section + chain section)
- `crates/capsule-verify/src/verifier.rs` (`ChainCheck` struct: add `pub note: Option<String>`)
- `crates/capsule-verify-cli/src/main.rs` (renderer: surface `chain.note` when present)

**Spec refs:** `spec/envelope.md` ("L2 / L3", "Encryption", cipher enum); `sdk/src/verifier.js` (encrypted branch lines 127-145).

**Behavior changes:**

1. Add a constant near the verifier module top:
   ```rust
   const SUPPORTED_CIPHERS: &[&str] = &["none", "ChaCha20-Poly1305"];
   ```

2. Cipher whitelist check (executed regardless of encryption state):
   ```
   if !SUPPORTED_CIPHERS.contains(&envelope.cipher.as_str()) {
       errors.push(TopError {
           category: Encryption,
           message: format!("unsupported cipher: {}", envelope.cipher),
       });
   }
   ```
   Place this near the format/version checks so it short-circuits early.

3. Encrypted-blob hash check (when `content.enc` exists in the ZIP):
   - If `envelope.encrypted_blob_hash` is `None`: error "encrypted blob present but envelope.encrypted_blob_hash=null".
   - If `envelope.cipher == "none"`: error "encrypted blob present but envelope.cipher='none'".
   - Otherwise, recompute `recomputed_blob_hash = sha256_hex(content_enc_bytes)` and compare against `envelope.encrypted_blob_hash`. Mismatch → error `"envelope.encrypted_blob_hash mismatch: stored {} vs recomputed {}"`.

4. Plain capsule path (when `content.enc` is absent — existing, leave as-is):
   - `envelope.encrypted_blob_hash` must be `None`.
   - `envelope.cipher` must be `"none"`.

5. Chain-skip semantics — when capsule is encrypted:
   - Do NOT call `parse_chain_jsonl` (no `chain/events.jsonl` exists in encrypted outers).
   - Set `chain.ok = true`, `chain.errors = []`, `chain.event_count = 0`, `chain.note = Some("deferred to L3 (encrypted outer)".to_string())`.
   - Skip the first/entry hash anchor checks (those go to chain anchors, but require a chain — defer to L3).

6. Plain capsule chain check — unchanged. `chain.note` stays `None`.

7. Add `pub note: Option<String>` to `ChainCheck`. Default to `None`. Update the `Default` impl.

8. CLI renderer (`main.rs::print_plain`):
   - When rendering the chain check line, if `chain.note.is_some()`, render `[✓] chain` followed by an indented note line: `chain.ok=true (deferred to L3 — encrypted outer)`. Don't render as `[✗]`.
   - JSON output gets `chain.note` for free via the Serialize derive.

**Tests in `verifier.rs`:**

1. `clean_encrypted_passes_l2` — load `clean-encrypted.capsule`, verify, assert:
   - `result.ok == true`
   - `result.envelope.signers.iter().all(|s| s.valid)`
   - `result.chain.ok == true`
   - `result.chain.note.is_some()` and contains `"deferred"` or `"encrypted"`
   - `result.errors.is_empty()`

2. `tampered_blob_fails_at_encrypted_blob_hash` — load `tampered-blob.capsule`, verify, assert:
   - `result.ok == false`
   - At least one error has `category == TopErrorCategory::Encryption`
   - At least one error message contains `"encrypted_blob_hash mismatch"`

3. `unsupported_cipher_rejected` — synthesize a capsule whose `provenance/envelope.json` has `cipher: "AES-256-GCM"` (this is a reserved-but-not-implemented value per spec). Easiest path: take the existing `format_version_mismatch_rejected` synthesizer and adapt it for cipher. Assert:
   - `result.ok == false`
   - At least one error message contains `"unsupported cipher"` and `"AES-256-GCM"`
   - The error has `category == TopErrorCategory::Encryption`

4. `encrypted_blob_present_with_cipher_none_rejected` — synthesize an encrypted-shape capsule (has `content.enc`) but with `cipher: "none"` in the envelope. Assert error mentions both `"encrypted blob present"` and `"cipher='none'"`.

(These last two are easier to write incrementally — if synthesizing them is awkward, document the gap and add only `clean_encrypted_passes_l2` and `tampered_blob_fails_at_encrypted_blob_hash`. The synthesized tests are belt-and-suspenders.)

**Update existing tests:**

- `encrypted_capsule_rejected_with_clear_message` (verifier.rs unit + integration test) → either rename to `encrypted_capsule_with_corrupted_blob_rejected` (asserting it fails at encrypted_blob_hash specifically) OR keep the substring-based assertion ("encrypted" or "cipher" appears in errors) which will still hold for the new "envelope.encrypted_blob_hash mismatch" message.
- `tests/parity_against_js_sdk.rs::encrypted_clean_capsule_also_rejected` — flip to `encrypted_clean_capsule_passes_l2`. Update assertions accordingly.
- `tests/parity_against_js_sdk.rs::encrypted_capsule_rejected_with_clear_message` — update to assert it fails at `encrypted_blob_hash` specifically (the more diagnostic assertion).

**Verification:**

```sh
. "$HOME/.cargo/env"
cd /Users/complex/repo/virion/capsule/new-design/verifier-rust
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

# CLI smoke
cargo run -p capsule-verify-cli -- verify ../examples/tamper-detection/output/clean-encrypted.capsule  # should PASS now
cargo run -p capsule-verify-cli -- verify ../examples/tamper-detection/output/tampered-blob.capsule    # should FAIL at encrypted_blob_hash
```

### Task 2 — `ChainAnchor` regression test

**Goal:** Close the gap noted in the v0.1 final review where `TopErrorCategory::ChainAnchor` had no test.

**Files:**
- `crates/capsule-verify/src/verifier.rs` (test module)
- Possibly `crates/capsule-verify/src/test_support.rs` (helper if the synthesizer is reused)

**Approach:** Synthesize a capsule by:
1. Reading `clean.capsule` bytes via `clean_capsule_bytes()`.
2. Unzipping to a path map.
3. Mutating `provenance/envelope.json` so `first_event_hash` differs from the actual chain (e.g., flip the last 4 hex chars).
4. Re-packing with the existing `verifier-rust` ZIP-writer-test helpers OR using the `zip` crate's writer.
5. Running `verify_capsule` on the result.
6. Asserting:
   - `result.ok == false`
   - At least one error has `category == TopErrorCategory::ChainAnchor`
   - At least one error message contains `"first_event_hash"` and `"mismatch"`

If repacking the ZIP turns out to be awkward, an alternative: check the inverse — load the existing `tampered-chain.capsule` and confirm that whatever the chain hash mismatch produces, it doesn't bury a `ChainAnchor` category error. This documents that ChainAnchor is reachable in principle even if we don't have a fixture.

**Verification:** standard cargo test + clippy.

### Task 3 — README + transcript refresh

**Goal:** Document the v0.2 changes and refresh the transcript section.

**Files:**
- `verifier-rust/README.md`

**Edits:**
1. Remove "(plain-only)" qualifiers throughout. The verifier now does plain-and-encrypted-L2.
2. Refresh the cross-impl outcome table (clean-encrypted PASSes; tampered-blob fails at encrypted_blob_hash).
3. Update the embedded transcript with re-captured CLI output for all six fixtures. Both encrypted fixtures should show new check states.
4. Update the "What it does NOT do (yet)" list — encrypted-outer L2 is now in scope; remove that bullet. Decryption / L3 / WASM remain out of scope.
5. Add a "v0.2 changes" section near the top under "Status" briefly noting: cipher whitelist, encrypted-blob hash check, chain-skip semantics, ChainAnchor regression test.

**Verification:** README renders cleanly. `cargo test --workspace` and clippy still pass (no code changes in this task, but a sanity check).

## Out of scope for v0.2

- **L3 / decryption.** Still parking-lot. ChaCha20-Poly1305 is not in Rust's `RustCrypto` AEAD set as a single-crate offering — would need either `chacha20poly1305` crate (RustCrypto, audited) or a vendored impl. Plus X25519 ECDH + HKDF-SHA256 for key wrap. v0.3 deliverable.
- **Capsule building / signing.** This is still a verifier, not a producer.
- **WASM target / FFI.** Still future.
- **Performance work.** Still microseconds-per-capsule.

## Risks

| # | Risk | Mitigation |
|---|---|---|
| 1 | `clean-encrypted.capsule` has a structural issue we missed and the new test fails | The JS SDK's L2 of `clean-encrypted.capsule` passes today (per the symptom-tracker example's verify.mjs output). If our Rust impl can't match, the divergence localizes a bug — fix it. |
| 2 | Cipher whitelist rejects a fixture that was working | Only `none` and `ChaCha20-Poly1305` are in our supported set. The fixtures only use those. No regression. |
| 3 | Chain-skip semantics change breaks downstream consumers | `ChainCheck.note` is a new optional field; existing consumers that don't read it are unaffected. JSON output gains the field via Serialize. |
| 4 | Synthesizing a `ChainAnchor` test requires re-packing a ZIP | The `zip` crate's writer is already used in the existing test harness for `rejects_*` cases. Reuse the pattern. If repacking is too involved, flag as DONE_WITH_CONCERNS and ship without that test (still in the v0.2 follow-up list). |

## Test oracle (post-v0.2)

After Task 1 lands, all 6 fixtures should produce the outcomes in the goal table:

```
✓  clean.capsule                  PASS
✓  tampered-payload.capsule       FAIL @ content_index
✓  tampered-chain.capsule         FAIL @ content_index + chain
✓  tampered-envelope.capsule      FAIL @ envelope signature
✓  clean-encrypted.capsule        PASS @ L2
✓  tampered-blob.capsule          FAIL @ encryption_state (encrypted_blob_hash mismatch)
```

When this passes, the Rust verifier covers the same L2 verification surface the JS reference covers.

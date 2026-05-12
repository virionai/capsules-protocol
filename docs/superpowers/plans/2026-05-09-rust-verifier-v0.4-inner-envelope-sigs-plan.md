# Rust Verifier v0.4 — Inner Envelope Signature Verification

**Status:** approved, ready to execute
**Builds on:** v0.1 + v0.2 + v0.3 (L3 decryption + inner chain walk + 5 cross-checks)
**Capsule format:** v0.6 (no schema changes)
**Output:** Modifications to `new-design/verifier-rust/`. New `inner_envelope` field on `VerifyResult`; CLI rendering; README + parity test refresh.

## Goal

When the verifier reaches L3 (decrypted inner content), also verify the inner envelope's signers using the same Ed25519 + domain-separated-JCS signing-input code path used for the outer envelope. Surface the result via `VerifyResult.inner_envelope: Option<EnvelopeCheck>` and propagate failure into `result.ok`.

After v0.4:

| Fixture | No key (L2) | With recipient key (L3) — v0.4 |
|---|---|---|
| `clean.capsule` | PASS @ L2 (no inner) | PASS @ L2 (key ignored, no inner) |
| `tampered-payload.capsule` | FAIL @ content_index | (same) |
| `tampered-chain.capsule` | FAIL @ content_index + chain | (same) |
| `tampered-envelope.capsule` | FAIL @ envelope_signature | (same) |
| `clean-encrypted.capsule` | PASS @ L2 (chain deferred, inner_envelope=None) | **PASS @ L3 with inner_envelope.ok=true; inner originator signature verifies** |
| `tampered-blob.capsule` | FAIL @ encryption_state | FAIL @ decrypt (inner_envelope never reached, =None) |

The **JSON shape gains** `inner_envelope: { ok, signers: [...], note }` when L3 succeeds; absent (`null`) otherwise.

## Why now

The v0.3 final review identified inner envelope signature verification as the v0.4 deliverable. The JS reference's `verifyCapsule` doesn't currently do this — but the spec's L3 description ("Open the inner ZIP as a normal capsule") strongly implies it should. By doing it in the Rust verifier, we close a real spec gap AND give the launch a stronger claim: *full envelope signature coverage at every nesting level*.

## Scope decisions

1. **Inner envelope sig only — not full inner manifest_hash / content_index recompute.** The spec says L3 should also verify inner manifest_hash and content_index, but those become v0.5 if/when called for. v0.4 is tightly scoped to the signature path so the change is clean and the moat claim is precise.
2. **`trusted_signer_count` stays outer-only** to match the JS field semantics. Inner trust is visible via `inner_envelope.signers[].trusted`. Callers can sum if they want a total. Document in the field's rustdoc.
3. **Allowlist applies symmetrically.** A signer (inner or outer) is `trusted` iff its public key is in `options.allowlist` AND its signature verifies. The same allowlist is consulted for both.
4. **Inner envelope sig failure propagates to `result.ok = false`.** Same rule as outer envelope. The L3 promotion to `level = "L3"` still happens (the L3 path executed), but `ok` reflects the failure.

## File changes

### Modify

- `verifier-rust/crates/capsule-verify/src/verifier.rs` — add field, populate at L3, include in `result.ok` computation, tests.
- `verifier-rust/crates/capsule-verify-cli/src/main.rs` — render `inner_envelope` check line + inner signers block.
- `verifier-rust/tests/parity_against_js_sdk.rs` — extend `encrypted_clean_capsule_passes_l3` to assert `inner_envelope.ok`.
- `verifier-rust/README.md` — v0.4 section + transcript + scope updates.

No new modules; this is a focused extension.

## Tasks

### Task 1 — Verifier change

**Goal:** Inner envelope sig verification populates `VerifyResult.inner_envelope` at L3 success; failure propagates to `result.ok`. Plain capsules and L2-only paths get `None`.

**Files:**
- `verifier-rust/crates/capsule-verify/src/verifier.rs`

**Changes:**

1. Add field to `VerifyResult`:
   ```rust
   #[derive(Debug, Clone, Serialize, Deserialize, Default)]
   pub struct VerifyResult {
       // ... existing fields ...
       /// Set when L3 verification ran and the inner envelope's signers were
       /// checked. None for plain capsules, L2-only paths, or when L3 failed
       /// before reaching the inner envelope.
       pub inner_envelope: Option<EnvelopeCheck>,
   }
   ```

   `EnvelopeCheck` already exists. Reuse it directly. The existing `note` field on `EnvelopeCheck` (carrying things like "envelope has no signers") flows through naturally.

2. In `l3_attempt_decrypt_and_verify` (verifier.rs around line 695), AFTER successful inner manifest + envelope + chain parse but BEFORE the cross-checks:

   ```rust
   // Verify inner envelope signers using the same code path as the outer.
   let inner_check = verify_envelope_signatures(&inner_envelope, &options.allowlist);
   *inner_envelope_check = Some(inner_check);
   ```

   Pass `inner_envelope_check: &mut Option<EnvelopeCheck>` into the helper. Set it before any cross-check error early-return paths (so even if cross-checks fail, the inner-envelope verification still surfaces).

   `verify_envelope_signatures` is the existing internal function used for the outer envelope. If its current signature is `(envelope, allowlist) -> EnvelopeCheck`, reuse as-is.

3. Update `result.ok` computation in `assemble_result`:
   ```rust
   result.ok = errors.is_empty()
       && content_index.ok
       && chain.ok
       && envelope.ok
       && inner_envelope.as_ref().map_or(true, |e| e.ok);
   ```

   `None` (no inner envelope to check) doesn't fail the ok; `Some(check)` requires `check.ok`.

4. Thread `inner_envelope: Option<EnvelopeCheck>` through `assemble_result` so all early-return paths can pass `None` and the L3-success path can pass `Some(...)`.

**Tests in `verifier.rs`:**

1. **`encrypted_clean_capsule_l3_inner_envelope_verifies`** — clean-encrypted + recipient secret. Assert:
   - `result.ok == true`
   - `result.level == "L3"`
   - `result.inner_envelope.is_some()`
   - `result.inner_envelope.as_ref().unwrap().ok == true`
   - `result.inner_envelope.as_ref().unwrap().signers.len() >= 1`
   - All inner signers have `valid == true`

2. **`inner_envelope_check_absent_at_l2`** — clean-encrypted + `recipient_private_key: None`. Assert:
   - `result.ok == true`
   - `result.level == "L2"`
   - `result.inner_envelope.is_none()`

3. **`inner_envelope_check_absent_for_plain`** — clean.capsule + recipient key (silently ignored). Assert:
   - `result.ok == true`
   - `result.inner_envelope.is_none()`
   - `result.level == "L2"`

4. **`mutated_inner_signature_unit_test`** — reach into the L3 decrypted bytes, parse the inner envelope struct, mutate one byte of the first signer's `signature` hex (e.g., flip the last hex char), run `verify_envelope_signatures` on the mutated struct, assert:
   - The returned `EnvelopeCheck.ok == false`
   - The first signer's `valid == false`

   This is a unit test on `verify_envelope_signatures`, not the full `verify_capsule` pipeline. It proves that IF inner envelope tampering is somehow injected, our verification helper catches it. The full integration test (a tampered-inner-envelope fixture) would require building an encrypted capsule with mutation — out of scope for v0.4 (a Rust-side capsule builder is a separate deliverable).

5. **Update existing v0.3 tests** to reflect the new field. `encrypted_clean_capsule_passes_l3_with_recipient_key` should now also assert `inner_envelope.is_some() && inner_envelope.unwrap().ok`.

   Existing assertions on `result.ok` for tampered fixtures should continue to hold (no inner envelope to fail against — those failures happen before L3 reaches the inner envelope step).

**Verification:**

```sh
. "$HOME/.cargo/env"
cd /Users/complex/repo/virion/capsule/new-design/verifier-rust
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All 92 existing tests must continue to pass; ~3-4 new tests pass. Test count: ~96.

### Task 2 — CLI rendering + parity test + README v0.4

**Goal:** CLI plain-output surfaces inner envelope check; parity test asserts inner_envelope at L3; README updated.

**Files:**
- `verifier-rust/crates/capsule-verify-cli/src/main.rs`
- `verifier-rust/tests/parity_against_js_sdk.rs`
- `verifier-rust/README.md`

**CLI plain output:**

When `result.inner_envelope.is_some()`, add a check line after the existing `envelope_signature` line and before `encryption_state`:

```
  [✓] inner_envelope_signature
```

(or `[✗]` with the failed-signers messages indented if `inner_envelope.ok == false`).

After the existing `Signers:` block, add an `Inner signers:` block when `inner_envelope.is_some()`:

```
Inner signers:
  - originator   c172289fcacf…  valid=true  trusted=false
```

(Same shape as outer `Signers:` block. If `--allowlist` is provided AND a key matches, `trusted=true`.)

JSON output: nothing to do — the new field flows through Serialize.

**Parity integration test:**

Extend the existing `encrypted_clean_capsule_passes_l3` test in `tests/parity_against_js_sdk.rs`:

```rust
// existing assertions stay
assert!(result.inner_envelope.is_some(), "L3 should populate inner_envelope");
let inner = result.inner_envelope.as_ref().unwrap();
assert!(inner.ok, "inner envelope signature should verify; got: {:?}", inner.signers);
assert!(inner.signers.iter().all(|s| s.valid), "all inner signers should be valid");
assert!(!inner.signers.is_empty(), "clean-encrypted has at least one inner signer");
```

**README updates:**

1. Add "What's new in v0.4" section near the top:
   - Inner envelope signature verification: at L3, the inner envelope's Ed25519 signers are now verified using the same domain-separated-JCS code path as the outer envelope.
   - New `inner_envelope: Option<EnvelopeCheck>` field on `VerifyResult` (visible in JSON; rendered in plain CLI output as a separate check line + `Inner signers:` block).
   - Allowlist applies symmetrically: an inner signer is `trusted` iff its key is in the allowlist AND its signature verifies.
   - Inner envelope sig failure propagates to `result.ok = false`, same as outer envelope sig failure.

2. Update the outcome table to add the inner envelope cell:
   - `clean-encrypted.capsule` with key: PASS @ L3 with inner_envelope.ok = true (1 signer verifies).

3. Re-capture the L3 transcript for `clean-encrypted.capsule --decryption-key $KEY`; the new transcript should show the `[✓] inner_envelope_signature` check line and the `Inner signers:` block.

4. Update the "What it does NOT do (yet)" section:
   - REMOVE: "Inner envelope signature verification" (it's done now).
   - ADD: a v0.5 placeholder for full inner manifest_hash + content_index recompute (the remaining L3 spec coverage gap).

5. Bump test count if mentioned.

**Verification:**

```sh
. "$HOME/.cargo/env"
cd /Users/complex/repo/virion/capsule/new-design/verifier-rust
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

KEY=$(jq -r '.recipient.privateKey' ../examples/tamper-detection/output/keys.json)
cargo run -p capsule-verify-cli -- verify ../examples/tamper-detection/output/clean-encrypted.capsule --decryption-key "$KEY"   # PASS @ L3 with [✓] inner_envelope_signature
cargo run -p capsule-verify-cli -- verify ../examples/tamper-detection/output/clean.capsule                                       # PASS @ L2 (no inner block)
```

## Out of scope for v0.4

- **Full inner plain-capsule verification.** v0.4 verifies inner envelope SIGNATURES only. Inner manifest_hash recompute and inner content_index recompute are deferred to v0.5 if anyone asks.
- **Tampered-inner-envelope fixture.** Would require a Rust-side capsule builder to produce one. The unit test on `verify_envelope_signatures` covers the mutation-detection logic.
- **Multiple inner envelopes / nested encrypted capsules.** v0.6 prototype only supports one level of encryption.
- **Capsule building / signing.** Still verifier-only.
- **WASM / FFI.** Still future.

## Risks

| # | Risk | Mitigation |
|---|---|---|
| 1 | Inner envelope's signing input differs from outer (e.g., different domain separator) | Spec says they're the same. The existing `verify_envelope_signatures` is reused verbatim — same domain separator, same JCS-canonical-minus-signers payload. Test against clean-encrypted's actual inner envelope. |
| 2 | `verify_envelope_signatures` signature doesn't match what we need | If it returns `(EnvelopeCheck, allowlist_check_done_inside)` we may need to adjust. Read the function before changing the call site. |
| 3 | The inner envelope might have zero signers (empty `signers[]`) — what then? | The existing `verify_envelope_signatures` should handle this: returns `EnvelopeCheck { ok: false, signers: [], note: Some("envelope has no signers") }`. Our `inner_envelope.ok` will be `false` and `result.ok` will be `false`. This matches outer behavior. |
| 4 | Adding the field breaks JSON consumers parsing v0.3 output | `Option<EnvelopeCheck>` serializes as `null` when None, which is forward-compatible. |
| 5 | The CLI rendering might over-clutter the output for plain capsules | The new lines render only when `inner_envelope.is_some()`, which only happens at L3. Plain output for plain capsules and L2-only paths is unchanged. |

## Test oracle (post-v0.4)

```
Without --decryption-key (L2 behavior, unchanged):
  ✓  clean.capsule                  PASS @ L2 (inner_envelope=None)
  ✓  tampered-payload.capsule       FAIL @ content_index
  ✓  tampered-chain.capsule         FAIL @ content_index + chain
  ✓  tampered-envelope.capsule      FAIL @ envelope_signature
  ✓  clean-encrypted.capsule        PASS @ L2 (chain deferred, inner_envelope=None)
  ✓  tampered-blob.capsule          FAIL @ encryption_state

With --decryption-key:
  ✓  clean.capsule                  PASS @ L2 (key ignored, inner_envelope=None)
  ✓  tampered-payload.capsule       FAIL @ content_index
  ✓  tampered-chain.capsule         FAIL @ content_index + chain
  ✓  tampered-envelope.capsule      FAIL @ envelope_signature
  ✓  clean-encrypted.capsule        PASS @ L3 with inner_envelope.ok=true (1 signer valid)
  ✓  tampered-blob.capsule          FAIL @ decryption (inner_envelope never reached, =None)
```

After v0.4 the launch claim becomes: *"Capsule has two independent implementations at every verification tier the spec defines, with full envelope signature coverage at every nesting level."*

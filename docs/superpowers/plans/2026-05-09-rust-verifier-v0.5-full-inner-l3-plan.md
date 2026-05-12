# Rust Verifier v0.5 — Full Inner Plain-Capsule Verification at L3

**Status:** approved, ready to execute
**Builds on:** v0.1 + v0.2 + v0.3 + v0.4
**Capsule format:** v0.6 (no schema changes)
**Output:** Modifications to `new-design/verifier-rust/`. New `inner_content_index: Option<ContentIndexCheck>` field; four new inner-side checks; README + CLI + tests.

## Goal

Close the remaining L3 spec coverage gap. The spec says: *"Open the inner ZIP as a normal capsule. Recompute first/entry event hashes, manifest hash, content index hash. Compare to the outer envelope."* — meaning **both** internal consistency on the inner (treated as a plain capsule) **and** cross-checks against the outer envelope.

v0.4 already covers: inner chain walk + inner envelope signatures + 5 outer-vs-inner cross-checks.

v0.5 adds the four missing inner-side checks:
1. **Inner format/version check** — `inner_manifest.format.version == "0.6"` and `inner_envelope.version == "0.6"`.
2. **Inner capsule_id derivation** — `SHA-256("capsule-id-v0.6\x00" || inner_originator_pubkey || inner_first_event_hash)` equals `inner_manifest.id` AND `inner_envelope.capsule_id`.
3. **Inner manifest hash recompute** — `sha256_hex(jcs(inner_manifest))` equals `inner_envelope.manifest_hash`.
4. **Inner content_index recompute** — every file in the inner ZIP (excluding the standard exclusion set) has its SHA-256 matching `inner_manifest.content_index.files`; the recomputed `index_hash` matches both `inner_manifest.content_index.index_hash` and `inner_envelope.content_index_hash`.

After v0.5:

| Fixture | No key (L2) | With recipient key (L3 v0.5) |
|---|---|---|
| `clean.capsule` | PASS @ L2 | (key ignored — plain) |
| `tampered-payload.capsule` | FAIL @ content_index | (same — plain) |
| `tampered-chain.capsule` | FAIL @ content_index + chain | (same — plain) |
| `tampered-envelope.capsule` | FAIL @ envelope_signature | (same — plain) |
| `clean-encrypted.capsule` | PASS @ L2 | **PASS @ L3** with all four new inner checks green |
| `tampered-blob.capsule` | FAIL @ encryption_state | FAIL @ decryption (inner checks never reached) |

## Why now

v0.3 + v0.4 cleared the moat bar. v0.5 is polish that strengthens the launch claim from *"two implementations at every verification tier with full envelope signature coverage at every nesting level"* to *"two implementations with full L3 coverage at every nesting level"*. It closes a real spec gap that an outside reviewer — exactly the audience for the moat — would notice.

## Scope decisions

1. **Inline checks in the L3 path**, not a recursive `verify_capsule` call. Recursion would require restructuring `VerifyResult` to embed a `Box<VerifyResult>`, which is a v1 architectural decision, not a v0.5 polish task. The four new checks slot naturally into the existing L3 step.

2. **Surfaces:** three of the four new checks use top-level `errors` with existing `TopErrorCategory` variants (`FormatVersion`, `CapsuleId`, `ManifestHash`). The fourth — content_index — gets its own `inner_content_index: Option<ContentIndexCheck>` field, mirroring v0.4's `inner_envelope` shape.

3. **Failure propagation:** any inner-side check failure flips `result.ok = false`. `level` still upgrades to `"L3"` because the L3 path executed; failures are visible in the structured fields.

4. **Error message convention:** all v0.5 inner-side errors prefix with `"L3 inner:"` so they're distinguishable from outer-side errors of the same category. Example: `"L3 inner: manifest.id mismatch: stored {} vs derived {}"`.

5. **`mutated_inner_*` integration coverage:** unit tests on the recompute helpers (mutate the parsed inner manifest struct, recompute, assert mismatch detected). A full pipeline test against a tampered-inner fixture remains out of scope (would require a Rust-side capsule mutator).

## File changes

### Modify

- `verifier-rust/crates/capsule-verify/src/verifier.rs` — add four inner checks in `l3_attempt_decrypt_and_verify`; add `inner_content_index` field; thread through `assemble_result`; tests.
- `verifier-rust/crates/capsule-verify-cli/src/main.rs` — render `[✓/✗] inner_content_index` check line when `inner_content_index.is_some()`.
- `verifier-rust/tests/parity_against_js_sdk.rs` — extend `encrypted_clean_capsule_passes_l3` with inner check assertions.
- `verifier-rust/README.md` — v0.5 section + transcript + scope updates.

No new modules. The four checks reuse existing helpers (`compute_capsule_id`, `manifest_hash`, `build_content_index` from `manifest.rs`).

## Tasks

### Task 1 — Inner-side recomputes + new field

**Goal:** Four new inner-side checks at L3. The three top-level errors fold into existing `errors`; the content_index gets its own field.

**Files:**
- `verifier-rust/crates/capsule-verify/src/verifier.rs`

**Changes:**

1. Add field to `VerifyResult`:
   ```rust
   #[derive(Debug, Clone, Serialize, Deserialize, Default)]
   pub struct VerifyResult {
       // ... existing fields ...
       /// Inner content_index check, populated when L3 verification ran
       /// and the inner ZIP was successfully unpacked. None for plain
       /// capsules, L2-only paths, or when L3 failed before reaching the
       /// inner content_index step.
       pub inner_content_index: Option<ContentIndexCheck>,
   }
   ```
   Place it next to `inner_envelope` for cohesion.

2. In `l3_attempt_decrypt_and_verify`, AFTER inner manifest+envelope+chain parse succeed AND AFTER inner_envelope is set (v0.4 step), BEFORE the cross-checks (v0.3 step), add:

   ```rust
   // (a) Inner format/version
   if inner_manifest.format.version != "0.6" {
       errors.push(TopError {
           category: TopErrorCategory::FormatVersion,
           message: format!("L3 inner: unsupported manifest format.version: {}", inner_manifest.format.version),
       });
   }
   if inner_envelope.version != "0.6" {
       errors.push(TopError {
           category: TopErrorCategory::FormatVersion,
           message: format!("L3 inner: unsupported envelope version: {}", inner_envelope.version),
       });
   }
   
   // (b) Inner capsule_id derivation
   match (
       hex_to_bytes(&inner_manifest.originator.public_key),
       /* parse inner_manifest.first_event_hash; reuse the helper used for outer if available */
   ) {
       (Ok(orig_pub_raw), ...) if orig_pub_raw.len() == 32 => {
           let derived = compute_capsule_id(/* args */);
           if derived != inner_manifest.id {
               errors.push(TopError {
                   category: TopErrorCategory::CapsuleId,
                   message: format!("L3 inner: manifest.id mismatch: stored {}, derived {}", inner_manifest.id, derived),
               });
           }
           if derived != inner_envelope.capsule_id {
               errors.push(TopError {
                   category: TopErrorCategory::CapsuleId,
                   message: format!("L3 inner: envelope.capsule_id mismatch: {} vs derived {}", inner_envelope.capsule_id, derived),
               });
           }
       }
       _ => {
           errors.push(TopError {
               category: TopErrorCategory::Malformed,
               message: "L3 inner: originator.public_key invalid".to_string(),
           });
       }
   }
   
   // (c) Inner manifest_hash recompute
   let recomputed_inner_mh = manifest_hash(&inner_manifest);
   if recomputed_inner_mh != inner_envelope.manifest_hash {
       errors.push(TopError {
           category: TopErrorCategory::ManifestHash,
           message: format!(
               "L3 inner: envelope.manifest_hash mismatch: stored {} vs recomputed {}",
               inner_envelope.manifest_hash, recomputed_inner_mh
           ),
       });
   }
   
   // (d) Inner content_index recompute
   let inner_content_check = recompute_content_index_check(&inner_files, &inner_manifest, &inner_envelope);
   *inner_content_index_check = Some(inner_content_check);
   ```

   Use the existing helpers exactly. The shape of `recompute_content_index_check` should mirror what the outer flow does for content_index — same predicate, same per-file SHA, same exclusion set, same comparison against both `manifest.content_index.index_hash` and `envelope.content_index_hash`.

   If there's already a private helper that builds the outer `ContentIndexCheck`, factor it so both outer and inner can call it. Pattern: `fn build_content_index_check(files: &BTreeMap<String, Vec<u8>>, manifest: &Manifest, envelope: &Envelope, label_prefix: &str) -> ContentIndexCheck` where `label_prefix` is `""` for outer and `"L3 inner: "` for inner. (Adjust the actual signature based on what's already there.)

3. Update `result.ok` in `assemble_result`:
   ```rust
   result.ok = errors.is_empty()
       && content_index.ok
       && chain.ok
       && envelope.ok
       && inner_envelope.as_ref().is_none_or(|e| e.ok)
       && inner_content_index.as_ref().is_none_or(|c| c.ok);  // NEW
   ```

4. Thread `inner_content_index: Option<ContentIndexCheck>` through `assemble_result`. All early-return paths pass `None`. Only L3-success-with-inner-zip-unpack populates it.

5. Order in the L3 path is important. The recommended order:
   - decrypt content.enc
   - unpack inner ZIP
   - parse inner manifest+envelope+chain
   - **NEW:** inner format check
   - **NEW:** inner capsule_id derivation
   - **NEW:** inner manifest_hash recompute
   - **NEW:** inner content_index recompute → set `inner_content_index`
   - inner envelope sigs (v0.4) → set `inner_envelope`
   - inner chain walk (v0.3) → updates `chain`
   - cross-checks (v0.3) → push to `errors`
   - upgrade level to L3

   The inner sigs (v0.4) and the new v0.5 checks can run in any order since they're independent. Place them in source order that reads naturally.

**Tests in `verifier.rs`:**

1. **`encrypted_clean_capsule_l3_inner_content_index_verifies`** — clean-encrypted + recipient secret. Assert:
   - `result.ok == true`
   - `result.level == "L3"`
   - `result.inner_content_index.is_some()`
   - `result.inner_content_index.as_ref().unwrap().ok == true`
   - `result.inner_content_index.as_ref().unwrap().errors.is_empty()`

2. **`encrypted_clean_capsule_l3_inner_full_check_verifies`** — clean-encrypted + recipient secret. Assert that none of the v0.5 inner errors fire by checking the full `errors` vec contains no message starting with `"L3 inner:"`. (This is a one-line filter assertion.)

3. **`inner_content_index_absent_at_l2`** — clean-encrypted, no key. Assert `result.inner_content_index.is_none()`.

4. **`inner_content_index_absent_for_plain`** — clean.capsule + key. Assert `result.inner_content_index.is_none()`.

5. **`mutated_inner_manifest_hash_unit_test`** — extract inner via decrypt, mutate `inner_manifest.created_at` (or any field that affects JCS but doesn't break parsing), recompute manifest_hash, assert it differs from the inner envelope's stored hash. Unit test on `manifest_hash` helper applied to the modified struct.

6. **`mutated_inner_content_index_unit_test`** — extract inner via decrypt, drop one inner file from the files map (or modify one byte), call the content_index recompute helper, assert the resulting `ContentIndexCheck.ok == false` and the errors list contains a hash mismatch.

7. **Update existing v0.4 tests** to also assert `result.inner_content_index.is_some() && .ok == true` at L3.

**Verification:**

```sh
. "$HOME/.cargo/env"
cd /Users/complex/repo/virion/capsule/new-design/verifier-rust
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: 96 + 6 = ~102 tests, all passing. Clippy clean.

### Task 2 — CLI rendering + parity test + README v0.5

**Goal:** CLI shows the new `inner_content_index` check; parity test asserts it; README updated.

**Files:**
- `verifier-rust/crates/capsule-verify-cli/src/main.rs`
- `verifier-rust/tests/parity_against_js_sdk.rs`
- `verifier-rust/README.md`

**CLI plain output:**

When `result.inner_content_index.is_some()`, add a check line. Place it AFTER `[✓/✗] inner_envelope_signature` and BEFORE `encryption_state`. Render order:

```
  [✓] format / version
  [✓] capsule_id / manifest_hash
  [✓] content_index
  [✓] chain
  [✓] envelope_signature
  [✓] inner_envelope_signature                    ← v0.4
  [✓] inner_content_index                          ← v0.5 NEW
  [✓] encryption_state
```

When `result.inner_content_index.is_none()`, the line is omitted (consistent with `inner_envelope_signature`'s gating).

The new v0.5 inner checks that surface as top-level errors (format/version, capsule_id, manifest_hash) flow through the existing categorized error rendering — they appear under the same section names as their outer counterparts but with `"L3 inner:"` prefix, so the user can tell which envelope failed.

**Parity test:**

Extend the existing `encrypted_clean_capsule_passes_l3` in `tests/parity_against_js_sdk.rs`:

```rust
assert!(
    result.inner_content_index.is_some(),
    "L3 should populate inner_content_index on a successfully decrypted capsule",
);
let inner_ci = result.inner_content_index.as_ref().unwrap();
assert!(
    inner_ci.ok,
    "inner content_index should verify; got errors: {:?}",
    inner_ci.errors,
);
assert!(
    inner_ci.errors.is_empty(),
    "inner content_index errors should be empty",
);
// All four inner checks pass:
assert!(
    !result.errors.iter().any(|e| e.message.starts_with("L3 inner:")),
    "no L3 inner errors expected; got: {:?}",
    result.errors,
);
```

**README updates:**

1. Add "What's new in v0.5" section near the top:
   - Full inner plain-capsule verification at L3: inner format/version, inner capsule_id derivation, inner manifest_hash, inner content_index all recomputed and checked.
   - New `inner_content_index: Option<ContentIndexCheck>` field on `VerifyResult` (mirrors v0.4's `inner_envelope`).
   - Inner-side errors prefixed `"L3 inner:"` to distinguish from outer-envelope failures of the same category.
   - Closes the spec's L3 "Open the inner ZIP as a normal capsule" requirement; the Rust verifier now does on the inner what plain L2 does on the outer.

2. "What it does" section: extend the L3 bullet to mention the four new inner checks.

3. "What it does NOT do (yet)" section:
   - REMOVE: "Full inner plain-capsule verification" parking-lot note (it's done now).
   - KEEP: "Capsule building / signing", "FFI / WASM target".

4. Re-capture the L3 transcript with the new `[✓] inner_content_index` line.

5. Bump test count: 96 → ~102.

**Verification:**

```sh
. "$HOME/.cargo/env"
cd /Users/complex/repo/virion/capsule/new-design/verifier-rust
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
KEY=$(jq -r '.recipient.privateKey' ../examples/tamper-detection/output/keys.json)
cargo run -p capsule-verify-cli -- verify ../examples/tamper-detection/output/clean-encrypted.capsule --decryption-key "$KEY"
```

Expected: L3 transcript shows `[✓] inner_content_index` line. All 102 tests pass. Clippy clean.

## Out of scope for v0.5

- **Recursive `verify_capsule(inner_bytes)` redesign.** Inline checks in the L3 path are sufficient for v0.5 and don't require API churn.
- **Tampered-inner-* integration fixtures.** Helper-level unit tests cover detection logic; a full-pipeline tampered-inner fixture requires a builder.
- **Capsule building / signing.** Verifier-only.
- **WASM / FFI.** Future.
- **`l3.rs` extraction.** `verifier.rs` is at ~980 production LOC; v0.5 will push it past 1050. The extraction is the cleanest follow-up but doesn't block this release.

## Risks

| # | Risk | Mitigation |
|---|---|---|
| 1 | The existing content_index helper has a signature that's hard to apply to the inner (e.g., assumes outer envelope) | Read the existing helper before changing the call site. If it's `(files, manifest, envelope) -> ContentIndexCheck`, it's symmetric and works for both. |
| 2 | `manifest_hash` helper assumes outer state | Same — read the helper first. The helper should be `(manifest) -> String` (computes JCS+SHA256), which is identity-symmetric. |
| 3 | "L3 inner:" message prefix collides with existing message wording | Search for existing message contents starting with "L3" (v0.3 added "L3:" prefixes). Disambiguate by using "L3 inner: " (with space) and "L3:" (no space, no "inner") — pattern-match cleanly. |
| 4 | Test count mismatch in README after Task 2 | After running `cargo test --workspace`, count the actual number and update README accordingly. |
| 5 | Inner originator pubkey hex decode fails | The four checks should run defensively — if one fails (e.g., bad hex on inner pubkey), don't panic; surface as `Malformed` error. The existing outer-side helper does this. |

## Test oracle (post-v0.5)

```
Without --decryption-key (L2 behavior, unchanged):
  ✓  clean.capsule                  PASS @ L2 (inner_envelope=None, inner_content_index=None)
  ✓  tampered-payload.capsule       FAIL @ content_index
  ✓  tampered-chain.capsule         FAIL @ content_index + chain
  ✓  tampered-envelope.capsule      FAIL @ envelope_signature
  ✓  clean-encrypted.capsule        PASS @ L2 (chain deferred)
  ✓  tampered-blob.capsule          FAIL @ encryption_state

With --decryption-key:
  ✓  clean.capsule                  PASS @ L2 (key ignored)
  ✓  tampered-payload.capsule       FAIL @ content_index
  ✓  tampered-chain.capsule         FAIL @ content_index + chain
  ✓  tampered-envelope.capsule      FAIL @ envelope_signature
  ✓  clean-encrypted.capsule        PASS @ L3 with inner_envelope.ok=true AND inner_content_index.ok=true; no "L3 inner:" errors
  ✓  tampered-blob.capsule          FAIL @ decryption (inner checks never reached)
```

After v0.5, the launch claim becomes: *"Capsule has two independent implementations with full L3 coverage at every nesting level."*

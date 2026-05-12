# Rust Verifier v0.6 — Structural Polish

**Status:** approved, ready to execute
**Builds on:** v0.1 – v0.5 (full L2 + L3 verification stack landed)
**Capsule format:** v0.6 (no schema changes)
**Output:** Modifications to `new-design/verifier-rust/`. New `l3.rs` module; `TopError.scope` discriminant; helper accessors; no behavior changes.

## Goal

Two focused refactors flagged in the v0.5 final review:

1. **Extract `l3.rs`.** `verifier.rs` is at 2483 total LOC / 1172 production. Moving `l3_attempt_decrypt_and_verify` and the L3-only state into its own module returns `verifier.rs` to ~600 production LOC of orchestration. Any third-implementation reviewer reading the L3 path will be able to do it in one file.

2. **Add `TopError.scope: TopErrorScope` discriminant.** JSON consumers currently substring-match `"L3 inner: "` to distinguish inner errors from outer errors of the same category. A `scope: "outer" | "inner"` tag makes this structural. Backward-compatible via `#[serde(default)]` defaulting to `Outer`.

No semantic changes. All 102 existing tests continue to pass. CLI plain output stays identical (the prefix is the rendering surface). JSON output gains the new field.

## Why now

The v0.5 final review identified both items as overdue. Both are low-risk, high-readability refactors. With the verifier moat closed (full L2 + L3 + inner-envelope sigs + inner-content_index), the remaining lever for outside-reviewer experience is making the code easy to read. These two changes are the highest-impact items.

## Scope decisions

1. **Extraction strategy:** move `l3_attempt_decrypt_and_verify` (and only that function) to `l3.rs`. The shared helpers it uses (`chain_walk_into`, `verify_content_index`, `verify_envelope_signatures`) stay in `verifier.rs` and become `pub(crate)`. This keeps the diff minimal — l3.rs is ~290 lines of focused L3 logic.

2. **Test placement:** L3 tests in `verifier.rs` test module exercise `verify_capsule()` (the public API), not the L3 helper directly. They stay in `verifier.rs`. Only the L3-helper-specific tests (none today; the mutation tests test the shared helpers) move with the function.

3. **Scope tag default:** `TopErrorScope::Outer`. Every push site in the outer pipeline keeps `Outer`. Every push site in `l3.rs`'s inner checks gets `Inner`. The `"L3 inner: "` message prefix STAYS — it's the rendering surface and the parity-test substring assertion; the `scope` tag is the structural complement.

4. **Helper constructors:** add tiny private helpers `outer_error(category, message)` and `inner_error(category, message)` to reduce noise at push sites and prevent forgetting the scope tag. Or expose them as associated functions on `TopError`: `TopError::outer(...)`, `TopError::inner(...)`.

5. **README note** (cosmetic): add a sentence explaining that `inner_envelope_signature` may render `[✓]` even when `[✗]` lines fire for `"L3 inner: "` format/version or capsule_id checks — by design, so the inner sig outcome surfaces independently. Already mentioned in the v0.5 follow-ups.

## Tasks

### Task 1 — Extract `l3.rs`

**Goal:** Move `l3_attempt_decrypt_and_verify` from `verifier.rs` to a new `crates/capsule-verify/src/l3.rs`. No behavior changes. All 102 existing tests still pass.

**Files:**
- `verifier-rust/crates/capsule-verify/src/l3.rs` (new)
- `verifier-rust/crates/capsule-verify/src/verifier.rs` (delete the moved function, mark dependent helpers `pub(crate)`)
- `verifier-rust/crates/capsule-verify/src/lib.rs` (declare new module)

**Specific steps:**

1. Identify what `l3_attempt_decrypt_and_verify` calls into `verifier.rs`:
   - `chain_walk_into` (or whatever the current name is)
   - `verify_content_index`
   - `verify_envelope_signatures`
   - Any private types it uses (`ChainCheck`, `ContentIndexCheck`, `EnvelopeCheck`, `TopError`, `TopErrorCategory`)

2. Mark each shared helper as `pub(crate)` in `verifier.rs`. Don't make them fully `pub` — they're internal helpers, not part of the library API.

3. Create `l3.rs` with the moved function. Re-import the helpers and types from `crate::verifier::{...}`.

4. In `lib.rs`, add `mod l3;` (private — l3.rs is internal; `verify_capsule` is the public surface and stays in `verifier.rs`).

5. In `verifier.rs`, the L3-success branch in `verify_capsule` already calls `l3_attempt_decrypt_and_verify(...)`. Just change the import path: `use crate::l3::l3_attempt_decrypt_and_verify;` (or move the call site to use the new path explicitly).

6. The `#[allow(clippy::too_many_arguments)]` on `l3_attempt_decrypt_and_verify` moves with it.

**Verification:**

```sh
. "$HOME/.cargo/env"
cd /Users/complex/repo/virion/capsule/new-design/verifier-rust
cargo build --workspace
cargo test --workspace      # all 102 still pass
cargo clippy --workspace --all-targets -- -D warnings
wc -l crates/capsule-verify/src/{verifier,l3}.rs
```

Expected: `verifier.rs` total LOC drops by ~290; `l3.rs` is ~290 LOC. 102/102 tests pass. Clippy clean.

**Out of scope for Task 1:**
- Adding the scope tag (Task 2).
- Splitting test modules.
- Renaming any helpers.
- Touching CLI / README / parity tests.

### Task 2 — Add `TopError.scope` discriminant + helper constructors + README note

**Goal:** Add `scope: TopErrorScope` to `TopError`. Update all push sites to set scope correctly. Add a brief README note about inner_envelope_signature semantics.

**Files:**
- `verifier-rust/crates/capsule-verify/src/verifier.rs` — `TopError` definition + `TopErrorScope` enum + outer pipeline push sites updated.
- `verifier-rust/crates/capsule-verify/src/l3.rs` — push sites in the L3 path get `scope: Inner`.
- `verifier-rust/crates/capsule-verify/src/lib.rs` — re-export `TopErrorScope`.
- `verifier-rust/README.md` — short note about inner_envelope rendering semantics.

**Specific steps:**

1. Add the enum in `verifier.rs`:
   ```rust
   #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
   #[serde(rename_all = "lowercase")]
   pub enum TopErrorScope {
       #[default]
       Outer,
       Inner,
   }
   ```

2. Update `TopError`:
   ```rust
   #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
   pub struct TopError {
       pub category: TopErrorCategory,
       #[serde(default)]
       pub scope: TopErrorScope,
       pub message: String,
   }
   ```
   `#[serde(default)]` on `scope` ensures backward-compat for any JSON consumer parsing v0.3-v0.5 output.

3. Add helper constructors:
   ```rust
   impl TopError {
       pub fn outer(category: TopErrorCategory, message: impl Into<String>) -> Self {
           Self { category, scope: TopErrorScope::Outer, message: message.into() }
       }
       pub fn inner(category: TopErrorCategory, message: impl Into<String>) -> Self {
           Self { category, scope: TopErrorScope::Inner, message: message.into() }
       }
   }
   ```

4. Update every push site:
   - In `verifier.rs` (outer pipeline): replace `TopError { category, message }` with `TopError::outer(category, message)`. There are ~10-15 outer push sites.
   - In `l3.rs` (inner pipeline): the L3-only inner checks (format/version, capsule_id, manifest_hash) push errors with `"L3 inner: "` prefix. Change to `TopError::inner(category, message)` — the prefix in the message stays.
   - In `l3.rs` (decrypt failure, parse failure, cross-check failures): these are about the L3 attempt itself, not strictly "inner content." Classify them as `Inner` since they happen during inner-side processing.
   - Any other sites? Grep for `TopError {`.

5. Re-export from `lib.rs`:
   ```rust
   pub use verifier::{..., TopError, TopErrorCategory, TopErrorScope};
   ```

6. Update one test to assert on scope structurally:
   - Pick `every_category_is_exercisable` or another category-touching test. Add an assertion like:
     ```rust
     // L3-inner errors should carry scope=Inner
     let inner_errors: Vec<_> = result.errors.iter()
         .filter(|e| e.message.starts_with("L3 inner:"))
         .collect();
     assert!(inner_errors.iter().all(|e| e.scope == TopErrorScope::Inner));
     ```

7. Add a 1-2 sentence README note (in the "What's new in v0.6" section you'll write):
   - "Inner envelope signature verification (`[✓]/[✗] inner_envelope_signature` line) populates independently of inner format/version or manifest_hash checks. A clean capsule with a tampered inner manifest will still render `[✓] inner_envelope_signature` if the signature itself is valid; the failure surfaces as a separate `[✗]` line under the affected check (`capsule_id / manifest_hash` etc.) with a `"L3 inner: "` prefixed message."

8. Add "What's new in v0.6" section to README:
   - **Structural polish:** L3 logic extracted to its own `l3.rs` module (verifier.rs returns to orchestration only).
   - **`TopError.scope` discriminant:** JSON consumers can now filter on `scope == "inner"` instead of substring-matching the `"L3 inner: "` message prefix. Backward-compatible (`#[serde(default)]`).
   - **Helper constructors:** `TopError::outer(...)` and `TopError::inner(...)` make push sites explicit about scope.
   - Sentence note about inner_envelope rendering semantics (see step 7 above).

9. Update the test-count claim if mentioned.

**Verification:**

```sh
. "$HOME/.cargo/env"
cd /Users/complex/repo/virion/capsule/new-design/verifier-rust
cargo build --workspace
cargo test --workspace      # all 102 still pass; may add 1 test for scope discriminant
cargo clippy --workspace --all-targets -- -D warnings

KEY=$(jq -r '.recipient.privateKey' ../examples/tamper-detection/output/keys.json)
# JSON output: confirm scope field present
cargo run -q -p capsule-verify-cli -- verify ../examples/tamper-detection/output/clean-encrypted.capsule --decryption-key "$KEY" --json | jq '.errors'
# (Should be empty array — clean fixture; the scope field appears when errors exist)

# Synthesize an inner-fault by mutating clean-encrypted's outer envelope (which exercises Inner-scope after decrypt)... or just inspect a tampered-payload run to confirm Outer-scope errors carry scope=outer:
cargo run -q -p capsule-verify-cli -- verify ../examples/tamper-detection/output/tampered-payload.capsule --json | jq '.errors[].scope' 
# Should print "outer" for each error.
```

**Out of scope for Task 2:**
- Renaming any errors / categories.
- Adding `scope` to per-check structs (e.g., `ContentIndexCheck.errors` are still `Vec<String>` — only `TopError` gets the discriminant).
- Changing plain CLI output (the `"L3 inner: "` message prefix stays for plain rendering).

## Test oracle (post-v0.6)

```
Without --decryption-key:
  ✓  All 6 fixtures behave identically to v0.5
  ✓  JSON output for errors now includes scope: "outer"

With --decryption-key:
  ✓  All 6 fixtures behave identically to v0.5
  ✓  Inner-fault JSON errors carry scope: "inner"; outer faults carry scope: "outer"

Test count: 102 (unchanged) or 103 (if one scope-discriminant test added)
```

## Out of scope for v0.6 entirely

- New verifier checks (the verification stack is complete after v0.5).
- A Rust-side capsule builder.
- WASM / FFI.
- Third-implementation scaffolding (out of scope for v0.6; a launch-week-plus deliverable).
- L3 inner test coverage on a full-pipeline tampered-inner fixture (still needs a builder).

## Risks

| # | Risk | Mitigation |
|---|---|---|
| 1 | Moving `l3_attempt_decrypt_and_verify` breaks the call site signature | Read the existing call site in `verify_capsule` first; the function's interface is wholly internal — move it as-is. |
| 2 | `chain_walk_into` etc. need to be visible to `l3.rs` but the existing visibility is `fn` (module-private) | Mark them `pub(crate) fn` — visible within the crate, not exported. |
| 3 | `TopErrorScope` enum naming collides with something else | Unlikely; grep first to confirm. |
| 4 | Adding `scope` field breaks existing JSON deserializers | `#[serde(default)]` on the field handles backward-compat. Test by deserializing a v0.5-shaped JSON sample. |
| 5 | Test count assertions in tests / README drift | Run `cargo test --workspace 2>&1 \| grep "test result"` after each task and update if needed. |

## v0.6 launch claim

No change to the moat claim — the verifier already covered everything in v0.5. v0.6 is reviewability polish, not new capability. Post-v0.6, a third-implementation reviewer can read the L3 path in one self-contained file, and JSON consumers can categorize errors structurally without substring-matching.

# Rust Verifier v0.5 — Full Inner Plain-Capsule Verification

**Status:** approved, ready to execute
**Builds on:** v0.1 + v0.2 + v0.3 + v0.4
**Capsule format:** v0.6 (no schema changes)
**Output:** Modifications to `new-design/verifier-rust/`. Extracted `verify_content_index` helper; new `VerifyResult.inner_content_index` field; inner manifest_hash recompute; CLI rendering + parity test + README.

## Goal

At L3, complete the spec's "Open the inner ZIP as a normal capsule" promise:

- Recompute the inner `manifest_hash` and compare to `inner_envelope.manifest_hash`.
- Recompute the inner `content_index` (per-file SHA-256s and the rollup `index_hash`) and compare to `inner_manifest.content_index.files[]`, `inner_manifest.content_index.index_hash`, and `inner_envelope.content_index_hash`.
- Surface inner content-index results via a new `inner_content_index: Option<ContentIndexCheck>` field on `VerifyResult` (mirroring the v0.4 `inner_envelope` pattern).
- Surface inner manifest_hash mismatches as top-level `errors` with category `ManifestHash` and message prefix `"L3 inner: "` (mirroring how outer manifest_hash is surfaced today).

After v0.5:

| Fixture | No key (L2) | With recipient key (L3) |
|---|---|---|
| `clean.capsule` | PASS @ L2 | PASS @ L2 (key ignored) |
| `tampered-payload.capsule` | FAIL @ content_index | (same — plain) |
| `tampered-chain.capsule` | FAIL @ content_index + chain | (same — plain) |
| `tampered-envelope.capsule` | FAIL @ envelope_signature | (same — plain) |
| `clean-encrypted.capsule` | PASS @ L2 (chain deferred, inner_*=None) | **PASS @ L3 with inner_envelope.ok=true, inner_content_index.ok=true, inner manifest_hash verifies** |
| `tampered-blob.capsule` | FAIL @ encryption_state | FAIL @ decryption (inner_*=None) |

The launch claim moves from *"full envelope signature coverage at every nesting level"* to *"full L3 content verification at every nesting level."*

## Why now

The v0.4 final review identified inner `manifest_hash` + `content_index` recompute as the remaining L3 spec coverage gap. This is the "polish" task before launch — small scope, real spec gap closure, strong "no L3 verification gap exists" framing for the writeup.

## Spec authority

- `spec/envelope.md` — L3 description: "Open the inner ZIP as a normal capsule. Recompute first/entry event hashes, manifest hash, content index hash."
- `spec/manifest.md` — content_index structure, sha256 per file, index_hash = sha256(jcs(files)).
- The existing v0.1 outer-envelope verification — already does this for outer; v0.5 just runs the same logic on the inner.

## Scope decisions

1. **Extract a shared `verify_content_index` helper** so outer and inner content-index verification can't drift. The current outer logic is inline in `verify_capsule`; v0.5 lifts it to a private `fn verify_content_index(files, manifest, envelope, excluded) -> ContentIndexCheck`. Used by both outer (replacing inline) and inner (new).
2. **Inner manifest_hash mismatches surface as top-level `errors`** with category `TopErrorCategory::ManifestHash` and message prefix `"L3 inner: "`. Symmetrical with outer manifest_hash — outer also goes via `errors`, not via a dedicated field.
3. **Inner content_index goes via a new `inner_content_index: Option<ContentIndexCheck>` field**. Symmetrical with v0.4's `inner_envelope: Option<EnvelopeCheck>`. Populated at L3 success only.
4. **`result.ok` propagation:** add `inner_content_index.as_ref().is_none_or(|ci| ci.ok)` to the AND chain. Inner manifest_hash errors are already covered by `errors.is_empty()`.
5. **Excluded files for inner content_index:** same as outer — `{manifest.json, provenance/envelope.json, content.enc}`. The inner ZIP shouldn't contain `content.enc`, but the predicate is safe regardless.
6. **No new categories.** Reuse `TopErrorCategory::ManifestHash` for inner manifest_hash; the renderer disambiguates via the `"L3 inner: "` prefix.

## File changes

- `verifier-rust/crates/capsule-verify/src/manifest.rs` — extract `verify_content_index` helper here (it's content-index/manifest territory) OR keep in `verifier.rs` as a private helper. Pick whichever fits the existing structure better.
- `verifier-rust/crates/capsule-verify/src/verifier.rs` — replace inline outer content_index logic with helper call; add inner manifest_hash + inner content_index logic in `l3_attempt_decrypt_and_verify`; add `inner_content_index` field; thread through `assemble_result`; update `result.ok`.
- `verifier-rust/crates/capsule-verify-cli/src/main.rs` — render `[✓/✗] inner_manifest_hash` and `[✓/✗] inner_content_index` check lines (Task 2).
- `verifier-rust/tests/parity_against_js_sdk.rs` — extend `encrypted_clean_capsule_passes_l3` (Task 2).
- `verifier-rust/README.md` — v0.5 section + transcript + scope updates (Task 2).

## Tasks

### Task 1 — Verifier change

**Goal:** Inner manifest_hash recompute + inner content_index recompute. Refactor outer content_index into a shared helper for parity. Add `inner_content_index` field. Tests.

**Files:**
- `verifier-rust/crates/capsule-verify/src/verifier.rs` (most of the work)
- Possibly `verifier-rust/crates/capsule-verify/src/manifest.rs` (if helper lives there)

**Changes:**

#### 1. Extract `verify_content_index` helper

Read the current outer content_index logic in `verify_capsule` (around the v0.1-era code that builds the recomputed index, compares per-file hashes, and compares `index_hash` to envelope/manifest claims). Lift it into a private function:

```rust
/// Verify a manifest's content_index against actually-stored files.
///
/// - For each file in `files` not in `excluded`, recompute SHA-256 and check
///   it against the manifest's `content_index.files[]` entry.
/// - Recompute `index_hash = sha256(jcs(files_array))` and compare to
///   `manifest.content_index.index_hash` AND (if non-empty) the envelope's
///   `content_index_hash`.
///
/// Used at the outer level (every capsule) and at the inner level on L3.
fn verify_content_index(
    files: &BTreeMap<String, Vec<u8>>,
    manifest: &Manifest,
    envelope_content_index_hash: Option<&str>,
    excluded: &[&str],
) -> ContentIndexCheck;
```

Replace the outer call site with this helper. Pass `Some(&envelope.content_index_hash)` for the outer envelope's claim.

This refactor MUST preserve the existing outer behavior exactly. Run all 96 v0.4 tests after the refactor and confirm zero regressions before adding the inner logic.

#### 2. Add inner manifest_hash recompute at L3

In `l3_attempt_decrypt_and_verify`, AFTER inner envelope sig verification (the v0.4 step) and BEFORE the existing cross-checks:

```rust
// v0.5: recompute inner manifest_hash, compare to inner envelope's claim.
let recomputed_inner_manifest_hash = manifest_hash(&inner_manifest);
if recomputed_inner_manifest_hash != inner_envelope.manifest_hash {
    errors.push(TopError {
        category: TopErrorCategory::ManifestHash,
        message: format!(
            "L3 inner: envelope.manifest_hash mismatch: stored {}, recomputed {}",
            inner_envelope.manifest_hash, recomputed_inner_manifest_hash,
        ),
    });
}
```

#### 3. Add inner content_index recompute at L3

Right after the inner manifest_hash check:

```rust
// v0.5: recompute inner content_index, surface as inner_content_index.
let inner_ci_check = verify_content_index(
    &inner_files,
    &inner_manifest,
    Some(&inner_envelope.content_index_hash),
    &CONTENT_INDEX_EXCLUDED,
);
*inner_content_index_check = Some(inner_ci_check);
```

(`CONTENT_INDEX_EXCLUDED` is the existing `[&str; 3]` constant.)

#### 4. Add `inner_content_index` field to `VerifyResult`

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VerifyResult {
    // ... existing fields ...
    /// Inner content_index check, populated when L3 verification ran and
    /// the inner ZIP was successfully unpacked + parsed. None for plain
    /// capsules, L2-only paths (no recipient key), or when L3 failed
    /// before reaching the inner content_index step (decrypt failure /
    /// inner ZIP unpack failure / inner schemas parse failure).
    pub inner_content_index: Option<ContentIndexCheck>,
}
```

Place adjacent to `inner_envelope` for visual symmetry.

#### 5. Update `assemble_result`

Add `inner_content_index: Option<ContentIndexCheck>` parameter. Thread it through all early-return paths (each passes `None`). Update the `ok` computation:

```rust
result.ok = errors.is_empty()
    && content_index.ok
    && chain.ok
    && envelope.ok
    && inner_envelope.as_ref().is_none_or(|e| e.ok)
    && inner_content_index.as_ref().is_none_or(|ci| ci.ok);
```

`#[allow(clippy::too_many_arguments)]` already applied to `assemble_result`; the count goes up by one.

#### 6. Tests in `verifier.rs`

1. **`encrypted_clean_capsule_l3_inner_content_index_verifies`** — clean-encrypted + recipient secret. Assert:
   - `result.ok == true`
   - `result.level == "L3"`
   - `result.inner_content_index.is_some()`
   - `result.inner_content_index.as_ref().unwrap().ok == true`
   - `result.inner_content_index.as_ref().unwrap().errors.is_empty()`
   - No `errors[]` entry has category `ManifestHash` with `"L3 inner"` substring (so inner manifest_hash also verifies).

2. **`inner_content_index_check_absent_at_l2`** — clean-encrypted + `recipient_private_key: None`. Assert:
   - `result.ok == true`
   - `result.inner_content_index.is_none()`

3. **`inner_content_index_check_absent_for_plain`** — clean.capsule + recipient key. Assert:
   - `result.ok == true`
   - `result.inner_content_index.is_none()`

4. **`mutated_inner_manifest_content_index_unit_test`** — extract decrypted inner files + inner manifest from clean-encrypted, mutate one byte of `inner_manifest.content_index.files[0].sha256` (e.g., flip last hex char), call `verify_content_index(...)` directly, assert:
   - `result.ok == false`
   - `result.errors` contains a "file hash mismatch" entry for the mutated path

5. **Update existing `encrypted_clean_capsule_passes_l3_with_recipient_key`** to also assert:
   - `result.inner_content_index.is_some()`
   - `result.inner_content_index.as_ref().unwrap().ok == true`

   Existing assertions on tampered fixtures continue to hold (decrypt fail → inner_content_index stays `None`).

**Verification:**

```sh
. "$HOME/.cargo/env"
cd /Users/complex/repo/virion/capsule/new-design/verifier-rust
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Required: 96 + 4 = **100 tests, all passing**. Clippy clean. All existing tests still pass (the `verify_content_index` extraction must not regress outer behavior).

#### Out of scope for Task 1

- CLI rendering of inner_manifest_hash + inner_content_index lines (Task 2).
- README updates (Task 2).
- Parity test extension (Task 2).
- Recursive `inner: Option<Box<VerifyResult>>` API (deliberately rejected; the field-level approach is more compatible).

### Task 2 — CLI rendering + parity test + README

**Goal:** CLI plain-output surfaces inner manifest_hash + inner content_index check lines. Parity test asserts inner content_index. README documents v0.5.

**Files:**
- `verifier-rust/crates/capsule-verify-cli/src/main.rs`
- `verifier-rust/tests/parity_against_js_sdk.rs`
- `verifier-rust/README.md`

**CLI plain output:**

When `r.inner_envelope.is_some()` (the v0.4 gate, which is also the L3-success gate for these new lines), render two NEW check lines AFTER `[✓/✗] inner_envelope_signature` and BEFORE `[✓] encryption_state`:

```
  [✓] inner_manifest_hash
  [✓] inner_content_index
```

For `inner_manifest_hash`:
- Scan `r.errors` for entries where `category == ManifestHash` AND `message` contains `"L3 inner"`.
- If any → `[✗] inner_manifest_hash` with each error message indented.
- Else → `[✓] inner_manifest_hash`.

For `inner_content_index`:
- If `r.inner_content_index.unwrap().ok` → `[✓] inner_content_index`.
- Else → `[✗] inner_content_index` with each `errors[]` entry indented.

JSON output: nothing to do — `inner_content_index` flows through Serialize.

**Parity test:**

Extend `encrypted_clean_capsule_passes_l3` in `tests/parity_against_js_sdk.rs`:

```rust
// existing v0.4 inner_envelope assertions stay
assert!(
    result.inner_content_index.is_some(),
    "L3 should populate inner_content_index",
);
let inner_ci = result.inner_content_index.as_ref().unwrap();
assert!(
    inner_ci.ok,
    "inner content_index should verify; got errors: {:?}",
    inner_ci.errors,
);
let inner_manifest_hash_errors: Vec<_> = result.errors.iter()
    .filter(|e| e.category == capsule_verify::TopErrorCategory::ManifestHash
            && e.message.contains("L3 inner"))
    .collect();
assert!(
    inner_manifest_hash_errors.is_empty(),
    "no inner manifest_hash errors expected; got: {:?}",
    inner_manifest_hash_errors,
);
```

**README updates:**

1. Add "What's new in v0.5" section near the top (above v0.4):

```markdown
## What's new in v0.5

- Full inner plain-capsule verification at L3: the inner manifest_hash is
  recomputed and compared against the inner envelope's claim, and the
  inner content_index is fully recomputed (per-file SHA-256s + rollup
  index_hash, cross-checked against both the inner manifest and the inner
  envelope).
- New `inner_content_index: Option<ContentIndexCheck>` field on
  `VerifyResult`, mirroring v0.4's `inner_envelope`. Visible in JSON;
  rendered in plain CLI output as a separate `[✓]/[✗] inner_content_index`
  check line.
- Inner manifest_hash mismatches surface as top-level `ManifestHash`
  errors with `"L3 inner: "` prefix; rendered as a `[✓]/[✗] inner_manifest_hash`
  check line.
- Shared `verify_content_index` helper now used by both outer and inner
  content_index verification — single source of truth for the spec's
  per-file + index_hash logic.
```

2. Update the dual-column outcome table to reflect inner_content_index state.

3. Re-capture the L3 transcript with the two new check lines visible:

```
Checks:
  [✓] format / version
  [✓] capsule_id / manifest_hash
  [✓] content_index
  [✓] chain
  [✓] envelope_signature
  [✓] inner_envelope_signature
  [✓] inner_manifest_hash             ← NEW v0.5
  [✓] inner_content_index             ← NEW v0.5
  [✓] encryption_state
```

4. Update "What it does NOT do (yet)" — REMOVE the "full inner plain-capsule verification" v0.5 placeholder. ADD a v0.6+ note about a Rust-side capsule mutator/builder (so tampered-inner-* integration fixtures become possible) if that's the natural next thing, OR just keep "Capsule building / signing" as-is.

5. Bump test count if mentioned (96 → 100).

6. Add the v0.5 row to "What it does":
   - "L3 inner content verification (with `--decryption-key`): inner manifest_hash recomputed, inner content_index per-file SHA-256s and rollup index_hash recomputed, all cross-checked against the inner manifest and inner envelope."

**Verification:**

```sh
. "$HOME/.cargo/env"
cd /Users/complex/repo/virion/capsule/new-design/verifier-rust
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

KEY=$(jq -r '.recipient.privateKey' ../examples/tamper-detection/output/keys.json)
cargo run -p capsule-verify-cli -- verify ../examples/tamper-detection/output/clean-encrypted.capsule --decryption-key "$KEY"
cargo run -p capsule-verify-cli -- verify ../examples/tamper-detection/output/clean-encrypted.capsule
cargo run -p capsule-verify-cli -- verify ../examples/tamper-detection/output/clean.capsule --decryption-key "$KEY"
```

Required:
- 100 tests still pass (Task 1's 4 new tests + 1 extended).
- Clippy clean.
- L3 plain output shows BOTH new check lines.
- L2 / plain output shows NEITHER (gated on inner_envelope.is_some()).

#### Out of scope for Task 2

- New verifier behavior (Task 1).
- A Rust-side capsule mutator or new tampered-inner-* fixtures.
- L4 / nested encryption.
- Capsule building / signing.
- WASM / FFI.

## Risks

| # | Risk | Mitigation |
|---|---|---|
| 1 | The `verify_content_index` extraction silently changes outer behavior | All 96 v0.4 tests must pass after the extraction with no edits. Run before adding inner logic. |
| 2 | Inner content_index helper signature can't accommodate the case where the envelope's content_index_hash is missing | Make the helper take `Option<&str>` for envelope_content_index_hash; outer always passes `Some`, inner always passes `Some`. Empty/absent case is a future extension. |
| 3 | "L3 inner" prefix collides with future error messages | Unlikely — the prefix is unique to v0.5. Document in the helper / message-construction site. |
| 4 | CLI rendering order changes break user expectations | The new lines slot AFTER `inner_envelope_signature` and BEFORE `encryption_state` — same gating as inner_envelope_signature. L2 / plain output is unchanged. |
| 5 | `inner_content_index.errors` strings differ from outer formatting | The shared helper guarantees identical formatting; this is one of the reasons for the extraction. |

## Test oracle (post-v0.5)

```
Without --decryption-key (L2 behavior, unchanged):
  ✓  clean.capsule                  PASS @ L2
  ✓  tampered-payload.capsule       FAIL @ content_index
  ✓  tampered-chain.capsule         FAIL @ content_index + chain
  ✓  tampered-envelope.capsule      FAIL @ envelope_signature
  ✓  clean-encrypted.capsule        PASS @ L2 (chain deferred, inner_*=None)
  ✓  tampered-blob.capsule          FAIL @ encryption_state

With --decryption-key:
  ✓  clean.capsule                  PASS @ L2 (key ignored)
  ✓  tampered-payload.capsule       FAIL @ content_index
  ✓  tampered-chain.capsule         FAIL @ content_index + chain
  ✓  tampered-envelope.capsule      FAIL @ envelope_signature
  ✓  clean-encrypted.capsule        PASS @ L3 with inner_envelope.ok=true,
                                          inner manifest_hash verifies,
                                          inner_content_index.ok=true
  ✓  tampered-blob.capsule          FAIL @ decryption (inner_*=None)
```

After v0.5, the moat claim becomes: *"Capsule has two independent implementations at every verification tier the spec defines, with full L3 content verification at every nesting level (envelope signatures, manifest_hash, content_index, chain anchors)."*

# C2 — verifier-rust EOCD strictness bypass (F02, critical)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Part of:** [Capsules pre-release remediation](./README.md) · Tier 1 (release-blocking)

**Findings closed:** F02

**Lanes touched:** verifier-rust, spec, sdk-js, sdk-py

**Tasks:** 3

**Depends on:** sdk-py-container-strictness (F15 — port scanCentralDirectory/assertStrictEntries to sdk-py/src/capsule/zip_io.py). Tasks 1 and 2 are independent; Task 3 (the conformance vector) must land AFTER F15, because CPython's zipfile opens a trailing-byte archive and the new open-stage vector fails the sdk-py registry lane until F15's raw central-directory scan exists. Measured, not assumed — see validation.

## Global Constraints

Copied verbatim from the project state; every task below implicitly includes these.

- The project is **pre-release (v0.6 prototype)**. Breaking changes are acceptable. Do not add compatibility shims or deprecation paths.
- `sdk-js` is the **reference implementation**. Where lanes disagree and no decision says otherwise, JS defines correct behaviour.
- The chain.md step-6 actor rule resolves as: **all five verifiers enforce** (actor is in `manifest.participants` or equals `system:host`), **and builders reject at `appendEvent` time**. Not auto-registration.
- Every normative rule this plan enforces must land with a **negative conformance vector**, consumed by every lane's spec-registry test. A fix without a vector does not count as done.
- Test frameworks by lane: `sdk-js` node:test · `sdk-py` pytest · `verifier-rust` `#[test]` · `sdk-swift` XCTest · `sdk-kotlin` its existing test style.
- Never claim a command was run without running it.

## Risks

1. HARD ORDERING RISK: Task 3 breaks the sdk-py conformance lane if it lands before F15 (sdk-py raw central-directory scan). Measured: `1 failed, 182 passed`, `test_malformed_registry_outcomes[trailing-bytes]: DID NOT RAISE ValueError`. Task 3 Step 1 is a preflight gate that detects this in 5 seconds; do not skip it.
2. Cross-lane string coupling: Task 3 adds `"trailing_bytes": r"end-of-central-directory"` to sdk-py's OPEN_REASON_PATTERNS. F15's port must raise a ValueError whose message contains the phrase "end-of-central-directory" (a direct translation of sdk-js's `zip scan: end-of-central-directory not found` does). If F15 picks different wording, that one regex must be updated with it — coordinate at merge.
3. Any lane that adds a malformed-layout registry consumer later must add a `trailing_bytes` mapping or it will hard-fail on an unknown reason (Rust `panic!("unknown open-stage reason")`, Python assert, JS `fail(...unknown open-stage reason...)`). Swift and Kotlin do not consume this registry today (verified by grep), so no action there.
4. Task 1 tightens `bytes.len() < EOCD_MIN` from a silent pass-through to `InvalidContainer("too small to be a zip")`. This changes the error *string* for tiny/garbage inputs (previously the `zip` crate's "Could not find EOCD"). `verifier::tests::malformed_zip_surfaces_as_malformed_category` and `every_category_is_exercisable` both feed `b"not a zip"` but assert only on `TopErrorCategory::Malformed`, so they still pass (verified). Any future assertion on that exact string would need updating.
5. Task 2's rename (`scan_duplicate_names` → `scan_central_directory`) touches the same lines Task 1 rewrites; execute Tasks 1 and 2 in order, and take Task 2's line numbers from the post-Task-1 file (they are given as such and were measured on the real intermediate file, not estimated).
6. `cargo fmt --check` is NOT clean on this repo today (pre-existing diffs in chain.rs, main.rs, etc.) and is not in CI; the new code is written in rustfmt's preferred shape so it adds no new diff hunks, but do not "fix formatting" repo-wide as part of these tasks.
7. Regenerating fixtures rewrites all ten existing malformed-layout capsules. They are byte-identical on regeneration (verified: only the new file shows as untracked), but if a future generator change makes them drift, the `malformed-fixtures-regen` conformance target will catch it — review the byte diff rather than committing it blind.

## Validation performed while specifying this plan

The steps below were applied to a **copy of the repository outside the working tree** and executed. This is the real output from that run, not a prediction.

<details>
<summary>Expand validation log</summary>

```
All work was applied and run on a copy at /private/tmp/claude-501/.../scratchpad/work-c2 (the repo itself was never modified; 'git status --porcelain' in the repo is unchanged).

RED (pre-fix), 'cd verifier-rust && cargo test -p capsule-verify':
'''
test zip_reader::tests::rejects_input_too_small_for_eocd ... FAILED
test zip_reader::tests::rejects_hidden_entry_behind_trailing_byte ... FAILED
test zip_reader::tests::rejects_archive_without_eocd_signature ... FAILED
test zip_reader::tests::rejects_trailing_bytes_after_eocd ... FAILED
---- zip_reader::tests::rejects_hidden_entry_behind_trailing_byte stdout ----
panicked at crates/capsule-verify/src/zip_reader.rs:612:38:
must reject hidden entry: {"a.txt": [97]}          <-- hidden 2nd entry invisible, unpack SUCCEEDED
---- zip_reader::tests::rejects_trailing_bytes_after_eocd stdout ----
panicked at crates/capsule-verify/src/zip_reader.rs:591:38:
must reject trailing bytes: {"a.txt": [97]}
---- zip_reader::tests::rejects_input_too_small_for_eocd stdout ----
unexpected error: invalid zip container: invalid Zip archive: Could not find EOCD
test result: FAILED. 102 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out
'''
RED for the verify-level test (run with the pristine repo zip_reader.rs in place, so 102 filtered out):
'''
thread 'verifier::tests::trailing_byte_after_eocd_fails_closed' panicked at crates/capsule-verify/src/verifier.rs:982:9:
padded capsule must not verify
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 102 filtered out
'''
GREEN after Task 1 only (locate_eocd + rename, no count cross-check yet), 'cargo test --workspace':
'''
test result: ok. 7 passed  (parity_against_js_sdk)
test result: ok. 3 passed  (spec_registry)
test result: ok. 107 passed; 0 failed
'''
Task 2 RED (tests added before the helper), 'cargo test -p capsule-verify':
'''
error[E0308]: mismatched types
error[E0425]: cannot find function 'cross_check_entry_count' in this scope
error[E0425]: cannot find function 'cross_check_entry_count' in this scope
error: could not compile 'capsule-verify' (lib test) due to 3 previous errors
'''
GREEN after Tasks 1+2+3, 'cargo test --workspace':
'''
test result: ok. 7 passed   (parity_against_js_sdk)
test result: ok. 3 passed   (spec_registry, now including the trailing-bytes vector)
test result: ok. 109 passed; 0 failed
'''
End-to-end CLI proof (same padded capsule = clean.capsule + one 0x00):
'''
# fixed build (copy)
$ cargo run -q -p capsule-verify-cli -- verify /tmp/padded.capsule
  [✗] container / parse
        invalid zip container: trailing bytes after end-of-central-directory record
Result: FAIL     exit=1
# unfixed build already in the repo (verifier-rust/target/debug/capsule-verify-cli)
$ capsule-verify-cli verify /tmp/padded.capsule
  [✓] content_index  [✓] chain  [✓] envelope_signature
Result: PASS     exit=0
'''
Vector lane runs (copy):
'''
$ node sdk-js/tools/generate-malformed-fixtures.mjs
wrote trailing-bytes.capsule (2602 bytes)      # every other fixture regenerated byte-identical:
                                               # git status shows only the new file as untracked
$ node sdk-js/tools/generate-malformed-fixtures.mjs --check
ok trailing-bytes.capsule (2602 bytes)
$ node tools/check-spec-vectors.mjs
spec vectors: ok (281 vectors)                 # exit 0
$ cd verifier-rust && cargo test --test spec_registry
test malformed_registry_outcomes ... ok        # 3 passed
$ cd sdk-js && npm test
# tests 57  # pass 57  # fail 0
$ PYTHONPATH=sdk-py/src python3 -m pytest sdk-py/tests
FAILED sdk-py/tests/test_spec_registry.py::test_malformed_registry_outcomes[trailing-bytes]
1 failed, 182 passed in 0.27s                  # the ONLY failure; DID NOT RAISE ValueError
'''
That last result is the measured proof of the F15 dependency: CPython's 'zipfile' opens the trailing-byte archive (verified separately: 'python zipfile OPENS trailing-byte archive; names: 4'), while sdk-js already rejects it ('zip scan: end-of-central-directory not found'). SHA-256 of the generated fixture: fb810182f654a311c0563245947468e3e59d48f0e65b66afca3d1ab7394acb48 (2602 bytes). Not run: Swift/Kotlin lanes — grep confirms neither consumes spec/vectors/malformed-layout (both read only tamper-detection/output), so they are unaffected.
```

</details>

---

## C2 — verifier-rust EOCD strictness bypass (F02, critical)

Execution order: Task 1 → Task 2 → Task 3. Tasks 1 and 2 depend only on each other. **Task 3 additionally requires F15 (the sdk-py raw central-directory port) to be merged first** — its Step 1 is a gate that proves this in five seconds. All line numbers below are real: Task 1's refer to the current `main`; Task 2's refer to the file *after* Task 1 (measured on the actual intermediate file, not estimated).

### Task 1: Make a missing or ambiguous EOCD a hard rejection

**Files:**
- Modify: `verifier-rust/crates/capsule-verify/src/zip_reader.rs:157-187`
- Modify: `verifier-rust/crates/capsule-verify/src/zip_reader.rs:280`
- Modify: `CHANGELOG.md:70-71`
- Test: `verifier-rust/crates/capsule-verify/src/zip_reader.rs:582` (insert between the `}` on line 581 and the `#[test]` on line 583)
- Test: `verifier-rust/crates/capsule-verify/src/verifier.rs:958` (insert between the `}` on line 957 and the doc comment on line 959)

**Interfaces:**
- Consumes: `fn read_u16(bytes: &[u8], at: usize) -> u16`; `fn read_u32(bytes: &[u8], at: usize) -> u32`; `const EOCD_SIG: u32`, `const EOCD_MIN: usize`, `const MAX_COMMENT: usize`; `ZipError::InvalidContainer(String)`; `pub fn unpack_zip(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, ZipError>`; `pub fn verify_capsule(bytes: &[u8], options: &VerifyOptions) -> VerifyResult`; `crate::test_support::clean_capsule_bytes() -> Vec<u8>`; `VerifyResult { ok, errors: Vec<TopError>, trusted_signer_count, .. }`; `TopError { category: TopErrorCategory, message: String, .. }`
- Produces: `fn locate_eocd(bytes: &[u8]) -> Result<usize, ZipError>`; `fn scan_central_directory(bytes: &[u8]) -> Result<(), ZipError>` (replaces `fn scan_duplicate_names`); three new error strings that later tasks and other lanes match on: `"trailing bytes after end-of-central-directory record"`, `"end-of-central-directory record not found"`, `"too small to be a zip"`

- [ ] **Step 1: Write the failing unit tests**

Insert into the `mod tests` block of `verifier-rust/crates/capsule-verify/src/zip_reader.rs`, immediately after `rejects_later_eocd_signature_hidden_in_comment` ends (line 581) and before the `#[test]` on line 583:

```rust
    #[test]
    fn rejects_trailing_bytes_after_eocd() {
        // One appended byte pushes EOF past the EOCD's declared comment
        // length. The strictness scan must reject the container instead of
        // silently deferring to `ZipArchive`, whose locator tolerates the
        // padding. sdk-js throws on the identical bytes.
        let mut bytes = make_zip(&[("a.txt", b"a", CompressionMethod::Stored)]);
        bytes.push(0x00);
        let err = unpack_zip(&bytes).expect_err("must reject trailing bytes");
        assert!(
            err.to_string()
                .contains("trailing bytes after end-of-central-directory"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_hidden_entry_behind_trailing_byte() {
        // The F02 attack shape: understate the EOCD entry count so a reader
        // that walks by that count never sees the last record, then append
        // one byte so the strictness pass used to no-op entirely.
        let mut bytes = make_zip(&[
            ("a.txt", b"a", CompressionMethod::Stored),
            ("zz-hidden.sh", b"#!/bin/sh\n", CompressionMethod::Stored),
        ]);
        let eocd = bytes.len() - 22;
        bytes[eocd + 8..eocd + 10].copy_from_slice(&1u16.to_le_bytes());
        bytes[eocd + 10..eocd + 12].copy_from_slice(&1u16.to_le_bytes());
        bytes.push(0x00);
        let err = unpack_zip(&bytes).expect_err("must reject hidden entry");
        assert!(
            err.to_string()
                .contains("trailing bytes after end-of-central-directory"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_input_too_small_for_eocd() {
        let err = unpack_zip(b"not a zip").expect_err("must reject short input");
        assert!(
            err.to_string().contains("too small to be a zip"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_archive_without_eocd_signature() {
        let mut bytes = make_zip(&[("a.txt", b"a", CompressionMethod::Stored)]);
        let eocd = bytes.len() - 22;
        bytes[eocd..eocd + 4].copy_from_slice(&0u32.to_le_bytes());
        let err = unpack_zip(&bytes).expect_err("must reject missing EOCD");
        assert!(
            err.to_string()
                .contains("end-of-central-directory record not found"),
            "unexpected error: {err}"
        );
    }

```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd verifier-rust && cargo test -p capsule-verify`

Expected: FAIL — four failures. `rejects_trailing_bytes_after_eocd` and `rejects_hidden_entry_behind_trailing_byte` panic on `expect_err` because `unpack_zip` *succeeds*:
```
must reject trailing bytes: {"a.txt": [97]}
must reject hidden entry: {"a.txt": [97]}
unexpected error: invalid zip container: invalid Zip archive: Could not find EOCD
test result: FAILED. 102 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out
```
(`{"a.txt": [97]}` is the smoking gun: the hidden second entry is invisible to this reader.)

- [ ] **Step 3: Write the failing verify-level regression test**

Insert into the `mod tests` block of `verifier-rust/crates/capsule-verify/src/verifier.rs`, immediately after `clean_capsule_passes_l2` ends (line 957) and before the doc comment `/// With the originator's pubkey on the allowlist,` on line 959:

```rust
    /// F02 regression. Appending a single byte after the EOCD must not
    /// disable the container strictness pass: the padded capsule fails
    /// closed with a Malformed error and zero trusted signers, while the
    /// unmodified fixture still verifies. The JS reference lane rejects
    /// the identical padded bytes at open time.
    #[test]
    fn trailing_byte_after_eocd_fails_closed() {
        let clean = clean_capsule_bytes();
        let map = unpack_zip(&clean).expect("clean fixture unzips");
        let manifest: Manifest =
            serde_json::from_slice(map.get("manifest.json").unwrap()).unwrap();
        let allowlist = vec![manifest.originator.public_key.clone()];

        let mut padded = clean.clone();
        padded.push(0x00);
        let padded_result = verify_capsule(
            &padded,
            &VerifyOptions {
                allowlist: allowlist.clone(),
                recipient_private_key: None,
            },
        );

        assert!(!padded_result.ok, "padded capsule must not verify");
        assert_eq!(
            padded_result.trusted_signer_count, 0,
            "no signer may be trusted on a rejected container"
        );
        assert!(
            padded_result.errors.iter().any(|e| {
                e.category == TopErrorCategory::Malformed
                    && e.message
                        .contains("trailing bytes after end-of-central-directory")
            }),
            "expected a Malformed trailing-bytes error, got: {:?}",
            padded_result.errors
        );

        let control = verify_capsule(
            &clean,
            &VerifyOptions {
                allowlist,
                recipient_private_key: None,
            },
        );
        assert!(
            control.ok,
            "control must verify; errors: {:?}",
            control.errors
        );
        assert!(control.trusted_signer_count >= 1, "control must be trusted");
    }

```

- [ ] **Step 4: Run the verify-level test to verify it fails**

Run: `cd verifier-rust && cargo test -p capsule-verify verifier::tests::trailing_byte_after_eocd_fails_closed`

Expected: FAIL with
```
thread 'verifier::tests::trailing_byte_after_eocd_fails_closed' panicked at crates/capsule-verify/src/verifier.rs:982:9:
padded capsule must not verify
test result: FAILED. 0 passed; 1 failed
```
(A real, signed capsule with one junk byte appended currently reports `ok = true`.)

- [ ] **Step 5: Replace the locator with a fail-closed one**

In `verifier-rust/crates/capsule-verify/src/zip_reader.rs`, replace lines 157-187 — the whole block from the doc comment `/// Detect duplicate entry names by walking the RAW central directory.` through `let Some(eocd) = eocd else { return Ok(()) };` (the next line, 188, is the comment `// Reject a later raw EOCD signature so this strictness scan cannot select`, which stays) — with:

```rust
/// Locate the archive's end-of-central-directory (EOCD) record.
///
/// The EOCD is the LAST record of a conforming archive: its declared
/// comment length must land exactly at end-of-file. A signature-shaped
/// byte sequence whose declared comment length points anywhere else is
/// not an EOCD, and an archive with no conforming candidate carries bytes
/// it does not account for — the exact shape that makes two ZIP readers
/// disagree about which central directory is authoritative. Both cases
/// are hard rejections: this reader never falls back to a more permissive
/// locator. Mirrors `scanCentralDirectory` in `sdk-js/src/zip.js`, which
/// throws.
fn locate_eocd(bytes: &[u8]) -> Result<usize, ZipError> {
    if bytes.len() < EOCD_MIN {
        return Err(ZipError::InvalidContainer(
            "too small to be a zip".to_string(),
        ));
    }
    let lowest = bytes.len().saturating_sub(EOCD_MIN + MAX_COMMENT);
    let mut stray_signature = false;
    let mut p = bytes.len() - EOCD_MIN;
    loop {
        if read_u32(bytes, p) == EOCD_SIG {
            if p + EOCD_MIN + read_u16(bytes, p + 20) as usize == bytes.len() {
                return Ok(p);
            }
            stray_signature = true;
        }
        if p == lowest {
            break;
        }
        p -= 1;
    }
    Err(ZipError::InvalidContainer(
        if stray_signature {
            "trailing bytes after end-of-central-directory record"
        } else {
            "end-of-central-directory record not found"
        }
        .to_string(),
    ))
}

/// Walk the RAW central directory and enforce every container rule the
/// `zip` crate does not.
///
/// The `zip` crate indexes entries by name and silently keeps one copy
/// when an archive contains duplicates, so the duplicate never surfaces
/// through `ZipArchive` — exactly the parser differential the spec must
/// reject. This scan runs before the crate parses anything.
///
/// Structural errors (missing/ambiguous EOCD, trailing bytes, truncated
/// directory) are hard rejections here: deferring them to `ZipArchive`,
/// whose locator tolerates trailing garbage, would skip every check below.
/// ZIP64 sentinel values are rejected because a capsule can never
/// legitimately need ZIP64 under the entry/size caps.
fn scan_central_directory(bytes: &[u8]) -> Result<(), ZipError> {
    let eocd = locate_eocd(bytes)?;
```

- [ ] **Step 6: Update the call site to the new name**

In the same file, at line 280 (the first statement of `pub fn unpack_zip`), replace:

```rust
    scan_duplicate_names(bytes)?;
```

with:

```rust
    scan_central_directory(bytes)?;
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cd verifier-rust && cargo test -p capsule-verify`

Expected: PASS —
```
test zip_reader::tests::rejects_trailing_bytes_after_eocd ... ok
test zip_reader::tests::rejects_hidden_entry_behind_trailing_byte ... ok
test zip_reader::tests::rejects_input_too_small_for_eocd ... ok
test zip_reader::tests::rejects_archive_without_eocd_signature ... ok
test verifier::tests::trailing_byte_after_eocd_fails_closed ... ok
test result: ok. 107 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

- [ ] **Step 8: Prove the fix end-to-end through the CLI**

Run:
```bash
cd /Users/complex/repo/open-source/capsules-protocol && \
python3 -c "import pathlib; p=pathlib.Path('spec/vectors/tamper-detection/output/clean.capsule'); pathlib.Path('/tmp/padded.capsule').write_bytes(p.read_bytes()+b'\x00')" && \
cd verifier-rust && cargo run -q -p capsule-verify-cli -- verify /tmp/padded.capsule; echo "exit=$?"
```
Expected: FAIL result, exit 1 —
```
  [✗] container / parse
        invalid zip container: trailing bytes after end-of-central-directory record
Result: FAIL
exit=1
```
(Before this task the same bytes printed `Result: PASS` / `exit=0`.)

- [ ] **Step 9: Run the full lane suite for regressions**

Run: `cd verifier-rust && cargo test --workspace`

Expected: every target green — `test result: ok. 107 passed; 0 failed` (capsule-verify lib), `test result: ok. 7 passed; 0 failed` (parity_against_js_sdk), `test result: ok. 3 passed; 0 failed` (spec_registry).

- [ ] **Step 10: Record the fix in the changelog**

In `CHANGELOG.md`, insert after line 70 (the last bullet of the `### Changed` block, `  supports \`--check\`, which runs as a required JavaScript conformance target.`) and before the `## v0.6.0-prototype.1` heading on line 72:

```markdown

### Security

- **verifier-rust: a single trailing byte no longer disables container
  strictness.** `zip_reader::unpack_zip`'s raw central-directory scan used to
  return `Ok(())` whenever it could not find an end-of-central-directory
  record whose declared comment length landed exactly at EOF, deferring to
  the `zip` crate's more permissive locator. Appending one byte therefore
  switched off duplicate-name detection, ZIP64 rejection, the
  `cd_offset + cd_size == eocd` check and the EOCD entry-count cross-check,
  so a capsule carrying entries the content index does not cover verified
  `PASS` with a trusted signer. A missing, ambiguous, or trailing-byte EOCD
  is now `InvalidContainer`, matching the JS reference reader.
```

- [ ] **Step 11: Commit**

```bash
git add verifier-rust/crates/capsule-verify/src/zip_reader.rs verifier-rust/crates/capsule-verify/src/verifier.rs CHANGELOG.md
git commit -m "fix(verifier-rust): reject missing or ambiguous EOCD instead of skipping strictness

A raw central-directory scan that returned Ok(()) when no EOCD candidate
ended at EOF let one appended byte disable duplicate detection, ZIP64
rejection and the EOCD entry-count cross-check, so a capsule with hidden
entries verified PASS. locate_eocd now fails closed, matching sdk-js.

Fixes F02."
```

---

### Task 2: Cross-check the raw record count against ZipArchive's index

**Files:**
- Modify: `verifier-rust/crates/capsule-verify/src/zip_reader.rs:199-212` (post-Task-1 numbering)
- Modify: `verifier-rust/crates/capsule-verify/src/zip_reader.rs:296` (post-Task-1 numbering)
- Modify: `verifier-rust/crates/capsule-verify/src/zip_reader.rs:306-311` (post-Task-1 numbering)
- Test: `verifier-rust/crates/capsule-verify/src/zip_reader.rs:667` (post-Task-1 numbering; insert between the `}` on line 666 and the `#[test]` on line 668)

**Interfaces:**
- Consumes: `fn scan_central_directory(bytes: &[u8]) -> Result<(), ZipError>` and `fn locate_eocd(bytes: &[u8]) -> Result<usize, ZipError>` (Task 1); `ZipArchive::len(&self) -> usize`; `ZipError::InvalidContainer(String)`
- Produces: `fn cross_check_entry_count(scanned: usize, parsed: usize) -> Result<(), ZipError>`; `fn scan_central_directory(bytes: &[u8]) -> Result<usize, ZipError>` (return type changes from `()` to the number of central-directory records walked); error string `"central-directory record count disagrees with archive parser"`

- [ ] **Step 1: Write the failing tests**

Insert into the `mod tests` block of `verifier-rust/crates/capsule-verify/src/zip_reader.rs`, immediately after `rejects_archive_without_eocd_signature` ends (line 666) and before the `#[test]` on line 668:

```rust
    #[test]
    fn scan_reports_the_number_of_central_directory_records() {
        let bytes = make_zip(&[
            ("a.txt", b"1", CompressionMethod::Stored),
            ("b.txt", b"2", CompressionMethod::Stored),
            ("c.txt", b"3", CompressionMethod::Stored),
        ]);
        assert_eq!(
            scan_central_directory(&bytes).expect("scan must succeed"),
            3
        );
    }

    #[test]
    fn entry_count_cross_check_rejects_parser_disagreement() {
        assert!(cross_check_entry_count(3, 3).is_ok());
        let err = cross_check_entry_count(3, 2).expect_err("mismatch must be rejected");
        assert!(
            err.to_string()
                .contains("central-directory record count disagrees with archive parser"),
            "unexpected error: {err}"
        );
    }

```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd verifier-rust && cargo test -p capsule-verify`

Expected: FAIL — the test target does not compile:
```
error[E0308]: mismatched types
error[E0425]: cannot find function `cross_check_entry_count` in this scope
error[E0425]: cannot find function `cross_check_entry_count` in this scope
error: could not compile `capsule-verify` (lib test) due to 3 previous errors
```

- [ ] **Step 3: Add the cross-check helper**

In `verifier-rust/crates/capsule-verify/src/zip_reader.rs`, insert immediately before line 199 (the doc comment `/// Walk the RAW central directory and enforce every container rule the`), i.e. between the closing `}` of `locate_eocd` on line 197 and that doc comment:

```rust
/// Cross-check the number of central-directory records this scan walked by
/// byte range against the number `ZipArchive` indexed (which it derives
/// from the attacker-controlled EOCD count). Any disagreement means the two
/// parsers are reading different archives, so reject rather than trust the
/// more permissive one.
fn cross_check_entry_count(scanned: usize, parsed: usize) -> Result<(), ZipError> {
    if scanned != parsed {
        return Err(ZipError::InvalidContainer(format!(
            "central-directory record count disagrees with archive parser (scan {scanned}, parser {parsed})"
        )));
    }
    Ok(())
}

```

- [ ] **Step 4: Return the walked record count from the scan**

In the same file, replace the doc line and signature (lines 199-200 and 212) and the scan's final `Ok(())` (line 296). First, replace:

```rust
/// Walk the RAW central directory and enforce every container rule the
/// `zip` crate does not.
```

with:

```rust
/// Walk the RAW central directory and enforce every container rule the
/// `zip` crate does not, returning the number of records walked.
```

then replace:

```rust
fn scan_central_directory(bytes: &[u8]) -> Result<(), ZipError> {
```

with:

```rust
fn scan_central_directory(bytes: &[u8]) -> Result<usize, ZipError> {
```

then replace the function's tail (lines 291-297), whose context is the entry-count mismatch check:

```rust
    if actual_entries != total_entries {
        return Err(ZipError::InvalidContainer(format!(
            "central-directory entry count mismatch (EOCD {total_entries}, actual {actual_entries})"
        )));
    }
    Ok(())
}
```

with:

```rust
    if actual_entries != total_entries {
        return Err(ZipError::InvalidContainer(format!(
            "central-directory entry count mismatch (EOCD {total_entries}, actual {actual_entries})"
        )));
    }
    Ok(actual_entries)
}
```

- [ ] **Step 5: Wire the cross-check into `unpack_zip`**

In the same file, replace lines 306-311 — the head of `pub fn unpack_zip`:

```rust
    scan_central_directory(bytes)?;
    let cursor = Cursor::new(bytes);
    let mut archive =
        ZipArchive::new(cursor).map_err(|e| ZipError::InvalidContainer(e.to_string()))?;

    let total_entries = archive.len();
```

with:

```rust
    let scanned_entries = scan_central_directory(bytes)?;
    let cursor = Cursor::new(bytes);
    let mut archive =
        ZipArchive::new(cursor).map_err(|e| ZipError::InvalidContainer(e.to_string()))?;

    let total_entries = archive.len();
    cross_check_entry_count(scanned_entries, total_entries)?;
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd verifier-rust && cargo test -p capsule-verify`

Expected: PASS —
```
test zip_reader::tests::scan_reports_the_number_of_central_directory_records ... ok
test zip_reader::tests::entry_count_cross_check_rejects_parser_disagreement ... ok
test result: ok. 109 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

- [ ] **Step 7: Run the full lane suite for regressions**

Run: `cd verifier-rust && cargo test --workspace`

Expected: every target green — `test result: ok. 109 passed; 0 failed` (capsule-verify lib), `test result: ok. 7 passed; 0 failed` (parity_against_js_sdk), `test result: ok. 3 passed; 0 failed` (spec_registry). In particular `rejects_too_many_entries` and `rejects_understated_central_directory_count` still fail in the scan (before the cross-check runs), so their error types are unchanged.

- [ ] **Step 8: Commit**

```bash
git add verifier-rust/crates/capsule-verify/src/zip_reader.rs
git commit -m "fix(verifier-rust): cross-check scanned CD record count against ZipArchive

The raw byte-range walk is the authority on how many central-directory
records exist; ZipArchive builds its index from the EOCD's declared count.
unpack_zip now rejects any disagreement instead of trusting archive.len().

Part of F02."
```

---

### Task 3: Pin trailing-bytes-after-EOCD as a malformed-layout conformance vector

**Depends on:** F15 (sdk-py raw central-directory scan). Step 1 is a hard gate — CPython's `zipfile` opens a trailing-byte archive today, so landing this task first turns the sdk-py conformance lane red (`1 failed, 182 passed`).

**Files:**
- Create: `spec/vectors/malformed-layout/output/trailing-bytes.capsule` (written by the generator in Step 4; 2602 bytes, sha256 `fb810182f654a311c0563245947468e3e59d48f0e65b66afca3d1ab7394acb48`)
- Modify: `spec/vectors/malformed-layout/vectors.json:16` and `spec/vectors/malformed-layout/vectors.json:69-73`
- Modify: `sdk-js/tools/generate-malformed-fixtures.mjs:94-99` and `sdk-js/tools/generate-malformed-fixtures.mjs:101-103`
- Modify: `tools/check-spec-vectors.mjs:146`
- Modify: `verifier-rust/tests/spec_registry.rs:144`
- Modify: `sdk-py/tests/test_spec_registry.py:42`
- Modify: `spec/format.md:98`
- Modify: `CHANGELOG.md:37-41`
- Test: `verifier-rust/tests/spec_registry.rs` (`malformed_registry_outcomes`), `sdk-py/tests/test_spec_registry.py` (`test_malformed_registry_outcomes[trailing-bytes]`), `tools/check-spec-vectors.mjs`

**Interfaces:**
- Consumes: `writeRawZip(entries) -> Buffer` from `sdk-js/tools/rawzip.mjs`; `unpackZip(bytes)` from `sdk-js/src/zip.js`; the registry's open-stage contract `{ ok: false, stage: "open", reason, detail? }`; Rust `fn open_reason_needles(reason: &str) -> &'static [&'static str]`; Python `OPEN_REASON_PATTERNS: dict[str, str]`; JS `const OPEN_REASON`; the error strings produced by Task 1
- Produces: registry reason category `trailing_bytes`; fixture `spec/vectors/malformed-layout/output/trailing-bytes.capsule`; generator fixture spec shape `{ entries, append }` (an entry value may now be either a plain array or `{ entries, append }`)

- [ ] **Step 1: Gate — confirm the sdk-py container-strictness port (F15) has landed**

Run:
```bash
cd /Users/complex/repo/open-source/capsules-protocol && PYTHONPATH=sdk-py/src python3 -c "
import pathlib
from capsule.zip_io import unpack_zip
data = pathlib.Path('spec/vectors/tamper-detection/output/clean.capsule').read_bytes() + b'\x00'
try:
    unpack_zip(data)
    print('GATE-NOT-MET: sdk-py still opens a trailing-byte archive')
except ValueError as e:
    print('GATE-MET:', e)
"
```
Expected: `GATE-MET: <message containing "end-of-central-directory">`. If it prints `GATE-NOT-MET`, STOP: land F15 first, otherwise this task turns the Python conformance lane red.

- [ ] **Step 2: Write the failing vector (registry entry)**

In `spec/vectors/malformed-layout/vectors.json`, add the reason category — replace line 16:

```json
    "symlink_entry": "an entry's Unix mode bits mark it as a symlink",
```

with:

```json
    "symlink_entry": "an entry's Unix mode bits mark it as a symlink",
    "trailing_bytes": "the archive carries bytes the container does not account for: the end-of-central-directory record's declared comment length does not land exactly at end-of-file, so readers that locate the EOCD by scanning for the last signature see a different archive than readers that validate the comment length",
```

and add the vector — replace lines 69-74 (the `symlink-entry` object and the closing `]`):

```json
    {
      "name": "symlink-entry",
      "capsule_file": "output/symlink-entry.capsule",
      "expected": { "ok": false, "stage": "open", "reason": "symlink_entry", "detail": "link" }
    }
  ]
```

with:

```json
    {
      "name": "symlink-entry",
      "capsule_file": "output/symlink-entry.capsule",
      "expected": { "ok": false, "stage": "open", "reason": "symlink_entry", "detail": "link" }
    },
    {
      "name": "trailing-bytes",
      "capsule_file": "output/trailing-bytes.capsule",
      "expected": { "ok": false, "stage": "open", "reason": "trailing_bytes", "detail": "one 0x00 byte appended after the end-of-central-directory record" }
    }
  ]
```

- [ ] **Step 3: Run the reference-lane checker to verify it fails**

Run: `cd /Users/complex/repo/open-source/capsules-protocol && node tools/check-spec-vectors.mjs; echo "exit=$?"`

Expected: FAIL with
```
FAIL: .../spec/vectors/malformed-layout/vectors.json [trailing-bytes]: capsule_file unreadable: ENOENT: no such file or directory, open '.../output/trailing-bytes.capsule'
exit=1
```

- [ ] **Step 4: Teach the generator to emit the fixture**

In `sdk-js/tools/generate-malformed-fixtures.mjs`, replace lines 94-99 (the `symlink-entry` fixture and the closing `};` of the `fixtures` object):

```js
    // Symlink mode bits in external attrs: must reject.
    "symlink-entry.capsule": [
      ...base,
      { name: "link", data: Buffer.from("program.md", "utf8"), mode: 0o120777 },
    ],
  };
```

with:

```js
    // Symlink mode bits in external attrs: must reject.
    "symlink-entry.capsule": [
      ...base,
      { name: "link", data: Buffer.from("program.md", "utf8"), mode: 0o120777 },
    ],

    // One byte appended after the EOCD record. Every entry and the central
    // directory are intact, so a reader that locates the EOCD by scanning
    // for the last signature (Python's zipfile, Rust's `zip` crate, JSZip)
    // still opens the archive, while a reader that requires the EOCD's
    // declared comment length to land exactly at EOF refuses it. The
    // divergence is the attack: bytes the container does not account for.
    "trailing-bytes.capsule": { entries: base, append: Buffer.from([0x00]) },
  };
```

then replace lines 101-103 (the head of the emit loop):

```js
  for (const [name, entries] of Object.entries(fixtures)) {
    const path = join(OUT_DIR, name);
    const bytes = writeRawZip(entries);
```

with:

```js
  for (const [name, spec] of Object.entries(fixtures)) {
    const path = join(OUT_DIR, name);
    // A fixture is either a plain entry list or { entries, append } for
    // shapes that need raw bytes glued on after the archive proper.
    const { entries, append } = Array.isArray(spec) ? { entries: spec, append: null } : spec;
    const bytes = append ? Buffer.concat([writeRawZip(entries), append]) : writeRawZip(entries);
```

- [ ] **Step 5: Generate the fixture bytes**

Run: `cd /Users/complex/repo/open-source/capsules-protocol && node sdk-js/tools/generate-malformed-fixtures.mjs && git status --porcelain spec/vectors/malformed-layout/`

Expected: `wrote trailing-bytes.capsule (2602 bytes)` as the last line, and `git status` shows exactly one line, `?? spec/vectors/malformed-layout/output/trailing-bytes.capsule` — every pre-existing fixture regenerates byte-identically. Confirm the bytes with `shasum -a 256 spec/vectors/malformed-layout/output/trailing-bytes.capsule` → `fb810182f654a311c0563245947468e3e59d48f0e65b66afca3d1ab7394acb48`.

- [ ] **Step 6: Map the reason category in the JS reference lane**

In `tools/check-spec-vectors.mjs`, replace line 146 (the last entry of `OPEN_REASON`):

```js
  symlink_entry: /symlink/,
```

with:

```js
  symlink_entry: /symlink/,
  trailing_bytes: /end-of-central-directory/,
```

- [ ] **Step 7: Run the reference-lane checker to verify it passes**

Run: `cd /Users/complex/repo/open-source/capsules-protocol && node tools/check-spec-vectors.mjs; echo "exit=$?"`

Expected: PASS — `spec vectors: ok (281 vectors)` / `exit=0`. (sdk-js rejects the fixture with `zip scan: end-of-central-directory not found`.)

- [ ] **Step 8: Map the reason category in the Rust lane**

In `verifier-rust/tests/spec_registry.rs`, replace line 144:

```rust
        "symlink_entry" => &["symlink"],
```

with:

```rust
        "symlink_entry" => &["symlink"],
        "trailing_bytes" => &[
            "trailing bytes after end-of-central-directory",
            "end-of-central-directory record not found",
        ],
```

- [ ] **Step 9: Map the reason category in the Python lane**

In `sdk-py/tests/test_spec_registry.py`, replace line 42 (the last entry of `OPEN_REASON_PATTERNS`):

```python
    "symlink_entry": r"symlink",
```

with:

```python
    "symlink_entry": r"symlink",
    "trailing_bytes": r"end-of-central-directory",
```

- [ ] **Step 10: Record the rule in the normative spec**

In `spec/format.md`, insert after line 98 (the end of the `- File-count and total-uncompressed-size limits ... rejection.` bullet) and before the blank line 99:

```markdown
- The end-of-central-directory (EOCD) record is the archive's last record:
  its declared comment length MUST end exactly at end-of-file, and the
  central directory MUST end exactly where the EOCD begins. Bytes before
  the first local header or after the EOCD's comment are a parser
  differential — ZIP libraries variously rebase, ignore, or reject them —
  so readers reject them. A reader that cannot locate a conforming EOCD
  MUST reject the container; it MUST NOT fall back to a more permissive
  locator, because that silently disables every check above.
```

- [ ] **Step 11: Record the new vector in the changelog**

In `CHANGELOG.md`, replace lines 38-40 (inside the `**Malformed-layout vector registry.**` bullet):

```markdown
  pins open-stage rejection outcomes (missing required files, invalid
  JSON, duplicate entries, unsafe paths, non-STORED compression, symlink
  entries, missing chain file) behind a normative `stage`/`reason`
```

with:

```markdown
  pins open-stage rejection outcomes (missing required files, invalid
  JSON, duplicate entries, unsafe paths, non-STORED compression, symlink
  entries, missing chain file, trailing bytes after the
  end-of-central-directory record) behind a normative `stage`/`reason`
```

- [ ] **Step 12: Run the Rust and Python registry lanes**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/verifier-rust && cargo test --test spec_registry && cd .. && PYTHONPATH=sdk-py/src python3 -m pytest sdk-py/tests/test_spec_registry.py -q`

Expected: PASS both — `test malformed_registry_outcomes ... ok` / `test result: ok. 3 passed; 0 failed`, and pytest reporting 0 failures with `test_malformed_registry_outcomes[trailing-bytes]` collected and passing.

- [ ] **Step 13: Run the full cross-lane suites for regressions**

Run: `cd /Users/complex/repo/open-source/capsules-protocol && node sdk-js/tools/generate-malformed-fixtures.mjs --check && node tools/check-spec-vectors.mjs && (cd sdk-js && npm test) && (cd verifier-rust && cargo test --workspace) && PYTHONPATH=sdk-py/src python3 -m pytest sdk-py/tests -q`

Expected: drift check prints `ok trailing-bytes.capsule (2602 bytes)`; `spec vectors: ok (281 vectors)`; sdk-js `# pass 57  # fail 0`; cargo `109 passed` / `7 passed` / `3 passed`; pytest `183 passed` (182 pre-existing plus the new parametrization), 0 failed.

- [ ] **Step 14: Commit**

```bash
git add spec/vectors/malformed-layout/vectors.json spec/vectors/malformed-layout/output/trailing-bytes.capsule sdk-js/tools/generate-malformed-fixtures.mjs tools/check-spec-vectors.mjs verifier-rust/tests/spec_registry.rs sdk-py/tests/test_spec_registry.py spec/format.md CHANGELOG.md
git commit -m "spec(vectors): pin trailing-bytes-after-EOCD as an open-stage rejection

Adds the trailing_bytes reason category and a deterministic fixture (clean
capsule plus one 0x00 byte) so every registry-consuming lane is pinned
against the F02 shape: readers that locate the EOCD by last signature open
the archive, readers that validate the declared comment length refuse it.
format.md now states the EOCD-is-last rule normatively."
```

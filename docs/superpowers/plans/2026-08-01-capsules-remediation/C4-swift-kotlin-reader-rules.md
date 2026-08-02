# C4 — Swift and Kotlin: conditional content.enc exclusion, duplicate/symlink rejection, and spec-registry wiring

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Part of:** [Capsules pre-release remediation](./README.md) · Tier 1 (release-blocking)

**Findings closed:** F21, F16, F12, F20

**Lanes touched:** sdk-swift, sdk-kotlin, spec, sdk-js

**Tasks:** 7

**Depends on:** C3

## Global Constraints

Copied verbatim from the project state; every task below implicitly includes these.

- The project is **pre-release (v0.6 prototype)**. Breaking changes are acceptable. Do not add compatibility shims or deprecation paths.
- `sdk-js` is the **reference implementation**. Where lanes disagree and no decision says otherwise, JS defines correct behaviour.
- The chain.md step-6 actor rule resolves as: **all five verifiers enforce** (actor is in `manifest.participants` or equals `system:host`), **and builders reject at `appendEvent` time**. Not auto-registration.
- Every normative rule this plan enforces must land with a **negative conformance vector**, consumed by every lane's spec-registry test. A fix without a vector does not count as done.
- Test frameworks by lane: `sdk-js` node:test · `sdk-py` pytest · `verifier-rust` `#[test]` · `sdk-swift` XCTest · `sdk-kotlin` its existing test style.
- Never claim a command was run without running it.

## Risks

CROSS-CLUSTER — C3 also edits `sdk-swift/Sources/Capsule/Zip.swift`. Both clusters touch the SAME central-directory loop inside `CapsuleZip.unpack` (original lines 93-121). C3's work there is bounds/robustness hardening on the same reads (`read32(bytesArr, p)`, `bytesArr[(p+46)..<(p+46+nameLen)]`, `bytesArr[dataOff..<(dataOff+compSize)]` are all unbounded today and will fault on a truncated archive). This cluster only ADDS three things inside that loop: `var seen = Set<String>()` before it, `let externalAttrs = read32(bytesArr, p + 38)` alongside the existing field reads, and two rejection guards after `try assertSafePath(name)`. Land C3 first if both are in flight — its bounds guards should wrap the same reads this task adds (`p + 38` needs the same "record fits inside the central directory" precondition as `p + 42`), and then this task's diff applies as a pure insertion. If this task lands first, C3 must extend its bounds checks to cover the new `p + 38` read. The identical warning applies to `sdk-kotlin/.../Zip.kt:77-92` if C3 covers Kotlin too. Task 3 and Task 6 are the only steps at risk; Tasks 1/2/4/5/7 touch disjoint files.

EXISTING TESTS LIKELY TO FAIL / BEHAVIOUR CHANGES:
- `Manifest.buildContentIndex`'s default exclusion set changes in BOTH lanes (from "structural + content.enc" to "structural only"). Swift's `CapsuleBuilder.seal(signedAt:recipients:)` is the one caller that genuinely needs the content.enc exclusion and is fixed in Task 2 Step 4; missing it silently changes the outer content-index hash of every encrypted capsule and breaks `EncryptedRoundTripTests` + `ParityTests.testCleanEncryptedL2Verifies`/`testDecryptCleanEncryptedWithJsRecipientKey`. Kotlin has no encrypted builder, so no equivalent call site — verified by grep, `Builder.kt:114` is the only other caller.
- The `content_index_hash` check's `detail` string changes shape in both lanes when the index fails (it now appends `; file present but not in manifest index: <path>` etc.). Nothing currently asserts on that detail — `ParityTests`/`ParityTest` assert only on `.ok` — but any downstream consumer parsing the detail as a bare hash prefix would break.
- Kotlin `CapsuleReader.parse` reorders its checks: the encrypted refusal now fires before `missing chain`/`missing program.md`, and `"missing envelope"` becomes `"missing provenance/envelope.json"`. `ParityTest.jsTamperedBlobCapsuleFailsUnderKotlin` depends on the encrypted refusal and stays green (verified), but any host code matching on the old strings breaks. Pre-release, so no shim.
- Swift and Kotlin reader JSON errors change from raw `NSError`/`JsonSyntaxException` text to `"failed to parse <file>"`. Diagnostic detail is deliberately dropped in favour of a stable, lane-neutral needle; if the maintainer wants the underlying parser message kept, append it after a colon and widen the registry needle to a prefix match.

DELIBERATE LANE ALLOWANCES, PINNED BY NAME (these are the honest gaps, not silent skips): Swift's `openRejectedVerifyVectors = {missing-chain, invalid-chain-json}` and Kotlin's identical `OPEN_REJECTED_VERIFY_VECTORS` record that both readers refuse those two fixtures at open rather than at verify (their `parse` requires `chain/events.jsonl` + `program.md`), which is stricter than the registry's verify-stage expectation. Kotlin's `ENCRYPTED_VECTORS = {clean-encrypted, tampered-blob}` records that the core module refuses encrypted capsules outright, so it cannot satisfy `clean-encrypted`'s `ok: true`. All three sets assert a concrete alternative outcome, so a lane that starts *accepting* one of these fails the test — but they do mean Swift/Kotlin are not yet bit-for-bit registry-conformant, and the sets should shrink as the readers gain the missing paths.

OTHER: the new tamper vector's `error_includes: "content.enc"` is what forces the per-file content-index attribution into both lanes; dropping it would let Tasks 2/5 skip the `storedIndex`/`indexProblems` block, at the cost of Swift and Kotlin being unable to honour any `error_includes` from the registry. Regenerating `spec/vectors/tamper-detection/output/` via `generate-tamper-fixtures.mjs` rotates the throwaway keypair and rewrites `clean.capsule`, which every `malformed-layout/` fixture derives from — Task 1 Step 4 deliberately derives only the new fixture to avoid that churn, and `tools/run-conformance.mjs`'s `malformed-fixtures-regen` target (which runs the malformed generator with `--check`) is the guard that catches it if someone re-baselines without regenerating downstream.

## Validation performed while specifying this plan

The steps below were applied to a **copy of the repository outside the working tree** and executed. This is the real output from that run, not a prediction.

<details>
<summary>Expand validation log</summary>

```
Applied the full cluster on a copy outside the repo ('/tmp/work-c4/repo', 'cp -r' of the pristine tree) and ran every lane. The repo itself was never modified ('git status --porcelain' at the end shows only the pre-existing ' M .gitignore').

RED, measured on a pristine copy ('/tmp/work-c4/red') carrying only the new fixture + vector entry and the new test files:
- 'node tools/check-spec-vectors.mjs' with the vector but no fixture: 'FAIL: .../tamper-detection/vectors.json [plain-stray-content-enc]: capsule_file unreadable: ENOENT: no such file or directory, open '.../plain-stray-content-enc.capsule''
- Swift 'swift test --filter StrictReaderTests': 'Executed 3 tests, with 5 failures' — 'testPlainCapsuleWithStrayContentEncFailsContentIndex': 'XCTAssertFalse failed - a signed plain capsule with a stray content.enc must not verify' and 'XCTAssertEqual failed: ("Optional(true)") is not equal to ("Optional(false)") - content_index_hash must fail; got Optional(Capsule.VerifyCheck(name: "content_index_hash", ok: true, detail: "f42f0eb348c4…"))'; 'testDuplicateEntryNameIsRejected' and 'testSymlinkEntryIsRejected': 'XCTAssertThrowsError failed: did not throw an error'. This reproduces F21/F16/F12 and F20 in Swift exactly.
- Kotlin './gradlew --no-daemon --offline :core:test --tests 'ai.virion.capsule.core.StrictReaderTest'': '3 tests completed, 3 failed' — 'Expected an exception of class java.lang.IllegalArgumentException to be thrown, but was completed successfully.' (x2) and 'a signed plain capsule with a stray content.enc must not verify'.
- Registry-test RED measured on a third copy ('/tmp/work-c4/red2' = fixed sources with only 'Reader.swift'/'Reader.kt' reverted): Swift 'SpecRegistryTests': 'Executed 2 tests, with 1 failure' — 'invalid-manifest-json: expected reason invalid_json (any of ["failed to parse manifest.json"]); got Error Domain=NSCocoaErrorDomain Code=3840 "No string key for value in object around line 1, column 2."'. Kotlin 'SpecRegistryTest': '2 tests completed, 2 failed' — 'clean-encrypted: expected the plain-only refusal; got missing chain' and 'missing-envelope: expected reason missing_required_file (any of [missing manifest.json, missing provenance/envelope.json]); got missing envelope'.

GREEN, all five lanes plus the harness on '/tmp/work-c4/repo' with every change applied:
- Swift ('DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test'): 'Executed 31 tests, with 0 failures (0 unexpected)'.
- Kotlin ('JAVA_HOME=/opt/homebrew/opt/openjdk@17 ./gradlew --no-daemon --offline :core:test'): 'BUILD SUCCESSFUL'; parsed 'core/build/test-results/test/*.xml' → 'kotlin total tests 16 failures 0' (EnvelopeTest 2, JcsNumbersVectorTest 1, ParityTest 6, RoundTripTest 2, SpecRegistryTest 2, StrictReaderTest 3).
- JS: 'node tools/check-spec-vectors.mjs' → 'spec vectors: ok (281 vectors)'; 'npm test' in sdk-js → '# tests 57 / # pass 57 / # fail 0'.
- Python: 'PYTHONPATH=src python3 -m pytest' → '183 passed in 0.25s'; 'tests/test_spec_registry.py' alone → '18 passed' (was 17 before the new vector).
- Rust: 'cargo test' → 'parity_against_js_sdk' 7 passed, 'spec_registry' 3 passed, 0 failed.
- Cross-lane harness: 'node tools/run-conformance.mjs' → 'PASS · 10/10 passed · 3.9s total'.

Fixture determinism verified directly: re-deriving 'plain-stray-content-enc.capsule' from the checked-in 'clean.capsule' with the exact 'addInnerFile' body added to 'generate-tamper-fixtures.mjs' reproduced the checked-in bytes — 'byte-identical: true 2726 bytes'.

Pre-fix behaviour confirming the finding: on the pristine copy, 'CapsuleVerifier.verify' returned 'content_index_hash ok: true' for the stray-blob capsule in Swift, and 'v.ok == true' in Kotlin — i.e. a signed plain capsule carrying an arbitrary appended blob verified clean in both lanes.

Toolchain notes for whoever executes this: '/usr/bin/swift' on this host is CommandLineTools and has no XCTest, so 'swift test' needs 'DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer'; the first build in a copied tree also needs 'rm -rf sdk-swift/.build' because the checked-in module cache pins the original absolute path. Gradle needs 'JAVA_HOME=/opt/homebrew/opt/openjdk@17' (no JDK on the default PATH) and '--offline' when the network is unavailable. CI ('.github/workflows/conformance.yml:174,194') uses the bare 'swift test' and './gradlew --no-daemon :core:test' forms, which the plan's Run lines match.
```

</details>

---

### Task 1: Add the `plain-stray-content-enc` conformance vector and fixture

**Files:**
- Modify: `spec/vectors/tamper-detection/vectors.json:36-41`
- Modify: `sdk-js/tools/generate-tamper-fixtures.mjs:49-52`, `sdk-js/tools/generate-tamper-fixtures.mjs:148-151`, `sdk-js/tools/generate-tamper-fixtures.mjs:172`
- Create: `spec/vectors/tamper-detection/output/plain-stray-content-enc.capsule`
- Test: `tools/check-spec-vectors.mjs` (existing JS-reference registry consumer; no new test file)

**Interfaces:**
- Consumes: `unpackZip(bytes) -> Promise<Map<string, Uint8Array>>` and `packZip(files) -> Promise<Uint8Array>` from `sdk-js/src/zip.js`
- Produces: fixture `spec/vectors/tamper-detection/output/plain-stray-content-enc.capsule` (2726 bytes) and registry vector `plain-stray-content-enc`; both consumed by Tasks 2, 4, 5 and 7

- [ ] **Step 1: Write the failing test**

The registry *is* the test here — every lane's registry consumer reads it. Add the vector entry. In `spec/vectors/tamper-detection/vectors.json`, lines 36-41 currently read:

```json
    {
      "name": "tampered-blob",
      "capsule_file": "output/tampered-blob.capsule",
      "expected": { "ok": false, "failing": ["encrypted_blob"], "error_includes": "encrypted_blob_hash" }
    }
  ]
```

Replace with:

```json
    {
      "name": "tampered-blob",
      "capsule_file": "output/tampered-blob.capsule",
      "expected": { "ok": false, "failing": ["encrypted_blob"], "error_includes": "encrypted_blob_hash" }
    },
    {
      "name": "plain-stray-content-enc",
      "capsule_file": "output/plain-stray-content-enc.capsule",
      "expected": { "ok": false, "failing": ["content_index"], "error_includes": "content.enc" },
      "note": "A signed plain capsule (envelope.cipher=\"none\") carrying an unaccounted-for content.enc blob. spec/manifest.md makes the content-index exclusion of content.enc conditional on the SIGNED envelope.cipher, so the stray blob MUST be indexed and content_index verification MUST fail. The envelope signature stays valid: an attacker who appends the blob cannot re-sign, and cannot flip cipher to force the exclusion."
    }
  ]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/complex/repo/open-source/capsules-protocol && node tools/check-spec-vectors.mjs`

Expected: FAIL with `FAIL: .../spec/vectors/tamper-detection/vectors.json [plain-stray-content-enc]: capsule_file unreadable: ENOENT: no such file or directory, open '.../spec/vectors/tamper-detection/output/plain-stray-content-enc.capsule'` (exit 1)

- [ ] **Step 3: Teach the fixture generator to emit the stray-blob capsule**

In `sdk-js/tools/generate-tamper-fixtures.mjs`, insert the new helper immediately above the existing `rewriteInnerFile` doc comment (currently line 49):

```js
/**
 * Rebuild a capsule ZIP with one extra entry added. Preserves all other
 * entries verbatim. Used for the stray-blob fixture, where the attacker
 * appends a file but cannot re-sign the envelope.
 */
async function addInnerFile(capsuleBytes, path, data) {
  const files = await unpackZip(capsuleBytes);
  if (files.has(path)) throw new Error(`entry already present in capsule: ${path}`);
  files.set(path, Buffer.from(data));
  return Buffer.from(await packZip(files));
}
```

Then replace lines 148-151 (the `tampered-blob` block) with:

```js
  // tampered-blob: flip a byte in the encrypted content.enc blob.
  const tamperedBlob = await rewriteInnerFile(cleanEncrypted, "content.enc", (b) =>
    flipByte(b, Math.floor(b.length / 2)),
  );

  // plain-stray-content-enc: a signed PLAIN capsule (cipher="none") with an
  // unaccounted-for content.enc appended. spec/manifest.md keys the
  // content-index exclusion of content.enc off the SIGNED envelope.cipher, so
  // the stray blob must be indexed and content_index verification must fail.
  // The envelope signature stays valid: the attacker cannot re-sign, and
  // cannot flip cipher to force the exclusion.
  const plainStrayContentEnc = await addInnerFile(
    cleanPlain,
    "content.enc",
    Buffer.from("stray unaccounted-for blob\n", "utf8"),
  );
```

And in the `artifacts` array, replace line 172 with:

```js
    ["tampered-blob.capsule", tamperedBlob],
    ["plain-stray-content-enc.capsule", plainStrayContentEnc],
```

- [ ] **Step 4: Produce the fixture bytes without re-baselining the keypair**

`generate-tamper-fixtures.mjs` rotates the throwaway keypair on every run and would churn `keys.json`, `clean.capsule`, and every `malformed-layout/` fixture derived from it. Derive only the new fixture, using exactly the `addInnerFile` body added in Step 3:

```bash
cd /Users/complex/repo/open-source/capsules-protocol && node --input-type=module -e '
import { readFile, writeFile } from "node:fs/promises";
import { packZip, unpackZip } from "./sdk-js/src/zip.js";
const CLEAN = "spec/vectors/tamper-detection/output/clean.capsule";
const OUT = "spec/vectors/tamper-detection/output/plain-stray-content-enc.capsule";
const files = await unpackZip(await readFile(CLEAN));
if (files.has("content.enc")) throw new Error("entry already present in capsule: content.enc");
files.set("content.enc", Buffer.from("stray unaccounted-for blob\n", "utf8"));
const bytes = Buffer.from(await packZip(files));
await writeFile(OUT, bytes);
console.log("wrote", bytes.length, "bytes");
'
```

Expected: `wrote 2726 bytes`

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd /Users/complex/repo/open-source/capsules-protocol && node tools/check-spec-vectors.mjs`

Expected: PASS — `spec vectors: ok (281 vectors)`

- [ ] **Step 6: Run the full JS/Python/Rust lanes for regressions**

Run: `cd /Users/complex/repo/open-source/capsules-protocol && node tools/run-conformance.mjs && (cd sdk-py && PYTHONPATH=src python3 -m pytest -q) && (cd verifier-rust && cargo test)`

Expected: `PASS · 10/10 passed`; `183 passed`; Rust `parity_against_js_sdk` 7 passed and `spec_registry` 3 passed, 0 failed. All three lanes already implement the cipher-keyed exclusion (`sdk-js/src/verifier.js:132`, `sdk-py/src/capsule/verifier.py:136`, `verifier-rust/.../verifier.rs:490`), so the new vector is green for them without code changes.

- [ ] **Step 7: Commit**
```bash
git add spec/vectors/tamper-detection/vectors.json spec/vectors/tamper-detection/output/plain-stray-content-enc.capsule sdk-js/tools/generate-tamper-fixtures.mjs
git commit -m "test(spec): pin a signed plain capsule carrying a stray content.enc"
```

---

### Task 2: Swift — key the `content.enc` content-index exclusion off the signed `envelope.cipher`

**Files:**
- Modify: `sdk-swift/Sources/Capsule/Manifest.swift:5-11`, `sdk-swift/Sources/Capsule/Manifest.swift:29-33`
- Modify: `sdk-swift/Sources/Capsule/Builder.swift:296-304`
- Modify: `sdk-swift/Sources/Capsule/Verifier.swift:203-214`
- Test: `sdk-swift/Tests/CapsuleTests/StrictReaderTests.swift`

**Interfaces:**
- Consumes: fixture `spec/vectors/tamper-detection/output/plain-stray-content-enc.capsule` (Task 1); `CapsuleVerifier.verify(_ bytes: Data, allowlist: Set<String>) -> CapsuleVerification`
- Produces: `Manifest.STRUCTURAL_EXCLUDED: Set<String>`, `Manifest.CONTENT_INDEX_EXCLUDED: Set<String>`, `Manifest.contentIndexExclusions(_ encrypted: Bool) -> Set<String>`, `Manifest.buildContentIndex(_ files: [(path: String, data: Data)], excluded: Set<String> = Manifest.STRUCTURAL_EXCLUDED) -> ContentIndex`; a `content_index_hash` check whose `detail` names offending paths (consumed by Task 4)

- [ ] **Step 1: Write the failing test**

Create `sdk-swift/Tests/CapsuleTests/StrictReaderTests.swift`:

```swift
// Reader strictness against the normative container rules:
//   - spec/manifest.md: a signed PLAIN capsule may not smuggle an
//     unaccounted-for content.enc past the content index
//   - spec/format.md: duplicate entry names are rejected on the RAW stored
//     central-directory name, before any dictionary collapse picks a winner
//   - spec/format.md: symlink entries are rejected
//
// The fixtures are the shared conformance corpus under spec/vectors/, so
// this lane refuses exactly what the JS/Python/Rust lanes refuse.

import Foundation
import XCTest
@testable import Capsule

final class StrictReaderTests: XCTestCase {

    private static let vectorsDir: URL = {
        URL(fileURLWithPath: #file)
            .deletingLastPathComponent()  // CapsuleTests/
            .deletingLastPathComponent()  // Tests/
            .deletingLastPathComponent()  // sdk-swift/
            .deletingLastPathComponent()  // <repo-root>/
            .appendingPathComponent("spec/vectors")
    }()

    private func fixture(_ relative: String) throws -> Data {
        try Data(contentsOf: Self.vectorsDir.appendingPathComponent(relative))
    }

    private func originatorPubkey() throws -> String {
        let data = try fixture("tamper-detection/output/keys.json")
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        return try XCTUnwrap((obj?["originator"] as? [String: Any])?["publicKey"] as? String)
    }

    /// spec/manifest.md: the `content.enc` content-index exclusion is
    /// conditional on the SIGNED `envelope.cipher`. A plain capsule
    /// (`cipher: "none"`) carrying a `content.enc` must index it, so the
    /// stray blob breaks content_index while the signature stays valid.
    func testPlainCapsuleWithStrayContentEncFailsContentIndex() throws {
        let bytes = try fixture("tamper-detection/output/plain-stray-content-enc.capsule")
        let v = CapsuleVerifier.verify(bytes, allowlist: [try originatorPubkey()])
        XCTAssertFalse(v.ok, "a signed plain capsule with a stray content.enc must not verify")
        let ci = v.checks.first(where: { $0.name == "content_index_hash" })
        XCTAssertEqual(ci?.ok, false,
                       "content_index_hash must fail; got \(String(describing: ci))")
        XCTAssertTrue(ci?.detail.contains("content.enc") ?? false,
                      "content_index detail should name the stray blob; got \(ci?.detail ?? "nil")")
        // The signature itself is untouched — an attacker cannot re-sign.
        XCTAssertEqual(v.checks.first(where: { $0.name == "envelope_signature" })?.ok, true,
                       "envelope signature should still be valid")
    }

    /// spec/format.md: duplicate entry names are a parser differential and
    /// must be rejected by the reader.
    func testDuplicateEntryNameIsRejected() throws {
        let bytes = try fixture("malformed-layout/output/duplicate-entry.capsule")
        XCTAssertThrowsError(try CapsuleZip.unpack(bytes)) { error in
            XCTAssertTrue("\(error)".contains("duplicate entry"),
                          "expected a duplicate-entry rejection; got \(error)")
        }
        XCTAssertFalse(CapsuleVerifier.verify(bytes).ok,
                       "duplicate-entry.capsule must not verify")
    }

    /// spec/format.md: symlink entries are rejected as ZIP-slip protection.
    func testSymlinkEntryIsRejected() throws {
        let bytes = try fixture("malformed-layout/output/symlink-entry.capsule")
        XCTAssertThrowsError(try CapsuleZip.unpack(bytes)) { error in
            XCTAssertTrue("\(error)".contains("symlink"),
                          "expected a symlink rejection; got \(error)")
        }
        XCTAssertFalse(CapsuleVerifier.verify(bytes).ok,
                       "symlink-entry.capsule must not verify")
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-swift && swift test --filter StrictReaderTests/testPlainCapsuleWithStrayContentEncFailsContentIndex`

(If `swift test` reports `no such module 'XCTest'`, this host has CommandLineTools selected — prefix with `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`.)

Expected: FAIL with `XCTAssertFalse failed - a signed plain capsule with a stray content.enc must not verify`, followed by `XCTAssertEqual failed: ("Optional(true)") is not equal to ("Optional(false)") - content_index_hash must fail; got Optional(Capsule.VerifyCheck(name: "content_index_hash", ok: true, detail: "f42f0eb348c4…"))`

- [ ] **Step 3: Split the exclusion set and add the cipher-keyed selector**

In `sdk-swift/Sources/Capsule/Manifest.swift`, replace lines 5-11:

```swift
public enum Manifest {
    /// Excluded from content_index.files (see manifest.md).
    public static let CONTENT_INDEX_EXCLUDED: Set<String> = [
        "manifest.json",
        "provenance/envelope.json",
        "content.enc",
    ]
```

with:

```swift
public enum Manifest {
    /// Excluded from content_index.files by structural necessity, for every
    /// capsule regardless of profile:
    ///   - manifest.json: the index lives inside it (would be circular)
    ///   - provenance/envelope.json: it commits to the index hash (circular)
    public static let STRUCTURAL_EXCLUDED: Set<String> = [
        "manifest.json",
        "provenance/envelope.json",
    ]

    /// `content.enc` is excluded from the content index ONLY for encrypted
    /// capsules, where it is bound separately by
    /// `envelope.encrypted_blob_hash`. In a plain capsule (`cipher: "none"`)
    /// a `content.enc` entry MUST be indexed like any other file, so a signed
    /// plain capsule cannot carry an unaccounted-for blob past verification
    /// (spec/manifest.md).
    public static let CONTENT_INDEX_EXCLUDED: Set<String> =
        STRUCTURAL_EXCLUDED.union(["content.enc"])

    /// Choose the content-index exclusion set for the capsule's profile.
    /// `encrypted` must be derived from the SIGNED `envelope.cipher`, never
    /// from the presence of a `content.enc` file.
    public static func contentIndexExclusions(_ encrypted: Bool) -> Set<String> {
        encrypted ? CONTENT_INDEX_EXCLUDED : STRUCTURAL_EXCLUDED
    }
```

Then replace lines 29-33 (the `buildContentIndex` doc comment, signature, and filter):

```swift
    /// Builds content_index over a sorted list of (path, bytes), excluding
    /// the three reserved files.
    public static func buildContentIndex(_ files: [(path: String, data: Data)]) -> ContentIndex {
        var entries: [(path: String, sha256: String)] = []
        for (path, data) in files where !CONTENT_INDEX_EXCLUDED.contains(path) {
```

with:

```swift
    /// Builds content_index over a sorted list of (path, bytes), skipping
    /// `excluded`. The default is the structural-only set; callers building
    /// or verifying an ENCRYPTED capsule pass
    /// `Manifest.contentIndexExclusions(true)`.
    public static func buildContentIndex(
        _ files: [(path: String, data: Data)],
        excluded: Set<String> = Manifest.STRUCTURAL_EXCLUDED
    ) -> ContentIndex {
        var entries: [(path: String, sha256: String)] = []
        for (path, data) in files where !excluded.contains(path) {
```

- [ ] **Step 4: Make the encrypted builder request the exclusion explicitly**

The default is now structural-only, so `seal(signedAt:recipients:)` must ask for the `content.enc` exclusion. In `sdk-swift/Sources/Capsule/Builder.swift`, replace lines 296-304:

```swift
        // 5) Outer manifest + envelope. The outer content_index covers
        // only skills/decryption/decryption.json — manifest.json,
        // provenance/envelope.json, and content.enc are excluded from the
        // index by `buildContentIndex` (see spec/manifest.md).
        let outerSidecars: [(String, Data)] = [
            ("skills/decryption/decryption.json", decryptionMetaBytes),
            ("content.enc", contentEnc),
        ]
        let outerContentIndex = Manifest.buildContentIndex(outerSidecars)
```

with:

```swift
        // 5) Outer manifest + envelope. The outer content_index covers
        // only skills/decryption/decryption.json — manifest.json,
        // provenance/envelope.json, and (because this capsule declares a
        // cipher) content.enc are excluded. The content.enc exclusion is
        // requested explicitly here: it is conditional on the signed
        // envelope.cipher, not on file presence (see spec/manifest.md).
        let outerSidecars: [(String, Data)] = [
            ("skills/decryption/decryption.json", decryptionMetaBytes),
            ("content.enc", contentEnc),
        ]
        let outerContentIndex = Manifest.buildContentIndex(
            outerSidecars,
            excluded: Manifest.contentIndexExclusions(true)
        )
```

- [ ] **Step 5: Key the verifier off `envelope.cipher` and attribute failures per file**

In `sdk-swift/Sources/Capsule/Verifier.swift`, replace lines 203-214:

```swift
        // content_index
        var indexInputs: [(String, Data)] = []
        for (path, data) in parsed.files where !Manifest.CONTENT_INDEX_EXCLUDED.contains(path) {
            indexInputs.append((path, data))
        }
        let ci = Manifest.buildContentIndex(indexInputs)
        if let storedMf = lookupString(parsed.manifest, ["content_index", "index_hash"]),
           let storedEnv = lookupString(parsed.envelope, ["content_index_hash"]) {
            record("content_index_hash",
                   ci.indexHash == storedMf && ci.indexHash == storedEnv,
                   String(ci.indexHash.prefix(12)) + "…")
        }
```

with:

```swift
        // content_index. `content.enc` drops out of the index only when the
        // SIGNED envelope declares a cipher (it is bound instead by
        // envelope.encrypted_blob_hash). Keying off file presence would let
        // an attacker append a stray blob to a signed plain capsule and have
        // it excluded for free; keying off the signed cipher means the stray
        // blob is indexed here and fails verification. See spec/manifest.md.
        let indexCipher = lookupString(parsed.envelope, ["cipher"]) ?? "none"
        let excluded = Manifest.contentIndexExclusions(indexCipher != "none")
        var indexInputs: [(String, Data)] = []
        for (path, data) in parsed.files where !excluded.contains(path) {
            indexInputs.append((path, data))
        }
        let ci = Manifest.buildContentIndex(indexInputs, excluded: excluded)
        // Per-file attribution, so a failing index names the offending paths
        // instead of only reporting a hash mismatch (mirrors the JS
        // reference's contentIndex.errors).
        var storedIndex: [String: String] = [:]
        if case .object(let mfPairs) = parsed.manifest,
           let civ = mfPairs.first(where: { $0.0 == "content_index" })?.1,
           case .object(let ciPairs) = civ,
           let filesV = ciPairs.first(where: { $0.0 == "files" })?.1,
           case .array(let rows) = filesV
        {
            for row in rows {
                guard case .object(let cols) = row,
                      let pv = cols.first(where: { $0.0 == "path" })?.1,
                      case .string(let path) = pv,
                      let hv = cols.first(where: { $0.0 == "sha256" })?.1,
                      case .string(let hash) = hv
                else { continue }
                storedIndex[path] = hash
            }
        }
        var indexProblems: [String] = []
        for f in ci.files {
            guard let want = storedIndex[f.path] else {
                indexProblems.append("file present but not in manifest index: \(f.path)")
                continue
            }
            if want != f.sha256 {
                indexProblems.append("file hash mismatch: \(f.path)")
            }
        }
        for path in storedIndex.keys.sorted() where !ci.files.contains(where: { $0.path == path }) {
            indexProblems.append("file in manifest index but missing from package: \(path)")
        }
        if let storedMf = lookupString(parsed.manifest, ["content_index", "index_hash"]),
           let storedEnv = lookupString(parsed.envelope, ["content_index_hash"]) {
            let hashesMatch = ci.indexHash == storedMf && ci.indexHash == storedEnv
            let short = String(ci.indexHash.prefix(12)) + "…"
            record("content_index_hash",
                   hashesMatch && indexProblems.isEmpty,
                   indexProblems.isEmpty ? short : ([short] + indexProblems).joined(separator: "; "))
        }
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-swift && swift test --filter StrictReaderTests/testPlainCapsuleWithStrayContentEncFailsContentIndex`

Expected: PASS — `Executed 1 test, with 0 failures`

- [ ] **Step 7: Run the full lane suite for regressions**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-swift && swift test`

Expected: `Executed 30 tests, with 0 failures (0 unexpected)` — the 26 pre-existing tests (`EncryptedRoundTripTests` 8, `EncryptionPrimitiveTests` 8, `JCSNumbersVectorTests` 1, `ParityTests` 7, `RoundTripTests` 2) plus `StrictReaderTests`' 3, of which the duplicate/symlink two still fail until Task 3. Confirm no *pre-existing* test regressed — in particular `ParityTests.testCleanEncryptedL2Verifies` and `EncryptedRoundTripTests` must stay green, since they exercise the encrypted exclusion path changed in Step 4.

- [ ] **Step 8: Commit**
```bash
git add sdk-swift/Sources/Capsule/Manifest.swift sdk-swift/Sources/Capsule/Builder.swift sdk-swift/Sources/Capsule/Verifier.swift sdk-swift/Tests/CapsuleTests/StrictReaderTests.swift
git commit -m "fix(sdk-swift): key the content.enc index exclusion off the signed envelope.cipher"
```

---

### Task 3: Swift — reject duplicate entry names and symlink entries on the raw central directory

**Files:**
- Modify: `sdk-swift/Sources/Capsule/Zip.swift:93-110`
- Test: `sdk-swift/Tests/CapsuleTests/StrictReaderTests.swift` (the two tests written in Task 2, Step 1)

**Interfaces:**
- Consumes: `CapsuleZip.unpack(_ bytes: Data) throws -> [(path: String, data: Data)]`
- Produces: `CapsuleError.malformed("zip: duplicate entry: <name>")` and `CapsuleError.malformed("zip entry is a symlink: <name>")` (needle strings consumed by Task 4)

- [ ] **Step 1: Write the failing test**

Already written in Task 2, Step 1: `testDuplicateEntryNameIsRejected` and `testSymlinkEntryIsRejected` in `sdk-swift/Tests/CapsuleTests/StrictReaderTests.swift`. No new code.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-swift && swift test --filter StrictReaderTests/testDuplicateEntryNameIsRejected`

Expected: FAIL with `StrictReaderTests.swift:58: error: -[CapsuleTests.StrictReaderTests testDuplicateEntryNameIsRejected] : XCTAssertThrowsError failed: did not throw an error`

- [ ] **Step 3: Track seen names and read the external attributes in `unpack`**

In `sdk-swift/Sources/Capsule/Zip.swift`, replace lines 93-110:

```swift
        var p = cdOffset
        var out: [(String, Data)] = []
        for _ in 0..<cdCount {
            guard read32(bytesArr, p) == 0x02014b50 else {
                throw CapsuleError.malformed("zip: bad CD signature")
            }
            let compression = read16(bytesArr, p + 10)
            let compSize = Int(read32(bytesArr, p + 20))
            let uncompSize = Int(read32(bytesArr, p + 24))
            let nameLen = Int(read16(bytesArr, p + 28))
            let extraLen = Int(read16(bytesArr, p + 30))
            let commentLen = Int(read16(bytesArr, p + 32))
            let localOff = Int(read32(bytesArr, p + 42))
            guard compression == 0 else { throw CapsuleError.malformed("zip: only STORED supported") }
            guard compSize == uncompSize else { throw CapsuleError.malformed("zip: STORED size mismatch") }
            let name = String(decoding: Array(bytesArr[(p + 46)..<(p + 46 + nameLen)]), as: UTF8.self)
            try assertSafePath(name)
            p += 46 + nameLen + extraLen + commentLen
```

with:

```swift
        var p = cdOffset
        var out: [(String, Data)] = []
        // Entry-name and entry-shape checks run on the name as stored in the
        // central directory, before any map/dictionary collapse — a reader
        // that dedupes on load silently accepts archives other readers reject
        // (spec/format.md "Container properties").
        var seen = Set<String>()
        for _ in 0..<cdCount {
            guard read32(bytesArr, p) == 0x02014b50 else {
                throw CapsuleError.malformed("zip: bad CD signature")
            }
            let compression = read16(bytesArr, p + 10)
            let compSize = Int(read32(bytesArr, p + 20))
            let uncompSize = Int(read32(bytesArr, p + 24))
            let nameLen = Int(read16(bytesArr, p + 28))
            let extraLen = Int(read16(bytesArr, p + 30))
            let commentLen = Int(read16(bytesArr, p + 32))
            let externalAttrs = read32(bytesArr, p + 38)
            let localOff = Int(read32(bytesArr, p + 42))
            guard compression == 0 else { throw CapsuleError.malformed("zip: only STORED supported") }
            guard compSize == uncompSize else { throw CapsuleError.malformed("zip: STORED size mismatch") }
            let name = String(decoding: Array(bytesArr[(p + 46)..<(p + 46 + nameLen)]), as: UTF8.self)
            try assertSafePath(name)
            // Duplicate names are a parser differential (ZIP libraries
            // disagree on which copy wins), so a signed capsule must never
            // contain one.
            guard !seen.contains(name) else {
                throw CapsuleError.malformed("zip: duplicate entry: \(name)")
            }
            seen.insert(name)
            // Unix mode bits live in the high 16 bits of the external attrs.
            let mode = (externalAttrs >> 16) & 0xFFFF
            if (mode & 0o170000) == 0o120000 {
                throw CapsuleError.malformed("zip entry is a symlink: \(name)")
            }
            p += 46 + nameLen + extraLen + commentLen
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-swift && swift test --filter StrictReaderTests`

Expected: PASS — `Executed 3 tests, with 0 failures (0 unexpected)`

- [ ] **Step 5: Run the full lane suite for regressions**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-swift && swift test`

Expected: `Executed 30 tests, with 0 failures (0 unexpected)` — every suite green, including `RoundTripTests` and `EncryptedRoundTripTests`, which round-trip through `CapsuleZip.pack`/`unpack`.

- [ ] **Step 6: Commit**
```bash
git add sdk-swift/Sources/Capsule/Zip.swift
git commit -m "fix(sdk-swift): reject duplicate entry names and symlink entries on the raw central directory"
```

---

### Task 4: Swift — consume the spec outcome registries in the test suite

**Files:**
- Create: `sdk-swift/Tests/CapsuleTests/SpecRegistryTests.swift`
- Modify: `sdk-swift/Sources/Capsule/Reader.swift:93-94`, `sdk-swift/Sources/Capsule/Reader.swift:122-125`, `sdk-swift/Sources/Capsule/Reader.swift:346`
- Test: `sdk-swift/Tests/CapsuleTests/SpecRegistryTests.swift`

**Interfaces:**
- Consumes: `spec/vectors/tamper-detection/vectors.json` and `spec/vectors/malformed-layout/vectors.json`; `CapsuleReader.parse(_ bytes: Data) throws -> ParsedCapsule`; `CapsuleVerifier.verify(_:allowlist:)`; the `zip: duplicate entry` / `zip entry is a symlink` messages from Task 3
- Produces: `CapsuleReader.parseJSONFile(_ data: Data, name: String) throws -> JCSValue` (internal); reader error `"failed to parse manifest.json"`

- [ ] **Step 1: Write the failing test**

Create `sdk-swift/Tests/CapsuleTests/SpecRegistryTests.swift`:

```swift
// Registry-driven conformance against spec/vectors.
//
// Mirrors sdk-py/tests/test_spec_registry.py and
// verifier-rust/tests/spec_registry.rs: this lane reads the
// language-neutral outcome registries directly, so Swift tracks the same
// normative expectations as the JS reference lane without hand-copied
// assertions:
//
//   - tamper-detection/vectors.json   (verify-stage outcomes)
//   - malformed-layout/vectors.json   (open-stage reasons + verify-stage)
//
// The registry's `reason` categories are normative; the substring table
// below maps each category onto this lane's error messages.

import Foundation
import XCTest
@testable import Capsule

final class SpecRegistryTests: XCTestCase {

    /// Walks up from this file to the repo root, matching ParityTests.
    private static let vectorsDir: URL = {
        URL(fileURLWithPath: #file)
            .deletingLastPathComponent()  // CapsuleTests/
            .deletingLastPathComponent()  // Tests/
            .deletingLastPathComponent()  // sdk-swift/
            .deletingLastPathComponent()  // <repo-root>/
            .appendingPathComponent("spec/vectors")
    }()

    // MARK: - Registry plumbing

    private func loadJSON(_ url: URL) throws -> [String: Any] {
        let data = try Data(contentsOf: url)
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            XCTFail("not a JSON object: \(url.path)")
            throw CocoaError(.fileReadCorruptFile)
        }
        return obj
    }

    /// Resolve the collection's allowlist: an inline hex key, or the
    /// originator key in a referenced keys.json.
    private func allowlist(_ doc: [String: Any], base: URL) throws -> Set<String> {
        if let k = doc["originator_public_key_hex"] as? String { return [k] }
        if let kf = doc["keys_file"] as? String {
            let keys = try loadJSON(base.appendingPathComponent(kf).standardizedFileURL)
            if let pk = (keys["originator"] as? [String: Any])?["publicKey"] as? String {
                return [pk]
            }
        }
        return []
    }

    /// Per-lane mapping of the registry's normative open-stage reason
    /// categories onto this lane's `CapsuleError.malformed` messages.
    private func openReasonNeedles(_ reason: String) -> [String] {
        switch reason {
        case "missing_required_file":
            return ["missing manifest.json", "missing provenance/envelope.json"]
        case "invalid_json":
            return ["failed to parse manifest.json"]
        case "duplicate_entry":
            return ["duplicate entry"]
        case "unsafe_path":
            return ["zip path traversal", "zip path: absolute"]
        case "unsupported_compression":
            return ["only STORED supported"]
        case "symlink_entry":
            return ["symlink"]
        default:
            XCTFail("unknown open-stage reason \(reason)")
            return []
        }
    }

    /// Registry `failing` area → this lane's check name.
    private static let areaCheck: [String: String] = [
        "content_index": "content_index_hash",
        "chain": "chain",
        "envelope": "envelope_signature",
        "encrypted_blob": "encrypted_blob_hash",
    ]

    /// Verify-stage vectors that THIS lane legitimately rejects at OPEN:
    /// `CapsuleReader.parse` requires chain/events.jsonl and program.md
    /// before it hands back a ParsedCapsule, so a capsule with a missing or
    /// unparseable chain never reaches the per-area checks. Refusing earlier
    /// is strictly stronger than the registry's ok=false requirement. Pinned
    /// by name so a lane that starts *accepting* one of these fails here.
    private static let openRejectedVerifyVectors: Set<String> = [
        "missing-chain",
        "invalid-chain-json",
    ]

    private func haystack(_ v: CapsuleVerification) -> String {
        v.checks.map { "\($0.name) \($0.detail)" }.joined(separator: " ")
    }

    private func assertVerifyOutcome(_ name: String,
                                     _ expected: [String: Any],
                                     _ v: CapsuleVerification) {
        let expectedOk = (expected["ok"] as? Bool) ?? true
        XCTAssertEqual(
            v.ok, expectedOk,
            "\(name): expected ok=\(expectedOk); failing checks: " +
            v.checks.filter { !$0.ok }.map { "\($0.name):\($0.detail)" }.joined(separator: ", ")
        )
        for area in (expected["failing"] as? [String]) ?? [] {
            guard let checkName = Self.areaCheck[area] else {
                XCTFail("\(name): unknown failing area \(area)")
                continue
            }
            let c = v.checks.first(where: { $0.name == checkName })
            XCTAssertNotNil(c, "\(name): expected a \(checkName) check entry")
            XCTAssertEqual(
                c?.ok, false,
                "\(name): expected \(checkName) to fail; got \(haystack(v))"
            )
        }
        if let needle = expected["error_includes"] as? String {
            XCTAssertTrue(
                haystack(v).contains(needle),
                "\(name): expected an error containing \(needle); got \(haystack(v))"
            )
        }
    }

    // MARK: - tamper-detection/vectors.json

    func testTamperRegistryOutcomes() throws {
        let path = Self.vectorsDir.appendingPathComponent("tamper-detection/vectors.json")
        let doc = try loadJSON(path)
        let base = path.deletingLastPathComponent()
        let keys = try allowlist(doc, base: base)
        let vectors = (doc["vectors"] as? [[String: Any]]) ?? []
        XCTAssertFalse(vectors.isEmpty, "tamper-detection registry is empty")
        for vector in vectors {
            let name = vector["name"] as? String ?? "<unnamed>"
            let file = try XCTUnwrap(vector["capsule_file"] as? String, "\(name): capsule_file")
            let expected = try XCTUnwrap(vector["expected"] as? [String: Any], "\(name): expected")
            let bytes = try Data(contentsOf: base.appendingPathComponent(file))
            assertVerifyOutcome(name, expected, CapsuleVerifier.verify(bytes, allowlist: keys))
        }
    }

    // MARK: - malformed-layout/vectors.json

    func testMalformedRegistryOutcomes() throws {
        let path = Self.vectorsDir.appendingPathComponent("malformed-layout/vectors.json")
        let doc = try loadJSON(path)
        let base = path.deletingLastPathComponent()
        let keys = try allowlist(doc, base: base)
        let vectors = (doc["vectors"] as? [[String: Any]]) ?? []
        XCTAssertFalse(vectors.isEmpty, "malformed-layout registry is empty")
        for vector in vectors {
            let name = vector["name"] as? String ?? "<unnamed>"
            let file = try XCTUnwrap(vector["capsule_file"] as? String, "\(name): capsule_file")
            let expected = try XCTUnwrap(vector["expected"] as? [String: Any], "\(name): expected")
            let bytes = try Data(contentsOf: base.appendingPathComponent(file))

            let isOpenStage = (expected["stage"] as? String) == "open"
                || Self.openRejectedVerifyVectors.contains(name)
            if isOpenStage {
                let reason = (expected["stage"] as? String) == "open"
                    ? try XCTUnwrap(expected["reason"] as? String, "\(name): reason")
                    : nil
                var thrown: Error?
                do { _ = try CapsuleReader.parse(bytes) } catch { thrown = error }
                let err = try XCTUnwrap(thrown, "\(name): reader must refuse this container")
                if let reason {
                    let needles = openReasonNeedles(reason)
                    XCTAssertTrue(
                        needles.contains(where: { "\(err)".contains($0) }),
                        "\(name): expected reason \(reason) (any of \(needles)); got \(err)"
                    )
                }
                // Fail-closed at the verifier surface too.
                XCTAssertFalse(CapsuleVerifier.verify(bytes, allowlist: keys).ok,
                               "\(name): open-stage fixture must not verify")
                continue
            }
            assertVerifyOutcome(name, expected, CapsuleVerifier.verify(bytes, allowlist: keys))
        }
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-swift && swift test --filter SpecRegistryTests`

Expected: FAIL with `SpecRegistryTests.swift:173: error: -[CapsuleTests.SpecRegistryTests testMalformedRegistryOutcomes] : XCTAssertTrue failed - invalid-manifest-json: expected reason invalid_json (any of ["failed to parse manifest.json"]); got Error Domain=NSCocoaErrorDomain Code=3840 "No string key for value in object around line 1, column 2." UserInfo={NSDebugDescription=No string key for value in object around line 1, column 2., NSJSONSerializationErrorIndex=2}` — `Executed 2 tests, with 1 failure`

- [ ] **Step 3: Attribute JSON parse failures to the offending file**

In `sdk-swift/Sources/Capsule/Reader.swift`, replace lines 93-94:

```swift
        let manifest = try parseJSON(mfBytes)
        let envelope = try parseJSON(envBytes)
```

with:

```swift
        let manifest = try parseJSONFile(mfBytes, name: "manifest.json")
        let envelope = try parseJSONFile(envBytes, name: "provenance/envelope.json")
```

Replace lines 122-125:

```swift
        var events: [JCSValue] = []
        for raw in evBytes.split(separator: 0x0A) where !raw.isEmpty {
            events.append(try parseJSON(Data(raw)))
        }
```

with:

```swift
        var events: [JCSValue] = []
        for raw in evBytes.split(separator: 0x0A) where !raw.isEmpty {
            events.append(try parseJSONFile(Data(raw), name: "chain/events.jsonl"))
        }
```

And insert the helper immediately above `static func parseJSON(_ data: Data) throws -> JCSValue {` (currently line 346):

```swift
    /// `parseJSON` with the offending file named in the error, so a reader
    /// rejection can be attributed to a specific document (mirrors the Rust
    /// verifier's "failed to parse manifest.json").
    static func parseJSONFile(_ data: Data, name: String) throws -> JCSValue {
        do { return try parseJSON(data) }
        catch { throw CapsuleError.malformed("failed to parse \(name)") }
    }

```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-swift && swift test --filter SpecRegistryTests`

Expected: PASS — `Executed 2 tests, with 0 failures (0 unexpected)`

- [ ] **Step 5: Run the full lane suite for regressions**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-swift && swift test`

Expected: `Executed 31 tests, with 0 failures (0 unexpected)` across `EncryptedRoundTripTests` (8), `EncryptionPrimitiveTests` (8), `JCSNumbersVectorTests` (1), `ParityTests` (7), `RoundTripTests` (2), `SpecRegistryTests` (2), `StrictReaderTests` (3)

- [ ] **Step 6: Commit**
```bash
git add sdk-swift/Tests/CapsuleTests/SpecRegistryTests.swift sdk-swift/Sources/Capsule/Reader.swift
git commit -m "test(sdk-swift): drive conformance from the spec outcome registries"
```

---

### Task 5: Kotlin — key the `content.enc` content-index exclusion off the signed `envelope.cipher`

**Files:**
- Modify: `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Manifest.kt:5-8`, `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Manifest.kt:23-25`
- Modify: `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Verifier.kt:60-68`
- Test: `sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/StrictReaderTest.kt`

**Interfaces:**
- Consumes: fixture `spec/vectors/tamper-detection/output/plain-stray-content-enc.capsule` (Task 1); `CapsuleVerifier.verify(bytes: ByteArray, allowlist: Set<String>): CapsuleVerification`
- Produces: `Manifest.STRUCTURAL_EXCLUDED: Set<String>`, `Manifest.CONTENT_INDEX_EXCLUDED: Set<String>`, `Manifest.contentIndexExclusions(encrypted: Boolean): Set<String>`, `Manifest.buildContentIndex(files: List<Pair<String, ByteArray>>, excluded: Set<String> = STRUCTURAL_EXCLUDED): ContentIndex`; a `content_index_hash` check whose `detail` names offending paths (consumed by Task 7)

- [ ] **Step 1: Write the failing test**

Create `sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/StrictReaderTest.kt`:

```kotlin
// Reader strictness against the normative container rules:
//   - spec/manifest.md: a signed PLAIN capsule may not smuggle an
//     unaccounted-for content.enc past the content index
//   - spec/format.md: duplicate entry names are rejected on the RAW stored
//     central-directory name, before any map collapse picks a winner
//   - spec/format.md: symlink entries are rejected
//
// The fixtures are the shared conformance corpus under spec/vectors/, so
// this lane refuses exactly what the JS/Python/Rust lanes refuse.

package ai.virion.capsule.core

import com.google.gson.JsonParser
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class StrictReaderTest {

    @Test
    fun plainCapsuleWithStrayContentEncFailsContentIndex() {
        val bytes = File(
            vectorsDir(),
            "tamper-detection/output/plain-stray-content-enc.capsule",
        ).readBytes()
        val v = CapsuleVerifier.verify(bytes = bytes, allowlist = setOf(originatorPubkey()))
        assertFalse(v.ok, "a signed plain capsule with a stray content.enc must not verify")
        val ci = v.checks.firstOrNull { it.name == "content_index_hash" }
        assertEquals(false, ci?.ok, "content_index_hash must fail; got $ci")
        assertTrue(
            ci!!.detail.contains("content.enc"),
            "content_index detail should name the stray blob; got ${ci.detail}",
        )
        // The signature itself is untouched — an attacker cannot re-sign.
        assertEquals(
            true, v.checks.firstOrNull { it.name == "envelope_signature" }?.ok,
            "envelope signature should still be valid",
        )
    }

    @Test
    fun duplicateEntryNameIsRejected() {
        val bytes = File(vectorsDir(), "malformed-layout/output/duplicate-entry.capsule").readBytes()
        val e = assertFailsWith<IllegalArgumentException> { CapsuleZip.unpack(bytes) }
        assertTrue(
            e.message!!.contains("duplicate entry"),
            "expected a duplicate-entry rejection; got ${e.message}",
        )
        assertFalse(
            CapsuleVerifier.verify(bytes).ok,
            "duplicate-entry.capsule must not verify",
        )
    }

    @Test
    fun symlinkEntryIsRejected() {
        val bytes = File(vectorsDir(), "malformed-layout/output/symlink-entry.capsule").readBytes()
        val e = assertFailsWith<IllegalArgumentException> { CapsuleZip.unpack(bytes) }
        assertTrue(
            e.message!!.contains("symlink"),
            "expected a symlink rejection; got ${e.message}",
        )
        assertFalse(
            CapsuleVerifier.verify(bytes).ok,
            "symlink-entry.capsule must not verify",
        )
    }

    companion object {

        /** Walk up from the gradle module dir until we find spec/vectors. */
        private fun repoRoot(): File {
            var p: File? = File(System.getProperty("user.dir")).absoluteFile
            while (p != null) {
                if (File(p, "spec/vectors/tamper-detection/output/keys.json").exists()) return p
                p = p.parentFile
            }
            error(
                "could not locate repo root containing " +
                    "spec/vectors/tamper-detection/output/keys.json " +
                    "starting from ${System.getProperty("user.dir")}",
            )
        }

        private fun vectorsDir(): File = File(repoRoot(), "spec/vectors")

        private fun originatorPubkey(): String {
            val keysJson = File(vectorsDir(), "tamper-detection/output/keys.json")
                .readText(Charsets.UTF_8)
            val root = JsonParser.parseString(keysJson).asJsonObject
            return root.getAsJsonObject("originator").get("publicKey").asString
        }
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-kotlin && ./gradlew --no-daemon :core:test --tests 'ai.virion.capsule.core.StrictReaderTest'`

(If Gradle reports `Unable to locate a Java Runtime`, prefix with `JAVA_HOME=/opt/homebrew/opt/openjdk@17`; add `--offline` when running without network.)

Expected: FAIL — `3 tests completed, 3 failed`, with `StrictReaderTest > plainCapsuleWithStrayContentEncFailsContentIndex FAILED  java.lang.AssertionError: a signed plain capsule with a stray content.enc must not verify`

- [ ] **Step 3: Split the exclusion set and add the cipher-keyed selector**

In `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Manifest.kt`, replace lines 5-8:

```kotlin
object Manifest {
    val CONTENT_INDEX_EXCLUDED = setOf(
        "manifest.json", "provenance/envelope.json", "content.enc"
    )
```

with:

```kotlin
object Manifest {
    /**
     * Excluded from content_index.files by structural necessity, for every
     * capsule regardless of profile: manifest.json (the index lives inside
     * it) and provenance/envelope.json (it commits to the index hash).
     */
    val STRUCTURAL_EXCLUDED = setOf("manifest.json", "provenance/envelope.json")

    /**
     * `content.enc` is excluded from the content index ONLY for encrypted
     * capsules, where it is bound separately by
     * `envelope.encrypted_blob_hash`. In a plain capsule (`cipher: "none"`)
     * a `content.enc` entry MUST be indexed like any other file, so a signed
     * plain capsule cannot carry an unaccounted-for blob past verification
     * (spec/manifest.md).
     */
    val CONTENT_INDEX_EXCLUDED = STRUCTURAL_EXCLUDED + "content.enc"

    /**
     * Choose the content-index exclusion set for the capsule's profile.
     * [encrypted] must be derived from the SIGNED `envelope.cipher`, never
     * from the presence of a `content.enc` file.
     */
    fun contentIndexExclusions(encrypted: Boolean): Set<String> =
        if (encrypted) CONTENT_INDEX_EXCLUDED else STRUCTURAL_EXCLUDED
```

Then replace lines 23-25 (the `buildContentIndex` signature and filter):

```kotlin
    fun buildContentIndex(files: List<Pair<String, ByteArray>>): ContentIndex {
        val entries = files
            .filter { it.first !in CONTENT_INDEX_EXCLUDED }
```

with:

```kotlin
    fun buildContentIndex(
        files: List<Pair<String, ByteArray>>,
        excluded: Set<String> = STRUCTURAL_EXCLUDED,
    ): ContentIndex {
        val entries = files
            .filter { it.first !in excluded }
```

`CapsuleBuilder.seal` (`Builder.kt:114`) is the only other caller and builds plain capsules only, so the new default is correct there with no edit.

- [ ] **Step 4: Key the verifier off `envelope.cipher` and attribute failures per file**

In `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Verifier.kt`, replace lines 60-68:

```kotlin
        val indexInputs = parsed.files
            .filter { it.key !in Manifest.CONTENT_INDEX_EXCLUDED }
            .map { it.key to it.value }
        val ci = Manifest.buildContentIndex(indexInputs)
        val storedIdxMf = CapsuleReader.lookupString(parsed.manifest, listOf("content_index", "index_hash"))
        val storedIdxEnv = CapsuleReader.lookupString(parsed.envelope, listOf("content_index_hash"))
        rec("content_index_hash",
            ci.indexHash == storedIdxMf && ci.indexHash == storedIdxEnv,
            ci.indexHash.take(12) + "…")
```

with:

```kotlin
        // `content.enc` drops out of the index only when the SIGNED envelope
        // declares a cipher (it is bound instead by
        // envelope.encrypted_blob_hash). Keying off file presence would let
        // an attacker append a stray blob to a signed plain capsule and have
        // it excluded for free; keying off the signed cipher means the stray
        // blob is indexed here and fails verification. See spec/manifest.md.
        val indexCipher = CapsuleReader.lookupString(parsed.envelope, listOf("cipher")) ?: "none"
        val excluded = Manifest.contentIndexExclusions(indexCipher != "none")
        val indexInputs = parsed.files
            .filter { it.key !in excluded }
            .map { it.key to it.value }
        val ci = Manifest.buildContentIndex(indexInputs, excluded)
        // Per-file attribution, so a failing index names the offending paths
        // instead of only reporting a hash mismatch (mirrors the JS
        // reference's contentIndex.errors).
        val storedIndex = LinkedHashMap<String, String>()
        val storedRows = ((parsed.manifest as? JCSValue.Obj)?.pairs
            ?.firstOrNull { it.first == "content_index" }?.second as? JCSValue.Obj)?.pairs
            ?.firstOrNull { it.first == "files" }?.second as? JCSValue.Arr
        storedRows?.items?.forEach { row ->
            val cols = (row as? JCSValue.Obj)?.pairs ?: return@forEach
            val path = (cols.firstOrNull { it.first == "path" }?.second as? JCSValue.Str)?.v
            val hash = (cols.firstOrNull { it.first == "sha256" }?.second as? JCSValue.Str)?.v
            if (path != null && hash != null) storedIndex[path] = hash
        }
        val indexProblems = mutableListOf<String>()
        for ((path, hash) in ci.files) {
            val want = storedIndex[path]
            if (want == null) indexProblems += "file present but not in manifest index: $path"
            else if (want != hash) indexProblems += "file hash mismatch: $path"
        }
        val recomputedPaths = ci.files.map { it.first }.toSet()
        for (path in storedIndex.keys.sorted()) {
            if (path !in recomputedPaths) {
                indexProblems += "file in manifest index but missing from package: $path"
            }
        }
        val storedIdxMf = CapsuleReader.lookupString(parsed.manifest, listOf("content_index", "index_hash"))
        val storedIdxEnv = CapsuleReader.lookupString(parsed.envelope, listOf("content_index_hash"))
        val indexHashesMatch = ci.indexHash == storedIdxMf && ci.indexHash == storedIdxEnv
        rec("content_index_hash",
            indexHashesMatch && indexProblems.isEmpty(),
            (listOf(ci.indexHash.take(12) + "…") + indexProblems).joinToString("; "))
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-kotlin && ./gradlew --no-daemon :core:test --tests 'ai.virion.capsule.core.StrictReaderTest.plainCapsuleWithStrayContentEncFailsContentIndex'`

Expected: PASS — `BUILD SUCCESSFUL`

- [ ] **Step 6: Run the full lane suite for regressions**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-kotlin && ./gradlew --no-daemon :core:test`

Expected: FAIL — only `StrictReaderTest > duplicateEntryNameIsRejected` and `StrictReaderTest > symlinkEntryIsRejected` (fixed by Task 6). The 11 pre-existing tests — `EnvelopeTest` (2), `JcsNumbersVectorTest` (1), `ParityTest` (6), `RoundTripTest` (2) — must all still pass; check `core/build/test-results/test/*.xml` and confirm `failures="0"` for each of those four suites.

- [ ] **Step 7: Commit**
```bash
git add sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Manifest.kt sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Verifier.kt sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/StrictReaderTest.kt
git commit -m "fix(sdk-kotlin): key the content.enc index exclusion off the signed envelope.cipher"
```

---

### Task 6: Kotlin — reject duplicate entry names and symlink entries on the raw central directory

**Files:**
- Modify: `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Zip.kt:77-92`
- Test: `sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/StrictReaderTest.kt` (the two tests written in Task 5, Step 1)

**Interfaces:**
- Consumes: `CapsuleZip.unpack(bytes: ByteArray): List<Pair<String, ByteArray>>`
- Produces: `IllegalArgumentException("zip: duplicate entry: <name>")` and `IllegalArgumentException("zip entry is a symlink: <name>")` (needle strings consumed by Task 7)

- [ ] **Step 1: Write the failing test**

Already written in Task 5, Step 1: `duplicateEntryNameIsRejected` and `symlinkEntryIsRejected` in `sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/StrictReaderTest.kt`. No new code.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-kotlin && ./gradlew --no-daemon :core:test --tests 'ai.virion.capsule.core.StrictReaderTest.duplicateEntryNameIsRejected'`

Expected: FAIL with `java.lang.AssertionError: Expected an exception of class java.lang.IllegalArgumentException to be thrown, but was completed successfully.`

- [ ] **Step 3: Track seen names and read the external attributes in `unpack`**

In `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Zip.kt`, replace lines 77-92:

```kotlin
        var p = cdOffset
        val out = mutableListOf<Pair<String, ByteArray>>()
        repeat(cdCount) {
            require(read32(bytes, p) == 0x02014b50) { "zip: bad CD signature" }
            val compression = read16(bytes, p + 10)
            val compSize = read32(bytes, p + 20)
            val uncompSize = read32(bytes, p + 24)
            val nameLen = read16(bytes, p + 28)
            val extraLen = read16(bytes, p + 30)
            val commentLen = read16(bytes, p + 32)
            val localOff = read32(bytes, p + 42)
            require(compression == 0) { "zip: only STORED supported" }
            require(compSize == uncompSize) { "zip: STORED size mismatch" }
            val name = String(bytes, p + 46, nameLen, Charsets.UTF_8)
            assertSafePath(name)
            p += 46 + nameLen + extraLen + commentLen
```

with:

```kotlin
        var p = cdOffset
        val out = mutableListOf<Pair<String, ByteArray>>()
        // Entry-name and entry-shape checks run on the name as stored in the
        // central directory, before any map collapse — a reader that dedupes
        // on load silently accepts archives other readers reject
        // (spec/format.md "Container properties").
        val seen = mutableSetOf<String>()
        repeat(cdCount) {
            require(read32(bytes, p) == 0x02014b50) { "zip: bad CD signature" }
            val compression = read16(bytes, p + 10)
            val compSize = read32(bytes, p + 20)
            val uncompSize = read32(bytes, p + 24)
            val nameLen = read16(bytes, p + 28)
            val extraLen = read16(bytes, p + 30)
            val commentLen = read16(bytes, p + 32)
            val externalAttrs = read32(bytes, p + 38)
            val localOff = read32(bytes, p + 42)
            require(compression == 0) { "zip: only STORED supported" }
            require(compSize == uncompSize) { "zip: STORED size mismatch" }
            val name = String(bytes, p + 46, nameLen, Charsets.UTF_8)
            assertSafePath(name)
            // Duplicate names are a parser differential (ZIP libraries
            // disagree on which copy wins), so a signed capsule must never
            // contain one.
            require(seen.add(name)) { "zip: duplicate entry: $name" }
            // Unix mode bits live in the high 16 bits of the external attrs.
            val mode = (externalAttrs ushr 16) and 0xFFFF
            require((mode and 0x0000F000) != 0x0000A000) { "zip entry is a symlink: $name" }
            p += 46 + nameLen + extraLen + commentLen
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-kotlin && ./gradlew --no-daemon :core:test --tests 'ai.virion.capsule.core.StrictReaderTest'`

Expected: PASS — `BUILD SUCCESSFUL`; `core/build/test-results/test/TEST-ai.virion.capsule.core.StrictReaderTest.xml` reports `tests="3" ... failures="0" errors="0"`

- [ ] **Step 5: Run the full lane suite for regressions**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-kotlin && ./gradlew --no-daemon :core:test`

Expected: PASS — `BUILD SUCCESSFUL`, 14 tests, 0 failures (`EnvelopeTest` 2, `JcsNumbersVectorTest` 1, `ParityTest` 6, `RoundTripTest` 2, `StrictReaderTest` 3). `RoundTripTest` round-trips through `CapsuleZip.pack`/`unpack`, so it is the regression guard for the new checks.

- [ ] **Step 6: Commit**
```bash
git add sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Zip.kt
git commit -m "fix(sdk-kotlin): reject duplicate entry names and symlink entries on the raw central directory"
```

---

### Task 7: Kotlin — consume the spec outcome registries in the test suite

**Files:**
- Create: `sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/SpecRegistryTest.kt`
- Modify: `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Reader.kt:23-49`, `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Reader.kt:62-63`
- Test: `sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/SpecRegistryTest.kt`

**Interfaces:**
- Consumes: `spec/vectors/tamper-detection/vectors.json` and `spec/vectors/malformed-layout/vectors.json`; `CapsuleVerifier.verify(bytes:allowlist:)`; the `zip: duplicate entry` / `zip entry is a symlink` messages from Task 6
- Produces: `CapsuleReader.parseJsonFile(bytes: ByteArray, name: String): JCSValue`; reader errors `"failed to parse manifest.json"` and `"missing provenance/envelope.json"`; encrypted refusal now raised before the plain-layout requirements

- [ ] **Step 1: Write the failing test**

Create `sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/SpecRegistryTest.kt`:

```kotlin
// Registry-driven conformance against spec/vectors.
//
// Mirrors sdk-py/tests/test_spec_registry.py and
// verifier-rust/tests/spec_registry.rs: this lane reads the
// language-neutral outcome registries directly, so Kotlin tracks the same
// normative expectations as the JS reference lane without hand-copied
// assertions:
//
//   - tamper-detection/vectors.json   (verify-stage outcomes)
//   - malformed-layout/vectors.json   (open-stage reasons + verify-stage)
//
// The registry's `reason` categories are normative; the substring table
// below maps each category onto this lane's error messages.

package ai.virion.capsule.core

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SpecRegistryTest {

    @Test
    fun tamperRegistryOutcomes() {
        val file = File(vectorsDir(), "tamper-detection/vectors.json")
        val doc = JsonParser.parseString(file.readText()).asJsonObject
        val base = file.parentFile
        val allowlist = registryAllowlist(doc, base)
        val vectors = doc.getAsJsonArray("vectors")
        assertTrue(vectors.size() > 0, "tamper-detection registry is empty")
        for (entry in vectors) {
            val v = entry.asJsonObject
            val name = v.get("name").asString
            val bytes = File(base, v.get("capsule_file").asString).readBytes()
            if (name in ENCRYPTED_VECTORS) {
                assertEncryptedRefused(name, bytes)
                continue
            }
            assertVerifyOutcome(name, v.getAsJsonObject("expected"), verify(bytes, allowlist))
        }
    }

    @Test
    fun malformedRegistryOutcomes() {
        val file = File(vectorsDir(), "malformed-layout/vectors.json")
        val doc = JsonParser.parseString(file.readText()).asJsonObject
        val base = file.parentFile
        val allowlist = registryAllowlist(doc, base)
        val vectors = doc.getAsJsonArray("vectors")
        assertTrue(vectors.size() > 0, "malformed-layout registry is empty")
        for (entry in vectors) {
            val v = entry.asJsonObject
            val name = v.get("name").asString
            val expected = v.getAsJsonObject("expected")
            val bytes = File(base, v.get("capsule_file").asString).readBytes()
            val declaredOpen = expected.has("stage") && expected.get("stage").asString == "open"
            if (declaredOpen || name in OPEN_REJECTED_VERIFY_VECTORS) {
                val result = verify(bytes, allowlist)
                assertFalse(result.ok, "$name: open-stage fixture must not verify")
                val parse = result.checks.firstOrNull { it.name == "parse" }
                assertEquals(false, parse?.ok, "$name: reader must refuse this container; got ${result.checks}")
                if (declaredOpen) {
                    val reason = expected.get("reason").asString
                    val needles = openReasonNeedles(reason)
                    assertTrue(
                        needles.any { parse!!.detail.contains(it) },
                        "$name: expected reason $reason (any of $needles); got ${parse!!.detail}",
                    )
                }
                continue
            }
            assertVerifyOutcome(name, expected, verify(bytes, allowlist))
        }
    }

    private fun assertEncryptedRefused(name: String, bytes: ByteArray) {
        val result = verify(bytes, emptySet())
        assertFalse(result.ok, "$name: core is a plain-capsule verifier and must refuse it")
        val parse = result.checks.firstOrNull { it.name == "parse" }
        assertEquals(false, parse?.ok, "$name: expected a failing parse check; got ${result.checks}")
        assertTrue(
            parse!!.detail.contains("encrypted capsule"),
            "$name: expected the plain-only refusal; got ${parse.detail}",
        )
    }

    private fun assertVerifyOutcome(
        name: String,
        expected: JsonObject,
        result: CapsuleVerification,
    ) {
        val expectedOk = expected.get("ok").asBoolean
        assertEquals(
            expectedOk, result.ok,
            "$name: expected ok=$expectedOk; failing checks: " +
                result.checks.filter { !it.ok }.joinToString { "${it.name}:${it.detail}" },
        )
        val failing = expected.getAsJsonArray("failing") ?: JsonArray()
        for (area in failing) {
            val checkName = AREA_CHECK[area.asString]
                ?: error("$name: unknown or unsupported failing area ${area.asString}")
            val check = result.checks.firstOrNull { it.name == checkName }
            assertEquals(
                false, check?.ok,
                "$name: expected $checkName to fail; got ${result.checks}",
            )
        }
        if (expected.has("error_includes")) {
            val needle = expected.get("error_includes").asString
            val haystack = result.checks.joinToString(" ") { "${it.name} ${it.detail}" }
            assertTrue(
                haystack.contains(needle),
                "$name: expected an error containing $needle; got $haystack",
            )
        }
    }

    private fun verify(bytes: ByteArray, allowlist: Set<String>): CapsuleVerification =
        CapsuleVerifier.verify(bytes = bytes, allowlist = allowlist)

    private fun registryAllowlist(doc: JsonObject, base: File): Set<String> {
        doc.get("originator_public_key_hex")?.let { return setOf(it.asString) }
        doc.get("keys_file")?.let {
            val keys = JsonParser.parseString(File(base, it.asString).readText()).asJsonObject
            return setOf(keys.getAsJsonObject("originator").get("publicKey").asString)
        }
        return emptySet()
    }

    /**
     * Per-lane mapping of the registry's normative open-stage reason
     * categories onto this lane's reader messages.
     */
    private fun openReasonNeedles(reason: String): List<String> = when (reason) {
        "missing_required_file" ->
            listOf("missing manifest.json", "missing provenance/envelope.json")
        "invalid_json" -> listOf("failed to parse manifest.json")
        "duplicate_entry" -> listOf("duplicate entry")
        "unsafe_path" -> listOf("zip path traversal", "zip path: absolute")
        "unsupported_compression" -> listOf("only STORED supported")
        "symlink_entry" -> listOf("symlink")
        else -> error("unknown open-stage reason $reason")
    }

    companion object {

        /** Registry `failing` area → this lane's check name. */
        private val AREA_CHECK = mapOf(
            "content_index" to "content_index_hash",
            "chain" to "chain",
            "envelope" to "envelope_signature",
        )

        /**
         * Encrypted fixtures. The core module is a plain-capsule (L2)
         * verifier: it has no X25519/ChaCha20 path and `CapsuleReader.parse`
         * refuses any capsule whose manifest carries a non-null `encryption`.
         * Refusing is strictly stronger than the registry's expectation for
         * `clean-encrypted` (ok=true), so these are asserted against the
         * documented refusal instead. Pinned by name: when this module grows
         * an encryption path, drop the name here and the registry expectation
         * applies again.
         */
        private val ENCRYPTED_VECTORS = setOf("clean-encrypted", "tampered-blob")

        /**
         * Verify-stage vectors that THIS lane legitimately rejects at OPEN:
         * `CapsuleReader.parse` requires chain/events.jsonl and program.md
         * before it hands back a ParsedCapsule, so a capsule with a missing
         * or unparseable chain never reaches the per-area checks. Refusing
         * earlier is strictly stronger than the registry's ok=false
         * requirement. Pinned by name so a lane that starts *accepting* one
         * of these fails here.
         */
        private val OPEN_REJECTED_VERIFY_VECTORS = setOf("missing-chain", "invalid-chain-json")

        /** Walk up from the gradle module dir until we find spec/vectors. */
        private fun repoRoot(): File {
            var p: File? = File(System.getProperty("user.dir")).absoluteFile
            while (p != null) {
                if (File(p, "spec/vectors/tamper-detection/output/keys.json").exists()) return p
                p = p.parentFile
            }
            error(
                "could not locate repo root containing " +
                    "spec/vectors/tamper-detection/output/keys.json " +
                    "starting from ${System.getProperty("user.dir")}",
            )
        }

        private fun vectorsDir(): File = File(repoRoot(), "spec/vectors")
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-kotlin && ./gradlew --no-daemon :core:test --tests 'ai.virion.capsule.core.SpecRegistryTest'`

Expected: FAIL — `2 tests completed, 2 failed`, with `java.lang.AssertionError: clean-encrypted: expected the plain-only refusal; got missing chain` and `java.lang.AssertionError: missing-envelope: expected reason missing_required_file (any of [missing manifest.json, missing provenance/envelope.json]); got missing envelope` (read them out of `core/build/test-results/test/TEST-ai.virion.capsule.core.SpecRegistryTest.xml`)

- [ ] **Step 3: Attribute reader rejections correctly**

In `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Reader.kt`, replace lines 23-49 (the whole `parse` body):

```kotlin
    fun parse(bytes: ByteArray): ParsedCapsule {
        val entries = CapsuleZip.unpack(bytes)
        val files = entries.toMap()
        val manifestBytes = files["manifest.json"]
            ?: throw CapsuleException("missing manifest.json")
        val envelopeBytes = files["provenance/envelope.json"]
            ?: throw CapsuleException("missing envelope")
        val eventsBytes = files["chain/events.jsonl"]
            ?: throw CapsuleException("missing chain")
        val programBytes = files["program.md"]
            ?: throw CapsuleException("missing program.md")

        val manifest = parseJson(manifestBytes)
        val envelope = parseJson(envelopeBytes)
        val events = String(eventsBytes, Charsets.UTF_8)
            .split('\n').filter { it.isNotEmpty() }
            .map { parseJson(it.toByteArray(Charsets.UTF_8)) }
        val programMd = String(programBytes, Charsets.UTF_8)
        val agentsMd = files["agents.md"]?.let { String(it, Charsets.UTF_8) }

        val encryption = (manifest as? JCSValue.Obj)?.pairs
            ?.firstOrNull { it.first == "encryption" }?.second
        if (encryption != null && encryption != JCSValue.Null) {
            throw CapsuleException("encrypted capsule; v0 reader supports plain only")
        }
        return ParsedCapsule(manifest, envelope, events, programMd, agentsMd, files)
    }
```

with:

```kotlin
    fun parse(bytes: ByteArray): ParsedCapsule {
        val entries = CapsuleZip.unpack(bytes)
        val files = entries.toMap()
        val manifestBytes = files["manifest.json"]
            ?: throw CapsuleException("missing manifest.json")
        val envelopeBytes = files["provenance/envelope.json"]
            ?: throw CapsuleException("missing provenance/envelope.json")

        val manifest = parseJsonFile(manifestBytes, "manifest.json")
        val envelope = parseJsonFile(envelopeBytes, "provenance/envelope.json")

        // Refuse encrypted capsules BEFORE demanding the plain-capsule
        // layout: the chain and program live inside the ciphertext, so
        // requiring them first would misattribute the refusal as
        // "missing chain".
        val encryption = (manifest as? JCSValue.Obj)?.pairs
            ?.firstOrNull { it.first == "encryption" }?.second
        if (encryption != null && encryption != JCSValue.Null) {
            throw CapsuleException("encrypted capsule; v0 reader supports plain only")
        }

        val eventsBytes = files["chain/events.jsonl"]
            ?: throw CapsuleException("missing chain")
        val programBytes = files["program.md"]
            ?: throw CapsuleException("missing program.md")
        val events = String(eventsBytes, Charsets.UTF_8)
            .split('\n').filter { it.isNotEmpty() }
            .map { parseJsonFile(it.toByteArray(Charsets.UTF_8), "chain/events.jsonl") }
        val programMd = String(programBytes, Charsets.UTF_8)
        val agentsMd = files["agents.md"]?.let { String(it, Charsets.UTF_8) }

        return ParsedCapsule(manifest, envelope, events, programMd, agentsMd, files)
    }
```

Then insert the helper immediately above the existing `/** Parse JSON bytes via Gson, ... */` comment (currently line 62):

```kotlin
    /**
     * [parseJson] with the offending file named in the error, so a reader
     * rejection can be attributed to a specific document (mirrors the Rust
     * verifier's "failed to parse manifest.json").
     */
    fun parseJsonFile(bytes: ByteArray, name: String): JCSValue =
        try {
            parseJson(bytes)
        } catch (_: Exception) {
            throw CapsuleException("failed to parse $name")
        }

```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-kotlin && ./gradlew --no-daemon :core:test --tests 'ai.virion.capsule.core.SpecRegistryTest'`

Expected: PASS — `BUILD SUCCESSFUL`; `TEST-ai.virion.capsule.core.SpecRegistryTest.xml` reports `tests="2" ... failures="0" errors="0"`

- [ ] **Step 5: Run the full lane suite for regressions**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-kotlin && ./gradlew --no-daemon :core:test`

Expected: PASS — `BUILD SUCCESSFUL`, 16 tests, 0 failures across `EnvelopeTest` (2), `JcsNumbersVectorTest` (1), `ParityTest` (6), `RoundTripTest` (2), `SpecRegistryTest` (2), `StrictReaderTest` (3). `ParityTest.jsTamperedBlobCapsuleFailsUnderKotlin` exercises the reordered encrypted refusal and must stay green.

- [ ] **Step 6: Commit**
```bash
git add sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/SpecRegistryTest.kt sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Reader.kt
git commit -m "test(sdk-kotlin): drive conformance from the spec outcome registries"
```


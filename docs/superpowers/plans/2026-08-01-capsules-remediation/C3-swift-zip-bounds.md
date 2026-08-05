# C3 — sdk-swift ZIP reader traps on hostile input (F17)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Part of:** [Capsules pre-release remediation](./README.md) · Tier 1 (release-blocking)

**Findings closed:** F17

**Lanes touched:** sdk-swift

**Tasks:** 2

**Depends on:** nothing — can start immediately

## Global Constraints

Copied verbatim from the project state; every task below implicitly includes these.

- The project is **pre-release (v0.6 prototype)**. Breaking changes are acceptable. Do not add compatibility shims or deprecation paths.
- `sdk-js` is the **reference implementation**. Where lanes disagree and no decision says otherwise, JS defines correct behaviour.
- The chain.md step-6 actor rule resolves as: **all five verifiers enforce** (actor is in `manifest.participants` or equals `system:host`), **and builders reject at `appendEvent` time**. Not auto-registration.
- Every normative rule this plan enforces must land with a **negative conformance vector**, consumed by every lane's spec-registry test. A fix without a vector does not count as done.
- Test frameworks by lane: `sdk-js` node:test · `sdk-py` pytest · `verifier-rust` `#[test]` · `sdk-swift` XCTest · `sdk-kotlin` its existing test style.
- Never claim a command was run without running it.

## Risks

WHAT COULD BREAK
- `pack` is deliberately untouched and stays non-throwing, so `Builder.swift:157,239,341` and the four `CapsuleZip.pack` call sites in `EncryptionTests.swift` compile unchanged. The only signature changes are on private helpers.
- Stricter shapes now rejected that the old Swift reader accepted: archives with a trailing comment whose length does not land at EOF, archives with more than one EOCD signature, ZIP64 sentinels, entry data located after the central directory, and archives whose EOCD count disagrees with the directory walk. `sdk-js` already rejects all of these, and all 26 pre-existing Swift tests (including the ParityTests that read JS-produced fixtures from `spec/vectors/tamper-detection/output/`) still pass, so no real capsule is affected.
- `unpack` is stricter than `zipfile`/JSZip about entry data preceding the central directory (`dataOff + compSize <= cdOffset`). Every capsule this repo produces has that layout; a third-party writer that interleaves the directory would now be refused.

EXISTING TESTS LIKELY TO FAIL: none observed — full suite green at 37/37.

CROSS-LANE COORDINATION: none. This cluster touches only `sdk-swift/**` plus one additive `### Security` block in `CHANGELOG.md`. If another cluster also appends to `## Unreleased`, expect a trivial merge in `CHANGELOG.md:70-71`.

NO CONFORMANCE VECTOR IS PROPOSED — and here is the honest reason. I built the natural fixtures (EOCD offset past EOF, ZIP64 sentinel) and traced what adding them to `spec/vectors/malformed-layout/vectors.json` would cost: a new normative `reason` category has to be wired into four separate needle tables (`tools/check-spec-vectors.mjs` `OPEN_REASON`, `sdk-py/tests/test_spec_registry.py` `OPEN_REASON_PATTERNS`, `verifier-rust/tests/spec_registry.rs` `open_reason_needles`), `sdk-js/tools/rawzip.mjs` needs EOCD-override support it does not have (it computes the EOCD), and — verified by running it — `sdk-py` would then FAIL, because `capsule/zip_io.py:52` lets `zipfile.BadZipFile` escape and the registry test asserts `pytest.raises(ValueError, ...)`; `BadZipFile` is not a `ValueError`. That is a real sdk-py defect but it is not F17, and fixing it here would put this cluster into three other lanes' files. The Swift XCTests fully pin the behavior for this finding; recommend routing the shared fixture + `sdk-py` exception-wrapping work as its own cluster.

TWO ADJACENT DEFECTS FOUND WHILE VALIDATING — NOT FIXED HERE, PLEASE ROUTE:
1. HIGH, same "verify must never trap" contract, different mechanism. `JCS.swift:41` is a `precondition` on integers outside ±(2^53−1), and it is reachable from `CapsuleVerifier.verify` on attacker-controlled bytes via `Manifest.hash(parsed.manifest)`. Reproduced on the copy — a 4-file capsule (`manifest.json` = `{"id":9007199254740993}`, plus `provenance/envelope.json`, `chain/events.jsonl`, `program.md`) kills the process with `Capsule/JCS.swift:41: Precondition failed: JCS: integer outside IEEE-754 exact range (|n| > 2^53 - 1)` and `exited with unexpected signal code 5`. `CHANGELOG.md:134-135` already claims these are "rejected fail-closed in Python/Kotlin/Swift", which is untrue for Swift. My Task 1/2 tests do NOT cover this, so a green `ZipRobustnessTests` must not be read as "verify never traps".
2. MEDIUM, container strictness parity. `CHANGELOG.md:54-56` states "All readers reject duplicate entry names"; the Swift reader does not — `CapsuleReader.parse` folds entries into a dictionary where the last duplicate silently wins. It also ignores the external-attribute symlink mode bits. That is why this cluster's Swift tests are self-contained rather than driving the shared `spec/vectors/malformed-layout` registry: Swift would fail `duplicate-entry.capsule` and `symlink-entry.capsule` today.
3. LOW, builder-side. `Zip.swift:14` (`for e in entries { try! assertSafePath(e.path) }`) and `Zip.swift:12` (`precondition(files.count <= MAX_ENTRIES)`) trap on host-app input: `addPayload(.init(path: "payload/../../x"))` passes Builder's `hasPrefix("payload/")` check and then dies on the `try!`. Fixing it means making `pack` throwing, which ripples through `Builder.swift` and `EncryptionTests.swift` — deliberately excluded from a release-blocking security fix.

## Validation performed while specifying this plan

The steps below were applied to a **copy of the repository outside the working tree** and executed. This is the real output from that run, not a prediction.

<details>
<summary>Expand validation log</summary>

```
Applied and ran for real on a copy outside the repo ('/tmp/work-c3', rsync'd with 'verifier-rust/target' and '.git' excluded; 'sdk-swift/.build' deleted because the copied module cache is path-pinned).

Toolchain note: '/usr/bin/swift' is Command Line Tools only and cannot build the test target ('error: no such module 'XCTest''). All runs used the Xcode toolchain, which is what CI's macos-15 runner has: 'DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift test'. Plan steps write the CI/README command 'swift test'.

1. BASELINE (unmodified copy): 'swift test' → 'Test Suite 'All tests' passed ... Executed 26 tests, with 0 failures (0 unexpected)'.

2. TASK 1 RED (new test file against the ORIGINAL Zip.swift): 'swift test --filter ZipRobustnessTests' →
'''
Test Case '-[CapsuleTests.ZipRobustnessTests testCentralDirectoryOffsetPastEndOfFileIsRejected]' started.
Swift/ContiguousArrayBuffer.swift:692: Fatal error: Index out of range
error: Process '/Applications/Xcode.app/Contents/Developer/usr/bin/xctest -XCTest ... CapsulePackageTests.xctest' exited with unexpected signal code 5
'''
Finding F17 reproduced exactly: the process dies, it is not a catchable failure.

3. TASK 1 GREEN (Task-1-only Zip.swift + Task-1-only test file, both reconstructed and run in isolation): 'Test Suite 'ZipRobustnessTests' passed ... Executed 9 tests, with 0 failures (0 unexpected)'.

4. TASK 2 RED (Task-1 Zip.swift + full test file): 
'''
.../ZipRobustnessTests.swift:164: error: -[... testEntryCountCapIsEnforcedOnRead] : XCTAssertThrowsError failed: did not throw an error
.../ZipRobustnessTests.swift:176: error: -[... testDeclaredEntryCountMustMatchTheDirectoryWalk] : XCTAssertThrowsError failed: did not throw an error
'''

5. TASK 2 GREEN + FULL SUITE (final Zip.swift + full test file): 'swift test --filter ZipRobustnessTests' → 'Executed 11 tests, with 0 failures'. 'swift test' → 'Test Suite 'All tests' passed at 2026-08-01 09:53:39.538 / Executed 37 tests, with 0 failures (0 unexpected) in 0.041 (0.044) seconds' (26 baseline + 11 new).

Cross-lane reference behavior confirmed on the same crafted bytes (22-byte EOCD with cdOffset=0x1000; ZIP64-sentinel EOCD; 64 bytes of 0x41): sdk-js 'verifyCapsule' → 'ok= false' for all three; sdk-py 'CapsuleReader.from_bytes' → 'BadZipFile: Bad offset for central directory' / 'File is not a zip file'. Neither crashes; Swift did.

Every line number in the plan was read from the actual files: original 'sdk-swift/Sources/Capsule/Zip.swift' (184 lines; constants 6-9, 'unpack' 74-122, 'read16'/'read32' 164-172), and the post-Task-1 file for Task 2's anchors (I generated that intermediate file and read its numbering directly). Task 2's edits are additionally anchored by unique verbatim snippets so they apply unambiguously even if Task 1 lands with cosmetic drift.
```

</details>

---

## C3 — sdk-swift ZIP reader traps on hostile input (F17)

`CapsuleZip.unpack` (`sdk-swift/Sources/Capsule/Zip.swift:74-122`) reads the EOCD's
central-directory offset and record count and then indexes `bytesArr` with completely
unvalidated offsets. In Swift an out-of-range array subscript is a `fatalError`, which the
`do`/`catch` in `CapsuleVerifier.verify` (`sdk-swift/Sources/Capsule/Verifier.swift:40`)
cannot contain — a 22-byte crafted file kills the host process. Confirmed on a copy outside
the repo: `Swift/ContiguousArrayBuffer.swift:692: Fatal error: Index out of range`, test
bundle `exited with unexpected signal code 5`. `sdk-js` and `sdk-py` both return clean
failures for the same bytes; `verifier-rust` documents that its reader never panics.

Task 1 makes every read bounds-checked. Task 2 enforces the `spec/format.md` reader limits
(10,000 entries, 1 GiB total) on the read path, where today `MAX_ENTRIES` is only checked in
`pack`.

### Task 1: Bounds-check every read in CapsuleZip.unpack

**Files:**
- Create: `sdk-swift/Tests/CapsuleTests/ZipRobustnessTests.swift`
- Modify: `sdk-swift/Sources/Capsule/Zip.swift:9` (constants block, after `MAX_ENTRIES`)
- Modify: `sdk-swift/Sources/Capsule/Zip.swift:74-122` (the whole `unpack` function)
- Modify: `sdk-swift/Sources/Capsule/Zip.swift:164-172` (`read16`/`read32`)
- Test: `sdk-swift/Tests/CapsuleTests/ZipRobustnessTests.swift`

**Interfaces:**
- Consumes: `CapsuleZip.pack(_ files: [(path: String, data: Data)]) -> Data`; `CapsuleVerifier.verify(_ bytes: Data, allowlist: Set<String> = []) -> CapsuleVerification`; `CapsuleError.malformed(String)`
- Produces: `CapsuleZip.unpack(_ bytes: Data) throws -> [(path: String, data: Data)]` (signature unchanged; now throws instead of trapping on every malformed shape). Private `peek16`/`peek32` return `Optional`; private `read16`/`read32` become `throws`. `pack` is untouched and stays non-throwing, so `Builder.swift:157,239,341` and `EncryptionTests.swift` need no change.

- [ ] **Step 1: Write the failing test**

Create `sdk-swift/Tests/CapsuleTests/ZipRobustnessTests.swift`:

```swift
// Robustness of the ZIP reader against hostile containers.
//
// Every offset the reader takes out of an archive is attacker-controlled.
// In Swift an out-of-range array subscript is a `fatalError`: it is not an
// error the `do`/`catch` in `CapsuleVerifier.verify` can contain, so a
// crafted 22-byte file would take the whole host process down. These tests
// pin the contract that `CapsuleZip.unpack` throws `CapsuleError.malformed`
// and `CapsuleVerifier.verify` returns `ok=false` for malformed bytes —
// matching sdk-js (`unpackZip`/`scanCentralDirectory`) and verifier-rust.
//
// A regression here does not show up as a failing assertion; it shows up as
// the test bundle crashing with "Fatal error: Index out of range".

import Foundation
import XCTest
@testable import Capsule

final class ZipRobustnessTests: XCTestCase {

    // MARK: - Raw crafting helpers (no guardrails; hostile shapes only)

    private static func le16(_ v: UInt16) -> Data {
        Data([UInt8(v & 0xFF), UInt8((v >> 8) & 0xFF)])
    }
    private static func le32(_ v: UInt32) -> Data {
        Data([
            UInt8(v & 0xFF),
            UInt8((v >> 8) & 0xFF),
            UInt8((v >> 16) & 0xFF),
            UInt8((v >> 24) & 0xFF),
        ])
    }

    /// A bare 22-byte EOCD record with attacker-chosen central-directory
    /// coordinates, optionally preceded by filler bytes.
    private static func eocd(entryCount: UInt16,
                             cdSize: UInt32,
                             cdOffset: UInt32,
                             prefix: Data = Data()) -> Data {
        var out = prefix
        out.append(le32(0x0605_4b50))
        out.append(le16(0))            // this disk
        out.append(le16(0))            // disk with CD start
        out.append(le16(entryCount))   // entries on this disk
        out.append(le16(entryCount))   // total entries
        out.append(le32(cdSize))
        out.append(le32(cdOffset))
        out.append(le16(0))            // comment length
        return out
    }

    /// A minimal well-formed capsule-shaped archive to mutate.
    private static func validArchive() -> Data {
        CapsuleZip.pack([
            (path: "manifest.json", data: Data(#"{"id":"x"}"#.utf8)),
            (path: "program.md", data: Data("# hi\n".utf8)),
        ])
    }

    /// Byte offset of the EOCD record in a well-formed archive.
    private static func eocdOffset(_ archive: Data) -> Int { archive.count - 22 }

    private func assertMalformed(_ bytes: Data,
                                 _ message: String,
                                 file: StaticString = #filePath,
                                 line: UInt = #line) {
        XCTAssertThrowsError(try CapsuleZip.unpack(bytes), message,
                             file: file, line: line) { err in
            guard case CapsuleError.malformed = err else {
                return XCTFail("\(message): expected CapsuleError.malformed, got \(err)",
                               file: file, line: line)
            }
        }
        let v = CapsuleVerifier.verify(bytes)
        XCTAssertFalse(v.ok, "\(message): verify must report ok=false",
                       file: file, line: line)
        XCTAssertEqual(v.checks.first?.name, "parse",
                       "\(message): first check must be the failed parse",
                       file: file, line: line)
    }

    // MARK: - Bounds

    func testCentralDirectoryOffsetPastEndOfFileIsRejected() {
        // 22 bytes total, EOCD claims a central directory at 0x1000.
        let hostile = Self.eocd(entryCount: 1, cdSize: 46, cdOffset: 0x0000_1000)
        XCTAssertEqual(hostile.count, 22)
        assertMalformed(hostile, "cd offset past EOF")
    }

    func testZip64SentinelsAreRejected() {
        let hostile = Self.eocd(entryCount: 0xFFFF,
                                cdSize: 0xFFFF_FFFF,
                                cdOffset: 0xFFFF_FFFF)
        assertMalformed(hostile, "zip64 sentinels")
    }

    func testCentralDirectoryNotEndingAtEocdIsRejected() {
        // Geometry that does not close on the EOCD: cdOffset + cdSize != eocd.
        let hostile = Self.eocd(entryCount: 1, cdSize: 10, cdOffset: 0,
                                prefix: Data(repeating: 0, count: 64))
        assertMalformed(hostile, "cd does not end at EOCD")
    }

    func testLocalHeaderOffsetPastEndOfFileIsRejected() {
        var archive = Self.validArchive()
        // Central-directory record 0 starts at the EOCD's cdOffset field.
        let eocdAt = Self.eocdOffset(archive)
        let cdOffset = Int(archive[eocdAt + 16]) | (Int(archive[eocdAt + 17]) << 8)
            | (Int(archive[eocdAt + 18]) << 16) | (Int(archive[eocdAt + 19]) << 24)
        // Patch the record's local-header offset (record + 42) past EOF.
        archive.replaceSubrange((cdOffset + 42)..<(cdOffset + 46),
                                with: Self.le32(0xFFFF_0000))
        assertMalformed(archive, "local header offset past EOF")
    }

    func testEntryNameLengthOverrunningCentralDirectoryIsRejected() {
        var archive = Self.validArchive()
        let eocdAt = Self.eocdOffset(archive)
        let cdOffset = Int(archive[eocdAt + 16]) | (Int(archive[eocdAt + 17]) << 8)
            | (Int(archive[eocdAt + 18]) << 16) | (Int(archive[eocdAt + 19]) << 24)
        // Patch record 0's name length (record + 28) to 0xFFFF.
        archive.replaceSubrange((cdOffset + 28)..<(cdOffset + 30),
                                with: Self.le16(0xFFFF))
        assertMalformed(archive, "name length overruns CD")
    }

    func testEveryOneByteEocdSmashDoesNotTrap() {
        // Exhaustive single-byte corruption of the EOCD record. Any of these
        // that reaches an unchecked read is a process kill, not a test
        // failure — so reaching the end of this loop IS the assertion.
        let archive = Self.validArchive()
        let eocdAt = Self.eocdOffset(archive)
        for i in eocdAt..<archive.count {
            for value: UInt8 in [0x00, 0x7F, 0xFF] {
                var mutated = archive
                mutated[i] = value
                _ = try? CapsuleZip.unpack(mutated)
                _ = CapsuleVerifier.verify(mutated)
            }
        }
    }

    func testTruncationAtEveryPrefixDoesNotTrap() {
        let archive = Self.validArchive()
        for cut in 0..<archive.count {
            let truncated = archive.prefix(cut)
            let v = CapsuleVerifier.verify(Data(truncated))
            XCTAssertFalse(v.ok, "truncation to \(cut) bytes must not verify")
        }
    }

    func testGarbageBytesAreRejected() {
        assertMalformed(Data(repeating: 0x41, count: 64), "garbage")
        assertMalformed(Data(), "empty")
        assertMalformed(Data([0x50, 0x4b, 0x05, 0x06]), "signature only")
    }

    // MARK: - The happy path still works

    func testWellFormedArchiveStillRoundTrips() throws {
        let archive = Self.validArchive()
        let entries = try CapsuleZip.unpack(archive)
        XCTAssertEqual(entries.map { $0.path }, ["manifest.json", "program.md"])
        XCTAssertEqual(entries[1].data, Data("# hi\n".utf8))
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-swift && swift test --filter ZipRobustnessTests`

Expected: FAIL — and not as an assertion. The test *process* dies:

```
Test Case '-[CapsuleTests.ZipRobustnessTests testCentralDirectoryOffsetPastEndOfFileIsRejected]' started.
Swift/ContiguousArrayBuffer.swift:692: Fatal error: Index out of range
error: Process '/Applications/Xcode.app/Contents/Developer/usr/bin/xctest -XCTest ... /sdk-swift/.build/arm64-apple-macosx/debug/CapsulePackageTests.xctest' exited with unexpected signal code 5
```

(`testCentralDirectoryNotEndingAtEocdIsRejected` passes first, then the run aborts — no
further tests execute. That abort *is* the bug: the same trap in a host app kills the app.)

- [ ] **Step 3: Add the reader constants**

In `sdk-swift/Sources/Capsule/Zip.swift`, replace lines 6-9:

```swift
public enum CapsuleZip {
    private static let DOS_TIME: UInt16 = 0
    private static let DOS_DATE: UInt16 = 0x0021 // 1980-01-01
    private static let MAX_ENTRIES = 10_000
```

with:

```swift
public enum CapsuleZip {
    private static let DOS_TIME: UInt16 = 0
    private static let DOS_DATE: UInt16 = 0x0021 // 1980-01-01
    private static let MAX_ENTRIES = 10_000
    private static let EOCD_MIN = 22
    private static let MAX_COMMENT = 0xFFFF
    private static let EOCD_SIG: UInt32 = 0x0605_4b50
    private static let CDH_SIG: UInt32 = 0x0201_4b50
    private static let LFH_SIG: UInt32 = 0x0403_4b50
```

- [ ] **Step 4: Make the little-endian reads bounds-checked**

In `sdk-swift/Sources/Capsule/Zip.swift`, replace the two helpers at lines 164-172:

```swift
    private static func read16(_ b: [UInt8], _ off: Int) -> UInt16 {
        UInt16(b[off]) | (UInt16(b[off + 1]) << 8)
    }
    private static func read32(_ b: [UInt8], _ off: Int) -> UInt32 {
        UInt32(b[off])
            | (UInt32(b[off + 1]) << 8)
            | (UInt32(b[off + 2]) << 16)
            | (UInt32(b[off + 3]) << 24)
    }
```

with:

```swift
    /// Bounds-checked little-endian reads. `peek*` return nil out of
    /// range (used by the EOCD scan, where misses are expected); `read*`
    /// throw, so a crafted offset surfaces as a malformed-capsule error
    /// instead of an array trap.
    private static func peek16(_ b: [UInt8], _ off: Int) -> UInt16? {
        guard off >= 0, off + 2 <= b.count else { return nil }
        return UInt16(b[off]) | (UInt16(b[off + 1]) << 8)
    }
    private static func peek32(_ b: [UInt8], _ off: Int) -> UInt32? {
        guard off >= 0, off + 4 <= b.count else { return nil }
        return UInt32(b[off])
            | (UInt32(b[off + 1]) << 8)
            | (UInt32(b[off + 2]) << 16)
            | (UInt32(b[off + 3]) << 24)
    }
    private static func read16(_ b: [UInt8], _ off: Int) throws -> UInt16 {
        guard let v = peek16(b, off) else {
            throw CapsuleError.malformed("zip: read past end of archive at \(off)")
        }
        return v
    }
    private static func read32(_ b: [UInt8], _ off: Int) throws -> UInt32 {
        guard let v = peek32(b, off) else {
            throw CapsuleError.malformed("zip: read past end of archive at \(off)")
        }
        return v
    }
```

- [ ] **Step 5: Rewrite `unpack` so every offset is validated before use**

In `sdk-swift/Sources/Capsule/Zip.swift`, replace the whole function at lines 74-122 (from
`public static func unpack(` through its closing `}`, i.e. everything above
`private static func assertSafePath`) with:

```swift
    /// Unpack a STORED-only ZIP.
    ///
    /// This function NEVER traps on input bytes. Every offset taken from
    /// the archive is attacker-controlled, so each one is bounds-checked
    /// before it indexes the byte array: a Swift out-of-range subscript is
    /// a `fatalError`, which no `do`/`catch` in `CapsuleVerifier` can
    /// contain, and would take the host process down with it. All
    /// structural violations throw `CapsuleError.malformed`.
    ///
    /// Mirrors `scanCentralDirectory` in `sdk-js/src/zip.js`: the central
    /// directory is walked by its declared byte size (not by the
    /// attacker-controlled EOCD record count) and ZIP64 sentinels are
    /// refused outright.
    public static func unpack(_ bytes: Data) throws -> [(path: String, data: Data)] {
        let b = [UInt8](bytes)
        guard b.count >= EOCD_MIN else { throw CapsuleError.malformed("zip too small") }

        // The EOCD is the LAST record; scan back over a possible trailing
        // comment. A signature-shaped byte sequence inside the comment is
        // not an EOCD unless its declared comment length lands exactly at
        // end-of-file.
        var eocd = -1
        let lowest = max(0, b.count - EOCD_MIN - MAX_COMMENT)
        var scan = b.count - EOCD_MIN
        while scan >= lowest {
            if peek32(b, scan) == EOCD_SIG,
               let commentLen = peek16(b, scan + 20),
               scan + EOCD_MIN + Int(commentLen) == b.count
            {
                eocd = scan
                break
            }
            scan -= 1
        }
        guard eocd >= 0 else { throw CapsuleError.malformed("zip: EOCD not found") }
        // Two EOCD signatures make the archive ambiguous across readers
        // (which record wins is library-dependent). Fail closed, as sdk-js
        // does, rather than pick one.
        var q = b.count - 4
        while q > eocd {
            if peek32(b, q) == EOCD_SIG {
                throw CapsuleError.malformed("zip: multiple end-of-central-directory records")
            }
            q -= 1
        }

        let cdCount = Int(try read16(b, eocd + 10))
        let cdSize = Int(try read32(b, eocd + 12))
        let cdOffset = Int(try read32(b, eocd + 16))
        // ZIP64 sentinels: a capsule can never legitimately need ZIP64
        // under the 10,000-entry / 1 GiB caps, so refuse rather than parse.
        guard cdCount != 0xFFFF, cdSize != 0xFFFF_FFFF, cdOffset != 0xFFFF_FFFF else {
            throw CapsuleError.malformed("zip: ZIP64 archives are not supported")
        }
        // Central-directory geometry must close exactly on the EOCD; this
        // is what makes every subsequent record offset in-bounds.
        guard cdOffset <= eocd, cdSize <= eocd, cdOffset + cdSize == eocd else {
            throw CapsuleError.malformed("zip: central directory does not end at EOCD")
        }

        let cdEnd = eocd
        var out: [(String, Data)] = []
        var p = cdOffset
        while p < cdEnd {
            guard p + 46 <= cdEnd else {
                throw CapsuleError.malformed(
                    "zip: truncated central-directory record \(out.count)")
            }
            let sig = try read32(b, p)
            guard sig == CDH_SIG else {
                throw CapsuleError.malformed("zip: bad CD signature at record \(out.count)")
            }
            let compression = try read16(b, p + 10)
            let compSize = Int(try read32(b, p + 20))
            let uncompSize = Int(try read32(b, p + 24))
            let nameLen = Int(try read16(b, p + 28))
            let extraLen = Int(try read16(b, p + 30))
            let commentLen = Int(try read16(b, p + 32))
            let localOff = Int(try read32(b, p + 42))
            guard compression == 0 else {
                throw CapsuleError.malformed("zip: only STORED supported")
            }
            guard compSize == uncompSize else {
                throw CapsuleError.malformed("zip: STORED size mismatch")
            }
            guard compSize != 0xFFFF_FFFF, localOff != 0xFFFF_FFFF else {
                throw CapsuleError.malformed("zip: ZIP64 archives are not supported")
            }
            let next = p + 46 + nameLen + extraLen + commentLen
            guard next <= cdEnd else {
                throw CapsuleError.malformed(
                    "zip: truncated central-directory record \(out.count)")
            }
            let name = String(decoding: b[(p + 46)..<(p + 46 + nameLen)], as: UTF8.self)
            try assertSafePath(name)
            p = next

            // Local header + entry data must live entirely before the
            // central directory.
            guard localOff + 30 <= cdOffset else {
                throw CapsuleError.malformed("zip: local header out of range for \(name)")
            }
            let lfhSig = try read32(b, localOff)
            guard lfhSig == LFH_SIG else {
                throw CapsuleError.malformed("zip: bad LFH signature for \(name)")
            }
            let lfhNameLen = Int(try read16(b, localOff + 26))
            let lfhExtraLen = Int(try read16(b, localOff + 28))
            let dataOff = localOff + 30 + lfhNameLen + lfhExtraLen
            guard dataOff <= cdOffset, compSize <= cdOffset - dataOff else {
                throw CapsuleError.malformed("zip: entry data out of range for \(name)")
            }
            out.append((name, Data(b[dataOff..<(dataOff + compSize)])))
        }
        return out
    }
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd sdk-swift && swift test --filter ZipRobustnessTests`

Expected: PASS — `Test Suite 'ZipRobustnessTests' passed`, `Executed 9 tests, with 0 failures (0 unexpected)`

- [ ] **Step 7: Run the full lane suite for regressions**

Run: `cd sdk-swift && swift test`

Expected: `Test Suite 'All tests' passed` — `Executed 35 tests, with 0 failures (0 unexpected)`
(26 pre-existing: EncryptionTests, JCSNumbersVectorTests, ParityTests, RoundTripTests; plus
the 9 new ones.)

- [ ] **Step 8: Commit**
```bash
git add sdk-swift/Sources/Capsule/Zip.swift sdk-swift/Tests/CapsuleTests/ZipRobustnessTests.swift
git commit -m "fix(sdk-swift): bounds-check every read in the ZIP reader

CapsuleZip.unpack indexed the byte array with unvalidated EOCD and
central-directory offsets, so a 22-byte crafted capsule caused a Swift
array trap — a fatalError the do/catch in CapsuleVerifier.verify cannot
contain, killing the host process. Validate the central-directory
geometry, bound every record and entry-data slice, reject ZIP64
sentinels and ambiguous multi-EOCD archives, and throw
CapsuleError.malformed on any violation, matching sdk-js and
verifier-rust."
```

### Task 2: Enforce the spec's reader limits on the sdk-swift read path

**Files:**
- Modify: `sdk-swift/Sources/Capsule/Zip.swift:9-10` (insert `MAX_TOTAL_BYTES` after `MAX_ENTRIES`, post-Task-1 numbering)
- Modify: `sdk-swift/Sources/Capsule/Zip.swift:88-91` (unpack doc comment, post-Task-1)
- Modify: `sdk-swift/Sources/Capsule/Zip.swift:130-141` (add entry-count cap + `totalBytes`, post-Task-1)
- Modify: `sdk-swift/Sources/Capsule/Zip.swift:191-193` (size accounting + count cross-check, post-Task-1)
- Modify: `sdk-swift/Tests/CapsuleTests/ZipRobustnessTests.swift:159` (insert a limits section before `// MARK: - The happy path still works`)
- Modify: `CHANGELOG.md:70-71` (new `### Security` block at the end of `## Unreleased`)
- Test: `sdk-swift/Tests/CapsuleTests/ZipRobustnessTests.swift`

**Interfaces:**
- Consumes: `CapsuleZip.unpack(_ bytes: Data) throws -> [(path: String, data: Data)]` and the private `read16`/`read32` throwing helpers from Task 1
- Produces: no new API. `unpack` gains three refusals: `"zip: too many entries (N)"`, `"zip: total-size limit exceeded"`, `"zip: central-directory entry count mismatch (EOCD N, actual M)"`

- [ ] **Step 1: Write the failing test**

In `sdk-swift/Tests/CapsuleTests/ZipRobustnessTests.swift`, insert this block immediately
before the `// MARK: - The happy path still works` line:

```swift
    // MARK: - Reader limits (spec/format.md: 10,000 entries, 1 GiB)

    func testEntryCountCapIsEnforcedOnRead() {
        // EOCD declares 20,000 entries; the cap must trip before any walk.
        let hostile = Self.eocd(entryCount: 20_000, cdSize: 0, cdOffset: 0)
        XCTAssertThrowsError(try CapsuleZip.unpack(hostile)) { err in
            XCTAssertTrue("\(err)".contains("too many entries"),
                          "expected an entry-count rejection, got \(err)")
        }
    }

    func testDeclaredEntryCountMustMatchTheDirectoryWalk() {
        // The walk is driven by the directory's byte size, so a lying EOCD
        // count cannot hide a record from the strictness checks.
        var archive = Self.validArchive()
        let eocdAt = Self.eocdOffset(archive)
        archive.replaceSubrange((eocdAt + 10)..<(eocdAt + 12), with: Self.le16(7))
        XCTAssertThrowsError(try CapsuleZip.unpack(archive)) { err in
            XCTAssertTrue("\(err)".contains("entry count mismatch"),
                          "expected a count-mismatch rejection, got \(err)")
        }
    }

```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-swift && swift test --filter ZipRobustnessTests`

Expected: FAIL with two `XCTAssertThrowsError failed: did not throw an error` errors —

```
Tests/CapsuleTests/ZipRobustnessTests.swift:164: error: -[CapsuleTests.ZipRobustnessTests testEntryCountCapIsEnforcedOnRead] : XCTAssertThrowsError failed: did not throw an error
Tests/CapsuleTests/ZipRobustnessTests.swift:176: error: -[CapsuleTests.ZipRobustnessTests testDeclaredEntryCountMustMatchTheDirectoryWalk] : XCTAssertThrowsError failed: did not throw an error
```

(After Task 1 the 20,000-entry EOCD is geometrically consistent with an empty directory, so
`unpack` returns `[]` instead of refusing; the lying count is likewise silently accepted.)

- [ ] **Step 3: Add the total-size constant**

In `sdk-swift/Sources/Capsule/Zip.swift`, replace:

```swift
    private static let MAX_ENTRIES = 10_000
    private static let EOCD_MIN = 22
```

with:

```swift
    private static let MAX_ENTRIES = 10_000
    /// Reader-side total-uncompressed-size cap (spec/format.md
    /// "File-count and total-uncompressed-size limits"): 1 GiB, matching
    /// sdk-js's MAX_TOTAL_BYTES and verifier-rust's MAX_TOTAL_BYTES.
    private static let MAX_TOTAL_BYTES = 1024 * 1024 * 1024
    private static let EOCD_MIN = 22
```

- [ ] **Step 4: Cap the declared entry count and start size accounting**

In `sdk-swift/Sources/Capsule/Zip.swift`, replace:

```swift
        guard cdCount != 0xFFFF, cdSize != 0xFFFF_FFFF, cdOffset != 0xFFFF_FFFF else {
            throw CapsuleError.malformed("zip: ZIP64 archives are not supported")
        }
        // Central-directory geometry must close exactly on the EOCD; this
        // is what makes every subsequent record offset in-bounds.
        guard cdOffset <= eocd, cdSize <= eocd, cdOffset + cdSize == eocd else {
            throw CapsuleError.malformed("zip: central directory does not end at EOCD")
        }

        let cdEnd = eocd
        var out: [(String, Data)] = []
        var p = cdOffset
```

with:

```swift
        guard cdCount != 0xFFFF, cdSize != 0xFFFF_FFFF, cdOffset != 0xFFFF_FFFF else {
            throw CapsuleError.malformed("zip: ZIP64 archives are not supported")
        }
        guard cdCount <= MAX_ENTRIES else {
            throw CapsuleError.malformed("zip: too many entries (\(cdCount))")
        }
        // Central-directory geometry must close exactly on the EOCD; this
        // is what makes every subsequent record offset in-bounds.
        guard cdOffset <= eocd, cdSize <= eocd, cdOffset + cdSize == eocd else {
            throw CapsuleError.malformed("zip: central directory does not end at EOCD")
        }

        let cdEnd = eocd
        var out: [(String, Data)] = []
        var totalBytes = 0
        var p = cdOffset
```

- [ ] **Step 5: Enforce the size cap per entry and cross-check the declared count**

In `sdk-swift/Sources/Capsule/Zip.swift`, replace:

```swift
            out.append((name, Data(b[dataOff..<(dataOff + compSize)])))
        }
        return out
    }
```

with:

```swift
            totalBytes += compSize
            guard totalBytes <= MAX_TOTAL_BYTES else {
                throw CapsuleError.malformed("zip: total-size limit exceeded")
            }
            out.append((name, Data(b[dataOff..<(dataOff + compSize)])))
            guard out.count <= MAX_ENTRIES else {
                throw CapsuleError.malformed("zip: too many entries (\(out.count))")
            }
        }
        guard out.count == cdCount else {
            throw CapsuleError.malformed(
                "zip: central-directory entry count mismatch (EOCD \(cdCount), actual \(out.count))")
        }
        return out
    }
```

- [ ] **Step 6: Update the `unpack` doc comment to state the limits**

In `sdk-swift/Sources/Capsule/Zip.swift`, replace:

```swift
    /// Mirrors `scanCentralDirectory` in `sdk-js/src/zip.js`: the central
    /// directory is walked by its declared byte size (not by the
    /// attacker-controlled EOCD record count) and ZIP64 sentinels are
    /// refused outright.
```

with:

```swift
    /// Mirrors `scanCentralDirectory` in `sdk-js/src/zip.js`: the central
    /// directory is walked by its declared byte size (not by the
    /// attacker-controlled EOCD record count, which is cross-checked
    /// afterwards), ZIP64 sentinels are refused outright, and the
    /// spec/format.md reader limits (10,000 entries, 1 GiB total) are
    /// enforced here on the read path, not only in `pack`.
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `cd sdk-swift && swift test --filter ZipRobustnessTests`

Expected: PASS — `Test Suite 'ZipRobustnessTests' passed`, `Executed 11 tests, with 0 failures (0 unexpected)`

- [ ] **Step 8: Run the full lane suite for regressions**

Run: `cd sdk-swift && swift test`

Expected: `Test Suite 'All tests' passed` — `Executed 37 tests, with 0 failures (0 unexpected)`

- [ ] **Step 9: Record the fix in the changelog**

In `CHANGELOG.md`, replace the last two lines of the `## Unreleased` section (lines 70-71,
the `Malformed-layout fixtures are drift-checked.` bullet immediately followed by the blank
line before `## v0.6.0-prototype.1`):

```markdown
- **Malformed-layout fixtures are drift-checked.** The deterministic generator
  supports `--check`, which runs as a required JavaScript conformance target.

## v0.6.0-prototype.1 — 2026-05-12 (unreleased)
```

with:

```markdown
- **Malformed-layout fixtures are drift-checked.** The deterministic generator
  supports `--check`, which runs as a required JavaScript conformance target.

### Security

- **The Swift reader no longer traps on hostile containers.**
  `CapsuleZip.unpack` indexed its byte array with unvalidated EOCD and
  central-directory offsets, so a 22-byte crafted `.capsule` produced a
  Swift array trap — a `fatalError`, which the `do`/`catch` in
  `CapsuleVerifier.verify` cannot contain — and killed the host process.
  Every offset is now bounds-checked, the central directory must close
  exactly on the EOCD, ZIP64 sentinels and ambiguous multi-EOCD archives
  are refused, and the `spec/format.md` reader limits (10,000 entries,
  1 GiB total) are enforced on the read path rather than only in `pack`.
  Malformed bytes now surface as `CapsuleError.malformed` / `ok=false`,
  matching the JS, Python, and Rust lanes.

## v0.6.0-prototype.1 — 2026-05-12 (unreleased)
```

- [ ] **Step 10: Commit**
```bash
git add sdk-swift/Sources/Capsule/Zip.swift sdk-swift/Tests/CapsuleTests/ZipRobustnessTests.swift CHANGELOG.md
git commit -m "fix(sdk-swift): enforce the spec reader limits when unpacking

MAX_ENTRIES was checked only in pack, so spec/format.md's 10,000-entry
and 1 GiB reader caps were unenforced in this lane. Cap the EOCD's
declared record count before walking, accumulate uncompressed bytes
against a 1 GiB ceiling, and cross-check the declared count against the
records actually consumed so an understated count cannot hide a record."
```


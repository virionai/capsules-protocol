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

    // MARK: - The happy path still works

    func testWellFormedArchiveStillRoundTrips() throws {
        let archive = Self.validArchive()
        let entries = try CapsuleZip.unpack(archive)
        XCTAssertEqual(entries.map { $0.path }, ["manifest.json", "program.md"])
        XCTAssertEqual(entries[1].data, Data("# hi\n".utf8))
    }
}

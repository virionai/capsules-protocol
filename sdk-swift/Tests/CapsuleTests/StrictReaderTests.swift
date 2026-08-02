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

    /// spec/format.md: the DOS directory attribute (0x10) on a name that does
    /// not end in "/" is a parser differential — JSZip drops the entry as a
    /// directory while unzip(1)/zipfile extract it as a file — so the reader
    /// must refuse the container instead of picking a side.
    func testDirectoryAttributeOnNonDirectoryNameIsRejected() throws {
        let bytes = try fixture("malformed-layout/output/dir-bit-smuggle.capsule")
        XCTAssertThrowsError(try CapsuleZip.unpack(bytes)) { error in
            XCTAssertTrue("\(error)".contains("directory attribute on non-directory name"),
                          "expected a directory-attribute rejection; got \(error)")
        }
        XCTAssertFalse(CapsuleVerifier.verify(bytes).ok,
                       "dir-bit-smuggle.capsule must not verify")
    }

    /// spec/format.md: a "/"-terminated name declaring content is the mirror
    /// image of the same differential — readers that key directory-ness on
    /// the name silently drop the body.
    func testDirectoryMarkerWithContentIsRejected() throws {
        let bytes = try fixture("malformed-layout/output/dir-marker-with-content.capsule")
        XCTAssertThrowsError(try CapsuleZip.unpack(bytes)) { error in
            XCTAssertTrue("\(error)".contains("directory marker with nonzero size"),
                          "expected a directory-marker rejection; got \(error)")
        }
        XCTAssertFalse(CapsuleVerifier.verify(bytes).ok,
                       "dir-marker-with-content.capsule must not verify")
    }

    /// spec/format.md: the LOCAL file-header name must equal the
    /// central-directory name. Readers that re-key by the local header (JSZip)
    /// otherwise extract a different entry set than the one the strictness
    /// scan validated.
    func testLocalCentralNameMismatchIsRejected() throws {
        let bytes = try fixture("malformed-layout/output/local-name-mismatch.capsule")
        XCTAssertThrowsError(try CapsuleZip.unpack(bytes)) { error in
            XCTAssertTrue("\(error)".contains("local/central name mismatch"),
                          "expected a name-mismatch rejection; got \(error)")
        }
        XCTAssertFalse(CapsuleVerifier.verify(bytes).ok,
                       "local-name-mismatch.capsule must not verify")
    }

    /// A well-formed zero-size "/" directory marker is unambiguous: it is
    /// skipped from the entry set (matching the JS/Python/Rust lanes) rather
    /// than rejected, and the EOCD record count still cross-checks.
    func testZeroSizeDirectoryMarkerIsSkippedNotRejected() throws {
        let archive = CapsuleZip.pack([
            (path: "a.txt", data: Data("hello\n".utf8)),
            (path: "notes/", data: Data()),
        ])
        let entries = try CapsuleZip.unpack(archive)
        XCTAssertEqual(entries.map { $0.path }, ["a.txt"],
                       "the directory marker must be skipped, not returned or rejected")
    }
}

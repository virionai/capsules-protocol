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

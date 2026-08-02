// Version-compatibility policy unit pins (spec/versioning.md). The
// registry-driven fixtures live in SpecRegistryTests
// (testVersionCompatRegistryOutcomes); this file pins the machinery:
// the classification vocabulary, the version-KEYED domain-separation
// selectors, and the report-never-decide host policy.

import Foundation
import XCTest
@testable import Capsule

final class VersionCompatTests: XCTestCase {

    private static let vectorsDir: URL = {
        URL(fileURLWithPath: #file)
            .deletingLastPathComponent()  // CapsuleTests/
            .deletingLastPathComponent()  // Tests/
            .deletingLastPathComponent()  // sdk-swift/
            .deletingLastPathComponent()  // <repo-root>/
            .appendingPathComponent("spec/vectors")
    }()

    func testClassifyVocabulary() {
        XCTAssertEqual(CapsuleVersions.classify("0.6"), .known)
        XCTAssertEqual(CapsuleVersions.classify("9.9"), .unknownNewer)
        XCTAssertEqual(CapsuleVersions.classify("1.0"), .unknownNewer)
        // Numeric ordering, not lexicographic: 0.10 > 0.6.
        XCTAssertEqual(CapsuleVersions.classify("0.10"), .unknownNewer)
        XCTAssertEqual(CapsuleVersions.classify("0.1"), .unknownOlder)
        XCTAssertEqual(CapsuleVersions.classify("banana"), .invalid)
        XCTAssertEqual(CapsuleVersions.classify("0.6.1"), .invalid)
        XCTAssertEqual(CapsuleVersions.classify("06.1"), .invalid)
        XCTAssertEqual(CapsuleVersions.classify(nil), .invalid)
    }

    /// A verifier that accepts a v0.6 capsule must retain the v0.6
    /// domain strings forever, selected by the capsule's DECLARED
    /// version — never a single current constant.
    func testDomainStringsAreKeyedByDeclaredVersion() {
        XCTAssertEqual(CapsuleVersions.idDomain("0.6"), Data("capsule-id-v0.6\0".utf8))
        XCTAssertEqual(CapsuleVersions.idDomain("0.7"), Data("capsule-id-v0.7\0".utf8))
        XCTAssertEqual(
            CapsuleVersions.provenanceDomain("0.7", role: "notary"),
            Data("capsule-provenance-v0.7:notary\0".utf8)
        )
        XCTAssertEqual(
            CapsuleVersions.keyWrapInfo("0.7"),
            Data("capsule-key-wrap-v0.7".utf8)
        )
        // computeCapsuleId is version-keyed: same inputs, different era,
        // a different identity.
        let pub = Data(repeating: 7, count: 32)
        let feh = String(repeating: "ab", count: 32)
        XCTAssertNotEqual(
            Manifest.computeCapsuleId(originatorPub: pub, firstEventHashHex: feh, version: "0.6"),
            Manifest.computeCapsuleId(originatorPub: pub, firstEventHashHex: feh, version: "0.7")
        )
        XCTAssertEqual(
            Manifest.computeCapsuleId(originatorPub: pub, firstEventHashHex: feh),
            Manifest.computeCapsuleId(originatorPub: pub, firstEventHashHex: feh, version: "0.6")
        )
    }

    /// Host policy: the SDK reports acceptance against a declared set,
    /// never decides — exactly the signer-allowlist shape.
    func testHostPolicyIsReportedNeverDecided() throws {
        let bytes = try Data(contentsOf: Self.vectorsDir
            .appendingPathComponent("version-compat/output/known-current-version.capsule"))

        let noPolicy = CapsuleVerifier.verify(bytes)
        XCTAssertTrue(noPolicy.ok, "positive fixture must verify")
        XCTAssertEqual(noPolicy.formatVersion.observed, "0.6")
        XCTAssertTrue(noPolicy.formatVersion.supported)
        XCTAssertEqual(noPolicy.formatVersion.status, "known")
        XCTAssertEqual(noPolicy.formatVersion.suite, "v0.6")
        XCTAssertNil(noPolicy.formatVersion.acceptedByPolicy)

        let accepted = CapsuleVerifier.verify(bytes, acceptVersions: ["0.6"])
        XCTAssertTrue(accepted.ok)
        XCTAssertEqual(accepted.formatVersion.acceptedByPolicy, true)

        let rejected = CapsuleVerifier.verify(bytes, acceptVersions: ["0.7"])
        // Integrity intact — ok stays true; the verdict is REPORTED and
        // a PASS outside the declared range is never silent.
        XCTAssertTrue(rejected.ok)
        XCTAssertEqual(rejected.formatVersion.acceptedByPolicy, false)
        XCTAssertTrue(rejected.notes.contains(where: { $0.contains("accepted") }),
                      "got notes: \(rejected.notes)")
    }
}

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
        // The default is the CURRENT sealing version.
        XCTAssertEqual(
            Manifest.computeCapsuleId(originatorPub: pub, firstEventHashHex: feh),
            Manifest.computeCapsuleId(
                originatorPub: pub, firstEventHashHex: feh, version: CapsuleVersions.current)
        )
    }

    /// ACCEPTANCE for the 0.6 → 0.7 bump: the FROZEN, genuine v0.6
    /// capsule — sealed by the pre-bump v0.6 SDK and byte-pinned, never
    /// regenerated — still verifies under the v0.6 rules, with the
    /// observed version reported as a fact.
    func testFrozenGenuineV06CapsuleStillVerifies() throws {
        let bytes = try Data(contentsOf: Self.vectorsDir
            .appendingPathComponent("version-compat/output/known-previous-version-0.6.capsule"))
        let result = CapsuleVerifier.verify(bytes)
        XCTAssertTrue(result.ok,
                      "frozen v0.6 fixture must verify: \(result.checks.filter { !$0.ok })")
        XCTAssertEqual(result.formatVersion.observed, "0.6")
        XCTAssertEqual(result.formatVersion.status, "known")
        XCTAssertEqual(result.formatVersion.suite, "v0.6")
    }

    /// Host policy: the SDK reports acceptance against a declared set,
    /// never decides — exactly the signer-allowlist shape.
    func testHostPolicyIsReportedNeverDecided() throws {
        let bytes = try Data(contentsOf: Self.vectorsDir
            .appendingPathComponent("version-compat/output/known-current-version.capsule"))

        let noPolicy = CapsuleVerifier.verify(bytes)
        XCTAssertTrue(noPolicy.ok, "positive fixture must verify")
        XCTAssertEqual(noPolicy.formatVersion.observed, CapsuleVersions.current)
        XCTAssertTrue(noPolicy.formatVersion.supported)
        XCTAssertEqual(noPolicy.formatVersion.status, "known")
        // 0.7 adopts the v0.6 algorithm suite unchanged (spec/versioning.md).
        XCTAssertEqual(noPolicy.formatVersion.suite, "v0.6")
        XCTAssertNil(noPolicy.formatVersion.acceptedByPolicy)

        let accepted = CapsuleVerifier.verify(bytes, acceptVersions: [CapsuleVersions.current])
        XCTAssertTrue(accepted.ok)
        XCTAssertEqual(accepted.formatVersion.acceptedByPolicy, true)

        let rejected = CapsuleVerifier.verify(bytes, acceptVersions: ["0.6"])
        // Integrity intact — ok stays true; the verdict is REPORTED and
        // a PASS outside the declared range is never silent.
        XCTAssertTrue(rejected.ok)
        XCTAssertEqual(rejected.formatVersion.acceptedByPolicy, false)
        XCTAssertTrue(rejected.notes.contains(where: { $0.contains("accepted") }),
                      "got notes: \(rejected.notes)")
    }

    /// REGRESSION — the seal path must be version-keyed end to end.
    ///
    /// Simulates the 0.6 → 0.7 bump the natural way (known table gains
    /// "0.7", current moves to "0.7") and seals an ENCRYPTED capsule.
    /// The defect this pins: Builder hardcoding the encryption AAD's
    /// version member and the key-wrap HKDF info to "0.6" while the read
    /// side keys both on the capsule's DECLARED version. That divergence
    /// produces the worst failure shape — the sealed capsule VERIFIES
    /// (AAD and wrap info are not covered by verification) but cannot be
    /// decrypted by a conforming reader, silently destroying archival
    /// recoverability. A test sealing only at the current version can
    /// never catch this class, because every hardcoded "0.6" coincides
    /// with current until the bump happens.
    func testSealUnderNonCurrentDeclaredVersionRoundTripsDecrypt() throws {
        // Simulate the NEXT era (one past CapsuleVersions.current): the
        // regression only bites when current moves past a hardcoded
        // literal, so the simulation must always stay ahead of current.
        try CapsuleVersions.simulatingBump(known: ["0.6", "0.7", "0.8"], current: "0.8") {
            let origin = Ed25519KeyPair.generate()
            let recipient = X25519KeyPair.generate()
            let builder = CapsuleBuilder(
                originator: .init(keyPair: origin, label: "bump-sim"),
                createdAt: "2026-05-12T20:00:00Z"
            )
            try builder
                .setProgram("# Bump simulation\n")
                .appendEvent(
                    actor: "human:test", kind: "decision",
                    action: "approved", target: "program.md",
                    payload: .object([("decision", .string("go"))])
                )
            let sealed = try builder.seal(
                signedAt: "2026-05-12T20:00:00Z",
                recipients: [.init(publicKey: recipient.publicKeyBytes)]
            )

            // The sealed capsule declares the bumped version everywhere.
            let outer = try CapsuleReader.parse(sealed.bytes)
            guard case .object(let mfPairs) = outer.manifest,
                  case .object(let fmt)? = mfPairs.first(where: { $0.0 == "format" })?.1,
                  case .string(let mfVersion)? = fmt.first(where: { $0.0 == "version" })?.1
            else { return XCTFail("outer manifest has no format.version") }
            XCTAssertEqual(mfVersion, "0.8",
                           "manifest.format.version must track CapsuleVersions.current")
            guard case .object(let envPairs) = outer.envelope,
                  case .string(let envVersion)? = envPairs.first(where: { $0.0 == "version" })?.1
            else { return XCTFail("outer envelope has no version") }
            XCTAssertEqual(envVersion, "0.8",
                           "envelope.version must track CapsuleVersions.current")

            // It verifies (AAD/wrap-info are NOT covered by verification —
            // which is exactly why verification alone cannot catch the
            // divergence)…
            let l2 = CapsuleVerifier.verify(sealed.bytes, allowlist: [origin.publicKeyHex])
            XCTAssertTrue(l2.ok, "L2 failed: \(l2.checks.filter { !$0.ok })")

            // …and a conforming reader of the bumped era MUST be able to
            // decrypt it: wrap-info and AAD on the seal side must have
            // been keyed by the same declared version the reader keys on.
            let inner = try CapsuleReader.openInner(
                outer,
                recipientPrivateKey: recipient.privateKeyBytes,
                recipientPublicKey: recipient.publicKeyBytes
            )
            XCTAssertEqual(inner.programMd, "# Bump simulation\n")
            XCTAssertEqual(inner.events.count, 1)
        }
    }
}

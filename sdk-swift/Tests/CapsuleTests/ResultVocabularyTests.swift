// Normalized verdict-surface unit pins (spec/results.md). The
// registry-driven fixtures live in SpecRegistryTests
// (testResultVocabularyRegistryOutcomes); this file pins the
// derivation: the ok/verdict invariant, the host-relative trust
// qualifiers, the empty-chain and encrypted-outer scope facts, and the
// canonical advisory notes that back them.
//
// Every member here is DERIVED from facts the result already carried
// before v0.7.1 — no capsule bytes change and no capsule that verified
// yesterday fails today.

import Foundation
import XCTest
@testable import Capsule

final class ResultVocabularyTests: XCTestCase {

    private static let vectorsDir: URL = {
        URL(fileURLWithPath: #file)
            .deletingLastPathComponent()  // CapsuleTests/
            .deletingLastPathComponent()  // Tests/
            .deletingLastPathComponent()  // sdk-swift/
            .deletingLastPathComponent()  // <repo-root>/
            .appendingPathComponent("spec/vectors")
    }()

    private static let signedAt = "2026-05-12T20:00:00Z"

    /// The strongest honest shape this builder can seal: a signer
    /// commitment, a declared participant set, and a walked chain.
    private func buildBoundCapsule() throws -> (origin: Ed25519KeyPair, bytes: Data) {
        let origin = Ed25519KeyPair.generate()
        let builder = CapsuleBuilder(originator: .init(keyPair: origin, label: "acme"),
                                     createdAt: Self.signedAt)
        _ = try builder
            .setParticipants([.init(actorId: "human:alice")])
            .setProgram("# Result vocabulary\n")
            .appendEvent(actor: "human:alice", kind: "decision", action: "submit",
                         target: "program.md", payload: jobj(("summary", "submitted")))
        return (origin, try builder.seal(signedAt: Self.signedAt).bytes)
    }

    func testUnqualifiedValidIsTheOnlyEmptyQualifierArray() throws {
        let (origin, bytes) = try buildBoundCapsule()
        let v = CapsuleVerifier.verify(bytes, allowlist: [origin.publicKeyHex])
        XCTAssertTrue(v.ok, "\(v.checks.filter { !$0.ok })")
        XCTAssertEqual(v.verdict, "valid")
        XCTAssertNil(v.verdictReason)
        XCTAssertEqual(v.qualifiers, [])
        XCTAssertEqual(v.trustedSignerCount, 1)
    }

    /// The trust qualifiers are host-relative — the SAME bytes carry
    /// different ones under different allowlists — and mutually
    /// exclusive. This is exactly why they can never be capsule members.
    func testTrustQualifiersAreHostRelativeAndMutuallyExclusive() throws {
        let (origin, bytes) = try buildBoundCapsule()

        let noAllowlist = CapsuleVerifier.verify(bytes)
        XCTAssertEqual(noAllowlist.verdict, "valid")
        XCTAssertEqual(noAllowlist.qualifiers, ["trust_not_evaluated"])
        XCTAssertTrue(noAllowlist.notes.contains(
            "no allowlist provided; trusted=false for all signers regardless of signature validity"))

        // P3: an allowlist that matched nothing is a PASS the host must
        // not read as trust — every lane now says why.
        let stranger = Ed25519KeyPair.generate()
        let noMatch = CapsuleVerifier.verify(bytes, allowlist: [stranger.publicKeyHex])
        XCTAssertEqual(noMatch.verdict, "valid")
        XCTAssertEqual(noMatch.qualifiers, ["no_trusted_signer"])
        XCTAssertEqual(noMatch.trustedSignerCount, 0)
        XCTAssertTrue(noMatch.notes.contains(
            "allowlist provided but matched no signer; trusted=false for all signers"))

        let matched = CapsuleVerifier.verify(bytes, allowlist: [origin.publicKeyHex])
        XCTAssertEqual(matched.qualifiers, [])
        XCTAssertFalse(matched.notes.contains(where: { $0.contains("matched no signer") }))
    }

    /// versioning.md "Host policy": the verdict is a fact beside the
    /// observed version, never a decision — integrity is untouched.
    func testVersionPolicyQualifierExistsOnlyWhenAPolicyWasDeclared() throws {
        let (origin, bytes) = try buildBoundCapsule()

        let noPolicy = CapsuleVerifier.verify(bytes, allowlist: [origin.publicKeyHex])
        XCTAssertFalse(noPolicy.qualifiers.contains("version_not_accepted_by_policy"))

        let excluded = CapsuleVerifier.verify(bytes, allowlist: [origin.publicKeyHex],
                                              acceptVersions: ["0.6"])
        XCTAssertTrue(excluded.ok)
        XCTAssertEqual(excluded.verdict, "valid")
        XCTAssertEqual(excluded.qualifiers, ["version_not_accepted_by_policy"])
        XCTAssertTrue(excluded.notes.contains(where: { $0.contains("not in the declared accepted set") }))
    }

    /// The trust.md threat-table capsule: no commitment, no
    /// participants, no events, no allowlist. It VERIFIES — each is a
    /// weaker claim made honestly — and every reduced assurance reaches
    /// the verdict, in the spec-defined order.
    func testMaximallyQualifiedValidCarriesEveryWeakerClaim() throws {
        let bytes = try Data(contentsOf: Self.vectorsDir.appendingPathComponent(
            "result-vocabulary/output/maximally-qualified-valid.capsule"))
        let v = CapsuleVerifier.verify(bytes)
        XCTAssertTrue(v.ok, "\(v.checks.filter { !$0.ok })")
        XCTAssertEqual(v.verdict, "valid")
        XCTAssertEqual(v.qualifiers, [
            "signer_set_unbound", "actor_set_unbound", "empty_chain_not_walked",
            "trust_not_evaluated",
        ])
        // Each qualifier restates a note the lanes already share
        // byte-identically (spec/results.md "Canonical note strings").
        XCTAssertTrue(v.notes.contains(
            "manifest.signer_commitment absent: the signer set is not bound by the seal"))
        XCTAssertTrue(v.notes.contains(
            "manifest.participants empty: chain actors are not bound to a declared participant set"))
        XCTAssertTrue(v.notes.contains(
            "empty chain: no events to walk; envelope anchors checked to be null instead"))
    }

    /// `encrypted_outer_only` is PER-RESULT: the L2 outer verified the
    /// seal and left the content unread; the L3 result read it.
    func testEncryptedOuterOnlyIsPerResult() throws {
        let origin = Ed25519KeyPair.generate()
        let recipient = X25519KeyPair.generate()
        let builder = CapsuleBuilder(originator: .init(keyPair: origin, label: "acme"),
                                     createdAt: Self.signedAt)
        _ = try builder
            .setParticipants([.init(actorId: "human:alice")])
            .setProgram("# Encrypted scope\n")
            .appendEvent(actor: "human:alice", kind: "decision", action: "submit",
                         target: "program.md", payload: jobj(("summary", "submitted")))
        let bytes = try builder.seal(
            signedAt: Self.signedAt,
            recipients: [.init(publicKey: recipient.publicKeyBytes)]
        ).bytes

        let l2 = CapsuleVerifier.verify(bytes, allowlist: [origin.publicKeyHex])
        XCTAssertEqual(l2.verdict, "valid")
        XCTAssertEqual(l2.level, "L2")
        XCTAssertTrue(l2.qualifiers.contains("encrypted_outer_only"))

        let l3 = CapsuleVerifier.verify(bytes,
                                        recipientPrivateKey: recipient.privateKeyBytes,
                                        recipientPublicKey: recipient.publicKeyBytes,
                                        allowlist: [origin.publicKeyHex])
        XCTAssertTrue(l3.ok, "\(l3.checks.filter { !$0.ok })")
        XCTAssertEqual(l3.verdict, "valid")
        XCTAssertFalse(l3.qualifiers.contains("encrypted_outer_only"),
                       "the L3 result read the content")
    }

    /// The refusal classes stay distinguishable at the NORMALIZED
    /// surface: "unsupported" is a limitation of THIS verifier (a
    /// different one may verify the capsule), "invalid" is a defect of
    /// the capsule. And `ok == (verdict == "valid")` holds across all of
    /// them.
    func testRefusalClassesAndTheOkVerdictInvariant() throws {
        func verify(_ path: String) throws -> CapsuleVerification {
            CapsuleVerifier.verify(try Data(contentsOf: Self.vectorsDir.appendingPathComponent(path)))
        }
        let newer = try verify("result-vocabulary/output/unsupported-newer.capsule")
        XCTAssertEqual(newer.verdict, "unsupported")
        XCTAssertEqual(newer.verdictReason, "unsupported_version_newer")
        XCTAssertEqual(newer.qualifiers, [])
        XCTAssertEqual(newer.formatVersion.observed, "9.9")

        let older = try verify("result-vocabulary/output/unsupported-older.capsule")
        XCTAssertEqual(older.verdictReason, "unsupported_version_older")

        let unsupportedProfile = try verify(
            "profile-declaration/output/unsupported-vendor-profile.capsule")
        XCTAssertEqual(unsupportedProfile.verdict, "unsupported")
        XCTAssertEqual(unsupportedProfile.verdictReason, "unsupported_profile")
        XCTAssertEqual(unsupportedProfile.qualifiers, [])
        XCTAssertNil(unsupportedProfile.formatVersion.suite,
                     "no suite fact is known about rules this verifier refused to apply")

        // A capsule self-contradiction is a DEFECT, not a verifier
        // limitation: verdict "invalid" with no reason channel.
        let mismatch = try verify("profile-declaration/output/profile-mismatch-value.capsule")
        XCTAssertEqual(mismatch.verdict, "invalid")
        XCTAssertNil(mismatch.verdictReason)

        let tampered = try verify("result-vocabulary/output/invalid-tamper.capsule")
        XCTAssertEqual(tampered.verdict, "invalid")
        XCTAssertNil(tampered.verdictReason)
        XCTAssertEqual(tampered.qualifiers, [])

        for v in [newer, older, unsupportedProfile, mismatch, tampered] {
            XCTAssertEqual(v.ok, v.verdict == "valid")
        }
    }

    /// The renderer floor (spec/results.md "Required renderer
    /// language"): every qualifier renders with its normative minimum
    /// substring, and an unknown entry — a later revision's name or an
    /// `x-` vendor extension — surfaces VERBATIM rather than being
    /// dropped as satisfied.
    func testRendererFloorCarriesEveryMinimumSubstring() throws {
        let required = [
            "signer_set_unbound": "signer set is not bound by the seal",
            "actor_set_unbound": "actors are not bound to a declared participant set",
            "empty_chain_not_walked": "no events to walk",
            "encrypted_outer_only": "content is encrypted and was not read",
            "version_not_accepted_by_policy": "not in the declared accepted set",
            "trust_not_evaluated": "no allowlist",
            "no_trusted_signer": "matched no signer",
            "lineage_declared_unverified": "declared, not verified",
            "lineage_mismatch": "different sealed state of the declared predecessor",
            "lineage_predecessor_invalid": "fails its own verification",
        ]
        for (qualifier, substring) in required {
            XCTAssertTrue(
                CapsuleResults.rendering(of: qualifier).contains(substring),
                "\(qualifier): the rendering must contain \"\(substring)\""
            )
        }
        XCTAssertEqual(CapsuleResults.rendering(of: "x-acme-air-gapped"), "x-acme-air-gapped")

        // A qualified pass never reads as a bare "verified", and an
        // unsupported verdict never reads as a failure.
        let (origin, bytes) = try buildBoundCapsule()
        XCTAssertEqual(CapsuleResults.headline(
            CapsuleVerifier.verify(bytes, allowlist: [origin.publicKeyHex])), "verified · trusted")
        XCTAssertEqual(CapsuleResults.headline(CapsuleVerifier.verify(bytes)),
                       "verified, with caveats")
        let unsupported = CapsuleVerifier.verify(try Data(contentsOf: Self.vectorsDir
            .appendingPathComponent("result-vocabulary/output/unsupported-newer.capsule")))
        XCTAssertEqual(CapsuleResults.headline(unsupported),
                       "not verifiable by this verifier (unsupported_version_newer)")
    }

    /// The gate order is a reported fact: an unknown era refuses first,
    /// and the profile declaration beside it is REPORTED but
    /// "unevaluated" — profile semantics are era-scoped, so an unknown
    /// era means the declaration cannot even be classified.
    func testVersionGateRefusesBeforeTheProfileGate() throws {
        let bytes = try Data(contentsOf: Self.vectorsDir.appendingPathComponent(
            "profile-declaration/output/unknown-version-profile-unevaluated.capsule"))
        let v = CapsuleVerifier.verify(bytes)
        XCTAssertEqual(v.verdict, "unsupported")
        XCTAssertEqual(v.verdictReason, "unsupported_version_newer")
        XCTAssertEqual(v.formatVersion.observed, "9.9")
        XCTAssertEqual(v.profile.status, "unevaluated")
        XCTAssertEqual(v.profile.observed, "x-test-kms-1")
        XCTAssertEqual(v.profile.observedVersion, "1.0")
        XCTAssertNil(v.profile.effective, "no profile's rules were applied")
    }
}

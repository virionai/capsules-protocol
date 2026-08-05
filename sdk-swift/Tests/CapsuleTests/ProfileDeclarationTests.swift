// Profile declaration policy unit pins (spec/profiles.md). The
// registry-driven fixtures live in SpecRegistryTests
// (testProfileDeclarationRegistryOutcomes); this file pins the
// machinery: the frozen default row, the identifier grammar, the closed
// status vocabulary over the declaration dyad, the typed refusals and
// their cross-lane needles, and the host-policy channel.

import Foundation
import XCTest
@testable import Capsule

final class ProfileDeclarationTests: XCTestCase {

    private static let defaultDeclaration = JCSValue.object([
        ("id", .string("v0.6-suite")), ("version", .string("1.0")),
    ])
    private static let vendorDeclaration = JCSValue.object([
        ("id", .string("x-test-kms-1")), ("version", .string("1.0")),
    ])

    /// The absence rule makes this spelling permanent: absence in a
    /// 0.6/0.7 capsule means THIS pair, forever, so it can never be
    /// renamed without reinterpreting every capsule already sealed.
    func testDefaultTableRowIsFrozen() {
        XCTAssertEqual(CapsuleProfiles.defaultProfile.id, "v0.6-suite")
        XCTAssertEqual(CapsuleProfiles.defaultProfile.version, "1.0")
        XCTAssertEqual(CapsuleProfiles.supportedProfiles, [CapsuleProfiles.defaultProfile])
    }

    func testIdentifierGrammar() {
        XCTAssertTrue(CapsuleProfiles.isValidProfileId("v0.6-suite"))
        XCTAssertTrue(CapsuleProfiles.isValidProfileId("x-acme-kms-es256"))
        XCTAssertTrue(CapsuleProfiles.isValidProfileId("a"))
        XCTAssertTrue(CapsuleProfiles.isValidProfileId(String(repeating: "a", count: 64)))
        XCTAssertFalse(CapsuleProfiles.isValidProfileId(String(repeating: "a", count: 65)),
                       "the cap is 64 bytes")
        XCTAssertFalse(CapsuleProfiles.isValidProfileId("Acme"), "lowercase only")
        XCTAssertFalse(CapsuleProfiles.isValidProfileId("Acme KMS!"), "closed charset")
        XCTAssertFalse(CapsuleProfiles.isValidProfileId("0abc"), "the first byte is a letter")
        XCTAssertFalse(CapsuleProfiles.isValidProfileId("abc-"), "no trailing dash")
        XCTAssertFalse(CapsuleProfiles.isValidProfileId("abc."), "no trailing dot")
        XCTAssertFalse(CapsuleProfiles.isValidProfileId("x-acme"),
                       "x- ids are vendor-scoped x-<vendor>-<name>")
        XCTAssertFalse(CapsuleProfiles.isValidProfileId(""))
        // The version grammar is the format-version grammar.
        XCTAssertTrue(CapsuleProfiles.isValidProfileVersion("1.0"))
        XCTAssertTrue(CapsuleProfiles.isValidProfileVersion("9.9"))
        XCTAssertFalse(CapsuleProfiles.isValidProfileVersion("1"))
        XCTAssertFalse(CapsuleProfiles.isValidProfileVersion("01.0"))
    }

    /// The closed status vocabulary over the dyad. Normalization is what
    /// keeps the truthful shapes legal: absence means the default, so
    /// the default declared in ONE document is coherent, while an
    /// alternate declared in one document is exactly as ambiguous as two
    /// disagreeing alternates.
    func testClassifyClosedStatusVocabulary() {
        func status(_ m: JCSValue?, _ e: JCSValue?) -> CapsuleProfiles.Status {
            CapsuleProfiles.classify(manifestDeclaration: m, envelopeDeclaration: e).status
        }
        let dflt = Self.defaultDeclaration
        let vendor = Self.vendorDeclaration
        XCTAssertEqual(status(nil, nil), .default)
        XCTAssertEqual(status(dflt, nil), .default)
        XCTAssertEqual(status(nil, dflt), .default)
        XCTAssertEqual(status(dflt, dflt), .default)
        XCTAssertEqual(status(vendor, vendor), .unsupported)
        XCTAssertEqual(status(vendor, dflt), .mismatched)
        XCTAssertEqual(status(vendor, nil), .mismatched)
        // Exact-match on the PAIR: a known id with an unknown version is
        // not understood, and two versions of one id disagree.
        XCTAssertEqual(
            status(.object([("id", .string("v0.6-suite")), ("version", .string("9.9"))]),
                   .object([("id", .string("v0.6-suite")), ("version", .string("9.9"))])),
            .unsupported
        )
        XCTAssertEqual(
            status(.object([("id", .string("x-a-b")), ("version", .string("1.0"))]),
                   .object([("id", .string("x-a-b")), ("version", .string("2.0"))])),
            .mismatched
        )
        // A present null is not a second spelling of absence.
        XCTAssertEqual(status(.null, nil), .invalid)
        XCTAssertEqual(status(.string("v0.6-suite"), nil), .invalid)
        // The object is CLOSED — including the reserved `critical` name.
        XCTAssertEqual(
            status(.object([("id", .string("v0.6-suite")), ("version", .string("1.0")),
                            ("critical", .array([]))]), nil),
            .invalid
        )
        // params are single-sourced in the manifest.
        XCTAssertEqual(
            status(nil, .object([("id", .string("v0.6-suite")), ("version", .string("1.0")),
                                 ("params", .object([]))])),
            .invalid
        )
        // ...and legal there, on a well-formed declaration.
        XCTAssertEqual(
            status(.object([("id", .string("v0.6-suite")), ("version", .string("1.0")),
                            ("params", .object([("issuer", .string("https://x.example"))]))]), nil),
            .default
        )
    }

    /// The three refusals stay three distinguishable facts, each with
    /// the cross-lane needle its remediation depends on.
    func testTypedRefusalsCarryTheCrossLaneNeedles() {
        func refusal(_ m: JCSValue?, _ e: JCSValue?) -> CapsuleError? {
            var manifest: [(String, JCSValue)] = []
            if let m { manifest.append(("format", .object([("profile", m)]))) }
            var envelope: [(String, JCSValue)] = []
            if let e { envelope.append(("profile", e)) }
            do {
                try CapsuleProfiles.requireSupported(manifest: .object(manifest),
                                                     envelope: .object(envelope))
                return nil
            } catch let error as CapsuleError {
                return error
            } catch {
                return nil
            }
        }
        XCTAssertNil(refusal(nil, nil), "absence is the default profile, not a refusal")
        XCTAssertNil(refusal(Self.defaultDeclaration, Self.defaultDeclaration))

        let unsupported = refusal(Self.vendorDeclaration, Self.vendorDeclaration)
        guard case .profileRefused(let status, let observed, let observedVersion, let declared, let message)?
            = unsupported
        else { return XCTFail("expected a profile refusal") }
        XCTAssertEqual(status, "unsupported")
        XCTAssertEqual(observed, "x-test-kms-1")
        XCTAssertEqual(observedVersion, "1.0")
        XCTAssertTrue(declared)
        XCTAssertTrue(message.contains("profile 'x-test-kms-1' version '1.0' is not supported by this verifier"))
        XCTAssertTrue(message.contains(
            "this is a limitation of the verifier, not corruption of the capsule "
            + "— verify it with an implementation of that profile"))

        let mismatch = refusal(Self.vendorDeclaration, Self.defaultDeclaration)
        guard case .profileRefused(let mStatus, _, _, _, let mMessage)? = mismatch
        else { return XCTFail("expected a profile refusal") }
        XCTAssertEqual(mStatus, "mismatched")
        XCTAssertTrue(mMessage.contains("envelope.profile does not match manifest.format.profile"))
        XCTAssertTrue(mMessage.contains("'x-test-kms-1' version '1.0'"))
        XCTAssertTrue(mMessage.contains("'v0.6-suite' version '1.0'"))
        XCTAssertFalse(mMessage.contains("unsupported"),
                       "a mismatch is a capsule defect, never a verifier limitation")

        let invalid = refusal(.null, nil)
        guard case .profileRefused(let iStatus, _, _, _, let iMessage)? = invalid
        else { return XCTFail("expected a profile refusal") }
        XCTAssertEqual(iStatus, "invalid")
        XCTAssertTrue(iMessage.hasPrefix("manifest.format.profile"),
                      "shape refusals are field-path prefixed")
        XCTAssertFalse(iMessage.contains("unsupported"),
                       "malformed is a defect of the capsule, never a support gap")
    }

    /// A capsule sealed by this SDK declares nothing — and the result
    /// SAYS what absence meant, rather than leaving it folklore.
    func testAbsenceIsReportedAsTheEffectiveDefault() throws {
        let origin = Ed25519KeyPair.generate()
        let builder = CapsuleBuilder(originator: .init(keyPair: origin, label: "acme"),
                                     createdAt: "2026-05-12T20:00:00Z")
        _ = try builder
            .setParticipants([.init(actorId: "human:alice")])
            .setProgram("# Profile absence\n")
            .appendEvent(actor: "human:alice", kind: "decision", action: "submit",
                         target: "program.md", payload: jobj(("summary", "submitted")))
        let bytes = try builder.seal(signedAt: "2026-05-12T20:00:00Z").bytes

        let v = CapsuleVerifier.verify(bytes, allowlist: [origin.publicKeyHex])
        XCTAssertTrue(v.ok, "\(v.checks.filter { !$0.ok })")
        XCTAssertNil(v.profile.observed)
        XCTAssertFalse(v.profile.declared)
        XCTAssertEqual(v.profile.effective, "v0.6-suite")
        XCTAssertEqual(v.profile.effectiveVersion, "1.0")
        XCTAssertTrue(v.profile.supported)
        XCTAssertEqual(v.profile.status, "default")
        XCTAssertNil(v.profile.acceptedByPolicy, "no policy declared: no verdict to report")
        XCTAssertEqual(v.formatVersion.suite, "v0.6", "the era default keeps the suite fact true")
    }

    /// Host policy is REPORTED, never decided: a capsule outside the
    /// accepted set still verifies, with the verdict beside the observed
    /// profile and a note the renderer can surface.
    func testAcceptProfilesIsReportedNeverDecided() throws {
        let origin = Ed25519KeyPair.generate()
        let builder = CapsuleBuilder(originator: .init(keyPair: origin, label: "acme"),
                                     createdAt: "2026-05-12T20:00:00Z")
        _ = try builder
            .setParticipants([.init(actorId: "human:alice")])
            .setProgram("# Profile policy\n")
            .appendEvent(actor: "human:alice", kind: "decision", action: "submit",
                         target: "program.md", payload: jobj(("summary", "submitted")))
        let bytes = try builder.seal(signedAt: "2026-05-12T20:00:00Z").bytes

        let accepted = CapsuleVerifier.verify(bytes, allowlist: [origin.publicKeyHex],
                                              acceptProfiles: ["v0.6-suite"])
        XCTAssertEqual(accepted.profile.acceptedByPolicy, true)
        XCTAssertTrue(accepted.ok)

        let rejected = CapsuleVerifier.verify(bytes, allowlist: [origin.publicKeyHex],
                                              acceptProfiles: ["x-acme-kms"])
        XCTAssertEqual(rejected.profile.acceptedByPolicy, false)
        XCTAssertTrue(rejected.ok, "policy never decides the verdict")
        XCTAssertEqual(rejected.verdict, "valid")
        XCTAssertTrue(rejected.notes.contains(where: { $0.contains("not in the declared accepted set") }))
    }

    /// The encrypted inner package is a fully-formed capsule, and
    /// `openInner` re-enters `CapsuleReader.parse` — so the inner
    /// declaration is gated independently at L3 (spec/profiles.md
    /// obligation 11: no inner/outer equality rule). Pinned by the happy
    /// path, mirroring the JS reference lane.
    func testL3InnerCapsuleIsGatedIndependently() throws {
        let origin = Ed25519KeyPair.generate()
        let recipient = X25519KeyPair.generate()
        let builder = CapsuleBuilder(originator: .init(keyPair: origin, label: "acme"),
                                     createdAt: "2026-05-12T20:00:00Z")
        _ = try builder
            .setParticipants([.init(actorId: "human:alice")])
            .setProgram("# Encrypted profile gate\n")
            .appendEvent(actor: "human:alice", kind: "decision", action: "submit",
                         target: "program.md", payload: jobj(("summary", "submitted")))
        let bytes = try builder.seal(
            signedAt: "2026-05-12T20:00:00Z",
            recipients: [.init(publicKey: recipient.publicKeyBytes)]
        ).bytes

        let outer = CapsuleVerifier.verify(bytes, allowlist: [origin.publicKeyHex])
        XCTAssertTrue(outer.ok, "\(outer.checks.filter { !$0.ok })")
        XCTAssertEqual(outer.profile.status, "default")

        // The inner package parses through the same gate.
        let inner = try CapsuleReader.openInner(
            try CapsuleReader.parse(bytes),
            recipientPrivateKey: recipient.privateKeyBytes,
            recipientPublicKey: recipient.publicKeyBytes
        )
        XCTAssertNil(CapsuleProfiles.member(inner.manifest, "format", "profile"),
                     "reference builders emit no declaration: absence is canonical")
        XCTAssertEqual(
            try CapsuleProfiles.requireSupported(manifest: inner.manifest,
                                                 envelope: inner.envelope).status,
            .default
        )
        let l3 = CapsuleVerifier.verify(bytes,
                                        recipientPrivateKey: recipient.privateKeyBytes,
                                        recipientPublicKey: recipient.publicKeyBytes,
                                        allowlist: [origin.publicKeyHex])
        XCTAssertTrue(l3.ok, "\(l3.checks.filter { !$0.ok })")
        XCTAssertEqual(l3.profile.status, "default")
    }
}

// Signer-set binding (manifest.signer_commitment), duplicate-signer
// rejection, distinct trusted-key counting, and originator binding.
//
// Mirrors sdk-js/test/signer-set.test.js at the unit level; the
// cross-lane fixture outcomes live in SpecRegistryTests (signer-set
// collection). Rule: PRESENCE BINDS, ABSENCE REPORTS.

import Foundation
import XCTest
@testable import Capsule

final class SignerSetTests: XCTestCase {

    private func sealedCapsule(_ kp: Ed25519KeyPair) throws -> CapsuleBuilder.BuildResult {
        let builder = CapsuleBuilder(
            originator: .init(keyPair: kp, label: "Acme"),
            createdAt: "2026-05-07T12:00:00Z"
        )
        builder
            .setProgram("# Loan file\n")
            .setParticipants([.init(actorId: "human:alice", role: "originator", label: "Alice")])
            .appendEvent(
                actor: "human:alice", kind: "decision",
                action: "submit", target: "program.md",
                payload: .object([("summary", .string("submitted"))])
            )
        return try builder.seal(signedAt: "2026-05-07T12:00:00Z")
    }

    func testSealEmitsSignerCommitment() throws {
        let kp = Ed25519KeyPair.generate()
        let result = try sealedCapsule(kp)
        let parsed = try CapsuleReader.parse(result.bytes)
        guard case .object(let pairs) = parsed.manifest,
              let scPair = pairs.first(where: { $0.0 == "signer_commitment" }),
              case .array(let members) = scPair.1
        else {
            XCTFail("manifest.signer_commitment must be present")
            return
        }
        XCTAssertEqual(members.count, 1)
        guard case .object(let member) = members[0] else {
            XCTFail("commitment member must be an object")
            return
        }
        let role = member.first(where: { $0.0 == "role" })?.1
        let key = member.first(where: { $0.0 == "public_key" })?.1
        XCTAssertEqual(role, .string("originator"))
        XCTAssertEqual(key, .string(kp.publicKeyHex))
    }

    func testBoundCapsuleVerifiesAndReportsBound() throws {
        let kp = Ed25519KeyPair.generate()
        let result = try sealedCapsule(kp)
        let v = CapsuleVerifier.verify(result.bytes, allowlist: [kp.publicKeyHex])
        XCTAssertTrue(v.ok, "\(v.checks.filter { !$0.ok })")
        XCTAssertTrue(v.signerSetBound)
        let check = v.checks.first(where: { $0.name == "signer_commitment" })
        XCTAssertEqual(check?.ok, true)
        let binding = v.checks.first(where: { $0.name == "originator_binding" })
        XCTAssertEqual(binding?.ok, true)
    }

    /// Post-seal append of a fresh, VALID attacker signature in a chosen
    /// role — the measured T1 attack. Only the commitment equality catches it.
    func testAppendedSignerInChosenRoleFailsClosed() throws {
        let kp = Ed25519KeyPair.generate()
        let attacker = Ed25519KeyPair.generate()
        let result = try sealedCapsule(kp)
        var files = try CapsuleZip.unpack(result.bytes)
        let envIdx = files.firstIndex(where: { $0.path == "provenance/envelope.json" })!
        var envelope = try CapsuleReader.parseJSON(files[envIdx].data)
        let input = try Envelope.signingInput(envelope, role: "notary")
        let sig = try attacker.sign(input)
        guard case .object(var pairs) = envelope,
              let sIdx = pairs.firstIndex(where: { $0.0 == "signers" }),
              case .array(var signers) = pairs[sIdx].1
        else {
            XCTFail("envelope must carry signers")
            return
        }
        signers.append(.object([
            ("role", .string("notary")),
            ("public_key", .string(attacker.publicKeyHex)),
            ("signature", .string(Bytes.toHex(sig))),
        ]))
        pairs[sIdx] = ("signers", .array(signers))
        envelope = .object(pairs)
        files[envIdx] = ("provenance/envelope.json", try JCS.bytes(envelope))
        let tampered = CapsuleZip.pack(files)

        let v = CapsuleVerifier.verify(tampered, allowlist: [kp.publicKeyHex])
        XCTAssertFalse(v.ok)
        let check = v.checks.first(where: { $0.name == "signer_commitment" })
        XCTAssertEqual(check?.ok, false, "\(v.checks)")
        XCTAssertTrue(check?.detail.contains("signer_commitment mismatch") == true,
                      check?.detail ?? "")
    }

    func testDuplicateSignerEntryIsMalformed() throws {
        let kp = Ed25519KeyPair.generate()
        let result = try sealedCapsule(kp)
        var files = try CapsuleZip.unpack(result.bytes)
        let envIdx = files.firstIndex(where: { $0.path == "provenance/envelope.json" })!
        var envelope = try CapsuleReader.parseJSON(files[envIdx].data)
        guard case .object(var pairs) = envelope,
              let sIdx = pairs.firstIndex(where: { $0.0 == "signers" }),
              case .array(var signers) = pairs[sIdx].1, let first = signers.first
        else {
            XCTFail("envelope must carry signers")
            return
        }
        signers.append(first)
        pairs[sIdx] = ("signers", .array(signers))
        envelope = .object(pairs)
        files[envIdx] = ("provenance/envelope.json", try JCS.bytes(envelope))
        let tampered = CapsuleZip.pack(files)

        let v = CapsuleVerifier.verify(tampered, allowlist: [kp.publicKeyHex])
        XCTAssertFalse(v.ok)
        let envCheck = v.checks.first(where: { $0.name == "envelope_signature" })
        XCTAssertEqual(envCheck?.ok, false)
        XCTAssertTrue(envCheck?.detail.contains("duplicate signer") == true,
                      envCheck?.detail ?? "")
        XCTAssertEqual(v.trustedSignerCount, 0, "duplicates must never inflate the count")
    }

    /// The absent-commitment and originator-binding negative cases are
    /// fixture-driven (SpecRegistryTests, signer-set collection); here we
    /// pin the unbound REPORT shape on a commitment-less capsule.
    func testAbsentCommitmentReportsUnbound() throws {
        let vectors = URL(fileURLWithPath: #file)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("spec/vectors/signer-set/output")
        let bytes = try Data(contentsOf: vectors.appendingPathComponent("commitment-absent.capsule"))
        let v = CapsuleVerifier.verify(bytes)
        XCTAssertTrue(v.ok, "\(v.checks.filter { !$0.ok })")
        XCTAssertFalse(v.signerSetBound)
        let check = v.checks.first(where: { $0.name == "signer_commitment" })
        XCTAssertEqual(check?.ok, true)
        XCTAssertTrue(check?.detail.contains("absent") == true, check?.detail ?? "")
        XCTAssertTrue(v.notes.joined(separator: " ").contains("signer_commitment absent"))
    }
}

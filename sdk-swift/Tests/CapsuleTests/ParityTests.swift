// Cross-implementation parity tests against the JS reference's
// tamper-detection corpus.
//
// Mirrors sdk-py/tests/test_parity_jssdk.py and the Kotlin
// ParityTest.kt. The JS SDK's examples/tamper-detection/build.mjs
// produces six fixtures plus a keys.json — committed to the repo so
// every SDK shares one source of truth. This file drives the Swift
// verifier against the four plain fixtures plus the two encrypted
// fixtures (one clean, one with the encrypted blob tampered), then
// proves Swift can decrypt a JS-produced encrypted capsule with the
// JS-supplied recipient key.
//
// These are the tests that catch cross-SDK divergence — exactly the
// class of bug the historical Kotlin Envelope domain-separator issue
// was (Kotlin signed with a space while JS signed with NUL, so any
// JS-produced capsule would have silently failed Kotlin verification).
// `testCleanCapsuleVerifies` is the canonical regression catcher for
// that class of bug in Swift.
//
// Fixture loading uses `#file` to walk up to the repo root rather than
// duplicating bytes into the test bundle. This matches the Python and
// Kotlin parity tests, which also read from the shared fixtures dir.

import Foundation
import XCTest
@testable import Capsule

final class ParityTests: XCTestCase {

    // MARK: - Fixture loading

    /// Resolves the shared `examples/tamper-detection/output/` directory
    /// relative to this test file. Walks up from
    ///   <repo>/sdk-swift/Tests/CapsuleTests/ParityTests.swift
    /// to
    ///   <repo>/examples/tamper-detection/output/
    /// by deleting four trailing path components.
    private static let fixturesURL: URL = {
        let testFile = URL(fileURLWithPath: #file)
        let repoRoot = testFile
            .deletingLastPathComponent()  // CapsuleTests/
            .deletingLastPathComponent()  // Tests/
            .deletingLastPathComponent()  // sdk-swift/
            .deletingLastPathComponent()  // <repo-root>/
        return repoRoot.appendingPathComponent("examples/tamper-detection/output")
    }()

    private func loadFixture(_ name: String) throws -> Data {
        let url = Self.fixturesURL.appendingPathComponent(name)
        guard FileManager.default.fileExists(atPath: url.path) else {
            XCTFail(
                "Tamper-detection fixture missing at \(url.path). " +
                "Regenerate via: cd examples/tamper-detection && npm install && npm run build"
            )
            throw CocoaError(.fileReadNoSuchFile)
        }
        return try Data(contentsOf: url)
    }

    /// Reads the originator public key (hex) from the JS-emitted keys.json
    /// so the allowlist exactly matches what JS signed with.
    private func jsOriginatorPubkey() throws -> String {
        let data = try loadFixture("keys.json")
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        let originator = obj?["originator"] as? [String: Any]
        guard let pub = originator?["publicKey"] as? String else {
            XCTFail("keys.json missing originator.publicKey")
            throw CocoaError(.fileReadCorruptFile)
        }
        return pub
    }

    /// Reads the recipient X25519 keypair from keys.json. Both halves are
    /// returned as raw 32-byte values (hex-decoded).
    private func jsRecipientKeys() throws -> (publicKey: Data, privateKey: Data) {
        let data = try loadFixture("keys.json")
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        let recipient = obj?["recipient"] as? [String: Any]
        guard let pub = recipient?["publicKey"] as? String,
              let priv = recipient?["privateKey"] as? String
        else {
            XCTFail("keys.json missing recipient.publicKey or recipient.privateKey")
            throw CocoaError(.fileReadCorruptFile)
        }
        return (Bytes.fromHex(pub), Bytes.fromHex(priv))
    }

    /// Returns the named check from a verification result, or fails the
    /// test if not present. Useful for asserting on the *specific* check
    /// that should have failed, not just on `ok == false`.
    private func check(_ v: CapsuleVerification, _ name: String) -> VerifyCheck? {
        v.checks.first(where: { $0.name == name })
    }

    // MARK: - Plain fixtures: Swift verifies what JS produced

    /// The canonical regression test for cross-SDK divergence. If this
    /// fails, the Swift verifier disagrees with the JS reference on a
    /// clean capsule — the same shape of bug the Kotlin SDK shipped with
    /// before its domain-separator was fixed.
    func testCleanCapsuleVerifies() throws {
        let bytes = try loadFixture("clean.capsule")
        let pub = try jsOriginatorPubkey()

        let v = CapsuleVerifier.verify(bytes, allowlist: [pub])
        XCTAssertTrue(
            v.ok,
            "JS-produced clean.capsule failed Swift verification: " +
            v.checks.filter { !$0.ok }.map { "\($0.name):\($0.detail)" }.joined(separator: ", ")
        )
        XCTAssertEqual(v.trustedSignerCount, 1, "expected one trusted signer")
        XCTAssertEqual(v.signers.count, 1, "expected one signer entry")
        XCTAssertEqual(v.signers.first?.role, "originator", "expected originator role")
        XCTAssertEqual(v.level, "L2", "plain capsule verifies at L2")
    }

    /// program.md byte-flipped → recomputed content_index.index_hash no
    /// longer matches the stored value. The verifier must surface this
    /// specifically as `content_index_hash` failing, not just as `ok=false`.
    func testTamperedPayloadFailsAtContentIndex() throws {
        let bytes = try loadFixture("tampered-payload.capsule")
        let pub = try jsOriginatorPubkey()

        let v = CapsuleVerifier.verify(bytes, allowlist: [pub])
        XCTAssertFalse(v.ok, "tampered-payload.capsule unexpectedly verified")
        let ci = check(v, "content_index_hash")
        XCTAssertNotNil(ci, "expected a content_index_hash check entry")
        XCTAssertEqual(ci?.ok, false,
                       "content_index_hash should have failed; got \(String(describing: ci))")
    }

    /// Rewriting an event payload changes both the chain link hash and
    /// the content_index hash for chain/events.jsonl. Either failing is
    /// the spec-correct outcome — matches the Python parity assertion.
    func testTamperedChainFails() throws {
        let bytes = try loadFixture("tampered-chain.capsule")
        let pub = try jsOriginatorPubkey()

        let v = CapsuleVerifier.verify(bytes, allowlist: [pub])
        XCTAssertFalse(v.ok, "tampered-chain.capsule unexpectedly verified")
        let chain = check(v, "chain")
        let ci = check(v, "content_index_hash")
        let failed = (chain?.ok == false) || (ci?.ok == false)
        XCTAssertTrue(
            failed,
            "expected chain or content_index_hash to fail; got chain=\(String(describing: chain)) ci=\(String(describing: ci))"
        )
    }

    /// Byte-flipping the originator's signature must fail envelope
    /// signature verification — not content_index, not chain.
    func testTamperedEnvelopeFailsAtEnvelope() throws {
        let bytes = try loadFixture("tampered-envelope.capsule")
        let pub = try jsOriginatorPubkey()

        let v = CapsuleVerifier.verify(bytes, allowlist: [pub])
        XCTAssertFalse(v.ok, "tampered-envelope.capsule unexpectedly verified")
        let env = check(v, "envelope_signature")
        XCTAssertNotNil(env, "expected an envelope_signature check entry")
        XCTAssertEqual(env?.ok, false,
                       "envelope_signature should have failed; got \(String(describing: env))")
        // The signer itself should also be reported invalid (and not trusted).
        XCTAssertEqual(v.signers.first?.valid, false, "originator signature should be invalid")
        XCTAssertEqual(v.trustedSignerCount, 0, "no signer should be trusted")
    }

    // MARK: - Encrypted fixtures: v0.2 verify + decrypt

    /// The JS-built encrypted clean capsule passes Swift's L2 verifier
    /// without any recipient key. Inner chain is deferred to L3.
    func testCleanEncryptedL2Verifies() throws {
        let bytes = try loadFixture("clean-encrypted.capsule")
        let pub = try jsOriginatorPubkey()

        // Sanity: the outer is genuinely encrypted before we ask the
        // verifier to handle it — otherwise we'd pass for the wrong reason.
        let parsed = try CapsuleReader.parse(bytes)
        XCTAssertTrue(parsed.isEncrypted, "clean-encrypted.capsule should report isEncrypted=true")

        let v = CapsuleVerifier.verify(bytes, allowlist: [pub])
        XCTAssertTrue(
            v.ok,
            "JS-produced clean-encrypted.capsule failed Swift L2: " +
            v.checks.filter { !$0.ok }.map { "\($0.name):\($0.detail)" }.joined(separator: ", ")
        )
        XCTAssertEqual(v.level, "L2", "encrypted-outer verifies at L2 without a recipient key")
        XCTAssertEqual(v.trustedSignerCount, 1, "expected one trusted signer")
        XCTAssertEqual(v.signers.count, 1, "expected one signer entry")
        // The chain check is recorded but deferred, and encrypted_blob_hash
        // must specifically verify.
        XCTAssertEqual(check(v, "encrypted_blob_hash")?.ok, true,
                       "encrypted_blob_hash should verify for the clean encrypted fixture")
        let chain = check(v, "chain")
        XCTAssertEqual(chain?.ok, true, "chain should be marked ok (deferred to L3)")
        XCTAssertTrue(
            chain?.detail.contains("deferred") ?? false,
            "chain detail should note that it is deferred; got: \(chain?.detail ?? "nil")"
        )
    }

    /// Byte-flipping a byte inside content.enc → SHA-256(content.enc) no
    /// longer matches the envelope's `encrypted_blob_hash`. The Swift
    /// verifier must surface this specifically.
    func testTamperedBlobFailsAtEncryptedBlobHash() throws {
        let bytes = try loadFixture("tampered-blob.capsule")
        let pub = try jsOriginatorPubkey()

        // Sanity: tamper target is still an encrypted-outer capsule.
        let parsed = try CapsuleReader.parse(bytes)
        XCTAssertTrue(parsed.isEncrypted, "tampered-blob.capsule should still report isEncrypted=true")

        let v = CapsuleVerifier.verify(bytes, allowlist: [pub])
        XCTAssertFalse(v.ok, "tampered-blob.capsule unexpectedly verified")
        let blob = check(v, "encrypted_blob_hash")
        XCTAssertNotNil(blob, "expected an encrypted_blob_hash check entry")
        XCTAssertEqual(
            blob?.ok, false,
            "encrypted_blob_hash should have failed; got \(String(describing: blob))"
        )
    }

    /// Decrypt a JS-produced encrypted capsule using the JS recipient
    /// key, parse the inner content, then verify inner content as well.
    /// Asserts the inner program.md is non-empty (the JS fixture ships
    /// real program content) — guards against a vacuous decrypt that
    /// returns an empty inner.
    func testDecryptCleanEncryptedWithJsRecipientKey() throws {
        let bytes = try loadFixture("clean-encrypted.capsule")
        let (recipientPub, recipientPriv) = try jsRecipientKeys()
        let pub = try jsOriginatorPubkey()

        let outer = try CapsuleReader.parse(bytes)
        XCTAssertTrue(outer.isEncrypted, "outer reader should report isEncrypted=true")
        XCTAssertEqual(outer.programMd, "", "outer programMd is hidden until decrypt")
        XCTAssertEqual(outer.events.count, 0, "outer events list is empty for encrypted-outer")

        // Decrypt with the JS recipient keypair from keys.json.
        let inner = try CapsuleReader.openInner(
            outer,
            recipientPrivateKey: recipientPriv,
            recipientPublicKey: recipientPub
        )
        XCTAssertFalse(inner.isEncrypted, "inner reader should report isEncrypted=false")
        XCTAssertFalse(
            inner.programMd.isEmpty,
            "inner programMd should have content; JS fixture ships real program.md"
        )
        XCTAssertTrue(
            inner.programMd.contains("# "),
            "inner programMd should have at least one markdown heading; got: \(inner.programMd.prefix(80))"
        )
        XCTAssertGreaterThan(inner.events.count, 0,
                             "inner chain should have at least one event")

        // L3 verification = outer + decrypt + inner + cross-checks.
        let v = CapsuleVerifier.verify(
            bytes,
            recipientPrivateKey: recipientPriv,
            recipientPublicKey: recipientPub,
            allowlist: [pub]
        )
        XCTAssertTrue(
            v.ok,
            "L3 verify of JS-built clean-encrypted.capsule failed: " +
            v.checks.filter { !$0.ok }.map { "\($0.name):\($0.detail)" }.joined(separator: ", ")
        )
        XCTAssertEqual(v.level, "L3", "decrypted verify should report level L3")
        // Outer originator + inner originator → 2 signer entries.
        XCTAssertEqual(v.signers.count, 2, "expected 2 signer entries (outer + inner)")
        XCTAssertEqual(v.trustedSignerCount, 2,
                       "both outer and inner originator signers should be trusted")
    }
}

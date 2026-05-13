// Encryption tests for Task B: X25519 + HKDF-SHA256 + ChaCha20-Poly1305
// primitives plus the multi-recipient builder/reader/verifier path.

import XCTest
@testable import Capsule
@testable import CapsuleSkills

final class EncryptionPrimitiveTests: XCTestCase {

    func testX25519DhRoundTrip() throws {
        let alice = X25519KeyPair.generate()
        let bob = X25519KeyPair.generate()
        let aShared = try alice.dh(peerPublicKey: bob.publicKeyBytes)
        let bShared = try bob.dh(peerPublicKey: alice.publicKeyBytes)
        XCTAssertEqual(aShared, bShared, "ECDH must yield identical shared secret")
        XCTAssertEqual(aShared.count, 32)
    }

    func testX25519RawPrivateRoundTrip() throws {
        let kp = X25519KeyPair.generate()
        let raw = kp.privateKeyBytes
        let restored = try X25519KeyPair.fromRawPrivate(raw)
        XCTAssertEqual(restored.privateKeyBytes, raw)
        XCTAssertEqual(restored.publicKeyBytes, kp.publicKeyBytes)
    }

    /// RFC 5869 §A.1 (Test Case 1: basic HKDF-SHA256).
    func testHkdfSha256RfcVector() {
        let ikm = Bytes.fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        let salt = Bytes.fromHex("000102030405060708090a0b0c")
        let info = Bytes.fromHex("f0f1f2f3f4f5f6f7f8f9")
        let expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        let okm = HKDF.sha256(ikm: ikm, salt: salt, info: info, length: 42)
        XCTAssertEqual(Bytes.toHex(okm), expected)
    }

    func testChaChaPolySealOpenRoundTrip() throws {
        let key = Random.key32()
        let nonce = Random.nonce12()
        let aad = Data("aad bytes".utf8)
        let plaintext = Data("hello world, this is some plaintext".utf8)
        let ct = try ChaCha20Poly1305.encrypt(
            key: key, nonce: nonce, aad: aad, plaintext: plaintext
        )
        // ciphertext is `plaintext || 16-byte tag`
        XCTAssertEqual(ct.count, plaintext.count + 16)
        let pt = try ChaCha20Poly1305.decrypt(
            key: key, nonce: nonce, aad: aad, ciphertext: ct
        )
        XCTAssertEqual(pt, plaintext)
    }

    func testChaChaPolyEmptyAad() throws {
        let key = Random.key32()
        let nonce = Random.nonce12()
        let plaintext = Data("payload".utf8)
        let ct = try ChaCha20Poly1305.encrypt(
            key: key, nonce: nonce, aad: Data(), plaintext: plaintext
        )
        let pt = try ChaCha20Poly1305.decrypt(
            key: key, nonce: nonce, aad: Data(), ciphertext: ct
        )
        XCTAssertEqual(pt, plaintext)
    }

    func testChaChaPolyTamperedCiphertextFailsAead() throws {
        let key = Random.key32()
        let nonce = Random.nonce12()
        let aad = Data("aad".utf8)
        var ct = try ChaCha20Poly1305.encrypt(
            key: key, nonce: nonce, aad: aad, plaintext: Data("hello".utf8)
        )
        // Flip a bit in the body (not the tag) — must still fail authentication.
        ct[0] ^= 0x01
        XCTAssertThrowsError(
            try ChaCha20Poly1305.decrypt(key: key, nonce: nonce, aad: aad, ciphertext: ct)
        )
    }

    func testChaChaPolyWrongAadFails() throws {
        let key = Random.key32()
        let nonce = Random.nonce12()
        let ct = try ChaCha20Poly1305.encrypt(
            key: key, nonce: nonce, aad: Data("aad-A".utf8), plaintext: Data("p".utf8)
        )
        XCTAssertThrowsError(
            try ChaCha20Poly1305.decrypt(
                key: key, nonce: nonce, aad: Data("aad-B".utf8), ciphertext: ct
            )
        )
    }

    func testRandomBytesAreDistinct() {
        let a = Random.key32()
        let b = Random.key32()
        XCTAssertEqual(a.count, 32)
        XCTAssertEqual(b.count, 32)
        XCTAssertNotEqual(a, b)
        XCTAssertEqual(Random.nonce12().count, 12)
    }
}

// MARK: - End-to-end encrypted capsule tests

final class EncryptedRoundTripTests: XCTestCase {

    /// Build a one-event capsule with a deterministic shape; returns the
    /// originator keypair, the recipient keypairs, and the sealed bytes.
    private func buildEncryptedCapsule(
        recipients: [X25519KeyPair],
        signedAt: String = "2026-05-12T20:00:00Z"
    ) throws -> (origin: Ed25519KeyPair, bytes: Data) {
        let origin = Ed25519KeyPair.generate()
        let builder = CapsuleBuilder(
            originator: .init(keyPair: origin, label: "test-originator"),
            createdAt: signedAt
        )
        builder
            .setProgram("# Hello\n\nEncrypted capsule under test.\n")
            .setAgents("# Agents\n")
            .appendEvent(
                actor: "human:test", kind: "observation",
                action: "noted", target: "program.md",
                payload: jobj(("note", "first event"))
            )
            .appendEvent(
                actor: "human:test", kind: "decision",
                action: "approved", target: "program.md",
                payload: jobj(("decision", "go"))
            )
            .addSkill(id: "demo", json: Data(#"{"id":"demo","actions":[]}"#.utf8),
                      markdown: "# Demo\n", signed: false)
            .addPayload(.init(path: "payload/notes.txt", bytes: Data("hello\n".utf8)))
        let result = try builder.seal(
            signedAt: signedAt,
            recipients: recipients.map { .init(publicKey: $0.publicKeyBytes) }
        )
        return (origin, result.bytes)
    }

    func testEncryptedRoundTrip() throws {
        let recipient = X25519KeyPair.generate()
        let (origin, bytes) = try buildEncryptedCapsule(recipients: [recipient])

        // L2 verifies the outer envelope without a recipient key.
        let l2 = CapsuleVerifier.verify(bytes, allowlist: [origin.publicKeyHex])
        XCTAssertTrue(l2.ok, "L2 failed: \(l2.checks.filter { !$0.ok })")
        XCTAssertEqual(l2.level, "L2")
        XCTAssertEqual(l2.trustedSignerCount, 1)

        // Reader.parse exposes the encrypted outer.
        let outerParsed = try CapsuleReader.parse(bytes)
        XCTAssertTrue(outerParsed.isEncrypted)
        XCTAssertEqual(outerParsed.programMd, "") // hidden until decrypt
        XCTAssertEqual(outerParsed.events.count, 0)
        XCTAssertNotNil(outerParsed.decryptionMetadata())
        XCTAssertNotNil(outerParsed.files["content.enc"])

        // openInner unwraps the content key and decrypts.
        let inner = try CapsuleReader.openInner(
            outerParsed,
            recipientPrivateKey: recipient.privateKeyBytes,
            recipientPublicKey: recipient.publicKeyBytes
        )
        XCTAssertFalse(inner.isEncrypted)
        XCTAssertEqual(inner.programMd.split(separator: "\n").first, "# Hello")
        XCTAssertEqual(inner.events.count, 2)

        // L3 verification = L2 outer + L2 inner + cross-checks.
        let l3 = CapsuleVerifier.verify(
            bytes,
            recipientPrivateKey: recipient.privateKeyBytes,
            recipientPublicKey: recipient.publicKeyBytes,
            allowlist: [origin.publicKeyHex]
        )
        XCTAssertTrue(l3.ok, "L3 failed: \(l3.checks.filter { !$0.ok }.map { "\($0.name):\($0.detail)" })")
        XCTAssertEqual(l3.level, "L3")
        // Outer + inner each have one originator signer → 2 signers total.
        XCTAssertEqual(l3.signers.count, 2)
        XCTAssertEqual(l3.trustedSignerCount, 2)
    }

    func testEncryptedRoundTripTwoRecipients() throws {
        let alice = X25519KeyPair.generate()
        let bob = X25519KeyPair.generate()
        let (origin, bytes) = try buildEncryptedCapsule(recipients: [alice, bob])
        let outer = try CapsuleReader.parse(bytes)

        // Each recipient independently decrypts to the same inner content.
        let innerA = try CapsuleReader.openInner(
            outer,
            recipientPrivateKey: alice.privateKeyBytes,
            recipientPublicKey: alice.publicKeyBytes
        )
        let innerB = try CapsuleReader.openInner(
            outer,
            recipientPrivateKey: bob.privateKeyBytes,
            recipientPublicKey: bob.publicKeyBytes
        )
        XCTAssertEqual(innerA.programMd, innerB.programMd)
        XCTAssertEqual(innerA.events.count, innerB.events.count)
        XCTAssertEqual(innerA.events.count, 2)

        let l3a = CapsuleVerifier.verify(
            bytes,
            recipientPrivateKey: alice.privateKeyBytes,
            recipientPublicKey: alice.publicKeyBytes,
            allowlist: [origin.publicKeyHex]
        )
        XCTAssertTrue(l3a.ok)
        let l3b = CapsuleVerifier.verify(
            bytes,
            recipientPrivateKey: bob.privateKeyBytes,
            recipientPublicKey: bob.publicKeyBytes,
            allowlist: [origin.publicKeyHex]
        )
        XCTAssertTrue(l3b.ok)
    }

    func testUnknownCipherRejected() throws {
        // Corrupt the cipher in the *outer envelope* to an unsupported
        // algorithm. The verifier and the reader.openInner must fail closed.
        let recipient = X25519KeyPair.generate()
        let (_, bytes) = try buildEncryptedCapsule(recipients: [recipient])

        // Decode the outer envelope, swap cipher, repack the zip.
        let entries = try CapsuleZip.unpack(bytes)
        var files = entries.reduce(into: [String: Data]()) { $0[$1.path] = $1.data }
        guard let envBytes = files["provenance/envelope.json"] else {
            return XCTFail("envelope missing")
        }
        guard var envStr = String(data: envBytes, encoding: .utf8) else {
            return XCTFail("envelope not utf-8")
        }
        envStr = envStr.replacingOccurrences(
            of: "\"cipher\":\"ChaCha20-Poly1305\"",
            with: "\"cipher\":\"AES-256-GCM\""
        )
        files["provenance/envelope.json"] = Data(envStr.utf8)
        let tampered = CapsuleZip.pack(files.map { ($0.key, $0.value) })

        // Reader should refuse to decrypt under an unsupported cipher.
        let outer = try CapsuleReader.parse(tampered)
        XCTAssertThrowsError(
            try CapsuleReader.openInner(
                outer,
                recipientPrivateKey: recipient.privateKeyBytes,
                recipientPublicKey: recipient.publicKeyBytes
            )
        )
        // Verifier reports the failure as a failed check; never panics.
        let v = CapsuleVerifier.verify(tampered)
        XCTAssertFalse(v.ok)
    }

    func testUnknownCipherInDecryptionMetadataRejected() throws {
        // Similar to the previous test but corrupts the cipher field
        // *inside* skills/decryption/decryption.json instead of the
        // envelope. Reader must still fail closed.
        let recipient = X25519KeyPair.generate()
        let (_, bytes) = try buildEncryptedCapsule(recipients: [recipient])

        let entries = try CapsuleZip.unpack(bytes)
        var files = entries.reduce(into: [String: Data]()) { $0[$1.path] = $1.data }
        guard let metaBytes = files["skills/decryption/decryption.json"],
              let metaStr = String(data: metaBytes, encoding: .utf8)
        else { return XCTFail("decryption.json missing") }
        let tamperedMeta = metaStr.replacingOccurrences(
            of: "\"cipher\":\"ChaCha20-Poly1305\"",
            with: "\"cipher\":\"AES-256-GCM\""
        )
        files["skills/decryption/decryption.json"] = Data(tamperedMeta.utf8)
        let tampered = CapsuleZip.pack(files.map { ($0.key, $0.value) })

        let outer = try CapsuleReader.parse(tampered)
        XCTAssertThrowsError(
            try CapsuleReader.openInner(
                outer,
                recipientPrivateKey: recipient.privateKeyBytes,
                recipientPublicKey: recipient.publicKeyBytes
            )
        )
    }

    func testTamperedEncryptedBlobFailsAead() throws {
        let recipient = X25519KeyPair.generate()
        let (_, bytes) = try buildEncryptedCapsule(recipients: [recipient])

        let entries = try CapsuleZip.unpack(bytes)
        var files = entries.reduce(into: [String: Data]()) { $0[$1.path] = $1.data }
        guard var blob = files["content.enc"] else {
            return XCTFail("content.enc missing")
        }
        blob[0] ^= 0x01
        files["content.enc"] = blob
        let tampered = CapsuleZip.pack(files.map { ($0.key, $0.value) })

        let outer = try CapsuleReader.parse(tampered)
        XCTAssertThrowsError(
            try CapsuleReader.openInner(
                outer,
                recipientPrivateKey: recipient.privateKeyBytes,
                recipientPublicKey: recipient.publicKeyBytes
            )
        ) { err in
            // CapsuleError.malformed with AEAD detail; not a panic.
            XCTAssertTrue("\(err)".lowercased().contains("aead"),
                          "expected AEAD-related malformed: got \(err)")
        }
    }

    func testWrongRecipientKeyFails() throws {
        let intended = X25519KeyPair.generate()
        let interloper = X25519KeyPair.generate()
        let (_, bytes) = try buildEncryptedCapsule(recipients: [intended])
        let outer = try CapsuleReader.parse(bytes)

        // Using the interloper's keypair: no bundle matches the
        // interloper's public key, so the reader fails before any AEAD
        // computation. This is the protocol-correct failure mode.
        XCTAssertThrowsError(
            try CapsuleReader.openInner(
                outer,
                recipientPrivateKey: interloper.privateKeyBytes,
                recipientPublicKey: interloper.publicKeyBytes
            )
        )

        // Substituting just the wrong private key while still presenting
        // the intended public key (no useful attack scenario, but makes
        // sure AEAD also catches a mismatched key half).
        XCTAssertThrowsError(
            try CapsuleReader.openInner(
                outer,
                recipientPrivateKey: interloper.privateKeyBytes,
                recipientPublicKey: intended.publicKeyBytes
            )
        )
    }

    func testL2EncryptedVerifies() throws {
        let recipient = X25519KeyPair.generate()
        let (origin, bytes) = try buildEncryptedCapsule(recipients: [recipient])
        // L2 must verify the outer envelope without any recipient key.
        let v = CapsuleVerifier.verify(bytes, allowlist: [origin.publicKeyHex])
        XCTAssertTrue(v.ok, "L2 not ok: \(v.checks.filter { !$0.ok })")
        XCTAssertEqual(v.level, "L2")
        XCTAssertEqual(v.signers.count, 1)
        XCTAssertEqual(v.trustedSignerCount, 1)
        // Encrypted_blob_hash check must appear in the L2 result.
        XCTAssertTrue(v.checks.contains { $0.name == "encrypted_blob_hash" && $0.ok })
        // Chain is deferred.
        XCTAssertTrue(v.checks.contains { $0.name == "chain" && $0.detail.contains("deferred") })
    }
}

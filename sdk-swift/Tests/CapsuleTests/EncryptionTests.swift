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

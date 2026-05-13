// Crypto — SHA-256, Ed25519, X25519, HKDF-SHA256, and ChaCha20-Poly1305
// via CryptoKit (Apple-supplied, FIPS path). Mirrors the JS reference;
// both produce identical hex bytes for the same inputs.
//
// X25519 raw 32-byte keys round-trip through CryptoKit's
// `Curve25519.KeyAgreement` types. HKDF uses CryptoKit's typed `HKDF<H>`.
// ChaChaPoly seals into a SealedBox; the on-wire layout the protocol
// mandates is `ciphertext || tag`, which is what `SealedBox.ciphertext`
// concatenated with `SealedBox.tag` produces — matching the JS Node
// `crypto` ChaCha20-Poly1305 output and the Python `cryptography`
// ChaCha20Poly1305 output.

import Foundation
import CryptoKit

public enum Hash {
    public static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }
    public static func sha256Hex(_ data: Data) -> String {
        Bytes.toHex(sha256(data))
    }
}

public enum Bytes {
    public static func toHex(_ data: Data) -> String {
        var out = ""
        out.reserveCapacity(data.count * 2)
        for b in data {
            out += String(format: "%02x", b)
        }
        return out
    }
    public static func fromHex(_ hex: String) -> Data {
        precondition(hex.count % 2 == 0, "hex: odd length")
        var out = Data(capacity: hex.count / 2)
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            guard let byte = UInt8(hex[idx..<next], radix: 16) else {
                preconditionFailure("hex: non-hex char")
            }
            out.append(byte)
            idx = next
        }
        return out
    }
    public static func concat(_ parts: Data...) -> Data {
        var out = Data()
        for p in parts { out.append(p) }
        return out
    }
}

// Ed25519 keypair. Private key persists as raw 32 bytes; the public key is
// derived. CryptoKit handles the signing primitives.
public struct Ed25519KeyPair {
    public let privateKey: Curve25519.Signing.PrivateKey
    public var publicKeyBytes: Data { privateKey.publicKey.rawRepresentation }
    public var publicKeyHex: String { Bytes.toHex(publicKeyBytes) }
    public var privateKeyBytes: Data { privateKey.rawRepresentation }

    public static func generate() -> Ed25519KeyPair {
        Ed25519KeyPair(privateKey: Curve25519.Signing.PrivateKey())
    }
    public static func fromRawPrivate(_ raw: Data) throws -> Ed25519KeyPair {
        let pk = try Curve25519.Signing.PrivateKey(rawRepresentation: raw)
        return Ed25519KeyPair(privateKey: pk)
    }
    public func sign(_ message: Data) throws -> Data {
        try privateKey.signature(for: message)
    }
}

public enum Ed25519 {
    public static func verify(publicKey: Data, message: Data, signature: Data) -> Bool {
        guard let pk = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else {
            return false
        }
        return pk.isValidSignature(signature, for: message)
    }
}

// MARK: - X25519 (Curve25519 ECDH)

// X25519 keypair. Mirrors `Ed25519KeyPair`'s shape: raw 32-byte private
// key is the canonical persistence; the public key is derived. Used for
// recipient-side key agreement during multi-recipient encryption.
public struct X25519KeyPair {
    public let privateKey: Curve25519.KeyAgreement.PrivateKey
    public var publicKeyBytes: Data { privateKey.publicKey.rawRepresentation }
    public var publicKeyHex: String { Bytes.toHex(publicKeyBytes) }
    public var privateKeyBytes: Data { privateKey.rawRepresentation }

    public static func generate() -> X25519KeyPair {
        X25519KeyPair(privateKey: Curve25519.KeyAgreement.PrivateKey())
    }
    public static func fromRawPrivate(_ raw: Data) throws -> X25519KeyPair {
        let pk = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: raw)
        return X25519KeyPair(privateKey: pk)
    }
    /// X25519 ECDH; returns the raw 32-byte shared secret.
    public func dh(peerPublicKey: Data) throws -> Data {
        guard peerPublicKey.count == 32 else {
            throw CapsuleError.malformed("X25519 peer pubkey must be 32 bytes, got \(peerPublicKey.count)")
        }
        let pk = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey)
        let secret = try privateKey.sharedSecretFromKeyAgreement(with: pk)
        return secret.withUnsafeBytes { Data($0) }
    }
}

// MARK: - HKDF-SHA256

public enum HKDF {
    /// HKDF-SHA256(IKM, salt, info, length). Matches Node `hkdfSync("sha256", ...)`
    /// and `cryptography.hazmat.primitives.kdf.hkdf.HKDF(SHA256)`.
    public static func sha256(ikm: Data, salt: Data, info: Data, length: Int) -> Data {
        precondition(length > 0, "HKDF length must be > 0")
        // SymmetricKey wraps the IKM without copying its raw bytes.
        let key = SymmetricKey(data: ikm)
        let derived = CryptoKit.HKDF<SHA256>.deriveKey(
            inputKeyMaterial: key,
            salt: salt,
            info: info,
            outputByteCount: length
        )
        return derived.withUnsafeBytes { Data($0) }
    }
}

// MARK: - ChaCha20-Poly1305 (AEAD)

public enum ChaCha20Poly1305 {
    /// Combined-output encrypt: returns `ciphertext || tag` (16-byte tag
    /// appended), matching JS Node `crypto.createCipheriv("chacha20-poly1305", …)`
    /// and Python `cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305`.
    /// The 12-byte nonce is *not* embedded in the output.
    public static func encrypt(key: Data, nonce: Data, aad: Data, plaintext: Data) throws -> Data {
        precondition(key.count == 32, "ChaCha20-Poly1305 key must be 32 bytes")
        precondition(nonce.count == 12, "ChaCha20-Poly1305 nonce must be 12 bytes")
        let symKey = SymmetricKey(data: key)
        let n = try ChaChaPoly.Nonce(data: nonce)
        let box = try ChaChaPoly.seal(plaintext, using: symKey, nonce: n, authenticating: aad)
        var out = Data()
        out.reserveCapacity(box.ciphertext.count + box.tag.count)
        out.append(box.ciphertext)
        out.append(box.tag)
        return out
    }

    /// Inverse of `encrypt`. Takes the `ciphertext || tag` combined buffer,
    /// the 12-byte nonce, and the original AAD. Throws if authentication
    /// fails.
    public static func decrypt(key: Data, nonce: Data, aad: Data, ciphertext: Data) throws -> Data {
        precondition(key.count == 32, "ChaCha20-Poly1305 key must be 32 bytes")
        precondition(nonce.count == 12, "ChaCha20-Poly1305 nonce must be 12 bytes")
        guard ciphertext.count >= 16 else {
            throw CapsuleError.malformed("ciphertext too short for ChaCha20-Poly1305 tag")
        }
        let symKey = SymmetricKey(data: key)
        let n = try ChaChaPoly.Nonce(data: nonce)
        let tagStart = ciphertext.count - 16
        let ct = ciphertext.prefix(tagStart)
        let tag = ciphertext.suffix(16)
        let box = try ChaChaPoly.SealedBox(nonce: n, ciphertext: ct, tag: tag)
        return try ChaChaPoly.open(box, using: symKey, authenticating: aad)
    }
}

// MARK: - Random

public enum Random {
    /// Cryptographically-secure random bytes via SecRandomCopyBytes.
    public static func bytes(_ count: Int) -> Data {
        precondition(count > 0, "random byte count must be > 0")
        var out = Data(count: count)
        let status = out.withUnsafeMutableBytes { ptr -> Int32 in
            guard let base = ptr.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed: \(status)")
        return out
    }
    public static func key32() -> Data { bytes(32) }
    public static func nonce12() -> Data { bytes(12) }
}

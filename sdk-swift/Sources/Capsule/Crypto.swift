// Crypto — SHA-256 + Ed25519 via CryptoKit (Apple-supplied, FIPS path).
// Mirrors the JS reference; both produce identical hex bytes for the same
// inputs.

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

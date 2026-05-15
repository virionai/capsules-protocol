// Provenance envelope: build, sign, verify. Mirrors envelope.js.

import Foundation

public enum Envelope {
    static let VERSION = "0.6"
    static let SUPPORTED_CIPHERS: Set<String> = ["none", "ChaCha20-Poly1305"]

    public struct Signer {
        public let role: String
        public let keyPair: Ed25519KeyPair
        public init(role: String, keyPair: Ed25519KeyPair) {
            self.role = role; self.keyPair = keyPair
        }
    }

    public static func build(
        capsuleId: String,
        firstEventHash: String,
        entryHash: String,
        manifestHash: String,
        contentIndexHash: String,
        encryptedBlobHash: String? = nil,
        cipher: String = "none",
        signedAt: String
    ) -> JCSValue {
        precondition(SUPPORTED_CIPHERS.contains(cipher), "unsupported cipher")
        if cipher == "none" {
            precondition(encryptedBlobHash == nil, "plain capsule must have encrypted_blob_hash=null")
        } else {
            precondition(encryptedBlobHash != nil, "encrypted capsule needs blob hash")
        }
        return .object([
            ("version", .string(VERSION)),
            ("capsule_id", .string(capsuleId)),
            ("first_event_hash", .string(firstEventHash)),
            ("entry_hash", .string(entryHash)),
            ("manifest_hash", .string(manifestHash)),
            ("content_index_hash", .string(contentIndexHash)),
            ("encrypted_blob_hash", encryptedBlobHash.map { .string($0) } ?? .null),
            ("cipher", .string(cipher)),
            ("signed_at", .string(signedAt)),
            ("signers", .array([])),
        ])
    }

    /// Returns JCS bytes of the envelope minus the `signers` field.
    static func canonicalPayload(_ envelope: JCSValue) -> Data {
        guard case .object(let pairs) = envelope else {
            preconditionFailure("envelope is not an object")
        }
        let withoutSigners = pairs.filter { $0.0 != "signers" }
        return JCS.bytes(.object(withoutSigners))
    }

    /// `domain_sep || canonical(envelope_minus_signers)` — the signing input.
    static func signingInput(_ envelope: JCSValue, role: String) -> Data {
        precondition(!role.isEmpty)
        let domain = Data("capsule-provenance-v\(VERSION):\(role)\0".utf8)
        return Bytes.concat(domain, canonicalPayload(envelope))
    }

    public static func sign(_ envelope: inout JCSValue, signers: [Signer]) throws {
        guard case .object(var pairs) = envelope else {
            preconditionFailure("envelope is not an object")
        }
        guard let sIdx = pairs.firstIndex(where: { $0.0 == "signers" }),
              case .array(let existing) = pairs[sIdx].1, existing.isEmpty
        else { throw CapsuleError.malformed("envelope already has signers") }

        var signed: [JCSValue] = []
        for s in signers {
            let input = signingInput(envelope, role: s.role)
            let sig = try s.keyPair.sign(input)
            signed.append(.object([
                ("role", .string(s.role)),
                ("public_key", .string(s.keyPair.publicKeyHex)),
                ("signature", .string(Bytes.toHex(sig))),
            ]))
        }
        pairs[sIdx] = ("signers", .array(signed))
        envelope = .object(pairs)
    }

    public struct VerifyResult {
        public let ok: Bool
        public let signers: [(role: String, publicKey: String, valid: Bool)]
        public let note: String?
    }

    public static func verifySignatures(_ envelope: JCSValue) -> VerifyResult {
        guard case .object(let pairs) = envelope,
              let versionPair = pairs.first(where: { $0.0 == "version" }),
              case .string(let v) = versionPair.1, v == VERSION
        else { return VerifyResult(ok: false, signers: [], note: "unsupported version") }

        guard let cipherPair = pairs.first(where: { $0.0 == "cipher" }),
              case .string(let c) = cipherPair.1, SUPPORTED_CIPHERS.contains(c)
        else { return VerifyResult(ok: false, signers: [], note: "unsupported cipher") }

        guard let signersPair = pairs.first(where: { $0.0 == "signers" }),
              case .array(let signersArr) = signersPair.1, !signersArr.isEmpty
        else { return VerifyResult(ok: false, signers: [], note: "no signers") }

        var allValid = true
        var out: [(String, String, Bool)] = []
        for s in signersArr {
            guard case .object(let sp) = s,
                  let rolePair = sp.first(where: { $0.0 == "role" }),
                  case .string(let role) = rolePair.1,
                  let pkPair = sp.first(where: { $0.0 == "public_key" }),
                  case .string(let pkHex) = pkPair.1,
                  let sigPair = sp.first(where: { $0.0 == "signature" }),
                  case .string(let sigHex) = sigPair.1
            else { allValid = false; continue }
            // Hex strings on the wire are caller-supplied — never panic.
            // A malformed signer is just an invalid signature.
            guard let pkBytes = try? Bytes.fromHexThrowing(pkHex, label: "signer.public_key"),
                  let sigBytes = try? Bytes.fromHexThrowing(sigHex, label: "signer.signature")
            else {
                allValid = false
                out.append((role, pkHex, false))
                continue
            }
            let input = signingInput(envelope, role: role)
            let valid = Ed25519.verify(
                publicKey: pkBytes,
                message: input,
                signature: sigBytes
            )
            if !valid { allValid = false }
            out.append((role, pkHex, valid))
        }
        return VerifyResult(ok: allValid, signers: out, note: nil)
    }
}

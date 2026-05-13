// CapsuleReader — open a sealed capsule, parse manifest/envelope/
// chain/program.md/agents.md, and surface its files map. Plain and
// encrypted-outer capsules are both accepted. For encrypted-outer the
// `programMd` field is empty and `events` is empty (no chain inside the
// outer); call `openInner(...)` with a recipient key to peel the outer
// wrapper and read the inner content. Verification lives in
// CapsuleVerifier; reader is just structured access.

import Foundation

public struct ParsedCapsule {
    public let manifest: JCSValue
    public let envelope: JCSValue
    /// Empty for encrypted-outer capsules.
    public let events: [JCSValue]
    /// Empty for encrypted-outer capsules; the inner package's program.md
    /// is exposed after a successful `openInner(...)` call.
    public let programMd: String
    /// `nil` for capsules without an `agents.md`.
    public let agentsMd: String?
    public let files: [String: Data]

    public init(manifest: JCSValue, envelope: JCSValue, events: [JCSValue],
                programMd: String, agentsMd: String?, files: [String: Data]) {
        self.manifest = manifest; self.envelope = envelope; self.events = events
        self.programMd = programMd; self.agentsMd = agentsMd; self.files = files
    }

    /// True when the outer manifest carries a non-null `encryption` field.
    /// Plain capsules return false; encrypted-outer capsules return true.
    public var isEncrypted: Bool {
        guard case .object(let pairs) = manifest,
              let enc = pairs.first(where: { $0.0 == "encryption" })
        else { return false }
        return enc.1 != .null
    }

    /// Parsed `skills/decryption/decryption.json` for encrypted outer
    /// capsules. `nil` when the file is absent, unparseable, or this
    /// capsule is plain.
    public func decryptionMetadata() -> JCSValue? {
        guard isEncrypted else { return nil }
        // Prefer the manifest-declared metadata_path; fall back to the
        // spec-default location for resilience.
        var path = "skills/decryption/decryption.json"
        if case .object(let pairs) = manifest,
           let encVal = pairs.first(where: { $0.0 == "encryption" })?.1,
           case .object(let encPairs) = encVal,
           let mp = encPairs.first(where: { $0.0 == "metadata_path" })?.1,
           case .string(let s) = mp
        {
            path = s
        }
        guard let bytes = files[path] else { return nil }
        return try? CapsuleReader.parseJSON(bytes)
    }
}

public struct VerifyCheck {
    public let name: String
    public let ok: Bool
    public let detail: String
    public init(name: String, ok: Bool, detail: String = "") {
        self.name = name; self.ok = ok; self.detail = detail
    }
}

public struct VerifyResult {
    public let ok: Bool
    public let checks: [VerifyCheck]
    public init(ok: Bool, checks: [VerifyCheck]) {
        self.ok = ok; self.checks = checks
    }
}

public enum CapsuleReader {

    /// Parse a sealed capsule's bytes. Accepts both plain and
    /// encrypted-outer capsules. For an encrypted outer the returned
    /// `ParsedCapsule.programMd` is `""` and `events` is `[]`; call
    /// `openInner(...)` with a recipient key to peel the outer wrapper.
    public static func parse(_ bytes: Data) throws -> ParsedCapsule {
        let entries = try CapsuleZip.unpack(bytes)
        var files = [String: Data]()
        for (path, data) in entries { files[path] = data }

        guard let mfBytes = files["manifest.json"] else {
            throw CapsuleError.malformed("missing manifest.json")
        }
        guard let envBytes = files["provenance/envelope.json"] else {
            throw CapsuleError.malformed("missing provenance/envelope.json")
        }
        let manifest = try parseJSON(mfBytes)
        let envelope = try parseJSON(envBytes)

        // Detect encrypted-outer. The chain/program/agents files live
        // inside the encrypted blob, not the outer zip.
        let encrypted: Bool = {
            guard case .object(let pairs) = manifest,
                  let enc = pairs.first(where: { $0.0 == "encryption" })
            else { return false }
            return enc.1 != .null
        }()

        if encrypted {
            // Outer must carry the ciphertext blob.
            if files["content.enc"] == nil {
                throw CapsuleError.malformed("encrypted outer missing content.enc")
            }
            return ParsedCapsule(
                manifest: manifest, envelope: envelope, events: [],
                programMd: "", agentsMd: nil, files: files
            )
        }

        guard let evBytes = files["chain/events.jsonl"] else {
            throw CapsuleError.malformed("missing chain/events.jsonl")
        }
        guard let progBytes = files["program.md"] else {
            throw CapsuleError.malformed("missing program.md")
        }
        var events: [JCSValue] = []
        for raw in evBytes.split(separator: 0x0A) where !raw.isEmpty {
            events.append(try parseJSON(Data(raw)))
        }
        let programMd = String(decoding: progBytes, as: UTF8.self)
        let agentsMd = files["agents.md"].map { String(decoding: $0, as: UTF8.self) }

        return ParsedCapsule(
            manifest: manifest, envelope: envelope, events: events,
            programMd: programMd, agentsMd: agentsMd, files: files
        )
    }

    /// Decrypt an encrypted-outer capsule and return a `ParsedCapsule`
    /// over the inner package. The caller supplies their X25519 raw
    /// private + public key (32 bytes each). The reader looks up the
    /// matching recipient bundle in `skills/decryption/decryption.json`,
    /// HKDF-derives the wrap key from the X25519 ECDH shared secret,
    /// unwraps the content key, rebuilds the AAD per the JS reference
    /// (no manifest_hash — see `Builder.swift`'s seal-encrypted comment),
    /// and ChaCha20-Poly1305-decrypts `content.enc`. The resulting inner
    /// zip is unpacked and re-parsed as a fresh `ParsedCapsule`.
    ///
    /// Throws `CapsuleError.malformed` on missing metadata, no matching
    /// recipient bundle, AEAD authentication failure, or unsupported
    /// cipher.
    public static func openInner(_ outer: ParsedCapsule,
                                 recipientPrivateKey: Data,
                                 recipientPublicKey: Data) throws -> ParsedCapsule
    {
        guard outer.isEncrypted else {
            throw CapsuleError.malformed("capsule is not encrypted")
        }
        guard recipientPrivateKey.count == 32 else {
            throw CapsuleError.malformed("recipientPrivateKey must be 32 bytes")
        }
        guard recipientPublicKey.count == 32 else {
            throw CapsuleError.malformed("recipientPublicKey must be 32 bytes")
        }
        // Outer cipher gate — defends against an attacker swapping the
        // outer envelope's cipher field to an unsupported algorithm.
        guard let envCipher = lookupString(outer.envelope, "cipher"),
              envCipher == "ChaCha20-Poly1305"
        else {
            throw CapsuleError.malformed("unsupported outer cipher")
        }
        // Manifest's encryption.cipher must agree with the envelope.
        guard case .object(let mfPairs) = outer.manifest,
              let encVal = mfPairs.first(where: { $0.0 == "encryption" })?.1,
              case .object(let encPairs) = encVal,
              let mfCipher = encPairs.first(where: { $0.0 == "cipher" })?.1,
              case .string(let mfCipherStr) = mfCipher,
              mfCipherStr == "ChaCha20-Poly1305"
        else {
            throw CapsuleError.malformed("manifest.encryption.cipher unsupported")
        }
        guard let metaVal = outer.decryptionMetadata() else {
            throw CapsuleError.malformed("missing decryption metadata")
        }
        guard case .object(let metaPairs) = metaVal,
              let metaCipher = metaPairs.first(where: { $0.0 == "cipher" })?.1,
              case .string(let metaCipherStr) = metaCipher,
              metaCipherStr == "ChaCha20-Poly1305"
        else {
            throw CapsuleError.malformed("decryption metadata cipher unsupported")
        }
        guard let nonceHex = metaPairs.first(where: { $0.0 == "content_nonce" })?.1,
              case .string(let contentNonceHex) = nonceHex
        else {
            throw CapsuleError.malformed("decryption metadata missing content_nonce")
        }
        guard let kbVal = metaPairs.first(where: { $0.0 == "key_bundles" })?.1,
              case .array(let bundles) = kbVal
        else {
            throw CapsuleError.malformed("decryption metadata missing key_bundles")
        }
        let recipientHex = Bytes.toHex(recipientPublicKey)
        var match: (ephPub: Data, wrapNonce: Data, wrappedKey: Data)? = nil
        for b in bundles {
            guard case .object(let pairs) = b,
                  let rpkV = pairs.first(where: { $0.0 == "recipient_public_key" })?.1,
                  case .string(let rpkHex) = rpkV
            else { continue }
            if rpkHex.lowercased() != recipientHex.lowercased() { continue }
            guard let epV = pairs.first(where: { $0.0 == "ephemeral_public_key" })?.1,
                  case .string(let epHex) = epV,
                  let wnV = pairs.first(where: { $0.0 == "wrap_nonce" })?.1,
                  case .string(let wnHex) = wnV,
                  let wkV = pairs.first(where: { $0.0 == "wrapped_key" })?.1,
                  case .string(let wkHex) = wkV
            else {
                throw CapsuleError.malformed("key bundle missing required fields")
            }
            match = (Bytes.fromHex(epHex), Bytes.fromHex(wnHex), Bytes.fromHex(wkHex))
            break
        }
        guard let m = match else {
            throw CapsuleError.malformed("no matching recipient bundle")
        }
        let recipient = try X25519KeyPair.fromRawPrivate(recipientPrivateKey)
        // Sanity: caller-supplied public key must match the derived one.
        // We don't enforce this strictly because the bundle was selected
        // by the caller-supplied public key already; if they disagree the
        // ECDH below produces a key that won't decrypt — handled by AEAD.

        let shared = try recipient.dh(peerPublicKey: m.ephPub)
        let wrapKey = HKDF.sha256(
            ikm: shared,
            salt: recipientPublicKey,
            info: Data("capsule-key-wrap-v0.6".utf8),
            length: 32
        )
        let contentKey: Data
        do {
            contentKey = try ChaCha20Poly1305.decrypt(
                key: wrapKey, nonce: m.wrapNonce, aad: Data(), ciphertext: m.wrappedKey
            )
        } catch {
            throw CapsuleError.malformed("wrap key unwrap failed (AEAD): \(error)")
        }
        // Reconstruct the AAD — must match the builder side exactly. Per
        // the JS reference comment in Builder.swift, manifest_hash is
        // intentionally omitted.
        guard let envCapsuleId = lookupString(outer.envelope, "capsule_id"),
              let envFirstHash = lookupString(outer.envelope, "first_event_hash")
        else {
            throw CapsuleError.malformed("outer envelope missing identity fields")
        }
        guard let mfOrigPub = lookupString(outer.manifest, "originator", "public_key") else {
            throw CapsuleError.malformed("outer manifest missing originator.public_key")
        }
        let aad = JCS.bytes(.object([
            ("version", .string("0.6")),
            ("capsule_id", .string(envCapsuleId)),
            ("first_event_hash", .string(envFirstHash)),
            ("originator_public_key", .string(mfOrigPub)),
            ("cipher", .string("ChaCha20-Poly1305")),
        ]))
        guard let contentEnc = outer.files["content.enc"] else {
            throw CapsuleError.malformed("content.enc missing")
        }
        let contentNonce = Bytes.fromHex(contentNonceHex)
        let innerZip: Data
        do {
            innerZip = try ChaCha20Poly1305.decrypt(
                key: contentKey, nonce: contentNonce, aad: aad, ciphertext: contentEnc
            )
        } catch {
            throw CapsuleError.malformed("content.enc AEAD decrypt failed: \(error)")
        }
        // The inner zip is itself a fully-formed plain capsule; re-parse.
        return try parse(innerZip)
    }

    private static func lookupString(_ v: JCSValue, _ keys: String...) -> String? {
        var cur = v
        for k in keys {
            guard case .object(let pairs) = cur,
                  let next = pairs.first(where: { $0.0 == k })?.1 else { return nil }
            cur = next
        }
        if case .string(let s) = cur { return s }
        return nil
    }

    /// Verify chain hash linkage. Independent of envelope sigs.
    public static func verifyChain(_ events: [JCSValue]) -> Bool {
        var prev = Chain.GENESIS_PREV
        for (i, e) in events.enumerated() {
            guard case .object(let pairs) = e else { return false }
            var withoutHash: [(String, JCSValue)] = []
            var stored: String?
            for (k, v) in pairs {
                if k == "hash", case .string(let s) = v { stored = s }
                else { withoutHash.append((k, v)) }
            }
            guard let storedHash = stored,
                  let prevHash = pairs.first(where: { $0.0 == "prev_hash" }),
                  case .string(let prevHex) = prevHash.1
            else { return false }
            if i == 0 && prevHex != Bytes.toHex(Chain.GENESIS_PREV) { return false }
            if i > 0 && prevHex != Bytes.toHex(prev) { return false }
            let canonical = JCS.bytes(.object(withoutHash))
            let h = Hash.sha256(Bytes.concat(prev, canonical))
            if Bytes.toHex(h) != storedHash { return false }
            prev = h
        }
        return true
    }

    static func parseJSON(_ data: Data) throws -> JCSValue {
        let any = try JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed)
        return convert(any)
    }

    static func convert(_ any: Any) -> JCSValue {
        if any is NSNull { return .null }
        if let n = any as? NSNumber {
            if String(cString: n.objCType) == "c" { return .bool(n.boolValue) }
            if CFNumberIsFloatType(n) { return .decimal(n.doubleValue) }
            return .integer(n.int64Value)
        }
        if let s = any as? String { return .string(s) }
        if let arr = any as? [Any] { return .array(arr.map(convert)) }
        if let dict = any as? [String: Any] {
            return .object(dict.map { ($0.key, convert($0.value)) })
        }
        return .null
    }
}


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
        let manifest = try parseJSONFile(mfBytes, name: "manifest.json")
        let envelope = try parseJSONFile(envBytes, name: "provenance/envelope.json")
        // Shape check at the parse boundary (mirrors the JS reference's
        // validateManifestShape / validateEnvelopeShape): full integrity is
        // the verifier's job, but a caller reading manifest fields without
        // verifying first can rely on the basic shapes, and verification
        // stays total over whatever the reader hands back.
        try validateManifestShape(manifest)
        try validateEnvelopeShape(envelope)

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
            events.append(try parseJSONFile(Data(raw), name: "chain/events.jsonl"))
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
            // Hex from untrusted capsule metadata — must not panic on
            // malformed input. Byte-count guards run here rather than
            // relying on the downstream ChaCha20-Poly1305 preconditions.
            let ephPub = try Bytes.fromHexThrowing(
                epHex, label: "decryption.key_bundles[].ephemeral_public_key"
            )
            guard ephPub.count == 32 else {
                throw CapsuleError.malformed(
                    "decryption.key_bundles[].ephemeral_public_key must decode to 32 bytes, got \(ephPub.count)"
                )
            }
            let wrapNonce = try Bytes.fromHexThrowing(
                wnHex, label: "decryption.key_bundles[].wrap_nonce"
            )
            guard wrapNonce.count == 12 else {
                throw CapsuleError.malformed(
                    "decryption.key_bundles[].wrap_nonce must decode to 12 bytes, got \(wrapNonce.count)"
                )
            }
            let wrappedKey = try Bytes.fromHexThrowing(
                wkHex, label: "decryption.key_bundles[].wrapped_key"
            )
            guard wrappedKey.count >= 16 else {
                throw CapsuleError.malformed(
                    "decryption.key_bundles[].wrapped_key too short (\(wrappedKey.count) bytes) for AEAD tag"
                )
            }
            match = (ephPub, wrapNonce, wrappedKey)
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
        let aad = try JCS.bytes(.object([
            ("version", .string("0.6")),
            ("capsule_id", .string(envCapsuleId)),
            ("first_event_hash", .string(envFirstHash)),
            ("originator_public_key", .string(mfOrigPub)),
            ("cipher", .string("ChaCha20-Poly1305")),
        ]))
        guard let contentEnc = outer.files["content.enc"] else {
            throw CapsuleError.malformed("content.enc missing")
        }
        let contentNonce = try Bytes.fromHexThrowing(
            contentNonceHex, label: "decryption.content_nonce"
        )
        guard contentNonce.count == 12 else {
            throw CapsuleError.malformed(
                "decryption.content_nonce must decode to 12 bytes, got \(contentNonce.count)"
            )
        }
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

    /// Lowercase 64-hex predicate, per the spec's canonical-hex rule.
    static func isHex64(_ s: String) -> Bool {
        s.count == 64 && s.allSatisfy { ("0"..."9").contains($0) || ("a"..."f").contains($0) }
    }

    /// Lightweight shape check on the manifest (spec/manifest.md field
    /// rules). Error messages carry the offending field path, prefixed
    /// `manifest.`, mirroring the JS reference's validateManifestShape —
    /// the registry's `invalid_manifest_shape` reason maps onto that
    /// prefix in this lane.
    static func validateManifestShape(_ manifest: JCSValue) throws {
        guard case .object(let pairs) = manifest else {
            throw CapsuleError.malformed("manifest.json is not a JSON object")
        }
        func member(_ key: String) -> JCSValue? { pairs.first(where: { $0.0 == key })?.1 }
        var version: String? = nil
        if case .object(let fmt)? = member("format"),
           case .string(let v)? = fmt.first(where: { $0.0 == "version" })?.1 {
            version = v
        }
        guard version == "0.6" else {
            throw CapsuleError.malformed(
                "manifest.format.version: expected '0.6', got \(Chain.debugQuoted(version))")
        }
        guard case .string(let id)? = member("id"), isHex64(id) else {
            throw CapsuleError.malformed("manifest.id is not a 64-char lowercase hex string")
        }
        var origPub: String? = nil
        if case .object(let orig)? = member("originator"),
           case .string(let pk)? = orig.first(where: { $0.0 == "public_key" })?.1 {
            origPub = pk
        }
        guard let op = origPub, isHex64(op) else {
            throw CapsuleError.malformed(
                "manifest.originator.public_key must be a 64-char lowercase hex string")
        }
        // null is the legal empty-chain shape (spec/chain.md "Empty
        // chains"): a zero-event capsule has no first event to hash. The
        // verifier enforces the null-anchor / event-count consistency; the
        // reader only rejects values that are neither null nor hex.
        switch member("first_event_hash") {
        case nil, .some(.null):
            break
        case .some(.string(let s)) where isHex64(s):
            break
        default:
            throw CapsuleError.malformed(
                "manifest.first_event_hash must be a 64-char lowercase hex string or null")
        }
        try validateContentIndexShape(member("content_index"))
    }

    static func validateContentIndexShape(_ index: JCSValue?) throws {
        guard case .object(let pairs)? = index else {
            throw CapsuleError.malformed("manifest.content_index must be a JSON object")
        }
        guard case .string(let ih)? = pairs.first(where: { $0.0 == "index_hash" })?.1,
              isHex64(ih)
        else {
            throw CapsuleError.malformed(
                "manifest.content_index.index_hash must be a 64-char lowercase hex string")
        }
        guard case .array(let files)? = pairs.first(where: { $0.0 == "files" })?.1 else {
            throw CapsuleError.malformed("manifest.content_index.files must be an array")
        }
        for (i, f) in files.enumerated() {
            guard case .object(let cols) = f else {
                throw CapsuleError.malformed(
                    "manifest.content_index.files[\(i)] must be a JSON object")
            }
            guard case .string(let p)? = cols.first(where: { $0.0 == "path" })?.1, !p.isEmpty else {
                throw CapsuleError.malformed(
                    "manifest.content_index.files[\(i)].path must be a non-empty string")
            }
            guard case .string(let h)? = cols.first(where: { $0.0 == "sha256" })?.1, isHex64(h) else {
                throw CapsuleError.malformed(
                    "manifest.content_index.files[\(i)].sha256 must be a 64-char lowercase hex string")
            }
        }
    }

    static func validateEnvelopeShape(_ envelope: JCSValue) throws {
        guard case .object(let pairs) = envelope else {
            throw CapsuleError.malformed("envelope.json is not a JSON object")
        }
        guard case .string("0.6")? = pairs.first(where: { $0.0 == "version" })?.1 else {
            throw CapsuleError.malformed("envelope.version: expected '0.6'")
        }
        guard case .string(let cid)? = pairs.first(where: { $0.0 == "capsule_id" })?.1,
              isHex64(cid)
        else {
            throw CapsuleError.malformed("envelope.capsule_id must be a 64-char lowercase hex string")
        }
        guard case .array(let signers)? = pairs.first(where: { $0.0 == "signers" })?.1,
              !signers.isEmpty
        else {
            throw CapsuleError.malformed("envelope.signers must be a non-empty array")
        }
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

    /// Verify chain hash linkage plus the per-event field rules from
    /// spec/chain.md (verification steps 6 and 7). Independent of
    /// envelope signatures. Returns one message per failure; an empty
    /// array means the chain verifies.
    ///
    /// The step-6 actor rule is CONDITIONAL on the manifest's own claim:
    /// a NON-EMPTY `participants` set binds every event actor to the
    /// declared set (or the literal "system:host"), fail-closed. An
    /// EMPTY set is the manifest making no claim about who acted — the
    /// walk accepts any actor then, and the CALLER (CapsuleVerifier)
    /// reports the reduced assurance. Safe because participants is
    /// covered by manifest_hash inside the signed payload. The `kind`
    /// enum is enforced unconditionally.
    public static func verifyChain(_ events: [JCSValue],
                                   participants: Set<String> = []) -> [String]
    {
        var errors: [String] = []
        var prev = Chain.GENESIS_PREV
        for (i, e) in events.enumerated() {
            let seq = i + 1
            guard case .object(let pairs) = e else {
                errors.append("seq \(seq): event is not a JSON object")
                continue
            }
            // spec/chain.md step 6 — when the manifest declares
            // participants, the actor must be one of them or the host.
            let actor = stringField(pairs, "actor")
            if !participants.isEmpty
                && actor != Chain.HOST_ACTOR
                && !(actor.map { participants.contains($0) } ?? false)
            {
                errors.append(
                    "seq \(seq): actor \(Chain.debugQuoted(actor)) "
                        + "not in manifest.participants and not system:host"
                )
            }
            // spec/chain.md "Field rules" — `kind` is a closed enum.
            let kind = stringField(pairs, "kind")
            if !(kind.map { Chain.isValidEventKind($0) } ?? false) {
                errors.append(
                    "seq \(seq): kind \(Chain.debugQuoted(kind)) is not one of "
                        + Chain.EVENT_KINDS.joined(separator: ", ")
                )
            }
            // spec/chain.md verification step 5 — `seq` is strictly
            // monotonic from 1. The stored value must equal the event's
            // 1-based position; trusting the stored seq (or merely
            // counting events) accepts a renumbered chain.
            let seqValue = pairs.first(where: { $0.0 == "seq" })?.1
            var storedSeq: Int64? = nil
            var seqRendered = "undefined"
            switch seqValue {
            case .some(.integer(let n)):
                storedSeq = n
                seqRendered = String(n)
            case .some(.string(let s)):
                seqRendered = Chain.debugQuoted(s)
            case .some(.decimal(let d)):
                seqRendered = String(d)
            case .some:
                seqRendered = "non-integer"
            case nil:
                break
            }
            if storedSeq != Int64(seq) {
                errors.append("seq \(seq): seq \(seqRendered) expected \(seq)")
            }
            // spec/chain.md "Untrusted content" — when present, every
            // marking must match the path grammar. An unparseable marking
            // silently unmarks LLM-authored content for every host.
            if let upfValue = pairs.first(where: { $0.0 == "untrusted_payload_fields" })?.1 {
                if case .array(let items) = upfValue {
                    for (idx, item) in items.enumerated() {
                        let ok: Bool
                        let rendered: String
                        if case .string(let p) = item {
                            ok = Chain.isValidUntrustedPayloadPath(p)
                            rendered = Chain.debugQuoted(p)
                        } else {
                            ok = false
                            rendered = "non-string"
                        }
                        if !ok {
                            errors.append(
                                "seq \(seq): untrusted_payload_fields[\(idx)] is not a "
                                    + "valid payload path: \(rendered)"
                            )
                        }
                    }
                } else {
                    errors.append(
                        "seq \(seq): untrusted_payload_fields must be an array of payload paths"
                    )
                }
            }
            var withoutHash: [(String, JCSValue)] = []
            var stored: String?
            for (k, v) in pairs {
                if k == "hash", case .string(let s) = v { stored = s }
                else { withoutHash.append((k, v)) }
            }
            guard let storedHash = stored else {
                errors.append("seq \(seq): hash missing or wrong length")
                continue
            }
            guard let prevHex = stringField(pairs, "prev_hash") else {
                errors.append("seq \(seq): prev_hash missing or wrong length")
                continue
            }
            let expectedPrev = Bytes.toHex(prev)
            if prevHex != expectedPrev {
                errors.append(
                    "seq \(seq): prev_hash mismatch: got \(prevHex), expected \(expectedPrev)"
                )
            }
            // An event that cannot be canonicalized (integer outside
            // ±(2^53 − 1)) has no interoperable hash — fail closed.
            guard let canonical = try? JCS.bytes(.object(withoutHash)) else {
                errors.append("seq \(seq): recompute failed: event cannot be canonicalized")
                continue
            }
            let h = Hash.sha256(Bytes.concat(prev, canonical))
            let recomputed = Bytes.toHex(h)
            if recomputed != storedHash {
                errors.append(
                    "seq \(seq): hash mismatch: stored \(storedHash), recomputed \(recomputed)"
                )
            }
            prev = h
        }
        return errors
    }

    /// Read a string field out of a JCS object's key/value pairs.
    static func stringField(_ pairs: [(String, JCSValue)], _ key: String) -> String? {
        guard let v = pairs.first(where: { $0.0 == key })?.1,
              case .string(let s) = v else { return nil }
        return s
    }

    /// Collect `manifest.participants[].actor_id` into a lookup set.
    public static func participantActorIds(_ manifest: JCSValue) -> Set<String> {
        guard case .object(let pairs) = manifest,
              let ps = pairs.first(where: { $0.0 == "participants" })?.1,
              case .array(let items) = ps
        else { return [] }
        var out: Set<String> = []
        for item in items {
            guard case .object(let fields) = item,
                  let id = stringField(fields, "actor_id") else { continue }
            out.insert(id)
        }
        return out
    }


    /// Reject JSON text carrying duplicate object member names, at any
    /// depth (spec/canonicalization.md "Objects"; RFC 7493 §2.3). Names
    /// compare AFTER escape processing ("a" and "\u0061" are the same
    /// name), as sequences of UTF-16 code units.
    ///
    /// This is a rule about the TEXT: JSONSerialization silently keeps the
    /// last duplicate, so the parsed tree cannot show it. The scanner
    /// assumes syntactically valid JSON — callers run JSONSerialization
    /// first, so syntax errors surface as parse errors.
    static func assertNoDuplicateMembers(_ text: String, name: String) throws {
        let chars = Array(text.unicodeScalars)
        let n = chars.count
        var i = 0
        func fail(_ message: String) throws -> Never {
            throw CapsuleError.malformed("\(name): \(message)")
        }
        func skipWs() {
            while i < n, chars[i] == " " || chars[i] == "\t"
                || chars[i] == "\n" || chars[i] == "\r" { i += 1 }
        }
        func parseString() throws -> String {
            i += 1  // opening quote
            var units: [UInt16] = []
            while i < n {
                let c = chars[i]
                if c == "\"" {
                    i += 1
                    return String(decoding: units, as: UTF16.self)
                }
                if c == "\\" {
                    guard i + 1 < n else { try fail("unterminated escape") }
                    let e = chars[i + 1]
                    i += 2
                    switch e {
                    case "\"": units.append(0x22)
                    case "\\": units.append(0x5C)
                    case "/": units.append(0x2F)
                    case "b": units.append(0x08)
                    case "f": units.append(0x0C)
                    case "n": units.append(0x0A)
                    case "r": units.append(0x0D)
                    case "t": units.append(0x09)
                    case "u":
                        guard i + 4 <= n else { try fail("truncated unicode escape") }
                        var v: UInt16 = 0
                        for k in 0..<4 {
                            let s = chars[i + k]
                            let d: UInt16
                            switch s {
                            case "0"..."9": d = UInt16(s.value - 0x30)
                            case "a"..."f": d = UInt16(s.value - 0x61 + 10)
                            case "A"..."F": d = UInt16(s.value - 0x41 + 10)
                            default: try fail("invalid unicode escape")
                            }
                            v = v << 4 | d
                        }
                        i += 4
                        units.append(v)
                    default:
                        try fail("invalid escape in string")
                    }
                } else {
                    units.append(contentsOf: Array(String(c).utf16))
                    i += 1
                }
            }
            try fail("unterminated string")
        }
        func parseValue() throws {
            skipWs()
            guard i < n else { return }
            switch chars[i] {
            case "{": try parseObject()
            case "[": try parseArray()
            case "\"": _ = try parseString()
            default:
                while i < n, chars[i] != ",", chars[i] != "}", chars[i] != "]",
                      chars[i] != " ", chars[i] != "\t", chars[i] != "\n", chars[i] != "\r" {
                    i += 1
                }
            }
        }
        func parseObject() throws {
            i += 1  // {
            var seen = Set<String>()
            skipWs()
            if i < n, chars[i] == "}" { i += 1; return }
            while true {
                skipWs()
                guard i < n, chars[i] == "\"" else { try fail("expected member name") }
                let member = try parseString()
                if !seen.insert(member).inserted {
                    try fail("duplicate object member \(Chain.debugQuoted(member))")
                }
                skipWs()
                guard i < n, chars[i] == ":" else { try fail("expected ':' after member name") }
                i += 1
                try parseValue()
                skipWs()
                guard i < n else { try fail("unterminated object") }
                if chars[i] == "," { i += 1; continue }
                if chars[i] == "}" { i += 1; return }
                try fail("expected ',' or '}' in object")
            }
        }
        func parseArray() throws {
            i += 1  // [
            skipWs()
            if i < n, chars[i] == "]" { i += 1; return }
            while true {
                try parseValue()
                skipWs()
                guard i < n else { try fail("unterminated array") }
                if chars[i] == "," { i += 1; continue }
                if chars[i] == "]" { i += 1; return }
                try fail("expected ',' or ']' in array")
            }
        }
        try parseValue()
    }

    /// `parseJSON` with the offending file named in the error, so a reader
    /// rejection can be attributed to a specific document (mirrors the Rust
    /// verifier's "failed to parse manifest.json").
    static func parseJSONFile(_ data: Data, name: String) throws -> JCSValue {
        let any: Any
        do { any = try JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed) }
        catch { throw CapsuleError.malformed("failed to parse \(name)") }
        // Duplicate-member gate over the raw text (spec/canonicalization.md
        // "Objects"): JSONSerialization silently keeps the last duplicate,
        // so the rule must be checked on the text, before the value is
        // handed to anything that hashes.
        try assertNoDuplicateMembers(String(decoding: data, as: UTF8.self), name: name)
        let value = convert(any)
        // I-JSON acceptance boundary (spec/canonicalization.md). Reported in
        // its own words, NOT as "failed to parse": the JSON is syntactically
        // fine, it is the value that lies outside the canonicalization input
        // domain, and the operator must be able to tell that apart from both
        // a syntax error and a hash mismatch.
        do { try JCS.assertAcceptable(value) }
        catch CapsuleError.malformed(let message) {
            throw CapsuleError.malformed("\(name): \(message)")
        }
        return value
    }

    static func parseJSON(_ data: Data) throws -> JCSValue {
        let any = try JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed)
        // Duplicate-member gate over the raw text; see parseJSONFile.
        try assertNoDuplicateMembers(String(decoding: data, as: UTF8.self), name: "JSON")
        let value = convert(any)
        // I-JSON acceptance boundary (spec/canonicalization.md). Rejecting
        // here means an unacceptable value never reaches a hash comparison,
        // and the refusal names the path rather than reading as a mismatch.
        try JCS.assertAcceptable(value)
        return value
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


// Verifier — the canonical surface for verifying a sealed capsule.
//
// Mirrors sdk/src/verifier.js's verifyCapsule. The verifier returns
// per-check booleans plus per-signer trust attribution against an
// optional allowlist of public keys. trusted=true only when both the
// signature is valid AND the signer's pubkey is on the allowlist.

import Foundation

public struct CapsuleVerification {
    public struct SignerCheck {
        public let role: String
        public let publicKey: String
        public let valid: Bool
        public let trusted: Bool
    }
    public let ok: Bool
    /// "L2" for outer-only verification, "L3" when the inner package was
    /// also decrypted and verified.
    public let level: String
    public let checks: [VerifyCheck]
    public let signers: [SignerCheck]
    public let trustedSignerCount: Int
    public let notes: [String]
}

public enum CapsuleVerifier {
    /// Verify a sealed capsule's bytes at L2 (outer-only; no recipient key
    /// required). Accepts both plain and encrypted capsules; for encrypted
    /// outer the chain is deferred to L3 since it lives inside the
    /// ciphertext, but the `encrypted_blob_hash` is checked against
    /// `SHA-256(content.enc)`.
    ///
    /// Pass `allowlist` of hex public keys (lowercase) to mark signers
    /// trusted; the verifier never returns trusted=true on its own.
    public static func verify(_ bytes: Data,
                              allowlist: Set<String> = []) -> CapsuleVerification
    {
        let parsed: ParsedCapsule
        do { parsed = try CapsuleReader.parse(bytes) }
        catch {
            var initialNotes: [String] = []
            if allowlist.isEmpty {
                initialNotes.append("no allowlist provided; trusted=false for all signers regardless of signature validity")
            }
            return CapsuleVerification(
                ok: false, level: "L2",
                checks: [VerifyCheck(name: "parse", ok: false, detail: "\(error)")],
                signers: [], trustedSignerCount: 0, notes: initialNotes
            )
        }
        return verifyParsed(parsed, level: "L2", allowlist: allowlist)
    }

    /// Verify a sealed capsule at L3 (decrypted-content). For plain
    /// capsules this is equivalent to `verify(bytes:allowlist:)`. For
    /// encrypted outer capsules, the outer envelope is verified at L2,
    /// then the inner package is decrypted with the supplied recipient
    /// key and verified in isolation. Cross-checks the inner envelope's
    /// capsule_id / first_event_hash / entry_hash against the outer.
    ///
    /// The returned `CapsuleVerification.checks` includes the outer
    /// checks first, then a `decrypt` step, then the inner checks
    /// prefixed with `inner.`.
    public static func verify(_ bytes: Data,
                              recipientPrivateKey: Data,
                              recipientPublicKey: Data,
                              allowlist: Set<String> = []) -> CapsuleVerification
    {
        let outerParsed: ParsedCapsule
        do { outerParsed = try CapsuleReader.parse(bytes) }
        catch {
            var initialNotes: [String] = []
            if allowlist.isEmpty {
                initialNotes.append("no allowlist provided; trusted=false for all signers regardless of signature validity")
            }
            return CapsuleVerification(
                ok: false, level: "L3",
                checks: [VerifyCheck(name: "parse", ok: false, detail: "\(error)")],
                signers: [], trustedSignerCount: 0, notes: initialNotes
            )
        }
        if !outerParsed.isEncrypted {
            // Plain capsule — L3 is the same surface as L2.
            return verifyParsed(outerParsed, level: "L3", allowlist: allowlist)
        }
        let outer = verifyParsed(outerParsed, level: "L3", allowlist: allowlist)
        var checks = outer.checks

        let inner: ParsedCapsule
        do {
            inner = try CapsuleReader.openInner(
                outerParsed,
                recipientPrivateKey: recipientPrivateKey,
                recipientPublicKey: recipientPublicKey
            )
        } catch {
            checks.append(VerifyCheck(name: "decrypt", ok: false, detail: "\(error)"))
            return CapsuleVerification(
                ok: false, level: "L3", checks: checks,
                signers: outer.signers,
                trustedSignerCount: outer.trustedSignerCount,
                notes: outer.notes
            )
        }
        checks.append(VerifyCheck(name: "decrypt", ok: true,
                                  detail: "\(inner.files.count) inner files"))
        let innerResult = verifyParsed(inner, level: "L3", allowlist: allowlist)
        for c in innerResult.checks {
            checks.append(VerifyCheck(name: "inner." + c.name, ok: c.ok, detail: c.detail))
        }
        // L3 cross-checks — inner envelope vs outer envelope.
        let outerCapsuleId = lookupString(outerParsed.envelope, ["capsule_id"])
        let outerFirst = lookupString(outerParsed.envelope, ["first_event_hash"])
        let outerEntry = lookupString(outerParsed.envelope, ["entry_hash"])
        let innerCapsuleId = lookupString(inner.envelope, ["capsule_id"])
        let innerFirst = lookupString(inner.envelope, ["first_event_hash"])
        let innerEntry = lookupString(inner.envelope, ["entry_hash"])
        checks.append(VerifyCheck(
            name: "inner_vs_outer.capsule_id",
            ok: outerCapsuleId != nil && outerCapsuleId == innerCapsuleId,
            detail: ""
        ))
        checks.append(VerifyCheck(
            name: "inner_vs_outer.first_event_hash",
            ok: outerFirst != nil && outerFirst == innerFirst,
            detail: ""
        ))
        checks.append(VerifyCheck(
            name: "inner_vs_outer.entry_hash",
            ok: outerEntry != nil && outerEntry == innerEntry,
            detail: ""
        ))

        // Aggregate signers: outer first, then inner with `inner:` role
        // prefix so duplicate roles don't collide.
        var allSigners = outer.signers
        for s in innerResult.signers {
            allSigners.append(CapsuleVerification.SignerCheck(
                role: "inner:" + s.role,
                publicKey: s.publicKey,
                valid: s.valid,
                trusted: s.trusted
            ))
        }
        let ok = checks.allSatisfy { $0.ok }
        return CapsuleVerification(
            ok: ok, level: "L3", checks: checks,
            signers: allSigners,
            trustedSignerCount: allSigners.filter { $0.trusted }.count,
            notes: outer.notes
        )
    }

    /// Verification of an already-parsed capsule (plain or encrypted-outer).
    private static func verifyParsed(_ parsed: ParsedCapsule,
                                     level: String,
                                     allowlist: Set<String>) -> CapsuleVerification
    {
        var checks: [VerifyCheck] = []
        func record(_ name: String, _ ok: Bool, _ detail: String = "") {
            checks.append(VerifyCheck(name: name, ok: ok, detail: detail))
        }
        var notes: [String] = []
        if allowlist.isEmpty {
            notes.append("no allowlist provided; trusted=false for all signers regardless of signature validity")
        }
        record("zip_parse", true, "\(parsed.files.count) files")
        record("json_parse", true)

        // capsule_id derivation
        if let pubHex = lookupString(parsed.manifest, ["originator", "public_key"]),
           let firstHash = lookupString(parsed.manifest, ["first_event_hash"]),
           let mfId = lookupString(parsed.manifest, ["id"]),
           let envId = lookupString(parsed.envelope, ["capsule_id"])
        {
            // Untrusted hex from manifest — degrade gracefully on bad input
            // (originator pub must be 64 hex chars, first_event_hash 64).
            if let pubBytes = try? Bytes.fromHexThrowing(pubHex, label: "manifest.originator.public_key"),
               pubBytes.count == 32, firstHash.count == 64,
               (try? Bytes.fromHexThrowing(firstHash, label: "manifest.first_event_hash")) != nil
            {
                let expected = Manifest.computeCapsuleId(
                    originatorPub: pubBytes,
                    firstEventHashHex: firstHash
                )
                record("capsule_id",
                       expected == mfId && expected == envId,
                       String(expected.prefix(12)) + "…")
            } else {
                record("capsule_id", false, "malformed hex fields")
            }
        } else {
            record("capsule_id", false, "missing fields")
        }

        // manifest hash
        let mh = Manifest.hash(parsed.manifest)
        if let stored = lookupString(parsed.envelope, ["manifest_hash"]) {
            record("manifest_hash", mh == stored, String(mh.prefix(12)) + "…")
        }

        // content_index
        var indexInputs: [(String, Data)] = []
        for (path, data) in parsed.files where !Manifest.CONTENT_INDEX_EXCLUDED.contains(path) {
            indexInputs.append((path, data))
        }
        let ci = Manifest.buildContentIndex(indexInputs)
        if let storedMf = lookupString(parsed.manifest, ["content_index", "index_hash"]),
           let storedEnv = lookupString(parsed.envelope, ["content_index_hash"]) {
            record("content_index_hash",
                   ci.indexHash == storedMf && ci.indexHash == storedEnv,
                   String(ci.indexHash.prefix(12)) + "…")
        }

        if parsed.isEncrypted {
            // Encrypted-outer specific checks: encrypted_blob_hash matches
            // SHA-256(content.enc), and cipher agreement across surfaces.
            if let blob = parsed.files["content.enc"] {
                let recomputed = Hash.sha256Hex(blob)
                if let stored = lookupString(parsed.envelope, ["encrypted_blob_hash"]) {
                    record("encrypted_blob_hash", recomputed == stored,
                           String(recomputed.prefix(12)) + "…")
                } else {
                    record("encrypted_blob_hash", false, "envelope missing encrypted_blob_hash")
                }
            } else {
                record("encrypted_blob_hash", false, "content.enc missing")
            }
            // Cipher must be the supported AEAD.
            let envCipher = lookupString(parsed.envelope, ["cipher"]) ?? ""
            record("envelope_cipher", envCipher == "ChaCha20-Poly1305",
                   envCipher.isEmpty ? "missing" : envCipher)
            let mfCipher = lookupString(parsed.manifest, ["encryption", "cipher"]) ?? ""
            record("manifest_cipher", mfCipher == "ChaCha20-Poly1305",
                   mfCipher.isEmpty ? "missing" : mfCipher)
            // chain is deferred — content lives inside the ciphertext.
            record("chain", true, "deferred to L3 (encrypted outer)")
        } else {
            // Plain-capsule checks: chain integrity + envelope anchors.
            let chainOk = CapsuleReader.verifyChain(parsed.events)
            record("chain", chainOk, "\(parsed.events.count) events")
            if let firstEvHash = parsed.events.first.flatMap({ lookupString($0, ["hash"]) }),
               let envFirst = lookupString(parsed.envelope, ["first_event_hash"]) {
                record("first_event_hash", firstEvHash == envFirst)
            }
            if let lastEvHash = parsed.events.last.flatMap({ lookupString($0, ["hash"]) }),
               let envEntry = lookupString(parsed.envelope, ["entry_hash"]) {
                record("entry_hash", lastEvHash == envEntry)
            }
            // Plain must declare cipher="none" and encrypted_blob_hash=null.
            let envCipher = lookupString(parsed.envelope, ["cipher"]) ?? ""
            record("envelope_cipher", envCipher == "none",
                   envCipher.isEmpty ? "missing" : envCipher)
        }

        // envelope signatures + trust attribution
        let env = Envelope.verifySignatures(parsed.envelope)
        let signers = env.signers.map { s in
            CapsuleVerification.SignerCheck(
                role: s.role,
                publicKey: s.publicKey,
                valid: s.valid,
                trusted: s.valid && allowlist.contains(s.publicKey.lowercased())
            )
        }
        let detail = signers
            .map { "\($0.role):\($0.valid ? "ok" : "bad")\($0.trusted ? " (trusted)" : "")" }
            .joined(separator: ", ")
        record("envelope_signature", env.ok, detail.isEmpty ? (env.note ?? "") : detail)

        let ok = checks.allSatisfy { $0.ok }
        return CapsuleVerification(
            ok: ok, level: level, checks: checks,
            signers: signers,
            trustedSignerCount: signers.filter { $0.trusted }.count,
            notes: notes
        )
    }

    private static func lookupString(_ v: JCSValue, _ path: [String]) -> String? {
        var cur = v
        for k in path {
            guard case .object(let pairs) = cur,
                  let next = pairs.first(where: { $0.0 == k })?.1 else { return nil }
            cur = next
        }
        if case .string(let s) = cur { return s }
        return nil
    }
}

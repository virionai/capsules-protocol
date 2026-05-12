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
    public let level: String        // "L2" — encrypted-aware verification not yet exposed
    public let checks: [VerifyCheck]
    public let signers: [SignerCheck]
    public let trustedSignerCount: Int
    public let notes: [String]
}

public enum CapsuleVerifier {
    /// Verify a sealed capsule's bytes. Pass `allowlist` of hex public
    /// keys (lowercase) to mark signers trusted; the verifier never
    /// returns trusted=true on its own.
    public static func verify(_ bytes: Data,
                              allowlist: Set<String> = []) -> CapsuleVerification
    {
        var checks: [VerifyCheck] = []
        func record(_ name: String, _ ok: Bool, _ detail: String = "") {
            checks.append(VerifyCheck(name: name, ok: ok, detail: detail))
        }
        var notes: [String] = []
        if allowlist.isEmpty {
            notes.append("no allowlist provided; trusted=false for all signers regardless of signature validity")
        }

        let parsed: ParsedCapsule
        do { parsed = try CapsuleReader.parse(bytes) }
        catch {
            return CapsuleVerification(
                ok: false, level: "L2",
                checks: [VerifyCheck(name: "parse", ok: false, detail: "\(error)")],
                signers: [], trustedSignerCount: 0, notes: notes
            )
        }
        record("zip_parse", true, "\(parsed.files.count) files")
        record("json_parse", true)

        // capsule_id derivation
        if let pubHex = lookupString(parsed.manifest, ["originator", "public_key"]),
           let firstHash = lookupString(parsed.manifest, ["first_event_hash"]),
           let mfId = lookupString(parsed.manifest, ["id"]),
           let envId = lookupString(parsed.envelope, ["capsule_id"])
        {
            let expected = Manifest.computeCapsuleId(
                originatorPub: Bytes.fromHex(pubHex),
                firstEventHashHex: firstHash
            )
            record("capsule_id",
                   expected == mfId && expected == envId,
                   String(expected.prefix(12)) + "…")
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

        // chain
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
            ok: ok, level: "L2", checks: checks,
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

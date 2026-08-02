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
    /// Number of DISTINCT public keys that are both valid and on the
    /// allowlist — never signer rows (the same key under two roles is one
    /// trusted key).
    public let trustedSignerCount: Int
    /// Signer-set binding (manifest.signer_commitment): PRESENCE BINDS,
    /// ABSENCE REPORTS. `true` means the manifest commits to the exact
    /// signer set (the `signer_commitment` check reflects the match,
    /// fail-closed); `false` means the capsule does not assert signer-set
    /// integrity — verification can still succeed, at a visibly lower
    /// assurance.
    public let signerSetBound: Bool
    /// Actor-set binding (chain.md step 6): the same claim shape as
    /// `signerSetBound`. `true` means `manifest.participants[]` is
    /// non-empty and every chain event actor must be a member or the
    /// literal `system:host` — failures surface in the `chain` check,
    /// fail-closed. `false` means the manifest declares no participants,
    /// i.e. no claim about who acted: verification can still succeed at a
    /// visibly lower assurance, reported in `notes`.
    public let actorSetBound: Bool
    /// Derived skill-trust classification (spec/trust.md "Skill trust").
    /// The tier is host-relative — it depends on the allowlist THIS
    /// verification ran with — so it derives from the verify result and
    /// is never read from the capsule: v0.6 has no manifest.skill_trust
    /// member, and a capsule carrying one (earlier drafts, hostile
    /// authors) contributes an inert unknown member to the hash and
    /// nothing here. Capsule-level in reality: one envelope signature
    /// covers the whole content index, so every skill under one seal
    /// shares `capsuleSigned`; per-id variation only reflects whether
    /// that skill ships an indexed skill.json.
    public let skillTrust: SkillTrust
    public let notes: [String]

    public struct SkillTrust: Equatable {
        /// content_index ok AND envelope signatures ok AND at least one
        /// DISTINCT trusted signer key.
        public let capsuleSigned: Bool
        /// Skill id -> "signed" | "unsigned". "signed" iff capsuleSigned
        /// AND skills/<id>/skill.json is listed in the content index.
        public let skills: [String: String]
        public static let failClosed = SkillTrust(capsuleSigned: false, skills: [:])
        public init(capsuleSigned: Bool, skills: [String: String]) {
            self.capsuleSigned = capsuleSigned
            self.skills = skills
        }
    }
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
                signers: [], trustedSignerCount: 0, signerSetBound: false,
                actorSetBound: false,
                skillTrust: .failClosed,
                notes: initialNotes
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
                signers: [], trustedSignerCount: 0, signerSetBound: false,
                actorSetBound: false,
                skillTrust: .failClosed,
                notes: initialNotes
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
                signerSetBound: outer.signerSetBound,
                actorSetBound: outer.actorSetBound,
                skillTrust: .failClosed,
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
            // Distinct-key counting applies PER ENVELOPE (it exists to stop
            // one key inflating a single envelope's quorum by repetition);
            // the L3 aggregate is the sum of the outer and inner envelopes'
            // distinct counts — the same composition the Rust verifier
            // documents for its separate outer/inner counts.
            trustedSignerCount: outer.trustedSignerCount + innerResult.trustedSignerCount,
            signerSetBound: outer.signerSetBound,
            actorSetBound: outer.actorSetBound,
            // Skills live inside the ciphertext: the inner verification's
            // derived classification is the one that describes them.
            skillTrust: innerResult.skillTrust,
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

        // capsule_id derivation. A null (or absent) manifest.first_event_hash
        // is the legal zero-event shape: capsule_id then derives with 32
        // zero bytes standing in for first_event_hash_raw (spec/chain.md
        // "Empty chains", spec/manifest.md "Capsule identity"). Whether the
        // chain actually HAS zero events is the anchor check's job below,
        // which fails closed on any anchor/event-count inconsistency.
        let mfFirstHashValue = lookupValue(parsed.manifest, ["first_event_hash"])
        if let pubHex = lookupString(parsed.manifest, ["originator", "public_key"]),
           let mfId = lookupString(parsed.manifest, ["id"]),
           let envId = lookupString(parsed.envelope, ["capsule_id"])
        {
            let firstHash: String
            switch mfFirstHashValue {
            case .some(.string(let s)): firstHash = s
            default: firstHash = String(repeating: "0", count: 64)  // null/absent
            }
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

        // Semantic binding: manifest.first_event_hash is the capsule_id
        // preimage; envelope.first_event_hash is what the chain anchor
        // checks below compare against. manifest.md and envelope.md both
        // pin them to the hash of chain event 1, so they must agree —
        // otherwise capsule_id names a chain this capsule does not carry.
        // null==null is the legal empty-chain shape, enforced against the
        // event count below.
        let mfFirstClaim = lookupString(parsed.manifest, ["first_event_hash"])
        let envFirstClaim = lookupString(parsed.envelope, ["first_event_hash"])
        record("first_event_hash_binding", mfFirstClaim == envFirstClaim,
               mfFirstClaim == envFirstClaim
                   ? (mfFirstClaim ?? "null")
                   : "manifest.first_event_hash mismatch: \(mfFirstClaim ?? "null") "
                     + "vs envelope.first_event_hash \(envFirstClaim ?? "null")")

        // manifest hash. Canonicalization can refuse the manifest (e.g. an
        // integer outside ±(2^53 − 1)) — that is a fail-closed check
        // failure, never a trap.
        do {
            let mh = try Manifest.hash(parsed.manifest)
            if let stored = lookupString(parsed.envelope, ["manifest_hash"]) {
                record("manifest_hash", mh == stored, String(mh.prefix(12)) + "…")
            }
        } catch {
            // Same wording as the JS reference: a canonicalization refusal
            // must read as a recompute failure, never as tampering.
            record("manifest_hash", false, "manifest hash recompute failed: \(error)")
        }

        // content_index. `content.enc` drops out of the index only when the
        // SIGNED envelope declares a cipher (it is bound instead by
        // envelope.encrypted_blob_hash). Keying off file presence would let
        // an attacker append a stray blob to a signed plain capsule and have
        // it excluded for free; keying off the signed cipher means the stray
        // blob is indexed here like any other file. Indexing alone is
        // accounting, not the rejection — a fully re-derived index can cover
        // the blob — the envelope_cipher shape check below rejects any
        // content.enc the signed envelope does not account for, indexed or
        // not. See spec/manifest.md.
        let indexCipher = lookupString(parsed.envelope, ["cipher"]) ?? "none"
        let excluded = Manifest.contentIndexExclusions(indexCipher != "none")
        var indexInputs: [(String, Data)] = []
        for (path, data) in parsed.files where !excluded.contains(path) {
            indexInputs.append((path, data))
        }
        var contentIndexOk = false
        do {
            let ci = try Manifest.buildContentIndex(indexInputs, excluded: excluded)
            // Per-file attribution, so a failing index names the offending paths
            // instead of only reporting a hash mismatch (mirrors the JS
            // reference's contentIndex.errors).
            var storedIndex: [String: String] = [:]
            if case .object(let mfPairs) = parsed.manifest,
               let civ = mfPairs.first(where: { $0.0 == "content_index" })?.1,
               case .object(let ciPairs) = civ,
               let filesV = ciPairs.first(where: { $0.0 == "files" })?.1,
               case .array(let rows) = filesV
            {
                for row in rows {
                    guard case .object(let cols) = row,
                          let pv = cols.first(where: { $0.0 == "path" })?.1,
                          case .string(let path) = pv,
                          let hv = cols.first(where: { $0.0 == "sha256" })?.1,
                          case .string(let hash) = hv
                    else { continue }
                    storedIndex[path] = hash
                }
            }
            var indexProblems: [String] = []
            for f in ci.files {
                guard let want = storedIndex[f.path] else {
                    indexProblems.append("file present but not in manifest index: \(f.path)")
                    continue
                }
                if want != f.sha256 {
                    indexProblems.append("file hash mismatch: \(f.path)")
                }
            }
            for path in storedIndex.keys.sorted() where !ci.files.contains(where: { $0.path == path }) {
                indexProblems.append("file in manifest index but missing from package: \(path)")
            }
            if let storedMf = lookupString(parsed.manifest, ["content_index", "index_hash"]),
               let storedEnv = lookupString(parsed.envelope, ["content_index_hash"]) {
                let hashesMatch = ci.indexHash == storedMf && ci.indexHash == storedEnv
                let short = String(ci.indexHash.prefix(12)) + "…"
                contentIndexOk = hashesMatch && indexProblems.isEmpty
                record("content_index_hash",
                       contentIndexOk,
                       indexProblems.isEmpty ? short : ([short] + indexProblems).joined(separator: "; "))
            }
        } catch {
            record("content_index_hash", false, "\(error)")
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
            // Cipher must be the supported AEAD. The manifest's own
            // encryption declaration is checked against the signed cipher
            // in the manifest_encryption block below.
            let envCipher = lookupString(parsed.envelope, ["cipher"]) ?? ""
            record("envelope_cipher", envCipher == "ChaCha20-Poly1305",
                   envCipher.isEmpty ? "missing" : envCipher)
            // chain is deferred — content lives inside the ciphertext.
            record("chain", true, "deferred to L3 (encrypted outer)")
        } else {
            if parsed.events.isEmpty {
                // Empty chain is LEGAL — the weakest honest shape (a
                // template or draft capsule with no recorded work yet) —
                // but the capsule must not claim chain anchors it does not
                // have: with zero events all three anchor claims MUST be
                // null (or absent), fail-closed. In a plain capsule those
                // anchors are the ONLY envelope-to-chain binding, so a
                // verifier that treats an empty chain as "nothing to
                // check" verifies an unbound capsule (spec/chain.md
                // "Empty chains").
                let emptyNote = "empty chain: no events to walk; envelope anchors checked to be null instead"
                record("chain", true, emptyNote)
                notes.append(emptyNote)
                func isNullAnchor(_ v: JCSValue?) -> Bool { v == nil || v == .null }
                let envFirst = lookupValue(parsed.envelope, ["first_event_hash"])
                record("first_event_hash", isNullAnchor(envFirst),
                       isNullAnchor(envFirst)
                           ? "null (empty chain)"
                           : "envelope.first_event_hash must be null when the chain has no events")
                let envEntry = lookupValue(parsed.envelope, ["entry_hash"])
                record("entry_hash", isNullAnchor(envEntry),
                       isNullAnchor(envEntry)
                           ? "null (empty chain)"
                           : "envelope.entry_hash must be null when the chain has no events")
                record("manifest_first_event_hash", isNullAnchor(mfFirstHashValue),
                       isNullAnchor(mfFirstHashValue)
                           ? "null (empty chain)"
                           : "manifest.first_event_hash must be null when the chain has no events")
            } else {
                // Plain-capsule checks: chain integrity (hash linkage plus
                // the spec/chain.md per-event actor and kind rules) +
                // envelope anchors. These MUST fail closed: an anchor that
                // is missing or null over a non-empty chain fails the
                // comparison like any other mismatch — in a plain capsule
                // these anchors are the only envelope-to-chain binding.
                let chainErrors = CapsuleReader.verifyChain(
                    parsed.events,
                    participants: CapsuleReader.participantActorIds(parsed.manifest)
                )
                record("chain", chainErrors.isEmpty,
                       chainErrors.isEmpty
                           ? "\(parsed.events.count) events"
                           : chainErrors.joined(separator: "; "))
                let firstEvHash = parsed.events.first.flatMap { lookupString($0, ["hash"]) }
                let envFirst = lookupString(parsed.envelope, ["first_event_hash"])
                record("first_event_hash",
                       firstEvHash != nil && firstEvHash == envFirst,
                       firstEvHash != nil && firstEvHash == envFirst
                           ? ""
                           : "envelope.first_event_hash mismatch: \(envFirst ?? "null") vs \(firstEvHash ?? "null")")
                let lastEvHash = parsed.events.last.flatMap { lookupString($0, ["hash"]) }
                let envEntry = lookupString(parsed.envelope, ["entry_hash"])
                record("entry_hash",
                       lastEvHash != nil && lastEvHash == envEntry,
                       lastEvHash != nil && lastEvHash == envEntry
                           ? ""
                           : "envelope.entry_hash mismatch: \(envEntry ?? "null") vs \(lastEvHash ?? "null")")
                var mfFirstIsString = false
                if case .some(.string) = mfFirstHashValue { mfFirstIsString = true }
                record("manifest_first_event_hash", mfFirstIsString,
                       mfFirstIsString
                           ? ""
                           : "manifest.first_event_hash must not be null when the chain has events")
            }
            // Encrypted-blob shape (mirrors verifier-rust). This runs for
            // EVERY capsule that is not in encrypted mode — empty chain
            // included — covering: no blob, or a blob the signed cipher
            // does not account for. The checks are keyed off blob
            // PRESENCE, never off "encrypted mode" (cipher AND blob): that
            // conjunction is false exactly when the two halves disagree —
            // a smuggled content.enc on a cipher='none' capsule, or a
            // declared cipher with no blob — which are precisely the
            // capsules that must fail here.
            let envCipher = lookupString(parsed.envelope, ["cipher"]) ?? ""
            var shapeProblems: [String] = []
            if let blob = parsed.files["content.enc"] {
                if let stored = lookupString(parsed.envelope, ["encrypted_blob_hash"]) {
                    let recomputed = Hash.sha256Hex(blob)
                    if recomputed != stored {
                        shapeProblems.append(
                            "envelope.encrypted_blob_hash mismatch: stored \(stored) "
                            + "vs recomputed \(recomputed)")
                    }
                } else {
                    shapeProblems.append(
                        "encrypted blob present but envelope.encrypted_blob_hash=null")
                }
                if envCipher == "none" {
                    shapeProblems.append("encrypted blob present but envelope.cipher='none'")
                } else if envCipher.isEmpty {
                    shapeProblems.append("encrypted blob present but envelope.cipher missing")
                }
            } else {
                if lookupString(parsed.envelope, ["encrypted_blob_hash"]) != nil {
                    shapeProblems.append("plain capsule must have envelope.encrypted_blob_hash=null")
                }
                if envCipher != "none" {
                    shapeProblems.append(
                        "plain capsule must have cipher='none', got "
                        + "'\(envCipher.isEmpty ? "null" : envCipher)'")
                }
            }
            record("envelope_cipher", shapeProblems.isEmpty,
                   shapeProblems.isEmpty ? envCipher : shapeProblems.joined(separator: "; "))
        }

        // Encryption declaration. manifest.md fixes manifest.encryption as
        // null for plain capsules and {metadata_path, cipher} for encrypted
        // ones. The SIGNED envelope.cipher is authoritative; the manifest
        // must agree with it, and the declared metadata_path must resolve
        // to a file that is present AND covered by the content index.
        let declaredCipher = lookupString(parsed.envelope, ["cipher"]) ?? ""
        let mfEncryptionPresent: Bool = {
            guard case .object(let pairs) = parsed.manifest,
                  let enc = pairs.first(where: { $0.0 == "encryption" })?.1
            else { return false }
            return enc != .null
        }()
        let mfCipher = lookupString(parsed.manifest, ["encryption", "cipher"])
        let mfMetadataPath = lookupString(parsed.manifest, ["encryption", "metadata_path"])
        if declaredCipher == "none" {
            record("manifest_encryption", !mfEncryptionPresent,
                   mfEncryptionPresent
                     ? "manifest.encryption must be null when envelope.cipher is 'none'"
                     : "null")
        } else if !mfEncryptionPresent {
            record("manifest_encryption", false,
                   "manifest.encryption must be an object when envelope.cipher is '\(declaredCipher)'")
        } else if mfCipher != declaredCipher {
            record("manifest_encryption", false,
                   "manifest.encryption.cipher mismatch: \(mfCipher ?? "null") "
                   + "vs envelope.cipher '\(declaredCipher)'")
        } else if let path = mfMetadataPath, !path.isEmpty {
            if parsed.files[path] == nil {
                record("manifest_encryption", false,
                       "manifest.encryption.metadata_path missing from capsule: \(path)")
            } else if !contentIndexPaths(parsed.manifest).contains(path) {
                record("manifest_encryption", false,
                       "manifest.encryption.metadata_path not covered by content index: \(path)")
            } else {
                record("manifest_encryption", true, path)
            }
        } else {
            record("manifest_encryption", false,
                   "manifest.encryption.metadata_path must be a non-empty string")
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

        // Signer-set binding: PRESENCE BINDS, ABSENCE REPORTS. A present
        // manifest.signer_commitment must equal the normalized envelope
        // signer set exactly (integrity invariant, fail-closed). An absent
        // commitment downgrades the reported assurance — it never fails
        // verification (templates and other writers make a weaker claim
        // honestly).
        var signerSetBound = false
        if let commitment = lookupValue(parsed.manifest, ["signer_commitment"]) {
            signerSetBound = true
            let scErrors = signerCommitmentErrors(commitment, envelope: parsed.envelope)
            record("signer_commitment",
                   scErrors.isEmpty,
                   scErrors.isEmpty ? "exact membership matched" : scErrors.joined(separator: "; "))
        } else {
            record("signer_commitment", true, "absent (signer set not bound by seal)")
            notes.append("manifest.signer_commitment absent: the signer set is not bound by the seal")
        }

        // Actor-set binding: PRESENCE BINDS, ABSENCE REPORTS — the same
        // contract as signer_commitment. A non-empty
        // manifest.participants[] bound the chain walk above
        // (fail-closed); an empty one is the manifest declining to name
        // who acted, which verifies at a visibly lower assurance. Safe to
        // condition on because participants is covered by manifest_hash
        // inside the signed payload.
        let actorSetBound = !CapsuleReader.participantActorIds(parsed.manifest).isEmpty
        if !actorSetBound {
            notes.append("manifest.participants empty: chain actors are not bound to a declared participant set")
        }
        // spec/manifest.md field rules (A06): every DECLARED actor_id must
        // sit in the closed namespace set (human/ai/system/capsule,
        // non-empty id). Unlike an empty participants[], an
        // uninterpretable declared entry is not a weaker claim — it is a
        // malformed one, rejected fail-closed. Conformance vector:
        // chain-rules/invalid-actor-namespace.
        let participantProblems = CapsuleReader.participantActorIdProblems(parsed.manifest)
        record("participants", participantProblems.isEmpty,
               participantProblems.map { "manifest.\($0)" }.joined(separator: "; "))

        // Originator binding (invariant): the manifest names an originator
        // key — that key must actually have sealed the capsule with a valid
        // envelope signature under role "originator".
        let originatorKey = lookupString(parsed.manifest, ["originator", "public_key"])?.lowercased()
        let originatorSigned = env.signers.contains {
            $0.role == "originator" && $0.valid && $0.publicKey.lowercased() == originatorKey
        }
        record("originator_binding", originatorSigned,
               originatorSigned
                   ? ""
                   : "originator binding: manifest.originator.public_key \(originatorKey ?? "(missing)") has no valid envelope signature with role 'originator'")

        let ok = checks.allSatisfy { $0.ok }
        // DISTINCT trusted keys, never rows.
        let trustedCount = Set(
            signers.filter { $0.trusted }.map { $0.publicKey.lowercased() }
        ).count

        // Skill trust: DERIVED from this verification, never read from the
        // capsule (spec/trust.md "Skill trust"). Any skill_trust manifest
        // member is an inert unknown member, never authority.
        let capsuleSigned = contentIndexOk && env.ok && trustedCount > 0
        let indexedPaths = contentIndexPaths(parsed.manifest)
        var skillTiers: [String: String] = [:]
        for (path, _) in parsed.files {
            let parts = path.split(separator: "/").map(String.init)
            guard parts.count == 3, parts[0] == "skills",
                  parts[2] == "skill.json" || parts[2] == "SKILL.md" else { continue }
            let id = parts[1]
            if id == "decryption" { continue } // encryption metadata, not a skill
            skillTiers[id] = (capsuleSigned && indexedPaths.contains("skills/\(id)/skill.json"))
                ? "signed" : "unsigned"
        }

        return CapsuleVerification(
            ok: ok, level: level, checks: checks,
            signers: signers,
            trustedSignerCount: trustedCount,
            signerSetBound: signerSetBound,
            actorSetBound: actorSetBound,
            skillTrust: .init(capsuleSigned: capsuleSigned, skills: skillTiers),
            notes: notes
        )
    }

    /// Validate a stored signer_commitment against the envelope's signer
    /// set. Returns the failure messages ([] = bound and matched). Rules:
    /// spec/manifest.md "signer_commitment".
    private static func signerCommitmentErrors(_ commitment: JCSValue,
                                               envelope: JCSValue) -> [String]
    {
        guard case .array(let list) = commitment else {
            return ["manifest.signer_commitment malformed: must be a non-empty array of {role, public_key}"]
        }
        if list.isEmpty {
            return ["manifest.signer_commitment malformed: must not be empty when present"]
        }
        var problems: [String] = []
        var members: [(key: String, role: String)] = []
        for (i, m) in list.enumerated() {
            guard case .object(let mp) = m else {
                problems.append("manifest.signer_commitment malformed: member \(i) is not an object")
                continue
            }
            let keys = mp.map { $0.0 }.sorted()
            guard keys == ["public_key", "role"],
                  case .string(let role)? = mp.first(where: { $0.0 == "role" })?.1,
                  case .string(let key)? = mp.first(where: { $0.0 == "public_key" })?.1
            else {
                problems.append("manifest.signer_commitment malformed: member \(i) must carry exactly {role, public_key}")
                continue
            }
            if role.isEmpty {
                problems.append("manifest.signer_commitment malformed: member \(i): role must be a non-empty string")
            }
            let keyOk = key.count == 64 && key.allSatisfy { ("0"..."9").contains($0) || ("a"..."f").contains($0) }
            if !keyOk {
                problems.append("manifest.signer_commitment malformed: member \(i): public_key must be lowercase 64-hex")
            }
            members.append((key, role))
        }
        if !problems.isEmpty { return problems }
        for i in 1..<members.count {
            let a = members[i - 1], b = members[i]
            if a == b {
                problems.append("manifest.signer_commitment malformed: duplicate member (role=\(b.role), public_key=\(b.key))")
            } else if a.key > b.key || (a.key == b.key && a.role > b.role) {
                problems.append("manifest.signer_commitment malformed: members not sorted ascending by (public_key, role)")
                break
            }
        }
        if !problems.isEmpty { return problems }

        // Normalized envelope signer set, sorted the same way.
        var actual: [(key: String, role: String)] = []
        if case .object(let ep) = envelope,
           case .array(let signersArr)? = ep.first(where: { $0.0 == "signers" })?.1
        {
            for s in signersArr {
                guard case .object(let sp) = s else {
                    actual.append((key: "", role: ""))
                    continue
                }
                let role = sp.first(where: { $0.0 == "role" }).flatMap {
                    if case .string(let r) = $0.1 { return r } else { return nil }
                } ?? ""
                let key = sp.first(where: { $0.0 == "public_key" }).flatMap {
                    if case .string(let k) = $0.1 { return k.lowercased() } else { return nil }
                } ?? ""
                actual.append((key: key, role: role))
            }
        }
        actual.sort { $0.key != $1.key ? $0.key < $1.key : $0.role < $1.role }

        // Merge-walk both sorted member lists; name every difference.
        var errors: [String] = []
        var i = 0, j = 0
        while i < members.count || j < actual.count {
            let cmp: Int
            if i >= members.count { cmp = 1 }
            else if j >= actual.count { cmp = -1 }
            else {
                let a = members[i], b = actual[j]
                if a == b { cmp = 0 }
                else if a.key != b.key ? a.key < b.key : a.role < b.role { cmp = -1 }
                else { cmp = 1 }
            }
            if cmp == 0 { i += 1; j += 1 }
            else if cmp < 0 {
                let m = members[i]; i += 1
                errors.append("signer_commitment mismatch: no envelope signer matches committed member (role=\(m.role), public_key=\(m.key))")
            } else {
                let m = actual[j]; j += 1
                errors.append("signer_commitment mismatch: envelope signer not committed (role=\(m.role), public_key=\(m.key))")
            }
        }
        return errors
    }

    /// Paths listed in `manifest.content_index.files[]`.
    private static func contentIndexPaths(_ manifest: JCSValue) -> Set<String> {
        guard case .object(let pairs) = manifest,
              let ci = pairs.first(where: { $0.0 == "content_index" })?.1,
              case .object(let ciPairs) = ci,
              let filesVal = ciPairs.first(where: { $0.0 == "files" })?.1,
              case .array(let items) = filesVal
        else { return [] }
        var out = Set<String>()
        for item in items {
            if case .object(let entry) = item,
               let pathVal = entry.first(where: { $0.0 == "path" })?.1,
               case .string(let path) = pathVal {
                out.insert(path)
            }
        }
        return out
    }

    private static func lookupValue(_ v: JCSValue, _ path: [String]) -> JCSValue? {
        var cur = v
        for k in path {
            guard case .object(let pairs) = cur,
                  let next = pairs.first(where: { $0.0 == k })?.1 else { return nil }
            cur = next
        }
        return cur
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

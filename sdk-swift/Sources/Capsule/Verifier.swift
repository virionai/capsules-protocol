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
    /// Normalized verdict (spec/results.md): "valid" | "invalid" |
    /// "unsupported", DERIVED from the facts below —
    /// `ok == (verdict == "valid")` is an invariant, and "unsupported"
    /// partitions today's failures into "a limitation of this verifier,
    /// not a defect of the capsule" (unknown version, unsupported
    /// profile).
    public let verdict: String
    /// Machine-readable cause of an "unsupported" verdict; non-nil IFF
    /// verdict == "unsupported" (`unsupported_version_newer`,
    /// `unsupported_version_older`, `unsupported_profile`,
    /// `unsupported_capability`). An invalid capsule's causes live in
    /// the checks, which have their own vocabulary.
    public let verdictReason: String?
    /// The weaker-claim facts that qualify a VALID verdict
    /// (spec/results.md), in the spec-defined order: the seven base
    /// names followed by the three lineage names. Non-empty only when
    /// verdict == "valid"; each entry restates exactly one fact already
    /// reported below, as a BARE string — payload-carrying facts
    /// (verified depth, per-entry statuses and reasons) live in
    /// `lineage`, never on this array. A renderer MUST NOT present a
    /// valid verdict without them.
    public let qualifiers: [String]
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
    /// Version-compatibility facts (spec/versioning.md): the observed
    /// declared version, whether this verifier supports that era, the
    /// closed status vocabulary ("known" | "unknown_newer" |
    /// "unknown_older" | "invalid" | "unread"), the era's algorithm
    /// suite, and the host's declared-acceptance verdict (nil when no
    /// acceptVersions policy was declared). Reported, never decided.
    public let formatVersion: FormatVersionReport
    /// Profile declaration facts (spec/profiles.md): the declaration as
    /// OBSERVED (reported even when the capsule was refused — it is
    /// what lets an auditor route the capsule to a capable verifier
    /// instead of declaring it corrupt), the profile actually applied
    /// (the absence rule made machine-visible), and the closed status
    /// vocabulary. Reported, never decided.
    public let profile: ProfileReport
    /// Lineage facts (spec/lineage.md): whether the manifest declares
    /// `predecessors`, the area verdict, the verified depth, and one
    /// entry per declared predecessor. The standalone checks fail the
    /// capsule closed (the `lineage` check); supplied-bytes linkage is
    /// REPORT-ONLY — it can falsify `lineage.ok` but never `ok`, so a
    /// host's file handling cannot forge a forgery verdict against an
    /// honest successor.
    public let lineage: LineageReport
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

    public struct FormatVersionReport {
        public let observed: String?
        public let supported: Bool
        public let status: String
        public let suite: String?
        public let acceptedByPolicy: Bool?

        /// The fail-closed "unread" shape used before the manifest's
        /// declaration could be read.
        public static let unread = FormatVersionReport(
            observed: nil, supported: false, status: "unread", suite: nil, acceptedByPolicy: nil
        )
    }

    /// The profile channel (spec/profiles.md "Reporting"), parallel to
    /// `FormatVersionReport`. `status` is the closed vocabulary
    /// default | supported | unsupported | mismatched | invalid |
    /// unevaluated | unread; `effective` is nil whenever no profile's
    /// rules were applied (any refusal, invalid, unread).
    public struct ProfileReport {
        public let observed: String?
        public let observedVersion: String?
        public let declared: Bool
        public let effective: String?
        public let effectiveVersion: String?
        public let supported: Bool
        public let status: String
        public let acceptedByPolicy: Bool?

        /// The fail-closed "unread" shape: the declaration could not be
        /// read at all.
        public static let unread = ProfileReport(
            observed: nil, observedVersion: nil, declared: false, effective: nil,
            effectiveVersion: nil, supported: false, status: "unread", acceptedByPolicy: nil
        )
    }

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
    ///
    /// `acceptVersions` / `acceptProfiles` are the host's declared
    /// policies (spec/versioning.md "Host policy", spec/profiles.md):
    /// REPORTED as `formatVersion.acceptedByPolicy` /
    /// `profile.acceptedByPolicy` and the matching qualifier, never
    /// decided — neither can change `ok`.
    ///
    /// `predecessors` is the candidate pool for lineage linkage
    /// (spec/lineage.md): sealed capsule bytes the host holds for the
    /// declared predecessors. REPORT-ONLY — it populates
    /// `CapsuleVerification.lineage` and never changes `ok`.
    public static func verify(_ bytes: Data,
                              allowlist: Set<String> = [],
                              acceptVersions: Set<String>? = nil,
                              acceptProfiles: Set<String>? = nil,
                              predecessors: [Data] = []) -> CapsuleVerification
    {
        let parsed: ParsedCapsule
        do { parsed = try CapsuleReader.parse(bytes) }
        catch {
            return openRefusal(bytes, error, level: "L2", allowlist: allowlist)
        }
        return verifyParsed(parsed, level: "L2", allowlist: allowlist,
                            acceptVersions: acceptVersions, acceptProfiles: acceptProfiles,
                            predecessors: predecessors)
    }

    /// The fail-closed result for a capsule the reader refused to open.
    /// Every channel holds its fail-closed default and the refusal is
    /// the only error carried (spec/versioning.md and spec/profiles.md
    /// refusal exclusivity) — but the observed version and profile
    /// declaration are still REPORTED, which is what lets an auditor
    /// tell "this verifier is too old / lacks that profile" apart from
    /// "this capsule is corrupt".
    private static func openRefusal(_ bytes: Data, _ error: Error, level: String,
                                    allowlist: Set<String>) -> CapsuleVerification
    {
        // The advisory keys off the EFFECTIVE allowlist, so a refusal
        // reached with an allowlist of only malformed entries still says
        // trust was never evaluated (spec/results.md `trust_not_evaluated`).
        let hygiene = normalizeAllowlist(allowlist)
        var initialNotes: [String] = hygiene.notes
        if hygiene.effective.isEmpty {
            initialNotes.append("no allowlist provided; trusted=false for all signers regardless of signature validity")
        }
        var files: [String: Data] = [:]
        if let entries = try? CapsuleZip.unpack(bytes) {
            for (path, data) in entries { files[path] = data }
        }
        let formatVersion = formatVersionOnOpenRefusal(files, error)
        let profile = profileOnOpenRefusal(files, error)
        // The manifest's observed version can be KNOWN while the
        // refusal came from the envelope's, so the refusal class rides
        // on the error rather than being re-read from the channel.
        var versionStatus = formatVersion.status
        if case CapsuleError.unsupportedVersion(_, let status, _) = error { versionStatus = status }
        let surface = deriveVerdict(ok: false, versionStatus: versionStatus,
                                    profileStatus: profile.status)
        return CapsuleVerification(
            ok: false, verdict: surface.verdict, verdictReason: surface.reason,
            qualifiers: surface.qualifiers, level: level,
            checks: [VerifyCheck(name: "parse", ok: false, detail: "\(error)")],
            signers: [], trustedSignerCount: 0, signerSetBound: false,
            actorSetBound: false,
            formatVersion: formatVersion,
            profile: profile,
            // Refusal exclusivity: after an open-stage refusal the
            // lineage channel holds its not-evaluated default too — the
            // refusal diagnosis is the only error the result carries and
            // every other channel sits at its fail-closed default.
            lineage: .notEvaluated,
            skillTrust: .failClosed,
            notes: initialNotes
        )
    }

    /// spec/versioning.md: the observed version stays a REPORTED fact
    /// even when open is refused — an unknown-version refusal must be
    /// distinguishable from tamper by machine, not just by prose. Read
    /// best-effort from the stored manifest, like the profile
    /// declaration beside it, so the fact survives refusals that never
    /// reached the version gate at all.
    private static func formatVersionOnOpenRefusal(_ files: [String: Data], _ error: Error)
        -> CapsuleVerification.FormatVersionReport
    {
        guard let bytes = files["manifest.json"],
              let manifest = try? CapsuleReader.parseJSON(bytes)
        else { return .unread }
        let observed = lookupString(manifest, ["format", "version"])
        let status = CapsuleVersions.classify(observed)
        var suite = status == .known ? observed.flatMap { CapsuleVersions.suite(for: $0) } : nil
        // Suite honesty (spec/profiles.md obligation 6): after a
        // profile-gate refusal no suite fact is known — reporting the
        // era's suite about rules this verifier refused to apply would
        // be a false fact on the result.
        if case CapsuleError.profileRefused = error { suite = nil }
        return CapsuleVerification.FormatVersionReport(
            observed: observed, supported: status == .known, status: status.rawValue,
            suite: suite, acceptedByPolicy: nil
        )
    }

    /// spec/profiles.md obligation 8: the observed declaration is a
    /// reported fact on every result, including open refusals.
    ///
    /// A typed profile refusal carries its own classification. A
    /// version-gate refusal reports the declaration with status
    /// "unevaluated" — read but not classified, because profile
    /// semantics are era-scoped and an unknown era means the
    /// declaration cannot be classified at all. Any other open failure
    /// never reached the gate either: the declaration is surfaced
    /// best-effort with the fail-closed "unread" status.
    ///
    /// This is an UNAUTHENTICATED observation. Nothing else may be
    /// concluded from it — not integrity, not signature validity, not
    /// authorship.
    private static func profileOnOpenRefusal(_ files: [String: Data], _ error: Error)
        -> CapsuleVerification.ProfileReport
    {
        if case CapsuleError.profileRefused(let status, let observed, let observedVersion,
                                            let declared, _) = error
        {
            return CapsuleVerification.ProfileReport(
                observed: observed, observedVersion: observedVersion, declared: declared,
                effective: nil, effectiveVersion: nil, supported: false,
                status: status, acceptedByPolicy: nil
            )
        }
        guard let manifestBytes = files["manifest.json"],
              let manifest = try? CapsuleReader.parseJSON(manifestBytes)
        else { return .unread }
        var declaration = CapsuleProfiles.member(manifest, "format", "profile")
        if declaration == nil, let envelopeBytes = files["provenance/envelope.json"],
           let envelope = try? CapsuleReader.parseJSON(envelopeBytes)
        {
            declaration = CapsuleProfiles.member(envelope, "profile")
        }
        var observed: String? = nil
        var observedVersion: String? = nil
        if case .object(let pairs)? = declaration {
            if case .string(let id)? = pairs.first(where: { $0.0 == "id" })?.1 { observed = id }
            if case .string(let v)? = pairs.first(where: { $0.0 == "version" })?.1 { observedVersion = v }
        }
        var isUnsupportedVersion = false
        if case CapsuleError.unsupportedVersion = error { isUnsupportedVersion = true }
        return CapsuleVerification.ProfileReport(
            observed: observed, observedVersion: observedVersion,
            declared: declaration != nil, effective: nil, effectiveVersion: nil,
            supported: false, status: isUnsupportedVersion ? "unevaluated" : "unread",
            acceptedByPolicy: nil
        )
    }

    /// Derive the normalized verdict surface (spec/results.md) from
    /// facts the result already carries. Report-only: no rule here can
    /// change whether a capsule verifies, and `ok == (verdict ==
    /// "valid")` holds by construction.
    private static func deriveVerdict(ok: Bool, versionStatus: String, profileStatus: String,
                                      qualifiers: [String] = [])
        -> (verdict: String, reason: String?, qualifiers: [String])
    {
        // Refused because the verifier cannot understand what the
        // capsule DECLARES — a different verifier may verify it. Not
        // corruption. The version gate runs before the profile gate, so
        // its diagnosis wins here too.
        if versionStatus == "unknown_newer" {
            return ("unsupported", "unsupported_version_newer", [])
        }
        if versionStatus == "unknown_older" {
            return ("unsupported", "unsupported_version_older", [])
        }
        if profileStatus == "unsupported" {
            return ("unsupported", "unsupported_profile", [])
        }
        if ok { return ("valid", nil, qualifiers) }
        // Everything else — tamper, malformation (including a profile
        // declaration that violates the shape or contradicts itself
        // across documents), canonicalization refusals, unread.
        return ("invalid", nil, [])
    }

    /// The version/profile refusal classes an error carries, in the
    /// shape `deriveVerdict` reads. Anything that is not a declaration
    /// the verifier cannot understand classifies as an ordinary failure.
    private static func refusalStatuses(_ error: Error) -> (version: String, profile: String) {
        if case CapsuleError.unsupportedVersion(_, let status, _) = error {
            return (status, "unread")
        }
        if case CapsuleError.profileRefused(let status, _, _, _, _) = error {
            return ("known", status)
        }
        return ("known", "default")
    }

    /// Allowlist hygiene (spec/results.md `trust_not_evaluated`): the
    /// qualifier names an EFFECTIVE — well-formed — allowlist being
    /// empty, so a caller entry that is not a 64-char hex Ed25519 public
    /// key is dropped and REPORTED rather than silently counted. Keeping
    /// it would suppress `trust_not_evaluated` (the raw set is
    /// non-empty) and emit `no_trusted_signer` instead, which is the
    /// cross-lane disagreement on identical bytes this vocabulary exists
    /// to prevent — sdk-js, sdk-py and verifier-rust all filter here.
    ///
    /// The parameter is an unordered Set, so ignored entries are
    /// reported sorted rather than by caller index; the shared substring
    /// `ignored invalid allowlist` is what the other lanes pin.
    static func normalizeAllowlist(_ allowlist: Set<String>)
        -> (effective: Set<String>, notes: [String])
    {
        var effective = Set<String>()
        var ignored: [String] = []
        for entry in allowlist {
            let lowered = entry.lowercased()
            let wellFormed = lowered.count == 64
                && lowered.allSatisfy { ("0"..."9").contains($0) || ("a"..."f").contains($0) }
            if wellFormed { effective.insert(lowered) } else { ignored.append(entry) }
        }
        let notes = ignored.sorted().map {
            "ignored invalid allowlist entry: must be a 64-char hex string "
                + "(32-byte Ed25519 public key); got \"\($0)\""
        }
        return (effective, notes)
    }

    /// The qualifier list for a VALID verdict, in the spec-defined
    /// order (spec/results.md): the seven base names, then the three
    /// lineage names. Each entry is a pure restatement of one
    /// already-reported fact; none of them can change whether a capsule
    /// verifies.
    ///
    /// `allowlist` is the EFFECTIVE (well-formed) set — see
    /// `normalizeAllowlist`.
    private static func qualifiers(signerSetBound: Bool,
                                   actorSetBound: Bool,
                                   emptyChainNotWalked: Bool,
                                   encryptedOuterOnly: Bool,
                                   versionAcceptedByPolicy: Bool?,
                                   allowlist: Set<String>,
                                   trustedSignerCount: Int,
                                   lineage: LineageReport = .notEvaluated) -> [String]
    {
        var out: [String] = []
        if !signerSetBound { out.append("signer_set_unbound") }
        if !actorSetBound { out.append("actor_set_unbound") }
        if emptyChainNotWalked { out.append("empty_chain_not_walked") }
        if encryptedOuterOnly { out.append("encrypted_outer_only") }
        if versionAcceptedByPolicy == false { out.append("version_not_accepted_by_policy") }
        // Mutually exclusive by construction: no EFFECTIVE allowlist vs
        // an allowlist that matched no distinct signer key.
        if allowlist.isEmpty { out.append("trust_not_evaluated") }
        else if trustedSignerCount == 0 { out.append("no_trusted_signer") }
        // Lineage (spec/results.md entries 8–10): "valid verdict, custody
        // claim not clean". Bare strings only — the verified depth and
        // the per-entry statuses/reasons stay in the `lineage` facts
        // channel.
        if lineage.declared {
            if lineage.entries.contains(where: {
                $0.status == "unverified" || $0.status == "predecessor_unverifiable"
            }) {
                out.append("lineage_declared_unverified")
            }
            if lineage.entries.contains(where: { $0.status == "mismatch" }) {
                out.append("lineage_mismatch")
            }
            if lineage.entries.contains(where: { $0.status == "predecessor_invalid" }) {
                out.append("lineage_predecessor_invalid")
            }
        }
        return out
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
                              allowlist: Set<String> = [],
                              acceptVersions: Set<String>? = nil,
                              acceptProfiles: Set<String>? = nil,
                              predecessors: [Data] = []) -> CapsuleVerification
    {
        let outerParsed: ParsedCapsule
        do { outerParsed = try CapsuleReader.parse(bytes) }
        catch {
            return openRefusal(bytes, error, level: "L3", allowlist: allowlist)
        }
        if !outerParsed.isEncrypted {
            // Plain capsule — L3 is the same surface as L2.
            return verifyParsed(outerParsed, level: "L3", allowlist: allowlist,
                                acceptVersions: acceptVersions, acceptProfiles: acceptProfiles,
                                predecessors: predecessors)
        }
        let outer = verifyParsed(outerParsed, level: "L3", allowlist: allowlist,
                                 acceptVersions: acceptVersions, acceptProfiles: acceptProfiles,
                                 predecessors: predecessors)
        var checks = outer.checks

        let inner: ParsedCapsule
        do {
            // The inner package is a fully-formed capsule: CapsuleReader
            // re-runs the version and profile gates over its own
            // documents, so its declaration is checked independently at
            // L3 (spec/profiles.md obligation 11 — no inner/outer
            // equality rule).
            inner = try CapsuleReader.openInner(
                outerParsed,
                recipientPrivateKey: recipientPrivateKey,
                recipientPublicKey: recipientPublicKey
            )
        } catch {
            checks.append(VerifyCheck(name: "decrypt", ok: false, detail: "\(error)"))
            // An inner-layer refusal (an unknown version or a profile
            // this verifier does not implement, inside the ciphertext)
            // is a limitation of this verifier, not corruption: it
            // derives the same non-tamper verdict the outer gate would.
            // The profile channel keeps describing the OUTER
            // declaration — the layer the caller handed in — while the
            // decrypt check detail names the inner refusal.
            let refusal = refusalStatuses(error)
            let surface = deriveVerdict(ok: false, versionStatus: refusal.version,
                                        profileStatus: refusal.profile)
            return CapsuleVerification(
                ok: false, verdict: surface.verdict, verdictReason: surface.reason,
                qualifiers: surface.qualifiers, level: "L3", checks: checks,
                signers: outer.signers,
                trustedSignerCount: outer.trustedSignerCount,
                signerSetBound: outer.signerSetBound,
                actorSetBound: outer.actorSetBound,
                formatVersion: outer.formatVersion,
                profile: outer.profile,
                // Like the profile channel, the lineage channel keeps
                // describing the OUTER layer — the one the caller handed
                // in — while the decrypt check detail names the inner
                // refusal.
                lineage: outer.lineage,
                skillTrust: .failClosed,
                notes: outer.notes
            )
        }
        checks.append(VerifyCheck(name: "decrypt", ok: true,
                                  detail: "\(inner.files.count) inner files"))
        // The outer manifest travels into the inner verification for the
        // L3 inner/outer lineage equality (spec/lineage.md "Encrypted
        // successors"): L2 evaluates the outer declaration, L3 the inner
        // plus the equality when both layers declare.
        let innerResult = verifyParsed(inner, level: "L3", allowlist: allowlist,
                                       predecessors: predecessors,
                                       outerManifest: outerParsed.manifest)
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
        // A successor MAY place `predecessors` in the inner manifest, the
        // outer, or both (spec/lineage.md "Encrypted successors"). The
        // inner declaration is the one the recipient reads, so it is
        // reported here when present; when only the outer declares, that
        // is the capsule's only declaration. When both declare, the
        // equality check above has already required them to be byte-equal.
        let reportedLineage = innerResult.lineage.declared ? innerResult.lineage : outer.lineage
        // The aggregate describes the OUTER capsule's declarations —
        // the same composition signerSetBound / actorSetBound / notes
        // already use — with two exceptions: the chain lives inside the
        // ciphertext, so the empty-chain fact is the INNER walk's (and
        // its canonical note rides along so note and qualifier cannot
        // disagree), and the lineage qualifiers describe whichever layer
        // actually declared. `encrypted_outer_only` is never carried
        // here: the content was read.
        let innerEmptyChain = innerResult.qualifiers.contains("empty_chain_not_walked")
        var notes = outer.notes
        if innerEmptyChain, let note = innerResult.notes.first(where: { $0.hasPrefix("empty chain:") }) {
            notes.append(note)
        }
        let trustedSignerCount = outer.trustedSignerCount + innerResult.trustedSignerCount
        let surface = deriveVerdict(
            ok: ok, versionStatus: outer.formatVersion.status,
            profileStatus: outer.profile.status,
            qualifiers: qualifiers(
                signerSetBound: outer.signerSetBound, actorSetBound: outer.actorSetBound,
                emptyChainNotWalked: innerEmptyChain, encryptedOuterOnly: false,
                versionAcceptedByPolicy: outer.formatVersion.acceptedByPolicy,
                allowlist: normalizeAllowlist(allowlist).effective,
                trustedSignerCount: trustedSignerCount,
                lineage: reportedLineage
            )
        )
        return CapsuleVerification(
            ok: ok, verdict: surface.verdict, verdictReason: surface.reason,
            qualifiers: surface.qualifiers, level: "L3", checks: checks,
            signers: allSigners,
            // Distinct-key counting applies PER ENVELOPE (it exists to stop
            // one key inflating a single envelope's quorum by repetition);
            // the L3 aggregate is the sum of the outer and inner envelopes'
            // distinct counts — the same composition the Rust verifier
            // documents for its separate outer/inner counts.
            trustedSignerCount: trustedSignerCount,
            signerSetBound: outer.signerSetBound,
            actorSetBound: outer.actorSetBound,
            formatVersion: outer.formatVersion,
            profile: outer.profile,
            lineage: reportedLineage,
            // Skills live inside the ciphertext: the inner verification's
            // derived classification is the one that describes them —
            // gated on the OVERALL L3 verdict (spec/trust.md): if any
            // outer or cross-check fails, the composite result is a
            // failing verification and must not classify anything signed.
            skillTrust: ok ? innerResult.skillTrust : .failClosed,
            notes: notes
        )
    }

    /// Verification of an already-parsed capsule (plain or encrypted-outer).
    private static func verifyParsed(_ parsed: ParsedCapsule,
                                     level: String,
                                     allowlist: Set<String>,
                                     acceptVersions: Set<String>? = nil,
                                     acceptProfiles: Set<String>? = nil,
                                     predecessors: [Data] = [],
                                     outerManifest: JCSValue? = nil) -> CapsuleVerification
    {
        var checks: [VerifyCheck] = []
        func record(_ name: String, _ ok: Bool, _ detail: String = "") {
            checks.append(VerifyCheck(name: name, ok: ok, detail: detail))
        }
        // Allowlist hygiene first (spec/results.md): every trust fact
        // below — the per-signer `trusted` flag, the distinct-key count,
        // both trust advisories and the trust qualifiers — reads the
        // EFFECTIVE set, so a malformed entry can never masquerade as a
        // consulted policy.
        let allowlistHygiene = normalizeAllowlist(allowlist)
        let effectiveAllowlist = allowlistHygiene.effective
        var notes: [String] = allowlistHygiene.notes
        if effectiveAllowlist.isEmpty {
            notes.append("no allowlist provided; trusted=false for all signers regardless of signature validity")
        }
        record("zip_parse", true, "\(parsed.files.count) files")
        record("json_parse", true)

        // Format-version facts (spec/versioning.md). CapsuleReader.parse
        // gates unknown versions, so a ParsedCapsule always declares a
        // KNOWN one; the observed version is REPORTED, and whether the
        // deployment accepts it is host policy — reported, never decided.
        let declaredVersion = lookupString(parsed.manifest, ["format", "version"])
            ?? CapsuleVersions.current

        // Profile gate (spec/profiles.md): version gate first, profile
        // gate second, nothing else until both pass. CapsuleReader.parse
        // enforces this at open; re-deriving it here keeps verification
        // total over a hand-constructed ParsedCapsule and pins refusal
        // exclusivity — after a profile refusal the profile diagnosis is
        // the only error carried and every other channel holds its
        // fail-closed default.
        let profileClass = CapsuleProfiles.classify(
            manifestDeclaration: CapsuleProfiles.member(parsed.manifest, "format", "profile"),
            envelopeDeclaration: CapsuleProfiles.member(parsed.envelope, "profile")
        )
        if let message = CapsuleProfiles.refusalMessage(for: profileClass) {
            let profile = CapsuleVerification.ProfileReport(
                observed: profileClass.observed, observedVersion: profileClass.observedVersion,
                declared: profileClass.declared, effective: nil, effectiveVersion: nil,
                supported: false, status: profileClass.status.rawValue, acceptedByPolicy: nil
            )
            let surface = deriveVerdict(ok: false, versionStatus: "known",
                                        profileStatus: profile.status)
            return CapsuleVerification(
                ok: false, verdict: surface.verdict, verdictReason: surface.reason,
                qualifiers: surface.qualifiers, level: level,
                checks: [VerifyCheck(name: "profile", ok: false, detail: message)],
                signers: [], trustedSignerCount: 0, signerSetBound: false, actorSetBound: false,
                // Suite honesty (spec/profiles.md obligation 6): the
                // suite fact is a statement about the rules governing
                // THIS capsule; after a profile-gate refusal none is
                // known.
                formatVersion: CapsuleVerification.FormatVersionReport(
                    observed: declaredVersion, supported: true, status: "known",
                    suite: nil, acceptedByPolicy: nil
                ),
                profile: profile,
                // Refusal exclusivity at the PROFILE gate, mirroring the
                // version gate: the profile diagnosis is the only error
                // carried, so the lineage channel holds its not-evaluated
                // default and `qualifiers` stays empty.
                lineage: .notEvaluated,
                skillTrust: .failClosed,
                notes: notes
            )
        }
        var profileAcceptedByPolicy: Bool? = nil
        if let acceptProfiles, let effective = profileClass.effective {
            // Host policy: DECLARED accepted profile ids. Reported,
            // never decided — the same shape as acceptVersions.
            profileAcceptedByPolicy = acceptProfiles.contains(effective)
            if profileAcceptedByPolicy == false {
                notes.append(
                    "host policy: effective profile \(effective)/\(profileClass.effectiveVersion ?? "") "
                    + "is not in the declared accepted set \(acceptProfiles.sorted())"
                )
            }
        }
        let profile = CapsuleVerification.ProfileReport(
            observed: profileClass.observed, observedVersion: profileClass.observedVersion,
            declared: profileClass.declared, effective: profileClass.effective,
            effectiveVersion: profileClass.effectiveVersion, supported: profileClass.supported,
            status: profileClass.status.rawValue, acceptedByPolicy: profileAcceptedByPolicy
        )
        // Suite honesty: the reported suite is the era's only while the
        // effective profile IS the era default. Unreachable while the
        // table holds one row; kept so a grown table cannot report the
        // v0.6 suite under alternate rules.
        let effectiveIsDefault = profileClass.effective == CapsuleProfiles.defaultProfile.id
            && profileClass.effectiveVersion == CapsuleProfiles.defaultProfile.version

        var acceptedByPolicy: Bool? = nil
        if let acceptVersions {
            acceptedByPolicy = acceptVersions.contains(declaredVersion)
            if acceptedByPolicy == false {
                notes.append(
                    "host policy: observed format version \(declaredVersion) is not in the "
                    + "declared accepted set \(acceptVersions.sorted())"
                )
            }
        }
        let formatVersion = CapsuleVerification.FormatVersionReport(
            observed: declaredVersion,
            supported: true,
            status: "known",
            suite: effectiveIsDefault ? CapsuleVersions.suite(for: declaredVersion) : nil,
            acceptedByPolicy: acceptedByPolicy
        )
        // manifest.format.version and envelope.version MUST be equal
        // (spec/versioning.md): two KNOWN versions that disagree leave
        // the capsule ambiguous about which era's rules bind it.
        let envDeclared = lookupString(parsed.envelope, ["version"])
        record("format_version_binding", envDeclared == declaredVersion,
               envDeclared == declaredVersion
                   ? declaredVersion
                   : "envelope.version '\(envDeclared ?? "null")' does not match "
                     + "manifest.format.version '\(declaredVersion)'")

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
                // Domain keyed by the capsule's DECLARED version
                // (spec/versioning.md "Version-keyed domain separation").
                let expected = Manifest.computeCapsuleId(
                    originatorPub: pubBytes,
                    firstEventHashHex: firstHash,
                    version: declaredVersion
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
                // A divergence names both values in the cross-lane wording
                // ("manifest_hash mismatch"): any post-seal edit to the
                // manifest — including an optional member like
                // `predecessors` — lands here, and the detail must say so
                // rather than repeating the recomputed prefix a passing
                // check also prints.
                record("manifest_hash", mh == stored,
                       mh == stored
                           ? String(mh.prefix(12)) + "…"
                           : "envelope.manifest_hash mismatch: stored \(stored) "
                             + "vs recomputed \(mh)")
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

        // Weaker-claim scope facts backing the qualifiers below
        // (spec/results.md): a zero-event chain whose null anchors were
        // checked instead of walked, and an outer-only L2 result whose
        // content was never read.
        var emptyChainNotWalked = false
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
                emptyChainNotWalked = true
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
                trusted: s.valid && effectiveAllowlist.contains(s.publicKey.lowercased())
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

        // Lineage declaration (spec/lineage.md). PRESENCE BINDS, ABSENCE
        // REPORTS: an absent member is "no claim" (declared=false); a
        // PRESENT member no reader can interpret is the capsule asserting
        // something meaningless about its own origin, rejected fail-closed
        // with the shared `predecessors[i].<member>` diagnoses. Linkage
        // against the supplied pool is REPORT-ONLY — it can falsify the
        // lineage AREA but never this check, so a host's file handling
        // cannot forge a forgery verdict against an honest successor.
        // The capsule's own observed era decides whether the member is
        // interpreted at all: in a pre-lineage era it is an unknown
        // member, exactly as it is when reached as a hop.
        let lineageEvaluation = Lineage.evaluate(
            manifest: parsed.manifest,
            version: declaredVersion,
            pool: predecessors,
            allowlist: effectiveAllowlist,
            acceptVersions: acceptVersions
        )
        let lineage = lineageEvaluation.report
        notes.append(contentsOf: lineageEvaluation.notes)
        if !lineageEvaluation.standaloneProblems.isEmpty {
            record("lineage", false,
                   lineageEvaluation.standaloneProblems
                       .map { "manifest.\($0)" }.joined(separator: "; "))
        } else if lineage.declared {
            // The check stays TRUE under a failing linkage: the area
            // boolean carries that verdict. The diagnoses ride along so an
            // operator reading the check list sees them.
            let linkage = lineage.entries.flatMap { entry in
                entry.errors.map { "predecessor \(entry.capsuleId ?? "(unknown id)"): \($0)" }
            }
            let summary = lineage.entries
                .map { "hop \($0.hop) \($0.status)\($0.reason.map { " (\($0))" } ?? "")" }
                .joined(separator: ", ")
            record("lineage", true,
                   ([ "\(lineage.entries.count) declared predecessor(s): \(summary); "
                        + "verified depth \(lineage.verifiedDepth)" ] + linkage)
                       .joined(separator: "; "))
        } else {
            // Absence is a weaker claim made honestly — recorded like an
            // absent signer_commitment, never a hole in the check list.
            record("lineage", true, "absent (no lineage declared)")
        }
        // Standalone check 4 — the inner/outer equality of an encrypted
        // successor's declarations, fail-closed only when BOTH manifests
        // carry the member (`outerManifest` is non-nil only for the inner
        // half of an L3 verification). Gated on the era like every other
        // lineage obligation: in a pre-lineage era both members are
        // unknown members and differ inertly.
        if Lineage.eraDefinesLineage(declaredVersion),
           let problem = Lineage.innerOuterProblem(inner: parsed.manifest, outer: outerManifest) {
            record("lineage_inner_outer", false, problem)
        }

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
        // An allowlist that matched nothing is a PASS the host must not
        // read as trust (spec/envelope.md step 8, spec/results.md): the
        // signatures verify, every signer is trusted=false, and the
        // report says why.
        if !effectiveAllowlist.isEmpty && trustedCount == 0 {
            notes.append("allowlist provided but matched no signer; trusted=false for all signers")
        }

        // Skill trust: DERIVED from this verification, never read from the
        // capsule (spec/trust.md "Skill trust"). Any skill_trust manifest
        // member is an inert unknown member, never authority. The OVERALL
        // verdict is consulted: a capsule that FAILS verification never
        // classifies anything signed — without `ok`, a capsule broken in
        // a way that spares content_index and the envelope signatures
        // (e.g. a signer_commitment naming a key that never signed) still
        // tells the host its skills are trustworthy. contentIndexOk /
        // env.ok stay in the conjunction for fail-closed redundancy.
        let capsuleSigned = ok && contentIndexOk && env.ok && trustedCount > 0
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

        // Normalized verdict surface (spec/results.md), derived last:
        // this is the only path that can reach verdict "valid".
        let surface = deriveVerdict(
            ok: ok, versionStatus: formatVersion.status, profileStatus: profile.status,
            qualifiers: qualifiers(
                signerSetBound: signerSetBound, actorSetBound: actorSetBound,
                emptyChainNotWalked: emptyChainNotWalked,
                // Per-result, never per-capsule: an outer L2 result of
                // an encrypted capsule verified the seal and left the
                // content unread; the L3 result of the decrypted inner
                // read it and never carries this.
                encryptedOuterOnly: parsed.isEncrypted && level == "L2",
                versionAcceptedByPolicy: formatVersion.acceptedByPolicy,
                allowlist: effectiveAllowlist, trustedSignerCount: trustedCount,
                // Entries 8–10: "valid verdict, custody claim not
                // clean". Gated on `ok` by deriveVerdict, like every
                // other qualifier.
                lineage: lineage
            )
        )
        return CapsuleVerification(
            ok: ok, verdict: surface.verdict, verdictReason: surface.reason,
            qualifiers: surface.qualifiers, level: level, checks: checks,
            signers: signers,
            trustedSignerCount: trustedCount,
            signerSetBound: signerSetBound,
            actorSetBound: actorSetBound,
            formatVersion: formatVersion,
            profile: profile,
            lineage: lineage,
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

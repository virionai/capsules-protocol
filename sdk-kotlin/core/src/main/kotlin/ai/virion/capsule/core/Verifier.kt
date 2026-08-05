// CapsuleVerifier — the canonical surface for verifying a sealed capsule.
//
// Mirrors sdk/src/verifier.js's verifyCapsule. Returns per-check booleans
// plus per-signer trust attribution against an optional allowlist of
// public keys. trusted=true only when both the signature is valid AND
// the signer's pubkey is on the allowlist.
//
// Every result also carries the normalized verdict surface of
// spec/results.md (verdict / verdictReason / qualifiers) and the profile
// channel of spec/profiles.md — both DERIVED from the facts below, never
// read from the capsule.

package ai.virion.capsule.core

data class CapsuleVerification(
    val ok: Boolean,
    val level: String,                                  // "L2"
    val checks: List<VerifyCheck>,
    val signers: List<SignerCheck>,
    /**
     * Number of DISTINCT public keys that are both valid and on the
     * allowlist — never signer rows (the same key under two roles is one
     * trusted key).
     */
    val trustedSignerCount: Int,
    /**
     * Signer-set binding (manifest.signer_commitment): PRESENCE BINDS,
     * ABSENCE REPORTS. `true` means the manifest commits to the exact
     * signer set (the `signer_commitment` check reflects the match,
     * fail-closed); `false` means the capsule does not assert signer-set
     * integrity — verification can still succeed, at a visibly lower
     * assurance.
     */
    val signerSetBound: Boolean,
    /**
     * Actor-set binding (chain.md step 6): the same claim shape as
     * [signerSetBound]. `true` means `manifest.participants[]` is
     * non-empty and every chain event actor must be a member or the
     * literal `system:host` — failures surface in the `chain` check,
     * fail-closed. `false` means the manifest declares no participants,
     * i.e. no claim about who acted: verification can still succeed at a
     * visibly lower assurance, reported in [notes].
     */
    val actorSetBound: Boolean = false,
    /**
     * Version-compatibility facts (spec/versioning.md): the observed
     * declared version, whether this verifier supports that era, the
     * closed status vocabulary ("known" | "unknown_newer" |
     * "unknown_older" | "invalid" | "unread"), the era's algorithm
     * suite, and the host's declared-acceptance verdict (null when no
     * acceptVersions policy was declared). Reported, never decided.
     */
    val formatVersion: FormatVersionReport = FormatVersionReport(),
    /**
     * Profile declaration facts (spec/profiles.md): the declaration as
     * OBSERVED (reported even on refusal — an unauthenticated
     * observation is what lets an auditor route the capsule to a capable
     * verifier instead of declaring it corrupt), the profile actually
     * applied, and the closed status vocabulary. Reported, never
     * decided.
     */
    val profile: ProfileReport = ProfileReport(),
    /**
     * Derived skill-trust classification (spec/trust.md "Skill trust").
     * The tier is host-relative — it depends on the allowlist THIS
     * verification ran with — so it derives from the verify result and is
     * never read from the capsule: v0.6 has no manifest.skill_trust
     * member, and a capsule carrying one (earlier drafts, hostile
     * authors) contributes an inert unknown member to the hash and
     * nothing here. Capsule-level in reality: one envelope signature
     * covers the whole content index, so every skill under one seal
     * shares [SkillTrustCheck.capsuleSigned]; per-id variation only
     * reflects whether that skill ships an indexed skill.json.
     */
    val skillTrust: SkillTrustCheck = SkillTrustCheck(),
    /**
     * Lineage declaration facts (spec/lineage.md,
     * `manifest.predecessors`). The default is the fail-closed
     * not-evaluated shape used by early-return paths: after an
     * open-stage refusal `declared=false` means "not evaluated", not
     * "absent". Standalone malformation fails the `lineage` check (and
     * so the overall verdict); supplied-bytes linkage is REPORT-ONLY —
     * it can falsify [LineageReport.ok] but never [ok].
     */
    val lineage: LineageReport = LineageReport(),
    val notes: List<String>,
    /**
     * The normalized verdict surface (spec/results.md), DERIVED from the
     * facts above and never read from the capsule. `ok == (verdict ==
     * "valid")` is an invariant: "unsupported" partitions the failures
     * into "a limitation of THIS verifier, not a defect of the capsule"
     * (an unknown era, an unimplemented profile, a capsule class this
     * lane cannot process), it never softens one.
     */
    val verdict: String = "invalid",
    /** Non-null iff [verdict] is "unsupported"; names the limitation. */
    val verdictReason: String? = null,
    /**
     * Weaker-claim facts qualifying a VALID verdict, in the spec-defined
     * order — the seven base names followed by the three lineage names
     * (spec/results.md). These are the reduced assurances a conforming
     * renderer must surface beside the verdict rather than reporting a
     * bare "verified". Empty unless [verdict] is "valid". BARE strings
     * only: payload-carrying facts (verified depth, per-entry statuses
     * and reasons) live in [lineage], never on this array.
     */
    val qualifiers: List<String> = emptyList(),
) {
    data class SignerCheck(
        val role: String,
        val publicKey: String,
        val valid: Boolean,
        val trusted: Boolean,
    )

    /** Defaults are the fail-closed "unread" shape. */
    data class FormatVersionReport(
        val observed: String? = null,
        val supported: Boolean = false,
        val status: String = "unread",
        val suite: String? = null,
        val acceptedByPolicy: Boolean? = null,
    )

    /**
     * Profile declaration channel (spec/profiles.md), parallel to
     * [FormatVersionReport]. [effective] is the profile actually applied
     * — "v0.6-suite" on every successful default path, the absence rule
     * made machine-visible — and null whenever no profile's rules were
     * applied. Defaults are the fail-closed "unread" shape.
     */
    data class ProfileReport(
        val observed: String? = null,
        val observedVersion: String? = null,
        val declared: Boolean = false,
        val effective: String? = null,
        val effectiveVersion: String? = null,
        val supported: Boolean = false,
        val status: String = "unread",
        val acceptedByPolicy: Boolean? = null,
    )

    /**
     * Derived skill classification. The default — capsuleSigned=false,
     * empty map — is the fail-closed shape used by early-return paths.
     */
    data class SkillTrustCheck(
        /** content_index ok AND envelope ok AND >=1 distinct trusted key. */
        val capsuleSigned: Boolean = false,
        /**
         * Skill id -> "signed" | "unsigned". "signed" iff capsuleSigned
         * AND skills/<id>/skill.json is listed in the content index.
         */
        val skills: Map<String, String> = emptyMap(),
    )
}

object CapsuleVerifier {
    /**
     * [predecessors] is the optional pool of candidate predecessor
     * artifacts for the lineage linkage walk (spec/lineage.md). It is
     * REPORT-ONLY: it affects [CapsuleVerification.lineage] and the
     * notes, never `ok` — otherwise a third party could flip a valid
     * capsule's verdict by handing this verifier the wrong file.
     */
    fun verify(
        bytes: ByteArray,
        allowlist: Set<String> = emptySet(),
        acceptVersions: Set<String>? = null,
        acceptProfiles: Set<String>? = null,
        predecessors: List<ByteArray> = emptyList(),
    ): CapsuleVerification {
        val checks = mutableListOf<VerifyCheck>()
        fun rec(name: String, ok: Boolean, detail: String = "") {
            checks += VerifyCheck(name, ok, detail)
        }
        // Allowlist hygiene first (spec/results.md): every trust fact
        // below — the per-signer `trusted` flag, the distinct-key count,
        // both trust advisories and the trust qualifiers — reads the
        // EFFECTIVE set, so a malformed entry can never masquerade as a
        // consulted policy.
        val (effectiveAllowlist, allowlistNotes) = normalizeAllowlist(allowlist)
        val notes = mutableListOf<String>()
        notes += allowlistNotes
        if (effectiveAllowlist.isEmpty()) {
            notes += "no allowlist provided; trusted=false for all signers regardless of signature validity"
        }

        val parsed = try { CapsuleReader.parse(bytes) } catch (e: Throwable) {
            // spec/versioning.md, spec/profiles.md: the observed version
            // and the observed profile declaration stay REPORTED facts
            // even when open is refused — an unknown-version or
            // unsupported-profile refusal must be distinguishable from
            // tamper by machine, not prose. Nothing else is evaluated:
            // after a gate refusal the diagnosis is the only error the
            // result carries and every other channel holds its
            // fail-closed default.
            val (peekedManifest, peekedEnvelope) = peekDocuments(bytes)
            val formatVersion = when (e) {
                // A version refusal carries its own facts: WHICH document
                // declared the unknown era, and how it classified.
                is UnsupportedVersionException -> CapsuleVerification.FormatVersionReport(
                    observed = e.observed, supported = false, status = e.status,
                )
                // Suite honesty (spec/profiles.md obligation 6): a suite
                // claim about rules this verifier refused to apply would
                // be false.
                is ProfileException -> peekFormatVersion(peekedManifest).copy(suite = null)
                else -> peekFormatVersion(peekedManifest)
            }
            val (verdict, verdictReason) = refusalVerdict(e)
            return CapsuleVerification(
                ok = false, level = "L2",
                checks = listOf(VerifyCheck("parse", false, e.message ?: "$e")),
                signers = emptyList(), trustedSignerCount = 0,
                signerSetBound = false, actorSetBound = false,
                formatVersion = formatVersion,
                profile = peekProfile(peekedManifest, peekedEnvelope, e),
                notes = notes,
                verdict = verdict, verdictReason = verdictReason,
            )
        }
        rec("zip_parse", true, "${parsed.files.size} files")
        rec("json_parse", true)

        // Format-version facts (spec/versioning.md). CapsuleReader.parse
        // gates unknown versions, so a ParsedCapsule always declares a
        // KNOWN one; the observed version is REPORTED, and whether the
        // deployment accepts it is host policy — reported, never decided.
        val declaredVersion = CapsuleReader.lookupString(
            parsed.manifest, listOf("format", "version")) ?: CapsuleVersions.CURRENT
        var acceptedByPolicy: Boolean? = null
        if (acceptVersions != null) {
            acceptedByPolicy = declaredVersion in acceptVersions
            if (!acceptedByPolicy) {
                notes += "host policy: observed format version $declaredVersion is not in " +
                    "the declared accepted set ${acceptVersions.sorted()}"
            }
        }
        // Profile channel (spec/profiles.md). CapsuleReader.parse ran the
        // gate, so a ParsedCapsule is always governed by a profile this
        // verifier implements; re-deriving the classification here is
        // what puts the applied profile on the result — the absence rule
        // (no declaration in a 0.6/0.7 capsule means v0.6-suite/1.0,
        // permanently) made machine-visible instead of left as folklore.
        val profileClass = CapsuleProfiles.classify(
            CapsuleProfiles.manifestDeclaration(parsed.manifest),
            CapsuleProfiles.envelopeDeclaration(parsed.envelope),
        )
        val effectiveIsDefault = profileClass.effective == CapsuleProfiles.DEFAULT.id &&
            profileClass.effectiveVersion == CapsuleProfiles.DEFAULT.version
        var acceptedProfileByPolicy: Boolean? = null
        if (acceptProfiles != null) {
            acceptedProfileByPolicy = profileClass.effective in acceptProfiles
            if (!acceptedProfileByPolicy) {
                notes += "host policy: effective profile ${profileClass.effective}/" +
                    "${profileClass.effectiveVersion} is not in the declared accepted set " +
                    "${acceptProfiles.sorted()}"
            }
        }
        val profile = CapsuleVerification.ProfileReport(
            observed = profileClass.observed,
            observedVersion = profileClass.observedVersion,
            declared = profileClass.declared,
            effective = profileClass.effective,
            effectiveVersion = profileClass.effectiveVersion,
            supported = profileClass.supported,
            status = profileClass.status,
            acceptedByPolicy = acceptedProfileByPolicy,
        )
        val formatVersion = CapsuleVerification.FormatVersionReport(
            observed = declaredVersion,
            supported = true,
            status = "known",
            // Suite honesty (spec/profiles.md obligation 6): the suite
            // fact states which algorithm set governs THIS capsule, so it
            // is null whenever the effective profile is not the era
            // default. Unreachable while the table holds one row; kept so
            // a grown table cannot report the default suite under
            // alternate rules.
            suite = if (effectiveIsDefault) CapsuleVersions.suiteFor(declaredVersion) else null,
            acceptedByPolicy = acceptedByPolicy,
        )
        // manifest.format.version and envelope.version MUST be equal
        // (spec/versioning.md): two KNOWN versions that disagree leave
        // the capsule ambiguous about which era's rules bind it.
        val envDeclared = CapsuleReader.lookupString(parsed.envelope, listOf("version"))
        rec(
            "format_version_binding",
            envDeclared == declaredVersion,
            if (envDeclared == declaredVersion) declaredVersion
            else "envelope.version '${envDeclared ?: "null"}' does not match " +
                "manifest.format.version '$declaredVersion'",
        )

        // capsule_id derivation. A null (or absent) manifest.first_event_hash
        // is the legal zero-event shape: capsule_id then derives with 32
        // zero bytes standing in for first_event_hash_raw (spec/chain.md
        // "Empty chains", spec/manifest.md "Capsule identity"). Whether the
        // chain actually HAS zero events is the anchor check's job below.
        val pubHex = CapsuleReader.lookupString(parsed.manifest, listOf("originator", "public_key"))
        val mfFirstHashValue = (parsed.manifest as? JCSValue.Obj)?.pairs
            ?.firstOrNull { it.first == "first_event_hash" }?.second
        val mfId = CapsuleReader.lookupString(parsed.manifest, listOf("id"))
        val envId = CapsuleReader.lookupString(parsed.envelope, listOf("capsule_id"))
        if (pubHex != null && mfId != null && envId != null) {
            val firstHash = (mfFirstHashValue as? JCSValue.Str)?.v ?: "0".repeat(64)
            val expected = Manifest.computeCapsuleId(
                CapsuleCrypto.hexToBytes(pubHex), firstHash, declaredVersion)
            rec("capsule_id", expected == mfId && expected == envId, expected.take(12) + "…")
        } else rec("capsule_id", false, "missing fields")

        // Semantic binding: manifest.first_event_hash is the capsule_id
        // preimage; envelope.first_event_hash is what the chain anchor
        // checks below compare against. manifest.md and envelope.md both
        // pin them to the hash of chain event 1, so they must agree —
        // otherwise capsule_id names a chain this capsule does not carry.
        // null==null is the legal empty-chain shape, enforced against the
        // event count below (manifest_first_event_hash), where a non-string
        // non-null value also fails closed.
        val mfFirstClaim = (mfFirstHashValue as? JCSValue.Str)?.v
        val envFirstClaim = CapsuleReader.lookupString(parsed.envelope, listOf("first_event_hash"))
        rec(
            "first_event_hash_binding",
            mfFirstClaim == envFirstClaim,
            if (mfFirstClaim == envFirstClaim) (mfFirstClaim ?: "null")
            else "manifest.first_event_hash mismatch: ${mfFirstClaim ?: "null"} " +
                "vs envelope.first_event_hash ${envFirstClaim ?: "null"}",
        )

        // Unknown members are hashed too (spec/manifest.md), so a hostile
        // value in one must surface as a recompute failure — never an
        // uncaught exception, and never a report that reads as tampering.
        try {
            val mh = Manifest.hash(parsed.manifest)
            val storedMh = CapsuleReader.lookupString(parsed.envelope, listOf("manifest_hash"))
            rec(
                "manifest_hash", mh == storedMh,
                if (mh == storedMh) mh.take(12) + "…"
                else "envelope.manifest_hash mismatch: stored ${storedMh ?: "null"} " +
                    "vs recomputed $mh",
            )
        } catch (e: IllegalArgumentException) {
            rec("manifest_hash", false, "manifest hash recompute failed: ${e.message}")
        }

        // `content.enc` drops out of the index only when the SIGNED envelope
        // declares a cipher (it is bound instead by
        // envelope.encrypted_blob_hash). Keying off file presence would let
        // an attacker append a stray blob to a signed plain capsule and have
        // it excluded for free; keying off the signed cipher means the stray
        // blob is indexed here like any other file. Indexing alone is
        // accounting, not the rejection — a fully re-derived index can cover
        // the blob — the envelope_cipher shape check below rejects any
        // content.enc the signed envelope does not account for, indexed or
        // not. See spec/manifest.md.
        val indexCipher = CapsuleReader.lookupString(parsed.envelope, listOf("cipher")) ?: "none"
        val excluded = Manifest.contentIndexExclusions(indexCipher != "none")
        val indexInputs = parsed.files
            .filter { it.key !in excluded }
            .map { it.key to it.value }
        val ci = Manifest.buildContentIndex(indexInputs, excluded)
        // Per-file attribution, so a failing index names the offending paths
        // instead of only reporting a hash mismatch (mirrors the JS
        // reference's contentIndex.errors).
        val storedIndex = LinkedHashMap<String, String>()
        val storedRows = ((parsed.manifest as? JCSValue.Obj)?.pairs
            ?.firstOrNull { it.first == "content_index" }?.second as? JCSValue.Obj)?.pairs
            ?.firstOrNull { it.first == "files" }?.second as? JCSValue.Arr
        storedRows?.items?.forEach { row ->
            val cols = (row as? JCSValue.Obj)?.pairs ?: return@forEach
            val path = (cols.firstOrNull { it.first == "path" }?.second as? JCSValue.Str)?.v
            val hash = (cols.firstOrNull { it.first == "sha256" }?.second as? JCSValue.Str)?.v
            if (path != null && hash != null) storedIndex[path] = hash
        }
        val indexProblems = mutableListOf<String>()
        for ((path, hash) in ci.files) {
            val want = storedIndex[path]
            if (want == null) indexProblems += "file present but not in manifest index: $path"
            else if (want != hash) indexProblems += "file hash mismatch: $path"
        }
        val recomputedPaths = ci.files.map { it.first }.toSet()
        for (path in storedIndex.keys.sorted()) {
            if (path !in recomputedPaths) {
                indexProblems += "file in manifest index but missing from package: $path"
            }
        }
        val storedIdxMf = CapsuleReader.lookupString(parsed.manifest, listOf("content_index", "index_hash"))
        val storedIdxEnv = CapsuleReader.lookupString(parsed.envelope, listOf("content_index_hash"))
        val indexHashesMatch = ci.indexHash == storedIdxMf && ci.indexHash == storedIdxEnv
        val contentIndexOk = indexHashesMatch && indexProblems.isEmpty()
        rec("content_index_hash",
            contentIndexOk,
            (listOf(ci.indexHash.take(12) + "…") + indexProblems).joinToString("; "))

        // Encrypted-blob shape (mirrors verifier-rust). Two legal shapes:
        //   - Plain:     no content.enc, cipher == "none",
        //                encrypted_blob_hash == null.
        //   - Encrypted: content.enc present, cipher != "none",
        //                encrypted_blob_hash == sha256(content.enc).
        // The checks are keyed off blob PRESENCE, never off "encrypted
        // mode" (cipher AND blob): that conjunction is false exactly when
        // the two halves disagree, which are the capsules that must fail
        // here. Without this check a cipher-declaring capsule with no blob
        // falls through to the plain path and verifies a chain it claims
        // to have encrypted — fail-open. Runs for EVERY capsule, empty
        // chain included.
        val rawCipher = CapsuleReader.lookupString(parsed.envelope, listOf("cipher"))
        val storedBlobHash =
            CapsuleReader.lookupString(parsed.envelope, listOf("encrypted_blob_hash"))
        val blobBytes = parsed.files["content.enc"]
        val blobProblems = mutableListOf<String>()
        if (blobBytes != null) {
            if (storedBlobHash == null) {
                blobProblems += "encrypted blob present but envelope.encrypted_blob_hash=null"
            } else {
                val recomputedBlobHash = CapsuleCrypto.sha256Hex(blobBytes)
                if (recomputedBlobHash != storedBlobHash) {
                    blobProblems += "envelope.encrypted_blob_hash mismatch: " +
                        "stored $storedBlobHash vs recomputed $recomputedBlobHash"
                }
            }
            if (rawCipher == "none") {
                blobProblems += "encrypted blob present but envelope.cipher='none'"
            } else if (rawCipher == null) {
                blobProblems += "encrypted blob present but envelope.cipher missing"
            }
        } else {
            if (storedBlobHash != null) {
                blobProblems += "plain capsule must have envelope.encrypted_blob_hash=null"
            }
            if (rawCipher != "none") {
                blobProblems += "plain capsule must have cipher='none', got '${rawCipher ?: "null"}'"
            }
        }
        rec(
            "envelope_cipher",
            blobProblems.isEmpty(),
            if (blobProblems.isEmpty()) (rawCipher ?: "none") else blobProblems.joinToString("; "),
        )

        if (parsed.events.isEmpty()) {
            // Empty chain is LEGAL — the weakest honest shape (a template
            // or draft capsule with no recorded work yet) — but the capsule
            // must not claim chain anchors it does not have: with zero
            // events all three anchor claims MUST be null (or absent),
            // fail-closed. In a plain capsule those anchors are the ONLY
            // envelope-to-chain binding, so a verifier that treats an empty
            // chain as "nothing to check" verifies an unbound capsule
            // (spec/chain.md "Empty chains").
            val emptyNote = "empty chain: no events to walk; envelope anchors checked to be null instead"
            rec("chain", true, emptyNote)
            notes += emptyNote
            fun isNullAnchor(v: JCSValue?): Boolean = v == null || v == JCSValue.Null
            val envPairs = (parsed.envelope as? JCSValue.Obj)?.pairs
            val envFirstV = envPairs?.firstOrNull { it.first == "first_event_hash" }?.second
            rec(
                "first_event_hash", isNullAnchor(envFirstV),
                if (isNullAnchor(envFirstV)) "null (empty chain)"
                else "envelope.first_event_hash must be null when the chain has no events",
            )
            val envEntryV = envPairs?.firstOrNull { it.first == "entry_hash" }?.second
            rec(
                "entry_hash", isNullAnchor(envEntryV),
                if (isNullAnchor(envEntryV)) "null (empty chain)"
                else "envelope.entry_hash must be null when the chain has no events",
            )
            rec(
                "manifest_first_event_hash", isNullAnchor(mfFirstHashValue),
                if (isNullAnchor(mfFirstHashValue)) "null (empty chain)"
                else "manifest.first_event_hash must be null when the chain has no events",
            )
        } else {
            // Chain integrity: hash linkage plus the spec/chain.md per-event
            // actor (step 6, conditional on declared participants) and kind
            // rules. A null (or missing) anchor over a non-empty chain fails
            // the comparison like any other mismatch — in a plain capsule
            // these anchors are the only envelope-to-chain binding.
            val chainErrors = verifyChain(
                parsed.events,
                CapsuleReader.participantActorIds(parsed.manifest),
            )
            rec(
                "chain",
                chainErrors.isEmpty(),
                if (chainErrors.isEmpty()) "${parsed.events.size} events"
                else chainErrors.joinToString("; "),
            )

            val firstEvHash = parsed.events.firstOrNull()?.let {
                CapsuleReader.lookupString(it, listOf("hash"))
            }
            val envFirst = CapsuleReader.lookupString(parsed.envelope, listOf("first_event_hash"))
            rec(
                "first_event_hash",
                firstEvHash != null && firstEvHash == envFirst,
                if (firstEvHash != null && firstEvHash == envFirst) ""
                else "envelope.first_event_hash mismatch: ${envFirst ?: "null"} vs ${firstEvHash ?: "null"}",
            )

            val lastEvHash = parsed.events.lastOrNull()?.let {
                CapsuleReader.lookupString(it, listOf("hash"))
            }
            val envEntry = CapsuleReader.lookupString(parsed.envelope, listOf("entry_hash"))
            rec(
                "entry_hash",
                lastEvHash != null && lastEvHash == envEntry,
                if (lastEvHash != null && lastEvHash == envEntry) ""
                else "envelope.entry_hash mismatch: ${envEntry ?: "null"} vs ${lastEvHash ?: "null"}",
            )
            val mfFirstIsString = mfFirstHashValue is JCSValue.Str
            rec(
                "manifest_first_event_hash", mfFirstIsString,
                if (mfFirstIsString) ""
                else "manifest.first_event_hash must not be null when the chain has events",
            )
        }

        // Encryption declaration. manifest.md fixes manifest.encryption as
        // null for plain capsules and {metadata_path, cipher} for encrypted
        // ones. The SIGNED envelope.cipher is authoritative; the manifest
        // must agree with it, and the declared metadata_path must resolve
        // to a file that is present AND covered by the content index.
        val declaredCipher = CapsuleReader.lookupString(parsed.envelope, listOf("cipher")) ?: ""
        val mfEncryption = (parsed.manifest as? JCSValue.Obj)?.pairs
            ?.firstOrNull { it.first == "encryption" }?.second
        val mfEncryptionPresent = mfEncryption != null && mfEncryption != JCSValue.Null
        val mfCipher = CapsuleReader.lookupString(parsed.manifest, listOf("encryption", "cipher"))
        val mfMetadataPath =
            CapsuleReader.lookupString(parsed.manifest, listOf("encryption", "metadata_path")) ?: ""
        when {
            declaredCipher == "none" -> rec(
                "manifest_encryption",
                !mfEncryptionPresent,
                if (mfEncryptionPresent)
                    "manifest.encryption must be null when envelope.cipher is 'none'"
                else "null",
            )
            !mfEncryptionPresent -> rec(
                "manifest_encryption", false,
                "manifest.encryption must be an object when envelope.cipher is '$declaredCipher'",
            )
            mfCipher != declaredCipher -> rec(
                "manifest_encryption", false,
                "manifest.encryption.cipher mismatch: ${mfCipher ?: "null"} " +
                    "vs envelope.cipher '$declaredCipher'",
            )
            mfMetadataPath.isEmpty() -> rec(
                "manifest_encryption", false,
                "manifest.encryption.metadata_path must be a non-empty string",
            )
            !parsed.files.containsKey(mfMetadataPath) -> rec(
                "manifest_encryption", false,
                "manifest.encryption.metadata_path missing from capsule: $mfMetadataPath",
            )
            mfMetadataPath !in contentIndexPaths(parsed.manifest) -> rec(
                "manifest_encryption", false,
                "manifest.encryption.metadata_path not covered by content index: $mfMetadataPath",
            )
            else -> rec("manifest_encryption", true, mfMetadataPath)
        }

        val env = Envelope.verifySignatures(parsed.envelope)
        val signers = env.signers.map { (role, pk, valid) ->
            CapsuleVerification.SignerCheck(
                role = role, publicKey = pk,
                valid = valid,
                trusted = valid && (pk.lowercase() in effectiveAllowlist),
            )
        }
        val detail = signers.joinToString(", ") {
            "${it.role}:${if (it.valid) "ok" else "bad"}${if (it.trusted) " (trusted)" else ""}"
        }
        rec("envelope_signature", env.ok, if (detail.isEmpty()) (env.note ?: "") else detail)

        // Signer-set binding: PRESENCE BINDS, ABSENCE REPORTS. A present
        // manifest.signer_commitment must equal the normalized envelope
        // signer set exactly (integrity invariant, fail-closed). An absent
        // commitment downgrades the reported assurance — it never fails
        // verification (templates and other writers make a weaker claim
        // honestly).
        val commitment = (parsed.manifest as? JCSValue.Obj)?.pairs
            ?.firstOrNull { it.first == "signer_commitment" }?.second
        val signerSetBound = commitment != null
        if (commitment != null) {
            val scErrors = signerCommitmentErrors(commitment, parsed.envelope)
            rec(
                "signer_commitment",
                scErrors.isEmpty(),
                if (scErrors.isEmpty()) "exact membership matched" else scErrors.joinToString("; "),
            )
        } else {
            rec("signer_commitment", true, "absent (signer set not bound by seal)")
            notes += "manifest.signer_commitment absent: the signer set is not bound by the seal"
        }

        // Actor-set binding: PRESENCE BINDS, ABSENCE REPORTS — the same
        // contract as signer_commitment. A non-empty
        // manifest.participants[] bound the chain walk above
        // (fail-closed); an empty one is the manifest declining to name
        // who acted, which verifies at a visibly lower assurance. Safe to
        // condition on because participants is covered by manifest_hash
        // inside the signed payload.
        val actorSetBound = CapsuleReader.participantActorIds(parsed.manifest).isNotEmpty()
        if (!actorSetBound) {
            notes += "manifest.participants empty: chain actors are not bound to " +
                "a declared participant set"
        }
        // spec/manifest.md field rules (A06): every DECLARED actor_id must
        // sit in the closed namespace set (human/ai/system/capsule,
        // non-empty id). Unlike an empty participants[], an
        // uninterpretable declared entry is not a weaker claim — it is a
        // malformed one, rejected fail-closed. Conformance vector:
        // chain-rules/invalid-actor-namespace.
        val participantProblems = CapsuleReader.participantActorIdProblems(parsed.manifest)
        rec(
            "participants", participantProblems.isEmpty(),
            participantProblems.joinToString("; ") { "manifest.$it" },
        )

        // Originator binding (invariant): the manifest names an originator
        // key — that key must actually have sealed the capsule with a valid
        // envelope signature under role "originator".
        val originatorKey = CapsuleReader
            .lookupString(parsed.manifest, listOf("originator", "public_key"))?.lowercase()
        val originatorSigned = env.signers.any { (role, pk, valid) ->
            role == "originator" && valid && pk.lowercase() == originatorKey
        }
        rec(
            "originator_binding", originatorSigned,
            if (originatorSigned) ""
            else "originator binding: manifest.originator.public_key " +
                "${originatorKey ?: "(missing)"} has no valid envelope signature " +
                "with role 'originator'",
        )

        // Lineage declaration (spec/lineage.md). Standalone checks fail
        // CLOSED — a PRESENT declaration no reader can interpret is the
        // capsule asserting something meaningless about its own origin,
        // and skipping it would let a lying capsule present identically
        // to an honestly silent one. The supplied [predecessors] pool is
        // REPORT-ONLY: it can falsify the area, never this verdict.
        // The capsule's own observed era decides whether the member is
        // interpreted at all: in a pre-lineage era it is an unknown
        // member, exactly as it is when reached as a hop.
        val lineageEval = Lineage.evaluate(
            manifest = parsed.manifest,
            version = declaredVersion,
            pool = predecessors,
            notes = notes,
        ) { predecessorBytes -> verify(predecessorBytes, effectiveAllowlist, acceptVersions) }
        val lineage = lineageEval.report
        rec(
            "lineage", lineageEval.problems.isEmpty(),
            if (lineageEval.problems.isNotEmpty())
                lineageEval.problems.joinToString("; ") { "manifest.$it" }
            else if (!lineage.declared) "absent (no lineage declared)"
            else "${lineage.entries.size} declared predecessor(s); " +
                "verified to depth ${lineage.verifiedDepth}",
        )

        val ok = checks.all { it.ok }
        // DISTINCT trusted keys, never rows.
        val trustedCount = signers.filter { it.trusted }
            .map { it.publicKey.lowercase() }.toSet().size
        // An allowlist that matched nothing is a PASS the host must not
        // read as trust: without this note a caller sees valid signatures,
        // trusted=false everywhere, and no statement of why
        // (spec/results.md canonical notes; vector
        // result-vocabulary/allowlist-no-match).
        if (effectiveAllowlist.isNotEmpty() && trustedCount == 0) {
            notes += "allowlist provided but matched no signer; trusted=false for all signers"
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
        val capsuleSigned = ok && contentIndexOk && env.ok && trustedCount > 0
        val indexedPaths = contentIndexPaths(parsed.manifest)
        val skillTiers = mutableMapOf<String, String>()
        for (path in parsed.files.keys) {
            val parts = path.split('/')
            if (parts.size != 3 || parts[0] != "skills") continue
            if (parts[2] != "skill.json" && parts[2] != "SKILL.md") continue
            val id = parts[1]
            if (id == "decryption") continue // encryption metadata, not a skill
            skillTiers[id] =
                if (capsuleSigned && "skills/$id/skill.json" in indexedPaths) "signed"
                else "unsigned"
        }

        // Normalized verdict surface (spec/results.md), derived last from
        // the facts above. A parsed capsule cleared both gates, so the
        // only verdicts reachable here are "valid" and "invalid";
        // "unsupported" belongs to the refusal path above. Each qualifier
        // restates exactly one already-reported weaker claim, in the
        // spec-defined order. encrypted_outer_only has no derivation in
        // this lane: an encrypted capsule never reaches this point (the
        // reader refuses it as unsupported_capability), and a capsule
        // declaring a cipher without a blob fails the envelope_cipher
        // check, so no result here can be a verified encrypted outer.
        val qualifiers = mutableListOf<String>()
        if (ok) {
            if (!signerSetBound) qualifiers += "signer_set_unbound"
            if (!actorSetBound) qualifiers += "actor_set_unbound"
            if (parsed.events.isEmpty()) qualifiers += "empty_chain_not_walked"
            if (acceptedByPolicy == false) qualifiers += "version_not_accepted_by_policy"
            // Mutually exclusive: no EFFECTIVE (well-formed) allowlist at
            // all vs an allowlist that matched no distinct signer key.
            // Keying off the RAW set here would make this lane emit
            // no_trusted_signer where sdk-js/sdk-py/verifier-rust emit
            // trust_not_evaluated for identical bytes.
            if (effectiveAllowlist.isEmpty()) qualifiers += "trust_not_evaluated"
            else if (trustedCount == 0) qualifiers += "no_trusted_signer"
            // Lineage (spec/results.md entries 8-10): "valid verdict,
            // custody claim not clean" — the facts a renderer must not
            // hide, as bare strings. verified_depth and the per-entry
            // statuses/reasons stay in the lineage facts channel.
            if (lineage.declared) {
                if (lineage.entries.any {
                        it.status == Lineage.STATUS_UNVERIFIED ||
                            it.status == Lineage.STATUS_PREDECESSOR_UNVERIFIABLE
                    }
                ) {
                    qualifiers += "lineage_declared_unverified"
                }
                if (lineage.entries.any { it.status == Lineage.STATUS_MISMATCH }) {
                    qualifiers += "lineage_mismatch"
                }
                if (lineage.entries.any { it.status == Lineage.STATUS_PREDECESSOR_INVALID }) {
                    qualifiers += "lineage_predecessor_invalid"
                }
            }
        }

        return CapsuleVerification(
            ok = ok, level = "L2", checks = checks,
            signers = signers,
            trustedSignerCount = trustedCount,
            signerSetBound = signerSetBound,
            actorSetBound = actorSetBound,
            formatVersion = formatVersion,
            profile = profile,
            skillTrust = CapsuleVerification.SkillTrustCheck(capsuleSigned, skillTiers),
            lineage = lineage,
            notes = notes,
            verdict = if (ok) "valid" else "invalid",
            qualifiers = qualifiers,
        )
    }

    /**
     * Allowlist hygiene (spec/results.md `trust_not_evaluated`): the
     * qualifier names an EFFECTIVE — well-formed — allowlist being
     * empty, so a caller entry that is not a 64-char hex Ed25519 public
     * key is dropped and REPORTED rather than silently counted. Keeping
     * it would suppress `trust_not_evaluated` (the raw set is non-empty)
     * and emit `no_trusted_signer` instead, which is a cross-lane
     * disagreement on identical bytes — sdk-js, sdk-py and verifier-rust
     * all filter here.
     *
     * The parameter is an unordered Set, so ignored entries are reported
     * sorted rather than by caller index; the shared substring
     * `ignored invalid allowlist` is what the other lanes pin.
     */
    internal fun normalizeAllowlist(allowlist: Set<String>): Pair<Set<String>, List<String>> {
        val keyHex = Regex("^[0-9a-f]{64}$")
        val effective = linkedSetOf<String>()
        val ignored = mutableListOf<String>()
        for (entry in allowlist) {
            val lowered = entry.lowercase()
            if (keyHex.matches(lowered)) effective += lowered else ignored += entry
        }
        val notes = ignored.sorted().map {
            "ignored invalid allowlist entry: must be a 64-char hex string " +
                "(32-byte Ed25519 public key); got \"$it\""
        }
        return effective to notes
    }

    /**
     * The verdict + verdict_reason an OPEN-stage refusal derives
     * (spec/results.md). "unsupported" names a limitation of THIS
     * verifier — an era it does not know, a profile it does not
     * implement, or a capsule class it cannot process — and always
     * carries a machine-readable reason so a host can route the capsule
     * to an implementation that can verify it. Everything else is a
     * defect of the capsule: "invalid", with the causes in `checks`.
     */
    private fun refusalVerdict(e: Throwable): Pair<String, String?> = when (e) {
        is UnsupportedVersionException ->
            "unsupported" to if (e.status == CapsuleVersions.Status.UNKNOWN_OLDER.token) {
                "unsupported_version_older"
            } else {
                "unsupported_version_newer"
            }
        is UnsupportedProfileException -> "unsupported" to "unsupported_profile"
        // The registry gates what this lane RUNS (requires:["encryption"]);
        // this is what its API reports when a host hands it such a capsule
        // anyway — one spelling for both mechanisms.
        is UnsupportedCapabilityException -> "unsupported" to "unsupported_capability"
        else -> "invalid" to null
    }

    /**
     * The two hashed documents of a capsule whose open was refused, read
     * best-effort so the refusal can still REPORT what the capsule
     * declares. Either half is null when it cannot be read.
     */
    private fun peekDocuments(bytes: ByteArray): Pair<JCSValue?, JCSValue?> {
        val files = try { CapsuleZip.unpack(bytes).toMap() } catch (_: Throwable) {
            return null to null
        }
        fun read(name: String): JCSValue? =
            try { files[name]?.let { CapsuleReader.parseJson(it) } } catch (_: Throwable) { null }
        return read("manifest.json") to read("provenance/envelope.json")
    }

    /**
     * Best-effort format-version channel for a refusal the version gate
     * did not raise (spec/versioning.md requirement 3: the observed
     * version is a REPORTED fact even when open is refused). The
     * fail-closed "unread" shape when the manifest could not be read.
     */
    private fun peekFormatVersion(manifest: JCSValue?): CapsuleVerification.FormatVersionReport {
        val observed = manifest?.let {
            CapsuleReader.lookupString(it, listOf("format", "version"))
        } ?: return CapsuleVerification.FormatVersionReport()
        val status = CapsuleVersions.classify(observed)
        val known = status == CapsuleVersions.Status.KNOWN
        return CapsuleVerification.FormatVersionReport(
            observed = observed,
            supported = known,
            status = status.token,
            suite = if (known) CapsuleVersions.suiteFor(observed) else null,
        )
    }

    /**
     * Best-effort profile channel for a capsule whose open was refused
     * (spec/profiles.md obligation 8: the observed declaration is a
     * reported fact even on refusal — it is what lets an auditor route
     * the capsule to a capable verifier instead of declaring it
     * corrupt). A typed [ProfileException] carries its own
     * classification. A VERSION refusal reports the declaration as
     * "unevaluated": profile semantics are era-scoped, so an unknown era
     * means the declaration cannot even be classified. Any other refusal
     * never reached the gate, so the channel stays "unread" with the
     * declaration surfaced best-effort.
     */
    private fun peekProfile(
        manifest: JCSValue?,
        envelope: JCSValue?,
        e: Throwable,
    ): CapsuleVerification.ProfileReport {
        if (e is ProfileException) {
            val cls = e.classification
            return CapsuleVerification.ProfileReport(
                observed = cls.observed,
                observedVersion = cls.observedVersion,
                declared = cls.declared,
                status = cls.status,
            )
        }
        val cls = CapsuleProfiles.classify(
            manifest?.let { CapsuleProfiles.manifestDeclaration(it) },
            envelope?.let { CapsuleProfiles.envelopeDeclaration(it) },
        )
        return CapsuleVerification.ProfileReport(
            observed = cls.observed,
            observedVersion = cls.observedVersion,
            declared = cls.declared,
            status = if (e is UnsupportedVersionException) "unevaluated" else "unread",
        )
    }

    /**
     * Validate a stored signer_commitment against the envelope's signer
     * set. Returns the failure messages (empty = bound and matched).
     * Rules: spec/manifest.md "signer_commitment".
     */
    private fun signerCommitmentErrors(commitment: JCSValue, envelope: JCSValue): List<String> {
        val list = (commitment as? JCSValue.Arr)?.items
            ?: return listOf(
                "manifest.signer_commitment malformed: must be a non-empty array of {role, public_key}"
            )
        if (list.isEmpty()) {
            return listOf("manifest.signer_commitment malformed: must not be empty when present")
        }
        val problems = mutableListOf<String>()
        val members = mutableListOf<Pair<String, String>>() // (public_key, role)
        val keyHex = Regex("^[0-9a-f]{64}$")
        for ((i, m) in list.withIndex()) {
            val pairs = (m as? JCSValue.Obj)?.pairs
            if (pairs == null) {
                problems += "manifest.signer_commitment malformed: member $i is not an object"
                continue
            }
            val role = (pairs.firstOrNull { it.first == "role" }?.second as? JCSValue.Str)?.v
            val key = (pairs.firstOrNull { it.first == "public_key" }?.second as? JCSValue.Str)?.v
            if (pairs.map { it.first }.sorted() != listOf("public_key", "role") ||
                role == null || key == null
            ) {
                problems += "manifest.signer_commitment malformed: member $i must carry exactly {role, public_key}"
                continue
            }
            if (role.isEmpty()) {
                problems += "manifest.signer_commitment malformed: member $i: role must be a non-empty string"
            }
            if (!keyHex.matches(key)) {
                problems += "manifest.signer_commitment malformed: member $i: public_key must be lowercase 64-hex"
            }
            members += key to role
        }
        if (problems.isNotEmpty()) return problems
        for (i in 1 until members.size) {
            val a = members[i - 1]
            val b = members[i]
            if (a == b) {
                problems += "manifest.signer_commitment malformed: duplicate member " +
                    "(role=${b.second}, public_key=${b.first})"
            } else if (a.first > b.first || (a.first == b.first && a.second > b.second)) {
                problems += "manifest.signer_commitment malformed: members not sorted " +
                    "ascending by (public_key, role)"
                break
            }
        }
        if (problems.isNotEmpty()) return problems

        // Normalized envelope signer set, sorted the same way.
        val signersArr = ((envelope as? JCSValue.Obj)?.pairs
            ?.firstOrNull { it.first == "signers" }?.second as? JCSValue.Arr)?.items.orEmpty()
        val actual = signersArr.map { s ->
            val pairs = (s as? JCSValue.Obj)?.pairs.orEmpty()
            val role = (pairs.firstOrNull { it.first == "role" }?.second as? JCSValue.Str)?.v ?: ""
            val key = (pairs.firstOrNull { it.first == "public_key" }?.second as? JCSValue.Str)?.v
                ?.lowercase() ?: ""
            key to role
        }.sortedWith(compareBy({ it.first }, { it.second }))

        // Merge-walk both sorted member lists; name every difference.
        val errors = mutableListOf<String>()
        var i = 0
        var j = 0
        while (i < members.size || j < actual.size) {
            val cmp = when {
                i >= members.size -> 1
                j >= actual.size -> -1
                else -> compareValuesBy(members[i], actual[j], { it.first }, { it.second })
            }
            when {
                cmp == 0 -> { i++; j++ }
                cmp < 0 -> {
                    val (key, role) = members[i]; i++
                    errors += "signer_commitment mismatch: no envelope signer matches " +
                        "committed member (role=$role, public_key=$key)"
                }
                else -> {
                    val (key, role) = actual[j]; j++
                    errors += "signer_commitment mismatch: envelope signer not committed " +
                        "(role=$role, public_key=$key)"
                }
            }
        }
        return errors
    }

    /** Paths listed in `manifest.content_index.files[]`. */
    private fun contentIndexPaths(manifest: JCSValue): Set<String> {
        val ci = (manifest as? JCSValue.Obj)?.pairs
            ?.firstOrNull { it.first == "content_index" }?.second as? JCSValue.Obj
            ?: return emptySet()
        val files = ci.pairs.firstOrNull { it.first == "files" }?.second as? JCSValue.Arr
            ?: return emptySet()
        return files.items.mapNotNull { entry ->
            ((entry as? JCSValue.Obj)?.pairs?.firstOrNull { it.first == "path" }?.second
                as? JCSValue.Str)?.v
        }.toSet()
    }

    /**
     * Walk the chain: hash linkage plus the spec/chain.md per-event field
     * rules (verification steps 6 and 7). Returns one message per
     * failure — empty means the chain verifies.
     *
     * The step-6 actor rule is CONDITIONAL on the manifest's own claim: a
     * NON-EMPTY [participants] set binds every event actor to the
     * declared set (or the literal `system:host`), fail-closed. An EMPTY
     * set is the manifest making no claim about who acted — the walk
     * accepts any actor then, and the caller reports the reduced
     * assurance. The `kind` enum is enforced unconditionally.
     */
    internal fun verifyChain(
        events: List<JCSValue>,
        participants: Set<String> = emptySet(),
    ): List<String> {
        val errors = mutableListOf<String>()
        var prev = Chain.GENESIS_PREV
        events.forEachIndexed { i, e ->
            val seq = i + 1
            val obj = e as? JCSValue.Obj
            if (obj == null) {
                errors += "seq $seq: event is not a JSON object"
                return@forEachIndexed
            }
            fun field(key: String): String? =
                (obj.pairs.firstOrNull { it.first == key }?.second as? JCSValue.Str)?.v

            // spec/chain.md step 6 — when the manifest declares
            // participants, the actor must be one of them or the host.
            val actor = field("actor")
            if (participants.isNotEmpty() &&
                (actor == null || (actor != Chain.HOST_ACTOR && actor !in participants))
            ) {
                errors += "seq $seq: actor ${Chain.debugQuoted(actor)} " +
                    "not in manifest.participants and not system:host"
            }
            // spec/chain.md "Field rules" — `kind` is a closed enum.
            val kind = field("kind")
            if (!Chain.isValidEventKind(kind)) {
                errors += "seq $seq: kind ${Chain.debugQuoted(kind)} is not one of " +
                    Chain.EVENT_KINDS.joinToString(", ")
            }
            // spec/chain.md verification step 5 — `seq` is strictly
            // monotonic from 1. The stored value must equal the event's
            // 1-based position; trusting the stored seq (or merely
            // counting events) accepts a renumbered chain.
            val seqValue = obj.pairs.firstOrNull { it.first == "seq" }?.second
            val storedSeq = (seqValue as? JCSValue.Integer)?.v
            if (storedSeq != seq.toLong()) {
                val rendered = when (seqValue) {
                    is JCSValue.Integer -> seqValue.v.toString()
                    is JCSValue.Str -> Chain.debugQuoted(seqValue.v)
                    null -> "undefined"
                    else -> "non-integer"
                }
                errors += "seq $seq: seq $rendered expected $seq"
            }
            // spec/chain.md "Untrusted content" — when present, every
            // marking must match the path grammar. An unparseable marking
            // silently unmarks LLM-authored content for every host.
            val upfValue = obj.pairs.firstOrNull { it.first == "untrusted_payload_fields" }?.second
            if (upfValue != null) {
                val items = (upfValue as? JCSValue.Arr)?.items
                if (items == null) {
                    errors += "seq $seq: untrusted_payload_fields must be an array of payload paths"
                } else {
                    items.forEachIndexed { idx, item ->
                        val p = (item as? JCSValue.Str)?.v
                        if (p == null || !Chain.isValidUntrustedPayloadPath(p)) {
                            val rendered2 = if (p != null) Chain.debugQuoted(p) else "non-string"
                            errors += "seq $seq: untrusted_payload_fields[$idx] is not a " +
                                "valid payload path: $rendered2"
                        }
                    }
                }
            }

            var stored: String? = null
            val withoutHash = mutableListOf<Pair<String, JCSValue>>()
            for ((k, v) in obj.pairs) {
                if (k == "hash" && v is JCSValue.Str) stored = v.v
                else withoutHash += k to v
            }
            val storedHash = stored
            if (storedHash == null) {
                errors += "seq $seq: hash missing or wrong length"
                return@forEachIndexed
            }
            val prevHex = field("prev_hash")
            if (prevHex == null) {
                errors += "seq $seq: prev_hash missing or wrong length"
                return@forEachIndexed
            }
            val expectedPrev = CapsuleCrypto.bytesToHex(prev)
            if (prevHex != expectedPrev) {
                errors += "seq $seq: prev_hash mismatch: got $prevHex, expected $expectedPrev"
            }
            val canonical = JCS.bytes(JCSValue.Obj(withoutHash))
            val h = CapsuleCrypto.sha256(CapsuleCrypto.concat(prev, canonical))
            val recomputed = CapsuleCrypto.bytesToHex(h)
            if (recomputed != storedHash) {
                errors += "seq $seq: hash mismatch: stored $storedHash, recomputed $recomputed"
            }
            prev = h
        }
        return errors
    }
}

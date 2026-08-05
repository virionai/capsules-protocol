// Lineage (spec/lineage.md): the `manifest.predecessors` standalone
// checks and the report-only supplied-bytes linkage walk. Mirrors
// sdk-js/src/lineage.js — the diagnosis strings, the entry-status
// vocabulary and the pinned note phrases are cross-lane conformance
// surface, not lane prose.
//
// Two groups of obligations. STANDALONE checks are properties of the
// successor artifact alone and fail it closed (the caller records them
// as the `lineage` check). LINKAGE checks depend on evidence the host
// supplied at verify time (the `predecessors` verify parameter) and are
// REPORT-ONLY: the successor's `ok` must remain a function of the
// capsule, never of the invocation — otherwise a third party flips a
// valid capsule's verdict by handing the verifier the wrong file.
//
// This lane is a plain-capsule (L2) verifier, so standalone check 4
// (the inner/outer JCS equality of an encrypted successor) has no L3 to
// run in; the exemption is recorded in spec/vectors/registry.json.

package ai.virion.capsule.core

/**
 * Slim summary of a supplied predecessor's own verification. Host trust
 * over a predecessor's originator derives from THAT verification's
 * per-signer results, so the lineage area never duplicates host policy.
 * [errorCount] counts this lane's failing checks — the shape in which
 * this verifier carries its errors.
 */
data class LineageArtifact(
    val ok: Boolean,
    val observedVersion: String?,
    val level: String,
    val errorCount: Int,
)

/**
 * One reported entry: the declared six members echoed (so hosts apply
 * key policy without re-parsing the manifest) plus the facts this
 * verification established. [status] is the closed vocabulary of
 * spec/lineage.md; [reason] is set only for
 * `predecessor_unverifiable`; [errors] are REPORT-ONLY diagnoses that
 * never join the capsule's own errors.
 */
data class LineageEntry(
    val capsuleId: String? = null,
    val formatVersion: String? = null,
    val originatorPublicKey: String? = null,
    val firstEventHash: String? = null,
    val entryHash: String? = null,
    val manifestHash: String? = null,
    val hop: Int = 1,
    val identityChecked: Boolean = false,
    val status: String = Lineage.STATUS_UNVERIFIED,
    val reason: String? = null,
    val errors: List<String> = emptyList(),
    val artifact: LineageArtifact? = null,
)

/**
 * The `lineage` result area. The DEFAULT is the fail-closed
 * not-evaluated shape: after an open-stage or version-gate refusal the
 * channel holds it and the refusal diagnosis is the only error carried,
 * so `declared=false` there means "not evaluated", not "absent"
 * (spec/lineage.md "Reporting").
 *
 * [ok] is true iff the standalone checks passed AND no CHECKED entry is
 * `mismatch` or `predecessor_invalid`. `unverified` and
 * `predecessor_unverifiable` entries never falsify it — unchecked is
 * not failed.
 */
data class LineageReport(
    val declared: Boolean = false,
    val ok: Boolean = false,
    val verifiedDepth: Int = 0,
    val entries: List<LineageEntry> = emptyList(),
)

object Lineage {
    const val STATUS_UNVERIFIED = "unverified"
    const val STATUS_VERIFIED = "verified"
    const val STATUS_MISMATCH = "mismatch"
    const val STATUS_PREDECESSOR_INVALID = "predecessor_invalid"
    const val STATUS_PREDECESSOR_UNVERIFIABLE = "predecessor_unverifiable"

    const val REASON_UNSUPPORTED_VERSION = "unsupported_version"
    const val REASON_ENCRYPTED_PREDECESSOR = "encrypted_predecessor"
    const val REASON_UNSUPPORTED_PROFILE = "unsupported_profile"

    /** The six spec-defined members of one entry, all REQUIRED. */
    val ENTRY_MEMBERS = listOf(
        "capsule_id",
        "format_version",
        "originator_public_key",
        "first_event_hash",
        "entry_hash",
        "manifest_hash",
    )

    /**
     * v0.7.1 default-profile scope (spec/lineage.md "Scope"): the era
     * default profile id, frozen forever. A predecessor declaring any
     * other profile is out of the entry grammar's scope — the entry
     * presumes the era-default identity derivation and key encoding.
     */
    const val DEFAULT_PROFILE_ID = "v0.6-suite"

    /**
     * Eras whose rule sets define lineage semantics. `predecessors` is
     * a CLAIM member, not a rule selector, so it follows per-era rule
     * sets: inside a capsule declaring an earlier era it stays an
     * unknown member even to a v0.7.1 reader — preserved, hashed, never
     * shape-checked (spec/versioning.md "In-era tightening and
     * cross-era force"; spec/lineage.md "No retroactive interpretation
     * of sealed eras"). The gate is the SAME whether the capsule is the
     * verification subject or a hop reached through the walk — one
     * artifact, one rule set.
     */
    private val LINEAGE_ERAS = setOf("0.7")

    /**
     * Whether an observed `<major>.<minor>` era interprets
     * `predecessors`. An unknown era never reaches here (the version
     * gate refuses the capsule first), so `false` means "known era,
     * pre-lineage rules".
     */
    fun eraDefinesLineage(version: String): Boolean = version in LINEAGE_ERAS

    /**
     * Resource limit, not a protocol rule (like the reader's file-count
     * and size caps): the walk never fetches — depth is bounded by the
     * supplied pool — and the cap bounds pathological pools.
     */
    const val HOP_CAP = 256

    /** The empty-chain genesis stand-in of the capsule_id derivation. */
    private val ZERO_HASH = "0".repeat(64)

    /** Standalone problems plus the area they describe. */
    data class Evaluation(val report: LineageReport, val problems: List<String>)

    /**
     * The declared alternate profile id of a manifest, or null when the
     * manifest is default-profile (declared explicitly or by absence).
     * A present-but-uninterpretable declaration returns a placeholder —
     * the caller treats it as non-default, and the profile machinery
     * (spec/profiles.md) owns its full diagnosis.
     */
    fun declaredAlternateProfileId(manifest: JCSValue?): String? {
        val format = member(manifest, "format")
        val profile = member(format, "profile")
        if (profile == null || profile == JCSValue.Null) return null
        val id = (member(profile, "id") as? JCSValue.Str)?.v
        if (id == DEFAULT_PROFILE_ID) return null
        return if (!id.isNullOrEmpty()) id else "(uninterpretable profile declaration)"
    }

    /**
     * Validate a stored `predecessors` value (standalone checks 1–3).
     * Returns problem strings, empty means well-formed; every problem
     * names its member as `predecessors[i].<member>`.
     *
     *   1. Shape and grammar — array of entry objects; the six members
     *      present with the required types; lowercase hex REQUIRED, not
     *      normalized (the claim is bound by its stored bytes); a
     *      present-but-EMPTY array is malformed ("no claim" has exactly
     *      one spelling: absence); two entries sharing a manifest_hash
     *      cite the same artifact twice. Two entries sharing a
     *      capsule_id with DIFFERENT manifest_hash values are LEGAL (a
     *      merge of two snapshots of one line). Vendor extensions
     *      inside an entry use the `x-` prefix; any other unrecognized
     *      member is malformed.
     *   2. Null coherence — first_event_hash and entry_hash both null
     *      (zero-event predecessor) or both 64-hex.
     *   3. Identity coherence — when the declared format_version is in
     *      THIS verifier's known table, the declared capsule_id must
     *      equal the recompute under THAT era's identity rule. An
     *      unknown declared era SKIPS the check (versioning.md forbids
     *      applying one era's formula to another era's claim); callers
     *      report identityChecked=false, never a failure.
     */
    fun predecessorsProblems(predecessors: JCSValue?): List<String> {
        val arr = predecessors as? JCSValue.Arr
            ?: return listOf("predecessors must be an array of predecessor entry objects")
        if (arr.items.isEmpty()) {
            return listOf(
                "predecessors must not be empty when present " +
                    "(\"no claim\" has exactly one spelling: absence)",
            )
        }
        val problems = mutableListOf<String>()
        arr.items.forEachIndexed { i, item ->
            val entry = item as? JCSValue.Obj
            if (entry == null) {
                problems += "predecessors[$i] must be an entry object"
                return@forEachIndexed
            }
            for ((key, _) in entry.pairs) {
                if (key !in ENTRY_MEMBERS && !key.startsWith("x-")) {
                    problems += "predecessors[$i].$key is not a spec-defined entry member " +
                        "(vendor extensions must use the x- prefix)"
                }
            }
            for (key in listOf("capsule_id", "originator_public_key", "manifest_hash")) {
                if (hex64(entry, key) == null) {
                    problems += "predecessors[$i].$key must be lowercase 64-hex"
                }
            }
            for (key in listOf("first_event_hash", "entry_hash")) {
                if (!nullableHex64Ok(entry, key)) {
                    problems += "predecessors[$i].$key must be lowercase 64-hex or null"
                }
            }
            val versionValue = member(entry, "format_version")
            val version = (versionValue as? JCSValue.Str)?.v
            val versionStatus = CapsuleVersions.classify(version)
            if (versionStatus == CapsuleVersions.Status.INVALID) {
                problems += "predecessors[$i].format_version must be a " +
                    "'<major>.<minor>' version string, got ${render(versionValue)}"
            }
            // Null coherence (check 2) — only meaningful once both members typed.
            val fehNull = member(entry, "first_event_hash") == JCSValue.Null
            val ehNull = member(entry, "entry_hash") == JCSValue.Null
            val nullShapeKnown =
                nullableHex64Ok(entry, "first_event_hash") && nullableHex64Ok(entry, "entry_hash")
            if (nullShapeKnown && fehNull != ehNull) {
                problems += "predecessors[$i].first_event_hash and predecessors[$i].entry_hash " +
                    "must be both null (zero-event predecessor) or both 64-hex — a mixed " +
                    "declaration describes a predecessor that cannot exist"
            }
            // Identity coherence (check 3) — known declared eras only.
            val capsuleId = hex64(entry, "capsule_id")
            val originatorKey = hex64(entry, "originator_public_key")
            if (versionStatus == CapsuleVersions.Status.KNOWN &&
                capsuleId != null && originatorKey != null &&
                nullShapeKnown && fehNull == ehNull
            ) {
                val derived = Manifest.computeCapsuleId(
                    CapsuleCrypto.hexToBytes(originatorKey),
                    hex64(entry, "first_event_hash") ?: ZERO_HASH,
                    version!!,
                )
                if (derived != capsuleId) {
                    problems += "predecessors[$i].capsule_id does not derive from the declared " +
                        "originator key and first event hash under era $version — the " +
                        "declaration contradicts its own members"
                }
            }
        }
        // Duplicate manifest_hash across entries (same artifact cited twice).
        val seen = mutableMapOf<String, Int>()
        arr.items.forEachIndexed { i, item ->
            val mh = hex64(item as? JCSValue.Obj ?: return@forEachIndexed, "manifest_hash")
                ?: return@forEachIndexed
            val first = seen[mh]
            if (first != null) {
                problems += "predecessors[$i].manifest_hash duplicates " +
                    "predecessors[$first].manifest_hash (the same sealed artifact cited twice)"
            } else {
                seen[mh] = i
            }
        }
        return problems
    }

    /**
     * True when the declared era's identity rule is available to this
     * implementation, i.e. check 3 actually ran for the entry.
     */
    fun identityCheckable(entry: JCSValue?): Boolean =
        CapsuleVersions.classify((member(entry, "format_version") as? JCSValue.Str)?.v) ==
            CapsuleVersions.Status.KNOWN

    /**
     * Evaluate the lineage area for one manifest. Standalone problems
     * are returned for the caller to fail closed; linkage facts live
     * only in the area and in [notes] (report-only).
     *
     * [verify] is the caller's verifier, passed in so the pool
     * verification runs with the SAME host options as the main
     * verification and never with the pool itself — a predecessor is
     * verified as a capsule under ITS declared version's rules, which
     * is the only recursion this walk performs.
     */
    fun evaluate(
        manifest: JCSValue,
        version: String,
        pool: List<ByteArray>,
        notes: MutableList<String>,
        verify: (ByteArray) -> CapsuleVerification,
    ): Evaluation {
        val declared = member(manifest, "predecessors")
            // No claim, nothing checked. ok=true: unchecked is not failed.
            ?: return Evaluation(LineageReport(declared = false, ok = true), emptyList())

        if (!eraDefinesLineage(version)) {
            // Present, but this capsule's era defines no lineage
            // semantics: the member is an unknown member under those
            // rules — preserved and hashed, never shape-checked.
            // Interpreting it would retroactively rewrite a sealed
            // era's verdict.
            notes += "lineage: this capsule declares era $version, whose rule set defines " +
                "no lineage semantics; its predecessors member is an unknown member " +
                "under that era and was not interpreted"
            return Evaluation(LineageReport(declared = false, ok = true), emptyList())
        }

        val problems = predecessorsProblems(declared)
        if (problems.isNotEmpty()) {
            return Evaluation(LineageReport(declared = true, ok = false), problems)
        }

        // Pinned phrase: no report may imply a consent bit exists before
        // the v0.8+ countersignature artifact.
        notes += "lineage: manifest.predecessors is the successor's one-way declaration; " +
            "the predecessor's originator has not countersigned it"

        val entries = (declared as JCSValue.Arr).items
            .map { workEntry(it, 1) }.toMutableList()
        val records = pool.map { classify(it, verify) }

        // Seen-set on the recomputed manifest_hash bounds pathological
        // pools (a true commitment cycle is a hash fixpoint and cannot
        // verify).
        val walked = mutableSetOf<String>()
        fun openEntry(predicate: (WorkEntry) -> Boolean): WorkEntry? =
            entries.firstOrNull { it.status == STATUS_UNVERIFIED && predicate(it) }

        var changed = true
        while (changed) {
            changed = false
            for (record in records) {
                if (record.assigned || record.kind == KIND_UNREADABLE) continue

                if (record.kind != KIND_VERIFIABLE) {
                    // Bytes in hand but rules unavailable: match by the
                    // artifact's claimed id (the status says explicitly
                    // that nothing was verified).
                    val claimed = record.claimedId ?: continue
                    val entry = openEntry { it.capsuleId == claimed } ?: continue
                    record.assigned = true
                    changed = true
                    entry.status = STATUS_PREDECESSOR_UNVERIFIABLE
                    entry.reason = record.kind
                    notes += unverifiableNote(entry, record)
                    continue
                }

                // Matching uses recomputed values only. Pair match
                // first; an id-only match is a different sealed state of
                // the same identity.
                var entry =
                    if (record.recomputedId == null || record.recomputedManifestHash == null) null
                    else openEntry {
                        it.capsuleId == record.recomputedId &&
                            it.manifestHash == record.recomputedManifestHash
                    }
                if (entry == null && record.recomputedId != null) {
                    entry = openEntry { it.capsuleId == record.recomputedId }
                }
                if (entry == null) continue
                record.assigned = true
                changed = true
                entry.artifact = record.summary
                val diffs = equalityDiffs(entry, record)
                val verification = record.verification

                if (verification != null && !verification.ok) {
                    // Two facts, never collapsed: "is this the declared
                    // artifact" vs "does it verify internally". Takes
                    // precedence over mismatch; the equalities are still
                    // reported informatively.
                    entry.status = STATUS_PREDECESSOR_INVALID
                    entry.errors += "supplied predecessor fails its own verification under era " +
                        "${record.version} (${record.summary?.errorCount ?: 0} error(s)); this is " +
                        "a property of the supplied artifact, not of the successor's declaration"
                    entry.errors += diffs
                } else if (diffs.isNotEmpty()) {
                    entry.status = STATUS_MISMATCH
                    entry.errors += "supplied artifact is a different sealed state of the " +
                        "declared predecessor (same capsule identity, different seal) — not " +
                        "evidence of tampering; re-seals of a growing line legitimately share " +
                        "a capsule_id"
                    entry.errors += diffs
                } else {
                    entry.status = STATUS_VERIFIED
                }

                // Recursive walk: a hop whose manifest matches the
                // declared manifest_hash contributes ITS OWN
                // first-person declaration to the frontier — even when
                // its event chain is broken (the commitment chain
                // authenticates the declaration bytes). A mismatched
                // artifact is NOT the declared artifact and never
                // contributes.
                val mh = record.recomputedManifestHash
                if (mh != null && entry.manifestHash == mh && walked.add(mh)) {
                    val child = member(record.manifest, "predecessors")
                    if (child != null) {
                        if (record.version !in LINEAGE_ERAS) {
                            notes += "lineage: predecessor ${entry.capsuleId} declares era " +
                                "${record.version}, whose rule set defines no lineage semantics; " +
                                "its predecessors member is an unknown member under that era and " +
                                "terminates the walk"
                        } else if (predecessorsProblems(child).isEmpty()) {
                            // A malformed hop declaration is diagnosed by
                            // that hop's own verification; nothing to walk.
                            if (entry.hop + 1 <= HOP_CAP) {
                                (child as JCSValue.Arr).items.forEach {
                                    entries += workEntry(it, entry.hop + 1)
                                }
                            } else {
                                notes += "lineage: hop cap $HOP_CAP reached; deeper " +
                                    "declarations were not walked"
                            }
                        }
                    }
                }
            }
        }

        // Unmatched supplied artifacts are named, never silently
        // ignored — a mistyped path must be visible.
        records.forEachIndexed { i, record ->
            if (record.assigned) return@forEachIndexed
            notes += if (record.kind == KIND_UNREADABLE) {
                "lineage: supplied predecessor artifact #${i + 1} could not be read as a " +
                    "capsule (${record.openError}); it matched no declared entry"
            } else {
                val label = record.claimedId ?: record.recomputedId ?: "(unknown id)"
                "lineage: supplied predecessor artifact #${i + 1} (capsule $label) " +
                    "matched no declared entry"
            }
        }

        // Pinned phrase: a custody claim must never quietly disappear
        // when bytes are missing — that is how a citation gets read as
        // an endorsement.
        for (entry in entries) {
            if (entry.status == STATUS_UNVERIFIED ||
                entry.status == STATUS_PREDECESSOR_UNVERIFIABLE
            ) {
                notes += "lineage: predecessor ${entry.capsuleId} (hop ${entry.hop}): " +
                    "declared, not verified"
            }
        }

        // verified_depth: the largest N such that EVERY declared entry
        // within N hops has status "verified".
        var depth = 0
        var hop = 1
        while (entries.any { it.hop == hop }) {
            if (!entries.filter { it.hop <= hop }.all { it.status == STATUS_VERIFIED }) break
            depth = hop
            hop += 1
        }
        if (depth >= 1) {
            val parents = entries.filter { it.hop == 1 }.joinToString(", ") { it.capsuleId ?: "null" }
            // Two distinct identities, always: the successor is never
            // presented as BEING the predecessor or as its endorsed
            // continuation.
            notes += "lineage: successor of capsule $parents; lineage verified to depth $depth"
        }

        // Area verdict: standalone passed AND nothing CHECKED
        // contradicts. Unchecked is not failed.
        val areaOk = entries.none {
            it.status == STATUS_MISMATCH || it.status == STATUS_PREDECESSOR_INVALID
        }
        return Evaluation(
            LineageReport(
                declared = true,
                ok = areaOk,
                verifiedDepth = depth,
                entries = entries.map { it.snapshot() },
            ),
            emptyList(),
        )
    }

    // -----------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------

    private const val KIND_VERIFIABLE = "verifiable"
    private const val KIND_UNREADABLE = "unreadable"
    private const val KIND_ENCRYPTED = REASON_ENCRYPTED_PREDECESSOR

    private class WorkEntry(
        val capsuleId: String?,
        val formatVersion: String?,
        val originatorPublicKey: String?,
        val firstEventHash: String?,
        val entryHash: String?,
        val manifestHash: String?,
        val hop: Int,
        val identityChecked: Boolean,
    ) {
        var status: String = STATUS_UNVERIFIED
        var reason: String? = null
        val errors = mutableListOf<String>()
        var artifact: LineageArtifact? = null

        fun snapshot() = LineageEntry(
            capsuleId = capsuleId,
            formatVersion = formatVersion,
            originatorPublicKey = originatorPublicKey,
            firstEventHash = firstEventHash,
            entryHash = entryHash,
            manifestHash = manifestHash,
            hop = hop,
            identityChecked = identityChecked,
            status = status,
            reason = reason,
            errors = errors.toList(),
            artifact = artifact,
        )
    }

    private fun workEntry(declared: JCSValue, hop: Int) = WorkEntry(
        capsuleId = str(declared, "capsule_id"),
        formatVersion = str(declared, "format_version"),
        originatorPublicKey = str(declared, "originator_public_key"),
        firstEventHash = str(declared, "first_event_hash"),
        entryHash = str(declared, "entry_hash"),
        manifestHash = str(declared, "manifest_hash"),
        hop = hop,
        identityChecked = identityCheckable(declared),
    )

    /**
     * One classified pool artifact. [kind] is `verifiable` (plain,
     * known era, default profile — carries the full own-era
     * verification and the recomputes), one of the
     * `predecessor_unverifiable` reasons, or `unreadable`. Matching for
     * the unverifiable kinds uses the artifact's own CLAIMED id
     * (nothing can be recomputed); their status says so explicitly.
     */
    private class PoolRecord {
        var kind: String = KIND_UNREADABLE
        var manifest: JCSValue? = null
        var envelope: JCSValue? = null
        var claimedId: String? = null
        var version: String? = null
        var recomputedId: String? = null
        var recomputedManifestHash: String? = null
        var originatorKey: String? = null
        var firstEventHash: String? = null
        var entryHash: String? = null
        var verification: CapsuleVerification? = null
        var summary: LineageArtifact? = null
        var assigned: Boolean = false
        var openError: String? = null
    }

    private fun classify(
        bytes: ByteArray,
        verify: (ByteArray) -> CapsuleVerification,
    ): PoolRecord {
        val record = PoolRecord()
        val files: Map<String, ByteArray>
        try {
            files = CapsuleZip.unpack(bytes).toMap()
            val manifestBytes = files["manifest.json"]
                ?: throw CapsuleException("missing manifest.json")
            record.manifest = CapsuleReader.parseJsonFile(manifestBytes, "manifest.json")
            files["provenance/envelope.json"]?.let {
                record.envelope = CapsuleReader.parseJsonFile(it, "provenance/envelope.json")
            }
        } catch (e: Throwable) {
            record.openError = e.message ?: "$e"
            return record
        }
        val manifest = record.manifest
        val claimed = CapsuleReader.lookupString(manifest!!, listOf("id"))
        record.claimedId = if (claimed != null && CapsuleReader.isHex64(claimed)) claimed else null
        record.version = CapsuleReader.lookupString(manifest, listOf("format", "version"))

        // Encryption is read off the SIGNED envelope plus blob presence,
        // never the manifest's own claim. An artifact whose envelope
        // does not declare `cipher: "none"` is not a plain capsule, and
        // v0.7.1 declarations commit to a PLAIN capsule's members — so
        // it is reported, never guessed at. Classifying it needs no
        // decryption path, which is why this plain-only lane reports the
        // same reason as every other lane.
        val cipher = record.envelope?.let { CapsuleReader.lookupString(it, listOf("cipher")) }
        if (cipher != "none" || files.containsKey("content.enc")) {
            record.kind = KIND_ENCRYPTED
            return record
        }
        if (CapsuleVersions.classify(record.version) != CapsuleVersions.Status.KNOWN) {
            record.kind = REASON_UNSUPPORTED_VERSION
            return record
        }
        if (declaredAlternateProfileId(manifest) != null) {
            record.kind = REASON_UNSUPPORTED_PROFILE
            return record
        }
        record.kind = KIND_VERIFIABLE

        // Recomputed values ONLY, never the artifact's own claims:
        // identity under the artifact's declared era's domain string,
        // manifest hash from the stored manifest document.
        val originatorKey =
            CapsuleReader.lookupString(manifest, listOf("originator", "public_key"))
        record.originatorKey = originatorKey?.lowercase()
        record.firstEventHash =
            (member(manifest, "first_event_hash") as? JCSValue.Str)?.v
        record.recomputedId = try {
            Manifest.computeCapsuleId(
                CapsuleCrypto.hexToBytes(originatorKey ?: ""),
                record.firstEventHash ?: ZERO_HASH,
                record.version!!,
            )
        } catch (_: Throwable) {
            null
        }
        record.recomputedManifestHash = try {
            Manifest.hash(manifest)
        } catch (_: Throwable) {
            null
        }
        record.entryHash =
            record.envelope?.let { CapsuleReader.lookupString(it, listOf("entry_hash")) }
        val verification = verify(bytes)
        record.verification = verification
        record.summary = LineageArtifact(
            ok = verification.ok,
            observedVersion = verification.formatVersion.observed ?: record.version,
            level = verification.level,
            errorCount = verification.checks.count { !it.ok },
        )
        return record
    }

    /**
     * The six equalities of the linkage check. Returns member-precise
     * difference strings (empty = the supplied artifact IS the declared
     * sealed state). Wording never uses tamper/corruption vocabulary:
     * the supplied file being a different genuine seal is the common
     * honest cause, and "wrong file supplied" versus "successor lied"
     * is genuinely indistinguishable here.
     */
    private fun equalityDiffs(entry: WorkEntry, record: PoolRecord): List<String> = listOf(
        Triple("format_version", entry.formatVersion, record.version),
        Triple("capsule_id", entry.capsuleId, record.recomputedId),
        Triple("originator_public_key", entry.originatorPublicKey, record.originatorKey),
        Triple("first_event_hash", entry.firstEventHash, record.firstEventHash),
        Triple("entry_hash", entry.entryHash, record.entryHash),
        Triple("manifest_hash", entry.manifestHash, record.recomputedManifestHash),
    ).mapNotNull { (name, declared, supplied) ->
        if (declared == supplied) null
        else "$name: declared ${declared ?: "null"}, supplied artifact has ${supplied ?: "null"}"
    }

    private fun unverifiableNote(entry: WorkEntry, record: PoolRecord): String = when (record.kind) {
        KIND_ENCRYPTED ->
            "lineage: supplied predecessor for capsule ${entry.capsuleId} is an encrypted " +
                "capsule; v0.7.1 lineage declarations commit to a plain capsule's members — " +
                "decrypt the inner capsule and supply it instead. The entry stays declared, " +
                "not verified"
        REASON_UNSUPPORTED_VERSION ->
            "lineage: supplied predecessor for capsule ${entry.capsuleId} declares format " +
                "version '${record.version}', which this verifier does not support — a " +
                "limitation of the verifier, not a defect of either capsule. The entry stays " +
                "declared, not verified"
        REASON_UNSUPPORTED_PROFILE ->
            "lineage: supplied predecessor for capsule ${entry.capsuleId} declares profile " +
                "'${declaredAlternateProfileId(record.manifest)}', which this verifier does " +
                "not implement (v0.7.1 lineage declarations commit to default-profile " +
                "predecessors) — a limitation of the verifier, not a defect of either capsule. " +
                "The entry stays declared, not verified"
        else ->
            "lineage: supplied predecessor for capsule ${entry.capsuleId} cannot be evaluated " +
                "by this verifier (${record.kind}) — a limitation of the verifier, not a defect " +
                "of either capsule. The entry stays declared, not verified"
    }

    private fun member(value: JCSValue?, key: String): JCSValue? =
        (value as? JCSValue.Obj)?.pairs?.firstOrNull { it.first == key }?.second

    private fun str(value: JCSValue?, key: String): String? =
        (member(value, key) as? JCSValue.Str)?.v

    /** The member's value when it is a lowercase 64-hex string, else null. */
    private fun hex64(entry: JCSValue?, key: String): String? {
        val s = (member(entry, key) as? JCSValue.Str)?.v ?: return null
        return if (CapsuleReader.isHex64(s)) s else null
    }

    /** True when the member is JSON null or a lowercase 64-hex string. */
    private fun nullableHex64Ok(entry: JCSValue?, key: String): Boolean =
        when (val v = member(entry, key)) {
            JCSValue.Null -> true
            is JCSValue.Str -> CapsuleReader.isHex64(v.v)
            else -> false
        }

    private fun render(value: JCSValue?): String = when (value) {
        null, JCSValue.Null -> "null"
        is JCSValue.Str -> Chain.debugQuoted(value.v)
        else -> "a non-string value"
    }
}

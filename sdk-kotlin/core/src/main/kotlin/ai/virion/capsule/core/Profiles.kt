// Profile declaration policy (spec/profiles.md). Mirrors
// sdk-js/src/profiles.js.
//
// A capsule may DECLARE the verification profile that governs it —
// `manifest.format.profile` and `envelope.profile`, mirroring the
// `format.version` / `envelope.version` dyad. A verifier keeps a table
// of the profiles it implements (keyed selection, exactly like the
// known-version table) and:
//
//   - treats ABSENCE of a declaration in a 0.6/0.7 capsule as the
//     default profile `v0.6-suite` version `1.0`, permanently — the
//     mirror of the algorithm-suite pin in spec/versioning.md;
//   - requires the two documents' NORMALIZED declarations (absence =
//     default) to agree; a capsule whose pairs differ is ambiguous
//     about which rules bind it and fails closed BEFORE any table
//     lookup (`profile_mismatch` — a defect of the capsule);
//   - FAILS CLOSED on a declared (id, version) pair outside the table,
//     with a diagnosis distinct from both tampering and malformation:
//     `unsupported_profile` is a limitation of the verifier, never a
//     defect of the capsule;
//   - treats a present declaration that violates the closed object
//     shape or the identifier grammar as a MALFORMED document
//     (invalid_manifest_shape), not a support gap.
//
// The gate runs at OPEN stage, after the version gate and before
// anything else — including the plain-only cipher refusal: applying the
// wrong profile's rules would manufacture mismatch errors
// indistinguishable from tampering, which is versioning.md's confusion
// reproduced on the profile axis.

package ai.virion.capsule.core

/**
 * A profile-gate refusal. Carries the full [classification] so a
 * fail-closed verify result can populate its profile channel from the
 * exception alone. Deliberately distinct from the plain
 * [CapsuleException] and from [UnsupportedVersionException]: an
 * operator must be able to tell "verify this with an implementation of
 * that profile" apart from both "this verifier is too old" and "this
 * capsule is corrupt".
 */
open class ProfileException(
    val classification: CapsuleProfiles.Classification,
    message: String,
) : CapsuleException(message)

/** A declared (id, version) pair outside this verifier's table. */
class UnsupportedProfileException(
    classification: CapsuleProfiles.Classification,
    message: String,
) : ProfileException(classification, message)

/** The two documents' normalized declarations disagree (a capsule defect). */
class ProfileMismatchException(
    classification: CapsuleProfiles.Classification,
    message: String,
) : ProfileException(classification, message)

/** A present declaration violating the closed shape or grammar (malformed). */
class InvalidProfileException(
    classification: CapsuleProfiles.Classification,
    message: String,
) : ProfileException(classification, message)

object CapsuleProfiles {

    data class Profile(val id: String, val version: String)

    /**
     * The default profile: the spec/envelope.md verification/encryption
     * procedure of the capsule's declared era with the v0.6 algorithm
     * suite of spec/versioning.md. The id deliberately matches the suite
     * fact (`v0.6`) verifiers already report. Frozen forever — the
     * absence rule makes this spelling permanent.
     */
    val DEFAULT = Profile("v0.6-suite", "1.0")

    /**
     * Every (id, version) profile row this implementation applies.
     * Exact-match on the pair — no ranges, no compatibility semantics. A
     * profile once supported is supported forever (the archival rule
     * applied to profiles), and the default row of every known era is
     * always present.
     */
    val SUPPORTED: List<Profile> = listOf(DEFAULT)

    /**
     * The outcome of classifying the (manifest, envelope) declaration
     * dyad. [status] is the closed vocabulary of spec/profiles.md:
     *   "default"     — no declaration, or the explicit era default:
     *                   default rules apply (explicit default is exactly
     *                   equivalent to absence — a redundant claim made
     *                   honestly).
     *   "supported"   — declared alternate profile this reader
     *                   implements (unreachable in-era: the reference
     *                   table holds one row).
     *   "unsupported" — declared alternate the reader does not
     *                   implement: a limitation of the verifier, not a
     *                   defect of the capsule.
     *   "mismatched"  — normalized declarations disagree: the capsule is
     *                   ambiguous about which rules bind it (a defect).
     *   "invalid"     — a present member violates the closed shape or
     *                   the grammar: a malformed document.
     */
    data class Classification(
        val status: String,
        val observed: String? = null,
        val observedVersion: String? = null,
        val declared: Boolean = false,
        val effective: String? = null,
        val effectiveVersion: String? = null,
        val supported: Boolean = false,
        val problems: List<String> = emptyList(),
        /** Both NORMALIZED pairs, present only when status is "mismatched". */
        val normalized: Pair<Profile, Profile>? = null,
    )

    // profile-id = lowletter *63( lowletter / DIGIT / "-" / "." )
    // 1..64 bytes, lowercase-only, no trailing "-" or "." (no leading
    // one by construction: the first byte is a letter).
    private val ID_GRAMMAR = Regex("^[a-z][a-z0-9.-]{0,63}$")
    // The vendor fence: an id beginning `x-` MUST be vendor-scoped
    // `x-<vendor>-<name>`; ids not beginning `x-` are reserved to the
    // spec, exactly like non-`x-` member keys.
    private val VENDOR_ID_GRAMMAR = Regex("^x-[a-z0-9.]+-[a-z0-9.-]+$")
    // profile-ver: the SAME grammar as format versions (versioning.md).
    private val VERSION_GRAMMAR = Regex("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$")

    /** True iff [id] satisfies the spec/profiles.md identifier grammar. */
    fun isValidProfileId(id: String?): Boolean {
        if (id == null || !ID_GRAMMAR.matches(id)) return false
        if (id.endsWith("-") || id.endsWith(".")) return false
        if (id.startsWith("x-") && !VENDOR_ID_GRAMMAR.matches(id)) return false
        return true
    }

    /** True iff [version] satisfies the profile-version grammar. */
    fun isValidProfileVersion(version: String?): Boolean =
        version != null && VERSION_GRAMMAR.matches(version)

    /** `manifest.format.profile` as stored — null when the member is absent. */
    fun manifestDeclaration(manifest: JCSValue): JCSValue? =
        member(member(manifest, "format"), "profile")

    /** `envelope.profile` as stored — null when the member is absent. */
    fun envelopeDeclaration(envelope: JCSValue): JCSValue? = member(envelope, "profile")

    private fun member(v: JCSValue?, key: String): JCSValue? =
        (v as? JCSValue.Obj)?.pairs?.firstOrNull { it.first == key }?.second

    /**
     * Shape problems for ONE document's PRESENT profile declaration.
     * Returns an empty list for a well-formed declaration; every message
     * is prefixed with the offending field path (the
     * invalid_manifest_shape idiom). [envelope] applies the
     * envelope-copy rules — no `params`: params are single-sourced in
     * the manifest so no second copy can diverge and the equality rule
     * needs no deep-equality machinery in five lanes.
     */
    fun declarationProblems(
        value: JCSValue,
        path: String,
        envelope: Boolean = false,
    ): List<String> {
        val shape = if (envelope) "{ id, version }" else "{ id, version, params? }"
        if (value == JCSValue.Null) {
            // null is NOT a declaration: the honest way to not declare is
            // to omit, and a second spelling of absence is a known
            // typed-decoder divergence across lanes.
            return listOf(
                "$path must be an object $shape; null is not a declaration — " +
                    "omit the member to not declare"
            )
        }
        val pairs = (value as? JCSValue.Obj)?.pairs
            ?: return listOf("$path must be an object $shape, got ${render(value)}")

        val problems = mutableListOf<String>()
        // The object is CLOSED: an uninterpretable member in the rule
        // SELECTOR is the capsule asserting something meaningless about
        // what governs it. Vendor freight rides in manifest params or in
        // ordinary x- members, so nothing is blocked.
        val allowed = if (envelope) listOf("id", "version") else listOf("id", "version", "params")
        for ((key, _) in pairs) {
            if (key in allowed) continue
            problems += if (key == "params" && envelope) {
                "$path.params is not allowed: params are single-sourced in manifest.format.profile"
            } else {
                "$path.$key is not a member of the closed profile object " +
                    "(exactly: ${allowed.joinToString(", ")})"
            }
        }
        val id = (member(value, "id") as? JCSValue.Str)?.v
        if (!isValidProfileId(id)) {
            problems += "$path.id must be a profile identifier (1-64 bytes, lowercase letter " +
                "first, then lowercase letters, digits, '-' or '.'; 'x-' ids vendor-scoped as " +
                "x-<vendor>-<name>), got ${render(member(value, "id"))}"
        }
        val version = (member(value, "version") as? JCSValue.Str)?.v
        if (!isValidProfileVersion(version)) {
            problems += "$path.version must be a '<major>.<minor>' version string, " +
                "got ${render(member(value, "version"))}"
        }
        val params = member(value, "params")
        if (!envelope && params != null && params !is JCSValue.Obj) {
            problems += "$path.params must be a JSON object, got ${render(params)}"
        }
        return problems
    }

    /**
     * Classify the (manifest, envelope) declaration dyad against this
     * implementation's table. Pass the raw member values — Kotlin `null`
     * means the member is ABSENT, [JCSValue.Null] means it is present
     * and JSON null. Pure and total; never throws.
     *
     * The caller owns gate ORDER: classify only after both documents
     * pass the version gate (the absence rule is era-keyed).
     */
    fun classify(manifestDecl: JCSValue?, envelopeDecl: JCSValue?): Classification {
        val declared = manifestDecl != null || envelopeDecl != null
        // The declared id/version as read — reported even on refusal and
        // even when invalid (the observed fact). On a dyad mismatch these
        // are the manifest values; when the manifest is silent, the
        // envelope's.
        val observedSource = (manifestDecl as? JCSValue.Obj) ?: (envelopeDecl as? JCSValue.Obj)
        val observed = (member(observedSource, "id") as? JCSValue.Str)?.v
        val observedVersion = (member(observedSource, "version") as? JCSValue.Str)?.v

        val problems = mutableListOf<String>()
        manifestDecl?.let { problems += declarationProblems(it, "manifest.format.profile") }
        envelopeDecl?.let {
            problems += declarationProblems(it, "envelope.profile", envelope = true)
        }
        if (problems.isNotEmpty()) {
            return Classification(
                status = "invalid", observed = observed, observedVersion = observedVersion,
                declared = declared, problems = problems,
            )
        }

        // Normalized dyad equality: absence means the era default, so the
        // default declared in exactly one document is coherent (both
        // readings mean the default) — refusing it would punish a
        // truthful statement.
        val m = normalize(manifestDecl)
        val e = normalize(envelopeDecl)
        if (m != e) {
            // Mismatch BEFORE table lookup: the effective declaration does
            // not exist until the documents agree, and reporting a
            // mismatched capsule as "unsupported" would hand the auditor a
            // false remediation ("find a better verifier" for a capsule
            // that is defective).
            return Classification(
                status = "mismatched", observed = observed, observedVersion = observedVersion,
                declared = declared, normalized = m to e,
            )
        }
        if (SUPPORTED.none { it == m }) {
            return Classification(
                status = "unsupported", observed = m.id, observedVersion = m.version,
                declared = declared,
            )
        }
        return Classification(
            status = if (m == DEFAULT) "default" else "supported",
            observed = observed, observedVersion = observedVersion, declared = declared,
            effective = m.id, effectiveVersion = m.version, supported = true,
        )
    }

    /** Cross-lane refusal wording (spec/profiles.md, spec/results.md). */
    fun unsupportedMessage(id: String?, version: String?): String =
        "profile '${id ?: ""}' version '${version ?: ""}' is not supported by this verifier " +
            "(supported: ${SUPPORTED.joinToString(", ") { "${it.id}/${it.version}" }}); " +
            "this is a limitation of the verifier, not corruption of the capsule — " +
            "verify it with an implementation of that profile"

    /** Cross-lane mismatch wording: both NORMALIZED pairs quoted. */
    fun mismatchMessage(manifest: Profile, envelope: Profile): String {
        fun fmt(p: Profile) = "'${p.id}' version '${p.version}'"
        return "envelope.profile does not match manifest.format.profile: " +
            "manifest normalizes to ${fmt(manifest)}, envelope normalizes to ${fmt(envelope)} " +
            "(absence means the era default ${DEFAULT.id}/${DEFAULT.version}); " +
            "the capsule is ambiguous about which rules bind it"
    }

    /**
     * The open-stage profile gate. Call AFTER both documents pass the
     * version gate. Throws a typed [ProfileException] subclass on
     * refusal; returns the classification when the capsule's effective
     * profile is one this implementation applies.
     */
    fun requireSupported(manifest: JCSValue, envelope: JCSValue): Classification {
        val cls = classify(manifestDeclaration(manifest), envelopeDeclaration(envelope))
        when (cls.status) {
            // Field-path-prefixed shape wording (the invalid_manifest_shape
            // idiom) — never the word "unsupported": malformed is a defect
            // of the capsule, unsupported a limitation of the verifier.
            "invalid" -> throw InvalidProfileException(cls, cls.problems.joinToString("; "))
            "mismatched" -> throw ProfileMismatchException(
                cls, mismatchMessage(cls.normalized!!.first, cls.normalized.second))
            "unsupported" -> throw UnsupportedProfileException(
                cls, unsupportedMessage(cls.observed, cls.observedVersion))
        }
        return cls
    }

    /** A well-formed declaration as its (id, version) pair; absence = default. */
    private fun normalize(decl: JCSValue?): Profile {
        if (decl == null) return DEFAULT
        return Profile(
            id = (member(decl, "id") as? JCSValue.Str)?.v ?: "",
            version = (member(decl, "version") as? JCSValue.Str)?.v ?: "",
        )
    }

    /** Diagnostic rendering of an offending value (strings debug-quoted). */
    private fun render(v: JCSValue?): String = when (v) {
        null -> "undefined"
        is JCSValue.Str -> Chain.debugQuoted(v.v)
        else -> JCS.canonical(v)
    }
}

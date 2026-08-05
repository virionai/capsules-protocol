// Profile declaration policy unit pins (spec/profiles.md). The
// cross-lane fixture outcomes live in SpecRegistryTest
// (profileDeclarationRegistryOutcomes); this file pins the machinery the
// fixtures cannot reach from a plain-only lane: the identifier grammar,
// the normalized-dyad classification, refusal exclusivity, and the
// report-never-decide acceptProfiles policy.

package ai.virion.capsule.core

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ProfileGateTest {

    private fun vectorsDir(): File {
        var dir = File(System.getProperty("user.dir")).absoluteFile
        while (true) {
            val candidate = File(dir, "spec/vectors")
            if (candidate.isDirectory) return candidate
            dir = dir.parentFile ?: error("spec/vectors not found above ${System.getProperty("user.dir")}")
        }
    }

    private fun profileFixture(name: String): ByteArray =
        File(vectorsDir(), "profile-declaration/output/$name.capsule").readBytes()

    private fun declaration(id: String, version: String) =
        jobj("id" to jstr(id), "version" to jstr(version))

    @Test
    fun identifierGrammar() {
        assertTrue(CapsuleProfiles.isValidProfileId("v0.6-suite"))
        assertTrue(CapsuleProfiles.isValidProfileId("x-acme-kms-es256"))
        assertFalse(CapsuleProfiles.isValidProfileId("Acme KMS!"))
        assertFalse(CapsuleProfiles.isValidProfileId("0-leading-digit"))
        assertFalse(CapsuleProfiles.isValidProfileId("trailing-"))
        assertFalse(CapsuleProfiles.isValidProfileId("trailing."))
        assertFalse(CapsuleProfiles.isValidProfileId("a".repeat(65)))
        // The vendor fence: an `x-` id MUST be vendor-scoped, so a vendor
        // cannot mint a bare-looking name inside the namespace the spec
        // reserves to itself.
        assertFalse(CapsuleProfiles.isValidProfileId("x-acme"))
        assertTrue(CapsuleProfiles.isValidProfileVersion("1.0"))
        assertFalse(CapsuleProfiles.isValidProfileVersion("1"))
        assertFalse(CapsuleProfiles.isValidProfileVersion("01.0"))
    }

    /**
     * Absence means the era default, permanently — so the default
     * declared in ONE document is coherent (both readings mean the
     * default) and classifies exactly like absence. Refusing a true,
     * redundant statement would be rigidity without a lie.
     */
    @Test
    fun normalizationTreatsAbsenceAsTheDefault() {
        val default = declaration("v0.6-suite", "1.0")
        assertEquals("default", CapsuleProfiles.classify(null, null).status)
        assertEquals("default", CapsuleProfiles.classify(default, null).status)
        assertEquals("default", CapsuleProfiles.classify(null, default).status)
        assertEquals("default", CapsuleProfiles.classify(default, default).status)

        val absent = CapsuleProfiles.classify(null, null)
        assertFalse(absent.declared)
        assertEquals(CapsuleProfiles.DEFAULT.id, absent.effective)
        assertEquals(CapsuleProfiles.DEFAULT.version, absent.effectiveVersion)
        assertTrue(CapsuleProfiles.classify(default, null).declared)
    }

    /**
     * Three different facts, three different diagnoses: malformed is a
     * defect of the capsule, mismatched a self-contradiction, unsupported
     * a limitation of the verifier. Collapsing any pair hands an auditor
     * the wrong remediation.
     */
    @Test
    fun classificationKeepsTheThreeRefusalsDistinct() {
        val vendor = declaration("x-test-kms-1", "1.0")
        assertEquals("unsupported", CapsuleProfiles.classify(vendor, vendor).status)
        // Exact-match on the PAIR: a known id at an unknown version is
        // not understood, period.
        assertEquals(
            "unsupported",
            CapsuleProfiles.classify(
                declaration("v0.6-suite", "9.9"), declaration("v0.6-suite", "9.9")).status,
        )
        assertEquals("mismatched", CapsuleProfiles.classify(vendor, null).status)
        assertEquals("invalid", CapsuleProfiles.classify(JCSValue.Null, null).status)
        assertEquals(
            "invalid",
            CapsuleProfiles.classify(
                jobj(
                    "id" to jstr("v0.6-suite"),
                    "version" to jstr("1.0"),
                    "critical" to jstr("yes"),
                ),
                null,
            ).status,
        )
        // Params are single-sourced in the manifest; the envelope copy is
        // exactly { id, version }.
        assertEquals(
            "invalid",
            CapsuleProfiles.classify(
                null,
                jobj(
                    "id" to jstr("v0.6-suite"),
                    "version" to jstr("1.0"),
                    "params" to jobj("issuer" to jstr("https://example.test")),
                ),
            ).status,
        )
    }

    /** The gate refuses at OPEN, with typed exceptions per diagnosis. */
    @Test
    fun readerGateRefusesAtOpen() {
        assertFailsWith<UnsupportedProfileException> {
            CapsuleReader.parse(profileFixture("unsupported-vendor-profile"))
        }
        assertFailsWith<ProfileMismatchException> {
            CapsuleReader.parse(profileFixture("profile-mismatch-value"))
        }
        assertFailsWith<InvalidProfileException> {
            CapsuleReader.parse(profileFixture("profile-invalid-null"))
        }
        // The explicit default opens and verifies exactly like absence.
        CapsuleReader.parse(profileFixture("explicit-default-equivalent"))
    }

    /**
     * Refusal exclusivity: having refused at the gate, the verifier
     * applies NO profile's rules — no hash recompute, no signature check,
     * no skill-trust derivation — so every other channel holds its
     * fail-closed default and the profile diagnosis is the only error.
     * The fixture is default-suite-valid apart from its declaration, so a
     * lane that ran the checks anyway would report them passing.
     */
    @Test
    fun profileRefusalCarriesOnlyTheProfileDiagnosis() {
        val result = CapsuleVerifier.verify(profileFixture("unsupported-vendor-profile"))
        assertFalse(result.ok)
        assertEquals("unsupported", result.verdict)
        assertEquals("unsupported_profile", result.verdictReason)
        assertEquals(listOf("parse"), result.checks.map { it.name })
        assertEquals(emptyList(), result.qualifiers)
        assertEquals(emptyList(), result.signers)
        assertEquals(0, result.trustedSignerCount)
        assertFalse(result.signerSetBound)
        assertFalse(result.actorSetBound)
        assertFalse(result.skillTrust.capsuleSigned)
        // The declared version stays a reported fact through a profile
        // refusal; only the SUITE claim is withheld — reporting "v0.6"
        // about a capsule governed by rules this verifier refused to
        // apply would be a false fact.
        assertEquals("0.7", result.formatVersion.observed)
        assertNull(result.formatVersion.suite)
        // The observed declaration is still REPORTED — it is what lets an
        // auditor route the capsule to an implementation of that profile
        // instead of declaring it corrupt.
        assertEquals("x-test-kms-1", result.profile.observed)
        assertEquals("1.0", result.profile.observedVersion)
        assertTrue(result.profile.declared)
        assertFalse(result.profile.supported)
        assertNull(result.profile.effective)
        assertEquals("unsupported", result.profile.status)
    }

    /**
     * Gate ordering: the version gate runs first, so an unknown-era
     * capsule carries the version diagnosis alone and its declaration is
     * reported "unevaluated" — profile semantics are era-scoped, so an
     * unknown era means the declaration cannot even be classified.
     */
    @Test
    fun versionGateRunsBeforeTheProfileGate() {
        val result = CapsuleVerifier.verify(
            profileFixture("unknown-version-profile-unevaluated"))
        assertEquals("unsupported", result.verdict)
        assertEquals("unsupported_version_newer", result.verdictReason)
        assertEquals("9.9", result.formatVersion.observed)
        assertEquals("unevaluated", result.profile.status)
        assertEquals("x-test-kms-1", result.profile.observed)
    }

    /**
     * Host policy: accepted profile ids are REPORTED beside the observed
     * profile and never decide the result — the acceptVersions and
     * signer-allowlist shape.
     */
    @Test
    fun acceptProfilesIsReportedNeverDecided() {
        val bytes = profileFixture("absent-profile-is-default")

        val noPolicy = CapsuleVerifier.verify(bytes)
        assertTrue(noPolicy.ok, "positive fixture must verify; got ${noPolicy.checks}")
        assertEquals("default", noPolicy.profile.status)
        assertEquals("v0.6-suite", noPolicy.profile.effective)
        assertEquals("v0.6", noPolicy.formatVersion.suite)
        assertNull(noPolicy.profile.acceptedByPolicy)

        val accepted = CapsuleVerifier.verify(bytes, acceptProfiles = setOf("v0.6-suite"))
        assertEquals(true, accepted.profile.acceptedByPolicy)

        val rejected = CapsuleVerifier.verify(bytes, acceptProfiles = setOf("x-acme-kms-es256"))
        assertTrue(rejected.ok, "policy never decides integrity")
        assertEquals(false, rejected.profile.acceptedByPolicy)
        assertTrue(
            rejected.notes.any { it.contains("not in the declared accepted set") },
            "got notes: ${rejected.notes}",
        )
    }
}

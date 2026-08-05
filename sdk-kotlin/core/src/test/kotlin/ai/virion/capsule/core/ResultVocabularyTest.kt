// The normalized verdict surface (spec/results.md) at the unit level.
// The cross-lane arrays are pinned by SpecRegistryTest
// (resultVocabularyRegistryOutcomes); this file pins what a plain-only
// lane's own capsules exercise: the ok == (verdict == "valid")
// invariant, the qualifier derivations a builder-sealed capsule
// produces, and this lane's capability refusal — the one place its
// verdict for a given set of bytes differs from a lane with an
// encryption path.

package ai.virion.capsule.core

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ResultVocabularyTest {

    private fun vectorsDir(): File {
        var dir = File(System.getProperty("user.dir")).absoluteFile
        while (true) {
            val candidate = File(dir, "spec/vectors")
            if (candidate.isDirectory) return candidate
            dir = dir.parentFile ?: error("spec/vectors not found above ${System.getProperty("user.dir")}")
        }
    }

    /** A committed, participant-bound, single-event capsule. */
    private fun sealed(kp: CapsuleCrypto.Ed25519KeyPair): CapsuleBuilder.BuildResult =
        CapsuleBuilder(
            originator = CapsuleBuilder.Originator(keyPair = kp, label = "Acme"),
            createdAt = "2026-05-07T12:00:00Z",
        ).setProgram("# Loan file\n")
            .setParticipants(listOf(CapsuleBuilder.Participant(actorId = "human:alice")))
            .appendEvent(
                actor = "human:alice", kind = "decision",
                action = "submit", target = "program.md",
                payload = jobj("summary" to jstr("submitted")),
            )
            .seal(signedAt = "2026-05-07T12:00:00Z")

    /**
     * The strongest honest shape carries NO qualifiers — the only capsule
     * allowed an empty array. Everything weaker must say so on the
     * verdict.
     */
    @Test
    fun unqualifiedValid() {
        val kp = CapsuleCrypto.generateEd25519()
        val result = CapsuleVerifier.verify(
            sealed(kp).bytes, allowlist = setOf(kp.publicKeyHex))
        assertTrue(result.ok, "fixture must verify; got ${result.checks}")
        assertEquals("valid", result.verdict)
        assertNull(result.verdictReason)
        assertEquals(emptyList(), result.qualifiers)
    }

    /**
     * The same bytes under weaker host configurations. Each qualifier is
     * a fact about THIS verification, not about the capsule — which is
     * exactly why none of them could ever be a capsule member.
     */
    @Test
    fun hostRelativeQualifiers() {
        val kp = CapsuleCrypto.generateEd25519()
        val bytes = sealed(kp).bytes

        val noAllowlist = CapsuleVerifier.verify(bytes)
        assertEquals(listOf("trust_not_evaluated"), noAllowlist.qualifiers)
        assertTrue(noAllowlist.notes.any { it.contains("no allowlist") })

        val stranger = CapsuleVerifier.verify(bytes, allowlist = setOf("ab".repeat(32)))
        assertEquals(listOf("no_trusted_signer"), stranger.qualifiers)
        // The advisory the qualifier restates: a PASS with trusted=false
        // everywhere must never be silent about why.
        assertTrue(
            stranger.notes.any { it.contains("matched no signer") },
            "got notes: ${stranger.notes}",
        )

        val policy = CapsuleVerifier.verify(
            bytes, allowlist = setOf(kp.publicKeyHex), acceptVersions = setOf("0.6"))
        assertTrue(policy.ok, "host policy never decides integrity")
        assertEquals(listOf("version_not_accepted_by_policy"), policy.qualifiers)
    }

    /**
     * The trust.md threat-table capsule: no signer commitment, no
     * participants, zero events, no allowlist. It VERIFIES — each is a
     * weaker claim made honestly — and every reduced assurance is a
     * qualifier a renderer must surface beside the verdict, in the
     * spec-defined order.
     */
    @Test
    fun maximallyQualifiedValid() {
        val bytes = File(
            vectorsDir(), "result-vocabulary/output/maximally-qualified-valid.capsule"
        ).readBytes()
        val result = CapsuleVerifier.verify(bytes)
        assertTrue(result.ok, "fixture must verify; got ${result.checks}")
        assertEquals(
            listOf(
                "signer_set_unbound",
                "actor_set_unbound",
                "empty_chain_not_walked",
                "trust_not_evaluated",
            ),
            result.qualifiers,
        )
    }

    /**
     * `ok == (verdict == "valid")` across every shape this lane produces:
     * "unsupported" partitions the failures, it never softens one. A
     * tampered capsule is a defect of the capsule ("invalid", causes in
     * `checks`), never a limitation of the verifier.
     */
    @Test
    fun verdictNeverDisagreesWithOk() {
        val kp = CapsuleCrypto.generateEd25519()
        val fixtures = listOf(
            sealed(kp).bytes,
            File(vectorsDir(), "tamper-detection/output/clean.capsule").readBytes(),
            File(vectorsDir(), "tamper-detection/output/tampered-payload.capsule").readBytes(),
            File(vectorsDir(), "version-compat/output/unknown-newer-version.capsule").readBytes(),
            File(vectorsDir(), "version-compat/output/version-not-a-version.capsule").readBytes(),
            File(vectorsDir(), "profile-declaration/output/unsupported-vendor-profile.capsule")
                .readBytes(),
            File(vectorsDir(), "profile-declaration/output/profile-mismatch-value.capsule")
                .readBytes(),
        )
        for (bytes in fixtures) {
            val result = CapsuleVerifier.verify(bytes)
            assertEquals(
                result.ok, result.verdict == "valid",
                "ok/verdict disagree: ok=${result.ok} verdict=${result.verdict}",
            )
            assertEquals(
                result.verdict == "unsupported", result.verdictReason != null,
                "verdictReason is non-null iff the verdict is 'unsupported': " +
                    "${result.verdict}/${result.verdictReason}",
            )
            if (result.verdict != "valid") assertEquals(emptyList(), result.qualifiers)
        }

        val tampered = CapsuleVerifier.verify(
            File(vectorsDir(), "tamper-detection/output/tampered-payload.capsule").readBytes())
        assertEquals("invalid", tampered.verdict)
        assertNull(tampered.verdictReason)
    }

    /**
     * This lane parses the container fine but has no X25519/ChaCha20
     * path, so an encrypted capsule another conforming lane verifies is
     * refused as a limitation of THIS verifier: verdict "unsupported"
     * with reason `unsupported_capability` (spec/results.md), never a
     * claim that the capsule is corrupt. The conformance registry
     * additionally gates such vectors with requires:["encryption"] — the
     * registry gates what this lane RUNS, this verdict is what its API
     * reports when a host hands it one anyway.
     */
    @Test
    fun encryptedCapsuleIsAnUnsupportedCapability() {
        val bytes = File(
            vectorsDir(), "tamper-detection/output/clean-encrypted.capsule").readBytes()
        val result = CapsuleVerifier.verify(bytes)
        assertFalse(result.ok)
        assertEquals("unsupported", result.verdict)
        assertEquals("unsupported_capability", result.verdictReason)
        assertEquals(emptyList(), result.qualifiers)
    }
}

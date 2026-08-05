// Lane-level lineage properties (spec/lineage.md) that the conformance
// vectors cannot reach from a capsule file alone: the report-only
// invariant seen from the caller's side, the not-evaluated channel
// default under an open-stage refusal, the honest reporting of supplies
// that match nothing, and the standalone grammar rules exercised
// directly against a declaration value.
//
// The vector-driven expectations live in SpecRegistryTest; these pin the
// rules a future refactor could quietly lose.

package ai.virion.capsule.core

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LineageTest {

    /** Absence is a weaker claim made honestly — never a failure. */
    @Test
    fun absentMemberIsNoClaim() {
        val result = CapsuleVerifier.verify(fixture("alice.capsule"))
        assertTrue(result.ok, "the control capsule must verify")
        assertFalse(result.lineage.declared)
        assertTrue(result.lineage.ok, "unchecked is not failed")
        assertEquals(emptyList(), result.lineage.entries)
        assertEquals(emptyList(), result.qualifiers)
    }

    /**
     * No retroactive interpretation of sealed eras: the SAME malformed
     * value that fails a 0.7 capsule closed (`empty-array`) is an inert
     * unknown member inside a 0.6 one. `predecessors` is a claim member,
     * so it follows per-era rule sets — and the gate applies to the
     * SUBJECT capsule, not only to hops reached through the walk.
     */
    @Test
    fun predecessorsInAPreLineageEraCapsuleIsInert() {
        val v07 = CapsuleVerifier.verify(fixture("empty-array.capsule"))
        assertFalse(v07.ok, "a 0.7 capsule's malformed declaration still fails closed")

        val v06 = CapsuleVerifier.verify(fixture("predecessors-in-v06-capsule.capsule"))
        assertTrue(v06.ok, "a v0.6 capsule verifies as a v0.6 reader gives it: ${v06.checks.filter { !it.ok }}")
        assertEquals("0.6", v06.formatVersion.observed)
        assertFalse(v06.lineage.declared)
        assertTrue(v06.lineage.ok)
        assertEquals(emptyList(), v06.lineage.entries)
        assertEquals(emptyList(), v06.qualifiers)
        assertTrue(
            v06.notes.any { it.contains("unknown member under that era") },
            "the uninterpreted member is reported: ${v06.notes}",
        )
    }

    /**
     * THE anti-framing rule: a host supplying the wrong file must not be
     * able to flip a valid capsule's verdict. The later genuine seal of
     * the same line falsifies the AREA and raises the qualifier while
     * `ok` stays true, and the diagnosis never reaches for tamper
     * vocabulary.
     */
    @Test
    fun linkageNeverFlipsTheVerdict() {
        val result = CapsuleVerifier.verify(
            fixture("bob.capsule"),
            predecessors = listOf(fixture("alice-later-seal.capsule")),
        )
        assertTrue(result.ok, "linkage is REPORT-ONLY: ${result.checks.filter { !it.ok }}")
        assertFalse(result.lineage.ok, "a checked mismatch falsifies the area")
        assertEquals(listOf("lineage_mismatch"), result.qualifiers)
        val entry = result.lineage.entries.single()
        assertEquals(Lineage.STATUS_MISMATCH, entry.status)
        val diagnosis = entry.errors.joinToString(" ")
        assertTrue(
            diagnosis.contains("different sealed state of the declared predecessor"),
            "expected the pinned phrase; got $diagnosis",
        )
        assertFalse(
            diagnosis.contains("tampering") && !diagnosis.contains("not evidence of tampering"),
            "mismatch wording must not read as tamper detection: $diagnosis",
        )
        assertTrue(
            entry.errors.any { it.startsWith("manifest_hash: declared") },
            "every differing member must be named; got ${entry.errors}",
        )
    }

    /** A mistyped path must be visible, never silently ignored. */
    @Test
    fun unmatchedSupplyIsNamed() {
        val result = CapsuleVerifier.verify(
            fixture("bob.capsule"),
            predecessors = listOf(fixture("dana.capsule"), "not a capsule".toByteArray()),
        )
        assertTrue(result.ok)
        assertEquals(Lineage.STATUS_UNVERIFIED, result.lineage.entries.single().status)
        assertTrue(
            result.notes.any { it.contains("matched no declared entry") },
            "an unmatched supply must be reported; got ${result.notes}",
        )
        assertTrue(
            result.notes.any { it.contains("could not be read as a capsule") },
            "an unreadable supply must be reported; got ${result.notes}",
        )
    }

    /**
     * Refusal exclusivity: after an open-stage refusal the lineage
     * channel holds its not-evaluated default and the refusal diagnosis
     * is the only error carried. `declared=false` there means "not
     * evaluated", not "absent" — which is why the default `ok` is false.
     */
    @Test
    fun openRefusalLeavesTheChannelUnevaluated() {
        val unknownEra = File(
            repoRoot(), "spec/vectors/version-compat/output/unknown-newer-version.capsule",
        ).readBytes()
        val result = CapsuleVerifier.verify(unknownEra, predecessors = listOf(fixture("alice.capsule")))
        assertFalse(result.ok)
        assertEquals(LineageReport(), result.lineage)
        assertEquals(emptyList(), result.qualifiers)
        assertEquals(listOf("parse"), result.checks.map { it.name })
    }

    /**
     * An entry may carry `x-<vendor>-<name>` extensions (the manifest-wide
     * unknown-member rule), but any OTHER unrecognized member is
     * malformed: the spec does not lend a verified-adjacent slot to
     * unverifiable reputation text.
     */
    @Test
    fun entryExtensionsMustUseTheVendorPrefix() {
        assertEquals(emptyList(), Lineage.predecessorsProblems(declaration("x-acme-note" to "hi")))
        val problems = Lineage.predecessorsProblems(declaration("label" to "official continuation"))
        assertEquals(1, problems.size, "got $problems")
        assertTrue(
            problems.single().contains("predecessors[0].label is not a spec-defined entry member"),
            "got $problems",
        )
    }

    /**
     * The unknown-era release valve: versioning.md forbids applying one
     * era's identity formula to another era's claim, so the recompute is
     * SKIPPED and reported — never failed. The rule must not punish a
     * capsule for the verifier's age, even when the declared id could not
     * possibly derive under any era this verifier knows.
     */
    @Test
    fun identityCoherenceSkipsUnknownEras() {
        val bogusId = "a".repeat(64)
        val known = declaration("capsule_id" to bogusId)
        assertTrue(
            Lineage.predecessorsProblems(known).any { it.contains("does not derive") },
            "a known era must fail closed on an incoherent id",
        )
        val unknown = declaration("capsule_id" to bogusId, "format_version" to "0.9")
        assertEquals(emptyList(), Lineage.predecessorsProblems(unknown))
        assertFalse(Lineage.identityCheckable(unknown.items.single()))
    }

    // -----------------------------------------------------------------

    /**
     * A well-formed, identity-coherent single-entry declaration with
     * [overrides] applied — the grammar rules exercised without sealing
     * a fixture.
     */
    private fun declaration(vararg overrides: Pair<String, String>): JCSValue.Arr {
        val originatorKey = "b".repeat(64)
        val firstEventHash = "c".repeat(64)
        val members = linkedMapOf(
            "capsule_id" to Manifest.computeCapsuleId(
                CapsuleCrypto.hexToBytes(originatorKey), firstEventHash, "0.7",
            ),
            "format_version" to "0.7",
            "originator_public_key" to originatorKey,
            "first_event_hash" to firstEventHash,
            "entry_hash" to "d".repeat(64),
            "manifest_hash" to "e".repeat(64),
        )
        for ((k, v) in overrides) members[k] = v
        return JCSValue.Arr(listOf(JCSValue.Obj(members.map { it.key to JCSValue.Str(it.value) })))
    }

    private fun fixture(name: String): ByteArray =
        File(repoRoot(), "spec/vectors/lineage/output/$name").readBytes()

    private fun repoRoot(): File {
        var p: File? = File(System.getProperty("user.dir")).absoluteFile
        while (p != null) {
            if (File(p, "spec/vectors/lineage/vectors.json").exists()) return p
            p = p.parentFile
        }
        error("could not locate the repo root from ${System.getProperty("user.dir")}")
    }
}

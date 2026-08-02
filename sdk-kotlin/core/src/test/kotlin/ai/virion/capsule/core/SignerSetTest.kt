// Signer-set binding (manifest.signer_commitment), duplicate-signer
// rejection, distinct trusted-key counting, and originator binding.
//
// Mirrors sdk-swift/Tests/CapsuleTests/SignerSetTests.swift at the unit
// level; the cross-lane fixture outcomes live in SpecRegistryTest
// (signer-set collection). Rule: PRESENCE BINDS, ABSENCE REPORTS.

package ai.virion.capsule.core

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class SignerSetTest {

    private fun sealed(kp: CapsuleCrypto.Ed25519KeyPair): CapsuleBuilder.BuildResult {
        val builder = CapsuleBuilder(
            originator = CapsuleBuilder.Originator(keyPair = kp, label = "Acme"),
            createdAt = "2026-05-07T12:00:00Z",
        )
        builder.setProgram("# Loan file\n")
            .setParticipants(
                listOf(
                    CapsuleBuilder.Participant(
                        actorId = "human:alice", role = "originator", label = "Alice",
                    )
                )
            )
            .appendEvent(
                actor = "human:alice", kind = "decision",
                action = "submit", target = "program.md",
                payload = JCSValue.Obj(listOf("summary" to JCSValue.Str("submitted"))),
            )
        return builder.seal(signedAt = "2026-05-07T12:00:00Z")
    }

    @Test
    fun sealEmitsSignerCommitment() {
        val kp = CapsuleCrypto.generateEd25519()
        val result = sealed(kp)
        val parsed = CapsuleReader.parse(result.bytes)
        val commitment = assertNotNull(
            (parsed.manifest as JCSValue.Obj).pairs
                .firstOrNull { it.first == "signer_commitment" }?.second as? JCSValue.Arr,
            "manifest.signer_commitment must be present",
        )
        assertEquals(1, commitment.items.size)
        val member = (commitment.items[0] as JCSValue.Obj).pairs
        assertEquals(
            JCSValue.Str("originator"),
            member.firstOrNull { it.first == "role" }?.second,
        )
        assertEquals(
            JCSValue.Str(kp.publicKeyHex),
            member.firstOrNull { it.first == "public_key" }?.second,
        )
    }

    @Test
    fun boundCapsuleVerifiesAndReportsBound() {
        val kp = CapsuleCrypto.generateEd25519()
        val result = sealed(kp)
        val v = CapsuleVerifier.verify(result.bytes, allowlist = setOf(kp.publicKeyHex))
        assertTrue(v.ok, "failing checks: ${v.checks.filter { !it.ok }}")
        assertTrue(v.signerSetBound)
        assertEquals(true, v.checks.firstOrNull { it.name == "signer_commitment" }?.ok)
        assertEquals(true, v.checks.firstOrNull { it.name == "originator_binding" }?.ok)
        assertEquals(1, v.trustedSignerCount)
    }

    /** Post-seal append of a fresh, VALID attacker signature in a chosen
     *  role — the measured T1 attack. Only the commitment equality
     *  catches it. */
    @Test
    fun appendedSignerInChosenRoleFailsClosed() {
        val kp = CapsuleCrypto.generateEd25519()
        val attacker = CapsuleCrypto.generateEd25519()
        val result = sealed(kp)
        val tampered = rewriteEnvelope(result.bytes) { envelope ->
            val obj = envelope as JCSValue.Obj
            val sigIdx = obj.pairs.indexOfFirst { it.first == "signers" }
            val signers = (obj.pairs[sigIdx].second as JCSValue.Arr).items.toMutableList()
            val input = Envelope.signingInput(envelope, "notary")
            val sig = attacker.sign(input)
            signers += JCSValue.Obj(listOf(
                "role" to JCSValue.Str("notary"),
                "public_key" to JCSValue.Str(attacker.publicKeyHex),
                "signature" to JCSValue.Str(CapsuleCrypto.bytesToHex(sig)),
            ))
            val mutated = obj.pairs.toMutableList()
            mutated[sigIdx] = "signers" to JCSValue.Arr(signers)
            JCSValue.Obj(mutated)
        }
        val v = CapsuleVerifier.verify(tampered, allowlist = setOf(kp.publicKeyHex))
        assertFalse(v.ok)
        val check = v.checks.firstOrNull { it.name == "signer_commitment" }
        assertEquals(false, check?.ok, "checks: ${v.checks}")
        assertTrue(check!!.detail.contains("signer_commitment mismatch"), check.detail)
    }

    @Test
    fun duplicateSignerEntryIsMalformed() {
        val kp = CapsuleCrypto.generateEd25519()
        val result = sealed(kp)
        val tampered = rewriteEnvelope(result.bytes) { envelope ->
            val obj = envelope as JCSValue.Obj
            val sigIdx = obj.pairs.indexOfFirst { it.first == "signers" }
            val signers = (obj.pairs[sigIdx].second as JCSValue.Arr).items
            val mutated = obj.pairs.toMutableList()
            mutated[sigIdx] = "signers" to JCSValue.Arr(signers + signers.first())
            JCSValue.Obj(mutated)
        }
        val v = CapsuleVerifier.verify(tampered, allowlist = setOf(kp.publicKeyHex))
        assertFalse(v.ok)
        val envCheck = v.checks.firstOrNull { it.name == "envelope_signature" }
        assertEquals(false, envCheck?.ok)
        assertTrue(envCheck!!.detail.contains("duplicate signer"), envCheck.detail)
        assertEquals(0, v.trustedSignerCount, "duplicates must never inflate the count")
    }

    /** Pin the unbound REPORT shape on a commitment-less fixture. */
    @Test
    fun absentCommitmentReportsUnbound() {
        val bytes = File(
            signerSetFixtures(), "commitment-absent.capsule"
        ).readBytes()
        val v = CapsuleVerifier.verify(bytes)
        assertTrue(v.ok, "failing checks: ${v.checks.filter { !it.ok }}")
        assertFalse(v.signerSetBound)
        val check = v.checks.firstOrNull { it.name == "signer_commitment" }
        assertEquals(true, check?.ok)
        assertTrue(check!!.detail.contains("absent"), check.detail)
        assertTrue(v.notes.joinToString(" ").contains("signer_commitment absent"))
    }

    private fun rewriteEnvelope(
        capsuleBytes: ByteArray,
        mutate: (JCSValue) -> JCSValue,
    ): ByteArray {
        val files = CapsuleZip.unpack(capsuleBytes).toMutableList()
        val idx = files.indexOfFirst { it.first == "provenance/envelope.json" }
        val envelope = CapsuleReader.parseJson(files[idx].second)
        files[idx] = "provenance/envelope.json" to JCS.bytes(mutate(envelope))
        return CapsuleZip.pack(files)
    }

    private fun signerSetFixtures(): File {
        var p: File? = File(System.getProperty("user.dir")).absoluteFile
        while (p != null) {
            val f = File(p, "spec/vectors/signer-set/output")
            if (f.isDirectory) return f
            p = p.parentFile
        }
        error("could not locate spec/vectors/signer-set/output from ${System.getProperty("user.dir")}")
    }
}

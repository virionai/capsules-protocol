// End-to-end round-trip tests for the Kotlin SDK.
//
// These exercise the real Builder → Verifier → Reader path with a real
// Ed25519 key, mirroring sdk-swift/Tests/CapsuleTests/RoundTripTests.swift.
// The most basic claim — "Kotlin can build a capsule that Kotlin can
// verify" — is what this file pins down.

package ai.virion.capsule.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RoundTripTest {

    @Test
    fun roundTripBuildVerifyParse() {
        val kp = CapsuleCrypto.generateEd25519()

        val builder = CapsuleBuilder(
            originator = CapsuleBuilder.Originator(keyPair = kp, label = "Test originator")
        )
        builder.setProgram("# Hello\n\nA test capsule.\n")
            .setAgents("# Agents\n\n- human:test\n")
            .setParticipants(
                listOf(
                    CapsuleBuilder.Participant(
                        actorId = "human:test",
                        role = "originator",
                        label = "Test",
                    )
                )
            )
            .appendEvent(
                actor = "human:test",
                kind = "observation",
                action = "noted",
                target = "program.md",
                payload = jobj("note" to jstr("first event")),
                untrustedPayloadFields = listOf("payload.note"),
            )
            .appendEvent(
                actor = "human:test",
                kind = "decision",
                action = "approved",
                target = "program.md",
                payload = jobj("decision" to jstr("go")),
            )
            .addSkill(
                id = "demo",
                json = "{\"id\":\"demo\",\"actions\":[]}".toByteArray(Charsets.UTF_8),
                markdown = "# Demo\n\nSkill markdown.\n",
                signed = false,
            )
            .addPayload(
                CapsuleBuilder.PayloadFile(
                    path = "payload/notes.txt",
                    bytes = "hello\n".toByteArray(Charsets.UTF_8),
                )
            )

        val result = builder.seal()
        assertTrue(result.bytes.isNotEmpty(), "sealed capsule should have bytes")
        assertEquals(64, result.capsuleId.length, "capsule_id must be 64-hex")

        val v = CapsuleVerifier.verify(
            bytes = result.bytes,
            allowlist = setOf(kp.publicKeyHex),
        )
        assertTrue(
            v.ok,
            "verification failed: ${v.checks.filter { !it.ok }.joinToString { "${it.name}: ${it.detail}" }}",
        )
        assertEquals(1, v.trustedSignerCount)
        assertEquals(1, v.signers.size)
        assertEquals("originator", v.signers.first().role)

        val parsed = CapsuleReader.parse(result.bytes)
        assertTrue(
            parsed.files.containsKey("skills/demo/skill.json"),
            "expected skills/demo/skill.json in parsed files, got: ${parsed.files.keys}",
        )
        assertTrue(
            parsed.files.containsKey("skills/demo/SKILL.md"),
            "expected skills/demo/SKILL.md in parsed files, got: ${parsed.files.keys}",
        )
        assertTrue(
            parsed.programMd.startsWith("# Hello"),
            "program.md should start with '# Hello', got: ${parsed.programMd.take(40)}",
        )
    }

    @Test
    fun tamperedCapsuleFailsVerification() {
        val kp = CapsuleCrypto.generateEd25519()

        val result = CapsuleBuilder(
            originator = CapsuleBuilder.Originator(keyPair = kp, label = "Tamper test"),
        )
            .setProgram("# Hi\n")
            .appendEvent(
                actor = "human:test",
                kind = "observation",
                action = "noted",
                target = "program.md",
                payload = jobj("note" to jstr("x")),
            )
            .seal()

        // Copy so we don't mutate BuildResult.bytes in-place.
        val tampered = result.bytes.copyOf()
        val idx = tampered.size / 2
        tampered[idx] = (tampered[idx].toInt() xor 0x01).toByte()

        // A byte flip can either yield ok=false (when verifier still parses
        // successfully) or surface as an exception (when the flip lands
        // inside a hex field the verifier eagerly decodes). Either is a
        // valid "verification failed" signal — what we MUST NOT see is
        // a tampered capsule reporting ok=true.
        val verifiedOk = try {
            CapsuleVerifier.verify(
                bytes = tampered,
                allowlist = setOf(kp.publicKeyHex),
            ).ok
        } catch (_: Throwable) {
            false
        }
        assertFalse(verifiedOk, "tampered capsule unexpectedly verified ok")
    }
}

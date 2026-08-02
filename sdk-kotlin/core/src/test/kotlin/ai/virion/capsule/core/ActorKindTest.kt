// spec/chain.md step-6 actor rule + the closed `kind` enum.
//
// Mirrors sdk-js/test/actor-kind.test.js, sdk-py/tests/test_actor_kind.py,
// and sdk-swift/Tests/CapsuleTests/ActorKindTests.swift:
//
//   - The actor rule is CONDITIONAL on the manifest's claim: when
//     `participants[]` is non-empty, every event actor must be a declared
//     participant or the literal "system:host" (fail-closed). When
//     participants is empty, the capsule has made no claim about who is
//     involved — verification succeeds and the verifier REPORTS the
//     unbound actor set (actorSetBound=false plus a note), mirroring the
//     signer_commitment "presence binds, absence reports" shape.
//   - `kind` is a closed enum in every tier: both the verifier and the
//     builder reject out-of-enum kinds unconditionally.
//   - The per-event messages are the same strings the Rust verifier puts
//     in ChainCheck.errors.

package ai.virion.capsule.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ActorKindTest {

    private val participants = setOf("human:alice")

    private fun events(
        actor: String = "human:alice",
        kind: String = "decision",
    ): List<JCSValue> =
        Chain.build(
            listOf(
                BareEvent(
                    actor = actor, kind = kind, action = "a", target = "t",
                    timestamp = TS, payload = JCSValue.Obj(emptyList()),
                )
            )
        ).map { e -> CapsuleReader.parseJson(e.jsonLine) }

    // --- verifyChain: the per-event walk -----------------------------------

    @Test
    fun verifyChainFlagsActorNotInParticipants() {
        val errors = CapsuleVerifier.verifyChain(events(actor = "human:mallory"), participants)
        assertEquals(
            listOf(
                "seq 1: actor \"human:mallory\" not in manifest.participants and not system:host"
            ),
            errors,
        )
    }

    @Test
    fun verifyChainAcceptsAnyActorWithoutDeclaredParticipants() {
        // Empty participants = the manifest makes no claim about who acted.
        assertEquals(
            emptyList<String>(),
            CapsuleVerifier.verifyChain(events(actor = "human:anyone"), emptySet()),
        )
    }

    @Test
    fun verifyChainAcceptsSystemHostEitherWay() {
        val evts = events(actor = "system:host", kind = "observation")
        assertEquals(emptyList<String>(), CapsuleVerifier.verifyChain(evts, emptySet()))
        assertEquals(emptyList<String>(), CapsuleVerifier.verifyChain(evts, participants))
    }

    @Test
    fun verifyChainRejectsUnknownKind() {
        val errors = CapsuleVerifier.verifyChain(events(kind = "gossip"), participants)
        assertEquals(
            listOf(
                "seq 1: kind \"gossip\" is not one of " +
                    "decision, observation, mutation, session, checkpoint"
            ),
            errors,
        )
    }

    @Test
    fun verifyChainRejectsUnknownKindEvenWithEmptyParticipants() {
        val errors = CapsuleVerifier.verifyChain(events(kind = "gossip"), emptySet())
        assertEquals(1, errors.size)
        assertTrue(errors[0].contains("kind \"gossip\" is not one of"))
    }

    @Test
    fun verifyChainAcceptsEveryEnumKind() {
        for (kind in Chain.EVENT_KINDS) {
            assertEquals(
                emptyList<String>(),
                CapsuleVerifier.verifyChain(events(kind = kind), participants),
                "kind $kind must be accepted",
            )
        }
    }

    // --- CapsuleVerifier: wiring manifest participants through -------------

    @Test
    fun verifierEnforcesActorRuleAgainstDeclaredParticipants() {
        val kp = CapsuleCrypto.generateEd25519()
        val builder = CapsuleBuilder(
            originator = CapsuleBuilder.Originator(keyPair = kp, label = "Acme"),
            createdAt = TS,
        )
        builder.setProgram("# Actor rule\n")
            .setParticipants(
                listOf(CapsuleBuilder.Participant("human:alice", "originator", "Alice"))
            )
            .appendEvent(
                actor = "human:alice", kind = "decision",
                action = "submit", target = "program.md",
            )
        // Swap the declared participant AFTER appending: the sealed
        // manifest still declares a NON-EMPTY set — just not the actor
        // the chain names. Only the actor rule can catch this.
        builder.setParticipants(
            listOf(CapsuleBuilder.Participant("human:bob", "originator", "Bob"))
        )
        val result = builder.seal(signedAt = TS)

        val v = CapsuleVerifier.verify(result.bytes, allowlist = setOf(kp.publicKeyHex))
        assertFalse(v.ok, "capsule with an undeclared actor must not verify")
        assertTrue(v.actorSetBound)
        val chain = v.checks.firstOrNull { it.name == "chain" }
        assertEquals(false, chain?.ok)
        assertTrue(
            (chain?.detail ?: "").contains(
                "seq 1: actor \"human:alice\" not in manifest.participants and not system:host"
            ),
            "expected the step-6 actor error; got: ${chain?.detail}",
        )
    }

    @Test
    fun verifierReportsUnboundActorSetForEmptyParticipants() {
        val kp = CapsuleCrypto.generateEd25519()
        val result = CapsuleBuilder(
            originator = CapsuleBuilder.Originator(keyPair = kp, label = "Acme"),
            createdAt = TS,
        )
            .setProgram("# Actor rule\n")
            .appendEvent(
                actor = "human:alice", kind = "decision",
                action = "submit", target = "program.md",
            )
            .seal(signedAt = TS)

        val v = CapsuleVerifier.verify(result.bytes, allowlist = setOf(kp.publicKeyHex))
        assertTrue(v.ok, "checks failed: ${v.checks.filter { !it.ok }}")
        assertFalse(v.actorSetBound)
        assertTrue(
            v.notes.any { it.contains("chain actors are not bound to a declared participant set") },
            "expected the unbound-actor-set note; got: ${v.notes}",
        )
    }

    @Test
    fun verifierGreenWhenActorIsDeclared() {
        val kp = CapsuleCrypto.generateEd25519()
        val result = CapsuleBuilder(
            originator = CapsuleBuilder.Originator(keyPair = kp, label = "Acme"),
            createdAt = TS,
        )
            .setProgram("# Actor rule\n")
            .setParticipants(
                listOf(CapsuleBuilder.Participant("human:alice", "originator", "Alice"))
            )
            .appendEvent(
                actor = "human:alice", kind = "decision",
                action = "submit", target = "program.md",
            )
            .seal(signedAt = TS)

        val v = CapsuleVerifier.verify(result.bytes, allowlist = setOf(kp.publicKeyHex))
        assertTrue(v.ok, "checks failed: ${v.checks.filter { !it.ok }}")
        assertTrue(v.actorSetBound)
        assertFalse(v.notes.any { it.contains("chain actors are not bound") })
    }

    // --- CapsuleBuilder.appendEvent: writer obligations --------------------

    @Test
    fun appendEventRejectsActorOutsideDeclaredParticipants() {
        val builder = newBuilder().setParticipants(
            listOf(CapsuleBuilder.Participant("human:alice", "originator", "Alice"))
        )
        val e = assertFailsWith<IllegalArgumentException> {
            builder.appendEvent(
                actor = "human:mallory", kind = "observation",
                action = "sneak", target = "capsule",
            )
        }
        assertTrue(
            e.message!!.contains(
                "event actor \"human:mallory\" is not a declared participant"
            ),
            "unexpected message: ${e.message}",
        )
    }

    @Test
    fun appendEventAcceptsAnyActorWithoutDeclaredParticipants() {
        newBuilder().appendEvent(
            actor = "human:anyone", kind = "observation",
            action = "created_note", target = "capsule",
        )
    }

    @Test
    fun appendEventAcceptsSystemHostWithoutParticipantEntry() {
        newBuilder()
            .setParticipants(
                listOf(CapsuleBuilder.Participant("human:alice", "originator", "Alice"))
            )
            .appendEvent(
                actor = "system:host", kind = "observation",
                action = "session_ended", target = "capsule",
            )
    }

    @Test
    fun appendEventRejectsUnknownKind() {
        val builder = newBuilder().setParticipants(
            listOf(CapsuleBuilder.Participant("human:alice", "originator", "Alice"))
        )
        val e = assertFailsWith<IllegalArgumentException> {
            builder.appendEvent(
                actor = "human:alice", kind = "gossip",
                action = "a", target = "t",
            )
        }
        assertTrue(
            e.message!!.contains("event kind \"gossip\" is not one of"),
            "unexpected message: ${e.message}",
        )
    }

    @Test
    fun appendEventRejectsUnknownKindEvenWithEmptyParticipants() {
        assertFailsWith<IllegalArgumentException> {
            newBuilder().appendEvent(
                actor = "human:anyone", kind = "gossip",
                action = "a", target = "t",
            )
        }
    }

    // --- participants[].actor_id namespace grammar (manifest.md, A06) ------
    //
    // The namespace set is CLOSED: human:, ai:, system:, capsule:, each
    // with a non-empty <id>. The builder refuses to declare a participant
    // outside the grammar; the verifier side is pinned by the
    // chain-rules/invalid-actor-namespace registry vector.

    @Test
    fun isValidActorIdAcceptsExactlyTheFourNamespaces() {
        for (good in listOf(
            "human:alice@acme.example", "ai:claude-opus-4-7", "system:host", "capsule:abc",
        )) {
            assertTrue(Chain.isValidActorId(good), good)
        }
        for (bad in listOf(
            "robot:r2d2", "human", "human:", ":alice", "", "Human:alice", " human:alice",
        )) {
            assertFalse(Chain.isValidActorId(bad), bad)
        }
    }

    @Test
    fun setParticipantsRejectsOutOfNamespaceActorId() {
        val e = assertFailsWith<IllegalArgumentException> {
            newBuilder().setParticipants(
                listOf(CapsuleBuilder.Participant("robot:origin", "originator", "R"))
            )
        }
        assertTrue(
            e.message!!.contains("does not match an allowed namespace"),
            "unexpected message: ${e.message}",
        )
    }

    private fun newBuilder() = CapsuleBuilder(
        originator = CapsuleBuilder.Originator(
            keyPair = CapsuleCrypto.generateEd25519(), label = "Acme",
        ),
        createdAt = TS,
    )

    private companion object {
        const val TS = "2026-05-07T12:00:00Z"
    }
}

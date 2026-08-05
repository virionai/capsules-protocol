// spec/chain.md step-6 actor rule + the closed `kind` enum.
//
// Mirrors sdk-js/test/actor-kind.test.js and sdk-py/tests/test_actor_kind.py:
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

import XCTest
@testable import Capsule

final class ActorKindTests: XCTestCase {

    private let participants: Set<String> = ["human:alice"]
    private static let ts = "2026-05-07T12:00:00Z"

    private func events(actor: String = "human:alice",
                        kind: String = "decision") throws -> [JCSValue]
    {
        let built = try Chain.build([
            BareEvent(
                actor: actor, kind: kind, action: "a", target: "t",
                timestamp: Self.ts, payload: .object([])
            )
        ])
        return built.map { e in
            var pairs: [(String, JCSValue)] = []
            if case .object(let p) = e.toJCSWithoutHash() { pairs = p }
            pairs.append(("hash", .string(e.hash)))
            return .object(pairs)
        }
    }

    // MARK: - verifyChain: the per-event walk

    func testVerifyChainFlagsActorNotInParticipants() throws {
        let errors = CapsuleReader.verifyChain(
            try events(actor: "human:mallory"), participants: participants
        )
        XCTAssertEqual(errors, [
            #"seq 1: actor "human:mallory" not in manifest.participants and not system:host"#,
        ])
    }

    func testVerifyChainAcceptsAnyActorWithoutDeclaredParticipants() throws {
        // Empty participants = the manifest makes no claim about who acted.
        let errors = CapsuleReader.verifyChain(
            try events(actor: "human:anyone"), participants: []
        )
        XCTAssertEqual(errors, [])
    }

    func testVerifyChainAcceptsSystemHostEitherWay() throws {
        let evts = try events(actor: "system:host", kind: "observation")
        XCTAssertEqual(CapsuleReader.verifyChain(evts, participants: []), [])
        XCTAssertEqual(CapsuleReader.verifyChain(evts, participants: participants), [])
    }

    func testVerifyChainRejectsUnknownKind() throws {
        let errors = CapsuleReader.verifyChain(
            try events(kind: "gossip"), participants: participants
        )
        XCTAssertEqual(errors, [
            #"seq 1: kind "gossip" is not one of decision, observation, mutation, session, checkpoint"#,
        ])
    }

    func testVerifyChainRejectsUnknownKindEvenWithEmptyParticipants() throws {
        let errors = CapsuleReader.verifyChain(
            try events(kind: "gossip"), participants: []
        )
        XCTAssertEqual(errors.count, 1)
        XCTAssertTrue(errors[0].contains(#"kind "gossip" is not one of"#))
    }

    func testVerifyChainAcceptsEveryEnumKind() throws {
        for kind in Chain.EVENT_KINDS {
            let errors = CapsuleReader.verifyChain(
                try events(kind: kind), participants: participants
            )
            XCTAssertEqual(errors, [], "kind \(kind) must be accepted")
        }
    }

    // MARK: - CapsuleVerifier: wiring manifest.participants through

    func testVerifierEnforcesActorRuleAgainstDeclaredParticipants() throws {
        let kp = Ed25519KeyPair.generate()
        let builder = CapsuleBuilder(originator: .init(keyPair: kp, label: "Acme"),
                                     createdAt: Self.ts)
        try builder
            .setProgram("# Actor rule\n")
            .setParticipants([
                .init(actorId: "human:alice", role: "originator", label: "Alice"),
            ])
            .appendEvent(
                actor: "human:alice", kind: "decision",
                action: "submit", target: "program.md"
            )
        // Swap the declared participant AFTER appending: the sealed
        // manifest still declares a NON-EMPTY set — just not the actor the
        // chain names. Only the actor rule can catch this.
        try builder.setParticipants([
            .init(actorId: "human:bob", role: "originator", label: "Bob"),
        ])
        let result = try builder.seal(signedAt: Self.ts)

        let v = CapsuleVerifier.verify(result.bytes, allowlist: [kp.publicKeyHex])
        XCTAssertFalse(v.ok)
        XCTAssertTrue(v.actorSetBound)
        let chain = v.checks.first(where: { $0.name == "chain" })
        XCTAssertEqual(chain?.ok, false)
        XCTAssertTrue(
            (chain?.detail ?? "").contains(
                #"seq 1: actor "human:alice" not in manifest.participants and not system:host"#
            ),
            "expected the step-6 actor error; got: \(chain?.detail ?? "")"
        )
    }

    func testVerifierReportsUnboundActorSetForEmptyParticipants() throws {
        let kp = Ed25519KeyPair.generate()
        let builder = CapsuleBuilder(originator: .init(keyPair: kp, label: "Acme"),
                                     createdAt: Self.ts)
        try builder
            .setProgram("# Actor rule\n")
            .appendEvent(
                actor: "human:alice", kind: "decision",
                action: "submit", target: "program.md"
            )
        let result = try builder.seal(signedAt: Self.ts)

        let v = CapsuleVerifier.verify(result.bytes, allowlist: [kp.publicKeyHex])
        XCTAssertTrue(v.ok, "checks failed: \(v.checks.filter { !$0.ok })")
        XCTAssertFalse(v.actorSetBound)
        XCTAssertTrue(
            v.notes.contains(where: {
                $0.contains("chain actors are not bound to a declared participant set")
            }),
            "expected the unbound-actor-set note; got: \(v.notes)"
        )
    }

    func testVerifierGreenWhenActorIsDeclared() throws {
        let kp = Ed25519KeyPair.generate()
        let builder = CapsuleBuilder(originator: .init(keyPair: kp, label: "Acme"),
                                     createdAt: Self.ts)
        try builder
            .setProgram("# Actor rule\n")
            .setParticipants([
                .init(actorId: "human:alice", role: "originator", label: "Alice"),
            ])
            .appendEvent(
                actor: "human:alice", kind: "decision",
                action: "submit", target: "program.md"
            )
        let result = try builder.seal(signedAt: Self.ts)
        let v = CapsuleVerifier.verify(result.bytes, allowlist: [kp.publicKeyHex])
        XCTAssertTrue(v.ok, "checks failed: \(v.checks.filter { !$0.ok })")
        XCTAssertTrue(v.actorSetBound)
        XCTAssertFalse(
            v.notes.contains(where: { $0.contains("chain actors are not bound") })
        )
    }

    // MARK: - CapsuleBuilder.appendEvent: writer obligations

    func testAppendEventRejectsActorOutsideDeclaredParticipants() throws {
        let kp = Ed25519KeyPair.generate()
        let builder = CapsuleBuilder(originator: .init(keyPair: kp))
        try builder.setParticipants([
            .init(actorId: "human:alice", role: "originator", label: "Alice"),
        ])
        XCTAssertThrowsError(
            try builder.appendEvent(
                actor: "human:mallory", kind: "observation",
                action: "sneak", target: "capsule"
            )
        ) { error in
            XCTAssertTrue(
                "\(error)".contains(#"event actor "human:mallory" is not a declared participant"#),
                "unexpected error: \(error)"
            )
        }
    }

    func testAppendEventAcceptsAnyActorWithoutDeclaredParticipants() {
        let kp = Ed25519KeyPair.generate()
        let builder = CapsuleBuilder(originator: .init(keyPair: kp))
        XCTAssertNoThrow(
            try builder.appendEvent(
                actor: "human:anyone", kind: "observation",
                action: "created_note", target: "capsule"
            )
        )
    }

    func testAppendEventAcceptsSystemHostWithoutParticipantEntry() throws {
        let kp = Ed25519KeyPair.generate()
        let builder = CapsuleBuilder(originator: .init(keyPair: kp))
        try builder.setParticipants([
            .init(actorId: "human:alice", role: "originator", label: "Alice"),
        ])
        XCTAssertNoThrow(
            try builder.appendEvent(
                actor: "system:host", kind: "observation",
                action: "session_ended", target: "capsule"
            )
        )
    }

    func testAppendEventRejectsUnknownKind() throws {
        let kp = Ed25519KeyPair.generate()
        let builder = CapsuleBuilder(originator: .init(keyPair: kp))
        try builder.setParticipants([
            .init(actorId: "human:alice", role: "originator", label: "Alice"),
        ])
        XCTAssertThrowsError(
            try builder.appendEvent(
                actor: "human:alice", kind: "gossip",
                action: "a", target: "t"
            )
        ) { error in
            XCTAssertTrue(
                "\(error)".contains(#"event kind "gossip" is not one of"#),
                "unexpected error: \(error)"
            )
        }
    }

    func testAppendEventRejectsUnknownKindEvenWithEmptyParticipants() {
        let kp = Ed25519KeyPair.generate()
        let builder = CapsuleBuilder(originator: .init(keyPair: kp))
        XCTAssertThrowsError(
            try builder.appendEvent(
                actor: "human:anyone", kind: "gossip",
                action: "a", target: "t"
            )
        )
    }

    // MARK: - participants[].actor_id namespace grammar (manifest.md, A06)
    //
    // The namespace set is CLOSED: human:, ai:, system:, capsule:, each
    // with a non-empty <id>. The builder refuses to declare a participant
    // outside the grammar; the verifier side is pinned by the
    // chain-rules/invalid-actor-namespace registry vector.

    func testIsValidActorIdAcceptsExactlyTheFourNamespaces() {
        for good in ["human:alice@acme.example", "ai:claude-opus-4-7", "system:host", "capsule:abc"] {
            XCTAssertTrue(Chain.isValidActorId(good), good)
        }
        for bad in ["robot:r2d2", "human", "human:", ":alice", "", "Human:alice", " human:alice"] {
            XCTAssertFalse(Chain.isValidActorId(bad), bad)
        }
    }

    func testSetParticipantsRejectsOutOfNamespaceActorId() {
        let kp = Ed25519KeyPair.generate()
        let builder = CapsuleBuilder(originator: .init(keyPair: kp))
        XCTAssertThrowsError(
            try builder.setParticipants([
                .init(actorId: "robot:origin", role: "originator", label: "R"),
            ])
        ) { error in
            XCTAssertTrue(
                "\(error)".contains("does not match an allowed namespace"),
                "unexpected error: \(error)"
            )
        }
    }
}

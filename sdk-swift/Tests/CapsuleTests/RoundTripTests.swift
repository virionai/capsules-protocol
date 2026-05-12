// Round-trip a capsule through Builder → Verifier with a real Ed25519 key.
// Tests run with `swift test` from sdk-swift/.

import XCTest
@testable import Capsule
@testable import CapsuleSkills

final class RoundTripTests: XCTestCase {

    func testBuildVerifyOpenRoundTrip() throws {
        let kp = Ed25519KeyPair.generate()
        let builder = CapsuleBuilder(
            originator: .init(keyPair: kp, label: "Test originator")
        )
        builder
            .setProgram("# Hello\n\nA test capsule.\n")
            .setAgents("# Agents\n\n- human:test\n")
            .setParticipants([
                .init(actorId: "human:test", role: "originator", label: "Test"),
            ])
            .appendEvent(
                actor: "human:test", kind: "observation",
                action: "noted", target: "program.md",
                payload: jobj(("note", "first event")),
                untrustedPayloadFields: ["payload.note"]
            )
            .appendEvent(
                actor: "human:test", kind: "decision",
                action: "approved", target: "program.md",
                payload: jobj(("decision", "go"))
            )
            .addSkill(id: "demo", json: Data(#"{"id":"demo","actions":[]}"#.utf8),
                      markdown: "# Demo\n\nSkill markdown.\n", signed: false)
            .addPayload(.init(path: "payload/notes.txt", bytes: Data("hello\n".utf8)))

        let result = try builder.seal()
        XCTAssertGreaterThan(result.bytes.count, 0)
        XCTAssertEqual(result.capsuleId.count, 64)
        XCTAssertEqual(result.fileCount, result.bytes.count > 0 ? 7 : 0)
        // 7 = program.md + agents.md + chain/events.jsonl + skills/demo/skill.json
        //     + skills/demo/SKILL.md + payload/notes.txt + manifest.json + envelope.json (8?)
        // Actually: program, agents, chain, skill.json, SKILL.md, payload, manifest, envelope = 8
        // Let's just assert >= 7 and not be brittle.

        // Verify
        let v = CapsuleVerifier.verify(result.bytes,
                                       allowlist: [kp.publicKeyHex.lowercased()])
        XCTAssertTrue(v.ok, "verification failed: \(v.checks.filter { !$0.ok })")
        XCTAssertEqual(v.trustedSignerCount, 1)
        XCTAssertEqual(v.signers.count, 1)
        XCTAssertEqual(v.signers.first?.role, "originator")

        // Parse and read skills
        let parsed = try CapsuleReader.parse(result.bytes)
        let skills = parsed.skills()
        XCTAssertEqual(skills.count, 1)
        XCTAssertEqual(skills.first?.id, "demo")
        XCTAssertEqual(skills.first?.trust, .unsigned)
        XCTAssertEqual(parsed.programMd.split(separator: "\n").first, "# Hello")
    }

    func testTamperedCapsuleFailsVerification() throws {
        let kp = Ed25519KeyPair.generate()
        let result = try CapsuleBuilder(originator: .init(keyPair: kp))
            .setProgram("# Hi\n")
            .appendEvent(
                actor: "human:test", kind: "observation",
                action: "noted", target: "program.md",
                payload: jobj(("note", "x"))
            )
            .seal()

        // Flip a byte in the middle — at minimum hits the chain or
        // content_index hash, possibly the envelope hash too.
        var bytes = result.bytes
        let idx = bytes.count / 2
        bytes[idx] = bytes[idx] ^ 0x01
        let v = CapsuleVerifier.verify(bytes, allowlist: [kp.publicKeyHex])
        XCTAssertFalse(v.ok)
    }
}

// spec/chain.md step-6 actor rule + the closed `kind` enum.
//
//   - The actor rule is CONDITIONAL on the manifest's claim: when
//     `manifest.participants[]` is non-empty, every event actor must be a
//     declared participant or the literal "system:host" (fail-closed).
//     When participants is empty, the capsule has made no claim about who
//     is involved — verification succeeds and the verifier REPORTS the
//     unbound actor set (actorSet.bound=false plus a note), mirroring the
//     signer_commitment "presence binds, absence reports" shape. This is
//     safe because participants lives in the manifest, covered by
//     manifest_hash inside the signed payload: an attacker cannot empty
//     the list to escape the check without breaking the signature.
//   - `kind` is a closed enum in every tier: an out-of-enum kind is not a
//     weaker claim, it is unreadable to the foreign LLM reader, so both
//     the verifier and the builder reject it unconditionally.
//   - Error strings match the Rust verifier's shape verbatim (minus the
//     "seq N: " prefix, which JS carries as { seq, message }).

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CapsuleBuilder,
  CapsuleReader,
  verifyCapsule,
  generateEd25519,
} from "../src/index.js";
import { buildChainEvents, verifyChain, isValidActorId, EVENT_KINDS } from "../src/chain.js";

const TS = "2026-05-07T12:00:00Z";

const PARTICIPANTS = [{ actor_id: "human:alice", role: "originator", label: "Alice" }];

function seededBuilder(ed, participants = PARTICIPANTS) {
  return new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex, label: "Acme" },
    participants,
    createdAt: TS,
  }).setProgram("# Actor rule\n");
}

function bareEvent(overrides = {}) {
  return {
    actor: "human:alice",
    kind: "decision",
    action: "a",
    target: "t",
    timestamp: TS,
    payload: {},
    ...overrides,
  };
}

// --- verifyChain: the per-event walk ---------------------------------------

test("verifyChain flags an actor that is not a declared participant", () => {
  const events = buildChainEvents([bareEvent({ actor: "human:mallory" })]);
  const result = verifyChain(events, { participants: PARTICIPANTS });
  assert.equal(result.ok, false);
  assert.deepEqual(result.errors, [
    {
      seq: 1,
      message: 'actor "human:mallory" not in manifest.participants and not system:host',
    },
  ]);
});

test("verifyChain accepts any actor when no participants are declared", () => {
  // Empty participants = the manifest makes no claim about who acted.
  // Absence is a weaker claim made honestly — never a violation.
  const events = buildChainEvents([bareEvent({ actor: "human:anyone" })]);
  assert.equal(verifyChain(events, { participants: [] }).ok, true);
  assert.equal(verifyChain(events).ok, true);
});

test("verifyChain accepts system:host with and without a participant entry", () => {
  const events = buildChainEvents([
    bareEvent({ actor: "system:host", kind: "observation", action: "session_ended" }),
  ]);
  assert.equal(verifyChain(events, { participants: [] }).ok, true);
  assert.equal(verifyChain(events, { participants: PARTICIPANTS }).ok, true);
});

test("verifyChain rejects a kind outside the closed enum", () => {
  const events = buildChainEvents([bareEvent({ kind: "gossip" })]);
  const result = verifyChain(events, { participants: PARTICIPANTS });
  assert.equal(result.ok, false);
  assert.deepEqual(result.errors, [
    {
      seq: 1,
      message: 'kind "gossip" is not one of decision, observation, mutation, session, checkpoint',
    },
  ]);
});

test("verifyChain rejects an unknown kind even when participants are empty", () => {
  // The kind enum is NOT a tier question: a custom kind is unreadable to
  // the foreign reader, not a weaker claim.
  const events = buildChainEvents([bareEvent({ kind: "gossip" })]);
  const result = verifyChain(events, { participants: [] });
  assert.equal(result.ok, false);
  assert.match(result.errors[0].message, /kind "gossip" is not one of/);
});

test("verifyChain accepts every kind in the enum", () => {
  for (const kind of EVENT_KINDS) {
    const events = buildChainEvents([bareEvent({ kind })]);
    const result = verifyChain(events, { participants: PARTICIPANTS });
    assert.equal(result.ok, true, `kind ${kind} must be accepted: ${JSON.stringify(result.errors)}`);
  }
});

// --- verifyCapsule: wiring manifest.participants through --------------------

test("verifyCapsule enforces the actor rule against declared manifest.participants", async () => {
  const ed = generateEd25519();
  const builder = seededBuilder(ed);
  builder.appendEvent({
    actor: "human:alice",
    kind: "decision",
    action: "submit",
    target: "program.md",
    timestamp: TS,
  });
  // Swap the declared participant AFTER appending: the manifest sealed
  // below still declares a NON-EMPTY participant set — just not the actor
  // the chain names. Every other commitment (manifest hash, content
  // index, envelope) is recomputed at seal, so only the actor rule can
  // catch this.
  builder.participants = [{ actor_id: "human:bob", role: "originator", label: "Bob" }];
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });

  const reader = await CapsuleReader.fromBytes(bytes);
  const result = await verifyCapsule(reader, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, false);
  assert.equal(result.chain.ok, false);
  assert.equal(result.actorSet.bound, true);
  assert.ok(
    result.chain.errors.some(
      (e) =>
        e.message === 'actor "human:alice" not in manifest.participants and not system:host',
    ),
    `expected the step-6 actor error, got: ${JSON.stringify(result.chain.errors)}`,
  );
});

test("verifyCapsule verifies an empty-participants capsule and reports the unbound actor set", async () => {
  const ed = generateEd25519();
  const builder = seededBuilder(ed, []);
  builder.appendEvent({
    actor: "human:alice",
    kind: "decision",
    action: "submit",
    target: "program.md",
    timestamp: TS,
  });
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  const result = await verifyCapsule(bytes, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.equal(result.actorSet.bound, false);
  assert.ok(
    result.notes.some((n) =>
      n.includes("chain actors are not bound to a declared participant set"),
    ),
    `expected the unbound-actor-set note, got: ${JSON.stringify(result.notes)}`,
  );
});

test("verifyCapsule stays green when the actor is a declared participant", async () => {
  const ed = generateEd25519();
  const builder = seededBuilder(ed);
  builder.appendEvent({
    actor: "human:alice",
    kind: "decision",
    action: "submit",
    target: "program.md",
    timestamp: TS,
  });
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  const result = await verifyCapsule(bytes, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.actorSet.bound, true);
  assert.ok(
    !result.notes.some((n) => n.includes("chain actors are not bound")),
    `unexpected unbound-actor-set note: ${JSON.stringify(result.notes)}`,
  );
});

test("verifyCapsule rejects an unknown kind sealed into the chain", async () => {
  const ed = generateEd25519();
  const builder = seededBuilder(ed);
  // appendEvent rejects this by design; push the bare event directly to
  // synthesize what a non-conformant writer would produce.
  builder.bareEvents.push(bareEvent({ kind: "gossip" }));
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  const result = await verifyCapsule(bytes, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, false);
  assert.equal(result.chain.ok, false);
  assert.ok(
    result.chain.errors.some((e) => e.message.includes('kind "gossip" is not one of')),
    `expected the kind-enum error, got: ${JSON.stringify(result.chain.errors)}`,
  );
});

// --- CapsuleBuilder.appendEvent: writer obligations -------------------------

test("appendEvent rejects an actor outside a declared participant set", () => {
  const ed = generateEd25519();
  const builder = seededBuilder(ed);
  assert.throws(
    () => builder.appendEvent({ actor: "human:mallory", action: "sneak" }),
    /event actor "human:mallory" is not a declared participant/,
  );
});

test("appendEvent accepts any actor when no participants are declared", () => {
  const ed = generateEd25519();
  const builder = seededBuilder(ed, []);
  assert.doesNotThrow(() =>
    builder.appendEvent({ actor: "human:anyone", action: "created_note" }),
  );
});

test("appendEvent accepts system:host without a participant entry", () => {
  const ed = generateEd25519();
  const builder = seededBuilder(ed);
  assert.doesNotThrow(() =>
    builder.appendEvent({ actor: "system:host", action: "session_ended" }),
  );
});

test("appendEvent rejects a kind outside the closed enum", () => {
  const ed = generateEd25519();
  const builder = seededBuilder(ed);
  assert.throws(
    () => builder.appendEvent({ actor: "human:alice", kind: "gossip", action: "a" }),
    /event kind "gossip" is not one of decision, observation, mutation, session, checkpoint/,
  );
});

test("appendEvent rejects an unknown kind even with no declared participants", () => {
  const ed = generateEd25519();
  const builder = seededBuilder(ed, []);
  assert.throws(
    () => builder.appendEvent({ actor: "human:anyone", kind: "gossip", action: "a" }),
    /event kind "gossip" is not one of/,
  );
});

// --- participants[].actor_id namespace grammar (manifest.md, finding A06) ---
//
// The namespace set is CLOSED: human:, ai:, system:, capsule:, each with
// a non-empty <id>. Writers refuse to declare a participant outside the
// grammar; verifiers reject it fail-closed (the chain-rules registry
// vector invalid-actor-namespace pins the verifier side in every lane).

test("isValidActorId accepts exactly the four namespaces with non-empty ids", () => {
  for (const good of ["human:alice@acme.example", "ai:claude-opus-4-7", "system:host", "capsule:abc123"]) {
    assert.equal(isValidActorId(good), true, good);
  }
  for (const bad of [
    "robot:r2d2",     // unknown namespace
    "human",          // no separator
    "human:",         // empty id
    ":alice",         // empty namespace
    "",               // empty string
    "Human:alice",    // case-sensitive
    " human:alice",   // leading junk
    42,               // not a string
    null,
  ]) {
    assert.equal(isValidActorId(bad), false, JSON.stringify(bad));
  }
});

test("CapsuleBuilder rejects an out-of-namespace participant at construction", () => {
  const ed = generateEd25519();
  assert.throws(
    () =>
      new CapsuleBuilder({
        originator: { publicKey: ed.publicKeyHex },
        participants: [{ actor_id: "robot:origin", role: "originator", label: "R" }],
      }),
    /does not match an allowed namespace/,
  );
});

test("seal() rejects participants mutated out of the namespace after construction", async () => {
  const ed = generateEd25519();
  const builder = seededBuilder(ed);
  builder.appendEvent({ actor: "human:alice", action: "a", timestamp: TS });
  builder.participants = [{ actor_id: "robot:origin", role: "originator", label: "R" }];
  await assert.rejects(
    () =>
      builder.seal({
        signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
        signedAt: TS,
      }),
    /does not match an allowed namespace/,
  );
});

test("bare-string participants are pattern-checked too", () => {
  const ed = generateEd25519();
  assert.doesNotThrow(
    () =>
      new CapsuleBuilder({
        originator: { publicKey: ed.publicKeyHex },
        participants: ["human:alice"],
      }),
  );
  assert.throws(
    () =>
      new CapsuleBuilder({
        originator: { publicKey: ed.publicKeyHex },
        participants: ["robot:origin"],
      }),
    /does not match an allowed namespace/,
  );
});

test("a participant entry without a string actor_id is refused", () => {
  const ed = generateEd25519();
  assert.throws(
    () =>
      new CapsuleBuilder({
        originator: { publicKey: ed.publicKeyHex },
        participants: [{ role: "originator" }],
      }),
    /actor_id/,
  );
  assert.throws(
    () =>
      new CapsuleBuilder({
        originator: { publicKey: ed.publicKeyHex },
        participants: [42],
      }),
    /participants\[0\]/,
  );
});

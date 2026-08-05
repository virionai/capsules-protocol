// Rewrap writer obligations (spec/lineage.md "Continuing a capsule",
// W1–W9): entry derivation, carry/reset policy, the pinned custody
// event, refusals and the loud override, reproducibility, re-rewrap,
// laundering equivalence, encrypted successors, and the explicit-values
// declaration path. Test ids T1–T10 follow the design's test plan.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CapsuleBuilder,
  CapsuleReader,
  PredecessorError,
  verifyCapsule,
  rewrapCapsule,
  derivePredecessorEntry,
  generateEd25519,
  generateX25519,
  computeCapsuleId,
  manifestHash,
  sha256Hex,
  packZip,
  unpackZip,
  hexToBytes,
} from "../src/index.js";

const TS = "2026-05-07T12:00:00Z";
const LATER = "2026-05-07T13:00:00Z";

function aliceBuilder(alice) {
  const builder = new CapsuleBuilder({
    originator: { publicKey: alice.publicKeyHex, label: "Alice" },
    participants: [
      { actor_id: "human:alice", role: "originator" },
      { actor_id: "ai:assistant", role: "advisor" },
    ],
    createdAt: TS,
  });
  builder.setProgram("# Loan Review\n\nStep one complete.\n");
  builder.setAgents("# Agents\n- human:alice\n");
  builder.addPayload("payload/evidence.csv", Buffer.from("k,v\nrate,0.07\n", "utf8"));
  builder.addSkill("review", { json: { name: "review" }, markdown: "# Review skill\n" });
  builder.appendEvent({
    actor: "human:alice", kind: "decision", action: "approved", target: "program.md",
    timestamp: TS, payload: { note: "approved step one" },
  });
  builder.appendEvent({
    actor: "ai:assistant", kind: "observation", action: "summarized", target: "program.md",
    timestamp: TS, payload: { note: "summary recorded" },
  });
  return builder;
}

async function sealedAlice(alice) {
  return Buffer.from(await aliceBuilder(alice).seal({
    signers: [{ role: "originator", publicKey: alice.publicKey, privateKey: alice.privateKey }],
    signedAt: TS,
  }));
}

async function tamperedCopy(bytes) {
  const files = await unpackZip(bytes);
  const program = Buffer.from(files.get("program.md"));
  program[0] ^= 0x01;
  files.set("program.md", program);
  return Buffer.from(await packZip(files));
}

test("T1: entry derivation — six members recomputed, manifest_hash never the envelope claim", async () => {
  const alice = generateEd25519();
  const bytes = await sealedAlice(alice);
  const reader = await CapsuleReader.fromBytes(bytes);
  const entry = derivePredecessorEntry(reader);
  const manifest = reader.manifest();
  const envelope = reader.envelope();
  assert.deepEqual(entry, {
    capsule_id: computeCapsuleId(hexToBytes(manifest.originator.public_key), manifest.first_event_hash, "0.7"),
    format_version: "0.7",
    originator_public_key: alice.publicKeyHex,
    first_event_hash: manifest.first_event_hash,
    entry_hash: envelope.entry_hash,
    manifest_hash: manifestHash(manifest),
  });
  // W1: recomputed from the stored manifest, never copied from the
  // envelope's claim — poison the claim and the derivation is unmoved.
  const files = await unpackZip(bytes);
  const env = JSON.parse(Buffer.from(files.get("provenance/envelope.json")).toString("utf8"));
  env.manifest_hash = "f".repeat(64);
  files.set("provenance/envelope.json", Buffer.from(JSON.stringify(env, null, 2), "utf8"));
  const poisonedReader = new CapsuleReader(files);
  const poisonedEntry = derivePredecessorEntry(poisonedReader);
  assert.equal(poisonedEntry.manifest_hash, entry.manifest_hash);
  assert.notEqual(poisonedEntry.manifest_hash, env.manifest_hash);
  // The same derivation continueFrom performs.
  const bob = generateEd25519();
  const { predecessorEntry } = await rewrapCapsule(bytes, {
    originator: { ...bob, label: "Bob" }, createdAt: LATER, signedAt: LATER,
  });
  assert.deepEqual(predecessorEntry, entry);
});

test("T2: carry/reset — files byte-identical, claims reset, carry predicate filters", async () => {
  const alice = generateEd25519();
  const bob = generateEd25519();
  const predBytes = await sealedAlice(alice);
  // A legacy content-indexed file survives the carry (predecessor
  // re-sealed low-level to include it).
  const predFiles = await unpackZip(predBytes);
  const { bytes, carriedPaths } = await rewrapCapsule(predBytes, {
    originator: { ...bob, label: "Bob" },
    participants: [{ actor_id: "human:bob", role: "custodian" }],
    createdAt: LATER, signedAt: LATER,
  });
  const successor = await CapsuleReader.fromBytes(bytes);
  const succFiles = successor.files_();
  assert.deepEqual(carriedPaths, [
    "agents.md",
    "payload/evidence.csv",
    "program.md",
    "skills/review/SKILL.md",
    "skills/review/skill.json",
  ]);
  for (const path of carriedPaths) {
    assert.equal(
      sha256Hex(succFiles.get(path)),
      sha256Hex(predFiles.get(path)),
      `${path} must carry byte-identically`,
    );
  }
  // Claims reset: fresh chain; the successor manifest carries the
  // CALLER's participants, its own signer_commitment, and no echo of
  // the predecessor's claims.
  const manifest = successor.manifest();
  assert.deepEqual(manifest.participants, [{ actor_id: "human:bob", role: "custodian" }]);
  assert.equal(manifest.created_at, LATER);
  assert.equal(manifest.originator.public_key, bob.publicKeyHex);
  assert.equal(successor.events().length, 1); // custody event only — history stays behind
  // carry predicate filters.
  const filtered = await rewrapCapsule(predBytes, {
    originator: { ...bob, label: "Bob" },
    createdAt: LATER, signedAt: LATER,
    carry: (path) => !path.startsWith("skills/"),
  });
  assert.deepEqual(filtered.carriedPaths, ["agents.md", "payload/evidence.csv", "program.md"]);
});

test("T3: custody event — template-exact, opt-out, custodyActor validated by the actor rule", async () => {
  const alice = generateEd25519();
  const bob = generateEd25519();
  const predBytes = await sealedAlice(alice);
  const predId = derivePredecessorEntry(await CapsuleReader.fromBytes(predBytes)).capsule_id;
  const { bytes } = await rewrapCapsule(predBytes, {
    originator: { ...bob, label: "Bob" }, createdAt: LATER, signedAt: LATER,
  });
  const events = (await CapsuleReader.fromBytes(bytes)).events();
  assert.equal(events.length, 1);
  const { seq, event_id, prev_hash, hash, ...bare } = events[0];
  assert.deepEqual(bare, {
    actor: "system:host",
    kind: "observation",
    action: "custody_received",
    target: `capsule:${predId}`,
    timestamp: LATER,
    payload: {
      note: `custody received from capsule ${predId}; lineage is declared in manifest.predecessors`,
    },
    untrusted_payload_fields: [],
  });
  // Opt-out: no custody event; seal's backstop covers the empty chain.
  const optOut = await rewrapCapsule(predBytes, {
    originator: { ...bob, label: "Bob" }, createdAt: LATER, signedAt: LATER,
    custodyEvent: false,
  });
  assert.equal(optOut.custodyEventEmitted, false);
  const optOutEvents = (await CapsuleReader.fromBytes(optOut.bytes)).events();
  assert.equal(optOutEvents[0].action, "session_ended");
  // custodyActor: a declared participant passes; an undeclared one
  // fails at the call site (the appendEvent actor rule, never a reader).
  const declared = await rewrapCapsule(predBytes, {
    originator: { ...bob, label: "Bob" }, createdAt: LATER, signedAt: LATER,
    participants: [{ actor_id: "human:bob", role: "custodian" }],
    custodyActor: "human:bob",
  });
  assert.equal((await CapsuleReader.fromBytes(declared.bytes)).events()[0].actor, "human:bob");
  await assert.rejects(
    rewrapCapsule(predBytes, {
      originator: { ...bob, label: "Bob" }, createdAt: LATER, signedAt: LATER,
      participants: [{ actor_id: "human:bob", role: "custodian" }],
      custodyActor: "human:mallory",
    }),
    /not a declared participant/,
  );
});

test("T4: refusals — tampered, unknown era, encrypted; decrypt-then-rewrap succeeds", async () => {
  const alice = generateEd25519();
  const bob = generateEd25519();
  const recipient = generateX25519();
  const predBytes = await sealedAlice(alice);
  // Tampered predecessor: PredecessorError verification_failed with the
  // full verify result attached.
  const tampered = await tamperedCopy(predBytes);
  await assert.rejects(
    rewrapCapsule(tampered, { originator: { ...bob, label: "Bob" } }),
    (err) => {
      assert.ok(err instanceof PredecessorError);
      assert.equal(err.reason, "verification_failed");
      assert.equal(err.verification.ok, false);
      assert.match(err.message, /allowInvalidPredecessor/);
      return true;
    },
  );
  // Unknown era: unsupported_version, versioning.md vocabulary, no
  // override honored.
  const files = await unpackZip(predBytes);
  const manifest = JSON.parse(Buffer.from(files.get("manifest.json")).toString("utf8"));
  manifest.format.version = "9.9";
  files.set("manifest.json", Buffer.from(JSON.stringify(manifest), "utf8"));
  const futureBytes = Buffer.from(await packZip(files));
  await assert.rejects(
    rewrapCapsule(futureBytes, {
      originator: { ...bob, label: "Bob" },
      allowInvalidPredecessor: true, // must NOT rescue an unknown era
    }),
    (err) => {
      assert.ok(err instanceof PredecessorError);
      assert.equal(err.reason, "unsupported_version");
      assert.match(err.message, /newer than this verifier supports/);
      return true;
    },
  );
  // Encrypted outer: encrypted_predecessor, message names the decrypt
  // path; decrypt-then-rewrap of the inner succeeds (the inner IS a
  // plain capsule).
  const encrypted = Buffer.from(await aliceBuilder(alice).seal({
    signers: [{ role: "originator", publicKey: alice.publicKey, privateKey: alice.privateKey }],
    signedAt: TS,
    recipients: [{ publicKey: recipient.publicKey }],
  }));
  await assert.rejects(
    rewrapCapsule(encrypted, { originator: { ...bob, label: "Bob" } }),
    (err) => {
      assert.ok(err instanceof PredecessorError);
      assert.equal(err.reason, "encrypted_predecessor");
      assert.equal(err.verification, null);
      assert.match(err.message, /decrypt/i);
      return true;
    },
  );
  const inner = await (await CapsuleReader.fromBytes(encrypted)).decrypt(recipient);
  const viaInner = await rewrapCapsule(inner, {
    originator: { ...bob, label: "Bob" }, createdAt: LATER, signedAt: LATER,
  });
  assert.equal((await verifyCapsule(viaInner.bytes)).ok, true);
});

test("T5: override — allowInvalidPredecessor seals; linkage reports predecessor_invalid", async () => {
  const alice = generateEd25519();
  const bob = generateEd25519();
  const tampered = await tamperedCopy(await sealedAlice(alice));
  const { bytes, predecessorVerification } = await rewrapCapsule(tampered, {
    originator: { ...bob, label: "Bob" }, createdAt: LATER, signedAt: LATER,
    allowInvalidPredecessor: true,
  });
  assert.equal(predecessorVerification.ok, false);
  const result = await verifyCapsule(bytes, { predecessors: [tampered] });
  assert.equal(result.ok, true); // the successor itself is a valid capsule
  assert.equal(result.lineage.entries[0].status, "predecessor_invalid");
});

test("T6: reproducibility — pinned timestamps byte-identical; unpinned diverge honestly", async () => {
  const alice = generateEd25519();
  const bob = generateEd25519();
  const predBytes = await sealedAlice(alice);
  const opts = { originator: { ...bob, label: "Bob" }, createdAt: LATER, signedAt: LATER };
  const a = await rewrapCapsule(predBytes, opts);
  const b = await rewrapCapsule(predBytes, opts);
  assert.ok(Buffer.from(a.bytes).equals(Buffer.from(b.bytes)));
  // Distinct timestamps → distinct genesis → distinct capsule ids: two
  // genuine successors, both honest (the rival-continuations row).
  const c = await rewrapCapsule(predBytes, {
    originator: { ...bob, label: "Bob" }, createdAt: "2026-05-07T14:00:00Z", signedAt: LATER,
  });
  assert.notEqual(a.capsuleId, c.capsuleId);
});

test("T7: re-rewrap — hop 2 declares exactly one entry; pool verifies depth 2", async () => {
  const alice = generateEd25519();
  const bob = generateEd25519();
  const carol = generateEd25519();
  const aliceBytes = await sealedAlice(alice);
  const bobWrap = await rewrapCapsule(aliceBytes, {
    originator: { ...bob, label: "Bob" }, createdAt: LATER, signedAt: LATER,
  });
  const carolWrap = await rewrapCapsule(bobWrap.bytes, {
    originator: { ...carol, label: "Carol" }, createdAt: LATER, signedAt: LATER,
  });
  const carolManifest = (await CapsuleReader.fromBytes(carolWrap.bytes)).manifest();
  assert.equal(carolManifest.predecessors.length, 1);
  assert.equal(carolManifest.predecessors[0].capsule_id, bobWrap.capsuleId);
  const result = await verifyCapsule(carolWrap.bytes, {
    predecessors: [bobWrap.bytes, aliceBytes],
  });
  assert.equal(result.lineage.verifiedDepth, 2);
});

test("T8: laundering equivalence — the override changes no emitted byte", async () => {
  const alice = generateEd25519();
  const bob = generateEd25519();
  const predBytes = await sealedAlice(alice);
  const opts = { originator: { ...bob, label: "Bob" }, createdAt: LATER, signedAt: LATER };
  const normal = await rewrapCapsule(predBytes, opts);
  const overridden = await rewrapCapsule(predBytes, { ...opts, allowInvalidPredecessor: true });
  // The flag is UX at the writer, not a security boundary: byte-for-byte
  // identical output, so no reader could ever distinguish the paths.
  assert.ok(Buffer.from(normal.bytes).equals(Buffer.from(overridden.bytes)));
});

test("T9: encrypted successor — recipients pass-through, lineagePlacement lands the member", async () => {
  const alice = generateEd25519();
  const bob = generateEd25519();
  const recipient = generateX25519();
  const predBytes = await sealedAlice(alice);
  const { bytes } = await rewrapCapsule(predBytes, {
    originator: { ...bob, label: "Bob" }, createdAt: LATER, signedAt: LATER,
    recipients: [{ publicKey: recipient.publicKey }],
    lineagePlacement: "both",
  });
  const outer = await CapsuleReader.fromBytes(bytes);
  assert.equal(outer.isEncrypted(), true);
  const inner = await outer.decrypt(recipient);
  // "both" emits the two copies byte-equal (reader check 4 by construction).
  assert.equal(
    JSON.stringify(outer.manifest().predecessors),
    JSON.stringify(inner.manifest().predecessors),
  );
  const innerResult = await verifyCapsule(inner, {
    outerEnvelope: outer.envelope(),
    outerManifest: outer.manifest(),
  });
  assert.equal(innerResult.ok, true);
  await assert.rejects(
    rewrapCapsule(predBytes, {
      originator: { ...bob, label: "Bob" },
      recipients: [{ publicKey: recipient.publicKey }],
      lineagePlacement: "sideways",
    }),
    /lineagePlacement/,
  );
});

test("T10: declarePredecessorEntry — accepts coherent entries, rejects each malformation", async () => {
  const alice = generateEd25519();
  const bob = generateEd25519();
  const entry = derivePredecessorEntry(await CapsuleReader.fromBytes(await sealedAlice(alice)));
  const fresh = () => new CapsuleBuilder({ originator: { publicKey: bob.publicKeyHex } });
  // Coherent explicit entry accepted; duplicate manifest_hash rejected.
  const builder = fresh().declarePredecessorEntry(entry);
  assert.throws(() => builder.declarePredecessorEntry({ ...entry }), /cited twice/);
  // Unknown-era explicit entry IS expressible (the archivist case):
  // identity coherence is validated only for known eras.
  fresh().declarePredecessorEntry({ ...entry, format_version: "0.9" });
  // Check-1/2/3 malformations rejected with the shared diagnoses.
  assert.throws(
    () => fresh().declarePredecessorEntry({ ...entry, capsule_id: entry.capsule_id.toUpperCase() }),
    /predecessors\[0\]\.capsule_id/,
  );
  assert.throws(
    () => fresh().declarePredecessorEntry({ ...entry, first_event_hash: null }),
    /cannot exist/,
  );
  assert.throws(
    () => fresh().declarePredecessorEntry({ ...entry, capsule_id: "0".repeat(64) }),
    /does not derive/,
  );
  assert.throws(
    () => fresh().declarePredecessorEntry({ ...entry, note: "advisory text" }),
    /predecessors\[0\]\.note/,
  );
});

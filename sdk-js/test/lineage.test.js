// Lineage verification (spec/lineage.md): the manifest.predecessors
// standalone checks (fail-closed), the report-only supplied-bytes
// linkage, the era-keyed recursive walk, the result.lineage area, the
// three emitted lineage qualifiers, and the pinned report phrases.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CapsuleBuilder,
  CapsuleReader,
  verifyCapsule,
  rewrapCapsule,
  generateEd25519,
  generateX25519,
  computeCapsuleId,
  predecessorsProblems,
  hexToBytes,
  manifestHash,
  buildManifest,
  buildContentIndex,
  buildSignerCommitment,
  buildChainEvents,
  buildEnvelope,
  signEnvelope,
  manifestBytes,
  packZip,
  unpackZip,
} from "../src/index.js";
import { eventsToJsonl, firstAndEntryHash } from "../src/chain.js";
import { bytesToHex, concatBytes, jcs, sha256 } from "../src/canonical.js";
import { ed25519Sign } from "../src/crypto.js";

const TS = "2026-05-07T12:00:00Z";
const LATER = "2026-05-07T13:00:00Z";

function predBuilder(ed, events = 2) {
  const builder = new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex, label: "Alice" },
    participants: [{ actor_id: "human:alice", role: "originator" }],
    createdAt: TS,
  });
  builder.setProgram("# Work\n\nStep one.\n");
  builder.addPayload("payload/data.csv", Buffer.from("a,b\n1,2\n", "utf8"));
  for (let i = 0; i < events; i++) {
    builder.appendEvent({
      actor: "human:alice",
      kind: "decision",
      action: `step_${i + 1}`,
      target: "program.md",
      timestamp: TS,
      payload: { note: `step ${i + 1}` },
    });
  }
  return builder;
}

async function sealedPred(ed, events = 2) {
  return Buffer.from(await predBuilder(ed, events).seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  }));
}

/**
 * Seal a capsule under an EARLIER era carrying an arbitrary
 * `predecessors` value. Byte-coherent under that era: identity from
 * `capsule-id-v<era>\0` and the signature over
 * `capsule-provenance-v<era>:originator\0`, the domain strings that
 * era's verifier reconstructs — so the ONLY thing under test is whether
 * a v0.7.1 reader interprets a member that era's rules do not define.
 */
async function sealAtEraWithPredecessors(ed, era, predecessorsValue) {
  const events = buildChainEvents([{
    actor: "human:alice",
    kind: "observation",
    action: "noted",
    target: "capsule",
    timestamp: TS,
    payload: {},
  }]);
  const { firstEventHash, entryHash } = firstAndEntryHash(events);
  const files = new Map();
  files.set("program.md", Buffer.from("# Program\n", "utf8"));
  files.set("chain/events.jsonl", eventsToJsonl(events));
  const contentIndex = buildContentIndex(files);
  const manifest = buildManifest({
    originator: { public_key: ed.publicKeyHex, label: "Alice" },
    participants: [{ actor_id: "human:alice", role: "originator" }],
    contentIndex,
    firstEventHash,
    encryption: null,
    createdAt: TS,
    signerCommitment: buildSignerCommitment([
      { role: "originator", public_key: ed.publicKeyHex },
    ]),
  });
  manifest.format.version = era;
  manifest.predecessors = predecessorsValue;
  manifest.id = bytesToHex(sha256(concatBytes(
    Buffer.from(`capsule-id-v${era}\x00`, "utf8"),
    ed.publicKey,
    hexToBytes(firstEventHash),
  )));
  const envelope = buildEnvelope({
    capsuleId: manifest.id,
    firstEventHash,
    entryHash,
    manifestHash: manifestHash(manifest),
    contentIndexHash: contentIndex.index_hash,
    encryptedBlobHash: null,
    cipher: "none",
    signedAt: TS,
  });
  envelope.version = era;
  const { signers: _drop, ...payload } = envelope;
  envelope.signers.push({
    role: "originator",
    public_key: ed.publicKeyHex,
    signature: bytesToHex(ed25519Sign(ed.privateKey, concatBytes(
      Buffer.from(`capsule-provenance-v${era}:originator\x00`, "utf8"),
      jcs(payload),
    ))),
  });
  const all = new Map(files);
  all.set("manifest.json", manifestBytes(manifest));
  all.set("provenance/envelope.json", Buffer.from(JSON.stringify(envelope, null, 2), "utf8"));
  return Buffer.from(await packZip(all));
}

/** Seal a minimal capsule with an arbitrary (possibly malformed) predecessors value. */
async function sealWithPredecessors(ed, predecessorsValue) {
  const events = buildChainEvents([{
    actor: "human:alice",
    kind: "observation",
    action: "noted",
    target: "capsule",
    timestamp: TS,
    payload: {},
  }]);
  const { firstEventHash, entryHash } = firstAndEntryHash(events);
  const files = new Map();
  files.set("program.md", Buffer.from("# Program\n", "utf8"));
  files.set("chain/events.jsonl", eventsToJsonl(events));
  const contentIndex = buildContentIndex(files);
  const manifest = buildManifest({
    originator: { public_key: ed.publicKeyHex, label: "Alice" },
    participants: [{ actor_id: "human:alice", role: "originator" }],
    contentIndex,
    firstEventHash,
    encryption: null,
    createdAt: TS,
    signerCommitment: buildSignerCommitment([
      { role: "originator", public_key: ed.publicKeyHex },
    ]),
  });
  if (predecessorsValue !== undefined) manifest.predecessors = predecessorsValue;
  manifest.id = computeCapsuleId(ed.publicKey, firstEventHash);
  const envelope = buildEnvelope({
    capsuleId: manifest.id,
    firstEventHash,
    entryHash,
    manifestHash: manifestHash(manifest),
    contentIndexHash: contentIndex.index_hash,
    encryptedBlobHash: null,
    cipher: "none",
    signedAt: TS,
  });
  signEnvelope(envelope, [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }]);
  const all = new Map(files);
  all.set("manifest.json", manifestBytes(manifest));
  all.set("provenance/envelope.json", Buffer.from(JSON.stringify(envelope, null, 2), "utf8"));
  return Buffer.from(await packZip(all));
}

test("no predecessors member: declared=false, lineage.ok=true, no qualifiers", async () => {
  const alice = generateEd25519();
  const result = await verifyCapsule(await sealedPred(alice));
  assert.equal(result.ok, true);
  assert.deepEqual(result.lineage, { declared: false, ok: true, verifiedDepth: 0, entries: [] });
  assert.deepEqual(result.qualifiers, []);
});

test("declared, no pool: unverified entry, pinned phrases, lineage_declared_unverified", async () => {
  const alice = generateEd25519();
  const bob = generateEd25519();
  const { bytes } = await rewrapCapsule(await sealedPred(alice), {
    originator: { ...bob, label: "Bob" },
    createdAt: LATER,
    signedAt: LATER,
  });
  const result = await verifyCapsule(bytes);
  assert.equal(result.ok, true);
  assert.equal(result.lineage.declared, true);
  assert.equal(result.lineage.ok, true);
  assert.equal(result.lineage.verifiedDepth, 0);
  assert.equal(result.lineage.entries.length, 1);
  assert.equal(result.lineage.entries[0].status, "unverified");
  assert.equal(result.lineage.entries[0].hop, 1);
  assert.equal(result.lineage.entries[0].identityChecked, true);
  assert.equal(result.lineage.entries[0].artifact, null);
  const notes = result.notes.join(" | ");
  // Pinned phrases: an unchecked custody claim must never quietly
  // disappear, and no report may imply a consent bit exists.
  assert.match(notes, /declared, not verified/);
  assert.match(notes, /not countersigned/);
  assert.deepEqual(result.qualifiers, ["lineage_declared_unverified"]);
});

test("linkage verified to depth 1; verified note names two identities", async () => {
  const alice = generateEd25519();
  const bob = generateEd25519();
  const predBytes = await sealedPred(alice);
  const { bytes, capsuleId, predecessorEntry } = await rewrapCapsule(predBytes, {
    originator: { ...bob, label: "Bob" },
    createdAt: LATER,
    signedAt: LATER,
  });
  const result = await verifyCapsule(bytes, { predecessors: [predBytes] });
  assert.equal(result.ok, true);
  assert.equal(result.lineage.ok, true);
  assert.equal(result.lineage.verifiedDepth, 1);
  assert.equal(result.lineage.entries[0].status, "verified");
  assert.equal(result.lineage.entries[0].artifact.ok, true);
  assert.equal(result.lineage.entries[0].artifact.observed_version, "0.7");
  // Distinct identities: the successor is never presented as BEING the
  // predecessor.
  assert.notEqual(capsuleId, predecessorEntry.capsule_id);
  assert.match(result.notes.join(" | "), /successor of capsule .*verified to depth 1/);
  assert.deepEqual(result.qualifiers, []);
});

test("era-keyed recursive walk: depth 2, hop numbers, re-rewrap declares one entry", async () => {
  const alice = generateEd25519();
  const bob = generateEd25519();
  const carol = generateEd25519();
  const aliceBytes = await sealedPred(alice);
  const bobWrap = await rewrapCapsule(aliceBytes, {
    originator: { ...bob, label: "Bob" }, createdAt: LATER, signedAt: LATER,
  });
  const carolWrap = await rewrapCapsule(bobWrap.bytes, {
    originator: { ...carol, label: "Carol" }, createdAt: LATER, signedAt: LATER,
  });
  // Re-rewrap never accumulates: hop-2 successor declares exactly one
  // entry (its immediate parent); ancestry never flattens inline.
  const carolReader = await CapsuleReader.fromBytes(carolWrap.bytes);
  assert.equal(carolReader.manifest().predecessors.length, 1);
  const result = await verifyCapsule(carolWrap.bytes, {
    predecessors: [bobWrap.bytes, aliceBytes],
  });
  assert.equal(result.ok, true);
  assert.equal(result.lineage.verifiedDepth, 2);
  const hops = result.lineage.entries.map((e) => [e.hop, e.status]);
  assert.deepEqual(hops, [[1, "verified"], [2, "verified"]]);
});

test("merge: two declared parents, one supplied — verified + unverified, depth 0", async () => {
  const alice = generateEd25519();
  const dana = generateEd25519();
  const bob = generateEd25519();
  const aliceBytes = await sealedPred(alice);
  const danaBytes = await sealedPred(dana, 1);
  const builder = await CapsuleBuilder.continueFrom(aliceBytes, {
    originator: { ...bob, label: "Bob" },
    createdAt: LATER,
  });
  await builder.declarePredecessor(danaBytes);
  const bytes = await builder.seal({ signers: [bob], signedAt: LATER });
  const result = await verifyCapsule(bytes, { predecessors: [aliceBytes] });
  assert.equal(result.ok, true);
  assert.equal(result.lineage.entries.length, 2);
  assert.deepEqual(result.lineage.entries.map((e) => e.status).sort(), [
    "unverified", "verified",
  ]);
  assert.equal(result.lineage.verifiedDepth, 0);
  assert.deepEqual(result.qualifiers, ["lineage_declared_unverified"]);
});

test("mismatch: a different seal of the same line is report-only and ok stays true", async () => {
  const alice = generateEd25519();
  const bob = generateEd25519();
  const threeEvents = await sealedPred(alice, 2);
  // A later genuine seal of the same line: same key, same genesis event,
  // one more event — same capsule_id, different manifest_hash.
  const laterSeal = Buffer.from(await predBuilder(alice, 3).seal({
    signers: [{ role: "originator", publicKey: alice.publicKey, privateKey: alice.privateKey }],
    signedAt: LATER,
  }));
  const { bytes } = await rewrapCapsule(threeEvents, {
    originator: { ...bob, label: "Bob" }, createdAt: LATER, signedAt: LATER,
  });
  const sameId = (await CapsuleReader.fromBytes(laterSeal)).manifest().id;
  assert.equal(sameId, (await CapsuleReader.fromBytes(threeEvents)).manifest().id);
  const result = await verifyCapsule(bytes, { predecessors: [laterSeal] });
  // The anti-framing pin: a host's file handling never flips the
  // successor's own verdict.
  assert.equal(result.ok, true);
  assert.equal(result.lineage.ok, false);
  assert.equal(result.lineage.entries[0].status, "mismatch");
  const errs = result.lineage.entries[0].errors.join(" | ");
  assert.match(errs, /different sealed state of the declared predecessor/);
  // The versioning.md diagnosis style: the honest cause is named and
  // tamper vocabulary appears only negated.
  assert.match(errs, /not evidence of tampering/);
  assert.doesNotMatch(errs, /corrupt/i);
  assert.deepEqual(result.qualifiers, ["lineage_mismatch"]);
});

test("predecessor_invalid: tampered supplied artifact, two facts never collapsed", async () => {
  const alice = generateEd25519();
  const bob = generateEd25519();
  const predBytes = await sealedPred(alice);
  const { bytes } = await rewrapCapsule(predBytes, {
    originator: { ...bob, label: "Bob" }, createdAt: LATER, signedAt: LATER,
  });
  // Tamper with a content file: the manifest (and thus the declared
  // manifest_hash) is untouched, so the artifact still pair-matches.
  const files = await unpackZip(predBytes);
  const program = Buffer.from(files.get("program.md"));
  program[0] ^= 0x01;
  files.set("program.md", program);
  const tampered = Buffer.from(await packZip(files));
  const result = await verifyCapsule(bytes, { predecessors: [tampered] });
  assert.equal(result.ok, true);
  assert.equal(result.lineage.ok, false);
  assert.equal(result.lineage.entries[0].status, "predecessor_invalid");
  assert.equal(result.lineage.entries[0].artifact.ok, false);
  assert.match(
    result.lineage.entries[0].errors.join(" "),
    /property of the supplied artifact/,
  );
  assert.deepEqual(result.qualifiers, ["lineage_predecessor_invalid"]);
});

test("unmatched supplied artifact is named in notes, never silently ignored", async () => {
  const alice = generateEd25519();
  const stranger = generateEd25519();
  const bob = generateEd25519();
  const { bytes } = await rewrapCapsule(await sealedPred(alice), {
    originator: { ...bob, label: "Bob" }, createdAt: LATER, signedAt: LATER,
  });
  const result = await verifyCapsule(bytes, { predecessors: [await sealedPred(stranger)] });
  assert.equal(result.ok, true);
  assert.match(result.notes.join(" | "), /matched no declared entry/);
});

test("encrypted supplied predecessor: predecessor_unverifiable/encrypted_predecessor", async () => {
  const alice = generateEd25519();
  const bob = generateEd25519();
  const recipient = generateX25519();
  // The encrypted twin shares identity and (inner) manifest with the
  // plain seal, so the declaration derived from the plain twin names it.
  const plainBytes = await sealedPred(alice);
  const encryptedBytes = Buffer.from(await predBuilder(alice, 2).seal({
    signers: [{ role: "originator", publicKey: alice.publicKey, privateKey: alice.privateKey }],
    signedAt: TS,
    recipients: [{ publicKey: recipient.publicKey }],
  }));
  const { bytes } = await rewrapCapsule(plainBytes, {
    originator: { ...bob, label: "Bob" }, createdAt: LATER, signedAt: LATER,
  });
  const result = await verifyCapsule(bytes, { predecessors: [encryptedBytes] });
  assert.equal(result.ok, true);
  assert.equal(result.lineage.entries[0].status, "predecessor_unverifiable");
  assert.equal(result.lineage.entries[0].reason, "encrypted_predecessor");
  assert.match(result.notes.join(" | "), /declared, not verified/);
  assert.deepEqual(result.qualifiers, ["lineage_declared_unverified"]);
});

test("alternate-profile supplied predecessor: predecessor_unverifiable/unsupported_profile", async () => {
  const alice = generateEd25519();
  const bob = generateEd25519();
  // Build a predecessor declaring an alternate profile (default math,
  // non-default declaration — the B2 scope case).
  const predBytes = await sealWithPredecessors(alice, undefined);
  const files = await unpackZip(predBytes);
  const manifest = JSON.parse(Buffer.from(files.get("manifest.json")).toString("utf8"));
  manifest.format.profile = { id: "acme-postquantum", version: "1.0" };
  const entry = {
    capsule_id: manifest.id,
    format_version: manifest.format.version,
    originator_public_key: manifest.originator.public_key,
    first_event_hash: manifest.first_event_hash,
    entry_hash: null,
    manifest_hash: null,
  };
  // Re-seal coherently with the profile declaration in the manifest.
  const contentIndex = manifest.content_index;
  const envelope = JSON.parse(Buffer.from(files.get("provenance/envelope.json")).toString("utf8"));
  entry.entry_hash = envelope.entry_hash;
  const resignedEnvelope = buildEnvelope({
    capsuleId: manifest.id,
    firstEventHash: manifest.first_event_hash,
    entryHash: envelope.entry_hash,
    manifestHash: manifestHash(manifest),
    contentIndexHash: contentIndex.index_hash,
    encryptedBlobHash: null,
    cipher: "none",
    signedAt: TS,
  });
  signEnvelope(resignedEnvelope, [
    { role: "originator", publicKey: alice.publicKey, privateKey: alice.privateKey },
  ]);
  entry.manifest_hash = manifestHash(manifest);
  files.set("manifest.json", manifestBytes(manifest));
  files.set("provenance/envelope.json", Buffer.from(JSON.stringify(resignedEnvelope, null, 2), "utf8"));
  const altPred = Buffer.from(await packZip(files));
  // The successor cites it via the explicit-values path (continueFrom
  // refuses alternate-profile predecessors, W5-adjacent).
  const builder = new CapsuleBuilder({
    originator: { publicKey: bob.publicKeyHex, label: "Bob" },
    createdAt: LATER,
  });
  builder.declarePredecessorEntry(entry);
  builder.appendEvent({
    actor: "system:host", action: "custody_received", target: `capsule:${entry.capsule_id}`,
    timestamp: LATER, payload: {},
  });
  const bytes = await builder.seal({ signers: [bob], signedAt: LATER });
  const result = await verifyCapsule(bytes, { predecessors: [altPred] });
  assert.equal(result.ok, true);
  const e = result.lineage.entries[0];
  // A verifier/scope limitation — never mismatch, never
  // predecessor_invalid (the B2 diagnosis-discipline pin).
  assert.equal(e.status, "predecessor_unverifiable");
  assert.equal(e.reason, "unsupported_profile");
});

test("standalone malformation fails closed with predecessors[i].<member> diagnoses", async () => {
  const alice = generateEd25519();
  const good = {
    capsule_id: computeCapsuleId(alice.publicKey, null, "0.7"),
    format_version: "0.7",
    originator_public_key: alice.publicKeyHex,
    first_event_hash: null,
    entry_hash: null,
    manifest_hash: "a".repeat(64),
  };
  const cases = [
    ["not-array", "yes", /predecessors must be an array/],
    ["empty", [], /predecessors must not be empty/],
    ["missing-manifest-hash", [(({ manifest_hash, ...r }) => r)(good)], /predecessors\[0\]\.manifest_hash/],
    ["uppercase-hex", [{ ...good, capsule_id: good.capsule_id.toUpperCase() }], /predecessors\[0\]\.capsule_id/],
    ["version-grammar", [{ ...good, format_version: "v0.7" }], /predecessors\[0\]\.format_version/],
    ["null-incoherent", [{ ...good, first_event_hash: null, entry_hash: "b".repeat(64) }], /cannot exist/],
    ["duplicate-manifest-hash", [good, { ...good, manifest_hash: good.manifest_hash }], /cited twice/],
    ["unknown-member", [{ ...good, label: "official continuation" }], /predecessors\[0\]\.label/],
  ];
  for (const [name, value, pattern] of cases) {
    const bytes = await sealWithPredecessors(alice, value);
    const result = await verifyCapsule(bytes);
    assert.equal(result.ok, false, name);
    assert.equal(result.lineage.declared, true, name);
    assert.equal(result.lineage.ok, false, name);
    assert.match(result.errors.join(" | "), pattern, name);
    // No qualifiers on an invalid verdict.
    assert.deepEqual(result.qualifiers, [], name);
  }
});

test("identity coherence: fail-closed under known eras, skipped-and-reported for unknown", async () => {
  const alice = generateEd25519();
  const entry = {
    capsule_id: computeCapsuleId(alice.publicKey, null, "0.7"),
    format_version: "0.7",
    originator_public_key: alice.publicKeyHex,
    first_event_hash: null,
    entry_hash: null,
    manifest_hash: "a".repeat(64),
  };
  // Known era, underivable id: fail closed (self-assertion, not linkage).
  const bad = { ...entry, capsule_id: entry.capsule_id.replace(/^./, entry.capsule_id[0] === "0" ? "1" : "0") };
  const badResult = await verifyCapsule(await sealWithPredecessors(alice, [bad]));
  assert.equal(badResult.ok, false);
  assert.match(badResult.errors.join(" "), /does not derive/);
  // Unknown declared era: the check SKIPS (the verifier is too old for
  // that era's formula) and the skip is reported — never a failure.
  const future = { ...entry, format_version: "0.9" };
  const futureResult = await verifyCapsule(await sealWithPredecessors(alice, [future]));
  assert.equal(futureResult.ok, true);
  assert.equal(futureResult.lineage.entries[0].identityChecked, false);
  assert.equal(futureResult.lineage.entries[0].status, "unverified");
});

test("zero-event predecessor: null/null anchors verify (32-zero-byte genesis rule)", async () => {
  const alice = generateEd25519();
  const bob = generateEd25519();
  // Zero-event template built low-level (seal() inserts a backstop).
  const files = new Map();
  files.set("program.md", Buffer.from("# Template\n", "utf8"));
  files.set("chain/events.jsonl", Buffer.from("", "utf8"));
  const contentIndex = buildContentIndex(files);
  const manifest = buildManifest({
    originator: { public_key: alice.publicKeyHex, label: "Alice" },
    participants: [],
    contentIndex,
    firstEventHash: null,
    encryption: null,
    createdAt: TS,
    signerCommitment: buildSignerCommitment([
      { role: "originator", public_key: alice.publicKeyHex },
    ]),
  });
  manifest.id = computeCapsuleId(alice.publicKey, null);
  const envelope = buildEnvelope({
    capsuleId: manifest.id,
    firstEventHash: null,
    entryHash: null,
    manifestHash: manifestHash(manifest),
    contentIndexHash: contentIndex.index_hash,
    encryptedBlobHash: null,
    cipher: "none",
    signedAt: TS,
  });
  signEnvelope(envelope, [{ role: "originator", publicKey: alice.publicKey, privateKey: alice.privateKey }]);
  const all = new Map(files);
  all.set("manifest.json", manifestBytes(manifest));
  all.set("provenance/envelope.json", Buffer.from(JSON.stringify(envelope, null, 2), "utf8"));
  const templateBytes = Buffer.from(await packZip(all));
  const { bytes, predecessorEntry } = await rewrapCapsule(templateBytes, {
    originator: { ...bob, label: "Bob" }, createdAt: LATER, signedAt: LATER,
  });
  assert.equal(predecessorEntry.first_event_hash, null);
  assert.equal(predecessorEntry.entry_hash, null);
  const result = await verifyCapsule(bytes, { predecessors: [templateBytes] });
  assert.equal(result.ok, true);
  assert.equal(result.lineage.entries[0].status, "verified");
  assert.equal(result.lineage.verifiedDepth, 1);
});

test("report-only linkage never runs on a version-refused capsule (refusal exclusivity)", async () => {
  const alice = generateEd25519();
  // A capsule this verifier cannot open holds the fail-closed
  // not-evaluated lineage default; the refusal is the only diagnosis.
  const bytes = await sealWithPredecessors(alice, undefined);
  const files = await unpackZip(bytes);
  const manifest = JSON.parse(Buffer.from(files.get("manifest.json")).toString("utf8"));
  manifest.format.version = "9.9";
  files.set("manifest.json", Buffer.from(JSON.stringify(manifest), "utf8"));
  const future = Buffer.from(await packZip(files));
  const result = await verifyCapsule(future);
  assert.equal(result.ok, false);
  assert.deepEqual(result.lineage, { declared: false, ok: false, verifiedDepth: 0, entries: [] });
  assert.deepEqual(result.qualifiers, []);
});

test("no self-reference rule: same-key zero-event declaration verifies (deliberate absence)", () => {
  const alice = generateEd25519();
  const zeroEventId = computeCapsuleId(alice.publicKey, null, "0.7");
  // A same-key zero-event template rewrap honestly declares a
  // predecessor id equal to its own (two zero-event capsules from one
  // originator share a capsule_id). No rule fails it.
  const problems = predecessorsProblems([{
    capsule_id: zeroEventId,
    format_version: "0.7",
    originator_public_key: alice.publicKeyHex,
    first_event_hash: null,
    entry_hash: null,
    manifest_hash: "c".repeat(64),
  }]);
  assert.deepEqual(problems, []);
});

test("same capsule_id with different manifest_hash values is a legal merge shape", () => {
  const alice = generateEd25519();
  const id = computeCapsuleId(alice.publicKey, null, "0.7");
  const base = {
    capsule_id: id,
    format_version: "0.7",
    originator_public_key: alice.publicKeyHex,
    first_event_hash: null,
    entry_hash: null,
  };
  assert.deepEqual(
    predecessorsProblems([
      { ...base, manifest_hash: "a".repeat(64) },
      { ...base, manifest_hash: "b".repeat(64) },
    ]),
    [],
  );
});

test("x- vendor members inside entries are preserved and legal", () => {
  const alice = generateEd25519();
  const problems = predecessorsProblems([{
    capsule_id: computeCapsuleId(alice.publicKey, null, "0.7"),
    format_version: "0.7",
    originator_public_key: alice.publicKeyHex,
    first_event_hash: null,
    entry_hash: null,
    manifest_hash: "d".repeat(64),
    "x-acme-relation": "fork",
  }]);
  assert.deepEqual(problems, []);
});

test("pre-lineage era: a predecessors member is inert, not shape-checked", async () => {
  const alice = generateEd25519();
  // The SAME value that fails a 0.7 capsule closed.
  const malformed = [];
  const v07 = await verifyCapsule(await sealWithPredecessors(alice, malformed));
  assert.equal(v07.ok, false);
  assert.ok(v07.errors.some((e) => e.startsWith("manifest.predecessors")));

  const v06 = await verifyCapsule(await sealAtEraWithPredecessors(alice, "0.6", malformed));
  assert.equal(v06.ok, true, v06.errors.join("; "));
  assert.equal(v06.formatVersion.observed, "0.6");
  assert.deepEqual(v06.lineage, { declared: false, ok: true, verifiedDepth: 0, entries: [] });
  assert.deepEqual(v06.qualifiers, []);
  assert.ok(v06.notes.some((n) => n.includes("unknown member under that era")));
});

test("pre-lineage era: a well-formed declaration is equally uninterpreted", async () => {
  const alice = generateEd25519();
  const bob = generateEd25519();
  const predBytes = await sealedPred(alice);
  const { bytes } = await rewrapCapsule(predBytes, {
    originator: { ...bob, label: "Bob" },
    createdAt: LATER,
    signedAt: LATER,
  });
  const entry = (await CapsuleReader.fromBytes(bytes)).manifest().predecessors[0];
  const result = await verifyCapsule(
    await sealAtEraWithPredecessors(bob, "0.6", [entry]),
    { predecessors: [predBytes] },
  );
  // Even with the predecessor bytes in hand: no era rules, no claim.
  assert.equal(result.ok, true, result.errors.join("; "));
  assert.equal(result.lineage.declared, false);
  assert.equal(result.lineage.entries.length, 0);
});

test("L3 inner/outer equality runs on the documented recipe, with no extra option", async () => {
  const alice = generateEd25519();
  const bob = generateEd25519();
  const recipient = generateX25519();
  const { bytes } = await rewrapCapsule(await sealedPred(alice), {
    originator: { ...bob, label: "Bob" },
    createdAt: LATER,
    signedAt: LATER,
    recipients: [{ publicKey: recipient.publicKey }],
    lineagePlacement: "both",
  });
  // A capsule asserting one origin to the world and another to its
  // recipients: rewrite the OUTER declaration only.
  const files = await unpackZip(bytes);
  const outerManifest = JSON.parse(Buffer.from(files.get("manifest.json")).toString("utf8"));
  outerManifest.predecessors = [
    { ...outerManifest.predecessors[0], manifest_hash: "e".repeat(64) },
  ];
  files.set("manifest.json", Buffer.from(JSON.stringify(outerManifest), "utf8"));
  const outer = await CapsuleReader.fromBytes(Buffer.from(await packZip(files)));
  const inner = await outer.decrypt(recipient);
  // The reader carries the layer it came out of, so the fail-closed
  // MUST is not opt-in.
  assert.equal(inner.outerManifest(), outer.manifest());
  const result = await verifyCapsule(inner, { outerEnvelope: outer.envelope() });
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => e.includes("predecessors differs between the inner and outer")));
});

test("encrypted successor: inner/outer lineage equality at L3 (both-present rule)", async () => {
  const alice = generateEd25519();
  const bob = generateEd25519();
  const recipient = generateX25519();
  const predBytes = await sealedPred(alice);
  const { bytes } = await rewrapCapsule(predBytes, {
    originator: { ...bob, label: "Bob" },
    createdAt: LATER,
    signedAt: LATER,
    recipients: [{ publicKey: recipient.publicKey }],
    lineagePlacement: "both",
  });
  const outer = await CapsuleReader.fromBytes(bytes);
  assert.ok(Array.isArray(outer.manifest().predecessors));
  const inner = await outer.decrypt(recipient);
  assert.ok(Array.isArray(inner.manifest().predecessors));
  const innerResult = await verifyCapsule(inner, {
    outerEnvelope: outer.envelope(),
    outerManifest: outer.manifest(),
  });
  assert.equal(innerResult.ok, true);
  // Single-layer placements are each a weaker claim made honestly.
  for (const [placement, hasOuter, hasInner] of [
    ["inner", false, true],
    ["outer", true, false],
  ]) {
    const wrapped = await rewrapCapsule(predBytes, {
      originator: { ...bob, label: "Bob" },
      createdAt: LATER,
      signedAt: LATER,
      recipients: [{ publicKey: recipient.publicKey }],
      lineagePlacement: placement,
    });
    const o = await CapsuleReader.fromBytes(wrapped.bytes);
    assert.equal("predecessors" in o.manifest(), hasOuter, placement);
    const i = await o.decrypt(recipient);
    assert.equal("predecessors" in i.manifest(), hasInner, placement);
    const r = await verifyCapsule(i, { outerEnvelope: o.envelope(), outerManifest: o.manifest() });
    assert.equal(r.ok, true, placement);
  }
});

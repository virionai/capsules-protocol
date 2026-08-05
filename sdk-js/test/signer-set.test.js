// Signer-set binding (manifest.signer_commitment), duplicate-signer
// rejection, distinct trusted-key counting, and originator binding.
//
// The defect being closed: the signing input is domain_sep(role) ||
// JCS(envelope minus signers), so signers[] is not an input to any
// signature, and provenance/envelope.json is structurally excluded from
// the content index. Nothing committed to the SET — signatures could be
// stripped without residue and fresh signatures appended in a chosen
// role. manifest.signer_commitment closes this: it is covered by
// manifest_hash, which IS inside every signature.
//
// Rule: PRESENCE BINDS, ABSENCE REPORTS. A commitment that is present
// must match the signer set exactly (fail closed). A manifest without
// one verifies, at an assurance level that visibly excludes signer-set
// integrity (signerSet.bound === false).

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CapsuleBuilder,
  CapsuleReader,
  verifyCapsule,
  generateEd25519,
  buildChainEvents,
  buildContentIndex,
  buildManifest,
  computeCapsuleId,
  buildEnvelope,
  signEnvelope,
  hexToBytes,
  ed25519Sign,
} from "../src/index.js";
import { manifestBytes, manifestHash } from "../src/manifest.js";
import { eventsToJsonl, firstAndEntryHash } from "../src/chain.js";
import { envelopeSigningInput } from "../src/envelope.js";
import { bytesToHex } from "../src/canonical.js";
import { packZip, unpackZip } from "../src/zip.js";

const TS = "2026-05-07T12:00:00Z";

function twoSignerBuilder() {
  const originator = generateEd25519();
  const approver = generateEd25519();
  const builder = new CapsuleBuilder({
    originator: { publicKey: originator.publicKeyHex, label: "Acme" },
    participants: [
      { actor_id: "human:alice", role: "originator", label: "Alice" },
      { actor_id: "human:bob", role: "approver", label: "Bob" },
    ],
    createdAt: TS,
  });
  builder.setProgram("# Loan file\n");
  builder.appendEvent({
    actor: "human:alice",
    kind: "decision",
    action: "submit",
    target: "program.md",
    timestamp: TS,
    payload: { summary: "submitted" },
  });
  return { builder, originator, approver };
}

async function sealTwoSigners() {
  const { builder, originator, approver } = twoSignerBuilder();
  const bytes = await builder.seal({
    signers: [
      { role: "originator", publicKey: originator.publicKey, privateKey: originator.privateKey },
      { role: "approver", publicKey: approver.publicKey, privateKey: approver.privateKey },
    ],
    signedAt: TS,
  });
  return { bytes, originator, approver };
}

/** Rewrite provenance/envelope.json inside a capsule via `mutate(env)`. */
async function rewriteEnvelope(capsuleBytes, mutate) {
  const files = await unpackZip(capsuleBytes);
  const env = JSON.parse(Buffer.from(files.get("provenance/envelope.json")).toString("utf8"));
  mutate(env);
  files.set("provenance/envelope.json", Buffer.from(JSON.stringify(env, null, 2), "utf8"));
  return Buffer.from(await packZip(files));
}

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

test("seal() emits manifest.signer_commitment: sorted exact membership", async () => {
  const { bytes, originator, approver } = await sealTwoSigners();
  const reader = await CapsuleReader.fromBytes(bytes);
  const commitment = reader.manifest().signer_commitment;
  assert.ok(Array.isArray(commitment), "signer_commitment must be present");
  const expected = [
    { role: "originator", public_key: originator.publicKeyHex },
    { role: "approver", public_key: approver.publicKeyHex },
  ].sort((a, b) =>
    a.public_key < b.public_key ? -1 : a.public_key > b.public_key ? 1 : a.role < b.role ? -1 : 1,
  );
  assert.deepEqual(commitment, expected);
});

test("seal() rejects duplicate (role, public_key) signers", async () => {
  const { builder, originator } = twoSignerBuilder();
  await assert.rejects(
    () =>
      builder.seal({
        signers: [
          { role: "originator", publicKey: originator.publicKey, privateKey: originator.privateKey },
          { role: "originator", publicKey: originator.publicKey, privateKey: originator.privateKey },
        ],
        signedAt: TS,
      }),
    /duplicate signer/,
  );
});

test("encrypted seal emits the commitment on the outer manifest too", async () => {
  const { builder, originator, approver } = twoSignerBuilder();
  const { generateX25519 } = await import("../src/crypto.js");
  const recipient = generateX25519();
  const bytes = await builder.seal({
    signers: [
      { role: "originator", publicKey: originator.publicKey, privateKey: originator.privateKey },
      { role: "approver", publicKey: approver.publicKey, privateKey: approver.privateKey },
    ],
    recipients: [{ publicKey: recipient.publicKey }],
    signedAt: TS,
  });
  const reader = await CapsuleReader.fromBytes(bytes);
  assert.ok(Array.isArray(reader.manifest().signer_commitment));
  assert.equal(reader.manifest().signer_commitment.length, 2);
  const result = await verifyCapsule(reader, { allowlist: [originator.publicKeyHex] });
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.equal(result.signerSet.bound, true);
});

// ---------------------------------------------------------------------------
// Positive control
// ---------------------------------------------------------------------------

test("positive control: bound two-signer capsule verifies", async () => {
  const { bytes, originator, approver } = await sealTwoSigners();
  const result = await verifyCapsule(await CapsuleReader.fromBytes(bytes), {
    allowlist: [originator.publicKeyHex, approver.publicKeyHex],
  });
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.equal(result.signerSet.bound, true);
  assert.equal(result.signerSet.ok, true);
  assert.equal(result.trustedSignerCount, 2);
});

// ---------------------------------------------------------------------------
// Strip / append / duplicate — the three measured attacks
// ---------------------------------------------------------------------------

test("stripped signer fails closed and names the missing member", async () => {
  const { bytes, originator, approver } = await sealTwoSigners();
  const stripped = await rewriteEnvelope(bytes, (env) => {
    env.signers = env.signers.filter((s) => s.role !== "approver");
  });
  const result = await verifyCapsule(await CapsuleReader.fromBytes(stripped), {
    allowlist: [originator.publicKeyHex, approver.publicKeyHex],
  });
  assert.equal(result.ok, false);
  assert.equal(result.signerSet.bound, true);
  assert.equal(result.signerSet.ok, false);
  const joined = result.errors.join(" ");
  assert.match(joined, /signer_commitment/);
  assert.ok(joined.includes(approver.publicKeyHex), "error must name the missing approver key");
});

test("appended fresh signature in a chosen role fails closed", async () => {
  const { bytes, originator, approver } = await sealTwoSigners();
  const attacker = generateEd25519();
  const appended = await rewriteEnvelope(bytes, (env) => {
    const input = envelopeSigningInput(env, "notary");
    const sig = ed25519Sign(attacker.privateKey, input);
    env.signers.push({
      role: "notary",
      public_key: attacker.publicKeyHex,
      signature: bytesToHex(sig),
    });
  });
  const result = await verifyCapsule(await CapsuleReader.fromBytes(appended), {
    allowlist: [originator.publicKeyHex, approver.publicKeyHex],
  });
  assert.equal(result.ok, false);
  assert.equal(result.envelope.ok, true, "the forged notary signature itself verifies");
  assert.equal(result.signerSet.ok, false);
  assert.match(result.errors.join(" "), /signer_commitment/);
});

test("duplicated signer entry is malformed and does not inflate the count", async () => {
  const { bytes, originator, approver } = await sealTwoSigners();
  const duplicated = await rewriteEnvelope(bytes, (env) => {
    env.signers.push({ ...env.signers[0] });
  });
  const result = await verifyCapsule(await CapsuleReader.fromBytes(duplicated), {
    allowlist: [originator.publicKeyHex, approver.publicKeyHex],
  });
  assert.equal(result.ok, false);
  assert.equal(result.envelope.ok, false);
  assert.match(result.errors.join(" "), /duplicate signer/);
  assert.ok(result.trustedSignerCount <= 2, "duplicates must never inflate the trusted count");
});

test("role swap between two committed signers fails closed", async () => {
  // Both keys legitimately re-sign, but under each other's roles. Every
  // signature verifies; the set no longer matches the commitment.
  const { builder, originator, approver } = twoSignerBuilder();
  const sealed = await builder.seal({
    signers: [
      { role: "originator", publicKey: originator.publicKey, privateKey: originator.privateKey },
      { role: "approver", publicKey: approver.publicKey, privateKey: approver.privateKey },
    ],
    signedAt: TS,
  });
  const swapped = await rewriteEnvelope(sealed, (env) => {
    const byRole = Object.fromEntries(env.signers.map((s) => [s.role, s]));
    const reSign = (role, keys) => ({
      role,
      public_key: keys.publicKeyHex,
      signature: bytesToHex(ed25519Sign(keys.privateKey, envelopeSigningInput(env, role))),
    });
    // originator key now signs as approver; approver key as originator.
    env.signers = [reSign("approver", originator), reSign("originator", approver)];
    assert.ok(byRole.originator); // silence unused
  });
  const result = await verifyCapsule(await CapsuleReader.fromBytes(swapped), {
    allowlist: [originator.publicKeyHex, approver.publicKeyHex],
  });
  assert.equal(result.ok, false);
  assert.equal(result.signerSet.ok, false);
});

// ---------------------------------------------------------------------------
// Distinct-key counting
// ---------------------------------------------------------------------------

test("trustedSignerCount counts DISTINCT trusted keys, not rows", async () => {
  // The same key legitimately signing under two roles is two set members
  // but ONE trusted key.
  const { builder, originator } = twoSignerBuilder();
  const bytes = await builder.seal({
    signers: [
      { role: "originator", publicKey: originator.publicKey, privateKey: originator.privateKey },
      { role: "notary", publicKey: originator.publicKey, privateKey: originator.privateKey },
    ],
    signedAt: TS,
  });
  const result = await verifyCapsule(await CapsuleReader.fromBytes(bytes), {
    allowlist: [originator.publicKeyHex],
  });
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.equal(result.envelope.signers.length, 2);
  assert.equal(result.trustedSignerCount, 1);
});

// ---------------------------------------------------------------------------
// Absence reports (does not fail)
// ---------------------------------------------------------------------------

/** Seal a plain capsule via the low-level surface, with no signer_commitment. */
async function sealWithoutCommitment(keys, role = "originator") {
  const events = buildChainEvents([
    {
      actor: "human:alice",
      kind: "decision",
      action: "submit",
      target: "program.md",
      timestamp: TS,
      payload: {},
    },
  ]);
  const { firstEventHash, entryHash } = firstAndEntryHash(events);
  const files = new Map();
  files.set("program.md", Buffer.from("# Program\n", "utf8"));
  files.set("chain/events.jsonl", eventsToJsonl(events));
  const contentIndex = buildContentIndex(files);
  const manifest = buildManifest({
    originator: { public_key: keys.publicKeyHex, label: "Legacy" },
    participants: [{ actor_id: "human:alice", role: "originator", label: "Alice" }],
    contentIndex,
    firstEventHash,
    encryption: null,
    createdAt: TS,
  });
  const capsuleId = computeCapsuleId(hexToBytes(keys.publicKeyHex), firstEventHash);
  manifest.id = capsuleId;
  const envelope = buildEnvelope({
    capsuleId,
    firstEventHash,
    entryHash,
    manifestHash: manifestHash(manifest),
    contentIndexHash: contentIndex.index_hash,
    encryptedBlobHash: null,
    cipher: "none",
    signedAt: TS,
  });
  signEnvelope(envelope, [
    { role, publicKey: keys.publicKey, privateKey: keys.privateKey },
  ]);
  const all = new Map(files);
  all.set("manifest.json", manifestBytes(manifest));
  all.set("provenance/envelope.json", Buffer.from(JSON.stringify(envelope, null, 2), "utf8"));
  return Buffer.from(await packZip(all));
}

test("absent signer_commitment verifies and reports unbound", async () => {
  const keys = generateEd25519();
  const bytes = await sealWithoutCommitment(keys);
  const result = await verifyCapsule(await CapsuleReader.fromBytes(bytes), {
    allowlist: [keys.publicKeyHex],
  });
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.equal(result.signerSet.bound, false);
  assert.equal(result.signerSet.ok, true);
  assert.match(result.notes.join(" "), /signer_commitment absent/);
});

// ---------------------------------------------------------------------------
// Malformed commitment (present but wrong) fails closed
// ---------------------------------------------------------------------------

test("unsorted commitment with honest membership fails closed", async () => {
  // The commitment bytes are signed as stored, so the sort order is
  // normative: an unsorted commitment is malformed even when membership
  // matches.
  const originator = generateEd25519();
  const approver = generateEd25519();
  const events = buildChainEvents([
    {
      actor: "human:alice",
      kind: "decision",
      action: "submit",
      target: "program.md",
      timestamp: TS,
      payload: {},
    },
  ]);
  const { firstEventHash, entryHash } = firstAndEntryHash(events);
  const files = new Map();
  files.set("program.md", Buffer.from("# Program\n", "utf8"));
  files.set("chain/events.jsonl", eventsToJsonl(events));
  const contentIndex = buildContentIndex(files);
  const members = [
    { role: "originator", public_key: originator.publicKeyHex },
    { role: "approver", public_key: approver.publicKeyHex },
  ].sort((a, b) => (a.public_key < b.public_key ? -1 : 1));
  members.reverse(); // deliberately wrong order
  const manifest = buildManifest({
    originator: { public_key: originator.publicKeyHex, label: "Acme" },
    participants: [{ actor_id: "human:alice", role: "originator", label: "Alice" }],
    contentIndex,
    firstEventHash,
    encryption: null,
    createdAt: TS,
    signerCommitment: members,
  });
  const capsuleId = computeCapsuleId(hexToBytes(originator.publicKeyHex), firstEventHash);
  manifest.id = capsuleId;
  const envelope = buildEnvelope({
    capsuleId,
    firstEventHash,
    entryHash,
    manifestHash: manifestHash(manifest),
    contentIndexHash: contentIndex.index_hash,
    encryptedBlobHash: null,
    cipher: "none",
    signedAt: TS,
  });
  signEnvelope(envelope, [
    { role: "originator", publicKey: originator.publicKey, privateKey: originator.privateKey },
    { role: "approver", publicKey: approver.publicKey, privateKey: approver.privateKey },
  ]);
  const all = new Map(files);
  all.set("manifest.json", manifestBytes(manifest));
  all.set("provenance/envelope.json", Buffer.from(JSON.stringify(envelope, null, 2), "utf8"));
  const bytes = Buffer.from(await packZip(all));
  const result = await verifyCapsule(await CapsuleReader.fromBytes(bytes), {
    allowlist: [originator.publicKeyHex],
  });
  assert.equal(result.ok, false);
  assert.equal(result.signerSet.ok, false);
  assert.match(result.errors.join(" "), /signer_commitment.*sorted|sorted.*signer_commitment/);
});

// ---------------------------------------------------------------------------
// Originator binding (A03)
// ---------------------------------------------------------------------------

test("manifest originator that never signed as 'originator' fails closed", async () => {
  const keys = generateEd25519();
  // The originator's own key signs — but only under role "creator".
  const bytes = await sealWithoutCommitment(keys, "creator");
  const result = await verifyCapsule(await CapsuleReader.fromBytes(bytes), {
    allowlist: [keys.publicKeyHex],
  });
  assert.equal(result.ok, false);
  assert.match(result.errors.join(" "), /originator binding/);
});

test("originator role signed by a DIFFERENT key fails closed", async () => {
  const { builder, originator } = twoSignerBuilder();
  const impostor = generateEd25519();
  // Builder derives capsule_id from `originator`, but only the impostor signs.
  const bytes = await builder.seal({
    signers: [
      { role: "originator", publicKey: impostor.publicKey, privateKey: impostor.privateKey },
    ],
    signedAt: TS,
  });
  const result = await verifyCapsule(await CapsuleReader.fromBytes(bytes), {
    allowlist: [originator.publicKeyHex, impostor.publicKeyHex],
  });
  assert.equal(result.ok, false);
  assert.match(result.errors.join(" "), /originator binding/);
});

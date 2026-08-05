// Normalized result vocabulary (spec/results.md).
//
// Policy under test:
//   1. Every result carries verdict / verdictReason / qualifiers, with
//      ok == (verdict === "valid") as an invariant.
//   2. "unsupported" partitions refusals that are a limitation of THIS
//      verifier (unknown version — both directions — and unsupported
//      profile); verdictReason is non-null iff verdict is "unsupported".
//   3. qualifiers restate the weaker-claim facts of a VALID verdict in
//      the spec-defined order, each a pure derivation of an
//      already-reported fact; empty on invalid/unsupported.
//   4. The two trust qualifiers are host-relative and mutually
//      exclusive; encrypted_outer_only is per-result (never on the
//      inner L3 result); version_not_accepted_by_policy exists only
//      when the host declared a policy.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CapsuleBuilder,
  CapsuleReader,
  verifyCapsule,
  generateEd25519,
  generateX25519,
  buildContentIndex,
  buildManifest,
  buildEnvelope,
  CURRENT_VERSION,
} from "../src/index.js";
import { manifestBytes, manifestHash, computeCapsuleId } from "../src/manifest.js";
import { signEnvelope } from "../src/envelope.js";
import { packZip, unpackZip } from "../src/zip.js";

const TS = "2026-05-07T12:00:00Z";

async function sealedCapsule({ keys = generateEd25519(), participants, commitment = true } = {}) {
  const builder = new CapsuleBuilder({
    originator: { publicKey: keys.publicKeyHex, label: "Acme" },
    participants: participants ?? [{ actor_id: "human:alice", role: "originator", label: "Alice" }],
    createdAt: TS,
  });
  builder.setProgram("# Result vocabulary\n");
  builder.appendEvent({
    actor: participants?.length === 0 ? "system:host" : "human:alice",
    kind: "decision",
    action: "submit",
    target: "program.md",
    timestamp: TS,
    payload: { summary: "submitted" },
  });
  void commitment; // the SDK builder always commits; weaker shapes are hand-rolled below
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: keys.publicKey, privateKey: keys.privateKey }],
    signedAt: TS,
  });
  return { bytes: Buffer.from(bytes), keys };
}

/** Zero events, no commitment, no participants — the weakest honest shape. */
async function weakestHonestCapsule() {
  const keys = generateEd25519();
  const files = new Map();
  files.set("program.md", Buffer.from("# Weakest honest shape\n", "utf8"));
  files.set("chain/events.jsonl", Buffer.alloc(0));
  const contentIndex = buildContentIndex(files);
  const manifest = buildManifest({
    originator: { public_key: keys.publicKeyHex, label: "Acme" },
    participants: [],
    contentIndex,
    firstEventHash: null,
    encryption: null,
    createdAt: TS,
  });
  manifest.id = computeCapsuleId(keys.publicKey, null);
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
  signEnvelope(envelope, [
    { role: "originator", publicKey: keys.publicKey, privateKey: keys.privateKey },
  ]);
  const all = new Map(files);
  all.set("manifest.json", manifestBytes(manifest));
  all.set("provenance/envelope.json", Buffer.from(JSON.stringify(envelope, null, 2), "utf8"));
  return { bytes: Buffer.from(await packZip(all)), keys };
}

test("unqualified valid: the strongest honest shape has an empty qualifiers array", async () => {
  const { bytes, keys } = await sealedCapsule();
  const result = await verifyCapsule(bytes, { allowlist: [keys.publicKeyHex] });
  assert.equal(result.ok, true, result.errors.join("; "));
  assert.equal(result.verdict, "valid");
  assert.equal(result.verdictReason, null);
  assert.deepEqual(result.qualifiers, []);
});

test("ok == (verdict === 'valid') holds across outcome classes", async () => {
  const { bytes, keys } = await sealedCapsule();
  for (const [input, opts] of [
    [bytes, { allowlist: [keys.publicKeyHex] }],
    [bytes, {}],
    [Buffer.from("not a capsule"), {}],
  ]) {
    const r = await verifyCapsule(input, opts);
    assert.equal(r.ok, r.verdict === "valid", `invariant broke: ok=${r.ok} verdict=${r.verdict}`);
    assert.equal(
      r.verdictReason !== null,
      r.verdict === "unsupported",
      "verdictReason non-null iff unsupported",
    );
    if (r.verdict !== "valid") assert.deepEqual(r.qualifiers, []);
  }
});

test("maximally qualified valid: every weaker-claim fact reaches the verdict, in order", async () => {
  const { bytes } = await weakestHonestCapsule();
  const result = await verifyCapsule(bytes);
  assert.equal(result.ok, true, result.errors.join("; "));
  assert.equal(result.verdict, "valid");
  assert.deepEqual(result.qualifiers, [
    "signer_set_unbound",
    "actor_set_unbound",
    "empty_chain_not_walked",
    "trust_not_evaluated",
  ]);
  // The canonical notes back each qualifier (spec/results.md).
  const notes = result.notes.join(" | ");
  assert.ok(notes.includes("the signer set is not bound by the seal"));
  assert.ok(notes.includes("chain actors are not bound to a declared participant set"));
  assert.ok(notes.includes("no events to walk"));
  assert.ok(notes.includes("no allowlist provided"));
});

test("trust qualifiers are host-relative and mutually exclusive", async () => {
  const { bytes, keys } = await sealedCapsule();
  const stranger = generateEd25519();

  const noPolicy = await verifyCapsule(bytes);
  assert.deepEqual(noPolicy.qualifiers, ["trust_not_evaluated"]);

  const noMatch = await verifyCapsule(bytes, { allowlist: [stranger.publicKeyHex] });
  assert.deepEqual(noMatch.qualifiers, ["no_trusted_signer"]);
  assert.ok(
    noMatch.notes.some((n) => n.includes("matched no signer")),
    `the no-match advisory must accompany the qualifier: ${noMatch.notes.join("; ")}`,
  );

  const matched = await verifyCapsule(bytes, { allowlist: [keys.publicKeyHex] });
  assert.deepEqual(matched.qualifiers, []);
});

test("version_not_accepted_by_policy exists only when the host declared a policy", async () => {
  const { bytes, keys } = await sealedCapsule();
  const outside = await verifyCapsule(bytes, {
    allowlist: [keys.publicKeyHex],
    acceptVersions: ["0.6"],
  });
  assert.equal(outside.ok, true);
  assert.deepEqual(outside.qualifiers, ["version_not_accepted_by_policy"]);
  assert.ok(outside.notes.some((n) => n.includes("not in the declared accepted set")));

  const inside = await verifyCapsule(bytes, {
    allowlist: [keys.publicKeyHex],
    acceptVersions: [CURRENT_VERSION],
  });
  assert.deepEqual(inside.qualifiers, []);
});

test("encrypted_outer_only is per-result: on the L2 outer, never on the L3 inner", async () => {
  const keys = generateEd25519();
  const recipient = generateX25519();
  const builder = new CapsuleBuilder({
    originator: { publicKey: keys.publicKeyHex, label: "Acme" },
    participants: [{ actor_id: "human:alice", role: "originator", label: "Alice" }],
    createdAt: TS,
  });
  builder.setProgram("# Encrypted result vocabulary\n");
  builder.appendEvent({
    actor: "human:alice",
    kind: "decision",
    action: "submit",
    target: "program.md",
    timestamp: TS,
    payload: { summary: "submitted" },
  });
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: keys.publicKey, privateKey: keys.privateKey }],
    recipients: [recipient],
    signedAt: TS,
  });
  const reader = await CapsuleReader.fromBytes(bytes);
  const outer = await verifyCapsule(reader, { allowlist: [keys.publicKeyHex] });
  assert.equal(outer.ok, true, outer.errors.join("; "));
  assert.equal(outer.level, "L2");
  assert.deepEqual(outer.qualifiers, ["encrypted_outer_only"]);

  const inner = await reader.decrypt(recipient);
  const innerResult = await verifyCapsule(inner, {
    allowlist: [keys.publicKeyHex],
    outerEnvelope: reader.envelope(),
  });
  assert.equal(innerResult.ok, true, innerResult.errors.join("; "));
  assert.equal(innerResult.level, "L3");
  assert.ok(
    !innerResult.qualifiers.includes("encrypted_outer_only"),
    "the decrypted inner is a plain-capsule verification; the scope qualifier never carries over",
  );
});

test("unsupported: both version refusal directions carry machine-readable reasons", async () => {
  // Reuse the checked-in version-compat fixtures (internally coherent
  // under their declared eras) rather than re-rolling them here.
  const { readFile } = await import("node:fs/promises");
  const base = new URL("../../spec/vectors/version-compat/output/", import.meta.url);
  const newer = await verifyCapsule(await readFile(new URL("unknown-newer-version.capsule", base)));
  assert.equal(newer.verdict, "unsupported");
  assert.equal(newer.verdictReason, "unsupported_version_newer");
  assert.deepEqual(newer.qualifiers, []);

  const older = await verifyCapsule(await readFile(new URL("unknown-older-version.capsule", base)));
  assert.equal(older.verdict, "unsupported");
  assert.equal(older.verdictReason, "unsupported_version_older");

  // The ENVELOPE-side refusal also derives unsupported, even though the
  // manifest's observed version is known.
  const envSide = await verifyCapsule(
    await readFile(new URL("envelope-version-newer.capsule", base)),
  );
  assert.equal(envSide.verdict, "unsupported");
  assert.equal(envSide.verdictReason, "unsupported_version_newer");
  assert.equal(envSide.formatVersion.observed, "0.6");
});

test("invalid: tamper and malformation carry no reason and no qualifiers", async () => {
  const { bytes, keys } = await sealedCapsule();
  const files = await unpackZip(bytes);
  files.set("program.md", Buffer.from("# TAMPERED\n", "utf8"));
  const tampered = Buffer.from(await packZip(files));
  const result = await verifyCapsule(tampered, { allowlist: [keys.publicKeyHex] });
  assert.equal(result.ok, false);
  assert.equal(result.verdict, "invalid");
  assert.equal(result.verdictReason, null);
  assert.deepEqual(result.qualifiers, []);

  const garbage = await verifyCapsule(Buffer.from("zip? no."));
  assert.equal(garbage.verdict, "invalid");
  assert.equal(garbage.verdictReason, null);
  assert.equal(garbage.profile.status, "unread");
});

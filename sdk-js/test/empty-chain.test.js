// Empty-chain binding rule (spec/chain.md "Empty chains", F22):
//
//   - A chain with ZERO events is legal — the weakest honest shape
//     (a template or draft capsule that carries no events yet).
//   - When the chain is empty, the capsule must not claim chain anchors:
//     manifest.first_event_hash, envelope.first_event_hash and
//     envelope.entry_hash MUST all be null. Claiming an anchor over a
//     chain that has no events is the capsule lying about its own bytes
//     — an integrity violation, rejected fail-closed.
//   - capsule_id for a zero-event capsule is derived with 32 zero bytes
//     (the genesis prev-hash value) standing in for first_event_hash_raw.
//   - The reported result must be honest about what was and was not
//     checked: the per-event walk did not run, and the anchors were
//     checked for null instead.

import { test } from "node:test";
import assert from "node:assert/strict";

import { generateEd25519, verifyCapsule } from "../src/index.js";
import {
  buildContentIndex,
  buildManifest,
  buildSignerCommitment,
  computeCapsuleId,
  manifestBytes,
  manifestHash,
} from "../src/manifest.js";
import { buildEnvelope, signEnvelope } from "../src/envelope.js";
import { packZip } from "../src/zip.js";

const TS = "2026-08-01T12:00:00Z";

/**
 * Seal a capsule whose chain/events.jsonl is present but zero-length,
 * bypassing the builder (whose backstop rule always emits an event).
 * `firstEventHash` / `entryHash` / `manifestFirstEventHash` default to
 * the honest null shape; tests pass fake hex to make the capsule lie.
 */
async function sealEmptyChainCapsule({
  firstEventHash = null,
  entryHash = null,
  manifestFirstEventHash = null,
} = {}) {
  const ed = generateEd25519();
  const files = new Map();
  files.set("program.md", Buffer.from("# Draft\n\nNo events yet.\n", "utf8"));
  files.set("chain/events.jsonl", Buffer.alloc(0));
  const contentIndex = buildContentIndex(files);
  const manifest = buildManifest({
    originator: { public_key: ed.publicKeyHex, label: "Drafter" },
    participants: [{ actor_id: "human:drafter", role: "originator", label: "Drafter" }],
    contentIndex,
    firstEventHash: manifestFirstEventHash,
    encryption: null,
    createdAt: TS,
    signerCommitment: buildSignerCommitment([
      { role: "originator", public_key: ed.publicKeyHex },
    ]),
  });
  manifest.id = computeCapsuleId(ed.publicKey, manifestFirstEventHash);
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
  signEnvelope(envelope, [
    { role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey },
  ]);
  const all = new Map(files);
  all.set("manifest.json", manifestBytes(manifest));
  all.set("provenance/envelope.json", Buffer.from(JSON.stringify(envelope, null, 2), "utf8"));
  return { bytes: Buffer.from(await packZip(all)), ed };
}

test("computeCapsuleId substitutes 32 zero bytes when first_event_hash is null", () => {
  const ed = generateEd25519();
  const viaNull = computeCapsuleId(ed.publicKey, null);
  const viaZeroHex = computeCapsuleId(ed.publicKey, "0".repeat(64));
  assert.equal(viaNull, viaZeroHex, "null must derive exactly like the genesis zero hash");
});

test("empty chain with null anchors verifies (weakest honest shape)", async () => {
  const { bytes, ed } = await sealEmptyChainCapsule();
  const result = await verifyCapsule(bytes, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.equal(result.chain.ok, true, JSON.stringify(result.chain));
  assert.deepEqual(result.chain.errors, []);
  // Honest reporting: the walk did not run; the anchors were checked
  // for null instead — machine-readably, in both chain.note and notes.
  assert.match(result.chain.note ?? "", /empty chain/);
  assert.ok(
    result.notes.some((n) => n.includes("empty chain")),
    `expected an empty-chain note; got ${JSON.stringify(result.notes)}`,
  );
});

test("empty chain with claimed anchors fails closed", async () => {
  const { bytes, ed } = await sealEmptyChainCapsule({
    firstEventHash: "1".repeat(64),
    entryHash: "2".repeat(64),
    manifestFirstEventHash: "1".repeat(64),
  });
  const result = await verifyCapsule(bytes, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, false, "claimed anchors over zero events must not verify");
  for (const field of [
    "envelope.first_event_hash",
    "envelope.entry_hash",
    "manifest.first_event_hash",
  ]) {
    assert.ok(
      result.errors.some(
        (e) => e.includes(field) && e.includes("must be null when the chain has no events"),
      ),
      `expected a null-anchor violation for ${field}; got ${JSON.stringify(result.errors)}`,
    );
  }
});

test("chain with events but null envelope anchors still fails (reverse direction)", async () => {
  // A capsule whose chain HAS events must claim them: null anchors with a
  // non-empty chain surface as plain anchor mismatches.
  const { CapsuleBuilder } = await import("../src/index.js");
  const ed = generateEd25519();
  const builder = new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex, label: "Acme" },
    participants: [{ actor_id: "human:alice", role: "originator", label: "Alice" }],
    createdAt: TS,
  });
  builder.setProgram("# P\n");
  const sealed = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  const { unpackZip } = await import("../src/zip.js");
  const files = await unpackZip(sealed);
  const env = JSON.parse(Buffer.from(files.get("provenance/envelope.json")).toString("utf8"));
  env.first_event_hash = null;
  env.entry_hash = null;
  files.set("provenance/envelope.json", Buffer.from(JSON.stringify(env, null, 2), "utf8"));
  const bytes = Buffer.from(await packZip(files));
  const result = await verifyCapsule(bytes, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, false, "null anchors over a non-empty chain must not verify");
  assert.ok(
    result.errors.some((e) => e.includes("envelope.first_event_hash mismatch")),
    JSON.stringify(result.errors),
  );
});

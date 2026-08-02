// Semantic-binding tests: the manifest's CLAIMS must agree with the signed
// envelope, the chain, and the files. Each capsule below is well-formed,
// internally consistent, and correctly signed — only its semantics are wrong,
// so nothing but an explicit cross-check catches it.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CapsuleBuilder,
  CapsuleReader,
  verifyCapsule,
  generateEd25519,
  generateX25519,
} from "../src/index.js";
import { hexToBytes } from "../src/canonical.js";
import { signEnvelope } from "../src/envelope.js";
import {
  buildContentIndex,
  computeCapsuleId,
  contentIndexExclusions,
  manifestBytes,
  manifestHash,
} from "../src/manifest.js";
import { packZip, unpackZip } from "../src/zip.js";

const TS = "2026-05-07T12:00:00Z";
const dec = new TextDecoder();

async function sealedCapsule({ recipients = [] } = {}) {
  const ed = generateEd25519();
  const builder = new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex, label: "Acme" },
    participants: [{ actor_id: "human:alice", role: "originator", label: "Alice" }],
    createdAt: TS,
  });
  builder.setProgram("# Program\n");
  builder.appendEvent({
    actor: "human:alice",
    kind: "decision",
    action: "approved",
    target: "program.md",
    timestamp: TS,
    payload: { amount: 1 },
  });
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
    recipients,
  });
  return { bytes: Buffer.from(bytes), ed };
}

/** Mutate manifest/envelope, re-derive every writer-derived value, re-sign. */
async function resign(bytes, ed, mutate, { encrypted = false, rebuildIndex = false } = {}) {
  const files = await unpackZip(bytes);
  const manifest = JSON.parse(dec.decode(files.get("manifest.json")));
  const envelope = JSON.parse(dec.decode(files.get("provenance/envelope.json")));
  mutate({ manifest, envelope, files });
  if (rebuildIndex) {
    const excluded = contentIndexExclusions(encrypted);
    const indexFiles = new Map();
    for (const [path, data] of files.entries()) {
      if (path === "manifest.json" || path === "provenance/envelope.json") continue;
      indexFiles.set(path, data);
    }
    manifest.content_index = buildContentIndex(indexFiles, excluded);
    envelope.content_index_hash = manifest.content_index.index_hash;
  }
  manifest.id = computeCapsuleId(
    hexToBytes(manifest.originator.public_key),
    manifest.first_event_hash,
  );
  envelope.capsule_id = manifest.id;
  files.set("manifest.json", manifestBytes(manifest));
  envelope.manifest_hash = manifestHash(manifest);
  envelope.signers = [];
  signEnvelope(envelope, [
    { role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey },
  ]);
  files.set("provenance/envelope.json", Buffer.from(JSON.stringify(envelope, null, 2), "utf8"));
  return Buffer.from(await packZip(files));
}

test("verifier rejects manifest.first_event_hash that disagrees with the envelope", async () => {
  const { bytes, ed } = await sealedCapsule();
  const drifted = await resign(bytes, ed, ({ manifest }) => {
    manifest.first_event_hash = "de".repeat(32);
  });
  const reader = await CapsuleReader.fromBytes(drifted);
  const result = await verifyCapsule(reader, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, false, "decoy manifest.first_event_hash must not verify");
  assert.ok(
    result.errors.some((e) => /manifest\.first_event_hash mismatch/.test(e)),
    `expected a first_event_hash binding error, got: ${JSON.stringify(result.errors)}`,
  );
});

test("verifier rejects manifest.encryption declared on a cipher='none' capsule", async () => {
  const { bytes, ed } = await sealedCapsule();
  const lying = await resign(bytes, ed, ({ manifest }) => {
    manifest.encryption = {
      metadata_path: "skills/decryption/decryption.json",
      cipher: "ChaCha20-Poly1305",
    };
  });
  const reader = await CapsuleReader.fromBytes(lying);
  const result = await verifyCapsule(reader, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, false, "plain capsule declaring encryption must not verify");
  assert.ok(
    result.errors.some((e) => /manifest\.encryption must be null/.test(e)),
    `expected an encryption-shape error, got: ${JSON.stringify(result.errors)}`,
  );
});

test("verifier rejects a metadata_path that is not in the package", async () => {
  const recipient = generateX25519();
  const { bytes, ed } = await sealedCapsule({ recipients: [{ publicKey: recipient.publicKey }] });
  const dangling = await resign(bytes, ed, ({ manifest }) => {
    manifest.encryption.metadata_path = "skills/decryption/absent.json";
  });
  const reader = await CapsuleReader.fromBytes(dangling);
  const result = await verifyCapsule(reader, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, false, "dangling metadata_path must not verify");
  assert.ok(
    result.errors.some((e) => /metadata_path missing from capsule/.test(e)),
    `expected a metadata_path error, got: ${JSON.stringify(result.errors)}`,
  );
});

test("relocated decryption metadata verifies and decrypts via the declared path", async () => {
  const recipient = generateX25519();
  const { bytes, ed } = await sealedCapsule({ recipients: [{ publicKey: recipient.publicKey }] });
  const relocated = await resign(
    bytes,
    ed,
    ({ manifest, files }) => {
      const meta = files.get("skills/decryption/decryption.json");
      files.delete("skills/decryption/decryption.json");
      files.set("skills/decryption/keys-v2.json", meta);
      manifest.encryption.metadata_path = "skills/decryption/keys-v2.json";
    },
    { encrypted: true, rebuildIndex: true },
  );
  const reader = await CapsuleReader.fromBytes(relocated);
  const result = await verifyCapsule(reader, { allowlist: [ed.publicKeyHex] });
  assert.equal(
    result.ok,
    true,
    `relocated metadata_path must verify, got: ${JSON.stringify(result.errors)}`,
  );
  const inner = await reader.decrypt({
    recipientPublicKey: recipient.publicKey,
    recipientPrivateKey: recipient.privateKey,
  });
  const innerResult = await verifyCapsule(inner, { allowlist: [ed.publicKeyHex] });
  assert.equal(innerResult.ok, true, "inner capsule must verify after decrypting");
});

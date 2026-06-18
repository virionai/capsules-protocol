#!/usr/bin/env node
// generate-tamper-fixtures.mjs
//
// Re-baselines the cross-implementation tamper-detection conformance
// fixtures on a FRESH keypair (the original signing key is lost). This
// script uses ONLY the SDK's own crypto + builder helpers — no hand-rolled
// crypto — so the fixtures match exactly what the JS reference produces.
//
// Output (written under spec/vectors/tamper-detection/output/):
//   clean.capsule              plain, untampered, must verify at L2
//   tampered-payload.capsule   one byte flipped in program.md
//   tampered-chain.capsule     one byte flipped in chain/events.jsonl
//   tampered-envelope.capsule  one byte flipped in an envelope signature
//   clean-encrypted.capsule    encrypted, untampered, single recipient
//   tampered-blob.capsule      one byte flipped in content.enc
//   keys.json                  {originator,recipient} pub+priv hex
//
// The TEST private keys in keys.json are intentional throwaway conformance
// fixtures — never production keys.

import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  CapsuleBuilder,
  generateEd25519,
  generateX25519,
  bytesToHex,
  hexToBytes,
} from "../src/index.js";
import { packZip, unpackZip } from "../src/zip.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..");
const OUT_DIR = join(REPO_ROOT, "spec", "vectors", "tamper-detection", "output");

// Deterministic timestamps keep the fixtures stable across regenerations
// (only the keypair changes between re-baselines).
const SIGNED_AT = "2026-05-08T12:00:00Z";

/** Flip the lowest bit of a single byte at `index` in a Buffer copy. */
function flipByte(buf, index) {
  const copy = Buffer.from(buf);
  copy[index] ^= 0x01;
  return copy;
}

/**
 * Rebuild a capsule ZIP with one inner file replaced by `mutate(bytes)`.
 * Preserves all other entries verbatim.
 */
async function rewriteInnerFile(capsuleBytes, path, mutate) {
  const files = await unpackZip(capsuleBytes);
  if (!files.has(path)) {
    throw new Error(`inner file not found in capsule: ${path}`);
  }
  const original = Buffer.from(files.get(path));
  files.set(path, Buffer.from(mutate(original)));
  return Buffer.from(await packZip(files));
}

function buildPlainCapsule(originator, signer) {
  const builder = new CapsuleBuilder({
    originator: { publicKey: originator.publicKeyHex, label: "ConformanceOriginator" },
    participants: [{ actor_id: "human:origin", role: "originator", label: "Origin" }],
    createdAt: SIGNED_AT,
  });
  builder.setProgram("# Conformance Program\n\nClean tamper-detection fixture.\n");
  builder.appendEvent({
    actor: "human:origin",
    kind: "decision",
    action: "approved",
    target: "program.md",
    timestamp: SIGNED_AT,
    payload: { amount: 4242, note: "clean fixture event" },
  });
  return builder.seal({ signers: [signer], signedAt: SIGNED_AT });
}

function buildEncryptedCapsule(originator, signer, recipient) {
  const builder = new CapsuleBuilder({
    originator: { publicKey: originator.publicKeyHex, label: "ConformanceOriginator" },
    participants: [{ actor_id: "human:origin", role: "originator", label: "Origin" }],
    createdAt: SIGNED_AT,
  });
  builder.setProgram("# Encrypted Conformance Program\n\nClean encrypted fixture.\n");
  builder.appendEvent({
    actor: "human:origin",
    kind: "decision",
    action: "approved",
    target: "program.md",
    timestamp: SIGNED_AT,
    payload: { amount: 9001, note: "clean encrypted fixture event" },
  });
  return builder.seal({
    signers: [signer],
    signedAt: SIGNED_AT,
    recipients: [{ publicKey: recipient.publicKey }],
  });
}

async function main() {
  await mkdir(OUT_DIR, { recursive: true });

  // (a) Fresh Ed25519 (signing) + X25519 (recipient) keypairs via the SDK.
  const originator = generateEd25519();
  const recipient = generateX25519();

  const signer = {
    role: "originator",
    publicKey: originator.publicKey,
    privateKey: originator.privateKey,
  };

  // (b) Clean plain + clean encrypted capsules.
  const cleanPlain = Buffer.from(await buildPlainCapsule(originator, signer));
  const cleanEncrypted = Buffer.from(
    await buildEncryptedCapsule(originator, signer, recipient),
  );

  // (c) Tampered variants — exactly one byte flipped in each.

  // tampered-payload: flip a byte in program.md content.
  const tamperedPayload = await rewriteInnerFile(cleanPlain, "program.md", (b) =>
    flipByte(b, Math.floor(b.length / 2)),
  );

  // tampered-chain: flip a byte in chain/events.jsonl.
  const tamperedChain = await rewriteInnerFile(cleanPlain, "chain/events.jsonl", (b) =>
    flipByte(b, Math.floor(b.length / 2)),
  );

  // tampered-envelope: flip one byte inside an envelope signature (hex).
  const tamperedEnvelope = await rewriteInnerFile(
    cleanPlain,
    "provenance/envelope.json",
    (b) => {
      const env = JSON.parse(b.toString("utf8"));
      if (!env.signers?.length) throw new Error("envelope has no signers to tamper");
      const sigHex = env.signers[0].signature;
      const sigBytes = flipByte(Buffer.from(hexToBytes(sigHex)), 0);
      env.signers[0].signature = bytesToHex(sigBytes);
      return Buffer.from(JSON.stringify(env, null, 2), "utf8");
    },
  );

  // tampered-blob: flip a byte in the encrypted content.enc blob.
  const tamperedBlob = await rewriteInnerFile(cleanEncrypted, "content.enc", (b) =>
    flipByte(b, Math.floor(b.length / 2)),
  );

  // (d) keys.json — fresh throwaway TEST keys (intentional re-baseline).
  const keys = {
    originator: {
      publicKey: originator.publicKeyHex,
      privateKey: originator.privateKeyHex,
    },
    recipient: {
      publicKey: recipient.publicKeyHex,
      privateKey: recipient.privateKeyHex,
    },
  };

  // (e) Write all artifacts.
  const artifacts = [
    ["clean.capsule", cleanPlain],
    ["tampered-payload.capsule", tamperedPayload],
    ["tampered-chain.capsule", tamperedChain],
    ["tampered-envelope.capsule", tamperedEnvelope],
    ["clean-encrypted.capsule", cleanEncrypted],
    ["tampered-blob.capsule", tamperedBlob],
    ["keys.json", Buffer.from(JSON.stringify(keys, null, 2) + "\n", "utf8")],
  ];

  for (const [name, bytes] of artifacts) {
    await writeFile(join(OUT_DIR, name), bytes);
    console.log(`wrote ${name} (${bytes.length} bytes)`);
  }

  console.log(`\noriginator pubkey: ${originator.publicKeyHex}`);
  console.log(`recipient pubkey:  ${recipient.publicKeyHex}`);
  console.log(`output dir:        ${OUT_DIR}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

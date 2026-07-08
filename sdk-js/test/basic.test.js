import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CapsuleBuilder,
  CapsuleReader,
  verifyCapsule,
  generateEd25519,
  generateX25519,
} from "../src/index.js";

const TS = "2026-05-07T12:00:00Z";

function basicBuilder() {
  const ed = generateEd25519();
  const builder = new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex, label: "Acme" },
    participants: [
      { actor_id: "human:alice", role: "originator", label: "Alice" },
    ],
    createdAt: TS,
  });
  builder.setProgram("# Loan Application\nApplicant: Alice\nAmount: $100\n");
  builder.setAgents("# Agents\n- human:alice (originator)\n");
  builder.appendEvent({
    actor: "human:alice",
    kind: "decision",
    action: "submit",
    target: "program.md",
    timestamp: TS,
    payload: { summary: "Alice submitted the application" },
  });
  return { builder, ed };
}

test("plain seal → read → verify roundtrip", async () => {
  const { builder, ed } = basicBuilder();
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  const reader = await CapsuleReader.fromBytes(bytes);
  assert.equal(reader.isEncrypted(), false);
  assert.equal(reader.manifest().format.version, "0.6");
  assert.equal(reader.manifest().originator.public_key, ed.publicKeyHex);
  assert.match(reader.program(), /Loan Application/);
  const result = await verifyCapsule(reader, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, true);
  assert.equal(result.level, "L2");
  assert.equal(result.trustedSignerCount, 1);
});

test("verify fails when allowlist excludes signer (signature still valid)", async () => {
  const { builder, ed } = basicBuilder();
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  const reader = await CapsuleReader.fromBytes(bytes);
  const result = await verifyCapsule(reader, { allowlist: [] });
  // ok=true (math), trusted=false (no allowlist hit)
  assert.equal(result.envelope.ok, true);
  assert.equal(result.trustedSignerCount, 0);
});

test("encrypted seal → decrypt → verify L2 and L3", async () => {
  const { builder, ed } = basicBuilder();
  const recipient = generateX25519();
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    recipients: [{ publicKey: recipient.publicKey }],
    signedAt: TS,
  });

  const outer = await CapsuleReader.fromBytes(bytes);
  assert.equal(outer.isEncrypted(), true);
  const l2 = await verifyCapsule(outer, { allowlist: [ed.publicKeyHex] });
  assert.equal(l2.ok, true, JSON.stringify(l2.errors));
  assert.equal(l2.level, "L2");

  const inner = await outer.decrypt({
    recipientPublicKey: recipient.publicKey,
    recipientPrivateKey: recipient.privateKey,
  });
  assert.equal(inner.isEncrypted(), false);
  assert.match(inner.program(), /Loan Application/);

  const l3 = await verifyCapsule(inner, {
    allowlist: [ed.publicKeyHex],
    outerEnvelope: outer.envelope(),
  });
  assert.equal(l3.ok, true, JSON.stringify(l3.errors));
  assert.equal(l3.level, "L3");
});

test("envelope refuses unknown cipher", async () => {
  const { builder, ed } = basicBuilder();
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  // Mutate envelope cipher and re-pack — should fail verification
  const { unpackZip } = await import("../src/zip.js");
  const { packZip } = await import("../src/zip.js");
  const files = await unpackZip(bytes);
  const env = JSON.parse(Buffer.from(files.get("provenance/envelope.json")).toString("utf8"));
  env.cipher = "AES-256-GCM";
  files.set("provenance/envelope.json", Buffer.from(JSON.stringify(env, null, 2), "utf8"));
  const tampered = await packZip(files);
  const reader = await CapsuleReader.fromBytes(tampered);
  const result = await verifyCapsule(reader, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, false);
  assert.ok(result.envelope.ok === false || result.errors.some((e) => /cipher/i.test(e)));
});

test("tampered program.md fails content index", async () => {
  const { builder, ed } = basicBuilder();
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  const { unpackZip, packZip } = await import("../src/zip.js");
  const files = await unpackZip(bytes);
  files.set("program.md", Buffer.from("# Loan Application\nApplicant: Mallory\n", "utf8"));
  const tampered = await packZip(files);
  const reader = await CapsuleReader.fromBytes(tampered);
  const result = await verifyCapsule(reader, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, false);
  assert.equal(result.contentIndex.ok, false);
});

test("tampered chain event fails chain verification", async () => {
  const { builder, ed } = basicBuilder();
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  const { unpackZip, packZip } = await import("../src/zip.js");
  const files = await unpackZip(bytes);
  const eventsBytes = files.get("chain/events.jsonl");
  const text = Buffer.from(eventsBytes).toString("utf8");
  const tamperedText = text.replace(/Alice submitted/, "Mallory submitted");
  files.set("chain/events.jsonl", Buffer.from(tamperedText, "utf8"));
  // Re-pack — content index will also break, but the chain should also break.
  const tampered = await packZip(files);
  const reader = await CapsuleReader.fromBytes(tampered);
  const result = await verifyCapsule(reader, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, false);
  // Either contentIndex or chain (or both) should reject
  assert.ok(!result.contentIndex.ok || !result.chain.ok);
});

test("tampered envelope signature fails signature verification", async () => {
  const { builder, ed } = basicBuilder();
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  const { unpackZip, packZip } = await import("../src/zip.js");
  const files = await unpackZip(bytes);
  const env = JSON.parse(Buffer.from(files.get("provenance/envelope.json")).toString("utf8"));
  // Flip one byte in the signature
  const sig = env.signers[0].signature;
  const flipped = sig.slice(0, -2) + (sig.slice(-2) === "ff" ? "00" : "ff");
  env.signers[0].signature = flipped;
  files.set("provenance/envelope.json", Buffer.from(JSON.stringify(env, null, 2), "utf8"));
  const tampered = await packZip(files);
  const reader = await CapsuleReader.fromBytes(tampered);
  const result = await verifyCapsule(reader, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, false);
  assert.equal(result.envelope.ok, false);
});

test("tampered encrypted blob fails AEAD on decrypt", async () => {
  const { builder, ed } = basicBuilder();
  const recipient = generateX25519();
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    recipients: [{ publicKey: recipient.publicKey }],
    signedAt: TS,
  });
  const { unpackZip, packZip } = await import("../src/zip.js");
  const files = await unpackZip(bytes);
  const blob = Buffer.from(files.get("content.enc"));
  blob[10] = blob[10] ^ 0xff;
  files.set("content.enc", blob);
  const tampered = await packZip(files);
  const outer = await CapsuleReader.fromBytes(tampered);
  // L2 catches it at encrypted_blob_hash
  const l2 = await verifyCapsule(outer, { allowlist: [ed.publicKeyHex] });
  assert.equal(l2.ok, false);
  // And decrypt fails authentication
  await assert.rejects(() =>
    outer.decrypt({
      recipientPublicKey: recipient.publicKey,
      recipientPrivateKey: recipient.privateKey,
    }),
  );
});

test("smuggled content.enc in a plain capsule fails verification", async () => {
  // A signed plain capsule (cipher="none") must not carry an unaccounted-for
  // content.enc blob past verification. content.enc is only excluded from the
  // content index for capsules that declare a cipher.
  const { builder, ed } = basicBuilder();
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  const { unpackZip, packZip } = await import("../src/zip.js");
  const files = await unpackZip(bytes);
  files.set("content.enc", Buffer.from("smuggled payload, covered by no hash"));
  const tampered = await packZip(files);
  const result = await verifyCapsule(await CapsuleReader.fromBytes(tampered), {
    allowlist: [ed.publicKeyHex],
  });
  assert.equal(result.ok, false);
  assert.equal(result.contentIndex.ok, false);
  assert.ok(result.contentIndex.errors.some((e) => e.includes("content.enc")));
});

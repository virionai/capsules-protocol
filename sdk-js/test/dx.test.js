// Developer-experience surface tests (2026-07-20):
//   - keypair objects work directly as originator / signer / recipient
//   - every key input accepts hex strings or raw bytes interchangeably
//   - seal() defaults signedAt; appendEvent() defaults kind/target/timestamp
//   - verifyCapsule() accepts raw bytes and fails closed on garbage
//   - decrypt() accepts a keypair object
//
// These pin the quickstart path in the README: if one of these breaks,
// the copy-paste onboarding flow breaks.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CapsuleBuilder,
  CapsuleReader,
  verifyCapsule,
  generateEd25519,
  generateX25519,
} from "../src/index.js";

test("quickstart: keypair object end-to-end with all defaults", async () => {
  const keys = generateEd25519();

  const bytes = await new CapsuleBuilder({ originator: { ...keys, label: "MyApp" } })
    .setProgram("# Hello capsule\n")
    .appendEvent({ actor: "human:me", action: "created_note" })
    .seal({ signers: keys });

  // verify straight from bytes, allowlisting the raw public key
  const result = await verifyCapsule(bytes, { allowlist: [keys.publicKey] });
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.equal(result.trustedSignerCount, 1);

  const reader = await CapsuleReader.fromBytes(bytes);
  const [event] = reader.events();
  assert.equal(event.kind, "observation");
  assert.equal(event.target, "capsule");
  assert.match(event.timestamp, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  assert.equal(reader.envelope().signers[0].role, "originator");
  assert.match(reader.envelope().signed_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
});

test("hex keys are accepted everywhere raw bytes are", async () => {
  const keys = generateEd25519();

  const bytes = await new CapsuleBuilder({
    originator: { publicKey: keys.publicKeyHex.toUpperCase(), label: "HexApp" },
  })
    .setProgram("# Hex\n")
    .appendEvent({ actor: "human:me", action: "noted" })
    .seal({
      signers: [{ role: "originator", publicKey: keys.publicKeyHex, privateKey: keys.privateKeyHex }],
    });

  const result = await verifyCapsule(bytes, { allowlist: [keys.publicKeyHex.toUpperCase()] });
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.equal(result.trustedSignerCount, 1);
  // wire format stays lowercase regardless of input case
  const reader = await CapsuleReader.fromBytes(bytes);
  assert.equal(reader.manifest().originator.public_key, keys.publicKeyHex);
});

test("verifyCapsule on garbage bytes fails closed, no throw", async () => {
  const result = await verifyCapsule(Buffer.from("this is not a capsule"));
  assert.equal(result.ok, false);
  assert.equal(result.trustedSignerCount, 0);
  assert.match(result.errors[0], /cannot be opened/);
});

test("encrypt/decrypt round-trip with keypair objects only", async () => {
  const signer = generateEd25519();
  const recipient = generateX25519();

  const bytes = await new CapsuleBuilder({ originator: { ...signer, label: "Enc" } })
    .setProgram("# Secret\n")
    .appendEvent({ actor: "human:me", action: "wrote_secret" })
    .seal({ signers: signer, recipients: recipient });

  const outer = await CapsuleReader.fromBytes(bytes);
  assert.equal(outer.isEncrypted(), true);

  const l2 = await verifyCapsule(bytes, { allowlist: [signer.publicKeyHex] });
  assert.equal(l2.ok, true, JSON.stringify(l2.errors));
  assert.equal(l2.level, "L2");

  const inner = await outer.decrypt(recipient);
  assert.equal(inner.program(), "# Secret\n");

  const l3 = await verifyCapsule(inner, {
    allowlist: [signer.publicKeyHex],
    outerEnvelope: outer.envelope(),
  });
  assert.equal(l3.ok, true, JSON.stringify(l3.errors));
  assert.equal(l3.level, "L3");
});

test("recipient as bare hex string also works", async () => {
  const signer = generateEd25519();
  const recipient = generateX25519();

  const bytes = await new CapsuleBuilder({ originator: signer })
    .setProgram("# Secret\n")
    .appendEvent({ actor: "human:me", action: "wrote_secret" })
    .seal({ signers: signer, recipients: [recipient.publicKeyHex] });

  const outer = await CapsuleReader.fromBytes(bytes);
  const inner = await outer.decrypt({
    recipientPublicKey: recipient.publicKeyHex,
    recipientPrivateKey: recipient.privateKeyHex,
  });
  assert.equal(inner.program(), "# Secret\n");
});

test("helpful errors on missing signer key material", async () => {
  const keys = generateEd25519();
  const builder = new CapsuleBuilder({ originator: keys }).setProgram("# X\n");
  await assert.rejects(() => builder.seal({}), /at least one signer/);
  await assert.rejects(
    () => builder.seal({ signers: [{ role: "originator" }] }),
    /publicKey and privateKey/,
  );
});

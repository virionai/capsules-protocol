// Cross-curve key confusion at the API boundary (finding A04).
//
// Ed25519 and X25519 keypair objects are structurally identical
// ({ publicKey, privateKey, publicKeyHex, privateKeyHex }), and X25519
// clamps and accepts any 32-byte u-coordinate, so ECDH against an
// Ed25519 public key "succeeds" and produces a wrapped key the holder
// of the Ed25519 private key can never unwrap. Nothing errors until a
// decryption attempt — potentially years after sealing. Seal-time
// round-trip verification CANNOT catch it (the sealer has no recipient
// private key, and the DH result looks normal), and the key types are
// indistinguishable from bytes. The only fix is typed key material:
// keypair objects carry a `curve` tag at generation, and the
// normalizers reject a mismatched (or, for recipients, missing) tag on
// the object path. Raw hex and raw bytes stay untagged and accepted —
// the caller who extracts bytes is asserting the curve themselves.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CapsuleBuilder,
  CapsuleReader,
  generateEd25519,
  generateX25519,
} from "../src/index.js";
import { toRecipient, toSigner } from "../src/keys.js";

function draftBuilder(keys) {
  return new CapsuleBuilder({ originator: keys })
    .setProgram("# Secret\n")
    .appendEvent({ actor: "human:me", action: "wrote_secret" });
}

test("generated keypairs carry a curve tag", () => {
  assert.equal(generateEd25519().curve, "ed25519");
  assert.equal(generateX25519().curve, "x25519");
});

test("an Ed25519 keypair is rejected as an encryption recipient", async () => {
  const ed = generateEd25519();
  // The exact CHANGELOG-advertised path: keypair objects work as-is as
  // recipients. Sealing to an Ed25519 key would encrypt to a key that
  // can never decrypt — unrecoverable content, no error until then.
  assert.throws(() => toRecipient(ed), /ed25519/);
  await assert.rejects(
    () => draftBuilder(ed).seal({ signers: ed, recipients: [ed] }),
    /ed25519/,
  );
});

test("an X25519 keypair is rejected as a signer", async () => {
  const ed = generateEd25519();
  const x = generateX25519();
  assert.throws(() => toSigner(x), /x25519/);
  await assert.rejects(
    () => draftBuilder(ed).seal({ signers: x }),
    /x25519/,
  );
});

test("an untagged keypair-shaped object is rejected as a recipient", () => {
  // A keypair object with the tag stripped (e.g. round-tripped through
  // JSON serialized before tagging existed) is indistinguishable from
  // the Ed25519 hazard, so the branded path is the ONLY object path:
  // full keypair objects must carry curve: "x25519".
  const x = generateX25519();
  assert.throws(
    () => toRecipient({ publicKey: x.publicKey, privateKey: x.privateKey }),
    /curve/,
  );
  assert.throws(
    () => toRecipient({ publicKeyHex: x.publicKeyHex, privateKeyHex: x.privateKeyHex }),
    /curve/,
  );
});

test("public-key-only and raw forms stay accepted (cannot do better)", () => {
  const x = generateX25519();
  // { publicKey } without private material is equivalent to handing over
  // raw bytes: the caller extracted the key, asserting the curve.
  assert.deepEqual(toRecipient({ publicKey: x.publicKey }).publicKey, Buffer.from(x.publicKey));
  assert.deepEqual(toRecipient(x.publicKeyHex).publicKey, Buffer.from(x.publicKey));
  assert.deepEqual(toRecipient(x.publicKey).publicKey, Buffer.from(x.publicKey));
});

test("untagged {role, publicKey, privateKey} signer dicts stay accepted", () => {
  // The documented dict form for signers. A cross-curve mistake here
  // fails loudly at first verification (the stored public key does not
  // match the signature), so the untagged form is not a silent hazard.
  const ed = generateEd25519();
  const s = toSigner({ role: "approver", publicKey: ed.publicKeyHex, privateKey: ed.privateKeyHex });
  assert.equal(s.role, "approver");
});

test("tagged X25519 keypair still seals and decrypts end-to-end", async () => {
  const ed = generateEd25519();
  const x = generateX25519();
  const bytes = await draftBuilder(ed).seal({ signers: ed, recipients: [x] });
  const outer = await CapsuleReader.fromBytes(bytes);
  const inner = await outer.decrypt(x);
  assert.equal(inner.program(), "# Secret\n");
});

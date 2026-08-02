// Ed25519 key/signature validation (added 2026-08-01):
//   - the 8 small-subgroup public keys are refused
//   - non-canonical 32-byte key encodings (masked y >= p) are refused
//   - a signature whose S is not reduced mod L is refused
//   - RFC 8032 test 2 still verifies
//
// Each negative triple is a witness: node:crypto's raw verify accepts it,
// with no private key involved. Vary any signed envelope field until the
// cofactored verification equation holds and the forgery is complete.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  ed25519PublicKeyIsAcceptable,
  ed25519SignatureSIsReduced,
  ed25519Verify,
} from "../src/crypto.js";

// [public key, signature R half, probe index] — message is
// `capsule-low-order-probe-<probe>`, signature is R || 32 zero bytes.
const SMALL_ORDER_WITNESSES = [
  ["0000000000000000000000000000000000000000000000000000000000000000",
   "0000000000000000000000000000000000000000000000000000000000000000", 5],
  ["0000000000000000000000000000000000000000000000000000000000000080",
   "0000000000000000000000000000000000000000000000000000000000000000", 0],
  ["0100000000000000000000000000000000000000000000000000000000000000",
   "0100000000000000000000000000000000000000000000000000000000000000", 0],
  ["26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
   "0000000000000000000000000000000000000000000000000000000000000000", 8],
  ["26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
   "0000000000000000000000000000000000000000000000000000000000000000", 3],
  ["c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
   "0000000000000000000000000000000000000000000000000000000000000000", 3],
  ["c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
   "0000000000000000000000000000000000000000000000000000000000000000", 15],
  ["ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
   "0100000000000000000000000000000000000000000000000000000000000000", 0],
  ["ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
   "0100000000000000000000000000000000000000000000000000000000000000", 0],
  ["edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
   "0000000000000000000000000000000000000000000000000000000000000000", 1],
  ["eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
   "0100000000000000000000000000000000000000000000000000000000000000", 0],
  ["0100000000000000000000000000000000000000000000000000000000000080",
   "0100000000000000000000000000000000000000000000000000000000000000", 0],
];

const RFC_PUBLIC_KEY = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
const RFC_MESSAGE = "72";
const RFC_SIGNATURE =
  "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
  "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";
const RFC_SIGNATURE_S_PLUS_L =
  "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
  "f52db7415978abc61b2c2eb6aeebfca0387b2eaeb4302aeeb00d291612bb0c10";

test("small-order and non-canonical public keys are refused", () => {
  for (const [publicKeyHex, rHex, probe] of SMALL_ORDER_WITNESSES) {
    const publicKey = Buffer.from(publicKeyHex, "hex");
    const message = Buffer.from(`capsule-low-order-probe-${probe}`, "utf8");
    const signature = Buffer.concat([Buffer.from(rHex, "hex"), Buffer.alloc(32)]);
    assert.equal(ed25519PublicKeyIsAcceptable(publicKey), false, publicKeyHex);
    assert.equal(ed25519Verify(publicKey, message, signature), false, publicKeyHex);
  }
});

test("a signature with a non-reduced S is refused", () => {
  const publicKey = Buffer.from(RFC_PUBLIC_KEY, "hex");
  const message = Buffer.from(RFC_MESSAGE, "hex");
  assert.equal(
    ed25519SignatureSIsReduced(Buffer.from(RFC_SIGNATURE_S_PLUS_L, "hex")),
    false,
  );
  assert.equal(
    ed25519Verify(publicKey, message, Buffer.from(RFC_SIGNATURE_S_PLUS_L, "hex")),
    false,
  );
});

test("RFC 8032 test 2 still verifies", () => {
  assert.equal(
    ed25519Verify(
      Buffer.from(RFC_PUBLIC_KEY, "hex"),
      Buffer.from(RFC_MESSAGE, "hex"),
      Buffer.from(RFC_SIGNATURE, "hex"),
    ),
    true,
  );
});

#!/usr/bin/env node
// generate-ed25519-key-validation-vector.mjs
//
// Emits spec/vectors/ed25519-key-validation.json: the negative registry
// for Ed25519 key and signature validation.
//
// Every negative vector pins a (public_key, message, signature) triple
// that an UNGUARDED Ed25519 verifier accepts — the triples are searched
// for here against node:crypto's raw verify, so the fixtures are
// witnesses, not merely assertions. A conforming implementation MUST
// report valid=false for all of them:
//
//   - the 8 points whose order divides 8 (small-subgroup forgery: no
//     private key needed, just vary a signed field until the cofactored
//     equation holds)
//   - non-canonical 32-byte encodings (masked y >= p)
//   - a signature whose S component is not reduced mod L
//
// plus one positive control (RFC 8032 test 2) so a verifier that simply
// returns false cannot pass the registry.
//
// Pass --check to compare generated output with the checked-in vector.

import { readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verify as nodeVerify } from "node:crypto";

import { ed25519PublicFromRaw } from "../src/crypto.js";
import { CURRENT_VERSION } from "../src/versions.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..");
const VECTORS = join(REPO_ROOT, "spec", "vectors");
const CHECK = process.argv.includes("--check");

// Ed25519 group order L, for the non-reduced-S fixture.
const ED25519_L = (1n << 252n) + 27742317777372353535851937790883648493n;

// The 8 canonical encodings of the points whose order divides 8, plus the
// non-canonical encodings that decode into that same subgroup.
const KEYS = [
  ["small-order-y0-x-even", "0000000000000000000000000000000000000000000000000000000000000000",
    "small_order_public_key", "order-4 point (y = 0, even x)"],
  ["small-order-y0-x-odd", "0000000000000000000000000000000000000000000000000000000000000080",
    "small_order_public_key", "order-4 point (y = 0, odd x)"],
  ["small-order-identity", "0100000000000000000000000000000000000000000000000000000000000000",
    "small_order_public_key", "identity (y = 1)"],
  ["small-order-order8-a", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "small_order_public_key", "order-8 point"],
  ["small-order-order8-b", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "small_order_public_key", "order-8 point (other x sign)"],
  ["small-order-order8-c", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "small_order_public_key", "order-8 point"],
  ["small-order-order8-d", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "small_order_public_key", "order-8 point (other x sign)"],
  ["small-order-y-minus-1", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "small_order_public_key", "order-2 point (y = p - 1)"],
  ["non-canonical-y-minus-1-sign-set", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "non_canonical_public_key", "y = p - 1 with the x-sign bit set on x = 0"],
  ["non-canonical-y-equals-p", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "non_canonical_public_key", "y = p decodes to the order-4 point y = 0"],
  ["non-canonical-y-equals-p-plus-1", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "non_canonical_public_key", "y = p + 1 decodes to the identity"],
  ["non-canonical-identity-sign-set", "0100000000000000000000000000000000000000000000000000000000000080",
    "non_canonical_public_key", "identity with the x-sign bit set on x = 0"],
];

// R candidates for the witness search: the 8 canonical small-order
// encodings. With S = 0 the verification equation reduces to
// R == -[k]A, so a small-order R is the only thing that can satisfy it.
const R_CANDIDATES = KEYS.slice(0, 8).map(([, hex]) => hex);
const MAX_PROBE = 200;

// RFC 8032 §7.1 TEST 2 — the positive control and the base for the
// non-reduced-S fixture.
const RFC_PUBLIC_KEY = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
const RFC_MESSAGE = "72";
const RFC_SIGNATURE =
  "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
  "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

/** Raw, unguarded Ed25519 verify — the oracle the witnesses are found against. */
function naiveVerify(publicKeyHex, messageHex, signatureHex) {
  try {
    const key = ed25519PublicFromRaw(Buffer.from(publicKeyHex, "hex"));
    return nodeVerify(
      null,
      Buffer.from(messageHex, "hex"),
      key,
      Buffer.from(signatureHex, "hex"),
    );
  } catch {
    return false;
  }
}

function findWitness(publicKeyHex) {
  for (const r of R_CANDIDATES) {
    for (let i = 0; i < MAX_PROBE; i += 1) {
      const messageHex = Buffer.from(`capsule-low-order-probe-${i}`, "utf8").toString("hex");
      const signatureHex = r + "00".repeat(32);
      if (naiveVerify(publicKeyHex, messageHex, signatureHex)) {
        return { messageHex, signatureHex };
      }
    }
  }
  throw new Error(`no unguarded-acceptance witness found for ${publicKeyHex}`);
}

function nonReducedSignature() {
  const r = RFC_SIGNATURE.slice(0, 64);
  const s = Buffer.from(RFC_SIGNATURE.slice(64), "hex");
  let value = 0n;
  for (let i = 31; i >= 0; i -= 1) value = (value << 8n) | BigInt(s[i]);
  const shifted = value + ED25519_L;
  if (shifted >= 1n << 256n) throw new Error("S + L does not fit in 32 bytes");
  const out = Buffer.alloc(32);
  let acc = shifted;
  for (let i = 0; i < 32; i += 1) {
    out[i] = Number(acc & 0xffn);
    acc >>= 8n;
  }
  return r + out.toString("hex");
}

async function main() {
  const vectors = KEYS.map(([name, publicKeyHex, reason, note]) => {
    const { messageHex, signatureHex } = findWitness(publicKeyHex);
    return {
      name,
      public_key_hex: publicKeyHex,
      message_hex: messageHex,
      signature_hex: signatureHex,
      expected: { valid: false },
      reason,
      note: `${note}; accepted by an unguarded verifier`,
    };
  });

  if (!naiveVerify(RFC_PUBLIC_KEY, RFC_MESSAGE, RFC_SIGNATURE)) {
    throw new Error("RFC 8032 test 2 signature does not verify — refusing to write");
  }
  const nonReduced = nonReducedSignature();
  vectors.push({
    name: "non-reduced-signature-s",
    public_key_hex: RFC_PUBLIC_KEY,
    message_hex: RFC_MESSAGE,
    signature_hex: nonReduced,
    expected: { valid: false },
    reason: "non_reduced_signature_s",
    note: "RFC 8032 test 2 signature with S replaced by S + L",
  });
  vectors.push({
    name: "rfc8032-test2-valid",
    public_key_hex: RFC_PUBLIC_KEY,
    message_hex: RFC_MESSAGE,
    signature_hex: RFC_SIGNATURE,
    expected: { valid: true },
    reason: "valid",
    note: "positive control: RFC 8032 section 7.1 TEST 2",
  });

  const doc = {
    meta: {
      kind: "ed25519-verify",
      name: "ed25519-key-validation",
      spec_version: CURRENT_VERSION,
      description:
        "Ed25519 key and signature validation registry. Implementations MUST report valid=false for every small-order public key, every non-canonically encoded public key, and every signature whose S component is not reduced mod L, and valid=true for the positive control.",
      generator: "sdk-js/tools/generate-ed25519-key-validation-vector.mjs",
      no_warranty: "Conformance fixtures only; not production templates or advice.",
    },
    reasons: {
      small_order_public_key:
        "the public key is one of the 8 points whose order divides 8; a signature over it can be forged without the private key",
      non_canonical_public_key:
        "the 32-byte encoding is non-canonical: with the x-sign bit masked off, y >= 2^255 - 19",
      non_reduced_signature_s:
        "the signature's S component is not reduced mod L (RFC 8032 section 5.1.7)",
      valid: "positive control: a conforming verifier MUST accept this triple",
    },
    vectors,
  };

  const out = join(VECTORS, "ed25519-key-validation.json");
  const serialized = JSON.stringify(doc, null, 2) + "\n";
  if (CHECK) {
    let checkedIn;
    try {
      checkedIn = await readFile(out, "utf8");
    } catch (err) {
      throw new Error(`checked-in vector missing or unreadable: ${err.message}`);
    }
    if (checkedIn !== serialized) {
      throw new Error("checked-in vector differs from deterministic generator output");
    }
    console.log("ed25519-key-validation.json: ok");
    return;
  }
  await writeFile(out, serialized, "utf8");
  console.log(`wrote ${out}`);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});

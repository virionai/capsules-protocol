// Key-input normalization for the public API surface.
//
// Protocol wire format is strict: lowercase 64-hex everywhere. The API
// boundary is forgiving: every place that takes a key accepts either a
// 32-byte Uint8Array/Buffer or a hex string (any case), including the
// keypair objects returned by generateEd25519()/generateX25519(), so
// callers never have to know which representation an internal layer
// wants. Normalization happens here, once, at the boundary.

import { bytesToHex, hexToBytes } from "./canonical.js";

const HEX_RE = /^[0-9a-fA-F]+$/;

/** Normalize a key to raw bytes. Accepts Uint8Array/Buffer or hex string. */
export function toRawKey(value, name, length = 32) {
  if (value instanceof Uint8Array) {
    if (value.length !== length) {
      throw new Error(`${name} must be ${length} bytes, got ${value.length}`);
    }
    return Buffer.from(value);
  }
  if (typeof value === "string") {
    if (value.length !== length * 2 || !HEX_RE.test(value)) {
      throw new Error(`${name} must be a ${length * 2}-char hex string or ${length} raw bytes`);
    }
    return Buffer.from(hexToBytes(value.toLowerCase()));
  }
  throw new Error(`${name} must be a hex string or Uint8Array, got ${typeof value}`);
}

/** Normalize a key to lowercase hex. Accepts Uint8Array/Buffer or hex string. */
export function toKeyHex(value, name, length = 32) {
  return bytesToHex(toRawKey(value, name, length));
}

// Curve tags (finding A04). Ed25519 (signing) and X25519 (key agreement)
// keypair objects are structurally identical, and the two key types are
// indistinguishable from their bytes (any X25519 public key also parses
// as an Ed25519 point). X25519 clamps and accepts any 32-byte
// u-coordinate, so encrypting to an Ed25519 public key "succeeds" and
// produces content the Ed25519 holder can never decrypt — a data-loss
// bug that surfaces only at decryption time, potentially years later.
// Seal-time round-trip verification cannot catch it (the sealer has no
// recipient private key). The generators therefore tag every keypair
// object with its curve, and the normalizers below enforce the tag on
// the object path. Raw hex and raw bytes stay untagged and accepted:
// a caller who extracts bytes is asserting the curve themselves.

/** Throw when an object carries a curve tag other than `expected`. */
function assertCurveTag(obj, expected, name) {
  if (obj.curve !== undefined && obj.curve !== expected) {
    throw new Error(
      `${name} is tagged curve '${obj.curve}' but must be an ${expected} key: ` +
        `Ed25519 signs, X25519 encrypts — the two are not interchangeable`,
    );
  }
}

/**
 * Normalize one signer. Accepts:
 *   - the object returned by generateEd25519() (role defaults to "originator")
 *   - { role?, publicKey, privateKey } with keys as hex strings or bytes
 * Returns { role, publicKey: Buffer(32), privateKey: Buffer(32) }.
 *
 * An object tagged with a non-Ed25519 curve (e.g. a generateX25519()
 * keypair) is rejected. Untagged dicts stay accepted: a cross-curve
 * mistake on the signing side fails loudly at first verification (the
 * stored public key does not match the signature), unlike the silent
 * recipient-side hazard.
 */
export function toSigner(signer, index = 0) {
  if (signer == null || typeof signer !== "object") {
    throw new Error(`signers[${index}] must be an object with publicKey and privateKey`);
  }
  assertCurveTag(signer, "ed25519", `signers[${index}]`);
  const role = signer.role ?? "originator";
  if (typeof role !== "string" || role.length === 0) {
    throw new Error(`signers[${index}].role must be a non-empty string`);
  }
  const pub = signer.publicKey ?? signer.publicKeyHex;
  const priv = signer.privateKey ?? signer.privateKeyHex;
  if (pub == null || priv == null) {
    throw new Error(`signers[${index}] requires publicKey and privateKey (hex or 32 bytes)`);
  }
  return {
    role,
    publicKey: toRawKey(pub, `signers[${index}].publicKey`),
    privateKey: toRawKey(priv, `signers[${index}].privateKey`),
  };
}

/**
 * Normalize one encryption recipient. Accepts:
 *   - a hex string or 32-byte Uint8Array (the X25519 public key itself)
 *   - { publicKey } with the key as hex or bytes
 *   - the object returned by generateX25519()
 * Returns { publicKey: Buffer(32) }.
 *
 * The keypair-object path is the branded path, and it is the ONLY
 * object path for keypair-shaped input: an object carrying private key
 * material must be tagged curve "x25519" (an Ed25519 tag, or no tag at
 * all, is rejected — the untagged shape is indistinguishable from the
 * Ed25519 hazard). Public-key-only objects, hex, and raw bytes stay
 * accepted untagged; those forms carry no evidence of curve either way
 * and are the caller's assertion.
 */
export function toRecipient(recipient, index = 0) {
  const isObject =
    recipient != null && typeof recipient === "object" && !(recipient instanceof Uint8Array);
  if (isObject) {
    assertCurveTag(recipient, "x25519", `recipients[${index}]`);
    const hasPrivate = recipient.privateKey != null || recipient.privateKeyHex != null;
    if (hasPrivate && recipient.curve === undefined) {
      throw new Error(
        `recipients[${index}] is a keypair object without a curve tag: cannot tell X25519 ` +
          `from Ed25519 key material by shape. Pass a generateX25519() keypair ` +
          `(curve: "x25519"), or just its publicKey (hex or 32 bytes)`,
      );
    }
  }
  const value = isObject ? (recipient.publicKey ?? recipient.publicKeyHex) : recipient;
  if (value == null) {
    throw new Error(`recipients[${index}] requires a publicKey (hex or 32 bytes)`);
  }
  return { publicKey: toRawKey(value, `recipients[${index}].publicKey`) };
}

/** Current UTC time as an ISO 8601 string with second precision. */
export function nowIso() {
  return new Date().toISOString().replace(/\.\d+Z$/, "Z");
}

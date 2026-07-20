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

/**
 * Normalize one signer. Accepts:
 *   - the object returned by generateEd25519() (role defaults to "originator")
 *   - { role?, publicKey, privateKey } with keys as hex strings or bytes
 * Returns { role, publicKey: Buffer(32), privateKey: Buffer(32) }.
 */
export function toSigner(signer, index = 0) {
  if (signer == null || typeof signer !== "object") {
    throw new Error(`signers[${index}] must be an object with publicKey and privateKey`);
  }
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
 */
export function toRecipient(recipient, index = 0) {
  const value =
    recipient != null && typeof recipient === "object" && !(recipient instanceof Uint8Array)
      ? (recipient.publicKey ?? recipient.publicKeyHex)
      : recipient;
  if (value == null) {
    throw new Error(`recipients[${index}] requires a publicKey (hex or 32 bytes)`);
  }
  return { publicKey: toRawKey(value, `recipients[${index}].publicKey`) };
}

/** Current UTC time as an ISO 8601 string with second precision. */
export function nowIso() {
  return new Date().toISOString().replace(/\.\d+Z$/, "Z");
}

// Crypto wrapper around node:crypto.
// Ed25519, X25519, HKDF-SHA256, ChaCha20-Poly1305.
// Raw 32-byte keys round-tripped via JWK so we don't have to write DER.

import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  sign as nodeSign,
  verify as nodeVerify,
} from "node:crypto";

import { bytesToHex, hexToBytes } from "./canonical.js";

// ---------- Ed25519 ----------
//
// Raw 32-byte key round-trip uses PKCS8/SPKI DER prefixes. JWK import
// requires both halves of the keypair, which we don't always have when
// loading from a raw 32-byte secret. DER prefixes let us import a
// private key from the raw secret alone.

const ED25519_PKCS8_PREFIX = Buffer.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);
const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
  0x70, 0x03, 0x21, 0x00,
]);

export function generateEd25519() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pubRaw = ed25519PublicToRaw(publicKey);
  const privRaw = ed25519PrivateToRaw(privateKey);
  return {
    publicKey: pubRaw,
    privateKey: privRaw,
    publicKeyHex: bytesToHex(pubRaw),
    privateKeyHex: bytesToHex(privRaw),
  };
}

export function ed25519PublicToRaw(keyObj) {
  const der = keyObj.export({ format: "der", type: "spki" });
  // SPKI DER for Ed25519 is 12-byte prefix + 32-byte key
  return Buffer.from(der.subarray(der.length - 32));
}

export function ed25519PrivateToRaw(keyObj) {
  const der = keyObj.export({ format: "der", type: "pkcs8" });
  // PKCS8 DER for Ed25519 is 16-byte prefix + 32-byte key
  return Buffer.from(der.subarray(der.length - 32));
}

export function ed25519PublicFromRaw(raw32) {
  if (raw32.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  const der = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw32)]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

export function ed25519PrivateFromRaw(raw32) {
  if (raw32.length !== 32) throw new Error("Ed25519 private key must be 32 bytes");
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(raw32)]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

/** Sign raw bytes (NOT a hex string). Returns 64-byte signature. */
export function ed25519Sign(privateKeyRaw, message) {
  const key = ed25519PrivateFromRaw(privateKeyRaw);
  return nodeSign(null, Buffer.from(message), key);
}

export function ed25519Verify(publicKeyRaw, message, signature) {
  try {
    const key = ed25519PublicFromRaw(publicKeyRaw);
    return nodeVerify(null, Buffer.from(message), key, Buffer.from(signature));
  } catch {
    return false;
  }
}

// ---------- X25519 ----------
//
// Same DER prefix approach as Ed25519, with the X25519 OID (2b 65 6e).

const X25519_PKCS8_PREFIX = Buffer.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);
const X25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
  0x6e, 0x03, 0x21, 0x00,
]);

export function generateX25519() {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  const pubRaw = x25519PublicToRaw(publicKey);
  const privRaw = x25519PrivateToRaw(privateKey);
  return {
    publicKey: pubRaw,
    privateKey: privRaw,
    publicKeyHex: bytesToHex(pubRaw),
    privateKeyHex: bytesToHex(privRaw),
  };
}

export function x25519PublicToRaw(keyObj) {
  const der = keyObj.export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(der.length - 32));
}

export function x25519PrivateToRaw(keyObj) {
  const der = keyObj.export({ format: "der", type: "pkcs8" });
  return Buffer.from(der.subarray(der.length - 32));
}

export function x25519PublicFromRaw(raw32) {
  if (raw32.length !== 32) throw new Error("X25519 public key must be 32 bytes");
  const der = Buffer.concat([X25519_SPKI_PREFIX, Buffer.from(raw32)]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

export function x25519PrivateFromRaw(raw32) {
  if (raw32.length !== 32) throw new Error("X25519 private key must be 32 bytes");
  const der = Buffer.concat([X25519_PKCS8_PREFIX, Buffer.from(raw32)]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

/** X25519 ECDH; returns 32-byte shared secret. */
export function x25519DH(privateKeyRaw, peerPublicKeyRaw) {
  return diffieHellman({
    privateKey: x25519PrivateFromRaw(privateKeyRaw),
    publicKey: x25519PublicFromRaw(peerPublicKeyRaw),
  });
}

// ---------- HKDF-SHA256 ----------

export function hkdfSha256(ikm, salt, info, length = 32) {
  return Buffer.from(hkdfSync("sha256", ikm, salt, info, length));
}

// ---------- ChaCha20-Poly1305 ----------

const TAG_LENGTH = 16;

/** Returns ciphertext || tag (one buffer). */
export function chacha20Poly1305Encrypt(key, nonce, aad, plaintext) {
  if (key.length !== 32) throw new Error("ChaCha20-Poly1305 key must be 32 bytes");
  if (nonce.length !== 12) throw new Error("ChaCha20-Poly1305 nonce must be 12 bytes");
  const cipher = createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: TAG_LENGTH });
  if (aad && aad.length > 0) cipher.setAAD(Buffer.from(aad), { plaintextLength: plaintext.length });
  const enc = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  return Buffer.concat([enc, cipher.getAuthTag()]);
}

/** Splits trailing tag, verifies, returns plaintext. Throws on auth failure. */
export function chacha20Poly1305Decrypt(key, nonce, aad, ciphertextWithTag) {
  if (key.length !== 32) throw new Error("ChaCha20-Poly1305 key must be 32 bytes");
  if (nonce.length !== 12) throw new Error("ChaCha20-Poly1305 nonce must be 12 bytes");
  if (ciphertextWithTag.length < TAG_LENGTH) throw new Error("ciphertext too short for tag");
  const ct = Buffer.from(ciphertextWithTag.subarray(0, ciphertextWithTag.length - TAG_LENGTH));
  const tag = Buffer.from(ciphertextWithTag.subarray(ciphertextWithTag.length - TAG_LENGTH));
  const decipher = createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: TAG_LENGTH });
  if (aad && aad.length > 0) decipher.setAAD(Buffer.from(aad), { plaintextLength: ct.length });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

// ---------- Random ----------

export function randomNonce12() {
  return randomBytes(12);
}

export function randomKey32() {
  return randomBytes(32);
}

// ---------- Hex helpers re-exported ----------

export { bytesToHex, hexToBytes };

// JCS (RFC 8785) via canonicalize package, plus SHA-256 helpers.
// No in-house canonicalization. This is the entire surface.

import canonicalize from "canonicalize";
import { createHash } from "node:crypto";

const enc = new TextEncoder();

/** JCS-canonicalize an object and return UTF-8 bytes. */
export function jcs(obj) {
  const s = canonicalize(obj);
  if (typeof s !== "string") {
    throw new Error("canonicalize() did not return a string");
  }
  return enc.encode(s);
}

/** SHA-256 over bytes; returns Buffer (32 bytes). */
export function sha256(bytes) {
  const h = createHash("sha256");
  h.update(bytes);
  return h.digest();
}

/** SHA-256 over bytes, lowercase hex. */
export function sha256Hex(bytes) {
  return sha256(bytes).toString("hex");
}

/** Concatenate Uint8Array / Buffer parts into one Buffer. */
export function concatBytes(...parts) {
  const total = parts.reduce((n, p) => n + p.byteLength, 0);
  const out = Buffer.alloc(total);
  let off = 0;
  for (const p of parts) {
    Buffer.from(p.buffer ?? p, p.byteOffset ?? 0, p.byteLength).copy(out, off);
    off += p.byteLength;
  }
  return out;
}

/**
 * Hex → Buffer; throws on invalid input.
 *
 * Strict per spec: protocol-bound hex fields are lowercase only. Mixed
 * case is rejected so that a hand-edited capsule whose stored hex
 * differs from the canonical form fails at the parse boundary with a
 * specific error, rather than silently succeeding here and failing
 * later with a confusing "hash mismatch".
 *
 * For user-supplied input that may be either case (e.g. an allowlist
 * key copied from a UI), normalize with .toLowerCase() before calling.
 */
export function hexToBytes(hex) {
  if (typeof hex !== "string") throw new Error("hexToBytes: expected string");
  if (hex.length % 2 !== 0) throw new Error("hexToBytes: odd length");
  if (/[A-F]/.test(hex)) {
    throw new Error("hexToBytes: uppercase hex is non-canonical; use lowercase");
  }
  if (!/^[0-9a-f]*$/.test(hex)) throw new Error("hexToBytes: non-hex characters");
  return Buffer.from(hex, "hex");
}

/** Buffer/Uint8Array → lowercase hex. */
export function bytesToHex(b) {
  return Buffer.from(b).toString("hex");
}

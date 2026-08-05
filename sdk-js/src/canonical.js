// JCS (RFC 8785) via canonicalize package, plus SHA-256 helpers.
// No in-house canonicalization. This is the entire surface.

import canonicalize from "canonicalize";
import { createHash } from "node:crypto";

const enc = new TextEncoder();

// RFC 8785 §3.1 is only defined over I-JSON (RFC 7493) input: every number
// must be exactly representable as an IEEE-754 binary64, and every string
// must be well-formed Unicode. The `canonicalize` package enforces neither,
// so the reference lane would otherwise seal capsules that sdk-py and
// verifier-rust cannot recompute. See spec/canonicalization.md.
const PLAIN_INTEGER_CEILING = 1e21;

/**
 * Reject values outside the I-JSON acceptance boundary.
 *
 * Numbers: ECMAScript Number::toString emits a *plain integer literal*
 * (no `.`, no `e`) exactly when the value is integral and |v| < 1e21.
 * A plain integer literal outside ±(2^53 - 1) does not survive a
 * round-trip through implementations whose JSON parsers use native
 * integers, so it is rejected here. Integral values >= 1e21 serialize in
 * exponent form (`1e+21`), which round-trips through every lane's
 * double path, and are accepted.
 *
 * Strings: an unpaired surrogate is not a Unicode scalar value. UTF-8
 * cannot encode it, so a capsule carrying one is unverifiable in any
 * lane whose strings are scalar sequences.
 *
 * `path` is a dotted breadcrumb used only in the error message.
 */
export function assertIJson(value, path = "$") {
  if (value === null || value === undefined) return;
  const t = typeof value;
  if (t === "boolean" || t === "symbol" || t === "function") return;
  if (t === "bigint") {
    throw new Error(`JCS: BigInt is not JSON at ${path}`);
  }
  if (t === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(`JCS: non-finite number at ${path}`);
    }
    const magnitude = Math.abs(value);
    if (
      Number.isInteger(value) &&
      magnitude > Number.MAX_SAFE_INTEGER &&
      magnitude < PLAIN_INTEGER_CEILING
    ) {
      throw new Error(
        `JCS: integer outside IEEE-754 exact range (|n| > 2^53 - 1) at ${path}; ` +
          "not representable identically across implementations",
      );
    }
    return;
  }
  if (t === "string") {
    assertWellFormedUnicode(value, path);
    return;
  }
  if (typeof value.toJSON === "function") {
    assertIJson(value.toJSON(), path);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, i) => assertIJson(entry, `${path}[${i}]`));
    return;
  }
  for (const key of Object.keys(value)) {
    assertWellFormedUnicode(key, `${path}.${key}`);
    assertIJson(value[key], `${path}.${key}`);
  }
}

/**
 * Throw if `s` contains an unpaired surrogate. Iterating a string with
 * for..of yields code points; a well-formed surrogate pair yields the
 * single astral code point, so any yielded value in D800..DFFF is an
 * unpaired surrogate.
 */
function assertWellFormedUnicode(s, path) {
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (cp >= 0xd800 && cp <= 0xdfff) {
      throw new Error(
        `JCS: unpaired surrogate U+${cp.toString(16).toUpperCase()} at ${path}; ` +
          "strings must be well-formed Unicode",
      );
    }
  }
}

/** JCS-canonicalize an object and return UTF-8 bytes. */
/**
 * Reject JSON text carrying duplicate object member names, at any depth
 * (spec/canonicalization.md "Objects"; RFC 7493 2.3). Names compare AFTER
 * escape processing ("a" and "\u0061" are the same name), as sequences of
 * UTF-16 code units.
 *
 * This is a rule about the TEXT: every mainstream parser silently keeps
 * the last value, so it cannot be checked on the parsed tree. The scanner
 * assumes syntactically valid JSON — call JSON.parse first (parseJsonStrict
 * does) so syntax errors surface as parse errors, not scanner confusion.
 */
export function assertNoDuplicateMembers(text, label = "JSON") {
  let i = 0;
  const n = text.length;
  const fail = (message) => {
    throw new Error(`${label}: ${message}`);
  };
  const skipWs = () => {
    while (i < n && (text[i] === " " || text[i] === "\t" || text[i] === "\n" || text[i] === "\r")) i++;
  };
  const parseString = () => {
    i++; // opening quote
    let out = "";
    while (i < n) {
      const c = text[i];
      if (c === '"') { i++; return out; }
      if (c === "\\") {
        const e = text[i + 1];
        i += 2;
        switch (e) {
          case '"': out += '"'; break;
          case "\\": out += "\\"; break;
          case "/": out += "/"; break;
          case "b": out += "\b"; break;
          case "f": out += "\f"; break;
          case "n": out += "\n"; break;
          case "r": out += "\r"; break;
          case "t": out += "\t"; break;
          case "u":
            out += String.fromCharCode(parseInt(text.slice(i, i + 4), 16));
            i += 4;
            break;
          default:
            fail("invalid escape in string");
        }
      } else {
        out += c;
        i++;
      }
    }
    fail("unterminated string");
    return "";
  };
  const parseValue = () => {
    skipWs();
    const c = text[i];
    if (c === "{") { parseObject(); return; }
    if (c === "[") { parseArray(); return; }
    if (c === '"') { parseString(); return; }
    while (i < n && !",}] \t\n\r".includes(text[i])) i++;
  };
  const parseObject = () => {
    i++; // {
    const seen = new Set();
    skipWs();
    if (text[i] === "}") { i++; return; }
    for (;;) {
      skipWs();
      if (text[i] !== '"') fail("expected member name");
      const name = parseString();
      if (seen.has(name)) {
        fail(`duplicate object member ${JSON.stringify(name)}`);
      }
      seen.add(name);
      skipWs();
      if (text[i] !== ":") fail("expected ':' after member name");
      i++;
      parseValue();
      skipWs();
      if (text[i] === ",") { i++; continue; }
      if (text[i] === "}") { i++; return; }
      fail("expected ',' or '}' in object");
    }
  };
  const parseArray = () => {
    i++; // [
    skipWs();
    if (text[i] === "]") { i++; return; }
    for (;;) {
      parseValue();
      skipWs();
      if (text[i] === ",") { i++; continue; }
      if (text[i] === "]") { i++; return; }
      fail("expected ',' or ']' in array");
    }
  };
  parseValue();
}

const strictDecoder = new TextDecoder();

/**
 * Parse JSON text (or UTF-8 bytes) destined for hashing: JSON.parse for
 * syntax, then the duplicate-member gate over the raw text. Every capsule
 * document parse in this SDK goes through here — manifest, envelope, chain
 * event lines, skills, decryption metadata — so a duplicate member never
 * reaches a hash comparison (spec/canonicalization.md "Objects").
 */
export function parseJsonStrict(textOrBytes, label = "JSON") {
  const text =
    typeof textOrBytes === "string" ? textOrBytes : strictDecoder.decode(textOrBytes);
  const value = JSON.parse(text);
  assertNoDuplicateMembers(text, label);
  return value;
}

export function jcs(obj) {
  assertIJson(obj);
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

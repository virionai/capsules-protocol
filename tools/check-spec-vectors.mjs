#!/usr/bin/env node
// Verify checked-in spec vectors against the JavaScript reference SDK.
//
// Seven vector shapes are recognized under spec/vectors/ (plus the
// signing-input doc, documented at checkSigningInput below):
//
//   1. Embedded positive vector: a JSON doc with `capsule_bytes_b64` and an
//      `expected` map of observed hashes (capsule_id, first_event_hash,
//      entry_hash, manifest_hash, content_index_hash, envelope_signature_hex,
//      event_hashes). The capsule must verify ok=true and reproduce every
//      pinned hash. (e.g. plain-basic.json)
//
//   2. A collection of outcome vectors: a JSON doc with a `vectors` array,
//      each entry referencing a checked-in `capsule_file` (path relative to
//      the collection file) and an `expected` outcome — `{ ok, failing?,
//      error_includes? }`. This is the language-neutral registry for the
//      tamper fixtures, which were previously asserted only inside the Rust
//      verifier's own tests.
//
//   3. A JCS number-serialization vector set (jcs-numbers.json): a `vectors`
//      array of `{ ieee_hex, expected, accepted? }` entries, where `ieee_hex`
//      is the big-endian IEEE-754 binary64 bit pattern of the input and
//      `expected` its canonical RFC 8785 serialization. Implementations must
//      parse the bit pattern (not the expected string) and serialize it.
//      `accepted: false` marks a bit pattern outside the I-JSON acceptance
//      boundary (spec/canonicalization.md): `expected` records the
//      Number::toString layout, but canonicalization must refuse the value.
//
//   4. An Ed25519 key/signature validation registry (meta.kind
//      "ed25519-verify"): a `vectors` array of `{ public_key_hex,
//      message_hex, signature_hex, expected: { valid }, reason }` entries.
//      The negative entries are witnesses an unguarded verifier accepts —
//      small-order and non-canonical public keys, and a non-reduced S.
//
//   5. An identity-attestation outcome set (meta.kind ===
//      "identity-attestation"): inline attestation documents plus the
//      verification context they must be checked against, with an expected
//      `{ ok, status, error_includes? }`. `status` is the attestation-layer
//      vocabulary of spec/federation.md "Failure reporting".
//
//   6. A JCS key-ordering vector set (meta.kind === "jcs-key-order"): a
//      `vectors` array of `{ name, keys, expected_key_order,
//      canonical_utf8_hex, sha256_hex }` entries. Build an object mapping
//      each key to its index in `keys`, canonicalize, and reproduce the
//      pinned bytes. RFC 8785 3.2.3 sorts members on UTF-16 code units,
//      which is neither code-point order nor a collation-aware order.
//
//   7. An I-JSON acceptance set (meta.kind === "ijson-acceptance"): a
//      `vectors` array of `{ name, input_json, expect, canonical?, reason? }`
//      entries carrying raw JSON text that must be accepted (with its
//      canonical form pinned) or refused, per spec/canonicalization.md. A
//      `reject` vector is satisfied by refusal at parse time OR at
//      canonicalization time; both are conforming.
//
// keys.json (the tamper-detection fixture keypair, consumed by the
// Rust/Python parity lanes) is the only JSON explicitly skipped. Any other
// unrecognized JSON under spec/vectors/ is a hard failure: this checker
// fails closed rather than silently skipping a vector file it cannot read.

import { readdir, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, resolve, dirname, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { CapsuleReader, verifyCapsule } from "../sdk-js/src/index.js";
import { verifyIdentityAttestation } from "../sdk-js/src/federation/attestation.js";
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  jcs,
  sha256,
} from "../sdk-js/src/canonical.js";
import { envelopeCanonicalPayload, envelopeSigningInput } from "../sdk-js/src/envelope.js";
import { ed25519Verify } from "../sdk-js/src/crypto.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..");
const VECTOR_DIR = join(REPO_ROOT, "spec", "vectors");

const errors = [];
let checked = 0;

function fail(message) {
  errors.push(message);
}

function isEmbeddedVector(v) {
  return v && typeof v === "object" && typeof v.capsule_bytes_b64 === "string" && v.expected;
}
function isCollection(v) {
  return v && typeof v === "object" && Array.isArray(v.vectors);
}
// Fixture key material for the tamper-detection lane, not a vector.
function isFixtureKeyFile(path) {
  return path.endsWith(`${sep}keys.json`) || path.endsWith("/keys.json");
}
// The number-serialization set also carries a `vectors` array, so detect it
// (by name or by entry shape) before treating a doc as an outcome collection.
function isNumberVectorSet(path, doc) {
  if (path.endsWith("jcs-numbers.json")) return true;
  return (
    isCollection(doc) &&
    doc.vectors.some((v) => v && typeof v === "object" && typeof v.ieee_hex === "string")
  );
}

async function jsonFiles() {
  if (!existsSync(VECTOR_DIR)) return [];
  const out = [];
  async function walk(dir) {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) await walk(path);
      else if (entry.name.endsWith(".json")) out.push(path);
    }
  }
  await walk(VECTOR_DIR);
  return out.sort();
}

async function checkEmbeddedVector(path, vector) {
  checked++;
  let reader;
  try {
    reader = await CapsuleReader.fromBytes(Buffer.from(vector.capsule_bytes_b64, "base64"));
  } catch (err) {
    fail(`${path}: embedded capsule cannot be opened: ${err.message}`);
    return;
  }
  const allowlist = vector.originator_public_key_hex ? [vector.originator_public_key_hex] : [];
  const result = await verifyCapsule(reader, { allowlist });
  if (!result.ok) fail(`${path}: embedded capsule does not verify: ${result.errors.join("; ")}`);

  const manifest = reader.manifest();
  const envelope = reader.envelope();
  const observed = {
    capsule_id: manifest.id,
    first_event_hash: manifest.first_event_hash,
    entry_hash: envelope.entry_hash,
    manifest_hash: envelope.manifest_hash,
    content_index_hash: envelope.content_index_hash,
    envelope_signature_hex: envelope.signers?.[0]?.signature ?? null,
  };
  for (const [field, want] of Object.entries(vector.expected)) {
    if (field === "event_hashes") continue;
    if (observed[field] !== want) fail(`${path}: ${field} mismatch`);
  }
  if (Array.isArray(vector.expected.event_hashes)) {
    const hashes = reader.events().map((e) => e.hash);
    if (hashes.length !== vector.expected.event_hashes.length) {
      fail(`${path}: event_hashes length mismatch`);
    } else {
      hashes.forEach((h, i) => {
        if (h !== vector.expected.event_hashes[i]) fail(`${path}: event_hashes[${i}] mismatch`);
      });
    }
  }
}

// Map a `failing` area name to a predicate over the verify result.
const FAILING_AREA = {
  content_index: (r) => r.contentIndex.ok === false,
  chain: (r) => r.chain.ok === false,
  envelope: (r) => r.envelope.ok === false,
  encrypted_blob: (r) => r.errors.some((e) => e.includes("encrypted_blob_hash")),
  signer_set: (r) => r.signerSet.ok === false,
  originator_binding: (r) => r.errors.some((e) => e.includes("originator binding")),
};

// Map an open-stage `reason` category to the JS reference lane's error
// message. The category is the normative contract; the exact string is
// implementation-defined per lane.
const OPEN_REASON = {
  missing_required_file: /missing (manifest\.json|provenance\/envelope\.json)/,
  invalid_json: /JSON/,
  // Every manifest shape error from reader.js validateManifestShape is
  // prefixed with the offending field path.
  invalid_manifest_shape: /^manifest\./,
  duplicate_entry: /duplicate entry/,
  unsafe_path: /(parent traversal|absolute|NUL)/,
  unsupported_compression: /only STORED supported/,
  symlink_entry: /symlink/,
  directory_marker_shape: /directory (attribute on non-directory name|marker with nonzero size)/,
  local_central_name_mismatch: /local\/central name mismatch/,
};

async function checkCollection(path, doc) {
  // capsule_file / keys_file paths are relative to the collection file.
  const base = dirname(path);
  // Resolve the allowlist origin: an inline hex key, or the originator key in
  // a referenced keys.json.
  let allowlist = [];
  if (doc.originator_public_key_hex) {
    allowlist = [doc.originator_public_key_hex];
  } else if (doc.keys_file) {
    try {
      const keys = JSON.parse(await readFile(join(base, doc.keys_file), "utf8"));
      if (keys.originator?.publicKey) allowlist = [keys.originator.publicKey];
    } catch (err) {
      fail(`${path}: keys_file unreadable: ${err.message}`);
    }
  }

  for (const v of doc.vectors) {
    checked++;
    const label = `${path} [${v.name}]`;
    if (!v.capsule_file || !v.expected) {
      fail(`${label}: vector requires capsule_file and expected`);
      continue;
    }
    let bytes;
    try {
      bytes = await readFile(join(base, v.capsule_file));
    } catch (err) {
      fail(`${label}: capsule_file unreadable: ${err.message}`);
      continue;
    }

    // Open-stage vectors: the reader must REFUSE the container, for the
    // named reason category. Verification is never reached.
    if (v.expected.stage === "open") {
      const pattern = OPEN_REASON[v.expected.reason];
      if (!pattern) {
        fail(`${label}: unknown open-stage reason '${v.expected.reason}'`);
        continue;
      }
      let openError = null;
      try {
        await CapsuleReader.fromBytes(bytes);
      } catch (err) {
        openError = err;
      }
      if (!openError) {
        fail(`${label}: expected open to fail (${v.expected.reason}), but capsule opened`);
      } else if (!pattern.test(openError.message)) {
        fail(
          `${label}: open failed, but not for reason '${v.expected.reason}': ${openError.message}`,
        );
      }
      continue;
    }

    let reader;
    try {
      reader = await CapsuleReader.fromBytes(bytes);
    } catch (err) {
      fail(`${label}: capsule_file cannot be opened: ${err.message}`);
      continue;
    }
    const result = await verifyCapsule(reader, { allowlist });

    if (typeof v.expected.ok === "boolean" && result.ok !== v.expected.ok) {
      fail(`${label}: expected ok=${v.expected.ok}, got ok=${result.ok} (${result.errors.join("; ")})`);
    }
    // Signer-set binding is PRESENCE BINDS, ABSENCE REPORTS: vectors pin
    // the machine-readable bound/unbound report, not just ok.
    if (typeof v.expected.signer_set_bound === "boolean" &&
        result.signerSet.bound !== v.expected.signer_set_bound) {
      fail(
        `${label}: expected signerSet.bound=${v.expected.signer_set_bound}, got ${result.signerSet.bound}`,
      );
    }
    for (const area of v.expected.failing ?? []) {
      const pred = FAILING_AREA[area];
      if (!pred) {
        fail(`${label}: unknown failing area '${area}'`);
      } else if (!pred(result)) {
        fail(`${label}: expected '${area}' to fail, but it did not`);
      }
    }
    if (v.expected.error_includes) {
      const haystack = [
        ...result.errors,
        ...result.contentIndex.errors,
        ...(result.chain.errors ?? []).map((e) => (typeof e === "string" ? e : e.message ?? "")),
      ].join(" ");
      if (!haystack.includes(v.expected.error_includes)) {
        fail(`${label}: expected an error containing '${v.expected.error_includes}'`);
      }
    }
    // Honest-reporting pins: some rules require the verifier to REPORT a
    // weaker claim machine-readably (e.g. a zero-event chain that was not
    // walked), not just to pass/fail. Those vectors pin a notes substring.
    if (v.expected.notes_includes) {
      if (!(result.notes ?? []).join(" ").includes(v.expected.notes_includes)) {
        fail(
          `${label}: expected a note containing '${v.expected.notes_includes}', got ${JSON.stringify(result.notes ?? [])}`,
        );
      }
    }
  }
}

function checkNumberVectors(path, doc) {
  if (!Array.isArray(doc.vectors) || doc.vectors.length === 0) {
    fail(`${path}: vectors must be a non-empty array`);
    return;
  }
  doc.vectors.forEach((entry, i) => {
    checked++;
    const { ieee_hex, expected } = entry ?? {};
    if (typeof ieee_hex !== "string" || !/^[0-9a-f]{16}$/.test(ieee_hex)) {
      fail(`${path}: vectors[${i}]: ieee_hex must be 16 lowercase hex chars`);
      return;
    }
    if (typeof expected !== "string" || expected.length === 0) {
      fail(`${path}: vectors[${i}]: missing expected string`);
      return;
    }
    const value = Buffer.from(ieee_hex, "hex").readDoubleBE(0);
    if (!Number.isFinite(value)) {
      fail(`${path}: vectors[${i}]: bit pattern is not a finite double`);
      return;
    }
    if (entry.accepted === false) {
      // Outside the I-JSON acceptance boundary: `expected` documents the
      // Number::toString layout, but canonicalization must refuse the value.
      let threw = false;
      try {
        jcs(value);
      } catch {
        threw = true;
      }
      if (!threw) {
        fail(`${path}: vectors[${i}] (bits ${ieee_hex}): accepted:false but jcs() accepted it`);
      }
      return;
    }
    const got = Buffer.from(jcs(value)).toString("utf8");
    if (got !== expected) {
      fail(`${path}: vectors[${i}] (bits ${ieee_hex}): JS SDK serializes ${got}, vector says ${expected}`);
    }
  });
}

// Array-index-like keys ("0", "1", ...) are reordered by JS engines when a
// canonical object is reparsed, which would make expected_key_order
// unverifiable here. Vectors must not use them.
const ARRAY_INDEX_KEY = /^(0|[1-9][0-9]*)$/;

// JCS object-member ordering (meta.kind === "jcs-key-order"): RFC 8785
// 3.2.3 sorts members on their UTF-16 code-unit sequences. This lane gets
// that for free (`a < b` on a JS string IS UTF-16 order), so the set is
// both the oracle's regression pin and the negative witness for lanes that
// sort by code point or with a collation-aware comparator.
function checkKeyOrderVectors(path, doc) {
  if (!Array.isArray(doc.vectors) || doc.vectors.length === 0) {
    fail(`${path}: vectors must be a non-empty array`);
    return;
  }
  for (const entry of doc.vectors) {
    checked++;
    const label = `${path} [${entry?.name}]`;
    const keys = entry?.keys;
    if (!Array.isArray(keys) || keys.length === 0 || keys.some((k) => typeof k !== "string")) {
      fail(`${label}: keys must be a non-empty array of strings`);
      continue;
    }
    if (new Set(keys).size !== keys.length) {
      fail(`${label}: keys must be distinct`);
      continue;
    }
    if (keys.some((k) => ARRAY_INDEX_KEY.test(k))) {
      fail(`${label}: array-index-like keys are not allowed in ordering vectors`);
      continue;
    }
    const obj = {};
    keys.forEach((k, i) => {
      obj[k] = i;
    });
    const canonical = jcs(obj);
    const gotHex = bytesToHex(canonical);
    if (gotHex !== entry.canonical_utf8_hex) {
      fail(`${label}: JS SDK canonicalizes to ${gotHex}, vector says ${entry.canonical_utf8_hex}`);
      continue;
    }
    if (bytesToHex(sha256(canonical)) !== entry.sha256_hex) {
      fail(`${label}: sha256_hex does not match SHA-256 of canonical_utf8_hex`);
    }
    const order = Object.keys(JSON.parse(Buffer.from(canonical).toString("utf8")));
    if (JSON.stringify(order) !== JSON.stringify(entry.expected_key_order)) {
      fail(`${label}: expected_key_order ${JSON.stringify(entry.expected_key_order)} != ${JSON.stringify(order)}`);
    }
  }
}

// Byte-level signing-input vector (meta.kind === "signing-input"): every
// canonical byte string and hash must be reproducible from the referenced
// embedded capsule, and each pinned signature must verify over the
// reconstructed signing input.
async function checkSigningInput(path, doc) {
  const sha256Hex = (b) => bytesToHex(sha256(b));
  const base = dirname(path);
  let reader;
  try {
    const refDoc = JSON.parse(await readFile(join(base, doc.meta.capsule_ref), "utf8"));
    reader = await CapsuleReader.fromBytes(Buffer.from(refDoc.capsule_bytes_b64, "base64"));
  } catch (err) {
    fail(`${path}: capsule_ref unreadable: ${err.message}`);
    return;
  }
  const manifest = reader.manifest();
  const envelope = reader.envelope();

  // capsule_id preimage
  checked++;
  const cid = doc.capsule_id;
  const idDomain = hexToBytes(cid.domain_hex);
  if (Buffer.from(cid.domain_utf8, "utf8").toString("hex") !== cid.domain_hex) {
    fail(`${path}: capsule_id.domain_utf8 and domain_hex disagree`);
  }
  const derivedId = sha256Hex(
    concatBytes(idDomain, hexToBytes(cid.originator_public_key_hex), hexToBytes(cid.first_event_hash_hex)),
  );
  if (derivedId !== cid.capsule_id_hex) fail(`${path}: capsule_id preimage does not hash to capsule_id_hex`);
  if (cid.capsule_id_hex !== manifest.id) fail(`${path}: capsule_id_hex != manifest.id`);
  if (cid.originator_public_key_hex !== manifest.originator.public_key) {
    fail(`${path}: originator_public_key_hex != manifest originator key`);
  }
  if (cid.first_event_hash_hex !== manifest.first_event_hash) {
    fail(`${path}: first_event_hash_hex != manifest.first_event_hash`);
  }

  // per-event canonical bytes + hash preimage
  const events = reader.events();
  if (!Array.isArray(doc.events) || doc.events.length !== events.length) {
    fail(`${path}: events length mismatch`);
  } else {
    doc.events.forEach((pin, i) => {
      checked++;
      const { hash, ...rest } = events[i];
      const canon = jcs(rest);
      if (bytesToHex(canon) !== pin.canonical_bytes_hex) {
        fail(`${path}: events[${i}] canonical bytes mismatch`);
      }
      if (rest.prev_hash !== pin.prev_hash_hex) fail(`${path}: events[${i}] prev_hash mismatch`);
      const recomputed = sha256Hex(concatBytes(hexToBytes(pin.prev_hash_hex), canon));
      if (recomputed !== pin.hash_hex) fail(`${path}: events[${i}] preimage does not hash to hash_hex`);
      if (recomputed !== hash) fail(`${path}: events[${i}] hash_hex != stored event hash`);
    });
  }

  // manifest canonical bytes
  checked++;
  const manifestCanon = jcs(manifest);
  if (bytesToHex(manifestCanon) !== doc.manifest.canonical_bytes_hex) {
    fail(`${path}: manifest canonical bytes mismatch`);
  }
  if (sha256Hex(manifestCanon) !== doc.manifest.sha256_hex) {
    fail(`${path}: manifest sha256 mismatch`);
  }
  if (doc.manifest.sha256_hex !== envelope.manifest_hash) {
    fail(`${path}: manifest.sha256_hex != envelope.manifest_hash`);
  }

  // content_index canonical bytes
  checked++;
  const indexCanon = jcs(manifest.content_index.files);
  if (bytesToHex(indexCanon) !== doc.content_index.canonical_bytes_hex) {
    fail(`${path}: content_index canonical bytes mismatch`);
  }
  if (sha256Hex(indexCanon) !== doc.content_index.sha256_hex) {
    fail(`${path}: content_index sha256 mismatch`);
  }
  if (doc.content_index.sha256_hex !== envelope.content_index_hash) {
    fail(`${path}: content_index.sha256_hex != envelope.content_index_hash`);
  }

  // envelope canonical payload + per-role signing input + signature
  checked++;
  const envCanon = envelopeCanonicalPayload(envelope);
  if (bytesToHex(envCanon) !== doc.envelope.canonical_payload_hex) {
    fail(`${path}: envelope canonical payload mismatch`);
  }
  if (sha256Hex(envCanon) !== doc.envelope.canonical_payload_sha256) {
    fail(`${path}: envelope canonical payload sha256 mismatch`);
  }
  if (!Array.isArray(doc.envelope.signers) || doc.envelope.signers.length !== envelope.signers.length) {
    fail(`${path}: envelope signers length mismatch`);
    return;
  }
  doc.envelope.signers.forEach((pin, i) => {
    checked++;
    const stored = envelope.signers[i];
    if (pin.role !== stored.role) fail(`${path}: signers[${i}] role mismatch`);
    if (pin.public_key_hex !== stored.public_key) fail(`${path}: signers[${i}] public key mismatch`);
    if (pin.signature_hex !== stored.signature) fail(`${path}: signers[${i}] signature mismatch`);
    if (Buffer.from(pin.domain_utf8, "utf8").toString("hex") !== pin.domain_hex) {
      fail(`${path}: signers[${i}] domain_utf8 and domain_hex disagree`);
    }
    const input = envelopeSigningInput(envelope, pin.role);
    const domainBytes = hexToBytes(pin.domain_hex);
    if (bytesToHex(input.subarray(0, domainBytes.length)) !== pin.domain_hex) {
      fail(`${path}: signers[${i}] signing input does not start with domain bytes`);
    }
    if (bytesToHex(input.subarray(domainBytes.length)) !== doc.envelope.canonical_payload_hex) {
      fail(`${path}: signers[${i}] signing input does not end with canonical payload`);
    }
    if (sha256Hex(input) !== pin.signing_input_sha256) {
      fail(`${path}: signers[${i}] signing input sha256 mismatch`);
    }
    let valid = false;
    try {
      valid = ed25519Verify(hexToBytes(pin.public_key_hex), input, hexToBytes(pin.signature_hex));
    } catch {
      valid = false;
    }
    if (!valid) fail(`${path}: signers[${i}] pinned signature does not verify over signing input`);
  });
}

function isSigningInputVector(doc) {
  return doc && typeof doc === "object" && doc.meta?.kind === "signing-input";
}

function isIJsonAcceptanceSet(doc) {
  return doc && typeof doc === "object" && doc.meta?.kind === "ijson-acceptance";
}

// I-JSON acceptance vectors (spec/canonicalization.md). `input_json` is raw
// JSON text: each lane feeds it to its own parser, then canonicalizes. A
// `reject` vector is satisfied by refusal at EITHER stage — some lanes' JSON
// parsers refuse lone-surrogate escapes outright, others accept them and the
// canonicalizer refuses. What is normative is that the value never reaches a
// hash.
const IJSON_REASONS = new Set(["integer_out_of_range", "unpaired_surrogate"]);

function checkIJsonAcceptance(path, doc) {
  if (!Array.isArray(doc.vectors) || doc.vectors.length === 0) {
    fail(`${path}: vectors must be a non-empty array`);
    return;
  }
  for (const v of doc.vectors) {
    checked++;
    const label = `${path} [${v.name}]`;
    if (typeof v.input_json !== "string") {
      fail(`${label}: input_json must be a string of raw JSON text`);
      continue;
    }
    let parsed;
    let parseFailed = false;
    try {
      parsed = JSON.parse(v.input_json);
    } catch {
      parseFailed = true;
    }
    if (v.expect === "accept") {
      if (parseFailed) {
        fail(`${label}: expected accept, but the JSON text does not parse`);
        continue;
      }
      let got;
      try {
        got = Buffer.from(jcs(parsed)).toString("utf8");
      } catch (err) {
        fail(`${label}: expected accept, but canonicalization threw: ${err.message}`);
        continue;
      }
      if (got !== v.canonical) {
        fail(`${label}: canonical mismatch: got ${got}, vector says ${v.canonical}`);
      }
      continue;
    }
    if (v.expect !== "reject") {
      fail(`${label}: expect must be "accept" or "reject"`);
      continue;
    }
    if (!IJSON_REASONS.has(v.reason)) {
      fail(`${label}: unknown reject reason '${v.reason}'`);
      continue;
    }
    if (parseFailed) continue; // parse-stage refusal is conforming
    let threw = false;
    try {
      jcs(parsed);
    } catch {
      threw = true;
    }
    if (!threw) {
      fail(`${label}: expected canonicalization to reject (${v.reason}), but it succeeded`);
    }
  }
}

function isKeyValidationVector(doc) {
  return doc && typeof doc === "object" && doc.meta?.kind === "ed25519-verify";
}

function isAttestationVectorSet(doc) {
  return doc && typeof doc === "object" && doc.meta?.kind === "identity-attestation";
}

// Attestation-layer outcome registry (spec/federation.md "Failure
// reporting"). Each vector carries a complete attestation document plus the
// verification context it must be checked against; `expected.status` pins the
// machine-readable outcome, which is what separates "unknown" from "negative".
function checkAttestationVectors(path, doc) {
  if (!Array.isArray(doc.vectors) || doc.vectors.length === 0) {
    fail(`${path}: vectors must be a non-empty array`);
    return;
  }
  for (const v of doc.vectors) {
    checked++;
    const label = `${path} [${v.name}]`;
    if (!v.attestation || !v.expected) {
      fail(`${label}: vector requires attestation and expected`);
      continue;
    }
    const ctx = { ...(doc.context ?? {}), ...(v.context ?? {}) };
    const trustRoots = v.trust_roots ?? doc.trust_roots;
    let result;
    try {
      result = verifyIdentityAttestation(v.attestation, {
        trustRoots,
        now: new Date(ctx.now),
        capsuleId: ctx.capsule_id,
        signerPublicKeyHex: ctx.signer_public_key,
        expectedIssuer: ctx.expected_issuer,
        audience: ctx.audience,
      });
    } catch (err) {
      fail(`${label}: verification threw: ${err.message}`);
      continue;
    }
    if (typeof v.expected.ok === "boolean" && result.ok !== v.expected.ok) {
      fail(`${label}: expected ok=${v.expected.ok}, got ok=${result.ok} (${result.errors.join("; ")})`);
    }
    if (v.expected.status && result.status !== v.expected.status) {
      fail(`${label}: expected status '${v.expected.status}', got '${result.status}'`);
    }
    if (v.expected.error_includes && !result.errors.join(" ").includes(v.expected.error_includes)) {
      fail(`${label}: expected an error containing '${v.expected.error_includes}', got ${result.errors.join("; ")}`);
    }
  }
}

// Ed25519 key/signature validation registry (meta.kind === "ed25519-verify"):
// each entry pins a (public_key, message, signature) triple and the verdict a
// conforming verifier must report. The negative entries are witnesses — an
// unguarded verifier accepts them — so this set fails closed on any lane that
// skips small-order / non-canonical key rejection.
function checkKeyValidationVectors(path, doc) {
  if (!Array.isArray(doc.vectors) || doc.vectors.length === 0) {
    fail(`${path}: vectors must be a non-empty array`);
    return;
  }
  for (const v of doc.vectors) {
    checked++;
    const label = `${path} [${v.name}]`;
    if (
      typeof v.public_key_hex !== "string" ||
      typeof v.message_hex !== "string" ||
      typeof v.signature_hex !== "string" ||
      typeof v.expected?.valid !== "boolean"
    ) {
      fail(`${label}: vector requires public_key_hex, message_hex, signature_hex, expected.valid`);
      continue;
    }
    let got;
    try {
      got = ed25519Verify(
        hexToBytes(v.public_key_hex),
        hexToBytes(v.message_hex),
        hexToBytes(v.signature_hex),
      );
    } catch {
      got = false;
    }
    if (got !== v.expected.valid) {
      fail(`${label}: expected valid=${v.expected.valid}, got valid=${got} (${v.reason})`);
    }
  }
}

async function checkFile(path) {
  if (isFixtureKeyFile(path)) return;
  let doc;
  try {
    doc = JSON.parse(await readFile(path, "utf8"));
  } catch (err) {
    fail(`${path}: cannot parse JSON: ${err.message}`);
    return;
  }
  if (isNumberVectorSet(path, doc)) checkNumberVectors(path, doc);
  // Must sit before isCollection, which would otherwise swallow the file
  // (it also carries a `vectors` array).
  else if (doc?.meta?.kind === "jcs-key-order") checkKeyOrderVectors(path, doc);
  else if (isIJsonAcceptanceSet(doc)) checkIJsonAcceptance(path, doc);
  else if (isSigningInputVector(doc)) await checkSigningInput(path, doc);
  else if (isKeyValidationVector(doc)) checkKeyValidationVectors(path, doc);
  else if (isAttestationVectorSet(doc)) checkAttestationVectors(path, doc);
  else if (isCollection(doc)) await checkCollection(path, doc);
  else if (isEmbeddedVector(doc)) await checkEmbeddedVector(path, doc);
  else {
    fail(
      `${path}: unrecognized vector document (expected capsule_bytes_b64 + expected, ` +
        `an outcome-vector collection, a signing-input doc, an ed25519-verify doc, ` +
        `an identity-attestation set, an ijson-acceptance set, a jcs number set, ` +
        `or a jcs key-order set)`
    );
  }
}

async function main() {
  const files = await jsonFiles();
  for (const file of files) await checkFile(file);
  if (checked === 0) fail("spec/vectors contains no recognizable vectors");

  if (errors.length > 0) {
    for (const error of errors) console.error(`FAIL: ${error}`);
    process.exit(1);
  }
  console.log(`spec vectors: ok (${checked} vector${checked === 1 ? "" : "s"})`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

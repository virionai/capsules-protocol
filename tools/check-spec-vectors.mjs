#!/usr/bin/env node
// Verify checked-in spec vectors against the JavaScript reference SDK.
//
// Three vector shapes are recognized under spec/vectors/:
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
//      array of `{ ieee_hex, expected }` entries, where `ieee_hex` is the
//      big-endian IEEE-754 binary64 bit pattern of the input and `expected`
//      its canonical RFC 8785 serialization. Implementations must parse the
//      bit pattern (not the expected string) and serialize it.
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
};

// Map an open-stage `reason` category to the JS reference lane's error
// message. The category is the normative contract; the exact string is
// implementation-defined per lane.
const OPEN_REASON = {
  missing_required_file: /missing (manifest\.json|provenance\/envelope\.json)/,
  invalid_json: /JSON/,
  duplicate_entry: /duplicate entry/,
  unsafe_path: /(parent traversal|absolute|NUL)/,
  unsupported_compression: /only STORED supported/,
  symlink_entry: /symlink/,
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
    const got = Buffer.from(jcs(value)).toString("utf8");
    if (got !== expected) {
      fail(`${path}: vectors[${i}] (bits ${ieee_hex}): JS SDK serializes ${got}, vector says ${expected}`);
    }
  });
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
  else if (isSigningInputVector(doc)) await checkSigningInput(path, doc);
  else if (isCollection(doc)) await checkCollection(path, doc);
  else if (isEmbeddedVector(doc)) await checkEmbeddedVector(path, doc);
  else {
    fail(
      `${path}: unrecognized vector document (expected capsule_bytes_b64 + expected, ` +
        `an outcome-vector collection, a signing-input doc, or a jcs number set)`
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

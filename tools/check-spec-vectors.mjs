#!/usr/bin/env node
// Verify checked-in spec vectors against the JavaScript reference SDK.
//
// Two vector shapes are recognized under spec/vectors/:
//
//   1. Embedded positive vector: a JSON doc with `capsule_bytes_b64` and an
//      `expected` map of observed hashes (capsule_id, first_event_hash,
//      entry_hash, manifest_hash, content_index_hash, envelope_signature_hex,
//      event_hashes). The capsule must verify ok=true and reproduce every
//      pinned hash. (e.g. plain-basic.json)
//
//   2. A collection of outcome vectors: a JSON doc with a `vectors` array,
//      each entry referencing a checked-in `capsule_file` (path relative to
//      spec/vectors/) and an `expected` outcome — `{ ok, failing?, error_includes? }`.
//      This is the language-neutral registry for the tamper fixtures, which
//      were previously asserted only inside the Rust verifier's own tests.
//
// Non-vector JSON (e.g. the tamper-detection keypair keys.json) is ignored.

import { readdir, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { CapsuleReader, verifyCapsule } from "../sdk-js/src/index.js";

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
    let reader;
    try {
      const bytes = await readFile(join(base, v.capsule_file));
      reader = await CapsuleReader.fromBytes(bytes);
    } catch (err) {
      fail(`${label}: capsule_file unreadable: ${err.message}`);
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

async function checkFile(path) {
  let doc;
  try {
    doc = JSON.parse(await readFile(path, "utf8"));
  } catch (err) {
    fail(`${path}: cannot parse JSON: ${err.message}`);
    return;
  }
  if (isCollection(doc)) await checkCollection(path, doc);
  else if (isEmbeddedVector(doc)) await checkEmbeddedVector(path, doc);
  // else: not a vector document (e.g. keys.json) — ignore.
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

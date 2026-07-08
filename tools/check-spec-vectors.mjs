#!/usr/bin/env node
// Verify checked-in spec vectors against the JavaScript reference SDK.

import { readdir, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { CapsuleReader, verifyCapsule } from "../sdk-js/src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..");
const VECTOR_DIR = join(REPO_ROOT, "spec", "vectors");

const errors = [];

function fail(message) {
  errors.push(message);
}

// A vector is a JSON document carrying `capsule_bytes_b64` + `expected`.
// Other JSON files live under spec/vectors/ too (e.g. the tamper-detection
// keypair `keys.json`, which is consumed by the Rust/Python parity lanes),
// so we filter by shape rather than by walking every *.json blindly.
function isVectorDocument(value) {
  return (
    value &&
    typeof value === "object" &&
    typeof value.capsule_bytes_b64 === "string" &&
    value.expected &&
    typeof value.expected === "object"
  );
}

async function vectorFiles() {
  if (!existsSync(VECTOR_DIR)) return [];
  const out = [];
  async function walk(dir) {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) await walk(path);
      else if (!entry.name.endsWith(".json")) continue;
      else {
        let parsed;
        try {
          parsed = JSON.parse(await readFile(path, "utf8"));
        } catch {
          // A malformed .json under spec/vectors is itself a failure.
          out.push(path);
          continue;
        }
        if (isVectorDocument(parsed)) out.push(path);
      }
    }
  }
  await walk(VECTOR_DIR);
  return out.sort();
}

async function checkVector(path) {
  let vector;
  try {
    vector = JSON.parse(await readFile(path, "utf8"));
  } catch (err) {
    fail(`${path}: cannot parse JSON: ${err.message}`);
    return;
  }

  const expected = vector.expected;
  if (!expected || typeof expected !== "object") fail(`${path}: missing expected object`);
  if (!vector.capsule_bytes_b64) fail(`${path}: missing capsule_bytes_b64`);
  if (!expected || !vector.capsule_bytes_b64) return;

  let reader;
  try {
    const bytes = Buffer.from(vector.capsule_bytes_b64, "base64");
    reader = await CapsuleReader.fromBytes(bytes);
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

  for (const [field, expectedValue] of Object.entries(expected)) {
    if (field === "event_hashes") continue;
    if (observed[field] !== expectedValue) {
      fail(`${path}: ${field} mismatch`);
    }
  }

  if (Array.isArray(expected.event_hashes)) {
    const hashes = reader.events().map((event) => event.hash);
    if (hashes.length !== expected.event_hashes.length) {
      fail(`${path}: event_hashes length mismatch`);
    } else {
      hashes.forEach((hash, i) => {
        if (hash !== expected.event_hashes[i]) fail(`${path}: event_hashes[${i}] mismatch`);
      });
    }
  }
}

async function main() {
  const files = await vectorFiles();
  if (files.length === 0) fail("spec/vectors contains no JSON vector files");
  for (const file of files) await checkVector(file);

  if (errors.length > 0) {
    for (const error of errors) console.error(`FAIL: ${error}`);
    process.exit(1);
  }
  console.log(`spec vectors: ok (${files.length} vector${files.length === 1 ? "" : "s"})`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

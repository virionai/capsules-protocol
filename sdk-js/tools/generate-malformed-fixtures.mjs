#!/usr/bin/env node
// generate-malformed-fixtures.mjs
//
// Generates the malformed-layout conformance fixtures under
// spec/vectors/malformed-layout/output/. Every fixture is derived
// deterministically from the checked-in tamper-detection clean fixture
// (spec/vectors/tamper-detection/output/clean.capsule) by removing,
// corrupting, duplicating, or smuggling ZIP entries with the guardrail-free
// raw writer (tools/rawzip.mjs) — the production packer refuses to write
// these shapes, which is the point.
//
// Fixture -> expected outcome lives in
// spec/vectors/malformed-layout/vectors.json (the language-neutral
// registry); this script only (re)generates the capsule bytes.
// Regeneration is an intentional spec change; review the byte-level diff.

import { readFile, mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { unpackZip } from "../src/zip.js";
import { writeRawZip } from "./rawzip.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..");
const CLEAN = join(REPO_ROOT, "spec", "vectors", "tamper-detection", "output", "clean.capsule");
const OUT_DIR = join(REPO_ROOT, "spec", "vectors", "malformed-layout", "output");

/** Sorted [{name, data}] view of the clean capsule's entries. */
async function cleanEntries() {
  const files = await unpackZip(await readFile(CLEAN));
  return [...files.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([name, data]) => ({ name, data: Buffer.from(data) }));
}

function without(entries, name) {
  return entries.filter((e) => e.name !== name);
}

function replaceData(entries, name, data) {
  return entries.map((e) => (e.name === name ? { ...e, data } : e));
}

async function main() {
  await mkdir(OUT_DIR, { recursive: true });
  const base = await cleanEntries();

  const fixtures = {
    // Required top-level files absent: readers must refuse to open.
    "missing-manifest.capsule": without(base, "manifest.json"),
    "missing-envelope.capsule": without(base, "provenance/envelope.json"),

    // manifest.json present but not JSON: readers must refuse to open.
    "invalid-manifest-json.capsule": replaceData(
      base,
      "manifest.json",
      Buffer.from("{ this is not json", "utf8"),
    ),

    // Chain file absent: capsule opens, verification must fail via the
    // content index (see vectors.json note on chain-area divergence).
    "missing-chain.capsule": without(base, "chain/events.jsonl"),

    // Two entries with the same name: parser differential; must reject.
    "duplicate-entry.capsule": base.flatMap((e) =>
      e.name === "program.md"
        ? [e, { name: "program.md", data: Buffer.from("# duplicate\n", "utf8") }]
        : [e],
    ),

    // ZIP-slip shapes: must reject on the raw stored name.
    "traversal-path.capsule": [
      ...base,
      { name: "../escape.txt", data: Buffer.from("escape\n", "utf8") },
    ],
    "absolute-path.capsule": [
      ...base,
      { name: "/absolute.txt", data: Buffer.from("absolute\n", "utf8") },
    ],

    // Non-STORED entry: spec/format.md mandates STORED-only.
    "compressed-entry.capsule": base.map((e) =>
      e.name === "program.md" ? { ...e, method: 8 } : e,
    ),

    // Symlink mode bits in external attrs: must reject.
    "symlink-entry.capsule": [
      ...base,
      { name: "link", data: Buffer.from("program.md", "utf8"), mode: 0o120777 },
    ],
  };

  for (const [name, entries] of Object.entries(fixtures)) {
    const bytes = writeRawZip(entries);
    await writeFile(join(OUT_DIR, name), bytes);
    console.log(`wrote ${name} (${bytes.length} bytes)`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

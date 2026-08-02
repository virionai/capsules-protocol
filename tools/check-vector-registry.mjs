#!/usr/bin/env node
// Enforce spec/vectors/registry.json — the lane × collection coverage
// manifest — against the repository's actual state.
//
// WHY THIS EXISTS. Registry consumption used to be opt-in per lane, by
// hardcoded filename: sdk-py, verifier-rust, sdk-swift and sdk-kotlin each
// kept their own list of vector files, and nothing asserted that the
// lists were COMPLETE. A new collection was therefore invisible to four
// of the five lanes by default — the generator behind several shipped
// gaps (Swift and Kotlin never consumed malformed-layout; later,
// malformed-shape / chain-binding / unknown-fields / signing-input were
// each missing from at least one lane). This checker makes the coverage
// claim itself machine-checked:
//
//   (a) every vector file on disk must be listed in registry.json — a
//       newly added collection FAILS with "not listed in registry.json"
//       instead of silently reaching only the lanes that opted in;
//   (b) every listed collection must exist, be non-empty, and use only
//       the reason/failing vocabulary the manifest declares (exactly —
//       declared-but-unused vocabulary fails too, so the declaration
//       cannot rot);
//   (c) for every (collection × lane), the manifest must say ONE of:
//         { consumer } — a witness file that must exist and literally
//                        reference the collection's token;
//         { via }      — consumed transitively through another collection
//                        (e.g. plain-basic.json through signing-input.json's
//                        meta.capsule_ref), which must itself be directly
//                        consumed by the same lane;
//         { exempt }   — a stated reason the collection legitimately does
//                        not apply to the lane (e.g. no federation layer).
//       A missing lane key is a hard failure: silent omission is not
//       expressible.
//
// HONEST LIMITS. The witness check is a STATIC scan: it proves the lane's
// declared consumer file mentions the collection (its directory name or
// file stem), not that the test executes or asserts anything meaningful —
// a comment would satisfy it, and a lane's suite must still actually run
// in CI for the consumption to mean anything. A dynamic alternative (each
// lane's tests emitting the collections they consumed, cross-checked
// here) would be stronger but cannot run in this harness: the five lanes
// execute as separate CI jobs on different toolchains, and one of them
// (Kotlin) has no runtime in some dev environments at all. The static
// scan is the tripwire that survives every environment; the per-lane
// non-empty assertions (F40) and the lanes' own CI jobs carry the rest.

import { readdir, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, resolve, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..");
const VECTOR_DIR = join(REPO_ROOT, "spec", "vectors");
const REGISTRY_PATH = join(VECTOR_DIR, "registry.json");

const errors = [];
let checked = 0;
const fail = (message) => errors.push(message);

/** Every lane entry must be exactly one of these shapes. */
function laneEntryKind(entry) {
  if (entry && typeof entry === "object") {
    const keys = Object.keys(entry).filter((k) => k !== "mode");
    if (keys.length === 1 && typeof entry[keys[0]] === "string" && entry[keys[0]].length > 0) {
      if (keys[0] === "consumer" || keys[0] === "via" || keys[0] === "exempt") return keys[0];
    }
  }
  return null;
}

/** The literal a consumer file must contain: dir name, or file stem. */
function collectionToken(relPath) {
  if (relPath.includes("/")) return relPath.split("/")[0];
  return basename(relPath, ".json");
}

/** Walk spec/vectors for vector documents (excluding fixtures + registry). */
async function diskCollections() {
  const out = [];
  async function walk(dir, rel) {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const abs = join(dir, entry.name);
      const relPath = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (entry.name === "output") continue; // generated fixtures + keypairs
        await walk(abs, relPath);
      } else if (
        entry.name.endsWith(".json") &&
        entry.name !== "keys.json" &&
        relPath !== "registry.json"
      ) {
        out.push(relPath);
      }
    }
  }
  await walk(VECTOR_DIR, "");
  return out.sort();
}

/** Collect the vocabulary a collection's vectors actually use. */
function usedVocabulary(doc) {
  const failing = new Set();
  const openReasons = new Set();
  const rejectReasons = new Set();
  for (const v of doc.vectors ?? []) {
    if (!v || typeof v !== "object") continue;
    const exp = v.expected;
    if (exp && typeof exp === "object") {
      for (const area of exp.failing ?? []) failing.add(area);
      if (exp.stage === "open" && typeof exp.reason === "string") openReasons.add(exp.reason);
    }
    if (v.expect === "reject" && typeof v.reason === "string") rejectReasons.add(v.reason);
  }
  return { failing, openReasons, rejectReasons };
}

function assertVocab(relPath, label, declared, used) {
  const declaredSet = new Set(declared ?? []);
  for (const value of used) {
    if (!declaredSet.has(value)) {
      fail(`${relPath}: ${label} value '${value}' is used by a vector but not declared in registry.json`);
    }
  }
  for (const value of declaredSet) {
    if (!used.has(value)) {
      fail(`${relPath}: ${label} value '${value}' is declared in registry.json but no vector uses it`);
    }
  }
}

async function main() {
  if (!existsSync(REGISTRY_PATH)) {
    fail("spec/vectors/registry.json is missing — the lane × collection coverage manifest is required");
    return finish();
  }
  let registry;
  try {
    registry = JSON.parse(await readFile(REGISTRY_PATH, "utf8"));
  } catch (err) {
    fail(`spec/vectors/registry.json: cannot parse: ${err.message}`);
    return finish();
  }
  if (registry?.meta?.kind !== "vector-registry") {
    fail("spec/vectors/registry.json: meta.kind must be 'vector-registry'");
  }
  const lanes = Object.keys(registry.lanes ?? {});
  if (lanes.length === 0) {
    fail("spec/vectors/registry.json: no lanes declared");
    return finish();
  }
  const collections = registry.collections ?? {};

  // (a) disk ⊆ manifest and manifest ⊆ disk.
  const onDisk = await diskCollections();
  for (const relPath of onDisk) {
    checked++;
    if (!(relPath in collections)) {
      fail(
        `spec/vectors/${relPath}: vector file exists on disk but is not listed in registry.json — ` +
          `add it with a consumer (or explicit exemption) for every lane`,
      );
    }
  }
  for (const relPath of Object.keys(collections)) {
    if (!onDisk.includes(relPath)) {
      fail(`registry.json lists '${relPath}' but spec/vectors/${relPath} does not exist`);
    }
  }

  for (const [relPath, spec] of Object.entries(collections)) {
    const abs = join(VECTOR_DIR, relPath);
    if (!existsSync(abs)) continue; // already reported above
    let doc;
    try {
      doc = JSON.parse(await readFile(abs, "utf8"));
    } catch (err) {
      fail(`spec/vectors/${relPath}: cannot parse: ${err.message}`);
      continue;
    }

    // (b) non-empty + vocabulary drift, both directions.
    if (Array.isArray(doc.vectors) && doc.vectors.length === 0) {
      fail(`spec/vectors/${relPath}: vectors array is empty`);
    }
    if (!Array.isArray(doc.vectors) && spec.kind !== "embedded-capsule" && spec.kind !== "signing-input") {
      fail(`spec/vectors/${relPath}: expected a vectors array for kind '${spec.kind}'`);
    }
    if (spec.kind === "embedded-capsule" && typeof doc.capsule_bytes_b64 !== "string") {
      fail(`spec/vectors/${relPath}: embedded-capsule collection must carry capsule_bytes_b64`);
    }
    if (spec.kind === "signing-input" && doc?.meta?.kind !== "signing-input") {
      fail(`spec/vectors/${relPath}: signing-input collection must carry meta.kind === 'signing-input'`);
    }
    const used = usedVocabulary(doc);
    assertVocab(relPath, "failing_areas", spec.failing_areas, used.failing);
    assertVocab(relPath, "open_reasons", spec.open_reasons, used.openReasons);
    assertVocab(relPath, "reject_reasons", spec.reject_reasons, used.rejectReasons);

    // (c) lane completeness: every declared lane, exactly one entry shape.
    const laneEntries = spec.lanes ?? {};
    for (const lane of lanes) {
      checked++;
      const entry = laneEntries[lane];
      if (entry === undefined) {
        fail(
          `${relPath}: lane '${lane}' is not declared — add a consumer, a via, or an explicit exemption ` +
            `(silent omission is the failure mode this manifest exists to kill)`,
        );
        continue;
      }
      const kind = laneEntryKind(entry);
      if (!kind) {
        fail(`${relPath}: lane '${lane}' entry must be exactly one of {consumer}, {via}, {exempt}`);
        continue;
      }
      if (kind === "exempt") continue; // the stated reason IS the record
      if (kind === "via") {
        const target = entry.via;
        const targetSpec = collections[target];
        if (!targetSpec) {
          fail(`${relPath}: lane '${lane}' via '${target}': target collection is not in registry.json`);
          continue;
        }
        if (laneEntryKind(targetSpec.lanes?.[lane]) !== "consumer") {
          fail(
            `${relPath}: lane '${lane}' via '${target}': target must be DIRECTLY consumed by the same lane`,
          );
        }
        continue;
      }
      // consumer: witness file exists and references the collection token.
      const witnessAbs = join(REPO_ROOT, entry.consumer);
      if (!existsSync(witnessAbs)) {
        fail(`${relPath}: lane '${lane}' consumer '${entry.consumer}' does not exist`);
        continue;
      }
      if (entry.mode === "walker") continue; // consumes by directory walk, fail-closed
      const token = entry.token ?? collectionToken(relPath);
      const content = await readFile(witnessAbs, "utf8");
      if (!content.includes(token)) {
        fail(
          `${relPath}: lane '${lane}' consumer '${entry.consumer}' never references '${token}' — ` +
            `the declared consumption is not visible in the file`,
        );
      }
    }
    // No lane keys outside the declared lane set.
    for (const lane of Object.keys(laneEntries)) {
      if (!lanes.includes(lane)) {
        fail(`${relPath}: unknown lane '${lane}' (declared lanes: ${lanes.join(", ")})`);
      }
    }
  }
  finish();
}

function finish() {
  if (errors.length > 0) {
    for (const error of errors) console.error(`FAIL: ${error}`);
    process.exit(1);
  }
  console.log(`vector registry: ok (${checked} checks)`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

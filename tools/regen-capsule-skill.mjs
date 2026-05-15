#!/usr/bin/env node
// Regenerate `skills/capsule/skill.json` from canonical sources.
//
// The Capsule v0.6 skill is the protocol's own self-description: a
// `skills/capsule/` bundle (SKILL.md + skill.json) that any v0.6 capsule
// can include so a foreign LLM cold-reading the capsule learns what the
// container is and how to verify it.
//
// `skill.json` is fully derived: a hash of each canonical source file
// (the spec docs and SKILL.md) is embedded under `provenance.sources`.
// Drift between the bundle and its sources is detected by `--check`.
//
// Usage:
//   node tools/regen-capsule-skill.mjs            # write skill.json
//   node tools/regen-capsule-skill.mjs --check    # CI: exit 1 on drift
//
// No dependencies; Node stdlib only.

import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..");
const SKILL_PATH = join(REPO_ROOT, "skills", "capsule", "skill.json");

// Canonical source files. Order is preserved in the generated JSON.
// SKILL.md is itself a source — the foreign-LLM content. Hashing it
// in the bundle lets CI detect "SKILL.md was edited but skill.json
// was not regenerated."
const SOURCES = [
  { path: "spec/README.md",          title: "Spec index" },
  { path: "spec/format.md",          title: "File layout" },
  { path: "spec/manifest.md",        title: "manifest.json schema" },
  { path: "spec/chain.md",           title: "Event chain rules" },
  { path: "spec/envelope.md",        title: "Provenance envelope" },
  { path: "spec/trust.md",           title: "Trust model" },
  { path: "spec/pith.md",            title: "Pith context style" },
  { path: "skills/capsule/SKILL.md", title: "Foreign-LLM instructions" },
];

async function sha256Hex(absPath) {
  const bytes = await readFile(absPath);
  return createHash("sha256").update(bytes).digest("hex");
}

async function buildSkillJson() {
  const sources = [];
  for (const s of SOURCES) {
    const abs = join(REPO_ROOT, s.path);
    const sha256 = await sha256Hex(abs);
    sources.push({ path: s.path, title: s.title, sha256 });
  }

  return {
    id: "capsule",
    version: "0.6.0",
    title: "Capsule v0.6 — portable verifiable work-product",
    description:
      "A portable unit of intelligence: a work product, the context to continue it, " +
      "and a signed append-only audit trail. Verifies offline. Cold-readable by foreign LLMs.",
    spec_version: "0.6",
    audience: ["foreign-llm", "auditor", "human-reader"],
    applies_to: 'manifest.format.version == "0.6"',
    links: {
      manifest: "manifest.json",
      program: "program.md",
      agents: "agents.md",
      chain: "chain/events.jsonl",
      envelope: "provenance/envelope.json",
    },
    references: [
      { type: "spec", path: "spec/README.md", title: "Spec index" },
      { type: "spec", path: "spec/format.md", title: "File layout" },
      { type: "spec", path: "spec/manifest.md", title: "manifest.json schema" },
      { type: "spec", path: "spec/chain.md", title: "Event chain rules" },
      { type: "spec", path: "spec/envelope.md", title: "Provenance envelope" },
      { type: "spec", path: "spec/trust.md", title: "Trust model" },
      { type: "spec", path: "spec/pith.md", title: "Pith context style" },
      { type: "sdk", path: "sdk-js/", title: "Reference SDK (Node)" },
      { type: "sdk", path: "sdk-py/", title: "Python SDK" },
      { type: "sdk", path: "sdk-swift/", title: "Swift SDK" },
      { type: "sdk", path: "sdk-kotlin/", title: "Kotlin SDK" },
      { type: "verifier", path: "verifier-rust/", title: "Independent Rust verifier" },
      { type: "cli", path: "cli/", title: "Capsule CLI" },
    ],
    issuer: {
      label: "capsules-protocol",
      url: "https://github.com/virion-ai/capsule",
    },
    provenance: {
      generated_by: "tools/regen-capsule-skill.mjs",
      sources,
    },
  };
}

function serialize(obj) {
  // Pretty-printed JSON with a trailing newline — stable across runs.
  return JSON.stringify(obj, null, 2) + "\n";
}

async function main() {
  const check = process.argv.includes("--check");
  const expected = serialize(await buildSkillJson());

  if (check) {
    let actual = "";
    try {
      actual = await readFile(SKILL_PATH, "utf8");
    } catch (err) {
      console.error(`skills/capsule/skill.json: missing (${err.code ?? err.message})`);
      console.error("Run: node tools/regen-capsule-skill.mjs");
      process.exit(1);
    }
    if (actual !== expected) {
      console.error("skills/capsule/skill.json is out of date.");
      console.error("Run: node tools/regen-capsule-skill.mjs");
      process.exit(1);
    }
    console.log("skills/capsule/skill.json: ok");
    return;
  }

  await writeFile(SKILL_PATH, expected, "utf8");
  console.log("Wrote skills/capsule/skill.json");
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});

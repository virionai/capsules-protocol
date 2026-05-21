#!/usr/bin/env node
// Validate the generic examples are small, self-contained, and free of
// project-specific demo residue.

import { readdir, readFile, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { CapsuleReader, verifyCapsule } from "../sdk-js/src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..");
const EXAMPLES_ROOT = join(REPO_ROOT, "examples");
const MAX_CAPSULE_BYTES = 256 * 1024;
const EXPECTED_EXAMPLES = [
  "generic-report",
  "generic-table-graph",
  "generic-react-render",
];

const LOCAL_DENYLIST_PATH = join(REPO_ROOT, ".capsule-example-denylist");

const TEXT_RULES = [
  { label: "absolute macOS user path", pattern: /\/Users\// },
  { label: "absolute Linux home path", pattern: /\/home\/[^/\s]+/ },
  { label: "absolute mounted-volume path", pattern: /\/Volumes\// },
  { label: "Windows user path", pattern: /[A-Za-z]:\\Users\\/ },
  { label: "private key block", pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { label: "environment file reference", pattern: /(^|[/\\])\.env([.\s]|$)/ },
];
const DISALLOWED_HTML = [
  { label: "external URL", pattern: /https?:\/\//i },
  { label: "external script", pattern: /<script[^>]+src=/i },
  { label: "external stylesheet", pattern: /<link[^>]+href=["']https?:\/\//i },
];

const errors = [];

function fail(message) {
  errors.push(message);
}

async function readText(path) {
  return await readFile(path, "utf8");
}

async function loadLocalTextRules() {
  if (!existsSync(LOCAL_DENYLIST_PATH)) return [];
  const text = await readText(LOCAL_DENYLIST_PATH);
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .map((term, i) => ({
      label: `local denylist entry ${i + 1}`,
      test: (textToCheck) => textToCheck.toLowerCase().includes(term.toLowerCase()),
    }));
}

async function checkTextRules(path, rules) {
  const text = await readText(path);
  for (const rule of rules) {
    const matched = rule.pattern ? rule.pattern.test(text) : rule.test(text);
    if (matched) fail(`${path} contains ${rule.label}`);
  }
  return text;
}

async function checkNoWarranty(path, rules) {
  const text = await checkTextRules(path, rules);
  if (!/no warranty/i.test(text)) fail(`${path} must contain a no-warranty notice`);
}

async function listFiles(dir) {
  const out = [];
  async function walk(current) {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) await walk(path);
      else out.push(path);
    }
  }
  await walk(dir);
  return out;
}

async function main() {
  const textRules = [...TEXT_RULES, ...(await loadLocalTextRules())];

  if (!existsSync(EXAMPLES_ROOT)) fail("examples/ directory is missing");
  else await checkNoWarranty(join(EXAMPLES_ROOT, "README.md"), textRules);

  for (const name of EXPECTED_EXAMPLES) {
    const dir = join(EXAMPLES_ROOT, name);
    if (!existsSync(dir)) {
      fail(`examples/${name}/ is missing`);
      continue;
    }
    await checkNoWarranty(join(dir, "README.md"), textRules);
    for (const required of ["build.mjs", "package.json", "verify.mjs"]) {
      const path = join(dir, required);
      if (!existsSync(path)) fail(`examples/${name}/${required} is missing`);
      else await checkTextRules(path, textRules);
    }

    const outputDir = join(dir, "output");
    const capsulePath = join(outputDir, `${name}.capsule`);
    if (!existsSync(capsulePath)) {
      fail(`examples/${name}/output/${name}.capsule is missing; run npm test in examples/${name}`);
      continue;
    }
    const s = await stat(capsulePath);
    if (s.size > MAX_CAPSULE_BYTES) {
      fail(`examples/${name} capsule is too large: ${s.size} bytes`);
    }

    const capsuleBytes = await readFile(capsulePath);
    const reader = await CapsuleReader.fromBytes(capsuleBytes);
    const result = await verifyCapsule(reader, {
      allowlist: [reader.manifest().originator.public_key],
    });
    if (!result.ok) fail(`examples/${name} capsule does not verify: ${result.errors.join("; ")}`);

    const files = reader.files_();
    const workproductPaths = [...files.keys()].filter((p) => p.startsWith("payload/workproduct/"));
    if (!workproductPaths.some((p) => p.endsWith(".html"))) {
      fail(`examples/${name} must include a payload/workproduct/*.html file`);
    }
    for (const path of workproductPaths) {
      if (!path.endsWith(".html")) continue;
      const html = new TextDecoder().decode(files.get(path));
      for (const rule of DISALLOWED_HTML) {
        if (rule.pattern.test(html)) fail(`${name}:${path} is not self-contained: ${rule.label}`);
      }
    }
  }

  if (existsSync(EXAMPLES_ROOT)) {
    for (const path of await listFiles(EXAMPLES_ROOT)) {
      if (path.includes("/node_modules/")) continue;
      if (path.includes("/output/") && path.endsWith(".capsule")) continue;
      await checkTextRules(path, textRules);
    }
  }

  if (errors.length > 0) {
    for (const e of errors) console.error(`FAIL: ${e}`);
    process.exit(1);
  }
  console.log("generic examples: ok");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

// CLI smoke test. Exercises every command against real fixtures from the
// tamper-detection and medical-journal examples. Asserts:
//   - exit codes (0 PASS, 1 FAIL, 2 I/O / arg error)
//   - JSON output is parseable
//   - vectors verify passes against the medical-journal parity vectors
//
// Run from the CLI directory: `npm test`.

import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync, mkdirSync, rmSync } from "node:fs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const NEW_DESIGN = resolve(ROOT, "..");

const BIN = join(ROOT, "bin", "capsule.mjs");
const TAMPER = join(NEW_DESIGN, "examples", "tamper-detection", "output");
const MJ = join(NEW_DESIGN, "examples", "medical-journal", "output", "medical-journal.capsule");
const VECTORS = join(NEW_DESIGN, "examples", "medical-journal", "parity-vectors.json");

const TMP = join("/tmp", `capsule-cli-smoke-${process.pid}`);

let passed = 0;
let failed = 0;
const failures = [];

function run(args, opts = {}) {
  const res = spawnSync("node", [BIN, ...args], {
    encoding: "utf8",
    timeout: 30_000,
    ...opts,
  });
  return { code: res.status ?? -1, stdout: res.stdout ?? "", stderr: res.stderr ?? "" };
}

function check(label, ok, detail = "") {
  if (ok) {
    console.log(`  ✓ ${label}` + (detail ? ` — ${detail}` : ""));
    passed++;
  } else {
    console.log(`  ✗ ${label}` + (detail ? ` — ${detail}` : ""));
    failed++;
    failures.push(label);
  }
}

function section(name) {
  console.log(`\n${name}`);
  console.log("-".repeat(name.length));
}

// ----------------------------------------------------------------------

section("help / version / unknown");

{
  const r = run(["--help"]);
  check("`capsule --help` exits 0", r.code === 0);
  check("`capsule --help` lists subcommands", /verify\s+verify/.test(r.stderr));

  const v = run(["--version"]);
  check("`capsule --version` exits 0", v.code === 0);
  check("`capsule --version` prints version line", /^capsule \d/.test(v.stdout));

  const u = run(["does-not-exist"]);
  check("unknown command exits 2", u.code === 2);
  check("unknown command names the bad cmd", /does-not-exist/.test(u.stderr));

  const empty = run([]);
  check("empty argv exits 2", empty.code === 2);
}

// ----------------------------------------------------------------------

section("verify — clean and tampered");

if (!existsSync(join(TAMPER, "clean.capsule"))) {
  console.log("  ! tamper-detection fixtures missing; run `npm test` in examples/tamper-detection first");
  failed++;
  failures.push("tamper-detection fixtures missing");
} else {
  const r = run(["verify", join(TAMPER, "clean.capsule")]);
  check("clean.capsule exits 0", r.code === 0);
  check("clean.capsule prints PASS", /Result: PASS/.test(r.stdout));

  const tp = run(["verify", join(TAMPER, "tampered-payload.capsule")]);
  check("tampered-payload exits 1", tp.code === 1);
  check("tampered-payload prints FAIL", /Result: FAIL/.test(tp.stdout));

  const tc = run(["verify", join(TAMPER, "tampered-chain.capsule")]);
  check("tampered-chain exits 1", tc.code === 1);

  const te = run(["verify", join(TAMPER, "tampered-envelope.capsule")]);
  check("tampered-envelope exits 1", te.code === 1);

  const tb = run(["verify", join(TAMPER, "tampered-blob.capsule")]);
  check("tampered-blob exits 1", tb.code === 1);

  // JSON mode is parseable on success and on failure.
  const j = run(["verify", join(TAMPER, "clean.capsule"), "--json"]);
  check("--json clean exits 0", j.code === 0);
  let parsedClean;
  try { parsedClean = JSON.parse(j.stdout); } catch { /* */ }
  check("--json clean output parses", parsedClean && parsedClean.ok === true);
  check("--json clean has capsule_id", parsedClean && /^[0-9a-f]{64}$/.test(parsedClean.capsule_id ?? ""));
  check("--json clean has level=L2", parsedClean && parsedClean.level === "L2");

  const jt = run(["verify", join(TAMPER, "tampered-payload.capsule"), "--json"]);
  check("--json tampered exits 1", jt.code === 1);
  let parsedT;
  try { parsedT = JSON.parse(jt.stdout); } catch { /* */ }
  check("--json tampered output parses + ok=false", parsedT && parsedT.ok === false);
}

// ----------------------------------------------------------------------

section("verify — missing file (exit 2)");

{
  const r = run(["verify", "/tmp/does-not-exist.capsule"]);
  check("missing file exits 2", r.code === 2);
  check("missing file message goes to stderr", r.stderr.length > 0);
}

// ----------------------------------------------------------------------

section("inspect / chain / manifest / envelope / program / agents");

if (existsSync(MJ)) {
  const i = run(["inspect", MJ]);
  check("inspect exits 0", i.code === 0);
  check("inspect shows action histogram", /logged_symptom\s+\d/.test(i.stdout));
  check("inspect lists payload files", /payload\/.+\.(jpg|wav|mp4)/.test(i.stdout));

  const ij = run(["inspect", MJ, "--json"]);
  let parsedI;
  try { parsedI = JSON.parse(ij.stdout); } catch { /* */ }
  check("inspect --json parses", parsedI && parsedI.capsule_id);
  check("inspect --json has chain_length", parsedI && typeof parsedI.chain_length === "number" && parsedI.chain_length > 0);
  check("inspect --json has action_histogram", parsedI && parsedI.action_histogram && Object.keys(parsedI.action_histogram).length > 0);

  const c = run(["chain", MJ, "--limit", "3"]);
  check("chain --limit 3 exits 0", c.code === 0);
  check("chain prints header line", /kind\/action/.test(c.stdout));
  check("chain truncates with hint", /more event/.test(c.stdout));

  const cj = run(["chain", MJ, "--json"]);
  let parsedC;
  try { parsedC = JSON.parse(cj.stdout); } catch { /* */ }
  check("chain --json parses to array", Array.isArray(parsedC));
  check("chain --json events have hashes", Array.isArray(parsedC) && parsedC.every((e) => /^[0-9a-f]{64}$/.test(e.hash)));

  const m = run(["manifest", MJ]);
  let parsedM;
  try { parsedM = JSON.parse(m.stdout); } catch { /* */ }
  check("manifest output parses", parsedM && parsedM.format && parsedM.format.version === "0.6");

  const e = run(["envelope", MJ]);
  let parsedE;
  try { parsedE = JSON.parse(e.stdout); } catch { /* */ }
  check("envelope output parses", parsedE && parsedE.version === "0.6");
  check("envelope has signers[]", parsedE && Array.isArray(parsedE.signers) && parsedE.signers.length > 0);

  const p = run(["program", MJ]);
  check("program prints markdown", /^# /m.test(p.stdout));

  const a = run(["agents", MJ]);
  check("agents prints markdown", /^# Agents/m.test(a.stdout));
} else {
  console.log("  ! medical-journal capsule missing; run `npm test` in examples/medical-journal first");
  failed++;
  failures.push("medical-journal capsule missing");
}

// ----------------------------------------------------------------------

section("extract");

if (existsSync(MJ)) {
  rmSync(TMP, { recursive: true, force: true });
  const r = run(["extract", MJ, TMP]);
  check("extract exits 0", r.code === 0);
  check("extract creates manifest.json", existsSync(join(TMP, "manifest.json")));
  check("extract creates chain/events.jsonl", existsSync(join(TMP, "chain", "events.jsonl")));
  check("extract creates payload/", existsSync(join(TMP, "payload")));

  // Refuses to overwrite without --force.
  mkdirSync(TMP, { recursive: true });
  const r2 = run(["extract", MJ, TMP]);
  check("extract refuses non-empty dir", r2.code === 2);

  const r3 = run(["extract", MJ, TMP, "--force"]);
  check("extract --force overwrites", r3.code === 0);

  rmSync(TMP, { recursive: true, force: true });
}

// ----------------------------------------------------------------------

section("vectors verify (the parity contract)");

if (existsSync(VECTORS)) {
  const r = run(["vectors", "verify", VECTORS]);
  check("vectors verify exits 0", r.code === 0);
  check("vectors verify prints PASS", /Result: PASS/.test(r.stdout));
  check("vectors verify shows hash parity table", /Hash parity:/.test(r.stdout));

  const j = run(["vectors", "verify", VECTORS, "--json"]);
  let parsedV;
  try { parsedV = JSON.parse(j.stdout); } catch { /* */ }
  check("vectors --json ok=true", parsedV && parsedV.ok === true);
  check("vectors --json no diffs", parsedV && Array.isArray(parsedV.diffs) && parsedV.diffs.length === 0);
} else {
  console.log("  ! parity-vectors.json missing; run `npm run parity-vectors` in examples/medical-journal");
  failed++;
  failures.push("parity-vectors.json missing");
}

// ----------------------------------------------------------------------

section("keygen");

{
  const r = run(["keygen", "--json"]);
  check("keygen --json exits 0", r.code === 0);
  let parsedK;
  try { parsedK = JSON.parse(r.stdout); } catch { /* */ }
  check("keygen --json output parses", parsedK && parsedK.algorithm === "Ed25519");
  check("keygen produces 64-hex public key", parsedK && /^[0-9a-f]{64}$/.test(parsedK.public_key_hex ?? ""));
  check("keygen produces 64-hex private key", parsedK && /^[0-9a-f]{64}$/.test(parsedK.private_key_hex ?? ""));
}

// ----------------------------------------------------------------------

section("Summary");

console.log(`  ${passed} passed, ${failed} failed`);
if (failed > 0) {
  console.log("");
  console.log("  failures:");
  for (const f of failures) console.log(`    - ${f}`);
  process.exit(1);
}
process.exit(0);

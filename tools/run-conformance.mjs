#!/usr/bin/env node
// Capsule v0.6 conformance test harness.
//
// Runs each required repo-local target serially, captures structured
// results, and writes both JSON and Markdown reports under output/.
//
// Invoke from the capsules-protocol/ directory:
//   node tools/run-conformance.mjs
//
// Exits 0 if all required targets pass, 1 otherwise. Skipped optional
// targets do not fail the run. No new dependencies; Node stdlib only.

import { spawn } from "node:child_process";
import { mkdir, writeFile, stat, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join, resolve, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const HARNESS_VERSION = "0.1.0";
const SCHEMA_VERSION = "1.0";

// ---------------------------------------------------------------------------
// Resolve repo root. The harness lives at <repo>/tools/run-conformance.mjs.
// ---------------------------------------------------------------------------
const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..");
const OUT_DIR = join(REPO_ROOT, "output");
const JSON_PATH = join(OUT_DIR, "conformance-report.json");
const MD_PATH = join(OUT_DIR, "conformance-report.md");

// ---------------------------------------------------------------------------
// Target specs. Hard-coded; no user input ever interpolated into shells.
// All cwd paths are repo-relative.
// ---------------------------------------------------------------------------
const TARGETS = [
  {
    // Drift detector for skills/capsule/skill.json. Runs first so spec
    // edits that forget to regenerate the canonical skill fail loudly
    // before any example build burns time. No dependencies — Node only.
    id: "skill-capsule-regen",
    name: "skills/capsule regeneration check",
    language: "javascript",
    kind: "check",
    cwd: ".",
    install_cmd: "true",
    test_cmd: "node tools/regen-capsule-skill.mjs --check",
    pass_signal: { type: "exit_code", value: 0 },
  },
  {
    id: "sdk-js",
    name: "@capsule/sdk-v0.6-prototype",
    language: "javascript",
    kind: "sdk",
    cwd: "sdk-js",
    install_cmd: "npm install --prefer-offline --no-audit --no-fund",
    test_cmd: "npm test",
    pass_signal: { type: "exit_code", value: 0 },
    // node --test emits "# tests N", "# pass N", "# fail N".
    parse_output: {
      patterns: [
        { name: "tests_total",  regex: /^#\s*tests\s+(\d+)/m,  type: "number" },
        { name: "tests_passed", regex: /^#\s*pass\s+(\d+)/m,   type: "number" },
        { name: "tests_failed", regex: /^#\s*fail\s+(\d+)/m,   type: "number" },
      ],
    },
  },
  {
    id: "cli",
    name: "@capsule/cli",
    language: "javascript",
    kind: "cli",
    cwd: "cli",
    install_cmd: "npm install --prefer-offline --no-audit --no-fund",
    test_cmd: "npm test",
    pass_signal: { type: "exit_code", value: 0 },
  },
  {
    id: "spec-vectors",
    name: "spec/vectors registry",
    language: "javascript",
    kind: "check",
    cwd: ".",
    install_cmd: "true",
    test_cmd: "node tools/check-spec-vectors.mjs",
    pass_signal: { type: "exit_code", value: 0 },
  },
  {
    id: "example-generic-report",
    name: "generic-report",
    language: "javascript",
    kind: "example",
    cwd: "examples/generic-report",
    install_cmd: "npm install --prefer-offline --no-audit --no-fund",
    test_cmd: "npm test",
    pass_signal: { type: "exit_code", value: 0 },
    capsule_path: "examples/generic-report/output/generic-report.capsule",
  },
  {
    id: "example-generic-table-graph",
    name: "generic-table-graph",
    language: "javascript",
    kind: "example",
    cwd: "examples/generic-table-graph",
    install_cmd: "npm install --prefer-offline --no-audit --no-fund",
    test_cmd: "npm test",
    pass_signal: { type: "exit_code", value: 0 },
    capsule_path: "examples/generic-table-graph/output/generic-table-graph.capsule",
  },
  {
    id: "example-generic-react-render",
    name: "generic-react-render",
    language: "javascript",
    kind: "example",
    cwd: "examples/generic-react-render",
    install_cmd: "npm install --prefer-offline --no-audit --no-fund",
    test_cmd: "npm test",
    pass_signal: { type: "exit_code", value: 0 },
    capsule_path: "examples/generic-react-render/output/generic-react-render.capsule",
  },
  {
    id: "examples-generic-hygiene",
    name: "generic examples hygiene",
    language: "javascript",
    kind: "check",
    cwd: ".",
    install_cmd: "true",
    test_cmd: "node tools/check-generic-examples.mjs",
    pass_signal: { type: "exit_code", value: 0 },
  },
];

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

const MAX_HEAD = 2000;
const MAX_TAIL = 2000;
const MAX_STDERR = 4000;

function truncHead(s) {
  if (s.length <= MAX_HEAD) return s;
  return s.slice(0, MAX_HEAD);
}

function truncTail(s) {
  if (s.length <= MAX_TAIL) return s;
  return s.slice(-MAX_TAIL);
}

function truncStderr(s) {
  if (s.length <= MAX_STDERR) return s;
  // Keep head + tail, mark the elision.
  const half = Math.floor((MAX_STDERR - 32) / 2);
  return s.slice(0, half) + "\n…[truncated]…\n" + s.slice(-half);
}

// Strip absolute repo paths to keep reports reproducible across machines.
function stripRepoPath(s) {
  if (!s) return s;
  const abs = REPO_ROOT + sep;
  // Use a plain string replace; no regex anchors that could backtrack.
  return s.split(abs).join("");
}

function nowIso() {
  return new Date().toISOString();
}

function fmtMs(ms) {
  if (ms == null) return "?";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function statusBadge(status) {
  if (status === "pass") return "PASS";
  if (status === "fail") return "FAIL";
  if (status === "skip") return "SKIP";
  return status;
}

function fmtBytes(n) {
  if (n == null) return null;
  return n.toLocaleString("en-US");
}

// ---------------------------------------------------------------------------
// Run a single shell command and capture stdout/stderr + duration + exit.
//
// We use shell: true because npm install / npm test / chained commands
// are easiest that way. Target specs are HARD-CODED at the top of this
// file — no user input ever reaches the shell.
// ---------------------------------------------------------------------------
function runCommand({ command, cwd, env }) {
  return new Promise((resolveP) => {
    const startNs = process.hrtime.bigint();
    let stdout = "";
    let stderr = "";

    let child;
    try {
      child = spawn(command, {
        cwd,
        shell: true,
        env: { ...process.env, ...(env || {}) },
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (err) {
      const endNs = process.hrtime.bigint();
      resolveP({
        exit_code: 127,
        duration_ms: Number((endNs - startNs) / 1_000_000n),
        stdout: "",
        stderr: `spawn failed: ${err && err.message ? err.message : String(err)}`,
        spawn_error: true,
      });
      return;
    }

    child.stdout.on("data", (chunk) => { stdout += chunk.toString("utf8"); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });

    child.on("error", (err) => {
      stderr += `\n[spawn error] ${err && err.message ? err.message : String(err)}\n`;
    });

    child.on("close", (code, signal) => {
      const endNs = process.hrtime.bigint();
      const duration_ms = Number((endNs - startNs) / 1_000_000n);
      resolveP({
        exit_code: code == null ? (signal ? 128 : 1) : code,
        signal: signal || null,
        duration_ms,
        stdout,
        stderr,
        spawn_error: false,
      });
    });
  });
}

// ---------------------------------------------------------------------------
// Decide whether to skip `npm install`. If node_modules/ doesn't exist,
// always install. If both node_modules/.package-lock.json and the
// target's package-lock.json exist and the latter isn't newer, skip.
// On any uncertainty, install.
// ---------------------------------------------------------------------------
async function shouldSkipInstall(cwdAbs) {
  const nm = join(cwdAbs, "node_modules");
  if (!existsSync(nm)) return false;
  const nmLock = join(nm, ".package-lock.json");
  const repoLock = join(cwdAbs, "package-lock.json");
  if (!existsSync(nmLock) || !existsSync(repoLock)) return false;
  try {
    const [nmStat, repoStat] = await Promise.all([stat(nmLock), stat(repoLock)]);
    return repoStat.mtimeMs <= nmStat.mtimeMs;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Decide pass/fail for a target.
// ---------------------------------------------------------------------------
function evaluatePass(target, testResult) {
  const sig = target.pass_signal;
  if (sig.type === "exit_code") {
    return testResult.exit_code === sig.value;
  }
  if (sig.type === "stdout_contains") {
    return testResult.exit_code === 0 && testResult.stdout.includes(sig.value);
  }
  // Unknown signal — treat as fail.
  return false;
}

function parseOutput(target, stdout) {
  if (!target.parse_output) return null;
  const out = {};
  for (const p of target.parse_output.patterns) {
    const m = stdout.match(p.regex);
    if (m) {
      const raw = m[1];
      out[p.name] = p.type === "number" ? Number(raw) : raw;
    } else {
      out[p.name] = null;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Run a single target end-to-end and produce its report entry.
// ---------------------------------------------------------------------------
async function runTarget(target) {
  const cwdAbs = join(REPO_ROOT, target.cwd);
  const notes = [];

  // --- Install step ---
  let installEntry;
  if (!existsSync(cwdAbs)) {
    installEntry = {
      command: target.install_cmd,
      duration_ms: 0,
      exit_code: -1,
      skipped: false,
    };
    notes.push(`cwd ${target.cwd} does not exist`);
    const missingStatus = target.optional ? "skip" : "fail";
    return {
      target,
      install: installEntry,
      test: { command: target.test_cmd, duration_ms: 0, exit_code: -1 },
      status: missingStatus,
      stdout_head: "",
      stdout_tail: "",
      stderr: `target cwd ${target.cwd} not found`,
      parsed: { tests_passed: null, tests_total: null, tests_failed: null, capsule_bytes: null },
      notes,
    };
  }

  const skipInstall = await shouldSkipInstall(cwdAbs);
  if (skipInstall) {
    installEntry = {
      command: target.install_cmd,
      duration_ms: 0,
      exit_code: 0,
      skipped: true,
    };
    notes.push("install skipped: node_modules present and lockfile unchanged");
  } else {
    const r = await runCommand({ command: target.install_cmd, cwd: cwdAbs });
    installEntry = {
      command: target.install_cmd,
      duration_ms: r.duration_ms,
      exit_code: r.exit_code,
      skipped: false,
    };
    if (r.exit_code !== 0) {
      // Install failed. Required targets fail closed; optional targets skip.
      const installStatus = target.optional ? "skip" : "fail";
      notes.push(`install failed (exit ${r.exit_code})`);
      return {
        target,
        install: installEntry,
        test: { command: target.test_cmd, duration_ms: 0, exit_code: -1 },
        status: installStatus,
        stdout_head: truncHead(stripRepoPath(r.stdout)),
        stdout_tail: truncTail(stripRepoPath(r.stdout)),
        stderr: truncStderr(stripRepoPath(r.stderr)),
        parsed: { tests_passed: null, tests_total: null, tests_failed: null, capsule_bytes: null },
        notes,
      };
    }
  }

  // --- Test step ---
  const test = await runCommand({ command: target.test_cmd, cwd: cwdAbs });
  const passed = evaluatePass(target, test);
  const parsedExtra = parseOutput(target, test.stdout) || {};

  // Resolve capsule size (if applicable). Path in spec is repo-relative.
  let capsule_bytes = null;
  if (target.capsule_path) {
    const absCapsule = join(REPO_ROOT, target.capsule_path);
    try {
      const s = await stat(absCapsule);
      capsule_bytes = s.size;
    } catch {
      capsule_bytes = null;
      notes.push(`capsule artifact not found: ${target.capsule_path}`);
    }
  }

  const parsed = {
    tests_passed: parsedExtra.tests_passed ?? null,
    tests_total:  parsedExtra.tests_total  ?? null,
    tests_failed: parsedExtra.tests_failed ?? null,
    capsule_bytes,
  };

  return {
    target,
    install: installEntry,
    test: {
      command: target.test_cmd,
      duration_ms: test.duration_ms,
      exit_code: test.exit_code,
    },
    status: passed ? "pass" : "fail",
    stdout_head: truncHead(stripRepoPath(test.stdout)),
    stdout_tail: truncTail(stripRepoPath(test.stdout)),
    stderr: truncStderr(stripRepoPath(test.stderr)),
    parsed,
    notes,
  };
}

// ---------------------------------------------------------------------------
// Build the final JSON document and markdown summary.
// ---------------------------------------------------------------------------
function buildJsonReport(entries, totalDurationMs) {
  const targets = {};
  let passed = 0, failed = 0, skipped = 0;
  for (const e of entries) {
    if (e.status === "pass") passed++;
    else if (e.status === "fail") failed++;
    else skipped++;
    targets[e.target.id] = {
      name: e.target.name,
      language: e.target.language,
      kind: e.target.kind,
      cwd: e.target.cwd,
      install: e.install,
      test: e.test,
      status: e.status,
      stdout_head: e.stdout_head,
      stdout_tail: e.stdout_tail,
      stderr: e.stderr,
      parsed: e.parsed,
      notes: e.notes,
    };
  }
  return {
    schema_version: SCHEMA_VERSION,
    generated_at: nowIso(),
    harness_version: HARNESS_VERSION,
    node_version: process.version,
    platform: process.platform,
    repo: "capsules-protocol",
    targets,
    summary: {
      total: entries.length,
      passed,
      failed,
      skipped,
      total_duration_ms: totalDurationMs,
      overall_status: failed > 0 ? "fail" : "pass",
    },
  };
}

function buildMarkdown(report) {
  const lines = [];
  const s = report.summary;
  const overall = s.overall_status === "pass" ? "PASS" : "FAIL";
  lines.push(`# Capsule v0.6 conformance report`);
  lines.push("");
  lines.push(`**Generated:** ${report.generated_at}  `);
  lines.push(`**Node:** ${report.node_version}  `);
  lines.push(`**Platform:** ${report.platform}  `);
  lines.push(`**Harness:** v${report.harness_version}  `);
  lines.push(
    `**Overall status:** ${overall} · ${s.passed}/${s.total} targets passed` +
      (s.failed ? ` · ${s.failed} failed` : "") +
      (s.skipped ? ` · ${s.skipped} skipped` : "") +
      ` · ${fmtMs(s.total_duration_ms)} total`,
  );
  lines.push("");
  lines.push(`## Targets`);
  lines.push("");

  for (const [id, t] of Object.entries(report.targets)) {
    const badge = statusBadge(t.status);
    lines.push(`### [${badge}] ${id} — ${t.name}`);
    lines.push(`- Language: ${t.language} · Kind: ${t.kind}`);
    lines.push(`- Test command: \`${t.test.command}\` (cwd: \`${t.cwd}\`)`);
    if (t.install.skipped) {
      lines.push(`- Install: skipped (cached) · Test duration: ${fmtMs(t.test.duration_ms)} · Exit code: ${t.test.exit_code}`);
    } else {
      lines.push(`- Install duration: ${fmtMs(t.install.duration_ms)} (exit ${t.install.exit_code}) · Test duration: ${fmtMs(t.test.duration_ms)} · Exit code: ${t.test.exit_code}`);
    }
    if (t.parsed && t.parsed.tests_total != null) {
      lines.push(`- Tests: ${t.parsed.tests_passed ?? "?"} passed of ${t.parsed.tests_total}${t.parsed.tests_failed ? ` (${t.parsed.tests_failed} failed)` : ""}`);
    }
    if (t.parsed && t.parsed.capsule_bytes != null) {
      // Derive a repo-relative capsule path from the target id by checking the spec list.
      const spec = TARGETS.find((x) => x.id === id);
      if (spec && spec.capsule_path) {
        lines.push(`- Sealed capsule: ${fmtBytes(t.parsed.capsule_bytes)} bytes (\`${spec.capsule_path}\`)`);
      } else {
        lines.push(`- Sealed capsule: ${fmtBytes(t.parsed.capsule_bytes)} bytes`);
      }
    }
    if (t.notes && t.notes.length > 0) {
      for (const n of t.notes) lines.push(`- Note: ${n}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------
async function main() {
  await mkdir(OUT_DIR, { recursive: true });

  const overallStart = process.hrtime.bigint();
  const entries = [];

  console.log(`Capsule v0.6 conformance harness v${HARNESS_VERSION}`);
  console.log(`Node ${process.version} on ${process.platform}`);
  console.log(`Targets: ${TARGETS.length}`);
  console.log("");

  for (let i = 0; i < TARGETS.length; i++) {
    const t = TARGETS[i];
    process.stdout.write(`[${i + 1}/${TARGETS.length}] ${t.id} ... `);
    const entry = await runTarget(t);
    entries.push(entry);
    const badge = statusBadge(entry.status);
    const dur = fmtMs(
      (entry.install.duration_ms || 0) + (entry.test.duration_ms || 0),
    );
    console.log(`${badge} (${dur})`);
  }

  const overallEnd = process.hrtime.bigint();
  const total_duration_ms = Number((overallEnd - overallStart) / 1_000_000n);

  const report = buildJsonReport(entries, total_duration_ms);
  const md = buildMarkdown(report);

  await writeFile(JSON_PATH, JSON.stringify(report, null, 2) + "\n", "utf8");
  await writeFile(MD_PATH, md.endsWith("\n") ? md : md + "\n", "utf8");

  console.log("");
  console.log(`Wrote ${relative(REPO_ROOT, JSON_PATH)}`);
  console.log(`Wrote ${relative(REPO_ROOT, MD_PATH)}`);
  console.log("");

  const { summary } = report;
  const overall = summary.overall_status === "pass" ? "PASS" : "FAIL";
  console.log(
    `${overall} · ${summary.passed}/${summary.total} passed` +
      (summary.failed ? ` · ${summary.failed} failed` : "") +
      (summary.skipped ? ` · ${summary.skipped} skipped` : "") +
      ` · ${fmtMs(summary.total_duration_ms)} total`,
  );

  process.exit(summary.failed > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error("Harness crashed:", err && err.stack ? err.stack : err);
  process.exit(2);
});

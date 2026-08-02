// CLI smoke test. Exercises every command against repo-local fixtures
// generated from the JavaScript reference SDK at test startup.
//
// Run from the CLI directory after `npm install`: `npm test`.

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  CapsuleBuilder,
  CapsuleReader,
  generateEd25519,
  packZip,
} from "@capsule/sdk-v0.6-prototype";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const BIN = join(ROOT, "bin", "capsule.mjs");

const TMP = join(tmpdir(), `capsule-cli-smoke-${process.pid}`);
const FIXTURES = join(TMP, "fixtures");
const CLEAN = join(FIXTURES, "clean.capsule");
const TAMPERED = join(FIXTURES, "tampered-payload.capsule");
const VECTORS = join(FIXTURES, "parity-vectors.json");
const EXTRACT_DIR = join(TMP, "extract");

let passed = 0;
let failed = 0;
const failures = [];

// Keys the trust-policy tests need; populated by buildFixtures().
const KEYS = { originatorPublicKeyHex: "", strangerPublicKeyHex: "" };

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
    console.log(`  ok - ${label}` + (detail ? ` - ${detail}` : ""));
    passed++;
  } else {
    console.log(`  not ok - ${label}` + (detail ? ` - ${detail}` : ""));
    failed++;
    failures.push(label);
  }
}

function section(name) {
  console.log(`\n${name}`);
  console.log("-".repeat(name.length));
}

async function buildFixtures() {
  rmSync(TMP, { recursive: true, force: true });
  mkdirSync(FIXTURES, { recursive: true });

  const originator = generateEd25519();
  KEYS.originatorPublicKeyHex = originator.publicKeyHex;
  // A perfectly valid key that signed nothing — the "wrong signer" case.
  KEYS.strangerPublicKeyHex = generateEd25519().publicKeyHex;
  const builder = new CapsuleBuilder({
    originator: { publicKey: originator.publicKeyHex, label: "CLI Smoke" },
    participants: [
      { actor_id: "human:cli", role: "originator", label: "CLI Test" },
      { actor_id: "tool:smoke", role: "verifier", label: "Smoke Test" },
    ],
  });

  builder.setProgram("# CLI Smoke\n\nCLI verification fixture.\n");
  builder.setAgents("# Agents\n\n- human:cli may create and verify this fixture.\n");
  builder.addPayload("payload/observation.txt", Buffer.from("fixture payload\n", "utf8"));
  builder.addSkill("smoke", {
    json: { id: "smoke", description: "CLI smoke-test skill fixture" },
    markdown: "# Smoke\n\nLocal test fixture.\n",
    signed: true,
  });

  await builder.appendEvent({
    actor: "human:cli",
    kind: "decision",
    action: "created",
    target: "program.md",
    timestamp: "2026-05-21T12:00:00Z",
    payload: { summary: "Created CLI smoke fixture" },
  });
  await builder.appendEvent({
    actor: "tool:smoke",
    kind: "observation",
    action: "reviewed",
    target: "payload/observation.txt",
    timestamp: "2026-05-21T12:00:01Z",
    payload: { summary: "Reviewed payload fixture" },
  });

  const cleanBytes = await builder.seal({
    signers: [
      { role: "originator", publicKey: originator.publicKey, privateKey: originator.privateKey },
    ],
    signedAt: "2026-05-21T12:00:02Z",
  });
  writeFileSync(CLEAN, Buffer.from(cleanBytes));

  const reader = await CapsuleReader.fromBytes(cleanBytes);
  const files = new Map(reader.files_());
  files.set("program.md", Buffer.from("# CLI Smoke\n\nTampered fixture.\n", "utf8"));
  writeFileSync(TAMPERED, Buffer.from(await packZip(files)));

  const manifest = reader.manifest();
  const envelope = reader.envelope();
  const events = reader.events();
  writeFileSync(
    VECTORS,
    JSON.stringify(
      {
        meta: {
          format_version: manifest.format.version,
          generator: "cli/test/smoke.mjs",
        },
        signed_at: envelope.signed_at,
        originator_public_key_hex: originator.publicKeyHex,
        expected: {
          capsule_id: manifest.id,
          first_event_hash: manifest.first_event_hash,
          entry_hash: envelope.entry_hash,
          manifest_hash: envelope.manifest_hash,
          content_index_hash: envelope.content_index_hash,
          envelope_signature_hex: envelope.signers[0].signature,
          event_hashes: events.map((e) => e.hash),
        },
        capsule_bytes_b64: Buffer.from(cleanBytes).toString("base64"),
      },
      null,
      2,
    ) + "\n",
  );
}

await buildFixtures();

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

section("verify - clean and tampered");

{
  const r = run(["verify", CLEAN]);
  check("clean.capsule exits 0", r.code === 0);
  check("clean.capsule prints PASS", /Result: PASS/.test(r.stdout));

  const t = run(["verify", TAMPERED]);
  check("tampered-payload exits 1", t.code === 1);
  check("tampered-payload prints FAIL", /Result: FAIL/.test(t.stdout));

  const j = run(["verify", CLEAN, "--json"]);
  check("--json clean exits 0", j.code === 0);
  let parsedClean;
  try { parsedClean = JSON.parse(j.stdout); } catch { /* noop */ }
  check("--json clean output parses", parsedClean && parsedClean.ok === true);
  check("--json clean has capsule_id", parsedClean && /^[0-9a-f]{64}$/.test(parsedClean.capsule_id ?? ""));
  check("--json clean has level=L2", parsedClean && parsedClean.level === "L2");

  const jt = run(["verify", TAMPERED, "--json"]);
  check("--json tampered exits 1", jt.code === 1);
  let parsedT;
  try { parsedT = JSON.parse(jt.stdout); } catch { /* noop */ }
  check("--json tampered output parses + ok=false", parsedT && parsedT.ok === false);
}

// ----------------------------------------------------------------------

section("verify - missing file (exit 2)");

{
  const r = run(["verify", join(TMP, "does-not-exist.capsule")]);
  check("missing file exits 2", r.code === 2);
  check("missing file message goes to stderr", r.stderr.length > 0);
}

// ----------------------------------------------------------------------

section("inspect / chain / manifest / envelope / program / agents");

{
  const i = run(["inspect", CLEAN]);
  check("inspect exits 0", i.code === 0);
  check("inspect shows action histogram", /created\s+\d/.test(i.stdout));
  check("inspect lists payload files", /payload\/observation\.txt/.test(i.stdout));

  const ij = run(["inspect", CLEAN, "--json"]);
  let parsedI;
  try { parsedI = JSON.parse(ij.stdout); } catch { /* noop */ }
  check("inspect --json parses", parsedI && parsedI.capsule_id);
  check("inspect --json has chain_length", parsedI && parsedI.chain_length === 2);
  check("inspect --json has action_histogram", parsedI && parsedI.action_histogram.created === 1);

  const c = run(["chain", CLEAN, "--limit", "1"]);
  check("chain --limit 1 exits 0", c.code === 0);
  check("chain prints header line", /kind\/action/.test(c.stdout));
  check("chain truncates with hint", /more event/.test(c.stdout));

  const cj = run(["chain", CLEAN, "--json"]);
  let parsedC;
  try { parsedC = JSON.parse(cj.stdout); } catch { /* noop */ }
  check("chain --json parses to array", Array.isArray(parsedC));
  check("chain --json events have hashes", Array.isArray(parsedC) && parsedC.every((e) => /^[0-9a-f]{64}$/.test(e.hash)));

  const m = run(["manifest", CLEAN]);
  let parsedM;
  try { parsedM = JSON.parse(m.stdout); } catch { /* noop */ }
  check("manifest output parses", parsedM && parsedM.format && parsedM.format.version === "0.6");

  const e = run(["envelope", CLEAN]);
  let parsedE;
  try { parsedE = JSON.parse(e.stdout); } catch { /* noop */ }
  check("envelope output parses", parsedE && parsedE.version === "0.6");
  check("envelope has signers[]", parsedE && Array.isArray(parsedE.signers) && parsedE.signers.length > 0);

  const p = run(["program", CLEAN]);
  check("program prints markdown", /^# CLI Smoke/m.test(p.stdout));

  const a = run(["agents", CLEAN]);
  check("agents prints markdown", /^# Agents/m.test(a.stdout));
}

// ----------------------------------------------------------------------

section("extract");

{
  rmSync(EXTRACT_DIR, { recursive: true, force: true });
  const r = run(["extract", CLEAN, EXTRACT_DIR]);
  check("extract exits 0", r.code === 0);
  check("extract creates manifest.json", existsSync(join(EXTRACT_DIR, "manifest.json")));
  check("extract creates chain/events.jsonl", existsSync(join(EXTRACT_DIR, "chain", "events.jsonl")));
  check("extract creates payload/", existsSync(join(EXTRACT_DIR, "payload")));

  mkdirSync(EXTRACT_DIR, { recursive: true });
  const r2 = run(["extract", CLEAN, EXTRACT_DIR]);
  check("extract refuses non-empty dir", r2.code === 2);

  const r3 = run(["extract", CLEAN, EXTRACT_DIR, "--force"]);
  check("extract --force overwrites", r3.code === 0);
}

// ----------------------------------------------------------------------

section("vectors verify");

{
  const r = run(["vectors", "verify", VECTORS]);
  check("vectors verify exits 0", r.code === 0);
  check("vectors verify prints PASS", /Result: PASS/.test(r.stdout));
  check("vectors verify shows hash parity table", /Hash parity:/.test(r.stdout));

  const j = run(["vectors", "verify", VECTORS, "--json"]);
  let parsedV;
  try { parsedV = JSON.parse(j.stdout); } catch { /* noop */ }
  check("vectors --json ok=true", parsedV && parsedV.ok === true);
  check("vectors --json no diffs", parsedV && Array.isArray(parsedV.diffs) && parsedV.diffs.length === 0);
}

// ----------------------------------------------------------------------

section("keygen");

{
  const r = run(["keygen", "--json"]);
  check("keygen --json exits 0", r.code === 0);
  let parsedK;
  try { parsedK = JSON.parse(r.stdout); } catch { /* noop */ }
  check("keygen --json output parses", parsedK && parsedK.algorithm === "Ed25519");
  check("keygen produces 64-hex public key", parsedK && /^[0-9a-f]{64}$/.test(parsedK.public_key_hex ?? ""));
  check("keygen produces 64-hex private key", parsedK && /^[0-9a-f]{64}$/.test(parsedK.private_key_hex ?? ""));
}

// ----------------------------------------------------------------------

section("verify - trust policy drives the verdict (F04)");

{
  const okKey = KEYS.originatorPublicKeyHex;
  const wrongKey = KEYS.strangerPublicKeyHex;

  // Allowlisted signer: integrity AND policy hold.
  const match = run(["verify", CLEAN, "--allowlist", okKey]);
  check("allowlisted signer exits 0", match.code === 0);
  check("allowlisted signer prints qualified PASS",
    /Result: PASS \(integrity verified; trust policy satisfied\)/.test(match.stdout));
  check("allowlisted signer shows trusted=true", /trusted=true/.test(match.stdout));

  // Supplied-but-unmatched allowlist: the capsule is signed by someone
  // the operator did not trust. That must FAIL loudly, not PASS quietly.
  const miss = run(["verify", CLEAN, "--allowlist", wrongKey]);
  check("unmatched allowlist exits 1", miss.code === 1);
  check("unmatched allowlist prints FAIL", /Result: FAIL/.test(miss.stdout));
  check("unmatched allowlist is loud about why",
    /no signer matches the supplied allowlist/.test(miss.stdout));

  const missJson = run(["verify", CLEAN, "--allowlist", wrongKey, "--json"]);
  check("unmatched allowlist --json exits 1", missJson.code === 1);
  let missParsed;
  try { missParsed = JSON.parse(missJson.stdout); } catch { /* noop */ }
  check("unmatched --json ok=false but integrity_ok=true",
    missParsed && missParsed.ok === false && missParsed.integrity_ok === true);
  check("unmatched --json trust block says unsatisfied",
    missParsed && missParsed.trust
      && missParsed.trust.policy === "allowlist"
      && missParsed.trust.satisfied === false
      && missParsed.trust.trusted_signer_count === 0);

  const matchJson = run(["verify", CLEAN, "--allowlist", okKey, "--json"]);
  let matchParsed;
  try { matchParsed = JSON.parse(matchJson.stdout); } catch { /* noop */ }
  check("matched --json ok=true and trust satisfied",
    matchParsed && matchParsed.ok === true && matchParsed.trust
      && matchParsed.trust.satisfied === true
      && matchParsed.trust.trusted_signer_count === 1);

  // No allowlist: no policy. PASS, but the verdict must say what it covers.
  const none = run(["verify", CLEAN]);
  check("no allowlist still exits 0", none.code === 0);
  check("no-allowlist PASS is qualified as integrity-only",
    /Result: PASS \(integrity only/.test(none.stdout));
  check("no-allowlist report says signer identity not checked",
    /signer identity not checked/.test(none.stdout));

  const noneJson = run(["verify", CLEAN, "--json"]);
  let noneParsed;
  try { noneParsed = JSON.parse(noneJson.stdout); } catch { /* noop */ }
  check("no-allowlist --json trust: policy none, satisfied null",
    noneParsed && noneParsed.ok === true && noneParsed.trust
      && noneParsed.trust.policy === "none"
      && noneParsed.trust.satisfied === null);

  // Integrity still gates: a tampered capsule fails even when the trust
  // policy would be satisfied.
  const tm = run(["verify", TAMPERED, "--allowlist", okKey]);
  check("tampered capsule fails even with satisfied policy", tm.code === 1);

  // A trust-config value that can never match a signer is a usage error
  // (parity with the Rust CLI's --allowlist validation), not a quiet
  // trusted=false.
  const badKey = run(["verify", CLEAN, "--allowlist", "not-a-key"]);
  check("malformed allowlist entry exits 2", badKey.code === 2);
  check("malformed allowlist message states the expected shape",
    /64 hex/.test(badKey.stderr));
}

// ----------------------------------------------------------------------

section("verify/inspect - self-attested time is labelled (F48)");

{
  const r = run(["verify", CLEAN]);
  check("verify labels sealed-at as attested", /Sealed at \(attested\):/.test(r.stdout));
  check("verify attested label carries the caveat", /signer-supplied/.test(r.stdout));

  const i = run(["inspect", CLEAN]);
  check("inspect labels sealed-at as attested", /Sealed at \(attested\):/.test(i.stdout));
}

// ----------------------------------------------------------------------

section("args - unknown flags and extra positionals fail closed (F03)");

{
  const someKey = "cc".repeat(32);

  // A typo'd trust flag must never silently drop the policy and PASS.
  const typo = run(["verify", CLEAN, "--alowlist", someKey]);
  check("typo'd --alowlist exits 2", typo.code === 2);
  check("typo'd --alowlist names the flag on stderr", /--alowlist/.test(typo.stderr));
  check("typo'd --alowlist prints no verdict", !/Result:/.test(typo.stdout));

  // The exact invocation inspect.mjs used to recommend; the flag does
  // not exist, so it must be an error, not a silent PASS.
  const dk = run(["verify", CLEAN, "--decryption-key", someKey]);
  check("verify --decryption-key exits 2 (flag not implemented)", dk.code === 2);
  check("verify --decryption-key names the flag on stderr", /--decryption-key/.test(dk.stderr));

  // Two files: verifying only the first and ignoring the second is a lie.
  const extra = run(["verify", CLEAN, TAMPERED]);
  check("second positional exits 2", extra.code === 2);
  check("second positional named on stderr", /unexpected argument/.test(extra.stderr));

  // Fail-closed parsing is parser-wide, not verify-specific.
  const short = run(["inspect", CLEAN, "-x"]);
  check("unknown short flag exits 2", short.code === 2);
  check("unknown short flag named on stderr", /-x/.test(short.stderr));

  // A flag that requires a value but has none is a clean usage error,
  // not a stack trace.
  const missing = run(["chain", CLEAN, "--limit"]);
  check("flag missing its value exits 2", missing.code === 2);
  check("flag missing its value gets a clean message", /requires a value/.test(missing.stderr) && !/at .*\(/.test(missing.stderr));

  // --help is universally recognized (it must not become an unknown flag).
  const help = run(["verify", "--help"]);
  check("verify --help exits 0", help.code === 0);
  check("verify --help prints usage", /usage: capsule verify/.test(help.stderr));
}

// ----------------------------------------------------------------------

section("Summary");

console.log(`  ${passed} passed, ${failed} failed`);
rmSync(TMP, { recursive: true, force: true });
if (failed > 0) {
  console.log("");
  console.log("  failures:");
  for (const f of failures) console.log(`    - ${f}`);
  process.exit(1);
}
process.exit(0);

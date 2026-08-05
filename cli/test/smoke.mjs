// CLI smoke test. Exercises every command against repo-local fixtures
// generated from the JavaScript reference SDK at test startup.
//
// Run from the CLI directory after `npm install`: `npm test`.

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  CapsuleBuilder,
  CapsuleReader,
  generateEd25519,
  generateX25519,
  packZip,
  SPEC_VERSION,
} from "@capsule/sdk-v0.7-prototype";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const BIN = join(ROOT, "bin", "capsule.mjs");

const TMP = join(tmpdir(), `capsule-cli-smoke-${process.pid}`);
const FIXTURES = join(TMP, "fixtures");
const CLEAN = join(FIXTURES, "clean.capsule");
const TAMPERED = join(FIXTURES, "tampered-payload.capsule");
const ENCRYPTED = join(FIXTURES, "encrypted.capsule");
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
      { actor_id: "system:smoke", role: "verifier", label: "Smoke Test" },
    ],
  });

  builder.setProgram("# CLI Smoke\n\nCLI verification fixture.\n");
  builder.setAgents("# Agents\n\n- human:cli may create and verify this fixture.\n");
  builder.addPayload("payload/observation.txt", Buffer.from("fixture payload\n", "utf8"));
  builder.addSkill("smoke", {
    json: { id: "smoke", description: "CLI smoke-test skill fixture" },
    markdown: "# Smoke\n\nLocal test fixture.\n",
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
    actor: "system:smoke",
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

  // Encrypted fixture: same originator, one X25519 recipient.
  const encBuilder = new CapsuleBuilder({
    originator: { publicKey: originator.publicKeyHex, label: "CLI Smoke Enc" },
  });
  encBuilder.setProgram("# CLI Smoke (encrypted)\n");
  await encBuilder.appendEvent({
    actor: "human:cli",
    kind: "decision",
    action: "created",
    target: "program.md",
    timestamp: "2026-05-21T12:00:00Z",
    payload: { summary: "Created encrypted CLI smoke fixture" },
  });
  const encBytes = await encBuilder.seal({
    signers: [
      { role: "originator", publicKey: originator.publicKey, privateKey: originator.privateKey },
    ],
    recipients: generateX25519(),
    signedAt: "2026-05-21T12:00:02Z",
  });
  writeFileSync(ENCRYPTED, Buffer.from(encBytes));

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
  check("clean.capsule prints VALID", /Result: VALID/.test(r.stdout));

  const t = run(["verify", TAMPERED]);
  check("tampered-payload exits 1", t.code === 1);
  check("tampered-payload prints INVALID", /Result: INVALID/.test(t.stdout));

  const j = run(["verify", CLEAN, "--json"]);
  {
    // spec/versioning.md: the observed format version is a REPORTED fact
    // on the verify result, and the human report names the era applied.
    const parsed = JSON.parse(j.stdout);
    check("verify --json reports format_version.observed",
      parsed.format_version?.observed === SPEC_VERSION && parsed.format_version?.supported === true);
    const human = run(["verify", CLEAN]);
    check("verify human report names the format version",
      new RegExp(`Format version:\\s+${SPEC_VERSION.replace(".", "\\.")}`).test(human.stdout));
  }
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
  check("manifest output parses", parsedM && parsedM.format && parsedM.format.version === SPEC_VERSION);

  const e = run(["envelope", CLEAN]);
  let parsedE;
  try { parsedE = JSON.parse(e.stdout); } catch { /* noop */ }
  check("envelope output parses", parsedE && parsedE.version === SPEC_VERSION);
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
  check("allowlisted signer prints an unqualified VALID naming its trust basis",
    /Result: VALID \(no qualifiers; 1 distinct trusted signer\)/.test(match.stdout));
  check("allowlisted signer reports the satisfied policy beside the verdict",
    /trust policy: SATISFIED/.test(match.stdout));
  check("allowlisted signer shows trusted=true", /trusted=true/.test(match.stdout));

  // Supplied-but-unmatched allowlist: the capsule is signed by someone
  // the operator did not trust. The MATH is still valid (the SDK reports
  // facts), so the verdict stays VALID — but the operator's demand went
  // unmet, so the run FAILS loudly at exit 1 and says which demand.
  const miss = run(["verify", CLEAN, "--allowlist", wrongKey]);
  check("unmatched allowlist exits 1", miss.code === 1);
  check("unmatched allowlist keeps the math verdict VALID", /Result: VALID/.test(miss.stdout));
  check("unmatched allowlist reports the failed policy beside the verdict",
    /trust policy: FAILED/.test(miss.stdout));
  check("unmatched allowlist is loud about why",
    /matched no signer/.test(miss.stdout));

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
  // Skill trust is DERIVED from the allowlist at verify time
  // (spec/trust.md "Skill trust"): an unmatched allowlist means the
  // fixture's skill classifies unsigned, whatever the capsule claims.
  check("unmatched --json derives skill_trust unsigned",
    missParsed && missParsed.skill_trust
      && missParsed.skill_trust.capsule_signed === false
      && missParsed.skill_trust.skills
      && missParsed.skill_trust.skills.smoke === "unsigned");

  const matchJson = run(["verify", CLEAN, "--allowlist", okKey, "--json"]);
  let matchParsed;
  try { matchParsed = JSON.parse(matchJson.stdout); } catch { /* noop */ }
  check("matched --json ok=true and trust satisfied",
    matchParsed && matchParsed.ok === true && matchParsed.trust
      && matchParsed.trust.satisfied === true
      && matchParsed.trust.trusted_signer_count === 1);
  check("matched --json derives skill_trust signed",
    matchParsed && matchParsed.skill_trust
      && matchParsed.skill_trust.capsule_signed === true
      && matchParsed.skill_trust.skills
      && matchParsed.skill_trust.skills.smoke === "signed");

  // A FAILING capsule must never classify its skills as signed, even
  // with the actual signer allowlisted (spec/trust.md: the derivation
  // consults the OVERALL verdict). The spec vector: envelope signature
  // valid, content index valid, but signer_commitment names a key that
  // never signed — ok=false, and skills stay unsigned.
  {
    const base = join(ROOT, "..", "spec", "vectors", "skill-trust");
    const phantom = join(base, "output", "commitment-phantom-signer.capsule");
    const keys = JSON.parse(
      readFileSync(join(base, "output", "keys.json"), "utf8"),
    );
    const res = run(["verify", phantom, "--allowlist", keys.originator.publicKey, "--json"]);
    check("failing-verdict vector exits 1", res.code === 1);
    let parsed;
    try { parsed = JSON.parse(res.stdout); } catch { /* noop */ }
    check("failing-verdict --json ok=false with signer_set failure",
      parsed && parsed.ok === false && parsed.integrity_ok === false
        && parsed.signer_set && parsed.signer_set.ok === false);
    check("failing verdict never derives skill_trust signed",
      parsed && parsed.skill_trust
        && parsed.skill_trust.capsule_signed === false
        && parsed.skill_trust.skills
        && parsed.skill_trust.skills.exfil === "unsigned");
    const human = run(["verify", phantom, "--allowlist", keys.originator.publicKey]);
    check("failing-verdict human report is INVALID", /Result: INVALID/.test(human.stdout));
    check("failing-verdict human report derives unsigned",
      /skills \(derived\):\s+exfil=unsigned/.test(human.stdout));
  }

  // No allowlist: no policy. VALID, but the verdict must say what it covers.
  const none = run(["verify", CLEAN]);
  check("no allowlist still exits 0", none.code === 0);
  check("no-allowlist VALID carries the trust_not_evaluated qualifier",
    /Result: VALID\n {2}qualifiers:\n(?: {4}- .*\n)* {4}- trust not evaluated: no allowlist supplied/.test(none.stdout));
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

section("encrypted capsules - honest decryption pointers (F47)");

{
  // No capsule-CLI command implements decryption, so no message may
  // point users at a `verify --decryption-key` flag that does not exist.
  const c = run(["chain", ENCRYPTED]);
  check("chain on encrypted capsule exits 2", c.code === 2);
  check("chain error says this CLI does not decrypt", /does not decrypt/.test(c.stderr));
  check("chain error does not recommend a nonexistent flag",
    !/capsule verify.*--decryption-key/.test(c.stderr));

  const i = run(["inspect", ENCRYPTED]);
  check("inspect on encrypted capsule exits 0", i.code === 0);
  check("inspect shows encryption cipher", /encrypted/.test(i.stdout));
  check("inspect chain-length note says this CLI cannot decrypt", /cannot decrypt/.test(i.stdout));
  check("inspect does not recommend a nonexistent flag", !/--decryption-key/.test(i.stdout));

  // The encrypted capsule still verifies at L2 (chain deferred), and the
  // trust policy applies to the outer envelope like any other capsule.
  const v = run(["verify", ENCRYPTED, "--allowlist", KEYS.originatorPublicKeyHex]);
  check("encrypted capsule verifies at L2 with trust satisfied", v.code === 0);
}

// ----------------------------------------------------------------------

section("verify - normalized verdict surface (spec/results.md)");

{
  // The CLI is the reference renderer for spec/results.md: the Result
  // block is verdict-first, every qualifier is enumerated with its
  // normative minimum substring, and the exit codes are 0/1/2 with no
  // third truth value. These run against the checked-in conformance
  // fixtures so the renderer is pinned to the same bytes the five lanes
  // verify.
  const RV = join(ROOT, "..", "spec", "vectors", "result-vocabulary", "output");
  const PD = join(ROOT, "..", "spec", "vectors", "profile-declaration", "output");
  const rvKeys = JSON.parse(readFileSync(join(RV, "keys.json"), "utf8"));
  const json = (args) => {
    const r = run(args);
    let parsed;
    try { parsed = JSON.parse(r.stdout); } catch { /* noop */ }
    return { ...r, parsed };
  };

  // P7: an unknown era is a verdict about the capsule/verifier pair, not
  // an operator error. Exit 2 ("cannot open capsule") was the historical
  // Node-CLI behavior and disagreed with the Rust CLI's exit 1.
  const newer = run(["verify", join(RV, "unsupported-newer.capsule")]);
  check("unknown-newer capsule exits 1, not 2 (P7)", newer.code === 1);
  check("unknown-newer renders UNSUPPORTED with its machine-readable reason",
    /Result: UNSUPPORTED \(unsupported_version_newer:/.test(newer.stdout));
  check("unknown-newer keeps the versioning.md needle in the report",
    /newer than this verifier supports/.test(newer.stdout));
  check("unknown-newer still reports the observed version",
    /Format version:\s+9\.9/.test(newer.stdout));
  const newerJson = json(["verify", join(RV, "unsupported-newer.capsule"), "--json"]);
  check("unknown-newer --json carries verdict/verdict_reason/qualifiers",
    newerJson.parsed
      && newerJson.parsed.verdict === "unsupported"
      && newerJson.parsed.verdict_reason === "unsupported_version_newer"
      && Array.isArray(newerJson.parsed.qualifiers)
      && newerJson.parsed.qualifiers.length === 0
      && newerJson.parsed.ok === false
      && newerJson.parsed.integrity_ok === false);
  check("unknown-newer --json exits 1", newerJson.code === 1);

  const older = run(["verify", join(RV, "unsupported-older.capsule")]);
  check("unknown-older capsule exits 1", older.code === 1);
  check("unknown-older names the other refusal direction",
    /Result: UNSUPPORTED \(unsupported_version_older:/.test(older.stdout)
      && /older than any version this verifier supports/.test(older.stdout));

  // A declared profile this verifier does not implement is the same
  // class of honesty: a limitation of the verifier, never a defect.
  const unsupProfile = run(["verify", join(PD, "unsupported-vendor-profile.capsule")]);
  check("unsupported profile exits 1", unsupProfile.code === 1);
  check("unsupported profile renders UNSUPPORTED with the profile reason",
    /Result: UNSUPPORTED \(unsupported_profile:/.test(unsupProfile.stdout));
  check("unsupported profile keeps the profiles.md needles",
    /profile 'x-test-kms-1' version '1\.0' is not supported by this verifier/.test(unsupProfile.stdout)
      && /limitation of the verifier/.test(unsupProfile.stdout));
  check("unsupported profile names the declaration on the Profile line",
    /Profile:\s+x-test-kms-1\/1\.0/.test(unsupProfile.stdout));

  // M2: a manifest/envelope profile disagreement is a capsule
  // self-contradiction — INVALID with no verdict_reason, never
  // UNSUPPORTED (which is reserved for verifier limitations).
  const mismatch = json(["verify", join(PD, "profile-mismatch-value.capsule"), "--json"]);
  check("profile mismatch is invalid with a null verdict_reason (M2)",
    mismatch.code === 1
      && mismatch.parsed
      && mismatch.parsed.verdict === "invalid"
      && mismatch.parsed.verdict_reason === null
      && mismatch.parsed.profile?.status === "mismatched");

  // The trust.md threat-table capsule: it VERIFIES, and every reduced
  // assurance reaches the operator beside the verdict.
  const maxQ = run(["verify", join(RV, "maximally-qualified-valid.capsule")]);
  check("maximally-qualified capsule exits 0", maxQ.code === 0);
  for (const needle of [
    "signer set is not bound by the seal",
    "actors are not bound to a declared participant set",
    "no events to walk",
    "no allowlist",
  ]) {
    check(`Result block carries the required substring: ${needle}`,
      new RegExp(`Result: VALID\\n(?:.*\\n)*?    - .*${needle}`).test(maxQ.stdout));
  }
  const maxQJson = json(["verify", join(RV, "maximally-qualified-valid.capsule"), "--json"]);
  check("maximally-qualified --json qualifiers match the spec order exactly",
    maxQJson.parsed && JSON.stringify(maxQJson.parsed.qualifiers) === JSON.stringify([
      "signer_set_unbound",
      "actor_set_unbound",
      "empty_chain_not_walked",
      "trust_not_evaluated",
    ]));

  // The one shape allowed an empty qualifiers array — and it says so.
  const unqualified = json([
    "verify", join(RV, "unqualified-valid.capsule"),
    "--allowlist", rvKeys.originator.publicKey, "--json",
  ]);
  check("unqualified valid exits 0 with an empty qualifiers array",
    unqualified.code === 0
      && unqualified.parsed
      && unqualified.parsed.verdict === "valid"
      && unqualified.parsed.verdict_reason === null
      && JSON.stringify(unqualified.parsed.qualifiers) === "[]");
  check("verdict never disagrees with ok (spec/results.md invariant)",
    unqualified.parsed && unqualified.parsed.integrity_ok === (unqualified.parsed.verdict === "valid"));

  const noMatch = json([
    "verify", join(RV, "unqualified-valid.capsule"),
    "--allowlist", rvKeys.stranger.publicKey, "--json",
  ]);
  check("non-matching allowlist keeps verdict valid and qualifies it",
    noMatch.code === 1
      && noMatch.parsed
      && noMatch.parsed.verdict === "valid"
      && JSON.stringify(noMatch.parsed.qualifiers) === JSON.stringify(["no_trusted_signer"])
      && noMatch.parsed.trust?.satisfied === false);

  // P1: --accept-versions is the first reference renderer for
  // formatVersion.acceptedByPolicy (spec/versioning.md "Host policy").
  const versionNo = json([
    "verify", join(RV, "unqualified-valid.capsule"),
    "--allowlist", rvKeys.originator.publicKey,
    "--accept-versions", "0.6", "--json",
  ]);
  check("--accept-versions excluding the capsule's version fails the run",
    versionNo.code === 1
      && versionNo.parsed
      && versionNo.parsed.integrity_ok === true
      && versionNo.parsed.verdict === "valid"
      && versionNo.parsed.qualifiers.includes("version_not_accepted_by_policy")
      && versionNo.parsed.format_version?.accepted_by_policy === false
      && versionNo.parsed.version_policy?.satisfied === false);
  const versionNoHuman = run([
    "verify", join(RV, "unqualified-valid.capsule"),
    "--allowlist", rvKeys.originator.publicKey, "--accept-versions", "0.6",
  ]);
  check("--accept-versions failure carries the versioning.md needle",
    /not in the declared accepted set/.test(versionNoHuman.stdout)
      && /version policy: FAILED/.test(versionNoHuman.stdout));

  const versionYes = json([
    "verify", join(RV, "unqualified-valid.capsule"),
    "--allowlist", rvKeys.originator.publicKey,
    "--accept-versions", "0.6", "--accept-versions", "0.7", "--json",
  ]);
  check("--accept-versions including the version satisfies the policy",
    versionYes.code === 0
      && versionYes.parsed
      && versionYes.parsed.format_version?.accepted_by_policy === true
      && JSON.stringify(versionYes.parsed.qualifiers) === "[]");

  const noVersionPolicy = json([
    "verify", join(RV, "unqualified-valid.capsule"),
    "--allowlist", rvKeys.originator.publicKey, "--json",
  ]);
  check("absent --accept-versions declares no policy (accepted_by_policy null)",
    noVersionPolicy.parsed
      && noVersionPolicy.parsed.format_version?.accepted_by_policy === null
      && noVersionPolicy.parsed.version_policy?.policy === "none");

  const badVersion = run([
    "verify", join(RV, "unqualified-valid.capsule"), "--accept-versions", "zero-point-seven",
  ]);
  check("malformed --accept-versions entry exits 2", badVersion.code === 2);
  check("malformed --accept-versions names the expected grammar",
    /<major>\.<minor>/.test(badVersion.stderr));

  // Qualifiers only ever qualify a VALID verdict.
  const tamperVec = json([
    "verify", join(RV, "invalid-tamper.capsule"),
    "--allowlist", rvKeys.originator.publicKey, "--json",
  ]);
  check("invalid capsule reports verdict invalid, no reason, no qualifiers",
    tamperVec.code === 1
      && tamperVec.parsed
      && tamperVec.parsed.verdict === "invalid"
      && tamperVec.parsed.verdict_reason === null
      && JSON.stringify(tamperVec.parsed.qualifiers) === "[]");

  // spec/profiles.md §4.2: the profile actually applied, reported beside
  // the format version, with absence rendered as the era default.
  check("verify names the effective profile on a default capsule",
    /Profile:\s+v0\.6-suite\/1\.0 \(default, undeclared\)/.test(maxQ.stdout));
  check("verify --json carries the profile channel",
    maxQJson.parsed
      && maxQJson.parsed.profile?.effective === "v0.6-suite"
      && maxQJson.parsed.profile?.status === "default"
      && maxQJson.parsed.profile?.declared === false);

  // The encrypted outer: the seal is verified, the content unread. The
  // scope is a qualifier, not a footnote.
  const enc = run(["verify", ENCRYPTED, "--allowlist", KEYS.originatorPublicKeyHex]);
  check("encrypted outer renders the plain-language scope qualifier",
    /content is encrypted and was not read/.test(enc.stdout));
  const encJson = json(["verify", ENCRYPTED, "--allowlist", KEYS.originatorPublicKeyHex, "--json"]);
  check("encrypted outer --json carries encrypted_outer_only",
    encJson.parsed && encJson.parsed.qualifiers.includes("encrypted_outer_only"));

  // A file that is not a capsule at all is a verification failure, not
  // an operator error: the CLI feeds the bytes to the total verifier.
  const junk = join(TMP, "not-a-capsule.bin");
  writeFileSync(junk, Buffer.from("this is not a zip file\n", "utf8"));
  const junkRun = run(["verify", junk]);
  check("unopenable file exits 1 with an INVALID verdict",
    junkRun.code === 1 && /Result: INVALID/.test(junkRun.stdout));
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

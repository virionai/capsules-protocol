// CLI lineage + rewrap test (spec/lineage.md). The centrepiece is the
// end-to-end two-actor hand-off: Alice seals, the naive continuation
// fails the originator binding (the problem lineage exists to fix),
// Bob rewraps, and `verify --predecessor` establishes the custody link
// hop by hop.
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
  manifestHash,
  packZip,
  unpackZip,
} from "@capsule/sdk-v0.7-prototype";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const BIN = join(ROOT, "bin", "capsule.mjs");

const TMP = join(tmpdir(), `capsule-cli-rewrap-${process.pid}`);
const F = (name) => join(TMP, name);

// Pinned timestamps everywhere: the successors these tests build must be
// reproducible byte-for-byte (spec/lineage.md reproducibility note).
const ALICE_TS = "2026-05-07T12:00:00Z";
const BOB_TS = "2026-05-08T09:30:00Z";
const CAROL_TS = "2026-05-09T09:30:00Z";

let passed = 0;
let failed = 0;
const failures = [];

function run(args, opts = {}) {
  const res = spawnSync("node", [BIN, ...args], { encoding: "utf8", timeout: 60_000, ...opts });
  return { code: res.status ?? -1, stdout: res.stdout ?? "", stderr: res.stderr ?? "" };
}

function json(res) {
  try { return JSON.parse(res.stdout); } catch { return null; }
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

const KEYS = {};

function aliceBuilder(alice, program) {
  const builder = new CapsuleBuilder({
    originator: { publicKey: alice.publicKeyHex, label: "Alice" },
    participants: [
      { actor_id: "human:alice", role: "originator" },
      { actor_id: "ai:assistant", role: "advisor" },
    ],
    createdAt: ALICE_TS,
  });
  builder.setProgram(program);
  builder.setAgents("# Agents\n\n- human:alice owns this review.\n");
  builder.addPayload("payload/evidence.csv", Buffer.from("k,v\nrate,0.07\n", "utf8"));
  return builder;
}

async function sealAlice(alice, program) {
  const builder = aliceBuilder(alice, program);
  // One fixed genesis event: two seals sharing it share a first_event_hash
  // and therefore a capsule_id, which is what makes the "different sealed
  // state of the declared predecessor" case constructible.
  await builder.appendEvent({
    actor: "human:alice", kind: "decision", action: "created", target: "program.md",
    timestamp: ALICE_TS, payload: { summary: "Opened the review" },
  });
  await builder.appendEvent({
    actor: "ai:assistant", kind: "observation", action: "summarized", target: "program.md",
    timestamp: ALICE_TS, payload: { summary: "Summarized the evidence" },
  });
  return Buffer.from(await builder.seal({
    signers: [{ role: "originator", publicKey: alice.publicKey, privateKey: alice.privateKey }],
    signedAt: ALICE_TS,
  }));
}

async function buildFixtures() {
  rmSync(TMP, { recursive: true, force: true });
  mkdirSync(TMP, { recursive: true });

  const alice = generateEd25519();
  KEYS.alice = alice.publicKeyHex;
  writeFileSync(F("alice.capsule"), await sealAlice(alice, "# Loan Review\n\nStep one complete.\n"));

  // A SECOND genuine seal of the same line: same originator, same genesis,
  // therefore the same capsule_id — a different manifest_hash.
  writeFileSync(
    F("alice-later-seal.capsule"),
    await sealAlice(alice, "# Loan Review\n\nStep one complete. Step two started.\n"),
  );

  // The problem lineage exists to fix (finding F-03): a continuation that
  // names Alice as originator but can only be signed by Bob's key.
  const naiveKey = generateEd25519();
  const naive = aliceBuilder(alice, "# Loan Review\n\nContinued by Bob.\n");
  await naive.appendEvent({
    actor: "human:alice", kind: "decision", action: "created", target: "program.md",
    timestamp: ALICE_TS, payload: { summary: "Opened the review" },
  });
  writeFileSync(F("naive-continuation.capsule"), Buffer.from(await naive.seal({
    signers: [{ role: "originator", publicKey: naiveKey.publicKey, privateKey: naiveKey.privateKey }],
    signedAt: BOB_TS,
  })));

  // A tampered copy of Alice's capsule (rewrap's W3 refusal case).
  const files = await unpackZip(new Uint8Array(readFileSync(F("alice.capsule"))));
  const program = Buffer.from(files.get("program.md"));
  program[0] ^= 0x01;
  files.set("program.md", program);
  writeFileSync(F("alice-tampered.capsule"), Buffer.from(await packZip(files)));

  // An unrelated valid capsule — the mistyped-path case at verify time.
  const stranger = generateEd25519();
  writeFileSync(F("stranger.capsule"), await sealAlice(stranger, "# Unrelated\n"));

  // An encrypted capsule, plus a successor that declares it. v0.7.1
  // declarations commit to a PLAIN capsule's members, so this is the
  // honest way to reach the encrypted_predecessor reason: the entry is
  // well-formed and identity-coherent; only the linkage is out of scope.
  const encBuilder = new CapsuleBuilder({
    originator: { publicKey: alice.publicKeyHex, label: "Alice" },
    createdAt: ALICE_TS,
  });
  encBuilder.setProgram("# Confidential\n");
  await encBuilder.appendEvent({
    actor: "human:alice", kind: "decision", action: "created", target: "program.md",
    timestamp: ALICE_TS, payload: { summary: "Sealed privately" },
  });
  const encBytes = await encBuilder.seal({
    signers: [{ role: "originator", publicKey: alice.publicKey, privateKey: alice.privateKey }],
    recipients: generateX25519(),
    signedAt: ALICE_TS,
  });
  writeFileSync(F("encrypted.capsule"), Buffer.from(encBytes));

  const encReader = await CapsuleReader.fromBytes(encBytes);
  const em = encReader.manifest();
  const ee = encReader.envelope();
  const dana = generateEd25519();
  const danaBuilder = new CapsuleBuilder({
    originator: { publicKey: dana.publicKeyHex, label: "Dana" },
    createdAt: CAROL_TS,
  });
  danaBuilder.setProgram("# Continued from a private capsule\n");
  danaBuilder.declarePredecessorEntry({
    capsule_id: em.id,
    format_version: em.format.version,
    originator_public_key: em.originator.public_key,
    first_event_hash: em.first_event_hash,
    entry_hash: ee.entry_hash,
    manifest_hash: manifestHash(em),
  });
  await danaBuilder.appendEvent({
    actor: "system:host", kind: "observation", action: "custody_received",
    target: `capsule:${em.id}`, timestamp: CAROL_TS, payload: { note: "custody received" },
  });
  writeFileSync(F("successor-of-encrypted.capsule"), Buffer.from(await danaBuilder.seal({
    signers: [{ role: "originator", publicKey: dana.publicKey, privateKey: dana.privateKey }],
    signedAt: CAROL_TS,
  })));
}

await buildFixtures();

// ----------------------------------------------------------------------

section("hand-off step 1-2 - Alice seals; the naive continuation is blocked");

{
  const a = run(["verify", F("alice.capsule")]);
  check("alice.capsule verifies", a.code === 0 && /Result: PASS/.test(a.stdout));
  check("alice.capsule declares no predecessor",
    !/Custody \(lineage\)/.test(a.stdout));

  // The block this whole feature exists to lift: a continuation cannot be
  // sealed under the predecessor's originator identity.
  const n = run(["verify", F("naive-continuation.capsule")]);
  check("naive continuation exits 1", n.code === 1);
  check("naive continuation fails the originator binding",
    /originator binding: /.test(n.stdout));
}

// ----------------------------------------------------------------------

section("hand-off step 3 - Bob rewraps");

{
  const kg = run(["keygen", "--out", TMP, "--label", "bob"]);
  check("keygen writes Bob's keypair", kg.code === 0 && existsSync(F("bob.private.hex")));

  const r = run(["rewrap", F("alice.capsule"),
    "--key", F("bob.private.hex"), "--out", F("bob.capsule"),
    "--participant", "human:bob", "--label", "Bob",
    "--created-at", BOB_TS, "--signed-at", BOB_TS]);
  check("rewrap exits 0", r.code === 0, r.stderr.trim());
  check("rewrap writes the successor", existsSync(F("bob.capsule")));
  // Pinned: rewrap never presents the successor as BEING the predecessor.
  check("rewrap reports a new identity", /new identity/.test(r.stdout));
  // Pinned: rewrap must never read as having obtained approval.
  check("rewrap prints the not-countersigned note", /not countersigned/.test(r.stdout));
  check("rewrap reports the carried files as byte-identical",
    /Carried files:\s+3 \(agents\.md, payload\/evidence\.csv, program\.md\) — byte-identical/.test(r.stdout));
  check("rewrap reports the fresh chain",
    /Chain:\s+fresh genesis — predecessor history remains in the predecessor/.test(r.stdout));
  check("rewrap reports the custody event", /Custody event:\s+emitted \(actor system:host\)/.test(r.stdout));
  // W9: the private key never appears in output.
  const priv = readFileSync(F("bob.private.hex"), "utf8").trim();
  check("rewrap never echoes the private key",
    !r.stdout.includes(priv) && !r.stderr.includes(priv));
}

// ----------------------------------------------------------------------

section("hand-off step 4 - the successor verifies, declared but unverified");

{
  const v = run(["verify", F("bob.capsule")]);
  check("successor verifies without predecessor bytes", v.code === 0);
  check("successor PASSes", /Result: PASS/.test(v.stdout));
  // The two pinned phrases a report may never drop.
  check("unchecked entry renders 'declared, not verified'",
    /declared, not verified/.test(v.stdout));
  check("declared lineage renders 'not countersigned'", /not countersigned/.test(v.stdout));
  check("custody block names the declaration", /Custody \(lineage\):/.test(v.stdout));
  check("no --predecessor means no custody policy",
    /policy:\s+none — no --predecessor supplied/.test(v.stdout));

  const j = json(run(["verify", F("bob.capsule"), "--json"]));
  check("--json lineage declared with one entry",
    j?.lineage?.declared === true && j.lineage.entries.length === 1);
  check("--json entry is unverified at depth 0",
    j?.lineage?.entries?.[0]?.status === "unverified" && j.lineage.verified_depth === 0);
  check("--json entry echoes the six declared members",
    /^[0-9a-f]{64}$/.test(j?.lineage?.entries?.[0]?.capsule_id ?? "")
      && j.lineage.entries[0].format_version === "0.7"
      && /^[0-9a-f]{64}$/.test(j.lineage.entries[0].originator_public_key)
      && /^[0-9a-f]{64}$/.test(j.lineage.entries[0].first_event_hash)
      && /^[0-9a-f]{64}$/.test(j.lineage.entries[0].entry_hash)
      && /^[0-9a-f]{64}$/.test(j.lineage.entries[0].manifest_hash));
  check("--json entry reports identity_checked", j?.lineage?.entries?.[0]?.identity_checked === true);
  check("--json custody policy is none when no file is supplied",
    j?.custody?.policy === "none" && j.custody.satisfied === null);
  check("--json declared predecessor is the ALICE capsule id",
    j?.lineage?.entries?.[0]?.capsule_id
      === json(run(["inspect", F("alice.capsule"), "--json"]))?.capsule_id);
}

// ----------------------------------------------------------------------

section("hand-off step 5 - verify --predecessor establishes depth 1");

{
  const v = run(["verify", F("bob.capsule"), "--predecessor", F("alice.capsule")]);
  check("verify --predecessor exits 0", v.code === 0, v.stderr.trim());
  check("custody policy is reported SATISFIED", /policy check:\s+SATISFIED/.test(v.stdout));
  check("verified lineage names depth and two identities",
    /successor of capsule [0-9a-f]{64}; lineage verified to depth 1/.test(v.stdout));
  check("verified lineage never claims endorsement", !/endorsed|official continuation/.test(v.stdout));
  check("the not-countersigned note survives a VERIFIED linkage",
    /not countersigned/.test(v.stdout));

  const j = json(run(["verify", F("bob.capsule"), "--predecessor", F("alice.capsule"), "--json"]));
  check("--json verified_depth is 1", j?.lineage?.verified_depth === 1);
  check("--json entry status is verified", j?.lineage?.entries?.[0]?.status === "verified");
  check("--json entry carries the artifact summary",
    j?.lineage?.entries?.[0]?.artifact?.ok === true
      && j.lineage.entries[0].artifact.observed_version === "0.7"
      && j.lineage.entries[0].artifact.error_count === 0);
  check("--json custody policy satisfied",
    j?.custody?.policy === "predecessor" && j.custody.satisfied === true
      && j.custody.unmatched_count === 0);
  check("--json lineage.ok true", j?.lineage?.ok === true);
}

// ----------------------------------------------------------------------

section("hand-off step 6 - continue the work, then seal (not just custody)");

{
  // The other half of the baseline claim: Bob evolves the work before
  // sealing. Uses the builder path the CLI's one-call rewrap composes.
  const bobPriv = readFileSync(F("bob.private.hex"), "utf8").trim();
  const bobPub = json(run(["verify", F("bob.capsule"), "--json"])).originator_public_key
    ?? (await CapsuleReader.fromBytes(new Uint8Array(readFileSync(F("bob.capsule"))))).manifest().originator.public_key;
  const builder = await CapsuleBuilder.continueFrom(
    new Uint8Array(readFileSync(F("alice.capsule"))),
    {
      originator: { publicKey: bobPub, label: "Bob" },
      participants: [{ actor_id: "human:bob", role: "custodian" }],
      createdAt: BOB_TS,
    },
  );
  builder.setProgram("# Loan Review\n\nStep one complete. Step two: Bob's analysis.\n");
  await builder.appendEvent({
    actor: "human:bob", kind: "decision", action: "continued", target: "program.md",
    timestamp: BOB_TS, payload: { summary: "Continued Alice's review" },
  });
  await builder.appendEvent({
    actor: "human:bob", kind: "observation", action: "reviewed", target: "payload/evidence.csv",
    timestamp: BOB_TS, payload: { summary: "Re-read the evidence" },
  });
  writeFileSync(F("continued.capsule"), Buffer.from(await builder.seal({
    signers: [{ role: "originator", publicKey: bobPub, privateKey: bobPriv }],
    signedAt: BOB_TS,
  })));

  const v = run(["verify", F("continued.capsule"), "--predecessor", F("alice.capsule")]);
  check("continued successor verifies to depth 1", v.code === 0
    && /lineage verified to depth 1/.test(v.stdout));
  const chain = json(run(["chain", F("continued.capsule"), "--json"]));
  check("continued successor carries the custody genesis event",
    chain?.[0]?.action === "custody_received" && chain[0].actor === "system:host");
  check("continued successor's chain is fresh (predecessor events absent)",
    chain?.every((e) => e.action !== "summarized"));
  const program = run(["program", F("continued.capsule")]);
  check("continued successor carries Bob's evolved program.md",
    /Bob's analysis/.test(program.stdout));
}

// ----------------------------------------------------------------------

section("hand-off step 7 - Carol rewraps Bob; depth 2, nothing accumulates");

{
  const kg = run(["keygen", "--out", TMP, "--label", "carol"]);
  check("keygen writes Carol's keypair", kg.code === 0);
  const r = run(["rewrap", F("bob.capsule"), "--key", F("carol.private.hex"),
    "--out", F("carol.capsule"), "--participant", "human:carol",
    "--created-at", CAROL_TS, "--signed-at", CAROL_TS]);
  check("Carol's rewrap exits 0", r.code === 0, r.stderr.trim());

  // Re-rewrap declares only its IMMEDIATE parent: ancestry never flattens
  // into an inline list.
  const m = JSON.parse(run(["manifest", F("carol.capsule")]).stdout);
  check("carol declares exactly one entry", m.predecessors.length === 1);
  const bobId = json(run(["inspect", F("bob.capsule"), "--json"])).capsule_id;
  check("carol's entry names Bob, not Alice", m.predecessors[0].capsule_id === bobId);

  const two = run(["verify", F("carol.capsule"),
    "--predecessor", F("bob.capsule"), "--predecessor", F("alice.capsule"), "--json"]);
  const j = json(two);
  check("two-hop verify exits 0", two.code === 0, two.stderr.trim());
  check("verified_depth is 2", j?.lineage?.verified_depth === 2);
  check("hops are pinned 1 then 2",
    j?.lineage?.entries?.[0]?.hop === 1 && j.lineage.entries[1]?.hop === 2);
  check("both hops verified",
    j?.lineage?.entries?.every((e) => e.status === "verified") === true);
  check("hop 2 is Alice", j?.lineage?.entries?.[1]?.capsule_id
    === json(run(["inspect", F("alice.capsule"), "--json"])).capsule_id);

  // A declared entry left unsupplied is reported, never an exit failure:
  // an operator may hold only one hop.
  const one = run(["verify", F("carol.capsule"), "--predecessor", F("bob.capsule"), "--json"]);
  const j1 = json(one);
  check("supplying only hop 1 still exits 0", one.code === 0);
  check("the unsupplied hop-2 entry is reported, not failed",
    j1?.lineage?.verified_depth === 1
      && j1.lineage.entries[1]?.status === "unverified"
      && j1.custody.satisfied === true);
  const oneHuman = run(["verify", F("carol.capsule"), "--predecessor", F("bob.capsule")]);
  check("the unsupplied hop renders 'declared, not verified'",
    /declared, not verified/.test(oneHuman.stdout));
}

// ----------------------------------------------------------------------

section("verify --predecessor - requested-policy failures (exit 1)");

{
  // A different genuine seal of the same line. The report must say what
  // it is and must NOT reach for tamper vocabulary.
  const mm = run(["verify", F("bob.capsule"), "--predecessor", F("alice-later-seal.capsule")]);
  check("mismatched sealed state exits 1", mm.code === 1);
  check("mismatch says 'different sealed state of the declared predecessor'",
    /different sealed state of the declared predecessor/.test(mm.stdout));
  check("mismatch names the differing member", /manifest_hash: declared/.test(mm.stdout));
  check("mismatch negates the tamper reading", /not evidence of tampering/.test(mm.stdout));

  const mj = json(run(["verify", F("bob.capsule"),
    "--predecessor", F("alice-later-seal.capsule"), "--json"]));
  // The anti-framing pin: a host's file handling never flips the
  // capsule's OWN verdict. Only the requested policy failed.
  check("mismatch leaves integrity_ok true", mj?.integrity_ok === true);
  check("mismatch falsifies only the lineage area and the custody policy",
    mj?.lineage?.ok === false && mj.ok === false && mj.custody.satisfied === false);
  check("mismatch status is 'mismatch'", mj?.lineage?.entries?.[0]?.status === "mismatch");

  // A predecessor that fails its own verification: two facts, never
  // collapsed into "the successor lied".
  const inv = run(["verify", F("bob.capsule"), "--predecessor", F("alice-tampered.capsule")]);
  check("invalid predecessor exits 1", inv.code === 1);
  check("invalid predecessor is worded as a property of the supplied artifact",
    /property of the supplied artifact, not of the successor's declaration/.test(inv.stdout));
  check("invalid predecessor names the era it was checked under",
    /fails its own verification under era 0\.7 \(3 error\(s\)\)/.test(inv.stdout));
  const invJson = json(run(["verify", F("bob.capsule"),
    "--predecessor", F("alice-tampered.capsule"), "--json"]));
  check("invalid predecessor keeps the successor's integrity verdict",
    invJson?.integrity_ok === true
      && invJson.lineage.entries[0].status === "predecessor_invalid");
  check("invalid predecessor's artifact summary counts its real errors",
    invJson?.lineage?.entries?.[0]?.artifact?.ok === false
      && invJson.lineage.entries[0].artifact.error_count === 3);

  // A mistyped path must never exit 0.
  const un = run(["verify", F("bob.capsule"), "--predecessor", F("stranger.capsule")]);
  check("an unmatched supplied file exits 1", un.code === 1);
  check("the unmatched file is named, never silently ignored",
    /matched no declared entry/.test(un.stdout));
  const unJson = json(run(["verify", F("bob.capsule"),
    "--predecessor", F("stranger.capsule"), "--json"]));
  check("--json counts the unmatched supply",
    unJson?.custody?.unmatched_count === 1 && unJson.custody.satisfied === false);
  check("the declared entry stays unverified after a wrong supply",
    unJson?.lineage?.entries?.[0]?.status === "unverified");

  // Supplying --predecessor for a capsule with no declaration at all.
  const nodecl = run(["verify", F("alice.capsule"), "--predecessor", F("stranger.capsule")]);
  check("--predecessor against an undeclared capsule exits 1", nodecl.code === 1);
  check("the undeclared case says so", /declares no predecessor/.test(nodecl.stdout));

  // Out-of-scope predecessor class: bytes in hand, rules unavailable.
  const enc = run(["verify", F("successor-of-encrypted.capsule"),
    "--predecessor", F("encrypted.capsule")]);
  check("encrypted predecessor exits 1 under a requested policy", enc.code === 1);
  check("encrypted predecessor reports the scope reason",
    /status=predecessor_unverifiable \(encrypted_predecessor\)/.test(enc.stdout));
  check("encrypted predecessor stays 'declared, not verified'",
    /declared, not verified/.test(enc.stdout));
  const encJson = json(run(["verify", F("successor-of-encrypted.capsule"),
    "--predecessor", F("encrypted.capsule"), "--json"]));
  check("encrypted predecessor never falsifies the lineage area",
    encJson?.lineage?.ok === true && encJson.integrity_ok === true
      && encJson.lineage.entries[0].reason === "encrypted_predecessor");

  // An unreadable --predecessor path is a usage error, not a smaller pool.
  const missing = run(["verify", F("bob.capsule"), "--predecessor", F("nope.capsule")]);
  check("unreadable --predecessor exits 2", missing.code === 2);
  check("unreadable --predecessor names the path on stderr",
    /nope\.capsule/.test(missing.stderr));
}

// ----------------------------------------------------------------------

section("rewrap - refusals and the loud override");

{
  const t = run(["rewrap", F("alice-tampered.capsule"), "--key", F("carol.private.hex"),
    "--out", F("never.capsule")]);
  check("failing predecessor refused with exit 1", t.code === 1);
  check("refusal counts the predecessor's real errors", /3 error\(s\)/.test(t.stderr));
  check("refusal names the override flag", /--allow-invalid-predecessor/.test(t.stderr));
  check("refusal writes nothing", !existsSync(F("never.capsule")));

  const o = run(["rewrap", F("alice-tampered.capsule"), "--key", F("carol.private.hex"),
    "--out", F("override.capsule"), "--allow-invalid-predecessor",
    "--created-at", CAROL_TS, "--signed-at", CAROL_TS]);
  check("--allow-invalid-predecessor exits 0", o.code === 0, o.stderr.trim());
  check("the override prints the pinned WARNING",
    /WARNING: predecessor failed verification \(3 error\(s\)\); sealing anyway — the declaration cites this exact artifact, and linkage verification will report it predecessor_invalid\./
      .test(o.stdout));
  const ov = run(["verify", F("override.capsule"), "--predecessor", F("alice-tampered.capsule"), "--json"]);
  check("the override's output verifies on its own", json(ov)?.integrity_ok === true);
  check("the override's citation reports predecessor_invalid, as promised",
    json(ov)?.lineage?.entries?.[0]?.status === "predecessor_invalid");

  // W5: an input class this command does not take — not a verdict about
  // the artifact, and the message names the supported path.
  const e = run(["rewrap", F("encrypted.capsule"), "--key", F("carol.private.hex"),
    "--out", F("never2.capsule")]);
  check("encrypted predecessor exits 2", e.code === 2);
  check("encrypted refusal points at the decrypt-then-rewrap path",
    /decrypt/i.test(e.stderr) && /inner/.test(e.stderr));
  check("encrypted refusal writes nothing", !existsSync(F("never2.capsule")));

  // W4: unknown era, no override — there is no honest entry to emit.
  const unknownEra = join(ROOT, "..", "spec", "vectors", "version-compat", "output",
    "unknown-newer-version.capsule");
  const u = run(["rewrap", unknownEra, "--key", F("carol.private.hex"),
    "--out", F("never3.capsule")]);
  check("unknown-era predecessor exits 1", u.code === 1);
  check("unknown-era refusal uses the versioning vocabulary",
    /newer than this verifier supports/.test(u.stderr));
  check("unknown-era refusal explains why there is no override",
    /fabricated commitment/.test(u.stderr));
  check("unknown-era refusal writes nothing", !existsSync(F("never3.capsule")));
  const uo = run(["rewrap", unknownEra, "--key", F("carol.private.hex"),
    "--out", F("never4.capsule"), "--allow-invalid-predecessor"]);
  check("--allow-invalid-predecessor does not override an unknown era", uo.code === 1);
}

// ----------------------------------------------------------------------

section("rewrap - usage errors (exit 2) and argument handling");

{
  const noOut = run(["rewrap", F("alice.capsule"), "--key", F("carol.private.hex")]);
  check("missing --out exits 2", noOut.code === 2);
  check("missing --out prints usage", /usage: capsule rewrap/.test(noOut.stderr));

  writeFileSync(F("occupied.capsule"), "not a capsule\n");
  const exists = run(["rewrap", F("alice.capsule"), "--key", F("carol.private.hex"),
    "--out", F("occupied.capsule")]);
  check("existing --out without --force exits 2", exists.code === 2);
  check("existing --out is not overwritten",
    readFileSync(F("occupied.capsule"), "utf8") === "not a capsule\n");
  const forced = run(["rewrap", F("alice.capsule"), "--key", F("carol.private.hex"),
    "--out", F("occupied.capsule"), "--force",
    "--created-at", CAROL_TS, "--signed-at", CAROL_TS]);
  check("--force overwrites", forced.code === 0);

  writeFileSync(F("bad.hex"), "not-a-key\n");
  const badKey = run(["rewrap", F("alice.capsule"), "--key", F("bad.hex"), "--out", F("x.capsule")]);
  check("malformed --key exits 2", badKey.code === 2);
  check("malformed --key states the expected shape", /64-hex/.test(badKey.stderr));

  const noKey = run(["rewrap", F("alice.capsule"), "--out", F("x.capsule")]);
  check("missing --key exits 2", noKey.code === 2);

  const badTime = run(["rewrap", F("alice.capsule"), "--key", F("carol.private.hex"),
    "--out", F("x.capsule"), "--signed-at", "yesterday"]);
  check("a malformed --signed-at exits 2", badTime.code === 2);
  check("the timestamp error states the expected shape",
    /ISO 8601 UTC/.test(badTime.stderr));
  check("a malformed timestamp writes nothing", !existsSync(F("x.capsule")));

  const unreadable = run(["rewrap", F("does-not-exist.capsule"),
    "--key", F("carol.private.hex"), "--out", F("x.capsule")]);
  check("unreadable predecessor exits 2", unreadable.code === 2);

  const notCapsule = run(["rewrap", F("bad.hex"), "--key", F("carol.private.hex"),
    "--out", F("x.capsule")]);
  check("a non-capsule predecessor exits 2", notCapsule.code === 2);
  check("a non-capsule predecessor says it cannot be opened",
    /cannot open predecessor capsule/.test(notCapsule.stderr));

  const typo = run(["rewrap", F("alice.capsule"), "--key", F("carol.private.hex"),
    "--out", F("x.capsule"), "--alow-invalid-predecessor"]);
  check("a typo'd flag exits 2 rather than silently dropping the policy", typo.code === 2);
  check("the typo'd flag is named on stderr", /--alow-invalid-predecessor/.test(typo.stderr));

  const help = run(["rewrap", "--help"]);
  check("rewrap --help exits 0", help.code === 0);
  check("rewrap --help prints usage", /usage: capsule rewrap/.test(help.stderr));

  const listed = run(["--help"]);
  check("rewrap is listed in the top-level help", /rewrap\s+seal a successor capsule/.test(listed.stderr));

  // Against a BOUND actor set, an undeclared custody actor must fail at
  // the call site that introduced it, never at a reader.
  const badActor = run(["rewrap", F("alice.capsule"), "--key", F("carol.private.hex"),
    "--out", F("x.capsule"), "--participant", "human:carol",
    "--custody-actor", "human:nobody"]);
  check("an undeclared --custody-actor exits 2", badActor.code === 2, badActor.stderr.trim());
  check("the undeclared custody actor is named on stderr",
    /human:nobody/.test(badActor.stderr));
  const goodActor = run(["rewrap", F("alice.capsule"), "--key", F("carol.private.hex"),
    "--out", F("actor.capsule"), "--participant", "human:carol",
    "--custody-actor", "human:carol", "--created-at", CAROL_TS, "--signed-at", CAROL_TS]);
  check("a declared --custody-actor is accepted", goodActor.code === 0, goodActor.stderr.trim());
  check("the custody actor is reported", /Custody event:\s+emitted \(actor human:carol\)/.test(goodActor.stdout));

  const noEvent = run(["rewrap", F("alice.capsule"), "--key", F("carol.private.hex"),
    "--out", F("no-event.capsule"), "--no-custody-event",
    "--created-at", CAROL_TS, "--signed-at", CAROL_TS]);
  check("--no-custody-event exits 0", noEvent.code === 0);
  check("--no-custody-event is reported", /Custody event:\s+not emitted/.test(noEvent.stdout));
  const noEventChain = json(run(["chain", F("no-event.capsule"), "--json"]));
  check("--no-custody-event emits no custody_received event",
    noEventChain?.every((e) => e.action !== "custody_received"));
}

// ----------------------------------------------------------------------

section("rewrap - JSON result and reproducibility");

{
  // Same predecessor, same key, same label, same participants, same
  // pinned timestamps as step 3's bob.capsule — the reproducibility claim.
  const j = json(run(["rewrap", F("alice.capsule"), "--key", F("bob.private.hex"),
    "--out", F("bob-json.capsule"), "--participant", "human:bob", "--label", "Bob",
    "--created-at", BOB_TS, "--signed-at", BOB_TS, "--json"]));
  check("--json reports ok and the output path",
    j?.ok === true && j.out === F("bob-json.capsule"));
  check("--json reports the successor's new identity",
    /^[0-9a-f]{64}$/.test(j?.successor?.capsule_id ?? "")
      && j.successor.capsule_id !== j.predecessor.entry.capsule_id);
  check("--json lists the carried paths",
    Array.isArray(j?.successor?.carried_paths)
      && j.successor.carried_paths.join(",") === "agents.md,payload/evidence.csv,program.md");
  check("--json carries the six-member entry",
    Object.keys(j?.predecessor?.entry ?? {}).sort().join(",")
      === "capsule_id,entry_hash,first_event_hash,format_version,manifest_hash,originator_public_key");
  check("--json reports the predecessor verification summary",
    j?.predecessor?.verification?.ok === true && j.predecessor.verification.error_count === 0);
  check("--json warnings are empty on a clean rewrap", j?.warnings?.length === 0);
  check("--json never contains the private key",
    !JSON.stringify(j).includes(readFileSync(F("bob.private.hex"), "utf8").trim()));

  // Pinned timestamps + the same key = byte-identical output.
  check("pinned timestamps reproduce the successor byte-for-byte",
    Buffer.compare(readFileSync(F("bob.capsule")), readFileSync(F("bob-json.capsule"))) === 0);

  // Unpinned timestamps produce a DIFFERENT genuine successor, not an error.
  const drift = run(["rewrap", F("alice.capsule"), "--key", F("bob.private.hex"),
    "--out", F("bob-drift.capsule"), "--participant", "human:bob", "--label", "Bob", "--json"]);
  check("an unpinned rewrap is a distinct genuine successor",
    drift.code === 0 && json(drift).successor.capsule_id !== j.successor.capsule_id);
}

// ----------------------------------------------------------------------

section("checked-in vectors - cross-era citation and a malformed declaration");

{
  // The conformance collection is the cross-lane pin; these two assert
  // the CLI renders what it consumes.
  const vec = (name) => join(ROOT, "..", "spec", "vectors", "lineage", "output", name);

  const v06 = run(["verify", vec("successor-of-v06.capsule"),
    "--predecessor", vec("known-previous-version-0.6.capsule")]);
  check("a v0.6 predecessor verifies to depth 1 across eras", v06.code === 0
    && /lineage verified to depth 1/.test(v06.stdout));
  check("the entry reports the predecessor's own era", /era 0\.6\s+status=verified/.test(v06.stdout));
  check("the artifact summary reports the era it was checked under",
    /version=0\.6/.test(v06.stdout));

  // Presence binds: a declaration no reader can interpret fails closed,
  // and the Custody block says where to look.
  const bad = run(["verify", vec("empty-array.capsule")]);
  check("a malformed declaration exits 1", bad.code === 1);
  check("a malformed declaration is named in the custody block",
    /present but malformed/.test(bad.stdout));
  check("the malformation diagnosis names the member",
    /manifest\.predecessors must not be empty when present/.test(bad.stdout));
  const badJson = json(run(["verify", vec("empty-array.capsule"), "--json"]));
  check("--json reports the lineage area as failed",
    badJson?.lineage?.declared === true && badJson.lineage.ok === false
      && badJson.integrity_ok === false);
}

// ----------------------------------------------------------------------

section("inspect - the declaration is printed, never hidden");

{
  const i = run(["inspect", F("bob.capsule")]);
  check("inspect prints the declaration", /Predecessors \(declared lineage, 1 entry\):/.test(i.stdout));
  check("inspect prints the entry members",
    /manifest_hash:\s+[0-9a-f]{64}/.test(i.stdout) && /entry_hash:\s+[0-9a-f]{64}/.test(i.stdout));
  check("inspect labels the entry 'declared, not verified'",
    /declared, not verified/.test(i.stdout));
  check("inspect prints the not-countersigned note", /not countersigned/.test(i.stdout));
  check("inspect points at the command that checks it",
    /capsule verify <file> --predecessor/.test(i.stdout));

  const ij = json(run(["inspect", F("bob.capsule"), "--json"]));
  check("inspect --json carries predecessors verbatim",
    Array.isArray(ij?.predecessors) && ij.predecessors.length === 1);

  const plain = json(run(["inspect", F("alice.capsule"), "--json"]));
  check("inspect --json reports null for an undeclared capsule", plain?.predecessors === null);
  check("inspect prints no lineage block for an undeclared capsule",
    !/Predecessors \(declared lineage/.test(run(["inspect", F("alice.capsule")]).stdout));
}

// ----------------------------------------------------------------------

section("pre-lineage era - the member is reported, never interpreted");

{
  // A capsule declaring era 0.6 carrying the same value that fails a 0.7
  // capsule closed. Its bytes verify exactly as a v0.6 reader gives them.
  const inertV06 = join(
    ROOT, "..", "spec", "vectors", "lineage", "output",
    "predecessors-in-v06-capsule.capsule",
  );
  const v = run(["verify", inertV06]);
  check("verify passes a v0.6 capsule carrying a predecessors member", v.code === 0);
  check("verify prints no Custody block for it", !/Custody \(lineage\)/.test(v.stdout));
  check("verify still reports the uninterpreted member",
    /unknown member under that era/.test(v.stdout));

  const i = run(["inspect", inertV06]);
  check("inspect labels the member uninterpreted rather than malformed",
    /Predecessors \(uninterpreted\)/.test(i.stdout)
      && !/fails this declaration closed/.test(i.stdout));
  check("inspect names the era that defines no lineage semantics",
    /era 0\.6 defines no lineage semantics/.test(i.stdout));
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

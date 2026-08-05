// `capsule verify <file> [--allowlist KEY...] [--predecessor FILE...] [--json]`
//
// Wraps the SDK's verifyCapsule() and applies the CLI's TRUST POLICY and
// CUSTODY POLICY on top. The split is deliberate: the SDK reports facts
// (which integrity checks passed; which signers are trusted under the
// supplied allowlist; which declared predecessors the supplied bytes
// establish) and never decides policy — the CLI is the policy layer,
// because the CLI is where an operator expresses what they demand.
//
//   - No --allowlist:  no trust policy. The verdict covers integrity
//                      only, and the report says so explicitly.
//   - --allowlist KEY (repeatable): trust policy "at least one distinct
//                      allowlisted key must carry a valid signature".
//                      A capsule whose math checks pass but whose
//                      signers all miss the allowlist FAILS (exit 1) —
//                      `capsule verify f --allowlist $KEY && deploy`
//                      must never deploy an artifact signed by someone
//                      the operator did not trust.
//   - No --predecessor: declared lineage is reported, never a verdict
//                      input (spec/lineage.md: linkage is report-only —
//                      a host's file handling must not forge a forgery
//                      verdict against an honest successor).
//   - --predecessor FILE (repeatable): custody policy "every supplied
//                      file matches a declared entry, verifies valid
//                      under its own era, and every equality holds".
//                      `capsule verify s --predecessor p && publish`
//                      must never publish on a failed custody check the
//                      operator asked for. Declared entries left
//                      unsupplied do NOT fail the exit (an operator may
//                      hold one branch of a merge) but are reported.
//
// Exit codes (documented in cli/README.md; CI depends on them):
//   0  integrity verified AND every requested policy satisfied
//   1  integrity failed OR a requested policy (trust, custody) failed
//   2  usage / I-O error (unknown flag, malformed key, unreadable file)
//
// The plain report mirrors the Rust verifier's layout. The JSON output
// carries the same integrity fields as the Rust CLI plus a `trust`
// block; `ok` here is the OVERALL verdict (integrity AND policy) and
// always matches the exit code, while `integrity_ok` preserves the
// SDK/Rust math-only verdict.

import { CapsuleReader, verifyCapsule } from "@capsule/sdk-v0.7-prototype";
import { parseArgs } from "../args.mjs";
import { CLIError, check, out, readBytes, truncHex } from "../format.mjs";

const USAGE = `usage: capsule verify <file> [--allowlist KEY...] [--predecessor FILE...] [--json]

  --allowlist KEY    Trusted Ed25519 public key (64 hex chars). Repeat
                     the flag for multiple keys. Supplying an allowlist
                     sets the trust policy: verification FAILS (exit 1)
                     unless at least one allowlisted key carries a
                     valid signature. Without it the verdict covers
                     integrity only, and the report says so.
  --predecessor FILE Sealed predecessor capsule to check the capsule's
                     manifest.predecessors declaration against. Repeat
                     the flag (merges, and one file per hop for deeper
                     lineage). Supplying one sets the custody policy:
                     verification FAILS (exit 1) unless every supplied
                     file matches a declared entry, verifies valid
                     under its own era, and every equality holds.
                     Without it, declared lineage is reported and never
                     affects the exit code.
  --json             Emit the full result as pretty-printed JSON.
                     Same exit code in either mode.
`;

export async function verifyCmd(argv) {
  const args = parseArgs(argv, {
    booleans: ["json"],
    arrays: ["allowlist", "predecessor"],
    maxPositionals: 1,
  });
  if (args.help) {
    process.stderr.write(USAGE);
    return 0;
  }
  const file = args._[0];
  if (!file) {
    process.stderr.write(USAGE);
    return 2;
  }

  // Trust configuration is validated at the argument boundary (parity
  // with the Rust CLI): an entry that is not a 32-byte Ed25519 public
  // key can never match a signer, so accepting it would only ever
  // manufacture a misleading FAIL — or, before F04, a misleading PASS.
  const allowlist = args.allowlist || [];
  for (const entry of allowlist) {
    if (!/^[0-9a-fA-F]{64}$/.test(entry)) {
      throw new CLIError(
        `--allowlist entry must be 64 hex chars (a 32-byte Ed25519 public key); got: ${entry}`,
        2,
      );
    }
  }

  const bytes = await readBytes(file);

  // The predecessor pool is read at the argument boundary too: an
  // unreadable path is a usage error, never a silently smaller pool
  // that would report the entry "declared, not verified".
  const predecessorFiles = args.predecessor || [];
  const pool = [];
  for (const path of predecessorFiles) pool.push(await readBytes(path));

  let reader;
  try {
    reader = await CapsuleReader.fromBytes(bytes);
  } catch (e) {
    throw new CLIError(`cannot open capsule: ${e.message}`, 2);
  }

  const result = await verifyCapsule(reader, { allowlist, predecessors: pool });

  // TRUST POLICY (the CLI-level decision the SDK deliberately never
  // makes). trustedSignerCount counts DISTINCT keys that are both valid
  // and allowlisted, so duplicate signer rows cannot satisfy the policy.
  const policy = allowlist.length > 0 ? "allowlist" : "none";
  const policySatisfied = policy === "none" ? null : result.trustedSignerCount > 0;

  // CUSTODY POLICY (spec/lineage.md "CLI exit policy"). The SDK's
  // linkage reporting is report-only in every lane; supplying
  // --predecessor is the operator asking for it to be decisive here.
  // A checked entry is one a supplied artifact was matched to, so the
  // count of them is the count of supplied files that matched
  // something: an unmatched file (a mistyped path) fails the policy,
  // and so does any checked entry that is not `verified`.
  const custody = custodyPolicy(result.lineage, predecessorFiles.length);
  const ok = result.ok && policySatisfied !== false && custody.satisfied !== false;

  if (args.json) {
    out(JSON.stringify(
      {
        ok,
        integrity_ok: result.ok,
        level: result.level,
        capsule_id: reader.manifest().id,
        signed_at: reader.envelope().signed_at,
        trust: {
          policy,
          allowlist_size: allowlist.length,
          trusted_signer_count: result.trustedSignerCount,
          satisfied: policySatisfied,
        },
        errors: result.errors,
        chain: result.chain,
        content_index: result.contentIndex,
        envelope: result.envelope,
        signer_set: result.signerSet,
        actor_set: result.actorSet,
        // spec/lineage.md reporting: the facts channel, in the spec's
        // snake_case. Report-only at the SDK level; `custody` beside it
        // carries the CLI policy this invocation asked for.
        lineage: lineageJson(result.lineage),
        custody: {
          policy: custody.policy,
          predecessors_supplied: predecessorFiles.length,
          unmatched_count: custody.unmatched,
          verified_depth: result.lineage.verifiedDepth,
          satisfied: custody.satisfied,
        },
        // spec/versioning.md: the observed format version is a reported
        // fact, next to (never inside) the integrity verdict.
        format_version: result.formatVersion,
        // Derived at verify time from THIS invocation's allowlist —
        // never read from the capsule (spec/trust.md "Skill trust").
        skill_trust: {
          capsule_signed: result.skillTrust.capsuleSigned,
          skills: result.skillTrust.skills,
        },
        notes: result.notes,
        trusted_signer_count: result.trustedSignerCount,
      },
      null,
      2,
    ));
    return ok ? 0 : 1;
  }

  // Human report.
  const m = reader.manifest();
  const e = reader.envelope();
  out(`File:                   ${file} (${bytes.length} bytes)`);
  out(`Capsule ID:             ${truncHex(m.id)}`);
  out(`Originator (Ed25519):   ${truncHex(m.originator.public_key)}`);
  // signed_at is asserted by the signer; the format has no external
  // time anchor, so it is labelled as attested, never verified.
  out(`Sealed at (attested):   ${e.signed_at}  — signer-supplied; no external time anchor`);
  out(`Level:                  ${result.level}`);
  // spec/versioning.md: report which era's rules were applied. Suite
  // "v0.6" = Ed25519 / SHA-256 / JCS / X25519+HKDF-SHA-256+ChaCha20.
  out(`Format version:         ${result.formatVersion.observed}` +
      (result.formatVersion.suite ? `  (${result.formatVersion.suite} suite)` : ""));
  out("");
  out("Checks:");
  out(`  [${check(result.contentIndex.ok)}] content_index` +
      (result.contentIndex.errors?.length ? `  (${result.contentIndex.errors.length} error(s))` : ""));
  out(`  [${check(result.chain.ok)}] chain` +
      (result.chain.errors?.length ? `  (${result.chain.errors.length} error(s))` : "") +
      (result.chain.note ? `  — ${result.chain.note}` : ""));
  out(`  [${check(result.envelope.ok)}] envelope_signature`);
  out(`  [${check(result.signerSet.ok)}] signer_set` +
      (result.signerSet.bound ? "" : "  — unbound (manifest.signer_commitment absent)"));
  // Actor-set binding: violations surface as chain errors; the line
  // fails when any chain error is an actor-rule error, and bound/unbound
  // is the honest-assurance report (mirrors signer_set).
  const actorErrors = (result.chain.errors ?? []).filter((ce) =>
    String(ce.message ?? "").includes("not in manifest.participants"));
  out(`  [${check(actorErrors.length === 0)}] actor_set` +
      (actorErrors.length ? `  (${actorErrors.length} error(s))` : "") +
      (result.actorSet.bound ? "" : "  — unbound (manifest.participants empty)"));

  // Trust is reported apart from the integrity checks: the checks above
  // are facts about the capsule; this block is the operator's policy.
  out("");
  out("Trust:");
  if (policy === "none") {
    out(`  policy:            none — no --allowlist supplied`);
    out(`  trusted signers:   0 (nothing is trusted without an allowlist)`);
    out(`  policy check:      NOT EVALUATED — signer identity not checked`);
  } else {
    out(`  policy:            allowlist (${allowlist.length} key${allowlist.length === 1 ? "" : "s"} supplied)`);
    out(`  trusted signers:   ${result.trustedSignerCount} distinct allowlisted key(s) with a valid signature`);
    out(`  policy check:      ${policySatisfied
      ? "SATISFIED"
      : "FAILED — no signer matches the supplied allowlist"}`);
  }
  // Skill trust is DERIVED from this invocation's allowlist, never read
  // from the capsule (spec/trust.md "Skill trust").
  const skillTiers = Object.entries(result.skillTrust.skills);
  if (skillTiers.length > 0) {
    out(`  skills (derived):  ${skillTiers.map(([id, tier]) => `${id}=${tier}`).join(", ")}`);
  }

  // Custody: the lineage declaration and what this invocation could
  // establish about it. A declared predecessor is NEVER omitted from
  // output — a custody claim that quietly disappears when bytes are
  // missing is how a citation gets read as an endorsement
  // (spec/lineage.md, required human-output language).
  const lineageNotes = (result.notes ?? []).filter((n) => String(n).startsWith("lineage:"));
  const custodyBlockShown = result.lineage.declared || predecessorFiles.length > 0;
  if (custodyBlockShown) {
    out("");
    out("Custody (lineage):");
    const malformed = result.lineage.declared && !result.lineage.ok
      && result.lineage.entries.length === 0;
    out(`  declared:          ${!result.lineage.declared
      ? "no manifest.predecessors member — this capsule declares no predecessor"
      : malformed
        ? "manifest.predecessors is present but malformed — see Errors"
        : `${result.lineage.entries.length} predecessor entr${result.lineage.entries.length === 1 ? "y" : "ies"}`}`);
    out(`  policy:            ${custody.policy === "none"
      ? "none — no --predecessor supplied; lineage does not affect the exit code"
      : `predecessor (${predecessorFiles.length} file${predecessorFiles.length === 1 ? "" : "s"} supplied)`}`);
    if (result.lineage.declared && !malformed) {
      out(`  verified depth:    ${result.lineage.verifiedDepth}`);
      for (const e of result.lineage.entries) {
        out(`  - hop ${e.hop}  capsule ${truncHex(e.capsule_id)}  era ${e.format_version}` +
            `  status=${e.status}${e.reason ? ` (${e.reason})` : ""}` +
            (e.identityChecked ? "" : "  identity_checked=false"));
        if (e.artifact) {
          out(`      supplied artifact: ok=${e.artifact.ok}  level=${e.artifact.level}` +
              `  version=${e.artifact.observed_version}  errors=${e.artifact.error_count}`);
        }
        for (const detail of e.errors) out(`      ${detail}`);
      }
    }
    if (custody.policy !== "none") {
      out(`  policy check:      ${custody.satisfied
        ? "SATISFIED — every supplied predecessor matched a declared entry and verified"
        : `FAILED — ${custody.reason}`}`);
    }
    if (lineageNotes.length) {
      out("  notes:");
      for (const n of lineageNotes) out(`    - ${String(n).replace(/^lineage: /, "")}`);
    }
  }

  out("");
  out("Signers:");
  if (result.envelope.signers?.length) {
    for (const s of result.envelope.signers) {
      out(`  - ${(s.role + ":").padEnd(13)} ${truncHex(s.public_key)}` +
          `  valid=${s.valid}  trusted=${s.trusted}`);
    }
  } else {
    out("  (none)");
  }

  if (result.errors?.length) {
    out("");
    out("Errors:");
    for (const er of result.errors) out(`  - ${er}`);
  }
  if (result.chain.errors?.length) {
    out("");
    out("Chain errors:");
    for (const ce of result.chain.errors) out(`  - seq ${ce.seq}: ${ce.message}`);
  }
  if (result.contentIndex.errors?.length) {
    out("");
    out("Content-index errors:");
    for (const ie of result.contentIndex.errors) out(`  - ${ie}`);
  }
  // Lineage notes are rendered in the Custody block above, where they
  // sit next to the entries they describe; printing them twice would
  // make one channel look like two. When there is no Custody block —
  // a pre-lineage-era capsule whose member was not interpreted — they
  // fall through to Notes rather than disappearing.
  const otherNotes = (result.notes ?? []).filter(
    (n) => !(custodyBlockShown && String(n).startsWith("lineage:")),
  );
  if (otherNotes.length) {
    out("");
    out("Notes:");
    for (const n of otherNotes) out(`  - ${n}`);
  }

  // The verdict line says exactly what it covers. PASS must never be
  // readable as more than what was actually checked.
  const qualifiers = [];
  if (result.ok) {
    qualifiers.push(policy === "none"
      ? "integrity only — signer identity not checked"
      : "integrity verified");
  } else {
    qualifiers.push("integrity checks failed");
  }
  if (policy !== "none") {
    qualifiers.push(policySatisfied
      ? "trust policy satisfied"
      : "trust policy FAILED: no signer matches the supplied allowlist");
  }
  if (custody.policy !== "none") {
    qualifiers.push(custody.satisfied
      ? `custody policy satisfied (lineage verified to depth ${result.lineage.verifiedDepth})`
      : `custody policy FAILED: ${custody.reason}`);
  }
  if (!result.signerSet.bound) qualifiers.push("signer set unbound");

  out("");
  out(`Result: ${ok ? "PASS" : "FAIL"} (${qualifiers.join("; ")})`);
  return ok ? 0 : 1;
}

/**
 * The custody policy this invocation asked for (spec/lineage.md "CLI
 * exit policy"). Every supplied artifact the SDK matched moved exactly
 * one entry off `unverified`, so the checked entries count the supplied
 * files that found a home: the rest are unmatched (a mistyped path must
 * not exit 0). Entries left `unverified` are declared-but-unsupplied —
 * an operator may hold one branch of a merge — and never fail the exit.
 */
function custodyPolicy(lineage, suppliedCount) {
  if (suppliedCount === 0) {
    return { policy: "none", satisfied: null, unmatched: 0, reason: null };
  }
  const checked = lineage.entries.filter((e) => e.status !== "unverified");
  const unmatched = suppliedCount - checked.length;
  const notVerified = checked.filter((e) => e.status !== "verified");
  const reasons = [];
  if (unmatched > 0) {
    reasons.push(
      `${unmatched} supplied predecessor file(s) matched no declared entry`,
    );
  }
  for (const e of notVerified) {
    reasons.push(
      `hop ${e.hop} ${e.capsule_id}: ${e.status}${e.reason ? ` (${e.reason})` : ""}`,
    );
  }
  return {
    policy: "predecessor",
    satisfied: reasons.length === 0,
    unmatched,
    reason: reasons.length === 0 ? null : reasons.join("; "),
  };
}

/** The lineage facts channel in the spec's snake_case for --json. */
function lineageJson(lineage) {
  return {
    declared: lineage.declared,
    ok: lineage.ok,
    verified_depth: lineage.verifiedDepth,
    entries: lineage.entries.map((e) => ({
      capsule_id: e.capsule_id,
      format_version: e.format_version,
      originator_public_key: e.originator_public_key,
      first_event_hash: e.first_event_hash,
      entry_hash: e.entry_hash,
      manifest_hash: e.manifest_hash,
      hop: e.hop,
      identity_checked: e.identityChecked,
      status: e.status,
      reason: e.reason,
      errors: e.errors,
      artifact: e.artifact,
    })),
  };
}

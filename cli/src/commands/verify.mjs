// `capsule verify <file> [--allowlist KEY...] [--json]`
//
// Wraps the SDK's verifyCapsule() and applies the CLI's TRUST POLICY on
// top. The split is deliberate: the SDK reports facts (which integrity
// checks passed; which signers are trusted under the supplied
// allowlist) and never decides policy — the CLI is the policy layer,
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
//
// Exit codes (documented in cli/README.md; CI depends on them):
//   0  integrity verified AND trust policy satisfied (or none supplied)
//   1  integrity failed OR the supplied trust policy is not satisfied
//   2  usage / I-O error (unknown flag, malformed key, unreadable file)
//
// The plain report mirrors the Rust verifier's layout. The JSON output
// carries the same integrity fields as the Rust CLI plus a `trust`
// block; `ok` here is the OVERALL verdict (integrity AND policy) and
// always matches the exit code, while `integrity_ok` preserves the
// SDK/Rust math-only verdict.

import { CapsuleReader, verifyCapsule } from "@capsule/sdk-v0.6-prototype";
import { parseArgs } from "../args.mjs";
import { CLIError, check, out, readBytes, truncHex } from "../format.mjs";

const USAGE = `usage: capsule verify <file> [--allowlist KEY...] [--json]

  --allowlist KEY    Trusted Ed25519 public key (64 hex chars). Repeat
                     the flag for multiple keys. Supplying an allowlist
                     sets the trust policy: verification FAILS (exit 1)
                     unless at least one allowlisted key carries a
                     valid signature. Without it the verdict covers
                     integrity only, and the report says so.
  --json             Emit the full result as pretty-printed JSON.
                     Same exit code in either mode.
`;

export async function verifyCmd(argv) {
  const args = parseArgs(argv, {
    booleans: ["json"],
    arrays: ["allowlist"],
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

  let reader;
  try {
    reader = await CapsuleReader.fromBytes(bytes);
  } catch (e) {
    throw new CLIError(`cannot open capsule: ${e.message}`, 2);
  }

  const result = await verifyCapsule(reader, { allowlist });

  // TRUST POLICY (the CLI-level decision the SDK deliberately never
  // makes). trustedSignerCount counts DISTINCT keys that are both valid
  // and allowlisted, so duplicate signer rows cannot satisfy the policy.
  const policy = allowlist.length > 0 ? "allowlist" : "none";
  const policySatisfied = policy === "none" ? null : result.trustedSignerCount > 0;
  const ok = result.ok && policySatisfied !== false;

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
        // spec/versioning.md: the observed format version is a reported
        // fact, next to (never inside) the integrity verdict.
        format_version: result.formatVersion,
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
  // signed_at is asserted by the signer; v0.6 has no external time
  // anchor, so it is labelled as attested, never presented as verified.
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
  if (result.notes?.length) {
    out("");
    out("Notes:");
    for (const n of result.notes) out(`  - ${n}`);
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
  if (!result.signerSet.bound) qualifiers.push("signer set unbound");

  out("");
  out(`Result: ${ok ? "PASS" : "FAIL"} (${qualifiers.join("; ")})`);
  return ok ? 0 : 1;
}

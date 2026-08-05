// `capsule rewrap <predecessor.capsule> --key FILE --out FILE [...]`
//
// The hand-off made one command (spec/lineage.md "Continuing a capsule"):
// sealed predecessor + NEW originator keypair in, sealed successor out,
// declaring the predecessor in `manifest.predecessors`. This is the
// CLI's first WRITING command; it adds no wire members and no verifier
// rules — the SDK's rewrapCapsule() does the work, and the CLI applies
// exactly one policy on top: do not build on a predecessor that fails
// verification, with the same supplied-flag override discipline as
// verify's --allowlist.
//
// Files carry, claims reset (W6): program.md, agents.md, payload/**,
// skills/** and any legacy content-indexed file travel byte-identically;
// participants, created_at, labels, the signer commitment and the
// predecessor's own predecessors member are the predecessor originator's
// claims about THAT capsule and are not echoed. The chain resets to a
// fresh genesis — predecessor history stays where it is signed.
//
// Exit codes (documented in cli/README.md; CI depends on them):
//   0  successor written (including under --allow-invalid-predecessor,
//      with the pinned warning)
//   1  the predecessor fails its own verification (W3 default refusal),
//      or its declared era is unknown (W4 — no override: the identity
//      recompute needs that era's domain string, so an entry would be a
//      fabricated commitment). Nothing is written.
//   2  usage / I-O / input-class error: missing or malformed --key,
//      missing --out, output exists without --force, unreadable
//      predecessor, unknown flag, or an input class this command does
//      not take (encrypted or alternate-profile predecessor, W5) —
//      not a verdict about the artifact.

import { writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import {
  CapsuleReader,
  PredecessorError,
  SPEC_VERSION,
  UnsupportedVersionError,
  bytesToHex,
  ed25519DerivePublic,
  hexToBytes,
  rewrapCapsule,
  verificationErrorCount,
} from "@capsule/sdk-v0.7-prototype";
import { parseArgs } from "../args.mjs";
import { CLIError, out, readBytes, truncHex } from "../format.mjs";

const USAGE = `usage: capsule rewrap <predecessor.capsule> --key FILE --out FILE
                      [--label NAME] [--participant ACTOR_ID ...]
                      [--custody-actor ACTOR_ID] [--no-custody-event]
                      [--allow-invalid-predecessor]
                      [--created-at ISO] [--signed-at ISO]
                      [--force] [--json]

  --key FILE          NEW originator Ed25519 private key, 64 hex chars
                      (the file \`capsule keygen --out\` writes). The
                      public key is derived from it; the private key is
                      never printed.
  --out FILE          successor output path. REQUIRED — a writing
                      command never invents a destination. Refuses to
                      overwrite an existing file without --force.
  --label NAME        originator label (advisory, default none).
  --participant ID    declare a successor participant actor id
                      (repeatable). Never inherited from the
                      predecessor: participants[] says who may act in
                      the SUCCESSOR's chain, which is your claim.
  --custody-actor ID  actor for the custody_received genesis event
                      (default system:host; must be system:host or a
                      declared --participant).
  --no-custody-event  do not emit the custody_received genesis event.
  --allow-invalid-predecessor
                      proceed when the predecessor fails verification.
                      Prints a warning; the declaration still cites the
                      exact artifact, and linkage verification reports
                      it predecessor_invalid either way.
  --created-at ISO    pin the successor's created_at (reproducible bytes)
  --signed-at ISO     pin the successor's signed_at (reproducible bytes)
  --force             overwrite an existing --out file.
  --json              emit the machine result instead of the report.
`;

export async function rewrapCmd(argv) {
  const args = parseArgs(argv, {
    booleans: ["json", "force", "no_custody_event", "allow_invalid_predecessor"],
    strings: ["key", "out", "label", "custody_actor", "created_at", "signed_at"],
    arrays: ["participant"],
    maxPositionals: 1,
  });
  if (args.help) {
    process.stderr.write(USAGE);
    return 0;
  }
  const file = args._[0];
  if (!file || !args.key || !args.out) {
    process.stderr.write(USAGE);
    return 2;
  }
  if (existsSync(args.out) && !args.force) {
    throw new CLIError(
      `--out ${args.out} already exists; pass --force to overwrite`,
      2,
    );
  }

  // W9: the key file is read, used to sign, and never echoed. Only the
  // derived public key is reported, truncated in the human output.
  const keyText = Buffer.from(await readBytes(args.key)).toString("utf8");
  const privateKeyHex = keyText.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(privateKeyHex)) {
    throw new CLIError(
      `--key ${args.key} must contain a 64-hex-char Ed25519 private key ` +
        `(the file \`capsule keygen --out DIR\` writes as <label>.private.hex)`,
      2,
    );
  }
  const privateKey = hexToBytes(privateKeyHex);
  const publicKeyHex = bytesToHex(ed25519DerivePublic(privateKey));

  // Timestamps are validated at the argument boundary, like --allowlist
  // entries: `created_at` and `signed_at` are ISO 8601 UTC without
  // fractional seconds (spec/manifest.md, spec/envelope.md), and a
  // writing command must not seal a shape the spec does not allow
  // because a flag value was a typo.
  for (const flag of ["created_at", "signed_at"]) {
    const value = args[flag];
    if (value !== undefined && !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) {
      throw new CLIError(
        `--${flag.replace("_", "-")} must be ISO 8601 UTC without fractional ` +
          `seconds (e.g. 2026-05-07T12:00:00Z); got: ${value}`,
        2,
      );
    }
  }

  const predecessorBytes = await readBytes(file);
  let predecessorReader;
  try {
    predecessorReader = await CapsuleReader.fromBytes(predecessorBytes);
  } catch (e) {
    if (e instanceof UnsupportedVersionError) {
      // W4, exit 1: a verdict about the artifact's era, in the
      // versioning.md vocabulary — machine-distinct from tamper.
      throw new CLIError(
        `predecessor ${e.message}. There is no override: the declaration's ` +
          `capsule_id recompute needs that era's domain string, so an entry ` +
          `derived here would be a fabricated commitment`,
        1,
      );
    }
    throw new CLIError(`cannot open predecessor capsule: ${e.message}`, 2);
  }

  const participants = (args.participant || []).map((actorId) => ({ actor_id: actorId }));
  const custodyEvent = args.no_custody_event !== true;
  const custodyActor = args.custody_actor || undefined;

  let rewrapped;
  try {
    rewrapped = await rewrapCapsule(predecessorReader, {
      originator: {
        publicKey: publicKeyHex,
        privateKey: privateKeyHex,
        ...(args.label ? { label: args.label } : {}),
      },
      participants,
      createdAt: args.created_at,
      signedAt: args.signed_at,
      custodyEvent,
      ...(custodyActor ? { custodyActor } : {}),
      allowInvalidPredecessor: args.allow_invalid_predecessor === true,
    });
  } catch (e) {
    if (e instanceof PredecessorError) throw refusal(e, args.out);
    // An actor-rule violation on --custody-actor, a bad --participant
    // id, a malformed timestamp: the builder fails at the call site
    // that introduced it, which is this invocation's arguments.
    throw new CLIError(e.message, 2);
  }

  await writeFile(args.out, Buffer.from(rewrapped.bytes));

  const predecessorVerification = rewrapped.predecessorVerification;
  const predecessorErrors = verificationErrorCount(predecessorVerification);
  const warnings = [];
  if (!predecessorVerification.ok) {
    warnings.push(
      `predecessor failed verification (${predecessorErrors} error(s)); ` +
        `sealing anyway — the declaration cites this exact artifact, and linkage ` +
        `verification will report it predecessor_invalid.`,
    );
  }

  if (args.json) {
    out(JSON.stringify({
      ok: true,
      out: args.out,
      successor: {
        capsule_id: rewrapped.capsuleId,
        originator_public_key: publicKeyHex,
        // W8: a successor is a new artifact of this SDK's era.
        format_version: SPEC_VERSION,
        participants: participants.map((p) => p.actor_id),
        custody_event_emitted: rewrapped.custodyEventEmitted,
        carried_paths: rewrapped.carriedPaths,
      },
      predecessor: {
        file,
        entry: rewrapped.predecessorEntry,
        verification: {
          ok: predecessorVerification.ok,
          level: predecessorVerification.level,
          format_version: predecessorVerification.formatVersion?.observed ?? null,
          error_count: predecessorErrors,
        },
      },
      warnings,
    }, null, 2));
    return 0;
  }

  const entry = rewrapped.predecessorEntry;
  const successor = await CapsuleReader.fromBytes(rewrapped.bytes);
  const outBytes = rewrapped.bytes.length;
  out(`Predecessor:            ${file} (${predecessorBytes.length} bytes)`);
  out(`  Capsule ID:           ${truncHex(entry.capsule_id)}`);
  out(`  Format version:       ${entry.format_version}` +
      (predecessorVerification.formatVersion?.suite
        ? `  (${predecessorVerification.formatVersion.suite} suite)`
        : ""));
  out(`  Verification:         ${predecessorVerification.ok
    ? "PASS (integrity only — signer identity not checked)"
    : `FAIL (${predecessorErrors} error(s))`}`);
  out("");
  out("Successor:");
  // "new identity": rewrap never presents the successor as BEING the
  // predecessor. The id derives from the NEW key and a NEW genesis.
  out(`  Capsule ID:           ${truncHex(successor.manifest().id)}   (new identity — derived from the new key and new genesis)`);
  out(`  Originator (Ed25519): ${truncHex(publicKeyHex)}`);
  out(`  Declared predecessors: 1 entry`);
  out(`  Participants:         ${participants.length
    ? participants.map((p) => p.actor_id).join(", ")
    : "(none declared — an unbound actor set, reported as such by every verifier)"}`);
  out(`  Custody event:        ${rewrapped.custodyEventEmitted
    ? `emitted (actor ${custodyActor || "system:host"})`
    : "not emitted (--no-custody-event)"}`);
  out(`  Carried files:        ${rewrapped.carriedPaths.length}` +
      (rewrapped.carriedPaths.length ? ` (${rewrapped.carriedPaths.join(", ")}) — byte-identical` : ""));
  out("  Chain:                fresh genesis — predecessor history remains in the predecessor");
  for (const w of warnings) {
    out("");
    out(`WARNING: ${w}`);
  }
  out("");
  // Pinned on every successful rewrap: the operator must never read
  // rewrap as having obtained the predecessor originator's approval.
  out("Note: lineage is the successor's declaration; the predecessor's");
  out("      originator has not countersigned it.");
  out("");
  out(`Wrote: ${args.out} (${outBytes} bytes)`);
  return 0;
}

/**
 * Map the builder's closed refusal vocabulary onto the CLI exit
 * contract. `verification_failed` and `unsupported_version` are
 * verdicts about the artifact (exit 1); the two scope refusals are
 * input classes this command does not take (exit 2), and each names
 * the supported path rather than guessing. Nothing is written on any
 * of them — `capsule rewrap p ... && capsule verify s` composes.
 */
function refusal(e, outPath) {
  const nothingWritten = `Nothing was written to ${outPath}`;
  switch (e.reason) {
    case "verification_failed":
      // The CLI states this one in its own words: the SDK's message
      // names the SDK's option, and its count reads only the
      // top-level errors array.
      return new CLIError(
        `predecessor fails its own verification ` +
          `(${verificationErrorCount(e.verification)} error(s)); ` +
          `run \`capsule verify\` on it to see them. ${nothingWritten}. Pass ` +
          `--allow-invalid-predecessor to declare it anyway — the declaration ` +
          `cites this exact artifact, and linkage verification reports it ` +
          `predecessor_invalid either way`,
        1,
      );
    case "unsupported_version":
      return new CLIError(`${e.message}. ${nothingWritten}`, 1);
    case "encrypted_predecessor":
    case "unsupported_profile":
      return new CLIError(`${e.message}. ${nothingWritten}`, 2);
    default:
      return new CLIError(`${e.message}. ${nothingWritten}`, 1);
  }
}

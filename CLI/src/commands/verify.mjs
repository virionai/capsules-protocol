// `capsule verify <file> [--allowlist KEY...] [--json]`
//
// Wraps the SDK's verifyCapsule(). Output mirrors the Rust verifier's
// shape so a tool that reads either output gets the same fields.

import { CapsuleReader, verifyCapsule } from "@capsule/sdk-v0.6-prototype";
import { parseArgs } from "../args.mjs";
import { CLIError, check, out, readBytes, truncHex } from "../format.mjs";

const USAGE = `usage: capsule verify <file> [--allowlist KEY...] [--json]

  --allowlist KEY    Trusted Ed25519 public key (lowercase hex, 64 chars).
                     Repeat the flag for multiple keys. A signer is
                     marked trusted only when its key appears here AND
                     its signature verifies.
  --json             Emit the full VerifyResult as pretty-printed JSON.
`;

export async function verifyCmd(argv) {
  const args = parseArgs(argv, {
    booleans: ["json"],
    arrays: ["allowlist"],
  });
  const file = args._[0];
  if (!file) {
    process.stderr.write(USAGE);
    return 2;
  }

  const bytes = await readBytes(file);

  let reader;
  try {
    reader = await CapsuleReader.fromBytes(bytes);
  } catch (e) {
    throw new CLIError(`cannot open capsule: ${e.message}`, 2);
  }

  const allowlist = args.allowlist || [];
  const result = await verifyCapsule(reader, { allowlist });

  if (args.json) {
    out(JSON.stringify(
      {
        ok: result.ok,
        level: result.level,
        capsule_id: reader.manifest().id,
        signed_at: reader.envelope().signed_at,
        errors: result.errors,
        chain: result.chain,
        content_index: result.contentIndex,
        envelope: result.envelope,
        notes: result.notes,
        trusted_signer_count: result.trustedSignerCount,
      },
      null,
      2,
    ));
    return result.ok ? 0 : 1;
  }

  // Human report.
  const m = reader.manifest();
  const e = reader.envelope();
  out(`File:                   ${file} (${bytes.length} bytes)`);
  out(`Capsule ID:             ${truncHex(m.id)}`);
  out(`Originator (Ed25519):   ${truncHex(m.originator.public_key)}`);
  out(`Sealed at:              ${e.signed_at}`);
  out(`Level:                  ${result.level}`);
  out("");
  out("Checks:");
  out(`  [${check(result.contentIndex.ok)}] content_index` +
      (result.contentIndex.errors?.length ? `  (${result.contentIndex.errors.length} error(s))` : ""));
  out(`  [${check(result.chain.ok)}] chain` +
      (result.chain.errors?.length ? `  (${result.chain.errors.length} error(s))` : "") +
      (result.chain.note ? `  — ${result.chain.note}` : ""));
  out(`  [${check(result.envelope.ok)}] envelope_signature`);
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

  out("");
  out(`Result: ${result.ok ? "PASS" : "FAIL"}`);
  return result.ok ? 0 : 1;
}

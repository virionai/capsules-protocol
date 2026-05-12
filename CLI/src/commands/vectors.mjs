// `capsule vectors verify <vectors.json> [--json]`
//
// Cross-implementation parity entry point. Reads a parity-vectors file
// produced by one of the example generators, decodes the embedded
// `capsule_bytes_b64`, and runs the SDK verifier over those bytes. Then
// asserts the verifier-observed identity / hashes match the file's
// `expected.*` fields.
//
// The contract is: any conforming v0.6 implementation should accept the
// embedded capsule bytes AND should compute the same capsule_id,
// manifest_hash, content_index_hash, first_event_hash, entry_hash. If
// any of those drift, this command exits 1 with a per-field diff. That
// is the cross-impl parity check distilled into one CLI invocation.
//
// This command is the single line a CI matrix can run across JS, Rust,
// Python, Swift, Kotlin to prove the implementations agree.

import { readFile } from "node:fs/promises";
import { CapsuleReader, verifyCapsule, hexToBytes } from "@capsule/sdk-v0.6-prototype";
import { parseArgs } from "../args.mjs";
import { CLIError, check, out, truncHex } from "../format.mjs";

const USAGE = `usage: capsule vectors <subcommand> [args...]

  verify <vectors.json> [--json]    re-verify an embedded capsule under the
                                    JS SDK and check its hashes match the
                                    file's expected.* fields.

The vectors.json schema (produced by the example generators):

  {
    "originator_public_key_hex": "<64-hex>",
    "expected": {
      "capsule_id": "<64-hex>",
      "first_event_hash": "<64-hex>",
      "entry_hash": "<64-hex>",
      "manifest_hash": "<64-hex>",
      "content_index_hash": "<64-hex>",
      "envelope_signature_hex": "<128-hex>",
      ...
    },
    "capsule_bytes_b64": "<base64 of the .capsule bytes>"
  }
`;

export async function vectorsCmd(argv) {
  const sub = argv[0];
  const rest = argv.slice(1);
  if (!sub || sub === "help" || sub === "-h" || sub === "--help") {
    process.stderr.write(USAGE);
    return sub ? 0 : 2;
  }
  if (sub === "verify") return await vectorsVerify(rest);
  process.stderr.write(`unknown vectors subcommand: ${sub}\n${USAGE}`);
  return 2;
}

async function vectorsVerify(argv) {
  const args = parseArgs(argv, { booleans: ["json"] });
  const file = args._[0];
  if (!file) { process.stderr.write(USAGE); return 2; }

  let vec;
  try {
    vec = JSON.parse(await readFile(file, "utf8"));
  } catch (e) {
    throw new CLIError(`cannot read vectors ${file}: ${e.message}`, 2);
  }

  if (!vec.expected) {
    throw new CLIError("vectors file missing 'expected' block", 2);
  }
  if (!vec.capsule_bytes_b64) {
    throw new CLIError("vectors file missing 'capsule_bytes_b64' (cannot rebuild without an embedded artifact)", 2);
  }
  const expected = vec.expected;
  const bytes = base64ToBytes(vec.capsule_bytes_b64);

  const reader = await CapsuleReader.fromBytes(bytes);
  const allowlist = vec.originator_public_key_hex ? [vec.originator_public_key_hex] : [];
  const result = await verifyCapsule(reader, { allowlist });

  // Diff observed vs expected.
  const m = reader.manifest();
  const e = reader.envelope();
  const observed = {
    capsule_id: m.id,
    first_event_hash: m.first_event_hash,
    entry_hash: e.entry_hash,
    manifest_hash: e.manifest_hash,
    content_index_hash: e.content_index_hash,
    envelope_signature_hex: e.signers?.[0]?.signature ?? null,
  };

  const fields = [
    "capsule_id",
    "first_event_hash",
    "entry_hash",
    "manifest_hash",
    "content_index_hash",
    "envelope_signature_hex",
  ];

  const diffs = [];
  for (const f of fields) {
    if (expected[f] !== undefined && observed[f] !== expected[f]) {
      diffs.push({ field: f, expected: expected[f], observed: observed[f] });
    }
  }

  // Optional: verify event_hashes[] one-by-one.
  if (Array.isArray(expected.event_hashes)) {
    const events = reader.events();
    if (events.length !== expected.event_hashes.length) {
      diffs.push({
        field: "event_hashes.length",
        expected: expected.event_hashes.length,
        observed: events.length,
      });
    } else {
      for (let i = 0; i < events.length; i++) {
        if (events[i].hash !== expected.event_hashes[i]) {
          diffs.push({
            field: `event_hashes[${i}]`,
            expected: expected.event_hashes[i],
            observed: events[i].hash,
          });
        }
      }
    }
  }

  const allHashesMatch = diffs.length === 0;
  const ok = result.ok && allHashesMatch;

  if (args.json) {
    out(JSON.stringify({
      ok,
      sdk_verifier_ok: result.ok,
      hashes_match: allHashesMatch,
      diffs,
      observed,
      sdk_result: {
        level: result.level,
        chain_ok: result.chain.ok,
        content_index_ok: result.contentIndex.ok,
        envelope_ok: result.envelope.ok,
        trusted_signer_count: result.trustedSignerCount,
      },
    }, null, 2));
    return ok ? 0 : 1;
  }

  out(`Vectors:           ${file}`);
  if (vec.meta?.format_version) out(`Format version:    ${vec.meta.format_version}`);
  if (vec.meta?.generator) out(`Generator:         ${vec.meta.generator}`);
  if (vec.signed_at) out(`Signed at (fixed): ${vec.signed_at}`);
  out("");
  out(`SDK verify:        ${check(result.ok)} (${result.level})`);
  out(`  chain:           ${check(result.chain.ok)}`);
  out(`  content_index:   ${check(result.contentIndex.ok)}`);
  out(`  envelope:        ${check(result.envelope.ok)}`);
  out(`  trusted signers: ${result.trustedSignerCount}`);
  out("");
  out("Hash parity:");
  for (const f of fields) {
    if (expected[f] === undefined) continue;
    const match = observed[f] === expected[f];
    out(`  [${check(match)}] ${f.padEnd(28)}  ${truncHex(observed[f] ?? "-", 16)}` +
        (match ? "" : ` ≠ expected ${truncHex(expected[f], 16)}`));
  }
  if (Array.isArray(expected.event_hashes)) {
    const events = reader.events();
    const matchN = expected.event_hashes.filter((h, i) => events[i]?.hash === h).length;
    out(`  [${check(matchN === expected.event_hashes.length && events.length === expected.event_hashes.length)}] event_hashes[]               ${matchN}/${expected.event_hashes.length} match`);
  }

  if (diffs.length > 0) {
    out("");
    out("Diffs (drift between this implementation and the vectors file):");
    for (const d of diffs) {
      out(`  ${d.field}`);
      out(`    expected: ${d.expected}`);
      out(`    observed: ${d.observed}`);
    }
  }

  out("");
  out(`Result: ${ok ? "PASS" : "FAIL"}`);
  return ok ? 0 : 1;
}

function base64ToBytes(b64) {
  const buf = Buffer.from(b64, "base64");
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

// Re-export for symmetry with the other commands.
export { hexToBytes };

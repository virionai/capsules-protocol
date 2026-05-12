// `capsule inspect <file> [--json]`
//
// One-screen overview: format version, identity, sealed time, file count,
// chain length, action histogram, payload tree size, signer summary. No
// verification — use `capsule verify` for that.

import { CapsuleReader } from "@capsule/sdk-v0.6-prototype";
import { parseArgs } from "../args.mjs";
import { bytesText, out, readBytes, truncHex } from "../format.mjs";

const USAGE = "usage: capsule inspect <file> [--json]\n";

export async function inspectCmd(argv) {
  const args = parseArgs(argv, { booleans: ["json"] });
  const file = args._[0];
  if (!file) {
    process.stderr.write(USAGE);
    return 2;
  }
  const bytes = await readBytes(file);
  const reader = await CapsuleReader.fromBytes(bytes);
  const m = reader.manifest();
  const env = reader.envelope();
  const encrypted = reader.isEncrypted();

  let actionHistogram = {};
  let chainLen = 0;
  if (!encrypted) {
    const events = reader.events();
    chainLen = events.length;
    for (const ev of events) {
      actionHistogram[ev.action] = (actionHistogram[ev.action] || 0) + 1;
    }
  }

  // Tally payload sizes if reader exposes the file map.
  let payloadFiles = [];
  let payloadTotalBytes = 0;
  if (typeof reader.files_ === "function") {
    for (const [path, b] of reader.files_().entries()) {
      if (path.startsWith("payload/")) {
        payloadFiles.push({ path, size: b.length });
        payloadTotalBytes += b.length;
      }
    }
  }

  if (args.json) {
    out(JSON.stringify({
      file,
      file_size_bytes: bytes.length,
      capsule_id: m.id,
      first_event_hash: m.first_event_hash,
      originator: m.originator,
      participants: m.participants,
      format: m.format,
      encryption: m.encryption,
      signed_at: env.signed_at,
      cipher: env.cipher,
      signers: env.signers?.map((s) => ({ role: s.role, public_key: s.public_key })) ?? [],
      content_index_files: m.content_index?.files?.length ?? 0,
      chain_length: chainLen,
      action_histogram: actionHistogram,
      payload_files: payloadFiles,
      payload_total_bytes: payloadTotalBytes,
    }, null, 2));
    return 0;
  }

  out(`File:                   ${file} (${bytesText(bytes.length)})`);
  out(`Format:                 ${m.format.version} / ${m.format.canonicalization} / ${m.format.hash_algorithm}`);
  out(`Capsule ID:             ${m.id}`);
  out(`Originator:             ${m.originator.label || "(no label)"}`);
  out(`  pubkey (Ed25519):     ${m.originator.public_key}`);
  out(`Sealed at:              ${env.signed_at}`);
  out(`Encryption:             ${encrypted ? `${env.cipher} (encrypted)` : "none (plain)"}`);
  out(`Content-index entries:  ${m.content_index?.files?.length ?? 0}`);
  out(`Chain length:           ${encrypted ? "(encrypted — run verify --decryption-key to inspect)" : chainLen}`);

  if (m.participants?.length) {
    out("");
    out("Participants:");
    for (const p of m.participants) {
      out(`  - ${p.actor_id.padEnd(28)} role=${p.role}` + (p.label ? `  ${p.label}` : ""));
    }
  }

  if (env.signers?.length) {
    out("");
    out("Signers:");
    for (const s of env.signers) {
      out(`  - ${(s.role + ":").padEnd(13)} ${truncHex(s.public_key)}`);
    }
  }

  if (Object.keys(actionHistogram).length) {
    out("");
    out("Action histogram:");
    const rows = Object.entries(actionHistogram).sort((a, b) => b[1] - a[1]);
    const w = Math.max(...rows.map(([k]) => k.length));
    for (const [k, n] of rows) out(`  ${k.padEnd(w)}  ${n}`);
  }

  if (payloadFiles.length) {
    out("");
    out(`Payload (${payloadFiles.length} file${payloadFiles.length === 1 ? "" : "s"}, ${bytesText(payloadTotalBytes)}):`);
    payloadFiles.sort((a, b) => (a.path < b.path ? -1 : 1));
    for (const f of payloadFiles) out(`  ${f.path.padEnd(48)} ${bytesText(f.size)}`);
  }

  return 0;
}

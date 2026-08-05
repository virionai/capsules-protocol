// `capsule inspect <file> [--json]`
//
// One-screen overview: format version, identity, sealed time, file count,
// chain length, action histogram, payload tree size, signer summary. No
// verification — use `capsule verify` for that.

import { CapsuleReader, eraDefinesLineage } from "@capsule/sdk-v0.7-prototype";
import { parseArgs } from "../args.mjs";
import { bytesText, out, readBytes, truncHex } from "../format.mjs";

const USAGE = "usage: capsule inspect <file> [--json]\n";

export async function inspectCmd(argv) {
  const args = parseArgs(argv, { booleans: ["json"], maxPositionals: 1 });
  if (args.help) {
    process.stderr.write(USAGE);
    return 0;
  }
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
      // The lineage declaration verbatim (spec/lineage.md). inspect
      // verifies nothing, so this is the claim as sealed — `capsule
      // verify --predecessor` is what checks it against bytes.
      predecessors: m.predecessors ?? null,
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
  out(`Sealed at (attested):   ${env.signed_at}`);
  out(`Encryption:             ${encrypted ? `${env.cipher} (encrypted)` : "none (plain)"}`);
  out(`Content-index entries:  ${m.content_index?.files?.length ?? 0}`);
  out(`Chain length:           ${encrypted ? "(encrypted — this CLI cannot decrypt; use the SDK reader.decrypt() or the Rust capsule-verify-cli)" : chainLen}`);

  if (m.participants?.length) {
    out("");
    out("Participants:");
    for (const p of m.participants) {
      out(`  - ${p.actor_id.padEnd(28)} role=${p.role}` + (p.label ? `  ${p.label}` : ""));
    }
  }

  // Declared lineage is printed whenever the member is present — a
  // custody claim must never quietly disappear from a report
  // (spec/lineage.md). inspect checks nothing, so every entry is
  // labelled exactly that.
  if (m.predecessors !== undefined) {
    out("");
    if (!eraDefinesLineage(m.format.version)) {
      // A claim member in a pre-lineage era: an unknown member there,
      // never shape-checked. Saying otherwise would promise a check
      // `capsule verify` deliberately does not run (spec/versioning.md).
      out("Predecessors (uninterpreted):");
      out(`  ${JSON.stringify(m.predecessors)}`);
      out(`  (era ${m.format.version} defines no lineage semantics — this is an unknown`);
      out("   member there: preserved and hashed, never shape-checked)");
    } else if (Array.isArray(m.predecessors)) {
      out(`Predecessors (declared lineage, ${m.predecessors.length} entr${m.predecessors.length === 1 ? "y" : "ies"}):`);
      for (const p of m.predecessors) {
        out(`  - capsule ${p?.capsule_id ?? "(missing capsule_id)"}  era ${p?.format_version ?? "(missing format_version)"}`);
        out(`      originator:        ${p?.originator_public_key ?? "(missing)"}`);
        out(`      first_event_hash:  ${p?.first_event_hash ?? "null"}`);
        out(`      entry_hash:        ${p?.entry_hash ?? "null"}`);
        out(`      manifest_hash:     ${p?.manifest_hash ?? "(missing)"}`);
        out("      declared, not verified — supply the predecessor bytes to");
        out("        `capsule verify <file> --predecessor <predecessor.capsule>`");
      }
    } else {
      out("Predecessors (declared lineage):");
      out(`  ${JSON.stringify(m.predecessors)}`);
      out("  (not an array — `capsule verify` fails this declaration closed)");
    }
    if (eraDefinesLineage(m.format.version)) {
      out("  Note: lineage is the successor's declaration; the predecessor's");
      out("        originator has not countersigned it.");
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

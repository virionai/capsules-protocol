// `capsule chain <file> [--limit N] [--json]`
//
// Walks the chain. Default output is one row per event, compact and
// readable. --json emits the full event objects. Encrypted capsules
// without a decryption key reach an early-out — direct the user at
// `capsule verify --decryption-key=...`.

import { CapsuleReader } from "@capsule/sdk-v0.6-prototype";
import { parseArgs } from "../args.mjs";
import { CLIError, out, readBytes, truncHex } from "../format.mjs";

const USAGE = "usage: capsule chain <file> [--limit N] [--json]\n";

export async function chainCmd(argv) {
  const args = parseArgs(argv, { booleans: ["json"], strings: ["limit"] });
  const file = args._[0];
  if (!file) { process.stderr.write(USAGE); return 2; }

  const bytes = await readBytes(file);
  const reader = await CapsuleReader.fromBytes(bytes);
  if (reader.isEncrypted()) {
    throw new CLIError(
      "capsule is encrypted; chain unavailable without a decryption key. Use `capsule verify <file> --json` after decrypting, or extract first.",
      2,
    );
  }
  const events = reader.events();
  let limit = events.length;
  if (args.limit !== undefined) {
    const n = parseInt(args.limit, 10);
    if (!Number.isFinite(n) || n < 0) {
      throw new CLIError(`--limit must be a non-negative integer, got ${args.limit}`, 2);
    }
    limit = n;
  }
  const slice = events.slice(0, limit);

  if (args.json) {
    out(JSON.stringify(slice, null, 2));
    return 0;
  }

  if (slice.length === 0) {
    out("(no events)");
    return 0;
  }

  // Header
  out(`#  date        actor                    kind/action                       payload-summary`);
  out(`-- ----------  -----------------------  --------------------------------  -----------------------`);
  for (const ev of slice) {
    const date = (ev.timestamp || "").slice(0, 10);
    const actor = (ev.actor || "").padEnd(23).slice(0, 23);
    const ka = `${ev.kind}/${ev.action}`.padEnd(32).slice(0, 32);
    const summary = summarizePayload(ev);
    const seq = String(ev.seq).padStart(2);
    out(`${seq}  ${date}  ${actor}  ${ka}  ${summary}`);
    const untrusted = ev.untrusted_payload_fields ?? [];
    if (untrusted.length) {
      out(`    untrusted: ${untrusted.join(", ")}`);
    }
    if (ev.payload?.media_path) {
      out(`    media:     ${ev.payload.media_path} (${ev.payload.mime_type ?? "?"})`);
    }
  }

  if (events.length > slice.length) {
    out(`… ${events.length - slice.length} more event(s) — pass --limit ${events.length} to see all`);
  }
  out("");
  out(`first_event_hash: ${truncHex(events[0].hash, 16)}`);
  out(`entry_hash:       ${truncHex(events[events.length - 1].hash, 16)}`);
  return 0;
}

function summarizePayload(ev) {
  const p = ev.payload || {};
  switch (ev.action) {
    case "logged_symptom":
      return `severity=${p.severity ?? "?"}` +
             (p.body_site ? ` site="${p.body_site}"` : "");
    case "logged_food":
      return `"${truncString(p.description, 40)}"`;
    case "logged_environment":
      return `${p.exposure_kind ?? "?"} ${truncString(p.description, 30)}`;
    case "logged_medicine":
      return `${p.name ?? "?"} ${p.dose ?? ""}` + (p.route ? ` (${p.route})` : "");
    case "logged_supplement":
      return `${p.name ?? "?"} ${p.dose ?? ""}`;
    case "logged_nutrient":
      return `${p.direction ?? ""} ${p.nutrient ?? ""}`.trim();
    case "logged_photo":
      return `${p.subject_kind ?? "?"} ${p.photo_ref ?? ""}`;
    case "logged_audio":
      return `audio ${p.audio_ref ?? ""} ${p.duration_seconds ?? "?"}s`;
    case "logged_video":
      return `video ${p.video_ref ?? ""} ${p.duration_seconds ?? "?"}s`;
    case "started_treatment":
      return `${p.name ?? ""} ${p.dose ?? ""}`;
    case "asked_question":
      return `Q: ${truncString(p.question, 40)}`;
    case "session_ended":
      return `(host backstop)`;
    default:
      return JSON.stringify(p).slice(0, 60);
  }
}

function truncString(s, n) {
  if (typeof s !== "string") return "";
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

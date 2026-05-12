// Event chain: hashing with raw bytes, no hex strings as inputs.

import { bytesToHex, concatBytes, hexToBytes, jcs, sha256 } from "./canonical.js";

const GENESIS_PREV = Buffer.alloc(32, 0);

/**
 * Compute event hash. event must NOT include "hash"; "prev_hash" must be hex.
 * Returns 32-byte Buffer.
 */
export function hashEvent(event) {
  if (event.hash !== undefined) throw new Error("hashEvent: event must not include 'hash'");
  if (typeof event.prev_hash !== "string" || event.prev_hash.length !== 64) {
    throw new Error("hashEvent: prev_hash must be 64-hex");
  }
  const prevRaw = hexToBytes(event.prev_hash);
  const canon = jcs(event);
  return sha256(concatBytes(prevRaw, canon));
}

/**
 * Walk a list of (mostly) bare events and assign prev_hash + hash + seq + event_id.
 * Events should already have actor/kind/action/target/timestamp/payload set.
 */
export function buildChainEvents(bareEvents) {
  let prev = GENESIS_PREV;
  const out = [];
  bareEvents.forEach((bare, i) => {
    const seq = i + 1;
    const event_id = bare.event_id ?? `evt_${String(seq).padStart(3, "0")}`;
    const e = {
      seq,
      event_id,
      ...bare,
      prev_hash: bytesToHex(prev),
    };
    if (e.payload === undefined) e.payload = {};
    if (!Array.isArray(e.untrusted_payload_fields)) {
      // default: mark common LLM-narrative fields untrusted if present
      const candidates = [];
      if (typeof e.payload?.summary === "string") candidates.push("payload.summary");
      if (typeof e.payload?.statement === "string") candidates.push("payload.statement");
      e.untrusted_payload_fields = candidates;
    }
    const h = hashEvent(e);
    e.hash = bytesToHex(h);
    out.push(e);
    prev = h;
  });
  return out;
}

/** Serialize built events into JSONL bytes. */
export function eventsToJsonl(events) {
  const lines = events.map((e) => JSON.stringify(e));
  return Buffer.from(lines.join("\n") + "\n", "utf8");
}

/** Parse JSONL bytes into events. */
export function eventsFromJsonl(bytes) {
  const text = Buffer.from(bytes).toString("utf8");
  const lines = text.split("\n").filter((l) => l.length > 0);
  return lines.map((line, i) => {
    try {
      return JSON.parse(line);
    } catch (err) {
      throw new Error(`chain line ${i + 1}: invalid JSON: ${err.message}`);
    }
  });
}

/** Verify a chain. Returns { ok, errors: [{ seq, message }] }. */
export function verifyChain(events) {
  const errors = [];
  let prev = GENESIS_PREV;
  events.forEach((e, i) => {
    const seq = e.seq ?? i + 1;
    if (e.seq !== i + 1) {
      errors.push({ seq, message: `seq ${e.seq} expected ${i + 1}` });
    }
    if (typeof e.prev_hash !== "string" || e.prev_hash.length !== 64) {
      errors.push({ seq, message: "prev_hash missing or wrong length" });
      return;
    }
    const expectedPrev = bytesToHex(prev);
    if (e.prev_hash !== expectedPrev) {
      errors.push({
        seq,
        message: `prev_hash mismatch: got ${e.prev_hash}, expected ${expectedPrev}`,
      });
    }
    if (typeof e.hash !== "string" || e.hash.length !== 64) {
      errors.push({ seq, message: "hash missing or wrong length" });
      return;
    }
    const { hash, ...rest } = e;
    let recomputedHex;
    try {
      const recomputed = hashEvent(rest);
      recomputedHex = bytesToHex(recomputed);
    } catch (err) {
      errors.push({ seq, message: `recompute failed: ${err.message}` });
      return;
    }
    if (recomputedHex !== hash) {
      errors.push({
        seq,
        message: `hash mismatch: stored ${hash}, recomputed ${recomputedHex}`,
      });
    }
    prev = hexToBytes(hash);
  });
  return { ok: errors.length === 0, errors };
}

export function firstAndEntryHash(events) {
  if (events.length === 0) throw new Error("chain is empty");
  return {
    firstEventHash: events[0].hash,
    entryHash: events[events.length - 1].hash,
  };
}

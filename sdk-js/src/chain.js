// Event chain: hashing with raw bytes, no hex strings as inputs.

import { bytesToHex, concatBytes, hexToBytes, jcs, sha256 } from "./canonical.js";

const GENESIS_PREV = Buffer.alloc(32, 0);

/**
 * The closed `kind` enum from spec/chain.md "Field rules": readers reject
 * unknown kinds, and builders refuse to append them. This is not a tier
 * question — a capsule with a custom event kind is not making a weaker
 * claim, it is unreadable to the foreign LLM reader the format serves.
 */
export const EVENT_KINDS = Object.freeze([
  "decision",
  "observation",
  "mutation",
  "session",
  "checkpoint",
]);

const EVENT_KIND_SET = new Set(EVENT_KINDS);

/**
 * The one actor a chain event may always name without a matching manifest
 * participant — backstop events emitted by the host runtime.
 */
export const HOST_ACTOR = "system:host";

/** True when `kind` is one of the five values spec/chain.md allows. */
export function isValidEventKind(kind) {
  return EVENT_KIND_SET.has(kind);
}

/**
 * Normalize a manifest `participants[]` array into a Set of actor ids.
 * Accepts participant objects ({ actor_id }) or bare actor-id strings;
 * anything else is ignored.
 */
export function participantActorIds(participants) {
  const out = new Set();
  if (!Array.isArray(participants)) return out;
  for (const p of participants) {
    if (typeof p === "string") out.add(p);
    else if (p && typeof p.actor_id === "string") out.add(p.actor_id);
  }
  return out;
}

// Chain-bound hex is lowercase per spec/chain.md. verifyChain feeds a
// stored hash straight into hexToBytes to seed the next link, so the
// canonical-form check has to happen before that call, not inside it.
const HEX64 = /^[0-9a-f]{64}$/;

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

/**
 * Verify a chain. Returns { ok, errors: [{ seq, message }] }.
 *
 * `options.participants` is the manifest's `participants[]` (objects with
 * `actor_id`, or bare actor-id strings). The spec/chain.md step-6 actor
 * rule is CONDITIONAL on that claim: when the set is non-empty, every
 * event actor must be a member or the literal "system:host" (fail-closed);
 * when it is empty or absent, the manifest binds no actor set and the walk
 * accepts any actor — the CALLER (verifyCapsule) reports the reduced
 * assurance. The `kind` enum is enforced unconditionally.
 */
export function verifyChain(events, options = {}) {
  const errors = [];
  const participantIds = participantActorIds(options.participants);
  let prev = GENESIS_PREV;
  events.forEach((e, i) => {
    if (e == null || typeof e !== "object" || Array.isArray(e)) {
      errors.push({ seq: i + 1, message: "event is not a JSON object" });
      return;
    }
    const seq = e.seq ?? i + 1;
    // spec/chain.md step 6 — when the manifest declares participants, the
    // actor must be one of them or the host. An empty set is no claim.
    if (participantIds.size > 0 && e.actor !== HOST_ACTOR && !participantIds.has(e.actor)) {
      errors.push({
        seq,
        message: `actor ${JSON.stringify(e.actor ?? null)} not in manifest.participants and not system:host`,
      });
    }
    // spec/chain.md "Field rules" — `kind` is a closed enum.
    if (!EVENT_KIND_SET.has(e.kind)) {
      errors.push({
        seq,
        message: `kind ${JSON.stringify(e.kind ?? null)} is not one of ${EVENT_KINDS.join(", ")}`,
      });
    }
    if (e.seq !== i + 1) {
      errors.push({ seq, message: `seq ${e.seq} expected ${i + 1}` });
    }
    if (typeof e.prev_hash !== "string" || e.prev_hash.length !== 64) {
      errors.push({ seq, message: "prev_hash missing or wrong length" });
      return;
    }
    if (!HEX64.test(e.prev_hash)) {
      errors.push({ seq, message: "prev_hash is not canonical lowercase hex" });
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
    if (!HEX64.test(e.hash)) {
      errors.push({ seq, message: "hash is not canonical lowercase hex" });
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
  const hashOf = (e) => (e != null && typeof e === "object" ? e.hash : undefined);
  return {
    firstEventHash: hashOf(events[0]),
    entryHash: hashOf(events[events.length - 1]),
  };
}

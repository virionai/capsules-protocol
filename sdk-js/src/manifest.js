// manifest.json construction, hashing, capsule_id derivation.

import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  jcs,
  sha256,
  sha256Hex,
} from "./canonical.js";

const ID_DOMAIN = Buffer.from("capsule-id-v0.6\x00", "utf8");

/**
 * Compute capsule_id from originator pubkey + first event hash.
 * All inputs are raw bytes; no hex strings.
 *
 * A zero-event capsule (spec/chain.md "Empty chains") has no first event:
 * its manifest carries `first_event_hash: null`, and the derivation uses
 * 32 zero bytes — the genesis prev-hash value — in place of
 * `first_event_hash_raw` (spec/manifest.md "id").
 */
export function computeCapsuleId(originatorPubKeyRaw, firstEventHashHex) {
  if (originatorPubKeyRaw.length !== 32) throw new Error("originator pubkey must be 32 bytes");
  let fehRaw;
  if (firstEventHashHex == null) {
    fehRaw = new Uint8Array(32); // genesis stand-in for an empty chain
  } else if (typeof firstEventHashHex === "string" && firstEventHashHex.length === 64) {
    fehRaw = hexToBytes(firstEventHashHex);
  } else {
    throw new Error("first_event_hash must be 64-hex or null (empty chain)");
  }
  const out = sha256(concatBytes(ID_DOMAIN, originatorPubKeyRaw, fehRaw));
  return bytesToHex(out);
}

/**
 * Files excluded from the content index by structural necessity, for every
 * capsule regardless of profile:
 *   - manifest.json: the index lives inside it (would be circular)
 *   - provenance/envelope.json: it commits to the index hash (would be circular)
 */
export const STRUCTURAL_EXCLUDED = new Set([
  "manifest.json",
  "provenance/envelope.json",
]);

/**
 * `content.enc` is excluded from the content index ONLY for encrypted
 * capsules, where it is bound separately by envelope.encrypted_blob_hash.
 * In a plain capsule there is no content.enc; if one is present it MUST be
 * indexed (and will therefore fail verification), so that a signed plain
 * capsule cannot smuggle an unaccounted-for blob past the verifier.
 */
export const CONTENT_INDEX_EXCLUDED = new Set([
  ...STRUCTURAL_EXCLUDED,
  "content.enc",
]);

/** Choose the content-index exclusion set for the capsule's profile. */
export function contentIndexExclusions(encrypted) {
  return encrypted ? CONTENT_INDEX_EXCLUDED : STRUCTURAL_EXCLUDED;
}

export function buildContentIndex(files, excluded = STRUCTURAL_EXCLUDED) {
  const entries = [];
  for (const [path, bytes] of files.entries()) {
    if (excluded.has(path)) continue;
    entries.push({ path, sha256: sha256Hex(bytes) });
  }
  entries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const indexHash = sha256Hex(jcs(entries));
  return { files: entries, index_hash: indexHash };
}

// ---------------------------------------------------------------------------
// Signer-set commitment (manifest.signer_commitment).
//
// The envelope's signing input is JCS(envelope minus signers), so signers[]
// is not an input to any signature — and provenance/envelope.json is
// structurally excluded from the content index. The commitment closes that
// gap: the manifest stores the exact (role, public_key) membership of the
// seal-time signer set, and manifest_hash IS inside every signature, so the
// set is transitively signed by every signer. See spec/manifest.md.
// ---------------------------------------------------------------------------

const SIGNER_KEY_HEX_RE = /^[0-9a-f]{64}$/;

/** Ascending by public_key, then role (byte order — equivalently, by each
 *  member's JCS bytes, since the "public_key" key sorts before "role"). */
export function compareCommitmentMembers(a, b) {
  if (a.public_key !== b.public_key) return a.public_key < b.public_key ? -1 : 1;
  if (a.role !== b.role) return a.role < b.role ? -1 : 1;
  return 0;
}

/**
 * Validate a stored signer_commitment value. Returns a list of problems;
 * empty means well-formed. Rules (spec/manifest.md): non-empty array;
 * each member is an object with exactly `role` (non-empty string) and
 * `public_key` (lowercase 64-hex); members sorted ascending by
 * (public_key, role); (role, public_key) pairs unique.
 */
export function signerCommitmentProblems(commitment) {
  if (!Array.isArray(commitment)) return ["must be a non-empty array of {role, public_key}"];
  if (commitment.length === 0) return ["must not be empty when present"];
  const problems = [];
  for (const [i, m] of commitment.entries()) {
    if (m == null || typeof m !== "object" || Array.isArray(m)) {
      problems.push(`member ${i} is not an object`);
      continue;
    }
    const keys = Object.keys(m).sort();
    if (keys.length !== 2 || keys[0] !== "public_key" || keys[1] !== "role") {
      problems.push(`member ${i} must carry exactly {role, public_key}`);
      continue;
    }
    if (typeof m.role !== "string" || m.role.length === 0) {
      problems.push(`member ${i}: role must be a non-empty string`);
    }
    if (typeof m.public_key !== "string" || !SIGNER_KEY_HEX_RE.test(m.public_key)) {
      problems.push(`member ${i}: public_key must be lowercase 64-hex`);
    }
  }
  if (problems.length > 0) return problems;
  for (let i = 1; i < commitment.length; i++) {
    const cmp = compareCommitmentMembers(commitment[i - 1], commitment[i]);
    if (cmp === 0) {
      problems.push(
        `duplicate member (role=${commitment[i].role}, public_key=${commitment[i].public_key})`,
      );
    } else if (cmp > 0) {
      problems.push("members not sorted ascending by (public_key, role)");
      break;
    }
  }
  return problems;
}

/**
 * Build a well-formed signer_commitment from seal-time members
 * [{role, public_key}]. Sorts ascending by (public_key, role) and throws
 * on duplicate (role, public_key) pairs — the same key under different
 * roles is permitted as distinct members.
 */
export function buildSignerCommitment(members) {
  const out = members
    .map((m) => ({ role: m.role, public_key: m.public_key.toLowerCase() }))
    .sort(compareCommitmentMembers);
  for (let i = 1; i < out.length; i++) {
    if (compareCommitmentMembers(out[i - 1], out[i]) === 0) {
      throw new Error(
        `duplicate signer (role=${out[i].role}, public_key=${out[i].public_key})`,
      );
    }
  }
  return out;
}

/** Build a v0.6 manifest object (without `id` populated). */
export function buildManifest({
  originator,
  participants,
  contentIndex,
  firstEventHash,
  skillTrust,
  encryption,
  createdAt,
  signerCommitment,
}) {
  const manifest = {
    format: {
      version: "0.6",
      container: "zip",
      canonicalization: "JCS-RFC8785",
      hash_algorithm: "SHA-256",
    },
    id: "",
    originator,
    participants,
    first_event_hash: firstEventHash,
    content_index: contentIndex,
    skill_trust: skillTrust ?? {},
    encryption: encryption ?? null,
    created_at: createdAt,
  };
  // Optional: templates and other unsigned tiers legitimately omit it.
  // JCS sorts keys at serialization time, so insertion position is
  // irrelevant to the canonical bytes.
  if (signerCommitment !== undefined) manifest.signer_commitment = signerCommitment;
  return manifest;
}

/** Compute manifest hash over a fully-populated manifest. */
export function manifestHash(manifest) {
  return sha256Hex(jcs(manifest));
}

/** JCS-canonical bytes of a manifest. */
export function manifestBytes(manifest) {
  return jcs(manifest);
}

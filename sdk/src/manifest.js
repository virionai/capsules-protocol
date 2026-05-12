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
 */
export function computeCapsuleId(originatorPubKeyRaw, firstEventHashHex) {
  if (originatorPubKeyRaw.length !== 32) throw new Error("originator pubkey must be 32 bytes");
  if (typeof firstEventHashHex !== "string" || firstEventHashHex.length !== 64) {
    throw new Error("first_event_hash must be 64-hex");
  }
  const fehRaw = hexToBytes(firstEventHashHex);
  const out = sha256(concatBytes(ID_DOMAIN, originatorPubKeyRaw, fehRaw));
  return bytesToHex(out);
}

/**
 * Build the content_index.files array from a Map<path, bytes>.
 *
 * Three files are excluded by definition:
 *   - manifest.json: the index lives inside it (would be circular)
 *   - provenance/envelope.json: it commits to the index hash (would be circular)
 *   - content.enc: bound separately by envelope.encrypted_blob_hash
 */
export const CONTENT_INDEX_EXCLUDED = new Set([
  "manifest.json",
  "provenance/envelope.json",
  "content.enc",
]);

export function buildContentIndex(files) {
  const entries = [];
  for (const [path, bytes] of files.entries()) {
    if (CONTENT_INDEX_EXCLUDED.has(path)) continue;
    entries.push({ path, sha256: sha256Hex(bytes) });
  }
  entries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const indexHash = sha256Hex(jcs(entries));
  return { files: entries, index_hash: indexHash };
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
}) {
  return {
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
}

/** Compute manifest hash over a fully-populated manifest. */
export function manifestHash(manifest) {
  return sha256Hex(jcs(manifest));
}

/** JCS-canonical bytes of a manifest. */
export function manifestBytes(manifest) {
  return jcs(manifest);
}

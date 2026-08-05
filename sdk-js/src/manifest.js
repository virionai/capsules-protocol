// manifest.json construction, hashing, capsule_id derivation.

import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  jcs,
  sha256,
  sha256Hex,
} from "./canonical.js";
import { CURRENT_VERSION, classifyVersion, idDomain } from "./versions.js";

/**
 * Compute capsule_id from originator pubkey + first event hash.
 * All inputs are raw bytes; no hex strings.
 *
 * A zero-event capsule (spec/chain.md "Empty chains") has no first event:
 * its manifest carries `first_event_hash: null`, and the derivation uses
 * 32 zero bytes — the genesis prev-hash value — in place of
 * `first_event_hash_raw` (spec/manifest.md "id").
 *
 * The hash domain embeds the capsule's format version
 * (`capsule-id-v<version>\0`), so derivation is KEYED by the DECLARED
 * version (spec/versioning.md): a verifier checking a v0.6 capsule uses
 * the v0.6 domain forever, whatever version it seals at.
 */
export function computeCapsuleId(originatorPubKeyRaw, firstEventHashHex, version = CURRENT_VERSION) {
  if (originatorPubKeyRaw.length !== 32) throw new Error("originator pubkey must be 32 bytes");
  let fehRaw;
  if (firstEventHashHex == null) {
    fehRaw = new Uint8Array(32); // genesis stand-in for an empty chain
  } else if (typeof firstEventHashHex === "string" && firstEventHashHex.length === 64) {
    fehRaw = hexToBytes(firstEventHashHex);
  } else {
    throw new Error("first_event_hash must be 64-hex or null (empty chain)");
  }
  const out = sha256(concatBytes(idDomain(version), originatorPubKeyRaw, fehRaw));
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
 * indexed like any other file (an attacker cannot force its exclusion
 * without breaking the envelope signature over content_index_hash). Note
 * that indexing alone is NOT what rejects the smuggled blob — a fully
 * re-derived index can cover it and the index checks pass — the verifier's
 * blob-shape invariant does: a content.enc that the SIGNED envelope does
 * not account for (cipher='none' or encrypted_blob_hash=null) fails
 * verification whether or not it is indexed. Pinned by the
 * smuggled-blob-indexed vector in spec/vectors/semantic-binding.
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

// ---------------------------------------------------------------------------
// Lineage declaration (manifest.predecessors) — spec/lineage.md.
//
// A successor capsule declares the exact sealed artifact(s) it continues
// from. Presence binds, absence reports: an absent member is "no claim";
// a PRESENT member no reader can interpret is the capsule asserting
// something meaningless about its own origin, rejected fail-closed with
// the SAME `predecessors[i].<member>` diagnoses in every lane.
// ---------------------------------------------------------------------------

const HEX64_LOWER = /^[0-9a-f]{64}$/;

/** The six spec-defined members of one predecessor entry, all REQUIRED. */
export const PREDECESSOR_ENTRY_MEMBERS = Object.freeze([
  "capsule_id",
  "format_version",
  "originator_public_key",
  "first_event_hash",
  "entry_hash",
  "manifest_hash",
]);

/**
 * v0.7.1 default-profile scope (spec/lineage.md "Scope"): lineage
 * declarations commit to DEFAULT-PROFILE predecessors. The era default
 * profile id is `v0.6-suite` (version 1.0), frozen forever. A manifest
 * that declares `format.profile` with any other id is an
 * alternate-profile capsule; this helper returns the declared id for
 * such a manifest, and null for the default (declared explicitly or by
 * absence). A present-but-uninterpretable declaration returns a
 * placeholder string — the caller treats it as non-default; the profile
 * machinery (spec/profiles.md, parallel track) owns its full diagnosis.
 */
export const DEFAULT_PROFILE_ID = "v0.6-suite";

export function declaredAlternateProfileId(manifest) {
  const profile = manifest?.format?.profile;
  if (profile === undefined || profile === null) return null;
  const id =
    typeof profile === "object" && !Array.isArray(profile) ? profile.id : undefined;
  if (id === DEFAULT_PROFILE_ID) return null;
  return typeof id === "string" && id.length > 0 ? id : "(uninterpretable profile declaration)";
}

/**
 * Validate a stored `predecessors` value (spec/lineage.md, standalone
 * checks 1–3). Returns a list of problem strings; empty means
 * well-formed. Every problem names its member as
 * `predecessors[i].<member>` — the shared cross-lane diagnosis strings.
 *
 * Checks:
 *   1. Shape and grammar — array of entry objects; six members present
 *      with required types; lowercase hex REQUIRED, not normalized (the
 *      claim is bound by its stored bytes); a present-but-EMPTY array is
 *      malformed ("no claim" has exactly one spelling: absence); two
 *      entries sharing a manifest_hash are malformed (the same artifact
 *      cited twice — the duplicate-signer precedent). Two entries
 *      sharing capsule_id with different manifest_hash values are LEGAL
 *      (a merge of two snapshots of one line). Vendor extensions inside
 *      an entry use the x- prefix; any other unrecognized member is
 *      malformed (the signer_commitment exact-members precedent).
 *   2. Null coherence — first_event_hash and entry_hash both null
 *      (zero-event predecessor) or both 64-hex; a mixed declaration
 *      describes a predecessor that cannot exist.
 *   3. Identity coherence — when the declared format_version is in THIS
 *      verifier's known table, the declared capsule_id must equal the
 *      recompute under THAT era's identity rule (32 zero bytes for a
 *      null first_event_hash). An unknown declared era SKIPS the check
 *      (versioning.md forbids applying one era's formula to another
 *      era's claim) — callers report identity_checked=false, never a
 *      failure: the rule must not punish a capsule for the verifier's
 *      age.
 */
export function predecessorsProblems(predecessors) {
  if (!Array.isArray(predecessors)) {
    return ["predecessors must be an array of predecessor entry objects"];
  }
  if (predecessors.length === 0) {
    return [
      "predecessors must not be empty when present (\"no claim\" has exactly one spelling: absence)",
    ];
  }
  const problems = [];
  predecessors.forEach((entry, i) => {
    if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
      problems.push(`predecessors[${i}] must be an entry object`);
      return;
    }
    for (const key of Object.keys(entry)) {
      if (!PREDECESSOR_ENTRY_MEMBERS.includes(key) && !key.startsWith("x-")) {
        problems.push(
          `predecessors[${i}].${key} is not a spec-defined entry member ` +
            `(vendor extensions must use the x- prefix)`,
        );
      }
    }
    for (const key of ["capsule_id", "originator_public_key", "manifest_hash"]) {
      if (typeof entry[key] !== "string" || !HEX64_LOWER.test(entry[key])) {
        problems.push(`predecessors[${i}].${key} must be lowercase 64-hex`);
      }
    }
    for (const key of ["first_event_hash", "entry_hash"]) {
      const value = entry[key];
      if (value === undefined) {
        problems.push(`predecessors[${i}].${key} must be lowercase 64-hex or null`);
      } else if (value !== null && (typeof value !== "string" || !HEX64_LOWER.test(value))) {
        problems.push(`predecessors[${i}].${key} must be lowercase 64-hex or null`);
      }
    }
    const versionClass = classifyVersion(entry.format_version);
    if (versionClass.status === "invalid") {
      problems.push(
        `predecessors[${i}].format_version must be a '<major>.<minor>' version string, ` +
          `got ${JSON.stringify(entry.format_version ?? null)}`,
      );
    }
    // Null coherence (check 2) — only meaningful once both members typed.
    const feh = entry.first_event_hash;
    const eh = entry.entry_hash;
    const fehOk = feh === null || (typeof feh === "string" && HEX64_LOWER.test(feh));
    const ehOk = eh === null || (typeof eh === "string" && HEX64_LOWER.test(eh));
    if (fehOk && ehOk && (feh === null) !== (eh === null)) {
      problems.push(
        `predecessors[${i}].first_event_hash and predecessors[${i}].entry_hash must be ` +
          `both null (zero-event predecessor) or both 64-hex — a mixed declaration ` +
          `describes a predecessor that cannot exist`,
      );
    }
    // Identity coherence (check 3) — known declared eras only.
    if (
      versionClass.status === "known" &&
      typeof entry.capsule_id === "string" && HEX64_LOWER.test(entry.capsule_id) &&
      typeof entry.originator_public_key === "string" &&
      HEX64_LOWER.test(entry.originator_public_key) &&
      fehOk && ehOk && (feh === null) === (eh === null)
    ) {
      const derived = computeCapsuleId(
        hexToBytes(entry.originator_public_key),
        feh,
        entry.format_version,
      );
      if (derived !== entry.capsule_id) {
        problems.push(
          `predecessors[${i}].capsule_id does not derive from the declared originator ` +
            `key and first event hash under era ${entry.format_version} — the ` +
            `declaration contradicts its own members`,
        );
      }
    }
  });
  // Duplicate manifest_hash across entries (same artifact cited twice).
  const seen = new Map();
  predecessors.forEach((entry, i) => {
    const mh = entry?.manifest_hash;
    if (typeof mh !== "string" || !HEX64_LOWER.test(mh)) return;
    if (seen.has(mh)) {
      problems.push(
        `predecessors[${i}].manifest_hash duplicates predecessors[${seen.get(mh)}].manifest_hash ` +
          `(the same sealed artifact cited twice)`,
      );
    } else {
      seen.set(mh, i);
    }
  });
  return problems;
}

/**
 * True when the declared era's identity rule is available to this
 * implementation, i.e. check 3 above actually ran for the entry.
 */
export function predecessorIdentityCheckable(entry) {
  return classifyVersion(entry?.format_version).status === "known";
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

/**
 * Build a current-version manifest object (without `id` populated).
 *
 * Deliberately absent: any `skill_trust` member. Skill trust is
 * host-relative and DERIVED at verify time (spec/trust.md); a capsule
 * from an earlier draft that carries the member is treated as having an
 * inert unknown member — preserved and hashed, never read as authority.
 */
export function buildManifest({
  originator,
  participants,
  contentIndex,
  firstEventHash,
  encryption,
  createdAt,
  signerCommitment,
  predecessors,
}) {
  const manifest = {
    format: {
      version: CURRENT_VERSION,
      container: "zip",
      canonicalization: "JCS-RFC8785",
      hash_algorithm: "SHA-256",
    },
    id: "",
    originator,
    participants,
    first_event_hash: firstEventHash,
    content_index: contentIndex,
    encryption: encryption ?? null,
    created_at: createdAt,
  };
  // Optional: templates and other unsigned tiers legitimately omit it.
  // JCS sorts keys at serialization time, so insertion position is
  // irrelevant to the canonical bytes.
  if (signerCommitment !== undefined) manifest.signer_commitment = signerCommitment;
  // Optional lineage declaration (spec/lineage.md): absence is "no
  // claim"; a present value must already satisfy predecessorsProblems.
  if (predecessors !== undefined) manifest.predecessors = predecessors;
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

// verifyCapsule: L2 (encrypted-aware) and L3 (decrypted-content) verification.
//
// The verifier reports per-signer outcomes. It does NOT decide trust on
// its own — the caller passes an allowlist of public keys. trusted=true
// only when a signer's key is on the allowlist AND its signature
// verifies.

import { sha256Hex, jcs } from "./canonical.js";
import { verifyChain, firstAndEntryHash } from "./chain.js";
import {
  buildContentIndex,
  contentIndexExclusions,
  manifestBytes,
  manifestHash,
  computeCapsuleId,
} from "./manifest.js";
import { hexToBytes } from "./crypto.js";
import { verifyEnvelopeSignatures } from "./envelope.js";

/**
 * verifyCapsule(reader, options)
 *
 * options:
 *   allowlist:     Array<hex pubkey> — signers must appear here for trusted=true
 *   outerEnvelope: optional envelope — for L3 verification, pass the outer
 *                  envelope so the inner can be checked against it.
 *
 * returns:
 *   {
 *     ok: bool,
 *     level: "L2" | "L3",
 *     errors: [string],
 *     chain: { ok, errors },
 *     contentIndex: { ok, errors },
 *     envelope: { ok, signers: [{role, public_key, valid, trusted}] },
 *     trustedSignerCount: number,
 *     notes: [string]
 *   }
 */
export async function verifyCapsule(reader, options = {}) {
  const allowlist = new Set((options.allowlist ?? []).map((k) => k.toLowerCase()));
  const errors = [];
  const notes = [];
  const result = {
    ok: false,
    level: options.outerEnvelope ? "L3" : "L2",
    errors,
    chain: { ok: false, errors: [] },
    contentIndex: { ok: false, errors: [] },
    envelope: { ok: false, signers: [] },
    trustedSignerCount: 0,
    notes,
  };

  const manifest = reader.manifest();
  const envelope = reader.envelope();

  // Format / version checks
  if (manifest.format?.version !== "0.6") {
    errors.push(`unsupported manifest format.version: ${manifest.format?.version}`);
  }
  if (envelope.version !== "0.6") {
    errors.push(`unsupported envelope version: ${envelope.version}`);
  }

  // Capsule identity
  try {
    const expectedId = computeCapsuleId(
      hexToBytes(manifest.originator.public_key),
      manifest.first_event_hash,
    );
    if (expectedId !== manifest.id) {
      errors.push(`manifest.id mismatch: stored ${manifest.id}, expected ${expectedId}`);
    }
    if (expectedId !== envelope.capsule_id) {
      errors.push(`envelope.capsule_id mismatch: ${envelope.capsule_id} vs derived ${expectedId}`);
    }
  } catch (err) {
    errors.push(`capsule_id derivation failed: ${err.message}`);
  }

  // Manifest hash
  const expectedManifestHash = manifestHash(manifest);
  if (expectedManifestHash !== envelope.manifest_hash) {
    errors.push(
      `envelope.manifest_hash mismatch: ${envelope.manifest_hash} vs recomputed ${expectedManifestHash}`,
    );
  }

  // Content index. content.enc is excluded only when the capsule declares a
  // cipher (bound instead by envelope.encrypted_blob_hash). We key off the
  // signed envelope.cipher, not file presence: an attacker who injects a
  // content.enc into a plain (cipher="none") capsule cannot force its
  // exclusion without breaking the envelope signature, so the stray blob is
  // indexed here and fails verification.
  const excluded = contentIndexExclusions(envelope.cipher !== "none");
  const files = reader.files_();
  const indexFiles = new Map();
  for (const [path, bytes] of files.entries()) {
    if (excluded.has(path)) continue;
    indexFiles.set(path, bytes);
  }
  const recomputedIndex = buildContentIndex(indexFiles, excluded);
  result.contentIndex.ok = true;
  if (recomputedIndex.index_hash !== manifest.content_index.index_hash) {
    result.contentIndex.ok = false;
    result.contentIndex.errors.push("manifest.content_index.index_hash does not match recomputed");
  }
  // Per-file verification too
  const stored = new Map(manifest.content_index.files.map((f) => [f.path, f.sha256]));
  for (const f of recomputedIndex.files) {
    const expected = stored.get(f.path);
    if (!expected) {
      result.contentIndex.errors.push(`file present but not in manifest index: ${f.path}`);
    } else if (expected !== f.sha256) {
      result.contentIndex.errors.push(`file hash mismatch: ${f.path}`);
    }
  }
  for (const f of manifest.content_index.files) {
    if (!recomputedIndex.files.find((g) => g.path === f.path)) {
      result.contentIndex.errors.push(`file in manifest index but missing from package: ${f.path}`);
    }
  }
  if (recomputedIndex.index_hash !== envelope.content_index_hash) {
    result.contentIndex.ok = false;
    result.contentIndex.errors.push(
      `envelope.content_index_hash mismatch: ${envelope.content_index_hash} vs recomputed ${recomputedIndex.index_hash}`,
    );
  }
  if (result.contentIndex.errors.length > 0) result.contentIndex.ok = false;

  // Encrypted blob hash
  if (reader.isEncrypted()) {
    const blob = reader.encryptedBlobBytes();
    const recomputed = sha256Hex(blob);
    if (recomputed !== envelope.encrypted_blob_hash) {
      errors.push(
        `envelope.encrypted_blob_hash mismatch: ${envelope.encrypted_blob_hash} vs recomputed ${recomputed}`,
      );
    }
    if (envelope.cipher === "none") {
      errors.push("encrypted blob present but envelope.cipher is 'none'");
    }
  } else {
    if (envelope.encrypted_blob_hash !== null) {
      errors.push("plain capsule must have envelope.encrypted_blob_hash=null");
    }
    if (envelope.cipher !== "none") {
      errors.push(`plain capsule must have cipher='none', got '${envelope.cipher}'`);
    }
  }

  // Chain
  if (!reader.isEncrypted()) {
    const events = reader.events();
    const chainResult = verifyChain(events);
    result.chain = chainResult;
    if (events.length > 0) {
      const { firstEventHash, entryHash } = firstAndEntryHash(events);
      if (firstEventHash !== envelope.first_event_hash) {
        errors.push(
          `envelope.first_event_hash mismatch: ${envelope.first_event_hash} vs ${firstEventHash}`,
        );
      }
      if (entryHash !== envelope.entry_hash) {
        errors.push(`envelope.entry_hash mismatch: ${envelope.entry_hash} vs ${entryHash}`);
      }
    }
  } else {
    // Encrypted outer cannot verify chain without decrypt; defer to L3.
    result.chain = { ok: true, errors: [], note: "deferred to L3 (encrypted outer)" };
  }

  // Envelope signatures
  const envelopeResult = verifyEnvelopeSignatures(envelope);
  result.envelope.ok = envelopeResult.ok;
  if (!envelopeResult.ok && envelopeResult.note) errors.push(envelopeResult.note);
  result.envelope.signers = envelopeResult.signers.map((s) => ({
    ...s,
    trusted: s.valid && allowlist.has(s.public_key.toLowerCase()),
  }));
  result.trustedSignerCount = result.envelope.signers.filter((s) => s.trusted).length;

  // L3: cross-check inner against outer envelope
  if (options.outerEnvelope) {
    const outer = options.outerEnvelope;
    if (outer.capsule_id !== envelope.capsule_id) {
      errors.push("L3: inner.capsule_id does not match outer.capsule_id");
    }
    if (outer.first_event_hash !== envelope.first_event_hash) {
      errors.push("L3: inner.first_event_hash does not match outer.first_event_hash");
    }
    if (outer.entry_hash !== envelope.entry_hash) {
      errors.push("L3: inner.entry_hash does not match outer.entry_hash");
    }
  }

  result.ok =
    errors.length === 0 &&
    result.contentIndex.ok &&
    result.chain.ok &&
    result.envelope.ok;

  if (allowlist.size === 0) {
    notes.push("no allowlist provided; trusted=false for all signers regardless of signature validity");
  }

  return result;
}

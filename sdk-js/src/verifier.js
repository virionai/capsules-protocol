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
  compareCommitmentMembers,
  contentIndexExclusions,
  manifestBytes,
  manifestHash,
  computeCapsuleId,
  signerCommitmentProblems,
} from "./manifest.js";
import { hexToBytes } from "./crypto.js";
import { verifyEnvelopeSignatures } from "./envelope.js";
import { CapsuleReader } from "./reader.js";
import { toKeyHex } from "./keys.js";

/**
 * verifyCapsule(readerOrBytes, options)
 *
 * Accepts a CapsuleReader or the raw .capsule bytes. When given bytes,
 * a container that cannot even be opened (malformed ZIP, missing or
 * invalid manifest/envelope) returns a fail-closed result — app code
 * needs no separate try/catch around opening.
 *
 * options:
 *   allowlist:     signer public keys to trust (hex strings or 32-byte
 *                  keys) — signers must appear here for trusted=true
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
 *     signerSet: { bound, ok, errors: [string] },
 *     trustedSignerCount: number,
 *     notes: [string]
 *   }
 *
 * signerSet is the signer-set binding check (manifest.signer_commitment):
 *   bound=true  — the manifest commits to the exact signer set; ok reflects
 *                 whether envelope.signers matches it (fail-closed).
 *   bound=false — the manifest carries no commitment. Verification still
 *                 succeeds (absence is a weaker claim, not a violation),
 *                 but the reported assurance visibly excludes signer-set
 *                 integrity.
 * trustedSignerCount counts DISTINCT trusted public keys, not signer rows.
 */
export async function verifyCapsule(readerOrBytes, options = {}) {
  let reader = readerOrBytes;
  if (reader instanceof Uint8Array || reader instanceof ArrayBuffer) {
    try {
      reader = await CapsuleReader.fromBytes(
        reader instanceof ArrayBuffer ? new Uint8Array(reader) : reader,
      );
    } catch (err) {
      return {
        ok: false,
        level: "L2",
        errors: [`capsule cannot be opened: ${err.message}`],
        chain: { ok: false, errors: [] },
        contentIndex: { ok: false, errors: [] },
        envelope: { ok: false, signers: [] },
        signerSet: { bound: false, ok: false, errors: [] },
        trustedSignerCount: 0,
        notes: [],
      };
    }
  }
  const errors = [];
  const notes = [];
  const allowlist = new Set();
  for (const [i, key] of (options.allowlist ?? []).entries()) {
    try {
      allowlist.add(toKeyHex(key, `allowlist[${i}]`));
    } catch (err) {
      // Trust configuration is external to capsule validity. Reject malformed
      // keys from the trust set without turning verification into an exception.
      notes.push(`ignored invalid allowlist[${i}]: ${err.message}`);
    }
  }
  const result = {
    ok: false,
    level: options.outerEnvelope ? "L3" : "L2",
    errors,
    chain: { ok: false, errors: [] },
    contentIndex: { ok: false, errors: [] },
    envelope: { ok: false, signers: [] },
    signerSet: { bound: false, ok: true, errors: [] },
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
    let events;
    try {
      events = reader.events();
    } catch (err) {
      events = [];
      result.chain = { ok: false, errors: [{ seq: 0, message: err.message }] };
    }
    if (events.length === 0) {
      result.chain ??= {
        ok: false,
        errors: [{ seq: 0, message: "chain/events.jsonl missing or empty" }],
      };
    } else {
      result.chain = verifyChain(events);
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
  // DISTINCT trusted keys, never rows: the same key signing under two roles
  // is one trusted key, and duplicate rows must never inflate a quorum.
  result.trustedSignerCount = new Set(
    result.envelope.signers.filter((s) => s.trusted).map((s) => s.public_key.toLowerCase()),
  ).size;

  // Signer-set binding: PRESENCE BINDS, ABSENCE REPORTS.
  // A present manifest.signer_commitment must equal the normalized
  // envelope signer set exactly (integrity invariant, fail-closed). An
  // absent commitment downgrades the reported assurance — it never fails
  // verification, because a capsule that does not assert signer-set
  // binding is making a weaker claim honestly (templates, other writers).
  const commitment = manifest.signer_commitment;
  if (commitment === undefined) {
    notes.push(
      "manifest.signer_commitment absent: the signer set is not bound by the seal",
    );
  } else {
    result.signerSet.bound = true;
    const scErrors = [];
    const problems = signerCommitmentProblems(commitment);
    if (problems.length > 0) {
      for (const p of problems) scErrors.push(`manifest.signer_commitment malformed: ${p}`);
    } else {
      const actual = (Array.isArray(envelope.signers) ? envelope.signers : [])
        .map((s) => ({
          role: typeof s?.role === "string" ? s.role : "",
          public_key: typeof s?.public_key === "string" ? s.public_key.toLowerCase() : "",
        }))
        .sort(compareCommitmentMembers);
      // Merge-walk both sorted member lists; report every difference by name.
      let i = 0;
      let j = 0;
      while (i < commitment.length || j < actual.length) {
        const cmp =
          i >= commitment.length ? 1 : j >= actual.length ? -1
          : compareCommitmentMembers(commitment[i], actual[j]);
        if (cmp === 0) {
          i++; j++;
        } else if (cmp < 0) {
          const m = commitment[i++];
          scErrors.push(
            `signer_commitment mismatch: no envelope signer matches committed member (role=${m.role}, public_key=${m.public_key})`,
          );
        } else {
          const m = actual[j++];
          scErrors.push(
            `signer_commitment mismatch: envelope signer not committed (role=${m.role}, public_key=${m.public_key})`,
          );
        }
      }
    }
    if (scErrors.length > 0) {
      result.signerSet.ok = false;
      result.signerSet.errors = scErrors;
      errors.push(...scErrors);
    }
  }

  // Originator binding (invariant): the manifest names an originator key —
  // that key must actually have sealed the capsule with a valid envelope
  // signature under role "originator". A manifest naming an originator who
  // never signed is the capsule asserting something false about itself.
  {
    const originatorKey =
      typeof manifest.originator?.public_key === "string"
        ? manifest.originator.public_key.toLowerCase()
        : null;
    const originatorSigned = envelopeResult.signers.some(
      (s) =>
        s.role === "originator" &&
        s.valid &&
        typeof s.public_key === "string" &&
        s.public_key.toLowerCase() === originatorKey,
    );
    if (!originatorSigned) {
      errors.push(
        `originator binding: manifest.originator.public_key ${originatorKey ?? "(missing)"} has no valid envelope signature with role 'originator'`,
      );
    }
  }

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

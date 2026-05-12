// Provenance envelope: build, sign, verify.
//
// Critical v0.6 changes vs prior format:
//   - signed payload is JCS(envelope minus signers), not a derived
//     "signing_hash"
//   - signing input is raw bytes: domain_sep_bytes || canonical_bytes
//   - domain separation per role
//   - signers[] is generalized; no fixed creator/originator slots

import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  jcs,
} from "./canonical.js";
import { ed25519Sign, ed25519Verify } from "./crypto.js";

const ENVELOPE_VERSION = "0.6";
const SUPPORTED_CIPHERS = new Set(["none", "ChaCha20-Poly1305"]);

export function buildEnvelope({
  capsuleId,
  firstEventHash,
  entryHash,
  manifestHash,
  contentIndexHash,
  encryptedBlobHash = null,
  cipher = "none",
  signedAt,
}) {
  if (!SUPPORTED_CIPHERS.has(cipher)) {
    throw new Error(`unsupported cipher: ${cipher}`);
  }
  if (cipher === "none" && encryptedBlobHash !== null) {
    throw new Error("plain capsule must have encrypted_blob_hash=null");
  }
  if (cipher !== "none" && (typeof encryptedBlobHash !== "string" || encryptedBlobHash.length !== 64)) {
    throw new Error("encrypted capsule requires encrypted_blob_hash (64-hex)");
  }
  return {
    version: ENVELOPE_VERSION,
    capsule_id: capsuleId,
    first_event_hash: firstEventHash,
    entry_hash: entryHash,
    manifest_hash: manifestHash,
    content_index_hash: contentIndexHash,
    encrypted_blob_hash: encryptedBlobHash,
    cipher,
    signed_at: signedAt,
    signers: [],
  };
}

/** JCS-canonical bytes of envelope minus the signers field. */
export function envelopeCanonicalPayload(envelope) {
  const { signers, ...rest } = envelope;
  return jcs(rest);
}

/** domain_sep_bytes || canonical_envelope_bytes — the raw signing input. */
export function envelopeSigningInput(envelope, role) {
  if (typeof role !== "string" || role.length === 0) {
    throw new Error("role must be a non-empty string");
  }
  const domain = Buffer.from(`capsule-provenance-v${ENVELOPE_VERSION}:${role}\x00`, "utf8");
  const canonical = envelopeCanonicalPayload(envelope);
  return concatBytes(domain, canonical);
}

/**
 * Sign and append signers in-place.
 * signers: [{ role, publicKey: 32 bytes, privateKey: 32 bytes }]
 */
export function signEnvelope(envelope, signers) {
  if (envelope.signers.length > 0) {
    throw new Error("envelope already has signers");
  }
  for (const s of signers) {
    if (!s.role) throw new Error("signer requires role");
    if (!s.privateKey || s.privateKey.length !== 32) throw new Error("signer requires 32-byte privateKey");
    if (!s.publicKey || s.publicKey.length !== 32) throw new Error("signer requires 32-byte publicKey");
    const input = envelopeSigningInput(envelope, s.role);
    const sig = ed25519Sign(s.privateKey, input);
    envelope.signers.push({
      role: s.role,
      public_key: bytesToHex(s.publicKey),
      signature: bytesToHex(sig),
    });
  }
  return envelope;
}

/**
 * Verify envelope signatures only (no manifest/chain cross-check).
 * Returns { ok, signers: [{ role, public_key, valid }] }.
 */
export function verifyEnvelopeSignatures(envelope) {
  const out = [];
  let allValid = true;
  if (envelope.version !== ENVELOPE_VERSION) {
    return { ok: false, signers: [], note: `unsupported envelope version: ${envelope.version}` };
  }
  if (!SUPPORTED_CIPHERS.has(envelope.cipher)) {
    return { ok: false, signers: [], note: `unsupported cipher: ${envelope.cipher}` };
  }
  if (!Array.isArray(envelope.signers) || envelope.signers.length === 0) {
    return { ok: false, signers: [], note: "envelope has no signers" };
  }
  for (const s of envelope.signers) {
    let valid = false;
    try {
      const input = envelopeSigningInput(envelope, s.role);
      const pub = hexToBytes(s.public_key);
      const sig = hexToBytes(s.signature);
      valid = ed25519Verify(pub, input, sig);
    } catch {
      valid = false;
    }
    if (!valid) allValid = false;
    out.push({ role: s.role, public_key: s.public_key, valid });
  }
  return { ok: allValid, signers: out };
}

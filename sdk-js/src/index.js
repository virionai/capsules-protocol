// Public surface of @capsule/sdk-v0.6-prototype.

export { CapsuleBuilder } from "./builder.js";
export { CapsuleReader } from "./reader.js";
export { verifyCapsule } from "./verifier.js";

export {
  generateEd25519,
  generateX25519,
  ed25519Sign,
  ed25519Verify,
  bytesToHex,
  hexToBytes,
} from "./crypto.js";

export {
  jcs,
  sha256,
  sha256Hex,
} from "./canonical.js";

export {
  buildChainEvents,
  hashEvent,
  verifyChain,
} from "./chain.js";

export {
  buildEnvelope,
  signEnvelope,
  verifyEnvelopeSignatures,
  envelopeCanonicalPayload,
  envelopeSigningInput,
} from "./envelope.js";

export {
  buildContentIndex,
  contentIndexExclusions,
  buildManifest,
  computeCapsuleId,
  manifestHash,
  manifestBytes,
} from "./manifest.js";

// Useful for demos and tooling that needs to read or rewrite the
// underlying ZIP container directly (e.g. tampering tests).
export { packZip, unpackZip, scanCentralDirectory } from "./zip.js";

// Pith — context-style discipline normalizer.
export {
  compressText,
  compressEventPayload,
  PITH_VERSION,
} from "./pith.js";

// Federation — optional, non-normative identity/encryption/policy overlay
// (e.g. Clerk). Never touches core verification; see spec/federation.md.
export * as federation from "./federation/index.js";

export const SPEC_VERSION = "0.6";

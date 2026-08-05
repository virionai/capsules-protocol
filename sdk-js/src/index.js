// Public surface of @capsule/sdk-v0.7-prototype.

export {
  CapsuleBuilder,
  PredecessorError,
  derivePredecessorEntry,
  rewrapCapsule,
} from "./builder.js";
export { CapsuleReader } from "./reader.js";
export { verifyCapsule } from "./verifier.js";

export {
  generateEd25519,
  generateX25519,
  ed25519DerivePublic,
  ed25519Sign,
  ed25519Verify,
  bytesToHex,
  hexToBytes,
} from "./crypto.js";

export {
  assertIJson,
  jcs,
  sha256,
  sha256Hex,
} from "./canonical.js";

export {
  buildChainEvents,
  hashEvent,
  verifyChain,
  isValidEventKind,
  isValidActorId,
  participantActorIds,
  participantActorIdProblems,
  ACTOR_NAMESPACES,
  EVENT_KINDS,
  HOST_ACTOR,
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
  buildSignerCommitment,
  compareCommitmentMembers,
  computeCapsuleId,
  manifestHash,
  manifestBytes,
  signerCommitmentProblems,
  predecessorsProblems,
  PREDECESSOR_ENTRY_MEMBERS,
  DEFAULT_PROFILE_ID,
} from "./manifest.js";

// Lineage verification internals (spec/lineage.md) — exposed for
// tooling and conformance work; app code reads verifyCapsule(...).lineage.
export {
  LINEAGE_HOP_CAP_DEFAULT,
  eraDefinesLineage,
  verificationErrorCount,
} from "./lineage.js";

// Useful for demos and tooling that needs to read or rewrite the
// underlying ZIP container directly (e.g. tampering tests).
export { packZip, unpackZip, scanCentralDirectory, DEFAULT_ZIP_LIMITS } from "./zip.js";

// Pith — context-style discipline normalizer.
export {
  compressText,
  compressEventPayload,
  normalizeEventPayload,
  PITH_VERSION,
} from "./pith.js";

// Federation — optional, non-normative identity/encryption/policy overlay
// (e.g. Clerk). Never touches core verification; see spec/federation.md.
export * as federation from "./federation/index.js";

// The spec version this SDK seals at — always the versions module's
// CURRENT_VERSION, never a separate literal (a second copy is exactly
// how a bump leaves a stale era behind).
export { CURRENT_VERSION as SPEC_VERSION } from "./versions.js";

// Version-compatibility policy (spec/versioning.md): the known-version
// table, the classifier behind the verify result's formatVersion channel,
// and the version-keyed domain-separation selectors.
export {
  KNOWN_VERSIONS,
  CURRENT_VERSION,
  SUITES,
  classifyVersion,
  UnsupportedVersionError,
  idDomain,
  provenanceDomain,
  keyWrapInfo,
} from "./versions.js";

// Profile declaration policy (spec/profiles.md): the supported-profile
// table, the default-profile pin behind the absence rule, the dyad
// classifier behind the verify result's profile channel, and the typed
// open-stage refusals.
export {
  SUPPORTED_PROFILES,
  DEFAULT_PROFILE,
  isValidProfileId,
  classifyProfile,
  profileDeclarationProblems,
  ProfileError,
  UnsupportedProfileError,
  ProfileMismatchError,
  InvalidProfileError,
} from "./profiles.js";

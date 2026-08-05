// Type declarations for @capsule/sdk-v0.7-prototype.
//
// The main integration surface (CapsuleBuilder, CapsuleReader,
// verifyCapsule, key generation) is typed precisely; lower-level
// protocol primitives are typed loosely — they exist for verifiers,
// tooling, and conformance work, not everyday app code.

/** Anywhere a key is accepted: lowercase/uppercase hex string or 32 raw bytes. */
export type KeyInput = string | Uint8Array;

export interface Ed25519KeyPair {
  /** Curve tag: lets the SDK reject an Ed25519 keypair passed where an
   *  X25519 one is required (and vice versa) — the two shapes are
   *  otherwise identical, and the mix-up seals unrecoverable content. */
  curve: "ed25519";
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  publicKeyHex: string;
  privateKeyHex: string;
}

export interface X25519KeyPair {
  /** Curve tag — see Ed25519KeyPair.curve. */
  curve: "x25519";
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  publicKeyHex: string;
  privateKeyHex: string;
}

/** Generate an Ed25519 signing keypair (raw 32-byte keys + hex forms). */
export function generateEd25519(): Ed25519KeyPair;
/** Generate an X25519 encryption keypair (raw 32-byte keys + hex forms). */
export function generateX25519(): X25519KeyPair;

/** Derive the raw 32-byte public key from a raw 32-byte private key. */
export function ed25519DerivePublic(privateKeyRaw: Uint8Array): Uint8Array;
export function ed25519Sign(privateKeyRaw: Uint8Array, message: Uint8Array): Uint8Array;
export function ed25519Verify(
  publicKeyRaw: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean;
export function bytesToHex(bytes: Uint8Array): string;
export function hexToBytes(hex: string): Uint8Array;

// ---------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------

export interface OriginatorInput {
  /** Hex string or 32 raw bytes. A generateEd25519() keypair works as-is. */
  publicKey?: KeyInput;
  publicKeyHex?: string;
  label?: string;
}

export interface Participant {
  actor_id: string;
  role: string;
  label?: string;
}

export interface CapsuleBuilderOptions {
  /** Signing identity of the capsule's originator. */
  originator: OriginatorInput | Ed25519KeyPair;
  participants?: Participant[];
  /** ISO 8601 UTC; defaults to now. */
  createdAt?: string;
  /**
   * Opt IN to Pith payload normalization for events (default false —
   * lossy narrative rewriting is never applied unless asked for).
   */
  pith?: boolean;
}

export interface EventInput {
  /** Who did it, e.g. "human:alice" or "ai:claude". Required. */
  actor: string;
  /** What they did, e.g. "approved_report". Required. */
  action: string;
  /** Default "observation". */
  kind?: string;
  /** What it applied to; default "capsule". */
  target?: string;
  /** ISO 8601 UTC; default now. */
  timestamp?: string;
  payload?: Record<string, unknown>;
  untrusted_payload_fields?: string[];
  /**
   * Author-declared Pith provenance: payload paths (spec/chain.md
   * grammar) whose narrative the author already normalized. The builder
   * unions in the fields its own normalizer changed.
   */
  pith_normalized_fields?: string[];
}

export interface SignerInput {
  /** Default "originator". */
  role?: string;
  publicKey?: KeyInput;
  privateKey?: KeyInput;
  publicKeyHex?: string;
  privateKeyHex?: string;
}

export type RecipientInput = KeyInput | { publicKey?: KeyInput; publicKeyHex?: string } | X25519KeyPair;

export interface SealOptions {
  /** One signer or an array. A generateEd25519() keypair works as-is. */
  signers: SignerInput | Ed25519KeyPair | Array<SignerInput | Ed25519KeyPair>;
  /** Presence enables encryption. One recipient or an array. */
  recipients?: RecipientInput | RecipientInput[];
  /** ISO 8601 UTC; defaults to now. Pass explicitly for reproducible builds. */
  signedAt?: string;
}

export interface SkillInput {
  json?: Record<string, unknown> | null;
  markdown?: string | null;
}

/**
 * One manifest.predecessors entry (spec/lineage.md): the exact sealed
 * predecessor state a successor declares it continues from. All six
 * members REQUIRED when an entry is present; the two chain anchors are
 * null together exactly for a zero-event predecessor.
 */
export interface PredecessorEntry {
  capsule_id: string;
  format_version: string;
  originator_public_key: string;
  first_event_hash: string | null;
  entry_hash: string | null;
  manifest_hash: string;
}

export interface ContinueFromOptions {
  /** The NEW originator — the successor is a new artifact with a new identity. */
  originator: OriginatorInput | Ed25519KeyPair;
  /** The successor's own actor set; never inherited from the predecessor. */
  participants?: Participant[];
  createdAt?: string;
  pith?: boolean;
  /** Emit the conventional custody_received genesis event (default true). */
  custodyEvent?: boolean;
  /** Actor for the custody event (default "system:host"; must satisfy the appendEvent actor rule). */
  custodyActor?: string;
  /** Optional filter over carriable predecessor file paths. */
  carry?: (path: string) => boolean;
  /** Proceed when the predecessor fails its own verification (W3 override). */
  allowInvalidPredecessor?: boolean;
}

export class CapsuleBuilder {
  constructor(options: CapsuleBuilderOptions);
  /**
   * Open a successor builder from a sealed predecessor: verify it under
   * its own era's rules, derive the lineage entry, carry content files
   * byte-identically, start a fresh chain, and queue the custody event.
   * Throws PredecessorError (W3–W5).
   */
  static continueFrom(
    predecessor: CapsuleReader | Uint8Array | ArrayBuffer,
    options: ContinueFromOptions,
  ): Promise<CapsuleBuilder>;
  /** Full verifyCapsule result for the predecessor (set by continueFrom). */
  predecessorVerification?: VerifyResult;
  /** Sorted predecessor paths carried into this builder (set by continueFrom). */
  carriedPaths?: string[];
  /** Lineage entries declared so far. */
  predecessors: PredecessorEntry[];
  /** Verify + derive + append one lineage entry (merges: once per parent). */
  declarePredecessor(
    predecessor: CapsuleReader | Uint8Array | ArrayBuffer,
    options?: { allowInvalidPredecessor?: boolean },
  ): Promise<this>;
  /**
   * Explicit-values path: validates grammar, null coherence, and
   * identity coherence (known eras) — form, never truth.
   */
  declarePredecessorEntry(entry: PredecessorEntry): this;
  setProgram(markdown: string): this;
  setAgents(markdown: string): this;
  addSkill(id: string, skill: SkillInput): this;
  addPayload(path: string, bytes: Uint8Array): this;
  /** Per-event { pith: true | false } overrides the builder's setting. */
  appendEvent(event: EventInput, options?: { pith?: boolean }): this;
  /** capsule_id seal() will assign; requires >= 1 appended event. */
  previewCapsuleId(): string;
  /** Seal and emit the .capsule bytes (a deterministic ZIP). */
  seal(options: SealOptions): Promise<Uint8Array>;
}

/**
 * Refusal to build on a predecessor (spec/lineage.md W3–W5).
 * `verification` is null for encrypted_predecessor.
 */
export class PredecessorError extends Error {
  reason:
    | "verification_failed"
    | "unsupported_version"
    | "encrypted_predecessor"
    | "unsupported_profile";
  verification: VerifyResult | null;
}

/** Derive the six-member lineage entry from an opened predecessor (W1). */
export function derivePredecessorEntry(reader: CapsuleReader): PredecessorEntry;

export interface RewrapOptions extends Omit<ContinueFromOptions, "pith"> {
  /** The NEW keypair; also the default signer. */
  originator: Ed25519KeyPair | (OriginatorInput & { privateKey?: KeyInput; privateKeyHex?: string });
  signers?: SealOptions["signers"];
  signedAt?: string;
  recipients?: RecipientInput | RecipientInput[];
  lineagePlacement?: "both" | "inner" | "outer";
}

export interface RewrapResult {
  bytes: Uint8Array;
  capsuleId: string;
  predecessorEntry: PredecessorEntry;
  predecessorVerification: VerifyResult;
  carriedPaths: string[];
  custodyEventEmitted: boolean;
}

/**
 * One-call custody transfer: continueFrom + immediate seal under the
 * new originator keypair. Single predecessor by design; merges go
 * through the builder path.
 */
export function rewrapCapsule(
  predecessor: CapsuleReader | Uint8Array | ArrayBuffer,
  options: RewrapOptions,
): Promise<RewrapResult>;

// ---------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------

export interface ChainEvent {
  seq: number;
  event_id: string;
  actor: string;
  kind: string;
  action: string;
  target: string;
  timestamp: string;
  payload: Record<string, unknown>;
  untrusted_payload_fields?: string[];
  prev_hash: string;
  hash: string;
}

export interface Envelope {
  version: string;
  capsule_id: string;
  first_event_hash: string;
  entry_hash: string;
  manifest_hash: string;
  content_index_hash: string;
  encrypted_blob_hash: string | null;
  cipher: string;
  signed_at: string;
  signers: Array<{ role: string; public_key: string; signature: string }>;
}

/** One member of manifest.signer_commitment. */
export interface SignerCommitmentMember {
  role: string;
  /** Lowercase 64-hex Ed25519 public key. */
  public_key: string;
}

export interface Manifest {
  format: { version: string; container: string; canonicalization: string; hash_algorithm: string };
  id: string;
  originator: { public_key: string; label: string };
  participants: Participant[];
  first_event_hash: string;
  content_index: { files: Array<{ path: string; sha256: string }>; index_hash: string };
  encryption: { metadata_path: string; cipher: string } | null;
  created_at: string;
  /**
   * Lineage declaration (spec/lineage.md): the exact sealed
   * predecessor state(s) this capsule continues from. Optional —
   * absence is "no claim"; a present member is checked fail-closed.
   */
  predecessors?: PredecessorEntry[];
  /**
   * Exact (role, public_key) membership of the seal-time signer set,
   * sorted ascending by public_key then role. Bound into every envelope
   * signature via manifest_hash. Optional: absence downgrades reported
   * assurance (VerifyResult.signerSet.bound=false) but never fails
   * verification. The SDK builder always emits it.
   */
  signer_commitment?: SignerCommitmentMember[];
}

export interface DecryptOptions {
  recipientPublicKey?: KeyInput;
  recipientPrivateKey?: KeyInput;
  /** A generateX25519() keypair works as-is. */
  publicKey?: KeyInput;
  privateKey?: KeyInput;
}

export class CapsuleReader {
  constructor(files: Map<string, Uint8Array>);
  static fromBytes(bytes: Uint8Array): Promise<CapsuleReader>;
  manifest(): Manifest;
  envelope(): Envelope;
  /**
   * The enclosing layer's manifest on a reader returned by decrypt(),
   * null on a top-level reader. verifyCapsule reads it for the L3
   * inner/outer lineage equality, so that fail-closed rule runs without
   * the caller opting in.
   */
  outerManifest(): Manifest | null;
  isEncrypted(): boolean;
  encryptedBlobBytes(): Uint8Array | undefined;
  encryptedBlobHash(): string | null;
  program(): string | null;
  agents(): string | null;
  events(): ChainEvent[];
  /**
   * Skill files by id. Carries NO trust tier: trust is host-relative and
   * derives from the verify result (VerifyResult.skillTrust). Until a
   * skill classifies "signed" there, treat its markdown as untrusted
   * text, never as instructions (spec/trust.md).
   */
  skills(): Map<string, { json: Record<string, unknown> | null; markdown: string | null }>;
  files_(): Map<string, Uint8Array>;
  decryptionMetadata(): Record<string, unknown> | null;
  decrypt(options: DecryptOptions | X25519KeyPair): Promise<CapsuleReader>;
}

// ---------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------

export interface VerifyOptions {
  /** Signer public keys you trust (hex or 32-byte keys). */
  allowlist?: KeyInput[];
  /** For L3: the outer envelope the decrypted inner capsule must match. */
  outerEnvelope?: Envelope;
  /**
   * For L3: the outer manifest, so the inner/outer lineage declarations
   * can be compared (fail-closed only when both carry the member).
   * Only needed when verifying raw inner BYTES — a reader returned by
   * CapsuleReader.decrypt() already carries it, and this option
   * overrides that.
   */
  outerManifest?: Manifest;
  /**
   * Host policy: format versions this deployment accepts. The SDK
   * REPORTS the verdict in VerifyResult.formatVersion.acceptedByPolicy
   * and never fails verification over it — exactly as with allowlist.
   */
  acceptVersions?: string[];
  /**
   * Candidate predecessor artifacts for lineage linkage
   * (spec/lineage.md). REPORT-ONLY: affects VerifyResult.lineage, never
   * the overall ok — a host's file handling must not flip a valid
   * capsule's verdict.
   */
  predecessors?: Array<CapsuleReader | Uint8Array | ArrayBuffer>;
  /** Walk resource limit (default 256), like the reader's size caps. */
  lineageHopCap?: number;
}

/** One reported lineage entry: the declared members echoed, plus facts. */
export interface LineageEntryReport extends PredecessorEntry {
  /** 1 = declared by the verified capsule; 2+ = discovered by the walk. */
  hop: number;
  /** Whether the identity-coherence recompute ran (false: unknown declared era). */
  identityChecked: boolean;
  status:
    | "unverified"
    | "verified"
    | "mismatch"
    | "predecessor_invalid"
    | "predecessor_unverifiable";
  /** Set only for predecessor_unverifiable. */
  reason: "unsupported_version" | "encrypted_predecessor" | "unsupported_profile" | "unsupported_capability" | null;
  errors: string[];
  /** Slim summary of the supplied artifact's own verification; null when nothing was checked. */
  artifact: { ok: boolean; observed_version: string | null; level: string; error_count: number } | null;
}

/**
 * The lineage result area (spec/lineage.md). `ok` is the AREA verdict:
 * standalone checks passed AND no checked entry contradicts the
 * declaration. Linkage failures falsify it without touching the overall
 * verdict; unchecked entries never falsify it (unchecked is not failed).
 * declared=false covers both "no member" and "not evaluated" (after an
 * open-stage refusal the channel holds this default).
 */
export interface LineageReport {
  declared: boolean;
  ok: boolean;
  verifiedDepth: number;
  entries: LineageEntryReport[];
}

/**
 * The version-compatibility fact channel (spec/versioning.md).
 * `observed` is the version the capsule DECLARES; `supported` says
 * whether this verifier knows that era; `status` distinguishes, machine-
 * readably, a verifier-too-old refusal (unknown_newer) from an
 * unknown-older era, a grammar violation (invalid), and a capsule whose
 * version could not be read at all (unread). None of these read as
 * tampering. `suite` is the era's algorithm-suite identifier ("v0.6":
 * Ed25519 / SHA-256 / JCS / X25519+HKDF-SHA-256+ChaCha20-Poly1305).
 */
export interface FormatVersionReport {
  observed: string | null;
  supported: boolean;
  status: "known" | "unknown_newer" | "unknown_older" | "invalid" | "unread";
  suite: string | null;
  /** null when the host declared no acceptVersions policy. */
  acceptedByPolicy: boolean | null;
}

export interface VerifyResult {
  /** True only when every check passed. Trust is reported separately. */
  ok: boolean;
  level: "L2" | "L3";
  errors: string[];
  chain: { ok: boolean; errors: Array<{ seq: number; message: string }>; note?: string };
  contentIndex: { ok: boolean; errors: string[] };
  envelope: {
    ok: boolean;
    signers: Array<{ role: string; public_key: string; valid: boolean; trusted: boolean }>;
  };
  /**
   * Signer-set binding (manifest.signer_commitment). bound=true means the
   * manifest commits to the exact signer set and ok reflects the match
   * (fail-closed). bound=false means the capsule does not assert
   * signer-set integrity: verification can still succeed, at a visibly
   * lower assurance.
   */
  signerSet: { bound: boolean; ok: boolean; errors: string[] };
  /**
   * Chain.md step-6 actor binding — same claim shape as signerSet.
   * bound=true means manifest.participants[] is non-empty and every chain
   * event actor must be a member or "system:host" (failures surface in
   * chain.errors, fail-closed). bound=false means the manifest declares
   * no participants — no claim about who acted — so verification can
   * still succeed at a visibly lower assurance (reported in notes).
   */
  actorSet: { bound: boolean };
  /** Observed format version + support/policy verdicts (reported facts). */
  formatVersion: FormatVersionReport;
  /**
   * DERIVED skill-trust classification (spec/trust.md "Skill trust").
   * capsuleSigned is the single capsule-level fact — ok (the overall
   * verdict) && contentIndex.ok && envelope.ok && trustedSignerCount > 0
   * — because ONE envelope
   * signature covers the whole content index; the format cannot make
   * skill A "signed" while skill B is "unsigned" under the same seal.
   * skills[id] is "signed" iff capsuleSigned and skills/<id>/skill.json
   * is listed in the content index. Hosts MUST take the tier from here:
   * the format has no manifest.skill_trust member, and any encountered
   * one is an inert unknown member, never authority.
   */
  skillTrust: { capsuleSigned: boolean; skills: Record<string, "signed" | "unsigned"> };
  /**
   * Lineage result area (spec/lineage.md): the manifest.predecessors
   * declaration checked standalone (fail-closed) and against any
   * supplied predecessor pool (report-only).
   */
  lineage: LineageReport;
  /** Number of DISTINCT public keys that are both valid and on your allowlist. */
  trustedSignerCount: number;
  /**
   * Verdict qualifiers (bare strings; non-empty only when ok). This
   * revision emits the three lineage names — lineage_declared_unverified,
   * lineage_mismatch, lineage_predecessor_invalid; payload-carrying
   * facts stay in the lineage area, never on this array.
   */
  qualifiers: string[];
  notes: string[];
}

/**
 * Verify a capsule. Accepts a CapsuleReader or the raw .capsule bytes.
 * Total: never throws, for any input. An unopenable container, a
 * malformed manifest, and a malformed chain all come back as a
 * fail-closed result with the reason in `errors`.
 */
export function verifyCapsule(
  readerOrBytes: CapsuleReader | Uint8Array | ArrayBuffer,
  options?: VerifyOptions,
): Promise<VerifyResult>;

// ---------------------------------------------------------------------
// Lower-level protocol primitives (verifiers, tooling, conformance)
// ---------------------------------------------------------------------

/**
 * Throws if `value` is outside the I-JSON acceptance boundary
 * (spec/canonicalization.md): a plain integer literal beyond ±(2^53 - 1),
 * a non-finite number, or an unpaired surrogate in any string or key.
 */
export function assertIJson(value: unknown, path?: string): void;
export function jcs(value: unknown): Uint8Array;
export function sha256(bytes: Uint8Array): Uint8Array;
export function sha256Hex(bytes: Uint8Array): string;

export function buildChainEvents(bareEvents: Array<Record<string, unknown>>): ChainEvent[];
export function hashEvent(event: Record<string, unknown>): Uint8Array;
export type EventKind =
  | "decision"
  | "observation"
  | "mutation"
  | "session"
  | "checkpoint";

/** The closed `kind` enum from spec/chain.md "Field rules". */
export const EVENT_KINDS: readonly EventKind[];
/** The one actor that never needs a participant entry: the host runtime. */
export const HOST_ACTOR: "system:host";
export function isValidEventKind(kind: unknown): kind is EventKind;

/** Closed actor-id namespace set (spec/manifest.md field rules). */
export type ActorNamespace = "human" | "ai" | "system" | "capsule";
export const ACTOR_NAMESPACES: readonly ActorNamespace[];
/** True for `<namespace>:<id>` with a known namespace and non-empty id. */
export function isValidActorId(actorId: unknown): boolean;
/** Grammar problems for a declared participants[] array ([] = well-formed). */
export function participantActorIdProblems(
  participants?: Array<Participant | string> | null,
): string[];
export function participantActorIds(
  participants?: Array<Participant | string> | null,
): Set<string>;

export function verifyChain(
  events: ChainEvent[],
  options?: { participants?: Array<Participant | string> | null },
): {
  ok: boolean;
  errors: Array<{ seq: number; message: string }>;
};

export function buildEnvelope(fields: Record<string, unknown>): Envelope;
export function signEnvelope(
  envelope: Envelope,
  signers: Array<{ role: string; publicKey: Uint8Array; privateKey: Uint8Array }>,
): Envelope;
export function verifyEnvelopeSignatures(envelope: Envelope): {
  ok: boolean;
  signers: Array<{ role: string; public_key: string; valid: boolean }>;
  note?: string;
};
export function envelopeCanonicalPayload(envelope: Envelope): Uint8Array;
export function envelopeSigningInput(envelope: Envelope, role: string): Uint8Array;

export function buildContentIndex(
  files: Map<string, Uint8Array>,
  excluded?: Set<string>,
): { files: Array<{ path: string; sha256: string }>; index_hash: string };
export function contentIndexExclusions(encrypted: boolean): Set<string>;
export function buildManifest(fields: Record<string, unknown>): Manifest;
export function computeCapsuleId(
  originatorPubKeyRaw: Uint8Array,
  firstEventHashHex: string,
): string;
export function manifestHash(manifest: Manifest): string;
export function manifestBytes(manifest: Manifest): Uint8Array;
/**
 * Problems with a stored manifest.predecessors value (spec/lineage.md
 * standalone checks 1–3); [] = well-formed. Each problem names its
 * member as `predecessors[i].<member>` — the shared cross-lane strings.
 */
export function predecessorsProblems(predecessors: unknown): string[];
/** The six spec-defined members of one predecessor entry. */
export const PREDECESSOR_ENTRY_MEMBERS: readonly string[];
/** The era default profile id ("v0.6-suite"), frozen forever. */
export const DEFAULT_PROFILE_ID: string;
/** Lineage walk hop cap default (a resource limit, not a protocol rule). */
export const LINEAGE_HOP_CAP_DEFAULT: number;
/**
 * Whether an observed `<major>.<minor>` era's rule set defines lineage.
 * `predecessors` is a claim member: in an earlier era it is an unknown
 * member, never shape-checked (spec/versioning.md).
 */
export function eraDefinesLineage(version: string): boolean;
/**
 * Problems a verify result diagnosed, across every channel — the count
 * every report that says "N error(s)" about an artifact uses.
 */
export function verificationErrorCount(result: VerifyResult): number;

/** Reader limits; see spec/format.md "Container properties". */
export interface ZipLimits {
  maxEntries?: number;
  maxTotalBytes?: number;
}
export const DEFAULT_ZIP_LIMITS: Readonly<{ maxEntries: number; maxTotalBytes: number }>;
export function packZip(files: Map<string, Uint8Array>, options?: ZipLimits): Promise<Uint8Array>;
export function unpackZip(
  bytes: Uint8Array,
  options?: ZipLimits,
): Promise<Map<string, Uint8Array>>;
export function scanCentralDirectory(
  bytes: Uint8Array,
  options?: ZipLimits,
): Array<{
  name: string;
  localName: string;
  method: number;
  compressedSize: number;
  size: number;
  externalAttrs: number;
  localHeaderOffset: number;
}>;

export interface PithOptions {
  /** Output length cap including the ellipsis; default 280. */
  maxChars?: number;
  /** Whole sentences kept before the length cap; default 3. */
  maxSentences?: number;
}
export function compressText(
  text: string,
  options?: PithOptions,
): { text: string; changed: boolean; version: string };
export function compressEventPayload<T>(payload: T, options?: PithOptions): T;
/** compressEventPayload plus the list of payload paths that changed. */
export function normalizeEventPayload<T>(
  payload: T,
  options?: PithOptions,
): { payload: T; normalizedFields: string[] };
export const PITH_VERSION: string;

/** Optional identity/encryption/policy overlay; see spec/federation.md. */
export const federation: Record<string, unknown>;

export const SPEC_VERSION: string;

// Version-compatibility policy (spec/versioning.md).
export const KNOWN_VERSIONS: string[];
export const CURRENT_VERSION: string;
export const SUITES: Record<string, string>;
export function classifyVersion(v: unknown): {
  observed: string | null;
  status: "known" | "unknown_newer" | "unknown_older" | "invalid";
};
export class UnsupportedVersionError extends Error {
  observed: string | null;
  status: "unknown_newer" | "unknown_older";
}
export function idDomain(version: string): Uint8Array;
export function provenanceDomain(version: string, role: string): Uint8Array;
export function keyWrapInfo(version: string): Uint8Array;

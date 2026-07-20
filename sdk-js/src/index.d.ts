// Type declarations for @capsule/sdk-v0.6-prototype.
//
// The main integration surface (CapsuleBuilder, CapsuleReader,
// verifyCapsule, key generation) is typed precisely; lower-level
// protocol primitives are typed loosely — they exist for verifiers,
// tooling, and conformance work, not everyday app code.

/** Anywhere a key is accepted: lowercase/uppercase hex string or 32 raw bytes. */
export type KeyInput = string | Uint8Array;

export interface Ed25519KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  publicKeyHex: string;
  privateKeyHex: string;
}

export interface X25519KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  publicKeyHex: string;
  privateKeyHex: string;
}

/** Generate an Ed25519 signing keypair (raw 32-byte keys + hex forms). */
export function generateEd25519(): Ed25519KeyPair;
/** Generate an X25519 encryption keypair (raw 32-byte keys + hex forms). */
export function generateX25519(): X25519KeyPair;

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
  /** Pith payload normalization for events; default true. */
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
  signed?: boolean;
}

export class CapsuleBuilder {
  constructor(options: CapsuleBuilderOptions);
  setProgram(markdown: string): this;
  setAgents(markdown: string): this;
  addSkill(id: string, skill: SkillInput): this;
  addPayload(path: string, bytes: Uint8Array): this;
  appendEvent(event: EventInput, options?: { pith?: boolean }): this;
  /** capsule_id seal() will assign; requires >= 1 appended event. */
  previewCapsuleId(): string;
  /** Seal and emit the .capsule bytes (a deterministic ZIP). */
  seal(options: SealOptions): Promise<Uint8Array>;
}

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

export interface Manifest {
  format: { version: string; container: string; canonicalization: string; hash_algorithm: string };
  id: string;
  originator: { public_key: string; label: string };
  participants: Participant[];
  first_event_hash: string;
  content_index: { files: Array<{ path: string; sha256: string }>; index_hash: string };
  skill_trust: Record<string, "signed" | "unsigned">;
  encryption: { metadata_path: string; cipher: string } | null;
  created_at: string;
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
  isEncrypted(): boolean;
  encryptedBlobBytes(): Uint8Array | undefined;
  encryptedBlobHash(): string | null;
  program(): string | null;
  agents(): string | null;
  events(): ChainEvent[];
  skills(): Map<string, { json: Record<string, unknown> | null; markdown: string | null; trust: string }>;
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
  /** Number of signers that are both valid and on your allowlist. */
  trustedSignerCount: number;
  notes: string[];
}

/**
 * Verify a capsule. Accepts a CapsuleReader or the raw .capsule bytes;
 * given bytes, an unopenable container returns a fail-closed result
 * instead of throwing.
 */
export function verifyCapsule(
  readerOrBytes: CapsuleReader | Uint8Array | ArrayBuffer,
  options?: VerifyOptions,
): Promise<VerifyResult>;

// ---------------------------------------------------------------------
// Lower-level protocol primitives (verifiers, tooling, conformance)
// ---------------------------------------------------------------------

export function jcs(value: unknown): Uint8Array;
export function sha256(bytes: Uint8Array): Uint8Array;
export function sha256Hex(bytes: Uint8Array): string;

export function buildChainEvents(bareEvents: Array<Record<string, unknown>>): ChainEvent[];
export function hashEvent(event: Record<string, unknown>): Uint8Array;
export function verifyChain(events: ChainEvent[]): {
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

export function packZip(files: Map<string, Uint8Array>): Promise<Uint8Array>;
export function unpackZip(bytes: Uint8Array): Promise<Map<string, Uint8Array>>;
export function scanCentralDirectory(
  bytes: Uint8Array,
): Array<{ name: string; method: number; externalAttrs: number }>;

export function compressText(text: string, options?: Record<string, unknown>): { text: string };
export function compressEventPayload<T>(payload: T, options?: Record<string, unknown>): T;
export const PITH_VERSION: string;

/** Optional identity/encryption/policy overlay; see spec/federation.md. */
export const federation: Record<string, unknown>;

export const SPEC_VERSION: string;

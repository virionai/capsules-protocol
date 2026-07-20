// CapsuleReader: opens a .capsule, exposes the inner pieces, decrypts.

import { jcs } from "./canonical.js";
import { eventsFromJsonl } from "./chain.js";
import {
  chacha20Poly1305Decrypt,
  hexToBytes,
  hkdfSha256,
  bytesToHex,
  x25519DH,
} from "./crypto.js";
import { unpackZip } from "./zip.js";
import { toRawKey } from "./keys.js";

const dec = new TextDecoder();

const HEX64 = /^[0-9a-f]{64}$/;

/**
 * Lightweight shape check on the manifest. Full integrity is the
 * verifier's job; this catches obvious malformation early so a caller
 * that reads `reader.manifest().id` without verifying first can rely
 * on the field being a 64-hex lowercase string per spec.
 */
function validateManifestShape(manifest) {
  if (manifest == null || typeof manifest !== "object") {
    throw new Error("manifest.json is not a JSON object");
  }
  if (manifest.format?.version !== "0.6") {
    throw new Error(`manifest.format.version: expected '0.6', got ${JSON.stringify(manifest.format?.version)}`);
  }
  if (!HEX64.test(manifest.id ?? "")) {
    throw new Error(`manifest.id is not a 64-char lowercase hex string: ${JSON.stringify(manifest.id)}`);
  }
  if (!manifest.originator || !HEX64.test(manifest.originator.public_key ?? "")) {
    throw new Error("manifest.originator.public_key must be a 64-char lowercase hex string");
  }
  if (!HEX64.test(manifest.first_event_hash ?? "")) {
    throw new Error("manifest.first_event_hash must be a 64-char lowercase hex string");
  }
}

function validateEnvelopeShape(envelope) {
  if (envelope == null || typeof envelope !== "object") {
    throw new Error("envelope.json is not a JSON object");
  }
  if (envelope.version !== "0.6") {
    throw new Error(`envelope.version: expected '0.6', got ${JSON.stringify(envelope.version)}`);
  }
  if (!HEX64.test(envelope.capsule_id ?? "")) {
    throw new Error("envelope.capsule_id must be a 64-char lowercase hex string");
  }
  if (!Array.isArray(envelope.signers) || envelope.signers.length === 0) {
    throw new Error("envelope.signers must be a non-empty array");
  }
}

export class CapsuleReader {
  constructor(files) {
    this.files = files; // Map<path, Uint8Array>
    const manifestBytes = files.get("manifest.json");
    if (!manifestBytes) throw new Error("missing manifest.json");
    this._manifest = JSON.parse(dec.decode(manifestBytes));
    validateManifestShape(this._manifest);
    const envBytes = files.get("provenance/envelope.json");
    if (!envBytes) throw new Error("missing provenance/envelope.json");
    this._envelope = JSON.parse(dec.decode(envBytes));
    validateEnvelopeShape(this._envelope);
  }

  static async fromBytes(bytes) {
    const files = await unpackZip(bytes);
    return new CapsuleReader(files);
  }

  manifest() { return this._manifest; }
  envelope() { return this._envelope; }

  isEncrypted() {
    return this._envelope.cipher !== "none" && this.files.has("content.enc");
  }

  encryptedBlobBytes() {
    return this.files.get("content.enc");
  }

  encryptedBlobHash() {
    return this._envelope.encrypted_blob_hash;
  }

  program() {
    const b = this.files.get("program.md");
    return b ? dec.decode(b) : null;
  }

  agents() {
    const b = this.files.get("agents.md");
    return b ? dec.decode(b) : null;
  }

  events() {
    const b = this.files.get("chain/events.jsonl");
    if (!b) return [];
    return eventsFromJsonl(b);
  }

  /**
   * Returns Map<skill_id, { json, markdown, trust }>.
   * Excludes 'decryption' (which is metadata, not a skill).
   */
  skills() {
    const out = new Map();
    const trust = this._manifest.skill_trust ?? {};
    for (const [path, bytes] of this.files.entries()) {
      const m = path.match(/^skills\/([^/]+)\/(skill\.json|SKILL\.md)$/);
      if (!m) continue;
      const id = m[1];
      if (id === "decryption") continue;
      if (!out.has(id)) out.set(id, { json: null, markdown: null, trust: trust[id] ?? "unsigned" });
      const slot = out.get(id);
      if (m[2] === "skill.json") slot.json = JSON.parse(dec.decode(bytes));
      else slot.markdown = dec.decode(bytes);
    }
    return out;
  }

  files_() { return this.files; }

  decryptionMetadata() {
    const path = this._manifest.encryption?.metadata_path ?? "skills/decryption/decryption.json";
    const b = this.files.get(path);
    if (!b) return null;
    return JSON.parse(dec.decode(b));
  }

  /**
   * Decrypt the inner capsule.
   *
   * Accepts { recipientPublicKey, recipientPrivateKey } — or the keypair
   * object returned by generateX25519() directly ({ publicKey,
   * privateKey }). Keys may be hex strings or 32 raw bytes. The public
   * key selects the matching recipient bundle.
   */
  async decrypt(options = {}) {
    if (!this.isEncrypted()) throw new Error("capsule is not encrypted");
    const pub = options.recipientPublicKey ?? options.publicKey ?? options.publicKeyHex;
    const priv = options.recipientPrivateKey ?? options.privateKey ?? options.privateKeyHex;
    if (pub == null || priv == null) {
      throw new Error(
        "decrypt requires the recipient keypair: { recipientPublicKey, recipientPrivateKey } (hex or 32 bytes)",
      );
    }
    const recipientPublicKey = toRawKey(pub, "recipientPublicKey");
    const recipientPrivateKey = toRawKey(priv, "recipientPrivateKey");
    const meta = this.decryptionMetadata();
    if (!meta) throw new Error("missing decryption metadata");
    if (meta.cipher !== "ChaCha20-Poly1305") {
      throw new Error(`unsupported cipher: ${meta.cipher}`);
    }
    const recipientPubHex = bytesToHex(recipientPublicKey);
    const bundle = (meta.key_bundles ?? []).find((b) => b.recipient_public_key === recipientPubHex);
    if (!bundle) throw new Error("no matching recipient bundle");

    const ephPub = hexToBytes(bundle.ephemeral_public_key);
    const wrapNonce = hexToBytes(bundle.wrap_nonce);
    const wrappedKey = hexToBytes(bundle.wrapped_key);

    const shared = x25519DH(recipientPrivateKey, ephPub);
    const wrapKey = hkdfSha256(
      shared,
      recipientPublicKey,
      Buffer.from("capsule-key-wrap-v0.6", "utf8"),
      32,
    );
    const contentKey = chacha20Poly1305Decrypt(wrapKey, wrapNonce, Buffer.alloc(0), wrappedKey);

    // AAD reconstructed per spec/envelope.md "Encryption" — must mirror
    // builder exactly. Do not include manifest_hash; see spec rationale.
    const aad = jcs({
      version: "0.6",
      capsule_id: this._envelope.capsule_id,
      first_event_hash: this._envelope.first_event_hash,
      originator_public_key: this._manifest.originator.public_key,
      cipher: "ChaCha20-Poly1305",
    });

    const contentNonce = hexToBytes(meta.content_nonce);
    const contentEnc = this.encryptedBlobBytes();
    const innerZipBytes = chacha20Poly1305Decrypt(contentKey, contentNonce, aad, contentEnc);

    const innerFiles = await unpackZip(innerZipBytes);
    return new CapsuleReader(innerFiles);
  }
}

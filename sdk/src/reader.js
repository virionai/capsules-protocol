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

const dec = new TextDecoder();

export class CapsuleReader {
  constructor(files) {
    this.files = files; // Map<path, Uint8Array>
    const manifestBytes = files.get("manifest.json");
    if (!manifestBytes) throw new Error("missing manifest.json");
    this._manifest = JSON.parse(dec.decode(manifestBytes));
    const envBytes = files.get("provenance/envelope.json");
    if (!envBytes) throw new Error("missing provenance/envelope.json");
    this._envelope = JSON.parse(dec.decode(envBytes));
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
   * options.recipientPrivateKey: 32 bytes
   * options.recipientPublicKey: 32 bytes (used to select the bundle)
   */
  async decrypt({ recipientPrivateKey, recipientPublicKey }) {
    if (!this.isEncrypted()) throw new Error("capsule is not encrypted");
    if (!recipientPrivateKey || recipientPrivateKey.length !== 32) {
      throw new Error("recipientPrivateKey must be 32 bytes");
    }
    if (!recipientPublicKey || recipientPublicKey.length !== 32) {
      throw new Error("recipientPublicKey must be 32 bytes");
    }
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

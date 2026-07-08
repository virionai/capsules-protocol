// CapsuleBuilder: assembles a v0.6 capsule and seals it.

import { jcs, sha256, sha256Hex } from "./canonical.js";
import {
  buildChainEvents,
  eventsToJsonl,
  firstAndEntryHash,
} from "./chain.js";
import {
  bytesToHex,
  chacha20Poly1305Encrypt,
  generateX25519,
  hkdfSha256,
  hexToBytes,
  randomKey32,
  randomNonce12,
  x25519DH,
} from "./crypto.js";
import {
  buildEnvelope,
  signEnvelope,
} from "./envelope.js";
import {
  buildContentIndex,
  buildManifest,
  computeCapsuleId,
  CONTENT_INDEX_EXCLUDED,
  manifestBytes,
  manifestHash,
} from "./manifest.js";
import { compressEventPayload } from "./pith.js";
import { packZip } from "./zip.js";

export class CapsuleBuilder {
  constructor({ originator, participants = [], createdAt, pith = true }) {
    if (!originator || typeof originator.publicKey !== "string") {
      throw new Error("originator.publicKey (hex) required");
    }
    this.originator = {
      public_key: originator.publicKey,
      label: originator.label ?? "",
    };
    this.participants = participants;
    this.createdAt = createdAt ?? new Date().toISOString().replace(/\.\d+Z$/, "Z");
    this.programMd = null;
    this.agentsMd = null;
    this.skills = new Map(); // id -> { json, markdown, signed }
    this.payload = new Map(); // path -> bytes
    this.bareEvents = [];
    this.pith = pith !== false; // default on; pass {pith:false} to disable
  }

  setProgram(md) {
    this.programMd = md;
    return this;
  }

  setAgents(md) {
    this.agentsMd = md;
    return this;
  }

  addSkill(id, { json, markdown, signed = false }) {
    if (typeof id !== "string" || !/^[a-zA-Z0-9_-]+$/.test(id)) {
      throw new Error(`invalid skill id: ${id}`);
    }
    if (id === "decryption") {
      throw new Error("'decryption' is reserved for encryption metadata; not a skill");
    }
    this.skills.set(id, { json: json ?? null, markdown: markdown ?? null, signed: !!signed });
    return this;
  }

  addPayload(path, bytes) {
    if (!path.startsWith("payload/")) {
      throw new Error(`payload path must start with 'payload/': ${path}`);
    }
    this.payload.set(path, Buffer.from(bytes));
    return this;
  }

  /**
   * Append a chain event. Per-call opt-out: { pith: false } skips
   * payload normalization for this event.
   */
  appendEvent(event, options = {}) {
    if (!event.actor || !event.kind || !event.action || !event.target) {
      throw new Error("event requires actor, kind, action, target");
    }
    const applyPith = options.pith !== false && this.pith;
    const rawPayload = event.payload ?? {};
    const payload = applyPith ? compressEventPayload(rawPayload) : rawPayload;
    this.bareEvents.push({
      actor: event.actor,
      kind: event.kind,
      action: event.action,
      target: event.target,
      timestamp: event.timestamp ?? this.createdAt,
      payload,
      ...(event.untrusted_payload_fields ? { untrusted_payload_fields: event.untrusted_payload_fields } : {}),
    });
    return this;
  }

  /**
   * Seal and emit the capsule bytes.
   *
   * options:
   *   signers:    [{ role, publicKey: 32 bytes, privateKey: 32 bytes }]
   *   recipients: optional [{ publicKey: 32 bytes }] — enables encryption
   *   signedAt:   ISO 8601 UTC string
   */
  async seal({ signers, recipients = [], signedAt }) {
    if (!signers || signers.length === 0) throw new Error("seal requires at least one signer");
    if (!signedAt) throw new Error("seal requires signedAt");
    if (this.programMd == null) this.programMd = "# Program\n";
    if (this.bareEvents.length === 0) {
      // host-emitted backstop event so we never seal an empty chain
      this.bareEvents.push({
        actor: "system:host",
        kind: "observation",
        action: "session_ended",
        target: "capsule",
        timestamp: signedAt,
        payload: { note: "host emitted backstop event before seal" },
      });
    }

    // 1) Build chain
    const events = buildChainEvents(this.bareEvents);
    const { firstEventHash, entryHash } = firstAndEntryHash(events);
    const eventsJsonl = eventsToJsonl(events);

    // 2) Inner files
    const innerFiles = new Map();
    innerFiles.set("program.md", Buffer.from(this.programMd, "utf8"));
    if (this.agentsMd != null) {
      innerFiles.set("agents.md", Buffer.from(this.agentsMd, "utf8"));
    }
    innerFiles.set("chain/events.jsonl", eventsJsonl);
    const skillTrust = {};
    for (const [id, s] of this.skills.entries()) {
      if (s.json != null) {
        innerFiles.set(`skills/${id}/skill.json`, Buffer.from(JSON.stringify(s.json, null, 2), "utf8"));
      }
      if (s.markdown != null) {
        innerFiles.set(`skills/${id}/SKILL.md`, Buffer.from(s.markdown, "utf8"));
      }
      skillTrust[id] = s.signed ? "signed" : "unsigned";
    }
    for (const [path, bytes] of this.payload.entries()) {
      innerFiles.set(path, bytes);
    }

    // 3) Build manifest (without id)
    const originatorPubRaw = hexToBytes(this.originator.public_key);
    const capsuleId = computeCapsuleId(originatorPubRaw, firstEventHash);

    if (recipients.length === 0) {
      // ---- Plain capsule ----
      const contentIndex = buildContentIndex(innerFiles);
      const manifest = buildManifest({
        originator: this.originator,
        participants: this.participants,
        contentIndex,
        firstEventHash,
        skillTrust,
        encryption: null,
        createdAt: this.createdAt,
      });
      manifest.id = capsuleId;
      const mfHash = manifestHash(manifest);

      const envelope = buildEnvelope({
        capsuleId,
        firstEventHash,
        entryHash,
        manifestHash: mfHash,
        contentIndexHash: contentIndex.index_hash,
        encryptedBlobHash: null,
        cipher: "none",
        signedAt,
      });
      signEnvelope(envelope, signers);

      const allFiles = new Map(innerFiles);
      allFiles.set("manifest.json", manifestBytes(manifest));
      allFiles.set("provenance/envelope.json", Buffer.from(JSON.stringify(envelope, null, 2), "utf8"));
      const zipBytes = await packZip(allFiles);
      return zipBytes;
    }

    // ---- Encrypted capsule ----

    // 3a) Pack inner ZIP (still includes manifest with id + content_index covering inner files)
    const innerContentIndex = buildContentIndex(innerFiles);
    const innerManifest = buildManifest({
      originator: this.originator,
      participants: this.participants,
      contentIndex: innerContentIndex,
      firstEventHash,
      skillTrust,
      encryption: null,
      createdAt: this.createdAt,
    });
    innerManifest.id = capsuleId;
    const innerMfHash = manifestHash(innerManifest);

    // The inner envelope is plain — used by L3 to verify the inner package.
    const innerEnvelope = buildEnvelope({
      capsuleId,
      firstEventHash,
      entryHash,
      manifestHash: innerMfHash,
      contentIndexHash: innerContentIndex.index_hash,
      encryptedBlobHash: null,
      cipher: "none",
      signedAt,
    });
    signEnvelope(innerEnvelope, signers);

    const innerAllFiles = new Map(innerFiles);
    innerAllFiles.set("manifest.json", manifestBytes(innerManifest));
    innerAllFiles.set(
      "provenance/envelope.json",
      Buffer.from(JSON.stringify(innerEnvelope, null, 2), "utf8"),
    );
    const innerZipBytes = await packZip(innerAllFiles);

    // 3b) Encrypt inner zip.
    // AAD per spec/envelope.md "Encryption" — version, capsule_id,
    // first_event_hash, originator_public_key, cipher. manifest_hash
    // is intentionally excluded (the outer manifest depends on the
    // encrypted_blob_hash, which depends on this step; the inner
    // content commitment is established at L3 by the inner envelope).
    // Field order is irrelevant — JCS sorts keys lexicographically.
    const contentKey = randomKey32();
    const contentNonce = randomNonce12();

    const aadObj = {
      version: "0.6",
      capsule_id: capsuleId,
      first_event_hash: firstEventHash,
      originator_public_key: this.originator.public_key,
      cipher: "ChaCha20-Poly1305",
    };
    const aad = jcs(aadObj);
    const contentEnc = chacha20Poly1305Encrypt(contentKey, contentNonce, aad, innerZipBytes);
    const encryptedBlobHash = sha256Hex(contentEnc);

    // 3c) Build recipient bundles
    const keyBundles = recipients.map((r) => {
      if (!r.publicKey || r.publicKey.length !== 32) {
        throw new Error("recipient.publicKey must be 32 bytes");
      }
      const eph = generateX25519();
      const shared = x25519DH(eph.privateKey, r.publicKey);
      const wrapKey = hkdfSha256(
        shared,
        r.publicKey,
        Buffer.from("capsule-key-wrap-v0.6", "utf8"),
        32,
      );
      const wrapNonce = randomNonce12();
      const wrappedKey = chacha20Poly1305Encrypt(wrapKey, wrapNonce, Buffer.alloc(0), contentKey);
      return {
        recipient_public_key: bytesToHex(r.publicKey),
        ephemeral_public_key: eph.publicKeyHex,
        wrap_nonce: bytesToHex(wrapNonce),
        wrapped_key: bytesToHex(wrappedKey),
      };
    });

    const decryptionMeta = {
      cipher: "ChaCha20-Poly1305",
      content_nonce: bytesToHex(contentNonce),
      key_bundles: keyBundles,
    };

    // 3d) Outer manifest covers content.enc and decryption metadata
    const outerSidecars = new Map();
    outerSidecars.set(
      "skills/decryption/decryption.json",
      Buffer.from(JSON.stringify(decryptionMeta, null, 2), "utf8"),
    );
    outerSidecars.set("content.enc", contentEnc);
    // Encrypted profile: content.enc is bound by envelope.encrypted_blob_hash,
    // so it is excluded from the content index here.
    const outerContentIndex = buildContentIndex(outerSidecars, CONTENT_INDEX_EXCLUDED);

    const outerManifest = buildManifest({
      originator: this.originator,
      participants: this.participants,
      contentIndex: outerContentIndex,
      firstEventHash,
      skillTrust: {}, // decryption metadata is not a skill
      encryption: {
        metadata_path: "skills/decryption/decryption.json",
        cipher: "ChaCha20-Poly1305",
      },
      createdAt: this.createdAt,
    });
    outerManifest.id = capsuleId;
    const outerMfHash = manifestHash(outerManifest);

    const outerEnvelope = buildEnvelope({
      capsuleId,
      firstEventHash,
      entryHash,
      manifestHash: outerMfHash,
      contentIndexHash: outerContentIndex.index_hash,
      encryptedBlobHash,
      cipher: "ChaCha20-Poly1305",
      signedAt,
    });
    signEnvelope(outerEnvelope, signers);

    const outerAllFiles = new Map(outerSidecars);
    outerAllFiles.set("manifest.json", manifestBytes(outerManifest));
    outerAllFiles.set(
      "provenance/envelope.json",
      Buffer.from(JSON.stringify(outerEnvelope, null, 2), "utf8"),
    );
    return await packZip(outerAllFiles);
  }
}

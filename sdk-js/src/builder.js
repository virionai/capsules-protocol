// CapsuleBuilder: assembles a capsule at the current format version and seals it.

import { assertIJson, jcs, sha256, sha256Hex } from "./canonical.js";
import {
  buildChainEvents,
  eventsToJsonl,
  firstAndEntryHash,
  isValidEventKind,
  isValidUntrustedPayloadPath,
  participantActorIdProblems,
  participantActorIds,
  EVENT_KINDS,
  HOST_ACTOR,
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
  buildSignerCommitment,
  computeCapsuleId,
  CONTENT_INDEX_EXCLUDED,
  manifestBytes,
  manifestHash,
} from "./manifest.js";
import { compressEventPayload } from "./pith.js";
import { packZip } from "./zip.js";
import { CURRENT_VERSION, keyWrapInfo } from "./versions.js";
import { nowIso, toKeyHex, toRecipient, toSigner } from "./keys.js";

/** Throw when a declared participants[] fails the actor-id grammar. */
function assertValidParticipants(participants) {
  const problems = participantActorIdProblems(participants);
  if (problems.length > 0) throw new Error(problems.join("; "));
}

export class CapsuleBuilder {
  constructor({ originator, participants = [], createdAt, pith = true } = {}) {
    // `originator` accepts { publicKey, label? } with the key as a hex
    // string or 32 raw bytes — including the keypair object returned by
    // generateEd25519() (spread in a label: { ...keys, label: "MyApp" }).
    const originatorKey = originator?.publicKey ?? originator?.publicKeyHex;
    if (originatorKey == null) {
      throw new Error("originator.publicKey required (hex string or 32 bytes)");
    }
    this.originator = {
      public_key: toKeyHex(originatorKey, "originator.publicKey"),
      label: originator.label ?? "",
    };
    // spec/manifest.md field rules: every declared actor_id must sit in
    // the closed namespace set. Refuse the shape at the call site that
    // introduced it — a capsule declaring an uninterpretable participant
    // fails every conformant verifier. Re-checked at seal() because
    // builder.participants is a mutable property.
    assertValidParticipants(participants);
    this.participants = participants;
    this.createdAt = createdAt ?? nowIso();
    this.programMd = null;
    this.agentsMd = null;
    this.skills = new Map(); // id -> { json, markdown }
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

  /**
   * Add a skill (skills/<id>/skill.json + SKILL.md). There is no trust
   * declaration here: skill trust is host-relative and DERIVED at verify
   * time (verifyCapsule(...).skillTrust), so an author cannot assert it —
   * the removed v0.5-draft `signed` flag is rejected loudly rather than
   * silently ignored.
   */
  addSkill(id, { json, markdown, ...rest } = {}) {
    if ("signed" in rest) {
      throw new Error(
        "addSkill: the 'signed' declaration was removed — skill trust is derived by the " +
          "verifier from the host's allowlist (verifyCapsule(...).skillTrust), not declared " +
          "by the author (spec/trust.md)",
      );
    }
    if (typeof id !== "string" || !/^[a-zA-Z0-9_-]+$/.test(id)) {
      throw new Error(`invalid skill id: ${id}`);
    }
    if (id === "decryption") {
      throw new Error("'decryption' is reserved for encryption metadata; not a skill");
    }
    this.skills.set(id, { json: json ?? null, markdown: markdown ?? null });
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
   * Append a chain event. `actor` and `action` are required; `kind`
   * defaults to "observation", `target` to "capsule", and `timestamp`
   * to the builder's `createdAt` value. Per-call opt-out: { pith: false }
   * skips payload normalization for this event.
   *
   * Rejects (spec/chain.md):
   *   - a `kind` outside the closed enum, always, and
   *   - when the builder declares a non-empty `participants[]`, an
   *     `actor` that is neither "system:host" nor a declared participant.
   *     The builder never auto-registers participants — declaring who may
   *     act is the caller's decision, and a capsule that names declared
   *     participants while its chain smuggles others would fail every
   *     conformant verifier. A builder with NO declared participants
   *     accepts any actor: that capsule makes a visibly weaker claim
   *     (verifiers report the actor set as unbound).
   */
  appendEvent(event, options = {}) {
    if (!event.actor || !event.action) {
      throw new Error("event requires actor and action");
    }
    const kind = event.kind ?? "observation";
    if (!isValidEventKind(kind)) {
      throw new Error(
        `event kind ${JSON.stringify(kind)} is not one of ${EVENT_KINDS.join(", ")}`,
      );
    }
    // Recomputed on every call so mutating builder.participants between
    // appends behaves predictably.
    const declared = participantActorIds(this.participants);
    if (declared.size > 0 && event.actor !== HOST_ACTOR && !declared.has(event.actor)) {
      throw new Error(
        `event actor ${JSON.stringify(event.actor)} is not a declared participant: ` +
          `add { actor_id: ${JSON.stringify(event.actor)}, role: "..." } to the builder's ` +
          `participants[] (only "system:host" may appear without one)`,
      );
    }
    // Writer obligation (spec/chain.md "Untrusted content"): a marking
    // outside the path grammar has no defined resolution, so refuse it at
    // the call site that introduced it rather than at some future reader.
    if (event.untrusted_payload_fields !== undefined) {
      if (!Array.isArray(event.untrusted_payload_fields)) {
        throw new Error("appendEvent: untrusted_payload_fields must be an array of payload paths");
      }
      for (const p of event.untrusted_payload_fields) {
        if (!isValidUntrustedPayloadPath(p)) {
          throw new Error(
            `appendEvent: untrusted_payload_fields entry ${JSON.stringify(p)} is not a valid ` +
              `payload path (expected "payload.<segment>" per spec/chain.md)`,
          );
        }
      }
    }
    const applyPith = options.pith !== false && this.pith;
    const rawPayload = event.payload ?? {};
    const payload = applyPith ? compressEventPayload(rawPayload) : rawPayload;
    // Fail here, not at seal(): a payload outside the I-JSON acceptance
    // boundary (spec/canonicalization.md) cannot be canonicalized, and the
    // caller still has the offending value in scope at this point.
    try {
      assertIJson(payload, `event[${this.bareEvents.length}].payload`);
    } catch (err) {
      throw new Error(`appendEvent: ${err.message}`);
    }
    this.bareEvents.push({
      actor: event.actor,
      kind,
      action: event.action,
      target: event.target ?? "capsule",
      timestamp: event.timestamp ?? this.createdAt,
      payload,
      ...(event.untrusted_payload_fields ? { untrusted_payload_fields: event.untrusted_payload_fields } : {}),
    });
    return this;
  }

  /**
   * Compute the capsule_id that seal() will assign, given the events
   * appended so far. capsule_id depends only on the originator key and the
   * first event hash, so it is knowable before sealing — letting an issuer
   * attest to the id (and the signer key) so the attestation can be embedded
   * under payload/ and bound by the content index. Requires at least one
   * appended event (so the first-event hash is final and no seal-time
   * backstop event is inserted).
   */
  previewCapsuleId() {
    if (this.bareEvents.length === 0) {
      throw new Error("previewCapsuleId requires at least one appended event");
    }
    const events = buildChainEvents(this.bareEvents);
    const { firstEventHash } = firstAndEntryHash(events);
    return computeCapsuleId(hexToBytes(this.originator.public_key), firstEventHash);
  }

  /**
   * Seal and emit the capsule bytes.
   *
   * options:
   *   signers:    one signer or an array. Each signer is
   *               { role?, publicKey, privateKey } with keys as hex
   *               strings or 32 raw bytes; the keypair object returned
   *               by generateEd25519() works as-is (role defaults to
   *               "originator").
   *   recipients: optional; enables encryption. One recipient or an
   *               array; each is an X25519 public key (hex or bytes),
   *               { publicKey }, or a generateX25519() keypair object.
   *   signedAt:   optional ISO 8601 UTC string; defaults to now. Pass
   *               an explicit value for reproducible builds.
   */
  async seal({ signers, recipients = [], signedAt } = {}) {
    // builder.participants is mutable between construction and seal;
    // never emit a manifest that fails the namespace grammar.
    assertValidParticipants(this.participants);
    const signerList = (Array.isArray(signers) ? signers : signers ? [signers] : []).map(toSigner);
    if (signerList.length === 0) throw new Error("seal requires at least one signer");
    const recipientList = (Array.isArray(recipients) ? recipients : [recipients]).map(toRecipient);
    signers = signerList;
    recipients = recipientList;
    signedAt = signedAt ?? nowIso();
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
    for (const [id, s] of this.skills.entries()) {
      if (s.json != null) {
        innerFiles.set(`skills/${id}/skill.json`, Buffer.from(JSON.stringify(s.json, null, 2), "utf8"));
      }
      if (s.markdown != null) {
        innerFiles.set(`skills/${id}/SKILL.md`, Buffer.from(s.markdown, "utf8"));
      }
    }
    for (const [path, bytes] of this.payload.entries()) {
      innerFiles.set(path, bytes);
    }

    // 3) Build manifest (without id)
    const originatorPubRaw = hexToBytes(this.originator.public_key);
    const capsuleId = computeCapsuleId(originatorPubRaw, firstEventHash);

    // Signer-set commitment: the exact (role, public_key) membership of the
    // seal-time signer set, bound into the manifest (and therefore into
    // every signature via manifest_hash). Plain and encrypted paths share
    // one signer list, so one commitment serves inner and outer manifests.
    const signerCommitment = buildSignerCommitment(
      signers.map((s) => ({ role: s.role, public_key: bytesToHex(s.publicKey) })),
    );

    if (recipients.length === 0) {
      // ---- Plain capsule ----
      const contentIndex = buildContentIndex(innerFiles);
      const manifest = buildManifest({
        originator: this.originator,
        participants: this.participants,
        contentIndex,
        firstEventHash,
        encryption: null,
        createdAt: this.createdAt,
        signerCommitment,
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
      encryption: null,
      createdAt: this.createdAt,
      signerCommitment,
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
      version: CURRENT_VERSION,
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
        keyWrapInfo(CURRENT_VERSION),
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
      encryption: {
        metadata_path: "skills/decryption/decryption.json",
        cipher: "ChaCha20-Poly1305",
      },
      createdAt: this.createdAt,
      signerCommitment,
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

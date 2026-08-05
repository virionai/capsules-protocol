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
  declaredAlternateProfileId,
  manifestBytes,
  manifestHash,
  predecessorsProblems,
} from "./manifest.js";
import { verificationErrorCount } from "./lineage.js";
import { normalizeEventPayload } from "./pith.js";
import { CapsuleReader } from "./reader.js";
import { verifyCapsule } from "./verifier.js";
import { packZip } from "./zip.js";
import { CURRENT_VERSION, keyWrapInfo, UnsupportedVersionError } from "./versions.js";
import { nowIso, toKeyHex, toRecipient, toSigner } from "./keys.js";

/** Throw when a declared participants[] fails the actor-id grammar. */
function assertValidParticipants(participants) {
  const problems = participantActorIdProblems(participants);
  if (problems.length > 0) throw new Error(problems.join("; "));
}

/**
 * Refusal to build on a predecessor (spec/lineage.md writer
 * obligations W3–W5). `reason` is the closed machine-readable
 * vocabulary, identical in both builder lanes:
 *   "verification_failed"   — the predecessor fails its own verification
 *                             (override: allowInvalidPredecessor)
 *   "unsupported_version"   — declared era outside the known table; the
 *                             entry members cannot be honestly derived,
 *                             so there is no override
 *   "encrypted_predecessor" — v0.7.1 defines no declaration mapping
 *                             onto an encrypted outer/inner pair;
 *                             decrypt the inner and rewrap that
 *   "unsupported_profile"   — the predecessor declares a profile this
 *                             implementation does not implement
 *                             (v0.7.1 lineage commits to default-profile
 *                             predecessors)
 * `verification` carries the full verifyCapsule result where one was
 * produced (null for encrypted_predecessor).
 */
export class PredecessorError extends Error {
  constructor(message, { reason, verification = null }) {
    super(message);
    this.name = "PredecessorError";
    this.reason = reason;
    this.verification = verification;
  }
}

/**
 * Derive the six-member lineage entry from opened predecessor bytes
 * (spec/lineage.md W1 "derive, never copy claims"): format_version,
 * originator key, and the two chain anchors are reads; capsule_id is
 * RECOMPUTED under the predecessor's declared era's domain string, and
 * manifest_hash is RECOMPUTED from the stored manifest document — never
 * taken from the envelope's claim.
 */
export function derivePredecessorEntry(reader) {
  const manifest = reader.manifest();
  const envelope = reader.envelope();
  const version = manifest.format?.version;
  return {
    capsule_id: computeCapsuleId(
      hexToBytes(manifest.originator.public_key),
      manifest.first_event_hash ?? null,
      version,
    ),
    format_version: version,
    originator_public_key: manifest.originator.public_key,
    first_event_hash: manifest.first_event_hash ?? null,
    entry_hash: envelope.entry_hash ?? null,
    manifest_hash: manifestHash(manifest),
  };
}

/**
 * Open + gate a predecessor for building (W3–W5). Returns
 * { reader, verification }; throws PredecessorError otherwise. The
 * refusal order is scope before validity: an encrypted or
 * alternate-profile predecessor is an input class this operation does
 * not take, whatever its verification verdict would be.
 */
async function openPredecessorForBuild(predecessor, { allowInvalidPredecessor = false } = {}) {
  let reader = null;
  let verifyInput = predecessor;
  if (predecessor instanceof CapsuleReader) {
    reader = predecessor;
  } else if (predecessor instanceof Uint8Array || predecessor instanceof ArrayBuffer) {
    const bytes =
      predecessor instanceof ArrayBuffer ? new Uint8Array(predecessor) : predecessor;
    verifyInput = bytes;
    try {
      reader = await CapsuleReader.fromBytes(bytes);
    } catch (err) {
      if (err instanceof UnsupportedVersionError) {
        // W4: no override — the identity recompute needs that era's
        // domain string, so an "entry" would be a fabricated commitment
        // wearing derived members' clothes. The diagnosis keeps the
        // versioning.md vocabulary, distinct from tamper.
        throw new PredecessorError(`predecessor ${err.message}`, {
          reason: "unsupported_version",
        });
      }
      reader = null;
    }
  } else {
    throw new Error(
      "predecessor must be a CapsuleReader, Uint8Array, or ArrayBuffer of .capsule bytes",
    );
  }
  const verification = await verifyCapsule(reader ?? verifyInput, {});
  if (reader == null) {
    throw new PredecessorError(
      `predecessor cannot be opened as a capsule: ${verification.errors[0] ?? "unreadable"}`,
      { reason: "verification_failed", verification },
    );
  }
  if (reader.isEncrypted()) {
    // W5. Privacy note (spec/lineage.md): declaring a decrypted inner
    // publishes existence-evidence of confidential work — the successor
    // author's disclosure choice.
    throw new PredecessorError(
      "predecessor is an encrypted capsule; v0.7.1 defines no declaration mapping onto " +
        "an encrypted capsule's outer/inner pair. Decrypt the inner capsule " +
        "(reader.decrypt(...)) and continue from that — the inner IS a plain capsule. " +
        "Note that declaring a decrypted inner publishes existence-evidence of " +
        "confidential work",
      { reason: "encrypted_predecessor" },
    );
  }
  const alternateProfile = declaredAlternateProfileId(reader.manifest());
  if (alternateProfile !== null) {
    throw new PredecessorError(
      `predecessor declares profile '${alternateProfile}', which this implementation ` +
        `does not implement; v0.7.1 lineage declarations commit to default-profile ` +
        `(v0.6-suite) predecessors — a limitation of the tool, not a defect of the capsule`,
      { reason: "unsupported_profile", verification },
    );
  }
  if (!verification.ok && !allowInvalidPredecessor) {
    // W3: refuse by default at the call site that introduced the
    // problem; the override still derives an exact, honest citation —
    // linkage verification reports the artifact predecessor_invalid
    // whichever path sealed the successor.
    throw new PredecessorError(
      `predecessor fails its own verification (${verificationErrorCount(verification)} error(s)); ` +
        `pass allowInvalidPredecessor: true to declare it anyway — the declaration ` +
        `cites this exact artifact, and linkage verification will report it ` +
        `predecessor_invalid`,
      { reason: "verification_failed", verification },
    );
  }
  return { reader, verification };
}

/**
 * Carry/reset rule (spec/lineage.md "Continuing a capsule"): files are
 * content and carry byte-identically; manifest members are the
 * predecessor originator's claims and reset. The chain resets to a
 * fresh genesis — predecessor history stays where it is signed.
 */
const RESET_PATHS = new Set(["manifest.json", "provenance/envelope.json", "chain/events.jsonl"]);

function isCarriablePath(path) {
  if (RESET_PATHS.has(path)) return false;
  // Cannot occur in the plain predecessor this path accepts; defensive.
  if (path === "content.enc" || path.startsWith("skills/decryption/")) return false;
  return true;
}

export class CapsuleBuilder {
  constructor({ originator, participants = [], createdAt, pith = false } = {}) {
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
    // Lineage declaration entries (spec/lineage.md), appended via
    // declarePredecessor / declarePredecessorEntry / continueFrom.
    this.predecessors = [];
    // Files carried byte-identically from a predecessor (continueFrom).
    // Merged into the inner file map at seal, under any setProgram/
    // setAgents/addSkill/addPayload the caller applies on top.
    this._carriedFiles = new Map();
    // Pith is OPT-IN (v0.7): lossy narrative normalization lands inside
    // the hash chain where the original is not preserved, so an author
    // who writes prose gets their prose unless they ask for the rewrite
    // (spec/pith.md; ROADMAP "Pith protocol boundary").
    this.pith = pith === true;
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
   * to the builder's `createdAt` value. Pith normalization follows the
   * builder setting (opt-in, default off); a per-call { pith: true } or
   * { pith: false } overrides it for this event only. When normalization
   * actually changed a field, the event records the affected payload
   * members in `pith_normalized_fields` (spec/chain.md) — a lossy
   * rewrite inside the hash chain is never silent.
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
    // Caller-declared Pith provenance (an LLM applying Pith as practice
    // may honestly mark the fields it rewrote). Same writer obligation as
    // untrusted_payload_fields: refuse an out-of-grammar entry here, at
    // the call site that introduced it.
    let pithMarks = [];
    if (event.pith_normalized_fields !== undefined) {
      if (!Array.isArray(event.pith_normalized_fields)) {
        throw new Error("appendEvent: pith_normalized_fields must be an array of payload paths");
      }
      for (const p of event.pith_normalized_fields) {
        if (!isValidUntrustedPayloadPath(p)) {
          throw new Error(
            `appendEvent: pith_normalized_fields entry ${JSON.stringify(p)} is not a valid ` +
              `payload path (expected "payload.<segment>" per spec/chain.md)`,
          );
        }
      }
      pithMarks = [...event.pith_normalized_fields];
    }
    const applyPith = options.pith === undefined ? this.pith : options.pith === true;
    const rawPayload = event.payload ?? {};
    let payload = rawPayload;
    if (applyPith) {
      const normalized = normalizeEventPayload(rawPayload);
      payload = normalized.payload;
      for (const field of normalized.normalizedFields) {
        if (!pithMarks.includes(field)) pithMarks.push(field);
      }
    }
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
      // Present when the caller declared marks OR the normalizer changed
      // a field; an event whose narrative was rewritten says so in-chain.
      ...(event.pith_normalized_fields !== undefined || pithMarks.length > 0
        ? { pith_normalized_fields: pithMarks }
        : {}),
    });
    return this;
  }

  /**
   * Open a successor builder from a sealed predecessor (the hand-off
   * made one operation — spec/lineage.md "Continuing a capsule").
   * `predecessor` is a CapsuleReader or the raw .capsule bytes. The
   * predecessor is verified under its own era's rules (refusals W3–W5,
   * thrown as PredecessorError), the six-member declaration entry is
   * derived (W1), content files are carried byte-identically per the
   * carry/reset rule, and the conventional custody_received genesis
   * event is queued (default on, opt-out). The successor's
   * participants[] is the CALLER's claim — never inherited: the
   * predecessor's list described its own chain, which stays behind.
   */
  static async continueFrom(predecessor, {
    originator,                       // REQUIRED — the NEW originator { publicKey, label? }
    participants = [],
    createdAt,
    pith = false,
    custodyEvent = true,
    custodyActor = HOST_ACTOR,        // validated by the appendEvent actor rule
    carry,                            // optional (path) => boolean over carriable paths
    allowInvalidPredecessor = false,  // W3 override
  } = {}) {
    if (originator == null) {
      throw new Error("continueFrom requires the NEW originator ({ publicKey, label? })");
    }
    const { reader, verification } = await openPredecessorForBuild(predecessor, {
      allowInvalidPredecessor,
    });
    const entry = derivePredecessorEntry(reader);
    const builder = new CapsuleBuilder({ originator, participants, createdAt, pith });
    builder.declarePredecessorEntry(entry);
    const carried = [];
    for (const [path, bytes] of reader.files_().entries()) {
      if (!isCarriablePath(path)) continue;
      if (carry && !carry(path)) continue;
      builder._carriedFiles.set(path, Buffer.from(bytes));
      carried.push(path);
    }
    carried.sort();
    if (custodyEvent) {
      // The pinned custody-event template: visible custody for the cold
      // reader, in the existing capsule: namespace. Advisory — never a
      // verifier rule; the manifest declaration is the binding claim.
      builder.appendEvent({
        actor: custodyActor,
        kind: "observation",
        action: "custody_received",
        target: `capsule:${entry.capsule_id}`,
        timestamp: builder.createdAt,
        payload: {
          note:
            `custody received from capsule ${entry.capsule_id}; ` +
            `lineage is declared in manifest.predecessors`,
        },
      });
    }
    builder.predecessorVerification = verification;
    builder.carriedPaths = carried;
    return builder;
  }

  /**
   * Verify + derive + append one lineage entry (merges: call once per
   * parent). Same refusal contract as continueFrom (W3–W5, thrown as
   * PredecessorError). Never emits an event.
   */
  async declarePredecessor(predecessor, { allowInvalidPredecessor = false } = {}) {
    const { reader } = await openPredecessorForBuild(predecessor, { allowInvalidPredecessor });
    return this.declarePredecessorEntry(derivePredecessorEntry(reader));
  }

  /**
   * Explicit-values path (the archivist case: lineage reconstructed
   * from records — hashes in hand, bytes gone). Validates grammar, null
   * coherence, and identity coherence (reader checks 1–3; identity only
   * for KNOWN declared eras, mirroring the reader's unknown-era skip),
   * and appends. Validates form, never truth — the builder cannot know
   * whether the cited artifact exists. Vendor x- members inside the
   * entry are preserved verbatim.
   */
  declarePredecessorEntry(entry) {
    if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error("declarePredecessorEntry requires an entry object");
    }
    const candidate = [...this.predecessors, { ...entry }];
    const problems = predecessorsProblems(candidate);
    if (problems.length > 0) {
      throw new Error(`declarePredecessorEntry: ${problems.join("; ")}`);
    }
    this.predecessors = candidate;
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
   *   lineagePlacement: encrypted successors only (ignored for plain):
   *               where a declared predecessors member lands — "both"
   *               (default: the strongest symmetric claim, the
   *               signer_commitment posture; the two copies are emitted
   *               byte-equal), "inner" (private citation), or "outer"
   *               (public-outer citation) — each single-layer choice a
   *               weaker claim made honestly (spec/lineage.md).
   */
  async seal({ signers, recipients = [], signedAt, lineagePlacement = "both" } = {}) {
    // builder.participants is mutable between construction and seal;
    // never emit a manifest that fails the namespace grammar.
    assertValidParticipants(this.participants);
    if (!["both", "inner", "outer"].includes(lineagePlacement)) {
      throw new Error(`lineagePlacement must be "both", "inner", or "outer", got ${JSON.stringify(lineagePlacement)}`);
    }
    // builder.predecessors is mutable too; never emit a declaration a
    // reader would fail closed (spec/lineage.md W2).
    if (this.predecessors.length > 0) {
      const predecessorProblems = predecessorsProblems(this.predecessors);
      if (predecessorProblems.length > 0) {
        throw new Error(`seal: ${predecessorProblems.join("; ")}`);
      }
    }
    const predecessors = this.predecessors.length > 0 ? this.predecessors : undefined;
    const signerList = (Array.isArray(signers) ? signers : signers ? [signers] : []).map(toSigner);
    if (signerList.length === 0) throw new Error("seal requires at least one signer");
    const recipientList = (Array.isArray(recipients) ? recipients : [recipients]).map(toRecipient);
    signers = signerList;
    recipients = recipientList;
    signedAt = signedAt ?? nowIso();
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

    // 2) Inner files. Carried predecessor files first, byte-identical
    // (never rewritten — no re-encoding, no normalization); everything
    // the caller set on the builder lands on top. Legacy content-indexed
    // files a predecessor carried (e.g. a pre-v0.7 surface.md) survive
    // here — silently dropping them would make a rewrap a lossy copy.
    const innerFiles = new Map();
    for (const [path, bytes] of this._carriedFiles.entries()) {
      innerFiles.set(path, bytes);
    }
    if (this.programMd != null) {
      innerFiles.set("program.md", Buffer.from(this.programMd, "utf8"));
    } else if (!innerFiles.has("program.md")) {
      innerFiles.set("program.md", Buffer.from("# Program\n", "utf8"));
    }
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
        predecessors,
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
      // The author's placement choice (spec/lineage.md "Encrypted
      // successors"): "both" emits byte-equal copies, satisfying the
      // reader's inner/outer equality check by construction.
      predecessors: lineagePlacement === "outer" ? undefined : predecessors,
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
      predecessors: lineagePlacement === "inner" ? undefined : predecessors,
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

/**
 * The one-call custody transfer (spec/lineage.md "Continuing a
 * capsule"): continueFrom + immediate seal under the NEW originator
 * keypair. Pure hand-off — callers who want to continue the work before
 * sealing use CapsuleBuilder.continueFrom and seal later. Single
 * predecessor by design (a hand-off has one subject); merges go through
 * the builder path (declarePredecessor per parent).
 *
 * Reproducibility: with pinned createdAt/signedAt and the same keypair
 * the output is byte-identical within this implementation; without
 * them, two rewraps of the same predecessor are two distinct genuine
 * successors (different genesis timestamp → different capsule_id) —
 * both honest.
 *
 * Throws PredecessorError per W3–W5 (see continueFrom).
 */
export async function rewrapCapsule(predecessor, {
  originator,                       // REQUIRED — the NEW keypair { publicKey, privateKey, label? }
  signers,                          // default [originator]; seal's originator binding applies
  participants = [],
  createdAt,
  signedAt,                         // pin both timestamps for reproducible bytes
  custodyEvent = true,
  custodyActor = HOST_ACTOR,
  carry,
  recipients = [],                  // encrypted-successor pass-through
  lineagePlacement = "both",
  allowInvalidPredecessor = false,
} = {}) {
  if (originator == null) {
    throw new Error(
      "rewrapCapsule requires originator (the NEW keypair { publicKey, privateKey, label? })",
    );
  }
  const builder = await CapsuleBuilder.continueFrom(predecessor, {
    originator,
    participants,
    createdAt,
    custodyEvent,
    custodyActor,
    carry,
    allowInvalidPredecessor,
  });
  const sealSigners = signers ?? [{
    role: "originator",
    publicKey: originator.publicKey ?? originator.publicKeyHex,
    privateKey: originator.privateKey ?? originator.privateKeyHex,
  }];
  const bytes = await builder.seal({
    signers: sealSigners,
    signedAt,
    recipients,
    lineagePlacement,
  });
  const sealed = await CapsuleReader.fromBytes(bytes);
  return {
    bytes,
    capsuleId: sealed.manifest().id,
    predecessorEntry: builder.predecessors[0],
    predecessorVerification: builder.predecessorVerification,
    carriedPaths: builder.carriedPaths,
    custodyEventEmitted: custodyEvent === true,
  };
}

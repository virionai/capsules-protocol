// verifyCapsule: L2 (encrypted-aware) and L3 (decrypted-content) verification.
//
// The verifier reports per-signer outcomes. It does NOT decide trust on
// its own — the caller passes an allowlist of public keys. trusted=true
// only when a signer's key is on the allowlist AND its signature
// verifies.

import { sha256Hex, jcs } from "./canonical.js";
import {
  verifyChain,
  firstAndEntryHash,
  participantActorIdProblems,
  participantActorIds,
} from "./chain.js";
import {
  buildContentIndex,
  compareCommitmentMembers,
  contentIndexExclusions,
  manifestBytes,
  manifestHash,
  computeCapsuleId,
  signerCommitmentProblems,
} from "./manifest.js";
import { hexToBytes } from "./crypto.js";
import { verifyEnvelopeSignatures } from "./envelope.js";
import { CapsuleReader } from "./reader.js";
import { toKeyHex } from "./keys.js";
import { parseJsonStrict } from "./canonical.js";
import { unpackZip } from "./zip.js";
import {
  SUITES,
  UnsupportedVersionError,
  classifyVersion,
  unsupportedVersionMessage,
} from "./versions.js";
import {
  DEFAULT_PROFILE,
  ProfileError,
  classifyProfile,
  profileMismatchMessage,
  unsupportedProfileMessage,
} from "./profiles.js";

/** The unread (fail-closed) formatVersion channel. */
function unreadFormatVersion() {
  return { observed: null, supported: false, status: "unread", suite: null, acceptedByPolicy: null };
}

/** The unread (fail-closed) profile channel (spec/profiles.md). */
function unreadProfile() {
  return {
    observed: null,
    observedVersion: null,
    declared: false,
    effective: null,
    effectiveVersion: null,
    supported: false,
    status: "unread",
    acceptedByPolicy: null,
  };
}

// Canonical cross-lane note strings (spec/results.md) that back the
// qualifier derivations below. The chain-note markers double as the
// derivational facts for empty_chain_not_walked / encrypted_outer_only.
const EMPTY_CHAIN_NOTE =
  "empty chain: no events to walk; envelope anchors checked to be null instead";
const DEFERRED_CHAIN_NOTE = "deferred to L3 (encrypted outer)";

/** The documented fail-closed result: every channel present, nothing trusted. */
function failClosed(message, level) {
  return {
    ok: false,
    level,
    errors: [message],
    chain: { ok: false, errors: [] },
    contentIndex: { ok: false, errors: [] },
    envelope: { ok: false, signers: [] },
    signerSet: { bound: false, ok: false, errors: [] },
    actorSet: { bound: false },
    formatVersion: unreadFormatVersion(),
    profile: unreadProfile(),
    skillTrust: { capsuleSigned: false, skills: {} },
    trustedSignerCount: 0,
    notes: [],
  };
}

/**
 * Derive the normalized verdict surface (spec/results.md): `verdict`,
 * `verdictReason`, `qualifiers`. Report-only — every member restates
 * facts the result already carries; `ok == (verdict === "valid")` is an
 * invariant. Mutates and returns `result`.
 *
 * options:
 *   versionRefusal: "unknown_newer" | "unknown_older" when the refusal
 *                   was an unsupported-version refusal that the
 *                   formatVersion channel alone cannot show (the
 *                   envelope-side refusal: the manifest's observed
 *                   version can be known while envelope.version is not).
 *   allowlistSize:  effective (well-formed) allowlist entry count, for
 *                   the two host-relative trust qualifiers. Only results
 *                   that can reach verdict "valid" need it.
 */
function deriveVerdict(result, { versionRefusal = null, allowlistSize = null } = {}) {
  let verdict;
  let reason = null;
  const versionStatus = versionRefusal ?? result.formatVersion?.status;
  if (versionStatus === "unknown_newer" || versionStatus === "unknown_older") {
    // Refused because the verifier cannot understand what the capsule
    // DECLARES — a different verifier may verify it. Not corruption.
    verdict = "unsupported";
    reason = versionStatus === "unknown_older" ? "unsupported_version_older" : "unsupported_version_newer";
  } else if (result.profile?.status === "unsupported") {
    verdict = "unsupported";
    reason = "unsupported_profile";
  } else if (result.ok === true) {
    verdict = "valid";
  } else {
    verdict = "invalid";
  }
  const qualifiers = [];
  if (verdict === "valid") {
    // Spec-defined emission order (spec/results.md). Each entry is a
    // pure restatement of one already-reported fact.
    if (result.signerSet?.bound === false) qualifiers.push("signer_set_unbound");
    if (result.actorSet?.bound === false) qualifiers.push("actor_set_unbound");
    if (result.chain?.note === EMPTY_CHAIN_NOTE) qualifiers.push("empty_chain_not_walked");
    if (result.level === "L2" && result.chain?.note === DEFERRED_CHAIN_NOTE) {
      qualifiers.push("encrypted_outer_only");
    }
    if (result.formatVersion?.acceptedByPolicy === false) {
      qualifiers.push("version_not_accepted_by_policy");
    }
    // Mutually exclusive by construction: no allowlist vs an allowlist
    // that matched no distinct signer key.
    if (allowlistSize === 0) qualifiers.push("trust_not_evaluated");
    else if (allowlistSize > 0 && result.trustedSignerCount === 0) {
      qualifiers.push("no_trusted_signer");
    }
  }
  result.verdict = verdict;
  result.verdictReason = reason;
  result.qualifiers = qualifiers;
  return result;
}

const SKILL_PATH = /^skills\/([^/]+)\/(skill\.json|SKILL\.md)$/;

/**
 * Derived skill-trust classification (spec/trust.md "Skill trust").
 *
 * The tier is host-relative — it depends on the allowlist the host passed
 * to THIS verification — so it can only be derived from the verify
 * result, never read from the capsule (the author cannot know the host's
 * allowlist, and the threat model's adversary IS the capsule author).
 *
 * The classification is CAPSULE-LEVEL in reality: one envelope signature
 * covers the whole content index, so every skill under one seal shares
 * the same `capsuleSigned` fact. Per-id variation only reflects whether
 * that skill ships a `skill.json` listed in the content index at all.
 */
function deriveSkillTrust({ files, manifest, verdictOk, contentIndexOk, envelopeOk, trustedSignerCount }) {
  // The OVERALL verdict is consulted (spec/trust.md): a capsule that
  // FAILS verification never classifies anything signed, whatever the
  // allowlist says. Without result.ok, a capsule broken in a way that
  // spares content_index and the envelope signatures (e.g. a
  // signer_commitment naming a key that never signed) still tells the
  // host its skills are trustworthy — the prompt-injection path the
  // derived tier exists to close. content_index.ok / envelope.ok are
  // kept in the conjunction for fail-closed redundancy.
  const capsuleSigned =
    verdictOk === true && contentIndexOk && envelopeOk && trustedSignerCount > 0;
  const indexedPaths = new Set(
    (Array.isArray(manifest?.content_index?.files) ? manifest.content_index.files : [])
      .map((f) => f?.path)
      .filter((p) => typeof p === "string"),
  );
  const skills = {};
  for (const path of files.keys()) {
    const m = path.match(SKILL_PATH);
    if (!m) continue;
    const id = m[1];
    if (id === "decryption") continue; // encryption metadata, not a skill
    skills[id] =
      capsuleSigned && indexedPaths.has(`skills/${id}/skill.json`) ? "signed" : "unsigned";
  }
  return { capsuleSigned, skills };
}

/**
 * Best-effort read of the DECLARED manifest.format.version from an
 * unpacked file map whose reader-construction failed. The observed
 * version is a reported fact even when the capsule cannot be processed —
 * that is what lets an auditor tell "this verifier is too old for the
 * capsule" apart from "this capsule is corrupt" (spec/versioning.md).
 */
function peekFormatVersion(files) {
  try {
    const bytes = files.get("manifest.json");
    if (!bytes) return unreadFormatVersion();
    const manifest = parseJsonStrict(bytes, "manifest.json");
    const cls = classifyVersion(manifest?.format?.version);
    return {
      observed: cls.observed,
      supported: cls.status === "known",
      status: cls.status,
      suite: cls.status === "known" ? SUITES[cls.observed] : null,
      acceptedByPolicy: null,
    };
  } catch {
    return unreadFormatVersion();
  }
}

/**
 * Best-effort profile channel for a capsule whose reader construction
 * failed (spec/profiles.md obligation: the observed declaration is a
 * reported fact even on refusal — it is what lets an auditor route the
 * capsule to a capable verifier instead of declaring it corrupt).
 *
 * A typed ProfileError carries its own classification. A version-gate
 * refusal reports the declaration with status "unevaluated" (read but
 * not classified: the version gate refused first — profile semantics
 * are era-scoped, so an unknown era means the declaration cannot be
 * classified). Any other open failure never reached the gate either:
 * the channel stays at the fail-closed "unread" default, with the
 * manifest's declaration surfaced best-effort when it parses.
 */
function peekProfile(files, err) {
  if (err instanceof ProfileError) {
    const cls = err.classification;
    return {
      observed: cls.observed,
      observedVersion: cls.observedVersion,
      declared: cls.declared,
      effective: null,
      effectiveVersion: null,
      supported: false,
      status: cls.status,
      acceptedByPolicy: null,
    };
  }
  let observed = null;
  let observedVersion = null;
  let declared = false;
  try {
    const bytes = files.get("manifest.json");
    if (!bytes) return unreadProfile();
    const manifest = parseJsonStrict(bytes, "manifest.json");
    const decl = manifest?.format?.profile;
    declared = decl !== undefined;
    if (decl !== null && typeof decl === "object" && !Array.isArray(decl)) {
      if (typeof decl.id === "string") observed = decl.id;
      if (typeof decl.version === "string") observedVersion = decl.version;
    }
    if (!declared) {
      try {
        const envBytes = files.get("provenance/envelope.json");
        if (envBytes) {
          const envelope = parseJsonStrict(envBytes, "provenance/envelope.json");
          if (envelope?.profile !== undefined) {
            declared = true;
            const e = envelope.profile;
            if (e !== null && typeof e === "object" && !Array.isArray(e)) {
              if (typeof e.id === "string") observed = e.id;
              if (typeof e.version === "string") observedVersion = e.version;
            }
          }
        }
      } catch {
        // envelope unreadable: the manifest-side observation stands
      }
    }
  } catch {
    return unreadProfile();
  }
  return {
    observed,
    observedVersion,
    declared,
    effective: null,
    effectiveVersion: null,
    supported: false,
    status: err instanceof UnsupportedVersionError ? "unevaluated" : "unread",
    acceptedByPolicy: null,
  };
}

/**
 * verifyCapsule(readerOrBytes, options)
 *
 * Accepts a CapsuleReader or the raw .capsule bytes. When given bytes,
 * a container that cannot even be opened (malformed ZIP, missing or
 * invalid manifest/envelope) returns a fail-closed result — app code
 * needs no separate try/catch around opening.
 *
 * This function is total: it never throws, for any input. A capsule that
 * cannot be fully evaluated comes back as a fail-closed result with the
 * underlying message in `errors`.
 *
 * options:
 *   allowlist:      signer public keys to trust (hex strings or 32-byte
 *                   keys) — signers must appear here for trusted=true
 *   outerEnvelope:  optional envelope — for L3 verification, pass the outer
 *                   envelope so the inner can be checked against it.
 *   acceptVersions: host policy — accepted format versions; reported in
 *                   formatVersion.acceptedByPolicy, never decided.
 *   acceptProfiles: host policy — accepted profile ids; reported in
 *                   profile.acceptedByPolicy, never decided.
 *
 * returns:
 *   {
 *     ok: bool,
 *     verdict: "valid" | "invalid" | "unsupported",
 *     verdictReason: string | null,   // non-null iff verdict "unsupported"
 *     qualifiers: [string],           // non-empty only when verdict "valid"
 *     level: "L2" | "L3",
 *     errors: [string],
 *     chain: { ok, errors },
 *     contentIndex: { ok, errors },
 *     envelope: { ok, signers: [{role, public_key, valid, trusted}] },
 *     signerSet: { bound, ok, errors: [string] },
 *     actorSet: { bound },
 *     formatVersion: { observed, supported, status, suite, acceptedByPolicy },
 *     profile: { observed, observedVersion, declared, effective,
 *                effectiveVersion, supported, status, acceptedByPolicy },
 *     skillTrust: { capsuleSigned, skills: { [id]: "signed"|"unsigned" } },
 *     trustedSignerCount: number,
 *     notes: [string]
 *   }
 *
 * verdict/verdictReason/qualifiers are the normalized verdict surface
 * (spec/results.md), DERIVED from the facts above — `ok == (verdict ===
 * "valid")` is an invariant, `unsupported` partitions today's failures
 * into "a limitation of this verifier, not a defect of the capsule"
 * (unknown version, unsupported profile), and each qualifier restates
 * exactly one weaker-claim fact a renderer must not hide.
 * profile is the profile declaration channel (spec/profiles.md):
 * observed is the declaration as read (reported even on refusal),
 * effective the profile actually applied (the absence rule made
 * machine-visible), status one of default | supported | unsupported |
 * mismatched | invalid | unevaluated | unread.
 *
 * signerSet is the signer-set binding check (manifest.signer_commitment):
 *   bound=true  — the manifest commits to the exact signer set; ok reflects
 *                 whether envelope.signers matches it (fail-closed).
 *   bound=false — the manifest carries no commitment. Verification still
 *                 succeeds (absence is a weaker claim, not a violation),
 *                 but the reported assurance visibly excludes signer-set
 *                 integrity.
 * actorSet is the chain.md step-6 actor binding, the same shape of claim:
 *   bound=true  — manifest.participants[] is non-empty; every chain event
 *                 actor must be a member or "system:host" (failures surface
 *                 in chain.errors, fail-closed).
 *   bound=false — the manifest declares no participants, so it makes no
 *                 claim about who acted. Verification still succeeds; the
 *                 unbound actor set is reported here and in notes.
 * skillTrust is the DERIVED skill classification (spec/trust.md):
 *   capsuleSigned — result.ok && contentIndex.ok && envelope.ok &&
 *                 trustedSignerCount>0, i.e. the capsule VERIFIES and every
 *                 content-indexed byte is covered by at least one valid
 *                 signature from a key on THIS host's allowlist. The
 *                 overall verdict is an input: a failing capsule never
 *                 classifies anything signed.
 *   skills[id]  — "signed" iff capsuleSigned and skills/<id>/skill.json is
 *                 listed in the content index; otherwise "unsigned". The
 *                 fact is capsule-level (one signature covers the whole
 *                 index); hosts MUST take the tier from here — the format
 *                 has no skill_trust manifest member, and any encountered
 *                 one is an inert unknown member, never authority.
 * trustedSignerCount counts DISTINCT trusted public keys, not signer rows.
 */
export async function verifyCapsule(readerOrBytes, options = {}) {
  const level = options?.outerEnvelope ? "L3" : "L2";
  let result;
  try {
    result = await verifyCapsuleInner(readerOrBytes, options);
  } catch (err) {
    // The contract above promises callers a result, not an exception, for
    // every input. Anything that escapes the checks below is a capsule we
    // could not fully evaluate, which is a verification failure.
    result = failClosed(`verification failed: ${err?.message ?? String(err)}`, level);
  }
  // Paths with refusal context (unsupported version/profile, the valid
  // path with its allowlist) derive the verdict surface themselves;
  // everything else is an ordinary failure.
  return "verdict" in result ? result : deriveVerdict(result);
}

async function verifyCapsuleInner(readerOrBytes, options = {}) {
  let reader = readerOrBytes;
  if (reader instanceof Uint8Array || reader instanceof ArrayBuffer) {
    const bytes = reader instanceof ArrayBuffer ? new Uint8Array(reader) : reader;
    let files;
    try {
      files = await unpackZip(bytes);
    } catch (err) {
      return failClosed(`capsule cannot be opened: ${err.message}`, "L2");
    }
    try {
      reader = new CapsuleReader(files);
    } catch (err) {
      const result = failClosed(`capsule cannot be opened: ${err.message}`, "L2");
      // Report the observed version and profile declaration even when
      // open is refused: an unknown-version or unsupported-profile
      // refusal must stay distinguishable from tamper.
      result.formatVersion = peekFormatVersion(files);
      result.profile = peekProfile(files, err);
      if (err instanceof ProfileError) {
        // Suite honesty (spec/versioning.md, spec/profiles.md): the
        // suite fact is a statement about the rules governing THIS
        // capsule; after a profile-gate refusal no suite fact is known.
        result.formatVersion.suite = null;
      }
      return deriveVerdict(result, {
        // The envelope-side version refusal: the manifest's observed
        // version can be known while envelope.version is not, so the
        // formatVersion channel alone cannot carry the refusal class.
        versionRefusal: err instanceof UnsupportedVersionError ? err.status : null,
      });
    }
  }
  const errors = [];
  const notes = [];
  const allowlist = new Set();
  for (const [i, key] of (options.allowlist ?? []).entries()) {
    try {
      allowlist.add(toKeyHex(key, `allowlist[${i}]`));
    } catch (err) {
      // Trust configuration is external to capsule validity. Reject malformed
      // keys from the trust set without turning verification into an exception.
      notes.push(`ignored invalid allowlist[${i}]: ${err.message}`);
    }
  }
  const result = {
    ok: false,
    level: options.outerEnvelope ? "L3" : "L2",
    errors,
    chain: { ok: false, errors: [] },
    contentIndex: { ok: false, errors: [] },
    envelope: { ok: false, signers: [] },
    signerSet: { bound: false, ok: true, errors: [] },
    actorSet: { bound: false },
    formatVersion: unreadFormatVersion(),
    profile: unreadProfile(),
    skillTrust: { capsuleSigned: false, skills: {} },
    trustedSignerCount: 0,
    notes,
  };

  const manifest = reader.manifest();
  const envelope = reader.envelope();

  // The observed profile declaration is a reported fact from here on.
  // Until BOTH documents pass the version gate the declaration cannot
  // be classified (the absence rule is era-keyed), so the channel
  // starts "unevaluated" and the version-gate early returns below carry
  // it as-is — the version diagnosis stays the only error.
  {
    const cls = classifyProfile(manifest?.format?.profile, envelope?.profile);
    result.profile = {
      observed: cls.observed,
      observedVersion: cls.observedVersion,
      declared: cls.declared,
      effective: null,
      effectiveVersion: null,
      supported: false,
      status: "unevaluated",
      acceptedByPolicy: null,
    };
  }

  // Actor-set binding: like signer_commitment, PRESENCE BINDS, ABSENCE
  // REPORTS. A non-empty manifest.participants[] binds every chain event
  // actor to the declared set (enforced in the chain walk below,
  // fail-closed — participants is covered by manifest_hash inside the
  // signed payload, so an attacker cannot empty it without breaking the
  // signature). An empty set is a visibly weaker claim made honestly:
  // verification proceeds and the reduced assurance is reported.
  // Shape defense for hand-constructed readers (the bytes path already
  // rejects this at open): a PRESENT non-array participants is malformed,
  // never a silent no-op of the actor rules (spec/manifest.md).
  if (
    manifest != null && typeof manifest === "object" &&
    "participants" in manifest && !Array.isArray(manifest.participants)
  ) {
    errors.push("manifest.participants must be an array of participant objects");
  }
  const participantIds = participantActorIds(manifest.participants);
  result.actorSet.bound = participantIds.size > 0;
  if (!result.actorSet.bound) {
    notes.push(
      "manifest.participants empty: chain actors are not bound to a declared participant set",
    );
  }
  // spec/manifest.md field rules (A06): every DECLARED actor_id must sit
  // in the closed namespace set (human/ai/system/capsule, non-empty id).
  // Unlike an empty participants[], an uninterpretable declared entry is
  // not a weaker claim — it is a malformed one, rejected fail-closed.
  // Conformance vector: spec/vectors/chain-rules (invalid-actor-namespace).
  for (const problem of participantActorIdProblems(manifest.participants)) {
    errors.push(`manifest.${problem}`);
  }

  // Format / version gate (spec/versioning.md). The observed version is
  // a REPORTED FACT; whether it is acceptable to this deployment is host
  // policy (acceptVersions), reported and never decided here. An unknown
  // version fails closed EARLY with only the version diagnosis — running
  // the wrong era's rules would bury "this verifier is too old" under
  // hash-mismatch noise indistinguishable from tampering.
  const versionClass = classifyVersion(manifest.format?.version);
  const capsuleVersion = versionClass.status === "known" ? versionClass.observed : null;
  result.formatVersion = {
    observed: versionClass.observed,
    supported: versionClass.status === "known",
    status: versionClass.status,
    suite: versionClass.status === "known" ? SUITES[versionClass.observed] : null,
    acceptedByPolicy: null,
  };
  if (versionClass.status === "invalid") {
    errors.push(
      `manifest.format.version: not a '<major>.<minor>' version string, got ${JSON.stringify(manifest.format?.version)}`,
    );
    return result;
  }
  if (versionClass.status !== "known") {
    errors.push(
      unsupportedVersionMessage("manifest.format.version", versionClass.observed, versionClass.status),
    );
    return result;
  }
  const envVersionClass = classifyVersion(envelope.version);
  if (envVersionClass.status !== "known") {
    errors.push(
      envVersionClass.status === "invalid"
        ? `envelope.version: not a '<major>.<minor>' version string, got ${JSON.stringify(envelope.version)}`
        : unsupportedVersionMessage("envelope.version", envelope.version, envVersionClass.status),
    );
    // The formatVersion channel reports the MANIFEST's observed version
    // (possibly known); the refusal class rides explicitly.
    return deriveVerdict(result, {
      versionRefusal: envVersionClass.status === "invalid" ? null : envVersionClass.status,
    });
  }
  if (envelope.version !== capsuleVersion) {
    // Two KNOWN versions that disagree: the capsule is ambiguous about
    // which era's rules bind it. Fail closed before applying either.
    errors.push(
      `envelope.version '${envelope.version}' does not match manifest.format.version '${capsuleVersion}'`,
    );
    return result;
  }

  // Profile gate (spec/profiles.md): version gate first, profile gate
  // second, nothing else until both pass. The CapsuleReader enforces
  // this at open; re-deriving it here keeps verification total over
  // hand-constructed readers and pins refusal exclusivity — after a
  // profile refusal the profile diagnosis is the only error carried and
  // every other channel holds its fail-closed default.
  const profileClass = classifyProfile(manifest.format?.profile, envelope.profile);
  result.profile = {
    observed: profileClass.observed,
    observedVersion: profileClass.observedVersion,
    declared: profileClass.declared,
    effective: profileClass.effective,
    effectiveVersion: profileClass.effectiveVersion,
    supported: profileClass.supported,
    status: profileClass.status,
    acceptedByPolicy: null,
  };
  if (profileClass.status !== "default" && profileClass.status !== "supported") {
    if (profileClass.status === "invalid") {
      errors.push(...profileClass.problems);
    } else if (profileClass.status === "mismatched") {
      errors.push(
        profileMismatchMessage(profileClass.normalized.manifest, profileClass.normalized.envelope),
      );
    } else {
      errors.push(unsupportedProfileMessage(profileClass.observed, profileClass.observedVersion));
    }
    // Suite honesty: the suite fact is a statement about the rules
    // governing THIS capsule; after a profile-gate refusal none is known.
    result.formatVersion.suite = null;
    return deriveVerdict(result);
  }
  if (
    profileClass.effective !== DEFAULT_PROFILE.id ||
    profileClass.effectiveVersion !== DEFAULT_PROFILE.version
  ) {
    // Unreachable while the reference table holds one row; kept so a
    // grown table cannot report the default suite under alternate rules.
    result.formatVersion.suite = null;
  }
  // Host policy: DECLARED accepted profiles. Reported, never decided —
  // same shape as acceptVersions and signer allowlists.
  if (Array.isArray(options.acceptProfiles)) {
    result.profile.acceptedByPolicy = options.acceptProfiles.includes(profileClass.effective);
    if (!result.profile.acceptedByPolicy) {
      notes.push(
        `host policy: effective profile ${profileClass.effective}/${profileClass.effectiveVersion} is not in the declared accepted set [${options.acceptProfiles.join(", ")}]`,
      );
    }
  }

  // Host policy: DECLARED accepted versions. Reported, never decided —
  // integrity ok is unaffected, exactly as with signer allowlists.
  if (Array.isArray(options.acceptVersions)) {
    result.formatVersion.acceptedByPolicy = options.acceptVersions.includes(capsuleVersion);
    if (!result.formatVersion.acceptedByPolicy) {
      notes.push(
        `host policy: observed format version ${capsuleVersion} is not in the declared accepted set [${options.acceptVersions.join(", ")}]`,
      );
    }
  }

  // Capsule identity
  try {
    const expectedId = computeCapsuleId(
      hexToBytes(manifest.originator.public_key),
      manifest.first_event_hash,
      capsuleVersion,
    );
    if (expectedId !== manifest.id) {
      errors.push(`manifest.id mismatch: stored ${manifest.id}, expected ${expectedId}`);
    }
    if (expectedId !== envelope.capsule_id) {
      errors.push(`envelope.capsule_id mismatch: ${envelope.capsule_id} vs derived ${expectedId}`);
    }
  } catch (err) {
    errors.push(`capsule_id derivation failed: ${err.message}`);
  }

  // Semantic binding: manifest.first_event_hash is the capsule_id input;
  // envelope.first_event_hash is what the chain walk below is checked
  // against. spec/manifest.md and spec/envelope.md both pin them to the
  // hash of chain event 1, so they must be equal — otherwise capsule_id
  // (the identity federation attestations bind to) names a chain the
  // capsule does not carry. Null==null is the legal empty-chain shape;
  // the chain walk enforces anchor/event-count consistency separately.
  if ((manifest.first_event_hash ?? null) !== (envelope.first_event_hash ?? null)) {
    errors.push(
      `manifest.first_event_hash mismatch: ${manifest.first_event_hash} vs envelope.first_event_hash ${envelope.first_event_hash}`,
    );
  }

  // Manifest hash. Unknown members are hashed too (spec/manifest.md), so a
  // hostile value in one — 1e999 parses as Infinity, which JCS refuses —
  // must surface as a recompute failure, not an exception. Mirrors sdk-py.
  try {
    const expectedManifestHash = manifestHash(manifest);
    if (expectedManifestHash !== envelope.manifest_hash) {
      errors.push(
        `envelope.manifest_hash mismatch: ${envelope.manifest_hash} vs recomputed ${expectedManifestHash}`,
      );
    }
  } catch (err) {
    errors.push(`manifest hash recompute failed: ${err.message}`);
  }

  // Content index. content.enc is excluded only when the capsule declares a
  // cipher (bound instead by envelope.encrypted_blob_hash). We key off the
  // signed envelope.cipher, not file presence: an attacker who injects a
  // content.enc into a plain (cipher="none") capsule cannot force its
  // exclusion without breaking the envelope signature, so the stray blob is
  // indexed here like any other file. Indexing alone is accounting, not the
  // rejection — a fully re-derived index can cover the blob and still pass
  // this check — the blob-shape check below rejects any content.enc the
  // SIGNED envelope does not account for, indexed or not.
  const excluded = contentIndexExclusions(envelope.cipher !== "none");
  const files = reader.files_();
  const indexFiles = new Map();
  for (const [path, bytes] of files.entries()) {
    if (excluded.has(path)) continue;
    indexFiles.set(path, bytes);
  }
  const recomputedIndex = buildContentIndex(indexFiles, excluded);
  result.contentIndex.ok = true;
  if (recomputedIndex.index_hash !== manifest.content_index.index_hash) {
    result.contentIndex.ok = false;
    result.contentIndex.errors.push("manifest.content_index.index_hash does not match recomputed");
  }
  // Per-file verification too
  const stored = new Map(manifest.content_index.files.map((f) => [f.path, f.sha256]));
  for (const f of recomputedIndex.files) {
    const expected = stored.get(f.path);
    if (!expected) {
      result.contentIndex.errors.push(`file present but not in manifest index: ${f.path}`);
    } else if (expected !== f.sha256) {
      result.contentIndex.errors.push(`file hash mismatch: ${f.path}`);
    }
  }
  for (const f of manifest.content_index.files) {
    if (!recomputedIndex.files.find((g) => g.path === f.path)) {
      result.contentIndex.errors.push(`file in manifest index but missing from package: ${f.path}`);
    }
  }
  if (recomputedIndex.index_hash !== envelope.content_index_hash) {
    result.contentIndex.ok = false;
    result.contentIndex.errors.push(
      `envelope.content_index_hash mismatch: ${envelope.content_index_hash} vs recomputed ${recomputedIndex.index_hash}`,
    );
  }
  if (result.contentIndex.errors.length > 0) result.contentIndex.ok = false;

  // Encrypted-blob shape (mirrors verifier-rust). Two legal shapes:
  //   - Plain:     no content.enc, cipher === "none", encrypted_blob_hash null.
  //   - Encrypted: content.enc present, cipher !== "none",
  //                encrypted_blob_hash === sha256(content.enc).
  // The checks are deliberately keyed off blob PRESENCE, never off
  // reader.isEncrypted() (the signed cipher AND the blob): that conjunction
  // is false exactly when the two halves disagree — a smuggled content.enc
  // on a cipher='none' capsule, or a declared cipher with no blob — which
  // are precisely the capsules that must fail here.
  if (files.has("content.enc")) {
    const storedBlobHash = envelope.encrypted_blob_hash ?? null;
    if (storedBlobHash === null) {
      errors.push("encrypted blob present but envelope.encrypted_blob_hash=null");
    } else {
      const recomputedBlobHash = sha256Hex(files.get("content.enc"));
      if (recomputedBlobHash !== storedBlobHash) {
        errors.push(
          `envelope.encrypted_blob_hash mismatch: ${storedBlobHash} vs recomputed ${recomputedBlobHash}`,
        );
      }
    }
    if (envelope.cipher === "none") {
      errors.push("encrypted blob present but envelope.cipher='none'");
    }
  } else {
    if (envelope.encrypted_blob_hash !== null) {
      errors.push("plain capsule must have envelope.encrypted_blob_hash=null");
    }
    if (envelope.cipher !== "none") {
      errors.push(`plain capsule must have cipher='none', got '${envelope.cipher}'`);
    }
  }

  // Encryption declaration. spec/manifest.md fixes manifest.encryption as
  // null for plain capsules and { metadata_path, cipher } for encrypted
  // ones. The SIGNED envelope.cipher is authoritative; the manifest
  // declaration must agree with it, and the declared metadata_path must
  // resolve to a file that exists AND is covered by the content index.
  const declaredEncryption = manifest.encryption ?? null;
  if (envelope.cipher === "none") {
    if (declaredEncryption !== null) {
      errors.push("manifest.encryption must be null when envelope.cipher is 'none'");
    }
  } else if (declaredEncryption === null || typeof declaredEncryption !== "object") {
    errors.push(
      `manifest.encryption must be an object when envelope.cipher is '${envelope.cipher}'`,
    );
  } else {
    if (declaredEncryption.cipher !== envelope.cipher) {
      errors.push(
        `manifest.encryption.cipher mismatch: ${JSON.stringify(declaredEncryption.cipher)} vs envelope.cipher '${envelope.cipher}'`,
      );
    }
    const metadataPath = declaredEncryption.metadata_path;
    if (typeof metadataPath !== "string" || metadataPath.length === 0) {
      errors.push("manifest.encryption.metadata_path must be a non-empty string");
    } else if (!files.has(metadataPath)) {
      errors.push(`manifest.encryption.metadata_path missing from capsule: ${metadataPath}`);
    } else if (!manifest.content_index.files.some((f) => f.path === metadataPath)) {
      errors.push(
        `manifest.encryption.metadata_path not covered by content index: ${metadataPath}`,
      );
    }
  }

  // Chain
  if (!reader.isEncrypted()) {
    let events = null;
    if (!files.has("chain/events.jsonl")) {
      // The chain FILE is required even when it carries no events; its
      // absence is a container defect, not a weaker claim.
      result.chain = { ok: false, errors: [{ seq: 0, message: "missing chain/events.jsonl" }] };
    } else {
      try {
        events = reader.events();
      } catch (err) {
        result.chain = { ok: false, errors: [{ seq: 0, message: err.message }] };
      }
    }
    if (events !== null && events.length === 0) {
      // Empty chain is LEGAL — the weakest honest shape (a template or
      // draft capsule that carries no events yet). But the capsule must
      // not claim chain anchors it does not have: with zero events there
      // is nothing for first_event_hash / entry_hash to commit to, so
      // all three anchor claims MUST be null. A capsule claiming an
      // anchor over an empty chain is lying about its own bytes — the
      // integrity violation to reject (spec/chain.md "Empty chains").
      result.chain = {
        ok: true,
        errors: [],
        note: EMPTY_CHAIN_NOTE,
      };
      notes.push(EMPTY_CHAIN_NOTE);
      if (envelope.first_event_hash !== null) {
        errors.push(
          `envelope.first_event_hash must be null when the chain has no events; got ${envelope.first_event_hash}`,
        );
      }
      if (envelope.entry_hash !== null) {
        errors.push(
          `envelope.entry_hash must be null when the chain has no events; got ${envelope.entry_hash}`,
        );
      }
      if (manifest.first_event_hash !== null) {
        errors.push(
          `manifest.first_event_hash must be null when the chain has no events; got ${manifest.first_event_hash}`,
        );
      }
    } else if (events !== null) {
      result.chain = verifyChain(events, { participants: manifest.participants });
      const { firstEventHash, entryHash } = firstAndEntryHash(events);
      if (firstEventHash !== envelope.first_event_hash) {
        errors.push(
          `envelope.first_event_hash mismatch: ${envelope.first_event_hash} vs ${firstEventHash}`,
        );
      }
      if (entryHash !== envelope.entry_hash) {
        errors.push(`envelope.entry_hash mismatch: ${envelope.entry_hash} vs ${entryHash}`);
      }
      if (manifest.first_event_hash == null) {
        errors.push("manifest.first_event_hash must not be null when the chain has events");
      }
    }
  } else {
    // Encrypted outer cannot verify chain without decrypt; defer to L3.
    result.chain = { ok: true, errors: [], note: DEFERRED_CHAIN_NOTE };
  }

  // Envelope signatures
  const envelopeResult = verifyEnvelopeSignatures(envelope);
  result.envelope.ok = envelopeResult.ok;
  if (!envelopeResult.ok && envelopeResult.note) errors.push(envelopeResult.note);
  result.envelope.signers = envelopeResult.signers.map((s) => ({
    ...s,
    trusted: s.valid && allowlist.has(String(s.public_key ?? "").toLowerCase()),
  }));
  // A bad signature is otherwise only visible as valid:false nested in
  // envelope.signers[i]; every other failure class produces a displayable
  // message, so give this one an error too.
  result.envelope.signers.forEach((s, i) => {
    if (!s.valid) {
      errors.push(
        `envelope.signers[${i}] signature invalid (role '${s.role}', public_key ${s.public_key})`,
      );
    }
  });
  // DISTINCT trusted keys, never rows: the same key signing under two roles
  // is one trusted key, and duplicate rows must never inflate a quorum.
  result.trustedSignerCount = new Set(
    result.envelope.signers.filter((s) => s.trusted).map((s) => s.public_key.toLowerCase()),
  ).size;

  // Signer-set binding: PRESENCE BINDS, ABSENCE REPORTS.
  // A present manifest.signer_commitment must equal the normalized
  // envelope signer set exactly (integrity invariant, fail-closed). An
  // absent commitment downgrades the reported assurance — it never fails
  // verification, because a capsule that does not assert signer-set
  // binding is making a weaker claim honestly (templates, other writers).
  const commitment = manifest.signer_commitment;
  if (commitment === undefined) {
    notes.push(
      "manifest.signer_commitment absent: the signer set is not bound by the seal",
    );
  } else {
    result.signerSet.bound = true;
    const scErrors = [];
    const problems = signerCommitmentProblems(commitment);
    if (problems.length > 0) {
      for (const p of problems) scErrors.push(`manifest.signer_commitment malformed: ${p}`);
    } else {
      const actual = (Array.isArray(envelope.signers) ? envelope.signers : [])
        .map((s) => ({
          role: typeof s?.role === "string" ? s.role : "",
          public_key: typeof s?.public_key === "string" ? s.public_key.toLowerCase() : "",
        }))
        .sort(compareCommitmentMembers);
      // Merge-walk both sorted member lists; report every difference by name.
      let i = 0;
      let j = 0;
      while (i < commitment.length || j < actual.length) {
        const cmp =
          i >= commitment.length ? 1 : j >= actual.length ? -1
          : compareCommitmentMembers(commitment[i], actual[j]);
        if (cmp === 0) {
          i++; j++;
        } else if (cmp < 0) {
          const m = commitment[i++];
          scErrors.push(
            `signer_commitment mismatch: no envelope signer matches committed member (role=${m.role}, public_key=${m.public_key})`,
          );
        } else {
          const m = actual[j++];
          scErrors.push(
            `signer_commitment mismatch: envelope signer not committed (role=${m.role}, public_key=${m.public_key})`,
          );
        }
      }
    }
    if (scErrors.length > 0) {
      result.signerSet.ok = false;
      result.signerSet.errors = scErrors;
      errors.push(...scErrors);
    }
  }

  // Originator binding (invariant): the manifest names an originator key —
  // that key must actually have sealed the capsule with a valid envelope
  // signature under role "originator". A manifest naming an originator who
  // never signed is the capsule asserting something false about itself.
  {
    const originatorKey =
      typeof manifest.originator?.public_key === "string"
        ? manifest.originator.public_key.toLowerCase()
        : null;
    const originatorSigned = envelopeResult.signers.some(
      (s) =>
        s.role === "originator" &&
        s.valid &&
        typeof s.public_key === "string" &&
        s.public_key.toLowerCase() === originatorKey,
    );
    if (!originatorSigned) {
      errors.push(
        `originator binding: manifest.originator.public_key ${originatorKey ?? "(missing)"} has no valid envelope signature with role 'originator'`,
      );
    }
  }

  // L3: cross-check inner against outer envelope
  if (options.outerEnvelope) {
    const outer = options.outerEnvelope;
    if (outer.capsule_id !== envelope.capsule_id) {
      errors.push("L3: inner.capsule_id does not match outer.capsule_id");
    }
    if (outer.first_event_hash !== envelope.first_event_hash) {
      errors.push("L3: inner.first_event_hash does not match outer.first_event_hash");
    }
    if (outer.entry_hash !== envelope.entry_hash) {
      errors.push("L3: inner.entry_hash does not match outer.entry_hash");
    }
  }

  result.ok =
    errors.length === 0 &&
    result.contentIndex.ok &&
    result.chain.ok &&
    result.envelope.ok;

  // Skill trust: DERIVED from this verification, never read from the
  // capsule. manifest.skill_trust does not exist in v0.6 — a capsule
  // carrying one (earlier drafts, hostile authors) contributes an inert
  // unknown member to the hash and NOTHING here (spec/trust.md).
  // Derived AFTER result.ok so the overall verdict is an input: a
  // failing capsule never classifies anything signed.
  result.skillTrust = deriveSkillTrust({
    files,
    manifest,
    verdictOk: result.ok,
    contentIndexOk: result.contentIndex.ok,
    envelopeOk: result.envelope.ok,
    trustedSignerCount: result.trustedSignerCount,
  });

  // Advisory notes: a PASS with trusted=false is never silent about why.
  // The unmatched case must never get LESS warning than the no-policy
  // case (wording matches verifier-rust).
  if (allowlist.size === 0) {
    notes.push("no allowlist provided; trusted=false for all signers regardless of signature validity");
  } else if (result.trustedSignerCount === 0) {
    notes.push("allowlist provided but matched no signer; trusted=false for all signers");
  }

  // Normalized verdict surface (spec/results.md): derived last, from
  // the facts above — the only path that can reach verdict "valid".
  return deriveVerdict(result, { allowlistSize: allowlist.size });
}

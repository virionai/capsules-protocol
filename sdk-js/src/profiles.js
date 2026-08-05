// Profile declaration policy (spec/profiles.md).
//
// A capsule may DECLARE the verification profile that governs it —
// `manifest.format.profile` and `envelope.profile`, mirroring the
// `format.version` / `envelope.version` dyad. A verifier keeps a table
// of the profiles it implements (keyed selection, exactly like the
// known-version table) and:
//
//   - Treats ABSENCE of a declaration in a 0.6/0.7 capsule as the
//     default profile `v0.6-suite` version `1.0`, permanently — the
//     mirror of the algorithm-suite pin in spec/versioning.md.
//   - Requires the two documents' NORMALIZED declarations (absence =
//     default) to agree; a capsule whose pairs differ is ambiguous
//     about which rules bind it and fails closed BEFORE any profile's
//     rules are applied (`profile_mismatch` — a defect of the capsule).
//   - FAILS CLOSED on a declared (id, version) pair outside the table,
//     with a diagnosis distinct from both tampering and malformation:
//     `unsupported_profile` is a limitation of the verifier, never a
//     defect of the capsule.
//   - Treats a present declaration that violates the closed object
//     shape or the identifier grammar as a MALFORMED document
//     (invalid_manifest_shape), not a support gap.
//
// The gate runs at OPEN stage, after the version gate and before
// anything else: a reader that cannot establish its governing rules
// cannot meaningfully construct at all, and applying the wrong
// profile's rules would manufacture mismatch errors indistinguishable
// from tampering — versioning.md's confusion, reproduced on the
// profile axis.

/**
 * The default profile: the envelope.md verification/encryption
 * procedure of the capsule's declared era with the v0.6 algorithm suite
 * of versioning.md. The id deliberately matches the suite fact
 * (`v0.6`) verifiers already report. Frozen forever — the absence rule
 * makes this spelling permanent.
 */
export const DEFAULT_PROFILE = Object.freeze({ id: "v0.6-suite", version: "1.0" });

/**
 * Every (id, version) profile row this implementation applies. Exact-
 * match on the pair — no ranges, no compatibility semantics. A profile
 * once supported is supported forever (the archival rule applied to
 * profiles), and the default row of every known era is always present.
 */
export const SUPPORTED_PROFILES = Object.freeze([DEFAULT_PROFILE]);

// profile-id = lowletter *63( lowletter / DIGIT / "-" / "." )
// 1..64 bytes, lowercase-only, no trailing "-" or "." (no leading one
// by construction: the first byte is a letter).
const PROFILE_ID_GRAMMAR = /^[a-z][a-z0-9.-]{0,63}$/;
// The vendor fence: an id beginning `x-` MUST be vendor-scoped
// `x-<vendor>-<name>`; ids not beginning `x-` are reserved to the spec,
// exactly like non-`x-` member keys.
const VENDOR_ID_GRAMMAR = /^x-[a-z0-9.]+-[a-z0-9.-]+$/;
// profile-ver: the SAME grammar as format versions (versioning.md).
const PROFILE_VERSION_GRAMMAR = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;

/** True iff `id` satisfies the spec/profiles.md identifier grammar. */
export function isValidProfileId(id) {
  if (typeof id !== "string" || !PROFILE_ID_GRAMMAR.test(id)) return false;
  if (id.endsWith("-") || id.endsWith(".")) return false;
  if (id.startsWith("x-") && !VENDOR_ID_GRAMMAR.test(id)) return false;
  return true;
}

/** True iff `version` satisfies the profile-version grammar. */
export function isValidProfileVersion(version) {
  return typeof version === "string" && PROFILE_VERSION_GRAMMAR.test(version);
}

/**
 * Shape problems for ONE document's present profile declaration.
 * Returns [] for a well-formed declaration; every message is prefixed
 * with the offending field path (the invalid_manifest_shape idiom).
 * `envelope: true` applies the envelope-copy rules (no `params`:
 * params are single-sourced in the manifest so no second copy can
 * diverge).
 */
export function profileDeclarationProblems(value, path, { envelope = false } = {}) {
  const problems = [];
  if (value === null) {
    // null is NOT a declaration: the honest way to not declare is to
    // omit, and a second spelling of absence is a known typed-decoder
    // divergence across lanes.
    problems.push(
      `${path} must be an object { id, version${envelope ? "" : ", params?"} }; ` +
        `null is not a declaration — omit the member to not declare`,
    );
    return problems;
  }
  if (typeof value !== "object" || Array.isArray(value)) {
    problems.push(
      `${path} must be an object { id, version${envelope ? "" : ", params?"} }, ` +
        `got ${JSON.stringify(value)}`,
    );
    return problems;
  }
  // The object is CLOSED: an uninterpretable member in the rule
  // SELECTOR is the capsule asserting something meaningless about what
  // governs it. Vendor freight rides in manifest params or x- members.
  const allowed = envelope ? ["id", "version"] : ["id", "version", "params"];
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      problems.push(
        key === "params" && envelope
          ? `${path}.params is not allowed: params are single-sourced in manifest.format.profile`
          : `${path}.${key} is not a member of the closed profile object ` +
              `(exactly: ${allowed.join(", ")})`,
      );
    }
  }
  if (!isValidProfileId(value.id)) {
    problems.push(
      `${path}.id must be a profile identifier (1-64 bytes, lowercase letter first, ` +
        `then lowercase letters, digits, '-' or '.'; 'x-' ids vendor-scoped as x-<vendor>-<name>), ` +
        `got ${JSON.stringify(value.id)}`,
    );
  }
  if (!isValidProfileVersion(value.version)) {
    problems.push(
      `${path}.version must be a '<major>.<minor>' version string, got ${JSON.stringify(value.version)}`,
    );
  }
  if (!envelope && "params" in value) {
    const params = value.params;
    if (params === null || typeof params !== "object" || Array.isArray(params)) {
      problems.push(`${path}.params must be a JSON object, got ${JSON.stringify(params)}`);
    }
  }
  return problems;
}

function bestEffortObserved(manifestDecl, envelopeDecl) {
  // The declared id/version as read — reported even on refusal and even
  // when invalid (the observed fact). On a dyad mismatch these are the
  // manifest values; when the manifest is silent, the envelope's.
  const source =
    manifestDecl !== undefined && manifestDecl !== null && typeof manifestDecl === "object"
      ? manifestDecl
      : envelopeDecl !== undefined && envelopeDecl !== null && typeof envelopeDecl === "object"
        ? envelopeDecl
        : null;
  return {
    observed: typeof source?.id === "string" ? source.id : null,
    observedVersion: typeof source?.version === "string" ? source.version : null,
  };
}

/**
 * Classify the (manifest, envelope) profile declaration dyad against
 * this implementation's table. Pass the raw member values (`undefined`
 * when absent). Pure and total; never throws.
 *
 * Returns { status, observed, observedVersion, declared, effective,
 * effectiveVersion, supported, problems }, where `status` is one of the
 * closed vocabulary of spec/profiles.md:
 *   "default"     — no declaration, or the explicit era default:
 *                   default rules apply (explicit default is exactly
 *                   equivalent to absence — a redundant claim made
 *                   honestly).
 *   "supported"   — declared alternate profile this reader implements
 *                   (unreachable in-era: the reference table holds one
 *                   row).
 *   "unsupported" — declared alternate the reader does not implement:
 *                   a limitation of the verifier, not a defect of the
 *                   capsule.
 *   "mismatched"  — normalized declarations disagree: the capsule is
 *                   ambiguous about which rules bind it (a defect).
 *   "invalid"     — a present member violates the closed shape or the
 *                   grammar: a malformed document.
 *
 * The caller is responsible for gate ORDER: classify only after both
 * documents pass the version gate (the absence rule is era-keyed).
 */
export function classifyProfile(manifestDecl, envelopeDecl) {
  const declared = manifestDecl !== undefined || envelopeDecl !== undefined;
  const { observed, observedVersion } = bestEffortObserved(manifestDecl, envelopeDecl);
  const base = {
    observed,
    observedVersion,
    declared,
    effective: null,
    effectiveVersion: null,
    supported: false,
    problems: [],
  };

  const problems = [
    ...(manifestDecl === undefined
      ? []
      : profileDeclarationProblems(manifestDecl, "manifest.format.profile")),
    ...(envelopeDecl === undefined
      ? []
      : profileDeclarationProblems(envelopeDecl, "envelope.profile", { envelope: true })),
  ];
  if (problems.length > 0) return { ...base, status: "invalid", problems };

  // Normalized dyad equality: absence means the era default, so the
  // default declared in exactly one document is coherent (both readings
  // mean the default) — refusing it would punish a truthful statement.
  const m = manifestDecl === undefined ? DEFAULT_PROFILE : { id: manifestDecl.id, version: manifestDecl.version };
  const e = envelopeDecl === undefined ? DEFAULT_PROFILE : { id: envelopeDecl.id, version: envelopeDecl.version };
  if (m.id !== e.id || m.version !== e.version) {
    // Mismatch BEFORE table lookup: the effective declaration does not
    // exist until the documents agree, and reporting a mismatched
    // capsule as "unsupported" would hand the auditor a false
    // remediation ("find a better verifier" for a defective capsule).
    return { ...base, status: "mismatched", normalized: { manifest: m, envelope: e } };
  }

  const row = SUPPORTED_PROFILES.find((p) => p.id === m.id && p.version === m.version);
  if (!row) {
    return { ...base, observed: m.id, observedVersion: m.version, status: "unsupported" };
  }
  const isDefault = m.id === DEFAULT_PROFILE.id && m.version === DEFAULT_PROFILE.version;
  return {
    ...base,
    status: isDefault ? "default" : "supported",
    effective: m.id,
    effectiveVersion: m.version,
    supported: true,
  };
}

/** Cross-lane refusal wording (spec/profiles.md, spec/results.md). */
export function unsupportedProfileMessage(id, version) {
  return (
    `profile '${id}' version '${version}' is not supported by this verifier ` +
    `(supported: ${SUPPORTED_PROFILES.map((p) => `${p.id}/${p.version}`).join(", ")}); ` +
    `this is a limitation of the verifier, not corruption of the capsule — ` +
    `verify it with an implementation of that profile`
  );
}

/** Cross-lane mismatch wording: both NORMALIZED pairs quoted. */
export function profileMismatchMessage(manifestPair, envelopePair) {
  const fmt = (p) => `'${p.id}' version '${p.version}'`;
  return (
    `envelope.profile does not match manifest.format.profile: ` +
    `manifest normalizes to ${fmt(manifestPair)}, envelope normalizes to ${fmt(envelopePair)} ` +
    `(absence means the era default ${DEFAULT_PROFILE.id}/${DEFAULT_PROFILE.version}); ` +
    `the capsule is ambiguous about which rules bind it`
  );
}

/**
 * Common base for typed profile-gate refusals: every subclass carries
 * the full classification so a fail-closed verify result can populate
 * its profile channel from the error alone.
 */
export class ProfileError extends Error {
  constructor(message, classification) {
    super(message);
    this.name = "ProfileError";
    this.observed = classification.observed;
    this.observedVersion = classification.observedVersion;
    this.classification = classification;
  }
}

/**
 * A declared (id, version) pair outside this verifier's table. Distinct
 * from UnsupportedVersionError and from malformed-shape errors on
 * purpose: an operator must be able to tell "verify this with an
 * implementation of that profile" apart from both "this verifier is too
 * old" and "this capsule is corrupt".
 */
export class UnsupportedProfileError extends ProfileError {
  constructor(message, classification) {
    super(message, classification);
    this.name = "UnsupportedProfileError";
  }
}

/** The two documents' normalized declarations disagree (a capsule defect). */
export class ProfileMismatchError extends ProfileError {
  constructor(message, classification) {
    super(message, classification);
    this.name = "ProfileMismatchError";
  }
}

/** A present declaration violating the closed shape or grammar (malformed). */
export class InvalidProfileError extends ProfileError {
  constructor(message, classification) {
    super(message, classification);
    this.name = "InvalidProfileError";
  }
}

/**
 * The open-stage profile gate. Call AFTER both documents pass the
 * version gate. Throws a typed ProfileError subclass on refusal;
 * returns the classification when the capsule's effective profile is
 * one this implementation applies.
 */
export function requireSupportedProfile(manifest, envelope) {
  const cls = classifyProfile(manifest?.format?.profile, envelope?.profile);
  if (cls.status === "invalid") {
    // Field-path-prefixed shape wording (the invalid_manifest_shape
    // idiom) — never the word "unsupported": malformed is a defect of
    // the capsule, unsupported a limitation of the verifier.
    throw new InvalidProfileError(cls.problems.join("; "), cls);
  }
  if (cls.status === "mismatched") {
    throw new ProfileMismatchError(
      profileMismatchMessage(cls.normalized.manifest, cls.normalized.envelope),
      cls,
    );
  }
  if (cls.status === "unsupported") {
    throw new UnsupportedProfileError(
      unsupportedProfileMessage(cls.observed, cls.observedVersion),
      cls,
    );
  }
  return cls;
}

// Version-compatibility policy (spec/versioning.md).
//
// A capsule DECLARES its format era (manifest.format.version and
// envelope.version), and every domain-separation string embeds that
// version. A verifier therefore keeps a table of the versions it knows —
// keyed selection, not a single current constant — and:
//
//   - OPENS any known version under that era's rules and constants, and
//     reports the observed version as a fact on the verify result. A
//     version once supported is supported forever (the archival profile:
//     sealed today, opened by an underwriter in three years).
//   - FAILS CLOSED on an unknown version, with a diagnosis distinct from
//     tamper detection: "this verifier is too old" (unknown_newer) is not
//     "this capsule is corrupt", and neither is unknown_older.
//   - Treats a string that is not <major>.<minor> at all as a shape
//     violation (invalid), not a version-support gap.
//
// The SDK reports; the host decides. Hosts declare an accepted range via
// verifyCapsule's acceptVersions option and read
// result.formatVersion.acceptedByPolicy.

/**
 * Every format version this implementation knows, oldest → newest. A
 * version is never removed from this list (spec/versioning.md: dropping a
 * version a verifier once knew is a conformance violation).
 */
export const KNOWN_VERSIONS = ["0.6"];

/** The version this implementation SEALS at. */
export const CURRENT_VERSION = "0.6";

/**
 * Per-era algorithm suite identifiers (spec/versioning.md "Algorithm
 * suites"). A v0.6 capsule names no algorithm anywhere in its bytes;
 * the spec pins the absence of algorithm identifiers to this suite,
 * permanently: Ed25519 / SHA-256 / JCS (RFC 8785) / X25519 +
 * HKDF-SHA-256 + ChaCha20-Poly1305.
 */
export const SUITES = { "0.6": "v0.6" };

// <major>.<minor>, decimal, no leading zeros. This is the version grammar;
// anything else is a malformed document, not an unknown era.
const VERSION_GRAMMAR = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;

function parseVersion(v) {
  const m = typeof v === "string" ? VERSION_GRAMMAR.exec(v) : null;
  return m ? [Number(m[1]), Number(m[2])] : null;
}

function compareVersions(a, b) {
  return a[0] - b[0] || a[1] - b[1];
}

const NEWEST_KNOWN = KNOWN_VERSIONS[KNOWN_VERSIONS.length - 1];
const OLDEST_KNOWN = KNOWN_VERSIONS[0];

/**
 * Classify a declared version string against the known-version table.
 * Returns { observed, status } where status is one of the closed
 * vocabulary "known" | "unknown_newer" | "unknown_older" | "invalid".
 * `observed` is the declared string when it IS a string (reported even
 * for invalid values — it is still the observed fact), else null.
 */
export function classifyVersion(v) {
  const observed = typeof v === "string" ? v : null;
  const parsed = parseVersion(v);
  if (parsed === null) return { observed, status: "invalid" };
  if (KNOWN_VERSIONS.includes(v)) return { observed, status: "known" };
  const status =
    compareVersions(parsed, parseVersion(NEWEST_KNOWN)) > 0 ? "unknown_newer" : "unknown_older";
  return { observed, status };
}

/**
 * Thrown when a capsule declares a well-formed version this verifier
 * does not know. Distinct from a malformed-shape error on purpose: an
 * operator and an auditor must be able to tell "this verifier is too
 * old / too new for the capsule" apart from "this capsule is corrupt".
 */
export class UnsupportedVersionError extends Error {
  constructor(message, { observed, status }) {
    super(message);
    this.name = "UnsupportedVersionError";
    this.observed = observed;
    this.status = status;
  }
}

/**
 * Standard diagnosis wording. The needles
 * "newer than this verifier supports" and
 * "older than any version this verifier supports" are the cross-lane
 * conformance contract (spec/vectors/version-compat/).
 */
export function unsupportedVersionMessage(field, observed, status) {
  if (status === "unknown_newer") {
    return (
      `${field} '${observed}' is newer than this verifier supports ` +
      `(newest known: ${NEWEST_KNOWN}); this is a limitation of the verifier, ` +
      `not corruption of the capsule — verify it with a newer implementation`
    );
  }
  return (
    `${field} '${observed}' is older than any version this verifier supports ` +
    `(oldest known: ${OLDEST_KNOWN}); this is not evidence of tampering — ` +
    `verify it with an implementation that retains the ${observed} rules`
  );
}

/**
 * Gate used by the reader's shape checks: returns the version when it is
 * known; throws a shape-style Error (field-path prefixed, mapping to the
 * invalid_manifest_shape reason) for grammar violations, and an
 * UnsupportedVersionError for well-formed unknown versions.
 */
export function requireKnownVersion(field, v) {
  const cls = classifyVersion(v);
  if (cls.status === "known") return v;
  if (cls.status === "invalid") {
    throw new Error(
      `${field}: not a '<major>.<minor>' version string, got ${JSON.stringify(v)}`,
    );
  }
  throw new UnsupportedVersionError(unsupportedVersionMessage(field, v, cls.status), cls);
}

// ---------------------------------------------------------------------------
// Version-keyed domain-separation strings. A verifier that accepts a
// v0.6 capsule must retain the v0.6 strings forever, selected by the
// capsule's DECLARED version — never a single current constant.
// ---------------------------------------------------------------------------

/** `capsule-id-v<version>\0` — the capsule_id hash domain. */
export function idDomain(version) {
  return Buffer.from(`capsule-id-v${version}\x00`, "utf8");
}

/** `capsule-provenance-v<version>:<role>\0` — the signing-input domain. */
export function provenanceDomain(version, role) {
  return Buffer.from(`capsule-provenance-v${version}:${role}\x00`, "utf8");
}

/** `capsule-key-wrap-v<version>` — the HKDF info for recipient key wrap. */
export function keyWrapInfo(version) {
  return Buffer.from(`capsule-key-wrap-v${version}`, "utf8");
}

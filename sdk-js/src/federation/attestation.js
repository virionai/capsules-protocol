// Identity attestations: bind a capsule signer key to an external identity
// (e.g. a Clerk user/org) WITHOUT making capsule verification depend on any
// network service.
//
// Portability firewall: nothing in this file is called by verifyCapsule().
// Core cryptographic verification stays offline and issuer-agnostic. An
// attestation is an OPTIONAL overlay a verifier checks only if it holds the
// issuer's trust roots (public keys) — which are small and cacheable. A
// verifier without them still verifies the capsule math; it just cannot say
// "who, in the issuer's terms" signed it.
//
// Two algorithms are supported:
//   - "ed25519-jcs": native to the protocol. Signing input is
//     DOMAIN || JCS(attestation-without-signature), signed with Ed25519.
//     Mirrors the envelope-signing discipline (domain separation + JCS +
//     raw-byte signing, never hashing hex strings).
//   - JWT ("ES256"/"RS256"): a compact JWS as issued by Clerk. Verified
//     against a JWKS with node:crypto. See profiles/clerk.md.

import { jcs, bytesToHex, hexToBytes } from "../canonical.js";
import { ed25519Sign, ed25519Verify } from "../crypto.js";
import { createPublicKey, verify as nodeVerify } from "node:crypto";
import { normalizeIssuer } from "./issuer.js";
import { CURRENT_VERSION, classifyVersion } from "../versions.js";

export const ATTESTATION_TYP = "capsule-identity-attestation";

// Attestation-layer outcome vocabulary (spec/federation.md "Failure
// reporting"). These are the machine-readable statuses a host policy keys
// off; `attestation_unverified` is "unknown", not "negative".
export const ATTESTATION_VERIFIED = "attestation_verified";
export const ATTESTATION_UNVERIFIED = "attestation_unverified";
export const ATTESTATION_REJECTED = "attestation_rejected";

/**
 * `capsule-identity-attestation-v<spec_version>\0` — the ed25519-jcs
 * signing domain, keyed by the attestation's DECLARED `spec_version`
 * exactly like the capsule domain strings (spec/versioning.md): an
 * issuer signs at the current version, and a verifier reconstructs the
 * domain from the version the attestation itself declares — which is
 * inside the signed payload, so it cannot be replayed across eras —
 * keeping every previously issued attestation verifiable forever.
 */
export function attestationDomain(specVersion) {
  return Buffer.from(`capsule-identity-attestation-v${specVersion}\x00`, "utf8");
}

// The current-era domain, kept for API compatibility with callers that
// imported the old constant. New code should key on attestationDomain().
export const ATTESTATION_DOMAIN = attestationDomain(CURRENT_VERSION);

// ---------------------------------------------------------------------------
// base64url (JWT wire format) — no padding.
// ---------------------------------------------------------------------------
function b64uToBuf(s) {
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}
function bufToB64u(b) {
  return Buffer.from(b)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// ---------------------------------------------------------------------------
// Signing input for the native ed25519-jcs profile. The domain embeds the
// attestation's DECLARED spec_version (which is itself under the
// signature); the caller gates that version against the known table
// BEFORE trusting a signature check with it.
// ---------------------------------------------------------------------------
function attestationSigningInput(attestation) {
  const { signature: _ignored, ...rest } = attestation;
  return Buffer.concat([attestationDomain(attestation.spec_version), Buffer.from(jcs(rest))]);
}

/**
 * Produce a native ed25519-jcs identity attestation binding a capsule signer
 * key to a subject identity. Called at authoring time by an issuer that holds
 * an Ed25519 trust-root private key.
 *
 * claims must include: capsule_id, signer_public_key, signer_role, subject.
 * issued_at/expires_at are ISO-8601 UTC.
 */
export function signIdentityAttestation({
  claims,
  issuer,
  kid,
  ed25519PrivateKeyHex,
}) {
  for (const f of ["capsule_id", "signer_public_key", "signer_role", "subject"]) {
    if (claims?.[f] == null) throw new Error(`attestation claims require '${f}'`);
  }
  const attestation = {
    typ: ATTESTATION_TYP,
    spec_version: CURRENT_VERSION,
    alg: "ed25519-jcs",
    issuer,
    kid,
    claims,
  };
  const sig = ed25519Sign(hexToBytes(ed25519PrivateKeyHex), attestationSigningInput(attestation));
  attestation.signature = bytesToHex(sig);
  return attestation;
}

// ---------------------------------------------------------------------------
// Trust roots: a small, cacheable set of issuer public keys. Each entry is
//   { kid, alg, public_key_hex }         // alg "ed25519-jcs"
//   { kid, alg, jwk }                     // alg "ES256" | "RS256" (Clerk JWKS)
// A JWKS ({ keys: [...] }) is accepted directly for the JWT algorithms.
// ---------------------------------------------------------------------------
function normalizeTrustRoots(trustRoots) {
  if (!trustRoots) return [];
  const keys = Array.isArray(trustRoots) ? trustRoots : trustRoots.keys ?? [];
  const out = [];
  for (const k of keys) {
    if (!k || typeof k !== "object") continue;
    // Already a native entry ({kid, alg, public_key_hex}) or a pre-wrapped
    // JWK entry ({kid, alg, jwk}).
    if (k.public_key_hex || k.jwk) {
      out.push(k);
      continue;
    }
    if (!k.kty) continue;
    // A raw JWKS entry: Clerk's /.well-known/jwks.json, or a conforming
    // issuer publishing its NATIVE ed25519-jcs trust root as a standard
    // RFC 8037 OKP JWK. The native verify path needs raw key bytes, so
    // decode the base64url `x` coordinate into public_key_hex here.
    if (k.kty === "OKP") {
      if (k.crv !== "Ed25519") continue; // X25519/Ed448 are not attestation keys
      const raw = b64uToBuf(typeof k.x === "string" ? k.x : "");
      if (raw.length !== 32) continue;
      out.push({ kid: k.kid, alg: "ed25519-jcs", public_key_hex: bytesToHex(raw), jwk: k });
      continue;
    }
    out.push({ kid: k.kid, alg: k.alg ?? "ES256", jwk: k });
  }
  return out;
}

// `kid` selects the key (spec/profiles/clerk.md "Security notes"). A cached
// trust-root set may hold several keys — possibly from several issuers — so
// an unknown or ambiguous kid MUST fail closed. Falling back to "any cached
// key whose alg matches" would accept an attestation signed by any key in
// the set. A kid-less attestation resolves only when the set holds exactly
// one key of the requested algorithm.
function selectKey(roots, kid, alg) {
  const byAlg = roots.filter((k) => k.alg === alg);
  if (kid == null || kid === "") return byAlg.length === 1 ? byAlg[0] : null;
  const matches = byAlg.filter((k) => k.kid === kid);
  return matches.length === 1 ? matches[0] : null;
}

// Claim timestamps are RFC 3339 instants (spec/federation.md: "issued_at /
// expires_at are ISO-8601 UTC"). `Date.parse` returns NaN for garbage and
// every comparison against NaN is false — so an unparseable `expires_at`
// silently becomes "never expires". Parse strictly and fail closed.
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
function parseInstant(value) {
  if (typeof value !== "string" || !RFC3339.test(value)) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

// Project a JWT NumericDate (seconds since epoch) into an RFC 3339 instant.
// Anything that is not a representable finite number is passed through as a
// string so parseInstant rejects it — never crash on attacker-shaped input
// (Date#toISOString throws on out-of-range or NaN dates).
function jwtInstant(value) {
  if (value == null) return undefined;
  if (typeof value === "number" && Number.isFinite(value) && Math.abs(value) <= 8.64e12) {
    return new Date(value * 1000).toISOString();
  }
  return String(value);
}

const JWT_ALG_TO_NODE = {
  ES256: { dsaEncoding: "ieee-p1363", hash: "sha256" },
  ES384: { dsaEncoding: "ieee-p1363", hash: "sha384" },
  RS256: { hash: "sha256" },
  RS384: { hash: "sha384" },
};

/**
 * Verify a compact JWT (Clerk-issued or compatible) against trust roots /
 * a JWKS. Fully offline given the JWKS. Returns
 * { ok, claims, errors, trustRootMissing? }.
 *
 * `claims` is the DECODED token payload, returned on failure too so callers
 * can report diagnostics — it is authenticated only when ok === true and MUST
 * never be treated as verified identity otherwise.
 *
 * Checks signature, alg/kid selection, exp/nbf when present, and the
 * caller-supplied issuer and audience — both REQUIRED. `trustRootMissing`
 * marks the "no cached key for this kid" case, which is unknown rather than
 * negative (spec/federation.md "Failure reporting").
 */
export function verifyJwt(compact, { trustRoots, now, issuer, audience } = {}) {
  if (typeof issuer !== "string" || issuer.length === 0) {
    throw new TypeError(
      "verifyJwt requires an expected issuer: `iss` is checked against caller-supplied trust configuration, never against the token that carries it",
    );
  }
  if (typeof audience !== "string" || audience.length === 0) {
    throw new TypeError(
      "verifyJwt requires an expected audience: an attestation JWT is scoped to the verifying host (spec/profiles/clerk.md)",
    );
  }
  const errors = [];
  const nowSec = Math.floor((now instanceof Date ? now.getTime() : (now ?? Date.now())) / 1000);
  const parts = String(compact).split(".");
  if (parts.length !== 3) return { ok: false, claims: null, errors: ["jwt: not a compact JWS"] };
  let header, claims;
  try {
    header = JSON.parse(b64uToBuf(parts[0]).toString("utf8"));
    claims = JSON.parse(b64uToBuf(parts[1]).toString("utf8"));
  } catch (e) {
    return { ok: false, claims: null, errors: [`jwt: undecodable: ${e.message}`] };
  }
  const nodeAlg = JWT_ALG_TO_NODE[header.alg];
  if (!nodeAlg) return { ok: false, claims, errors: [`jwt: unsupported alg ${header.alg}`] };

  const roots = normalizeTrustRoots(trustRoots);
  const match = selectKey(roots, header.kid, header.alg);
  if (!match || !match.jwk) {
    // Not a negative signal: the host simply holds no key for this kid.
    return {
      ok: false,
      claims,
      errors: [`jwt: no trust-root key for kid=${header.kid}`],
      trustRootMissing: true,
    };
  }
  let signatureValid = false;
  try {
    const pub = createPublicKey({ key: match.jwk, format: "jwk" });
    const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`);
    const sig = b64uToBuf(parts[2]);
    signatureValid = nodeVerify(
      nodeAlg.hash,
      signingInput,
      nodeAlg.dsaEncoding ? { key: pub, dsaEncoding: nodeAlg.dsaEncoding } : pub,
      sig,
    );
  } catch (e) {
    return { ok: false, claims, errors: [`jwt: verify error: ${e.message}`] };
  }
  if (!signatureValid) errors.push("jwt: signature invalid");
  if (typeof claims.exp === "number" && nowSec >= claims.exp) errors.push("jwt: expired");
  if (typeof claims.nbf === "number" && nowSec < claims.nbf) errors.push("jwt: not yet valid");
  if (normalizeIssuer(claims.iss) !== normalizeIssuer(issuer)) {
    errors.push(`jwt: issuer mismatch (${claims.iss})`);
  }
  const aud = Array.isArray(claims.aud) ? claims.aud : claims.aud == null ? [] : [claims.aud];
  if (!aud.includes(audience)) errors.push(`jwt: audience mismatch (${claims.aud})`);
  return { ok: errors.length === 0, claims, errors };
}

/**
 * Verify an identity attestation offline and confirm it binds THIS capsule's
 * signer. Returns { ok, status, identity, errors }, where status is one of
 * ATTESTATION_VERIFIED / ATTESTATION_UNVERIFIED / ATTESTATION_REJECTED
 * (spec/federation.md "Failure reporting").
 *
 * `identity` is `{ status, subject, claims }` when — and ONLY when — the
 * attestation verified. An unverified or rejected attestation yields
 * `identity: null`: a claim never leaves this function without its basis,
 * and a caller cannot read a subject while skipping the verdict.
 *
 * options (capsuleId and signerPublicKeyHex are REQUIRED — an attestation
 * that is not checked against a specific capsule and signer binds nothing;
 * see spec/federation.md "Identity attestation"):
 *   trustRoots          issuer public keys / JWKS (required for a real check)
 *   now                 Date | ms | undefined (defaults to Date.now)
 *   capsuleId           expected capsule_id the attestation MUST bind
 *   signerPublicKeyHex  expected signer key the attestation MUST bind
 *   expectedIssuer      REQUIRED issuer identity (origin or bare DNS form)
 *   audience            REQUIRED for the JWT profile: expected `aud`
 *   jwtBindingClaim     for JWT profile: claim key holding the capsule binding
 *                       object (default "cap")
 */
export function verifyIdentityAttestation(attestation, options = {}) {
  if (typeof options.capsuleId !== "string" || options.capsuleId.length === 0) {
    throw new TypeError(
      "verifyIdentityAttestation requires options.capsuleId: an attestation is only meaningful against a specific capsule (spec/federation.md)",
    );
  }
  if (typeof options.signerPublicKeyHex !== "string" || options.signerPublicKeyHex.length === 0) {
    throw new TypeError(
      "verifyIdentityAttestation requires options.signerPublicKeyHex: an attestation is only meaningful against a specific signer (spec/federation.md)",
    );
  }
  if (typeof options.expectedIssuer !== "string" || options.expectedIssuer.length === 0) {
    throw new TypeError(
      "verifyIdentityAttestation requires options.expectedIssuer: the issuer is caller-supplied trust configuration, never read from the attestation being checked (spec/federation.md)",
    );
  }
  const errors = [];
  let trustRootMissing = false;
  const now = options.now instanceof Date ? options.now.getTime() : options.now ?? Date.now();
  if (!attestation || attestation.typ !== ATTESTATION_TYP) {
    return {
      ok: false,
      status: ATTESTATION_REJECTED,
      identity: null,
      errors: ["not a capsule identity attestation"],
    };
  }
  if (normalizeIssuer(attestation.issuer) !== normalizeIssuer(options.expectedIssuer)) {
    errors.push(`attestation issuer mismatch: ${attestation.issuer} vs ${options.expectedIssuer}`);
  }

  let claims;
  let versionUnknown = false;
  if (attestation.alg === "ed25519-jcs") {
    // The signing domain embeds the DECLARED spec_version
    // (spec/versioning.md keying, applied to the attestation overlay):
    // gate it against the known table BEFORE reconstructing the domain.
    // Checking a signature under the wrong era's domain would emit
    // "signature invalid" — tamper-flavored noise for what is actually
    // a version-support gap — so an unknown version skips the check and
    // reports as UNVERIFIED (unknown, not negative), while a version
    // violating the <major>.<minor> grammar is a malformed document.
    const versionClass = classifyVersion(attestation.spec_version);
    if (versionClass.status === "invalid") {
      errors.push(
        `attestation spec_version is not a '<major>.<minor>' version string: ${JSON.stringify(
          attestation.spec_version,
        )}`,
      );
    } else if (versionClass.status !== "known") {
      errors.push(
        `attestation spec_version '${attestation.spec_version}' is ${
          versionClass.status === "unknown_newer"
            ? "newer than this verifier supports"
            : "older than any version this verifier supports"
        }; this is a limitation of the verifier, not evidence of tampering`,
      );
      versionUnknown = true;
    } else {
      const roots = normalizeTrustRoots(options.trustRoots);
      const key = selectKey(roots, attestation.kid, "ed25519-jcs");
      if (!key || !key.public_key_hex) {
        errors.push(`no trust-root key for kid=${attestation.kid}`);
        trustRootMissing = true;
      } else if (typeof attestation.signature !== "string") {
        errors.push("attestation missing signature");
      } else {
        const ok = ed25519Verify(
          hexToBytes(key.public_key_hex),
          attestationSigningInput(attestation),
          hexToBytes(attestation.signature),
        );
        if (!ok) errors.push("attestation signature invalid");
      }
    }
    claims = attestation.claims ?? {};
  } else if (attestation.jwt) {
    // JWT profile (Clerk): the binding lives inside the verified token.
    if (typeof options.audience !== "string" || options.audience.length === 0) {
      throw new TypeError(
        "verifyIdentityAttestation requires options.audience for the JWT profile: the attestation JWT is scoped to the verifying host (spec/profiles/clerk.md)",
      );
    }
    const res = verifyJwt(attestation.jwt, {
      trustRoots: options.trustRoots,
      now,
      // The expected issuer is caller trust configuration. Reading it from
      // `attestation.issuer` — a field on the same untrusted wrapper — would
      // make the `iss` check self-referential and therefore vacuous.
      issuer: options.expectedIssuer,
      audience: options.audience,
    });
    errors.push(...res.errors);
    if (res.trustRootMissing) trustRootMissing = true;
    const bindingKey = options.jwtBindingClaim ?? "cap";
    const binding = res.claims?.[bindingKey] ?? {};
    claims = {
      capsule_id: binding.capsule_id,
      signer_public_key: binding.signer_public_key,
      signer_role: binding.signer_role,
      issued_at: jwtInstant(res.claims?.iat),
      expires_at: jwtInstant(res.claims?.exp),
      subject: {
        clerk_user_id: res.claims?.sub,
        clerk_org_id: res.claims?.org_id,
        email: res.claims?.email,
        org_role: res.claims?.org_role,
      },
    };
  } else {
    return {
      ok: false,
      status: ATTESTATION_REJECTED,
      identity: null,
      errors: [`unsupported attestation alg ${attestation.alg}`],
    };
  }

  // Expiry (ed25519-jcs carries ISO instants in claims; the JWT profile
  // reprojects iat/exp). An attestation with no expiry, or with an
  // unparseable one, is REJECTED — never treated as "never expires".
  if (claims.expires_at == null) {
    errors.push("attestation missing required claim 'expires_at'");
  } else {
    const expiresAt = parseInstant(claims.expires_at);
    if (expiresAt === null) {
      errors.push(`attestation expires_at is not an RFC 3339 instant: ${claims.expires_at}`);
    } else if (now >= expiresAt) {
      errors.push("attestation expired");
    }
  }
  if (claims.issued_at != null) {
    const issuedAt = parseInstant(claims.issued_at);
    if (issuedAt === null) {
      errors.push(`attestation issued_at is not an RFC 3339 instant: ${claims.issued_at}`);
    } else if (issuedAt - now > 5 * 60 * 1000) {
      errors.push("attestation issued in the future");
    }
  }

  // The binding claims are MANDATORY (spec/federation.md "Identity
  // attestation"): an attestation whose claims omit them binds nothing. A raw
  // provider session token — which carries no `cap` object at all — lands
  // here and is rejected (spec/profiles/clerk.md "Security notes").
  let bindingComplete = true;
  for (const field of ["capsule_id", "signer_public_key", "signer_role"]) {
    const value = claims?.[field];
    if (typeof value !== "string" || value.length === 0) {
      errors.push(`attestation missing required binding claim '${field}'`);
      bindingComplete = false;
    }
  }

  // Binding checks: the attestation MUST be for THIS capsule and signer.
  if (bindingComplete) {
    if (claims.capsule_id !== options.capsuleId) {
      errors.push(`capsule_id binding mismatch: ${claims.capsule_id} vs ${options.capsuleId}`);
    }
    if (claims.signer_public_key.toLowerCase() !== options.signerPublicKeyHex.toLowerCase()) {
      errors.push("signer_public_key binding mismatch");
    }
  }

  // spec/federation.md "Failure reporting" distinguishes two oppositely
  // signed outcomes: `attestation_unverified` (no trust roots cached — the
  // signer is valid but identity-unverified, NOT a negative signal) from
  // `attestation_rejected` (a strong negative: bad signature, expiry, or
  // binding mismatch). Collapsing both into ok:false loses that sign.
  const ok = errors.length === 0;
  const status = ok
    ? ATTESTATION_VERIFIED
    : (trustRootMissing || versionUnknown) && errors.length === 1
      ? ATTESTATION_UNVERIFIED
      : ATTESTATION_REJECTED;
  return {
    ok,
    status,
    // The verified identity travels WITH its basis, or not at all.
    identity: ok ? { status, subject: claims.subject ?? null, claims } : null,
    errors,
  };
}

// Exposed for issuers/tests that need to construct a compact JWT.
export const _jwt = { b64uToBuf, bufToB64u };

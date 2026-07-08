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

export const ATTESTATION_TYP = "capsule-identity-attestation";
export const ATTESTATION_DOMAIN = Buffer.from(
  "capsule-identity-attestation-v0.6\x00",
  "utf8",
);

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
// Signing input for the native ed25519-jcs profile.
// ---------------------------------------------------------------------------
function attestationSigningInput(attestation) {
  const { signature: _ignored, ...rest } = attestation;
  return Buffer.concat([ATTESTATION_DOMAIN, Buffer.from(jcs(rest))]);
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
    spec_version: "0.6",
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
  return keys.map((k) => {
    // A raw JWKS entry (from Clerk's /.well-known/jwks.json) has kty/kid/alg.
    if (k.kty && !k.public_key_hex && !k.jwk) {
      return { kid: k.kid, alg: k.alg ?? (k.kty === "OKP" ? "ed25519-jcs" : "ES256"), jwk: k };
    }
    return k;
  });
}

function selectKey(roots, kid, alg) {
  const byKid = roots.filter((k) => k.kid === kid);
  const pool = byKid.length ? byKid : roots;
  return pool.find((k) => k.alg === alg) ?? null;
}

const JWT_ALG_TO_NODE = {
  ES256: { dsaEncoding: "ieee-p1363", hash: "sha256" },
  ES384: { dsaEncoding: "ieee-p1363", hash: "sha384" },
  RS256: { hash: "sha256" },
  RS384: { hash: "sha384" },
};

/**
 * Verify a compact JWT (Clerk-issued or compatible) against trust roots /
 * a JWKS. Fully offline given the JWKS. Returns { ok, claims, errors }.
 *
 * Checks signature, alg/kid selection, and (when present) exp/nbf plus the
 * caller-supplied issuer/audience.
 */
export function verifyJwt(compact, { trustRoots, now, issuer, audience } = {}) {
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
    return { ok: false, claims, errors: [`jwt: no trust-root key for kid=${header.kid}`] };
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
  if (issuer && claims.iss !== issuer) errors.push(`jwt: issuer mismatch (${claims.iss})`);
  if (audience) {
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!aud.includes(audience)) errors.push(`jwt: audience mismatch (${claims.aud})`);
  }
  return { ok: errors.length === 0, claims, errors };
}

/**
 * Verify an identity attestation offline and confirm it binds THIS capsule's
 * signer. Returns { ok, subject, claims, errors }.
 *
 * options:
 *   trustRoots          issuer public keys / JWKS (required for a real check)
 *   now                 Date | ms | undefined (defaults to Date.now)
 *   capsuleId           expected capsule_id the attestation must bind
 *   signerPublicKeyHex  expected signer key the attestation must bind
 *   jwtBindingClaim     for JWT profile: claim key holding the capsule binding
 *                       object (default "cap")
 */
export function verifyIdentityAttestation(attestation, options = {}) {
  const errors = [];
  const now = options.now instanceof Date ? options.now.getTime() : options.now ?? Date.now();
  if (!attestation || attestation.typ !== ATTESTATION_TYP) {
    return { ok: false, subject: null, claims: null, errors: ["not a capsule identity attestation"] };
  }

  let claims;
  if (attestation.alg === "ed25519-jcs") {
    const roots = normalizeTrustRoots(options.trustRoots);
    const key = selectKey(roots, attestation.kid, "ed25519-jcs");
    if (!key || !key.public_key_hex) {
      errors.push(`no trust-root key for kid=${attestation.kid}`);
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
    claims = attestation.claims ?? {};
  } else if (attestation.jwt) {
    // JWT profile (Clerk): the binding lives inside the verified token.
    const res = verifyJwt(attestation.jwt, {
      trustRoots: options.trustRoots,
      now,
      issuer: attestation.issuer,
    });
    errors.push(...res.errors);
    const bindingKey = options.jwtBindingClaim ?? "cap";
    const binding = res.claims?.[bindingKey] ?? {};
    claims = {
      capsule_id: binding.capsule_id,
      signer_public_key: binding.signer_public_key,
      signer_role: binding.signer_role,
      issued_at: res.claims?.iat != null ? new Date(res.claims.iat * 1000).toISOString() : undefined,
      expires_at: res.claims?.exp != null ? new Date(res.claims.exp * 1000).toISOString() : undefined,
      subject: {
        clerk_user_id: res.claims?.sub,
        clerk_org_id: res.claims?.org_id,
        email: res.claims?.email,
        org_role: res.claims?.org_role,
      },
    };
  } else {
    return { ok: false, subject: null, claims: null, errors: [`unsupported attestation alg ${attestation.alg}`] };
  }

  // Expiry (ed25519-jcs carries ISO timestamps in claims).
  if (claims.expires_at && now >= Date.parse(claims.expires_at)) errors.push("attestation expired");
  if (claims.issued_at && Date.parse(claims.issued_at) - now > 5 * 60 * 1000) {
    errors.push("attestation issued in the future");
  }

  // Binding checks: the attestation must be for THIS capsule and signer.
  if (options.capsuleId && claims.capsule_id !== options.capsuleId) {
    errors.push(`capsule_id binding mismatch: ${claims.capsule_id} vs ${options.capsuleId}`);
  }
  if (
    options.signerPublicKeyHex &&
    claims.signer_public_key?.toLowerCase() !== options.signerPublicKeyHex.toLowerCase()
  ) {
    errors.push("signer_public_key binding mismatch");
  }

  return { ok: errors.length === 0, subject: claims.subject ?? null, claims, errors };
}

// Exposed for issuers/tests that need to construct a compact JWT.
export const _jwt = { b64uToBuf, bufToB64u };

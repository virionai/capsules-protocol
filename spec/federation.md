# Capsule Federation (v0.6, informative → normative-in-progress)

This document defines how a capsule signer key is bound to an **external
identity** (a person, organization, or service managed by an identity
provider such as Clerk), how **encrypted-capsule recipients** are discovered,
and how a host expresses **signer-role and quorum policy** — all without
making capsule verification depend on any network service.

It fills the gap named in [trust.md](trust.md): *"a capsule is trustworthy in
proportion to the verifier's ability to obtain the issuer's public key
out-of-band. The format does not provide that binding."* Federation is that
binding, expressed as optional, self-describing artifacts.

Status: the artifact shapes and the portability rule below are stabilizing
for v1.0. Concrete provider mappings live in `spec/profiles/` (see
[profiles/clerk.md](profiles/clerk.md)).

## The portability firewall (normative)

> **Capsule verification MUST NOT require a network call.** Federation adds
> identity, recipient discovery, and policy strictly as overlays around the
> portable file. It never changes the wire shape and never gates the
> cryptographic result.

Consequences a conforming implementation MUST preserve:

1. **Core verification is issuer-agnostic and offline.** `verifyCapsule`
   (L2/L3: hashes, chain, envelope signatures, encrypted-blob binding) runs
   with no federation input and no network. A verifier that has never heard
   of the issuer still returns the same `valid`/`ok` math result.
2. **Attestation checking is offline given cached trust roots.** Verifying an
   identity attestation requires only the issuer's public keys (a small,
   cacheable JWKS). Absent them, the verifier reports the signer as
   *valid but identity-unverified* — never *invalid*.
3. **Decryption is offline.** Recipient key discovery happens only at
   authoring time. Decrypting a capsule requires only the recipient's local
   private key — never a call to the identity provider.

Federation touches the network at exactly two moments, both optional and both
outside verification: **authoring** (request an attestation; look up recipient
keys) and **policy refresh** (fetch and cache an issuer's trust roots).

## Roles

An **issuer** is an authority that binds capsule keys to identities and
publishes trust roots. In a Clerk deployment the issuer is the application's
backend acting on Clerk-authenticated sessions; the trust root is a JWKS.

A **trust root** is a public key the issuer signs attestations (or JWTs) with.
Verifiers cache trust roots out-of-band, exactly as [trust.md](trust.md)
already requires for signer keys.

A **key directory** maps an identity (user id, org id, email) to that
principal's published, non-secret **X25519 capsule encryption key**.

## Issuer metadata document

Conventionally served at `<issuer>/.well-known/capsule-issuer.json`:

```json
{
  "issuer": "https://capsules.example",
  "spec_version": "0.6",
  "profiles": ["ed25519-jcs", "clerk-jwt"],
  "trust_roots": {
    "jwks": { "keys": [ /* … */ ] }
  },
  "key_directory": {
    "recipients_uri": "https://capsules.example/directory/recipients",
    "signers_uri": "https://capsules.example/.well-known/capsule-signers"
  }
}
```

`trust_roots` MAY instead carry `jwks_uri`. The document is cacheable; a
verifier that already holds the trust roots never fetches it.

## Identity attestation

An attestation is a signed statement binding **one capsule** and **one signer
key** to an external subject. Its binding claims MUST include `capsule_id`,
`signer_public_key`, and `signer_role`; verifiers MUST reject an attestation
whose `capsule_id`/`signer_public_key` do not match the capsule and signer
being checked, and MUST reject an expired attestation.

Because `capsule_id = SHA-256(domain ‖ originator_pubkey ‖ first_event_hash)`
depends only on the originator key and first event, it is known before sealing.
An issuer can therefore attest to it, and the attestation MAY be **embedded**
in the capsule under `payload/attestations/…` (where the content index makes
it tamper-evident) or delivered as a **detached sidecar** and re-associated by
`capsule_id`. Embedding is preferred: the attestation travels with the file and
cannot be altered without failing verification.

Two algorithm profiles are defined:

### `ed25519-jcs` (native)

Mirrors the envelope-signing discipline: domain separation + JCS + raw-byte
Ed25519, never hashing hex strings.

```
signing_input = "capsule-identity-attestation-v0.6\x00" ‖ JCS(attestation_without_signature)
signature     = Ed25519(issuer_trust_root_private_key, signing_input)
```

```json
{
  "typ": "capsule-identity-attestation",
  "spec_version": "0.6",
  "alg": "ed25519-jcs",
  "issuer": "https://capsules.example",
  "kid": "issuer-key-1",
  "claims": {
    "capsule_id": "<64-hex>",
    "signer_public_key": "<64-hex ed25519>",
    "signer_role": "originator",
    "subject": { "clerk_user_id": "user_…", "clerk_org_id": "org_…",
                 "email": "a@example", "org_role": "admin" },
    "issued_at": "2026-05-07T12:00:00Z",
    "expires_at": "2027-05-07T12:00:00Z"
  },
  "signature": "<hex>"
}
```

### JWT (`ES256`/`RS256`)

For providers that already issue JWTs (Clerk). The attestation carries a
compact JWS whose payload holds the standard identity claims plus a `cap`
binding object `{ capsule_id, signer_public_key, signer_role }`. Verification
is ordinary JWT verification against the issuer JWKS. See
[profiles/clerk.md](profiles/clerk.md).

## Signer-role and quorum policy

A host MAY require that specific roles (optionally scoped to a provider role
such as an org `admin`) sign a capsule, with a quorum. A signer counts toward
a requirement only if it is BOTH a trusted signer in the verification result
(valid signature on the host's allowlist) AND covered by a verified
attestation for the required role. Policy evaluation is a pure function of the
verification result plus verified attestations — no network, no effect on the
cryptographic result. This is the beginning of the roadmap's
signer-role/quorum item; the expression above is intentionally minimal.

## What federation deliberately does not do

- It does not hide outer metadata (see encrypted-outer-metadata-minimization
  in the roadmap).
- It does not provide revocation or key lifecycle; a cached trust root is
  valid until the verifier refreshes it (see key-lifecycle in the roadmap).
- It does not make identity a precondition for validity — only an overlay.

# Capsule Federation

**Status: informative for v0.6, in two layers.** The *overlay layer*
(identity attestations, recipient discovery, signer-role/quorum policy)
rides on unmodified v0.6 capsules, has a working reference adapter
(`sdk-js/src/federation/`), and is stabilizing for v1.0. The *discovery
layer* (signer document, key lifecycle, envelope `issuer` field,
temporal anchors) touches the envelope schema and is therefore a
**v0.7 draft** — per [envelope.md](envelope.md), envelope schema
additions are v0.7 changes. Nothing in this document changes what a
v0.6 verifier accepts or rejects.

This document defines how a capsule signer key is bound to an
**external identity** (a person, organization, or service managed by an
identity provider such as Clerk), how a verifier discovers **which keys
an issuer vouches for and whether they are still valid**, how
**encrypted-capsule recipients** are discovered, how a capsule gains
**external time evidence**, and how a host expresses **signer-role and
quorum policy** — all without making capsule verification depend on any
network service.

It fills the gap named in [trust.md](trust.md): *"a capsule is
trustworthy in proportion to the verifier's ability to obtain the
issuer's public key out-of-band. The format does not provide that
binding."* Federation is that binding, expressed as optional,
self-describing artifacts. Concrete provider mappings live in
`spec/profiles/` (see [profiles/clerk.md](profiles/clerk.md)).

The layers compose along three questions:

1. **Which keys does this issuer vouch for, and are they still valid?**
   — the signer document, discovery methods, and key lifecycle.
2. **Who controls this key?** — identity attestations binding one
   capsule + one signer key to an external subject.
3. **When was this sealed?** — temporal anchors, the evidence key
   lifecycle needs to mean anything.

## The portability firewall (normative)

> **Capsule verification MUST NOT require a network call.** Federation
> adds identity, key discovery, recipient discovery, time evidence, and
> policy strictly as overlays around the portable file. It never changes
> the cryptographic result, and — for the overlay layer — never changes
> the wire shape.

Consequences a conforming implementation MUST preserve:

1. **Core verification is issuer-agnostic and offline.** `verifyCapsule`
   (L2/L3: hashes, chain, envelope signatures, encrypted-blob binding)
   runs with no federation input and no network. A verifier that has
   never heard of the issuer still returns the same `valid`/`ok` math
   result. A capsule that verifies on an air-gapped machine today MUST
   still verify there under v0.7.
2. **Discovery is a separate, host-side, cacheable step.** A verifier
   never fetches anything while checking math. Signer documents and
   issuer metadata are fetched and cached out-of-band, on the host's
   schedule.
3. **Attestation checking is offline given cached trust roots.**
   Verifying an identity attestation requires only the issuer's public
   keys (a small, cacheable JWKS). Absent them, the verifier reports the
   signer as *valid but identity-unverified* — never *invalid*.
4. **Anchor checking is offline given bundled proofs.** Temporal anchors
   carry their inclusion proofs or TSA tokens inside the capsule; the
   verifier checks them against locally pinned log/TSA keys.
5. **Decryption is offline.** Recipient key discovery happens only at
   authoring time. Decrypting a capsule requires only the recipient's
   local private key — never a call to the identity provider.
6. **No required runtime.** Discovery rides on boring, auditable
   transports (HTTPS, DNS, Sigstore's public log) — not on a
   peer-to-peer runtime, a blockchain, or any system a regulator's
   auditor cannot independently query with standard tooling.

Federation touches the network at exactly two moments, both optional
and both outside verification: **authoring** (request an attestation;
look up recipient keys; obtain an anchor) and **trust refresh** (fetch
and cache an issuer's metadata and signer document).

## Vocabulary

- **Issuer** — the entity that operates capsule signing keys and vouches
  for them: a platform, a firm, a regulator, an application backend
  acting on identity-provider sessions. Canonically identified by a
  **lowercase DNS name** (the domain that publishes its documents),
  e.g. `loanco.example`; its HTTPS origin is `https://<issuer>`. Fields
  that are URLs by convention (issuer metadata `issuer`, JWT `iss`)
  carry the origin form; fields inside signer documents and envelopes
  carry the bare DNS name. Verifiers MUST treat the two forms as the
  same issuer after normalization (strip scheme, lowercase, drop
  trailing slash).
- **Trust root** — a host-side configuration entry: an issuer identifier
  plus either pinned key material or a discovery rule. The pinned or
  discovered material is of two kinds: *attestation-verification keys*
  (a JWKS the issuer signs attestations or JWTs with) and *signer keys*
  (the envelope keys the issuer vouches for, via the signer document).
  The host's allowlist ([trust.md](trust.md)) is derived from its trust
  roots. Verifiers cache trust roots out-of-band, exactly as trust.md
  already requires for signer keys.
- **Issuer metadata document** — the entry-point JSON document at
  `/.well-known/capsule-issuer.json`: declared profiles, attestation
  trust roots, and pointers to the key directories.
- **Signer document** — the JSON document at
  `/.well-known/capsule-signers` listing the issuer's envelope signing
  keys, their roles, validity windows, and lifecycle status.
- **Identity attestation** — a signed statement binding one capsule and
  one signer key to an external subject.
- **Key directory (recipients)** — maps an identity (user id, org id,
  email) to that principal's published, non-secret **X25519 capsule
  encryption key**.
- **Temporal anchor** — externally verifiable evidence of sealing time,
  bundled in the capsule.

## Issuer documents

Two documents, one entry point. The **issuer metadata document** holds
what changes rarely (profiles, attestation trust roots, directory
URIs); the **signer document** holds what lifecycle churns (key status,
validity windows). Splitting them keeps the lifecycle-bearing key list
independently cacheable and keeps `/.well-known/capsule-signers`
exactly the convention [trust.md](trust.md) already names — a verifier
that only needs signer keys MAY fetch it directly, skipping the
metadata document.

### Issuer metadata document

Served at `https://<issuer>/.well-known/capsule-issuer.json`:

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

### Signer document

Served at `https://<issuer>/.well-known/capsule-signers`, content type
`application/json`:

```json
{
  "version": "0.7-draft",
  "issuer": "loanco.example",
  "updated_at": "2026-07-01T00:00:00Z",
  "keys": [
    {
      "public_key": "<64-hex ed25519 raw>",
      "algo": "ed25519",
      "roles": ["originator", "creator"],
      "label": "LoanCo production signer 2026",
      "not_before": "2026-01-01T00:00:00Z",
      "not_after": null,
      "status": "active",
      "revoked_at": null
    }
  ],
  "sigstore": [
    {
      "identity": "release@loanco.example",
      "oidc_issuer": "https://accounts.google.com"
    }
  ],
  "previous": null
}
```

Field rules:

- `version`: readers MUST reject documents whose version they do not
  understand. No silent downgrade.
- `issuer`: MUST equal the domain the document was fetched from. A
  mismatch is a hard discovery failure.
- `keys[].public_key`: lowercase hex, same encoding as
  `signers[].public_key` in the envelope.
- `keys[].roles`: the envelope roles this key is expected to sign
  under. A valid signature under a role not listed here yields
  `trusted = false` for that signer.
- `keys[].status`: `active | retired | revoked`. Status transitions are
  append-only in spirit: a key MUST never move from `revoked` back to
  `active`. `retired` means "stop trusting for new capsules, keep
  trusting for capsules sealed while it was active"; `revoked` means the
  key is presumed compromised and host policy decides how far back
  distrust reaches. Distinguishing "sealed while active" from "sealed
  after compromise" requires temporal anchoring (below); without an
  anchor, `signed_at` is the only (self-attested) evidence and hosts
  SHOULD treat it accordingly.
- `previous`: optional URL of an archived older document, so auditors
  can reconstruct what the issuer published at a past date.
- `sigstore`: optional identities whose Fulcio-certified signatures
  (logged in Rekor) the issuer claims. This lets an issuer anchor its
  key list to a second, independently operated transparency system.

Serving rules: HTTPS only, cache-friendly (`ETag`/`Last-Modified`), no
authentication required to read. Hosts SHOULD cache signer documents
and record the fetch time; a capsule evaluated against a cached
document MUST report the document's `updated_at` and fetch time
alongside the trust result.

## Discovery methods

In order of preference:

| # | Method | Transport | Notes |
|---|---|---|---|
| 1 | `.well-known/capsule-issuer.json` → `.well-known/capsule-signers` | HTTPS | Normative in v0.7. Either entry point resolves to the same signer document. |
| 2 | Sigstore identity | Fulcio + Rekor | For issuers that sign via OIDC identities rather than long-lived keys. Verification uses Rekor inclusion proofs, which can be bundled and checked offline. |
| 3 | DNS TXT `_capsule-signers.<domain>` | DNS | Contains the URL of the signer document. Fallback for issuers that cannot serve `.well-known` paths. |
| 4 | Distributed key list | out-of-band | Regulator- or consortium-published lists. Profile-specific; the list format is the signer-document shape, delivery is whatever the authority uses. |

A profile that names a discovery method the reader does not implement
is an unsupported profile: the reader reports it as such and computes
no trust. It does not fall back to a weaker method.

## Envelope binding (v0.7 change)

v0.7 envelopes MAY carry an `issuer` field (the issuer identifier, DNS
form) inside the signed payload. When present, a reader computing
trust:

1. Resolves the issuer's signer document via a discovery method above.
2. Requires each signer's `public_key` to appear in that document with
   a matching role and a lifecycle status acceptable under host policy.
3. Reports per-signer `trusted` accordingly.

v0.6 capsules have no `issuer` field; hosts map keys to issuers via
locally configured trust roots only. That behavior remains valid in
v0.7 — the field is an optimization for discovery, not a trust grant.
An attacker naming someone else's `issuer` in their envelope gains
nothing: their key is not in that issuer's document.

## Identity attestation

An attestation is a signed statement binding **one capsule** and **one
signer key** to an external subject. Its binding claims MUST include
`capsule_id`, `signer_public_key`, and `signer_role`; verifiers MUST
reject an attestation whose `capsule_id`/`signer_public_key` do not
match the capsule and signer being checked, and MUST reject an expired
attestation.

Because `capsule_id = SHA-256(domain ‖ originator_pubkey ‖ first_event_hash)`
depends only on the originator key and first event, it is known before
sealing. An issuer can therefore attest to it, and the attestation MAY
be **embedded** in the capsule under `payload/attestations/…` (where the
content index makes it tamper-evident) or delivered as a **detached
sidecar** and re-associated by `capsule_id`. Embedding is preferred: the
attestation travels with the file and cannot be altered without failing
verification.

The attestation answers "who controls this key"; the signer document
answers "does the issuer still vouch for it". They are independent
checks over the same key and compose in policy (below).

Two algorithm profiles are defined:

### `ed25519-jcs` (native)

Mirrors the envelope-signing discipline: domain separation + JCS +
raw-byte Ed25519, never hashing hex strings.

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
compact JWS whose payload holds the standard identity claims plus a
`cap` binding object `{ capsule_id, signer_public_key, signer_role }`.
Verification is ordinary JWT verification against the issuer JWKS. See
[profiles/clerk.md](profiles/clerk.md).

## Recipient key directory

A key directory maps an identity (user id, org id, email) to that
principal's published, non-secret **X25519 capsule encryption key**,
resolved at `key_directory.recipients_uri` (or a provider API — see
[profiles/clerk.md](profiles/clerk.md) for the Clerk public-metadata
realization). Authoring resolves recipient keys and passes them to
`seal({ recipients })`; unresolved recipients are surfaced so the author
can decide whether to proceed. Decryption never consults the directory —
the recipient holds the matching X25519 private key locally.

## Temporal anchoring (v0.7 companion)

Key lifecycle only works if "when was this sealed" has evidence better
than self-attested `signed_at`. The companion v0.7 change: envelopes
MAY carry an `anchors` array:

```json
"anchors": [
  { "type": "rekor",   "log_index": 123456, "inclusion_proof": { } },
  { "type": "rfc3161", "tsa_token_b64": "<DER token>" }
]
```

Both anchor types bundle their proofs in the capsule, so anchor
verification is offline like everything else — the verifier checks the
inclusion proof or TSA token against locally pinned log/TSA keys.

**Recommendation: anchor to a public transparency log (Rekor) or an
established public RFC 3161 TSA — do not operate your own TSA for your
own capsules.** A timestamp signed by the same party that sealed the
capsule adds no independent evidence; for the regulated-work use case
it re-introduces exactly the "trust the issuer about time" problem the
anchor exists to remove. Self-operated TSAs are acceptable only as an
*additional* anchor alongside an independent one.

## Signer-role and quorum policy

A host MAY require that specific roles (optionally scoped to a provider
role such as an org `admin`) sign a capsule, with a quorum. This is
where the layers compose. A signer counts toward a requirement only if
**all** of the following hold:

1. **Valid signature** — the signer is valid in the L2 verification
   result.
2. **Trusted key** — the key is on the host's allowlist, derived from
   its trust roots (pinned keys, or the issuer's signer document
   resolved via a discovery method).
3. **In lifecycle** — when a signer document is in play, the key is
   listed with the required role and a lifecycle status acceptable
   under host policy for the capsule's evidenced sealing time (temporal
   anchors preferred; self-attested `signed_at` otherwise).
4. **Attested identity** — where the requirement is identity-scoped,
   the signer is covered by a verified identity attestation for the
   required role (and, if scoped, the required provider role).

Policy evaluation is a pure function of the verification result,
verified attestations, and cached issuer documents — no network, no
effect on the cryptographic result. This is the beginning of the
roadmap's signer-role/quorum item; the expression above is
intentionally minimal.

## Failure reporting

Federation failures are trust failures, never math failures, and they
are distinguishable. Discovery-layer categories:

- `key_not_in_issuer_document` — document fetched, key absent or role
  mismatch. Strong negative signal.
- `issuer_unreachable` — document could not be fetched and no usable
  cache exists. Unknown, not negative; host policy decides whether to
  hold or reject.
- `issuer_document_invalid` — fetched but unparseable, version-unknown,
  or `issuer` mismatch. Treat as unreachable, log loudly.
- `key_lifecycle_rejected` — key found but `retired`/`revoked` under
  host policy for this capsule's evidence of sealing time.

Attestation-layer categories:

- `attestation_unverified` — no trust roots cached for the attestation
  issuer. Unknown, not negative: the signer is *valid but
  identity-unverified*.
- `attestation_rejected` — trust roots present but the attestation is
  expired, its signature fails, or its `capsule_id`/`signer_public_key`
  binding does not match. Strong negative signal.

The verifier's L2 math result is unchanged in every case.

## What federation deliberately does not do

- **Reputation.** A valid signer document or attestation proves the
  issuer publishes/vouches for the key, not that the issuer is honest.
  Same boundary as [trust.md](trust.md).
- **Outer metadata privacy.** Discovery necessarily reveals which
  issuer a host is asking about, and federation does not hide outer
  capsule metadata (see encrypted-outer-metadata-minimization in the
  roadmap).
- **Identity as a precondition for validity.** Identity is only an
  overlay; a capsule with no attestation still verifies.
- **Instant revocation.** Caching means revocation propagates at cache
  latency. Hosts with stricter needs shorten cache windows or require
  fresh fetches by policy.

## Open questions for review

1. Should the signer document itself be signed (self-signed by a
   long-lived issuer root key, or witnessed via Rekor), or is HTTPS +
   caching + `previous` archaeology sufficient for v0.7?
2. Minimum required cache/staleness semantics, or leave entirely to
   host policy?
3. Whether `retired` needs a machine-readable successor-key pointer
   for rotation UX.
4. Whether the DNS TXT method earns its place in v0.7 or waits for
   demand.

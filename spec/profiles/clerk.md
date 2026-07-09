# Clerk Federation Profile (v0.6, informative)

This profile maps [Clerk](https://clerk.com) onto the generic
[federation](../federation.md) vocabulary. It lets a Clerk-authenticated
application issue capsules whose signer keys are bound to Clerk users and
organizations, and encrypt capsules to Clerk-directory recipients — **without
capsules depending on Clerk at verification or decryption time**.

Reference adapter: `sdk-js/src/federation/` (`federation.*` exports). It takes
an **injected** Clerk client, so it runs — and is fully tested — offline.

## Mapping

| Federation concept        | Clerk realization |
|---------------------------|-------------------|
| Issuer                    | The application backend acting on Clerk-authenticated sessions |
| Trust root                | The Clerk instance JWKS (`https://<instance>/.well-known/jwks.json`), algorithm `ES256`/`RS256` |
| Identity attestation      | A short-lived JWT the backend mints for the signer, carrying a `cap` binding claim |
| Key directory (recipients)| A principal's X25519 capsule key published in Clerk **public metadata** |
| Signer-role / quorum      | Clerk organization roles (`admin`, `member`, …) referenced by policy |

## Identity: signer key → Clerk user/org

Sealing flow (authoring time):

1. The user authenticates with Clerk; the backend has the verified session
   (`userId`, `orgId`, `orgRole`).
2. The author appends events and computes `capsule_id`
   (`CapsuleBuilder.previewCapsuleId()`), then proves control of the Ed25519
   signer key to the backend.
3. The backend mints a JWT bound to that capsule and key:

```jsonc
{
  "iss": "https://clerk.<instance>",   // or the app issuer
  "sub": "user_123",                    // Clerk user id
  "org_id": "org_456",
  "org_role": "admin",
  "email": "alice@example.com",
  "iat": 1810000000,
  "exp": 1810003600,
  "cap": {                               // capsule binding (this profile)
    "capsule_id": "<64-hex>",
    "signer_public_key": "<64-hex ed25519>",
    "signer_role": "originator"
  }
}
```

4. The JWT is wrapped as an attestation and embedded at
   `payload/attestations/clerk.json` (content-index bound) or delivered as a
   sidecar.

Verifying (offline, given the cached Clerk JWKS): `verifyIdentityAttestation`
verifies the JWT signature against the JWKS, checks `exp`, and confirms the
`cap` binding matches the capsule and signer being verified. A verifier
without the JWKS still verifies the capsule math and reports the signer as
identity-unverified.

> Clerk session tokens are short-lived and audience-bound to the app; they are
> not themselves capsule attestations. The backend mints a **purpose-scoped**
> attestation JWT (a Clerk JWT template, or the app's own issuer key published
> in the issuer metadata JWKS). Never embed a raw end-user session token.

## Encryption: recipients from the Clerk directory

Each recipient publishes a **non-secret** X25519 capsule key in Clerk public
metadata:

```json
{ "capsule_x25519_public_key": "<64-hex>" }
```

Authoring resolves recipient keys via the Clerk Backend API and passes them to
`seal({ recipients })`:

```js
const dir = federation.clerkRecipientDirectory(clerkBackendClient);
const { resolved, missing } = await federation.resolveRecipientKeys(
  dir, ["alice@example.com", "org_456"]);
// resolved[].x25519_public_key_hex → seal recipients
```

`clerkBackendClient` need only expose `getPublicMetadata(identifier)`; wire it
to Clerk's Backend API (`users.getUser`, `organizations.getOrganization`, or
an email lookup) in your deployment. **Decryption never calls Clerk** — the
recipient holds the matching X25519 private key locally.

Only resolved recipients can decrypt; `missing` recipients (no published key)
are surfaced so the author can decide whether to proceed.

## Policy: Clerk org roles

```js
const policy = { issuer, required: [
  { role: "originator", org_role: "admin" },
  { role: "reviewer",  quorum: 2 },
]};
const decision = federation.evaluateSignerPolicy(verifyResult, attestedSigners, policy);
```

`attestedSigners` are the claims of attestations already verified with
`verifyIdentityAttestation`. The check is offline and does not alter the
cryptographic verification result.

## Security notes

- The JWKS is a **trust root**: obtain it out-of-band and pin/cache it. Clerk
  rotates signing keys; refresh on the host's schedule (`kid` selects the key).
- Attestations bind exactly one `capsule_id` + `signer_public_key`; they cannot
  be replayed onto another capsule.
- Publishing an X25519 key in public metadata is intentional and safe — it is
  an encryption public key, never a secret.
- This profile adds **no** revocation. A compromised Clerk key is contained by
  refreshing the JWKS and re-attesting; historical capsules follow the
  roadmap's key-lifecycle work.

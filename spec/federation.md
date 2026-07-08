# Federation Vocabulary — Draft

**Status: informative draft, proposed for v0.7. Not part of the v0.6
conformance target.** Nothing in this document changes what a v0.6
verifier accepts or rejects. It exists so the key-discovery design can
be reviewed before it becomes normative.

## The gap this closes

[trust.md](trust.md) is explicit: L2 verification proves the math, and
a capsule is trustworthy in proportion to the verifier's ability to
obtain the issuer's public key out-of-band. v0.6 documents that
requirement and deliberately does not pick a mechanism. This draft
picks the mechanisms.

Two constraints carry over from the operating principle
(`portable file -> deterministic verification -> explicit trust policy
-> optional host integrations`):

1. **Verification stays offline.** Discovery is a separate, host-side,
   cacheable step. A verifier never fetches anything while checking
   math. A capsule that verifies on an air-gapped machine today must
   still verify there under v0.7.
2. **No required runtime.** Discovery rides on boring, auditable
   transports (HTTPS, DNS, Sigstore's public log) — not on a
   peer-to-peer runtime, a blockchain, or any system a regulator's
   auditor cannot independently query with standard tooling.

## Vocabulary

- **Issuer** — the entity that operates signing keys: a platform, a
  firm, a regulator. Identified by a lowercase DNS name (the domain
  that publishes its signer document), e.g. `loanco.example`.
- **Signer document** — the JSON document an issuer publishes listing
  its keys, their roles, validity windows, and lifecycle status.
- **Trust root** — a host-side configuration entry: an issuer
  identifier plus either pinned keys or a discovery rule. The host's
  allowlist is derived from its trust roots.

## Signer document

Published at:

```
https://<issuer>/.well-known/capsule-signers
```

Content type `application/json`. Shape:

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

- `version`: readers reject documents whose version they do not
  understand. No silent downgrade.
- `issuer`: must equal the domain the document was fetched from.
  A mismatch is a hard discovery failure.
- `keys[].public_key`: lowercase hex, same encoding as
  `signers[].public_key` in the envelope.
- `keys[].roles`: the envelope roles this key is expected to sign
  under. A valid signature under a role not listed here yields
  `trusted = false` for that signer.
- `keys[].status`: `active | retired | revoked`. Status transitions
  are append-only in spirit: a key must never move from `revoked`
  back to `active`. `retired` means "stop trusting for new capsules,
  keep trusting for capsules sealed while it was active"; `revoked`
  means the key is presumed compromised and host policy decides how
  far back distrust reaches. Distinguishing "sealed while active"
  from "sealed after compromise" requires temporal anchoring (below);
  without an anchor, `signed_at` is the only (self-attested) evidence
  and hosts should treat it accordingly.
- `previous`: optional URL of an archived older document, so auditors
  can reconstruct what the issuer published at a past date.
- `sigstore`: optional identities whose Fulcio-certified signatures
  (logged in Rekor) the issuer claims. This lets an issuer anchor its
  key list to a second, independently operated transparency system.

Serving rules: HTTPS only, cache-friendly (`ETag`/`Last-Modified`),
no authentication required to read. Hosts SHOULD cache signer
documents and record the fetch time; a capsule evaluated against a
cached document must report the document's `updated_at` and fetch
time alongside the trust result.

## Envelope binding (v0.7 change)

v0.7 envelopes MAY carry an `issuer` field (the issuer identifier)
inside the signed payload. When present, a reader computing trust:

1. Resolves the issuer's signer document via a discovery method below.
2. Requires each signer's `public_key` to appear in that document with
   a matching role and a lifecycle status acceptable under host policy.
3. Reports per-signer `trusted` accordingly.

v0.6 capsules have no `issuer` field; hosts map keys to issuers via
locally configured trust roots only. That behavior remains valid in
v0.7 — the field is an optimization for discovery, not a trust grant.
An attacker naming someone else's `issuer` in their envelope gains
nothing: their key is not in that issuer's document.

## Discovery methods

In order of preference:

| # | Method | Transport | Notes |
|---|---|---|---|
| 1 | `.well-known/capsule-signers` | HTTPS | Normative in v0.7. |
| 2 | Sigstore identity | Fulcio + Rekor | For issuers that sign via OIDC identities rather than long-lived keys. Verification uses Rekor inclusion proofs, which can be bundled and checked offline. |
| 3 | DNS TXT `_capsule-signers.<domain>` | DNS | Contains the URL of the signer document. Fallback for issuers that cannot serve `.well-known` paths. |
| 4 | Distributed key list | out-of-band | Regulator- or consortium-published lists. Profile-specific; the list format is the signer-document shape, delivery is whatever the authority uses. |

A profile that names a discovery method the reader does not implement
is an unsupported profile: the reader reports it as such and computes
no trust. It does not fall back to a weaker method.

## Temporal anchoring (companion, same milestone)

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

## Failure reporting

Discovery failures are trust failures, never math failures, and they
are distinguishable:

- `key_not_in_issuer_document` — document fetched, key absent or role
  mismatch. Strong negative signal.
- `issuer_unreachable` — document could not be fetched and no
  usable cache exists. Unknown, not negative; host policy decides
  whether to hold or reject.
- `issuer_document_invalid` — fetched but unparseable, version-unknown,
  or `issuer` mismatch. Treat as unreachable, log loudly.
- `key_lifecycle_rejected` — key found but `retired`/`revoked` under
  host policy for this capsule's evidence of sealing time.

The verifier's L2 math result is unchanged in every case.

## What this draft does not solve

- **Reputation.** A valid signer document proves the issuer publishes
  the key, not that the issuer is honest. Same boundary as v0.6.
- **Quorum and role policy.** Separate roadmap item; the `roles` field
  here feeds it but does not implement it.
- **Issuer metadata privacy.** Discovery necessarily reveals which
  issuer a host is asking about. Minimization is a separate open item.
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

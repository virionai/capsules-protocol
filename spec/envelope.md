# Provenance Envelope

`provenance/envelope.json` carries the signatures that bind the capsule
to one or more keys at one moment in time. The schema and signing
procedure below are the v0.6 cryptographic profile: they define the
interoperable working model for this spec version, not a permanent
prescription for every Capsule deployment.

Deployments may integrate different verification, encryption,
authorization, identity, or key-management technologies as alternate
profiles. Such profiles must be explicitly declared, versioned, and
fail-closed in readers that do not understand them. They are outside the
v0.6 conformance target unless and until a later spec version or profile
registry defines them.

## Schema

```json
{
  "version": "0.6",
  "capsule_id": "<64-hex>",
  "first_event_hash": "<64-hex> | null",
  "entry_hash": "<64-hex> | null",
  "manifest_hash": "<64-hex>",
  "content_index_hash": "<64-hex>",
  "encrypted_blob_hash": "<64-hex> | null",
  "cipher": "none | ChaCha20-Poly1305",
  "signed_at": "2026-05-07T12:00:00Z",
  "signers": [
    {
      "role": "originator",
      "public_key": "<64-hex ed25519 raw>",
      "signature": "<128-hex ed25519 sig>"
    }
  ]
}
```

## Field rules

- `version`: `"0.6"`; MUST equal `manifest.format.version`. Readers
  accept any KNOWN version under that era's rules and fail closed on an
  unknown one — with a diagnosis distinct from tamper detection, and no
  silent upgrade path in either direction. See
  [versioning.md](versioning.md); conformance vectors:
  `spec/vectors/version-compat/`.
- `capsule_id`: matches `manifest.id`.
- `first_event_hash`: 32-byte SHA-256 hex; equals chain event 1's hash.
- `entry_hash`: 32-byte SHA-256 hex; equals the final event's hash at
  seal time. Together with `first_event_hash`, commits to the chain
  range covered by the seal. In a plain capsule these two anchors are
  the ONLY binding between the envelope and the chain — a verifier MUST
  actually compare them.
- **Empty chain:** when the chain has zero events (see
  [chain.md](chain.md) "Empty chains"), `first_event_hash` and
  `entry_hash` MUST both be `null`; there is no chain range to commit
  to, and a non-null anchor over an empty chain fails verification
  closed. `null` anchors over a non-empty chain fail the anchor
  comparison like any other mismatch. Conformance vectors:
  `spec/vectors/chain-binding/`.
- `manifest_hash`: SHA-256 of the JCS-canonical bytes of the manifest
  *with `id` populated and no other modifications*.
- `content_index_hash`: matches `manifest.content_index.index_hash`.
  Bound separately so a verifier can cheaply check the index without
  reparsing the manifest.
- `encrypted_blob_hash`: SHA-256 of `content.enc` for encrypted
  capsules; `null` for plain capsules.
- `cipher`: enumerated value. Unknown values fail verification closed.
  Reserved values that are not implemented today (e.g. `AES-256-GCM`)
  are *not* in this enum. Adding a cipher is a v0.7 schema change.
- `signed_at`: ISO 8601 UTC, no fractional seconds. Self-attested by the
  signer at seal time.
- `signers[]`: at least one entry. See "Signing" below.

## Unknown members

The preservation rule of [manifest.md](manifest.md) "Unknown members"
applies to the envelope, with a sharper consequence: unknown members sit
*inside* the signed payload (`JCS(envelope minus "signers")`).

- Writers MAY add vendor members under the same `x-<vendor>-<name>` key
  convention; future spec versions will never define `x-`-prefixed
  members.
- Readers MUST preserve unknown members verbatim and MUST include them
  when reconstructing the canonical payload. A reader that drops them
  reconstructs bytes the signer never signed and rejects every
  legitimately extended capsule; an attacker who injects or mutates one
  breaks every signature. Reconstructing the payload from a
  re-serialized typed projection of the envelope is a conformance
  violation.
- Members inside individual `signers[]` entries are outside the signed
  payload and carry no integrity guarantee; do not put anything there
  that needs one.

Conformance vectors: `spec/vectors/unknown-fields/`.

## Signing

The signed payload is the JCS-canonical serialization of the envelope
*minus the `signers` field*. There is no separate "signing hash" or
intermediate hash construction.

```
canonical_payload = JCS(envelope minus "signers")          // bytes
domain_sep        = utf8("capsule-provenance-v0.6:" + role + "\x00")
signing_input     = domain_sep || canonical_payload         // bytes
signature         = Ed25519.sign(signing_input)             // 64 bytes
signature_hex     = hex(signature)
```

Each signer in `signers[]`:

- supplies their own `role` (free-form string; conventional roles are
  `originator`, `creator`, `approver`, `notary`, `compliance`,
  `legal`).
- signs with their own private key over `domain_sep || canonical_payload`
  where `role` is *their* role.
- the resulting signature lands in `signers[i].signature`.

**The signing input is raw bytes.** Hex strings, lowercased or
otherwise, never appear in the signed input. This is the v0.6 fix for
the prior `Ed25519.sign(utf8(hex_string))` interop bomb.

**Domain separation per role** prevents replay of a signature across
roles: a `creator` signature is not also a valid `notary` signature even
over identical envelope bytes.

**The domain embeds the declared version.** Verifiers reconstruct the
domain from the envelope's own `version` member — keyed selection per
[versioning.md](versioning.md), so a v0.6 signature stays verifiable by
every future reader that knows v0.6.

## Signer set binding

The envelope does **not** bind its own `signers[]`. The signing input is
`JCS(envelope minus signers)`, so the array is not an input to any
signature — and `provenance/envelope.json` is structurally excluded from
the content index. This is deliberate and matches TUF and DSSE: a
signature array cannot authenticate itself (adding any signature would
invalidate every existing one). The *requirement* is authenticated in a
signed parent instead:

- `manifest.signer_commitment` (see [manifest.md](manifest.md)) stores
  the exact `(role, public_key)` membership of the seal-time signer
  set. `envelope.manifest_hash` is inside the canonical payload, so the
  commitment is transitively signed by every signer.
- **Presence binds, absence reports.** When the commitment is present,
  the normalized signer set MUST equal it exactly — a stripped signer,
  an appended signature in a chosen role, a role swap, or a duplicated
  entry fails verification closed. When absent, verification MAY
  succeed, but the verifier MUST report machine-readably that the
  signer set is unbound. Per-role domain separation alone stops
  replaying one key's signature into another role; it does nothing
  against a *fresh* signature in a chosen role — only the commitment
  closes that.
- **Duplicate signer entries are malformed.** A verifier MUST reject an
  envelope whose `signers[]` contains two entries with the same
  `(role, lowercase public_key)`, whether or not a commitment is
  present. Counting rows instead of members lets one key satisfy an
  M-of-N policy by repetition.
- **Distinct-key counting.** Any signer count a verifier reports (e.g.
  a trusted-signer count) MUST count distinct public keys, never array
  rows. This is TUF's threshold rule and DSSE's: the same key under two
  roles is two set members but one key.
- **Originator binding.** `signers[]` MUST include an entry with role
  `originator` whose `public_key` equals
  `manifest.originator.public_key` and whose signature verifies
  (integrity invariant; see manifest.md).

Post-seal countersigning is *not* expressed by appending to
`signers[]` — the set is fixed when the manifest is built, and mutating
a finalized structure is not countersigning (RFC 9338 requires a
finalized target). A post-seal approval is a separate signed artifact
whose subject names the finalized capsule; a countersignature-capsule
profile is future (v0.7+) work.

Conformance vectors: `spec/vectors/signer-set/`.

## Verification

For each signer:

1. Reconstruct `canonical_payload` from the envelope minus `signers`.
2. Reconstruct `domain_sep` from the signer's `role`.
3. Reconstruct `signing_input = domain_sep || canonical_payload`.
4. Convert `signers[i].public_key` (hex) to 32 raw bytes.
5. Convert `signers[i].signature` (hex) to 64 raw bytes.
6. `Ed25519.verify(public_key, signing_input, signature)`.
7. Record per-signer `valid: true | false`.

### Key and signature validation

Before step 6, a verifier MUST reject the signer outright — recording
`valid: false`, never calling into the signature primitive — when either:

- the 32-byte public key is **non-canonically encoded**: with the x-sign
  bit (the high bit of byte 31) masked off, the little-endian value is
  `>= 2^255 - 19`; or
- the public key is one of the **8 points whose order divides 8**. With the
  sign bit masked off, the rejected y encodings are:
  `0000…0000` (y = 0), `0100…0000` (y = 1),
  `26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05`,
  `c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a`, and
  `ecff…ff7f` (y = p - 1).

A verifier MUST also reject a signature whose `S` component (bytes 32..64,
little-endian) is not reduced mod
`L = 2^252 + 27742317777372353535851937790883648493` (RFC 8032 §5.1.7).

A small-order public key is a forgery primitive that needs no private key:
the attacker picks the key, sends a 64-byte all-zero signature, and varies
any signed field until the cofactored verification equation happens to
hold. Several widely used Ed25519 backends (OpenSSL, CryptoKit,
`ed25519-dalek`'s non-strict `verify`) accept such keys, so the check
belongs in the protocol implementation, not the backend.

Negative conformance vectors for every case above are checked in at
`spec/vectors/ed25519-key-validation.json`.

Then:

1. Reject the envelope if `signers[]` contains duplicate
   `(role, lowercase public_key)` entries.
2. Recompute `manifest_hash` from the manifest as actually stored.
   Compare to `envelope.manifest_hash`.
3. Recompute `content_index_hash` from `manifest.content_index.files`.
   Compare.
4. Recompute `first_event_hash` and `entry_hash` from the chain.
   Compare. With zero events there is nothing to recompute: require
   both anchors (and `manifest.first_event_hash`) to be `null`
   instead, fail-closed, and report that the chain walk covered no
   events (chain.md "Empty chains").
5. For encrypted capsules: recompute SHA-256 of `content.enc`. Compare
   to `encrypted_blob_hash`.
6. Signer-set binding: when `manifest.signer_commitment` is present,
   require the normalized signer set to equal it exactly (fail closed);
   when absent, report the set as unbound without failing. See "Signer
   set binding".
7. Originator binding: require a valid signer with role `originator`
   whose key equals `manifest.originator.public_key`.
8. Report any signer count over distinct public keys, not rows.

The verifier reports an L2 result with per-signer outcomes. **The
verifier does not return `trusted: true`.** Trust is a host concern,
not a verifier concern — see [trust.md](trust.md).

## Encryption

Encrypted capsules use the outer/inner shape from
[format.md](format.md). The encryption procedure:

```
content_key   = random(32)
content_nonce = random(12)

aad = JCS({
  "version":               "0.6",
  "capsule_id":            <hex>,
  "first_event_hash":      <hex>,
  "originator_public_key": <hex>,
  "cipher":                "ChaCha20-Poly1305"
})

content.enc = ChaCha20-Poly1305(content_key, content_nonce, aad, inner_zip_bytes)
```

**Why no `manifest_hash` in AAD.** The outer manifest commits to
`encrypted_blob_hash` (via its `content_index`), which is the hash of
`content.enc`, which depends on the AAD. Including the outer
`manifest_hash` in the AAD would close a cycle. The inner
`manifest_hash` is available pre-encryption but is intentionally
omitted here: the inner content's integrity is established at L3 by
recomputing the inner manifest hash from the decrypted bytes and
checking it against the inner envelope (which is itself signed by the
originator). The AAD's job is to prevent cross-envelope substitution
of `content.enc`; the combination of `capsule_id` (derived from
`originator_public_key || first_event_hash`) plus `first_event_hash`
already binds the ciphertext to a specific origin and chain genesis.
Implementations MUST NOT include `manifest_hash` in the AAD.

The KDF info string `capsule-key-wrap-v0.6` and the AAD's `version`
member both carry the capsule's declared version, keyed as in
[versioning.md](versioning.md). No algorithm identifiers appear in the
sealed bytes beyond `cipher`; the agreement and KDF are fixed by the
v0.6 suite ([versioning.md](versioning.md) "Algorithm suites").

For each recipient X25519 public key:

```
ephemeral_priv, ephemeral_pub = X25519.keygen()
shared      = X25519(ephemeral_priv, recipient_pub)
wrap_key    = HKDF-SHA256(
                ikm    = shared,
                salt   = recipient_pub,
                info   = utf8("capsule-key-wrap-v0.6"),
                length = 32
              )
wrap_nonce  = random(12)
wrapped_key = ChaCha20-Poly1305(wrap_key, wrap_nonce, aad="", content_key)
```

The recipient bundle stored in `skills/decryption/decryption.json`:

```json
{
  "cipher": "ChaCha20-Poly1305",
  "content_nonce": "<24-hex>",
  "key_bundles": [
    {
      "recipient_public_key": "<64-hex x25519>",
      "ephemeral_public_key": "<64-hex x25519>",
      "wrap_nonce": "<24-hex>",
      "wrapped_key": "<hex>"
    }
  ]
}
```

This file is *metadata*. It is not a markdown skill. The prior format's
`skills/decryption/SKILL.md` is removed in v0.6 because a markdown
instruction surface for crypto-adjacent operations is a prompt-injection
vector aimed at a recipient with their private key in scope.

## L2 / L3

- **L2** (encrypted outer verification, no recipient key required):
  envelope signatures verify, manifest hash matches, content index hash
  matches, encrypted blob hash matches, chain anchors match. The
  verifier reports per-signer outcomes. Does not require decryption.

- **L3** (decrypted content verification, recipient key required):
  decrypt `content.enc` with AAD and recipient flow above. Open the
  inner ZIP as a normal capsule. Recompute first/entry event hashes,
  manifest hash, content index hash. Compare to the outer envelope.

There is no L1 in v0.6. L1 (ledger-anchored existence) is parking-lot.

## What the envelope does *not* prove

- That the keys in `signers[]` belong to whom they claim. The envelope
  proves the math; trust is the host's responsibility.
- That `signers[]` is the set that sealed the capsule — *on its own*.
  The envelope's signatures do not cover the array; that binding comes
  from `manifest.signer_commitment`, and a capsule without one makes no
  signer-set claim at all (verifiers report it as unbound).
- That any role satisfies a policy. `signer_commitment` authenticates
  the set's membership, not identity or quorum: which keys count, which
  roles are required, and how many, remain host policy
  ([trust.md](trust.md), [federation.md](federation.md)) — the
  commitment is what makes evaluating that policy over the reported set
  sound.
- That `signed_at` is the real time of sealing. Self-attested time is
  trivially backdatable. External anchoring (Rekor / RFC 3161) is
  parking-lot for v0.7+.
- That the contents are correct, true, or non-malicious. Integrity is
  not authority.

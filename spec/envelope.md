# Provenance Envelope

`provenance/envelope.json` carries the signatures that bind the capsule
to one or more keys at one moment in time. The schema and signing
procedure below replace the prior format's `signing_hash` construction.

## Schema

```json
{
  "version": "0.6",
  "capsule_id": "<64-hex>",
  "first_event_hash": "<64-hex>",
  "entry_hash": "<64-hex>",
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

- `version`: `"0.6"`. Readers reject unknown versions; no silent
  upgrade path.
- `capsule_id`: matches `manifest.id`.
- `first_event_hash`: 32-byte SHA-256 hex; equals chain event 1's hash.
- `entry_hash`: 32-byte SHA-256 hex; equals the final event's hash at
  seal time. Together with `first_event_hash`, commits to the chain
  range covered by the seal.
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

## Verification

For each signer:

1. Reconstruct `canonical_payload` from the envelope minus `signers`.
2. Reconstruct `domain_sep` from the signer's `role`.
3. Reconstruct `signing_input = domain_sep || canonical_payload`.
4. Convert `signers[i].public_key` (hex) to 32 raw bytes.
5. Convert `signers[i].signature` (hex) to 64 raw bytes.
6. `Ed25519.verify(public_key, signing_input, signature)`.
7. Record per-signer `valid: true | false`.

Then:

1. Recompute `manifest_hash` from the manifest as actually stored.
   Compare to `envelope.manifest_hash`.
2. Recompute `content_index_hash` from `manifest.content_index.files`.
   Compare.
3. Recompute `first_event_hash` and `entry_hash` from the chain.
   Compare.
4. For encrypted capsules: recompute SHA-256 of `content.enc`. Compare
   to `encrypted_blob_hash`.

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
- That `signed_at` is the real time of sealing. Self-attested time is
  trivially backdatable. External anchoring (Rekor / RFC 3161) is
  parking-lot for v0.7+.
- That the contents are correct, true, or non-malicious. Integrity is
  not authority.

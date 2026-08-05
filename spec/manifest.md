# manifest.json

The manifest is the typed metadata sidecar. It is small (~20 fields) and
machine-readable. Human-readable narrative lives in `program.md`, not
here.

## Schema

```json
{
  "format": {
    "version": "0.7",
    "container": "zip",
    "canonicalization": "JCS-RFC8785",
    "hash_algorithm": "SHA-256"
  },
  "id": "<64-hex>",
  "originator": {
    "public_key": "<64-hex ed25519 raw>",
    "label": "Acme Loan Co."
  },
  "participants": [
    {
      "actor_id": "human:alice@acme.example",
      "role": "originator",
      "label": "Alice (loan officer)"
    },
    {
      "actor_id": "ai:claude-opus-4-7",
      "role": "advisor",
      "label": "AI advisor"
    }
  ],
  "first_event_hash": "<64-hex> | null",
  "content_index": {
    "files": [
      { "path": "program.md", "sha256": "<64-hex>" },
      { "path": "agents.md", "sha256": "<64-hex>" },
      { "path": "chain/events.jsonl", "sha256": "<64-hex>" },
      { "path": "skills/foo/skill.json", "sha256": "<64-hex>" },
      { "path": "skills/foo/SKILL.md", "sha256": "<64-hex>" }
    ],
    "index_hash": "<64-hex>"
  },
  "signer_commitment": [
    { "role": "approver", "public_key": "<64-hex ed25519 raw>" },
    { "role": "originator", "public_key": "<64-hex ed25519 raw>" }
  ],
  "encryption": null,
  "created_at": "2026-05-07T12:00:00Z"
}
```

## Field rules

- `format.*`: fixed for v0.7 capsules. `format.version` declares the
  capsule's format era and MUST equal `envelope.version`. Readers accept
  any KNOWN version under that era's rules, and fail closed on an
  unknown one with a diagnosis distinct from tamper detection — see
  [versioning.md](versioning.md). Conformance vectors:
  `spec/vectors/version-compat/`.
- `id`: derived; see "Capsule identity" below. Computed by the writer
  and checked by the reader.
- `originator.public_key`: 32 bytes of Ed25519 raw public key, lowercase
  hex. The `signers[]` of the envelope MUST include an entry whose
  `public_key` equals this value with role `originator`, and that
  entry's signature MUST verify. This is an integrity invariant enforced
  by verifiers at every profile — a manifest naming an originator who
  never signed is the capsule asserting something false about itself.
  Conformance vector: `spec/vectors/signer-set/` (`originator-not-a-signer`).
- `originator.label`: free-text, advisory only, and OPTIONAL — it MAY
  be absent, and it is never a verification input. Auditors verify the
  public key, not the label. Conformance vector:
  `spec/vectors/chain-rules/` (`absent-advisory-manifest-members`).
- `participants`: an ARRAY of participant objects when present. The
  member may be ABSENT, and the array may be EMPTY — both are the same
  weaker claim made honestly (no assertion about who acted; verifiers
  report an unbound actor set and proceed). A PRESENT `participants`
  of any other type (object, string, number, …) is a malformed
  manifest, rejected fail-closed: silently skipping it would no-op the
  actor-membership rule and the `actor_id` grammar check below while
  presenting exactly like an honest unbound capsule. Conformance
  vectors: `spec/vectors/malformed-shape/` (`participants-not-array`,
  `participants-string`); `spec/vectors/chain-rules/`
  (`absent-participants`, `unbound-actors`).
- `participants[]` entry shape: each entry is a participant object, and
  `actor_id` is the ONE member of it this spec interprets. A bare
  actor-id STRING is an accepted equivalent shorthand for
  `{ "actor_id": <string> }` — writers MAY emit either shape, and
  verifiers MUST interpret both identically: grammar-checked (below)
  and binding the actor set. An entry of any other shape, or an entry
  whose `actor_id` is missing or not a string, is a DECLARED
  participant no reader can bind: malformed, rejected fail-closed with
  the same `participants[i].actor_id` diagnosis in every lane — never a
  lane-specific parse failure that makes a spec-valid capsule look
  corrupt. Conformance vectors: `spec/vectors/chain-rules/`
  (`participant-bare-string`, `participant-missing-actor-id`).
- `participants[].actor_id`: must match one of the patterns
  `human:<id>`, `ai:<id>`, `system:<id>`, `capsule:<id>` — the
  namespace set is CLOSED and `<id>` is any non-empty string
  (case-sensitive; nothing before the namespace, one `:` separates it
  from `<id>`). Writers refuse to declare a participant outside the
  grammar; verifiers reject one fail-closed. This is not an assurance
  tier: an EMPTY `participants[]` is a weaker claim made honestly
  (reported as an unbound actor set), but a DECLARED entry no reader
  can interpret is the manifest asserting something meaningless about
  who acted. Not cryptographically bound to a key by default — only
  `originator` is. Conformance vector: `spec/vectors/chain-rules/`
  (`invalid-actor-namespace`).
- `participants[].role`, `participants[].label`: OPTIONAL advisory
  attribution/display text, like `originator.label`. They are NEVER
  verification inputs: verifiers MUST NOT gate any outcome on their
  presence, absence, or type, and a typed reader MUST NOT refuse to
  open a capsule over them — the values sit under `manifest_hash`
  either way, so tampering is still sealed out. A participant declared
  with only an `actor_id` is a weaker claim made honestly: who is
  involved, without asserting what function each served. Auditors
  verify keys and the actor binding, not display text. Conformance
  vectors: `spec/vectors/chain-rules/` (`participant-only-actor-id`,
  `advisory-members-any-type`).
- `first_event_hash`: 32 bytes of SHA-256, lowercase hex; equals the
  hash of the first event in `chain/events.jsonl`. When the chain has
  ZERO events (see [chain.md](chain.md) "Empty chains") this member
  MUST be `null` — a zero-event capsule has no first event, and a
  non-null value over an empty chain is an integrity violation that
  verifiers reject fail-closed. Conversely, `null` with a non-empty
  chain fails verification. Conformance vectors:
  `spec/vectors/chain-binding/`.
- `content_index.files`: every file in the capsule *except* the
  structural files `manifest.json` (the index lives inside it) and
  `provenance/envelope.json` (it commits to the index hash), plus — **only
  when the envelope declares a cipher other than `none`** — `content.enc`,
  which is bound instead by `envelope.encrypted_blob_hash`.
  - Sorted by `path` on **UTF-16 code-unit sequences** — the same ordering
    RFC 8785 §3.2.3 applies to object members. `content_index.files` is a
    JSON array, so this order is inside the bytes `index_hash` covers.
    This is NOT Unicode code-point order: the two disagree whenever a
    supplementary-plane path (>= U+10000, UTF-16 lead surrogate
    0xD800..0xDBFF) is compared against a path in U+E000..U+FFFF. Nor is it
    a normalization- or collation-aware order: canonically equivalent paths
    are distinct entries and MUST be strictly ordered. For ASCII-only paths
    every candidate ordering coincides. Pinned by
    `spec/vectors/jcs-key-order.json`.
  - `sha256` is over the raw file bytes as stored in the ZIP.
  - The `content.enc` exclusion is conditional on the *signed*
    `envelope.cipher`, not on file presence. In a plain capsule
    (`cipher: "none"`) a `content.enc` entry MUST be indexed like any other
    file, so a signed plain capsule cannot carry an unaccounted-for blob
    past verification. Forcing the exclusion by editing `cipher` invalidates
    the envelope signature.
- `content_index.index_hash`: SHA-256 over the JCS-canonical
  serialization of `content_index.files`.
- There is **no `skill_trust` member**. Skill trust is host-relative —
  it depends on the allowlist the verifying host supplies — so it is
  DERIVED from the verify result, never declared by the author (see
  [trust.md](trust.md) "Skill trust"). A capsule from an earlier draft
  that carries the member is treated as carrying an unknown member:
  preserved verbatim, included in `manifest_hash`, and semantically
  inert — verifiers MUST NOT read it as a trust input. Conformance
  vectors: `spec/vectors/skill-trust/`.
- `signer_commitment`: the exact membership of the seal-time signer
  set, as an array of `{role, public_key}` members. The envelope's
  signing input is `JCS(envelope minus signers)`, so `signers[]` is not
  an input to any signature; this field is what binds the set, because
  `manifest_hash` *is* inside every signature. (This is the TUF/DSSE
  shape: authenticate the requirement in a signed parent, never the
  signature array itself.)
  - **Optional — presence binds, absence reports.** When present, the
    normalized envelope signer set MUST equal this array exactly (see
    below); any mismatch fails verification closed. When absent, the
    capsule does not assert signer-set integrity: verification MAY
    still succeed, and the verifier MUST report, machine-readably, that
    the signer set is unbound (a weaker claim made honestly — this is
    what lets unsigned templates and legacy capsules share the format
    with a notarised loan file). A writer that seals with the v0.7
    cryptographic profile SHOULD always emit it; the SDK builders do.
  - Each member carries exactly `role` (non-empty string) and
    `public_key` (lowercase 64-hex Ed25519 raw key). Members are sorted
    ascending by `public_key`, then `role`, byte order — equivalently,
    by each member's JCS bytes. `(role, public_key)` pairs MUST be
    unique; the same key under different roles is permitted as distinct
    members. The commitment is bound by its stored bytes, so the sort
    order is normative: a commitment that is unsorted, has duplicate
    members, or is present-but-empty is malformed and fails
    verification closed.
  - **Equality rule (normative):** normalize each `envelope.signers[]`
    entry to `(role, lowercase public_key)`; the resulting set, sorted
    as above, MUST equal `signer_commitment` member-for-member. A
    stripped signer, an appended signer (any role), a role swap, or a
    duplicated signer entry all fail.
  - One commitment value serves both the inner and outer manifests of
    an encrypted capsule — both are sealed by the same signer list.
  - Conformance vectors: `spec/vectors/signer-set/`.
- `encryption`: `null` for plain capsules; for encrypted capsules a
  small object pointing to the decryption metadata path:
  ```json
  { "metadata_path": "skills/decryption/decryption.json", "cipher": "ChaCha20-Poly1305" }
  ```
- `created_at`: ISO 8601 UTC; advisory only, and OPTIONAL — it MAY be
  absent and is never a verification input. Authoritative time-binding
  is the envelope's `signed_at`. Conformance vector:
  `spec/vectors/chain-rules/` (`absent-advisory-manifest-members`).

## Unknown members

Organisations building on Capsules extend the manifest with their own
members — auth metadata, policy tags, deployment identifiers. The format
supports this without a registry, because `manifest_hash` covers the
whole document:

- Writers MAY include members beyond the schema above. An extension
  member MUST use a key prefixed `x-`, vendor-scoped as
  `x-<vendor>-<name>` (e.g. `x-acme-policy`). Future spec versions will
  never define a member whose key begins with `x-`, so extensions cannot
  collide with the spec.
- Readers MUST preserve unknown members verbatim — recognised or not —
  and MUST include them in the JCS canonicalization when recomputing
  `manifest_hash`. Dropping or rewriting an unknown member is a
  conformance violation: the recomputed hash diverges from what the
  signer signed, and a valid capsule fails verification. In particular,
  a reader MUST NOT recompute the hash from a re-serialized typed
  projection of the manifest; it hashes the document as stored.
- Preservation is an integrity invariant, enforced identically at every
  deployment profile. Whether a given extension member is *meaningful*
  is host policy; that it is *covered by the seal* is not.

This one rule buys extensibility and archival durability together: a
legitimate signer signs over their own extensions; an attacker cannot
inject or mutate a member without breaking `manifest_hash` (and with it
the envelope signature); and a capsule sealed today stays verifiable by
readers built against future spec versions that add members.

Conformance vectors: `spec/vectors/unknown-fields/`.

## Capsule identity

```
capsule_id = SHA-256(
    "capsule-id-v<version>\x00" ||       # <version> = format.version
    originator_public_key_raw_bytes ||
    first_event_hash_raw_bytes
)
```

Notes:

- All concatenations are raw bytes. No hex strings as inputs.
- Domain-separation prefix `"capsule-id-v0.7\x00"` (for a capsule
  declaring version 0.7) is 16 ASCII bytes including the trailing NUL,
  so the prefix has a fixed boundary. The
  prefix embeds the capsule's declared format version and is selected
  BY that declared version, forever — a verifier recomputing the id of
  a v0.6 capsule uses the v0.6 domain whatever version it seals at
  ([versioning.md](versioning.md) "Version-keyed domain separation").
- **Empty chain:** when `first_event_hash` is `null` (zero-event
  capsule, see [chain.md](chain.md) "Empty chains"),
  `first_event_hash_raw_bytes` is 32 zero bytes — the same value as the
  chain's genesis previous-hash. Consequence: two zero-event capsules
  from the same originator share a `capsule_id`; identity diverges once
  the first event is appended and the capsule is re-sealed. That is the
  honest reading of a draft with no history.
- This binds the identity to a public key. Identity squatting on a
  future ledger requires the squatter to also possess a private key
  whose public key the squatter wants to claim — not a free win.

## What the manifest does *not* contain

- No `surface.md` pointer (the program is at `program.md`, fixed path).
- No `state.json` projection (state is computed from the chain).
- No `plan.md` pointer (the plan is a section of `program.md`).
- No skill execution metadata (`runtime`, `entrypoint`, `command`,
  `tool_id` are all rejected; skills are instructions, not programs).
- No `last_sequence` counter (read it from the chain).

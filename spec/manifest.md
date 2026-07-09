# manifest.json

The manifest is the typed metadata sidecar. It is small (~20 fields) and
machine-readable. Human-readable narrative lives in `program.md`, not
here.

## Schema

```json
{
  "format": {
    "version": "0.6",
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
  "first_event_hash": "<64-hex>",
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
  "skill_trust": {
    "<skill_id>": "signed | unsigned"
  },
  "encryption": null,
  "created_at": "2026-05-07T12:00:00Z"
}
```

## Field rules

- `format.*`: fixed for v0.6 capsules. Readers reject unknown
  `format.version`.
- `id`: derived; see "Capsule identity" below. Computed by the writer
  and checked by the reader.
- `originator.public_key`: 32 bytes of Ed25519 raw public key, lowercase
  hex. The `signers[]` of the envelope must include an entry whose
  `public_key` equals this value with role `originator`.
- `originator.label`: free-text, advisory only. Auditors verify the
  public key, not the label.
- `participants[].actor_id`: must match one of the patterns
  `human:<id>`, `ai:<id>`, `system:<id>`, `capsule:<id>`. Not
  cryptographically bound to a key by default — only `originator` is.
- `first_event_hash`: 32 bytes of SHA-256, lowercase hex; equals the
  hash of the first event in `chain/events.jsonl`.
- `content_index.files`: every file in the capsule *except* the
  structural files `manifest.json` (the index lives inside it) and
  `provenance/envelope.json` (it commits to the index hash), plus — **only
  when the envelope declares a cipher other than `none`** — `content.enc`,
  which is bound instead by `envelope.encrypted_blob_hash`.
  - Sorted by `path`, ASCII order.
  - `sha256` is over the raw file bytes as stored in the ZIP.
  - The `content.enc` exclusion is conditional on the *signed*
    `envelope.cipher`, not on file presence. In a plain capsule
    (`cipher: "none"`) a `content.enc` entry MUST be indexed like any other
    file, so a signed plain capsule cannot carry an unaccounted-for blob
    past verification. Forcing the exclusion by editing `cipher` invalidates
    the envelope signature.
- `content_index.index_hash`: SHA-256 over the JCS-canonical
  serialization of `content_index.files`.
- `skill_trust`: per-skill trust assertion (see [trust.md](trust.md)).
  Skills marked `signed` must have their `skill.json` covered by an
  envelope signature; unsigned skills are passed to readers as
  untrusted content.
- `encryption`: `null` for plain capsules; for encrypted capsules a
  small object pointing to the decryption metadata path:
  ```json
  { "metadata_path": "skills/decryption/decryption.json", "cipher": "ChaCha20-Poly1305" }
  ```
- `created_at`: ISO 8601 UTC; advisory only. Authoritative time-binding
  is the envelope's `signed_at`.

## Capsule identity

```
capsule_id = SHA-256(
    "capsule-id-v0.6\x00" ||
    originator_public_key_raw_bytes ||
    first_event_hash_raw_bytes
)
```

Notes:

- All concatenations are raw bytes. No hex strings as inputs.
- Domain-separation prefix `"capsule-id-v0.6\x00"` is 16 ASCII bytes
  including the trailing NUL, so the prefix has a fixed boundary.
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

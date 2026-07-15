# File Layout

A `.capsule` is a deterministic ZIP archive. The container is standard
ZIP; the determinism comes from canonical file ordering and fixed
timestamps inside the archive.

## Plain (unencrypted) capsule

```
example.capsule
├── manifest.json
├── program.md
├── agents.md
├── chain/
│   └── events.jsonl
├── skills/
│   └── <skill_id>/
│       ├── skill.json
│       └── SKILL.md
├── payload/
│   └── ...arbitrary files...
└── provenance/
    └── envelope.json
```

## Encrypted capsule (outer layer)

The outer archive is plaintext metadata; the inner capsule is encrypted
as one blob.

```
example.capsule
├── manifest.json                       outer manifest, encryption-aware
├── content.enc                         encrypted inner ZIP
├── skills/
│   └── decryption/
│       └── decryption.json             cipher, nonce, recipient bundles
└── provenance/
    └── envelope.json                   signs the encrypted-blob hash
```

The decrypted inner content is a normal capsule layout (the "Plain"
shape above) parsed by the same reader.

## Required files

Every capsule has:

- `manifest.json`
- `program.md`
- `chain/events.jsonl`
- `provenance/envelope.json`

Optional but conventional:

- `agents.md` — recommended whenever more than one actor participates
- `skills/<id>/skill.json` and/or `skills/<id>/SKILL.md` — see
  [trust.md](trust.md) for trust tiers
- `payload/...` — arbitrary

For encrypted capsules, the inner shape contains the required files; the
outer shape replaces them with `content.enc` plus decryption metadata.

## Files that are *not* part of v0.6

The following files appeared in the prior format and are not part of
v0.6:

- `surface.md` — replaced by `program.md`
- `handoff.md` — folded into `program.md` as a "Continuation" section
- `state/state.json` — state is a projection of the chain; not stored
- `plan.md` — folded into `program.md` as a "Plan" section
- `skills_used_in_this_capsule.md` — computed at read
- `surface-citations.md` convention — ordinary markdown links

A reader that encounters these files in an old capsule should ignore
them (they are not authoritative under v0.6) but should not error.

## Container properties

- File entries are sorted by path, ASCII order.
- Internal ZIP timestamps are fixed at `1980-01-01T00:00:00Z` (the ZIP
  epoch) so identical content produces identical bytes.
- Compression: `STORED` (no compression). This makes archive bytes a
  function of content only, not of compression-library version. Readers
  reject any entry with another compression method.
- Symlinks, hardlinks, and out-of-tree paths (`..`, absolute paths, NULs)
  are rejected by readers as ZIP-slip protection.
- Duplicate entry names are rejected by readers. Two entries with the
  same name are a parser differential (ZIP libraries disagree on which
  copy wins), so a signed capsule must never contain one.
- Entry-name and entry-shape checks apply to the names as stored in the
  archive's central directory. A reader whose ZIP library sanitizes or
  deduplicates names on load must check the raw central directory
  itself, or it will silently accept archives that other readers reject.
- File-count and total-uncompressed-size limits are configurable on the
  reader; defaults are 10,000 entries and 1 GiB. Exceeding either is a
  rejection.

Malformed-container conformance fixtures for these rules live in
`spec/vectors/malformed-layout/`.

## Determinism boundary

Determinism is a write-time property of one implementation, not a
protocol guarantee across implementations. Two implementations producing
"the same" capsule are not required to produce byte-identical archives;
they are required to produce archives whose `content_index` (per-file
hashes) match, and whose canonical envelope payload matches.

This is the right boundary because it is what an auditor actually checks.

# Changelog

All notable changes to the Capsule format, reference SDKs, and tooling
in this repository will be documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
protocol uses semantic-version pinning at the format layer (the
`0.6` in the file format will not silently mean different things —
incompatible wire changes ship as `0.7`).

## v0.6.0-prototype.1 — 2026-05-12 (unreleased)

The v0.6 redesign of the Capsule format around the actual product:
a portable unit of intelligence with the document, its agents, and a
signed append-only audit trail. Not backwards-compatible with the
`0.5.x` line. See `README.md` for the full rationale.

### Changed

- **Document artifacts collapsed.** `surface.md` + `handoff.md` +
  `state.json` + `plan.md` + `skills_used_in_this_capsule.md` are
  replaced by `program.md` + `agents.md`. State is computed; handoff
  and plan are sections of `program.md`; skill inventory is computed
  at read.
- **Chain hash linkage uses raw bytes.** Previous: `SHA-256(prev_hash_hex_utf8 || JCS(event))`. Now: `SHA-256(prev_hash_raw32 || JCS(event))`.
  Hex-encoded inputs are gone from the hash domain.
- **Envelope signing payload is the JCS-canonical envelope minus
  signers.** Previous: a derived `SHA-256(checkpoint_hash || ciphertext_hash || skill_hash)`. Signatures now bind what they claim to bind.
- **Signature input includes domain separation.** Previous: `Ed25519.sign(utf8(hex_string))`. Now: `Ed25519.sign(domain_sep_bytes || canonical_payload)`. No cross-protocol replay.
- **Cipher enum trimmed and fail-closed.** Previous:
  `none | ChaCha20-Poly1305 | AES-256-GCM` (last not implemented).
  Now: `none | ChaCha20-Poly1305`; unknown ciphers fail closed.
- **Capsule identity is not squattable.** Previous:
  `first_event_hash`. Now: `SHA-256("capsule-id-v0.6\x00" || originator_pubkey || first_event_hash)`.
- **Signers are a list, not two fixed roles.** Envelopes now carry
  `signers: [{role, public_key, signature}, ...]`, so multi-party
  workflows model naturally.
- **Self-attested temporal anchor.** Envelopes now carry `signed_at`.
  RFC 3161 / Rekor anchoring is planned.
- **RFC 8785 JCS via a reference library.** The in-house "matches RFC
  8785 semantics" implementation is gone in favor of an external,
  vetted JCS library.
- **Standard ZIP via a vetted library.** The custom deterministic
  `ZIP_STORED` writer is replaced with a standard ZIP library.
- **Skill instructions split into trust tiers.** Decryption is
  metadata only; instructions are tiered per `agents.md`.
- **Provenance version matched to SDK.** Previous: provenance `1.0`
  ahead of SDK `0.1.x`. Now: both at `0.6`.

### Notes

This release is **prototype**. The envelope schema is locked at `0.6`
on purpose — it will only graduate to `1.0` once a second independent
implementation round-trips the test vectors and an outside party
reviews the crypto. See `ROADMAP.md` for the path to lock.

Future entries in this changelog will follow the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) sections
(`Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`).

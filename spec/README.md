# Capsule Spec — v0.6

A portable unit of intelligence: a work product, the context to continue
it, and a verifiable audit trail.

## What v0.6 keeps

These five things are the actual product. They survive untouched.

1. **Skill bundles as foreign-LLM context.** A capsule carries the
   instructions a different model needs to pick up the work.
2. **Append-only signed event chain.** Audit-grade primitive for "who
   decided what, when, against which evidence."
3. **Encrypted content with public attestation.** L2 verification proves
   the encrypted artifact exists and binds to the envelope without
   revealing contents. Loan applications, AML reviews, scoping
   documents, regulatory filings.
4. **Pith as a context-style discipline.** Cold-reading LLMs absorb
   Pith-styled narrative faster and with fewer hallucinations than
   free-form prose. The reference library is a normalizer, not
   "deterministic compression" — that framing was misleading.
5. **Offline-first verification.** The capsule file verifies without a
   server. Hosted services are optional layers, never required.

## What v0.6 strips

Subtractions that remove weight without removing capability.

- `surface.md` + `handoff.md` + `state.json` + `plan.md` →
  one `program.md` with sections.
- `skills_used_in_this_capsule.md` → computed on read.
- Surface-citation convention → ordinary markdown links.
- Custom in-house JCS implementation → RFC 8785 reference library.
- Custom deterministic ZIP_STORED writer → standard ZIP via vetted
  library.
- `SkillExecutor` execution-hook scaffolding → skills are *instructions
  for foreign LLMs*; hosts run whatever they want.
- Embedded SDK inside the skill bundle → SDK declared as a dependency.
- `skills/decryption/SKILL.md` markdown twin → decryption is metadata
  only; no agent-instruction surface for crypto-adjacent operations.
- `access_endpoint` field in decryption metadata → no fetched-content-key
  feature without a documented threat model.
- Reserved-but-unimplemented `AES-256-GCM` cipher → fail closed on
  unknown ciphers.
- `Tool:` plan directive lane (already deprecated) → removed entirely;
  no shim.
- "Mobile-readability non-negotiable" claim ahead of measurement →
  softened until benchmarked.
- "Deterministic compression" framing for Pith → relabeled as a
  context-style discipline.

## What v0.6 replaces

| Topic | Was | Now |
|---|---|---|
| Chain hash linkage | `SHA-256(prev_hex_utf8 \|\| JCS(event))` | `SHA-256(prev_raw32 \|\| JCS(event))` |
| Genesis previous hash | 64 ASCII zeroes | 32 zero bytes |
| Envelope signing payload | `SHA-256(checkpoint_hash \|\| ciphertext_hash \|\| skill_hash)` | JCS-canonical envelope minus signers |
| Signature input | `Ed25519.sign(utf8(hex_string))` | `Ed25519.sign(domain_sep_bytes \|\| canonical_envelope_bytes)` |
| Capsule identity | `first_event_hash` | `SHA-256("capsule-id-v0.6\x00" \|\| originator_pubkey \|\| first_event_hash)` |
| Signers | Two fixed roles | `signers: [{role, public_key, signature}, ...]` |
| Temporal binding | None | Self-attested `signed_at` (ISO 8601 UTC) |
| Cipher enum | Includes unimplemented `AES-256-GCM` | `none \| ChaCha20-Poly1305` |

See [envelope.md](envelope.md) for the full envelope schema and signing
procedure.

## Document index

- [format.md](format.md) — file layout
- [manifest.md](manifest.md) — manifest.json schema and capsule identity
- [chain.md](chain.md) — event format and hash linkage
- [envelope.md](envelope.md) — provenance envelope, signing, encryption
- [trust.md](trust.md) — trust model, allowlists, skill trust tiers
- [pith.md](pith.md) — context-style discipline for narrative fields

## Versioning

This spec is `v0.6`. So is the SDK lane and the envelope schema. They
move together until a second independent implementation lands.

`v1.0` is the schema that will be verified for ten years. v0.6 is the
schema that earns its way there.

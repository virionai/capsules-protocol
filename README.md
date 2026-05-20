# Capsules

> An open protocol for portable, signed, AI-readable records of multi-actor work.

**The protocol behind [capsules.run](https://capsules.run).** Built by [Virion.AI](https://virion.ai). MIT licensed. v0.6 prototype.

[Kaggle Gemma 4 Good Hackathon submission](https://capsules.run/competitions/gemma-4-good/) · [Live in-browser reader](https://capsules.run/load/) · [Roadmap](https://capsules.run/roadmap/) · [Conformance](https://capsules.run/conformance/)

---

## 20 minutes to a verified capsule

If you arrived here from the Kaggle submission and want to verify the work:

1. **Clone and run.**
   ```sh
   git clone https://github.com/virionai/capsules
   cd capsules
   ```

2. **Pick an SDK lane and round-trip a capsule:**
   - **JavaScript** (reference impl): `cd sdk-js && npm install && npm test`
   - **Python**: `cd sdk-py && pip install -e . && pytest`
   - **Rust verifier**: `cd verifier-rust && cargo test`

   All three produce or verify the same canonical capsule artifacts. Cross-impl parity is the [ROADMAP.md](ROADMAP.md) milestone 5 unlock signal.

3. **Open a real capsule in your browser.**
   Visit [capsules.run/load](https://capsules.run/load/) and click any of the ten gallery capsules (health, crisis response, B2B sales, research, verifiability demos). The page parses and verifies the chain offline in your browser. Drop your own `.capsule` file too.

4. **Try the tamper-detection demo.**
   The "Tampered payload" card in the gallery is a capsule with one byte flipped. The reader names the failing check (content_index mismatch). Tamper-evident by construction.

## What's in this repo

```
spec/                  v0.6 protocol specification (normative)
  README.md            stripped/replaced/kept summary
  format.md            file layout
  manifest.md          manifest.json schema
  chain.md             event chain rules
  envelope.md          provenance envelope schema
  trust.md             trust model and skill trust tiers
  pith.md              context-style discipline (informative)

sdk-js/                JavaScript reference SDK (npm)
sdk-py/                Python SDK
sdk-swift/             Swift SDK (iOS/macOS via SwiftPM)
sdk-kotlin/            Kotlin SDK (Android/JVM via Gradle)
verifier-rust/         independent Rust verifier (cargo)
cli/                   command-line verifier and inspector
tools/                 conformance harness
.github/workflows/     CI: conformance harness on every push + nightly
```

## What v0.6 is

A redesign of the Capsule format around the actual product:

> A portable unit of intelligence. The work product (loan application, AML
> review, scoping document, code, media) travels with the context needed to
> continue it (Pith-style narrative, agents, skills) and an append-only,
> signed audit trail. Foreign LLMs can cold-load it. Regulators and auditors
> can verify it months later. Platforms can ship it as the unit of work.

This directory is a stripped, working prototype of that idea. It is not
backwards-compatible with the prior `0.5.x` shape.

## The protocol earns its weight by being load-bearing in a specific use case

The first reference application is **Operators**: the [submission writeup](https://capsules.run/competitions/gemma-4-good/) for the full architecture.

Other verticals under active integration with our client products: lender-ready loan packets (ReadySet), compliance investigations (ComplianceQ), home-renovation project records (Fix.Now), and multi-party B2B correspondence. Same protocol; different domains. The [live gallery](https://capsules.run/load/) demonstrates this.

## The minimum viable capsule

```
example.capsule (deterministic ZIP)
├── manifest.json                   ~20 fields: id, originator, participants, content_index
├── program.md                      the document: loan app, review, scope, etc.
├── agents.md                       who's allowed to do what; skill-trust roots
├── chain/events.jsonl              append-only signed decision log
├── skills/                         carry-on context for foreign LLMs
│   └── <id>/
│       ├── skill.json              typed metadata
│       └── SKILL.md                instructions (trust tier per agents.md)
├── payload/                        whatever travels: PDFs, code, datasets, media
└── provenance/envelope.json        signed envelope, optional encryption
```

There is no `state.json`, `handoff.md`, `plan.md`, `surface-citations.md`,
or `skills_used_in_this_capsule.md`. State is computed. Handoff is a
section of `program.md`. Plan is a section of `program.md`. Citations are
markdown links. Skill inventory is computed at read.

## Status

Prototype. Not v1.0. The envelope schema is `0.6` on purpose; locked once a second independent implementation round-trips the test vectors and an outside party reviews the crypto. See [ROADMAP.md](ROADMAP.md) for the five review checkpoints.

## Conformance

Live signal at [capsules.run/conformance](https://capsules.run/conformance/) regenerated on every push to main plus nightly. Five SDK lanes target the same signed test vectors. The site mirrors the GitHub-side report.

## Try the demo locally

```sh
cd sdk-js
npm install
npm test
```

The JS test suite builds capsules (clean and tampered) and runs verification on each. The clean capsule passes. Each tampered capsule fails at a distinct, reported check.

For the cross-language conformance harness, see `tools/` and `.github/workflows/conformance.yml`.

## License

MIT. See [LICENSE](LICENSE). Contributing welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Security disclosure: see [SECURITY.md](SECURITY.md).

---

## Design rationale and history

### What changed at a glance

Six artifacts collapsed to two-plus-chain, custom parsers replaced with
vetted libraries, the envelope reworked so signatures actually bind what
they claim to bind.

| Topic | Old | New |
|---|---|---|
| Document artifacts | `surface.md` + `handoff.md` + `state.json` + `plan.md` + `skills_used_in_this_capsule.md` | `program.md` + `agents.md` (state is computed) |
| Chain hash linkage | `SHA-256(prev_hash_hex_utf8 \|\| JCS(event))` | `SHA-256(prev_hash_raw32 \|\| JCS(event))` |
| Envelope signing payload | `SHA-256(checkpoint_hash \|\| ciphertext_hash \|\| skill_hash)` | JCS-canonical envelope minus signers |
| Signature input | `Ed25519.sign(utf8(hex_string))` | `Ed25519.sign(domain_sep_bytes \|\| canonical_payload)` |
| Cipher enum | `none \| ChaCha20-Poly1305 \| AES-256-GCM` (last not implemented) | `none \| ChaCha20-Poly1305` (fail-closed on unknown) |
| Capsule identity | `first_event_hash` (squattable) | `SHA-256("capsule-id-v0.6\x00" \|\| originator_pubkey \|\| first_event_hash)` |
| Signers | Two fixed roles | `signers: [{role, public_key, signature}, ...]` |
| Temporal anchor | None | Self-attested `signed_at` (RFC 3161/Rekor planned) |
| JCS | In-house "matches RFC 8785 semantics" | RFC 8785 reference library |
| ZIP | Custom deterministic ZIP_STORED writer | Standard ZIP via vetted library |
| Skill instructions | Mixed metadata + markdown for foreign LLMs | Two trust tiers; decryption is metadata only |
| Provenance version | `1.0` ahead of SDK `0.1.x` | `0.6` matched to SDK |

For the full rationale see [CHANGELOG.md](CHANGELOG.md) and the normative [spec/](spec/) documents.

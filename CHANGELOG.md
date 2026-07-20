# Changelog

All notable changes to the Capsule format, reference SDKs, and tooling
in this repository will be documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
protocol uses semantic-version pinning at the format layer (the
`0.6` in the file format will not silently mean different things —
incompatible wire changes ship as `0.7`).

## Unreleased

### Added

- **sdk-py onboarding surface.** The Python SDK mirrors the sdk-js
  ergonomics: every key input accepts hex strings (any case) or 32 raw
  bytes, `Ed25519KeyPair`/`X25519KeyPair` objects work as-is as
  `originator`, `signers`, `recipients`, and `decrypt()` arguments,
  `seal()` defaults `signed_at`, `append_event()` defaults
  `kind`/`target`/`timestamp`, and `verify_capsule()` accepts raw bytes
  with a fail-closed result for unopenable containers
  (`capsule.keys` module; README rewritten as a quickstart pinned by
  `tests/test_dx.py`). Wire format unchanged.
- **sdk-js onboarding surface.** Every key input now accepts hex strings
  (any case) or 32 raw bytes interchangeably, and the keypair objects
  from `generateEd25519()`/`generateX25519()` work as-is as
  `originator`, `signers`, `recipients`, and `decrypt()` arguments
  (signer role defaults to `"originator"`). `seal()` defaults
  `signedAt` to now; `appendEvent()` defaults `kind`/`target`/
  `timestamp`. `verifyCapsule()` accepts raw capsule bytes and returns a
  fail-closed result for unopenable containers instead of throwing.
  TypeScript declarations ship as `src/index.d.ts` (wired via
  `types`/`exports`). The README is rewritten as an app-integration
  quickstart whose code runs verbatim in CI as `examples/quickstart/`
  (new `example-quickstart` conformance target). Wire format unchanged.

- **Malformed-layout vector registry.** `spec/vectors/malformed-layout/`
  pins open-stage rejection outcomes (missing required files, invalid
  JSON, duplicate entries, unsafe paths, non-STORED compression, symlink
  entries, missing chain file) behind a normative `stage`/`reason`
  vocabulary, generated deterministically from the clean tamper fixture.
- **Byte-level signing-input vectors.** `spec/vectors/signing-input.json`
  pins the exact bytes signed, hashed, and identified for the
  `plain-basic` capsule: capsule_id preimage, per-event hash preimages,
  manifest/content-index canonical bytes, envelope canonical payload,
  and per-role Ed25519 signing inputs.
- **Registry-driven lanes.** Python (`test_spec_registry.py`) and Rust
  (`spec_registry.rs`) now consume the tamper-detection and
  malformed-layout outcome registries and the signing-input pins
  directly, instead of hand-copied per-fixture assertions.

### Changed

- **Container strictness is now uniform and checked against the raw
  central directory.** All readers reject duplicate entry names (a ZIP
  parser differential); the JS reference reader now rejects non-STORED
  compression and symlink entries (Python and Rust already did) and
  validates entry names before JSZip's load-time sanitization can mask
  them. `spec/format.md` records the duplicate-entry and
  raw-central-directory rules as container properties.
- **Python `verify_capsule` fails closed on a missing/unparseable chain
  file** (chain error in the result, matching the Rust verifier) instead
  of raising out of the verify call.

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

### Added

- **JCS number vector set.** `spec/vectors/jcs-numbers.json`: 256
  IEEE-754 bit patterns with their canonical serializations (Node
  `JSON.stringify` as oracle), covering exponent-notation thresholds,
  subnormals, extremes, and the 2^53 boundary. Vector-driven tests run
  in all five lanes; `tools/check-spec-vectors.mjs` validates the set
  against the JS SDK.
- **Kotlin and Swift CI lanes.** `conformance-kotlin` runs the Kotlin
  `:core` tests on every push; `conformance-swift` runs `swift test` on
  macOS. The conformance summary now gates on all five SDK lanes.

### Fixed

- **Cross-implementation JCS number canonicalization.** The Python,
  Kotlin, and Swift SDKs previously punted on ECMAScript
  `Number::toString` layout for non-integer doubles (e.g. emitting
  `1.5e-05`/`1.5E-5` where the reference emits `0.000015`), so a capsule
  containing such a number could verify under JS/Rust and fail under the
  other lanes. All three now implement the full ECMA-262 §7.1.12.1
  layout; Kotlin derives shortest-round-trip digits from the IEEE-754
  bits via exact BigDecimal arithmetic so results do not depend on the
  runtime's `Double.toString` (which differs between pre-19 JDKs,
  JDK 19+, and Android ART). Integers outside ±(2^53 − 1) are now
  rejected fail-closed in Python/Kotlin/Swift rather than serialized
  in a way JS cannot represent.
- **`tools/check-spec-vectors.mjs` no longer misclassifies non-capsule
  JSON.** It previously failed on `tamper-detection/output/keys.json`
  (fixture key material) and any non-capsule vector file; it now
  dispatches by vector type.
- **Kotlin SDK license metadata.** `sdk-kotlin/README.md` claimed
  Apache-2.0; the repository (and every other package) is MIT.

### Changed (docs)

- **Conformance harness framed as the JavaScript lane.**
  `tools/run-conformance.mjs` runs JS targets only; cross-implementation
  gating lives in the CI workflow. The harness banner, report header,
  and README now say so instead of implying the harness itself is the
  cross-language check.
- **Kotlin SDK scope labeled honestly.** The Kotlin core module is a
  plain-capsule (L2) implementation — no X25519/HKDF/ChaCha20-Poly1305,
  encrypted capsules rejected fail-closed. README and module docs now
  state this instead of presenting five equal SDKs.

### Notes

This release is **prototype**. The envelope schema is locked at `0.6`
on purpose — it will only graduate to `1.0` once a second independent
implementation round-trips the test vectors and an outside party
reviews the crypto. See `ROADMAP.md` for the path to lock.

Future entries in this changelog will follow the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) sections
(`Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`).

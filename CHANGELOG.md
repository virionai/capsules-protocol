# Changelog

All notable changes to the Capsule format, reference SDKs, and tooling
in this repository will be documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
protocol uses semantic-version pinning at the format layer (the
`0.6` in the file format will not silently mean different things —
incompatible wire changes ship as `0.7`).

## Unreleased

### Security

- **The chain.md step-6 actor rule and the closed `kind` enum are now
  enforced in all five lanes — with the actor rule conditioned on the
  manifest's own claim.** Only verifier-rust implemented step 6
  ("actor appears in manifest participants or is `system:host`"): the
  JS `verifyChain` never even received the manifest, and sdk-py,
  sdk-swift, and sdk-kotlin had no check at all, so a capsule whose
  audit-trail events were attributed to actors absent from the audited
  participant set — the audit-spoofing shape the rule exists to catch —
  verified `ok=true` with a trusted signer in four lanes while Rust
  rejected it. The settled rule, normative in `spec/chain.md`: a
  NON-EMPTY `participants[]` binds every event actor to the declared
  set or `system:host`, fail-closed in every verifier; an EMPTY
  `participants[]` is the manifest making no claim about who acted —
  a weaker claim made honestly (template / open-publication tiers) —
  so verification succeeds and every verifier REPORTS the unbound
  actor set machine-readably (`actorSet`/`actor_set`/`actorSetBound` =
  unbound, plus a note), mirroring the signer-set "presence binds,
  absence reports" contract. Conditioning on the list is safe because
  `participants[]` is covered by `manifest_hash` inside the signed
  payload — an attacker cannot empty it without breaking every
  envelope signature. Rust's previously unconditional check is
  relaxed accordingly. Separately, `kind` is a CLOSED enum
  (`decision | observation | mutation | session | checkpoint`) in
  every tier — no lane validated it — because a custom kind is not a
  weaker claim, it is unreadable to the foreign LLM reader; all five
  verifiers now reject unknown kinds per event (new verification step
  7). Both reference builders (`appendEvent` / `append_event`, plus
  the Swift and Kotlin builders) reject at append time: unknown kinds
  always, undeclared actors whenever participants are declared —
  never by auto-registering the actor (chain.md gains a "Writer
  obligations" section; Swift's `appendEvent` is now throwing). Every
  lane emits the Rust verifier's per-event message shape verbatim.
  New conformance collection `spec/vectors/chain-rules/`
  (deterministic generator
  `sdk-js/tools/generate-chain-rule-fixtures.mjs`, `--check` wired
  into the conformance harness): `actor-not-participant` and
  `unknown-kind` MUST fail in the chain area, and the
  `unbound-actors` positive control (empty participants, named actor)
  MUST verify with the unbound report — pinned machine-readably via
  the new `actor_set_bound` registry key, consumed by the JS, Python,
  Rust, Swift, and Kotlin registry lanes. The CLI reports `actor_set`
  in `--json` and the human checklist. Wire format unchanged.
- **The JS CLI's PASS now means exactly what was checked (T9: F03,
  F04, F47, F48).** `capsule verify` computed its exit code and
  PASS/FAIL line purely from the SDK's integrity-only verdict, so
  `--allowlist` had zero effect: a capsule signed by a completely
  different key than the operator allowlisted printed PASS and exited
  0 on the documented CI-gating path — and the argument parser treated
  any unrecognized long flag as a boolean, so a typo'd `--alowlist`
  (or the `--decryption-key` flag inspect wrongly recommended, or a
  second file argument) was silently ignored. The CLI is now the
  explicit policy layer the SDK deliberately is not: supplying
  `--allowlist` sets the policy "at least one distinct allowlisted key
  must carry a valid signature" and an unmatched allowlist FAILS with
  exit 1 and a loud reason; no allowlist means the PASS is qualified
  `integrity only — signer identity not checked` (absence downgrades
  reported assurance, never rejects); malformed allowlist entries are
  exit-2 usage errors (Rust CLI parity); the parser fails closed on
  unknown flags and unexpected positionals; every command answers
  `--help`. Exit codes are documented in `cli/README.md`: 0 =
  integrity verified AND policy satisfied, 1 = either failed, 2 =
  usage/I-O. JSON output gains `integrity_ok` and a
  `trust {policy, allowlist_size, trusted_signer_count, satisfied}`
  block, with `ok` now the overall verdict matching the exit code.
  `envelope.signed_at` renders as `Sealed at (attested)` — it is
  signer-supplied with no external time anchor and SKILL.md lists it
  under "what you must not trust". Encrypted-capsule messages no
  longer point at the unimplemented `verify --decryption-key`; they
  name the SDK's `reader.decrypt()` and the Rust `capsule-verify-cli`
  instead. sdk-js's `verifyCapsule` additionally emits the
  "allowlist provided but matched no signer" advisory (wording
  identical to verifier-rust), so the mismatch case never gets less
  warning than the no-policy case; the Python, Swift, and Kotlin
  lanes still lack that advisory and are tracked as follow-up. CLI
  smoke tests: 50 → 91.

- **Empty chains are legal — and then the anchors must be null.** A
  plain capsule's only envelope-to-chain binding is the
  `envelope.first_event_hash` / `entry_hash` comparison against the
  recomputed chain, and every verifier skipped it when the chain had
  zero events (there was no first event to compare), so a capsule
  claiming anchors over an empty `chain/events.jsonl` verified with the
  chain check rendered as an unqualified pass; the JS verifier
  additionally failed the empty case with an *empty* errors array (a
  dead `??=` assignment). The settled rule, normative in
  `spec/chain.md` ("Empty chains"): a zero-event chain is a legitimate
  weaker shape (templates, drafts — the open tier), and then
  `manifest.first_event_hash`, `envelope.first_event_hash` and
  `envelope.entry_hash` MUST all be `null` — claiming any of them over
  zero events fails closed; `capsule_id` derives with 32 zero bytes
  (the genesis prev-hash value) standing in for
  `first_event_hash_raw`; and verifiers report machine-readably
  (`chain.note` + `notes`) that no events were walked, never a bare
  pass. A `null` anchor over a non-empty chain keeps failing as a
  mismatch. Implemented in sdk-js, sdk-py, and verifier-rust (whose
  CLI now renders the chain note and no longer forces the line to PASS
  when a note is present); the Swift and Kotlin lanes still skip the
  comparison and are tracked as follow-up. New conformance collection
  `spec/vectors/chain-binding/` (deterministic generator
  `sdk-js/tools/generate-chain-binding-fixtures.mjs`, `--check` wired
  into the conformance harness) pins the passing null-anchor shape
  (with a `notes_includes` honest-reporting pin, newly supported by the
  JS/Python/Rust registry consumers), the failing claimed-anchor shape,
  and an event-without-`untrusted_payload_fields` positive that
  witnesses stored-line event hashing.

- **verifier-rust allowlist entries are validated and never fail
  silently.** A truncated or mangled `--allowlist` value never matched
  any signer, and because the vector was non-empty the "no allowlist
  provided" advisory was suppressed too — the run reported PASS with
  `trusted=false` and an empty notes array. `verify_capsule` now drops
  any entry that is not exactly 64 hex chars (any case, normalized to
  lowercase — JS `toKeyHex` parity) with a per-entry
  `ignored invalid allowlist[i]` note, keys the no-allowlist advisory
  off the well-formed entries, and adds an
  "allowlist provided but matched no signer" advisory (outer and L3
  inner signers considered). The Rust CLI also rejects a malformed
  `--allowlist` entry up front with exit 2, mirroring
  `--decryption-key`.

- **The envelope signer set is now bound by the seal
  (`manifest.signer_commitment`).** The signing input is
  `JCS(envelope minus signers)`, so `signers[]` was never an input to
  any signature — and `provenance/envelope.json` is structurally
  excluded from the content index. Measured on the previous code: a
  signer could be stripped with no residue (`ok:true`, count 2→1), and
  anyone holding the bytes could append a fresh valid signature in a
  role of their choosing (`notary`, `compliance`, …) that verified
  clean. The fix is the TUF/DSSE-shaped one: the manifest now stores the
  exact sorted `(role, public_key)` membership of the seal-time signer
  set, which is transitively signed by every signer via
  `envelope.manifest_hash`. The rule is **presence binds, absence
  reports**: a present commitment must equal the normalized signer set
  exactly (strip / append / role-swap / unsorted / duplicated all fail
  closed); a manifest without one still verifies, and every verifier
  reports the set as unbound machine-readably (JS
  `result.signerSet.bound`, Python `result["signer_set"]["bound"]`,
  Rust `VerifyResult::signer_set.bound`, Swift/Kotlin
  `signerSetBound`) — templates and legacy capsules make a weaker claim
  honestly instead of failing. Two adjacent holes closed in the same
  change: duplicate `(role, public_key)` signer entries are rejected as
  malformed and trusted-signer counts are over DISTINCT keys (an M-of-N
  policy can no longer be satisfied by repeating one key), and
  `manifest.originator.public_key` must now actually have a valid
  envelope signature with role `originator` (originator binding — the
  rule was already in spec/manifest.md but no lane enforced it).
  Spec: `spec/manifest.md` ("signer_commitment"), `spec/envelope.md`
  ("Signer set binding"), `spec/trust.md` threat table,
  `spec/federation.md` quorum step 0. New conformance collection
  `spec/vectors/signer-set/` (deterministic generator
  `sdk-js/tools/generate-signer-set-fixtures.mjs`, `--check` wired into
  the conformance harness) pins a bound positive control, the unbound
  absent-commitment report, and strip / append / duplicate / role-swap /
  unsorted / originator-not-a-signer negatives, consumed by the JS
  (`tools/check-spec-vectors.mjs`), Python (`test_spec_registry.py`),
  Rust (`spec_registry.rs`), Swift (`SpecRegistryTests.swift`), and
  Kotlin (`SpecRegistryTest.kt`) lanes. All five SDK builders emit the
  commitment on every seal (one commitment serves the inner and outer
  manifests of an encrypted capsule); the tamper-detection and
  malformed-layout fixtures were re-baselined so their clean capsules
  carry it.

### Added

- **Unknown-member preservation is normative.** `spec/manifest.md`,
  `spec/envelope.md`, and `spec/chain.md` now state that unknown members
  in `manifest.json`, `provenance/envelope.json`, and chain events MUST
  be preserved verbatim and included in canonicalization/hashing —
  readers MUST NOT recompute a hash (or reconstruct the signed envelope
  payload) from a re-serialized typed projection of the document. The
  reserved vendor namespace is `x-<vendor>-<name>` (future spec versions
  will never define `x-`-prefixed members), which gives organisations
  collision-free manifest/envelope/event extensions that are covered by
  the seal: a signer signs over their own extensions, an attacker cannot
  inject or mutate one without breaking `manifest_hash`, the envelope
  signature, or the event hash, and capsules stay verifiable across
  future spec versions that add members. New conformance collection
  `spec/vectors/unknown-fields/` (deterministic generator
  `sdk-js/tools/generate-unknown-fields-fixtures.mjs`) pins a positive
  capsule carrying `x-` members plus three post-seal tamper negatives,
  consumed by the JS (`tools/check-spec-vectors.mjs`), Python
  (`test_spec_registry.py`), Rust (`spec_registry.rs`), Kotlin
  (`ParityTest.kt`), and Swift (`ParityTests.swift`) lanes.

- **sdk-py onboarding surface.** The Python SDK mirrors the sdk-js
  ergonomics: every key input accepts hex strings (any case) or 32 raw
  bytes, `Ed25519KeyPair`/`X25519KeyPair` objects work as-is as
  `originator`, `signers`, `recipients`, and `decrypt()` arguments,
  `seal()` defaults `signed_at`, `append_event()` defaults
  `kind`/`target` and inherits `timestamp` from the builder's `created_at`,
  and `verify_capsule()` accepts raw bytes
  with a fail-closed result for unopenable containers
  (`capsule.keys` module; README rewritten as a quickstart pinned by
  `tests/test_dx.py`). Wire format unchanged.
- **sdk-js onboarding surface.** Every key input now accepts hex strings
  (any case) or 32 raw bytes interchangeably, and the keypair objects
  from `generateEd25519()`/`generateX25519()` work as-is as
  `originator`, `signers`, `recipients`, and `decrypt()` arguments
  (signer role defaults to `"originator"`). `seal()` defaults
  `signedAt` to now; `appendEvent()` defaults `kind`/`target` and inherits
  `timestamp` from the builder's `createdAt`. `verifyCapsule()` accepts raw capsule bytes and returns a
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

### Fixed

- **verifier-rust silently dropped unknown manifest/envelope/event
  members, rejecting legitimately extended capsules.** The Rust verifier
  deserialized `manifest.json`, `provenance/envelope.json`, and chain
  events into fixed structs and re-serialized those structs to recompute
  `manifest_hash`, the signed envelope payload, and per-event chain
  hashes — silently dropping any member the v0.6 structs did not know
  (and re-inventing defaults for absent optional fields), so a capsule
  carrying signed-over extension members failed all three checks. The
  verifier now parses each document once into a preserved
  `serde_json::Value` tree, canonicalises THAT for every hash and
  signature input (outer and L3 inner paths), and keeps the typed
  structs purely as field-access views (`ParsedEvent` pairs each chain
  event with its preserved tree; `manifest_hash`,
  `envelope::canonical_payload`/`signing_input`/`verify_signatures`
  now take the preserved tree).

### Changed

- **Federation identity attestations now bind to something.**
  `verifyIdentityAttestation` requires the caller to supply `capsuleId`,
  `signerPublicKeyHex`, and `expectedIssuer` (plus `audience` for the JWT
  profile) and rejects any attestation whose `capsule_id` /
  `signer_public_key` / `signer_role` binding claims are absent — a raw
  provider session token, which carries no `cap` object, previously
  verified with a fully populated subject. `verifyJwt` requires an
  expected issuer and audience instead of checking `iss` against a field
  of the same untrusted wrapper. `kid` now selects exactly one trust root
  or none, instead of falling back to any cached key with a matching
  `alg`. An Ed25519 OKP JWK is decoded into raw key bytes, so an issuer
  publishing its native trust root as a standard JWKS is consumable. An
  unparseable or absent `expires_at` is a rejection rather than "never
  expires" (and a garbage JWT `exp` no longer crashes the verifier).
  `evaluateSignerPolicy` takes a required `{ capsuleId }` and drops
  attestations bound to another capsule. Every result carries a
  machine-readable `status` from `spec/federation.md`'s own vocabulary
  (`attestation_verified` / `attestation_unverified` /
  `attestation_rejected`), pinned by the new
  `spec/vectors/identity-attestation/` registry, and the subject/claims
  projection is nested under `identity` — non-null only when verified —
  so a caller can never read a claim without its basis.
  `fetchIssuerMetadata` requires `issuer` to match the fetch origin and
  `loadTrustRoots` requires `jwks_uri` to share it. `spec/federation.md`
  and `spec/profiles/clerk.md` state these as normative verifier rules.
  Wire format unchanged; the overlay API is a breaking change.
- **Container strictness is now uniform and checked against the raw
  central directory.** All readers reject duplicate entry names (a ZIP
  parser differential); the JS reference reader now rejects non-STORED
  compression and symlink entries (Python and Rust already did) and
  validates entry names before JSZip's load-time sanitization can mask
  them. The JS and Rust raw scans consume the full central-directory byte
  range and cross-check the EOCD record count, preventing understated-count
  parser differentials. `spec/format.md` records the duplicate-entry and
  raw-central-directory rules as container properties.
- **JS and Python verifiers fail closed on missing, empty, or unparseable
  chain data** (chain error in the result, matching the Rust verifier), pinned
  by missing-chain and invalid-chain-JSON registry fixtures.
- **Malformed allowlist entries fail trust closed without throwing.** JS and
  Python ignore invalid keys, report them in verifier notes, and never mark
  a signer trusted from malformed configuration.
- **Malformed-layout fixtures are drift-checked.** The deterministic generator
  supports `--check`, which runs as a required JavaScript conformance target.

### Security

- **The Swift reader no longer traps on hostile containers.**
  `CapsuleZip.unpack` indexed its byte array with unvalidated EOCD and
  central-directory offsets, so a 22-byte crafted `.capsule` produced a
  Swift array trap — a `fatalError`, which the `do`/`catch` in
  `CapsuleVerifier.verify` cannot contain — and killed the host process.
  Every offset is now bounds-checked, the central directory must close
  exactly on the EOCD, ZIP64 sentinels and ambiguous multi-EOCD archives
  are refused, and the `spec/format.md` reader limits (10,000 entries,
  1 GiB total) are enforced on the read path rather than only in `pack`.
  Malformed bytes now surface as `CapsuleError.malformed` / `ok=false`,
  matching the JS, Python, and Rust lanes.
- **Swift JCS canonicalization no longer kills the process on
  out-of-range numbers.** `JCS.canonical` used `precondition` for
  integers outside ±(2^53 − 1) and non-finite doubles, both reachable
  from `CapsuleVerifier.verify` on attacker-controlled manifest,
  envelope, and chain bytes (a manifest of `{"id":9007199254740993}`
  was a process kill). They now throw `CapsuleError.malformed` and the
  verifier reports the affected checks as failed — the catchable
  behaviour Python (`ValueError`) and Kotlin
  (`IllegalArgumentException`) already had.

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

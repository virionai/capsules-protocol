# Changelog

All notable changes to the Capsule format, reference SDKs, and tooling
in this repository will be documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
protocol uses semantic-version pinning at the format layer (the
`0.6` in the file format will not silently mean different things —
incompatible wire changes ship as `0.7`).

## Unreleased

### Added

- **The version-compatibility policy (`spec/versioning.md`) — the gate
  for the v0.7 bump.** Every lane previously hard-rejected any
  `manifest.format.version` / `envelope.version` other than exactly
  `"0.6"`, so the moment the project bumps to 0.7, every capsule sealed
  today becomes unopenable by the new verifier — not because the capsule
  is bad, but because time passed. That is the strictest possible
  violation of the archival profile (sealed today, opened by an
  underwriter in three years). The policy, now normative and implemented
  in all five lanes: a verifier keeps a KNOWN-VERSION table and opens
  any known version under that era's rules forever; the observed version
  is a REPORTED fact on the verify result (`formatVersion` /
  `format_version` channel: observed, supported, status, suite,
  accepted-by-policy) — even when open is refused; an unknown NEWER
  version fails closed with a verifier-too-old diagnosis that is
  machine-distinguishable from tamper detection, an unknown OLDER
  version with its own reason, and a version violating the
  `<major>.<minor>` grammar as a malformed document; after refusing an
  unknown version the verifier applies none of its own era's rules, so
  the refusal never manufactures hash-mismatch noise; and hosts DECLARE
  an accepted range (`acceptVersions` / `accept_versions`) whose verdict
  is reported, never decided — the signer-allowlist shape applied to
  time. Domain-separation strings (`capsule-id-v<V>`,
  `capsule-provenance-v<V>:<role>`, `capsule-key-wrap-v<V>`) are now
  selected BY the capsule's declared version in every lane, never a
  current-version constant, so the v0.6 strings are retained forever.
  `spec/versioning.md` also pins the algorithm-suite rule: a sealed v0.6
  capsule names no signature/hash/KDF/AEAD algorithm anywhere, so the
  spec now states normatively that the absence of an algorithm
  identifier means the v0.6 suite (Ed25519 / SHA-256 / JCS RFC 8785 /
  X25519 + HKDF-SHA-256 + ChaCha20-Poly1305) — a later field cannot
  retroactively disambiguate capsules sealed today; this statement can.
  Conformance vectors: `spec/vectors/version-compat/` (known version
  verifies + reports; coherent unknown-newer/-older refused with the
  pinned reasons and the observed version still reported; grammar
  violation refused as malformed; unknown envelope version gated
  identically), consumed by all five lanes and registered in
  `spec/vectors/registry.json`. The 0.6 → 0.7 bump itself is NOT
  performed here; this policy is what makes it safe.

### Security

- **The semantic-binding layer: manifest claims are now tied to the
  signed envelope, the chain, and the files in every lane.**
  `capsule_id` is derived from `manifest.first_event_hash`, but no lane
  ever compared that value to `envelope.first_event_hash` or the chain —
  only the envelope value was checked against the recomputed anchor — so
  a correctly-signed capsule could carry a `capsule_id` (the identity
  federation attestations bind to) naming a chain it does not contain.
  All five verifiers now require
  `manifest.first_event_hash == envelope.first_event_hash == hash(chain
  event 1)`, the third term deferred to L3 on an encrypted outer.
  `manifest.encryption` was never checked against the SIGNED
  `envelope.cipher` (amendment M05 measured a plain capsule declaring
  encryption producing four different outcomes across four lanes); it
  must now be null when the cipher is `none`, agree with the cipher
  otherwise, and name a `metadata_path` that is present AND covered by
  the content index. sdk-py's `is_encrypted()` used OR-semantics
  (manifest claim OR cipher OR blob presence), so an attacker who merely
  APPENDED a `content.enc` to a plain capsule flipped the reader into
  encrypted mode and chain verification was silently skipped ("deferred
  to L3") — `chain.ok` reported True for a broken chain; verifier-rust
  keyed the same decision off file presence alone. Both now require the
  signed cipher AND the blob, matching the reference. verifier-rust's
  decryptor hardcoded `skills/decryption/decryption.json`, rejecting
  spec-conformant capsules the reference reader decrypts through
  `manifest.encryption.metadata_path`; it now resolves the declared
  path. sdk-swift and sdk-kotlin keyed encrypted-mode detection off the
  manifest's own claim and wrote their envelope-to-chain anchor checks
  as optional bindings, so a MISSING mandatory anchor became silent
  success and an empty chain was accepted with claimed anchors
  unchecked; both now follow the empty-chain null-anchor rule (zero
  events verify only with all three anchors null, reported honestly via
  the shared note) and fail closed on missing or null anchors over a
  non-empty chain. New `spec/vectors/semantic-binding/` registry
  (7 vectors: manifest/envelope drift, agreed-decoy chain mismatch,
  false encryption claim, dangling and relocated metadata_path,
  smuggled blob over a broken chain, plain positive control) consumed
  by all five lanes; sdk-swift and sdk-kotlin now also consume
  `spec/vectors/chain-binding/`.

- **Encrypted-blob shape checks are now keyed off blob PRESENCE in
  every lane, closing two fail-opens the semantic-binding remediation
  introduced.** The remediation settled encrypted-mode detection on
  "signed cipher AND `content.enc` present" — correct for choosing
  whether to walk the chain, but sdk-py, sdk-js, sdk-swift and
  sdk-kotlin also gated the cipher/blob-hash SHAPE checks behind that
  conjunction, which is false exactly when the two halves disagree.
  Consequences: (1) sdk-kotlin verified `ok=true` for a capsule whose
  SIGNED `envelope.cipher` named a real cipher while carrying no
  `content.enc` and a plaintext chain — it walked the plaintext chain
  of a capsule claiming to be encrypted (before the remediation the
  same bytes were accidentally refused); (2) sdk-py — which had
  rejected it before the remediation — plus sdk-js, sdk-swift and
  sdk-kotlin verified `ok=true` for a plain (`cipher='none'`) capsule
  with a stray `content.enc` appended AND correctly content-indexed,
  index/manifest-hash/signature re-derived. verifier-rust already had
  the correct split (`blob_present` for the shape checks, `blob_present
  && cipher != "none"` only for mode selection); the other four lanes
  now mirror it: a present blob must be accounted for by the signed
  cipher and `encrypted_blob_hash`, and an absent blob means plain —
  `cipher='none'`, `encrypted_blob_hash=null` — unconditionally
  (integrity invariant: the capsule must not lie about its own bytes;
  a manifest that merely OMITS the optional `encryption` member is
  still not a violation). Two new semantic-binding vectors pin it in
  all five lanes: `cipher-declared-no-blob` (reason
  `cipher_without_blob`) and `smuggled-blob-indexed` (reason
  `blob_without_cipher`). Also corrected the sdk-js
  `CONTENT_INDEX_EXCLUDED`/verifier comments, which claimed indexing a
  smuggled blob is what fails verification — a fully re-derived index
  passes the index checks; the blob-shape invariant is what rejects
  it. The CLI's vendored `@capsule/sdk-v0.6-prototype` was a stale
  directory copy of sdk-js; it is now an npm `file:` symlink, so the
  CLI lane exercises the current SDK.
- **Lane × collection vector coverage is now itself machine-checked
  (T10).** Registry consumption used to be opt-in per lane, by
  hardcoded filename — each of sdk-py, verifier-rust, sdk-swift and
  sdk-kotlin kept its own list of vector files, and nothing asserted
  the lists were COMPLETE, so a new collection was invisible to four
  lanes by default (the generator behind the Swift/Kotlin
  malformed-layout gap, and behind malformed-shape / chain-binding /
  unknown-fields / signing-input each missing from at least one lane).
  New `spec/vectors/registry.json` declares, for every collection, its
  reason/failing vocabulary and the set of lanes required to consume it
  — as a witness consumer file, a transitive `via`, or an explicit
  reasoned exemption (e.g. only sdk-js implements federation
  attestations); silent omission is not expressible. The new required
  conformance target `vector-registry`
  (`tools/check-vector-registry.mjs`) fails on an unlisted or missing
  or EMPTY collection (F40 — an empty `vectors` array used to record
  nothing and pass; the per-lane loaders now also refuse missing/empty
  registries instead of silently collecting zero tests), on vocabulary
  drift in either direction, and on a declared consumer that never
  references the collection. The gaps the manifest surfaced were
  closed rather than exempted: Swift and Kotlin now consume
  malformed-shape, chain-binding, unknown-fields and signing-input
  (Swift gained the empty-chain null-anchor rules, zero-byte
  capsule_id derivation, manifest/envelope shape validation at parse,
  and byte-level signing-input pins; Kotlin the same by construction),
  and Rust consumes malformed-shape.
- **Duplicate JSON object members are rejected in every lane (A13).**
  I-JSON (RFC 7493 §2.3) forbids them; no lane enforced it. Every
  mainstream parser silently keeps the last value, so `{"a":1,"a":2}`
  and `{"a":2}` were two different byte sequences with one canonical
  form — a reviewer/verifier smuggling primitive, one future
  first-wins parser away from a cross-lane verification split.
  `spec/canonicalization.md` gains the "Objects" rule (names compare
  after escape processing); every capsule-document parse path now
  refuses duplicates (JS text scanner + `parseJsonStrict`, Python
  `object_pairs_hook`, Rust visitor-based `parse_json_strict`, Swift
  UTF-16 scanner, Kotlin streaming `JsonReader` re-scan), pinned by
  three new `ijson-acceptance` vectors with reason `duplicate_member`
  including the `"\u0061"`-vs-`"a"` escaped-name collision.
- **Remaining cross-lane parity gaps from the addendum are closed with
  vectors (A10, A11, A12, A15).** (1) Swift and Kotlin did not enforce
  contiguous chain sequence numbers — a correctly hashed, signed chain
  renumbered `seq=2` verified in both; chain.md step 5 is now enforced
  in all five lanes (`chain-rules/non-contiguous-seq`). (2) Swift and
  Kotlin accepted UPPERCASE envelope signer-key hex that JS/Python/
  Rust reject: the key decodes to the same bytes and `signers[]` sits
  outside the canonical payload, so those lanes saw a valid signature
  on bytes the strict lanes refuse; both hex decoders are now strict
  lowercase, and Kotlin's signature path no longer throws on malformed
  hex (`malformed-shape/uppercase-signer-key-hex`). (3) verifier-rust
  uniquely required participant `label`, refusing a spec-valid capsule
  every other lane verified; the typed view now treats `label` as the
  advisory optional field the spec defines
  (`chain-rules/participant-without-label`). (4)
  `untrusted_payload_fields` had no enforceable grammar and no host
  projection contract — a host could not tell which payload members
  the author marked untrusted without inventing semantics.
  `spec/chain.md` now defines the normative path grammar
  (`payload(.segment)+`, `segment = [A-Za-z0-9_-]+`), the resolution
  rules (object-member traversal only; unresolved paths mark nothing;
  hosts never guess), and verification step 8: an out-of-grammar
  marking is a chain-area failure in every profile, and all four
  builders refuse it at append time
  (`chain-rules/invalid-untrusted-path`).

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

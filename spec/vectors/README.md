# Capsule v0.6 Vectors

This directory contains checked-in protocol vectors. Six shapes exist, all
verified by `tools/check-spec-vectors.mjs` (the `spec-vectors` conformance
lane):

1. **Embedded positive vector** — a JSON doc with `capsule_bytes_b64` and an
   `expected` map of pinned hashes (`capsule_id`, `first_event_hash`,
   `entry_hash`, `manifest_hash`, `content_index_hash`,
   `envelope_signature_hex`, `event_hashes`). The capsule must verify and
   reproduce every hash. See `plain-basic.json`.

2. **Outcome-vector collection** — a JSON doc with a `vectors` array, each
   entry referencing a checked-in `capsule_file` and an `expected` outcome.
   This is the language-neutral registry for negative cases. Two stages
   exist:

   - *Verify stage* (default): `{ ok, failing?, error_includes? }`, where
     `failing` names the result areas that must fail (`content_index`,
     `chain`, `envelope`, `encrypted_blob`). See
     `tamper-detection/vectors.json` and `unknown-fields/vectors.json`
     (the latter pins the unknown-member preservation rule of
     `spec/manifest.md` / `spec/envelope.md` / `spec/chain.md`: a capsule
     carrying `x-` extension members must verify, and a post-seal
     mutation of an unknown member must fail).
   - *Open stage*: `{ ok: false, stage: "open", reason, detail? }` — the
     reader must refuse the container before verification, for the named
     `reason` category (by error, exception, or fail-closed result, per the
     host language's idiom). The `reason` categories are normative; exact
     error strings are implementation-defined. `detail` is informative.
     See `malformed-layout/vectors.json`, whose `reasons` map documents the
     category vocabulary (including reserved categories that do not have
     checked-in fixtures yet).

   Independent implementations SHOULD reproduce these outcomes; the Python
   (`sdk-py/tests/test_spec_registry.py`) and Rust
   (`verifier-rust/tests/spec_registry.rs`) lanes consume these collections
   directly.

3. **Byte-level signing-input vector** (`signing-input.json`, detected by
   `meta.kind: "signing-input"`) — pins the exact bytes being signed,
   hashed, and identified for the `plain-basic` capsule: capsule_id domain
   separation and preimage, per-event JCS canonical bytes and hash
   preimages, manifest and content-index canonical bytes, the envelope
   canonical payload (JCS of envelope minus `signers`), and each signer's
   domain string plus full Ed25519 signing input. Implementations MUST
   reproduce every canonical byte string and hash, and verify the pinned
   signature over the reconstructed signing input.

4. **JCS number-serialization set** (`jcs-numbers.json`): a `vectors` array
   of `{ ieee_hex, expected }` entries, where `ieee_hex` is the big-endian
   IEEE-754 binary64 bit pattern of the input and `expected` its canonical
   RFC 8785 serialization. Implementations must parse the bit pattern (not
   the expected string) and serialize it.

5. **Ed25519 key/signature validation set** (`ed25519-key-validation.json`,
   detected by `meta.kind: "ed25519-verify"`) — a `vectors` array of
   `{ name, public_key_hex, message_hex, signature_hex, expected: { valid },
   reason }` entries. Every negative entry is a *witness*: an unguarded
   Ed25519 verifier accepts the triple. Implementations MUST report
   `valid: false` for all 8 small-subgroup public keys, for non-canonical
   32-byte key encodings (masked y >= p), and for a signature whose S is not
   reduced mod L — and `valid: true` for the RFC 8032 positive control.
   The Python (`test_ed25519_key_validation_registry`), Rust
   (`ed25519_key_validation_registry`), Swift (`Ed25519KeyValidationTests`)
   and Kotlin (`Ed25519KeyValidationVectorTest`) lanes consume it directly.

6. **Identity-attestation outcome set**
   (`identity-attestation/vectors.json`, detected by
   `meta.kind: "identity-attestation"`) — inline attestation documents for
   the native `ed25519-jcs` profile, the trust-root set and verification
   context each is checked against (`capsule_id`, `signer_public_key`,
   `expected_issuer`, `now`; per-vector `trust_roots`/`context` override the
   top-level ones), and an expected `{ ok, status, error_includes? }`.
   `status` is the attestation-layer vocabulary of `spec/federation.md`
   *Failure reporting*: `attestation_verified`, `attestation_unverified`
   (unknown — no trust roots cached), `attestation_rejected` (strong
   negative). Only the native profile is pinned: Ed25519 signatures are
   deterministic, ECDSA (the JWT profile) is not.

Other JSON here (e.g. `tamper-detection/output/keys.json` and
`unknown-fields/output/keys.json`) is supporting material, not a vector,
and is ignored by the checker.

Generators (deterministic; regeneration is an intentional spec change and
should be reviewed with the byte-level diff):

- `sdk-js/tools/generate-tamper-fixtures.mjs` → `tamper-detection/output/`
- `sdk-js/tools/generate-malformed-fixtures.mjs` → `malformed-layout/output/`
  (derived from the tamper-detection clean fixture)
- `sdk-js/tools/generate-unknown-fields-fixtures.mjs` → `unknown-fields/output/`
  (fixed throwaway TEST keypair; byte-stable, supports `--check`)
- `sdk-js/tools/generate-signing-input-vector.mjs` → `signing-input.json`
  (derived from `plain-basic.json`)
- `sdk-js/tools/generate-ed25519-key-validation-vector.mjs` →
  `ed25519-key-validation.json` (searches node:crypto's raw verify for the
  acceptance witnesses; `--check` detects drift)
- `sdk-js/tools/generate-attestation-vectors.mjs` →
  `identity-attestation/vectors.json` (fixed throwaway TEST issuer seed;
  byte-stable, supports `--check`)

No warranty: vectors are conformance fixtures only. They are not production
templates, compliance artifacts, legal advice, security advice, or
operational guidance.

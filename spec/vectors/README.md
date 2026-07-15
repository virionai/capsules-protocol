# Capsule v0.6 Vectors

This directory contains checked-in protocol vectors. Four shapes exist, all
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
     `tamper-detection/vectors.json`.
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
   (`verifier-rust/tests/spec_registry.rs`) lanes consume both collections
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

Other JSON here (e.g. `tamper-detection/output/keys.json`) is supporting
material, not a vector, and is ignored by the checker.

Generators (deterministic; regeneration is an intentional spec change and
should be reviewed with the byte-level diff):

- `sdk-js/tools/generate-tamper-fixtures.mjs` → `tamper-detection/output/`
- `sdk-js/tools/generate-malformed-fixtures.mjs` → `malformed-layout/output/`
  (derived from the tamper-detection clean fixture)
- `sdk-js/tools/generate-signing-input-vector.mjs` → `signing-input.json`
  (derived from `plain-basic.json`)

No warranty: vectors are conformance fixtures only. They are not production
templates, compliance artifacts, legal advice, security advice, or
operational guidance.

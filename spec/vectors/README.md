# Capsule v0.6 Vectors

This directory contains checked-in protocol vectors. Two shapes exist, both
verified by `tools/check-spec-vectors.mjs` (the `spec-vectors` conformance
lane):

1. **Embedded positive vector** — a JSON doc with `capsule_bytes_b64` and an
   `expected` map of pinned hashes (`capsule_id`, `first_event_hash`,
   `entry_hash`, `manifest_hash`, `content_index_hash`,
   `envelope_signature_hex`, `event_hashes`). The capsule must verify and
   reproduce every hash. See `plain-basic.json`.

2. **Outcome-vector collection** — a JSON doc with a `vectors` array, each
   entry referencing a checked-in `capsule_file` and an `expected` outcome
   `{ ok, failing?, error_includes? }`. This is the language-neutral registry
   for negative cases (tamper fixtures), where `failing` names the areas that
   must fail (`content_index`, `chain`, `envelope`, `encrypted_blob`). See
   `tamper-detection/vectors.json`. Independent implementations SHOULD
   reproduce these outcomes.

Other JSON here (e.g. `tamper-detection/output/keys.json`) is supporting
material, not a vector, and is ignored by the checker.

These fixtures are deterministic once checked in. Regeneration is an
intentional spec change and should be reviewed with the byte-level diff.

No warranty: vectors are conformance fixtures only. They are not production
templates, compliance artifacts, legal advice, security advice, or
operational guidance.

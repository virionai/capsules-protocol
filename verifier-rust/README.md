# verifier-rust — second independent Capsule v0.6 verifier

A Rust verifier for Capsule v0.6 capsules (plain and encrypted-outer).
Written from the spec, not ported from the JS reference. Byte-compatible
with the JS SDK (`new-design/sdk/`) on the canonical tamper-detection
corpus (`new-design/examples/tamper-detection/`).

## Why this exists

The JS SDK is the reference implementation. A single-implementation
format, no matter how clean, is just a JS library — the wire format is
whatever that one codebase happens to do this week. A second,
independent implementation in another language is the thing that turns
Capsule from a library into a *format*: anything either implementation
disagrees on is a spec bug, not a behavioral nuance.

This Rust verifier runs the same checks the JS verifier runs and
produces the same outcomes on the tamper-detection fixtures. Each of
the six fixtures (one clean plain, three tampered plain, one clean
encrypted, one tampered encrypted) resolves to the same PASS/FAIL the
JS SDK reaches, with the failure attributed to the same check. As of
v0.3 the verifier covers both L2 (envelope-only) and L3 (decrypted
inner chain) — pass `--decryption-key` to promote an encrypted capsule
from L2 to L3.

## What's new in v0.6

- **Structural polish:** L3 logic extracted to its own `l3.rs` module so
  `verifier.rs` returns to pure orchestration (~860 LOC) instead of
  bundling the L3 path inline.
- **`TopError.scope` discriminant:** JSON consumers can now filter errors
  by `scope == "inner"` instead of substring-matching the `"L3 inner: "`
  message prefix. Backward-compatible via `#[serde(default)]` defaulting
  to `Outer` — v0.3-v0.5 JSON deserializes unchanged.
- **Helper constructors:** `TopError::outer(...)` and `TopError::inner(...)`
  make every push site explicit about scope.
- **Inner-envelope rendering note:** `inner_envelope_signature` populates
  independently of the inner format/version, `capsule_id`, and
  `manifest_hash` checks. A clean capsule with a tampered inner manifest
  will still render `[✓] inner_envelope_signature` if the signature
  itself is valid; the manifest failure surfaces as a separate `[✗]`
  line with a `"L3 inner: "` prefix and `scope == "inner"` in JSON.

## What's new in v0.5

- Full inner plain-capsule verification at L3: inner format/version, inner
  `capsule_id` derivation, inner `manifest_hash`, and inner `content_index`
  are all recomputed and checked against the inner envelope's claims —
  what plain L2 does on the outer, the verifier now does on the inner.
- New `inner_content_index: Option<ContentIndexCheck>` field on
  `VerifyResult` (mirrors v0.4's `inner_envelope`; visible in JSON;
  rendered in plain CLI output as a separate `[✓]/[✗] inner_content_index`
  check line).
- Inner-side errors prefixed `"L3 inner:"` to distinguish from outer-
  envelope failures of the same category — surfaced through the existing
  categorized error rendering, so e.g. an inner manifest-hash mismatch
  appears under `capsule_id / manifest_hash` with the prefix making the
  envelope clear.
- Closes the spec's L3 "Open the inner ZIP as a normal capsule"
  requirement: the Rust verifier now performs full plain-capsule
  verification on the decrypted inner ZIP.

## What's new in v0.4

- Inner envelope signature verification: at L3, the inner envelope's
  Ed25519 signers are now verified using the same domain-separated-JCS
  code path as the outer envelope.
- New `inner_envelope: Option<EnvelopeCheck>` field on `VerifyResult`
  (visible in JSON; rendered in plain CLI output as a separate
  `[✓]/[✗] inner_envelope_signature` check line + an `Inner signers:`
  block).
- Allowlist applies symmetrically: an inner signer is `trusted` iff its
  key is in the allowlist AND its signature verifies.
- Inner envelope sig failure propagates to `result.ok = false`, same as
  outer envelope sig failure.

## What's new in v0.3

- Full L3 (decrypted-content) verification: with the recipient's X25519
  private key, the verifier decrypts `content.enc`, parses the inner
  ZIP, and runs the chain walk against the outer envelope's anchors.
- New `decrypt.rs` module: ChaCha20-Poly1305 AEAD via RustCrypto, X25519
  ECDH, HKDF-SHA256. AAD shape pinned against a JCS oracle captured
  from the JS reference.
- New `--decryption-key <HEX|FILE>` CLI flag. When provided + capsule
  is encrypted → L3 path. Otherwise unchanged.
- 5 new L3 cross-checks (inner-vs-outer + inner-events-vs-inner-envelope)
  ensure the inner chain anchors match the outer envelope.

## What's new in v0.2

- L2 verification of encrypted-outer capsules (envelope-only — does
  not decrypt). `content.enc` is rehashed against
  `envelope.encrypted_blob_hash`; manifest hash, content index, and
  envelope signature all verify normally.
- Cipher whitelist enforcement: only `none` and `ChaCha20-Poly1305`
  are accepted. `AES-256-GCM` and any other reserved-but-unimplemented
  values are rejected with a clear `Encryption` error.
- New `ChainCheck.note` field (visible in JSON output). The CLI
  renders the deferred-chain state on encrypted outers as `[✓] chain`
  with an indented "deferred to L3 (encrypted outer)" note instead of
  a misleading `[✗]`.
- Regression test for `TopErrorCategory::ChainAnchor` — every renderer
  category is now exercised.

## What it does

L2 verification end to end, on plain and encrypted-outer capsules,
plus L3 (decrypted-content) verification on encrypted capsules when
the recipient's X25519 private key is supplied:

- ZIP container parse and safety checks (STORED-only at our layer; size
  / entry caps; rejects path traversal, absolute paths, symlinks).
- `capsule_id` derivation: `SHA-256("capsule-id-v0.6\x00" || originator_pubkey || first_event_hash)`.
- `manifest_hash` over the JCS-canonical manifest minus the
  self-referential field.
- `content_index` re-hashing: every committed file's bytes, the
  per-entry hash, and the `index_hash` rollup all recomputed and
  compared.
- Chain walk (plain capsules): every event's stored `hash` recomputed
  from `SHA-256(prev_hash_raw32 || JCS(event))`, with the per-event
  `prev_hash` linkage checked end to end. On encrypted outers without
  a recipient key the chain walk is deferred at L2 (rendered as
  `[✓] chain` with a "deferred to L3 (encrypted outer)" note).
- Envelope Ed25519 signature verification over
  `domain_sep_bytes || JCS(envelope_minus_signers)`, optional
  allowlist trust check (signer is `trusted=true` only if its key
  appears in the allowlist *and* the signature verifies).
- Encryption-state check: cipher whitelist (`none`,
  `ChaCha20-Poly1305`); for encrypted outers, `content.enc` SHA-256
  recomputed and compared against `envelope.encrypted_blob_hash`.
- L3 (with `--decryption-key`): `content.enc` is decrypted via
  ChaCha20-Poly1305 with the AEAD key derived through X25519 ECDH +
  HKDF-SHA256, the inner ZIP is unpacked, the inner chain is walked
  in place of the L2 deferral, and inner-vs-outer anchor cross-checks
  (`capsule_id`, `first_event_hash`, `entry_hash`, plus inner-chain-vs-
  inner-envelope) ensure the inner content matches what the outer
  envelope committed to. The inner envelope's Ed25519 signers are also
  verified using the same domain-separated-JCS code path as the outer
  envelope, surfaced as `result.inner_envelope`. As of v0.5, full inner
  plain-capsule verification runs on the decrypted inner ZIP: inner
  format/version, inner `capsule_id` derivation, inner `manifest_hash`,
  and inner `content_index` are all recomputed and checked, with
  per-check failures prefixed `"L3 inner:"` and the inner content_index
  outcome surfaced as `result.inner_content_index`.

## What it does *not* do (yet)

- **No capsule building or signing.** Verifier only.
- **No FFI.** No WASM, no C ABI, no Python bindings. Yet.

## Build and test

```sh
cd new-design/verifier-rust
cargo build --workspace
cargo test --workspace          # 104 tests, all pass
cargo run -p capsule-verify-cli -- verify <FILE.capsule>
```

`cargo` requires the Rust toolchain. On a fresh machine:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
```

CLI flags:

```
verify <FILE>
  --json                       Pretty-printed VerifyResult instead of plain text.
  --allowlist <HEX> [<HEX>...]  Trusted Ed25519 pubkeys (lowercase 64-char hex).
                                A signer is trusted only if its key is in the
                                allowlist AND its signature verifies.
  --decryption-key <KEY>        Recipient's X25519 private key for L3
                                verification. <KEY> is either a 64-char
                                lowercase hex string OR a path to a file
                                containing 32 raw bytes / 64-char hex /
                                base64. On encrypted capsules, promotes
                                the verifier from L2 to L3 (decrypts the
                                inner ZIP and walks the inner chain). On
                                plain capsules, the flag is silently
                                ignored.
```

Exit codes: `0` PASS, `1` FAIL, `2` I/O or argument error.

## Layout

```
verifier-rust/
├── Cargo.toml                  workspace manifest + parity-tests host package
├── crates/
│   ├── capsule-verify/         library
│   │   └── src/
│   │       ├── crypto.rs       sha256, ed25519_verify, hex codec
│   │       ├── jcs.rs          RFC 8785 (via serde_jcs)
│   │       ├── zip_reader.rs   STORED-only with safety checks
│   │       ├── schemas.rs      Manifest / Envelope / ChainEvent
│   │       ├── manifest.rs     capsule_id, content_index, manifest_hash
│   │       ├── chain.rs        chain walk + per-event hash recompute
│   │       ├── envelope.rs     canonical payload, signing input, sig verify
│   │       ├── decrypt.rs      L3: ChaCha20-Poly1305 + X25519 + HKDF-SHA256
│   │       ├── verifier.rs     top-level orchestrator (L2 + L3 promotion)
│   │       └── lib.rs          re-exports
│   └── capsule-verify-cli/     binary
│       └── src/main.rs         clap CLI: verify <FILE> [--json] [--allowlist ...] [--decryption-key ...]
└── tests/
    └── parity_against_js_sdk.rs    integration test vs tamper-detection fixtures
```

## Crate selection

| Crate | Why |
|---|---|
| `serde_jcs` | RFC 8785. Uses `ryu-js` for ECMAScript-compatible float formatting — that is the part everyone gets wrong. Verified byte-identical against the JCS oracles captured from the JS reference. |
| `sha2` | SHA-256. RustCrypto, audited, no surprises. |
| `ed25519-dalek` | Ed25519 signature verification. Strict pubkey/signature length checks, no malleable variants enabled. |
| `hex` | Strict lowercase hex codec. The verifier rejects uppercase and non-canonical input the same way the JS reader does. |
| `zip` | STORED-only at our layer, but we use a real implementation rather than hand-roll the central directory parser. Safety checks (entry count cap, total bytes cap, path traversal, absolute paths, symlinks) are layered on top. |
| `serde`, `serde_json` | Schemas. |
| `clap` | CLI argument parsing (binary only). |
| `thiserror` | Error enums with `Display` and `Error` derived; no anyhow at the library boundary. |
| `chacha20poly1305` | ChaCha20-Poly1305 AEAD for L3 content decryption. RustCrypto, audited. |
| `x25519-dalek` | X25519 ECDH for L3 key agreement. `static_secrets` feature gives us non-ephemeral secret-key handling. |
| `hkdf` | HKDF-SHA256 for L3 key derivation from the ECDH shared secret. RustCrypto, audited. |
| `base64` | Optional base64 decode for `--decryption-key <FILE>` content (CLI binary only). |

## Anti-features

- **No hand-rolled crypto.** Hashing, signatures, and JCS all come from
  vetted libraries. The verifier wires them; it does not implement them.
- **No async.** Verification is sync. A capsule is a small file; the
  whole pipeline is microseconds. Async buys nothing here and would
  push complexity onto every consumer.
- **No FFI.** The library is plain Rust. WASM, a C ABI, or Python
  bindings can come later if someone has a use case.
- **Pure-Rust, no system deps** beyond `rustc 1.95+`. No OpenSSL, no
  libsodium, nothing to install.

## Cross-impl parity outcomes

Below is the full output of running the CLI against each tamper-detection
fixture, captured from the working build. This is the moat-strengthening
deliverable: the Rust verifier reaches the same PASS/FAIL the JS SDK
reaches on each of the six fixtures, and the failure (where there is
one) is attributed to the same check. With v0.3, both L2 and L3 paths
are exercised against the encrypted fixtures.

| Fixture | No key (L2) | With recipient key (L3) |
|---|---|---|
| `clean.capsule` | PASS @ L2 | PASS @ L2 (key silently ignored — plain) |
| `tampered-payload.capsule` | FAIL @ `content_index` | (same — plain capsule, key ignored) |
| `tampered-chain.capsule` | FAIL @ `content_index` + `chain` | (same — plain capsule, key ignored) |
| `tampered-envelope.capsule` | FAIL @ `envelope_signature` | (same — plain capsule, key ignored) |
| `clean-encrypted.capsule` | PASS @ L2 (chain deferred to L3) | **PASS @ L3 (chain fully verified; `inner_envelope.ok=true`, 1 inner signer valid; `inner_content_index.ok=true`)** |
| `tampered-blob.capsule` | FAIL @ `encryption_state` | FAIL @ decryption (auth tag mismatch) |

Full transcript (no `--decryption-key`):

```
=== clean.capsule ===
File:                   ../examples/tamper-detection/output/clean.capsule (4493 bytes)
Capsule ID:             d6d73f94c78e…
Originator (Ed25519):   c172289fcacf…
Sealed at:              2026-05-07T12:00:00Z
Level:                  L2

Checks:
  [✓] format / version
  [✓] capsule_id / manifest_hash
  [✓] content_index
  [✓] chain
  [✓] envelope_signature
  [✓] encryption_state

Signers:
  - originator   c172289fcacf…  valid=true  trusted=false

Notes:
  - no allowlist provided; trusted=false for all signers regardless of signature validity

Result: PASS

=== tampered-payload.capsule ===
File:                   ../examples/tamper-detection/output/tampered-payload.capsule (4493 bytes)
Capsule ID:             d6d73f94c78e…
Originator (Ed25519):   c172289fcacf…
Sealed at:              2026-05-07T12:00:00Z
Level:                  L2

Checks:
  [✓] format / version
  [✓] capsule_id / manifest_hash
  [✗] content_index
        file hash mismatch: program.md: stored b3ea10a3261b9484d761b509aa7059e293e4f4287526a5f2226b5c06ae2b9a04 vs recomputed 9b8b2c71c8acb0bdd1a96d8127f0a797431e4de486ec653c2729c3192af6b89a
        manifest.content_index.index_hash mismatch: stored 1e8b657ba3422c4433a93a1241d977d057e6f2369fce90b1d9029bf48798f4f6 vs recomputed 21f6087cb4a8f1ff817249767bef755091e5c9b7eaacb230cbe62e6766617b18
        envelope.content_index_hash mismatch: 1e8b657ba3422c4433a93a1241d977d057e6f2369fce90b1d9029bf48798f4f6 vs recomputed 21f6087cb4a8f1ff817249767bef755091e5c9b7eaacb230cbe62e6766617b18
  [✓] chain
  [✓] envelope_signature
  [✓] encryption_state

Signers:
  - originator   c172289fcacf…  valid=true  trusted=false

Notes:
  - no allowlist provided; trusted=false for all signers regardless of signature validity

Result: FAIL

=== tampered-chain.capsule ===
File:                   ../examples/tamper-detection/output/tampered-chain.capsule (4495 bytes)
Capsule ID:             d6d73f94c78e…
Originator (Ed25519):   c172289fcacf…
Sealed at:              2026-05-07T12:00:00Z
Level:                  L2

Checks:
  [✓] format / version
  [✓] capsule_id / manifest_hash
  [✗] content_index
        file hash mismatch: chain/events.jsonl: stored bcc729bdd6af7267189f3bf1d6e96dad67ae7ccd75f0a5b2783e9b121eefb2ea vs recomputed 6bd5b29e37e773027d54dda1a5d1cd04e827fed84df1f8ca7c2b52f15250470a
        manifest.content_index.index_hash mismatch: stored 1e8b657ba3422c4433a93a1241d977d057e6f2369fce90b1d9029bf48798f4f6 vs recomputed 6d9633975182006672440fd1de2500a86d29bb6f9f1a7cb43f1ce6ba7d8ada8f
        envelope.content_index_hash mismatch: 1e8b657ba3422c4433a93a1241d977d057e6f2369fce90b1d9029bf48798f4f6 vs recomputed 6d9633975182006672440fd1de2500a86d29bb6f9f1a7cb43f1ce6ba7d8ada8f
  [✗] chain
        seq 1: hash mismatch: stored 577a1933292463b7ecf8f3a5b32dbc970804fef418aab805b8a94fccf819d076, recomputed c3b2e62d0ffc1ba0517c88550ca29fc204cab9a5e761e6e5c1a2ef7a42945467
  [✓] envelope_signature
  [✓] encryption_state

Signers:
  - originator   c172289fcacf…  valid=true  trusted=false

Notes:
  - no allowlist provided; trusted=false for all signers regardless of signature validity

Result: FAIL

=== tampered-envelope.capsule ===
File:                   ../examples/tamper-detection/output/tampered-envelope.capsule (4493 bytes)
Capsule ID:             d6d73f94c78e…
Originator (Ed25519):   c172289fcacf…
Sealed at:              2026-05-07T12:00:00Z
Level:                  L2

Checks:
  [✓] format / version
  [✓] capsule_id / manifest_hash
  [✓] content_index
  [✓] chain
  [✗] envelope_signature
        signer originator (c172289fcacf…) signature did not verify
  [✓] encryption_state

Signers:
  - originator   c172289fcacf…  valid=false  trusted=false

Notes:
  - no allowlist provided; trusted=false for all signers regardless of signature validity

Result: FAIL

=== clean-encrypted.capsule ===
File:                   ../examples/tamper-detection/output/clean-encrypted.capsule (7320 bytes)
Capsule ID:             d6d73f94c78e…
Originator (Ed25519):   c172289fcacf…
Sealed at:              2026-05-07T12:00:00Z
Level:                  L2

Checks:
  [✓] format / version
  [✓] capsule_id / manifest_hash
  [✓] content_index
  [✓] chain
        deferred to L3 (encrypted outer)
  [✓] envelope_signature
  [✓] encryption_state

Signers:
  - originator   c172289fcacf…  valid=true  trusted=false

Notes:
  - no allowlist provided; trusted=false for all signers regardless of signature validity

Result: PASS

=== tampered-blob.capsule ===
File:                   ../examples/tamper-detection/output/tampered-blob.capsule (7320 bytes)
Capsule ID:             d6d73f94c78e…
Originator (Ed25519):   c172289fcacf…
Sealed at:              2026-05-07T12:00:00Z
Level:                  L2

Checks:
  [✓] format / version
  [✓] capsule_id / manifest_hash
  [✓] content_index
  [✓] chain
        deferred to L3 (encrypted outer)
  [✓] envelope_signature
  [✗] encryption_state
        envelope.encrypted_blob_hash mismatch: stored 4ac3fb41626ffbb69a26d75cd346fcfd17203b267af248b55715d42a05346d16 vs recomputed e7c4251f24aa0e9d9053296c84d65eae43bd9e2ca2e7d4ff1f38a0c8d177c08c

Signers:
  - originator   c172289fcacf…  valid=true  trusted=false

Notes:
  - no allowlist provided; trusted=false for all signers regardless of signature validity

Result: FAIL
```

`clean-encrypted.capsule` passes at L2: the envelope, manifest,
content index, and encrypted-blob hash all verify; the inner chain
is deferred to L3 and shown as `[✓] chain` with an indented "deferred
to L3 (encrypted outer)" note. `tampered-blob.capsule` fails at
`encryption_state` because the stored `envelope.encrypted_blob_hash`
does not match a fresh SHA-256 over the on-disk `content.enc`.

L3 transcript (with `--decryption-key`):

```
=== clean-encrypted.capsule (with --decryption-key) ===
File:                   ../examples/tamper-detection/output/clean-encrypted.capsule (7320 bytes)
Capsule ID:             d6d73f94c78e…
Originator (Ed25519):   c172289fcacf…
Sealed at:              2026-05-07T12:00:00Z
Level:                  L3

Checks:
  [✓] format / version
  [✓] capsule_id / manifest_hash
  [✓] content_index
  [✓] chain
  [✓] envelope_signature
  [✓] inner_envelope_signature
  [✓] inner_content_index
  [✓] encryption_state

Signers:
  - originator   c172289fcacf…  valid=true  trusted=false

Inner signers:
  - originator   c172289fcacf…  valid=true  trusted=false

Notes:
  - no allowlist provided; trusted=false for all signers regardless of signature validity

Result: PASS

=== tampered-blob.capsule (with --decryption-key) ===
File:                   ../examples/tamper-detection/output/tampered-blob.capsule (7320 bytes)
Capsule ID:             d6d73f94c78e…
Originator (Ed25519):   c172289fcacf…
Sealed at:              2026-05-07T12:00:00Z
Level:                  L2

Checks:
  [✓] format / version
  [✓] capsule_id / manifest_hash
  [✓] content_index
  [✓] chain
        deferred to L3 (encrypted outer)
  [✓] envelope_signature
  [✗] encryption_state
        envelope.encrypted_blob_hash mismatch: stored 4ac3fb41626ffbb69a26d75cd346fcfd17203b267af248b55715d42a05346d16 vs recomputed e7c4251f24aa0e9d9053296c84d65eae43bd9e2ca2e7d4ff1f38a0c8d177c08c
        L3: decryption failed: content decrypt failed (ChaCha20-Poly1305 auth tag invalid for content.enc)

Signers:
  - originator   c172289fcacf…  valid=true  trusted=false

Notes:
  - no allowlist provided; trusted=false for all signers regardless of signature validity

Result: FAIL
```

With the recipient's X25519 key supplied, `clean-encrypted.capsule`
promotes to L3: `content.enc` is decrypted, the inner ZIP is unpacked,
the inner chain is walked, and the inner-vs-outer anchor cross-checks
all pass. The chain line renders as `[✓] chain` with no skip note —
because a real walk happened. `tampered-blob.capsule` still fails at
L2 (`encryption_state`) and additionally surfaces the L3 decrypt
failure: the ChaCha20-Poly1305 auth tag does not validate against the
flipped ciphertext bytes, which is exactly what AEAD is supposed to
catch.

## License + provenance

- **License:** Apache-2.0 (workspace-wide).
- **Spec:** `new-design/spec/`. Anything that disagrees with the spec
  is a verifier bug.
- **Reference SDK:** `new-design/sdk/` (TypeScript-free JS).
- **Test fixtures:** `new-design/examples/tamper-detection/output/`,
  produced by the JS SDK and consumed unchanged by the Rust verifier.

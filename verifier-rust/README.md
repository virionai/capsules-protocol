# verifier-rust — second independent Capsule v0.7 verifier

A Rust verifier for Capsule v0.7 capsules (plain and encrypted-outer; v0.6 capsules stay supported forever per spec/versioning.md).
Written from the spec, not ported from the JS reference. Byte-compatible
with the JS SDK (`sdk-js/`) on the canonical shared vector corpus
(`spec/vectors/tamper-detection/`).

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

## What's new in v0.7.1

- **Profile gate (`spec/profiles.md`).** A capsule may declare the
  verification rule set that governs it (`manifest.format.profile` /
  `envelope.profile`). The gate runs after the version gate and before
  anything else: absence means the default profile `v0.6-suite`/`1.0`
  permanently; normalized declarations that disagree refuse with
  `profile_mismatch` (a capsule defect) before any table lookup; a
  declared `(id, version)` outside this verifier's exact-match table
  refuses with `unsupported_profile` — **a limitation of the verifier,
  not corruption of the capsule** — and a shape or grammar violation is
  a malformed document, never "unsupported". Refusal exclusivity: no
  hash recompute, no signature check, no chain walk past a refusal, and
  the reported `format_version.suite` nulls, because a suite claim about
  rules this verifier refused to apply would be false. The inner capsule
  of an encrypted one is gated independently at L3 (there is no
  inner/outer equality rule).
- **`VerifyResult.profile: ProfileCheck`** — `observed`,
  `observed_version`, `declared`, `effective`, `effective_version`,
  `supported`, `status`, `accepted_by_policy` — present on EVERY result,
  including refusals, because the observed declaration is what lets an
  auditor route a capsule to a capable verifier instead of concluding it
  is corrupt. New `TopErrorCategory::Profile`; new `Profile:` line in
  the plain CLI output.
- **Normalized verdict surface (`spec/results.md`):**
  `VerifyResult.verdict` (`valid | invalid | unsupported`, with
  `ok == (verdict == valid)` as an invariant), `verdict_reason`
  (non-null iff `unsupported`), and `qualifiers` — the weaker-claim
  facts a renderer must not hide beside a valid verdict. All three are
  `#[serde(default)]`, so pre-v0.7.1 result JSON still deserializes into
  the fail-closed shape. `QUALIFIERS` is the closed TEN-name vocabulary:
  the seven base names plus the three lineage names below. The CLI
  Result block is verdict-first and enumerates every qualifier in plain
  language; an unqualified valid states its trust basis explicitly.
- **Lineage (`spec/lineage.md`, `manifest.predecessors`):** the verify
  side, in full. `VerifyResult.lineage` reports
  `{declared, ok, verified_depth, entries}`; the standalone shape /
  null-coherence / era-keyed identity-coherence checks fail closed under
  the new `TopErrorCategory::Lineage`; the supplied-bytes linkage walk
  (`VerifyOptions::predecessors`, CLI `--predecessor`, repeatable) is
  REPORT-ONLY — it can falsify `lineage.ok` but never the capsule's own
  `ok`, so a host handing the verifier the wrong file cannot brand an
  honest successor a forgery. Each supplied artifact is verified under
  ITS declared version's rules and matched on RECOMPUTED values only;
  a verified hop's own declaration joins the walk (`verified_depth`).
  Its three qualifiers — `lineage_declared_unverified`,
  `lineage_mismatch`, `lineage_predecessor_invalid` — ride the same
  `qualifiers` array as the seven base names, each meaning "valid
  verdict, custody claim not clean". Payload-carrying facts stay in the
  `lineage` channel.
- **`--accept-versions` (host version policy).** The one mandated fact
  that no CLI could previously reach: reported, never decided.
- **CLI custody policy:** `--predecessor` sets a policy the way
  `--allowlist` and `--accept-versions` do. Without it, declared lineage
  never affects the exit code; with it, exit 1 unless every supplied
  artifact matched a declared entry and verified. Declared entries left
  unsupplied are reported, never a policy failure — an operator may hold
  one branch of a merge.
- **Exit-code/report coherence fix.** The trust policy behind exit 0 now
  counts distinct trusted signers across BOTH envelopes, the same
  outer-or-inner fact the `no_trusted_signer` qualifier and its advisory
  note are derived from. Previously an encrypted capsule opened with
  `--decryption-key`, whose only allowlisted signer sealed the INNER
  envelope, printed `Result: VALID` with no qualifier and still exited 1
  — a failed policy with nothing rendered to explain it.
- The registry consumer (`tests/spec_registry.rs`) now runs
  `spec/vectors/profile-declaration/`, `spec/vectors/result-vocabulary/`
  and `spec/vectors/lineage/`, and asserts `expected.verdict` /
  `verdict_reason` / `qualifiers` (one exact array over all ten names) /
  `profile.*` / `suite` / `lineage.*` / `capsule_id`, with the per-vector
  `predecessors` pool and `accept_versions` policy, across every
  collection that pins them.

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
- Version gate then profile gate, before any other check: an unknown era
  or an unimplementable declared profile fails closed with a diagnosis
  distinct from tampering, and nothing else runs under rules this
  verifier did not apply. Every result reports the observed version, the
  observed profile declaration, the derived verdict, and the qualifiers
  that weaken it.
- `capsule_id` derivation: `SHA-256("capsule-id-v<version>\x00" || originator_pubkey || first_event_hash)`, keyed by the capsule's declared version.
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
- Lineage (`manifest.predecessors`): the standalone shape,
  null-coherence and era-keyed identity-coherence checks fail closed on
  a present declaration; with `--predecessor` artifacts supplied, each
  is verified under its own era and matched against the declaration on
  recomputed values, reported in `result.lineage` — report-only, so the
  pool never changes the capsule's own verdict.
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

- **No capsule building or signing.** Verifier only. That includes
  **rewrap**: this lane verifies a successor's `manifest.predecessors`
  declaration but cannot write one, so a Rust-only operator can check a
  custody claim and not perform a hand-off (`spec/lineage.md` writer
  obligations live in the builder lanes).
- **No FFI.** No WASM, no C ABI, no Python bindings. Yet.

## Build and test

```sh
cd verifier-rust
cargo build --workspace
cargo test --workspace          # 218 tests, all pass
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
                                allowlist AND its signature verifies. Supplying
                                the flag REQUESTS a trust policy: an allowlist
                                that matched no signer keeps the `valid`
                                verdict but exits 1.
  --decryption-key <KEY>        Recipient's X25519 private key for L3
                                verification. <KEY> is either a 64-char
                                lowercase hex string OR a path to a file
                                containing 32 raw bytes / 64-char hex /
                                base64. On encrypted capsules, promotes
                                the verifier from L2 to L3 (decrypts the
                                inner ZIP and walks the inner chain). On
                                plain capsules, the flag is silently
                                ignored.
  --accept-versions <V> [<V>...] Format versions this deployment ACCEPTS
                                (spec/versioning.md "Host policy").
                                Reported, never decided: a capsule
                                outside the set still verifies and its
                                verdict carries the
                                `version_not_accepted_by_policy`
                                qualifier — but since the policy was
                                requested here, failing it exits 1.
  --predecessor <FILE>          Candidate predecessor artifact for lineage
                                linkage (spec/lineage.md). Repeatable.
                                Inside the library the pool is REPORT-ONLY
                                — it can never flip the capsule's own
                                verdict — but supplying it here sets a
                                POLICY, exactly as --allowlist does: every
                                supplied file must match a declared entry
                                and verify under its own era, or the run
                                exits 1. Declared entries left unsupplied
                                are reported, never a policy failure.
```

Exit codes (spec/results.md, identical in both reference CLIs): `0`
VALID and every requested policy satisfied, `1` INVALID / UNSUPPORTED /
a requested policy failed, `2` usage or I/O error. An unknown format
version or an unsupported profile exits `1`, never `2`: it is a verdict
about the capsule-verifier pair, not an operator error.

`--allowlist`, `--accept-versions`, and `--predecessor` are REQUESTED
policies, and an unmet one exits `1`. That is not the verifier deciding
trust: the `VerifyResult` still reports per-signer `valid` and never
`trusted` (spec/trust.md), reports lineage linkage without letting it
touch `ok`, and the verdict beside the failed policy stays `valid`. The
host is the one deciding — and on this command line the host is the
operator who typed the flag, so a demand the capsule did not meet must
fail the run rather than pass in silence. Every failed policy is also
RENDERED: the exit code never disagrees with the report.

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
│   │       ├── lineage.rs      manifest.predecessors checks + linkage walk
│   │       ├── envelope.rs     canonical payload, signing input, sig verify
│   │       ├── decrypt.rs      L3: ChaCha20-Poly1305 + X25519 + HKDF-SHA256
│   │       ├── versions.rs     known-version table + version-keyed domains
│   │       ├── profiles.rs     profile table, grammar, declaration gate
│   │       ├── verifier.rs     top-level orchestrator (L2 + L3 promotion)
│   │       └── lib.rs          re-exports
│   └── capsule-verify-cli/     binary
│       └── src/main.rs         clap CLI: verify <FILE> [--json] [--allowlist ...]
│                               [--decryption-key ...] [--accept-versions ...]
│                               [--predecessor ...]
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
deliverable: the Rust verifier reaches the same verdict the JS SDK
reaches on each of the six fixtures, and the failure (where there is
one) is attributed to the same check. With v0.3, both L2 and L3 paths
are exercised against the encrypted fixtures.

| Fixture | No key (L2) | With recipient key (L3) |
|---|---|---|
| `clean.capsule` | VALID @ L2 | VALID @ L2 (key silently ignored — plain) |
| `tampered-payload.capsule` | INVALID @ `content_index` | (same — plain capsule, key ignored) |
| `tampered-chain.capsule` | INVALID @ `content_index` + `chain` | (same — plain capsule, key ignored) |
| `tampered-envelope.capsule` | INVALID @ `envelope_signature` | (same — plain capsule, key ignored) |
| `clean-encrypted.capsule` | VALID @ L2, qualified `encrypted_outer_only` | **VALID @ L3 (chain fully verified; `inner_envelope.ok=true`, 1 inner signer valid; `inner_content_index.ok=true`)** |
| `tampered-blob.capsule` | INVALID @ `encryption_state` | INVALID @ decryption (auth tag mismatch) |

Full transcript (no `--decryption-key`):

```
=== clean.capsule ===
File:                   ../spec/vectors/tamper-detection/output/clean.capsule (2708 bytes)
Capsule ID:             3e9dd801d3de…
Originator (Ed25519):   9a0ad2b05c92…
Sealed at:              2026-05-08T12:00:00Z
Level:                  L2
Profile:                v0.6-suite (default, undeclared)

Checks:
  [✓] format / version
  [✓] capsule_id / manifest_hash
  [✓] content_index
  [✓] chain
  [✓] envelope_signature
  [✓] signer_set
  [✓] encryption_state

Signers:
  - originator   9a0ad2b05c92…  valid=true  trusted=false

Notes:
  - no allowlist provided; trusted=false for all signers regardless of signature validity

Result: VALID
  qualifiers:
    - trust not evaluated: no allowlist supplied

=== tampered-payload.capsule ===
File:                   ../spec/vectors/tamper-detection/output/tampered-payload.capsule (2708 bytes)
Capsule ID:             3e9dd801d3de…
Originator (Ed25519):   9a0ad2b05c92…
Sealed at:              2026-05-08T12:00:00Z
Level:                  L2
Profile:                v0.6-suite (default, undeclared)

Checks:
  [✓] format / version
  [✓] capsule_id / manifest_hash
  [✗] content_index
        file hash mismatch: program.md: stored b1dad3e029e172beae7c5d47f26197824f5fea47f66042a3d7d3f701d443afb0 vs recomputed cf1ad15cb9cfc558c7e2ef5bba4e886dd6ef9c0d4fe2f44820af109aff63ef61
        manifest.content_index.index_hash mismatch: stored f42f0eb348c41f4edec7b90d4dee8a5df2bf5d88536fd1dc44f2bb493c66e9d4 vs recomputed 5c30e700250d88cf5b3774b57a2e4970a633ea90164b53f227d5ea286a394cb2
        envelope.content_index_hash mismatch: stored f42f0eb348c41f4edec7b90d4dee8a5df2bf5d88536fd1dc44f2bb493c66e9d4 vs recomputed 5c30e700250d88cf5b3774b57a2e4970a633ea90164b53f227d5ea286a394cb2
  [✓] chain
  [✓] envelope_signature
  [✓] signer_set
  [✓] encryption_state

Signers:
  - originator   9a0ad2b05c92…  valid=true  trusted=false

Notes:
  - no allowlist provided; trusted=false for all signers regardless of signature validity

Result: INVALID

=== tampered-chain.capsule ===
File:                   ../spec/vectors/tamper-detection/output/tampered-chain.capsule (2708 bytes)
Capsule ID:             3e9dd801d3de…
Originator (Ed25519):   9a0ad2b05c92…
Sealed at:              2026-05-08T12:00:00Z
Level:                  L2
Profile:                v0.6-suite (default, undeclared)

Checks:
  [✓] format / version
  [✓] capsule_id / manifest_hash
  [✗] content_index
        file hash mismatch: chain/events.jsonl: stored a59cbdfc456813b9a25499ffae444e4ed79ebfedae63f9c4d7a9ccff61a2914f vs recomputed 4a61c02617165a675c2fc5c4d4a0314b13e47bee92b8e4f5b00076d1f7571ab9
        manifest.content_index.index_hash mismatch: stored f42f0eb348c41f4edec7b90d4dee8a5df2bf5d88536fd1dc44f2bb493c66e9d4 vs recomputed fe3bedf1308600a2441927a3ca045493d89b311f601c60b16576b80a094101e3
        envelope.content_index_hash mismatch: stored f42f0eb348c41f4edec7b90d4dee8a5df2bf5d88536fd1dc44f2bb493c66e9d4 vs recomputed fe3bedf1308600a2441927a3ca045493d89b311f601c60b16576b80a094101e3
  [✗] chain
        seq 1: hash mismatch: stored 6c0ca4d536c9e19b4f14163520ca47fa8c7623e0cb201e929964d10e9956c4ad, recomputed c9e66a79586bd62aed7bcb3f0df2a468dfce02053826f8304af99192aff726a3
  [✓] envelope_signature
  [✓] signer_set
  [✓] encryption_state

Signers:
  - originator   9a0ad2b05c92…  valid=true  trusted=false

Notes:
  - no allowlist provided; trusted=false for all signers regardless of signature validity

Result: INVALID

=== tampered-envelope.capsule ===
File:                   ../spec/vectors/tamper-detection/output/tampered-envelope.capsule (2708 bytes)
Capsule ID:             3e9dd801d3de…
Originator (Ed25519):   9a0ad2b05c92…
Sealed at:              2026-05-08T12:00:00Z
Level:                  L2
Profile:                v0.6-suite (default, undeclared)

Checks:
  [✓] format / version
  [✓] capsule_id / manifest_hash
  [✓] content_index
  [✓] chain
  [✗] envelope_signature
        signer originator (9a0ad2b05c92…) signature did not verify
  [✗] signer_set
        originator binding: manifest.originator.public_key 9a0ad2b05c9276891dcd3e183946660bcfe895adb3e63f6911a9514d666b7249 has no valid envelope signature with role 'originator'
  [✓] encryption_state

Signers:
  - originator   9a0ad2b05c92…  valid=false  trusted=false

Notes:
  - no allowlist provided; trusted=false for all signers regardless of signature validity

Result: INVALID

=== clean-encrypted.capsule ===
File:                   ../spec/vectors/tamper-detection/output/clean-encrypted.capsule (5587 bytes)
Capsule ID:             b4b1792c79b3…
Originator (Ed25519):   9a0ad2b05c92…
Sealed at:              2026-05-08T12:00:00Z
Level:                  L2
Profile:                v0.6-suite (default, undeclared)

Checks:
  [✓] format / version
  [✓] capsule_id / manifest_hash
  [✓] content_index
  [✓] chain
        deferred to L3 (encrypted outer)
  [✓] envelope_signature
  [✓] signer_set
  [✓] encryption_state

Signers:
  - originator   9a0ad2b05c92…  valid=true  trusted=false

Notes:
  - no allowlist provided; trusted=false for all signers regardless of signature validity

Result: VALID
  qualifiers:
    - content is encrypted and was not read (L2 outer only; chain deferred to L3)
    - trust not evaluated: no allowlist supplied

=== tampered-blob.capsule ===
File:                   ../spec/vectors/tamper-detection/output/tampered-blob.capsule (5587 bytes)
Capsule ID:             b4b1792c79b3…
Originator (Ed25519):   9a0ad2b05c92…
Sealed at:              2026-05-08T12:00:00Z
Level:                  L2
Profile:                v0.6-suite (default, undeclared)

Checks:
  [✓] format / version
  [✓] capsule_id / manifest_hash
  [✓] content_index
  [✓] chain
        deferred to L3 (encrypted outer)
  [✓] envelope_signature
  [✓] signer_set
  [✗] encryption_state
        envelope.encrypted_blob_hash mismatch: stored f3283b5803e595ece1c8b9c0846bdc807cd0a17f9854c11013cbafe90f2accc5 vs recomputed 9126b3ef7e4badf58c85d30b7950015a26471eef9245de43a1ec294c58a9039e

Signers:
  - originator   9a0ad2b05c92…  valid=true  trusted=false

Notes:
  - no allowlist provided; trusted=false for all signers regardless of signature validity

Result: INVALID
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
File:                   ../spec/vectors/tamper-detection/output/clean-encrypted.capsule (5587 bytes)
Capsule ID:             b4b1792c79b3…
Originator (Ed25519):   9a0ad2b05c92…
Sealed at:              2026-05-08T12:00:00Z
Level:                  L3
Profile:                v0.6-suite (default, undeclared)

Checks:
  [✓] format / version
  [✓] capsule_id / manifest_hash
  [✓] content_index
  [✓] chain
  [✓] envelope_signature
  [✓] signer_set
  [✓] inner_envelope_signature
  [✓] inner_content_index
  [✓] encryption_state

Signers:
  - originator   9a0ad2b05c92…  valid=true  trusted=false

Inner signers:
  - originator   9a0ad2b05c92…  valid=true  trusted=false

Notes:
  - no allowlist provided; trusted=false for all signers regardless of signature validity

Result: VALID
  qualifiers:
    - trust not evaluated: no allowlist supplied

=== tampered-blob.capsule (with --decryption-key) ===
File:                   ../spec/vectors/tamper-detection/output/tampered-blob.capsule (5587 bytes)
Capsule ID:             b4b1792c79b3…
Originator (Ed25519):   9a0ad2b05c92…
Sealed at:              2026-05-08T12:00:00Z
Level:                  L2
Profile:                v0.6-suite (default, undeclared)

Checks:
  [✓] format / version
  [✓] capsule_id / manifest_hash
  [✓] content_index
  [✓] chain
        deferred to L3 (encrypted outer)
  [✓] envelope_signature
  [✓] signer_set
  [✗] encryption_state
        envelope.encrypted_blob_hash mismatch: stored f3283b5803e595ece1c8b9c0846bdc807cd0a17f9854c11013cbafe90f2accc5 vs recomputed 9126b3ef7e4badf58c85d30b7950015a26471eef9245de43a1ec294c58a9039e
        L3: decryption failed: content decrypt failed (ChaCha20-Poly1305 auth tag invalid for content.enc)

Signers:
  - originator   9a0ad2b05c92…  valid=true  trusted=false

Notes:
  - no allowlist provided; trusted=false for all signers regardless of signature validity

Result: INVALID
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
- **Spec:** `spec/`. Anything that disagrees with the spec
  is a verifier bug.
- **Reference SDK:** `sdk-js/` (TypeScript-free JS).
- **Test fixtures:** `spec/vectors/tamper-detection/output/`,
  produced by the JS SDK and consumed unchanged by the Rust verifier.

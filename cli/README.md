# capsule — CLI for Capsule v0.6 files

A command-line tool for inspecting, verifying, extracting, and parity-
testing Capsule v0.6 artifacts. Wraps the JS reference SDK.

The Rust verifier at `../verifier-rust/` is the trust-critical, minimal
implementation (memory-safe, vetted crypto crates, single-purpose). This
CLI is the everyday user-facing tool: cross-platform, npm-installable,
multi-command, structured JSON output for scripting.

## Install

```sh
cd CLI
npm install
npm link            # optional; exposes `capsule` globally
```

Or invoke directly without linking:

```sh
node cli/bin/capsule.mjs <command> [args...]
```

Requires Node ≥ 20.

## Commands

### `capsule verify <file> [--allowlist KEY...] [--json]`

Wraps the SDK's `verifyCapsule()`. Checks signature(s), capsule_id
derivation, manifest hash, content-index hash, and chain hash linkage.

```text
$ capsule verify clean.capsule
File:                   clean.capsule (4493 bytes)
Capsule ID:             d6d73f94c78e…
Originator (Ed25519):   c172289fcacf…
Sealed at:              2026-05-07T12:00:00Z
Level:                  L2

Checks:
  [✓] content_index
  [✓] chain
  [✓] envelope_signature

Signers:
  - originator:   c172289fcacf…  valid=true  trusted=false

Notes:
  - no allowlist provided; trusted=false for all signers regardless of signature validity

Result: PASS
```

`--allowlist <hex>` may be repeated. A signer is `trusted=true` only
when its key appears on the allowlist *and* its signature verifies.

`--json` emits a structured `VerifyResult` object instead of the
human-readable report. Same exit code in either mode.

### `capsule inspect <file> [--json]`

One-screen overview: format version, identity, sealed time, file count,
chain length, action histogram, payload tree size, signer summary. No
verification — use `verify` for that.

### `capsule chain <file> [--limit N] [--json]`

Walks the chain. Default output is one row per event with kind, action,
date, payload summary, and any flagged `untrusted_payload_fields`.
`--json` emits the full event objects (including hashes) as a JSON
array — useful for scripting downstream analysis.

### `capsule manifest <file>` / `capsule envelope <file>`

Print `manifest.json` / `provenance/envelope.json` parsed and pretty-
formatted. Always JSON; pipe to `jq` for filtering.

### `capsule program <file>` / `capsule agents <file>`

Print `program.md` / `agents.md` to stdout.

### `capsule extract <file> <out-dir> [--force]`

Unpack the entire capsule into a directory tree. The doctor's reader
does this in-browser; this is the same operation from the command
line, useful when an analyst wants to grep the chain or run external
tools on the payload media.

Refuses to write into a non-empty directory unless `--force`.

### `capsule keygen [--out DIR] [--label NAME] [--json]`

Generate a fresh Ed25519 keypair. Writes lowercase hex (64 chars per
key) — the same shape every multi-language SDK accepts.

```sh
$ capsule keygen --out ./keys --label clinic-rx7q
Generated Ed25519 keypair (clinic-rx7q):
  public  → ./keys/clinic-rx7q.public.hex
  private → ./keys/clinic-rx7q.private.hex  (chmod 600)
  pubkey  : 7c6df3ac1d55b8c4...
```

### `capsule vectors verify <vectors.json> [--json]`

The cross-implementation parity check. Reads a `parity-vectors.json`
file (produced by an example's generator) which embeds the canonical
sealed `.capsule` bytes plus the expected per-field hashes.

The CLI:

1. Decodes the embedded bytes.
2. Runs the SDK verifier over them.
3. Diffs every observed hash against the file's `expected.*` block.
4. Prints PASS only if both conditions hold.

This is the single command a CI matrix can run across **JS, Rust,
Python, Swift, and Kotlin** to prove the implementations agree on the
canonical bytes for a given chain seed. Drift in any field surfaces as
a labeled diff.

```text
$ capsule vectors verify ../examples/medical-journal/parity-vectors.json
Vectors:           parity-vectors.json
Format version:    0.6
Generator:         examples/medical-journal/generate-parity-vectors.mjs
Signed at (fixed): 2026-04-29T12:00:00Z

SDK verify:        ✓ (L2)
  chain:           ✓
  content_index:   ✓
  envelope:        ✓
  trusted signers: 1

Hash parity:
  [✓] capsule_id                    fe683de20ea0408f…
  [✓] first_event_hash              dbb72055de126a42…
  [✓] entry_hash                    a2ef9d8fe2fa799c…
  [✓] manifest_hash                 c06a1c2506262bf8…
  [✓] content_index_hash            0730401a3739719b…
  [✓] envelope_signature_hex        dc31925f5d4fa1f7…
  [✓] event_hashes[]                6/6 match

Result: PASS
```

## Exit codes

```
0    success / verification passed / hashes match
1    verification failed / vectors mismatch / signature invalid
2    I/O, argument, or environment error (file missing, encrypted-
     capsule reader path requested without a key, malformed input, …)
```

`verify`, `vectors verify`, and `extract` are the three commands that
care about exit codes for scripting; `inspect`, `chain`, `manifest`,
etc. exit 2 only on bad input.

## JSON mode

Every command that has structured output supports `--json`. The shape
is stable across the prototype line — wire it into CI without expecting
changes from minor revisions.

## What's *not* in this CLI

- **Building** a capsule. Builders are example-specific (the
  symptom-tracker and medical-journal each shape their own chain).
  Capsule construction lives in those examples and in the per-language
  SDKs. The CLI verifies and inspects — it does not author.
- **Decryption with a recipient key.** Encrypted-capsule support is
  parking-lot for a follow-up CLI revision. For now, encrypted capsules
  surface a clean error pointing at the SDK or the doctor's reader.

## Test

```sh
npm test
```

Runs `test/smoke.mjs`, which exercises every command against the
tamper-detection and medical-journal example fixtures. Asserts exit
codes (0 / 1 / 2) and JSON-output shape. 53 checks at the time of
writing.

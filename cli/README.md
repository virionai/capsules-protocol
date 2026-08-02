# capsule — CLI for Capsule v0.6 files

A command-line tool for inspecting, verifying, extracting, and parity-
testing Capsule v0.6 artifacts. Wraps the JS reference SDK.

The Rust verifier at `../verifier-rust/` is the trust-critical, minimal
implementation (memory-safe, vetted crypto crates, single-purpose). This
CLI is the everyday user-facing tool: cross-platform, npm-installable,
multi-command, structured JSON output for scripting.

## Install

```sh
cd cli
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

Wraps the SDK's `verifyCapsule()` and applies the CLI's **trust
policy** on top. The SDK checks the math — signature(s), capsule_id
derivation, manifest hash, content-index hash, chain hash linkage,
signer-set binding — and reports facts; it never decides policy. The
CLI does, because the CLI is where the operator says what they demand:

- **No `--allowlist`** — no trust policy. The verdict covers integrity
  only, and both the report and the `Result:` line say so. Signer
  identity is *not checked*: anyone's valid signature passes.
- **`--allowlist <hex>`** (repeatable) — sets the trust policy: at
  least one **distinct** allowlisted key must carry a valid signature.
  A capsule whose math checks pass but whose signers all miss the
  allowlist **FAILS with exit 1** — `capsule verify f --allowlist $KEY
  && deploy` will not deploy an artifact signed by someone you did not
  trust. An entry that is not 64 hex chars is a usage error (exit 2).

```text
$ capsule verify clean.capsule --allowlist c172289fcacf...
File:                   clean.capsule (4493 bytes)
Capsule ID:             d6d73f94c78e…
Originator (Ed25519):   c172289fcacf…
Sealed at (attested):   2026-05-07T12:00:00Z  — signer-supplied; no external time anchor
Level:                  L2

Checks:
  [✓] content_index
  [✓] chain
  [✓] envelope_signature
  [✓] signer_set

Trust:
  policy:            allowlist (1 key supplied)
  trusted signers:   1 distinct allowlisted key(s) with a valid signature
  policy check:      SATISFIED

Signers:
  - originator:   c172289fcacf…  valid=true  trusted=true

Result: PASS (integrity verified; trust policy satisfied)
```

Without an allowlist the same capsule prints
`Result: PASS (integrity only — signer identity not checked)`; with an
allowlist no signer matches, it prints
`Result: FAIL (integrity verified; trust policy FAILED: no signer
matches the supplied allowlist)` and exits 1.

`Sealed at` is labelled **(attested)** deliberately: `signed_at` is
self-attested by the signer and v0.6 has no external time anchor, so
the CLI never presents it as a verified fact.

`--json` emits a structured result instead of the human-readable
report. Same exit code in either mode. `ok` is the **overall** verdict
(integrity AND policy — it always matches the exit code);
`integrity_ok` preserves the SDK's math-only verdict (the analogue of
the Rust CLI's `ok`); the `trust` block carries
`{policy, allowlist_size, trusted_signer_count, satisfied}`, where
`satisfied` is `null` when no policy was supplied.

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

Unpack the entire capsule into a directory tree. This is useful when an
analyst wants to inspect the chain or run external tools on payload
files.

Refuses to write into a non-empty directory unless `--force`.

### `capsule keygen [--out DIR] [--label NAME] [--json]`

Generate a fresh Ed25519 keypair. Writes lowercase hex (64 chars per
key) — the same shape every multi-language SDK accepts.

```sh
$ capsule keygen --out ./keys --label originator
Generated Ed25519 keypair (originator):
  public  → ./keys/originator.public.hex
  private → ./keys/originator.private.hex  (chmod 600)
  pubkey  : 7c6df3ac1d55b8c4...
```

### `capsule vectors verify <vectors.json> [--json]`

The cross-implementation parity check. Reads a vectors JSON file that
embeds canonical sealed `.capsule` bytes plus the expected per-field
hashes.

The CLI:

1. Decodes the embedded bytes.
2. Runs the SDK verifier over them.
3. Diffs every observed hash against the file's `expected.*` block.
4. Prints PASS only if both conditions hold.

This is the single command a CI matrix can run across implementations
to prove they agree on the canonical bytes for a given chain seed.
Drift in any field surfaces as a labeled diff.

```text
$ capsule vectors verify spec/vectors/plain-basic.json
Vectors:           parity-vectors.json
Format version:    0.6
Generator:         spec/vectors/plain-basic
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

CI depends on these; they are part of the CLI's contract (enforced by
`test/smoke.mjs`).

```
0    success — for verify: integrity verified AND any supplied trust
     policy satisfied. With no --allowlist, exit 0 means integrity
     only; signer identity was NOT checked.
1    verification failed — integrity checks failed, OR a supplied
     trust policy was not satisfied (no allowlisted key signed), OR
     vectors mismatch.
2    usage, I/O, or environment error — unknown flag, unexpected
     positional, malformed --allowlist entry, missing file, capsule
     that cannot be opened, encrypted-capsule content requested
     without decryption, …
```

The parser fails closed: any flag a command does not declare, and any
positional beyond what it accepts, is an exit-2 error. A typo'd
`--alowlist` can never silently drop your trust policy.

`verify`, `vectors verify`, and `extract` are the three commands that
care about exit codes for scripting; `inspect`, `chain`, `manifest`,
etc. exit 2 only on bad input.

## JSON mode

Every command that has structured output supports `--json`. The shape
is stable across the prototype line — wire it into CI without expecting
changes from minor revisions.

## What's *not* in this CLI

- **Building** a capsule. Builders are example-specific (the
  calling application defines its own actor, action, and payload
  vocabulary). Capsule construction lives in the per-language SDKs. The
  CLI verifies and inspects — it does not author.
- **Decryption with a recipient key.** Encrypted-capsule support is
  parking-lot for a follow-up CLI revision. For now, encrypted capsules
  surface a clean error pointing at the tools that do decrypt: the
  SDK's `reader.decrypt()` and the Rust `capsule-verify-cli`, whose
  `--decryption-key` flag performs verified L3 (decrypted-content)
  verification. No `capsule` command accepts `--decryption-key`, and
  the parser rejects it rather than ignoring it.

## Test

```sh
npm test
```

Runs `test/smoke.mjs`, which exercises every command against the
repo-local fixtures generated by the JavaScript reference SDK at test
startup. Asserts exit codes (0 / 1 / 2) and JSON-output shape.

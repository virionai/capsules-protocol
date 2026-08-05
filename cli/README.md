# capsule — CLI for Capsule v0.7 files

A command-line tool for inspecting, verifying, extracting, and parity-
testing Capsule v0.7 artifacts. Wraps the JS reference SDK.

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

### `capsule verify <file> [--allowlist KEY...] [--accept-versions VERSION...] [--json]`

Wraps the SDK's `verifyCapsule()` and applies the CLI's **policy
layer** on top. The SDK checks the math — signature(s), capsule_id
derivation, manifest hash, content-index hash, chain hash linkage,
signer-set binding — and reports facts; it never decides policy. The
CLI does, because the CLI is where the operator says what they demand:

- **No `--allowlist`** — no trust policy. The verdict covers integrity
  only, and both the report and the `Result:` block say so. Signer
  identity is *not checked*: anyone's valid signature passes.
- **`--allowlist <hex>`** (repeatable) — sets the trust policy: at
  least one **distinct** allowlisted key must carry a valid signature.
  A capsule whose math checks pass but whose signers all miss the
  allowlist **fails the run with exit 1** — `capsule verify f
  --allowlist $KEY && deploy` will not deploy an artifact signed by
  someone you did not trust. An entry that is not 64 hex chars is a
  usage error (exit 2).
- **`--accept-versions <major.minor>`** (repeatable) — sets the version
  policy (`spec/versioning.md` "Host policy"). A capsule declaring a
  version outside the set still verifies — the math is unaffected, and
  the SDK reports rather than decides — but the run **fails with exit
  1** and the verdict carries `version_not_accepted_by_policy`. Absent
  the flag, no policy is declared and the fact is reported as `null`.
  A value outside the `<major>.<minor>` grammar is a usage error
  (exit 2).

```text
$ capsule verify clean.capsule --allowlist c172289fcacf...
File:                   clean.capsule (4493 bytes)
Capsule ID:             d6d73f94c78e…
Originator (Ed25519):   c172289fcacf…
Sealed at (attested):   2026-05-07T12:00:00Z  — signer-supplied; no external time anchor
Level:                  L2
Format version:         0.7  (v0.6 suite)
Profile:                v0.6-suite/1.0 (default, undeclared)

Checks:
  [✓] content_index
  [✓] chain
  [✓] envelope_signature
  [✓] signer_set
  [✓] actor_set

Trust:
  policy:            allowlist (1 key supplied)
  trusted signers:   1 distinct allowlisted key(s) with a valid signature
  policy check:      SATISFIED

Signers:
  - originator:   c172289fcacf…  valid=true  trusted=true

Result: VALID (no qualifiers; 1 distinct trusted signer)
  trust policy: SATISFIED
```

#### The Result block (`spec/results.md`)

The verdict is **verdict-first and fully qualified**: `VALID`,
`INVALID`, or `UNSUPPORTED`, taken from the SDK's normalized verdict,
with every qualifier enumerated beneath it. A qualifier names a
weaker claim the capsule made honestly (or a scope this run did not
cover); a renderer that hides one turns an honest weaker claim by the
author into a false stronger claim by the tooling, so the CLI never
prints a bare `VALID`:

```text
Result: VALID
  qualifiers:
    - signer set is not bound by the seal (manifest.signer_commitment absent)
    - chain actors are not bound to a declared participant set (manifest.participants empty)
    - empty chain: no events to walk; envelope anchors checked to be null instead
    - trust not evaluated: no allowlist supplied
```

`UNSUPPORTED` is the honest verdict for a capsule this verifier cannot
understand — an era it does not know, or a declared profile it does not
implement. It is **a limitation of the verifier, not a defect of the
capsule**, it stays distinguishable from tamper, and it exits 1:

```text
Result: UNSUPPORTED (unsupported_version_newer: manifest.format.version '9.9' is newer than this verifier supports (newest known: 0.7))
Result: UNSUPPORTED (unsupported_profile: profile 'x-acme-kms' version '1.0' is not supported by this verifier (supported: v0.6-suite/1.0))
```

A requested policy that went unmet prints its own line under the
verdict (`trust policy: FAILED — …`, `version policy: FAILED — …`) —
exit 1 with a `VALID` verdict is only honest if the report says which
demand failed.

`Sealed at` is labelled **(attested)** deliberately: `signed_at` is
self-attested by the signer and the format has no external time anchor, so
the CLI never presents it as a verified fact.

`--json` emits a structured result instead of the human-readable
report. Same exit code in either mode. `ok` is the **overall** verdict
(integrity AND every requested policy — it always matches the exit
code); `integrity_ok` preserves the SDK's math-only verdict (the
analogue of the Rust CLI's `ok`); `verdict` / `verdict_reason` /
`qualifiers` are the normalized verdict surface, byte-identical in
every lane; the `trust` block carries
`{policy, allowlist_size, trusted_signer_count, satisfied}` and
`version_policy` carries `{policy, accept_versions, satisfied}`, where
`satisfied` is `null` when that policy was not supplied;
`format_version` and `profile` are the reported version/profile
channels, under the Rust CLI's member names.

### `capsule inspect <file> [--json]`

One-screen overview: format version, identity, sealed time, file count,
chain length, action histogram, payload tree size, signer summary. No
verification — use `verify` for that.

When the capsule **declares** a profile (`spec/profiles.md`), the raw
declaration is printed as written (`Profile (declared): <id>/<version>`)
and carried in `--json` under `profile.manifest` / `profile.envelope`.
Absence is not a missing fact — it *is* the era default — so nothing is
printed for it; `capsule verify` names the profile actually applied
either way.

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
Format version:    0.7
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
`test/smoke.mjs`) and they are the exit codes `spec/results.md` fixes
for both reference CLIs. There is no exit 3.

```
0    success — for verify: verdict VALID AND every requested policy
     satisfied. With no --allowlist, exit 0 means integrity only;
     signer identity was NOT checked, and the Result block says so.
1    verdict INVALID or UNSUPPORTED, a requested policy not satisfied
     (--allowlist matched no signer, --accept-versions excludes the
     declared version), or vectors mismatch.
2    usage, I/O, or environment error — unknown flag, unexpected
     positional, malformed --allowlist or --accept-versions entry,
     missing or unreadable file, encrypted-capsule content requested
     without decryption, …
```

**Changed in v0.7.1 (CI-observable):** a capsule this verifier cannot
open — an unknown format version, an unsupported declared profile, or
a malformed container — now exits **1**, not 2. An unknown era is a
verdict about the capsule/verifier pair, not an operator error; `verify`
feeds the bytes to the total verifier and renders the fail-closed
result, which is what the Rust `capsule-verify-cli` has always done.
Exit 2 now means only "this invocation was wrong or the file could not
be read".

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

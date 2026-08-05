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

### `capsule verify <file> [--allowlist KEY...] [--predecessor FILE...] [--json]`

Wraps the SDK's `verifyCapsule()` and applies the CLI's **trust policy**
and **custody policy** on top. The SDK checks the math — signature(s),
capsule_id derivation, manifest hash, content-index hash, chain hash
linkage, signer-set binding, the `manifest.predecessors` declaration —
and reports facts; it never decides policy. The CLI does, because the
CLI is where the operator says what they demand:

- **No `--allowlist`** — no trust policy. The verdict covers integrity
  only, and both the report and the `Result:` line say so. Signer
  identity is *not checked*: anyone's valid signature passes.
- **`--allowlist <hex>`** (repeatable) — sets the trust policy: at
  least one **distinct** allowlisted key must carry a valid signature.
  A capsule whose math checks pass but whose signers all miss the
  allowlist **FAILS with exit 1** — `capsule verify f --allowlist $KEY
  && deploy` will not deploy an artifact signed by someone you did not
  trust. An entry that is not 64 hex chars is a usage error (exit 2).
- **No `--predecessor`** — no custody policy. A declared lineage is
  reported in full (it is never omitted) but never affects the exit
  code: linkage is a fact about a *pair* of artifacts, the second one
  chosen by whoever ran the command, so it must not be able to brand an
  honest capsule a forgery.
- **`--predecessor <file>`** (repeatable) — sets the custody policy:
  every supplied file must match a declared entry, verify valid under
  its own era, and satisfy every one of the six equalities.
  `capsule verify s --predecessor p && publish` will not publish on a
  failed custody check you asked for. Repeat the flag for merges and
  for deeper lineage (one file per hop). Declared entries you did not
  supply are reported but do **not** fail the exit — an operator may
  hold only one branch of a merge. A supplied file that matches nothing
  DOES fail it: a mistyped path must never exit 0. An unreadable path
  is a usage error (exit 2).

```text
$ capsule verify bob.capsule --predecessor alice.capsule
...
Custody (lineage):
  declared:          1 predecessor entry
  policy:            predecessor (1 file supplied)
  verified depth:    1
  - hop 1  capsule 3fa29c018e4d…  era 0.7  status=verified
      supplied artifact: ok=true  level=L2  version=0.7  errors=0
  policy check:      SATISFIED — every supplied predecessor matched a declared entry and verified
  notes:
    - manifest.predecessors is the successor's one-way declaration; the
      predecessor's originator has not countersigned it
    - successor of capsule 3fa29c01…; lineage verified to depth 1
```

Lineage wording is pinned by `spec/lineage.md` and asserted by
`test/rewrap.test.mjs`: an unchecked entry always renders **"declared,
not verified"**; a declared lineage always carries the **"not
countersigned"** statement (citation is not endorsement — there is no
consent bit in v0.7.1); a supplied file that is a different genuine seal
of the same identity is reported as a **"different sealed state of the
declared predecessor"**, never as tampering; and a predecessor that
fails its own verification is worded as a property of *that artifact*,
naming the era it was checked under.

`--json` adds a `lineage` block (`declared`, `ok`, `verified_depth`,
`entries[]` — the spec's facts channel, per-entry `status` one of
`unverified` | `verified` | `mismatch` | `predecessor_invalid` |
`predecessor_unverifiable`) and a `custody` block
(`policy`, `predecessors_supplied`, `unmatched_count`, `verified_depth`,
`satisfied`) carrying this invocation's policy. `integrity_ok` stays the
capsule's own verdict: a failed custody check moves `ok` and the exit
code, never `integrity_ok`.

### `capsule rewrap <predecessor.capsule> --key FILE --out FILE [...]`

Continue someone else's sealed capsule under **your own** identity. The
originator binding means a successor cannot be signed under the
predecessor's key; a successor instead *declares* the exact sealed
artifact it continues from, in `manifest.predecessors`
(`spec/lineage.md`). `rewrap` is that hand-off as one command — the
CLI's only writing command.

```sh
capsule keygen --out ./keys --label bob
capsule rewrap alice.capsule --key ./keys/bob.private.hex \
    --out bob.capsule --participant human:bob --label Bob
capsule verify bob.capsule --predecessor alice.capsule    # exit 0, depth 1
```

What travels and what does not: **files carry, claims reset.**
`program.md`, `agents.md`, `payload/**`, `skills/**` and any other
content-indexed file are copied byte-identically — they are the work
being continued. The predecessor's manifest members are its originator's
claims about *that* capsule and are not echoed: `participants`
(yours to declare — `--participant`, repeatable; the default is an
unbound actor set), `created_at`, labels, the signer commitment, and the
predecessor's own `predecessors` member. Re-rewrapping declares only the
immediate parent, so ancestry never flattens into an inline list — it is
recovered hop by hop with repeated `--predecessor` flags. The chain
resets to a fresh genesis (predecessor history stays where it is
signed) opening with a `custody_received` observation event
(`--custody-actor`, default `system:host`; `--no-custody-event` to omit).

Refusals — the CLI applies exactly one policy, "do not build on a
predecessor that fails verification", with the same supplied-flag
override discipline as `--allowlist`:

- predecessor fails its own verification → **exit 1**, nothing written.
  `--allow-invalid-predecessor` proceeds, prints a warning, and still
  cites the exact artifact — linkage verification reports it
  `predecessor_invalid` whichever path sealed the successor. The flag
  changes no emitted byte; it is UX, not a security boundary.
- predecessor declares an era this build does not know → **exit 1**, no
  override: the entry's `capsule_id` recompute needs that era's domain
  string, so a derived entry would be a fabricated commitment.
- predecessor is **encrypted** (or declares an alternate profile) →
  **exit 2**: an input class this command does not take, not a verdict
  about the artifact. v0.7.1 declarations commit to a plain,
  default-profile capsule's members; decrypt the inner capsule with the
  SDK (`reader.decrypt(...)`) and rewrap that — the inner IS a plain
  capsule.

`--created-at` / `--signed-at` pin both timestamps: the same
predecessor, key and flags then reproduce the successor byte-for-byte.
Without them, two rewraps are two distinct genuine successors (a
different genesis timestamp is a different `capsule_id`) — both honest;
the format ranks no successor over another. The private key is read,
used to sign, and never printed. `--json` emits the machine result
(successor id, carried paths, the six-member entry, the predecessor's
verification summary, warnings).

Rewrap obtains nothing from the predecessor's originator: every
successful run prints the "not countersigned" note, and the successor's
id line says **"new identity"**.

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
self-attested by the signer and the format has no external time anchor, so
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
`test/smoke.mjs`).

```
0    success — for verify: integrity verified AND every supplied policy
     satisfied (--allowlist, --predecessor). With neither flag, exit 0
     means integrity only; signer identity was NOT checked and no
     custody claim was established. For rewrap: the successor was
     written (including under --allow-invalid-predecessor).
1    verification failed — integrity checks failed, OR a supplied
     policy was not satisfied (no allowlisted key signed; a supplied
     predecessor did not establish the declared linkage), OR vectors
     mismatch, OR rewrap refused its predecessor (fails its own
     verification, or declares an era this build does not know).
     rewrap writes nothing on exit 1.
2    usage, I/O, or environment error — unknown flag, unexpected
     positional, malformed --allowlist entry, --key file or
     --created-at/--signed-at value, missing --out, an --out that
     exists without --force, missing file,
     capsule that cannot be opened, encrypted-capsule content
     requested without decryption, an input class a command does not
     take (rewrap of an encrypted or alternate-profile predecessor), …
```

The parser fails closed: any flag a command does not declare, and any
positional beyond what it accepts, is an exit-2 error. A typo'd
`--alowlist` can never silently drop your trust policy, and a typo'd
`--alow-invalid-predecessor` can never silently seal on a broken
artifact.

The split between 1 and 2 is deliberate: exit 1 is always a statement
about an artifact (it failed, or it did not satisfy what you asked
for); exit 2 is always a statement about the invocation or about what
this build can process. A refusal for a class this CLI does not handle
is never dressed up as a verdict on the capsule.

`verify`, `rewrap`, `vectors verify`, and `extract` are the commands
that care about exit codes for scripting; `inspect`, `chain`,
`manifest`, etc. exit 2 only on bad input.

## JSON mode

Every command that has structured output supports `--json`. The shape
is stable across the prototype line — wire it into CI without expecting
changes from minor revisions.

## What's *not* in this CLI

- **Building** a capsule from scratch. Builders are example-specific
  (the calling application defines its own actor, action, and payload
  vocabulary). Capsule construction lives in the per-language SDKs.
  `rewrap` is the one exception: continuing an EXISTING capsule needs
  no application vocabulary, because everything it writes is derived
  from the predecessor plus your key.
- **Merging** two predecessors in one command. `rewrap` takes one
  predecessor (a hand-off has one subject); a successor declaring two
  parents is built through the SDK builder
  (`continueFrom` + `declarePredecessor` per parent) and verifies here
  with repeated `--predecessor` flags.
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

Runs two suites against repo-local fixtures generated by the JavaScript
reference SDK at test startup:

- `test/smoke.mjs` — every command, exit codes (0 / 1 / 2), JSON shape.
- `test/rewrap.test.mjs` — lineage and rewrap, built around the
  end-to-end two-actor hand-off: Alice seals, the naive continuation
  fails the originator binding, Bob rewraps, `verify --predecessor`
  reaches depth 1, Carol rewraps Bob and it reaches depth 2. Asserts
  every pinned phrase, both policy failure modes, and each refusal's
  exit code.

# Verifier Results and Renderer Language

This document normalizes the *report* of verification: a shared verdict
surface, a closed qualifier vocabulary, the canonical note strings, and
the minimum language a renderer must show a human. It is a
**normalization of an existing reporting surface, not a new
verification feature**: every name below restates a fact at least one
spec section already mandates ([manifest.md](manifest.md)
`signer_commitment`, [chain.md](chain.md) step 6 and "Empty chains",
[versioning.md](versioning.md) requirement 3 and "Host policy",
[envelope.md](envelope.md) verification step 8,
[profiles.md](profiles.md) reporting), and no rule here adds a
rejection or changes capsule bytes.

The failure mode this closes is the [trust.md](trust.md) threat row "a
renderer or verifier report that labels math-only verification as
trust": a host truthfully says "verified" about a capsule with an
unbound signer set, an unwalked zero-event chain, no allowlist
consulted, and a version outside the host's accepted set. Every one of
those facts is on the result object; none was required to reach the
human. The capsule didn't lie; the report lied by omission.

## The result surface

Three members, added to every lane's existing verify result alongside
all existing fields (nothing is removed or renamed in v0.7.1):

```json
{
  "verdict": "valid",
  "verdict_reason": null,
  "qualifiers": ["signer_set_unbound", "actor_set_unbound"]
}
```

- `verdict` — string, closed enum: `"valid" | "invalid" | "unsupported"`.
- `verdict_reason` — string or null. Non-null **iff** `verdict ==
  "unsupported"`; names the machine-readable cause of the refusal.
- `qualifiers` — array of strings, always present. Non-empty only when
  `verdict == "valid"`. Order: the spec-defined order below for
  spec-defined entries; `x-` extension entries (if any) follow, in
  emitter order.

The *values* are the wire vocabulary, byte-identical in every lane; the
container members follow each lane's casing idiom, exactly as
`formatVersion`/`format_version` already does:

| Surface | Members |
|---|---|
| sdk-js result | `verdict`, `verdictReason`, `qualifiers` |
| sdk-py result dict | `verdict`, `verdict_reason`, `qualifiers` |
| verifier-rust `VerifyResult` | `verdict: Verdict` (serde-renamed `valid/invalid/unsupported`), `verdict_reason: Option<String>`, `qualifiers: Vec<String>` (strings, not an enum, so `x-` entries pass through) |
| sdk-swift `CapsuleVerification` | `verdict`, `verdictReason`, `qualifiers` |
| sdk-kotlin `CapsuleVerification` | `verdict`, `verdictReason`, `qualifiers` (defaulted) |
| Node CLI `--json` | top-level `verdict`, `verdict_reason`, `qualifiers` beside `ok`/`integrity_ok` (CLI `ok` remains integrity AND policy; `verdict` is the SDK fact — the CLI stays the policy layer) |
| Conformance registry | `expected.verdict`, `expected.verdict_reason`, `expected.qualifiers` (exact array after stripping `x-` entries), `expected.profile.status`; per-vector `accept_versions` |

## Verdict derivation (normative, total)

Derived — like `skill_trust` — from facts the result already carries,
in this order:

1. `unsupported` iff the capsule was refused *because the verifier
   cannot understand what it declares*: an unknown declared format
   version in either document (`unknown_newer`/`unknown_older`,
   whether the refusal fired at open or verify stage), a declared
   profile the verifier does not implement (profile status
   `unsupported`, [profiles.md](profiles.md)), or a documented lane
   capability refusal (below). Not corruption; a different verifier may
   verify it.
2. `valid` iff the existing overall verdict is true (`ok` — the
   conjunction each lane already computes).
3. `invalid` otherwise — tamper, malformation (including
   version-grammar violations), canonicalization refusals, `unread`.

`verdict` never disagrees with `ok`: **`ok == (verdict == "valid")` is
an invariant**, pinned by vectors. `unsupported` is a partition *of*
`ok: false`, not a third truth value.

**Profile mismatch maps to `verdict: "invalid"`, `verdict_reason:
null`.** A mismatch between the manifest and envelope profile
declarations is a capsule self-contradiction — a defect — not a
verifier limitation; `unsupported` and the `verdict_reason` channel are
reserved for verifier limitations. The profile channel carries status
`mismatched`, and the open-stage reason is `profile_mismatch`. (Stated
once, here; no surface invents a `verdict_reason` for mismatch.)

## `verdict_reason` vocabulary

Values reuse the existing normative open-stage category names — no new
vocabulary is invented:

| Value | Derivation | Status |
|---|---|---|
| `unsupported_version_newer` | version status `unknown_newer` (either document) | emitted |
| `unsupported_version_older` | version status `unknown_older` | emitted |
| `unsupported_profile` | declared profile the verifier does not implement ([profiles.md](profiles.md)) | emitted |
| `unsupported_capability` | a documented lane capability refusal of a capsule class the lane can otherwise parse but another conforming lane verifies (today: sdk-kotlin core on encrypted capsules) | emitted (by the affected lane) |

`verdict_reason` is null for `valid` and for `invalid` (an invalid
capsule's causes live in `errors`/`failing` areas, which have their own
normative vocabulary).

On `unsupported_capability`: the conformance registry KEEPS
`requires: ["encryption"]` vector gating — the two mechanisms coexist.
The registry gates what a lane *runs*; the runtime verdict is what its
*API reports* when a host hands it such a capsule anyway. One spelling,
everywhere: `unsupported_capability` (it is also the
capability-limitation value in the lineage
`predecessor_unverifiable.reason` vocabulary — same concept, same
string).

## Qualifier vocabulary (spec-defined set, v0.7.1)

Each qualifier restates exactly one already-mandated fact; a lane
implements each as a pure function of values it already computes. The
closed emitted set is **ten names**, in this order:

| Order | Qualifier | Derivation (existing facts) |
|---|---|---|
| 1 | `signer_set_unbound` | `signer_set.bound == false` (manifest.md: absence of `signer_commitment` MUST be reported machine-readably) |
| 2 | `actor_set_unbound` | `actor_set.bound == false` (chain.md step 6) |
| 3 | `empty_chain_not_walked` | chain evaluated with zero events: the null-anchor checks substituted for the walk (chain.md "Empty chains") |
| 4 | `encrypted_outer_only` | `level == "L2"` and signed `envelope.cipher != "none"`: the seal is verified, the content unread, the chain deferred. Per-result: the outer L2 result of an encrypted capsule always carries it; the L3 result of the decrypted inner never does |
| 5 | `version_not_accepted_by_policy` | `format_version.accepted_by_policy === false` (possible only when the host declared a policy; versioning.md "Host policy" mandates the non-silent report) |
| 6 | `trust_not_evaluated` | effective (well-formed) allowlist empty |
| 7 | `no_trusted_signer` | allowlist non-empty and `trusted_signer_count == 0` (distinct keys, envelope.md step 8) |
| 8 | `lineage_declared_unverified` | lineage declared (`manifest.predecessors` present), linkage not established in this run — subsumes the unverifiable case; per-entry reasons live in the `lineage` facts channel |
| 9 | `lineage_mismatch` | lineage checked against supplied predecessor bytes; sealed states differ |
| 10 | `lineage_predecessor_invalid` | lineage checked; a supplied predecessor fails its own verification |

Qualifiers 6 and 7 are mutually exclusive; all others may co-occur. The
three lineage qualifiers (8–10) are emitted by the lineage machinery
([manifest.md](manifest.md) `predecessors`): each is "valid verdict,
custody claim not clean" — exactly what a renderer must not hide, at
the same host-relative rank as `version_not_accepted_by_policy`.
Positive lineage facts (`declared`, `verified`, `verified_depth`,
per-entry statuses and reasons) are **facts-channel-only** (the
`lineage` result area): the qualifiers array carries bare strings, and
payload-carrying facts never ride it.

**Closed vs extensible — both, by the format's existing idiom:**

- The spec-defined set is **CLOSED per spec revision**: a conforming
  verifier at v0.7.1 emits exactly the subset of the ten names whose
  derivations hold, and nothing else.
- **Extension qualifiers MUST use the `x-<vendor>-<name>` convention**
  of manifest.md "Unknown members"; future spec revisions will never
  define an `x-`-prefixed qualifier.
- **Consumer rule (forward compatibility):** a consumer encountering
  ANY unknown qualifier string — bare (a future revision's name) or
  `x-` (a vendor's) — MUST surface it verbatim and MUST NOT treat it as
  satisfied or ignorable. The preserve-verbatim rule applied to
  reports.
- **Consumer rule (migration):** a result *lacking* the `qualifiers`
  member is vocabulary-unaware (the verifier predates v0.7.1), never
  unqualified. Absence of the member is "this verifier cannot say";
  absence of entries in a present member is "unqualified".
- **Conformance comparison rule:** registry vectors assert the
  spec-defined subset — a checker strips `x-` entries from the result
  before the exact-array comparison. The repo lanes never emit `x-`
  entries, so for them this is an exact match; a vendor implementation
  carrying a documented extension can still pass the registry.

**Reserved (defined, not emitted in v0.7.1):** `time_not_anchored` —
for the temporal-anchoring profile (self-attested `signed_at` is
constant within era 0.7; an always-present qualifier carries no
information until the stronger alternative exists).

**Deliberately not qualifiers:** pith markers (no mandated result fact
exists; the marker lives in-chain), advisory-member absences (the
format itself says these are never verification inputs), self-attested
time (reserved, above), skill trust (on a `valid` verdict it is exactly
determined by qualifiers 6/7 plus the per-skill index facts already
reported).

**Never from capsule bytes.** A capsule member (known or `x-`) naming a
verdict, reason, or qualifier is an inert unknown member — preserved,
hashed, semantically nothing. The `skill_trust` rule generalized: the
report is the verifier's claim about the capsule, and the capsule's
author is the party it must not be able to speak for.

## Canonical note strings

Fixed here; pinned by `notes_includes` vectors. These are the strings
the lanes already share byte-identically where emitted (the wording
drifts and omissions the audit found are repaired to these):

| Backs | Canonical note |
|---|---|
| `signer_set_unbound` | `manifest.signer_commitment absent: the signer set is not bound by the seal` |
| `actor_set_unbound` | `manifest.participants empty: chain actors are not bound to a declared participant set` |
| `empty_chain_not_walked` | `empty chain: no events to walk; envelope anchors checked to be null instead` |
| `encrypted_outer_only` | (chain check note) `deferred to L3 (encrypted outer)` |
| `version_not_accepted_by_policy` | lane-format note containing `not in the declared accepted set` |
| `trust_not_evaluated` | `no allowlist provided; trusted=false for all signers regardless of signature validity` (lowercase `trusted=false`, all lanes) |
| `no_trusted_signer` | `allowlist provided but matched no signer; trusted=false for all signers` (all five lanes emit it) |
| lineage checks | the lineage-pinned phrases `declared, not verified`, `not countersigned`, and `different sealed state of the declared predecessor` join this table with the `predecessors` machinery |

## Required renderer language (normative minimum substrings)

versioning.md-style: the substring MUST appear in the same rendered
report as the verdict; exact phrasing around it is the renderer's.
Substrings are contained in the canonical notes wherever one exists, so
a renderer that passes notes through is at or near compliance:

| Qualifier | Required substring |
|---|---|
| `signer_set_unbound` | `signer set is not bound by the seal` |
| `actor_set_unbound` | `actors are not bound to a declared participant set` |
| `empty_chain_not_walked` | `no events to walk` |
| `encrypted_outer_only` | `content is encrypted and was not read` (deliberately NOT the SDK-jargon note: the renderer floor is plain language) |
| `version_not_accepted_by_policy` | `not in the declared accepted set` |
| `trust_not_evaluated` | `no allowlist` |
| `no_trusted_signer` | `matched no signer` |
| `lineage_declared_unverified` | `declared, not verified` |
| `lineage_mismatch` | `different sealed state of the declared predecessor` |
| `lineage_predecessor_invalid` | `fails its own verification` |

**Renderer obligation** (the normative half of trust.md's "incomplete"
sentence): a conforming renderer MUST NOT present a `valid` verdict
without rendering every qualifier present, using at least the minimum
substrings above, in the same rendered report as the verdict. A
renderer MUST NOT emit the bare words "verified"/"valid"/"PASS" for a
`valid` verdict carrying qualifiers without the qualifier renderings
adjacent. On `invalid`/`unsupported` the existing error/diagnosis
obligations apply unchanged (versioning.md substrings, profiles.md
needles).

## CLI reference renderer

The `capsule verify` Result block is verdict-first, qualifiers
enumerated; an unqualified valid states its trust basis explicitly:

```
Result: VALID
  qualifiers:
    - signer set is not bound by the seal (manifest.signer_commitment absent)
    - trust not evaluated: no allowlist supplied
```

```
Result: VALID (no qualifiers; 2 distinct trusted signers)
Result: INVALID          — followed by the existing error sections
Result: UNSUPPORTED (unsupported_version_newer: declared version 9.9 is newer than this verifier supports)
```

**Exit codes (both CLIs):** `0` = VALID and every requested policy
satisfied; `1` = INVALID, UNSUPPORTED, or any requested-policy failure
(a `--predecessor` linkage failure is a requested-policy failure,
following the `--allowlist` pattern); `2` = usage/I-O/input-class
errors only. There is no exit 3. Unknown-version capsules exit `1`
(UNSUPPORTED), never `2` — an unknown era is a verdict about the
capsule-verifier pair, not an operator error. (This corrects the Node
CLI's historical exit-2 behavior; the change is observable by CI and
noted in the CHANGELOG.)

## Era treatment

Additive within era 0.7 — spec revision v0.7.1, no version bump.
Nothing in capsule bytes changes: no new member, no domain-string
change, no hash-input change; every acceptance/rejection outcome is
bit-identical and only the *names* on the report change. New readers
emit the three members for every known era, including frozen v0.6
capsules (the version-compat frozen fixture gains qualifier assertions
without regeneration — assertions bind the result, never the bytes).
Old result consumers see additive JSON members; the migration hazard is
covered by the consumer rules above.

Conformance vectors: `spec/vectors/result-vocabulary/`, plus additive
verdict/qualifier assertions across `signer-set/`, `chain-rules/`,
`chain-binding/`, `version-compat/`, and `profile-declaration/`.

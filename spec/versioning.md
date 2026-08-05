# Version Compatibility

A capsule declares its format era twice: `manifest.format.version` and
`envelope.version`. This document defines what a verifier MUST do with
that declaration — including for versions it does not know — and pins
the algorithm suite of a capsule that names no algorithms.

The governing rule is the archival profile's: **everything required to
verify is captured inside the capsule at seal time; discovery is an
optimization, never a precondition.** A capsule sealed today must be
verifiable by a reader built years later, when the sealing SDK no longer
exists. A version gate that rejects an older-but-known capsule before
reading it is the strictest possible violation of that rule.

## Version grammar and ordering

A format version is the string `<major>.<minor>`, where each component
is a decimal integer with no leading zeros (`0.6`, `0.10`, `1.0`).
Versions are totally ordered numerically by major, then minor —
`0.10` orders after `0.6`. A version string that does not match this
grammar is a **malformed document** (a shape violation), not an unknown
era.

`manifest.format.version` and `envelope.version` MUST be equal. A
capsule whose two declarations disagree is ambiguous about which era's
rules bind it; verifiers fail closed on the mismatch before applying
either rule set.

## Known versions: open forever, report honestly

A verifier maintains a table of **known versions** — every format
version it has ever supported — carrying, per version:

- that era's normative rule set (the spec documents at that version),
- that era's domain-separation strings (below),
- that era's algorithm suite (below).

Requirements:

1. A verifier MUST verify a capsule declaring any known version under
   **that version's** rules and constants. A v0.6 capsule opened by a
   v0.9-era verifier is checked as a v0.6 capsule.
2. A version, once known, is known forever. Removing a version from the
   table is a conformance violation — it is precisely the "sealed today,
   opened in three years" case this format exists to serve.
3. The verify result MUST report, machine-readably: the **observed**
   version (the capsule's declaration, reported even when unsupported),
   whether it is **supported**, and the era's algorithm **suite**
   identifier when it is. An older capsule is not malformed; it simply
   asserts what its era could assert — absence is not a violation,
   applied across time.

## Unknown versions: fail closed, diagnose distinctly

A capsule declaring a well-formed version outside the known table MUST
fail closed — the verifier cannot check what it cannot understand — but
the diagnosis MUST be distinguishable from tamper detection, machine-
readably and in prose. The closed status vocabulary:

- `known` — the version is in the table; verification proceeded under
  that era's rules.
- `unknown_newer` — the declared version orders after the newest known
  version. **This verifier is too old for the capsule.** The capsule is
  not thereby corrupt; a newer implementation may verify it. Diagnosis
  wording MUST include `newer than this verifier supports`.
- `unknown_older` — any other unknown version (orders before the newest
  known). Not evidence of tampering; an implementation retaining that
  era's rules may verify it. Diagnosis wording MUST include
  `older than any version this verifier supports`.
- `invalid` — the declared value violates the version grammar: a
  malformed document, reported like any other shape violation.
- `unread` — the version could not be read at all (missing manifest,
  unparseable JSON): the fail-closed default.

Having refused an unknown version, a verifier MUST NOT go on to apply
its own era's rules to the capsule: recomputing hashes with the wrong
era's domain strings manufactures mismatch errors indistinguishable
from tampering, which is exactly the confusion this section exists to
kill. The version diagnosis is the only error such a result carries.

There is no silent upgrade path in either direction.

## Version-keyed domain separation

Every domain-separation string in this format embeds the format
version:

| Purpose | String |
| --- | --- |
| capsule_id hash domain | `capsule-id-v<version>` + `0x00` |
| envelope signing input | `capsule-provenance-v<version>:<role>` + `0x00` |
| recipient key-wrap HKDF info | `capsule-key-wrap-v<version>` |

Consequence: a verifier that accepts a version must retain that
version's strings **forever**, and selection is keyed by the capsule's
**declared** version — never by the verifier's current sealing version.
A v0.9-era verifier recomputing the id of a v0.6 capsule uses
`capsule-id-v0.6\0`; verifying its signatures reconstructs
`capsule-provenance-v0.6:<role>\0`; unwrapping its recipient keys uses
`capsule-key-wrap-v0.6`. Writers seal at their current version only.

This keying is deliberate, not incidental: it is what makes the domain
strings an anti-cross-protocol measure without turning them into a
time bomb. Conformance vectors: `spec/vectors/version-compat/` and the
byte-level pins in `spec/vectors/signing-input.json`.

## Algorithm suites

A sealed v0.6 capsule names **no** algorithm identifier for signatures,
hashing, KDF, or AEAD anywhere in its bytes (the strings `Ed25519` and
`X25519` appear nowhere in a sealed plain capsule). A field added by a
later spec version cannot retroactively disambiguate capsules already
sealed; this normative statement can, permanently:

> **In a capsule whose declared format version is `0.6`, the absence of
> an algorithm identifier means the v0.6 suite, and nothing else:**
>
> - signatures: **Ed25519** (RFC 8032), 32-byte raw public keys,
>   64-byte signatures, with the key/signature validation rules of
>   [envelope.md](envelope.md);
> - hashing: **SHA-256** for every hash in the format (capsule_id,
>   event hashes, manifest_hash, content_index, encrypted_blob_hash);
> - canonicalization: **JCS** (RFC 8785) over the I-JSON acceptance
>   boundary of [canonicalization.md](canonicalization.md);
> - encryption: **X25519** key agreement, **HKDF-SHA-256** key wrap,
>   **ChaCha20-Poly1305** AEAD, per [envelope.md](envelope.md)
>   "Encryption". (`envelope.cipher` names the AEAD; the agreement and
>   KDF are fixed by this suite.)

The suite identifier `v0.6` is what verifiers report alongside the
observed version. Future versions that introduce algorithm agility MUST
declare identifiers explicitly and MUST NOT reinterpret the absence of
one in a v0.6 capsule.

**Version 0.7 introduces no algorithm changes and no agility.** In a
capsule whose declared format version is `0.7`, the absence of an
algorithm identifier likewise means the v0.6 suite, permanently — the
suite identifier names the algorithm set by the era that introduced it,
not the sealing era, so verifiers report suite `v0.6` for both 0.6 and
0.7 capsules.

## In-era tightening and cross-era force

A spec revision MAY add an OPTIONAL member — and a fail-closed rule for
a PRESENT-but-malformed value of it — **within** an existing era,
without a version bump, exactly when all of the following hold (the
bright-line rule; precedents: the `participants` shape tightening, the
v0.7.1 `predecessors` member of [lineage.md](lineage.md), and profile
declarations):

1. the member is optional: absence remains the era's legal
   weaker-claim shape, and no capsule sealed without the member changes
   verdict;
2. the member's key sits in the spec-reserved (non-`x-`) namespace, so
   no conforming writer of that era could have emitted it — any sealed
   capsule the new rule rejects was already non-conformant when
   written: **zero honestly sealed capsules change verdict**;
3. the new rule fires only on a PRESENT value that no reader could
   interpret — a capsule asserting something meaningless about itself —
   never on a weaker claim made honestly; and
4. the diagnosis is a shared cross-lane vocabulary, never a
   lane-specific parse failure.

How far such a member's interpretation reaches across eras follows a
second distinction:

- **Rule-selector members** (members that select which rules bind
  verification, e.g. a profile declaration) get **cross-era fail-closed
  force**, era-keyed: leaving one uninterpreted in ANY known era means
  possibly verifying under the wrong rules — the wrong-rules hazard
  this document exists to kill, which is era-independent.
- **Claim members** (claims interpreted within an era's rule set, e.g.
  `predecessors`) follow **per-era rule sets** and stay inert in eras
  whose rules do not define them: leaving one uninterpreted loses only
  a report. A `predecessors` member inside a v0.6 capsule is an unknown
  member even to a v0.7.1 reader — preserved, hashed, never
  shape-checked.

A claim member MAY still *refer across* eras: the lineage identity
recompute keys the domain string to the DECLARED predecessor era
(`capsule-id-v0.6\0` for a cited v0.6 capsule) — reusing the retained
version-keyed strings above, never extending them.

## Host policy: the SDK reports, the host decides

Whether an observed version is *acceptable* is deployment policy, not
integrity. A host MAY declare its accepted versions to the verifier
(e.g. `acceptVersions: ["0.6"]`); the verifier reports the verdict as a
fact next to the observed version and MUST NOT fail an otherwise-valid
known-version capsule because of it — exactly the signer-allowlist
shape: report `trusted`, never decide with it. A reported
not-accepted verdict MUST NOT be silent (it surfaces in notes).

An unknown version is never accepted-by-policy: policy cannot un-fail
a capsule the verifier could not check.

## What this section does *not* do

- It does not perform a version bump. Introducing a new version — as
  the 0.6 → 0.7 bump did — is a deliberate spec change that adds a row
  to the known-version table; this section is what makes such bumps
  safe for every capsule already sealed.
- It does not promise forward compatibility of *content*: a v0.6
  verifier refuses a v0.7 capsule (fail closed, `unknown_newer`); it
  does not guess.
- It does not make `x-` extension members version-gated; unknown-member
  preservation ([manifest.md](manifest.md)) is orthogonal and applies
  within every version.

Conformance vectors: `spec/vectors/version-compat/` — a known-version
capsule that must verify with the observed version reported, a FROZEN
genuine v0.6 capsule (sealed by the pre-bump v0.6 SDK, byte-pinned,
never regenerated) that a current verifier must open under the v0.6
rules reporting `0.6`, an unknown-newer and an unknown-older capsule
that must fail closed with the distinguishable reasons above, and a
grammar-violating version that must be reported as malformed, not
unsupported.

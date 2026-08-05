# Lineage

Spec revision v0.7.1, additive within era 0.7. This document defines the
`manifest.predecessors` member — how a successor capsule verifiably
declares the exact sealed artifact(s) it continues from — plus the
verification and reporting obligations it creates, and the writer
conventions for continuing a capsule ("rewrap").

## Why this member exists

The originator binding ([manifest.md](manifest.md)
`originator.public_key`) is correct and stays: a manifest naming an
originator who never signed is the capsule asserting something false
about itself. Its consequence: Alice hands Bob a sealed capsule; Bob
evolves the work; Bob cannot seal under Alice's identity, because
`signers[]` must contain a valid signature by Alice's key. The fix is
not to weaken the binding. It is a **successor capsule**: a new capsule,
sealed by a new originator, that verifiably declares the exact sealed
artifact(s) it continues from — attribution and history flow through
verifiable reference, the way citation works, rather than through key
sharing, which the format rightly makes impossible.

This is the one manifest member whose entire purpose is to make claims
about **bytes the signer did not produce**. Either the reader also holds
the predecessor — in which case the declaration is checkable to
cryptographic certainty from the two files and this spec — or they do
not, in which case it degrades to an honestly reported, machine-readable
claim, never a silent pretense of verified ancestry.

## Wire shape

One OPTIONAL manifest member, `predecessors` — spec-defined, no `x-`
prefix. An ARRAY of one or more entry objects; each entry declares one
**immediate** predecessor:

```json
"predecessors": [
  {
    "capsule_id":            "<64-hex lowercase>",
    "format_version":        "0.6",
    "originator_public_key": "<64-hex lowercase ed25519 raw>",
    "first_event_hash":      "<64-hex lowercase> | null",
    "entry_hash":            "<64-hex lowercase> | null",
    "manifest_hash":         "<64-hex lowercase>"
  }
]
```

Shape rules (normative):

- `predecessors` is the set of **immediate parents** (git's parent
  vocabulary) — never an inline ancestry chain. Everything past hop 1
  would be hearsay the successor copies but cannot have witnessed; deep
  ancestry is recovered and verified hop by hop (below). The array
  exists for merges: a successor combining two workstreams declares two
  entries, each an independent claim verified independently. Array order
  is preserved bytes (hash-covered) with **no normative meaning**; there
  is no "primary parent".
- **All six members are REQUIRED when an entry is present** (nullability
  only where marked). There is no "weaker declaration made honestly"
  *inside* an entry — the weaker honest claim is the member's absence,
  plus prose in `program.md`.
- `first_event_hash` and `entry_hash` are **both `null`** (a zero-event
  predecessor — a template hand-off is legitimate) **or both 64-hex**. A
  mixed declaration describes a predecessor that cannot exist.
- `entry_hash` is defined as the predecessor **seal's**
  `envelope.entry_hash`, never a mid-chain position: one sealed artifact
  has one entry hash, so no history-truncation claim is expressible.
- `manifest_hash` is the decisive pin: it transitively commits the
  predecessor's content index (every file, including the full chain
  file), participants, and `signer_commitment`, and disambiguates
  re-seals sharing a `capsule_id` and zero-event drafts sharing an id.
- Lowercase hex is REQUIRED, not normalized: the claim is bound by its
  stored bytes, and case-variant spellings of one claim are a cross-lane
  comparison differential.
- A present-but-EMPTY array is malformed — "no claim" has exactly one
  spelling: absence (the `signer_commitment` present-but-empty
  precedent).
- Two entries sharing a `manifest_hash` are malformed (the same artifact
  cited twice has no legitimate producer — the duplicate-signer
  precedent). Two entries sharing `capsule_id` with **different**
  `manifest_hash` values are LEGAL: a merge of two snapshots of one line
  is a coherent claim.
- **No advisory members inside entries** — no `label`, `note`, or
  `relation`. A successor's display text about *someone else's* work,
  sitting next to verified-adjacent hashes, is a reputation-laundering
  slot and a contradiction surface against the predecessor's own
  authoritative self-description. Authors characterize the relationship
  in `program.md`, the hand-off chain event, or `x-<vendor>-<name>`
  members (permitted inside entries and beside the member, preserved
  verbatim under the manifest-wide unknown-member rule). Any other
  unrecognized entry member is malformed.

### Scope: plain, default-profile predecessors

A v0.7.1 declaration commits to a **plain** capsule's members, and to a
predecessor verified under the era's **default profile** (`v0.6-suite`,
version `1.0`) — the entry grammar presumes the era-default identity
derivation and key encoding.

- **Encrypted predecessors.** The genuine encrypted use case — you
  decrypted the inner capsule and continued the work — needs no special
  case, because the inner IS a plain capsule: declare the inner's
  members and supply the decrypted inner bytes at verification. Privacy
  note (normative): doing so publishes existence-evidence — id,
  originator key, manifest hash — of confidential work; that is the
  successor author's disclosure choice, and hosts should know it is one.
  v0.7.1 defines no mapping from a declaration onto an encrypted
  capsule's outer/inner manifest pair, so a supplied predecessor that
  turns out to be an encrypted capsule is reported
  `predecessor_unverifiable` / `encrypted_predecessor`, never guessed
  at. Encrypted-predecessor lineage is deferred with the
  encrypted-metadata-minimization work.
- **Alternate-profile predecessors.** A supplied predecessor that
  declares a profile this verifier does not implement is reported
  `predecessor_unverifiable` / `unsupported_profile` — a verifier/scope
  limitation, never `mismatch` and never `predecessor_invalid`.
  Alternate-profile lineage joins encrypted-predecessor lineage in the
  deferred bucket; the citation intent stays expressible via `x-`
  members.
- `predecessors` interpretation is part of the profile authoring
  contract's **invariant core** (like unknown-member preservation): no
  profile may redefine or remove lineage semantics. It is a claim, not
  verification math.

### Encrypted successors

A successor that is itself encrypted MAY carry `predecessors` in the
inner manifest, the outer manifest, or both — the author chooses whether
the citation is public. Inner-only (private citation) and outer-only are
each a weaker claim made honestly; mandating outer=inner would force
disclosure of a confidential association. But when BOTH manifests carry
the member, they MUST be equal (JCS byte equality), fail-closed at L3:
a capsule asserting one origin to the world and another to its
recipients is lying about itself across layers. L2 evaluates the outer
declaration; L3 evaluates the inner (plus the equality when both are
present).

### Chain treatment

The successor starts a **fresh chain**: new genesis, 32-zero previous
hash, new `first_event_hash`, hence a new `capsule_id` derived from the
NEW originator key and NEW genesis — nothing squats on the predecessor's
identity, and the empty-chain identity rule composes unchanged (a
zero-event successor — a template rewrap — is legal). The predecessor's
final state travels as files (content forward, byte-identical where
unchanged); the custody point is bound by the declaration.

Copying predecessor events into the successor chain is not forbidden
(they are content the successor may reproduce), but it is **worthless as
history**: re-hashed under a new chain context, the copies are fresh
assertions on the successor's authority wearing old actors' names —
nothing binds a copy to the original, so a hostile successor could edit
while copying, and history that looks audit-grade but is not is worse
than absence. The predecessor's history stays where it is signed — in
the predecessor, reachable through the declaration.

### What hashes and signatures cover it

`predecessors` is ordinary manifest content: inside the JCS bytes of
`manifest_hash`, inside the canonical envelope payload, under every
signer's Ed25519 signature. Post-seal tampering with a declaration
breaks every signature; a false citation is a **signed** false citation,
permanently pinned to its author's key. No new domain string, no new
hash construction, no change to the `capsule_id` formula, no envelope or
chain change. Old readers preserve the member verbatim as an unknown
member (covered by `manifest_hash`), so it survives round-trips through
v0.7.0 tooling.

## Verifier obligations

Two groups. **Standalone** checks are properties of the successor
artifact alone and can fail it closed. **Linkage** checks depend on
evidence the host supplied at verify time and are REPORT-ONLY: the
successor's `ok` must remain a function of the capsule, never of the
invocation — otherwise a third party flips a valid capsule's verdict by
handing the verifier the wrong file. Absent `predecessors`: no claim,
nothing checked, `declared=false` reported. Presence binds, absence
reports.

All obligations produce identical outcomes in every lane, with the
malformation diagnoses as shared strings (`predecessors`,
`predecessors[i].<member>`), never a lane-specific parse crash: typed
lanes parse the member leniently (every member optional/raw at parse
time) and diagnose at check time, and hashing always runs over stored
bytes, never a typed re-serialization.

### Standalone (always run when the member is present) — FAIL CLOSED

1. **Shape and grammar.** An array of entry objects; each entry's six
   members present with the required types; `format_version` matching
   the `<major>.<minor>` grammar; the hash/key members exactly 64
   lowercase hex characters (`null` permitted only where marked);
   no empty array; no duplicate `manifest_hash`; no non-`x-`
   unrecognized entry members. A PRESENT declaration no reader can
   interpret is the capsule asserting something meaningless about its
   own origin — skipping it would make a lying capsule present
   identically to an honestly silent one.
2. **Null coherence.** `first_event_hash` and `entry_hash` both `null`
   or both 64-hex.
3. **Identity coherence — fail-closed when checkable; reported
   unchecked when not.** When the declared `format_version` is in this
   verifier's known-version table: recompute
   `SHA-256("capsule-id-v<declared>\x00" || originator_public_key_raw || first_event_hash_raw)`
   (32 zero bytes when `null`) under THAT era's identity rule and
   require equality with the declared `capsule_id`. A mismatch fails
   closed: the declaration contradicts its own members — no honest
   writer produces this, and no external evidence is involved, so this
   is self-assertion, not linkage. When the declared era is unknown
   (well-formed, outside the table): SKIP —
   [versioning.md](versioning.md) forbids applying one era's formula to
   another era's claim — and report `identity_checked=false` on the
   entry. The successor is not lying; this verifier is too old for that
   era. The unknown-era skip is the rule's release valve: it never
   punishes a capsule for the verifier's age.
4. **Inner/outer equality (encrypted successor, at L3).** Fail-closed
   only when BOTH manifests carry the member: JCS byte equality
   (above). Single-layer presence is legal.

There is deliberately **no self-reference rule.** Two zero-event
capsules from the same originator share a `capsule_id`
([manifest.md](manifest.md) "Capsule identity"), so a same-key zero-event
template rewrap honestly declares a predecessor id equal to its own —
id equality is not artifact identity. The true self-reference — a
declared `manifest_hash` equal to the capsule's own — is a hash fixpoint
and cannot be constructed. Conformance vector:
`same-id-zero-event-rewrap`.

### Linkage (predecessor bytes supplied) — REPORT-ONLY

API: a pool of candidate predecessor artifacts (the `predecessors`
verify option in every lane; CLI `--predecessor FILE`, repeatable).

5. **Matching.** Each supplied artifact is verified fully as a capsule
   under ITS declared version's rules (the existing versioning.md
   machinery, with the same host options as the main verification),
   then its `capsule_id` and `manifest_hash` are RECOMPUTED and matched
   against declared entries by the recomputed pair. Matching uses
   recomputed values only, never the artifact's own claims. An artifact
   matching an entry by `capsule_id` alone reports `mismatch` on that
   entry, and the diagnosis MUST say the artifact is a **"different
   sealed state of the declared predecessor"** identity — re-seals
   legitimately share an id, and "wrong file supplied" versus
   "successor lied" is genuinely indistinguishable here; the verifier
   reports the precise fact and never decides. A supplied artifact
   matching nothing is reported in `notes` as unmatched — a mistyped
   path is visible, never silently ignored.
6. **Entry statuses** (closed vocabulary, identical strings in every
   lane):
   - `unverified` — no bytes supplied for this entry;
   - `verified` — matched; the predecessor is valid under its own era;
     all six equalities hold (`format_version`, recomputed `capsule_id`,
     `originator_public_key`, `first_event_hash`, `envelope.entry_hash`
     plus the recomputed final event hash, recomputed `manifest_hash`);
   - `mismatch` — id-matched artifact whose recomputed values diverge —
     every differing member named; the wording never uses
     tamper/corruption vocabulary (the supplied file being a different
     genuine seal is the common honest cause);
   - `predecessor_invalid` — matched but the artifact fails its own
     verification; takes precedence over `mismatch`, with the equalities
     still reported informatively;
   - `predecessor_unverifiable` — bytes in hand but rules unavailable,
     with `reason`: `unsupported_version` (declared era unknown —
     applying this era's suite would manufacture tamper-shaped noise) |
     `encrypted_predecessor` (plain-predecessor scope) |
     `unsupported_profile` (default-profile scope) |
     `unsupported_capability` (a lane that cannot process this artifact
     class — e.g. a plain-only lane handed an encrypted pool artifact).
7. **Recursive walk and depth.** After a predecessor verifies, its own
   `predecessors` declaration (standalone-checked as part of that
   artifact's own verification) joins the frontier and further supplied
   artifacts are matched against it — each hop verified against real
   bytes, each hop's declaration the first-person signed claim of that
   hop's originator; no hop is hearsay. The walk interprets
   `predecessors` only in hops whose declared era defines it: a v0.6
   hop's `predecessors` member is an unknown member under v0.6 rules
   and terminates the interpretable walk (reported in notes). The walk
   MAY continue through a hop whose own verification failed when its
   manifest matches the declared `manifest_hash` — the commitment chain
   authenticates that hop's declaration bytes even when its event chain
   is broken; "is this the declared artifact" and "does it verify
   internally" are two facts, never collapsed. Per-entry results carry
   a `hop` number; `verified_depth` is the largest N such that every
   declared entry within N hops has status `verified`. Implementation
   guidance (not protocol rules): keep a seen-set of predecessor
   `manifest_hash` values (a true commitment cycle is a hash fixpoint
   and cannot verify; the seen-set bounds pathological pools); the walk
   never fetches — depth is bounded by the supplied pool — and a
   configurable hop cap (default 256) sits beside the reader's
   file-count/size caps as a resource limit.

**Why linkage is report-only.** Fail-closed governs what a capsule
asserts about itself, checkable from its own bytes (checks 1–4). Linkage
verdicts are about a *pair* of artifacts, the second chosen by the host
at verify time. A mismatch does not prove the successor lied — the same
originator legitimately re-seals a growing line under one `capsule_id`,
and a host supplying the later seal against a declaration of the earlier
one would, under a fail-closed rule, brand an honest successor a forgery
because of the host's own file handling. The fail-closed *experience*
belongs to the policy layer (the CLI exit policy below). A conformance
vector pins `ok: true` under a mismatched supply so no lane can
"helpfully" harden this into a parity break.

## Reporting

Machine-readable result area `lineage` (the wire member is
`predecessors` — the `signer_commitment`/`signer_set` naming precedent):
`{ declared, ok, verified_depth, entries }` in each lane's established
casing (sdk-js `result.lineage.verifiedDepth`; sdk-py
`result["lineage"]["verified_depth"]`; verifier-rust
`VerifyResult.lineage: LineageCheck` with `#[serde(default)]`;
sdk-swift/sdk-kotlin `CapsuleVerification.lineage: LineageReport`; CLI
`--json` `lineage`).

Each entry record echoes the declared six members (so hosts apply key
policy without re-parsing the manifest) plus `hop`, `identity_checked`,
`status`, member-precise `errors`, and `artifact` — a slim summary of
the supplied predecessor's own verification (`ok`, `observed_version`,
`level`, `error_count`), `null` when nothing was checked. Host trust
over predecessor originators derives from the predecessor's own verify
result (per-signer `valid`/`trusted`); the lineage area does not
duplicate host policy.

Semantics of the area's `ok`: true iff the standalone checks passed
(malformation ⇒ `lineage.ok=false` AND overall `ok=false`) AND no
checked entry is `mismatch` or `predecessor_invalid` (either of those ⇒
`lineage.ok=false` with overall `ok` unchanged). `unverified` and
`predecessor_unverifiable` entries never falsify it — unchecked is not
failed. After an open-stage or version-gate refusal, the lineage channel
holds its not-evaluated default (`declared=false` there means "not
evaluated", not "absent") and the refusal diagnosis is the only error
carried.

**Verdict qualifiers.** Three lineage names are EMITTED (bare strings on
the result's `qualifiers` array, non-empty only on a valid verdict):

- `lineage_declared_unverified` — lineage declared, linkage not
  established for at least one entry (subsumes the unverifiable case;
  per-entry reasons live in the facts channel);
- `lineage_mismatch` — checked against supplied bytes, sealed states
  differ;
- `lineage_predecessor_invalid` — checked, and the predecessor fails
  its own verification.

All three are "valid verdict, custody claim not clean" — exactly what a
renderer must not hide. `lineage_declared`, `lineage_verified` (with
`verified_depth`), and per-entry statuses/reasons are facts-channel-only
(`result.lineage`); payload-carrying facts never ride the bare-string
qualifiers array.

**Required human-output language** (pinned phrases):

- Any unchecked entry MUST render with the phrase **"declared, not
  verified"** and MUST NOT be omitted from output — a custody claim that
  quietly disappears when bytes are missing is how a citation gets read
  as an endorsement.
- Whenever lineage is declared, output MUST include a statement that the
  declaration is the successor's one-way claim, containing **"not
  countersigned"** — e.g. "lineage is the successor's declaration; the
  predecessor's originator has not countersigned it." No report may
  imply a consent bit exists before the v0.8+ countersignature artifact.
- `verified` MUST name the depth and present two distinct identities
  ("successor of capsule `<pred id>`; lineage verified to depth N") and
  MUST NOT present the successor as *being* the predecessor or as its
  "official"/"endorsed" continuation.
- An id-matching state mismatch MUST include **"different sealed state
  of the declared predecessor"**; mismatch wording MUST NOT use
  tamper/corruption vocabulary except to negate it.
- `predecessor_invalid` / `predecessor_unverifiable` MUST be worded as a
  property of the supplied artifact or of this verifier's support,
  distinct from any claim about the successor's honesty, and MUST name
  the era (or profile) the artifact was checked under or could not be.

**CLI exit policy** (the CLI is the policy layer; supplying a flag sets
a policy, following the documented `--allowlist` pattern): without
`--predecessor`, declared lineage never affects the exit code. With at
least one `--predecessor`, a linkage failure is a requested-policy
failure: exit 1 unless every supplied file matched a declared entry,
verified valid under its own era, and every equality held —
`capsule verify s --predecessor p && publish` must never publish on a
failed custody check the operator asked for. Declared entries left
unsupplied do not fail the exit (an operator may hold one branch of a
merge) but are reported; an unmatched supplied file fails it (a mistyped
path must not exit 0). Exit codes stay 0/1/2: 0 = valid AND every
requested policy satisfied; 1 = invalid, unsupported, or any
requested-policy failure; 2 = usage/I-O/input-class. The SDK-level
result remains report-only in every lane.

## Continuing a capsule (rewrap) — writer obligations

Rewrap is the hand-off made into one operation: sealed predecessor + new
originator keypair in, sealed lineage-declaring successor out. It adds
**no wire members, no verifier rules, no hashes, no domain strings** —
it is a writer composition over existing primitives. Builders MUST NOT
emit a declaration a reader would reject under checks 1–3; the failure
surfaces at the call site that introduced it (the
[chain.md](chain.md) writer-obligation pattern). The obligations below
are writer conventions (SHOULD — the backstop-event precedent), pinned
by the reference builders' outputs in `spec/vectors/lineage/`:

- **W1 — Derive, never copy claims.** All six entry members derive from
  opened predecessor bytes: `format.version`, `originator.public_key`,
  `first_event_hash`, `envelope.entry_hash` are reads; `capsule_id` and
  `manifest_hash` are **recomputed** — `capsule_id` under the
  predecessor's declared era's domain string, `manifest_hash` from the
  stored manifest document, never taken from the envelope's claim.
- **W2 — Never emit what readers fail closed.** Guaranteed by W1 for the
  derived path; enforced by explicit grammar + null-coherence +
  identity-coherence validation on the explicit-values path
  (`declarePredecessorEntry` — an archivist reconstructing lineage from
  records may hold hashes but not bytes; the builder validates form, it
  cannot and does not validate truth. Identity coherence is validated
  only for KNOWN declared eras, mirroring the reader's unknown-era
  skip, so an unknown-era explicit entry IS expressible there).
- **W3 — Refuse a failing predecessor by default; the override is
  explicit and loud.** Readers do NOT reject a successor whose
  predecessor is invalid (linkage is report-only), so an outright ban
  would make the tool more rigid than the format — but the default
  caller feeding rewrap a failing file is holding a truncated download
  or a tampered artifact. Refuse by default with the full verify result
  attached; proceed under `allowInvalidPredecessor` /
  `--allow-invalid-predecessor`, which still derives an entry that
  passes checks 1–3 — the citation is exact and honest ("I continued
  from this exact artifact, corrupt as it is"), and linkage
  verification reports it `predecessor_invalid` whichever path sealed
  it. The override changes no emitted byte; it is tool UX, not a
  security boundary.
- **W4 — Refuse an unknown-era predecessor, no override.** The identity
  recompute needs that era's domain string; an "entry" would be a
  fabricated commitment wearing derived members' clothes. The diagnosis
  uses the versioning.md vocabulary, machine-distinct from tamper and
  from W3's refusal.
- **W5 — Refuse an encrypted (outer) predecessor; point at the decrypt
  path** (decrypt the inner via the existing L3 machinery, then rewrap
  the inner — which IS a plain capsule; reason `encrypted_predecessor`).
  Refuse an alternate-profile predecessor the same way (reason
  `unsupported_profile`). The machine-readable refusal vocabulary is
  `verification_failed` | `unsupported_version` |
  `encrypted_predecessor` | `unsupported_profile`, identical in every
  builder lane.
- **W6 — Files carry, claims reset.** The predecessor's content files
  (`program.md`, `agents.md`, `payload/**`, `skills/<id>/**`, and any
  legacy content-indexed files) are the work being continued: they
  travel byte-identically, never rewritten (no re-encoding, no
  normalization; a filter predicate may exclude paths). The
  predecessor's manifest members are its originator's claims about THAT
  capsule and reset: `participants` (the successor's actor set is the
  caller's claim — default `[]`, the format's existing
  weaker-claim-made-honestly; auto-carrying would assert that every
  prior actor may act in the successor), `created_at`,
  `originator.label`, `signer_commitment`, the predecessor's own
  `predecessors` member (re-rewrap declares only its immediate parent —
  ancestry never flattens), and unknown/vendor members. The chain
  resets to a fresh genesis; rewrap offers NO option to copy events (a
  caller who wants them as *content* appends them deliberately, on
  their own authority).
- **W7 — Custody event, default on, opt-out.** `continueFrom`/rewrap
  SHOULD open the successor chain with the pinned template below;
  low-level `declarePredecessor`/`declarePredecessorEntry` never
  auto-emit an event. It makes custody visible to the cold LLM reader in
  the chain narrative; it is NOT a verifier rule (`action`/`target` are
  advisory members no verification rule reads, and a mandatory chain
  echo would be a second surface that must agree with the first).

  ```json
  { "actor": "system:host", "kind": "observation",
    "action": "custody_received",
    "target": "capsule:<predecessor capsule_id>",
    "payload": { "note": "custody received from capsule <predecessor capsule_id>; lineage is declared in manifest.predecessors" } }
  ```

  The default actor `system:host` is the one actor id always legal
  under the chain.md actor rule, and honest: the rewrap host observed
  the custody transfer (the backstop-event posture). A caller-supplied
  custody actor is validated by the existing append-time actor rule —
  the builder never guesses who the custodian is. The payload carries
  prose only, no hashes: the manifest declaration is the binding claim.
- **W8 — Seal at the current version, always.** A successor is a new
  artifact of the sealing SDK's era; cross-era citation is the
  declaration's job (`format_version` member + era-keyed recompute),
  not the seal's.
- **W9 — Never print or embed private key material.** Nothing key-shaped
  is written into the successor beyond the manifest/envelope members
  the format defines.

Reproducibility: with pinned `createdAt`/`signedAt` and the same
keypair, rewrap output is byte-identical *within one implementation*
(cross-implementation byte equality is NOT promised — the
[format.md](format.md) determinism boundary). Without pinned timestamps,
two rewraps of the same predecessor are two distinct genuine successors
— both honest; the format ranks no successor over another.

## Era and versioning treatment

Additive within era 0.7 — spec revision v0.7.1. No version bump, no
domain-string changes, no new hash constructions.

- **Old v0.7.0 readers on new capsules:** `predecessors` is an unknown
  member — preserved verbatim, covered by `manifest_hash`, semantically
  inert. The successor verifies exactly as before; the reader reports
  strictly fewer facts.
- **New readers on old capsules:** no member, `declared=false`,
  byte-identical verification of everything else.
- **The fail-closed question** (can a v0.7.1 reader reject a capsule an
  original v0.7.0 reader accepted?): yes, narrowly — for a PRESENT
  malformed `predecessors` member — under the in-era-tightening rule of
  [versioning.md](versioning.md). No released v0.7.0 builder emits the
  member, and the extension rule reserves the non-`x-` namespace to the
  spec, so any sealed capsule carrying a bare `predecessors` member was
  already non-conformant when written: **zero honestly sealed capsules
  change verdict.**
- **No retroactive interpretation of sealed eras.** A v0.6 capsule
  verifies under v0.6 rules, which contain no lineage semantics — a
  `predecessors` member inside a v0.6 capsule stays an unknown member
  even to a v0.7.1 reader (inert, never shape-checked). Within era 0.7
  the rule set now includes lineage, so a 0.7 capsule's member is
  interpreted regardless of whether it was sealed before or after this
  revision. `predecessors` is a *claim member*, not a rule selector —
  see versioning.md "In-era tightening and cross-era force".
- **Cross-era citation is a feature.** Standalone check 3 keys the id
  recompute to the *predecessor's* era (`capsule-id-v0.6\x00` for a
  v0.6 predecessor) — the version-keyed-domain discipline versioning.md
  already requires every verifier to retain forever, reused, never
  extended. Linkage verifies the predecessor under its own era's rules.
  An unknown declared era is skipped-and-reported standalone and
  `predecessor_unverifiable` with bytes — machine-distinguishable from
  lies and from tampering.

## What lineage does *not* prove

- **Endorsement.** The declaration is the successor's one-way claim;
  the predecessor's originator has not countersigned it. Anyone holding
  public sealed bytes can seal a successor citing them — the format
  converts the reputation squat into an exact, attributable,
  non-exclusive, signed claim, and the required "not countersigned"
  language keeps citation from laundering into endorsement. Post-seal
  approval is a v0.8+ artifact. *(Non-normative forward note: that
  countersignature artifact SHOULD adopt `(capsule_id, manifest_hash)`
  as its subject reference, making lineage and countersigning two uses
  of one predecessor-naming vocabulary.)*
- **Possession or continuation quality.** The six members are readable
  from a public manifest+envelope; no cryptographic statement can
  establish semantic derivation. The chain, the files, and the pinned
  predecessor give an auditor everything needed to judge continuation
  themselves.
- **Exclusivity or freshness.** Rival continuations of one predecessor
  are a named use case (forks); canonical-branch selection is
  host/ledger territory. `signed_at` stays self-attested; temporal
  anchoring remains parking-lot.
- **Ancestry completeness.** A successor can cite a grandparent and
  erase a parent, or cite nothing — content derivation is not a
  cryptographic property. What IS declared is exact and checkable, and
  `declared=false` is a reported fact, so absence never looks like
  presence.

Conformance vectors: `spec/vectors/lineage/` (generator
`sdk-js/tools/generate-lineage-fixtures.mjs`; the frozen v0.6
predecessor fixture is a byte-identical copy of the version-compat
original, asserted by the generator's `--check` and never resealed).

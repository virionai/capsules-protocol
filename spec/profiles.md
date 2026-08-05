# Profile Declaration

A capsule may declare the verification profile that governs it. This
document defines the two wire members that carry the declaration, the
identifier grammar, the default profile and the absence rule, what a
verifier MUST do with a declaration it does not implement, and the
contract an alternate profile's author must publish. It makes
enforceable the promise [envelope.md](envelope.md) and
[trust.md](trust.md) have carried since v0.7: alternate profiles "must
be explicitly declared, versioned, and fail-closed in readers that do
not understand them" — a reader that does not understand a declared
profile "must reject it rather than silently downgrade" to the
defaults.

Spec revision: **v0.7.1, additive within era 0.7** (see "Era treatment"
below and [versioning.md](versioning.md) "In-era tightening and
cross-era force", which carries the bright-line rule for in-era
fail-closed additions).

> **Note on the `spec/profiles/` directory.** That directory holds
> ecosystem *adapter* contracts (e.g. `profiles/clerk.md`) — mappings of
> external identity/policy providers onto the federation overlay, a
> different layer entirely. An adapter rides alongside a default-profile
> capsule; the profiles in THIS document replace verification rules and
> are declared in the capsule's own bytes.

## Wire shape

Two OPTIONAL members, mirroring the `format.version` / `envelope.version`
dyad and for the same reason: each document must be self-describing
about which rules bind it before either rule set is applied. (The
envelope, because a profile can change the signature scheme; the
manifest, because the outer manifest of an encrypted capsule must
reveal the profile before any verification work begins.)

**Manifest** — inside the `format` block:

```json
{
  "format": {
    "version": "0.7",
    "container": "zip",
    "canonicalization": "JCS-RFC8785",
    "hash_algorithm": "SHA-256",
    "profile": {
      "id": "x-acme-kms-es256",
      "version": "1.0",
      "params": { "issuer": "https://capsules.acme.example" }
    }
  }
}
```

**Envelope** — top level, next to `version`:

```json
{
  "version": "0.7",
  "profile": { "id": "x-acme-kms-es256", "version": "1.0" }
}
```

Rules:

- `manifest.format.profile` is an object with exactly: `id` (required
  string), `version` (required string), `params` (optional JSON object,
  contents entirely profile-defined and uninterpreted by
  non-implementing readers). The object is **CLOSED**: any other member
  — including the RESERVED name `critical` (below) — is a malformed
  manifest, fail-closed. This is the one place absolute closure is
  right: the object is the capsule's selection of its own verification
  rules, and an uninterpretable member in the rule *selector* is the
  capsule asserting something meaningless about what governs it.
  Vendor freight rides in `params` or in ordinary `x-` members; nothing
  is blocked.
- `envelope.profile` is an object with exactly `id` and `version` —
  **no `params`**. Params are single-sourced in the manifest so no
  second copy can diverge and the equality rule needs no deep-equality
  machinery in five lanes. (The manifest, params included, is bound by
  `manifest_hash` inside every signature, so params are sealed
  regardless.)
- `null` is not a declaration. A present-`null` or non-object `profile`
  in either document is malformed, fail-closed. The honest way to not
  declare is to omit — the format's absence idiom — and a second
  spelling of absence is a known typed-decoder divergence across lanes.

## Identifier grammar

```
profile-id   = lowletter *63( lowletter / DIGIT / "-" / "." )
lowletter    = %x61-7A
profile-ver  = <major> "." <minor>     ; the SAME grammar and parser as
                                       ; format versions (versioning.md)
```

- `profile-id`: 1–64 bytes, lowercase-only by grammar, no
  leading/trailing `-` or `.`, byte-for-byte comparison, no ordering
  semantics, no internal structure a reader may parse meaning out of —
  **except** the namespace fence: an id beginning `x-` is a vendor id
  and MUST be vendor-scoped `x-<vendor>-<name>`; ids not beginning `x-`
  are reserved to the spec, exactly like non-`x-` member keys. Future
  spec versions will never define an `x-` profile id.
- **Exact-match on the `(id, version)` pair.** No ranges, no
  compatibility semantics: a reader that knows `x-acme-kms-es256` `1.0`
  and sees `2.0` does not understand the capsule, period. A vendor who
  revises compatibly ships a reader that knows both rows. This mirrors
  the known-version table and keeps refusal decidable with a set lookup
  in every lane. Partial recognition ("I know the id but not the
  version, I'll guess") is a conformance violation — guessing at a rule
  set is the wrong-rules hazard this design exists to kill.

## The default profile and the absence rule

The spec-defined identifier **`v0.6-suite`, version `1.0`** names the
default profile: the [envelope.md](envelope.md)
verification/encryption procedure of the capsule's declared era with
the v0.6 algorithm suite of [versioning.md](versioning.md). The id
deliberately matches the suite fact (`v0.6`) verifiers already report;
like the suite identifier, it names the rule stack by the era that
introduced it, not the sealing era. It is frozen forever.

Normative absence rule, the mirror of the algorithm-suite pin:

> **In a capsule whose declared format version is `0.6` or `0.7`, the
> absence of a profile declaration means profile `v0.6-suite` version
> `1.0`, and nothing else — permanently.** A member added by a later
> spec version cannot retroactively reinterpret capsules already
> sealed; this statement can.

Explicit declaration of the default is **legal and exactly equivalent
to absence** — a redundant claim made honestly; rejecting a true,
coherent, redundant statement would be rigidity without a lie. Absence
is canonical: reference builders never emit the member, and writers
SHOULD omit it (the explicit form is the one declared shape that
pre-0.7.1 readers still verify with the *correct* rules, but a shipped
typed reader stricter than the spec about members inside `format`
could refuse to open it — omission costs nothing and risks nothing).

*Non-normative recommendation for future eras:* absence-means-default
in every era (the weakest honest form stays legal); the 0.8 era text
owns that decision.

## The equality rule (normalized dyad)

Normalize each document's declaration to `(id, version)`, **treating
absence as `("v0.6-suite", "1.0")`**. The two normalized pairs MUST be
equal. A capsule whose pairs differ is ambiguous about which rules bind
it and fails closed *before any profile's rules are applied*, with a
mismatch diagnosis distinct from tamper and distinct from unsupported.

Consequence of normalization: the default declared in exactly one
document is coherent (both readings mean the default) and verifies —
refusing it would punish a truthful statement. Every genuinely
ambiguous shape (an alternate id in one document and anything else in
the other) still fails.

## What covers it, and what a refusing reader may conclude

- `manifest.format.profile` (params included) → manifest bytes →
  `manifest_hash` → inside every signature's payload under whatever
  scheme the profile defines. `envelope.profile` → inside
  `JCS(envelope minus signers)` → directly signed. Stripping or
  injecting a declaration on a sealed capsule is tamper, caught by any
  reader capable of checking — and the declaration separates signature
  payloads by construction, whatever the algorithm. Conformance vector:
  `profile-declaration-tampered`.
- **But** at the moment a reader decides whether it can apply the
  declared rules, neither copy is authenticated — authenticating them
  requires running the very rules being selected. The declaration is an
  *observed fact*, exactly like the version declaration. A refusing
  reader may conclude ONLY: (a) the capsule's stored documents carry
  declaration D; (b) how D classifies against its table. It may NOT
  conclude anything about integrity (intact or tampered), signature
  validity, authorship, chain linkage, or the authenticity of D itself;
  skill trust stays at its fail-closed default; the profile diagnosis
  is the only error the result carries. Acting on an unauthenticated D
  is safe because every path that acts on it terminates in a refusal or
  in full verification under exactly one rule set — no path exists
  where a forged D produces acceptance under rules the sealer did not
  use.

## The `critical` member: rejected mechanism, reserved name

There is no per-member critical/must-understand list (X.509 critical
extensions, JOSE `crit`). For a mainstream reader the profile id
already does everything a crit list would — it fails closed on the
whole capsule. For the implementing reader, the exact-match versioned
profile *document* enumerates the load-bearing member set. JOSE needed
`crit` because a JOSE message has no profile identity; a capsule
declares its governing rule set wholesale. The member name `critical`
inside the profile object is RESERVED (the closed object already
fails-closed on it today; a future era may define it).

## Relationship to `cipher`

`envelope.cipher` remains an enumerated in-era value **within a
profile**. The default profile's enum is `none | ChaCha20-Poly1305`,
unchanged; adding a cipher to the default profile is still a
format-version schema change. An alternate profile defines its own enum
in its profile document. Composition rule: the profile gate runs
**before** the cipher check, so a mainstream reader refuses an
alternate-profile capsule at the gate with `unsupported_profile` and
never reports that profile's cipher as unknown-cipher tamper-noise.
`cipher` is the in-era knob; `profile` is the cross-suite knob; they
never overlap because each profile owns its enum.

## Verifier obligations

Numbered; fail-closed (FC) or report-only (RO). Identical outcomes are
required in every lane; `spec/vectors/profile-declaration/` is the
witness.

1. **Ordering: version gate first, profile gate second, nothing else
   until both pass.** (FC) The version is classified per
   [versioning.md](versioning.md) before the profile is looked at —
   profile semantics are era-scoped (the absence rule is keyed by era),
   so an unknown era means the declaration cannot be classified. After
   a version refusal, the version diagnosis is the only error carried;
   the profile channel reports the observed declaration with status
   `unevaluated`. Vector: `unknown-version-profile-unevaluated`.

2. **Shape and grammar.** (FC) A present `profile` in either document
   MUST be the exact closed object above (envelope copy: no `params`;
   `null`/non-object/extra member: malformed). Violations are
   malformed-document failures — open-stage reason
   `invalid_manifest_shape`, profile status `invalid` — NOT a support
   gap. Malformed is a defect of the capsule; unsupported is a
   limitation of the verifier; mismatched is a self-contradiction:
   three different facts, three different remediations, kept
   distinguishable.

3. **Normalized dyad equality, before table lookup.** (FC) Normalize
   both documents; unequal pairs refuse at open with reason
   `profile_mismatch`, status `mismatched`, both normalized pairs in
   the diagnosis — and the table is never consulted: the effective
   declaration does not exist until the documents agree, and reporting
   a mismatched capsule as "unsupported" would hand the auditor a false
   remediation ("find a better verifier" for a capsule that is
   defective). Stage note: the profile gate is entirely OPEN-stage,
   unlike the version-dyad equality which sits at verify stage — a
   reader that cannot establish its governing rules cannot meaningfully
   construct at all, and a profile may change envelope parsing itself.

4. **Table lookup; refusal on unsupported.** (FC) The agreed
   `(id, version)` is looked up in the reader's profile table. Found:
   proceed under that profile exclusively (obligation 6). Not found:
   refuse at open with reason `unsupported_profile`, status
   `unsupported` — **a limitation of the verifier, not a defect of the
   capsule.** Applying the wrong profile's rules manufactures
   mismatches indistinguishable from tampering — the same attack on
   diagnosis integrity versioning.md exists to kill.

5. **Refusal exclusivity.** (FC) Having refused at the profile gate
   (`unsupported`, `mismatched`, or shape-`invalid`), a verifier MUST
   NOT apply any profile's rules to the capsule: no hash recomputation,
   no signature check, no chain walk, no skill-trust derivation, no
   actor binding. The profile diagnosis is the only error the result
   carries; every other channel holds its fail-closed default. Direct
   port of versioning.md's "having refused an unknown version" clause.

6. **Exclusive application; no mixing; suite honesty.** (FC) A
   supported profile is applied entirely as its document defines;
   mixing default rules with profile rules, or falling back to defaults
   on failure, is a conformance violation (no dual-validity, no silent
   downgrade — trust.md's sentence, now enforceable). Additionally:
   whenever the effective profile is not the era default — including on
   every profile-gate refusal where a non-default declaration was
   observed — the reported `formatVersion.suite` fact MUST be `null`.
   The suite fact is a statement about the rules governing THIS
   capsule; reporting `v0.6` under (or about) alternate rules would be
   false. The profile channel is the suite authority for non-default
   capsules ([versioning.md](versioning.md) "Algorithm suites").

7. **Explicit default proceeds.** (RO) The default declared in both
   documents — or, via normalization, in one — verifies under the era's
   default rules exactly as if absent, with `declared: true` reported
   so an auditor sees the redundant form. No outcome may gate on the
   redundancy. Recorded as a non-rule so nobody later "tidies" it into
   a rejection.

8. **Observed-fact reporting on every result.** (RO) The profile
   channel (below) is present on every verify result — including
   open-refusals and unreadable containers — populated best-effort and
   labeled for what it is: an unauthenticated observation. The observed
   fact is what lets an auditor route the capsule to a capable verifier
   instead of declaring it corrupt.

9. **Default-row obligation; profiles supported forever.** A conforming
   verifier MUST support the default profile of every era it knows (era
   support IS default-suite support; versioning.md binds them), and a
   profile once supported is supported forever — the archival rule
   applied to profiles.

10. **Host policy: `acceptProfiles`, reported never decided.** (RO)
    Hosts MAY declare accepted profile ids; the verdict is reported
    beside the observed profile exactly like `acceptVersions`, and
    never decides the result. An unsupported profile is never
    accepted-by-policy: policy cannot un-fail a capsule the verifier
    could not check.

11. **Encrypted capsules: outer governs decryption; inner
    independent.** The outer layer's effective profile governs L2 and
    the decryption flow; the inner capsule declares its own profile,
    checked by obligations 1–10 independently at L3. **No inner/outer
    equality rule**: a KMS-wrapped outer over a plain default inner is
    a legitimate authorial shape (the vendor replaced only encryption);
    blocking it would restrict expression the format has no reason to
    restrict. The default profile leaves the L3 binding checks
    unchanged; an alternate outer profile's document owns them if it
    changes them. AAD and key-wrap strings for the default profile:
    unchanged.

12. **Writer obligations.** (FC at the builder) A writer MUST NOT seal
    a declaration whose `(id, version)` it does not implement — sealing
    rules nobody applied is a lie at birth, refused at the call site
    that introduced it. Reference builders implement only the default
    profile and emit absence; they expose no profile parameter
    (conformance fixtures are generated by direct document construction
    with TEST keys — the established generator pattern). Vendor
    builders extend their own tables.

## Reporting: the profile channel

Every verify result carries a `profile` channel, parallel to the
`formatVersion` / `format_version` channel, with per-lane casing of:
`observed`, `observed_version`, `declared`, `effective`,
`effective_version`, `supported`, `status`, `accepted_by_policy`.

- `observed` / `observed_version`: the declared id/version as read
  (reported even on refusal and even when invalid — the observed fact;
  on a dyad mismatch, the manifest values, with both normalized pairs
  quoted in the error text); `null` when absent/unreadable.
- `declared`: whether a declaration was present in either document.
- `effective` / `effective_version`: the profile actually applied —
  `"v0.6-suite"` / `"1.0"` on every successful default path (the
  absence rule made machine-visible: the result *says* what absence
  meant); `null` whenever no profile's rules were applied (any refusal,
  invalid, unread).
- `supported`: true iff status is `default` or `supported`.
- `status`, closed vocabulary:

| status | Meaning | Verdict effect |
|---|---|---|
| `default` | No declaration, or explicit era-default: default rules applied | none |
| `supported` | Declared alternate profile, implemented by this reader, applied exclusively (reachable only in vendor readers in-era) | none |
| `unsupported` | Declared alternate the reader does not implement. A limitation of the verifier, not a defect of the capsule | FC, sole diagnosis; verdict `unsupported`, verdict_reason `unsupported_profile` ([results.md](results.md)) |
| `mismatched` | Normalized manifest/envelope declarations disagree: capsule ambiguous about which rules bind | FC, sole diagnosis; verdict `invalid` ([results.md](results.md)) |
| `invalid` | Present member violates shape/grammar: malformed document | FC (shape machinery); verdict `invalid` |
| `unevaluated` | Read but not classified: the version gate refused first | none beyond the version diagnosis |
| `unread` | Could not be read at all (missing/unparseable manifest): the fail-closed default | accompanies open failure |

Required human-output language (cross-lane needles):

- `unsupported` MUST include: `profile '<id>' version '<v>' is not
  supported by this verifier` and `this is a limitation of the
  verifier, not corruption of the capsule — verify it with an
  implementation of that profile`.
- `mismatched` MUST include: `envelope.profile does not match
  manifest.format.profile` and both normalized pairs.
- `invalid`: shape-violation wording, field-path prefixed (the existing
  idiom); never the word "unsupported".
- CLI `verify` gains one line beside `Format version:`:
  `Profile: v0.6-suite (default, undeclared)` / `(declared)` / the
  refusal wording above. `inspect` surfaces the raw declaration when
  present.

## Negotiation, defined for a portable file

Negotiation is exactly three offline facts, nothing interactive:

1. Every verifier exposes its supported-profile table as an API
   constant (`SUPPORTED_PROFILES`, the default row always present).
2. Every verify result reports observed vs. supported (above).
3. Discovery — "which profiles does this issuer emit?" — is
   federation/host territory. Note: the issuer-metadata `profiles`
   array in [federation.md](federation.md) today names *attestation
   algorithm* profiles (`ed25519-jcs`, `clerk-jwt`) — a different
   namespace. Federation should introduce a separate `capsule_profiles`
   array using this document's grammar when it freezes; v0.7.1 changes
   nothing there.

## The Profile Authoring Contract

A conforming alternate profile is a versioned document that disposes of
every verification area — "base rule" or full replacement:

1. canonicalization + acceptance boundary;
2. hashing + capsule-identity derivation;
3. chain event hashing;
4. envelope signing — payload, domain separation, key encodings,
   key/signature validation;
5. signer-set commitment + originator binding semantics;
6. encryption — agreement, KDF, AEAD, AAD, recipient bundles, cipher
   enum;
7. identity/trust integration (advisory, host territory).

**Invariant core** — what a profile MUST NOT replace:

- container rules ([format.md](format.md)) — an unsupported-profile
  capsule is still an openable, displayable file; only verification
  refuses;
- the version gate and the profile gate themselves;
- unknown-member preservation (hash the document as stored, never a
  typed projection);
- chain shape rules: the `kind` enum and `untrusted_payload_fields`
  validation ([chain.md](chain.md): "in every profile");
- **`predecessors` interpretation** ([manifest.md](manifest.md)): the
  lineage declaration is a *claim*, not verification math — no profile
  may redefine or remove its semantics, exactly as no profile may drop
  unknown-member preservation;
- report-never-decide: per-signer `valid`, host-computed `trusted`;
- fail-closed refusal with the distinct-diagnosis vocabulary of this
  document and [results.md](results.md).

One hard cryptographic MUST: **a profile that defines its own signing
or key wrap MUST embed its profile id and profile version in every
domain-separation string** (e.g.
`capsule-provenance-v0.7:x-acme-kms-es256/1.0:<role>\x00`). Cost to the
vendor: zero. Benefit: a signature can never validate under two
profiles, for the same reason it can never validate under two eras —
dual-valid capsules become unconstructible for conforming profiles.

And the ecosystem guidance, stated once (SHOULD): **if your
verification math is the v0.6 suite, you are an overlay, not a
profile.** Identity stacks, policy tags, KMS-custody of an Ed25519 key,
attestations — all ride as `x-` members and federation overlays on a
default-profile capsule every mainstream reader verifies. Declare a
profile only when you replace verification primitives, and accept the
visible price: the declaration is the price tag. This keeps the
mainstream-verifiable share of the ecosystem as large as it can
honestly be.

## Era treatment

Additive within era 0.7, as spec revision v0.7.1. Profile declaration
is legal in 0.6/0.7 capsules from v0.7.1 on; an unknown declared
profile is refused `unsupported_profile` — a verifier limitation, never
a permanent capsule defect. The fail-closed gate is licensed by the
bright-line rule of [versioning.md](versioning.md) "In-era tightening
and cross-era force": no conforming writer could have emitted an unprefixed
`profile` member (the spec owns the non-`x-` namespace), enforcement
can only convert acceptances of self-contradictory documents into
refusals, and leaving the member unreserved would let a future era
create cross-reader semantic divergence over in-era capsules.

`format.profile` / `envelope.profile` are **rule selectors** — they
select which rules bind verification — so the gate has cross-era
fail-closed force, era-keyed: a declared-alternate 0.6 capsule refuses
`unsupported_profile` exactly like a 0.7 one (pinned by
`unsupported-profile-0.6-era`). See versioning.md for the
selector-vs-claim distinction this rests on.

Old/new reader matrix, in brief: already-sealed capsules carry no
declaration and verify byte-identically everywhere, forever. An
explicit-default capsule verifies under the correct rules even in
pre-0.7.1 readers (the member rides as an unknown member inside
`manifest_hash` and the signed payload). A conforming alternate capsule
already fails every pre-0.7.1 reader — with tamper-flavored noise;
v0.7.1 changes its diagnosis from slander to a clean, remediable
refusal, not its verdict. **Domain strings: none added, none changed**
for the default profile.

Conformance vectors: `spec/vectors/profile-declaration/`.

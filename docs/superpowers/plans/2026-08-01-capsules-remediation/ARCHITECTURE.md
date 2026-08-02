# Remediation Architecture — the model the plan is built on

This document is the spine. It supersedes the reasoning in the v1 plan, which
organised work by severity. Severity turned out to be the wrong axis.

---

## 1. The organising distinction: invariant vs policy

Capsules span deployment profiles from fully open to maximally strict. A
non-profit publishing business tools has no keys, no accounts and no vendor. A
marketplace has auth and encryption in its engine. Two engineers exchange
capsules peer-to-peer with pinned keys and no network at all. An enterprise
seals today and an underwriter opens it in three years. **The format must be
secure for the strictest and lax where open is the requirement**, without
forking.

That is achievable because two different things were being conflated:

**An integrity invariant is the capsule not lying about its own bytes.** The
content index covers every file. The local header matches the central
directory. A hash matches what it claims. A signature is a real signature.
These are enforced unconditionally, at every profile, fail-closed, forever. An
unsigned open-publication capsule still must not conceal a file — otherwise
"capsule" means nothing at any tier.

**A policy requirement is what a deployment demands.** Two signers. An
allowlisted issuer. Encryption present. An escrow recipient. Anchored time.
The SDK **reports these as facts and never decides**. `spec/trust.md` already
does exactly this for signer allowlists — L2 returns per-signer math, the host
supplies the allowlist, and "the SDK never claims trust on its own." That
pattern was already right. It simply needs generalising from signers to every
assurance dimension.

**Absence is not a violation.** A capsule with no declared participants, no
signer commitment, no events yet, or no anchor is making a weaker claim
honestly. It downgrades the reported assurance; it must never fail
verification. This is what lets templates, drafts and open publication exist on
the same format as a notarised loan file.

### Consequences for specific findings

| Finding | Was | Is | Why |
|---|---|---|---|
| F22 empty chain | "reject" | **invariant, restated** | An empty chain is legal. The real defect is that Rust skips both signed envelope anchor checks when the chain is empty. Correct rule: empty chain is fine, but then the anchors MUST be null. Claiming a `first_event_hash` with no events is the lie. |
| F09 actor ∉ participants | "always enforce; builders always reject" | **conditional invariant** | Enforce strictly *when `participants` is non-empty*. Safe because `participants` sits in the manifest, covered by `manifest_hash`, inside the signed payload — an attacker cannot empty it to escape the check without breaking the signature. Empty participants is a visibly weaker claim, not an error. Builders reject only when participants are declared. |
| `signer_commitment` | "required; reject manifests without it" | **presence binds, absence reports** | The v1 reasoning was "there is no deployed corpus to protect." That is wrong twice: templates are a permanent tier, and every capsule sealed today *is* the 2029 corpus. |
| A03 originator binding | policy | **invariant** | A manifest naming an originator who never signed is the capsule asserting something false about itself. |

---

## 2. The authority correction

Every v1 cluster file carried this constraint:

> `sdk-js` is the reference implementation. Where lanes disagree and no
> decision says otherwise, JS defines correct behaviour.

**That is now inverted.** The implementations are working examples of a full
spec, not the authority. The spec and its conformance vectors are
authoritative; `sdk-js` conforms like every other lane and gets no vote by
virtue of having been written first.

This changes real outcomes. For the I-JSON boundary the v1 plan proposed
tightening JS to match Python. Under the corrected framing the rule is decided
in the spec first, then all five lanes move to it — and the answer may be
neither lane's current behaviour.

---

## 3. Build order, corrected

The v1 plan treated signer-set binding as a design spike with zero tasks, to be
decided before envelope work. The adversarial critique showed that is a
build-order error, not a scheduling one:

> Until it lands, `requireOriginatorSigner`, `signers.required`,
> `trustedSignerCount`, and every `assurance.proven` string are a well-typed
> way to launder an unbound signer set into an affirmative claim.

An assurance report whose most load-bearing field counts rows in an unbound
array cannot be honest. Anyone can append a valid signature in a role of their
choosing — including `compliance`, `notary` or `legal`, since roles are
free-form (`spec/envelope.md:78-80`). On a loan file that is a forged approval
that verifies.

**Signer-set binding moves to step 2.** It is a derivation change with the
longest lead time, it gates the real fix for algorithm identifiers, and every
downstream assurance claim depends on it.

### Phase order

```
0.  Slot 0 — canonicalize manifest & envelope from the PARSED document,
    preserving unknown members.                          [A07, in flight]
1.  Container & crypto invariants.                       [C1 C2 C3 C4 C5, in flight]
2.  Signer-set binding.                                  [was S1 memo — now code]
3.  Verifier totality + assurance report.                [C6 + new]
4.  Cross-lane determinism.                              [C9 C10, A13 A14]
5.  Semantic binding + registry.                         [C12, C7, C8]
6.  Federation & self-containment.                       [C11 + new slots]
7.  QA, fixture regeneration, v0.7 bump.
```

Slot 0 is the precondition for everything additive: until the Rust lane hashes
a preserved `serde_json::Value` rather than a struct round-trip, filling *any*
new field manufactures a false tamper accusation in the standalone verifier.
Measured this session: `format.profile` and `pith_version` each PASS in JS and
FAIL in Rust with `envelope.manifest_hash mismatch`.

---

## 4. Two corrections to earlier reasoning in this project

Recorded because both were stated confidently and both were wrong.

**"Unknown-field preservation makes every future attribute additive, so no
slots need reserving."** Half right. It holds for fields a verifier *evaluates*
— those can arrive later and old readers simply report them unevaluated. It
fails for fields that *change the interpretation of an operation*, because
silent-ignore is a downgrade vector. Demonstrated: a capsule declaring
`kdf: HKDF-SHA512`, `kem: X448`, `profile: capsule-enc-v0.9-pq-hybrid`,
correctly re-signed, was decrypted anyway by **both** the JS and Rust lanes,
which ignored all three. So a profile/version field with fail-closed semantics
must ship *now* — added later, every deployed reader ignores it.

**"Round-tripping the wrap at seal time would catch the cross-curve recipient
bug."** Wrong. The sealer does not hold the recipient private key, and X25519
ECDH against an Ed25519 public key *succeeds*, returning a normal-looking
32-byte secret. Distinguishing the key types from bytes is also impossible:
400/400 X25519 public keys parse as valid Ed25519 points. Round-trip
verification is still worth doing — it catches AAD drift, nonce reuse and
wrap-step bugs, at ~40–60% of seal cost, under 12 ms on an 800 KB capsule — but
it cannot catch this. Only typed key material at the API boundary can, and even
that must be the *only* accepted path, or it is defeated by callers passing raw
bytes.

---

## 5. The reserved slots

An unused field is a cost. The bar: **its later addition would break the wire
format, or would arrive too late to ever be enforceable.**

| Slot | Field | Status |
|---|---|---|
| 0 | canonicalize from parsed document, preserve unknown members | **precondition — in flight as A07** |
| 1 | `manifest.format.profile` | ship in v0.7, fail-closed on unrecognised |
| 2 | per-signature algorithm identifier | **rework** — see below |
| 3 | `decryption.suite` + strict metadata parsing + recipient `label`/`role` | ship in v0.7 |
| 4 | post-seal sidecar slot, **with presence-binding** | ship with binding, or not at all |
| 5 | ~~generic extension field~~ | **dropped** — replaced by an `x-<vendor>-` namespace rule |
| 6 | signer-set commitment | derivation change, phase 2 |

**Slot 2 must move.** The design placed the algorithm identifier inside
`signers[]` — which is precisely the region the signing payload *excludes*
(`JCS(envelope minus signers)`). An unsigned algorithm identifier is worse than
none, because it looks authoritative and is attacker-editable. It belongs
wherever the signer-set commitment lands in phase 2.

---

## 6. What the SDK exposes vs what an organisation owns

The SDK's job is to make policy *activatable*, not to have policy.

**The SDK offers:** every assurance dimension as a reported fact; declared
seal-time requirements it enforces at seal; declared verify-time requirements
it evaluates and reports; fail-closed handling of profiles and algorithms it
does not recognise; and a report that cannot present an unevaluated or
self-asserted claim as a verified one.

**The organisation owns:** key custody and rotation; retention and escrow
policy; revocation; which profile a workflow demands; and the trust roots it
brings. The SDK never invents a trust anchor and never decides that a capsule
is acceptable.

Two API surfaces, not one — the critique showed a single `CapsuleProfile`
object is incoherent because half its members are silent no-ops at each end:

- **`SealPolicy`** — enforced at seal. Refuses to produce a capsule that
  violates it.
- **`VerifyPolicy`** — evaluated at verify. Never mutates, only reports whether
  the observed facts satisfy the declared requirements.

With an explicit, documented derivation from the first to the second, so an
organisation can state its requirement once.

---

## 7. The assurance report

`verifyCapsule` currently returns a verification outcome — `ok`, `errors`,
`signers`. An analyst or underwriter needs an assurance report: what is
cryptographically **proven**, what is merely **asserted**, and what is
**absent**.

Four of the review's findings are the same missing abstraction seen from
different angles: the CLI printing self-attested `signed_at` as a bare fact
above PASS (F48), the exit code ignoring the allowlist entirely (F04), skill
trust read from the author's own declaration (A01), and the examples
allowlisting the key read out of the capsule under test (F25). They were filed
as four bugs across three severity levels. They are one hole, and an
underwriter is the user each one harms.

Binding rules, from the critique:

1. No accessor returns a claim without its basis. `time.claimed` must be
   `{value, basis}`, never a bare backdatable string sitting beside a separate
   `basis` field.
2. The top-level verdict must not be the word `verified`. It denotes integrity
   only — says nothing about trust, identity, time or recoverability — and a
   harness branching on `verdict === "verified"` reproduces exactly the
   misreading the report exists to prevent. Use `intact`.
3. Unevaluated is a distinct state from absent and from failed. A reader that
   could not evaluate a claim must say so rather than omit it.

---

## 8. Open decisions for the maintainer

1. **Anchored time in v0.7, or documented limitation?** Required exactly when a
   party who was not present at sealing must rely on the record — an analyst,
   underwriter or regulator. Two-party exchange can ship honestly without it.
   Determines whether the envelope needs a field now.
2. **Composition semantics.** `capsule:<id>` exists in the `actor_id` namespace
   (`spec/manifest.md:65`) and nothing builds on it. Needed rule: a capsule's
   effective assurance for any claim depending on an embedded or referenced
   capsule cannot exceed that capsule's own. Without it, composition is a
   laundering path.
3. **Third-party review access.** An analyst who was not an original recipient
   cannot open an encrypted capsule. Sealing to a standing institutional key is
   the shape that survives, but it requires recipients to carry a role and be
   recorded — a format change.
4. **Recipient-set integrity.** An escrow bundle can be deleted and the capsule
   re-signed, and **`capsule_id` is unchanged**, because it derives only from
   the originator key and first event hash. An archive keyed on `capsule_id`
   cannot distinguish the original from an escrow-stripped substitute.
   Separately, `key_bundles: []` — openable by nobody, ever — verifies `ok:
   true` in both JS and Rust today.

# S1 — Design spike: binding the envelope signer set (decision memo)

> **Decision memo, not an implementation plan.** Settle this before any work that touches the envelope schema, or that work gets done twice.

**Part of:** [Capsules pre-release remediation](./README.md) · Tier 0

---

# S1 — Design spike: binding the envelope signer set

**Status:** decision memo. Not an implementation plan. Read the recommendation, make the two policy calls at the end, then S1 can be turned into TDD tasks.

**Bottom line:** Do **(a)** — bind the exact signer set from the manifest. Do **not** do (b). Use (c) only for in-session approvals, where the chain already covers them for free. Add a separate **countersignature-capsule profile** for post-seal approval, because *no* option on the table supports mutating a sealed capsule, and pretending otherwise is the only way this decision goes wrong.

The single most decision-relevant consequence: **(a) does not touch the envelope schema, so choosing it unblocks every other envelope-touching item immediately.** Choosing (b) welds signer-set binding, the federation `issuer` field, and the `anchors` array into one 4–6 week envelope break. That is the "done twice" risk, inverted.

---

## 1. What is actually broken

Reproduced against unmodified `sdk-js` (see validation for the script and raw output):

| Attack | Key needed | Result today |
|---|---|---|
| Strip the `approver` entry from `signers[]` | none | `ok:true`, `errors:[]`, `trustedSignerCount` 2 → 1 |
| Duplicate the `originator` entry ×4 | none | `ok:true`, `errors:[]`, `trustedSignerCount` 1 → 4 |
| Append a fresh signature in role `notary` | attacker's own | `ok:true`, `errors:[]`, `notary` reports `valid` |

The mechanism is four facts composing:

1. `envelopeCanonicalPayload` destructures `signers` away — `sdk-js/src/envelope.js:55-58`; mirrored at `sdk-py/src/capsule/envelope.py:48-51`, `verifier-rust/crates/capsule-verify/src/envelope.rs:33-46`, `sdk-swift/Sources/Capsule/Envelope.swift:50-60`, `sdk-kotlin/.../Envelope.kt:38-46`.
2. `envelopeSigningInput` prepends only `utf8("capsule-provenance-v0.6:" + role + "\0")` — `sdk-js/src/envelope.js:61-68`. Every signer signs the same bytes modulo role.
3. `signers[]` is therefore not an input to any signature.
4. `provenance/envelope.json` is in `STRUCTURAL_EXCLUDED` — `sdk-js/src/manifest.js:34-37` — so the file's bytes are not in `content_index` either.

Per-role domain separation stops replaying *one key's* signature into another role. It does nothing against a fresh signature in a chosen role. `signers[]` is unfalsifiable in both directions.

One thing that is *not* broken and is worth knowing before choosing: `sdk-js/src/federation/policy.js:31-36` already dedupes by key when evaluating quorum, so the duplicate attack does not inflate `evaluateSignerPolicy`. Strip still defeats it completely. The reference quorum engine is unsound today, and it is unsound for exactly one reason: the set it reads is attacker-controlled.

---

## 2. What each option actually changes

### (a) Manifest-bound signer set

**Wire:** one new manifest field. No envelope schema change.

```json
"signer_commitment": [
  { "role": "approver",   "public_key": "<64-hex>" },
  { "role": "originator", "public_key": "<64-hex>" }
]
```

Sorted ascending by `public_key`, then `role`, ASCII/byte order — which is exactly "sort members by their JCS byte string", since JCS emits `{"public_key":…,"role":…}` and the key prefix is identical across members. Specifying it both ways is free and removes the tuple-order footgun. `(role, public_key)` pairs MUST be unique. The same key appearing under two roles is two legitimate members.

**Why it binds:** `manifest_hash` = SHA-256(JCS(manifest)) (`sdk-js/src/manifest.js:96-98`) and `envelope.manifest_hash` is inside the canonical payload every signer signs. So the commitment is transitively signed by every signer, with no envelope change.

**No ordering cycle.** `capsule_id` = f(originator pubkey, first_event_hash) only — unchanged by this field, so `previewCapsuleId()` (`sdk-js/src/builder.js:121-128`) and the federation attestation flow that depends on it are unaffected. In `seal()`, the signer list is known at entry (`builder.js:145-149`) and the manifest is built at `builder.js:198-206` / `233-241` / `327-338`, all before `signEnvelope`. The commitment slots in cleanly. Plain and encrypted paths share one signer list, so one commitment value serves both the inner and outer manifest.

**Verifier change:** normalize `envelope.signers` to `(role, lowercase public_key)`, reject duplicates, sort, require byte-equality with the stored commitment. Insert before the existing signature loop at `sdk-js/src/verifier.js:220-228` and equivalents.

**Files, all five lanes:**

- `sdk-js/src/manifest.js:67-93` (buildManifest) + new `normalizeSignerCommitment`; `sdk-js/src/builder.js:198-206, 233-241, 327-338`; `sdk-js/src/verifier.js:220`; `sdk-js/src/index.d.ts`.
- `sdk-py/src/capsule/manifest.py:63-88`; `sdk-py/src/capsule/builder.py:212, 247, 310`; `sdk-py/src/capsule/verifier.py:233`.
- `verifier-rust/crates/capsule-verify/src/schemas.rs:107-118` (**mandatory** — see below); `verifier.rs:471-480`.
- `sdk-swift/Sources/Capsule/Manifest.swift:64-104`; `Builder.swift:127, 209, 305`; `Verifier.swift:259-276`.
- `sdk-kotlin/.../Manifest.kt:38-78`; `Builder.kt:115`; `Verifier.kt:56-58`.

**The cost the finding understates.** "No envelope schema change" does not mean "no code change in every lane." Rust holds the manifest as a typed struct with no `#[serde(flatten)]` (`schemas.rs:107-118`) and recomputes `manifest_hash` by re-serializing that struct (`manifest.rs:132-142`). I fed a capsule carrying `signer_commitment` to the unmodified prebuilt Rust CLI and got:

```
[✗] capsule_id / manifest_hash
      envelope.manifest_hash mismatch: stored 8de4b0e0b0ebfd6b… vs recomputed 2bb21332a4be3fe1de…
Result: FAIL
```

Rust drops the field and recomputes a different hash. It fails **closed**, which is the safe direction, but it means (a) is a lockstep five-lane change, and it exposes a general defect: *any* future manifest field breaks Rust. That is the L-1 schema/admissibility item, and S1 should land with or after it.

**What (a) forecloses:** post-seal countersigning. The set is fixed when the manifest is built.

---

### (b) Hash `signers[]` (minus `signature`) into the signed payload

**Wire:** envelope schema change → v0.7. New field (e.g. `signer_set_hash`) inside the canonical payload, or a rule that the payload includes the normalized signer members.

**What it buys over (a):** nothing.

That is the finding I did not expect and it is the crux of the memo. Work it through: if the signed payload commits to the whole signer set, then adding a signer changes the payload, which invalidates **every existing signature**. So (b) fixes the set at seal time too — *identically to (a)*. (b) is not "the clean fix that preserves countersigning." It is the same restriction, purchased with a wire break that blocks the federation `issuer` field, the `anchors` array, and every other envelope item behind a single 4–6 week coordinated change.

The only shape that *would* permit post-seal addition is the layered variant — call it **(b′)** — where signer *i* signs `domain_sep(role) ‖ JCS(envelope minus signers) ‖ JCS(signers[0..i-1])`. That is genuinely append-friendly: stripping a middle signer breaks every later signature. But truncating the **tail** is still undetectable, because the surviving prefix's signatures are untouched. To detect tail truncation you need an authenticated statement of what the set is supposed to be — which is (a). So (b′) = (a) + a chained signing input + a much harder spec. Reject.

**Verdict on (b): reject.** Same restriction as (a), 4–6× the cost, and it holds the rest of the envelope roadmap hostage.

---

### (c) Approvals as chain events

**Wire:** zero change. `chain/events.jsonl` is in `content_index`, and `content_index_hash` is in the signed payload, so an approval expressed as an event cannot be stripped without breaking verification.

**Two hard limits the finding does not state:**

1. **Chain events carry no signature.** The event schema (`spec/chain.md:8-22`, `sdk-js/src/chain.js:25-51`) has `actor`, `payload`, `prev_hash`, `hash` — and nothing else. An approval event proves the *sealer* wrote "Bob approved," not that Bob authorized anything. That is the same unfalsifiable claim the whole finding is about, relocated. **Unless** you define an approval predicate carried *inside* `payload` with its own detached, domain-separated signature over a canonical approval statement `{capsule_id, approver_public_key, role, prev_event_hash, timestamp}`. `payload` is free-form JSON, so this needs no schema change — but it needs a specified predicate, a domain separator, and vectors. Not free, just cheaper than (b).
2. **The chain is closed at seal.** `envelope.entry_hash` is the last event's hash and is inside the signed payload (`spec/envelope.md:45-47`). Appending an event after sealing changes `entry_hash` and breaks every signature. **(c) is a seal-time mechanism, not a post-seal one.**

**Verdict on (c): keep, scoped.** It is the right home for in-session, ordered, multi-actor approvals — because the chain already gives ordering and tamper-evidence that a flat `signers[]` never will. It is not a substitute for binding the signer set, and it is not a countersigning rail.

---

## 3. What the external baselines actually do

I re-checked all four live rather than from memory.

### TUF — the decisive precedent

TUF's `signatures` array is **also not covered by any signature**. The structure is `{ "signed": ROLE, "signatures": [{keyid, sig}] }` and only `signed` is authenticated. TUF is nevertheless immune to strip-and-add, because the *requirement* lives in an authenticated parent: root metadata's `roles[R].keyids` and `roles[R].threshold` are inside a signed `signed` block. Removing signatures does not silently reduce a count — it makes the threshold fail.

TUF also states, normatively: *"Even if a KEYID is listed more than once in the 'signatures' list a client MUST NOT count more than one verified SIGNATURE from that KEYID towards the THRESHOLD."* That is the duplicate-inflation bug (F-01), already solved by prior art, and it is solved as a **counting rule**, not as a signature over the array.

**Conclusion: TUF's answer to this exact problem is option (a).** The manifest is Capsule's authenticated parent — it is already bound by `manifest_hash` inside the signed payload. Do not try to make the signature array self-authenticating; authenticate the requirement separately.

### DSSE

Same architecture, same answer. `PAE(type, body) = "DSSEv1" ‖ SP ‖ LEN(type) ‖ SP ‖ type ‖ SP ‖ LEN(body) ‖ SP ‖ body`. Each signature covers exactly `PAYLOAD_TYPE` and `SERIALIZED_BODY`. The set of signatures is not covered. `KEYID` is explicitly unauthenticated and **"MUST NOT be used for security decisions."** Thresholds are `(t, n)` over *unique trusted public keys*, with `t` application-specific and key authorization deliberately out-of-envelope.

This directly validates Capsule's existing valid-vs-trusted split (`spec/trust.md:26-56`) — and it validates keeping quorum policy host-side (`spec/federation.md:340-363`). What it does **not** validate is evaluating that policy over an unauthenticated set. DSSE's threshold is over *unique trusted keys*, plural-deduped, drawn from an out-of-band authorization decision. Capsule today counts array entries.

### COSE countersignatures, RFC 9338

The `Countersign_structure` is `[Context, Body_protected, Sign_protected, External_aad, Payload, Other_fields]`, with context strings `"CounterSignature"`, `"CounterSignature0"`, `"CounterSignatureV2"`, `"CounterSignature0V2"`. The normative precondition: *"The target structure of the countersignature needs to have all of its cryptographic functions finalized before computing the signature."*

Read that against Capsule: a countersignature's target must be **finalized**. A sealed capsule is finalized. Therefore a countersignature is a signature over the *sealed* capsule — not a new element inside the thing it countersigns. Appending to `signers[]` after sealing is not countersigning in the RFC 9338 sense; it is mutation of a finalized structure. RFC 9338 says the post-seal approval belongs *outside*.

RFC 9338 also warns that countersigning encrypted data attests to the ciphertext, not the plaintext — directly relevant to countersigning an encrypted capsule's outer envelope. A countersignature on an encrypted capsule attests only to the sealed ciphertext, and the profile must say so.

### in-toto attestations

Four layers: **Predicate** ("arbitrary metadata about a subject artifact, with a type-specific schema"), **Statement** ("binds the attestation to a particular subject and unambiguously identifies the types of the predicate"), **Envelope** ("authentication and serialization"), **Bundle** ("a method of grouping multiple attestations together").

That is the shape of the answer for post-seal approval. A notary's approval is a *statement* with a *subject binding* to the finalized capsule, authenticated by the notary's own *envelope*, and delivered alongside — not merged into — the original. Capsule already has the pieces: `capsule_id` is knowable pre-seal (`previewCapsuleId`), `spec/federation.md:240-301` already defines an attestation with `capsule_id` + `signer_public_key` + `signer_role` binding claims, and `actor: "capsule:<id>"` already exists in the chain vocabulary.

**All four baselines converge:** authenticate the requirement, not the signature array; count unique keys; countersign a finalized target from outside.

---

## 4. The decisive question: does post-seal countersigning need to be possible?

The question is real but the option set answers it for us: **no option on the table supports it.** (a), (b), and (c) all fix the set at seal time — (b) does so for exactly the same structural reason as (a), and (c) is fenced by `entry_hash`. The only post-seal-capable variant, (b′), still cannot detect tail truncation without (a) underneath it.

So the question is not "which option preserves post-seal countersigning." It is: **is post-seal approval expressed by mutating the sealed capsule, or by a separate signed artifact that names it?**

Every baseline says the second. RFC 9338 requires a finalized target. in-toto separates subject binding from envelope authentication precisely so a third party can attest without touching the artifact. And there is a plain-language argument that matters more for the regulated-work use case: a notary who can alter the document they are notarizing is not a notary. The countersignature must be a distinct, independently sealed, independently timestamped artifact — otherwise "the approval was added later" and "the approval was there all along" are the same bytes, which is the exact ambiguity this whole finding is about.

**Answer: post-seal countersigning must be possible, and it must NOT be done by mutating `signers[]`.** It is a separate capsule whose subject is the finalized one. That costs the protocol nothing today — it is a profile, written later, on unchanged machinery.

What each option forecloses, stated plainly:

| | Seal-time multi-signer | Post-seal approval | Other envelope work |
|---|---|---|---|
| (a) | authenticated | via separate capsule | **unblocked** |
| (b) | authenticated | via separate capsule | blocked behind one v0.7 break |
| (b′) | tail-truncatable | in-envelope append | blocked; still needs (a) |
| (c) alone | ordered, but builder-attested | impossible (`entry_hash`) | unblocked |

---

## 5. Do (a) and (c) compose?

Yes, and the composition is better than either alone — but they are not two halves of the signer-set fix. They answer different questions, and the memo's recommendation is that all three of the following coexist:

- **(a) — who sealed this.** Authenticated membership of the seal-time signer set. The cryptographic fix. Mandatory.
- **(c) — what happened, in what order, before the seal.** In-session approvals, already tamper-evident via `content_index`. Free. Made *cryptographically* meaningful, when needed, by a signed approval predicate inside `payload` — no schema change.
- **Countersignature capsule — who approved after the fact.** A separate sealed capsule whose subject binding names the finalized target.

They compose without overlap: (a) authenticates the set that `evaluateSignerPolicy` already reads, (c) gives ordering the flat array cannot express, and the countersignature capsule gives the post-seal path RFC 9338 demands. (a) is load-bearing for all three: without it, (c)'s "the approver also signed the envelope" claim is strippable, and a countersignature capsule that names a subject with a mutable signer set attests to something that can be silently rewritten under it.

---

## 6. RECOMMENDATION

**Adopt (a): required `manifest.signer_commitment`, exact-membership, with a uniqueness rule. Reject (b) and (b′). Scope (c) to in-session approvals. Specify the countersignature capsule as a v0.7 profile, implement later.**

Reasoning, in priority order:

1. **It is the TUF-shaped fix.** The authenticated parent already exists and is already inside the signed payload. Nothing needs inventing.
2. **(b) buys nothing.** Same seal-time restriction, 4–6× cost, and it holds the envelope roadmap hostage. That is the whole reason this memo exists.
3. **It unblocks envelope work immediately.** The federation `issuer` field and `anchors` array can be designed without waiting on this.
4. **It makes existing code sound rather than adding new code.** `federation.evaluateSignerPolicy` already dedupes by key; it is unsound only because its input set is attacker-controlled. (a) fixes its input.
5. **It is prototyped and measured, not theorized.** Working in JS: honest capsules verify, strip/add/duplicate all fail closed, 57/57 unit tests still pass.

**Exact membership, not a hash.** Store the sorted `(role, public_key)` array, not a digest over it. It is inspectable without the envelope, the manifest is already the "typed metadata sidecar" (`spec/manifest.md:3-5`), the failure message can name the missing approver, and it leaks nothing — the signer public keys are already in the envelope in the clear, including on the outer envelope of encrypted capsules. Cost is ~100 bytes per signer.

**Estimated cost: ~1.5 weeks of focused work.** Spec ~1 day; five lanes ~0.5 day each; vector regeneration + new negative vectors ~1.5 days; CLI ~0.5 day; cross-lane parity chase ~1 day. The long pole is fixtures and five-lane parity, not crypto.

### The two decisions you must make alongside it

**Decision 1 — fail-closed policy: make the field REQUIRED. Reject a manifest without it.**

The finding's caveat ("old capsules have no such field, so readers need a deliberate policy — reject, or accept-and-report-unbound") assumes a deployed corpus. There isn't one. The project is pre-release; the only "old capsules" are checked-in fixtures, and I measured the exact blast radius: three positive vectors fail, all regenerable by existing generators. An `accept-and-report-unbound` mode is a compatibility shim by another name, and it would ship an `ok:true` path whose signer set is unfalsifiable — the precise thing being fixed. **Reject.** Error text should name the condition, e.g. `manifest.signer_commitment missing: signer set is unbound`.

**Decision 2 — version bump: bump `format.version` and `envelope.version` to `"0.7"`, once, when the semantic-binding cluster lands.**

This is the first change that alters the manifest wire shape. The version string is the only signal an out-of-tree reader has, and silently redefining `"0.6"` mid-flight is worse than a break. Spend one bump on all the settled semantic-binding fixes together. Note this is a *manifest* shape change under a *shared* version field — the envelope schema itself is untouched, so this bump does not commit you to any envelope field.

---

## 7. What must be specified for the recommendation

### New/changed spec text

1. **`spec/manifest.md`** — new `signer_commitment` field rules in the schema block and "Field rules": required, non-empty, array of `{role, public_key}`, `public_key` lowercase 64-hex, sort ascending by `public_key` then `role` (equivalently: by each member's JCS bytes), `(role, public_key)` pairs unique, same key under multiple roles permitted as distinct members. State the normative equality rule: the normalized `envelope.signers` set MUST byte-equal this array's JCS form.
2. **`spec/envelope.md`** — new "Signer set binding" section stating explicitly that the envelope does not bind its own `signers[]`, that the manifest does via `manifest_hash` inside the canonical payload, and that this is deliberate and matches TUF/DSSE. Add the set-equality and uniqueness steps to "Verification". Amend "What the envelope does *not* prove" — the current text is silent on this and reads as if it were complete.
3. **`spec/trust.md`** — rewrite the final threat-table row ("A workflow that requires approval quorum or role policy … Open"). Add an explicit adversary row for a signer-list mutator (strip / add / duplicate) with its new disposition.
4. **`spec/federation.md:340-363`** — insert a step 0 into "Signer-role and quorum policy": *the envelope signer set matches `manifest.signer_commitment`*. Without it the section advertises quorum over an unauthenticated set.
5. **New: countersignature-capsule profile** (own file, or a section in `envelope.md`). Subject binding = `{capsule_id, subject_envelope_digest}` where `subject_envelope_digest = SHA-256(JCS(subject envelope as stored, including signers))`. `capsule_id` alone is insufficient — it binds only the originator key and first event, not the sealed content or the signer set. Cite RFC 9338's finalized-target requirement, and its warning that countersigning an encrypted capsule attests to ciphertext only.
6. **`spec/chain.md`** — a short note that a chain-expressed approval is *sealer-attested* unless it carries a payload-level detached signature, and that `entry_hash` closes the chain at seal, so chain approvals are seal-time only.

### New vectors

New collection `spec/vectors/signer-set/vectors.json`, matching the outcome-vector schema in `spec/vectors/tamper-detection/vectors.json` (`meta`, `keys_file`, `vectors[].{name, capsule_file, expected:{ok, failing?, error_includes?}}`):

- `commitment-strip` — a signer removed from `signers[]`
- `commitment-add` — a fresh valid signature appended in a chosen role
- `commitment-duplicate` — an existing entry copied N times
- `commitment-role-swap` — same two keys, roles exchanged (catches role-insensitive normalization)
- `commitment-missing` — manifest with no `signer_commitment` (the fail-closed vector)
- `commitment-unsorted` — correct membership, wrong sort order; must fail, since the commitment is bound by stored bytes and the ordering is normative

New generator `sdk-js/tools/generate-signer-set-fixtures.mjs`, alongside the three existing generators listed in `spec/vectors/README.md`.

`tools/check-spec-vectors.mjs:130-135` needs a new `signer_set` entry in the closed `FAILING_AREA` map, and the registry consumers (`sdk-py/tests/test_spec_registry.py`, `verifier-rust/tests/spec_registry.rs`) must learn it.

**Regenerate:** `spec/vectors/plain-basic.json`, `spec/vectors/signing-input.json` (the manifest canonical-bytes pin changes), `spec/vectors/tamper-detection/output/*` + expectations, `spec/vectors/malformed-layout/output/*` (derived from the tamper clean fixture).

### Lanes that change

All five, plus `cli/`, `tools/`, `spec/`. Enumerated with line anchors in §2. **Rust is mandatory, not optional** — proven by execution.

---

## 8. What this does not solve

State it in the spec so the claim ceiling is honest:

- **It does not authenticate identity.** `signer_commitment` proves the set was fixed at seal, not who the keys belong to. That stays with the allowlist and federation (`spec/trust.md:37-55`).
- **It does not give quorum semantics.** It makes host-side quorum *sound* by authenticating its input. Required roles and thresholds remain host policy per `spec/federation.md:340-363`. Signer-set binding is a precondition for provable N-of-M, not the whole of it.
- **It does not fix the entry-count metric.** `trustedSignerCount` should count *distinct trusted public keys* (TUF's rule, DSSE's rule). Under (a) duplicates are rejected outright so the count can no longer be inflated — but the honest metric is still distinct keys, and that rename belongs to the Phase-0 cluster, sequenced *after* S1.
- **It does not bind time.** `signed_at` stays self-attested until temporal anchoring lands.


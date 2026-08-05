# Adversarial Completeness Review — Capsules Protocol Remediation Plan

Everything below was checked against the working tree at `/Users/complex/repo/open-source/capsules-protocol` (`main`, baseline confirmed: `npm test` → 57 JS tests, `node tools/check-spec-vectors.mjs` → `spec vectors: ok (280 vectors)`).

---

## P0 — Coverage holes: findings no cluster owns

### G1. F15 (HIGH) is unclaimed, and C2 declares it a hard blocker
`C2-rust-eocd` literally names its dependency as `sdk-py-container-strictness (F15)` and proves with measured output that Task 3 fails without it (`1 failed, 182 passed … DID NOT RAISE ValueError`). No cluster in the list claims F15. C1 Task 5 touches `sdk-py/src/capsule/zip_io.py` but only adds directory-shape and name-mismatch checks; it does not claim F15 and its own scope note calls sdk-py "not nominally this cluster's lane."

Evidence the defect is real and untouched — `sdk-py/src/capsule/zip_io.py:48-81` reads **only** `zipfile`-sanitized names:
```
60:            if zi.filename in seen:
63:        for zi in sorted(infos, key=lambda x: x.filename):
64:            if zi.is_dir():
66:            _assert_safe_path(zi.filename)
80:            out[zi.filename] = payload
```
There is no raw central-directory scan, no EOCD locator, no ZIP64 rejection, no `cd_offset+cd_size == eocd` check anywhere in the file. **C2 Task 3 cannot land as written.**

### G2. F03 and F04 (both HIGH) are misfiled into tier 3
The brief says tier 1+2 = F01–F23. F03 and F04 are `high` in the review (`cli/src/args.mjs:51`, `cli/src/commands/verify.mjs:112`) but the maintainer routed them into the review's "release hygiene" bucket (suggested-order item 13). Both are still live:

```
cli/src/args.mjs:50   // Unknown long flag — preserve, treat as boolean true unless inline
cli/src/args.mjs:51   out[key] = inlineVal === null ? true : inlineVal;
cli/src/commands/verify.mjs:112   return result.ok ? 0 : 1;      // trustedSignerCount never consulted
```
Consequence after the plan lands: **C8 makes the Rust CLI reject a malformed `--allowlist` with exit 2, while the JS CLI still silently accepts `--alowlist` and still exits 0 with zero trusted signers.** Two CLIs in one repo with opposite allowlist semantics, and the JS one is the documented CI-gating path.

### G3. The entire A01–A15 addendum is unscoped — six of them HIGH
`CODE-REVIEW-2026-07-31.md` line 1394+ contains a second, self-contained ledger (82 findings total, 27 high). The plan's cluster set touches only the F-series. Unowned HIGHs:

| ID | Defect | Verified in tree |
|---|---|---|
| A01 | `skill_trust` is author-declared but presented as verified | `plain-basic` manifest carries `"skill_trust": {}`; no verify-time derivation anywhere |
| A02 | Signer set/roles committed by no signature | S1 is a memo with **`tasks: 0`** — see G4 |
| A03 | `manifest.originator.public_key` not bound to an originator-role signature | `sdk-js/src/verifier.js:100-113` only recomputes `capsule_id`; never requires a matching originator signer |
| A07 | Rust hashes a typed projection → unsigned unknown manifest/envelope fields accepted | Proven independently by S1's own CLI run (`manifest_hash mismatch` when JS adds a field) |
| A08 | Swift/Kotlin accept an empty chain | **Confirmed below (G12)** |
| A09 | Swift/Kotlin `if let` anchor checks fail open when a required hash is absent | **Confirmed below (G12)** |

The review's own integration note says *"treat A01–A03 as immediate semantic/trust blockers."* None is scheduled.

### G4. C5 fixes one half of a two-part attack chain; the other half has zero tasks
F13's own text: *"combined with the known unbound-signer-set finding, an attacker with no private key can replace the genuine signer."* C5 closes the key-validation half. The signer-set half is `S1-signer-set-spike`, **`tasks: 0`, tier 0, a decision memo**. After the full plan, A02/F-01 remains open: an intermediary can still strip an approver or append a signer. S1's own measured output proves it:
```
2. approver stripped         ok:true  trustedSignerCount:1  errors:[]
4. attacker notary added     ok:true  trustedSignerCount:3  errors:[]
```
Nothing in tiers 1–2 changes that. If "release-blocking" means "an attacker with no key gets a trusted PASS," this belongs in tier 1 with tasks, not tier 0 with a memo.

---

## P1 — Ordering hazards that invalidate another cluster's work

### G5. **C4 makes Swift and Kotlin malformed-layout consumers, and then C1/C2/C8's new vectors hard-fail both lanes.** No cluster states this.
Three clusters assert the opposite as a load-bearing fact:
- C1: *"Swift and Kotlin do NOT read malformed-layout/vectors.json (verified…) so those lanes are unaffected by this cluster."*
- C2: *"Swift and Kotlin do not consume this registry today (verified by grep), so no action there."*
- C8: *"sdk-swift and sdk-kotlin do not consume this registry, so no action there."*

All three are true **only before C4 lands**. C4's own RED evidence shows it wires *both* collections into both lanes (Swift `SpecRegistryTests` failing on `invalid-manifest-json`, a malformed-layout vector; Kotlin `SpecRegistryTest` failing on `missing-envelope`, also malformed-layout). C4 is tier 1 and will land first. Then:

| New vector | Owner | Swift after C3+C4 | Kotlin after C4 |
|---|---|---|---|
| `dir-bit-smuggle` (open/DOS dir bit) | C1 | **FAIL** — `Zip.swift:74-121` never reads `p+38` external attrs for a dir bit | **FAIL** — `Zip.kt:64-100` never reads external attrs at all |
| `dir-marker-with-content` | C1 | **FAIL** — Swift has *no directory-marker handling whatsoever*; `"x/"` becomes a regular file entry | **FAIL** — same |
| `local-name-mismatch` | C1 | **FAIL** — reads name from CD (`p+46`), data from LFH (`localOff`), never compares | **FAIL** — same (`Zip.kt:93-98`) |
| `trailing-bytes` | C2 | pass (C3 adds EOF-anchored EOCD) | **FAIL** — `Zip.kt:66-74` scans backwards for `PK\x05\x06` with no comment-length or EOF check |
| `empty-chain` | C8 | **FAIL** — see G12 | **FAIL** — see G12 |

Net: after the plan, `conformance-swift` and `conformance-kotlin` (both hard-gated in `.github/workflows/conformance.yml:197-224`) go red on ~3 and ~5 vectors respectively. **This is the single largest ordering hazard in the plan.**

### G6. C1 and C2 rewrite the same Rust function, and C1's text already presupposes C2's rename
Current tree:
```
verifier-rust/crates/capsule-verify/src/zip_reader.rs:168  fn scan_duplicate_names(bytes: &[u8]) -> Result<(), ZipError> {
verifier-rust/crates/capsule-verify/src/zip_reader.rs:187  let Some(eocd) = eocd else { return Ok(()) };   <-- F02
verifier-rust/crates/capsule-verify/src/zip_reader.rs:303  if name.ends_with('/') && entry.size() == 0 {   <-- F67
```
C2 Task 2 renames `scan_duplicate_names` → `scan_central_directory`. C1's risk text says its Rust change *"is only safe because `scan_central_directory` now rejects `/`-with-content first"* — a function that **does not exist until C2 Task 2 lands**. Both clusters declare `depends_on: none` and neither mentions the other. C1's stated line anchors (168/187/303) are all inside C2's rewrite window.

### G7. C8 × C9 both rewrite `chain.rs::verify_chain`; C8 × C12 both rewrite `verifier.rs`
- `verifier-rust/.../chain.rs:71 pub fn verify_chain(events: &[ChainEvent])` — C8 Task 2 changes the signature to `&[ChainRecord]` and changes the hash preimage to raw on-disk bytes (F41). C9 adds the I-JSON guard inside the same function. C9's risk section names only the actor cluster and `chain_walk_into`; it never mentions C8. **If C8's F41 fix makes Rust hash the raw JSON line, C9's number-acceptance guard must run over the raw value tree, not the typed struct — otherwise a `1e19` in a chain payload is accepted by Rust and rejected by JS/Py, which is the exact class of bug C9 exists to close.**
- `verifier-rust/.../verifier.rs` — C8 Task 1 (`chain_walk_into`), C7 (three new tests), C12 (`is_encrypted` decision, semantic-binding block, `trusted_signer_count`). C12 and C8 both rewrite the chain-vs-encryption branch; neither mentions the other.

### G8. C9 makes Swift `JCS.canonical` throwing; C10 and every lane's number-vector test call it non-throwing
C9's Swift task is validated by "compiled the patched `JCS.swift` standalone against a `CapsuleError` stub" — i.e. `canonical` now throws. But:
- `sdk-swift/Tests/CapsuleTests/JCSNumbersVectorTests.swift:45` calls `JCS.canonical(.decimal(value))` with no `try`.
- C10 Task 5 adds `JCSKeyOrderTests` calling `JCS.bytes(.object(pairs))` with no `try`.
- Neither cluster mentions the other, and **C9's Swift task and C10's Swift task both edit `sdk-swift/Sources/Capsule/JCS.swift`**, C9 at the number guard, C10 at the key comparator.

Related: C3 flags `JCS.swift:41` as an uncatchable `precondition` reachable from `CapsuleVerifier.verify` (a HIGH, reproduced: *"exited with unexpected signal code 5"*). C9's change probably fixes it as a side effect — but nobody says so, no cluster owns it, and C3 explicitly warns *"a green `ZipRobustnessTests` must not be read as 'verify never traps'."* **The trap-in-verify contract for Swift is closed by accident or not at all.**

### G9. Five spec files are hashed into `skills/capsule/skill.json`; only C1 and C7 know it
`tools/regen-capsule-skill.mjs:33-40`:
```js
{ path: "spec/README.md" }, { path: "spec/format.md" },  { path: "spec/manifest.md" },
{ path: "spec/chain.md" },  { path: "spec/envelope.md" }, { path: "spec/trust.md" },
{ path: "spec/pith.md" },   { path: "skills/capsule/SKILL.md" },
```
`skill-capsule-regen` is target **1 of N** in `tools/run-conformance.mjs:46-52` (`node tools/regen-capsule-skill.mjs --check`). Clusters that edit one of those files without a stated regen step:

| Cluster | Spec file edited | Regen step stated? | Ran `run-conformance.mjs`? |
|---|---|---|---|
| C5 | `spec/envelope.md` ("appends after line 103") | **no** | **no** |
| C9 | `spec/chain.md` (Hashing, 43-56) + pith rule | **no** | **no** |
| C10 | `spec/format.md:81`, `spec/manifest.md:74` | **no** — Task 8 is described as *"spec wording only, no executable check"* | yes (10/10) — contradicts Task 8's description |
| C4 | `spec/manifest.md` (F21) | **no** | yes |
| C12 | `spec/manifest.md` (F37/F38) | **no** | yes |

C1 hit this and documented it (*"editing spec/format.md breaks skill-capsule-regen"*). C7 hit it too. The other five did not. **C10's Task 8 claim that a spec-wording change has "no executable check" is factually wrong.**

### G10. Every cluster's expected-output numbers are computed off the same baseline and are all wrong in combination
Verified baselines: sdk-js 57, sdk-py 182, spec vectors 280, Rust lib 102.

| Cluster | claims sdk-js | claims vectors |
|---|---|---|
| C1 | 63 | 283 |
| C5 | 60 | 294 |
| C6 | 66 | 285 |
| C7 | 65 | 282 |
| C9 | 69 | 295 |
| C10 | 58 | 288 |
| C11 | 79 | 291 |
| C12 | 61 | 286 |

Combined: ~122 JS tests and ~346 vectors. **Every plan step whose acceptance criterion is a literal `# tests 65` line will fail as written after the second cluster lands.** Same for `PASS · 10/10` / `11/11` (C6, C7 and C12 each add a conformance target; combined it is 13). Acceptance criteria need to be deltas or predicates (`# fail 0`), not absolute counts.

### G11. No cluster owns the fixture re-baseline order
- `spec/vectors/malformed-layout/output/*` derive from `tamper-detection/output/clean.capsule` (`vectors.json` `generator` field says so).
- C12's six semantic-binding fixtures also derive from `clean.capsule` / `clean-encrypted.capsule` / `tampered-chain.capsule`.
- `generate-tamper-fixtures.mjs` mints a **fresh keypair every run**.
- `spec/vectors/signing-input.json` derives from `plain-basic.json`.
- S1, if ever executed, invalidates `plain-basic.json`, `signing-input.json`, and every downstream fixture (measured in S1's own validation: three FAILs from `check-spec-vectors`).

C12 flags the coupling. C1, C2, C8 do not. There is no cluster that owns "regenerate the corpus, in this order, once."

---

## P2 — Unstated breakage I found by looking

### G12. Swift and Kotlin accept an empty chain and skip anchor checks — and C8's stated JS behaviour is wrong

**JS (measured, not read):** built `clean.capsule` with a zero-byte `chain/events.jsonl`:
```
ok: false
chain: {"ok":false,"errors":[]}
errors: []
```
`sdk-js/src/verifier.js:84` initialises `chain: { ok: false, errors: [] }`, so the `result.chain ??= {...}` at **line 199** never fires. C8's risk section states *"JS (sdk-js/src/verifier.js:198-202) … already emit `chain/events.jsonl missing or empty` for a zero-event chain."* **It does not.** C8's `empty-chain` vector passes in JS only because `ok` is false; add `error_includes` to it and JS fails. This is addendum finding A05, unclaimed and unfixed — and it directly contradicts C6's F56 goal ("no displayable message anywhere").

**Swift** (`Verifier.swift:241-249`) — with zero events, `verifyChain([])` returns `true` and both anchor checks are skipped by `if let … .first.flatMap`:
```swift
let chainOk = CapsuleReader.verifyChain(parsed.events)   // Reader.swift:322 — loop never runs → true
record("chain", chainOk, "\(parsed.events.count) events")
if let firstEvHash = parsed.events.first.flatMap({...}), let envFirst = ... { record(...) }
```
**Kotlin** (`Verifier.kt:70-82`) — identical shape, `if (firstEvHash != null && envFirst != null)`.

That is A08 + A09, both HIGH, both unclaimed. It is also why C8's `empty-chain` vector kills Swift and Kotlin once C4 wires them in (G5). Neither lane checks `seq` at all either (A10) — grep both `verifyChain` bodies: no `seq`.

### G13. Kotlin has *no* entry-count or total-size cap at all
```
sdk-js/src/zip.js:14      const MAX_ENTRIES = 10_000;
sdk-py/.../zip_io.py:9    MAX_ENTRIES = 10_000
sdk-swift/.../Zip.swift:9 private static let MAX_ENTRIES = 10_000
verifier-rust/.../zip_reader.rs:34  pub const MAX_ENTRIES: usize = 10_000;
sdk-kotlin/.../Zip.kt      (nothing)
```
`spec/format.md:96` says these limits are normative-with-defaults and *configurable on the reader*. C1 claims F58 but its measured work is a JS-only `packZip`/`unpackZip` options arg plus a JS unit test. Kotlin has no cap (unbounded `repeat(cdCount)` + `copyOfRange`), Swift/Py/Rust are hardcoded, and `malformed-layout/vectors.json` marks `entry_count_limit` and `total_size_limit` **RESERVED with no fixture**. F58 is claimed but only ~20% delivered, and there is no vector that would ever detect the gap.

### G14. Swift has no directory-marker concept at all
`Zip.swift:94-121` appends every central-directory record to `out`, including a name ending in `/`. `assertSafePath` (line 123+) does not reject a trailing slash. So an entry `skills/` lands in Swift's file map and in `buildContentIndex`, while JS (`zip.js:129,176`), Python (`zip_io.py:64`) and Rust (`zip_reader.rs:303`) all skip it. That is a *fifth* variant of the F01/F67 family, in the lane C4 is about to make registry-conformant. No finding, no cluster.

### G15. `sdk-py`'s registry consumer silently no-ops on a missing path — F40's Python analogue
```python
sdk-py/tests/test_spec_registry.py:65-68
def _collection_params(path: pathlib.Path):
    if not path.exists():
        return []
    doc = _load(path)
    return [pytest.param(...) for v in doc["vectors"]]
```
An empty list into `parametrize` is a **skip**, not a failure (pytest default `empty_parameter_set_mark=skip`). A typo'd path, or an empty `vectors[]`, silently deletes the whole Python conformance lane. Rust guards this (`spec_registry.rs:124,156 assert!(!vectors.is_empty())`); `tools/check-spec-vectors.mjs`'s `checkCollection` does **not** (only `checkNumberVectors` has the guard, line 239). The plan adds four new Python registry consumers (C5, C6, C7, C12) that will copy this idiom. F40 is parked in tier 3 while the plan quadruples its blast radius.

### G16. `spec/vectors/README.md` becomes stale and stays wrong
It says *"Four shapes exist"* and *"the Python … and Rust … lanes consume both collections directly."* The plan adds ~7 new collections/shapes (`ed25519-key-validation.json`, `jcs-key-order.json`, `malformed-shape/`, `chain-rules/`, `semantic-binding/`, `identity-attestation/`, `unicode-boundary` + ijson-acceptance) and two new consumer lanes (Swift, Kotlin, via C4). No cluster lists `spec/vectors/README.md` as an edited file. It also says implementations **SHOULD** reproduce the outcomes — the plan never upgrades that to MUST.

### G17. The examples still teach the anti-pattern the trust work is meant to kill
`examples/lib/example-kit.mjs:94`:
```js
allowlist: [reader.manifest().originator.public_key],
```
A self-referential trust anchor (F25, tier 3). After C5 (key validation), C8 (allowlist validation), C12 (distinct-key counting) and S1's memo, the repo's own copy-paste template still allowlists the key it reads out of the capsule under test. Combined with A03 (originator identity unbound — unclaimed), this example is a working demonstration of the substitution attack described in A03, shipped as documentation.

---

## P3 — Verification gaps

### G18. `tools/run-conformance.mjs` is JavaScript-only; three clusters cite it as their cross-lane gate
`run-conformance.mjs:481` says it itself: *"This report covers the JavaScript targets only."* Its targets are `skill-capsule-regen, sdk-js, cli, malformed-fixtures-regen, spec-vectors, example-*`. C1, C4, C6, C10 and C12 all cite `PASS · 10/10` / `11/11` as evidence of cross-lane health. It proves nothing about Python, Rust, Swift or Kotlin. The only real five-lane gate is the five separate CI jobs (`conformance.yml:103-224`) — which nobody can run locally.

### G19. Kotlin is executed by zero clusters that change Kotlin behaviour
| Cluster | Kotlin work | Executed? |
|---|---|---|
| C4 | `Reader.kt`, `Verifier.kt`, `Manifest.kt`, new `StrictReaderTest`, `SpecRegistryTest` | yes (`JAVA_HOME=…openjdk@17`) |
| C5 | new BouncyCastle pin test | **no — "no JRE on this machine"** |
| C7 | `Chain.kt`, `Verifier.kt`, `Builder.kt`, `RoundTripTest.kt` | **no — "no JVM"** |
| C9 | `Canonical.kt` I-JSON guard (the lane C9 itself calls *"the one lane where the failure mode is silent corruption"*) | **no** |
| C10 | audit only, no change | **no** |
| C12 | `Verifier.kt` semantic binding + `verifyReasonNeedles` | **no — "treat Task 14 as the one task that needs a real gradle run"** |

Five clusters write Kotlin, one ran it. C9 additionally flags a possible pre-existing compile break (`CapsuleException` referenced at `Reader.kt:27,29,31,33,46` with no visible declaration) that would mean `:core` is already red — unresolved.

Swift is similar: C7, C9, C10 never ran `swift test` (C7: *"the Swift TEST files … were NOT compiled or run"*; C10: *"verified by inspection against the real API… not executed"*).

### G20. Two clusters claim a cross-lane fix but pin it in only two lanes
- **C6** creates `spec/vectors/malformed-shape/` and states outright that Rust, Swift and Kotlin *"neither see nor break on the new one"*, deferring the wiring to *"a later cluster"* that does not exist in this plan. So after C6, "the verifier is a total function on malformed-but-openable capsules" is enforced in 2 of 5 lanes with a vector 3 lanes ignore.
- **C7** ships `chain-rules/` consumed by JS/Py/Rust; Swift and Kotlin pin the strings in local unit tests instead. C7 admits the gap. That means the actor rule — *the review's "most visible interop break in the repo"* — has no cross-lane vector for 2 of 5 lanes.

---

## P4 — The meta-pattern: does the plan close it?

**No. It fixes 46 instances and leaves the generator intact — and creates at least three new instances.**

The review's thesis is: *normative rules exist with no enforcement and no negative vector.* The mechanism that allows that is visible in the tree:

1. **Registry consumption is opt-in per lane, by hardcoded filename.**
   ```
   sdk-py/tests/test_spec_registry.py:29-30   TAMPER = …/tamper-detection/vectors.json
                                              MALFORMED = …/malformed-layout/vectors.json
   verifier-rust/tests/spec_registry.rs:119,151,178   three literal joins
   sdk-swift/…/ParityTests.swift:44           tamper-detection/output only
   sdk-kotlin/…/ParityTest.kt:117             tamper-detection/output only
   ```
   Nothing asserts that lane × registry coverage is complete. A new registry is invisible to four lanes by default — and *silently* invisible in Python (G15). The plan adds 7 registries under this regime.

2. **The spec does not use RFC 2119, so "enumerate the MUSTs" is not mechanically possible.** `grep -rc MUST spec/` → `federation.md:11, manifest.md:1, envelope.md:1, everything else 0` — **16 total**. Every rule that was actually violated is prose: `chain.md:32` *"Readers reject unknown kinds"*, `chain.md:106` *"Confirm `actor` appears in manifest participants"*, `format.md:96` *"limits are configurable on the reader"*. None is a MUST. No cluster proposes normalizing the language or assigning rule IDs.

3. **There is no traceability artifact.** No vector carries a spec anchor; no doc maps rule → vector → lanes. `spec/vectors/README.md` says implementations *SHOULD* reproduce outcomes and names only two consumer lanes.

4. **F40 — the check that would keep a registry from being silently emptied — is parked in tier 3** while the plan multiplies registries by 4×.

5. **C4 introduces a sanctioned escape hatch**: `openRejectedVerifyVectors`, `OPEN_REJECTED_VERIFY_VECTORS`, `ENCRYPTED_VECTORS`. Honest and well-documented, but it is the same shape as the original problem — a named exception to a normative rule, living in a test file, with nothing tracking when it should shrink.

**What would actually close it (no cluster does any of this):**

- `spec/vectors/registry.json`: a machine-readable manifest listing every collection, its `reason`/`failing` vocabulary, and the set of lanes required to consume it. Add a conformance target that (a) fails if a `vectors.json` exists on disk but is absent from the manifest, and (b) fails if a lane's consumer set ≠ its required set. That is the one change that would have caught F12/F16/F20/F21 (Swift/Kotlin not consuming malformed-layout) *and* would prevent C6's `malformed-shape` from shipping half-wired.
- A non-empty assertion in **every** consumer (`check-spec-vectors.mjs` `checkCollection`, `test_spec_registry.py::_collection_params` — replace `if not path.exists(): return []` with a hard failure), i.e. land F40 in tier 1, not tier 3.
- A `rule_id` field on every vector pointing at a spec anchor, plus a lint that every normative statement in `spec/*.md` carries an ID and every ID is referenced by ≥1 vector. This requires first normalizing the spec's prose to RFC 2119 — a task no cluster owns and which S1's version-bump question (`0.6` → `0.7`) is the natural moment for.
- An explicit expiry/owner on each C4-style exception set.

---

## Summary table

| # | Gap | Type | Severity |
|---|---|---|---|
| G1 | F15 unclaimed; C2 declares it a blocker | coverage | **blocker** |
| G5 | C4 wiring makes C1/C2/C8 vectors fail Swift+Kotlin CI | ordering | **blocker** |
| G6 | C1 and C2 rewrite the same Rust fn; C1 presupposes C2's rename | ordering | **blocker** |
| G2 | F03/F04 (HIGH) misfiled tier 3; JS vs Rust CLI diverge on allowlist | coverage | high |
| G3 | A01–A15 unscoped (6 HIGH, incl. A03 originator binding, A07 Rust field drop) | coverage | high |
| G4 | F13's other half (signer-set binding) has zero tasks | coverage | high |
| G7 | C8×C9 on `chain.rs`; C8×C12 on `verifier.rs` | ordering | high |
| G8 | C9 makes Swift `JCS.canonical` throwing; C10 + 5 number-vector tests call it non-throwing | ordering | high |
| G9 | Spec edits invalidate `skill.json`; C5/C9/C10/C4/C12 omit the regen step | breakage | high |
| G12 | Swift/Kotlin accept empty chain; JS empty-chain has **zero** diagnostics (C8's claim is wrong) | breakage | high |
| G10 | All expected test counts share one baseline; all wrong in combination | verification | high |
| G19 | 5 clusters write Kotlin, 1 ran it; 3 write Swift without running it | verification | high |
| G20 | C6's `malformed-shape` and C7's `chain-rules` pinned in 2–3 of 5 lanes | verification | high |
| G11 | No owner for fixture re-baseline order | ordering | medium |
| G13 | Kotlin has no entry/size caps; F58 delivered in JS only; caps have no vector | breakage | medium |
| G14 | Swift has no directory-marker concept — fifth F01-family variant | breakage | medium |
| G15 | `_collection_params` silently skips on missing path (F40's Python form) | breakage | medium |
| G18 | `run-conformance.mjs` is JS-only but cited as the cross-lane gate | verification | medium |
| G16 | `spec/vectors/README.md` goes stale | breakage | low |
| G17 | Examples still teach the self-referential allowlist | breakage | low |
| P4 | Meta-pattern not closed; plan adds 3 new instances | structural | **strategic** |
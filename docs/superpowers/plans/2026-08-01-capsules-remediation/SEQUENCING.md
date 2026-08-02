# Capsules Protocol — Execution Sequence and Collision Map

**Basis:** all collisions below were checked against the working tree at `/Users/complex/repo/open-source/capsules-protocol` (branch `main`, `85e1da0`, clean except pre-existing ` M .gitignore`). Nothing was modified.

Verified baseline facts the sequence depends on:

| Fact | Verified at |
|---|---|
| `tools/run-conformance.mjs` has **10** targets today | `tools/run-conformance.mjs:47–157` |
| CI is **5 jobs**: JS harness + `sdk-py` pytest + `cargo test --workspace` + `./gradlew :core:test` + `swift test`, gated by an "assert all lanes passed" summary | `.github/workflows/conformance.yml:18,104,132,150,177,197` |
| `check-spec-vectors.mjs` dispatches via a 4-branch `if/else` and two **closed** maps (`FAILING_AREA` 4 entries, `OPEN_REASON` 6 entries); unrecognised docs **fail closed** | `tools/check-spec-vectors.mjs:130,140,398–410` |
| `malformed-layout/vectors.json` holds **10** vectors, all derived from `tamper-detection/output/clean.capsule` | `spec/vectors/malformed-layout/vectors.json`, `sdk-js/tools/generate-malformed-fixtures.mjs:6,27` |
| Only `sdk-py` and `verifier-rust` consume the outcome registries; both **hard-code** `tamper-detection/vectors.json` + `malformed-layout/vectors.json`. Swift/Kotlin read only `tamper-detection/output/` and `jcs-numbers.json` | `sdk-py/tests/test_spec_registry.py:29-30`, `verifier-rust/tests/spec_registry.rs:119,151`, `ParityTests.swift:44`, `ParityTest.kt:117` |
| `skills/capsule/skill.json` hashes **seven** spec docs: `README/format/manifest/chain/envelope/trust/pith` + `SKILL.md`. `federation.md` is **not** hashed | `tools/regen-capsule-skill.mjs:32-40` |
| `sdk-js` has a raw `scanCentralDirectory` (rejects trailing bytes, multi-EOCD, ZIP64); **`sdk-py` has none** — it delegates to CPython `zipfile` | `sdk-js/src/zip.js:31-74` vs `sdk-py/src/capsule/zip_io.py:50` |
| Swift `unpack` central-directory loop reads `p+10/20/24/28/30/32/42/46` and `dataOff..<dataOff+compSize` **unbounded** | `sdk-swift/Sources/Capsule/Zip.swift:93-121` |
| Rust has **two** `trusted_signer_count` sites, not one | `verifier.rs:623` and `verifier.rs:892` |
| Swift/Kotlin `CONTENT_INDEX_EXCLUDED` excludes `content.enc` **unconditionally** | `Manifest.swift:7-11`, `Manifest.kt:6-8` |
| `JCS.swift:41` is a `precondition` (process trap), not a throw | `sdk-swift/Sources/Capsule/JCS.swift:40-45` |

---

## 1. Execution sequence

### Phase 0 — decision gate (no code)

| # | Cluster | Why here |
|---|---|---|
| 0 | **S1** (tier 0, 0 tasks) | Memo only. Its *decision* gates the design of C11 Task 7 (`evaluateSignerPolicy` quorum) and C12 Task 13 (signer-count semantics). Its *implementation* must not land here — see Phase 3. |

**Deliverable of Phase 0 is two maintainer answers, not a diff:** (a) accept/reject `manifest.signer_commitment`; (b) whether `format.version` bumps to `0.7`. C11 and C12 both write code whose meaning changes under (a); they must not start until (a) is answered. Answer (b) determines how every other cluster labels its break.

### Phase 1 — tier 1, release-blocking

| # | Cluster | Tasks | Blocked by | Rationale |
|---|---|---|---|---|
| 1 | **C3** swift ZIP traps | 2 | — | Cheapest tier-1 item, single lane (`sdk-swift/**` + CHANGELOG), zero shared infra. Unblocks C4. Ship it first so the Swift lane stops crashing on hostile bytes. |
| 2 | **C1** js container integrity | 6 | — | Tier-1 keystone. Establishes the `rawzip.mjs` extension, three new malformed-layout vectors, and — critically — the **sdk-py raw central-directory scan** that C2 depends on. |
| 3 | **C2** rust EOCD bypass | 3 | **C1** | Its stated `depends_on` (F15, sdk-py raw scan) is satisfied only by C1 Task 5 — and only if C1 Task 5 is extended (see §6.1). Task 3's own preflight gate is the 5-second check. |
| 4 | **C4** swift/kotlin rules | 7 | **C3** | Declared dependency, independently confirmed: both edit the same `CapsuleZip.unpack` loop. |
| 5 | **C5** ed25519 keys | 7 | — | Free-floating; placed last in tier 1 so its `check-spec-vectors.mjs` dispatch branch and its `spec/envelope.md` append rebase onto C1/C2's edits rather than the reverse. Can be pulled forward if a second person is available (see §4). |

### Phase 2 — tier 2

| # | Cluster | Tasks | Blocked by | Rationale |
|---|---|---|---|---|
| 6 | **C8** rust empty chain | 4 | C1, C2 (vectors.json) | Cheapest tier-2 item. Re-signatures `parse_chain_jsonl` / `verify_chain` / `first_and_entry_hash` to `ChainRecord` — do this **before** C7 and C9 touch the same functions, or they rebase twice. |
| 7 | **C6** total verifiers | 8 | — | Makes JS/Py verifiers total functions. Every later cluster's negative fixtures rely on it: C12's own RED output shows `verify_capsule` *raising* `MalformedCapsuleError` today where it must *return* a result. Also lands the `malformed-shape` registry. |
| 8 | **C10** JCS key order | 8 | C1 (sdk-py `zip_io.py`), C3/C4 (Swift `Zip.swift`) | Pure comparator work; mutates no existing vector. Low risk, and it lands the `jcs-key-order.json` vector that C9's lane tasks sit beside. |
| 9 | **C9** I-JSON + Pith | 9 | C8 (Rust `chain.rs`), C10 (same JCS files) | Carries the **Swift `JCS.swift:41` precondition→throw** conversion, which closes C3's adjacent defect #1. See §6.2 — consider promoting that one edit into Phase 1. |
| 10 | **C7** actor rule | 10 | C8 (`chain_walk_into`), C6 (JS/Py verifier), C9 (`chain.md`, `appendEvent`) | Widest blast radius of any tier-2 cluster (9 lanes, ~30 enumerated call sites). Land it after the verifier and chain internals have stopped moving. |
| 11 | **C11** federation | 10 | S1 decision (Task 7 only) | Fully isolated in `sdk-js/src/federation/**` + `spec/federation.md` (not skill-hashed) + a new registry. Position in the serial list is arbitrary — it is the #1 parallel candidate. |
| 12 | **C12** semantic binding | 14 | C6, C7, C8, C4, S1 decision | Largest cluster, five lanes, touches every file the others touch. Deliberately last so it rebases once instead of being rebased onto seven times. |

### Phase 3 — S1 implementation (only if option (a) is accepted)

| # | Work | Rationale |
|---|---|---|
| 13 | **S1-impl** signer-set binding | S1 measured that it invalidates `plain-basic.json`, `signing-input.json`, **all** `tamper-detection/output/*` and therefore **all** derived `malformed-layout/`, `chain-rules/`, `semantic-binding/`, `unicode-boundary` fixtures. Landing it mid-programme forces N fixture regenerations; landing it last forces exactly one. It also requires a Rust `schemas.rs` change (proven: Rust drops unknown manifest fields and recomputes a different `manifest_hash`) — all five lanes plus the whole corpus must land in **one** merge. |

---

## 2. FILE COLLISIONS

### 2.1 `sdk-swift/Sources/Capsule/Zip.swift` — C3 · C4 · C10

Confirmed by reading `Zip.swift:74-122`. Today every field read inside the central-directory loop (`read32(bytesArr, p)`, `p+10/20/24/28/30/32/42`, the name slice at `p+46`, and `bytesArr[dataOff..<(dataOff+compSize)]`) is unbounded.

- **First: C3.** It wraps those reads in bounds checks and adds the EOCD/count validation.
- **Second: C4** rebases as a pure insertion into C3's hardened loop: `var seen = Set<String>()` before it, `let externalAttrs = read32(bytesArr, p + 38)` beside the existing field reads, two guards after `try assertSafePath(name)`. **C4 must confirm C3's "record fits inside the central directory" precondition covers the new `p + 38` read** — C3 has no reason to bound an offset nobody reads yet.
- **Third: C10** touches only `pack`'s sort line (`Zip.swift:15`, `files.sorted { $0.path < $1.path }` → `utf16Less`). Disjoint from both; no rebase needed.
- If C4 somehow lands first, C3 must extend its bounds checks to cover `p + 38`.

### 2.2 `sdk-kotlin/.../Zip.kt` — C4 · C10 (and an unowned gap)

C4 edits the `unpack` loop (`Zip.kt:77-92`); C10 edits the `pack` sort (`Zip.kt:15`). No overlap. **Gap:** C3 does not cover Kotlin, and C1's own risk note says Swift and Kotlin "almost certainly have the same directory-marker/local-name gap". Nobody owns Kotlin ZIP-reader robustness. See §6.3.

### 2.3 `spec/vectors/malformed-layout/vectors.json` + `output/` + `generate-malformed-fixtures.mjs` — C1 · C2 · C8

Three clusters append to the same 10-entry array and re-run the same generator.

- **Order: C1 (+3) → C2 (+1 `trailing-bytes`) → C8 (+1 `empty-chain`).**
- C2 rebases onto C1's `vectors.json` **and** onto C1's extended `rawzip.mjs` (C1 adds the raw-write capability; C2 and C8 both benefit).
- **Each new `reason` must land in the same commit as three needle tables**, all verified present: `tools/check-spec-vectors.mjs` `OPEN_REASON` (line 140), `sdk-py/tests/test_spec_registry.py` `OPEN_REASON_PATTERNS`, `verifier-rust/tests/spec_registry.rs` `open_reason_needles` (which `panic!`s on an unknown reason). C8's `empty-chain` is verify-stage and uses the existing `FAILING_AREA.chain` — no table change.
- **After every rebase, run `node sdk-js/tools/generate-malformed-fixtures.mjs --check`.** Pre-existing fixtures must stay byte-identical (C1, C2 and C8 each measured this independently). A byte diff here means the tamper baseline moved — stop and read §2.7.

### 2.4 `tools/check-spec-vectors.mjs` — C1 · C2 · C5 · C6 · C9 · C10 · C11 · C12 (eight clusters)

This is the single worst collision in the programme. The file has a 4-branch `if/else` in `checkFile` (line 398) and two closed maps. Every cluster that adds a vector kind or reason edits the same 30 lines:

| Cluster | Edit |
|---|---|
| C1 / C2 | new `OPEN_REASON` entries (`trailing_bytes: /end-of-central-directory/`) |
| C5 | new dispatch branch for `meta.kind: "ed25519-verify"` |
| C6 | new `OPEN_REASON` entry `invalid_manifest_shape` + `malformed-shape/` collection |
| C9 | recognizer for `ijson-acceptance` + `unicode-boundary` |
| C10 | recognizer for `jcs-key-order.json` (the checker **walks the tree** and fails closed on anything it does not recognise) |
| C11 | recognizer for `identity-attestation/` |
| C12 | new `expected` fields (`trusted_signer_count`, `decryptable_with`) + a `reasons{}` vocabulary |

**Recommended one-time infra step, owned by C1 (first to touch the file):** convert `checkFile`'s `if/else` chain into a `meta.kind` → handler dispatch table and make `OPEN_REASON`/`FAILING_AREA` extendable rows. Cost ≈ 30 minutes. Without it, seven subsequent clusters produce guaranteed textual conflicts in the same hunk, and each one's "spec vectors: ok (N)" expectation is measured against a different file.

**Ordering rule if the refactor is skipped:** everyone **appends** rows; nobody restructures. **C12 goes last** because it is the only cluster that widens the `expected` *schema* — do not make six clusters rebase onto a moving schema.

### 2.5 `verifier-rust/.../verifier.rs` and `chain.rs` — C8 · C7 · C9 · C12

- `chain_walk_into` (verified at `verifier.rs:761`, currently `events: &[ChainEvent]`): C8 Task 1 adds the empty-chain guard at its top, Task 2 changes its parameter to `&[ChainRecord]`. C7 adds three actor-rule tests in the same file. **C8 first**; C7's tests must be written against the post-C8 `ChainRecord` signature.
- `chain.rs` `verify_chain` / `parse_chain_jsonl` / `first_and_entry_hash`: C8 re-signatures all three; C9 edits `verify_chain` for the I-JSON boundary. **C8 first**, C9 rebases onto `ChainRecord` (its `Deref<Target = ChainEvent>` keeps read-only field access compiling).
- `trusted_signer_count`: **two** sites, `verifier.rs:623` and `verifier.rs:892` — not one. C12 Task 13 must change both, and S1-impl later touches the same lines. C12 → S1-impl.

### 2.6 `sdk-js/src/verifier.js` and `sdk-py/src/capsule/verifier.py` — C6 · C7 · C12 · S1-impl

All four edit the ~30 lines around signer evaluation and the result assembly (`verifier.js:220-228`, `verifier.py:233-249`). **Order: C6 → C7 → C12 → S1-impl.** C6 must go first because it wraps the whole body in a catch-all; C7 and C12 then add errors *inside* a function that already cannot throw. Reversing this means C6 has to re-derive its catch-all boundary around two later feature sets.

### 2.7 `spec/vectors/tamper-detection/output/` — the fixture root (C4 · C12 · C1 · C2 · C8 · C7 · C9 · S1-impl)

Verified: `generate-malformed-fixtures.mjs:27` derives every malformed fixture from `clean.capsule`. C4 derives `plain-stray-content-enc.capsule` from it; C12 derives six from `clean`/`clean-encrypted`/`tampered-chain`; C7 derives two; C9 derives one.

**Rule for the whole programme: `generate-tamper-fixtures.mjs`'s write path is frozen.** It mints a fresh keypair on every run, so re-baselining rotates `keys.json` and rewrites every downstream fixture in eight clusters at once. C4 Task 1 Step 4 already derives its fixture rather than re-baselining — everyone follows that pattern. If S1-impl forces a re-baseline (it does, under option (a)), it happens **once, last, as a dedicated commit**, with a byte-level diff review per `spec/vectors/README.md`.

### 2.8 The seven skill-hashed spec docs — C1 · C5 · C7 · C9 · C10 · C12

Verified `tools/regen-capsule-skill.mjs:32-40`: `spec/{README,format,manifest,chain,envelope,trust,pith}.md` + `skills/capsule/SKILL.md` are hashed into `skills/capsule/skill.json`, which is conformance target **#1**.

| Doc | Clusters |
|---|---|
| `format.md` | C1 (Task 6), C10 (Task 8, "ASCII order") |
| `envelope.md` | C5 (appends after line 103) |
| `chain.md` | C9 (Hashing, lines 43-56), C7 (Verification list) |
| `manifest.md` | C10 (line 74), C12 |
| `federation.md`, `profiles/clerk.md` | C11 — **not hashed, no regen needed** |

**Rules:** (a) any commit touching a hashed doc runs `node tools/regen-capsule-skill.mjs` in that same commit — C1 discovered this the hard way and Task 6 already includes the step; (b) `skill.json` is generated — **never hand-merge it**; resolve the `.md` conflict, then re-run the generator; (c) C9 before C7 on `chain.md` (different sections — Hashing vs Verification — but merge in one direction, per C9's own instruction).

### 2.9 `sdk-py/src/capsule/zip_io.py` — C1 · C10

C1 Task 5 rewrites `unpack_zip` (line 50); C10 Task 3 edits `pack_zip` (line 32) and adds `import capsule.canonical` (verified acyclic — `canonical.py` imports only stdlib). Different functions, same file. **C1 first** (tier 1); C10 rebases trivially.

### 2.10 `sdk-py/src/capsule/canonical.py`, `sdk-swift/.../JCS.swift`, `sdk-kotlin/.../Canonical.kt` — C10 · C9

C10 changes the object-member sort comparator; C9 adds the I-JSON number/surrogate guard and (in Swift) converts `precondition` → `throw`. Adjacent, not overlapping. **C10 → C9.**

### 2.11 `CHANGELOG.md` `## Unreleased` — every cluster

Trivial but constant. C3 already predicts a merge at lines 70-71. Append-only, resolve by keeping both.

---

## 3. SHARED-INFRASTRUCTURE ORDERING

| Infrastructure | Established by | Consumed by | Ordering obligation |
|---|---|---|---|
| **`rawzip.mjs` raw-write extension** (`sdk-js/tools/rawzip.mjs`, currently exports only `writeRawZip`) | **C1** | C2 (`trailing-bytes`), C8 (`empty-chain`) | C1 first. C3 separately notes `rawzip.mjs` lacks EOCD-override support — if C2's trailing-byte fixture needs it, C2 extends it, and any later EOCD-shaped fixture inherits that. |
| **`sdk-py` raw central-directory scan** (`zip_io.py`) | **C1 Task 5** (extended — see §6.1) | C2 Task 3 (hard, measured), all future open-stage layout vectors | C1 before C2. Wording contract: the `ValueError` must contain **`end-of-central-directory`** (C2 hard-codes that regex in `OPEN_REASON_PATTERNS`). |
| **`malformed-layout` registry expansion** | already exists; extended by **C1** | C2, C8 | Append-only; three needle tables per new reason. |
| **`malformed-shape` registry + generator** (`generate-malformed-shape-fixtures.mjs`, new conformance target) | **C6** | Nobody yet. C6 explicitly leaves the Rust wiring as follow-up: add `"invalid_manifest_shape" => &["failed to parse manifest.json"]` to `open_reason_needles` and a third `#[test]`. | Assign that follow-up to **C12** (already editing `spec_registry.rs`) or to a named cleanup task, or it is lost. |
| **`chain-rules` registry + generator + conformance target** | **C7** | C12 (may want chain-anchored negatives) | C7 before any cluster adding a chain-rule vector. |
| **`semantic-binding` registry + `expected` schema widening** (`trusted_signer_count`, `decryptable_with`, `requires[]`, `reasons{}`, **five** per-lane needle tables) | **C12** | S1-impl (needs a `signer_set` failing-area, which C12's `FAILING_AREA` widening makes possible) | C12 before S1-impl. C12 must land the widened `FAILING_AREA` so S1's negative vectors are expressible — S1's own risk #4 names this exactly. |
| **`ed25519-verify` doc kind** (`meta.kind` dispatch branch) | **C5** | Nobody | First non-collection, non-signing-input doc kind. If §2.4's dispatch-table refactor happens, C5 is its first customer. |
| **`identity-attestation` registry** | **C11** | Nobody (isolated) | None. |
| **`jcs-key-order.json`** | **C10 Task 1** | C10 Tasks 5/6/7 (Swift, Kotlin, Rust all read the file and fail with ENOENT until it exists) | Task 1 strictly before Tasks 5-7 — intra-cluster, already flagged by C10. |
| **`ijson-acceptance` + `unicode-boundary` + the `accepted:false` marker on 13 `jcs-numbers.json` entries** | **C9 Task 2** | Every lane's number-vector test | The marker is backward-compatible: a lane that ignores the field still passes until it gains its guard. So Task 2 can land ahead of the lane tasks safely. |
| **`run-conformance.mjs` target list** (10 today) | +1 C6, +1 C7, +1 C12; recommended +1 C5, +1 C9 | — | See §5 for the count arithmetic. Every cluster's "PASS · 11/11" claim was measured against a baseline of 10 and is wrong the moment a second cluster lands. |

---

## 4. PARALLELISATION

### Safe to run simultaneously (disjoint files, verified)

**Track A — container (one person):** `C3 → C1 → C2 → C4`
Strictly serial internally. C3→C4 share `Zip.swift`; C1→C2 share `vectors.json`, `rawzip.mjs`, and the sdk-py scan.

**Track B — crypto/federation (second person):** `C5 → C11`
- C5 touches `Crypto.*` in five lanes, `spec/envelope.md`, and one `check-spec-vectors.mjs` branch. No overlap with Track A except that one file.
- C11 touches only `sdk-js/src/federation/**` — verified: `grep -rl federation` over `cli/`, `examples/`, `tools/` and the other four SDK lanes returns nothing but docs. It is the most parallelisable cluster in the set.
- **Single sync point with Track A:** `tools/check-spec-vectors.mjs`. Coordinate by having Track A land §2.4's dispatch refactor early, then both tracks append rows.

**Track C — canonicalisation (third person, from Phase 2):** `C10 → C9`
Shares `Zip.swift`/`Manifest.swift`/`zip_io.py` with Track A, so it cannot start until C1 and C4 have landed. After that it is independent of Tracks A and B.

### Must be serialised — do not parallelise

- **C1 ∥ C2 ∥ C8**: same `vectors.json` array, same generator, same three needle tables. Three-way conflict guaranteed.
- **C3 ∥ C4**: same `CapsuleZip.unpack` loop body.
- **C6 ∥ C7 ∥ C12**: same `verifier.js` + `verifier.py` signer/result region, plus `sdk-py/tests/test_spec_registry.py` and `verifier-rust/tests/spec_registry.rs`.
- **C8 ∥ C7 ∥ C9**: same Rust chain functions (`chain_walk_into`, `verify_chain`).
- **C9 ∥ C10**: same four canonicalizer files across four lanes.
- **C7 ∥ C9 on `appendEvent`**: both make the same builder method reject input, in all five lanes.
- **Anything ∥ S1-impl**: S1-impl rewrites the entire fixture corpus. It gets exclusive access to the tree.

### Toolchain constraint on parallelisation

Three clusters could not be fully validated on the authoring machine and need real hardware:
- **Swift** (C3, C4, C5, C9, C10, C12) requires a full Xcode toolchain — `/usr/bin/swift` from CommandLineTools has no XCTest. C3, C4 and C12 ran with `DEVELOPER_DIR=...`; C5, C9, C10's Swift tests are inspection-only.
- **Kotlin** (C4, C5, C7, C9, C10, C12) — **no JRE on the authoring machine**. C4 is the only cluster that actually executed Gradle. C5, C7, C9, C10 and C12's Kotlin work is unrun. CI's `./gradlew --no-daemon :core:test` is the first real execution for five clusters.

**Assign the Swift and Kotlin lanes to whoever has both toolchains, and treat every unrun Kotlin task as unproven** — in particular C5's claim that BouncyCastle 1.78.1 needs no guard (verified by bytecode inspection only) and C9's note that `sdk-kotlin :core` may not compile today because `CapsuleException` has no visible declaration (`grep -rln CapsuleException sdk-kotlin/` hits only `Reader.kt` and `ParityTest.kt`). **Verify that Kotlin compiles at all before Phase 1 starts** — if it does not, that is a separate finding blocking six clusters.

---

## 5. CHECKPOINTS

### What "green" can and cannot mean

`node tools/run-conformance.mjs` covers **JavaScript targets only** — the JS SDK, CLI, examples, `spec-vectors`, `skill-capsule-regen`, and the fixture-regen checks. The harness's own report says so. It does **not** run Rust, Python, Swift, or Kotlin.

**The real gate is the five CI jobs** (`conformance.yml:18,104,132,150,177`), asserted together by the summary job at line 197:

```
node tools/run-conformance.mjs                          # JS harness
PYTHONPATH=sdk-py/src python3 -m pytest sdk-py/tests    # Python parity
cd verifier-rust && cargo test --workspace              # Rust parity   (--workspace, not bare `cargo test`)
cd sdk-kotlin && ./gradlew --no-daemon :core:test       # Kotlin parity
cd sdk-swift && swift test                              # Swift parity
```

Two traps, both measured by cluster authors:
- `cargo test` at the workspace root runs only the root parity package. **`--workspace` is required** to reach the 100+ lib unit tests (C9 found this).
- Every absolute number in every cluster plan — `# tests 63`, `188 passed`, `spec vectors: ok (283)`, `PASS · 11/11` — was measured against the **pristine** baseline in isolation. **Read them all as deltas.** Baselines: sdk-js 57, sdk-py 182, Rust lib 102, Swift 26, Kotlin 16, vectors 280, conformance targets 10.

### Checkpoint table

| After | All five lanes must be green | Target count | Vector count | What is *intentionally* still broken |
|---|---|---|---|---|
| **C3** | ✅ | 10 | 280 | Nothing. Single-lane, +11 Swift tests (26→37). |
| **C1** | ✅ | 10 | **283** | Nothing new fails, but the malformed-registry now feeds three harnesses — if any one is red, C1 Task 6 landed before Tasks 3/4/5. `skill-capsule-regen` will be red until `regen-capsule-skill.mjs` is run (C1 edits `format.md`). |
| **C2** | ✅ | 10 | **284** | **Hold Task 3 until C1's sdk-py scan exists.** Measured symptom of getting this wrong: `test_malformed_registry_outcomes[trailing-bytes]: DID NOT RAISE ValueError`, `1 failed, 182 passed`. |
| **C4** | ✅ | 10 | **285** | Swift/Kotlin are *deliberately* not bit-for-bit registry-conformant: `openRejectedVerifyVectors = {missing-chain, invalid-chain-json}` and Kotlin's `ENCRYPTED_VECTORS = {clean-encrypted, tampered-blob}` are pinned-by-name allowances, each asserting a concrete alternative outcome. Green here means "green **with** those named exemptions". They should shrink later; they are not silent skips. |
| **C5** | ✅ | 10 | **299** | **First checkpoint where CI, not a developer, is the first executor of a Kotlin test.** If `./gradlew :core:test` fails on C5's pin test, the finding is that BouncyCastle 1.78.1 does *not* reject some encoding, and Kotlin needs the explicit guard the other four lanes got. |
| **— end of tier 1 —** | **Full five-lane green required before any tier-2 work starts.** | 10 | 299 | This is the release-blocking gate. |
| **C8** | ✅ | 10 | **300** | Four pre-existing Rust tests are *edited* by design (`first_and_entry_hash_empty`, `detects_seq_skew`, `detects_hash_tampering`, `chain_event_round_trip`) — they must be edited, not merely made to pass. |
| **C6** | ✅ | **11** | **305** | `sdk-py/tests/test_reader.py::test_is_encrypted_when_manifest_has_encryption` is *rewritten* by design — it hand-builds a manifest the new validator refuses. That is the only pre-existing test in either lane C6 has to touch. Rust's `malformed-shape` wiring is a knowingly-open follow-up (§3). |
| **C10** | ✅ | 11 | **313** | Nothing. All existing fixtures are ASCII-keyed, so no hash in the repo moves — that is why C10 is safe to land anywhere after C1/C4. |
| **C9** | ✅ | 11 | **328** | **13 `jcs-numbers.json` vectors flip from "serialize" to "reject"** — unavoidable, they are integer-valued doubles in [2^53, 1e21). Green means every lane's number-vector test honours the new `accepted:false` flag. A lane that has the guard but not the test update is red; a lane with neither is *green but wrong*. |
| **C7** | ✅ | **12** | **330** | ~30 enumerated call sites across `dx.test.js`, `examples/quickstart`, both READMEs, and the Swift/Kotlin round-trip tests break **by design** and are fixed inside Tasks 4/8/9/10. Green means the CI-gated onboarding path (`examples/quickstart` + `sdk-js/README.md:52-56`) was updated, not just the unit tests. |
| **C11** | ✅ | 12 | **341** | ~10 existing `federation.test.js` assertions rewritten by design. Isolated — no other lane moves. |
| **C12** | ✅ | **13** | **347** | C12's "known adjacent defect left alone" (unconditional `content.enc` exclusion in Swift/Kotlin) **is already fixed by C4** at this point — C12 must rebase that assumption rather than re-fix it. Kotlin Task 14 is compile-unverified; it needs a real `./gradlew --no-daemon :core:test` before it is trusted. |
| **S1-impl** | ✅ after one bulk regeneration | 13 | 347 (all bytes changed) | The **entire pinned corpus regenerates**. Expect `check-spec-vectors.mjs` to fail on all positive vectors until regeneration completes — measured, three FAIL lines. Review as a byte-level diff, not a rubber stamp. Rust parity, Python registry, Swift `ParityTests` and Kotlin `ParityTest` all pin cross-lane hashes and all go red until the regen lands in the same merge. |

**Recommended additions to the target list** (neither cluster proposed them, both ship a `--check` generator): C5's `generate-ed25519-key-validation-vector.mjs --check` and C9's `generate-unicode-boundary-fixture.mjs --check`. That makes the final count **15**. Without them, those two vector sets can silently drift.

**Operational note for every checkpoint:** `run-conformance.mjs` rewrites `output/conformance-report.{json,md}`, and CI auto-commits them on push to main. Keep them out of manual `git add` lists.

---

## 6. Work the ordering exposes as unowned

These are collisions in the sense that matters most: gaps between clusters that only become visible when you line them up.

### 6.1 F15 has no owner — and C2 hard-depends on it

C2's `depends_on` names **F15 (port `scanCentralDirectory`/`assertStrictEntries` to `sdk-py/src/capsule/zip_io.py`)**. F15 appears in **no cluster's finding list**. C1 covers F01/F11/F58/F67 only.

Verified directly: `sdk-py/src/capsule/zip_io.py:50` opens archives with CPython `zipfile` and has no raw EOCD locator. `sdk-js/src/zip.js:37-74` has one, and it is what rejects trailing bytes, multiple EOCDs and ZIP64 sentinels.

C1 Task 5 *does* rewrite the same function and *does* require raw local+central header parsing (it turns a `BadZipFile` into a `ValueError` for the local/central name mismatch). So C1 is the natural home — but C1 does not claim the **EOCD half**.

**Resolution: extend C1 Task 5 to port the full `scanCentralDirectory`, including the EOCD strictness, and require the raised `ValueError` to contain the literal phrase `end-of-central-directory`.** C2 Task 3 hard-codes that regex. If C1 Task 5 is not extended, **C2 Task 3 must be deferred** to a named F15 cluster, and C2 ships as Tasks 1+2 only (Rust-side fix without the cross-lane vector).

### 6.2 Swift `verify` can still be crashed through all of tier 1

C3's contract is "verify must never trap". C3 closes the ZIP path. But C3 itself reports — and I confirmed at `sdk-swift/Sources/Capsule/JCS.swift:40-45` — that `JCS.canonical` uses a **`precondition`**, reachable from `CapsuleVerifier.verify` on attacker-controlled bytes via `Manifest.hash(parsed.manifest)`. A 4-file capsule with `manifest.json = {"id":9007199254740993}` kills the process (`exited with unexpected signal code 5`). `CHANGELOG.md:134-135` already claims these are "rejected fail-closed in Python/Kotlin/Swift", which is untrue for Swift.

The fix lives in **C9 Task 6** (which converts the Swift number rule to a throw) — a **tier-2** cluster, seven positions later.

**Recommendation: promote the `precondition` → `throw` conversion in `JCS.swift` into C3 (or a two-line tier-1 hotfix).** Otherwise "tier 1 complete" ships a Swift verifier that a hostile capsule can still crash, and a green `ZipRobustnessTests` will be misread as proof otherwise. C9 keeps the full I-JSON boundary; only the trap-removal moves.

### 6.3 Kotlin ZIP-reader robustness is unowned

C3 covers Swift only. C1's risk note says Swift and Kotlin "almost certainly have the same directory-marker/local-name gap" and recommends they adopt the same three checks. C4 adds duplicate/symlink rejection to Kotlin but not bounds hardening or directory-marker checks. **Either extend C4 with a Kotlin equivalent of C3's Task 1, or open a named cluster.** Do not let "C4 touched Kotlin" read as "Kotlin is covered".

### 6.4 Rust's typed-manifest drop blocks all future manifest extensibility

S1 proved by execution that `verifier-rust` deserialises into a typed `Manifest` struct (`schemas.rs:107-118`, no `#[serde(flatten)]`) and re-serialises it for `manifest_hash` (`manifest.rs:132-142`) — so **any** unknown manifest field is silently dropped and the hash diverges. That is not specific to `signer_commitment`: it breaks every future manifest field (federation, anchors, profiles). It fails *closed*, which is the safe direction, but it is a latent blocker sitting under S1-impl, C12, and anything after.

**Fix it before S1-impl**, by canonicalising a preserved `serde_json::Value` tree instead of a struct. No cluster owns this. It is a prerequisite for Phase 3, not part of it.

### 6.5 S1 and C12 disagree about duplicate signers

C12 Task 13 makes `trusted_signer_count` count **distinct keys** — its `duplicate-signer` vector expects `ok: true, trusted_signer_count: 1` for a capsule with two identical signers. S1's option (a) **rejects duplicates outright** (`envelope.signers not a well-formed set: duplicate signer member`), i.e. `ok: false`.

These are incompatible expected outcomes for the same fixture. **Resolve at the Phase 0 decision gate**, not at merge time. If option (a) is accepted, C12's `duplicate-signer` vector must be authored as `ok: false` from the start, or S1-impl will have to rewrite a vector C12 just pinned. S1's own risk #5 flags the same five `trusted_signer_count` call sites — plus the second Rust site at `verifier.rs:892` that neither plan mentions.

### 6.6 C11's federation policy is documented as sound and is not

`spec/federation.md:340-363` documents `evaluateSignerPolicy` as quorum over the signer set. S1 proved the signer set is unauthenticated (strip / duplicate / attacker-adds-notary all return `ok: true` with zero errors). `evaluateSignerPolicy` dedupes by key, so it is immune to duplication — but **not to stripping**. C11 fixes capsule-binding and issuer-binding but does not fix this, and says so.

**Either C11 adds the step-0 amendment to `spec/federation.md` in the same change, or the reference policy engine keeps advertising quorum over an unauthenticated set** until S1-impl lands. Given C11 is already editing that file and it is not skill-hashed, folding the amendment in is nearly free.
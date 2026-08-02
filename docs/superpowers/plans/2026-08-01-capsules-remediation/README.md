# Capsules Protocol Pre-Release Remediation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every tier-1 and tier-2 finding from [the pre-release code review](../../../../CODE-REVIEW-2026-07-31.md) so that the five implementation lanes agree on one protocol and no verifier accepts a capsule carrying bytes its signature does not cover.

**Architecture:** Twelve independent fix clusters plus one design spike, each grounded in the real code and each landing with a negative conformance vector consumed by every lane. Clusters are sized so a reviewer can accept or reject one without touching its neighbours. The spike (S1) is a decision gate, not code — it must be answered before any work that changes the manifest or envelope wire shape.

**Tech Stack:** JavaScript (node:test) · Python (pytest) · Rust (cargo test) · Swift (XCTest) · Kotlin (Gradle) · JSON conformance vectors under `spec/vectors/`

## Global Constraints

Every task in every cluster implicitly includes these.

- The project is **pre-release (v0.6 prototype)**. Breaking changes are acceptable. Do not add compatibility shims or deprecation paths.
- `sdk-js` is the **reference implementation**. Where lanes disagree and no decision below says otherwise, JS defines correct behaviour.
- The chain.md step-6 actor rule resolves as: **all five verifiers enforce** (`actor` is in `manifest.participants` or equals `system:host`), **and builders reject at `appendEvent` time**. Not auto-registration. *(Maintainer decision, 2026-08-01.)*
- Every normative rule this plan enforces must land with a **negative conformance vector** consumed by every lane's spec-registry test. A fix without a vector does not count as done — that is the exact gap the review identified as the root pattern.
- Test frameworks by lane: `sdk-js` node:test · `sdk-py` pytest · `verifier-rust` `#[test]` · `sdk-swift` XCTest · `sdk-kotlin` its existing style.
- Never claim a command was run without running it.

---

## Read this first: two decisions gate the work

**[S1 — Signer-set binding decision memo](S1-signer-set-decision.md)** is Phase 0. It is a memo, not tasks. Its recommendation, prototyped and measured against the real code:

> Adopt option (a) — a required `manifest.signer_commitment` holding the sorted `(role, public_key)` set. Reject the envelope-schema change (option b). Scope chain-expressed approvals to in-session use, and specify post-seal countersignature as a separate v0.7 capsule profile.

Two answers are needed from you before C11 and C12 start, because both write code whose meaning changes underneath them:

1. **Accept or reject `manifest.signer_commitment`**, and if accepted, confirm the memo's fail-closed recommendation: make the field **required**, rejecting any manifest without it. There is no deployed corpus to protect — the only "old capsules" are checked-in fixtures, all regenerable.
2. **Does `format.version` bump to `0.7`?** This plan makes the first manifest wire-shape change. The memo recommends one bump covering all settled semantic-binding fixes rather than silently redefining `0.6`.

Until these are answered, clusters C1–C10 can proceed; C11 Task 7 and C12 Task 13 cannot.

---

## The clusters

| Cluster | Tier | Tasks | Findings closed | Lanes |
|---|---|---|---|---|
| [S1 — signer-set decision](S1-signer-set-decision.md) | 0 | memo | *(prior findings doc)* | spec, all |
| [C1 — JS container integrity](C1-js-container-integrity.md) | 1 | 6 | F01 F11 F58 F67 | sdk-js, sdk-py, verifier-rust, spec |
| [C2 — Rust EOCD strictness](C2-rust-eocd-strictness.md) | 1 | 3 | F02 | verifier-rust, spec, sdk-js, sdk-py |
| [C3 — Swift ZIP bounds](C3-swift-zip-bounds.md) | 1 | 2 | F17 | sdk-swift |
| [C4 — Swift/Kotlin reader rules](C4-swift-kotlin-reader-rules.md) | 1 | 7 | F21 F16 F12 F20 | sdk-swift, sdk-kotlin, spec, sdk-js |
| [C5 — Ed25519 key validation](C5-ed25519-key-validation.md) | 1 | 7 | F13 | all five, spec, tools |
| [C6 — total verifiers](C6-total-verifiers.md) | 2 | 8 | F10 F06 F14 F34 F56 | sdk-js, sdk-py, spec, tools |
| [C7 — actor rule + kind enum](C7-actor-rule-and-kind-enum.md) | 2 | 10 | F09 F18 F23 F57 F51 F62 F66 | all five, spec, tools, cli, examples |
| [C8 — Rust chain + allowlist](C8-rust-chain-and-allowlist.md) | 2 | 4 | F22 F41 F44 | verifier-rust, spec, sdk-js |
| [C9 — I-JSON boundary + pith](C9-ijson-boundary-and-pith.md) | 2 | 9 | F05 F32 F08 | all five, spec, tools |
| [C10 — JCS key ordering](C10-jcs-key-ordering.md) | 2 | 8 | F30 F31 F35 | all five, spec, tools |
| [C11 — federation binding](C11-federation-binding.md) | 2 | 10 | F07 F19 F28 F27 F39 F54 F53 F63 | sdk-js, spec |
| [C12 — semantic-binding registry](C12-semantic-binding-registry.md) | 2 | 14 | F37 F43 F38 F33 F42 F29 | all five, spec, tools |

**88 tasks.** Tier 1 is release-blocking (25 tasks). Tier 2 is v0.7 correctness (63 tasks). Tier 3 release hygiene — README quickstart, package metadata, licence mismatches, SECURITY.md — is deliberately excluded here; those are one-line edits tracked in the review's own tier-3 list.

## Execution order

Full reasoning, file-collision map, parallelisation guidance and checkpoints are in **[SEQUENCING.md](SEQUENCING.md)**. The short version:

```
Phase 0   S1 decision gate (no code)
Phase 1   C3 → C1 → C2 → C4 → C5          release-blocking
Phase 2   C8 → C6 → C10 → C9 → C7 → C11 → C12
Phase 3   S1 implementation, if option (a) accepted — must land as one merge
```

C3 goes first because it is the cheapest single-lane fix and unblocks C4. C1 is the tier-1 keystone: it establishes the raw central-directory scan that C2 depends on. C12 is deliberately last so it rebases once instead of being rebased onto seven times. S1's implementation lands last because it invalidates every checked-in fixture, and doing it last forces exactly one regeneration.

**C11 is the best parallelisation candidate** — it is fully isolated in `sdk-js/src/federation/**` and `spec/federation.md`, and can be worked simultaneously with anything.

## ⚠ This plan is not yet complete — read this section before starting

An adversarial completeness review ([CRITIQUE.md](CRITIQUE.md)) ran against the finished clusters and found real coverage holes. **The plan below closes 46 finding-instances; it does not yet cover everything, and it does not close the pattern that generates them.** Fix these before execution begins.

### The A01–A15 addendum is entirely unscoped

`CODE-REVIEW-2026-07-31.md` gained a second finding ledger after this plan's clusters were specified. **No cluster covers it.** A01–A06 restate the six findings already tracked in `capsulesfindingsexpanded.md`, but **A07–A15 are nine genuinely new cross-lane defects**, six of them HIGH:

| ID | Defect | Status |
|---|---|---|
| A07 | Rust hashes a typed projection, so unsigned unknown manifest/envelope fields are accepted | Independently rediscovered by the sequencing pass (§6.4) — blocks every future manifest field |
| A08 | Swift and Kotlin accept an empty chain other lanes reject | Confirmed by the critique (G12); C8 fixes Rust only |
| A09 | Swift/Kotlin optional anchor checks turn a missing mandatory hash into success | Fail-open; unowned |
| A10 | Swift and Kotlin do not enforce contiguous chain sequence numbers | Unowned |
| A11 | Swift accepts uppercase signer-key hex that stricter lanes reject | Unowned |
| A12 | Rust uniquely requires participant `label` | Unowned |
| A13 | Duplicate JSON members have a cross-lane acceptance differential | **Supersedes the review's "found sound" bullet on duplicate keys** |
| A14 | Event JSONL serialization is not canonical across producer lanes | Unowned |
| A15 | `untrusted_payload_fields` has no path grammar or safe host-projection contract | Unowned |

Amendments M01–M06 in the same document strengthen F29, F10, F43, F13, F38 and F41 with runtime evidence; M04 notes F13 must **not** be read as an all-zero-key finding, since all four executed lanes reject that — the non-canonical `edff…ff7f` encoding is the live case. C5's tasks target the correct case.

**These need a second specification pass before the plan is complete.**

### Four more coverage holes

1. **F15 (HIGH) is unclaimed and C2 hard-depends on it.** `sdk-py/zip_io.py` reads only `zipfile`-sanitized names — no raw central-directory scan, no EOCD locator, no ZIP64 rejection. C2 Task 3 measured its own failure without it (`DID NOT RAISE ValueError`). **C2 Task 3 cannot land as written.** Extend C1 Task 5 to port the full `scanCentralDirectory`, or ship C2 as Tasks 1+2 only.
2. **F03 and F04 (both HIGH) sit in tier 3.** After this plan lands, C8 makes the Rust CLI reject a malformed `--allowlist` with exit 2 while the JS CLI still accepts `--alowlist` silently and exits 0 with zero trusted signers — two CLIs in one repo with opposite allowlist semantics, and the JS one is the documented CI-gating path. **Promote both into tier 2.**
3. **C5 fixes half of a two-part attack chain.** Its own finding text says the key-validation flaw combines with the unbound signer set. C5 closes the key half; the signer half is S1 — a memo with zero tasks. S1's measured output shows `approver stripped → ok:true` and `attacker notary added → ok:true` remain true after the entire plan. If release-blocking means "an attacker with no private key gets a trusted PASS," **S1 implementation belongs in tier 1 with tasks, not tier 0 with a memo.**
4. **Swift can still be crashed after all of tier 1** — see gap 2 in the sequencing list below.

### The meta-pattern is not closed

The review's thesis is that normative rules exist with no enforcement and no negative vector. The critique's verdict: **the plan fixes instances and leaves the generator intact, while adding three new instances.** Concretely — registry consumption is opt-in per lane by hardcoded filename, so each of the 7 new registries is invisible to four lanes by default; the spec does not use RFC 2119 (16 MUSTs total, and *none* of the actually-violated rules is one of them), so "enumerate the MUSTs" is not mechanically possible; no vector carries a spec anchor; and F40 — the check that stops a registry being silently emptied — is parked in tier 3 while the plan multiplies registries fourfold.

What would actually close it, owned by no cluster:

- A `spec/vectors/registry.json` manifest listing every collection and the lanes required to consume it, plus a conformance target that fails when a `vectors.json` exists but is unlisted, or when a lane's consumer set differs from its required set. **This single change would have caught F12/F16/F20/F21.**
- Land **F40 in tier 1**, with a hard non-empty assertion in every consumer (`sdk-py`'s currently returns `[]` on a missing path — a silent no-op).
- Normalize the spec's prose to RFC 2119 with rule IDs, and require every vector to carry a `rule_id`. S1's `0.6 → 0.7` version bump is the natural moment.

### Gaps the sequencing exposed

These are not in any cluster. They surfaced only when the clusters were lined up, and each needs a decision:

1. **F15 has no owner, and C2 hard-depends on it.** C2's dependency names "port `scanCentralDirectory`/`assertStrictEntries` to `sdk-py/zip_io.py`" — which no cluster claims. C1 Task 5 rewrites the same function and is the natural home, but does not cover the EOCD half. **Extend C1 Task 5, or defer C2 Task 3 and ship C2 as Tasks 1+2 only.**
2. **Swift `verify` can still be crashed after all of tier 1.** C3 closes the ZIP trap, but `JCS.swift:40-45` uses a `precondition` reachable from `CapsuleVerifier.verify` via `Manifest.hash`; a manifest with `{"id":9007199254740993}` kills the process. The fix lives in C9 Task 6 — seven positions later, in tier 2. **Promote that two-line `precondition` → `throw` conversion into tier 1**, or "tier 1 complete" ships a still-crashable Swift verifier. Note `CHANGELOG.md:134-135` already claims Swift rejects these fail-closed, which is currently untrue.
3. **Kotlin ZIP robustness is unowned.** C3 hardens Swift only; C4 adds duplicate/symlink rejection to Kotlin but no bounds hardening. Do not let "C4 touched Kotlin" read as "Kotlin is covered."
4. **Rust silently drops unknown manifest fields.** `schemas.rs:107-118` deserialises into a typed struct with no `#[serde(flatten)]` and re-serialises for `manifest_hash`, so any future manifest field diverges the hash. It fails closed, which is the safe direction, but it blocks S1-impl, C12, and every future manifest extension. **Fix before Phase 3; no cluster owns it.**
5. **S1 and C12 disagree about duplicate signers.** C12 Task 13 expects `ok: true, trusted_signer_count: 1` for a capsule with two identical signer entries; S1 option (a) rejects duplicates outright with `ok: false`. Same fixture, incompatible expectations. **Resolve at the Phase 0 gate**, not at merge.

## How this plan was built

Twelve specification agents plus one spike agent each read the actual code across the lanes they touch, wrote the tests and implementations, then **applied their cluster to a copy of the repository outside the working tree and ran it**. Each cluster file ends with an expandable validation log containing that real output — red before the fix, green after, plus full-suite regression runs. Where a toolchain was unavailable (the system `swift` is Command Line Tools only and cannot build XCTest targets), the agent says so explicitly rather than claiming a run.

The working tree was never modified during specification.

## Status

- [x] 12 fix clusters specified and validated on a repo copy — 88 tasks
- [x] Signer-set design spike complete, with a prototyped recommendation
- [x] Execution sequence and collision map ([SEQUENCING.md](SEQUENCING.md))
- [x] Adversarial completeness critique ([CRITIQUE.md](CRITIQUE.md))
- [ ] **Second pass needed:** specify clusters for A07–A15, claim F15, promote F03/F04 and F40, and decide whether S1 implementation moves into tier 1
- [ ] Maintainer decisions at the Phase 0 gate (signer commitment, version bump, duplicate-signer semantics)

**Do not treat this plan as ready to execute end-to-end.** Tier 1 clusters C1–C5 are individually sound and validated; the gaps above are about what the plan *omits*, not about whether the specified tasks work.

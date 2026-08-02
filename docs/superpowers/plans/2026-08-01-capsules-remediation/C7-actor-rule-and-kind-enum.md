# C7 — chain.md step-6 actor rule + the closed `kind` enum, enforced in all five verifiers and both reference builders

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Part of:** [Capsules pre-release remediation](./README.md) · Tier 2 (v0.7 correctness)

**Findings closed:** F09, F18, F23, F57, F51, F62, F66

**Lanes touched:** sdk-js, sdk-py, verifier-rust, sdk-swift, sdk-kotlin, spec, tools, cli, examples

**Tasks:** 10

**Depends on:** nothing — can start immediately

## Global Constraints

Copied verbatim from the project state; every task below implicitly includes these.

- The project is **pre-release (v0.6 prototype)**. Breaking changes are acceptable. Do not add compatibility shims or deprecation paths.
- `sdk-js` is the **reference implementation**. Where lanes disagree and no decision says otherwise, JS defines correct behaviour.
- The chain.md step-6 actor rule resolves as: **all five verifiers enforce** (actor is in `manifest.participants` or equals `system:host`), **and builders reject at `appendEvent` time**. Not auto-registration.
- Every normative rule this plan enforces must land with a **negative conformance vector**, consumed by every lane's spec-registry test. A fix without a vector does not count as done.
- Test frameworks by lane: `sdk-js` node:test · `sdk-py` pytest · `verifier-rust` `#[test]` · `sdk-swift` XCTest · `sdk-kotlin` its existing test style.
- Never claim a command was run without running it.

## Risks

BREAKING BY DESIGN — precise blast radius of the builder rejection (every appendEvent/append_event caller in the repo was enumerated by grep and classified):

BREAKS, must be fixed in this plan (Tasks 4, 8, 9, 10):
- sdk-js/test/dx.test.js — 6 builder constructions (lines 25, 49, 64-66, 83, 105, 132), all appending actor "human:me" with no participants. Reproduced: exactly these 6 fail.
- examples/quickstart/quickstart.mjs:21-24 and its verbatim twin sdk-js/README.md:52-56 — actors human:alice + ai:assistant, no participants. This is the CI-gated onboarding path.
- sdk-py/tests/test_builder.py:51,144,172,204,343,366,399; test_reader.py:15; test_verifier.py:15,160; test_dx.py:29,53,68,93,115,143 — participants=[] (or absent) with an appended actor.
- sdk-py/tests/test_chain.py:152,170,196 — bare verify_chain(events) now reports actor errors.
- sdk-py/README.md:36 — quickstart mirror.
- sdk-swift/Tests/CapsuleTests/RoundTripTests.swift:62-69 (testTamperedCapsuleFailsVerification) and EncryptionTests.swift:118-133 (buildEncryptedCapsule) — actor human:test, no setParticipants.
- sdk-kotlin/core/src/test/kotlin/.../RoundTripTest.kt:98-109 (tamperedCapsuleFailsVerification) — same.

ALREADY SAFE, verified no change needed: sdk-js/test/basic.test.js:25, pith.test.js:103/134/158/169, federation.test.js:273/347, strictness.test.js (no appendEvent; its two bare verifyChain calls only assert ok===false plus a regex match, so extra actor errors are harmless — confirmed green), sdk-js/tools/generate-tamper-fixtures.mjs:70/88, cli/test/smoke.mjs:80/88, examples/lib/example-kit.mjs:68 + examples/generic-{report,table-graph,react-render}/build.mjs, sdk-py/tests/test_parity_jssdk.py:119/198, test_reader.py:117, sdk-kotlin/README.md:75-86, spec/pith.md:81. sdk-py/tests/test_manifest.py:90/114/130 and the participants=[] sites in test_builder.py:77/95/111/123/129/135/436 and test_reader.py:153/185/220 pass participants=[] but never append an event — untouched.

API breaks beyond callers:
- sdk-js `verifyChain(events)` → `verifyChain(events, { participants })`. Defaulting participants to [] is FAIL-CLOSED: a lane that forgets to wire it rejects every non-system:host actor loudly rather than skipping the rule silently. Same for sdk-py, Swift, Kotlin.
- Swift `CapsuleBuilder.appendEvent` becomes `throws`, so every chained call site needs `try`. Swift `CapsuleReader.verifyChain` returns `[String]` instead of `Bool`; `CapsuleVerification` gains a `chainErrors` stored property, which changes its (internal) memberwise init — 5 construction sites in Verifier.swift must be updated together or the module will not compile.
- Kotlin `CapsuleVerification` gains `chainErrors: List<String> = emptyList()` (defaulted, so positional construction elsewhere is unaffected); `CapsuleVerifier.verifyChain` goes private→internal and Bool→List<String>.

Cross-lane coordination: the exact error strings are the contract. Rust is the reference (`seq {}: actor {:?} not in manifest.participants and not system:host`); JS/Py use JSON.stringify/json.dumps and Swift/Kotlin use a new `Chain.debugQuoted` helper so all five produce byte-identical `"human:mallory"` quoting. JS/Py/Swift/Kotlin omit the `seq N: ` prefix inside the per-event record and add it when rendering (JS/Py carry `{seq, message}`; Swift/Kotlin bake it into the string, matching Rust). If a lane's string drifts, the `error_includes` assertions in spec/vectors/chain-rules/vectors.json catch it in JS, Python, and Rust — but NOT in Swift or Kotlin, which do not consume the vector registries at all. That gap is pre-existing and out of scope here; the Swift/Kotlin unit tests pin the strings literally instead.

Unverified-locally risk: Tasks 9 (Swift) and 10 (Kotlin) were validated by compile (Swift lib only) and inspection. Whoever executes them must actually run `swift test` and `./gradlew :core:test` at Steps 2/4/5 — those steps are the real gate, and the plan's expected-output lines are predictions, not observations.

Adjacent finding NOT addressed (deliberately out of cluster): actor-id prefix validation. spec/manifest.md:64 requires `human:|ai:|system:|capsule:`, but cli/test/smoke.mjs uses `tool:smoke` and examples/lib/example-kit.mjs uses `tool:renderer`, and sdk-py tests use `h:a`. Those all pass the new rule because they ARE declared participants. Enforcing the prefix pattern would break them and belongs to whichever cluster owns manifest field validation.

## Validation performed while specifying this plan

The steps below were applied to a **copy of the repository outside the working tree** and executed. This is the real output from that run, not a prediction.

<details>
<summary>Expand validation log</summary>

```
Applied the ENTIRE cluster on a copy at /tmp/work-c7 (cp -r of the repo) and ran every lane whose toolchain exists on this machine. Real output:

sdk-js ('cd sdk-js && npm test'): baseline before changes '# tests 57 / # pass 57 / # fail 0'. After Task 3 (builder rejection) and BEFORE Task 4, exactly 6 tests failed — all in dx.test.js — with 'error: 'event actor "human:me" is not a declared participant: add { actor_id: "human:me", role: "..." } to the builder's participants[] (only "system:host" may appear without one)'' (not ok 10, 11, 12, 13, 15, 16). After Task 4 + the new test file: '# tests 65 / # pass 65 / # fail 0'.

sdk-py ('python3 -m venv .venv-c7; .venv-c7/bin/pip install -e '.[dev]'; .venv-c7/bin/python -m pytest'): baseline 182 passed. After Task 7 and BEFORE Task 8, 28 tests failed ('FAILED tests/test_builder.py::test_skill_files_land_in_capsule - ValueError: ...', all of test_dx.py's 6 build paths, test_verifier.py's 11, test_reader.py's 1, test_chain.py::test_verify_chain_clean_passes 'assert False is True'). After Task 8: '192 passed in 0.25s'. '.venv-c7/bin/python -m ruff check src tests' → 'All checks passed!' (needed one '__all__' re-sort, folded into the task).

verifier-rust ('cargo test' and 'cargo test -p capsule-verify'): 'test result: ok. 105 passed' for the lib (was 102 — the three new tests are 'verifier::tests::actor_not_in_participants_surfaces_as_chain_error', 'verifier::tests::unknown_event_kind_surfaces_as_chain_error', 'verifier::tests::all_enum_kinds_accepted', all '... ok'), '7 passed' for parity_against_js_sdk, '4 passed' for spec_registry (was 3; 'test chain_rule_registry_outcomes ... ok').

spec vectors: 'node sdk-js/tools/generate-chain-rule-fixtures.mjs' → 'wrote actor-not-participant.capsule (2554 bytes) / wrote unknown-kind.capsule (2607 bytes)'; '--check' → 'ok actor-not-participant.capsule (2554 bytes) / ok unknown-kind.capsule (2607 bytes)'. 'node tools/check-spec-vectors.mjs' → 'spec vectors: ok (282 vectors)' (was 280). 'node tools/regen-capsule-skill.mjs --check' failed after the chain.md edit ('skills/capsule/skill.json is out of date.') — regenerated, then 'ok'.

Full JS conformance harness ('node tools/run-conformance.mjs'): 'PASS · 11/11 passed · 3.8s total', including the new '[5/11] chain-rule-fixtures-regen ... PASS'.

sdk-swift: 'swift test' is NOT runnable on this machine — only CommandLineTools is installed ('xcode-select -p' → '/Library/Developer/CommandLineTools'), so 'import XCTest' fails with 'error: no such module 'XCTest''. I verified the Swift source changes compile: 'cd sdk-swift && swift build' → 'Build complete!' after every Swift edit (Chain.swift, Reader.swift, Verifier.swift, Builder.swift). The Swift TEST files (RoundTripTests, EncryptionTests, ActorKindTests) were written against the real API but NOT compiled or run — verified by inspection only.

sdk-kotlin: './gradlew :core:test' is NOT runnable — no JVM on this machine ('Unable to locate a Java Runtime'). The Kotlin changes are verified by inspection against the real API only. Two type-safety issues were caught and fixed during inspection: 'actor !in participants' with 'actor: String?' against 'Set<String>' (Kotlin's '@OnlyInputTypes' contains would not type-check — rewritten as 'actor == null || (actor != Chain.HOST_ACTOR && actor !in participants)'), and bare 'emptyList()' in 'assertEquals' (changed to 'emptyList<String>()').
```

</details>

---

## C7 — chain.md step-6 actor rule + the closed `kind` enum

Ten tasks. Tasks 1-4 (sdk-js) are the reference and must land first: Tasks 5-8 mirror them into sdk-py, Task 9/10 into Swift/Kotlin, Task 7 pins the Rust side, and Task 8 ships the conformance vectors that hold all five honest. The exact per-event error strings are the cross-lane contract; Rust already emits the actor string today (`verifier.rs:786`) and every other lane is being brought to match it verbatim.

---

### Task 1: sdk-js — actor + kind rules inside `verifyChain`

**Files:**
- Modify: `sdk-js/src/chain.js:5-5` (constants block), `sdk-js/src/chain.js:72-78` (`verifyChain` head)
- Test: `sdk-js/test/actor-kind.test.js`

**Interfaces:**
- Consumes: `buildChainEvents(bareEvents)` from `sdk-js/src/chain.js:25`
- Produces: `EVENT_KINDS: readonly string[]`, `HOST_ACTOR: "system:host"`, `isValidEventKind(kind): boolean`, `participantActorIds(participants): Set<string>`, `verifyChain(events, options?: { participants })` — all exported from `sdk-js/src/chain.js`

- [ ] **Step 1: Write the failing test**

Create `sdk-js/test/actor-kind.test.js`:

```js
// spec/chain.md step-6 actor rule + the closed `kind` enum.
//
//   - verifyChain flags every event whose actor is neither "system:host"
//     nor a manifest participant, and every event with a kind outside the
//     five-value enum. Error strings match the Rust verifier's shape.
//   - verifyCapsule feeds manifest.participants into that walk.
//   - CapsuleBuilder.appendEvent refuses both at append time, so the
//     reference SDK cannot produce a capsule its own verifiers reject.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CapsuleBuilder,
  CapsuleReader,
  verifyCapsule,
  generateEd25519,
} from "../src/index.js";
import { buildChainEvents, verifyChain } from "../src/chain.js";

const TS = "2026-05-07T12:00:00Z";

const PARTICIPANTS = [{ actor_id: "human:alice", role: "originator", label: "Alice" }];

function seededBuilder(ed, participants = PARTICIPANTS) {
  return new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex, label: "Acme" },
    participants,
    createdAt: TS,
  }).setProgram("# Actor rule\n");
}

test("verifyChain flags an actor that is not a participant", () => {
  const events = buildChainEvents([
    { actor: "human:mallory", kind: "decision", action: "a", target: "t", timestamp: TS, payload: {} },
  ]);
  const result = verifyChain(events, { participants: PARTICIPANTS });
  assert.equal(result.ok, false);
  assert.deepEqual(result.errors, [
    {
      seq: 1,
      message: 'actor "human:mallory" not in manifest.participants and not system:host',
    },
  ]);
});

test("verifyChain accepts system:host without a participant entry", () => {
  const events = buildChainEvents([
    { actor: "system:host", kind: "observation", action: "session_ended", target: "capsule", timestamp: TS, payload: {} },
  ]);
  assert.equal(verifyChain(events, { participants: [] }).ok, true);
});

test("verifyChain rejects a kind outside the closed enum", () => {
  const events = buildChainEvents([
    { actor: "human:alice", kind: "gossip", action: "a", target: "t", timestamp: TS, payload: {} },
  ]);
  const result = verifyChain(events, { participants: PARTICIPANTS });
  assert.equal(result.ok, false);
  assert.deepEqual(result.errors, [
    {
      seq: 1,
      message: 'kind "gossip" is not one of decision, observation, mutation, session, checkpoint',
    },
  ]);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-js && node --test test/actor-kind.test.js`

Expected: FAIL with `not ok 1 - verifyChain flags an actor that is not a participant`, whose diff shows `Expected values to be loosely deep-equal: [] !== [ { seq: 1, message: 'actor "human:mallory" not in manifest.participants and not system:host' } ]` (all three tests fail: the current `verifyChain` accepts both events).

- [ ] **Step 3: Add the enum, the host actor, and the participant-set helper to chain.js**

In `sdk-js/src/chain.js`, replace line 5:

```js
const GENESIS_PREV = Buffer.alloc(32, 0);
```

with:

```js
const GENESIS_PREV = Buffer.alloc(32, 0);

/**
 * The closed `kind` enum from spec/chain.md "Field rules": readers reject
 * unknown kinds, and builders refuse to append them.
 */
export const EVENT_KINDS = Object.freeze([
  "decision",
  "observation",
  "mutation",
  "session",
  "checkpoint",
]);

const EVENT_KIND_SET = new Set(EVENT_KINDS);

/**
 * The one actor a chain event may name without a matching manifest
 * participant — backstop events emitted by the host runtime.
 */
export const HOST_ACTOR = "system:host";

/** True when `kind` is one of the five values spec/chain.md allows. */
export function isValidEventKind(kind) {
  return EVENT_KIND_SET.has(kind);
}

/**
 * Normalize a manifest `participants[]` array into a Set of actor ids.
 * Accepts participant objects ({ actor_id }) or bare actor-id strings.
 */
export function participantActorIds(participants) {
  const out = new Set();
  for (const p of participants ?? []) {
    if (typeof p === "string") out.add(p);
    else if (p && typeof p.actor_id === "string") out.add(p.actor_id);
  }
  return out;
}
```

- [ ] **Step 4: Add the two per-event checks to `verifyChain`**

In `sdk-js/src/chain.js`, replace lines 72-78:

```js
/** Verify a chain. Returns { ok, errors: [{ seq, message }] }. */
export function verifyChain(events) {
  const errors = [];
  let prev = GENESIS_PREV;
  events.forEach((e, i) => {
    const seq = e.seq ?? i + 1;
    if (e.seq !== i + 1) {
```

with:

```js
/**
 * Verify a chain. Returns { ok, errors: [{ seq, message }] }.
 *
 * `options.participants` is the manifest's `participants[]` (objects with
 * `actor_id`, or bare actor-id strings). It defaults to the empty set, so a
 * caller that forgets to pass it fails closed: every actor except
 * "system:host" is rejected. This is spec/chain.md step 6.
 */
export function verifyChain(events, options = {}) {
  const errors = [];
  const participantIds = participantActorIds(options.participants);
  let prev = GENESIS_PREV;
  events.forEach((e, i) => {
    const seq = e.seq ?? i + 1;
    // spec/chain.md step 6 — actor must be a declared participant or the host.
    if (e.actor !== HOST_ACTOR && !participantIds.has(e.actor)) {
      errors.push({
        seq,
        message: `actor ${JSON.stringify(e.actor ?? null)} not in manifest.participants and not system:host`,
      });
    }
    // spec/chain.md "Field rules" — `kind` is a closed enum.
    if (!EVENT_KIND_SET.has(e.kind)) {
      errors.push({
        seq,
        message: `kind ${JSON.stringify(e.kind ?? null)} is not one of ${EVENT_KINDS.join(", ")}`,
      });
    }
    if (e.seq !== i + 1) {
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd sdk-js && node --test test/actor-kind.test.js`

Expected: PASS — `# pass 3 / # fail 0`.

- [ ] **Step 6: Run the full lane suite for regressions**

Run: `cd sdk-js && npm test`

Expected: `# tests 60 / # pass 60 / # fail 0`. (The two bare `verifyChain(events)` calls in `test/strictness.test.js:68` and `:86` now also collect actor errors, but both tests only assert `ok === false` plus a regex over `result.errors`, so they stay green.)

- [ ] **Step 7: Commit**

```bash
git add sdk-js/src/chain.js sdk-js/test/actor-kind.test.js
git commit -m "feat(sdk-js)!: enforce chain.md step-6 actor rule and the kind enum in verifyChain

Adds EVENT_KINDS / HOST_ACTOR / isValidEventKind / participantActorIds and
two per-event checks. verifyChain now takes { participants }; it defaults to
the empty set so a caller that forgets to wire it fails closed. Error strings
match verifier-rust/crates/capsule-verify/src/verifier.rs:786 verbatim.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: sdk-js — feed `manifest.participants` into `verifyCapsule`'s chain walk

**Files:**
- Modify: `sdk-js/src/verifier.js:204-204`
- Test: `sdk-js/test/actor-kind.test.js`

**Interfaces:**
- Consumes: `verifyChain(events, { participants })` from Task 1
- Produces: none (behavioral — `result.chain.errors` now carries actor/kind failures)

- [ ] **Step 1: Write the failing test**

Append to `sdk-js/test/actor-kind.test.js`:

```js
test("verifyCapsule enforces the actor rule against manifest.participants", async () => {
  const ed = generateEd25519();
  const builder = seededBuilder(ed);
  builder.appendEvent({
    actor: "human:alice",
    kind: "decision",
    action: "submit",
    target: "program.md",
    timestamp: TS,
  });
  // Drop the participant AFTER appending: the manifest sealed below no
  // longer declares human:alice, while the chain still names it. Every
  // other commitment (manifest hash, content index, envelope) is
  // recomputed at seal, so only the actor rule can catch this.
  builder.participants = [];
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });

  const reader = await CapsuleReader.fromBytes(bytes);
  const result = await verifyCapsule(reader, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, false);
  assert.equal(result.chain.ok, false);
  assert.ok(
    result.chain.errors.some(
      (e) =>
        e.message === 'actor "human:alice" not in manifest.participants and not system:host',
    ),
    `expected the step-6 actor error, got: ${JSON.stringify(result.chain.errors)}`,
  );
});

test("verifyCapsule stays green when the actor is a declared participant", async () => {
  const ed = generateEd25519();
  const builder = seededBuilder(ed);
  builder.appendEvent({
    actor: "human:alice",
    kind: "decision",
    action: "submit",
    target: "program.md",
    timestamp: TS,
  });
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  const result = await verifyCapsule(bytes, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, true, JSON.stringify(result));
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-js && node --test test/actor-kind.test.js`

Expected: FAIL with `not ok 4 - verifyCapsule enforces the actor rule against manifest.participants` and `error: 'Expected values to be strictly equal: true !== false'` at `assert.equal(result.ok, false)` — `verifyCapsule` currently never passes the manifest to `verifyChain`, so the capsule verifies clean.

- [ ] **Step 3: Pass the manifest's participants through**

In `sdk-js/src/verifier.js`, replace line 204:

```js
      result.chain = verifyChain(events);
```

with:

```js
      result.chain = verifyChain(events, { participants: manifest.participants });
```

(`manifest` is already in scope from `sdk-js/src/verifier.js:91`.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd sdk-js && node --test test/actor-kind.test.js`

Expected: PASS — `# pass 5 / # fail 0`.

- [ ] **Step 5: Run the full lane suite for regressions**

Run: `cd sdk-js && npm test`

Expected: `# tests 62 / # pass 62 / # fail 0`.

- [ ] **Step 6: Commit**

```bash
git add sdk-js/src/verifier.js sdk-js/test/actor-kind.test.js
git commit -m "fix(sdk-js): pass manifest.participants into verifyCapsule's chain walk

Closes the gap where sdk-js verifyChain never saw the manifest, so the
reference verifier accepted capsules that verifier-rust rejects.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: sdk-js — `appendEvent` rejects undeclared actors and unknown kinds

**Files:**
- Modify: `sdk-js/src/builder.js:4-8` (chain import), `sdk-js/src/builder.js:87-102` (`appendEvent`), `sdk-js/src/index.js:22-26` (re-exports), `sdk-js/src/index.d.ts:235-238` (`verifyChain` declaration)
- Test: `sdk-js/test/actor-kind.test.js`

**Interfaces:**
- Consumes: `isValidEventKind`, `participantActorIds`, `EVENT_KINDS`, `HOST_ACTOR` from Task 1
- Produces: `CapsuleBuilder.appendEvent` now throws `Error` for a non-participant actor or an out-of-enum kind

- [ ] **Step 1: Write the failing test**

Append to `sdk-js/test/actor-kind.test.js`:

```js
test("appendEvent rejects an actor that is not a declared participant", () => {
  const ed = generateEd25519();
  const builder = seededBuilder(ed);
  assert.throws(
    () => builder.appendEvent({ actor: "human:mallory", action: "sneak" }),
    /event actor "human:mallory" is not a declared participant/,
  );
});

test("appendEvent accepts system:host without a participant entry", () => {
  const ed = generateEd25519();
  const builder = seededBuilder(ed, []);
  assert.doesNotThrow(() =>
    builder.appendEvent({ actor: "system:host", action: "session_ended" }),
  );
});

test("appendEvent rejects a kind outside the closed enum", () => {
  const ed = generateEd25519();
  const builder = seededBuilder(ed);
  assert.throws(
    () => builder.appendEvent({ actor: "human:alice", kind: "gossip", action: "a" }),
    /event kind "gossip" is not one of decision, observation, mutation, session, checkpoint/,
  );
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-js && node --test test/actor-kind.test.js`

Expected: FAIL with `not ok 6 - appendEvent rejects an actor that is not a declared participant` and `error: 'Missing expected exception'` (and the same for the kind test) — `appendEvent` currently validates only that `actor` and `action` are truthy.

- [ ] **Step 3: Import the helpers into builder.js**

In `sdk-js/src/builder.js`, replace lines 4-8:

```js
import {
  buildChainEvents,
  eventsToJsonl,
  firstAndEntryHash,
} from "./chain.js";
```

with:

```js
import {
  buildChainEvents,
  eventsToJsonl,
  firstAndEntryHash,
  isValidEventKind,
  participantActorIds,
  EVENT_KINDS,
  HOST_ACTOR,
} from "./chain.js";
```

- [ ] **Step 4: Add the two guards to `appendEvent`**

In `sdk-js/src/builder.js`, replace lines 87-102:

```js
  /**
   * Append a chain event. `actor` and `action` are required; `kind`
   * defaults to "observation", `target` to "capsule", and `timestamp`
   * to the builder's `createdAt` value. Per-call opt-out: { pith: false }
   * skips payload normalization for this event.
   */
  appendEvent(event, options = {}) {
    if (!event.actor || !event.action) {
      throw new Error("event requires actor and action");
    }
    const applyPith = options.pith !== false && this.pith;
    const rawPayload = event.payload ?? {};
    const payload = applyPith ? compressEventPayload(rawPayload) : rawPayload;
    this.bareEvents.push({
      actor: event.actor,
      kind: event.kind ?? "observation",
```

with:

```js
  /**
   * Append a chain event. `actor` and `action` are required; `kind`
   * defaults to "observation", `target` to "capsule", and `timestamp`
   * to the builder's `createdAt` value. Per-call opt-out: { pith: false }
   * skips payload normalization for this event.
   *
   * Rejects (spec/chain.md):
   *   - a `kind` outside the closed enum, and
   *   - an `actor` that is neither "system:host" nor a declared
   *     participant. The builder never auto-registers participants:
   *     declaring who may act is the caller's decision, and a capsule
   *     built otherwise would fail every conformant verifier.
   */
  appendEvent(event, options = {}) {
    if (!event.actor || !event.action) {
      throw new Error("event requires actor and action");
    }
    const kind = event.kind ?? "observation";
    if (!isValidEventKind(kind)) {
      throw new Error(
        `event kind ${JSON.stringify(kind)} is not one of ${EVENT_KINDS.join(", ")}`,
      );
    }
    if (event.actor !== HOST_ACTOR && !participantActorIds(this.participants).has(event.actor)) {
      throw new Error(
        `event actor ${JSON.stringify(event.actor)} is not a declared participant: ` +
          `add { actor_id: ${JSON.stringify(event.actor)}, role: "..." } to the builder's ` +
          `participants[] (only "system:host" may appear without one)`,
      );
    }
    const applyPith = options.pith !== false && this.pith;
    const rawPayload = event.payload ?? {};
    const payload = applyPith ? compressEventPayload(rawPayload) : rawPayload;
    this.bareEvents.push({
      actor: event.actor,
      kind,
```

(The participant set is recomputed on every call so that mutating `builder.participants` between appends behaves predictably — Task 2's test depends on this.)

- [ ] **Step 5: Export the new chain symbols and update the type declarations**

In `sdk-js/src/index.js`, replace lines 22-26:

```js
export {
  buildChainEvents,
  hashEvent,
  verifyChain,
} from "./chain.js";
```

with:

```js
export {
  buildChainEvents,
  hashEvent,
  verifyChain,
  isValidEventKind,
  participantActorIds,
  EVENT_KINDS,
  HOST_ACTOR,
} from "./chain.js";
```

In `sdk-js/src/index.d.ts`, replace lines 235-238:

```ts
export function verifyChain(events: ChainEvent[]): {
  ok: boolean;
  errors: Array<{ seq: number; message: string }>;
};
```

with:

```ts
export type EventKind =
  | "decision"
  | "observation"
  | "mutation"
  | "session"
  | "checkpoint";

export const EVENT_KINDS: readonly EventKind[];
export const HOST_ACTOR: "system:host";
export function isValidEventKind(kind: unknown): kind is EventKind;
export function participantActorIds(
  participants?: Array<Participant | string> | null,
): Set<string>;

export function verifyChain(
  events: ChainEvent[],
  options?: { participants?: Array<Participant | string> },
): {
  ok: boolean;
  errors: Array<{ seq: number; message: string }>;
};
```

(`Participant` is already declared at `sdk-js/src/index.d.ts:50`.)

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd sdk-js && node --test test/actor-kind.test.js`

Expected: PASS — `# pass 8 / # fail 0`.

- [ ] **Step 7: Run the full lane suite and record the breakage**

Run: `cd sdk-js && npm test`

Expected: FAIL — `# tests 65 / # pass 59 / # fail 6`. Exactly six failures, all in `test/dx.test.js`, each with:
`error: 'event actor "human:me" is not a declared participant: add { actor_id: "human:me", role: "..." } to the builder's participants[] (only "system:host" may appear without one)'`
(`not ok 10`, `11`, `12`, `13`, `15`, `16`). This is the intended breaking change; Task 4 fixes the callers.

- [ ] **Step 8: Commit**

```bash
git add sdk-js/src/builder.js sdk-js/src/index.js sdk-js/src/index.d.ts sdk-js/test/actor-kind.test.js
git commit -m "feat(sdk-js)!: reject undeclared actors and unknown kinds at appendEvent

BREAKING: CapsuleBuilder.appendEvent now throws when actor is neither
system:host nor a declared participant, and when kind is outside the
chain.md enum. No auto-registration — declaring who may act is the host's
decision. Callers are updated in the next commit.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: sdk-js / examples / README — fix the callers the builder guard breaks

**Files:**
- Modify: `sdk-js/test/dx.test.js:25-25`, `:49-49`, `:64-66`, `:83-83`, `:105-105`, `:132-132`
- Modify: `examples/quickstart/quickstart.mjs:21-21`
- Modify: `sdk-js/README.md:52-52`
- Test: `sdk-js/test/dx.test.js`, `examples/quickstart/quickstart.mjs`

**Interfaces:**
- Consumes: `CapsuleBuilder({ participants })` from Task 3
- Produces: none

- [ ] **Step 1: Declare `human:me` in the six dx.test.js builders**

In `sdk-js/test/dx.test.js`, apply these six replacements in order.

Line 25:
```js
  const bytes = await new CapsuleBuilder({ originator: { ...keys, label: "MyApp" } })
```
→
```js
  const bytes = await new CapsuleBuilder({
    originator: { ...keys, label: "MyApp" },
    participants: [{ actor_id: "human:me", role: "originator" }],
  })
```

Line 49:
```js
    new CapsuleBuilder({ originator: keys, createdAt })
```
→
```js
    new CapsuleBuilder({
      originator: keys,
      createdAt,
      participants: [{ actor_id: "human:me", role: "originator" }],
    })
```

Lines 64-66:
```js
  const bytes = await new CapsuleBuilder({
    originator: { publicKey: keys.publicKeyHex.toUpperCase(), label: "HexApp" },
  })
```
→
```js
  const bytes = await new CapsuleBuilder({
    originator: { publicKey: keys.publicKeyHex.toUpperCase(), label: "HexApp" },
    participants: [{ actor_id: "human:me", role: "originator" }],
  })
```

Line 83:
```js
  const bytes = await new CapsuleBuilder({ originator: keys, createdAt: "2026-07-20T12:00:00Z" })
```
→
```js
  const bytes = await new CapsuleBuilder({
    originator: keys,
    createdAt: "2026-07-20T12:00:00Z",
    participants: [{ actor_id: "human:me", role: "originator" }],
  })
```

Line 105:
```js
  const bytes = await new CapsuleBuilder({ originator: { ...signer, label: "Enc" } })
```
→
```js
  const bytes = await new CapsuleBuilder({
    originator: { ...signer, label: "Enc" },
    participants: [{ actor_id: "human:me", role: "originator" }],
  })
```

Line 132:
```js
  const bytes = await new CapsuleBuilder({ originator: signer })
```
→
```js
  const bytes = await new CapsuleBuilder({
    originator: signer,
    participants: [{ actor_id: "human:me", role: "originator" }],
  })
```

(`sdk-js/test/dx.test.js:147`, `new CapsuleBuilder({ originator: keys }).setProgram("# X\n")`, appends no event and stays as-is.)

- [ ] **Step 2: Run the lane suite to verify it passes**

Run: `cd sdk-js && npm test`

Expected: PASS — `# tests 65 / # pass 65 / # fail 0`.

- [ ] **Step 3: Declare participants in the CI-gated quickstart**

In `examples/quickstart/quickstart.mjs`, replace lines 21-22:

```js
const bytes = await new CapsuleBuilder({ originator: { ...keys, label: "MyApp" } })
  .setProgram("# Quarterly report\n\nDraft written by Alice, reviewed by AI.\n")
```

with:

```js
const bytes = await new CapsuleBuilder({
  originator: { ...keys, label: "MyApp" },
  // Every event actor must be declared here (or be the literal
  // "system:host") — spec/chain.md step 6. appendEvent enforces it.
  participants: [
    { actor_id: "human:alice", role: "originator", label: "Alice" },
    { actor_id: "ai:assistant", role: "advisor", label: "AI advisor" },
  ],
})
  .setProgram("# Quarterly report\n\nDraft written by Alice, reviewed by AI.\n")
```

- [ ] **Step 4: Run the quickstart example**

Run: `cd examples/quickstart && npm test`

Expected: PASS — output ends with `event 1: human:alice wrote_draft`, `event 2: ai:assistant suggested_edits`, `quickstart: ok`.

- [ ] **Step 5: Mirror the change into the README so the copy-paste path matches**

In `sdk-js/README.md`, replace lines 52-53 (inside the quickstart fence):

```js
const bytes = await new CapsuleBuilder({ originator: { ...keys, label: "MyApp" } })
  .setProgram("# Quarterly report\n\nDraft written by Alice, reviewed by AI.\n")
```

with the identical block used in Step 3:

```js
const bytes = await new CapsuleBuilder({
  originator: { ...keys, label: "MyApp" },
  // Every event actor must be declared here (or be the literal
  // "system:host") — spec/chain.md step 6. appendEvent enforces it.
  participants: [
    { actor_id: "human:alice", role: "originator", label: "Alice" },
    { actor_id: "ai:assistant", role: "advisor", label: "AI advisor" },
  ],
})
  .setProgram("# Quarterly report\n\nDraft written by Alice, reviewed by AI.\n")
```

- [ ] **Step 6: Run the full JS conformance harness for regressions**

Run: `node tools/run-conformance.mjs`

Expected: `PASS · 10/10 passed` — every target green, including `cli`, `example-quickstart`, and the three `example-generic-*` targets (whose builders already declare `human:cli`/`tool:smoke` and `human:originator`/`tool:renderer`, so they need no edit).

- [ ] **Step 7: Commit**

```bash
git add sdk-js/test/dx.test.js sdk-js/README.md examples/quickstart/quickstart.mjs
git commit -m "test(sdk-js): declare event actors as participants in dx tests and quickstart

Follows the appendEvent guard: the six dx.test.js builders and the
CI-gated README quickstart now declare their actors. No other appendEvent
caller in the repo needed a change — basic/pith/federation tests, the
tamper-fixture generator, cli smoke, and examples/lib already declare theirs.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: sdk-py — actor + kind rules in `verify_chain`, wired through `verify_capsule`

**Files:**
- Modify: `sdk-py/src/capsule/chain.py:10-11` (constants), `sdk-py/src/capsule/chain.py:88-94` (`verify_chain` head)
- Modify: `sdk-py/src/capsule/verifier.py:207-207`
- Modify: `sdk-py/src/capsule/__init__.py:16-23`, `sdk-py/src/capsule/__init__.py:112-112`
- Test: `sdk-py/tests/test_actor_kind.py`

**Interfaces:**
- Consumes: `build_chain_events(bare_events)` from `sdk-py/src/capsule/chain.py:37`
- Produces: `EVENT_KINDS: tuple[str, ...]`, `HOST_ACTOR: str`, `is_valid_event_kind(kind) -> bool`, `participant_actor_ids(participants) -> set[str]`, `verify_chain(events, *, participants=None) -> ChainResult`

- [ ] **Step 1: Write the failing test**

Create `sdk-py/tests/test_actor_kind.py`:

```python
"""spec/chain.md step-6 actor rule + the closed ``kind`` enum.

Mirrors sdk-js/test/actor-kind.test.js:

  - verify_chain flags every event whose actor is neither "system:host"
    nor a manifest participant, and every event with a kind outside the
    five-value enum. Error strings match the Rust verifier's shape.
  - verify_capsule feeds manifest["participants"] into that walk.
  - CapsuleBuilder.append_event refuses both at append time, so the SDK
    cannot produce a capsule its own verifiers reject.
"""

from __future__ import annotations

import pytest

from capsule import (
    CapsuleBuilder,
    CapsuleReader,
    build_chain_events,
    generate_ed25519,
    verify_capsule,
    verify_chain,
)

TS = "2026-05-07T12:00:00Z"
PARTICIPANTS = [{"actor_id": "human:alice", "role": "originator", "label": "Alice"}]


def _bare(actor: str = "human:alice", kind: str = "decision") -> list[dict]:
    return [
        {
            "actor": actor,
            "kind": kind,
            "action": "a",
            "target": "t",
            "timestamp": TS,
            "payload": {},
        }
    ]


def _builder(kp, participants=None) -> CapsuleBuilder:
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": "Acme"},
        participants=PARTICIPANTS if participants is None else participants,
        created_at=TS,
    )
    builder.set_program("# Actor rule\n")
    return builder


def _seal(builder, kp) -> bytes:
    return builder.seal(
        signers=[
            {"role": "originator", "public_key": kp.public_key, "private_key": kp.private_key}
        ],
        signed_at=TS,
    )


def test_verify_chain_flags_actor_not_in_participants():
    events = build_chain_events(_bare(actor="human:mallory"))
    result = verify_chain(events, participants=PARTICIPANTS)
    assert result["ok"] is False
    assert result["errors"] == [
        {
            "seq": 1,
            "message": 'actor "human:mallory" not in manifest.participants and not system:host',
        }
    ]


def test_verify_chain_accepts_system_host_without_participant():
    events = build_chain_events(_bare(actor="system:host", kind="observation"))
    assert verify_chain(events, participants=[])["ok"] is True


def test_verify_chain_rejects_unknown_kind():
    events = build_chain_events(_bare(kind="gossip"))
    result = verify_chain(events, participants=PARTICIPANTS)
    assert result["ok"] is False
    assert result["errors"] == [
        {
            "seq": 1,
            "message": (
                'kind "gossip" is not one of decision, observation, mutation, '
                "session, checkpoint"
            ),
        }
    ]


def test_verify_capsule_enforces_actor_rule_against_manifest_participants():
    kp = generate_ed25519()
    builder = _builder(kp)
    builder.append_event(
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "submit",
            "target": "program.md",
            "timestamp": TS,
        }
    )
    # Drop the participant AFTER appending: the manifest sealed below no
    # longer declares human:alice, while the chain still names it. Every
    # other commitment is recomputed at seal, so only the actor rule can
    # catch this.
    builder.participants = []
    data = _seal(builder, kp)

    result = verify_capsule(CapsuleReader.from_bytes(data), allowlist=[kp.public_key_hex])
    assert result["ok"] is False
    assert result["chain"]["ok"] is False
    assert any(
        e["message"] == 'actor "human:alice" not in manifest.participants and not system:host'
        for e in result["chain"]["errors"]
    ), result["chain"]["errors"]


def test_verify_capsule_green_when_actor_is_declared():
    kp = generate_ed25519()
    builder = _builder(kp)
    builder.append_event(
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "submit",
            "target": "program.md",
            "timestamp": TS,
        }
    )
    result = verify_capsule(_seal(builder, kp), allowlist=[kp.public_key_hex])
    assert result["ok"] is True, result
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-py && python -m pytest tests/test_actor_kind.py -q`

Expected: FAIL with `ImportError: cannot import name 'build_chain_events'`? No — `build_chain_events` is already exported. The real failure is `TypeError: verify_chain() got an unexpected keyword argument 'participants'` on the first three tests, and `assert False` / `assert True is False` on `test_verify_capsule_enforces_actor_rule_against_manifest_participants`. Expect `4 failed, 1 passed`.

- [ ] **Step 3: Add the enum and helpers to chain.py**

In `sdk-py/src/capsule/chain.py`, replace lines 10-11:

```python
GENESIS_PREV_BYTES: bytes = b"\x00" * 32
GENESIS_PREV_HEX: str = "0" * 64
```

with:

```python
GENESIS_PREV_BYTES: bytes = b"\x00" * 32
GENESIS_PREV_HEX: str = "0" * 64

#: The closed ``kind`` enum from spec/chain.md "Field rules". Readers reject
#: unknown kinds, and builders refuse to append them.
EVENT_KINDS: tuple[str, ...] = (
    "decision",
    "observation",
    "mutation",
    "session",
    "checkpoint",
)

_EVENT_KIND_SET = frozenset(EVENT_KINDS)

#: The one actor a chain event may name without a matching manifest
#: participant — backstop events emitted by the host runtime.
HOST_ACTOR = "system:host"


def is_valid_event_kind(kind: object) -> bool:
    """True when ``kind`` is one of the five values spec/chain.md allows."""
    return isinstance(kind, str) and kind in _EVENT_KIND_SET


def participant_actor_ids(participants: object) -> set[str]:
    """Normalize a manifest ``participants[]`` list into a set of actor ids.

    Accepts participant mappings (``{"actor_id": ...}``) or bare actor-id
    strings; anything else is ignored.
    """
    out: set[str] = set()
    if not isinstance(participants, (list, tuple)):
        return out
    for p in participants:
        if isinstance(p, str):
            out.add(p)
        elif isinstance(p, dict) and isinstance(p.get("actor_id"), str):
            out.add(p["actor_id"])
    return out
```

- [ ] **Step 4: Add the two per-event checks to `verify_chain`**

In `sdk-py/src/capsule/chain.py`, replace lines 88-94:

```python
def verify_chain(events: list[dict]) -> ChainResult:
    """Verify a chain. Returns ChainResult with ok and collected errors."""
    errors: list[ChainError] = []
    prev = GENESIS_PREV_BYTES
    for i, e in enumerate(events):
        seq = e.get("seq", i + 1)
        if e.get("seq") != i + 1:
```

with:

```python
def verify_chain(events: list[dict], *, participants: object = None) -> ChainResult:
    """Verify a chain. Returns ChainResult with ok and collected errors.

    ``participants`` is the manifest's ``participants[]``. It defaults to
    the empty set, so a caller that forgets to pass it fails closed: every
    actor except ``"system:host"`` is rejected. This is spec/chain.md
    step 6.
    """
    errors: list[ChainError] = []
    participant_ids = participant_actor_ids(participants)
    prev = GENESIS_PREV_BYTES
    for i, e in enumerate(events):
        seq = e.get("seq", i + 1)
        # spec/chain.md step 6 — actor must be a declared participant or the host.
        actor = e.get("actor")
        if actor != HOST_ACTOR and actor not in participant_ids:
            errors.append(
                {
                    "seq": seq,
                    "message": (
                        f"actor {json.dumps(actor)} not in manifest.participants "
                        "and not system:host"
                    ),
                }
            )
        # spec/chain.md "Field rules" — `kind` is a closed enum.
        if not is_valid_event_kind(e.get("kind")):
            errors.append(
                {
                    "seq": seq,
                    "message": (
                        f"kind {json.dumps(e.get('kind'))} is not one of "
                        + ", ".join(EVENT_KINDS)
                    ),
                }
            )
        if e.get("seq") != i + 1:
```

(`json` is already imported at `sdk-py/src/capsule/chain.py:5`; `json.dumps` is used rather than `repr` so the quoting matches Rust's `{:?}` and JS's `JSON.stringify`.)

- [ ] **Step 5: Pass the manifest's participants through verify_capsule**

In `sdk-py/src/capsule/verifier.py`, replace line 207:

```python
                result["chain"] = verify_chain(events)
```

with:

```python
                result["chain"] = verify_chain(
                    events, participants=manifest.get("participants")
                )
```

- [ ] **Step 6: Re-export the new symbols**

In `sdk-py/src/capsule/__init__.py`, replace lines 16-23:

```python
from .chain import (
    build_chain_events,
    events_from_jsonl,
    events_to_jsonl,
    first_and_entry_hash,
    hash_event,
    verify_chain,
)
```

with:

```python
from .chain import (
    EVENT_KINDS,
    HOST_ACTOR,
    build_chain_events,
    events_from_jsonl,
    events_to_jsonl,
    first_and_entry_hash,
    hash_event,
    is_valid_event_kind,
    participant_actor_ids,
    verify_chain,
)
```

and add `"EVENT_KINDS"`, `"HOST_ACTOR"`, `"is_valid_event_kind"`, `"participant_actor_ids"` to `__all__`. Ruff's `RUF022` requires `__all__` stay sorted, so run `python -m ruff check --fix src` to place them (it moves `"EVENT_KINDS"` and `"HOST_ACTOR"` up after `"CONTENT_INDEX_EXCLUDED"`, and `"is_valid_event_kind"` / `"participant_actor_ids"` into the lowercase run).

- [ ] **Step 7: Run the test to verify it passes**

Run: `cd sdk-py && python -m pytest tests/test_actor_kind.py -q`

Expected: PASS — `5 passed`.

- [ ] **Step 8: Run the full lane suite for regressions**

Run: `cd sdk-py && python -m pytest -q`

Expected: FAIL — 1 failure, `FAILED tests/test_chain.py::test_verify_chain_clean_passes - assert False is True`. The three bare `verify_chain(events)` calls in `tests/test_chain.py:152`, `:170`, `:196` now surface actor errors; only line 152's test asserts `errors == []`. Task 6 fixes it alongside the builder-driven breakage.

- [ ] **Step 9: Commit**

```bash
git add sdk-py/src/capsule/chain.py sdk-py/src/capsule/verifier.py sdk-py/src/capsule/__init__.py sdk-py/tests/test_actor_kind.py
git commit -m "feat(sdk-py)!: enforce chain.md step-6 actor rule and the kind enum

verify_chain gains a keyword-only participants argument (defaulting to the
empty set so it fails closed) and two per-event checks; verify_capsule
passes manifest['participants'] through. Error strings match the Rust
verifier verbatim.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: sdk-py — `append_event` rejection + fix every broken caller

**Files:**
- Modify: `sdk-py/src/capsule/builder.py:10-10` (chain import), `sdk-py/src/capsule/builder.py:99-114` (`append_event`)
- Modify: `sdk-py/tests/test_builder.py:51`, `:144`, `:172`, `:204`, `:343`, `:366`, `:399`
- Modify: `sdk-py/tests/test_reader.py:15`
- Modify: `sdk-py/tests/test_verifier.py:15`, `:160`
- Modify: `sdk-py/tests/test_chain.py:152`, `:170`, `:196`
- Modify: `sdk-py/tests/test_dx.py:29`, `:53`, `:68-70`, `:93`, `:115`, `:143`
- Modify: `sdk-py/README.md:36-36`
- Test: `sdk-py/tests/test_actor_kind.py`

**Interfaces:**
- Consumes: `is_valid_event_kind`, `participant_actor_ids`, `EVENT_KINDS`, `HOST_ACTOR` from Task 5
- Produces: `CapsuleBuilder.append_event` raises `ValueError` for a non-participant actor or an out-of-enum kind

- [ ] **Step 1: Write the failing test**

Append to `sdk-py/tests/test_actor_kind.py`:

```python
def test_append_event_rejects_undeclared_actor():
    kp = generate_ed25519()
    builder = _builder(kp)
    with pytest.raises(ValueError, match='event actor "human:mallory" is not a declared'):
        builder.append_event({"actor": "human:mallory", "action": "sneak"})


def test_append_event_accepts_system_host_without_participant():
    kp = generate_ed25519()
    builder = _builder(kp, participants=[])
    builder.append_event({"actor": "system:host", "action": "session_ended"})
    assert builder.bare_events[0]["actor"] == "system:host"


def test_append_event_rejects_unknown_kind():
    kp = generate_ed25519()
    builder = _builder(kp)
    with pytest.raises(ValueError, match='event kind "gossip" is not one of'):
        builder.append_event({"actor": "human:alice", "kind": "gossip", "action": "a"})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-py && python -m pytest tests/test_actor_kind.py -q -k "append_event"`

Expected: FAIL — `2 failed, 1 passed`, both failures `DID NOT RAISE <class 'ValueError'>`.

- [ ] **Step 3: Import the helpers into builder.py**

In `sdk-py/src/capsule/builder.py`, replace line 10:

```python
from .chain import build_chain_events, events_to_jsonl, first_and_entry_hash
```

with:

```python
from .chain import (
    EVENT_KINDS,
    HOST_ACTOR,
    build_chain_events,
    events_to_jsonl,
    first_and_entry_hash,
    is_valid_event_kind,
    participant_actor_ids,
)
```

- [ ] **Step 4: Add the two guards to `append_event`**

In `sdk-py/src/capsule/builder.py`, replace lines 100-114:

```python
        """Append a chain event.

        ``actor`` and ``action`` are required; ``kind`` defaults to
        "observation", ``target`` to "capsule", and ``timestamp`` to the
        builder's ``created_at`` value.
        """
        for required in ("actor", "action"):
            if not event.get(required):
                raise ValueError(f"event requires {required}")
        apply_pith = self.pith if pith is None else (self.pith and pith)
        raw_payload = event.get("payload", {})
        payload = compress_event_payload(raw_payload) if apply_pith else raw_payload
        bare = {
            "actor": event["actor"],
            "kind": event.get("kind", "observation"),
```

with:

```python
        """Append a chain event.

        ``actor`` and ``action`` are required; ``kind`` defaults to
        "observation", ``target`` to "capsule", and ``timestamp`` to the
        builder's ``created_at`` value.

        Rejects (spec/chain.md):
          - a ``kind`` outside the closed enum, and
          - an ``actor`` that is neither ``"system:host"`` nor a declared
            participant. The builder never auto-registers participants:
            declaring who may act is the caller's decision, and a capsule
            built otherwise would fail every conformant verifier.
        """
        for required in ("actor", "action"):
            if not event.get(required):
                raise ValueError(f"event requires {required}")
        kind = event.get("kind", "observation")
        if not is_valid_event_kind(kind):
            raise ValueError(
                f"event kind {json.dumps(kind)} is not one of " + ", ".join(EVENT_KINDS)
            )
        actor = event["actor"]
        if actor != HOST_ACTOR and actor not in participant_actor_ids(self.participants):
            raise ValueError(
                f"event actor {json.dumps(actor)} is not a declared participant: add "
                f'{{"actor_id": {json.dumps(actor)}, "role": "..."}} to the builder\'s '
                'participants[] (only "system:host" may appear without one)'
            )
        apply_pith = self.pith if pith is None else (self.pith and pith)
        raw_payload = event.get("payload", {})
        payload = compress_event_payload(raw_payload) if apply_pith else raw_payload
        bare = {
            "actor": actor,
            "kind": kind,
```

(`json` is already imported at `sdk-py/src/capsule/builder.py:5`.)

- [ ] **Step 5: Run the test and record the lane breakage**

Run: `cd sdk-py && python -m pytest -q`

Expected: FAIL — `28 failed, 163 passed`. The failures are: `tests/test_chain.py::test_verify_chain_clean_passes`; all 6 build paths in `tests/test_dx.py`; 10 in `tests/test_builder.py`; 11 in `tests/test_verifier.py`; 1 in `tests/test_reader.py` — every one raising `ValueError` from `src/capsule/builder.py` line ~131. Every failing site is a `participants=[]` (or absent) builder that appends a non-`system:host` actor.

- [ ] **Step 6: Declare the actor at every broken build site**

In `sdk-py/tests/test_builder.py`, replace the line `        participants=[],` at lines **51** and **204** with:

```python
        participants=[{"actor_id": "human:alice", "role": "originator"}],
```

and at lines **144**, **172**, **343**, **366**, **399** with:

```python
        participants=[{"actor_id": "h:a", "role": "originator"}],
```

(Leave `participants=[]` at `test_builder.py:77`, `:95`, `:111`, `:123`, `:129`, `:135`, `:436` — those tests append no event.)

In `sdk-py/tests/test_reader.py`, replace `        participants=[],` at line **15** with:

```python
        participants=[{"actor_id": "human:alice", "role": "originator"}],
```

(Leave `:153`, `:185`, `:220` — no appended events.)

In `sdk-py/tests/test_verifier.py`, replace `        participants=[],` at lines **15** and **160** with:

```python
        participants=[{"actor_id": "human:alice", "role": "originator"}],
```

In `sdk-py/tests/test_chain.py`, replace all three occurrences of:

```python
    result = verify_chain(events)
```

(lines 152, 170, 196) with:

```python
    result = verify_chain(events, participants=[{"actor_id": "human:alice"}, {"actor_id": "h:a"}])
```

In `sdk-py/tests/test_dx.py`, apply these five replacements (the second matches twice, at lines 115 and 143):

```python
    builder = CapsuleBuilder(originator=keys)
    builder.set_program("# Hello capsule\n")
```
→
```python
    builder = CapsuleBuilder(originator=keys, participants=[{"actor_id": "human:me", "role": "originator"}])
    builder.set_program("# Hello capsule\n")
```

```python
    builder = CapsuleBuilder(originator=signer)
```
→
```python
    builder = CapsuleBuilder(originator=signer, participants=[{"actor_id": "human:me", "role": "originator"}])
```

```python
        builder = CapsuleBuilder(originator=keys, created_at=created_at)
```
→
```python
        builder = CapsuleBuilder(
            originator=keys, created_at=created_at, participants=[{"actor_id": "human:me", "role": "originator"}]
        )
```

```python
    builder = CapsuleBuilder(
        originator={"public_key": keys.public_key_hex.upper(), "label": "HexApp"}
    )
```
→
```python
    builder = CapsuleBuilder(
        originator={"public_key": keys.public_key_hex.upper(), "label": "HexApp"},
        participants=[{"actor_id": "human:me", "role": "originator"}],
    )
```

```python
    builder = CapsuleBuilder(originator=keys, created_at="2026-07-20T12:00:00Z")
```
→
```python
    builder = CapsuleBuilder(
        originator=keys, created_at="2026-07-20T12:00:00Z", participants=[{"actor_id": "human:me", "role": "originator"}]
    )
```

(`test_dx.py:158`, `CapsuleBuilder(originator=keys)` inside `test_helpful_errors_on_missing_signer_material`, appends no event and stays as-is.)

In `sdk-py/README.md`, replace line 36:

```python
builder = CapsuleBuilder(originator=keys)  # or {"public_key": ..., "label": "MyApp"}
```

with:

```python
builder = CapsuleBuilder(
    originator=keys,  # or {"public_key": ..., "label": "MyApp"}
    # Every event actor must be declared here (or be the literal
    # "system:host") — spec/chain.md step 6. append_event enforces it.
    participants=[
        {"actor_id": "human:alice", "role": "originator", "label": "Alice"},
        {"actor_id": "ai:assistant", "role": "advisor", "label": "AI advisor"},
    ],
)
```

- [ ] **Step 7: Run the full lane suite for regressions**

Run: `cd sdk-py && python -m pytest -q && python -m ruff check src tests`

Expected: `192 passed` and `All checks passed!`.

- [ ] **Step 8: Commit**

```bash
git add sdk-py/src/capsule/builder.py sdk-py/tests sdk-py/README.md
git commit -m "feat(sdk-py)!: reject undeclared actors and unknown kinds at append_event

BREAKING: append_event raises ValueError when actor is neither system:host
nor a declared participant, and when kind is outside the chain.md enum.
Every test that built with participants=[] and appended a real actor now
declares it; the README quickstart matches.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: verifier-rust — add the `kind` enum check next to the existing actor check

**Files:**
- Modify: `verifier-rust/crates/capsule-verify/src/chain.rs:18-19`
- Modify: `verifier-rust/crates/capsule-verify/src/verifier.rs:37-37`, `verifier-rust/crates/capsule-verify/src/verifier.rs:783-790`
- Modify: `verifier-rust/crates/capsule-verify/src/lib.rs:26-26`
- Test: `verifier-rust/crates/capsule-verify/src/verifier.rs` (`mod tests`, inserted before `clean_capsule_passes_l2` at line 922)

**Interfaces:**
- Consumes: `chain_walk_into(events, manifest, envelope, chain_check, errors, scope)` at `verifier.rs:762`; `parse_chain_jsonl`, `Manifest`, `Envelope`, `ChainCheck`, `TopError`, `TopErrorScope` — all already in scope via `use super::*`
- Produces: `capsule_verify::EVENT_KINDS: [&str; 5]`, `capsule_verify::is_valid_event_kind(&str) -> bool`

- [ ] **Step 1: Write the failing test**

In `verifier-rust/crates/capsule-verify/src/verifier.rs`, insert immediately before the doc comment `/// L2 happy path. The clean fixture must verify cleanly with no errors,` (line 922):

```rust
    /// chain.md step 6: an actor that is neither a declared participant
    /// nor `system:host` must surface a per-event chain error. Pins the
    /// exact message shape — the JS, Python, Swift, and Kotlin lanes
    /// reproduce this string verbatim (minus the `seq N: ` prefix, which
    /// each lane adds when rendering).
    #[test]
    fn actor_not_in_participants_surfaces_as_chain_error() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).unwrap();
        let manifest: Manifest = serde_json::from_slice(map.get("manifest.json").unwrap()).unwrap();
        let envelope: Envelope =
            serde_json::from_slice(map.get("provenance/envelope.json").unwrap()).unwrap();
        let mut events = parse_chain_jsonl(map.get("chain/events.jsonl").unwrap()).unwrap();
        events[0].actor = "human:mallory".to_string();

        let mut chain_check = ChainCheck::default();
        let mut errors: Vec<TopError> = Vec::new();
        chain_walk_into(
            &events,
            &manifest,
            &envelope,
            &mut chain_check,
            &mut errors,
            TopErrorScope::Outer,
        );

        assert!(!chain_check.ok, "undeclared actor must fail the chain check");
        assert!(
            chain_check.errors.iter().any(|e| e
                == "seq 1: actor \"human:mallory\" not in manifest.participants and not system:host"),
            "expected the step-6 actor error; got: {:?}",
            chain_check.errors
        );
    }

    /// chain.md "Field rules": `kind` is a closed enum and readers reject
    /// unknown kinds.
    #[test]
    fn unknown_event_kind_surfaces_as_chain_error() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).unwrap();
        let manifest: Manifest = serde_json::from_slice(map.get("manifest.json").unwrap()).unwrap();
        let envelope: Envelope =
            serde_json::from_slice(map.get("provenance/envelope.json").unwrap()).unwrap();
        let mut events = parse_chain_jsonl(map.get("chain/events.jsonl").unwrap()).unwrap();
        events[0].kind = "gossip".to_string();

        let mut chain_check = ChainCheck::default();
        let mut errors: Vec<TopError> = Vec::new();
        chain_walk_into(
            &events,
            &manifest,
            &envelope,
            &mut chain_check,
            &mut errors,
            TopErrorScope::Outer,
        );

        assert!(!chain_check.ok, "unknown kind must fail the chain check");
        assert!(
            chain_check.errors.iter().any(|e| e
                == "seq 1: kind \"gossip\" is not one of decision, observation, mutation, session, checkpoint"),
            "expected the kind-enum error; got: {:?}",
            chain_check.errors
        );
    }

    /// Every kind in the enum passes the same walk.
    #[test]
    fn all_enum_kinds_accepted() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).unwrap();
        let manifest: Manifest = serde_json::from_slice(map.get("manifest.json").unwrap()).unwrap();
        let envelope: Envelope =
            serde_json::from_slice(map.get("provenance/envelope.json").unwrap()).unwrap();
        let base = parse_chain_jsonl(map.get("chain/events.jsonl").unwrap()).unwrap();

        for kind in EVENT_KINDS {
            let mut events = base.clone();
            events[0].kind = kind.to_string();
            let mut chain_check = ChainCheck::default();
            let mut errors: Vec<TopError> = Vec::new();
            chain_walk_into(
                &events,
                &manifest,
                &envelope,
                &mut chain_check,
                &mut errors,
                TopErrorScope::Outer,
            );
            assert!(
                !chain_check.errors.iter().any(|e| e.contains("is not one of")),
                "kind {kind:?} must be accepted; got: {:?}",
                chain_check.errors
            );
        }
    }

```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd verifier-rust && cargo test -p capsule-verify --lib unknown_event_kind_surfaces_as_chain_error`

Expected: FAIL to compile — `error[E0425]: cannot find value 'EVENT_KINDS' in this scope` (from `all_enum_kinds_accepted`). After only the `EVENT_KINDS` import is added, it fails at runtime instead: `unknown kind must fail the chain check` panics on `assert!(!chain_check.ok, ...)`, because the current `chain_walk_into` never inspects `kind`.

- [ ] **Step 3: Add the enum + predicate to chain.rs**

In `verifier-rust/crates/capsule-verify/src/chain.rs`, replace lines 18-19:

```rust
/// Genesis previous-hash: 32 zero bytes.
const GENESIS_PREV: [u8; 32] = [0u8; 32];
```

with:

```rust
/// Genesis previous-hash: 32 zero bytes.
const GENESIS_PREV: [u8; 32] = [0u8; 32];

/// The closed `kind` enum from `chain.md` "Field rules". Readers reject
/// unknown kinds; the reference builders refuse to append them.
pub const EVENT_KINDS: [&str; 5] = [
    "decision",
    "observation",
    "mutation",
    "session",
    "checkpoint",
];

/// True when `kind` is one of the five values `chain.md` allows.
pub fn is_valid_event_kind(kind: &str) -> bool {
    EVENT_KINDS.contains(&kind)
}
```

- [ ] **Step 4: Add the kind check to `chain_walk_into` and re-export**

In `verifier-rust/crates/capsule-verify/src/verifier.rs`, replace line 37:

```rust
use crate::chain::{first_and_entry_hash, verify_chain};
```

with:

```rust
use crate::chain::{first_and_entry_hash, is_valid_event_kind, verify_chain, EVENT_KINDS};
```

Then replace lines 783-790:

```rust
    for e in events {
        if e.actor != "system:host" && !participant_ids.contains(e.actor.as_str()) {
            chain_check.errors.push(format!(
                "seq {}: actor {:?} not in manifest.participants and not system:host",
                e.seq, e.actor
            ));
        }
    }
```

with:

```rust
    for e in events {
        if e.actor != "system:host" && !participant_ids.contains(e.actor.as_str()) {
            chain_check.errors.push(format!(
                "seq {}: actor {:?} not in manifest.participants and not system:host",
                e.seq, e.actor
            ));
        }
        // Per-event `kind` enum. chain.md declares a closed set and says
        // "Readers reject unknown kinds."
        if !is_valid_event_kind(&e.kind) {
            chain_check.errors.push(format!(
                "seq {}: kind {:?} is not one of {}",
                e.seq,
                e.kind,
                EVENT_KINDS.join(", ")
            ));
        }
    }
```

In `verifier-rust/crates/capsule-verify/src/lib.rs`, replace line 26:

```rust
pub use decrypt::{decrypt_inner_zip, DecryptError, DecryptionMetadata, KeyBundle};
```

with:

```rust
pub use chain::{is_valid_event_kind, EVENT_KINDS};
pub use decrypt::{decrypt_inner_zip, DecryptError, DecryptionMetadata, KeyBundle};
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd verifier-rust && cargo test -p capsule-verify --lib actor_not_in_participants_surfaces_as_chain_error unknown_event_kind_surfaces_as_chain_error all_enum_kinds_accepted`

Expected: PASS — three lines of `... ok` and `test result: ok. 3 passed; 0 failed`.

- [ ] **Step 6: Run the full lane suite for regressions**

Run: `cd verifier-rust && cargo test --workspace`

Expected: `test result: ok. 105 passed; 0 failed` for the `capsule-verify` lib (up from 102), `7 passed` for `parity_against_js_sdk`, `3 passed` for `spec_registry`, `0 failed` everywhere.

- [ ] **Step 7: Commit**

```bash
git add verifier-rust/crates/capsule-verify/src/chain.rs verifier-rust/crates/capsule-verify/src/verifier.rs verifier-rust/crates/capsule-verify/src/lib.rs
git commit -m "feat(verifier-rust): reject chain events whose kind is outside the enum

chain.md declares kind a closed set; the verifier modelled it as a bare
String and never checked it. Adds EVENT_KINDS + is_valid_event_kind and the
per-event check beside the existing actor whitelist. Also pins the actor
error string with a regression test — four other lanes copy it verbatim.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 8: spec — negative conformance vectors for both rules, wired into three lanes

**Files:**
- Create: `sdk-js/tools/generate-chain-rule-fixtures.mjs`
- Create: `spec/vectors/chain-rules/vectors.json`
- Create: `spec/vectors/chain-rules/output/actor-not-participant.capsule` (generated)
- Create: `spec/vectors/chain-rules/output/unknown-kind.capsule` (generated)
- Modify: `spec/chain.md:29-32`, `spec/chain.md:105-109`
- Modify: `tools/run-conformance.mjs:93-93` (new target before `spec-vectors`)
- Modify: `sdk-py/tests/test_spec_registry.py:7-9`, `:30-30`, `:101-101`
- Modify: `verifier-rust/tests/spec_registry.rs:7-9`, `:132-132`
- Test: `sdk-py/tests/test_spec_registry.py`, `verifier-rust/tests/spec_registry.rs`, `tools/check-spec-vectors.mjs`

**Interfaces:**
- Consumes: `CapsuleBuilder` (Tasks 1-3), `builder.participants`, `builder.bareEvents`; the checked-in keypair at `spec/vectors/tamper-detection/output/keys.json`
- Produces: `spec/vectors/chain-rules/vectors.json` (outcome collection with `keys_file`, `vectors[].expected.{ok,failing,error_includes}` — the same schema as `spec/vectors/tamper-detection/vectors.json`)

- [ ] **Step 1: Write the fixture generator**

Create `sdk-js/tools/generate-chain-rule-fixtures.mjs`:

```js
#!/usr/bin/env node
// generate-chain-rule-fixtures.mjs
//
// Generates the chain-rule conformance fixtures under
// spec/vectors/chain-rules/output/. Both capsules are fully
// self-consistent — real signatures, correct manifest hash, correct
// content index — and violate exactly one per-event rule from
// spec/chain.md:
//
//   actor-not-participant.capsule  event actor is absent from
//                                  manifest.participants[] and is not
//                                  the literal "system:host" (step 6)
//   unknown-kind.capsule           event kind is outside the closed
//                                  enum decision | observation |
//                                  mutation | session | checkpoint
//
// Signed with the checked-in throwaway conformance keypair from
// spec/vectors/tamper-detection/output/keys.json, so the whole vector
// tree shares one originator key.
//
// The reference builder REFUSES to emit either shape — that is the
// point of the builder-side guard. This generator therefore reaches
// past appendEvent() (mutating builder.participants after the append,
// and pushing a bare event directly) to synthesize what a
// non-conformant writer would produce. Fixture -> expected outcome
// lives in spec/vectors/chain-rules/vectors.json. Pass --check to
// compare generated bytes with the checked-in fixtures.

import { readFile, mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { CapsuleBuilder } from "../src/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..");
const KEYS = join(REPO_ROOT, "spec", "vectors", "tamper-detection", "output", "keys.json");
const OUT_DIR = join(REPO_ROOT, "spec", "vectors", "chain-rules", "output");
const CHECK = process.argv.includes("--check");

// Deterministic timestamps keep the fixtures byte-stable across runs.
const SIGNED_AT = "2026-05-08T12:00:00Z";

function newBuilder(originatorPublicKey) {
  const builder = new CapsuleBuilder({
    originator: { publicKey: originatorPublicKey, label: "ConformanceOriginator" },
    participants: [{ actor_id: "human:origin", role: "originator", label: "Origin" }],
    createdAt: SIGNED_AT,
  });
  builder.setProgram("# Chain Rule Fixture\n\nOne event, one broken field rule.\n");
  return builder;
}

/** Event actor is not in manifest.participants and is not system:host. */
async function buildActorNotParticipant(keys, signer) {
  const builder = newBuilder(keys.originator.publicKey);
  builder.appendEvent({
    actor: "human:origin",
    kind: "decision",
    action: "approved",
    target: "program.md",
    timestamp: SIGNED_AT,
    payload: { amount: 4242, note: "actor-not-participant fixture event" },
  });
  // Strip the declaration AFTER the append: the sealed manifest carries
  // participants: [] while the chain still names human:origin.
  builder.participants = [];
  return Buffer.from(await builder.seal({ signers: [signer], signedAt: SIGNED_AT }));
}

/** Event kind is outside the closed enum. */
async function buildUnknownKind(keys, signer) {
  const builder = newBuilder(keys.originator.publicKey);
  // appendEvent() rejects this kind by design, so push the bare event
  // straight onto the builder's queue. seal() hashes and signs it
  // normally, producing a capsule that is valid everywhere except the
  // kind enum.
  builder.bareEvents.push({
    actor: "human:origin",
    kind: "gossip",
    action: "approved",
    target: "program.md",
    timestamp: SIGNED_AT,
    payload: { amount: 4242, note: "unknown-kind fixture event" },
  });
  return Buffer.from(await builder.seal({ signers: [signer], signedAt: SIGNED_AT }));
}

async function main() {
  await mkdir(OUT_DIR, { recursive: true });
  const keys = JSON.parse(await readFile(KEYS, "utf8"));
  const signer = {
    role: "originator",
    publicKey: keys.originator.publicKey,
    privateKey: keys.originator.privateKey,
  };

  const fixtures = {
    "actor-not-participant.capsule": await buildActorNotParticipant(keys, signer),
    "unknown-kind.capsule": await buildUnknownKind(keys, signer),
  };

  for (const [name, bytes] of Object.entries(fixtures)) {
    const path = join(OUT_DIR, name);
    if (CHECK) {
      let checkedIn;
      try {
        checkedIn = await readFile(path);
      } catch (err) {
        throw new Error(`${name}: checked-in fixture missing or unreadable: ${err.message}`);
      }
      if (!checkedIn.equals(bytes)) {
        throw new Error(`${name}: checked-in fixture differs from deterministic generator output`);
      }
      console.log(`ok ${name} (${bytes.length} bytes)`);
    } else {
      await writeFile(path, bytes);
      console.log(`wrote ${name} (${bytes.length} bytes)`);
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
```

- [ ] **Step 2: Generate the fixtures**

Run: `node sdk-js/tools/generate-chain-rule-fixtures.mjs`

Expected: `wrote actor-not-participant.capsule (2554 bytes)` and `wrote unknown-kind.capsule (2607 bytes)`.

- [ ] **Step 3: Write the outcome registry**

Create `spec/vectors/chain-rules/vectors.json`:

```json
{
  "meta": {
    "name": "chain-rules",
    "spec_version": "0.6",
    "description": "Language-neutral expected verifier outcomes for the per-event field rules in chain.md. Both capsules are cryptographically well-formed — real signatures, correct manifest hash, correct content index — and break exactly one field rule, so a verifier that skips the rule reports ok=true and fails this registry.",
    "no_warranty": "Conformance fixtures only; not production templates or advice."
  },
  "generator": "sdk-js/tools/generate-chain-rule-fixtures.mjs (signed with ../tamper-detection/output/keys.json)",
  "keys_file": "../tamper-detection/output/keys.json",
  "notes": [
    "chain.md verification step 6: 'Confirm actor appears in manifest participants or is system:host.'",
    "chain.md field rules: kind is one of decision | observation | mutation | session | checkpoint; readers reject unknown kinds.",
    "Both rules are per-event: a conformant reader reports which seq failed which check and does not stop at the first error."
  ],
  "vectors": [
    {
      "name": "actor-not-participant",
      "capsule_file": "output/actor-not-participant.capsule",
      "expected": {
        "ok": false,
        "failing": ["chain"],
        "error_includes": "not in manifest.participants and not system:host"
      },
      "note": "manifest.participants is empty; the single event's actor is human:origin."
    },
    {
      "name": "unknown-kind",
      "capsule_file": "output/unknown-kind.capsule",
      "expected": {
        "ok": false,
        "failing": ["chain"],
        "error_includes": "is not one of decision, observation, mutation, session, checkpoint"
      },
      "note": "The single event declares kind \"gossip\"."
    }
  ]
}
```

Run: `node tools/check-spec-vectors.mjs`

Expected: `spec vectors: ok (282 vectors)` — up from 280. (`tools/check-spec-vectors.mjs` walks `spec/vectors/**/*.json` and already understands this collection shape and the `chain` failing-area predicate; no change to the checker is needed.)

- [ ] **Step 4: Wire the collection into the Python registry lane**

In `sdk-py/tests/test_spec_registry.py`, replace lines 7-9:

```python
  - tamper-detection/vectors.json   (verify-stage outcomes)
  - malformed-layout/vectors.json   (open-stage reasons + verify-stage)
  - signing-input.json              (byte-level signing/hashing pins)
```

with:

```python
  - tamper-detection/vectors.json   (verify-stage outcomes)
  - malformed-layout/vectors.json   (open-stage reasons + verify-stage)
  - chain-rules/vectors.json        (per-event actor + kind field rules)
  - signing-input.json              (byte-level signing/hashing pins)
```

After line 30 (`MALFORMED = VECTORS / "malformed-layout" / "vectors.json"`) add:

```python
CHAIN_RULES = VECTORS / "chain-rules" / "vectors.json"
```

Immediately before line 101's `@pytest.mark.parametrize("doc,vector,base", _collection_params(MALFORMED))` insert:

```python
@pytest.mark.parametrize("doc,vector,base", _collection_params(CHAIN_RULES))
def test_chain_rule_registry_outcomes(doc: dict, vector: dict, base: pathlib.Path):
    """chain.md per-event field rules: actor whitelist (step 6) + kind enum."""
    data = (base / vector["capsule_file"]).read_bytes()
    reader = CapsuleReader.from_bytes(data)
    result = verify_capsule(reader, allowlist=_allowlist(doc, base))
    _assert_verify_outcome(vector["name"], vector["expected"], result)


```

Run: `cd sdk-py && python -m pytest tests/test_spec_registry.py -q`

Expected: PASS — `19 passed` (17 before, plus the two new parametrized cases).

- [ ] **Step 5: Wire the collection into the Rust registry lane**

In `verifier-rust/tests/spec_registry.rs`, replace lines 7-9:

```rust
//!   - tamper-detection/vectors.json   (verify-stage outcomes)
//!   - malformed-layout/vectors.json   (open-stage reasons + verify-stage)
//!   - signing-input.json              (byte-level signing/hashing pins)
```

with:

```rust
//!   - tamper-detection/vectors.json   (verify-stage outcomes)
//!   - malformed-layout/vectors.json   (open-stage reasons + verify-stage)
//!   - chain-rules/vectors.json        (per-event actor + kind field rules)
//!   - signing-input.json              (byte-level signing/hashing pins)
```

Immediately before line 132's `/// Per-lane mapping of the registry's normative open-stage reason` insert:

```rust
/// chain.md per-event field rules: the actor whitelist (verification
/// step 6) and the closed `kind` enum. Both fixtures are otherwise
/// cryptographically well-formed, so only those two checks can catch them.
#[test]
fn chain_rule_registry_outcomes() {
    let path = vectors_dir().join("chain-rules/vectors.json");
    let doc = load_json(&path);
    let base = path.parent().unwrap().to_path_buf();
    let allowlist = registry_allowlist(&doc, &base);
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty());
    for v in vectors {
        let name = v["name"].as_str().expect("name");
        let result = verify_fixture(&base, &allowlist, v);
        assert_verify_outcome(name, &v["expected"], &result);
    }
}

```

Run: `cd verifier-rust && cargo test --test spec_registry`

Expected: PASS — `test chain_rule_registry_outcomes ... ok` and `test result: ok. 4 passed; 0 failed`.

- [ ] **Step 6: Add the regeneration-drift gate to the JS conformance harness**

In `tools/run-conformance.mjs`, insert immediately before line 93's `{` that opens the `spec-vectors` target:

```js
  {
    id: "chain-rule-fixtures-regen",
    name: "chain-rules fixture regeneration check",
    language: "javascript",
    kind: "check",
    cwd: ".",
    install_cmd: "true",
    test_cmd: "node sdk-js/tools/generate-chain-rule-fixtures.mjs --check",
    pass_signal: { type: "exit_code", value: 0 },
  },
```

Run: `node sdk-js/tools/generate-chain-rule-fixtures.mjs --check`

Expected: `ok actor-not-participant.capsule (2554 bytes)` and `ok unknown-kind.capsule (2607 bytes)`.

- [ ] **Step 7: Make the spec normative about both rules and the writer obligation**

In `spec/chain.md`, replace lines 29-32:

```markdown
- `actor`: `human:`, `ai:`, `system:`, or `capsule:` prefix. Must appear
  in the manifest's `participants[]` *or* be the literal `system:host`
  for backstop events emitted by the host runtime.
- `kind`: one of the listed values. Readers reject unknown kinds.
```

with:

```markdown
- `actor`: `human:`, `ai:`, `system:`, or `capsule:` prefix. Must appear
  in the manifest's `participants[]` *or* be the literal `system:host`
  for backstop events emitted by the host runtime. Writers reject the
  event at append time rather than registering the actor implicitly —
  declaring who may act is the host's decision, not the SDK's.
- `kind`: one of the listed values. Readers reject unknown kinds and
  writers refuse to append them.
```

Then replace lines 105-109:

```markdown
5. Confirm `seq` is strictly monotonic from 1.
6. Confirm `actor` appears in manifest participants or is `system:host`.

A mismatch at any step fails verification. The reader reports which
event failed which check; it does not stop at the first error.
```

with:

```markdown
5. Confirm `seq` is strictly monotonic from 1.
6. Confirm `actor` appears in manifest participants or is `system:host`.
7. Confirm `kind` is one of the five values in the enum above.

A mismatch at any step fails verification. The reader reports which
event failed which check; it does not stop at the first error.

Steps 6 and 7 are per-event field rules, not chain-integrity rules: a
capsule can have a perfectly linked, correctly signed chain and still
fail them. Conformance fixtures for both live in
`spec/vectors/chain-rules/`.

## Writer obligations

A writer MUST NOT emit an event that a reader would reject at steps 6 or
7. In practice that means the builder validates `actor` and `kind` when
the event is appended, so the failure surfaces at the call site that
introduced it rather than at some future reader. A builder that
auto-registers an undeclared actor into `participants[]` is
non-conformant: it converts an authorization question into a silent
side effect.
```

Then regenerate the derived skill (editing `spec/chain.md` makes `skills/capsule/skill.json` stale and the `skill-capsule-regen` conformance target fails otherwise):

Run: `node tools/regen-capsule-skill.mjs && node tools/regen-capsule-skill.mjs --check`

Expected: `Wrote skills/capsule/skill.json` then `skills/capsule/skill.json: ok`.

- [ ] **Step 8: Run the full JS harness plus both other registry lanes**

Run: `node tools/run-conformance.mjs && (cd verifier-rust && cargo test --workspace) && (cd sdk-py && python -m pytest -q)`

Expected: `PASS · 11/11 passed` (with `[5/11] chain-rule-fixtures-regen ... PASS`), all Rust suites `0 failed`, and `192 passed` for Python.

- [ ] **Step 9: Commit**

```bash
git add sdk-js/tools/generate-chain-rule-fixtures.mjs spec/vectors/chain-rules spec/chain.md skills/capsule/skill.json tools/run-conformance.mjs sdk-py/tests/test_spec_registry.py verifier-rust/tests/spec_registry.rs
git commit -m "feat(spec): add chain-rules negative vectors for the actor and kind rules

Two cryptographically well-formed capsules that break exactly one
per-event field rule each, so a verifier that skips the rule reports
ok=true and fails the registry. Consumed by the JS, Python, and Rust
lanes; regeneration is drift-gated by a new conformance target.
chain.md gains verification step 7 and a Writer obligations section.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 9: sdk-swift — per-event chain errors in the verifier, rejection in the builder

**Files:**
- Modify: `sdk-swift/Sources/Capsule/Chain.swift:61-62`
- Modify: `sdk-swift/Sources/Capsule/Reader.swift:321-344`
- Modify: `sdk-swift/Sources/Capsule/Verifier.swift:21-24`, `:46-50`, `:77-81`, `:99-104`, `:147-152`, `:164-164`, `:240-242`, `:273-278`
- Modify: `sdk-swift/Sources/Capsule/Builder.swift:82-90`
- Modify: `sdk-swift/Tests/CapsuleTests/RoundTripTests.swift:15-15`, `:62-64`
- Modify: `sdk-swift/Tests/CapsuleTests/EncryptionTests.swift:118-121`
- Modify: `sdk-swift/README.md:52-52`
- Test: `sdk-swift/Tests/CapsuleTests/ActorKindTests.swift`

**Interfaces:**
- Consumes: `Chain.build(_:)`, `BuiltEvent.toJCSWithoutHash()`, `CapsuleReader.parse(_:)`, `CapsuleVerifier.verify(_:allowlist:)`
- Produces: `Chain.EVENT_KINDS: [String]`, `Chain.HOST_ACTOR: String`, `Chain.isValidEventKind(_:) -> Bool`, `Chain.debugQuoted(_:) -> String`, `CapsuleReader.verifyChain(_:participants:) -> [String]`, `CapsuleReader.participantActorIds(_:) -> Set<String>`, `CapsuleVerification.chainErrors: [String]`, `CapsuleBuilder.appendEvent(...) throws -> CapsuleBuilder`

- [ ] **Step 1: Write the failing test**

Create `sdk-swift/Tests/CapsuleTests/ActorKindTests.swift`:

```swift
// spec/chain.md step-6 actor rule + the closed `kind` enum.
//
// Mirrors sdk-js/test/actor-kind.test.js and
// sdk-py/tests/test_actor_kind.py. The per-event messages are the same
// strings the Rust verifier emits in ChainCheck.errors.

import XCTest
@testable import Capsule

final class ActorKindTests: XCTestCase {

    private let participants: Set<String> = ["human:alice"]

    private func events(actor: String = "human:alice",
                        kind: String = "decision") -> [JCSValue]
    {
        let built = Chain.build([
            BareEvent(
                actor: actor, kind: kind, action: "a", target: "t",
                timestamp: "2026-05-07T12:00:00Z", payload: .object([])
            )
        ])
        return built.map { e in
            var pairs: [(String, JCSValue)] = []
            if case .object(let p) = e.toJCSWithoutHash() { pairs = p }
            pairs.append(("hash", .string(e.hash)))
            return .object(pairs)
        }
    }

    func testVerifyChainFlagsActorNotInParticipants() {
        let errors = CapsuleReader.verifyChain(
            events(actor: "human:mallory"), participants: participants
        )
        XCTAssertEqual(errors, [
            #"seq 1: actor "human:mallory" not in manifest.participants and not system:host"#,
        ])
    }

    func testVerifyChainAcceptsSystemHostWithoutParticipant() {
        let errors = CapsuleReader.verifyChain(
            events(actor: "system:host", kind: "observation"), participants: []
        )
        XCTAssertEqual(errors, [])
    }

    func testVerifyChainRejectsUnknownKind() {
        let errors = CapsuleReader.verifyChain(
            events(kind: "gossip"), participants: participants
        )
        XCTAssertEqual(errors, [
            #"seq 1: kind "gossip" is not one of decision, observation, mutation, session, checkpoint"#,
        ])
    }

    func testVerifyChainAcceptsEveryEnumKind() {
        for kind in Chain.EVENT_KINDS {
            let errors = CapsuleReader.verifyChain(
                events(kind: kind), participants: participants
            )
            XCTAssertEqual(errors, [], "kind \(kind) must be accepted")
        }
    }

    func testVerifierEnforcesActorRuleAgainstManifestParticipants() throws {
        let kp = Ed25519KeyPair.generate()
        let builder = CapsuleBuilder(originator: .init(keyPair: kp, label: "Acme"),
                                     createdAt: "2026-05-07T12:00:00Z")
        try builder
            .setProgram("# Actor rule\n")
            .setParticipants([
                .init(actorId: "human:alice", role: "originator", label: "Alice"),
            ])
            .appendEvent(
                actor: "human:alice", kind: "decision",
                action: "submit", target: "program.md"
            )
        // Drop the participant AFTER appending: the sealed manifest no
        // longer declares human:alice while the chain still names it.
        builder.setParticipants([])
        let result = try builder.seal(signedAt: "2026-05-07T12:00:00Z")

        let v = CapsuleVerifier.verify(result.bytes, allowlist: [kp.publicKeyHex])
        XCTAssertFalse(v.ok)
        XCTAssertTrue(
            v.chainErrors.contains(
                #"seq 1: actor "human:alice" not in manifest.participants and not system:host"#
            ),
            "expected the step-6 actor error; got: \(v.chainErrors)"
        )
    }

    func testVerifierGreenWhenActorIsDeclared() throws {
        let kp = Ed25519KeyPair.generate()
        let builder = CapsuleBuilder(originator: .init(keyPair: kp, label: "Acme"),
                                     createdAt: "2026-05-07T12:00:00Z")
        try builder
            .setProgram("# Actor rule\n")
            .setParticipants([
                .init(actorId: "human:alice", role: "originator", label: "Alice"),
            ])
            .appendEvent(
                actor: "human:alice", kind: "decision",
                action: "submit", target: "program.md"
            )
        let result = try builder.seal(signedAt: "2026-05-07T12:00:00Z")
        let v = CapsuleVerifier.verify(result.bytes, allowlist: [kp.publicKeyHex])
        XCTAssertTrue(v.ok, "checks failed: \(v.checks.filter { !$0.ok })")
        XCTAssertEqual(v.chainErrors, [])
    }

    func testAppendEventRejectsUndeclaredActor() {
        let kp = Ed25519KeyPair.generate()
        let builder = CapsuleBuilder(originator: .init(keyPair: kp))
        builder.setParticipants([
            .init(actorId: "human:alice", role: "originator", label: "Alice"),
        ])
        XCTAssertThrowsError(
            try builder.appendEvent(
                actor: "human:mallory", kind: "observation",
                action: "sneak", target: "capsule"
            )
        ) { error in
            XCTAssertTrue(
                "\(error)".contains(#"event actor "human:mallory" is not a declared participant"#),
                "unexpected error: \(error)"
            )
        }
    }

    func testAppendEventAcceptsSystemHostWithoutParticipant() {
        let kp = Ed25519KeyPair.generate()
        let builder = CapsuleBuilder(originator: .init(keyPair: kp))
        XCTAssertNoThrow(
            try builder.appendEvent(
                actor: "system:host", kind: "observation",
                action: "session_ended", target: "capsule"
            )
        )
    }

    func testAppendEventRejectsUnknownKind() {
        let kp = Ed25519KeyPair.generate()
        let builder = CapsuleBuilder(originator: .init(keyPair: kp))
        builder.setParticipants([
            .init(actorId: "human:alice", role: "originator", label: "Alice"),
        ])
        XCTAssertThrowsError(
            try builder.appendEvent(
                actor: "human:alice", kind: "gossip",
                action: "a", target: "t"
            )
        ) { error in
            XCTAssertTrue(
                "\(error)".contains(#"event kind "gossip" is not one of"#),
                "unexpected error: \(error)"
            )
        }
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-swift && swift test --filter ActorKindTests`

Expected: FAIL to compile — `error: value of type 'Chain.Type' has no member 'EVENT_KINDS'`, `error: extra argument 'participants' in call` (for `CapsuleReader.verifyChain`), `error: value of type 'CapsuleVerification' has no member 'chainErrors'`, and `warning: no calls to throwing functions occur within 'try' expression` for `try builder.appendEvent`.

- [ ] **Step 3: Add the enum and the Rust-compatible quoting helper to Chain.swift**

In `sdk-swift/Sources/Capsule/Chain.swift`, replace lines 61-62:

```swift
public enum Chain {
    static let GENESIS_PREV = Data(repeating: 0, count: 32)
```

with:

```swift
public enum Chain {
    static let GENESIS_PREV = Data(repeating: 0, count: 32)

    /// The closed `kind` enum from spec/chain.md "Field rules". Readers
    /// reject unknown kinds; the builder refuses to append them.
    public static let EVENT_KINDS = [
        "decision", "observation", "mutation", "session", "checkpoint",
    ]

    /// The one actor a chain event may name without a matching manifest
    /// participant — backstop events emitted by the host runtime.
    public static let HOST_ACTOR = "system:host"

    /// True when `kind` is one of the five values spec/chain.md allows.
    public static func isValidEventKind(_ kind: String) -> Bool {
        EVENT_KINDS.contains(kind)
    }

    /// Render a string the way Rust's `{:?}` renders a `String`, so all
    /// five lanes emit byte-identical verifier messages. `nil` renders as
    /// `null` (a missing field).
    public static func debugQuoted(_ s: String?) -> String {
        guard let s else { return "null" }
        var out = "\""
        for ch in s.unicodeScalars {
            switch ch {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            default: out.unicodeScalars.append(ch)
            }
        }
        return out + "\""
    }
```

- [ ] **Step 4: Turn `verifyChain` into a per-event error walk**

In `sdk-swift/Sources/Capsule/Reader.swift`, replace lines 321-344 (the whole existing `verifyChain`):

```swift
    /// Verify chain hash linkage. Independent of envelope sigs.
    public static func verifyChain(_ events: [JCSValue]) -> Bool {
        var prev = Chain.GENESIS_PREV
        for (i, e) in events.enumerated() {
            guard case .object(let pairs) = e else { return false }
            var withoutHash: [(String, JCSValue)] = []
            var stored: String?
            for (k, v) in pairs {
                if k == "hash", case .string(let s) = v { stored = s }
                else { withoutHash.append((k, v)) }
            }
            guard let storedHash = stored,
                  let prevHash = pairs.first(where: { $0.0 == "prev_hash" }),
                  case .string(let prevHex) = prevHash.1
            else { return false }
            if i == 0 && prevHex != Bytes.toHex(Chain.GENESIS_PREV) { return false }
            if i > 0 && prevHex != Bytes.toHex(prev) { return false }
            let canonical = JCS.bytes(.object(withoutHash))
            let h = Hash.sha256(Bytes.concat(prev, canonical))
            if Bytes.toHex(h) != storedHash { return false }
            prev = h
        }
        return true
    }
```

with:

```swift
    /// Verify chain hash linkage plus the per-event field rules from
    /// spec/chain.md: `actor` must be a declared participant or the
    /// literal `system:host` (verification step 6), and `kind` must be one
    /// of the five values in the closed enum. Independent of envelope
    /// signatures.
    ///
    /// Returns one message per failure; an empty array means the chain
    /// verifies. `participants` defaults to the empty set, so a caller
    /// that forgets to pass it fails closed: every actor except
    /// `system:host` is rejected.
    public static func verifyChain(_ events: [JCSValue],
                                   participants: Set<String> = []) -> [String]
    {
        var errors: [String] = []
        var prev = Chain.GENESIS_PREV
        for (i, e) in events.enumerated() {
            let seq = i + 1
            guard case .object(let pairs) = e else {
                errors.append("seq \(seq): event is not a JSON object")
                continue
            }
            let actor = stringField(pairs, "actor")
            if actor != Chain.HOST_ACTOR && !(actor.map { participants.contains($0) } ?? false) {
                errors.append(
                    "seq \(seq): actor \(Chain.debugQuoted(actor)) "
                        + "not in manifest.participants and not system:host"
                )
            }
            let kind = stringField(pairs, "kind")
            if !(kind.map { Chain.isValidEventKind($0) } ?? false) {
                errors.append(
                    "seq \(seq): kind \(Chain.debugQuoted(kind)) is not one of "
                        + Chain.EVENT_KINDS.joined(separator: ", ")
                )
            }
            var withoutHash: [(String, JCSValue)] = []
            var stored: String?
            for (k, v) in pairs {
                if k == "hash", case .string(let s) = v { stored = s }
                else { withoutHash.append((k, v)) }
            }
            guard let storedHash = stored else {
                errors.append("seq \(seq): hash missing or wrong length")
                continue
            }
            guard let prevHex = stringField(pairs, "prev_hash") else {
                errors.append("seq \(seq): prev_hash missing or wrong length")
                continue
            }
            let expectedPrev = Bytes.toHex(prev)
            if prevHex != expectedPrev {
                errors.append(
                    "seq \(seq): prev_hash mismatch: got \(prevHex), expected \(expectedPrev)"
                )
            }
            let canonical = JCS.bytes(.object(withoutHash))
            let h = Hash.sha256(Bytes.concat(prev, canonical))
            let recomputed = Bytes.toHex(h)
            if recomputed != storedHash {
                errors.append(
                    "seq \(seq): hash mismatch: stored \(storedHash), recomputed \(recomputed)"
                )
            }
            prev = h
        }
        return errors
    }

    /// Read a string field out of a JCS object's key/value pairs.
    static func stringField(_ pairs: [(String, JCSValue)], _ key: String) -> String? {
        guard let v = pairs.first(where: { $0.0 == key })?.1,
              case .string(let s) = v else { return nil }
        return s
    }

    /// Collect `manifest.participants[].actor_id` into a lookup set.
    public static func participantActorIds(_ manifest: JCSValue) -> Set<String> {
        guard case .object(let pairs) = manifest,
              let ps = pairs.first(where: { $0.0 == "participants" })?.1,
              case .array(let items) = ps
        else { return [] }
        var out: Set<String> = []
        for item in items {
            guard case .object(let fields) = item,
                  let id = stringField(fields, "actor_id") else { continue }
            out.insert(id)
        }
        return out
    }
```

- [ ] **Step 5: Surface `chainErrors` on `CapsuleVerification` and wire the walk**

In `sdk-swift/Sources/Capsule/Verifier.swift`, make five edits.

(a) Replace lines 21-25:

```swift
    public let checks: [VerifyCheck]
    public let signers: [SignerCheck]
    public let trustedSignerCount: Int
    public let notes: [String]
}
```

with:

```swift
    public let checks: [VerifyCheck]
    public let signers: [SignerCheck]
    public let trustedSignerCount: Int
    public let notes: [String]
    /// Per-event chain failures, one message per failing rule, in the
    /// shape `seq N: <message>` — the same strings the Rust verifier
    /// puts in `ChainCheck.errors`. Empty when the chain verifies (or
    /// when chain verification was deferred to L3).
    public let chainErrors: [String]
}
```

(b) In both parse-failure early returns (lines 46-50 and 77-81), append `chainErrors: []` after `notes: initialNotes`:

```swift
            return CapsuleVerification(
                ok: false, level: "L2",
                checks: [VerifyCheck(name: "parse", ok: false, detail: "\(error)")],
                signers: [], trustedSignerCount: 0, notes: initialNotes,
                chainErrors: []
            )
```

and the identical change on the `level: "L3"` one.

(c) In the decrypt-failure return (lines 99-104), append `chainErrors: outer.chainErrors` after `notes: outer.notes`. In the L3 aggregate return (lines 147-152), append `chainErrors: outer.chainErrors + innerResult.chainErrors` after `notes: outer.notes`.

(d) After line 164 (`var notes: [String] = []`) add:

```swift
        var chainErrors: [String] = []
```

(e) Replace lines 240-242:

```swift
            // Plain-capsule checks: chain integrity + envelope anchors.
            let chainOk = CapsuleReader.verifyChain(parsed.events)
            record("chain", chainOk, "\(parsed.events.count) events")
```

with:

```swift
            // Plain-capsule checks: chain integrity (hash linkage plus the
            // spec/chain.md per-event actor and kind rules) + envelope anchors.
            chainErrors = CapsuleReader.verifyChain(
                parsed.events,
                participants: CapsuleReader.participantActorIds(parsed.manifest)
            )
            record("chain", chainErrors.isEmpty,
                   chainErrors.isEmpty
                       ? "\(parsed.events.count) events"
                       : chainErrors.joined(separator: "; "))
```

and in the `verifyParsed` return (lines 273-278) append `chainErrors: chainErrors` after `notes: notes`.

- [ ] **Step 6: Make `appendEvent` throwing and add the guards**

In `sdk-swift/Sources/Capsule/Builder.swift`, replace lines 82-91:

```swift
    /// Append a chain event. The seq, event_id, prev_hash, and hash are
    /// computed at seal time.
    @discardableResult
    public func appendEvent(
        actor: String, kind: String, action: String, target: String,
        timestamp: String? = nil,
        payload: JCSValue = .object([]),
        untrustedPayloadFields: [String] = []
    ) -> CapsuleBuilder {
        bareEvents.append(BareEvent(
```

with:

```swift
    /// Append a chain event. The seq, event_id, prev_hash, and hash are
    /// computed at seal time.
    ///
    /// Throws (spec/chain.md) when `kind` is outside the closed enum, or
    /// when `actor` is neither `"system:host"` nor an actor id already
    /// passed to `setParticipants(_:)`. The builder never auto-registers
    /// participants — call `setParticipants(_:)` before `appendEvent`.
    @discardableResult
    public func appendEvent(
        actor: String, kind: String, action: String, target: String,
        timestamp: String? = nil,
        payload: JCSValue = .object([]),
        untrustedPayloadFields: [String] = []
    ) throws -> CapsuleBuilder {
        guard Chain.isValidEventKind(kind) else {
            throw CapsuleError.malformed(
                "event kind \(Chain.debugQuoted(kind)) is not one of "
                    + Chain.EVENT_KINDS.joined(separator: ", ")
            )
        }
        guard actor == Chain.HOST_ACTOR
                || participants.contains(where: { $0.actorId == actor })
        else {
            throw CapsuleError.malformed(
                "event actor \(Chain.debugQuoted(actor)) is not a declared participant: "
                    + "call setParticipants(_:) with actor_id \(Chain.debugQuoted(actor)) "
                    + "before appendEvent (only \"system:host\" may appear without one)"
            )
        }
        bareEvents.append(BareEvent(
```

Confirm the library still compiles:

Run: `cd sdk-swift && swift build`

Expected: `Build complete!`

- [ ] **Step 7: Fix the two existing tests the change breaks**

In `sdk-swift/Tests/CapsuleTests/RoundTripTests.swift`, replace line 15:

```swift
        builder
```

with:

```swift
        try builder
```

and replace lines 62-64:

```swift
        let result = try CapsuleBuilder(originator: .init(keyPair: kp))
            .setProgram("# Hi\n")
            .appendEvent(
```

with:

```swift
        let result = try CapsuleBuilder(originator: .init(keyPair: kp))
            .setProgram("# Hi\n")
            .setParticipants([
                .init(actorId: "human:test", role: "originator", label: "Test"),
            ])
            .appendEvent(
```

In `sdk-swift/Tests/CapsuleTests/EncryptionTests.swift`, replace lines 118-121:

```swift
        builder
            .setProgram("# Hello\n\nEncrypted capsule under test.\n")
            .setAgents("# Agents\n")
            .appendEvent(
```

with:

```swift
        try builder
            .setProgram("# Hello\n\nEncrypted capsule under test.\n")
            .setAgents("# Agents\n")
            .setParticipants([
                .init(actorId: "human:test", role: "originator", label: "Test"),
            ])
            .appendEvent(
```

In `sdk-swift/README.md`, replace line 52 inside the quickstart fence:

```swift
builder
```

with:

```swift
try builder
```

(The README already calls `setParticipants` before `appendEvent`, so only the `try` is needed.)

- [ ] **Step 8: Run the test to verify it passes**

Run: `cd sdk-swift && swift test --filter ActorKindTests`

Expected: PASS — `Executed 9 tests, with 0 failures`.

- [ ] **Step 9: Run the full lane suite for regressions**

Run: `cd sdk-swift && swift test`

Expected: all suites pass, `0 failures` — `RoundTripTests` (2), `EncryptedRoundTripTests`, `ParityTests`, `JCSNumbersVectorTests`, and the 9 new `ActorKindTests`.

- [ ] **Step 10: Commit**

```bash
git add sdk-swift/Sources sdk-swift/Tests sdk-swift/README.md
git commit -m "feat(sdk-swift)!: enforce chain.md step-6 actor rule and the kind enum

BREAKING: CapsuleReader.verifyChain returns [String] of per-event errors
instead of Bool and takes the manifest participant set; CapsuleVerification
gains chainErrors; CapsuleBuilder.appendEvent is throwing and rejects
undeclared actors and out-of-enum kinds. Messages match verifier-rust.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 10: sdk-kotlin — per-event chain errors in the verifier, rejection in the builder

**Files:**
- Modify: `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Chain.kt:30-31`
- Modify: `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Reader.kt:62-62`
- Modify: `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Verifier.kt:10-17`, `:70-70`, `:98-102`, `:105-126`
- Modify: `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Builder.kt:60-65`
- Modify: `sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/RoundTripTest.kt:101-102`
- Create: `sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/ActorKindTest.kt`
- Modify: `CHANGELOG.md:10-12`
- Test: `sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/ActorKindTest.kt`

**Interfaces:**
- Consumes: `Chain.build(List<BareEvent>)`, `CapsuleReader.parseJson(ByteArray)`, `CapsuleVerifier.verify(bytes, allowlist)`
- Produces: `Chain.EVENT_KINDS: List<String>`, `Chain.HOST_ACTOR: String`, `Chain.isValidEventKind(String?): Boolean`, `Chain.debugQuoted(String?): String`, `CapsuleReader.participantActorIds(JCSValue): Set<String>`, `CapsuleVerifier.verifyChain(List<JCSValue>, Set<String>): List<String>` (internal), `CapsuleVerification.chainErrors: List<String>`

- [ ] **Step 1: Write the failing test**

Create `sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/ActorKindTest.kt`:

```kotlin
// spec/chain.md step-6 actor rule + the closed `kind` enum.
//
// Mirrors sdk-js/test/actor-kind.test.js, sdk-py/tests/test_actor_kind.py,
// and sdk-swift/Tests/CapsuleTests/ActorKindTests.swift. The per-event
// messages are the same strings the Rust verifier emits in
// ChainCheck.errors.

package ai.virion.capsule.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

class ActorKindTest {

    private val participants = setOf("human:alice")

    private fun events(
        actor: String = "human:alice",
        kind: String = "decision",
    ): List<JCSValue> =
        Chain.build(
            listOf(
                BareEvent(
                    actor = actor, kind = kind, action = "a", target = "t",
                    timestamp = TS, payload = JCSValue.Obj(emptyList()),
                )
            )
        ).map { e -> CapsuleReader.parseJson(e.jsonLine) }

    @Test
    fun verifyChainFlagsActorNotInParticipants() {
        val errors = CapsuleVerifier.verifyChain(events(actor = "human:mallory"), participants)
        assertEquals(
            listOf(
                "seq 1: actor \"human:mallory\" not in manifest.participants and not system:host"
            ),
            errors,
        )
    }

    @Test
    fun verifyChainAcceptsSystemHostWithoutParticipant() {
        val errors = CapsuleVerifier.verifyChain(
            events(actor = "system:host", kind = "observation"),
            emptySet(),
        )
        assertEquals(emptyList<String>(), errors)
    }

    @Test
    fun verifyChainRejectsUnknownKind() {
        val errors = CapsuleVerifier.verifyChain(events(kind = "gossip"), participants)
        assertEquals(
            listOf(
                "seq 1: kind \"gossip\" is not one of " +
                    "decision, observation, mutation, session, checkpoint"
            ),
            errors,
        )
    }

    @Test
    fun verifyChainAcceptsEveryEnumKind() {
        for (kind in Chain.EVENT_KINDS) {
            assertEquals(
                emptyList<String>(),
                CapsuleVerifier.verifyChain(events(kind = kind), participants),
                "kind $kind must be accepted",
            )
        }
    }

    @Test
    fun verifierEnforcesActorRuleAgainstManifestParticipants() {
        val kp = CapsuleCrypto.generateEd25519()
        val builder = CapsuleBuilder(
            originator = CapsuleBuilder.Originator(keyPair = kp, label = "Acme"),
            createdAt = TS,
        )
        builder.setProgram("# Actor rule\n")
            .setParticipants(
                listOf(CapsuleBuilder.Participant("human:alice", "originator", "Alice"))
            )
            .appendEvent(
                actor = "human:alice", kind = "decision",
                action = "submit", target = "program.md",
            )
        // Drop the participant AFTER appending: the sealed manifest no
        // longer declares human:alice while the chain still names it.
        builder.setParticipants(emptyList())
        val result = builder.seal(signedAt = TS)

        val v = CapsuleVerifier.verify(result.bytes, allowlist = setOf(kp.publicKeyHex))
        assertFalse(v.ok, "capsule with an undeclared actor must not verify")
        assertTrue(
            v.chainErrors.contains(
                "seq 1: actor \"human:alice\" not in manifest.participants and not system:host"
            ),
            "expected the step-6 actor error; got: ${v.chainErrors}",
        )
    }

    @Test
    fun verifierGreenWhenActorIsDeclared() {
        val kp = CapsuleCrypto.generateEd25519()
        val result = CapsuleBuilder(
            originator = CapsuleBuilder.Originator(keyPair = kp, label = "Acme"),
            createdAt = TS,
        )
            .setProgram("# Actor rule\n")
            .setParticipants(
                listOf(CapsuleBuilder.Participant("human:alice", "originator", "Alice"))
            )
            .appendEvent(
                actor = "human:alice", kind = "decision",
                action = "submit", target = "program.md",
            )
            .seal(signedAt = TS)

        val v = CapsuleVerifier.verify(result.bytes, allowlist = setOf(kp.publicKeyHex))
        assertTrue(v.ok, "checks failed: ${v.checks.filter { !it.ok }}")
        assertEquals(emptyList<String>(), v.chainErrors)
    }

    @Test
    fun appendEventRejectsUndeclaredActor() {
        val builder = newBuilder().setParticipants(
            listOf(CapsuleBuilder.Participant("human:alice", "originator", "Alice"))
        )
        val e = assertFailsWith<IllegalArgumentException> {
            builder.appendEvent(
                actor = "human:mallory", kind = "observation",
                action = "sneak", target = "capsule",
            )
        }
        assertTrue(
            e.message!!.contains(
                "event actor \"human:mallory\" is not a declared participant"
            ),
            "unexpected message: ${e.message}",
        )
    }

    @Test
    fun appendEventAcceptsSystemHostWithoutParticipant() {
        newBuilder().appendEvent(
            actor = "system:host", kind = "observation",
            action = "session_ended", target = "capsule",
        )
    }

    @Test
    fun appendEventRejectsUnknownKind() {
        val builder = newBuilder().setParticipants(
            listOf(CapsuleBuilder.Participant("human:alice", "originator", "Alice"))
        )
        val e = assertFailsWith<IllegalArgumentException> {
            builder.appendEvent(
                actor = "human:alice", kind = "gossip",
                action = "a", target = "t",
            )
        }
        assertTrue(
            e.message!!.contains("event kind \"gossip\" is not one of"),
            "unexpected message: ${e.message}",
        )
    }

    private fun newBuilder() = CapsuleBuilder(
        originator = CapsuleBuilder.Originator(
            keyPair = CapsuleCrypto.generateEd25519(), label = "Acme",
        ),
        createdAt = TS,
    )

    private companion object {
        const val TS = "2026-05-07T12:00:00Z"
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-kotlin && ./gradlew --no-daemon :core:test --tests '*ActorKindTest*'`

Expected: FAIL to compile — `e: ... Unresolved reference: EVENT_KINDS`, `e: ... Cannot access 'verifyChain': it is private in 'CapsuleVerifier'`, `e: ... Unresolved reference: chainErrors`.

- [ ] **Step 3: Add the enum and the Rust-compatible quoting helper to Chain.kt**

In `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Chain.kt`, replace lines 30-31:

```kotlin
object Chain {
    val GENESIS_PREV: ByteArray = ByteArray(32)
```

with:

```kotlin
object Chain {
    val GENESIS_PREV: ByteArray = ByteArray(32)

    /**
     * The closed `kind` enum from spec/chain.md "Field rules". Readers
     * reject unknown kinds; the builder refuses to append them.
     */
    val EVENT_KINDS: List<String> =
        listOf("decision", "observation", "mutation", "session", "checkpoint")

    /**
     * The one actor a chain event may name without a matching manifest
     * participant — backstop events emitted by the host runtime.
     */
    const val HOST_ACTOR: String = "system:host"

    /** True when [kind] is one of the five values spec/chain.md allows. */
    fun isValidEventKind(kind: String?): Boolean = kind != null && kind in EVENT_KINDS

    /**
     * Render a string the way Rust's `{:?}` renders a `String`, so all
     * five lanes emit byte-identical verifier messages. `null` renders as
     * `null` (a missing field).
     */
    fun debugQuoted(s: String?): String {
        if (s == null) return "null"
        val sb = StringBuilder("\"")
        for (ch in s) {
            when (ch) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                else -> sb.append(ch)
            }
        }
        return sb.append('"').toString()
    }
```

- [ ] **Step 4: Add the participant-set reader to Reader.kt**

In `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Reader.kt`, insert immediately before line 62 (`/** Parse JSON bytes via Gson, then convert to JCSValue keeping insertion order. */`):

```kotlin
    /** Collect `manifest.participants[].actor_id` into a lookup set. */
    fun participantActorIds(manifest: JCSValue): Set<String> {
        val obj = manifest as? JCSValue.Obj ?: return emptySet()
        val ps = obj.pairs.firstOrNull { it.first == "participants" }?.second
        val arr = ps as? JCSValue.Arr ?: return emptySet()
        val out = mutableSetOf<String>()
        for (item in arr.items) {
            val fields = item as? JCSValue.Obj ?: continue
            val id = fields.pairs.firstOrNull { it.first == "actor_id" }?.second
            if (id is JCSValue.Str) out += id.v
        }
        return out
    }

```

- [ ] **Step 5: Rewrite the Kotlin chain walk and surface `chainErrors`**

In `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Verifier.kt`, make four edits.

(a) Replace lines 10-17:

```kotlin
data class CapsuleVerification(
    val ok: Boolean,
    val level: String,                                  // "L2"
    val checks: List<VerifyCheck>,
    val signers: List<SignerCheck>,
    val trustedSignerCount: Int,
    val notes: List<String>,
) {
```

with:

```kotlin
data class CapsuleVerification(
    val ok: Boolean,
    val level: String,                                  // "L2"
    val checks: List<VerifyCheck>,
    val signers: List<SignerCheck>,
    val trustedSignerCount: Int,
    val notes: List<String>,
    /**
     * Per-event chain failures, one message per failing rule, in the shape
     * `seq N: <message>` — the same strings the Rust verifier puts in
     * `ChainCheck.errors`. Empty when the chain verifies.
     */
    val chainErrors: List<String> = emptyList(),
) {
```

(The default keeps the parse-failure construction at line 38 compiling unchanged.)

(b) Replace line 70:

```kotlin
        rec("chain", verifyChain(parsed.events), "${parsed.events.size} events")
```

with:

```kotlin
        // Chain integrity: hash linkage plus the spec/chain.md per-event
        // actor (step 6) and kind rules.
        val chainErrors = verifyChain(
            parsed.events,
            CapsuleReader.participantActorIds(parsed.manifest),
        )
        rec(
            "chain",
            chainErrors.isEmpty(),
            if (chainErrors.isEmpty()) "${parsed.events.size} events"
            else chainErrors.joinToString("; "),
        )
```

(c) Replace lines 98-102:

```kotlin
        return CapsuleVerification(
            ok = ok, level = "L2", checks = checks,
            signers = signers, trustedSignerCount = signers.count { it.trusted },
            notes = notes,
        )
```

with:

```kotlin
        return CapsuleVerification(
            ok = ok, level = "L2", checks = checks,
            signers = signers, trustedSignerCount = signers.count { it.trusted },
            notes = notes, chainErrors = chainErrors,
        )
```

(d) Replace lines 105-126 (the whole private `verifyChain`):

```kotlin
    private fun verifyChain(events: List<JCSValue>): Boolean {
        var prev = Chain.GENESIS_PREV
        events.forEachIndexed { i, e ->
            val obj = e as? JCSValue.Obj ?: return false
            var stored: String? = null
            val withoutHash = mutableListOf<Pair<String, JCSValue>>()
            for ((k, v) in obj.pairs) {
                if (k == "hash" && v is JCSValue.Str) stored = v.v
                else withoutHash += k to v
            }
            val storedHash = stored ?: return false
            val prevHex = (obj.pairs.firstOrNull { it.first == "prev_hash" }?.second
                as? JCSValue.Str)?.v ?: return false
            if (i == 0 && prevHex != CapsuleCrypto.bytesToHex(Chain.GENESIS_PREV)) return false
            if (i > 0 && prevHex != CapsuleCrypto.bytesToHex(prev)) return false
            val canonical = JCS.bytes(JCSValue.Obj(withoutHash))
            val h = CapsuleCrypto.sha256(CapsuleCrypto.concat(prev, canonical))
            if (CapsuleCrypto.bytesToHex(h) != storedHash) return false
            prev = h
        }
        return true
    }
```

with:

```kotlin
    /**
     * Walk the chain: hash linkage plus the spec/chain.md per-event field
     * rules. Returns one message per failure — empty means the chain
     * verifies. [participants] defaults to the empty set, so a caller that
     * forgets to pass it fails closed: every actor except `system:host` is
     * rejected.
     */
    internal fun verifyChain(
        events: List<JCSValue>,
        participants: Set<String> = emptySet(),
    ): List<String> {
        val errors = mutableListOf<String>()
        var prev = Chain.GENESIS_PREV
        events.forEachIndexed { i, e ->
            val seq = i + 1
            val obj = e as? JCSValue.Obj
            if (obj == null) {
                errors += "seq $seq: event is not a JSON object"
                return@forEachIndexed
            }
            fun field(key: String): String? =
                (obj.pairs.firstOrNull { it.first == key }?.second as? JCSValue.Str)?.v

            val actor = field("actor")
            if (actor == null || (actor != Chain.HOST_ACTOR && actor !in participants)) {
                errors += "seq $seq: actor ${Chain.debugQuoted(actor)} " +
                    "not in manifest.participants and not system:host"
            }
            val kind = field("kind")
            if (!Chain.isValidEventKind(kind)) {
                errors += "seq $seq: kind ${Chain.debugQuoted(kind)} is not one of " +
                    Chain.EVENT_KINDS.joinToString(", ")
            }

            var stored: String? = null
            val withoutHash = mutableListOf<Pair<String, JCSValue>>()
            for ((k, v) in obj.pairs) {
                if (k == "hash" && v is JCSValue.Str) stored = v.v
                else withoutHash += k to v
            }
            val storedHash = stored
            if (storedHash == null) {
                errors += "seq $seq: hash missing or wrong length"
                return@forEachIndexed
            }
            val prevHex = field("prev_hash")
            if (prevHex == null) {
                errors += "seq $seq: prev_hash missing or wrong length"
                return@forEachIndexed
            }
            val expectedPrev = CapsuleCrypto.bytesToHex(prev)
            if (prevHex != expectedPrev) {
                errors += "seq $seq: prev_hash mismatch: got $prevHex, expected $expectedPrev"
            }
            val canonical = JCS.bytes(JCSValue.Obj(withoutHash))
            val h = CapsuleCrypto.sha256(CapsuleCrypto.concat(prev, canonical))
            val recomputed = CapsuleCrypto.bytesToHex(h)
            if (recomputed != storedHash) {
                errors += "seq $seq: hash mismatch: stored $storedHash, recomputed $recomputed"
            }
            prev = h
        }
        return errors
    }
```

(The `actor == null ||` branch is load-bearing: `actor !in participants` alone will not type-check, because Kotlin's `Iterable<T>.contains` is `@OnlyInputTypes` and `actor` is `String?` while `participants` is `Set<String>`.)

- [ ] **Step 6: Add the two guards to the Kotlin builder**

In `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Builder.kt`, replace lines 60-66:

```kotlin
    fun appendEvent(
        actor: String, kind: String, action: String, target: String,
        timestamp: String? = null,
        payload: JCSValue = JCSValue.Obj(emptyList()),
        untrustedPayloadFields: List<String> = emptyList(),
    ) = apply {
        bareEvents += BareEvent(
```

with:

```kotlin
    /**
     * Append a chain event. seq, event_id, prev_hash, and hash are computed
     * at seal time.
     *
     * Throws [IllegalArgumentException] (spec/chain.md) when [kind] is
     * outside the closed enum, or when [actor] is neither `"system:host"`
     * nor an actor id already passed to [setParticipants]. The builder
     * never auto-registers participants — call [setParticipants] before
     * [appendEvent].
     */
    fun appendEvent(
        actor: String, kind: String, action: String, target: String,
        timestamp: String? = null,
        payload: JCSValue = JCSValue.Obj(emptyList()),
        untrustedPayloadFields: List<String> = emptyList(),
    ) = apply {
        require(Chain.isValidEventKind(kind)) {
            "event kind ${Chain.debugQuoted(kind)} is not one of " +
                Chain.EVENT_KINDS.joinToString(", ")
        }
        require(actor == Chain.HOST_ACTOR || participants.any { it.actorId == actor }) {
            "event actor ${Chain.debugQuoted(actor)} is not a declared participant: " +
                "call setParticipants(...) with actorId ${Chain.debugQuoted(actor)} " +
                "before appendEvent (only \"system:host\" may appear without one)"
        }
        bareEvents += BareEvent(
```

- [ ] **Step 7: Fix the one existing Kotlin test the change breaks**

In `sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/RoundTripTest.kt`, replace lines 101-102:

```kotlin
            .setProgram("# Hi\n")
            .appendEvent(
```

with:

```kotlin
            .setProgram("# Hi\n")
            .setParticipants(
                listOf(
                    CapsuleBuilder.Participant(
                        actorId = "human:test",
                        role = "originator",
                        label = "Test",
                    )
                )
            )
            .appendEvent(
```

(`roundTripBuildVerifyParse` at line 20 already calls `setParticipants` with `human:test` before appending, so it needs no change.)

- [ ] **Step 8: Run the test to verify it passes**

Run: `cd sdk-kotlin && ./gradlew --no-daemon :core:test --tests '*ActorKindTest*'`

Expected: PASS — `BUILD SUCCESSFUL`, 9 tests executed, 0 failed.

- [ ] **Step 9: Run the full lane suite for regressions**

Run: `cd sdk-kotlin && ./gradlew --no-daemon :core:test`

Expected: `BUILD SUCCESSFUL` — `RoundTripTest` (2), `ParityTest`, `EnvelopeTest`, `JcsNumbersVectorTest`, and `ActorKindTest` (9), 0 failures.

- [ ] **Step 10: Record the breaking change in the CHANGELOG**

In `CHANGELOG.md`, insert immediately after line 10 (`## Unreleased`) and before line 12 (`### Added`):

```markdown
### Changed

- **BREAKING — chain.md step-6 actor rule and the `kind` enum are now
  enforced everywhere.** All five verifiers (sdk-js, sdk-py,
  verifier-rust, sdk-swift, sdk-kotlin) reject a chain event whose
  `actor` is neither `system:host` nor a declared
  `manifest.participants[].actor_id`, and whose `kind` falls outside
  `decision | observation | mutation | session | checkpoint`. Previously
  only verifier-rust checked the actor and no lane checked the kind, so
  the reference SDK's default onboarding path produced capsules the
  repo's own Rust verifier rejected. Every lane emits the same per-event
  message shape. `CapsuleBuilder.appendEvent` / `append_event` now
  rejects both at append time rather than auto-registering the actor;
  callers must declare participants before appending. `verifyChain` /
  `verify_chain` take the participant set (defaulting to empty, i.e.
  fail-closed); Swift's `CapsuleReader.verifyChain` returns per-event
  errors instead of `Bool` and its `appendEvent` is throwing; Swift and
  Kotlin `CapsuleVerification` gain `chainErrors`. New negative vectors
  live in `spec/vectors/chain-rules/`. Wire format unchanged.

```

- [ ] **Step 11: Commit**

```bash
git add sdk-kotlin/core/src CHANGELOG.md
git commit -m "feat(sdk-kotlin)!: enforce chain.md step-6 actor rule and the kind enum

BREAKING: CapsuleVerifier.verifyChain returns per-event error strings
instead of Bool and takes the manifest participant set; CapsuleVerification
gains chainErrors; CapsuleBuilder.appendEvent requires the actor to be a
declared participant (or system:host) and the kind to be in the enum.
Messages match verifier-rust. Completes C7 across all five lanes.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```


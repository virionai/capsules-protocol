# C9 — The I-JSON acceptance boundary and Pith surrogate splitting

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Part of:** [Capsules pre-release remediation](./README.md) · Tier 2 (v0.7 correctness)

**Findings closed:** F05, F32, F08

**Lanes touched:** spec, sdk-js, sdk-py, verifier-rust, sdk-swift, sdk-kotlin, tools

**Tasks:** 9

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

1. **13 existing jcs-numbers vectors flip from "serialize" to "reject".** This is unavoidable: they are integer-valued doubles in [2^53, 1e21) whose canonical token is exactly the unsafe plain integer literal the boundary forbids. Task 2 marks them `"accepted": false` and each lane task teaches its own number-vector test to honour the flag. If a lane task lands without its test update, that lane's number-vector test fails. Task order matters: Task 2 (marker) is backward compatible — a lane that ignores the new field still passes until it gains its guard.

2. **sdk-kotlin `:core` may not compile today, independent of this cluster.** `CapsuleException` is thrown in five places in Reader.kt (lines 27, 29, 31, 33, 46) and I could not find a declaration anywhere under sdk-kotlin (`grep -rln CapsuleException sdk-kotlin/` returns only Reader.kt and ParityTest.kt). If that is real, `./gradlew :core:test` is already red and Task 7's verification steps will fail for a reason that is not C9's. Task 7 therefore uses `require(...)`/IllegalArgumentException, matching the existing idiom at Canonical.kt:30, and introduces no dependency on that type. Flag to the maintainer: this looks like a separate finding.

3. **Kotlin's failure mode is silent corruption, not an exception.** `String.toByteArray(Charsets.UTF_8)` replaces unmappable code units with `?` (0x3F) rather than throwing, so today a lone surrogate in a Kotlin-read capsule produces a *different hash*, not an error. Task 7 is the only lane fix that changes a silent-wrong-answer into a refusal. It is also the one lane I could not execute.

4. **Cross-lane message coupling.** Every lane emits the same substring `integer outside IEEE-754 exact range (|n| > 2^53 - 1)` (already the wording in sdk-py, sdk-swift and sdk-kotlin before this change) and `unpaired surrogate`. The vector files key off normative `reason` categories, not exact strings, so a lane may reword — but the per-lane number-vector tests assert on the substring, so a reword needs a matching test update in that lane.

5. **Cross-cluster contact on spec/chain.md and the Rust chain walk.** The chain.md step-6 actor-rule cluster edits chain.md's *Verification* list and `chain_walk_into` in verifier.rs. C9 edits chain.md's *Hashing* section (lines 43-56) and `verify_chain` in chain.rs. Different sections and different functions, but the same two files — merge them in one direction, not concurrently. I deliberately did not add a numbered step to chain.md's Verification list for this reason.

6. **`assertIJson` walks every value on every `jcs()` call.** For a capsule with a large payload this doubles the traversal (guard, then `canonicalize`). Measured cost is invisible at conformance-fixture sizes (sdk-js suite went 95.9ms -> 96.9ms), but a host sealing megabyte payloads will notice. If that ever matters, the fix is to fold the check into an in-house canonicalizer, not to drop it.

7. **`appendEvent` now throws.** Task 2 makes `CapsuleBuilder.appendEvent` reject non-I-JSON payloads. Pre-release, breaking changes are fine, but any host that appends machine-generated numeric payloads (nanosecond timestamps are the obvious case) will start seeing throws at a call site that previously never threw. That is the intended behaviour — the alternative is sealing an unverifiable capsule — but it is a visible API behaviour change.

8. **The unicode-boundary fixture is signed by a throwaway key generated at fixture-creation time.** Regenerating it (running the generator without `--check`) rewrites every hash in the capsule. Task 9's generator therefore supports `--check`, and the plan says to run the write path exactly once.

## Validation performed while specifying this plan

The steps below were applied to a **copy of the repository outside the working tree** and executed. This is the real output from that run, not a prediction.

<details>
<summary>Expand validation log</summary>

```
Applied the whole cluster on a copy at /private/tmp/.../scratchpad/work-c9 (outside the repo) and ran every lane I could.

REPRODUCTION FIRST (pristine code, work copy):
- 'node -e "jcs(1e19)"' -> '10000000000000000000'; 'jcs(9007199254740993)' -> '9007199254740992'; 'jcs('a\ud83d')' -> bytes '22615c756438336422' (i.e. '"a\ud83d"').
- 'compressText('🙂'.repeat(200))' -> len 280, tail code units '['1f642','d83d','2026']', lone-surrogate regex = true.
- End-to-end: JS built an emoji-summary capsule, 'JS verify ok = true'; Python: 'PY verify ok = False', 'chain: {'ok': False, 'errors': [{'seq': 1, 'message': "recompute failed: 'utf-8' codec can't encode character '\\ud83d' in position 238: surrogates not allowed"}]}'. F08 confirmed exactly as reported.

AFTER THE FIX (same work copy):
- sdk-js 'npm test': '# tests 69 / # pass 69 / # fail 0' (baseline was 57; +8 ijson.test.js, +4 pith).
- sdk-py 'PYTHONPATH=src python3 -m pytest': '197 passed in 0.25s' (baseline 182; I added the 14 ijson-acceptance params and the 1 unicode-boundary param but did NOT add the 4 test_canonical.py unit tests from Task 4, so the plan's stated 201 = 182 + 4 + 14 + 1).
- verifier-rust 'cargo test --workspace': lib '107 passed; 0 failed' (baseline 102, +5), parity '7 passed', spec_registry '5 passed' (baseline 3, +2). Note: plain 'cargo test' at the workspace root runs only the root parity package — '--workspace' is required to reach the lib unit tests.
- 'node tools/check-spec-vectors.mjs': 'spec vectors: ok (295 vectors)' (baseline 280; +14 ijson-acceptance, +1 unicode-boundary).
- 'node sdk-js/tools/generate-unicode-boundary-fixture.mjs --check': 'unicode-boundary fixture: ok'.
- 'node sdk-js/tools/generate-malformed-fixtures.mjs --check': all 10 fixtures 'ok'.
- cli 'npm test': '50 passed, 0 failed'.
- Re-ran the end-to-end repro after the pith fix: 'PY verify ok = True | chain ok = True'.
- 13 of the 256 vectors in spec/vectors/jcs-numbers.json are integer-valued doubles in [2^53, 1e21) whose canonical token is a plain integer literal out of range (bits 4340000000000000, 4340000000000001, 4341c37937e08000, 4415af1d78b58c40, 444b1ae4d6e2ef4f, c41ffe4ab369fb39, 435755d5d0c11597, 4441ec887006ad1f, 43d781da8f3fda6b, 441b1a5318c779e1, c3a990cc3ef98a28, c3a2446e028e9985, 438c3df5b984cf13). Adding the guard breaks the number-vector test in every lane unless those entries are marked. I discovered this by running the tests, not by inspection, and Task 2 carries the marker script. I also confirmed 'JSON.stringify(doc, null, 2) + "\n"' round-trips the existing file byte-identically, so the marker script produces a clean 26-line diff.

SWIFT: 'swift test' cannot run in this environment ('error: no such module 'XCTest'' — CommandLineTools-only toolchain), and the copied '.build' had a stale module cache that had to be deleted first. What I did instead: 'swift build' from the patched sdk-swift -> 'Build complete! (12.85s)', exit 0, so JCS.swift, Reader.swift and Builder.swift compile with the change. Then I compiled the patched 'JCS.swift' standalone against a 'CapsuleError' stub with 'swiftc' and ran it. Real output: decimal 1e19 REJECTED, 1.7e18 REJECTED, 1e21 ACCEPTED, 9007199254740991 ACCEPTED, 9007199254740992 REJECTED, integer 2^53-1 ACCEPTED, integer 2^53 REJECTED, nested '$.payload.ts_ns' REJECTED with the path in the message, 1.5 ACCEPTED, astral string ACCEPTED; 'canonical(1e19) = 10000000000000000000', 'canonical(1e21) = 1e+21'. I did NOT run the Swift XCTest suite — the test-file edits in Task 6 are verified by inspection only.
Separately confirmed with a Foundation probe that Swift's 'JSONSerialization' already refuses '"x\ud83d"' at parse ("expected low-surrogate code point but did not find one"), which is why Task 6 enforces only the number rule.

KOTLIN: not run. 'java -version' -> "Unable to locate a Java Runtime", so './gradlew :core:test' is impossible here. Task 7 is written against the real API (JCSValue sealed class, 'JCS.canonical'/'bytes', 'private const val MAX_SAFE_INTEGER' at Canonical.kt:51, 'CapsuleReader.parseJson' at Reader.kt:63, 'CapsuleBuilder.seal' at Builder.kt:85-95) and is verified by inspection only. I deliberately used 'require(...)' rather than 'CapsuleException' — see risks.
```

</details>

---

## C9 — The I-JSON acceptance boundary and Pith surrogate splitting

**The disease.** RFC 8785 is only defined over I-JSON (RFC 7493) input, and nothing in the reference lane enforces that. `sdk-js/src/canonical.js:10` hands arbitrary JS values to the `canonicalize` package, which happily serializes `1e19` as the twenty-digit literal `10000000000000000000` and emits lone surrogates as `\ud83d` escapes. `sdk-py/src/capsule/canonical.py:21` refuses the first and `encode('utf-8')` blows up on the second; `serde_json` refuses lone-surrogate escapes at parse. Meanwhile `sdk-js/src/pith.js:99` slices UTF-16 code units at an odd index, Pith is on by default, and so ordinary emoji-bearing user text gets a lone surrogate baked into `chain/events.jsonl` and signed. Reproduced end-to-end: JS says `ok: true`, Python says `recompute failed: 'utf-8' codec can't encode character '\ud83d'` — an encoder bug wearing a tampering costume.

**The cure.** One normative acceptance rule in `spec/`, expressed on the *canonical token* so it is trivially portable ("a plain integer literal must satisfy |n| ≤ 2^53−1; every string must be well-formed Unicode"), enforced identically at every lane's JCS boundary, with builders failing at append time rather than sealing something only they can verify.

Task order is load-bearing: Task 2 marks the 13 out-of-boundary entries in the shared `jcs-numbers.json`, and each lane task teaches its own vector test to honour that flag as it adds its guard. Tasks 8 and 9 add the shared vectors last, once every lane can pass them.

---

### Task 1: Write the I-JSON acceptance boundary into the spec

**Files:**
- Create: `spec/canonicalization.md`
- Modify: `spec/README.md:90-99`
- Modify: `spec/chain.md:43-56`
- Modify: `spec/pith.md:57-68`
- Test: `spec/canonicalization.md` (prose; verified by the link check in Step 5)

**Interfaces:**
- Consumes: none
- Produces: normative document `spec/canonicalization.md`, referenced by every later task's code comments

- [ ] **Step 1: Write the failing test**

There is no test framework for spec prose. The failing check is that the document index does not resolve — every other `spec/*.md` is reachable from `spec/README.md`, and the new file must be too. Write the check first:

```bash
# scratch check — every relative .md link in spec/*.md must resolve,
# and every spec/*.md must be reachable from spec/README.md
cd /Users/complex/repo/open-source/capsules-protocol
node -e '
const { readdirSync, readFileSync, existsSync } = require("node:fs");
const { join, dirname } = require("node:path");
let bad = 0;
const files = readdirSync("spec").filter((f) => f.endsWith(".md"));
for (const f of files) {
  const src = readFileSync(join("spec", f), "utf8");
  for (const m of src.matchAll(/\]\(([^)#]+\.md)\)/g)) {
    const target = join(dirname(join("spec", f)), m[1]);
    if (!existsSync(target)) { console.error(`BROKEN ${f} -> ${m[1]}`); bad++; }
  }
}
const index = readFileSync("spec/README.md", "utf8");
for (const f of files) {
  if (f === "README.md") continue;
  if (!index.includes(`(${f})`)) { console.error(`UNINDEXED ${f}`); bad++; }
}
console.log(bad === 0 ? "spec links: ok" : `spec links: ${bad} problem(s)`);
process.exit(bad === 0 ? 0 : 1);
'
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/complex/repo/open-source/capsules-protocol && node -e '<the script from Step 1>'` after creating an empty `spec/canonicalization.md` with `touch spec/canonicalization.md`

Expected: FAIL with `UNINDEXED canonicalization.md` and `spec links: 1 problem(s)`, exit code 1.

- [ ] **Step 3: Write `spec/canonicalization.md`**

```markdown
# Canonicalization Input (I-JSON)

RFC 8785 (JCS) defines a canonical serialization for JSON values. It does
not define one for every value a JSON parser can produce. Its input domain
is I-JSON (RFC 7493): numbers exactly representable as IEEE-754 binary64,
strings that are well-formed Unicode.

Every JCS call in this spec — the chain event hash ([chain.md](chain.md)),
`manifest_hash` and `content_index.index_hash` ([manifest.md](manifest.md)),
the envelope canonical payload and the encryption AAD
([envelope.md](envelope.md)), and the federation attestation signing input
([federation.md](federation.md)) — takes I-JSON input and nothing else.

## The acceptance boundary

A value is **acceptable** when both rules below hold, recursively, for
every number, string, and object key it contains.

### Numbers

- Every number MUST be a finite IEEE-754 binary64. NaN and ±Infinity are
  not JSON and MUST be rejected.
- A number whose canonical token is a **plain integer literal** — the token
  contains neither `.` nor `e` — MUST satisfy |n| ≤ 2^53 − 1
  (`9007199254740991`).

The second rule is a rule about the *token*, not about the host language's
type system. ECMAScript `Number::toString`, which RFC 8785 §3.2.2.3
mandates, emits a plain integer literal exactly when the value is integral
and |n| < 10^21; at or above 10^21 it emits exponent form (`1e+21`).
Exponent-form tokens round-trip identically through every implementation's
double path and are acceptable at any magnitude. Plain integer literals
outside ±(2^53 − 1) are not: an implementation whose JSON parser uses
native integers keeps the exact digits, one whose parser uses binary64
silently rounds them, and the two then hash different bytes.

Worked example. `1e19` is an ordinary value — `Date.now() * 1e6`, a
nanosecond timestamp — and canonicalizes to the twenty-digit token
`10000000000000000000`. A binary64 parser reads that token back as `1e19`;
a native-integer parser reads it as the exact integer. The capsule verifies
in the first implementation and fails in the second, and the failure
surfaces as a chain-hash mismatch that reads like tampering.

### Strings

- Every string, and every object key, MUST be well-formed Unicode: no
  surrogate code point may appear outside a well-formed surrogate pair.

An unpaired surrogate is not a Unicode scalar value and has no UTF-8
encoding. `\uD83D` alone in a JSON string is representable in UTF-16-based
languages and unrepresentable everywhere else; the byte sequence JCS is
defined over cannot exist.

## Where the boundary is enforced

- **Builders MUST reject at build time.** A builder that seals a capsule
  containing an unacceptable value has produced an artifact only its own
  implementation can verify. Rejection happens when the value is appended,
  not when the bytes are written, so the caller still has the offending
  value in hand.
- **Verifiers MUST reject.** Rejection may happen at JSON parse time or at
  the canonicalization gate, whichever the implementation reaches first;
  both are conforming. What is normative is that an unacceptable value
  never reaches a hash comparison.
- **The rejection MUST be distinguishable from a hash mismatch.** A
  verifier that reports "hash mismatch" for an unacceptable value tells the
  operator the capsule was tampered with. It was not; the producer emitted
  bytes outside the acceptance boundary. Report the canonicalization
  refusal.

## Conformance vectors

- `spec/vectors/ijson-acceptance.json` — raw JSON texts that MUST be
  accepted (with the canonical form pinned) or rejected, with a normative
  `reason` vocabulary.
- `spec/vectors/jcs-numbers.json` — bit patterns marked `"accepted": false`
  are outside the boundary. Their `expected` field records the
  `Number::toString` layout for reference, but canonicalization MUST refuse
  the value.
- `spec/vectors/unicode-boundary/` — a sealed capsule whose narrative field
  carries truncated astral text. Every implementation MUST verify it
  `ok: true`.

## Normalizers must not manufacture violations

Any transform applied to a narrative field before sealing — the Pith
normalizer is the one this spec ships — operates on text that will be
canonicalized. A transform that cuts a string at a UTF-16 code-unit index
can split a surrogate pair and produce an unacceptable value from
acceptable input. Truncation MUST cut on a code-point boundary. See
[pith.md](pith.md).
```

- [ ] **Step 4: Add the document to the spec index**

In `spec/README.md`, the "Document index" section currently reads:

```markdown
## Document index

- [format.md](format.md) — file layout
- [manifest.md](manifest.md) — manifest.json schema and capsule identity
```

Replace those four lines with:

```markdown
## Document index

- [format.md](format.md) — file layout
- [canonicalization.md](canonicalization.md) — JCS input domain: the
  I-JSON acceptance boundary every implementation enforces identically
- [manifest.md](manifest.md) — manifest.json schema and capsule identity
```

- [ ] **Step 5: Point chain.md's Hashing section at the boundary**

`spec/chain.md:43-56` currently ends the "Hashing" section with:

```markdown
The genesis previous-hash value is 32 zero bytes (not the 64 ASCII zeros
of the prior format).
```

Replace that paragraph with:

```markdown
The genesis previous-hash value is 32 zero bytes (not the 64 ASCII zeros
of the prior format).

`JCS(...)` above is defined only over I-JSON input. An event whose payload
carries a number outside the IEEE-754 exact-integer range, or a string with
an unpaired surrogate, has no canonical form: builders MUST reject it at
`appendEvent` time, and verifiers MUST report the refusal as a
canonicalization error rather than as a hash mismatch. See
[canonicalization.md](canonicalization.md).
```

- [ ] **Step 6: Make surrogate-safe truncation normative in pith.md**

`spec/pith.md:57-68` currently ends the "Library defaults" section with:

```markdown
These defaults are a starting point, not protocol. Implementations may
tune. Two implementations producing the same JSON event after
normalization are considered conformant; byte-for-byte identical
normalized output across implementations is *not* a v0.6 promise.
```

Insert a new section immediately after that paragraph (before `## Opting out`):

```markdown
## Truncation and the canonicalization boundary

Normalized text is canonicalized and hashed. The normalizer therefore MUST
NOT produce a string that JCS cannot accept.

Concretely: `maxChars` counts characters, and a truncating implementation
MUST cut on a Unicode code-point boundary. Cutting at a UTF-16 code-unit
index splits surrogate pairs — with the default `maxChars` of 280 the cut
index is odd, so ordinary text containing emoji lands mid-pair — and the
resulting unpaired surrogate is outside the acceptance boundary in
[canonicalization.md](canonicalization.md). The capsule then seals in the
implementation that produced it and fails to verify everywhere else, with
an error that reads like tampering.

This is a MUST even though byte-identical normalizer output is not a v0.6
promise: what varies across implementations is *where* the cut lands, not
*whether* the result is well-formed Unicode.
```

- [ ] **Step 7: Run the link check to verify it passes**

Run: `cd /Users/complex/repo/open-source/capsules-protocol && node -e '<the script from Step 1>'`

Expected: PASS — prints `spec links: ok`, exit code 0.

- [ ] **Step 8: Run the JS conformance harness for regressions**

Run: `cd /Users/complex/repo/open-source/capsules-protocol && node tools/regen-capsule-skill.mjs --check && node tools/check-spec-vectors.mjs`

Expected: the skill-regen check exits 0, and `spec vectors: ok (280 vectors)`.

- [ ] **Step 9: Commit**
```bash
git add spec/canonicalization.md spec/README.md spec/chain.md spec/pith.md
git commit -m "spec: make the I-JSON acceptance boundary normative

RFC 8785 is only defined over I-JSON input. Nothing in the spec said so,
so implementations disagreed on out-of-range integer literals and unpaired
surrogates and the disagreement surfaced as a chain-hash mismatch that
reads like tampering. State the rule on the canonical token, require
builders to reject at build time, and require verifiers to report a
canonicalization refusal rather than a hash mismatch."
```

---

### Task 2: Enforce the acceptance boundary in the sdk-js JCS boundary

**Files:**
- Modify: `sdk-js/src/canonical.js:7-16`
- Modify: `sdk-js/src/builder.js:3` and `sdk-js/src/builder.js:97-100`
- Modify: `sdk-js/src/index.js:16-20`
- Modify: `sdk-js/src/index.d.ts:229`
- Modify: `spec/vectors/jcs-numbers.json` (add `"accepted": false` to 13 entries)
- Modify: `sdk-js/test/jcs-numbers.test.js:15-19`
- Modify: `tools/check-spec-vectors.mjs:19-23` and `tools/check-spec-vectors.mjs:254-262`
- Test: `sdk-js/test/ijson.test.js` (new)

**Interfaces:**
- Consumes: `spec/canonicalization.md` (Task 1); `canonicalize(object) -> string` from the `canonicalize` npm package
- Produces: `assertIJson(value, path = "$") -> void` (throws `Error`), exported from `sdk-js/src/canonical.js` and re-exported from `sdk-js/src/index.js`; `jcs(obj)` now throws on unacceptable input; `CapsuleBuilder.appendEvent` now throws; the `accepted?: boolean` field on `jcs-numbers.json` vector entries

- [ ] **Step 1: Write the failing test**

Create `sdk-js/test/ijson.test.js`:

```js
// I-JSON acceptance boundary (spec/canonicalization.md).
//
// RFC 8785 is only defined over I-JSON input. The `canonicalize` package
// enforces neither the number nor the string half of that, so without an
// explicit guard the reference builder seals capsules that sdk-py and
// verifier-rust cannot recompute.

import { test } from "node:test";
import assert from "node:assert/strict";

import { assertIJson, jcs } from "../src/canonical.js";
import { CapsuleBuilder, generateEd25519 } from "../src/index.js";

const TS = "2026-05-07T12:00:00Z";

test("jcs rejects a plain integer literal outside the IEEE-754 exact range", () => {
  // Date.now() * 1e6 — a nanosecond timestamp, ~1.7e18, entirely plausible.
  assert.throws(
    () => jcs({ ts_ns: 1.7e18 }),
    /integer outside IEEE-754 exact range/,
  );
  // 1e19 serializes as the 20-digit literal 10000000000000000000.
  assert.throws(() => jcs(1e19), /integer outside IEEE-754 exact range/);
  // 2^53 itself is one past the exact range.
  assert.throws(() => jcs(9007199254740992), /integer outside IEEE-754 exact range/);
});

test("jcs accepts the exact-range boundary and exponent-form magnitudes", () => {
  assert.equal(Buffer.from(jcs(9007199254740991)).toString("utf8"), "9007199254740991");
  assert.equal(Buffer.from(jcs(-9007199254740991)).toString("utf8"), "-9007199254740991");
  // >= 1e21 serializes in exponent form, which round-trips through every
  // lane's double path.
  assert.equal(Buffer.from(jcs(1e21)).toString("utf8"), "1e+21");
  assert.equal(Buffer.from(jcs(1.5)).toString("utf8"), "1.5");
});

test("jcs rejects unpaired surrogates in values and in keys", () => {
  assert.throws(() => jcs({ summary: "a\ud83d" }), /unpaired surrogate U\+D83D/);
  assert.throws(() => jcs({ summary: "\udc00b" }), /unpaired surrogate U\+DC00/);
  assert.throws(() => jcs({ "k\ud800": 1 }), /unpaired surrogate U\+D800/);
  assert.throws(() => jcs(["ok", "x\udfff"]), /unpaired surrogate U\+DFFF/);
});

test("jcs accepts well-formed astral characters", () => {
  assert.equal(Buffer.from(jcs({ s: "a\u{1F642}" })).toString("utf8"), '{"s":"a\u{1F642}"}');
});

test("assertIJson names the offending path", () => {
  assert.throws(
    () => assertIJson({ payload: { open_items: [{ item: "x\ud83d" }] } }),
    /at \$\.payload\.open_items\[0\]\.item/,
  );
});

test("jcs still rejects non-finite numbers", () => {
  assert.throws(() => jcs(Number.NaN), /non-finite number/);
  assert.throws(() => jcs(Number.POSITIVE_INFINITY), /non-finite number/);
});

test("appendEvent rejects an out-of-range integer before the capsule is sealed", () => {
  const ed = generateEd25519();
  const builder = new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex },
    participants: [{ actor_id: "human:alice", role: "originator" }],
    createdAt: TS,
  });
  assert.throws(
    () =>
      builder.appendEvent({
        actor: "human:alice",
        action: "note",
        payload: { ts_ns: 1.7e18 },
      }),
    /appendEvent: JCS: integer outside IEEE-754 exact range .* at event\[0\]\.payload\.ts_ns/,
  );
});

test("appendEvent rejects an unpaired surrogate before the capsule is sealed", () => {
  const ed = generateEd25519();
  const builder = new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex },
    participants: [{ actor_id: "human:alice", role: "originator" }],
    createdAt: TS,
  });
  assert.throws(
    () =>
      builder.appendEvent(
        { actor: "human:alice", action: "note", payload: { note: "x\ud83d" } },
        { pith: false },
      ),
    /appendEvent: JCS: unpaired surrogate U\+D83D at event\[0\]\.payload\.note/,
  );
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-js && node --test test/ijson.test.js`

Expected: FAIL — the first subtest reports `The expression evaluated to a falsy value: assert.throws(...)` because `jcs({ ts_ns: 1.7e18 })` currently succeeds, and the import of `assertIJson` resolves to `undefined`. Summary line `# fail 7` (the astral-passthrough test is the only one that passes today).

- [ ] **Step 3: Add the guard to `sdk-js/src/canonical.js`**

Lines 7-16 currently read:

```js
const enc = new TextEncoder();

/** JCS-canonicalize an object and return UTF-8 bytes. */
export function jcs(obj) {
  const s = canonicalize(obj);
  if (typeof s !== "string") {
    throw new Error("canonicalize() did not return a string");
  }
  return enc.encode(s);
}
```

Replace with:

```js
const enc = new TextEncoder();

// RFC 8785 §3.1 is only defined over I-JSON (RFC 7493) input: every number
// must be exactly representable as an IEEE-754 binary64, and every string
// must be well-formed Unicode. The `canonicalize` package enforces neither,
// so the reference lane would otherwise seal capsules that sdk-py and
// verifier-rust cannot recompute. See spec/canonicalization.md.
const PLAIN_INTEGER_CEILING = 1e21;

/**
 * Reject values outside the I-JSON acceptance boundary.
 *
 * Numbers: ECMAScript Number::toString emits a *plain integer literal*
 * (no `.`, no `e`) exactly when the value is integral and |v| < 1e21.
 * A plain integer literal outside ±(2^53 - 1) does not survive a
 * round-trip through implementations whose JSON parsers use native
 * integers, so it is rejected here. Integral values >= 1e21 serialize in
 * exponent form (`1e+21`), which round-trips through every lane's
 * double path, and are accepted.
 *
 * Strings: an unpaired surrogate is not a Unicode scalar value. UTF-8
 * cannot encode it, so a capsule carrying one is unverifiable in any
 * lane whose strings are scalar sequences.
 *
 * `path` is a dotted breadcrumb used only in the error message.
 */
export function assertIJson(value, path = "$") {
  if (value === null || value === undefined) return;
  const t = typeof value;
  if (t === "boolean" || t === "symbol" || t === "function") return;
  if (t === "bigint") {
    throw new Error(`JCS: BigInt is not JSON at ${path}`);
  }
  if (t === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(`JCS: non-finite number at ${path}`);
    }
    const magnitude = Math.abs(value);
    if (
      Number.isInteger(value) &&
      magnitude > Number.MAX_SAFE_INTEGER &&
      magnitude < PLAIN_INTEGER_CEILING
    ) {
      throw new Error(
        `JCS: integer outside IEEE-754 exact range (|n| > 2^53 - 1) at ${path}; ` +
          "not representable identically across implementations",
      );
    }
    return;
  }
  if (t === "string") {
    assertWellFormedUnicode(value, path);
    return;
  }
  if (typeof value.toJSON === "function") {
    assertIJson(value.toJSON(), path);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, i) => assertIJson(entry, `${path}[${i}]`));
    return;
  }
  for (const key of Object.keys(value)) {
    assertWellFormedUnicode(key, `${path}.${key}`);
    assertIJson(value[key], `${path}.${key}`);
  }
}

/**
 * Throw if `s` contains an unpaired surrogate. Iterating a string with
 * for..of yields code points; a well-formed surrogate pair yields the
 * single astral code point, so any yielded value in D800..DFFF is an
 * unpaired surrogate.
 */
function assertWellFormedUnicode(s, path) {
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (cp >= 0xd800 && cp <= 0xdfff) {
      throw new Error(
        `JCS: unpaired surrogate U+${cp.toString(16).toUpperCase()} at ${path}; ` +
          "strings must be well-formed Unicode",
      );
    }
  }
}

/** JCS-canonicalize an object and return UTF-8 bytes. */
export function jcs(obj) {
  assertIJson(obj);
  const s = canonicalize(obj);
  if (typeof s !== "string") {
    throw new Error("canonicalize() did not return a string");
  }
  return enc.encode(s);
}
```

- [ ] **Step 4: Make `appendEvent` fail at append time**

In `sdk-js/src/builder.js`, line 3 currently reads:

```js
import { jcs, sha256, sha256Hex } from "./canonical.js";
```

Replace with:

```js
import { assertIJson, jcs, sha256, sha256Hex } from "./canonical.js";
```

Then lines 97-100 currently read:

```js
    const applyPith = options.pith !== false && this.pith;
    const rawPayload = event.payload ?? {};
    const payload = applyPith ? compressEventPayload(rawPayload) : rawPayload;
    this.bareEvents.push({
```

Replace with:

```js
    const applyPith = options.pith !== false && this.pith;
    const rawPayload = event.payload ?? {};
    const payload = applyPith ? compressEventPayload(rawPayload) : rawPayload;
    // Fail here, not at seal(): a payload outside the I-JSON acceptance
    // boundary (spec/canonicalization.md) cannot be canonicalized, and the
    // caller still has the offending value in scope at this point.
    try {
      assertIJson(payload, `event[${this.bareEvents.length}].payload`);
    } catch (err) {
      throw new Error(`appendEvent: ${err.message}`);
    }
    this.bareEvents.push({
```

- [ ] **Step 5: Export the guard from the public surface**

In `sdk-js/src/index.js`, lines 16-20 currently read:

```js
export {
  jcs,
  sha256,
  sha256Hex,
} from "./canonical.js";
```

Replace with:

```js
export {
  assertIJson,
  jcs,
  sha256,
  sha256Hex,
} from "./canonical.js";
```

In `sdk-js/src/index.d.ts`, line 229 currently reads:

```ts
export function jcs(value: unknown): Uint8Array;
```

Replace with:

```ts
/** Throws if `value` is outside the I-JSON acceptance boundary. */
export function assertIJson(value: unknown, path?: string): void;
export function jcs(value: unknown): Uint8Array;
```

- [ ] **Step 6: Run the new test to verify it passes**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-js && node --test test/ijson.test.js`

Expected: PASS — `# tests 8 / # pass 8 / # fail 0`.

- [ ] **Step 7: Mark the 13 out-of-boundary entries in the shared number vectors**

`spec/vectors/jcs-numbers.json` contains 256 bit patterns; 13 of them are integer-valued doubles in [2^53, 1e21) whose canonical token is a plain integer literal out of range, so the guard now refuses them. Mark them deterministically — the file round-trips byte-identically through `JSON.stringify(doc, null, 2) + "\n"`, so the diff is exactly the added fields. Write and run this one-shot script:

```js
// scratch/mark-unaccepted.mjs — run once from the repo root, then delete.
import { readFileSync, writeFileSync } from "node:fs";
const path = "spec/vectors/jcs-numbers.json";
const doc = JSON.parse(readFileSync(path, "utf8"));
let marked = 0;
for (const v of doc.vectors) {
  const value = Buffer.from(v.ieee_hex, "hex").readDoubleBE(0);
  const magnitude = Math.abs(value);
  if (Number.isInteger(value) && magnitude > Number.MAX_SAFE_INTEGER && magnitude < 1e21) {
    v.accepted = false;
    marked++;
  }
}
writeFileSync(path, JSON.stringify(doc, null, 2) + "\n");
console.log(`marked ${marked} vectors as accepted:false`);
```

Run: `cd /Users/complex/repo/open-source/capsules-protocol && node scratch/mark-unaccepted.mjs && git diff --stat spec/vectors/jcs-numbers.json`

Expected: `marked 13 vectors as accepted:false` and `1 file changed, 26 insertions(+), 13 deletions(-)`. The 13 marked bit patterns are `4340000000000000`, `4340000000000001`, `4341c37937e08000`, `4415af1d78b58c40`, `444b1ae4d6e2ef4f`, `c41ffe4ab369fb39`, `435755d5d0c11597`, `4441ec887006ad1f`, `43d781da8f3fda6b`, `441b1a5318c779e1`, `c3a990cc3ef98a28`, `c3a2446e028e9985`, `438c3df5b984cf13`. Also update the file's `description` field so the new flag is documented — replace the trailing sentence `Implementations must parse the bit pattern (not the expected string) and serialize it.` with `Implementations must parse the bit pattern (not the expected string) and serialize it. An entry marked \"accepted\": false is outside the I-JSON acceptance boundary (spec/canonicalization.md): \"expected\" records the Number::toString layout for reference, but canonicalization must refuse the value.`

- [ ] **Step 8: Teach the JS number-vector test the new flag**

`sdk-js/test/jcs-numbers.test.js:15-19` currently reads:

```js
  for (const { ieee_hex, expected } of vectors) {
    const value = Buffer.from(ieee_hex, "hex").readDoubleBE(0);
    const got = Buffer.from(jcs(value)).toString("utf8");
    assert.equal(got, expected, `bits ${ieee_hex}`);
  }
```

Replace with:

```js
  for (const { ieee_hex, expected, accepted } of vectors) {
    const value = Buffer.from(ieee_hex, "hex").readDoubleBE(0);
    if (accepted === false) {
      // Outside the I-JSON acceptance boundary (spec/canonicalization.md):
      // `expected` records the layout Number::toString would produce, but
      // the value must never reach a canonical serialization.
      assert.throws(
        () => jcs(value),
        /integer outside IEEE-754 exact range/,
        `bits ${ieee_hex} must be rejected (would serialize as ${expected})`,
      );
      continue;
    }
    const got = Buffer.from(jcs(value)).toString("utf8");
    assert.equal(got, expected, `bits ${ieee_hex}`);
  }
```

- [ ] **Step 9: Teach the spec-vector checker the new flag**

`tools/check-spec-vectors.mjs:254-262` (inside `checkNumberVectors`) currently reads:

```js
    const value = Buffer.from(ieee_hex, "hex").readDoubleBE(0);
    if (!Number.isFinite(value)) {
      fail(`${path}: vectors[${i}]: bit pattern is not a finite double`);
      return;
    }
    const got = Buffer.from(jcs(value)).toString("utf8");
    if (got !== expected) {
      fail(`${path}: vectors[${i}] (bits ${ieee_hex}): JS SDK serializes ${got}, vector says ${expected}`);
    }
```

Replace with:

```js
    const value = Buffer.from(ieee_hex, "hex").readDoubleBE(0);
    if (!Number.isFinite(value)) {
      fail(`${path}: vectors[${i}]: bit pattern is not a finite double`);
      return;
    }
    if (entry.accepted === false) {
      // Outside the I-JSON acceptance boundary: `expected` documents the
      // Number::toString layout, but canonicalization must refuse the value.
      let threw = false;
      try {
        jcs(value);
      } catch {
        threw = true;
      }
      if (!threw) {
        fail(`${path}: vectors[${i}] (bits ${ieee_hex}): accepted:false but jcs() accepted it`);
      }
      return;
    }
    const got = Buffer.from(jcs(value)).toString("utf8");
    if (got !== expected) {
      fail(`${path}: vectors[${i}] (bits ${ieee_hex}): JS SDK serializes ${got}, vector says ${expected}`);
    }
```

And update the header comment at `tools/check-spec-vectors.mjs:19-23`, which currently reads:

```js
//   3. A JCS number-serialization vector set (jcs-numbers.json): a `vectors`
//      array of `{ ieee_hex, expected }` entries, where `ieee_hex` is the
//      big-endian IEEE-754 binary64 bit pattern of the input and `expected`
//      its canonical RFC 8785 serialization. Implementations must parse the
//      bit pattern (not the expected string) and serialize it.
```

Replace with:

```js
//   3. A JCS number-serialization vector set (jcs-numbers.json): a `vectors`
//      array of `{ ieee_hex, expected, accepted? }` entries, where `ieee_hex`
//      is the big-endian IEEE-754 binary64 bit pattern of the input and
//      `expected` its canonical RFC 8785 serialization. Implementations must
//      parse the bit pattern (not the expected string) and serialize it.
//      `accepted: false` marks a bit pattern outside the I-JSON acceptance
//      boundary: `expected` records the Number::toString layout, but
//      canonicalization must refuse the value.
```

- [ ] **Step 10: Run the full lane suite for regressions**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-js && npm test && cd .. && node tools/check-spec-vectors.mjs && cd cli && npm test`

Expected: sdk-js `# tests 65 / # pass 65 / # fail 0` (57 baseline + 8 new); `spec vectors: ok (280 vectors)`; cli `50 passed, 0 failed`.

- [ ] **Step 11: Commit**
```bash
git add sdk-js/src/canonical.js sdk-js/src/builder.js sdk-js/src/index.js \
        sdk-js/src/index.d.ts sdk-js/test/ijson.test.js \
        sdk-js/test/jcs-numbers.test.js spec/vectors/jcs-numbers.json \
        tools/check-spec-vectors.mjs
git commit -m "fix(sdk-js): enforce the I-JSON acceptance boundary at the JCS gate

canonicalize() enforces neither half of RFC 8785's I-JSON input domain, so
the reference builder sealed capsules with nanosecond timestamps and lone
surrogates that verified here and failed in sdk-py and verifier-rust.
assertIJson() rejects a plain integer literal outside +/-(2^53 - 1) and any
unpaired surrogate, and appendEvent applies it so the failure lands on the
offending call rather than at seal time. 13 jcs-numbers vectors are marked
accepted:false: their expected field still documents the Number::toString
layout, but the value must never be canonicalized."
```

---

### Task 3: Cut Pith truncation on code-point boundaries

**Files:**
- Modify: `sdk-js/src/pith.js:94-99`
- Modify: `sdk-js/src/pith.js:113` (insert helper before `positiveIntegerOrDefault`)
- Test: `sdk-js/test/pith.test.js` (append)

**Interfaces:**
- Consumes: `compressText(input, options) -> { text, changed, version }`; `assertIJson` from Task 2 (only as the thing that would otherwise reject the output)
- Produces: `compressText` output is guaranteed well-formed Unicode

- [ ] **Step 1: Write the failing test**

Append to `sdk-js/test/pith.test.js`:

```js

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

test("compressText: truncation never splits a surrogate pair", () => {
  // The default cut index (280 - 1 ellipsis = 279) is odd, so an all-emoji
  // string lands mid-pair without a boundary guard.
  const out = compressText("🙂".repeat(200));
  assert.ok(out.text.length <= 280);
  assert.ok(!LONE_SURROGATE.test(out.text), "output must be well-formed Unicode");
  assert.ok(out.text.endsWith("…"));
});

test("compressText: surrogate-safe at every odd and even cut index", () => {
  const input = "🙂".repeat(64);
  for (let maxChars = 2; maxChars <= 128; maxChars++) {
    const { text } = compressText(input, { maxChars });
    assert.ok(!LONE_SURROGATE.test(text), `maxChars=${maxChars} split a pair`);
    assert.ok(text.length <= maxChars, `maxChars=${maxChars} overflowed`);
  }
});

test("compressText: maxChars of 1 yields the bare ellipsis", () => {
  assert.equal(compressText("hello world", { maxChars: 1 }).text, "…");
  assert.equal(compressText("🙂🙂🙂", { maxChars: 1 }).text, "…");
});

test("CapsuleBuilder: an emoji summary seals and its chain bytes canonicalize", async () => {
  const ed = generateEd25519();
  const builder = new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex },
    participants: [{ actor_id: "human:alice", role: "originator" }],
    createdAt: TS,
  });
  builder.setProgram("# X");
  builder.appendEvent({
    actor: "human:alice",
    kind: "observation",
    action: "note",
    target: "x",
    timestamp: TS,
    payload: { summary: "🙂".repeat(200) },
  });
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  const summary = (await CapsuleReader.fromBytes(bytes)).events()[0].payload.summary;
  assert.ok(!LONE_SURROGATE.test(summary));
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-js && node --test test/pith.test.js`

Expected: FAIL — `compressText: truncation never splits a surrogate pair` fails on `output must be well-formed Unicode`, and (with Task 2 in place) `CapsuleBuilder: an emoji summary seals...` fails with `appendEvent: JCS: unpaired surrogate U+D83D at event[0].payload.summary`. Summary line reports `# fail 3` (the `maxChars: 1` test already passes).

- [ ] **Step 3: Make the slice code-point safe**

`sdk-js/src/pith.js:94-99` currently reads:

```js
function truncateAtWordBoundary(input, maxChars) {
  if (input.length <= maxChars) return input;
  if (maxChars <= ELLIPSIS.length) return ELLIPSIS.slice(0, maxChars);

  const limit = maxChars - ELLIPSIS.length;
  const prefix = input.slice(0, limit);
```

Replace with:

```js
function truncateAtWordBoundary(input, maxChars) {
  if (input.length <= maxChars) return input;
  // maxChars is a positive integer and ELLIPSIS is one UTF-16 code unit,
  // so this branch is only reachable with maxChars === 1: there is no room
  // for content, only the ellipsis itself.
  if (maxChars <= ELLIPSIS.length) return ELLIPSIS;

  const limit = maxChars - ELLIPSIS.length;
  const prefix = sliceAtCodePointBoundary(input, limit);
```

- [ ] **Step 4: Add the boundary-safe slice helper**

`sdk-js/src/pith.js:113-115` currently reads:

```js
function positiveIntegerOrDefault(value, fallback) {
  return Number.isInteger(value) && value > 0 ? value : fallback;
}
```

Insert the helper immediately before it:

```js
/**
 * `input.slice(0, limit)` cuts UTF-16 code units. When the code unit at
 * `limit - 1` is a high surrogate its low surrogate lives at `limit`, so a
 * naive slice ends in a lone surrogate — text that is no longer well-formed
 * Unicode and that the JCS acceptance boundary rejects at seal time
 * (spec/canonicalization.md). Drop the straddling unit instead.
 *
 * `limit` is always >= 1 here because the maxChars <= ELLIPSIS.length case
 * returns earlier.
 */
function sliceAtCodePointBoundary(input, limit) {
  if (limit >= input.length) return input;
  const unit = input.charCodeAt(limit - 1);
  if (unit >= 0xd800 && unit <= 0xdbff) return input.slice(0, limit - 1);
  return input.slice(0, limit);
}

function positiveIntegerOrDefault(value, fallback) {
  return Number.isInteger(value) && value > 0 ? value : fallback;
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-js && node --test test/pith.test.js`

Expected: PASS — `# fail 0`. The default-`maxChars` case now returns a 279-code-unit string (one emoji dropped so the pair stays intact) ending in `…`.

- [ ] **Step 6: Confirm the cross-lane reproduction is dead**

Run from the repo root:

```bash
cd /Users/complex/repo/open-source/capsules-protocol
node -e '
import("./sdk-js/src/index.js").then(async ({ CapsuleBuilder, generateEd25519 }) => {
  const { writeFileSync } = await import("node:fs");
  const keys = generateEd25519();
  const b = new CapsuleBuilder({
    originator: { publicKey: keys.publicKeyHex, label: "T" },
    participants: [{ actor_id: "human:a", role: "originator", label: "A" }],
    createdAt: "2026-05-07T12:00:00Z",
  });
  b.appendEvent({ actor: "human:a", action: "note", payload: { summary: "🙂".repeat(200) } });
  const bytes = await b.seal({ signers: { ...keys, role: "originator" }, signedAt: "2026-05-07T12:00:00Z" });
  writeFileSync("/tmp/emoji.capsule", bytes);
  writeFileSync("/tmp/emoji-key.txt", keys.publicKeyHex);
  console.log("sealed", bytes.length);
});'
cd sdk-py && PYTHONPATH=src python3 -c "
from capsule import CapsuleReader, verify_capsule
r = CapsuleReader.from_bytes(open('/tmp/emoji.capsule','rb').read())
res = verify_capsule(r, allowlist=[open('/tmp/emoji-key.txt').read()])
print('PY verify ok =', res['ok'], '| chain ok =', res['chain']['ok'])"
```

Expected: `sealed <n>` then `PY verify ok = True | chain ok = True`. (Before this task, the same script prints `PY verify ok = False` with `recompute failed: 'utf-8' codec can't encode character '\ud83d'`.)

- [ ] **Step 7: Run the full lane suite for regressions**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-js && npm test`

Expected: PASS — `# tests 69 / # pass 69 / # fail 0` (65 after Task 2, + 4 new here).

- [ ] **Step 8: Commit**
```bash
git add sdk-js/src/pith.js sdk-js/test/pith.test.js
git commit -m "fix(sdk-js): cut Pith truncation on code-point boundaries

truncateAtWordBoundary sliced UTF-16 code units. With the default maxChars
of 280 the cut index is odd, so ordinary user text containing emoji ended
in a lone surrogate, got signed into chain/events.jsonl, and failed in
sdk-py with a chain-hash error that read like tampering. Drop the
straddling code unit instead. Also collapse the maxChars <= 1 branch to
return the ellipsis directly, which is all it could ever produce."
```

---

### Task 4: Give sdk-py an explicit acceptance refusal instead of an encoder crash

**Files:**
- Modify: `sdk-py/src/capsule/canonical.py:76-87`
- Modify: `sdk-py/src/capsule/canonical.py:90-94`
- Modify: `sdk-py/tests/test_canonical.py:154-157`
- Test: `sdk-py/tests/test_canonical.py` (append)

**Interfaces:**
- Consumes: `spec/canonicalization.md` (Task 1); the `accepted` field on `jcs-numbers.json` entries (Task 2)
- Produces: `jcs(value)` raises `ValueError` with `"JCS: unpaired surrogate U+XXXX; strings must be well-formed Unicode"` or `"JCS: integer outside IEEE-754 exact range (|n| > 2^53 - 1); ..."`

- [ ] **Step 1: Write the failing test**

Append to `sdk-py/tests/test_canonical.py`:

```python
def test_jcs_rejects_unpaired_surrogates():
    with pytest.raises(ValueError, match="unpaired surrogate U\\+D83D"):
        jcs({"summary": "a\ud83d"})
    with pytest.raises(ValueError, match="unpaired surrogate U\\+DC00"):
        jcs({"summary": "\udc00b"})
    # Object keys are canonicalized through the same encoder.
    with pytest.raises(ValueError, match="unpaired surrogate U\\+D800"):
        jcs({"k\ud800": 1})


def test_jcs_accepts_well_formed_astral_pair():
    assert jcs({"s": "a\U0001F642"}) == '{"s":"a\U0001F642"}'.encode()


def test_jcs_rejects_float_that_serializes_as_out_of_range_integer_literal():
    # A float, not an int, so the existing int guard never sees it. Its
    # canonical token is the 20-digit literal 10000000000000000000.
    with pytest.raises(ValueError, match="integer outside IEEE-754 exact range"):
        jcs(1e19)
    with pytest.raises(ValueError, match="integer outside IEEE-754 exact range"):
        jcs(1.7e18)
    # Exponent-form tokens round-trip through every lane and stay accepted.
    assert jcs(1e21) == b"1e+21"
    assert jcs(float(2**53 - 1)) == b"9007199254740991"


def test_verify_chain_reports_a_surrogate_as_a_canonicalization_refusal():
    # The failure must name the encoder fault, not read like tampering.
    from capsule.chain import verify_chain

    event = {
        "seq": 1,
        "event_id": "evt_001",
        "actor": "human:alice",
        "kind": "observation",
        "action": "note",
        "target": "capsule",
        "timestamp": "2026-05-07T12:00:00Z",
        "payload": {"summary": "x\ud83d"},
        "untrusted_payload_fields": ["payload.summary"],
        "prev_hash": "0" * 64,
        "hash": "0" * 64,
    }
    result = verify_chain([event])
    assert result["ok"] is False
    assert "unpaired surrogate" in result["errors"][0]["message"]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-py && PYTHONPATH=src python3 -m pytest tests/test_canonical.py -k "surrogate or astral or out_of_range"`

Expected: FAIL — `test_jcs_rejects_unpaired_surrogates` fails with `UnicodeEncodeError: 'utf-8' codec can't encode character '\ud83d'` (which is a `ValueError`, but the message does not match `unpaired surrogate`), and `test_jcs_rejects_float_that_serializes_as_out_of_range_integer_literal` fails with `DID NOT RAISE <class 'ValueError'>`. `4 failed`.

- [ ] **Step 3: Guard the number token**

`sdk-py/src/capsule/canonical.py:76-87` currently reads:

```python
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        head = digits[0] + ("." + digits[1:] if k > 1 else "")
        out = f"{head}e{'+' if e >= 0 else '-'}{abs(e)}"

    return ("-" + out) if negative else out
```

Replace with:

```python
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        head = digits[0] + ("." + digits[1:] if k > 1 else "")
        out = f"{head}e{'+' if e >= 0 else '-'}{abs(e)}"

    # I-JSON acceptance boundary (spec/canonicalization.md): a plain integer
    # literal — no "." and no "e" — must be exactly representable, or the
    # token does not survive a round-trip through parsers that use native
    # integers. Exponent-form tokens round-trip through every lane's double
    # path and are accepted.
    if "." not in out and "e" not in out and abs(v) > _MAX_SAFE_INTEGER:
        raise ValueError(
            "JCS: integer outside IEEE-754 exact range (|n| > 2^53 - 1); "
            "not representable identically across implementations"
        )

    return ("-" + out) if negative else out
```

- [ ] **Step 4: Guard the string encoder**

`sdk-py/src/capsule/canonical.py:90-94` currently reads:

```python
def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        c = ord(ch)
        if c == 0x22:
```

Replace with:

```python
def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        c = ord(ch)
        if 0xD800 <= c <= 0xDFFF:
            # I-JSON acceptance boundary (spec/canonicalization.md). Without
            # this, the surrogate survives until .encode("utf-8") and the
            # verifier reports an opaque "recompute failed" that reads like
            # tampering rather than an encoder fault.
            raise ValueError(
                f"JCS: unpaired surrogate U+{c:04X}; "
                "strings must be well-formed Unicode"
            )
        if c == 0x22:
```

- [ ] **Step 5: Teach the Python number-vector test the `accepted` flag**

`sdk-py/tests/test_canonical.py:154-157` currently reads:

```python
    for entry in vectors:
        value = struct.unpack(">d", bytes.fromhex(entry["ieee_hex"]))[0]
        got = jcs(value).decode("utf-8")
        assert got == entry["expected"], f"bits {entry['ieee_hex']}"
```

Replace with:

```python
    for entry in vectors:
        value = struct.unpack(">d", bytes.fromhex(entry["ieee_hex"]))[0]
        if entry.get("accepted") is False:
            # Outside the I-JSON acceptance boundary (spec/canonicalization.md):
            # "expected" records the Number::toString layout, but the value must
            # never reach a canonical serialization.
            with pytest.raises(ValueError, match="integer outside IEEE-754 exact range"):
                jcs(value)
            continue
        got = jcs(value).decode("utf-8")
        assert got == entry["expected"], f"bits {entry['ieee_hex']}"
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-py && PYTHONPATH=src python3 -m pytest tests/test_canonical.py`

Expected: PASS — `24 passed` (20 baseline in this file + 4 new).

- [ ] **Step 7: Run the full lane suite for regressions**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-py && PYTHONPATH=src python3 -m pytest`

Expected: PASS — `186 passed` (182 baseline + 4 new).

- [ ] **Step 8: Commit**
```bash
git add sdk-py/src/capsule/canonical.py sdk-py/tests/test_canonical.py
git commit -m "fix(sdk-py): refuse non-I-JSON input explicitly at the JCS gate

Two gaps. Floats whose canonical token is a plain integer literal out of
the exact range slipped past the int-only guard (1e19 -> the 20-digit
literal). And a lone surrogate reached .encode('utf-8'), so verify_chain
reported \"recompute failed: 'utf-8' codec can't encode character\" — an
encoder fault that reads like tampering. Both now raise a named
canonicalization refusal. The number-vector test honours the new
accepted:false flag."
```

---

### Task 5: Enforce the number rule in verifier-rust's chain walk

**Files:**
- Modify: `verifier-rust/crates/capsule-verify/src/jcs.rs:47` (insert before the test module)
- Modify: `verifier-rust/crates/capsule-verify/src/jcs.rs:235-244` (the vector test)
- Modify: `verifier-rust/crates/capsule-verify/src/chain.rs:126-128`
- Modify: `verifier-rust/crates/capsule-verify/src/lib.rs:27`
- Test: `verifier-rust/crates/capsule-verify/src/jcs.rs` (tests module) and `verifier-rust/crates/capsule-verify/src/chain.rs` (tests module)

**Interfaces:**
- Consumes: `spec/canonicalization.md` (Task 1); the `accepted` field on `jcs-numbers.json` (Task 2); `serde_json::Value`
- Produces: `capsule_verify::check_ijson(&Value) -> Result<(), String>` (also reachable as `capsule_verify::jcs::check_ijson`)

- [ ] **Step 1: Write the failing test**

In `verifier-rust/crates/capsule-verify/src/jcs.rs`, insert these four tests immediately before `fn deterministic_sha256_of_canonical_form()` (line 193), inside `mod tests`:

```rust
    #[test]
    fn check_ijson_rejects_plain_integer_literal_out_of_range() {
        // A 20-digit integer literal: serde_json parses it as u64, serde_jcs
        // would happily echo it, and a JS reader would round it. Refuse.
        let v: Value = serde_json::from_str(r#"{"payload":{"ts":10000000000000000000}}"#)
            .expect("valid json");
        let err = check_ijson(&v).expect_err("must be rejected");
        assert!(
            err.contains("integer outside IEEE-754 exact range"),
            "unexpected message: {err}"
        );
        assert!(
            err.contains("$.payload.ts"),
            "message must name the path: {err}"
        );
    }

    #[test]
    fn check_ijson_rejects_exponent_input_that_serializes_as_plain_integer() {
        // `1e19` arrives as an f64 but Number::toString lays it out as
        // 10000000000000000000 - the same unsafe plain literal.
        let v: Value = serde_json::from_str("[1e19]").expect("valid json");
        assert!(check_ijson(&v).is_err());
        assert_eq!(
            String::from_utf8(jcs(&v)).unwrap(),
            "[10000000000000000000]"
        );
    }

    #[test]
    fn check_ijson_accepts_max_safe_and_exponent_form() {
        let safe: Value = serde_json::from_str("9007199254740991").expect("valid json");
        assert!(check_ijson(&safe).is_ok());
        // 1e21 and above serialize in exponent form, which round-trips
        // through every lane's double path.
        let big: Value = serde_json::from_str("1e21").expect("valid json");
        assert!(check_ijson(&big).is_ok());
        assert_eq!(String::from_utf8(jcs(&big)).unwrap(), "1e+21");
    }

    #[test]
    fn serde_json_rejects_lone_surrogate_escape_at_parse() {
        // The string half of the acceptance boundary is enforced by the
        // parser in this lane: Rust `String` cannot hold a lone surrogate.
        assert!(
            serde_json::from_str::<Value>(r#"{"s":"x\ud83dy"}"#).is_err(),
            "an unpaired high surrogate escape must not parse"
        );
        assert!(
            serde_json::from_str::<Value>(r#"{"s":"x\udc00"}"#).is_err(),
            "an unpaired low surrogate escape must not parse"
        );
        // The well-formed pair is accepted and yields one astral scalar.
        let ok: Value = serde_json::from_str(r#"{"s":"x\ud83d\ude42"}"#).expect("valid pair");
        assert_eq!(String::from_utf8(jcs(&ok)).unwrap().chars().count(), 10);
    }
```

And in `verifier-rust/crates/capsule-verify/src/chain.rs`, insert this test immediately before `fn detects_hash_tampering()` (line 232), inside `mod tests`:

```rust
    #[test]
    fn rejects_event_payload_outside_ijson_acceptance_boundary() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).unwrap();
        let jsonl = map.get("chain/events.jsonl").unwrap();
        let mut events = parse_chain_jsonl(jsonl).unwrap();
        // A nanosecond timestamp: plausible payload, 19 digits, > 2^53 - 1.
        events[0].payload = serde_json::json!({ "ts_ns": 1_700_000_000_000_000_000u64 });
        let errors = verify_chain(&events);
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("integer outside IEEE-754 exact range")),
            "expected an I-JSON acceptance error, got: {errors:?}"
        );
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/verifier-rust && cargo test --workspace`

Expected: FAIL to compile — `error[E0425]: cannot find function 'check_ijson' in this scope` (three times in `jcs.rs`), then `error: could not compile 'capsule-verify' (lib test)`. Note `cargo test` without `--workspace` only builds the root parity package and will not surface this.

- [ ] **Step 3: Add `check_ijson` to `jcs.rs`**

`verifier-rust/crates/capsule-verify/src/jcs.rs:47` currently begins the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256_hex;
```

Insert the following immediately before that `#[cfg(test)]` line:

```rust
/// Largest integer exactly representable as an IEEE-754 binary64: 2^53 - 1.
const MAX_SAFE_INTEGER: i128 = (1i128 << 53) - 1;

/// Smallest magnitude whose ECMAScript `Number::toString` form uses exponent
/// notation. Below it an integral double serializes as a plain integer
/// literal; at or above it the token carries an `e`.
const PLAIN_INTEGER_CEILING: f64 = 1e21;

/// Enforce the I-JSON acceptance boundary from `spec/canonicalization.md`.
///
/// RFC 8785 canonicalization is only defined over I-JSON (RFC 7493) input.
/// This verifier's strings are Rust `String`s, which cannot hold unpaired
/// surrogates (`serde_json` rejects lone-surrogate escapes at parse time), so
/// only the number rule needs enforcing here: a number whose canonical token
/// is a *plain integer literal* must satisfy |n| <= 2^53 - 1.
///
/// Returns `Err(message)` naming the offending path, or `Ok(())`.
pub fn check_ijson(value: &Value) -> Result<(), String> {
    check_ijson_at(value, "$")
}

fn check_ijson_at(value: &Value, path: &str) -> Result<(), String> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(n) => check_number(n, path),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                check_ijson_at(item, &format!("{path}[{i}]"))?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (k, v) in map {
                check_ijson_at(v, &format!("{path}.{k}"))?;
            }
            Ok(())
        }
    }
}

fn out_of_range(path: &str) -> String {
    format!(
        "JCS: integer outside IEEE-754 exact range (|n| > 2^53 - 1) at {path}; \
         not representable identically across implementations"
    )
}

fn check_number(n: &serde_json::Number, path: &str) -> Result<(), String> {
    if let Some(u) = n.as_u64() {
        return if i128::from(u) > MAX_SAFE_INTEGER {
            Err(out_of_range(path))
        } else {
            Ok(())
        };
    }
    if let Some(i) = n.as_i64() {
        return if i128::from(i).abs() > MAX_SAFE_INTEGER {
            Err(out_of_range(path))
        } else {
            Ok(())
        };
    }
    let f = n
        .as_f64()
        .ok_or_else(|| format!("JCS: non-finite number at {path}"))?;
    if !f.is_finite() {
        return Err(format!("JCS: non-finite number at {path}"));
    }
    let magnitude = f.abs();
    if f.fract() == 0.0 && magnitude > MAX_SAFE_INTEGER as f64 && magnitude < PLAIN_INTEGER_CEILING
    {
        return Err(out_of_range(path));
    }
    Ok(())
}
```

- [ ] **Step 4: Wire the gate into the chain walk**

`verifier-rust/crates/capsule-verify/src/chain.rs:126-128` currently reads:

```rust
        if let Some(map) = event_value.as_object_mut() {
            map.remove("hash");
        }
        let recomputed = match hash_event_value(&event_value) {
```

Replace with:

```rust
        if let Some(map) = event_value.as_object_mut() {
            map.remove("hash");
        }
        // I-JSON acceptance boundary (spec/canonicalization.md). Reported as
        // its own error rather than folded into a hash mismatch, so an
        // out-of-range number reads as a canonicalization refusal instead of
        // looking like tampering.
        if let Err(message) = crate::jcs::check_ijson(&event_value) {
            errors.push(ChainErr {
                seq: seq_for_msg,
                message,
            });
            continue;
        }
        let recomputed = match hash_event_value(&event_value) {
```

- [ ] **Step 5: Re-export `check_ijson` from the crate root**

`verifier-rust/crates/capsule-verify/src/lib.rs:27` currently reads:

```rust
pub use jcs::jcs;
```

Replace with:

```rust
pub use jcs::{check_ijson, jcs};
```

- [ ] **Step 6: Teach the Rust number-vector test the `accepted` flag**

`verifier-rust/crates/capsule-verify/src/jcs.rs:235-244` (inside `mod vector_tests`) currently reads:

```rust
        for entry in vectors {
            let hex = entry["ieee_hex"].as_str().expect("ieee_hex");
            let expected = entry["expected"].as_str().expect("expected");
            let bits = u64::from_str_radix(hex, 16).expect("hex bits");
            let value = f64::from_bits(bits);
            let num = serde_json::Number::from_f64(value)
                .expect("vectors contain only finite doubles");
            let got = String::from_utf8(jcs(&Value::Number(num))).expect("utf8");
            assert_eq!(got, expected, "bits {hex}");
        }
```

Replace with:

```rust
        for entry in vectors {
            let hex = entry["ieee_hex"].as_str().expect("ieee_hex");
            let expected = entry["expected"].as_str().expect("expected");
            let bits = u64::from_str_radix(hex, 16).expect("hex bits");
            let value = f64::from_bits(bits);
            let num = serde_json::Number::from_f64(value)
                .expect("vectors contain only finite doubles");
            if entry["accepted"] == Value::Bool(false) {
                // Outside the I-JSON acceptance boundary
                // (spec/canonicalization.md): `expected` documents the
                // Number::toString layout, but the value must be refused.
                assert!(
                    super::check_ijson(&Value::Number(num)).is_err(),
                    "bits {hex} (would serialize as {expected}) must be rejected"
                );
                continue;
            }
            let got = String::from_utf8(jcs(&Value::Number(num))).expect("utf8");
            assert_eq!(got, expected, "bits {hex}");
        }
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/verifier-rust && cargo test --workspace check_ijson`

Expected: PASS — `test jcs::tests::check_ijson_rejects_plain_integer_literal_out_of_range ... ok`, `check_ijson_rejects_exponent_input_that_serializes_as_plain_integer ... ok`, `check_ijson_accepts_max_safe_and_exponent_form ... ok`.

- [ ] **Step 8: Run the full lane suite for regressions**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/verifier-rust && cargo test --workspace`

Expected: PASS — lib `test result: ok. 107 passed; 0 failed` (102 baseline + 5 new), parity `7 passed; 0 failed`, spec_registry `3 passed; 0 failed`.

- [ ] **Step 9: Commit**
```bash
git add verifier-rust/crates/capsule-verify/src/jcs.rs \
        verifier-rust/crates/capsule-verify/src/chain.rs \
        verifier-rust/crates/capsule-verify/src/lib.rs
git commit -m "fix(verifier-rust): gate the chain walk on the I-JSON boundary

serde_json reads 10000000000000000000 as a u64 and serde_jcs echoes it, so
this lane silently disagreed with any reader whose JSON numbers are
doubles. check_ijson refuses a plain integer literal outside +/-(2^53 - 1),
including a 1e19-shaped f64 whose Number::toString layout is that same
literal, and verify_chain reports it as its own error rather than as a hash
mismatch. The string half needs no code: serde_json refuses lone-surrogate
escapes at parse, which a test now pins."
```

---

### Task 6: Add a throwing acceptance gate to sdk-swift

**Files:**
- Modify: `sdk-swift/Sources/Capsule/JCS.swift:64-66` (insert after `bytes`)
- Modify: `sdk-swift/Sources/Capsule/Reader.swift:346-349`
- Modify: `sdk-swift/Sources/Capsule/Builder.swift:388`
- Modify: `sdk-swift/Tests/CapsuleTests/JCSNumbersVectorTests.swift:16-19` and `:45-50`
- Test: `sdk-swift/Tests/CapsuleTests/IJsonAcceptanceTests.swift` (new)

**Interfaces:**
- Consumes: `spec/canonicalization.md` (Task 1); the `accepted` field on `jcs-numbers.json` (Task 2); `CapsuleError.malformed(String)` from `Sources/Capsule/Zip.swift:175`
- Produces: `JCS.assertAcceptable(_ v: JCSValue, path: String = "$") throws`; `JCS.maxSafeInteger: Int64`

- [ ] **Step 1: Write the failing test**

Create `sdk-swift/Tests/CapsuleTests/IJsonAcceptanceTests.swift`:

```swift
// I-JSON acceptance boundary (spec/canonicalization.md).
//
// Swift's String is a Unicode-scalar sequence and JSONSerialization refuses
// lone-surrogate escapes at parse time, so this lane's exposure is the
// number rule: JCS.canonical would lay 1e19 out as the plain literal
// 10000000000000000000, which no native-integer parser reads back the same.

import Foundation
import XCTest
@testable import Capsule

final class IJsonAcceptanceTests: XCTestCase {

    func testRejectsPlainIntegerLiteralOutsideExactRange() {
        // Date.now() * 1e6 — a nanosecond timestamp.
        XCTAssertThrowsError(try JCS.assertAcceptable(.decimal(1.7e18)))
        XCTAssertThrowsError(try JCS.assertAcceptable(.decimal(1e19)))
        // 2^53 itself is one past the exact range.
        XCTAssertThrowsError(try JCS.assertAcceptable(.decimal(9007199254740992)))
        XCTAssertThrowsError(try JCS.assertAcceptable(.integer(9007199254740992)))
    }

    func testAcceptsExactRangeBoundaryAndExponentForm() throws {
        try JCS.assertAcceptable(.integer(9007199254740991))
        try JCS.assertAcceptable(.decimal(9007199254740991))
        // >= 1e21 serializes in exponent form and round-trips everywhere.
        try JCS.assertAcceptable(.decimal(1e21))
        XCTAssertEqual(JCS.canonical(.decimal(1e21)), "1e+21")
        try JCS.assertAcceptable(.decimal(1.5))
    }

    func testMessageNamesTheOffendingPath() {
        let value = jobj(("payload", jobj(("ts_ns", .decimal(1.7e18)))))
        XCTAssertThrowsError(try JCS.assertAcceptable(value)) { error in
            XCTAssertTrue(
                "\(error)".contains("$.payload.ts_ns"),
                "message must name the path: \(error)"
            )
        }
    }

    func testParseJSONRefusesAnOutOfRangeIntegerLiteral() {
        let data = Data(#"{"payload":{"ts":10000000000000000000}}"#.utf8)
        XCTAssertThrowsError(try CapsuleReader.parseJSON(data))
    }

    func testParseJSONRefusesALoneSurrogateEscape() {
        // Foundation refuses this at parse; the capsule never reaches a hash.
        let data = Data(##"{"s":"x\ud83d"}"##.utf8)
        XCTAssertThrowsError(try CapsuleReader.parseJSON(data))
    }

    func testParseJSONAcceptsAWellFormedAstralPair() throws {
        let data = Data(##"{"s":"x\ud83d\ude42"}"##.utf8)
        let value = try CapsuleReader.parseJSON(data)
        XCTAssertEqual(JCS.canonical(value), "{\"s\":\"x\u{1F642}\"}")
    }

    func testSealRefusesAPayloadOutsideTheBoundary() throws {
        let keys = try CapsuleCrypto.generateEd25519()
        let builder = CapsuleBuilder(originator: .init(keyPair: keys, label: "T"),
                                     createdAt: "2026-05-07T12:00:00Z")
        builder.setParticipants([.init(actorId: "human:a", role: "originator", label: "A")])
        builder.appendEvent(
            actor: "human:a", kind: "observation", action: "note", target: "capsule",
            timestamp: "2026-05-07T12:00:00Z",
            payload: jobj(("ts_ns", .decimal(1.7e18)))
        )
        XCTAssertThrowsError(try builder.seal(signedAt: "2026-05-07T12:00:00Z")) { error in
            XCTAssertTrue(
                "\(error)".contains("integer outside IEEE-754 exact range"),
                "unexpected: \(error)"
            )
        }
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-swift && swift test`

Expected: FAIL to compile — `error: type 'JCS' has no member 'assertAcceptable'` at each `JCS.assertAcceptable` call site.

- [ ] **Step 3: Add the acceptance gate to `JCS.swift`**

`sdk-swift/Sources/Capsule/JCS.swift:64-66` currently reads:

```swift
    public static func bytes(_ v: JCSValue) -> Data {
        return Data(canonical(v).utf8)
    }
```

Replace with:

```swift
    public static func bytes(_ v: JCSValue) -> Data {
        return Data(canonical(v).utf8)
    }

    /// Largest integer exactly representable as an IEEE-754 binary64: 2^53 - 1.
    public static let maxSafeInteger: Int64 = (1 << 53) - 1

    /// Smallest magnitude whose ECMAScript `Number::toString` form uses
    /// exponent notation. Below it an integral double serializes as a plain
    /// integer literal; at or above it the token carries an `e`.
    private static let plainIntegerCeiling = 1e21

    /// Enforce the I-JSON acceptance boundary from `spec/canonicalization.md`.
    ///
    /// Swift `String` is a sequence of Unicode scalars and `JSONSerialization`
    /// refuses lone-surrogate escapes at parse time, so only the number rule
    /// needs enforcing here: a number whose canonical token is a *plain
    /// integer literal* must satisfy |n| <= 2^53 - 1. Values at or above
    /// 1e21 serialize in exponent form, which round-trips through every
    /// lane's double path, and are accepted.
    ///
    /// This is the throwing acceptance gate. `canonical` keeps its
    /// preconditions as a last-resort invariant; untrusted input reaches it
    /// only after passing through here.
    public static func assertAcceptable(_ v: JCSValue, path: String = "$") throws {
        switch v {
        case .null, .bool, .string:
            return
        case .integer(let i):
            if i.magnitude > UInt64(maxSafeInteger) {
                throw CapsuleError.malformed(outOfExactRange(path))
            }
        case .decimal(let d):
            if !d.isFinite {
                throw CapsuleError.malformed("JCS: non-finite number at \(path)")
            }
            let magnitude = abs(d)
            if d == d.rounded(.towardZero),
                magnitude > Double(maxSafeInteger),
                magnitude < plainIntegerCeiling
            {
                throw CapsuleError.malformed(outOfExactRange(path))
            }
        case .array(let items):
            for (i, item) in items.enumerated() {
                try assertAcceptable(item, path: "\(path)[\(i)]")
            }
        case .object(let pairs):
            for (key, value) in pairs {
                try assertAcceptable(value, path: "\(path).\(key)")
            }
        }
    }

    private static func outOfExactRange(_ path: String) -> String {
        "JCS: integer outside IEEE-754 exact range (|n| > 2^53 - 1) at \(path); "
            + "not representable identically across implementations"
    }
```

- [ ] **Step 4: Gate the reader's parse boundary**

`sdk-swift/Sources/Capsule/Reader.swift:346-349` currently reads:

```swift
    static func parseJSON(_ data: Data) throws -> JCSValue {
        let any = try JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed)
        return convert(any)
    }
```

Replace with:

```swift
    static func parseJSON(_ data: Data) throws -> JCSValue {
        let any = try JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed)
        let value = convert(any)
        // I-JSON acceptance boundary (spec/canonicalization.md). Rejecting
        // here keeps the non-throwing JCS.canonical off untrusted input.
        try JCS.assertAcceptable(value)
        return value
    }
```

- [ ] **Step 5: Gate the builder's seal path**

`sdk-swift/Sources/Capsule/Builder.swift:388` currently reads:

```swift
        let events = Chain.build(bare)
```

Replace with:

```swift
        // I-JSON acceptance boundary (spec/canonicalization.md): refuse to
        // seal a payload that cannot be canonicalized identically in every
        // lane, rather than emitting a capsule only this lane can verify.
        for (i, event) in bare.enumerated() {
            try JCS.assertAcceptable(event.payload, path: "event[\(i)].payload")
        }
        let events = Chain.build(bare)
```

- [ ] **Step 6: Teach the Swift number-vector test the `accepted` flag**

`sdk-swift/Tests/CapsuleTests/JCSNumbersVectorTests.swift:16-19` currently reads:

```swift
    private struct Vector: Decodable {
        let ieee_hex: String
        let expected: String
    }
```

Replace with:

```swift
    private struct Vector: Decodable {
        let ieee_hex: String
        let expected: String
        /// Absent means accepted. `false` marks a bit pattern outside the
        /// I-JSON acceptance boundary (spec/canonicalization.md): `expected`
        /// documents the Number::toString layout, but the value must be
        /// refused before it can be canonicalized.
        let accepted: Bool?
    }
```

And lines 45-50 currently read:

```swift
            let value = Double(bitPattern: bits)
            XCTAssertEqual(
                JCS.canonical(.decimal(value)),
                vector.expected,
                "bits \(vector.ieee_hex)"
            )
```

Replace with:

```swift
            let value = Double(bitPattern: bits)
            if vector.accepted == false {
                XCTAssertThrowsError(
                    try JCS.assertAcceptable(.decimal(value)),
                    "bits \(vector.ieee_hex) (would serialize as \(vector.expected)) must be rejected"
                )
                continue
            }
            XCTAssertEqual(
                JCS.canonical(.decimal(value)),
                vector.expected,
                "bits \(vector.ieee_hex)"
            )
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-swift && swift test --filter IJsonAcceptanceTests`

Expected: PASS — `Executed 7 tests, with 0 failures`.

- [ ] **Step 8: Run the full lane suite for regressions**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-swift && swift build && swift test`

Expected: `Build complete!` then all XCTest cases pass with `0 failures`.

- [ ] **Step 9: Commit**
```bash
git add sdk-swift/Sources/Capsule/JCS.swift sdk-swift/Sources/Capsule/Reader.swift \
        sdk-swift/Sources/Capsule/Builder.swift \
        sdk-swift/Tests/CapsuleTests/JCSNumbersVectorTests.swift \
        sdk-swift/Tests/CapsuleTests/IJsonAcceptanceTests.swift
git commit -m "fix(sdk-swift): add a throwing I-JSON acceptance gate

JCS.canonical laid 1e19 out as the plain literal 10000000000000000000, and
its only integer guard was a precondition, which traps the process rather
than failing a capsule. assertAcceptable is the throwing gate: parseJSON
applies it to untrusted input and seal applies it to every event payload,
so canonical's preconditions become an invariant nothing hostile reaches.
JSONSerialization already refuses lone-surrogate escapes at parse, which a
test now pins."
```

---

### Task 7: Stop sdk-kotlin silently substituting `?` for unpaired surrogates

**Files:**
- Modify: `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Canonical.kt:49-51`
- Modify: `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Canonical.kt:154-156`
- Modify: `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Reader.kt:63-64`
- Modify: `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Builder.kt:95`
- Modify: `sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/JcsNumbersVectorTest.kt:22-29`
- Test: `sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/IJsonAcceptanceTest.kt` (new)

**Interfaces:**
- Consumes: `spec/canonicalization.md` (Task 1); the `accepted` field on `jcs-numbers.json` (Task 2)
- Produces: `JCS.assertAcceptable(v: JCSValue, path: String = "$")` (throws `IllegalArgumentException`)

Note: this lane's failure mode is worse than the others. `String.toByteArray(Charsets.UTF_8)` replaces unmappable code units with `?` (0x3F) instead of throwing, so today a lone surrogate produces a *different hash*, silently. The guard converts that into a refusal.

- [ ] **Step 1: Write the failing test**

Create `sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/IJsonAcceptanceTest.kt`:

```kotlin
package ai.virion.capsule.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * I-JSON acceptance boundary (spec/canonicalization.md).
 *
 * This lane's exposure is the worst of the five: a Java String can hold an
 * unpaired surrogate, and toByteArray(UTF_8) replaces it with '?' rather
 * than throwing, so the capsule hashed different bytes with no error at all.
 */
class IJsonAcceptanceTest {

    @Test
    fun rejectsPlainIntegerLiteralOutsideExactRange() {
        // A nanosecond timestamp: plausible payload, 19 digits.
        assertFailsWith<IllegalArgumentException> {
            JCS.assertAcceptable(JCSValue.Decimal(1.7e18))
        }
        assertFailsWith<IllegalArgumentException> {
            JCS.assertAcceptable(JCSValue.Decimal(1e19))
        }
        assertFailsWith<IllegalArgumentException> {
            JCS.assertAcceptable(JCSValue.Integer(9007199254740992L))
        }
    }

    @Test
    fun acceptsExactRangeBoundaryAndExponentForm() {
        JCS.assertAcceptable(JCSValue.Integer(9007199254740991L))
        JCS.assertAcceptable(JCSValue.Decimal(9007199254740991.0))
        JCS.assertAcceptable(JCSValue.Decimal(1e21))
        assertEquals("1e+21", JCS.canonical(JCSValue.Decimal(1e21)))
        JCS.assertAcceptable(JCSValue.Decimal(1.5))
    }

    @Test
    fun messageNamesTheOffendingPath() {
        val value = jobj("payload" to jobj("ts_ns" to JCSValue.Decimal(1.7e18)))
        val error = assertFailsWith<IllegalArgumentException> { JCS.assertAcceptable(value) }
        assertTrue(
            error.message!!.contains("\$.payload.ts_ns"),
            "message must name the path: ${error.message}",
        )
    }

    @Test
    fun rejectsUnpairedSurrogatesInValuesAndKeys() {
        assertFailsWith<IllegalArgumentException> {
            JCS.assertAcceptable(JCSValue.Str("a\uD83D"))
        }
        assertFailsWith<IllegalArgumentException> {
            JCS.assertAcceptable(JCSValue.Str("\uDC00b"))
        }
        assertFailsWith<IllegalArgumentException> {
            JCS.assertAcceptable(jobj("k\uD800" to JCSValue.Integer(1L)))
        }
    }

    @Test
    fun canonicalRefusesRatherThanSubstitutingAQuestionMark() {
        // Without the guard this produced {"s":"a?"} — a different hash and
        // no error whatsoever.
        assertFailsWith<IllegalArgumentException> {
            JCS.bytes(jobj("s" to JCSValue.Str("a\uD83D")))
        }
    }

    @Test
    fun acceptsWellFormedAstralPair() {
        val bytes = JCS.bytes(jobj("s" to JCSValue.Str("a\uD83D\uDE42")))
        assertEquals("{\"s\":\"a\uD83D\uDE42\"}", String(bytes, Charsets.UTF_8))
    }

    @Test
    fun parseJsonRefusesAnOutOfRangeIntegerLiteral() {
        val text = """{"payload":{"ts":10000000000000000000}}"""
        assertFailsWith<IllegalArgumentException> {
            CapsuleReader.parseJson(text.toByteArray(Charsets.UTF_8))
        }
    }

    @Test
    fun parseJsonRefusesALoneSurrogateEscape() {
        // Gson accepts the escape and hands back a lone surrogate; the gate
        // is what stops it reaching a hash.
        val text = """{"s":"x\ud83d"}"""
        assertFailsWith<IllegalArgumentException> {
            CapsuleReader.parseJson(text.toByteArray(Charsets.UTF_8))
        }
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-kotlin && ./gradlew --no-daemon :core:test --tests '*IJsonAcceptanceTest*'`

Expected: FAIL to compile — `e: ... Unresolved reference: assertAcceptable`.

- [ ] **Step 3: Add the acceptance gate to `Canonical.kt`**

Lines 49-51 currently read:

```kotlin
    fun bytes(v: JCSValue): ByteArray = canonical(v).toByteArray(Charsets.UTF_8)

    private const val MAX_SAFE_INTEGER = (1L shl 53) - 1
```

Replace with:

```kotlin
    fun bytes(v: JCSValue): ByteArray = canonical(v).toByteArray(Charsets.UTF_8)

    private const val MAX_SAFE_INTEGER = (1L shl 53) - 1

    /**
     * Smallest magnitude whose ECMAScript Number::toString form uses
     * exponent notation. Below it an integral double serializes as a
     * plain integer literal; at or above it the token carries an `e`.
     */
    private const val PLAIN_INTEGER_CEILING = 1e21

    /**
     * Enforce the I-JSON acceptance boundary from spec/canonicalization.md.
     *
     * Numbers: a value whose canonical token is a plain integer literal
     * (no "." and no "e") must satisfy |n| <= 2^53 - 1. Exponent-form
     * tokens round-trip through every lane's double path and are accepted
     * at any magnitude.
     *
     * Strings: a Java String is UTF-16 and can hold an unpaired surrogate.
     * toByteArray(UTF_8) then substitutes '?' silently, so the capsule
     * hashes different bytes with no error at all. Refuse instead.
     */
    fun assertAcceptable(v: JCSValue, path: String = "$") {
        when (v) {
            is JCSValue.Null, is JCSValue.Bool -> Unit
            is JCSValue.Str -> assertWellFormedUnicode(v.v, path)
            is JCSValue.Integer -> require(Math.abs(v.v) <= MAX_SAFE_INTEGER) {
                outOfExactRange(path)
            }
            is JCSValue.Decimal -> {
                require(v.v.isFinite()) { "JCS: non-finite number at $path" }
                val magnitude = Math.abs(v.v)
                val integral = v.v == Math.floor(v.v)
                require(
                    !(integral &&
                        magnitude > MAX_SAFE_INTEGER.toDouble() &&
                        magnitude < PLAIN_INTEGER_CEILING)
                ) { outOfExactRange(path) }
            }
            is JCSValue.Arr -> v.items.forEachIndexed { i, item ->
                assertAcceptable(item, "$path[$i]")
            }
            is JCSValue.Obj -> v.pairs.forEach { (key, value) ->
                assertWellFormedUnicode(key, "$path.$key")
                assertAcceptable(value, "$path.$key")
            }
        }
    }

    private fun outOfExactRange(path: String): String =
        "JCS: integer outside IEEE-754 exact range (|n| > 2^53 - 1) at $path; " +
            "not representable identically across implementations"

    /** Throw unless every surrogate in [s] is part of a well-formed pair. */
    private fun assertWellFormedUnicode(s: String, path: String) {
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (Character.isHighSurrogate(c)) {
                require(i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) {
                    unpairedSurrogate(c, path)
                }
                i += 2
                continue
            }
            require(!Character.isLowSurrogate(c)) { unpairedSurrogate(c, path) }
            i++
        }
    }

    private fun unpairedSurrogate(c: Char, path: String): String =
        "JCS: unpaired surrogate U+%04X at %s; strings must be well-formed Unicode"
            .format(c.code, path)
```

- [ ] **Step 4: Make `encodeString` refuse rather than substitute**

`Canonical.kt:154-156` currently reads:

```kotlin
    private fun encodeString(s: String): String {
        val out = StringBuilder(s.length + 2)
        out.append('"')
```

Replace with:

```kotlin
    private fun encodeString(s: String): String {
        // Backstop for every canonicalization path, including callers that
        // did not go through assertAcceptable. Without it, the surrogate
        // survives to toByteArray(UTF_8), which replaces it with '?' and
        // yields a wrong hash with no error.
        assertWellFormedUnicode(s, "(string)")
        val out = StringBuilder(s.length + 2)
        out.append('"')
```

- [ ] **Step 5: Gate the reader's parse boundary**

`Reader.kt:63-64` currently reads:

```kotlin
    fun parseJson(bytes: ByteArray): JCSValue =
        convert(JsonParser.parseString(String(bytes, Charsets.UTF_8)))
```

Replace with:

```kotlin
    /** Parse JSON bytes via Gson, then convert to JCSValue keeping insertion order. */
    fun parseJson(bytes: ByteArray): JCSValue {
        val value = convert(JsonParser.parseString(String(bytes, Charsets.UTF_8)))
        // I-JSON acceptance boundary (spec/canonicalization.md). Gson accepts
        // lone-surrogate escapes and oversized integer literals; neither has
        // a canonical form, so refuse before anything is hashed.
        JCS.assertAcceptable(value)
        return value
    }
```

(The existing KDoc comment on line 62 is folded into the replacement above; delete the duplicate.)

- [ ] **Step 6: Gate the builder's seal path**

`Builder.kt:95` currently reads:

```kotlin
        val events = Chain.build(bare)
```

Replace with:

```kotlin
        // I-JSON acceptance boundary (spec/canonicalization.md): refuse to
        // seal a payload that cannot be canonicalized identically in every
        // lane, rather than emitting a capsule only this lane can verify.
        bare.forEachIndexed { i, event ->
            JCS.assertAcceptable(event.payload, "event[$i].payload")
        }
        val events = Chain.build(bare)
```

- [ ] **Step 7: Teach the Kotlin number-vector test the `accepted` flag**

`JcsNumbersVectorTest.kt:22-29` currently reads:

```kotlin
        for (entry in vectors) {
            val v = entry.asJsonObject
            val hex = v.get("ieee_hex").asString
            val expected = v.get("expected").asString
            val bits = java.lang.Long.parseUnsignedLong(hex, 16)
            val value = java.lang.Double.longBitsToDouble(bits)
            assertEquals(expected, JCS.canonical(JCSValue.Decimal(value)), "bits $hex")
        }
```

Replace with:

```kotlin
        for (entry in vectors) {
            val v = entry.asJsonObject
            val hex = v.get("ieee_hex").asString
            val expected = v.get("expected").asString
            val bits = java.lang.Long.parseUnsignedLong(hex, 16)
            val value = java.lang.Double.longBitsToDouble(bits)
            if (v.has("accepted") && !v.get("accepted").asBoolean) {
                // Outside the I-JSON acceptance boundary
                // (spec/canonicalization.md): "expected" documents the
                // Number::toString layout, but the value must be refused.
                assertFailsWith<IllegalArgumentException>(
                    "bits $hex (would serialize as $expected) must be rejected"
                ) { JCS.assertAcceptable(JCSValue.Decimal(value)) }
                continue
            }
            assertEquals(expected, JCS.canonical(JCSValue.Decimal(value)), "bits $hex")
        }
```

Add the import at `JcsNumbersVectorTest.kt:6`, which currently reads `import kotlin.test.assertEquals`:

```kotlin
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
```

- [ ] **Step 8: Run the test to verify it passes**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-kotlin && ./gradlew --no-daemon :core:test --tests '*IJsonAcceptanceTest*'`

Expected: PASS — `BUILD SUCCESSFUL`, 8 tests executed, 0 failures.

- [ ] **Step 9: Run the full lane suite for regressions**

Run: `cd /Users/complex/repo/open-source/capsules-protocol/sdk-kotlin && ./gradlew --no-daemon :core:test`

Expected: `BUILD SUCCESSFUL` with 0 failures. If it instead fails with `Unresolved reference: CapsuleException` in `Reader.kt`, that is a pre-existing breakage unrelated to this task — see the cluster risks — and must be resolved separately before this lane can be verified.

- [ ] **Step 10: Commit**
```bash
git add sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Canonical.kt \
        sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Reader.kt \
        sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Builder.kt \
        sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/JcsNumbersVectorTest.kt \
        sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/IJsonAcceptanceTest.kt
git commit -m "fix(sdk-kotlin): refuse non-I-JSON input instead of hashing '?'

A Java String can hold an unpaired surrogate and toByteArray(UTF_8)
replaces it with '?' rather than throwing, so this lane hashed different
bytes than every other lane with no error at all. assertAcceptable refuses
unpaired surrogates and plain integer literals outside +/-(2^53 - 1);
encodeString carries the string check as a backstop so no canonicalization
path can substitute silently. parseJson and seal apply the gate."
```

---

### Task 8: Add the shared I-JSON acceptance vectors

**Files:**
- Create: `spec/vectors/ijson-acceptance.json`
- Modify: `tools/check-spec-vectors.mjs:391-393` (insert detector + checker) and `tools/check-spec-vectors.mjs:404-412` (dispatch + error text)
- Modify: `spec/vectors/README.md:3-5` and `spec/vectors/README.md:46-50`
- Modify: `sdk-py/tests/test_spec_registry.py:31` and `:116`
- Modify: `verifier-rust/tests/spec_registry.rs:19-21` and `:132`
- Test: `sdk-py/tests/test_spec_registry.py`, `verifier-rust/tests/spec_registry.rs`, `tools/check-spec-vectors.mjs`

**Interfaces:**
- Consumes: `assertIJson`/`jcs` (Task 2), `jcs` (Task 4), `check_ijson` (Task 5)
- Produces: vector shape `{ name, input_json, expect: "accept" | "reject", canonical?, reason? }` with normative reason vocabulary `integer_out_of_range` and `unpaired_surrogate`

- [ ] **Step 1: Write the vector file**

Create `spec/vectors/ijson-acceptance.json`:

```json
{
  "meta": {
    "kind": "ijson-acceptance"
  },
  "description": "I-JSON acceptance boundary vectors (spec/canonicalization.md). `input_json` is the raw JSON text an implementation must feed to its own parser plus canonicalizer. `expect: accept` pins the canonical output; `expect: reject` requires the value to be refused, at parse time or at canonicalization time, whichever this lane reaches first. Both are conforming: what is normative is that the value never reaches a hash.",
  "reasons": {
    "integer_out_of_range": "A number whose canonical token is a plain integer literal (no '.', no 'e') with |n| > 2^53 - 1.",
    "unpaired_surrogate": "A string, or an object key, containing a surrogate code point that is not part of a well-formed pair."
  },
  "vectors": [
    {
      "name": "max-safe-integer",
      "input_json": "{\"n\":9007199254740991}",
      "expect": "accept",
      "canonical": "{\"n\":9007199254740991}"
    },
    {
      "name": "negative-max-safe-integer",
      "input_json": "{\"n\":-9007199254740991}",
      "expect": "accept",
      "canonical": "{\"n\":-9007199254740991}"
    },
    {
      "name": "exponent-form-above-plain-ceiling",
      "input_json": "{\"n\":1e21}",
      "expect": "accept",
      "canonical": "{\"n\":1e+21}"
    },
    {
      "name": "fractional-number",
      "input_json": "{\"n\":4.35}",
      "expect": "accept",
      "canonical": "{\"n\":4.35}"
    },
    {
      "name": "well-formed-astral-pair",
      "input_json": "{\"s\":\"a\\ud83d\\ude42\"}",
      "expect": "accept",
      "canonical": "{\"s\":\"a🙂\"}"
    },
    {
      "name": "non-ascii-passthrough",
      "input_json": "{\"s\":\"héllo\"}",
      "expect": "accept",
      "canonical": "{\"s\":\"héllo\"}"
    },
    {
      "name": "twenty-digit-integer-literal",
      "input_json": "{\"ts\":10000000000000000000}",
      "expect": "reject",
      "reason": "integer_out_of_range"
    },
    {
      "name": "nanosecond-timestamp",
      "input_json": "{\"ts_ns\":1700000000000000000}",
      "expect": "reject",
      "reason": "integer_out_of_range"
    },
    {
      "name": "two-pow-53-plus-one",
      "input_json": "{\"n\":9007199254740993}",
      "expect": "reject",
      "reason": "integer_out_of_range"
    },
    {
      "name": "exponent-input-plain-integer-output",
      "input_json": "{\"n\":1e19}",
      "expect": "reject",
      "reason": "integer_out_of_range"
    },
    {
      "name": "lone-high-surrogate",
      "input_json": "{\"s\":\"x\\ud83d\"}",
      "expect": "reject",
      "reason": "unpaired_surrogate"
    },
    {
      "name": "lone-low-surrogate",
      "input_json": "{\"s\":\"\\udc00x\"}",
      "expect": "reject",
      "reason": "unpaired_surrogate"
    },
    {
      "name": "lone-surrogate-in-object-key",
      "input_json": "{\"k\\ud800\":1}",
      "expect": "reject",
      "reason": "unpaired_surrogate"
    },
    {
      "name": "lone-surrogate-nested-in-payload",
      "input_json": "{\"payload\":{\"summary\":\"ok \\ud83d\"}}",
      "expect": "reject",
      "reason": "unpaired_surrogate"
    }
  ]
}
```

- [ ] **Step 2: Run the checker to verify it fails**

Run: `cd /Users/complex/repo/open-source/capsules-protocol && node tools/check-spec-vectors.mjs`

Expected: FAIL — `FAIL: spec/vectors/ijson-acceptance.json: unrecognized vector document (expected capsule_bytes_b64 + expected, an outcome-vector collection, a signing-input doc, or a jcs number set)`, exit code 1. (`isCollection` matches on `vectors`, but the dispatch order reaches the `unrecognized` branch because the entries carry no `capsule_file`; either way the doc is not understood.)

- [ ] **Step 3: Teach `tools/check-spec-vectors.mjs` the new shape**

`tools/check-spec-vectors.mjs:391-393` currently reads:

```js
function isSigningInputVector(doc) {
  return doc && typeof doc === "object" && doc.meta?.kind === "signing-input";
}
```

Replace with:

```js
function isSigningInputVector(doc) {
  return doc && typeof doc === "object" && doc.meta?.kind === "signing-input";
}

function isIJsonAcceptanceSet(doc) {
  return doc && typeof doc === "object" && doc.meta?.kind === "ijson-acceptance";
}

// I-JSON acceptance vectors (spec/canonicalization.md). `input_json` is raw
// JSON text: each lane feeds it to its own parser, then canonicalizes. A
// `reject` vector is satisfied by refusal at EITHER stage — some lanes' JSON
// parsers refuse lone-surrogate escapes outright, others accept them and the
// canonicalizer refuses. What is normative is that the value never reaches a
// hash.
const IJSON_REASONS = new Set(["integer_out_of_range", "unpaired_surrogate"]);

function checkIJsonAcceptance(path, doc) {
  if (!Array.isArray(doc.vectors) || doc.vectors.length === 0) {
    fail(`${path}: vectors must be a non-empty array`);
    return;
  }
  for (const v of doc.vectors) {
    checked++;
    const label = `${path} [${v.name}]`;
    if (typeof v.input_json !== "string") {
      fail(`${label}: input_json must be a string of raw JSON text`);
      continue;
    }
    let parsed;
    let parseFailed = false;
    try {
      parsed = JSON.parse(v.input_json);
    } catch {
      parseFailed = true;
    }
    if (v.expect === "accept") {
      if (parseFailed) {
        fail(`${label}: expected accept, but the JSON text does not parse`);
        continue;
      }
      let got;
      try {
        got = Buffer.from(jcs(parsed)).toString("utf8");
      } catch (err) {
        fail(`${label}: expected accept, but canonicalization threw: ${err.message}`);
        continue;
      }
      if (got !== v.canonical) {
        fail(`${label}: canonical mismatch: got ${got}, vector says ${v.canonical}`);
      }
      continue;
    }
    if (v.expect !== "reject") {
      fail(`${label}: expect must be "accept" or "reject"`);
      continue;
    }
    if (!IJSON_REASONS.has(v.reason)) {
      fail(`${label}: unknown reject reason '${v.reason}'`);
      continue;
    }
    if (parseFailed) continue; // parse-stage refusal is conforming
    let threw = false;
    try {
      jcs(parsed);
    } catch {
      threw = true;
    }
    if (!threw) {
      fail(`${label}: expected canonicalization to reject (${v.reason}), but it succeeded`);
    }
  }
}
```

Then `tools/check-spec-vectors.mjs:404` currently reads:

```js
  if (isNumberVectorSet(path, doc)) checkNumberVectors(path, doc);
  else if (isSigningInputVector(doc)) await checkSigningInput(path, doc);
```

Replace with:

```js
  if (isNumberVectorSet(path, doc)) checkNumberVectors(path, doc);
  else if (isIJsonAcceptanceSet(doc)) checkIJsonAcceptance(path, doc);
  else if (isSigningInputVector(doc)) await checkSigningInput(path, doc);
```

And the fallthrough message at `tools/check-spec-vectors.mjs:410-411` currently reads:

```js
      `${path}: unrecognized vector document (expected capsule_bytes_b64 + expected, ` +
        `an outcome-vector collection, a signing-input doc, or a jcs number set)`
```

Replace with:

```js
      `${path}: unrecognized vector document (expected capsule_bytes_b64 + expected, ` +
        `an outcome-vector collection, a signing-input doc, an ijson-acceptance ` +
        `doc, or a jcs number set)`
```

Finally add the shape to the file's header comment, immediately after the block ending `...canonicalization must refuse the value.` (added in Task 2, Step 9):

```js
//
//   4. An I-JSON acceptance set (meta.kind === "ijson-acceptance"): a
//      `vectors` array of `{ name, input_json, expect, canonical?, reason? }`
//      entries carrying raw JSON text that must be accepted (with its
//      canonical form pinned) or refused, per spec/canonicalization.md.
```

- [ ] **Step 4: Run the checker to verify it passes**

Run: `cd /Users/complex/repo/open-source/capsules-protocol && node tools/check-spec-vectors.mjs`

Expected: PASS — `spec vectors: ok (294 vectors)` (280 baseline + 14).

- [ ] **Step 5: Consume the vectors from the Python registry test**

`sdk-py/tests/test_spec_registry.py:31` currently reads:

```python
SIGNING_INPUT = VECTORS / "signing-input.json"
```

Replace with:

```python
SIGNING_INPUT = VECTORS / "signing-input.json"
IJSON_ACCEPTANCE = VECTORS / "ijson-acceptance.json"

# Normative reject-reason vocabulary from ijson-acceptance.json.
IJSON_REASONS = {"integer_out_of_range", "unpaired_surrogate"}
```

Then insert this immediately before `def test_signing_input_pins():` (line 116):

```python
def _ijson_params():
    if not IJSON_ACCEPTANCE.exists():
        return []
    doc = _load(IJSON_ACCEPTANCE)
    return [pytest.param(v, id=v["name"]) for v in doc["vectors"]]


@pytest.mark.parametrize("vector", _ijson_params())
def test_ijson_acceptance_boundary(vector: dict):
    """spec/canonicalization.md: identical accept/reject boundary in every lane.

    A reject vector is satisfied by refusal at parse time OR at
    canonicalization time — whichever this lane reaches first.
    """
    name = vector["name"]
    try:
        parsed = json.loads(vector["input_json"])
    except ValueError:
        assert vector["expect"] == "reject", f"{name}: an accept vector must parse"
        return
    if vector["expect"] == "accept":
        assert jcs(parsed).decode("utf-8") == vector["canonical"], name
        return
    assert vector["reason"] in IJSON_REASONS, f"{name}: unknown reason {vector['reason']!r}"
    with pytest.raises(ValueError):
        jcs(parsed)


```

- [ ] **Step 6: Consume the vectors from the Rust registry test**

`verifier-rust/tests/spec_registry.rs:19-21` currently reads:

```rust
use capsule_verify::{
    ed25519_verify, jcs, sha256_hex, unpack_zip, verify_capsule, VerifyOptions, VerifyResult,
};
```

Replace with:

```rust
use capsule_verify::{
    check_ijson, ed25519_verify, jcs, sha256_hex, unpack_zip, verify_capsule, VerifyOptions,
    VerifyResult,
};
```

Then insert this immediately before the comment `/// Per-lane mapping of the registry's normative open-stage reason` (line 132):

```rust
/// Normative reject-reason vocabulary from `ijson-acceptance.json`.
const IJSON_REASONS: &[&str] = &["integer_out_of_range", "unpaired_surrogate"];

/// `spec/canonicalization.md`: the acceptance boundary is identical in every
/// lane. A reject vector is satisfied by refusal at parse time OR at the
/// canonicalization gate — whichever this lane reaches first. In Rust
/// `serde_json` refuses lone-surrogate escapes at parse; `check_ijson`
/// refuses out-of-range integer literals.
#[test]
fn ijson_acceptance_boundary() {
    let path = vectors_dir().join("ijson-acceptance.json");
    let doc = load_json(&path);
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty());
    for v in vectors {
        let name = v["name"].as_str().expect("name");
        let text = v["input_json"].as_str().expect("input_json");
        let expect = v["expect"].as_str().expect("expect");
        let parsed: Value = match serde_json::from_str(text) {
            Ok(value) => value,
            Err(e) => {
                assert_eq!(expect, "reject", "{name}: an accept vector must parse ({e})");
                continue;
            }
        };
        if expect == "accept" {
            check_ijson(&parsed).unwrap_or_else(|e| panic!("{name}: must be accepted: {e}"));
            let canonical = v["canonical"].as_str().expect("canonical");
            assert_eq!(
                String::from_utf8(jcs(&parsed)).expect("utf8"),
                canonical,
                "{name}"
            );
            continue;
        }
        assert_eq!(expect, "reject", "{name}: expect must be accept or reject");
        let reason = v["reason"].as_str().expect("reason");
        assert!(
            IJSON_REASONS.contains(&reason),
            "{name}: unknown reason {reason:?}"
        );
        assert!(
            check_ijson(&parsed).is_err(),
            "{name}: parsed, so the canonicalization gate must refuse it"
        );
    }
}

```

- [ ] **Step 7: Document the new shape in the vectors README**

`spec/vectors/README.md:3-5` currently reads:

```markdown
This directory contains checked-in protocol vectors. Four shapes exist, all
verified by `tools/check-spec-vectors.mjs` (the `spec-vectors` conformance
lane):
```

Replace with:

```markdown
This directory contains checked-in protocol vectors. Five shapes exist, all
verified by `tools/check-spec-vectors.mjs` (the `spec-vectors` conformance
lane):
```

And `spec/vectors/README.md:46-50` currently reads:

```markdown
4. **JCS number-serialization set** (`jcs-numbers.json`): a `vectors` array
   of `{ ieee_hex, expected }` entries, where `ieee_hex` is the big-endian
   IEEE-754 binary64 bit pattern of the input and `expected` its canonical
   RFC 8785 serialization. Implementations must parse the bit pattern (not
   the expected string) and serialize it.
```

Replace with:

```markdown
4. **JCS number-serialization set** (`jcs-numbers.json`): a `vectors` array
   of `{ ieee_hex, expected, accepted? }` entries, where `ieee_hex` is the
   big-endian IEEE-754 binary64 bit pattern of the input and `expected` its
   canonical RFC 8785 serialization. Implementations must parse the bit
   pattern (not the expected string) and serialize it. `accepted: false`
   marks a bit pattern outside the I-JSON acceptance boundary
   (`spec/canonicalization.md`): `expected` records the `Number::toString`
   layout for reference, but canonicalization MUST refuse the value.

5. **I-JSON acceptance set** (`ijson-acceptance.json`, detected by
   `meta.kind: "ijson-acceptance"`): a `vectors` array of
   `{ name, input_json, expect, canonical?, reason? }` entries. `input_json`
   is raw JSON text; each implementation feeds it to its own parser and then
   canonicalizes. `expect: "accept"` pins the canonical output.
   `expect: "reject"` is satisfied by refusal at parse time OR at
   canonicalization time — both are conforming; what is normative is that the
   value never reaches a hash. The `reason` categories
   (`integer_out_of_range`, `unpaired_surrogate`) are normative; exact error
   strings are implementation-defined. The Python
   (`sdk-py/tests/test_spec_registry.py`) and Rust
   (`verifier-rust/tests/spec_registry.rs`) lanes consume this set directly.
```

- [ ] **Step 8: Run the full multi-lane suite for regressions**

Run:
```bash
cd /Users/complex/repo/open-source/capsules-protocol
node tools/check-spec-vectors.mjs
(cd sdk-js && npm test)
(cd sdk-py && PYTHONPATH=src python3 -m pytest)
(cd verifier-rust && cargo test --workspace)
```

Expected: `spec vectors: ok (294 vectors)`; sdk-js `# pass 69 / # fail 0`; sdk-py `200 passed` (186 after Task 4 + 14 new params); verifier-rust lib `107 passed`, parity `7 passed`, spec_registry `4 passed`.

- [ ] **Step 9: Commit**
```bash
git add spec/vectors/ijson-acceptance.json spec/vectors/README.md \
        tools/check-spec-vectors.mjs sdk-py/tests/test_spec_registry.py \
        verifier-rust/tests/spec_registry.rs
git commit -m "test(spec): add I-JSON acceptance vectors consumed by three lanes

Fourteen raw-JSON-text vectors covering out-of-range integer literals,
nanosecond timestamps, the 2^53 boundary, exponent-form magnitudes, lone
high/low surrogates, a lone surrogate in an object key, and a well-formed
astral pair. A reject vector is satisfied by refusal at parse OR at
canonicalization, because Rust and Swift refuse lone surrogates at parse
while JS, Python and Kotlin refuse them at the gate; what the vector pins
is that the value never reaches a hash."
```

---

### Task 9: Freeze the astral-Pith reproduction as a cross-lane capsule fixture

**Files:**
- Create: `sdk-js/tools/generate-unicode-boundary-fixture.mjs`
- Create: `spec/vectors/unicode-boundary/vectors.json`
- Create: `spec/vectors/unicode-boundary/output/astral-pith.capsule` (generated)
- Create: `spec/vectors/unicode-boundary/output/keys.json` (generated)
- Modify: `spec/vectors/README.md` (generator list, currently lines 55-62)
- Modify: `sdk-py/tests/test_spec_registry.py:30` and `:101`
- Modify: `verifier-rust/tests/spec_registry.rs:132`
- Test: `sdk-py/tests/test_spec_registry.py`, `verifier-rust/tests/spec_registry.rs`, `tools/check-spec-vectors.mjs`

**Interfaces:**
- Consumes: the surrogate-safe truncation from Task 3; `CapsuleBuilder`, `CapsuleReader`, `verifyCapsule`, `generateEd25519` from `sdk-js/src/index.js`; the existing outcome-collection shape (`keys_file` + `vectors[].capsule_file` + `expected`)
- Produces: `spec/vectors/unicode-boundary/` collection; `node sdk-js/tools/generate-unicode-boundary-fixture.mjs [--check]`

- [ ] **Step 1: Write the failing test**

Create `spec/vectors/unicode-boundary/vectors.json`:

```json
{
  "meta": {
    "name": "unicode-boundary",
    "spec_version": "0.6",
    "description": "A capsule whose event summary is 200 astral code points, long enough that the Pith normalizer must truncate it. Before the surrogate-pair-safe cut in the reference builder this capsule verified in JS and failed everywhere else with an opaque chain-hash error. Independent implementations MUST verify it ok:true; a failure here means the lane's canonicalization disagrees on well-formed astral text, not that the capsule was tampered with.",
    "no_warranty": "Conformance fixtures only; not production templates or advice."
  },
  "keys_file": "output/keys.json",
  "vectors": [
    {
      "name": "astral-pith",
      "capsule_file": "output/astral-pith.capsule",
      "expected": { "ok": true }
    }
  ]
}
```

- [ ] **Step 2: Run the checker to verify it fails**

Run: `cd /Users/complex/repo/open-source/capsules-protocol && node tools/check-spec-vectors.mjs`

Expected: FAIL — `FAIL: spec/vectors/unicode-boundary/vectors.json: keys_file unreadable: ENOENT: no such file or directory, open '.../unicode-boundary/output/keys.json'` and `FAIL: spec/vectors/unicode-boundary/vectors.json [astral-pith]: capsule_file unreadable: ENOENT ...`, exit code 1.

- [ ] **Step 3: Write the fixture generator**

Create `sdk-js/tools/generate-unicode-boundary-fixture.mjs`:

```js
#!/usr/bin/env node
// generate-unicode-boundary-fixture.mjs
//
// Freezes the C9 reproduction as a cross-lane conformance fixture: a capsule
// whose event summary is 200 astral code points, long enough that the Pith
// normalizer must truncate it. Before the surrogate-pair-safe cut in
// sdk-js/src/pith.js this capsule verified ok:true in JS and failed in
// sdk-py with "'utf-8' codec can't encode character '\ud83d'".
//
// Output (spec/vectors/unicode-boundary/output/):
//   astral-pith.capsule   plain, must verify ok:true in every lane
//   keys.json             {originator} pub+priv hex (throwaway fixture key)
//
// Run with --check to assert the checked-in fixture still verifies without
// rewriting it (regeneration changes the signing key and therefore every
// pinned hash, so it must be an explicit, reviewed act).

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { CapsuleBuilder, CapsuleReader, generateEd25519, verifyCapsule } from "../src/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..");
const OUT_DIR = join(REPO_ROOT, "spec", "vectors", "unicode-boundary", "output");
const SIGNED_AT = "2026-05-08T12:00:00Z";

// 200 astral code points = 400 UTF-16 code units. The default Pith cut index
// (280 - 1 for the ellipsis = 279) is odd, so a naive slice lands mid-pair.
const ASTRAL_SUMMARY = "\u{1F642}".repeat(200);

async function buildCapsule(signer) {
  const builder = new CapsuleBuilder({
    originator: { publicKey: signer.publicKeyHex, label: "ConformanceOriginator" },
    participants: [{ actor_id: "human:origin", role: "originator", label: "Origin" }],
    createdAt: SIGNED_AT,
  });
  builder.setProgram("# Unicode Boundary\n\nAstral-character Pith fixture.\n");
  builder.appendEvent({
    actor: "human:origin",
    kind: "observation",
    action: "recorded",
    target: "program.md",
    timestamp: SIGNED_AT,
    payload: { summary: ASTRAL_SUMMARY },
  });
  return builder.seal({ signers: [signer], signedAt: SIGNED_AT });
}

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

async function assertFixtureIsSound(bytes, publicKeyHex) {
  const reader = await CapsuleReader.fromBytes(bytes);
  const result = await verifyCapsule(reader, { allowlist: [publicKeyHex] });
  if (!result.ok) throw new Error(`fixture does not verify: ${result.errors.join("; ")}`);
  const summary = reader.events()[0].payload.summary;
  if (LONE_SURROGATE.test(summary)) {
    throw new Error("fixture summary contains an unpaired surrogate");
  }
}

async function main() {
  const check = process.argv.includes("--check");
  if (check) {
    const keys = JSON.parse(await readFile(join(OUT_DIR, "keys.json"), "utf8"));
    const bytes = await readFile(join(OUT_DIR, "astral-pith.capsule"));
    await assertFixtureIsSound(bytes, keys.originator.publicKey);
    console.log("unicode-boundary fixture: ok");
    return;
  }
  await mkdir(OUT_DIR, { recursive: true });
  const signer = generateEd25519();
  const bytes = await buildCapsule({ ...signer, role: "originator" });
  await assertFixtureIsSound(bytes, signer.publicKeyHex);
  await writeFile(join(OUT_DIR, "astral-pith.capsule"), bytes);
  await writeFile(
    join(OUT_DIR, "keys.json"),
    JSON.stringify(
      { originator: { publicKey: signer.publicKeyHex, privateKey: signer.privateKeyHex } },
      null,
      2,
    ) + "\n",
  );
  console.log(`wrote ${OUT_DIR}/astral-pith.capsule`);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
```

- [ ] **Step 4: Generate the fixture (write path — run exactly once)**

Run: `cd /Users/complex/repo/open-source/capsules-protocol && node sdk-js/tools/generate-unicode-boundary-fixture.mjs`

Expected: `wrote .../spec/vectors/unicode-boundary/output/astral-pith.capsule`, and `ls spec/vectors/unicode-boundary/output/` shows `astral-pith.capsule` (~3.1 KB) and `keys.json`. Regenerating rewrites every hash in the capsule; from here on use `--check`.

- [ ] **Step 5: Run the checker to verify it passes**

Run: `cd /Users/complex/repo/open-source/capsules-protocol && node tools/check-spec-vectors.mjs && node sdk-js/tools/generate-unicode-boundary-fixture.mjs --check`

Expected: PASS — `spec vectors: ok (295 vectors)` (294 after Task 8 + 1) then `unicode-boundary fixture: ok`.

- [ ] **Step 6: Consume the fixture from the Python registry test**

`sdk-py/tests/test_spec_registry.py:30` currently reads:

```python
MALFORMED = VECTORS / "malformed-layout" / "vectors.json"
```

Replace with:

```python
MALFORMED = VECTORS / "malformed-layout" / "vectors.json"
UNICODE_BOUNDARY = VECTORS / "unicode-boundary" / "vectors.json"
```

Then insert this immediately before `@pytest.mark.parametrize("doc,vector,base", _collection_params(MALFORMED))` (line 101):

```python
@pytest.mark.parametrize("doc,vector,base", _collection_params(UNICODE_BOUNDARY))
def test_unicode_boundary_registry_outcomes(doc: dict, vector: dict, base: pathlib.Path):
    """A JS-built capsule carrying truncated astral text must verify here."""
    data = (base / vector["capsule_file"]).read_bytes()
    reader = CapsuleReader.from_bytes(data)
    result = verify_capsule(reader, allowlist=_allowlist(doc, base))
    _assert_verify_outcome(vector["name"], vector["expected"], result)


```

- [ ] **Step 7: Consume the fixture from the Rust registry test**

In `verifier-rust/tests/spec_registry.rs`, insert this immediately before the comment `/// Per-lane mapping of the registry's normative open-stage reason` (line 132 before Task 8's insertion; after Task 8 it sits directly above that same comment):

```rust
/// A JS-built capsule carrying Pith-truncated astral text must verify here.
/// A failure means this lane's canonicalization disagrees on well-formed
/// astral text — not that the capsule was tampered with.
#[test]
fn unicode_boundary_registry_outcomes() {
    let path = vectors_dir().join("unicode-boundary/vectors.json");
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

- [ ] **Step 8: Register the generator in the vectors README**

`spec/vectors/README.md` lists the generators:

```markdown
- `sdk-js/tools/generate-tamper-fixtures.mjs` → `tamper-detection/output/`
- `sdk-js/tools/generate-malformed-fixtures.mjs` → `malformed-layout/output/`
  (derived from the tamper-detection clean fixture)
- `sdk-js/tools/generate-signing-input-vector.mjs` → `signing-input.json`
  (derived from `plain-basic.json`)
```

Replace with:

```markdown
- `sdk-js/tools/generate-tamper-fixtures.mjs` → `tamper-detection/output/`
- `sdk-js/tools/generate-malformed-fixtures.mjs` → `malformed-layout/output/`
  (derived from the tamper-detection clean fixture)
- `sdk-js/tools/generate-signing-input-vector.mjs` → `signing-input.json`
  (derived from `plain-basic.json`)
- `sdk-js/tools/generate-unicode-boundary-fixture.mjs` →
  `unicode-boundary/output/` (`--check` re-verifies the checked-in fixture
  without rewriting it; regeneration mints a new signing key and changes
  every hash)
```

- [ ] **Step 9: Run the full multi-lane suite for regressions**

Run:
```bash
cd /Users/complex/repo/open-source/capsules-protocol
node tools/check-spec-vectors.mjs
node sdk-js/tools/generate-unicode-boundary-fixture.mjs --check
node sdk-js/tools/generate-malformed-fixtures.mjs --check
(cd sdk-js && npm test)
(cd cli && npm test)
(cd sdk-py && PYTHONPATH=src python3 -m pytest)
(cd verifier-rust && cargo test --workspace)
```

Expected: `spec vectors: ok (295 vectors)`; `unicode-boundary fixture: ok`; all 10 malformed fixtures `ok`; sdk-js `# pass 69 / # fail 0`; cli `50 passed, 0 failed`; sdk-py `201 passed`; verifier-rust lib `107 passed`, parity `7 passed`, spec_registry `5 passed`.

- [ ] **Step 10: Commit**
```bash
git add sdk-js/tools/generate-unicode-boundary-fixture.mjs \
        spec/vectors/unicode-boundary spec/vectors/README.md \
        sdk-py/tests/test_spec_registry.py verifier-rust/tests/spec_registry.rs
git commit -m "test(spec): freeze the astral-Pith capsule as a cross-lane fixture

The C9 reproduction, checked in: a sealed capsule whose event summary is
200 astral code points, so Pith must truncate it. On the old code this
verified ok:true in JS and failed in sdk-py with a chain-hash error that
read like tampering. Every lane must now verify it ok:true, so a future
regression in truncation or in string canonicalization is caught by the
conformance registry rather than by a downstream verifier."
```

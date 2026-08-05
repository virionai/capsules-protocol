# C6 — Make the JS and Python verifiers total functions

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Part of:** [Capsules pre-release remediation](./README.md) · Tier 2 (v0.7 correctness)

**Findings closed:** F10, F06, F14, F34, F56

**Lanes touched:** sdk-js, sdk-py, spec, tools

**Tasks:** 8

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

EXISTING TESTS THAT CHANGE

1. `sdk-py/tests/test_reader.py::test_is_encrypted_when_manifest_has_encryption` FAILS once reader shape validation lands — it hand-builds a manifest with only `format` and an envelope with `signers: []`, which the ported validator now refuses (`MalformedCapsuleError: manifest.id is not a 64-char lowercase hex string: None`). Task 5 Step 5 fixes the fixture in place; that is the only pre-existing test in either lane that this cluster has to touch. Verified: with the fixture updated, `197 passed`.

2. Per-signer errors (Tasks 4 and 7) add entries to `result.errors` / `result["errors"]` for capsules that previously reported an invalid signature only inside `envelope.signers[i]`. I checked every assertion on those arrays: `sdk-py/tests/test_parity_jssdk.py:247 assert result["errors"] == []` and `sdk-js/test/dx.test.js:98` both run on clean or unopenable capsules, so neither is affected. `tamper-detection/vectors.json` vector `tampered-envelope` expects `failing: ["envelope"]` with no `error_includes`, so the extra error is additive. The Rust lane's `error_includes` haystack is unaffected because Rust is not changed. Confirmed by the green `spec vectors: ok (285 vectors)` and `197 passed` runs.

3. Chain error strings are deliberately additive, not renamed. `prev_hash missing or wrong length` and `hash missing or wrong length` appear verbatim in `verifier-rust/crates/capsule-verify/src/chain.rs:89,108`; the plan keeps both branches intact and adds a separate `... is not canonical lowercase hex` branch after them, so cross-lane message parity is preserved.

CROSS-LANE COORDINATION

4. The new `spec/vectors/malformed-shape/` collection is deliberately a NEW directory rather than more entries in `malformed-layout/vectors.json`. Adding a new `reason` category to malformed-layout would hit `verifier-rust/tests/spec_registry.rs:146` (`other => panic!("unknown open-stage reason {other:?}")`) and break the Rust lane, which is out of this cluster's scope. Rust and Swift/Kotlin hard-code the two existing collection paths, so they neither see nor break on the new one. FOLLOW-UP FOR A LATER CLUSTER: wire `malformed-shape` into `verifier-rust/tests/spec_registry.rs` (add `"invalid_manifest_shape" => &["failed to parse manifest.json"]` to `open_reason_needles` and a third `#[test]` over the new path). Rust's `Manifest`/`ContentIndex`/`FileEntry` serde structs already make all four open-stage fixtures fail to deserialize, so no Rust verifier change should be needed — but that must be confirmed by running `cargo test`, which I did not do.

5. `tools/check-spec-vectors.mjs` fails closed on any unrecognized JSON under `spec/vectors/`, so the new `vectors.json` must land in the same commit as its `output/*.capsule` fixtures or the `spec-vectors` conformance target fails (observed: 5x `capsule_file unreadable: ENOENT`). Task 8 orders the steps so this window never exists in a committed state.

OTHER RISKS

6. Task 3's catch-all changes `verifyCapsule`'s failure mode for programmer errors too: a genuine bug inside the verifier now surfaces as `ok:false, errors:["verification failed: ..."]` instead of a stack trace. That is the documented contract (verifier.js:26-29, index.d.ts:216-219) and the reason the finding is HIGH, but it does make verifier bugs quieter in development. The inner function is left intact and unexported, so a debugger can still break inside it.

7. Task 5 makes `CapsuleReader.from_bytes` strictly stricter in Python. Any Python-side consumer that hands the reader a capsule the JS reference already refuses will now get `MalformedCapsuleError` where it previously got a reader. That is the point of F34 (parity with sdk-js reader.js), and the project is pre-release, but it is a behavioral break for anything outside this repo.

8. `first_and_entry_hash` changes its declared return type from `tuple[str, str]` to `tuple[str | None, str | None]`. It is exported from `capsule.chain` but grep shows the only caller is `verifier.py`, which compares the values against the envelope and reports a mismatch on `None` (observed: `envelope.first_event_hash mismatch: 866cc8... vs None`).

## Validation performed while specifying this plan

The steps below were applied to a **copy of the repository outside the working tree** and executed. This is the real output from that run, not a prediction.

<details>
<summary>Expand validation log</summary>

```
Applied the whole cluster on a copy at /tmp/work-c6 (rsync of the repo, verifier-rust/target excluded) and ran every command below there. Nothing in /Users/complex/repo/open-source/capsules-protocol was modified.

BASELINE (unmodified copy):
- 'cd sdk-js && npm test' -> '# tests 57 / # pass 57 / # fail 0'
- 'cd sdk-py && PYTHONPATH=src python3 -m pytest' -> '182 passed in 0.29s'
- 'node tools/check-spec-vectors.mjs' -> 'spec vectors: ok (280 vectors)'

FINDINGS REPRODUCED on the baseline copy (repro scripts /tmp/work-c6/repro-js.mjs, /tmp/work-c6/repro-py.py):
JS: 'missing content_index: THREW TypeError: Cannot read properties of undefined (reading 'index_hash')'; 'files not array: THREW TypeError: manifest.content_index.files.map is not a function'; 'uppercase stored hash: THREW Error: hexToBytes: uppercase hex is non-canonical; use lowercase'; 'bad signature: {"ok":false,"errors":[],"notes":[],"chainErrors":[],"ciErrors":[],"signers":[{...,"valid":false,"trusted":false}]}' (F56 — no displayable message anywhere).
PY: 'manifest is array: RAISED AttributeError: 'list' object has no attribute 'get''; 'entry missing sha256: RAISED KeyError: 'sha256''; 'non-object chain event: RAISED AttributeError: 'str' object has no attribute 'get''; 'uppercase stored hash: RAISED ValueError: hex_to_bytes: non-hex characters'.

AFTER the full cluster:
- 'cd sdk-js && npm test' -> '# tests 66 / # pass 66 / # fail 0'
- 'cd sdk-py && PYTHONPATH=src python3 -m pytest' -> '197 passed in 0.26s'
- 'cd sdk-py && ruff check src tests' (ruff 0.15.4) -> 'All checks passed!'
- 'node tools/check-spec-vectors.mjs' -> 'spec vectors: ok (285 vectors)'
- 'node sdk-js/tools/generate-malformed-shape-fixtures.mjs --check' -> 'ok manifest-not-object.capsule (1747 bytes) / ok missing-content-index.capsule (2402 bytes) / ok content-index-files-not-array.capsule (2530 bytes) / ok content-index-entry-missing-sha256.capsule (2634 bytes) / ok uppercase-event-hash.capsule (2601 bytes)'
- 'node tools/run-conformance.mjs' -> 'PASS · 11/11 passed · 3.1s total' (all of skill-capsule-regen, sdk-js, cli, malformed-fixtures-regen, malformed-shape-fixtures-regen, spec-vectors, example-quickstart, example-generic-report, example-generic-table-graph, example-generic-react-render, examples-generic-hygiene)
- 'cd cli && npm test' -> '50 passed, 0 failed'
- Post-fix repro output: every JS case now returns 'ok=false' with a message ('capsule cannot be opened: manifest.content_index must be a JSON object', '... files must be an array', '... files[0].sha256 must be a 64-char lowercase hex string', 'manifest.json is not a JSON object'), the uppercase case yields chain error 'hash is not canonical lowercase hex', and the bad signature yields 'envelope.signers[0] signature invalid (role 'originator', public_key ...)'. Python identical.

EVERY "Expected: FAIL" IN THIS PLAN WAS OBSERVED, at the exact intermediate state the task describes. I restored each pristine source file one at a time and re-ran the relevant tests:
- Task 1 (reader pristine): 'not ok 1 ... error: "Cannot read properties of undefined (reading 'index_hash')"', 'not ok 2 ... error: 'manifest.content_index.files.map is not a function'', 'not ok 3 ... AssertionError: Expected values to be strictly equal: true !== false', 'not ok 4 ... The input did not match the regular expression /manifest\\.json is not a JSON object/. Input: "manifest.format.version: expected '0.6', got undefined"'. With ONLY reader.js patched: 'ok 1..4 / # pass 4 / # fail 0'.
- Task 2 (chain pristine, reader patched): 3 fail; with chain.js patched and verifier.js still pristine: '# tests 3 / # pass 3 / # fail 0'.
- Task 3/4 (verifier pristine): 'not ok 1 ... error: "Cannot read properties of undefined (reading 'index_hash')"', 'not ok 2 ... error: 'expected a signer error in result.errors, got: []''.
- Task 5 (python reader pristine): 'Failed: DID NOT RAISE <class 'capsule.reader.MalformedCapsuleError'>', 'assert True is False', 'assert True is False', 'KeyError: 'sha256''; with only reader.py patched: '4 passed, 6 deselected'.
- Task 6 (python chain pristine): 'ValueError: hex_to_bytes: non-hex characters' x2 and 'AttributeError: 'str' object has no attribute 'get'' x2; with chain.py patched and verifier.py pristine: '4 passed, 6 deselected'.
- Task 7 (python verifier pristine): 'AttributeError: 'list' object has no attribute 'get'' and 'assert False +where False = any(...)'; '2 failed, 8 deselected'.
- Task 8: with vectors.json present but no fixtures: 'FAIL: .../malformed-shape/vectors.json [manifest-not-object]: capsule_file unreadable: ENOENT ...' (x5). With fixtures but no OPEN_REASON entry: 'FAIL: .../malformed-shape/vectors.json [manifest-not-object]: unknown open-stage reason 'invalid_manifest_shape'' (x4).

One correction I made mid-validation and folded into the plan: the first draft of the Python wrapper carried '# noqa: BLE001', and 'ruff check' flagged 'RUF100 [*] Unused 'noqa' directive (non-enabled: 'BLE001')'. The code in Task 7 is the ruff-clean version.

I did NOT run cargo/Swift/Kotlin. I did verify by 'diff -rq' that this cluster changes nothing those lanes read: 'diff -r <repo>/spec /tmp/work-c6/spec' reports only 'Only in /tmp/work-c6/spec/vectors: malformed-shape', and 'diff -rq' over verifier-rust/crates and verifier-rust/tests reports no differences. verifier-rust/tests/spec_registry.rs hard-codes 'tamper-detection/vectors.json' and 'malformed-layout/vectors.json' (both byte-identical after this cluster), and grep shows no Swift or Kotlin test reads any registry other than 'tamper-detection/output/'.
```

</details>

---

## C6 — Make the JS and Python verifiers total functions

Both reference verifiers document a fail-closed contract (`sdk-js/src/verifier.js:26-29`, `sdk-js/src/index.d.ts:216-219`, `sdk-py/src/capsule/verifier.py:49-55`, both READMEs) and then break it on hand-edited capsules. This section closes every escape in both lanes, gives an invalid signature a displayable error, and pins the new behaviour with a language-neutral vector collection.

Task order matters: Tasks 1-4 are sdk-js in sequence (they share one new test file), Tasks 5-7 are sdk-py in sequence, Task 8 depends on Tasks 1-2 and 5-6 (its fixtures assert the new reader and chain behaviour).

---

### Task 1: sdk-js — validate content_index shape at the reader boundary

**Files:**
- Create: `sdk-js/test/totality.test.js`
- Modify: `sdk-js/src/reader.js:25-41`
- Test: `sdk-js/test/totality.test.js`

**Interfaces:**
- Consumes: `CapsuleReader.fromBytes(bytes: Uint8Array): Promise<CapsuleReader>`, `verifyCapsule(readerOrBytes, options): Promise<VerifyResult>`, `packZip(files: Map<string, Uint8Array>): Promise<Buffer>`, `unpackZip(bytes): Promise<Map<string, Uint8Array>>`, `new CapsuleBuilder({originator, participants, createdAt})`, `generateEd25519()`
- Produces: module-private `validateContentIndexShape(index)` in `reader.js`, called from `validateManifestShape`. Reader error strings later tasks and vectors depend on: `manifest.json is not a JSON object`, `manifest.content_index must be a JSON object`, `manifest.content_index.index_hash must be a 64-char lowercase hex string`, `manifest.content_index.files must be an array`, `manifest.content_index.files[<i>] must be a JSON object`, `manifest.content_index.files[<i>].path must be a non-empty string`, `manifest.content_index.files[<i>].sha256 must be a 64-char lowercase hex string`. Test helpers `sealedCapsule()`, `repack(bytes, mutate)`, `editManifest(files, mutate)`, `assertFailClosedShape(result)` reused by Tasks 2-4.

- [ ] **Step 1: Write the failing test**

Create `sdk-js/test/totality.test.js`:

```js
// Totality tests added 2026-08-01:
//   - CapsuleReader rejects a malformed manifest.content_index at parse time
//   - verifyChain reports non-canonical stored hex instead of throwing
//   - verifyCapsule converts any unexpected throw into the documented
//     fail-closed result
//   - an invalid envelope signature produces a displayable error

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CapsuleBuilder,
  CapsuleReader,
  verifyCapsule,
  generateEd25519,
} from "../src/index.js";
import { packZip, unpackZip } from "../src/zip.js";

const TS = "2026-05-07T12:00:00Z";

async function sealedCapsule() {
  const ed = generateEd25519();
  const builder = new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex, label: "Acme" },
    participants: [{ actor_id: "human:alice", role: "originator", label: "Alice" }],
    createdAt: TS,
  });
  builder.setProgram("# Program\n");
  builder.appendEvent({
    actor: "human:alice",
    kind: "decision",
    action: "approved",
    target: "program.md",
    timestamp: TS,
    payload: {},
  });
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  return { bytes, ed };
}

async function repack(bytes, mutate) {
  const files = await unpackZip(bytes);
  mutate(files);
  return await packZip(files);
}

function editManifest(files, mutate) {
  const mf = JSON.parse(Buffer.from(files.get("manifest.json")).toString("utf8"));
  mutate(mf);
  files.set("manifest.json", Buffer.from(JSON.stringify(mf, null, 2) + "\n", "utf8"));
}

/** Every channel the VerifyResult contract promises is present and fail-closed. */
function assertFailClosedShape(result) {
  assert.equal(result.ok, false);
  assert.ok(Array.isArray(result.errors) && result.errors.length > 0);
  assert.equal(result.chain.ok, false);
  assert.ok(Array.isArray(result.chain.errors));
  assert.equal(result.contentIndex.ok, false);
  assert.ok(Array.isArray(result.contentIndex.errors));
  assert.equal(result.envelope.ok, false);
  assert.deepEqual(result.envelope.signers, []);
  assert.equal(result.trustedSignerCount, 0);
  assert.ok(Array.isArray(result.notes));
}

test("verifyCapsule fails closed when manifest.content_index is missing", async () => {
  const { bytes, ed } = await sealedCapsule();
  const tampered = await repack(bytes, (files) =>
    editManifest(files, (mf) => {
      delete mf.content_index;
    }),
  );
  const result = await verifyCapsule(tampered, { allowlist: [ed.publicKeyHex] });
  assertFailClosedShape(result);
  assert.match(result.errors[0], /manifest\.content_index must be a JSON object/);
});

test("verifyCapsule fails closed when content_index.files is not an array", async () => {
  const { bytes, ed } = await sealedCapsule();
  const tampered = await repack(bytes, (files) =>
    editManifest(files, (mf) => {
      mf.content_index.files = {};
    }),
  );
  const result = await verifyCapsule(tampered, { allowlist: [ed.publicKeyHex] });
  assertFailClosedShape(result);
  assert.match(result.errors[0], /manifest\.content_index\.files must be an array/);
});

test("verifyCapsule fails closed when a content_index entry has no sha256", async () => {
  const { bytes, ed } = await sealedCapsule();
  const tampered = await repack(bytes, (files) =>
    editManifest(files, (mf) => {
      mf.content_index.files = mf.content_index.files.map(({ path }) => ({ path }));
    }),
  );
  const result = await verifyCapsule(tampered, { allowlist: [ed.publicKeyHex] });
  assertFailClosedShape(result);
  assert.match(result.errors[0], /manifest\.content_index\.files\[0\]\.sha256/);
});

test("CapsuleReader rejects a manifest that is not a JSON object", async () => {
  const { bytes } = await sealedCapsule();
  const tampered = await repack(bytes, (files) => {
    files.set("manifest.json", Buffer.from("[]", "utf8"));
  });
  await assert.rejects(
    () => CapsuleReader.fromBytes(tampered),
    /manifest\.json is not a JSON object/,
  );
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-js && node --test --test-name-pattern="content_index|not a JSON object" test/totality.test.js`

Expected: FAIL — `# tests 4 / # pass 0 / # fail 4`, with
- test 1 `error: "Cannot read properties of undefined (reading 'index_hash')"`, `code: 'ERR_TEST_FAILURE'`
- test 2 `error: 'manifest.content_index.files.map is not a function'`, `code: 'ERR_TEST_FAILURE'`
- test 3 `AssertionError: Expected values to be strictly equal: true !== false` (chain.ok is still true)
- test 4 `AssertionError: The input did not match the regular expression /manifest\.json is not a JSON object/. Input: "manifest.format.version: expected '0.6', got undefined"`

- [ ] **Step 3: Reject a non-object manifest before the field checks**

In `sdk-js/src/reader.js:26`, replace:

```js
  if (manifest == null || typeof manifest !== "object") {
    throw new Error("manifest.json is not a JSON object");
  }
```

with:

```js
  if (manifest == null || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new Error("manifest.json is not a JSON object");
  }
```

- [ ] **Step 4: Validate content_index from validateManifestShape**

In `sdk-js/src/reader.js:38-43`, replace:

```js
  if (!HEX64.test(manifest.first_event_hash ?? "")) {
    throw new Error("manifest.first_event_hash must be a 64-char lowercase hex string");
  }
}

function validateEnvelopeShape(envelope) {
```

with:

```js
  if (!HEX64.test(manifest.first_event_hash ?? "")) {
    throw new Error("manifest.first_event_hash must be a 64-char lowercase hex string");
  }
  validateContentIndexShape(manifest.content_index);
}

/**
 * verifyCapsule reads content_index.index_hash and iterates
 * content_index.files unconditionally. Checking the shape at the parse
 * boundary is what keeps verification a total function over whatever the
 * reader hands back, instead of a TypeError on a hand-edited manifest.
 */
function validateContentIndexShape(index) {
  if (index == null || typeof index !== "object" || Array.isArray(index)) {
    throw new Error("manifest.content_index must be a JSON object");
  }
  if (!HEX64.test(index.index_hash ?? "")) {
    throw new Error("manifest.content_index.index_hash must be a 64-char lowercase hex string");
  }
  if (!Array.isArray(index.files)) {
    throw new Error("manifest.content_index.files must be an array");
  }
  index.files.forEach((f, i) => {
    if (f == null || typeof f !== "object" || Array.isArray(f)) {
      throw new Error(`manifest.content_index.files[${i}] must be a JSON object`);
    }
    if (typeof f.path !== "string" || f.path.length === 0) {
      throw new Error(`manifest.content_index.files[${i}].path must be a non-empty string`);
    }
    if (!HEX64.test(f.sha256 ?? "")) {
      throw new Error(
        `manifest.content_index.files[${i}].sha256 must be a 64-char lowercase hex string`,
      );
    }
  });
}

function validateEnvelopeShape(envelope) {
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd sdk-js && node --test --test-name-pattern="content_index|not a JSON object" test/totality.test.js`

Expected: PASS — `# tests 4 / # pass 4 / # fail 0`

- [ ] **Step 6: Run the full lane suite for regressions**

Run: `cd sdk-js && npm test`

Expected: `# tests 61 / # pass 61 / # fail 0` (57 pre-existing + 4 new)

- [ ] **Step 7: Commit**
```bash
git add sdk-js/src/reader.js sdk-js/test/totality.test.js
git commit -m "fix(sdk-js): validate manifest.content_index shape at the reader boundary"
```

---

### Task 2: sdk-js — verifyChain reports non-canonical hex instead of throwing

**Files:**
- Modify: `sdk-js/src/chain.js:5` (insert after), `sdk-js/src/chain.js:76-95`, `sdk-js/src/chain.js:116-122`
- Test: `sdk-js/test/totality.test.js`

**Interfaces:**
- Consumes: `verifyChain(events): { ok, errors: [{seq, message}] }`, plus `sealedCapsule()` / `repack()` / helpers from Task 1
- Produces: new chain error messages `event is not a JSON object`, `prev_hash is not canonical lowercase hex`, `hash is not canonical lowercase hex`; `firstAndEntryHash(events)` now returns `{firstEventHash: string|undefined, entryHash: string|undefined}` instead of throwing on a non-object event

- [ ] **Step 1: Write the failing test**

Add the `verifyChain` import and append three tests to `sdk-js/test/totality.test.js`. Change the import block from:

```js
import { packZip, unpackZip } from "../src/zip.js";
```

to:

```js
import { verifyChain } from "../src/chain.js";
import { packZip, unpackZip } from "../src/zip.js";
```

and append at the end of the file:

```js
test("verifyChain reports a non-canonical stored hash instead of throwing", () => {
  const result = verifyChain([
    { seq: 1, prev_hash: "0".repeat(64), hash: "A".repeat(64) },
  ]);
  assert.equal(result.ok, false);
  assert.ok(
    result.errors.some((e) => /hash is not canonical lowercase hex/.test(e.message)),
    `expected a canonical-hex error, got: ${JSON.stringify(result.errors)}`,
  );
});

test("verifyChain reports a non-object event instead of throwing", () => {
  const result = verifyChain([null]);
  assert.equal(result.ok, false);
  assert.deepEqual(result.errors, [{ seq: 1, message: "event is not a JSON object" }]);
});

test("verifyCapsule fails closed on an uppercase stored event hash", async () => {
  const { bytes, ed } = await sealedCapsule();
  const tampered = await repack(bytes, (files) => {
    const lines = Buffer.from(files.get("chain/events.jsonl"))
      .toString("utf8")
      .split("\n")
      .filter((l) => l.length > 0);
    const first = JSON.parse(lines[0]);
    first.hash = first.hash.toUpperCase();
    files.set(
      "chain/events.jsonl",
      Buffer.from([JSON.stringify(first), ...lines.slice(1)].join("\n") + "\n", "utf8"),
    );
  });
  const result = await verifyCapsule(tampered, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, false);
  assert.equal(result.chain.ok, false);
  assert.ok(
    result.chain.errors.some((e) => /hash is not canonical lowercase hex/.test(e.message)),
    `expected a canonical-hex chain error, got: ${JSON.stringify(result.chain.errors)}`,
  );
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-js && node --test --test-name-pattern="verifyChain|uppercase stored" test/totality.test.js`

Expected: FAIL — `# tests 3 / # pass 0 / # fail 3`, with
- `verifyChain reports a non-canonical stored hash instead of throwing` → `error: 'hexToBytes: uppercase hex is non-canonical; use lowercase'`, `code: 'ERR_TEST_FAILURE'`
- `verifyChain reports a non-object event instead of throwing` → `error: "Cannot read properties of null (reading 'seq')"`, `code: 'ERR_TEST_FAILURE'`
- `verifyCapsule fails closed on an uppercase stored event hash` → `error: 'hexToBytes: uppercase hex is non-canonical; use lowercase'`, `code: 'ERR_TEST_FAILURE'`

- [ ] **Step 3: Add the canonical-hex pattern**

In `sdk-js/src/chain.js:5`, replace:

```js
const GENESIS_PREV = Buffer.alloc(32, 0);
```

with:

```js
const GENESIS_PREV = Buffer.alloc(32, 0);

// Chain-bound hex is lowercase per spec/chain.md. verifyChain feeds a
// stored hash straight into hexToBytes to seed the next link, so the
// canonical-form check has to happen before that call, not inside it.
const HEX64 = /^[0-9a-f]{64}$/;
```

- [ ] **Step 4: Guard the event object and prev_hash**

In `sdk-js/src/chain.js:76-85`, replace:

```js
  events.forEach((e, i) => {
    const seq = e.seq ?? i + 1;
    if (e.seq !== i + 1) {
      errors.push({ seq, message: `seq ${e.seq} expected ${i + 1}` });
    }
    if (typeof e.prev_hash !== "string" || e.prev_hash.length !== 64) {
      errors.push({ seq, message: "prev_hash missing or wrong length" });
      return;
    }
    const expectedPrev = bytesToHex(prev);
```

with:

```js
  events.forEach((e, i) => {
    if (e == null || typeof e !== "object" || Array.isArray(e)) {
      errors.push({ seq: i + 1, message: "event is not a JSON object" });
      return;
    }
    const seq = e.seq ?? i + 1;
    if (e.seq !== i + 1) {
      errors.push({ seq, message: `seq ${e.seq} expected ${i + 1}` });
    }
    if (typeof e.prev_hash !== "string" || e.prev_hash.length !== 64) {
      errors.push({ seq, message: "prev_hash missing or wrong length" });
      return;
    }
    if (!HEX64.test(e.prev_hash)) {
      errors.push({ seq, message: "prev_hash is not canonical lowercase hex" });
      return;
    }
    const expectedPrev = bytesToHex(prev);
```

The existing `prev_hash missing or wrong length` string is kept verbatim — `verifier-rust/crates/capsule-verify/src/chain.rs:89` emits the same text and cross-lane message parity is intentional.

- [ ] **Step 5: Guard the stored hash before it reaches hexToBytes**

In `sdk-js/src/chain.js:92-96` (now shifted by Step 3 and Step 4), replace:

```js
    if (typeof e.hash !== "string" || e.hash.length !== 64) {
      errors.push({ seq, message: "hash missing or wrong length" });
      return;
    }
    const { hash, ...rest } = e;
```

with:

```js
    if (typeof e.hash !== "string" || e.hash.length !== 64) {
      errors.push({ seq, message: "hash missing or wrong length" });
      return;
    }
    if (!HEX64.test(e.hash)) {
      errors.push({ seq, message: "hash is not canonical lowercase hex" });
      return;
    }
    const { hash, ...rest } = e;
```

- [ ] **Step 6: Make firstAndEntryHash total**

In `sdk-js/src/chain.js:116-122`, replace:

```js
export function firstAndEntryHash(events) {
  if (events.length === 0) throw new Error("chain is empty");
  return {
    firstEventHash: events[0].hash,
    entryHash: events[events.length - 1].hash,
  };
}
```

with:

```js
export function firstAndEntryHash(events) {
  if (events.length === 0) throw new Error("chain is empty");
  const hashOf = (e) => (e != null && typeof e === "object" ? e.hash : undefined);
  return {
    firstEventHash: hashOf(events[0]),
    entryHash: hashOf(events[events.length - 1]),
  };
}
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `cd sdk-js && node --test --test-name-pattern="verifyChain|uppercase stored" test/totality.test.js`

Expected: PASS — `# tests 3 / # pass 3 / # fail 0`

- [ ] **Step 8: Run the full lane suite for regressions**

Run: `cd sdk-js && npm test`

Expected: `# tests 64 / # pass 64 / # fail 0`

- [ ] **Step 9: Commit**
```bash
git add sdk-js/src/chain.js sdk-js/test/totality.test.js
git commit -m "fix(sdk-js): report non-canonical chain hex instead of throwing out of verifyChain"
```

---

### Task 3: sdk-js — verifyCapsule never throws

**Files:**
- Modify: `sdk-js/src/verifier.js:20-21` (insert after), `sdk-js/src/verifier.js:25-29`, `sdk-js/src/verifier.js:48-67`, `sdk-js/src/index.d.ts:215-219`, `sdk-js/README.md:82-83`
- Test: `sdk-js/test/totality.test.js`

**Interfaces:**
- Consumes: `CapsuleReader.fromBytes`, `reader.manifest()`; helpers from Task 1
- Produces: module-private `failClosed(message, level): VerifyResult` and `verifyCapsuleInner(readerOrBytes, options)`; the public `verifyCapsule` signature is unchanged. New error prefix `verification failed: ` on any unanticipated throw.

- [ ] **Step 1: Write the failing test**

Append to `sdk-js/test/totality.test.js`:

```js
test("verifyCapsule converts an unexpected throw into the fail-closed shape", async () => {
  const { bytes, ed } = await sealedCapsule();
  const reader = await CapsuleReader.fromBytes(bytes);
  // Mutate AFTER the reader's parse-time validation: only the total-function
  // wrapper stands between this and a TypeError escaping verifyCapsule.
  delete reader.manifest().content_index;
  const result = await verifyCapsule(reader, { allowlist: [ed.publicKeyHex] });
  assertFailClosedShape(result);
  assert.match(result.errors[0], /^verification failed:/);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-js && node --test --test-name-pattern="unexpected throw" test/totality.test.js`

Expected: FAIL — `# tests 1 / # pass 0 / # fail 1`, `error: "Cannot read properties of undefined (reading 'index_hash')"`, `code: 'ERR_TEST_FAILURE'`

- [ ] **Step 3: Add the failClosed helper**

In `sdk-js/src/verifier.js:20-22`, replace:

```js
import { toKeyHex } from "./keys.js";

/**
 * verifyCapsule(readerOrBytes, options)
```

with:

```js
import { toKeyHex } from "./keys.js";

/** The documented fail-closed result: every channel present, nothing trusted. */
function failClosed(message, level) {
  return {
    ok: false,
    level,
    errors: [message],
    chain: { ok: false, errors: [] },
    contentIndex: { ok: false, errors: [] },
    envelope: { ok: false, signers: [] },
    trustedSignerCount: 0,
    notes: [],
  };
}

/**
 * verifyCapsule(readerOrBytes, options)
```

- [ ] **Step 4: State the totality contract in the docblock**

In `sdk-js/src/verifier.js:25-30` (shifted by Step 3), replace:

```js
 * Accepts a CapsuleReader or the raw .capsule bytes. When given bytes,
 * a container that cannot even be opened (malformed ZIP, missing or
 * invalid manifest/envelope) returns a fail-closed result — app code
 * needs no separate try/catch around opening.
 *
 * options:
```

with:

```js
 * Accepts a CapsuleReader or the raw .capsule bytes. When given bytes,
 * a container that cannot even be opened (malformed ZIP, missing or
 * invalid manifest/envelope) returns a fail-closed result — app code
 * needs no separate try/catch around opening.
 *
 * This function is total: it never throws, for any input. A capsule that
 * cannot be fully evaluated comes back as a fail-closed result with the
 * underlying message in `errors`.
 *
 * options:
```

- [ ] **Step 5: Wrap the body**

In `sdk-js/src/verifier.js:48-67` (shifted by Steps 3-4), replace:

```js
export async function verifyCapsule(readerOrBytes, options = {}) {
  let reader = readerOrBytes;
  if (reader instanceof Uint8Array || reader instanceof ArrayBuffer) {
    try {
      reader = await CapsuleReader.fromBytes(
        reader instanceof ArrayBuffer ? new Uint8Array(reader) : reader,
      );
    } catch (err) {
      return {
        ok: false,
        level: "L2",
        errors: [`capsule cannot be opened: ${err.message}`],
        chain: { ok: false, errors: [] },
        contentIndex: { ok: false, errors: [] },
        envelope: { ok: false, signers: [] },
        trustedSignerCount: 0,
        notes: [],
      };
    }
  }
```

with:

```js
export async function verifyCapsule(readerOrBytes, options = {}) {
  const level = options?.outerEnvelope ? "L3" : "L2";
  try {
    return await verifyCapsuleInner(readerOrBytes, options);
  } catch (err) {
    // The contract above promises callers a result, not an exception, for
    // every input. Anything that escapes the checks below is a capsule we
    // could not fully evaluate, which is a verification failure.
    return failClosed(`verification failed: ${err?.message ?? String(err)}`, level);
  }
}

async function verifyCapsuleInner(readerOrBytes, options = {}) {
  let reader = readerOrBytes;
  if (reader instanceof Uint8Array || reader instanceof ArrayBuffer) {
    try {
      reader = await CapsuleReader.fromBytes(
        reader instanceof ArrayBuffer ? new Uint8Array(reader) : reader,
      );
    } catch (err) {
      return failClosed(`capsule cannot be opened: ${err.message}`, "L2");
    }
  }
```

- [ ] **Step 6: Update the public type declaration**

In `sdk-js/src/index.d.ts:215-219`, replace:

```ts
/**
 * Verify a capsule. Accepts a CapsuleReader or the raw .capsule bytes;
 * given bytes, an unopenable container returns a fail-closed result
 * instead of throwing.
 */
```

with:

```ts
/**
 * Verify a capsule. Accepts a CapsuleReader or the raw .capsule bytes.
 * Total: never throws, for any input. An unopenable container, a
 * malformed manifest, and a malformed chain all come back as a
 * fail-closed result with the reason in `errors`.
 */
```

- [ ] **Step 7: Update the README claim**

In `sdk-js/README.md:82-83`, replace:

```markdown
`"originator"`, and `verifyCapsule(bytes)` on unopenable input returns a
fail-closed result (`ok: false`) instead of throwing.
```

with:

```markdown
`"originator"`, and `verifyCapsule()` never throws: unopenable input, a
malformed manifest, and a malformed chain all come back as a fail-closed
result (`ok: false`) with the reason in `errors`.
```

- [ ] **Step 8: Run the test to verify it passes**

Run: `cd sdk-js && node --test --test-name-pattern="unexpected throw" test/totality.test.js`

Expected: PASS — `# tests 1 / # pass 1 / # fail 0`

- [ ] **Step 9: Run the full lane suite for regressions**

Run: `cd sdk-js && npm test`

Expected: `# tests 65 / # pass 65 / # fail 0`

- [ ] **Step 10: Commit**
```bash
git add sdk-js/src/verifier.js sdk-js/src/index.d.ts sdk-js/README.md sdk-js/test/totality.test.js
git commit -m "fix(sdk-js): make verifyCapsule a total function, never throwing to callers"
```

---

### Task 4: sdk-js — an invalid signature gets a displayable error

**Files:**
- Modify: `sdk-js/src/verifier.js:224-228` (pre-plan numbering; after Task 3 this block sits at `:244-248`)
- Test: `sdk-js/test/totality.test.js`

**Interfaces:**
- Consumes: `verifyEnvelopeSignatures(envelope): { ok, signers: [{role, public_key, valid}], note? }`
- Produces: error string `envelope.signers[<i>] signature invalid (role '<role>', public_key <hex>)` in `result.errors`

- [ ] **Step 1: Write the failing test**

Append to `sdk-js/test/totality.test.js`:

```js
test("an invalid envelope signature produces a displayable error", async () => {
  const { bytes, ed } = await sealedCapsule();
  const tampered = await repack(bytes, (files) => {
    const env = JSON.parse(Buffer.from(files.get("provenance/envelope.json")).toString("utf8"));
    const sig = env.signers[0].signature;
    env.signers[0].signature = (sig[0] === "0" ? "1" : "0") + sig.slice(1);
    files.set(
      "provenance/envelope.json",
      Buffer.from(JSON.stringify(env, null, 2) + "\n", "utf8"),
    );
  });
  const result = await verifyCapsule(tampered, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, false);
  assert.equal(result.envelope.ok, false);
  assert.equal(result.envelope.signers[0].valid, false);
  assert.ok(
    result.errors.some((e) => /envelope\.signers\[0\] signature invalid/.test(e)),
    `expected a signer error in result.errors, got: ${JSON.stringify(result.errors)}`,
  );
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-js && node --test --test-name-pattern="displayable error" test/totality.test.js`

Expected: FAIL — `# tests 1 / # pass 0 / # fail 1`, `error: 'expected a signer error in result.errors, got: []'`, `code: 'ERR_ASSERTION'`

- [ ] **Step 3: Emit a per-signer error**

In `sdk-js/src/verifier.js`, replace (this is `:224-228` in the current repo, `:244-248` after Task 3):

```js
  result.envelope.signers = envelopeResult.signers.map((s) => ({
    ...s,
    trusted: s.valid && allowlist.has(s.public_key.toLowerCase()),
  }));
  result.trustedSignerCount = result.envelope.signers.filter((s) => s.trusted).length;
```

with:

```js
  result.envelope.signers = envelopeResult.signers.map((s) => ({
    ...s,
    trusted: s.valid && allowlist.has(String(s.public_key ?? "").toLowerCase()),
  }));
  // A bad signature is otherwise only visible as valid:false nested in
  // envelope.signers[i]; every other failure class produces a displayable
  // message, so give this one an error too.
  result.envelope.signers.forEach((s, i) => {
    if (!s.valid) {
      errors.push(
        `envelope.signers[${i}] signature invalid (role '${s.role}', public_key ${s.public_key})`,
      );
    }
  });
  result.trustedSignerCount = result.envelope.signers.filter((s) => s.trusted).length;
```

The `String(s.public_key ?? "")` change also removes a second throw path: a signer entry whose `public_key` is absent previously produced `TypeError: Cannot read properties of undefined (reading 'toLowerCase')`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd sdk-js && node --test --test-name-pattern="displayable error" test/totality.test.js`

Expected: PASS — `# tests 1 / # pass 1 / # fail 0`

- [ ] **Step 5: Run the full lane suite for regressions**

Run: `cd sdk-js && npm test`

Expected: `# tests 66 / # pass 66 / # fail 0`

- [ ] **Step 6: Run the JS conformance harness**

Run: `node tools/run-conformance.mjs`

Expected: `PASS · 10/10 passed` — in particular `spec-vectors ... PASS` (the `tampered-envelope` vector expects `failing: ["envelope"]` and carries no `error_includes`, so the new error is additive)

- [ ] **Step 7: Commit**
```bash
git add sdk-js/src/verifier.js sdk-js/test/totality.test.js
git commit -m "fix(sdk-js): surface an invalid envelope signature as a displayable error"
```

---

### Task 5: sdk-py — port manifest/envelope shape validation into CapsuleReader

**Files:**
- Create: `sdk-py/tests/test_totality.py`
- Modify: `sdk-py/src/capsule/reader.py:5`, `sdk-py/src/capsule/reader.py:16-19`, `sdk-py/src/capsule/reader.py:35-37`, `sdk-py/src/capsule/reader.py:156-158`, `sdk-py/tests/test_reader.py:83-87`
- Test: `sdk-py/tests/test_totality.py`

**Interfaces:**
- Consumes: `CapsuleReader.from_bytes(data: bytes) -> CapsuleReader`, `MalformedCapsuleError(ValueError)`, `verify_capsule(reader, *, allowlist=None, outer_envelope=None) -> VerifyResult`, `CapsuleBuilder(originator=..., participants=...)`, `generate_ed25519()`
- Produces: module-private `_HEX64`, `_is_hex64(value) -> bool`, `_validate_manifest_shape(manifest) -> None`, `_validate_content_index_shape(index) -> None`, `_validate_envelope_shape(envelope) -> None` in `capsule.reader`; the same error strings as sdk-js reader.js, all raised as `MalformedCapsuleError`. Test helpers `_sealed()`, `_repack(zip_bytes, mutate)`, `_edit_manifest(mutate)`, `_assert_fail_closed_shape(result)` reused by Tasks 6-7.

- [ ] **Step 1: Write the failing test**

Create `sdk-py/tests/test_totality.py`:

```python
"""verify_capsule is a total function; CapsuleReader shape-checks its input.

Mirrors sdk-js/test/totality.test.js:
  - CapsuleReader.from_bytes rejects a malformed manifest at parse time
  - verify_chain reports non-canonical hex / non-object events instead of raising
  - verify_capsule converts any unexpected exception into the fail-closed result
  - an invalid envelope signature produces a displayable error
"""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from capsule.builder import CapsuleBuilder
from capsule.crypto import generate_ed25519
from capsule.reader import CapsuleReader, MalformedCapsuleError
from capsule.verifier import verify_capsule

TS = "2026-05-07T12:00:00Z"


def _sealed():
    kp = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": "Acme"},
        participants=[],
    )
    builder.set_program("# Program\n")
    builder.append_event(
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "approved",
            "target": "program.md",
            "timestamp": TS,
            "payload": {},
        }
    )
    return builder.seal(
        signers=[
            {"role": "originator", "public_key": kp.public_key, "private_key": kp.private_key}
        ],
        signed_at=TS,
    ), kp


def _repack(zip_bytes: bytes, mutate) -> bytes:
    """Rewrite every entry through `mutate(name, data) -> data`."""
    buf = io.BytesIO()
    with (
        zipfile.ZipFile(io.BytesIO(zip_bytes)) as src,
        zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as dst,
    ):
        for zi in src.infolist():
            data = mutate(zi.filename, src.read(zi))
            new_zi = zipfile.ZipInfo(zi.filename, date_time=(1980, 1, 1, 0, 0, 0))
            new_zi.compress_type = zipfile.ZIP_STORED
            dst.writestr(new_zi, data)
    return buf.getvalue()


def _edit_manifest(mutate):
    def _fn(name: str, data: bytes) -> bytes:
        if name != "manifest.json":
            return data
        m = json.loads(data.decode("utf-8"))
        mutate(m)
        return json.dumps(m, indent=2).encode("utf-8")

    return _fn


def _assert_fail_closed_shape(result: dict) -> None:
    assert result["ok"] is False
    assert isinstance(result["errors"], list) and result["errors"]
    assert result["chain"]["ok"] is False
    assert isinstance(result["chain"]["errors"], list)
    assert result["content_index"]["ok"] is False
    assert isinstance(result["content_index"]["errors"], list)
    assert result["envelope"]["ok"] is False
    assert result["envelope"]["signers"] == []
    assert result["trusted_signer_count"] == 0
    assert isinstance(result["notes"], list)


def test_manifest_not_an_object_is_refused_at_open():
    zip_bytes, _ = _sealed()
    tampered = _repack(zip_bytes, lambda n, d: b"[]" if n == "manifest.json" else d)
    with pytest.raises(MalformedCapsuleError, match=r"manifest\.json is not a JSON object"):
        CapsuleReader.from_bytes(tampered)


def test_missing_content_index_fails_closed():
    zip_bytes, kp = _sealed()
    tampered = _repack(zip_bytes, _edit_manifest(lambda m: m.pop("content_index")))
    result = verify_capsule(tampered, allowlist=[kp.public_key_hex])
    _assert_fail_closed_shape(result)
    assert "manifest.content_index must be a JSON object" in result["errors"][0]


def test_content_index_files_not_a_list_fails_closed():
    zip_bytes, kp = _sealed()
    tampered = _repack(
        zip_bytes, _edit_manifest(lambda m: m["content_index"].__setitem__("files", {}))
    )
    result = verify_capsule(tampered, allowlist=[kp.public_key_hex])
    _assert_fail_closed_shape(result)
    assert "manifest.content_index.files must be an array" in result["errors"][0]


def test_content_index_entry_without_sha256_fails_closed():
    zip_bytes, kp = _sealed()

    def _strip(m):
        m["content_index"]["files"] = [{"path": f["path"]} for f in m["content_index"]["files"]]

    tampered = _repack(zip_bytes, _edit_manifest(_strip))
    result = verify_capsule(tampered, allowlist=[kp.public_key_hex])
    _assert_fail_closed_shape(result)
    assert "manifest.content_index.files[0].sha256" in result["errors"][0]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-py && PYTHONPATH=src python3 -m pytest tests/test_totality.py`

Expected: FAIL — `4 failed`, with
- `test_manifest_not_an_object_is_refused_at_open` → `Failed: DID NOT RAISE <class 'capsule.reader.MalformedCapsuleError'>`
- `test_missing_content_index_fails_closed` → `assert True is False` (on `result["chain"]["ok"] is False`)
- `test_content_index_files_not_a_list_fails_closed` → `assert True is False`
- `test_content_index_entry_without_sha256_fails_closed` → `KeyError: 'sha256'` raised out of `verifier.py:146`

- [ ] **Step 3: Import re**

In `sdk-py/src/capsule/reader.py:5`, replace:

```python
import json
```

with:

```python
import json
import re
```

- [ ] **Step 4: Add the shape validators**

In `sdk-py/src/capsule/reader.py:15-19`, replace:

```python
class MalformedCapsuleError(ValueError):
    pass


class CapsuleReader:
```

with:

```python
class MalformedCapsuleError(ValueError):
    pass


_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _is_hex64(value) -> bool:
    return isinstance(value, str) and _HEX64.match(value) is not None


def _validate_manifest_shape(manifest) -> None:
    """Shape check on manifest.json. Mirrors sdk-js reader.js.

    Full integrity is the verifier's job; this catches obvious
    malformation at the parse boundary so a caller that reads
    ``reader.manifest()["id"]`` without verifying can rely on the field
    being 64-char lowercase hex per spec, and so ``verify_capsule``
    stays a total function over whatever the reader hands back.
    """
    if not isinstance(manifest, dict):
        raise MalformedCapsuleError("manifest.json is not a JSON object")
    fmt = manifest.get("format")
    version = fmt.get("version") if isinstance(fmt, dict) else None
    if version != "0.6":
        raise MalformedCapsuleError(f"manifest.format.version: expected '0.6', got {version!r}")
    if not _is_hex64(manifest.get("id")):
        raise MalformedCapsuleError(
            f"manifest.id is not a 64-char lowercase hex string: {manifest.get('id')!r}"
        )
    originator = manifest.get("originator")
    if not isinstance(originator, dict) or not _is_hex64(originator.get("public_key")):
        raise MalformedCapsuleError(
            "manifest.originator.public_key must be a 64-char lowercase hex string"
        )
    if not _is_hex64(manifest.get("first_event_hash")):
        raise MalformedCapsuleError(
            "manifest.first_event_hash must be a 64-char lowercase hex string"
        )
    _validate_content_index_shape(manifest.get("content_index"))


def _validate_content_index_shape(index) -> None:
    if not isinstance(index, dict):
        raise MalformedCapsuleError("manifest.content_index must be a JSON object")
    if not _is_hex64(index.get("index_hash")):
        raise MalformedCapsuleError(
            "manifest.content_index.index_hash must be a 64-char lowercase hex string"
        )
    files = index.get("files")
    if not isinstance(files, list):
        raise MalformedCapsuleError("manifest.content_index.files must be an array")
    for i, f in enumerate(files):
        if not isinstance(f, dict):
            raise MalformedCapsuleError(f"manifest.content_index.files[{i}] must be a JSON object")
        path = f.get("path")
        if not isinstance(path, str) or not path:
            raise MalformedCapsuleError(
                f"manifest.content_index.files[{i}].path must be a non-empty string"
            )
        if not _is_hex64(f.get("sha256")):
            raise MalformedCapsuleError(
                f"manifest.content_index.files[{i}].sha256 must be a 64-char lowercase hex string"
            )


def _validate_envelope_shape(envelope) -> None:
    """Shape check on provenance/envelope.json. Mirrors sdk-js reader.js."""
    if not isinstance(envelope, dict):
        raise MalformedCapsuleError("envelope.json is not a JSON object")
    if envelope.get("version") != "0.6":
        raise MalformedCapsuleError(
            f"envelope.version: expected '0.6', got {envelope.get('version')!r}"
        )
    if not _is_hex64(envelope.get("capsule_id")):
        raise MalformedCapsuleError("envelope.capsule_id must be a 64-char lowercase hex string")
    signers = envelope.get("signers")
    if not isinstance(signers, list) or not signers:
        raise MalformedCapsuleError("envelope.signers must be a non-empty array")


class CapsuleReader:
```

- [ ] **Step 5: Call the validators from from_bytes and from decrypt**

In `sdk-py/src/capsule/reader.py:35-37` (shifted by Steps 3-4), replace:

```python
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise MalformedCapsuleError(f"manifest/envelope parse: {e}") from e
        return cls(files, manifest, envelope)
```

with:

```python
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise MalformedCapsuleError(f"manifest/envelope parse: {e}") from e
        _validate_manifest_shape(manifest)
        _validate_envelope_shape(envelope)
        return cls(files, manifest, envelope)
```

and in `sdk-py/src/capsule/reader.py:156-158`, replace:

```python
        inner_manifest = json.loads(inner_files["manifest.json"].decode("utf-8"))
        inner_envelope = json.loads(inner_files["provenance/envelope.json"].decode("utf-8"))
        return CapsuleReader(inner_files, inner_manifest, inner_envelope)
```

with:

```python
        try:
            inner_manifest = json.loads(inner_files["manifest.json"].decode("utf-8"))
            inner_envelope = json.loads(inner_files["provenance/envelope.json"].decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise MalformedCapsuleError(f"decrypted manifest/envelope parse: {e}") from e
        _validate_manifest_shape(inner_manifest)
        _validate_envelope_shape(inner_envelope)
        return CapsuleReader(inner_files, inner_manifest, inner_envelope)
```

- [ ] **Step 6: Repair the one existing fixture the new validation refuses**

`sdk-py/tests/test_reader.py::test_is_encrypted_when_manifest_has_encryption` hand-builds a stub capsule that the ported validator now rejects with `MalformedCapsuleError: manifest.id is not a 64-char lowercase hex string: None`. Give it a shape-valid manifest and envelope — the test is about `is_encrypted()`, not about shape.

In `sdk-py/tests/test_reader.py:83-87`, replace:

```python
    manifest = {
        "format": {"version": "0.6"},
        "encryption": {"metadata_path": "x", "cipher": "ChaCha20-Poly1305"},
    }
    envelope = {"version": "0.6", "cipher": "ChaCha20-Poly1305", "signers": []}
```

with:

```python
    manifest = {
        "format": {"version": "0.6"},
        "id": "11" * 32,
        "originator": {"public_key": "22" * 32, "label": "Acme"},
        "first_event_hash": "33" * 32,
        "content_index": {"files": [], "index_hash": "44" * 32},
        "encryption": {"metadata_path": "x", "cipher": "ChaCha20-Poly1305"},
    }
    envelope = {
        "version": "0.6",
        "capsule_id": "11" * 32,
        "cipher": "ChaCha20-Poly1305",
        "signers": [{"role": "originator", "public_key": "22" * 32, "signature": "55" * 64}],
    }
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `cd sdk-py && PYTHONPATH=src python3 -m pytest tests/test_totality.py`

Expected: PASS — `4 passed`

- [ ] **Step 8: Run the full lane suite for regressions**

Run: `cd sdk-py && PYTHONPATH=src python3 -m pytest`

Expected: `186 passed` (182 pre-existing + 4 new)

- [ ] **Step 9: Lint**

Run: `cd sdk-py && ruff check src tests`

Expected: `All checks passed!`

- [ ] **Step 10: Commit**
```bash
git add sdk-py/src/capsule/reader.py sdk-py/tests/test_reader.py sdk-py/tests/test_totality.py
git commit -m "fix(sdk-py): shape-check manifest and envelope in CapsuleReader.from_bytes"
```

---

### Task 6: sdk-py — verify_chain tolerates non-dict events and non-canonical hex

**Files:**
- Modify: `sdk-py/src/capsule/chain.py:5`, `sdk-py/src/capsule/chain.py:10-13`, `sdk-py/src/capsule/chain.py:92-98`, `sdk-py/src/capsule/chain.py:107-110`, `sdk-py/src/capsule/chain.py:127-131`
- Test: `sdk-py/tests/test_totality.py`

**Interfaces:**
- Consumes: `verify_chain(events) -> ChainResult`; helpers from Task 5
- Produces: chain error messages `event is not a JSON object`, `prev_hash is not canonical lowercase hex`, `hash is not canonical lowercase hex` (byte-identical to the sdk-js strings from Task 2); `first_and_entry_hash(events) -> tuple[str | None, str | None]`

- [ ] **Step 1: Write the failing test**

Add the `verify_chain` import and append four tests to `sdk-py/tests/test_totality.py`. Change:

```python
from capsule.builder import CapsuleBuilder
from capsule.crypto import generate_ed25519
```

to:

```python
from capsule.builder import CapsuleBuilder
from capsule.chain import verify_chain
from capsule.crypto import generate_ed25519
```

and append at the end of the file:

```python
def test_verify_chain_reports_non_canonical_hash():
    result = verify_chain([{"seq": 1, "prev_hash": "0" * 64, "hash": "A" * 64}])
    assert result["ok"] is False
    assert any("hash is not canonical lowercase hex" in e["message"] for e in result["errors"])


def test_verify_chain_reports_non_object_event():
    result = verify_chain(["not an event"])
    assert result["ok"] is False
    assert result["errors"] == [{"seq": 1, "message": "event is not a JSON object"}]


def test_uppercase_stored_event_hash_fails_closed():
    zip_bytes, kp = _sealed()

    def _upper(name: str, data: bytes) -> bytes:
        if name != "chain/events.jsonl":
            return data
        lines = [ln for ln in data.decode("utf-8").split("\n") if ln]
        first = json.loads(lines[0])
        first["hash"] = first["hash"].upper()
        return ("\n".join([json.dumps(first), *lines[1:]]) + "\n").encode("utf-8")

    tampered = _repack(zip_bytes, _upper)
    result = verify_capsule(tampered, allowlist=[kp.public_key_hex])
    assert result["ok"] is False
    assert result["chain"]["ok"] is False
    assert any(
        "hash is not canonical lowercase hex" in e["message"] for e in result["chain"]["errors"]
    )


def test_non_object_chain_event_fails_closed():
    zip_bytes, kp = _sealed()
    tampered = _repack(
        zip_bytes,
        lambda n, d: b'"not an event"\n' if n == "chain/events.jsonl" else d,
    )
    result = verify_capsule(tampered, allowlist=[kp.public_key_hex])
    assert result["ok"] is False
    assert result["chain"]["ok"] is False
    assert any("event is not a JSON object" in e["message"] for e in result["chain"]["errors"])
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-py && PYTHONPATH=src python3 -m pytest tests/test_totality.py -k "verify_chain or uppercase or non_object_chain"`

Expected: FAIL — `4 failed, 4 deselected`, with `ValueError: hex_to_bytes: non-hex characters` for the two hash-case tests and `AttributeError: 'str' object has no attribute 'get'` for the two non-object-event tests

- [ ] **Step 3: Import re and add the canonical-hex helper**

In `sdk-py/src/capsule/chain.py:5-13`, replace:

```python
import json
from typing import TypedDict

from .canonical import bytes_to_hex, concat_bytes, hex_to_bytes, jcs, sha256

GENESIS_PREV_BYTES: bytes = b"\x00" * 32
GENESIS_PREV_HEX: str = "0" * 64


class ChainError(TypedDict):
```

with:

```python
import json
import re
from typing import TypedDict

from .canonical import bytes_to_hex, concat_bytes, hex_to_bytes, jcs, sha256

GENESIS_PREV_BYTES: bytes = b"\x00" * 32
GENESIS_PREV_HEX: str = "0" * 64

# Chain-bound hex is lowercase per spec/chain.md. verify_chain feeds a
# stored hash straight into hex_to_bytes to seed the next link, so the
# canonical-form check has to happen before that call, not inside it.
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _is_hex64(value) -> bool:
    return isinstance(value, str) and _HEX64.match(value) is not None


class ChainError(TypedDict):
```

- [ ] **Step 4: Guard the event object and prev_hash**

In `sdk-py/src/capsule/chain.py:92-99` (shifted by Step 3), replace:

```python
    for i, e in enumerate(events):
        seq = e.get("seq", i + 1)
        if e.get("seq") != i + 1:
            errors.append({"seq": seq, "message": f"seq {e.get('seq')} expected {i + 1}"})
        if not isinstance(e.get("prev_hash"), str) or len(e["prev_hash"]) != 64:
            errors.append({"seq": seq, "message": "prev_hash missing or wrong length"})
            continue
        expected_prev = bytes_to_hex(prev)
```

with:

```python
    for i, e in enumerate(events):
        if not isinstance(e, dict):
            errors.append({"seq": i + 1, "message": "event is not a JSON object"})
            continue
        seq = e.get("seq", i + 1)
        if e.get("seq") != i + 1:
            errors.append({"seq": seq, "message": f"seq {e.get('seq')} expected {i + 1}"})
        if not isinstance(e.get("prev_hash"), str) or len(e["prev_hash"]) != 64:
            errors.append({"seq": seq, "message": "prev_hash missing or wrong length"})
            continue
        if not _is_hex64(e["prev_hash"]):
            errors.append({"seq": seq, "message": "prev_hash is not canonical lowercase hex"})
            continue
        expected_prev = bytes_to_hex(prev)
```

- [ ] **Step 5: Guard the stored hash before it reaches hex_to_bytes**

In `sdk-py/src/capsule/chain.py:107-110` (shifted by Steps 3-4), replace:

```python
        if not isinstance(e.get("hash"), str) or len(e["hash"]) != 64:
            errors.append({"seq": seq, "message": "hash missing or wrong length"})
            continue
        rest = {k: v for k, v in e.items() if k != "hash"}
```

with:

```python
        if not isinstance(e.get("hash"), str) or len(e["hash"]) != 64:
            errors.append({"seq": seq, "message": "hash missing or wrong length"})
            continue
        if not _is_hex64(e["hash"]):
            errors.append({"seq": seq, "message": "hash is not canonical lowercase hex"})
            continue
        rest = {k: v for k, v in e.items() if k != "hash"}
```

- [ ] **Step 6: Make first_and_entry_hash total**

In `sdk-py/src/capsule/chain.py:127-131`, replace:

```python
def first_and_entry_hash(events: list[dict]) -> tuple[str, str]:
    """Return (first_event_hash, entry_hash) for the chain."""
    if not events:
        raise ValueError("chain is empty")
    return events[0]["hash"], events[-1]["hash"]
```

with:

```python
def first_and_entry_hash(events: list[dict]) -> tuple[str | None, str | None]:
    """Return (first_event_hash, entry_hash) for the chain.

    Returns None for an event that is not an object or carries no hash,
    matching sdk-js: the caller compares against the envelope and reports
    a mismatch rather than raising.
    """
    if not events:
        raise ValueError("chain is empty")

    def _hash_of(e):
        return e.get("hash") if isinstance(e, dict) else None

    return _hash_of(events[0]), _hash_of(events[-1])
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `cd sdk-py && PYTHONPATH=src python3 -m pytest tests/test_totality.py -k "verify_chain or uppercase or non_object_chain"`

Expected: PASS — `4 passed, 4 deselected`

- [ ] **Step 8: Run the full lane suite for regressions**

Run: `cd sdk-py && PYTHONPATH=src python3 -m pytest`

Expected: `190 passed`

- [ ] **Step 9: Commit**
```bash
git add sdk-py/src/capsule/chain.py sdk-py/tests/test_totality.py
git commit -m "fix(sdk-py): report non-dict events and non-canonical chain hex instead of raising"
```

---

### Task 7: sdk-py — verify_capsule never raises, and reports invalid signatures

**Files:**
- Modify: `sdk-py/src/capsule/verifier.py:42-70`, `sdk-py/src/capsule/verifier.py:145-149`, `sdk-py/src/capsule/verifier.py:163-169`, `sdk-py/src/capsule/verifier.py:248-249`, `sdk-py/README.md:66-67`
- Test: `sdk-py/tests/test_totality.py`

**Interfaces:**
- Consumes: `verify_envelope_signatures(envelope) -> dict`, `CapsuleReader.from_bytes`
- Produces: module-private `_fail_closed(message: str, level: str) -> VerifyResult` and `_verify_capsule_impl(reader, *, allowlist, outer_envelope) -> VerifyResult`; the public `verify_capsule` signature is unchanged. New error strings `verification failed: <ExcType>: <msg>` and `envelope.signers[<i>] signature invalid (role '<role>', public_key <hex>)`.

- [ ] **Step 1: Write the failing test**

Append to `sdk-py/tests/test_totality.py`:

```python
class _ManifestIsAnArrayReader:
    """A hand-built reader whose manifest is a JSON array.

    from_bytes now refuses this shape, so the only way in is a reader
    constructed by hand — which verify_capsule accepts. Without the
    total-function wrapper this raises AttributeError on manifest.get().
    """

    def manifest(self):
        return []

    def envelope(self):
        return {}

    def files(self):
        return {}

    def is_encrypted(self):
        return False


def test_unexpected_exception_becomes_fail_closed_result():
    result = verify_capsule(_ManifestIsAnArrayReader(), allowlist=[])
    _assert_fail_closed_shape(result)
    assert result["errors"][0].startswith("verification failed: AttributeError")


def test_invalid_envelope_signature_produces_a_displayable_error():
    zip_bytes, kp = _sealed()

    def _flip(name: str, data: bytes) -> bytes:
        if name != "provenance/envelope.json":
            return data
        env = json.loads(data.decode("utf-8"))
        sig = env["signers"][0]["signature"]
        env["signers"][0]["signature"] = ("1" if sig[0] == "0" else "0") + sig[1:]
        return json.dumps(env, indent=2).encode("utf-8")

    tampered = _repack(zip_bytes, _flip)
    result = verify_capsule(tampered, allowlist=[kp.public_key_hex])
    assert result["ok"] is False
    assert result["envelope"]["ok"] is False
    assert result["envelope"]["signers"][0]["valid"] is False
    assert any("envelope.signers[0] signature invalid" in e for e in result["errors"])
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-py && PYTHONPATH=src python3 -m pytest tests/test_totality.py -k "unexpected_exception or displayable"`

Expected: FAIL — `2 failed, 8 deselected`, with `AttributeError: 'list' object has no attribute 'get'` raised out of `verifier.py:96` and `assert False +where False = any(<generator ...>)` for the signature test

- [ ] **Step 3: Split the body behind a total wrapper**

In `sdk-py/src/capsule/verifier.py:42-71`, replace:

```python
def verify_capsule(
    reader,
    *,
    allowlist: list | None = None,
    outer_envelope: dict | None = None,
) -> VerifyResult:
    """Verify a capsule.

    Accepts a ``CapsuleReader`` or the raw ``.capsule`` bytes. Given
    bytes, a container that cannot even be opened (malformed ZIP,
    missing or invalid manifest/envelope) returns a fail-closed result
    instead of raising, so app code has a single failure path.

    ``allowlist`` entries may be hex strings (any case) or 32 raw bytes.
    """
    if isinstance(reader, (bytes, bytearray, memoryview)):
        try:
            reader = CapsuleReader.from_bytes(bytes(reader))
        except (ValueError, BadZipFile) as e:
            return {
                "ok": False,
                "level": "L2",
                "errors": [f"capsule cannot be opened: {e}"],
                "chain": {"ok": False, "errors": []},
                "content_index": {"ok": False, "errors": []},
                "envelope": {"ok": False, "signers": []},
                "trusted_signer_count": 0,
                "notes": [],
            }
    errors: list[str] = []
```

with:

```python
def _fail_closed(message: str, level: str) -> VerifyResult:
    """The documented fail-closed result: every channel present, nothing trusted."""
    return {
        "ok": False,
        "level": level,
        "errors": [message],
        "chain": {"ok": False, "errors": []},
        "content_index": {"ok": False, "errors": []},
        "envelope": {"ok": False, "signers": []},
        "trusted_signer_count": 0,
        "notes": [],
    }


def verify_capsule(
    reader,
    *,
    allowlist: list | None = None,
    outer_envelope: dict | None = None,
) -> VerifyResult:
    """Verify a capsule.

    Accepts a ``CapsuleReader`` or the raw ``.capsule`` bytes. Given
    bytes, a container that cannot even be opened (malformed ZIP,
    missing or invalid manifest/envelope) returns a fail-closed result
    instead of raising, so app code has a single failure path.

    Verification is total: no input produces an exception. Anything the
    checks below fail to anticipate comes back as a fail-closed result
    with the underlying message in ``errors``.

    ``allowlist`` entries may be hex strings (any case) or 32 raw bytes.
    """
    level = "L3" if outer_envelope is not None else "L2"
    try:
        return _verify_capsule_impl(reader, allowlist=allowlist, outer_envelope=outer_envelope)
    except Exception as e:
        # The docstring promises callers a result, not an exception, for
        # every input. Anything that escapes the checks below is a capsule
        # we could not fully evaluate, which is a verification failure.
        return _fail_closed(f"verification failed: {type(e).__name__}: {e}", level)


def _verify_capsule_impl(
    reader,
    *,
    allowlist: list | None = None,
    outer_envelope: dict | None = None,
) -> VerifyResult:
    if isinstance(reader, (bytes, bytearray, memoryview)):
        try:
            reader = CapsuleReader.from_bytes(bytes(reader))
        except (ValueError, BadZipFile) as e:
            return _fail_closed(f"capsule cannot be opened: {e}", "L2")
    errors: list[str] = []
```

Do NOT add a `# noqa: BLE001` to the `except Exception` — `BLE` is not in the project's ruff `select` list, so the directive would fail `RUF100 Unused 'noqa' directive`.

- [ ] **Step 4: Read the stored content index defensively**

In `sdk-py/src/capsule/verifier.py:145-149` (shifted by Step 3), replace:

```python
    stored_files = manifest.get("content_index", {}).get("files", [])
    stored_map = {f["path"]: f["sha256"] for f in stored_files}

    ci_ok = True
    if recomputed["index_hash"] != manifest.get("content_index", {}).get("index_hash"):
```

with:

```python
    # A reader built by from_bytes has already shape-checked these, but
    # verify_capsule also accepts hand-constructed readers, so read the
    # stored index defensively and report rather than raise.
    stored_index = manifest.get("content_index")
    if not isinstance(stored_index, dict):
        stored_index = {}
        result["content_index"]["errors"].append("manifest.content_index is not a JSON object")
    stored_files = stored_index.get("files")
    if not isinstance(stored_files, list):
        if stored_index:
            result["content_index"]["errors"].append("manifest.content_index.files is not an array")
        stored_files = []
    stored_files = [f for f in stored_files if isinstance(f, dict)]
    stored_map = {f.get("path"): f.get("sha256") for f in stored_files}

    ci_ok = True
    if recomputed["index_hash"] != stored_index.get("index_hash"):
```

- [ ] **Step 5: Stop indexing stored entries with []**

In `sdk-py/src/capsule/verifier.py:163-169` (shifted), replace:

```python
    recomputed_paths = {f["path"] for f in recomputed["files"]}
    for f in stored_files:
        if f["path"] not in recomputed_paths:
            ci_ok = False
            result["content_index"]["errors"].append(
                f"file in manifest index but missing from package: {f['path']}"
            )
```

with:

```python
    recomputed_paths = {f["path"] for f in recomputed["files"]}
    for f in stored_files:
        if f.get("path") not in recomputed_paths:
            ci_ok = False
            result["content_index"]["errors"].append(
                f"file in manifest index but missing from package: {f.get('path')}"
            )
```

- [ ] **Step 6: Emit a per-signer error**

In `sdk-py/src/capsule/verifier.py:248-249` (shifted), replace:

```python
    result["envelope"]["signers"] = signers
    result["trusted_signer_count"] = sum(1 for s in signers if s["trusted"])
```

with:

```python
    result["envelope"]["signers"] = signers
    # A bad signature is otherwise only visible as valid=False nested in
    # envelope.signers[i]; every other failure class produces a displayable
    # message, so give this one an error too.
    for i, s in enumerate(signers):
        if not s["valid"]:
            errors.append(
                f"envelope.signers[{i}] signature invalid "
                f"(role {s['role']!r}, public_key {s['public_key']})"
            )
    result["trusted_signer_count"] = sum(1 for s in signers if s["trusted"])
```

- [ ] **Step 7: Update the README claim**

In `sdk-py/README.md:66-67`, replace:

```markdown
`"originator"`, and `verify_capsule(bytes)` on unopenable input returns
a fail-closed result (`ok: False`) instead of raising.
```

with:

```markdown
`"originator"`, and `verify_capsule()` never raises: unopenable input, a
malformed manifest, and a malformed chain all come back as a fail-closed
result (`ok: False`) with the reason in `errors`.
```

- [ ] **Step 8: Run the test to verify it passes**

Run: `cd sdk-py && PYTHONPATH=src python3 -m pytest tests/test_totality.py -k "unexpected_exception or displayable"`

Expected: PASS — `2 passed, 8 deselected`

- [ ] **Step 9: Run the full lane suite for regressions**

Run: `cd sdk-py && PYTHONPATH=src python3 -m pytest`

Expected: `192 passed` (in particular `tests/test_parity_jssdk.py`, whose `assert result["errors"] == []` runs on a clean capsule and is unaffected by the new signer errors)

- [ ] **Step 10: Lint**

Run: `cd sdk-py && ruff check src tests`

Expected: `All checks passed!`

- [ ] **Step 11: Commit**
```bash
git add sdk-py/src/capsule/verifier.py sdk-py/README.md sdk-py/tests/test_totality.py
git commit -m "fix(sdk-py): make verify_capsule total and surface invalid signatures as errors"
```

---

### Task 8: spec — malformed-shape conformance vectors

**Files:**
- Create: `spec/vectors/malformed-shape/vectors.json`
- Create: `sdk-js/tools/generate-malformed-shape-fixtures.mjs`
- Create: `spec/vectors/malformed-shape/output/manifest-not-object.capsule` (generated, 1747 bytes)
- Create: `spec/vectors/malformed-shape/output/missing-content-index.capsule` (generated, 2402 bytes)
- Create: `spec/vectors/malformed-shape/output/content-index-files-not-array.capsule` (generated, 2530 bytes)
- Create: `spec/vectors/malformed-shape/output/content-index-entry-missing-sha256.capsule` (generated, 2634 bytes)
- Create: `spec/vectors/malformed-shape/output/uppercase-event-hash.capsule` (generated, 2601 bytes)
- Modify: `tools/check-spec-vectors.mjs:140-147`
- Modify: `tools/run-conformance.mjs:83-92`
- Modify: `sdk-py/tests/test_spec_registry.py:7-9`, `sdk-py/tests/test_spec_registry.py:28-31`, `sdk-py/tests/test_spec_registry.py:36-43`, `sdk-py/tests/test_spec_registry.py:101-113`
- Modify: `spec/vectors/README.md:27-34`, `spec/vectors/README.md:58-60`
- Test: `sdk-py/tests/test_spec_registry.py`, `tools/check-spec-vectors.mjs`

**Interfaces:**
- Consumes: reader error strings from Tasks 1 and 5 (all prefixed `manifest.`), chain error strings from Tasks 2 and 6, `writeRawZip(entries)` from `sdk-js/tools/rawzip.mjs`, `unpackZip` from `sdk-js/src/zip.js`, the clean fixture `spec/vectors/tamper-detection/output/clean.capsule` and its `keys.json`
- Produces: new normative open-stage reason category `invalid_manifest_shape`, registered in `tools/check-spec-vectors.mjs` `OPEN_REASON` and `sdk-py/tests/test_spec_registry.py` `OPEN_REASON_PATTERNS`; Python helper `_assert_registry_vector(doc, vector, base)`; conformance target id `malformed-shape-fixtures-regen`

This collection is deliberately a new directory rather than more entries in `malformed-layout/vectors.json`: `verifier-rust/tests/spec_registry.rs:146` panics on an unknown reason category and hard-codes the two existing collection paths, so a new category there would break the Rust lane, which is outside this cluster.

- [ ] **Step 1: Write the registry**

Create `spec/vectors/malformed-shape/vectors.json`:

```json
{
  "meta": {
    "name": "malformed-shape",
    "spec_version": "0.6",
    "description": "Language-neutral expected outcomes for capsules whose ZIP container is well-formed but whose manifest or chain documents violate the required field shapes. Independent implementations MUST refuse these capsules: stage 'open' means the reader rejects the document before verification (by error, exception, or fail-closed result, per the host language's idiom); the default verify stage means the capsule opens but verification reports ok=false. No fixture here may make a verifier raise an unhandled exception.",
    "no_warranty": "Conformance fixtures only; not production templates or advice."
  },
  "generator": "sdk-js/tools/generate-malformed-shape-fixtures.mjs (derived from ../tamper-detection/output/clean.capsule)",
  "keys_file": "../tamper-detection/output/keys.json",
  "reasons": {
    "invalid_manifest_shape": "manifest.json parses as JSON but a required field is absent or has the wrong type/format (not an object, no content_index, content_index.files not an array, a files[] entry without a 64-char lowercase hex sha256)"
  },
  "notes": [
    "The 'reason' field is normative: an implementation must reject the fixture for the named reason category. Exact error strings are implementation-defined.",
    "uppercase-event-hash opens successfully — the shape violation is inside chain/events.jsonl, so it surfaces at the verify stage. A verifier that feeds the stored hash to a strict hex decoder without a canonical-form guard raises instead of reporting, which this vector exists to catch."
  ],
  "vectors": [
    {
      "name": "manifest-not-object",
      "capsule_file": "output/manifest-not-object.capsule",
      "expected": { "ok": false, "stage": "open", "reason": "invalid_manifest_shape", "detail": "manifest.json is not a JSON object" }
    },
    {
      "name": "missing-content-index",
      "capsule_file": "output/missing-content-index.capsule",
      "expected": { "ok": false, "stage": "open", "reason": "invalid_manifest_shape", "detail": "manifest.content_index" }
    },
    {
      "name": "content-index-files-not-array",
      "capsule_file": "output/content-index-files-not-array.capsule",
      "expected": { "ok": false, "stage": "open", "reason": "invalid_manifest_shape", "detail": "manifest.content_index.files" }
    },
    {
      "name": "content-index-entry-missing-sha256",
      "capsule_file": "output/content-index-entry-missing-sha256.capsule",
      "expected": { "ok": false, "stage": "open", "reason": "invalid_manifest_shape", "detail": "manifest.content_index.files[0].sha256" }
    },
    {
      "name": "uppercase-event-hash",
      "capsule_file": "output/uppercase-event-hash.capsule",
      "expected": { "ok": false, "failing": ["chain", "content_index"] }
    }
  ]
}
```

- [ ] **Step 2: Run the checker to verify it fails**

Run: `node tools/check-spec-vectors.mjs`

Expected: FAIL with five lines, the first being
`FAIL: <repo>/spec/vectors/malformed-shape/vectors.json [manifest-not-object]: capsule_file unreadable: ENOENT: no such file or directory, open '<repo>/spec/vectors/malformed-shape/output/manifest-not-object.capsule'`

- [ ] **Step 3: Write the fixture generator**

Create `sdk-js/tools/generate-malformed-shape-fixtures.mjs`:

```js
#!/usr/bin/env node
// generate-malformed-shape-fixtures.mjs
//
// Generates the malformed-shape conformance fixtures under
// spec/vectors/malformed-shape/output/. Where malformed-layout attacks the
// ZIP container, these fixtures keep the container well-formed and break the
// *documents* inside it: manifest.json that is not an object, a missing or
// mistyped content_index, a content-index entry without its sha256, and a
// stored event hash written in uppercase hex.
//
// Every fixture is derived deterministically from the checked-in
// tamper-detection clean fixture (spec/vectors/tamper-detection/output/
// clean.capsule) with the guardrail-free raw writer (tools/rawzip.mjs), so the
// entry order and timestamps match the other generated collections byte for
// byte.
//
// Fixture -> expected outcome lives in
// spec/vectors/malformed-shape/vectors.json (the language-neutral registry);
// this script only (re)generates the capsule bytes. Regeneration is an
// intentional spec change; review the byte-level diff. Pass --check to compare
// generated bytes with the checked-in fixtures.

import { readFile, mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { unpackZip } from "../src/zip.js";
import { writeRawZip } from "./rawzip.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..");
const CLEAN = join(REPO_ROOT, "spec", "vectors", "tamper-detection", "output", "clean.capsule");
const OUT_DIR = join(REPO_ROOT, "spec", "vectors", "malformed-shape", "output");
const CHECK = process.argv.includes("--check");

/** Sorted [{name, data}] view of the clean capsule's entries. */
async function cleanEntries() {
  const files = await unpackZip(await readFile(CLEAN));
  return [...files.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([name, data]) => ({ name, data: Buffer.from(data) }));
}

function replaceData(entries, name, data) {
  return entries.map((e) => (e.name === name ? { ...e, data } : e));
}

function readJson(entries, name) {
  const entry = entries.find((e) => e.name === name);
  if (!entry) throw new Error(`clean fixture has no ${name}`);
  return JSON.parse(entry.data.toString("utf8"));
}

/** Serialize a mutated JSON document the way the builder writes it. */
function writeJson(value) {
  return Buffer.from(JSON.stringify(value, null, 2) + "\n", "utf8");
}

function withManifest(entries, mutate) {
  const manifest = readJson(entries, "manifest.json");
  mutate(manifest);
  return replaceData(entries, "manifest.json", writeJson(manifest));
}

async function main() {
  await mkdir(OUT_DIR, { recursive: true });
  const base = await cleanEntries();

  // Uppercase the stored hash of the first chain event. The hex is still
  // 64 characters, so a length-only guard lets it through and the stored
  // value reaches hexToBytes, which rejects non-canonical hex by throwing.
  const jsonlEntry = base.find((e) => e.name === "chain/events.jsonl");
  if (!jsonlEntry) throw new Error("clean fixture has no chain/events.jsonl");
  const lines = jsonlEntry.data.toString("utf8").split("\n").filter((l) => l.length > 0);
  const firstEvent = JSON.parse(lines[0]);
  firstEvent.hash = firstEvent.hash.toUpperCase();
  const uppercasedJsonl = Buffer.from(
    [JSON.stringify(firstEvent), ...lines.slice(1)].join("\n") + "\n",
    "utf8",
  );

  const fixtures = {
    // manifest.json parses, but as an array — not the object every field
    // access below assumes.
    "manifest-not-object.capsule": replaceData(
      base,
      "manifest.json",
      Buffer.from("[]", "utf8"),
    ),

    // content_index absent entirely: the verifier reads
    // manifest.content_index.index_hash unconditionally.
    "missing-content-index.capsule": withManifest(base, (m) => {
      delete m.content_index;
    }),

    // content_index.files present but an object: the verifier calls .map on it.
    "content-index-files-not-array.capsule": withManifest(base, (m) => {
      m.content_index.files = {};
    }),

    // A content-index entry without its sha256 commitment.
    "content-index-entry-missing-sha256.capsule": withManifest(base, (m) => {
      m.content_index.files = m.content_index.files.map(({ path }) => ({ path }));
    }),

    // Stored event hash in uppercase hex: 64 chars, non-canonical.
    "uppercase-event-hash.capsule": replaceData(base, "chain/events.jsonl", uppercasedJsonl),
  };

  for (const [name, entries] of Object.entries(fixtures)) {
    const path = join(OUT_DIR, name);
    const bytes = writeRawZip(entries);
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

- [ ] **Step 4: Generate the fixture bytes**

Run: `node sdk-js/tools/generate-malformed-shape-fixtures.mjs`

Expected:
```
wrote manifest-not-object.capsule (1747 bytes)
wrote missing-content-index.capsule (2402 bytes)
wrote content-index-files-not-array.capsule (2530 bytes)
wrote content-index-entry-missing-sha256.capsule (2634 bytes)
wrote uppercase-event-hash.capsule (2601 bytes)
```

- [ ] **Step 5: Run the checker to verify the reason category is still unknown**

Run: `node tools/check-spec-vectors.mjs`

Expected: FAIL with four lines, the first being
`FAIL: <repo>/spec/vectors/malformed-shape/vectors.json [manifest-not-object]: unknown open-stage reason 'invalid_manifest_shape'`
(the fifth vector, `uppercase-event-hash`, is verify-stage and already passes)

- [ ] **Step 6: Register the reason category in the JS reference checker**

In `tools/check-spec-vectors.mjs:142-143`, replace:

```js
  invalid_json: /JSON/,
  duplicate_entry: /duplicate entry/,
```

with:

```js
  invalid_json: /JSON/,
  // Every manifest shape error from reader.js validateManifestShape is
  // prefixed with the offending field path.
  invalid_manifest_shape: /^manifest\./,
  duplicate_entry: /duplicate entry/,
```

- [ ] **Step 7: Run the checker to verify it passes**

Run: `node tools/check-spec-vectors.mjs`

Expected: PASS — `spec vectors: ok (285 vectors)` (280 before this task)

- [ ] **Step 8: Wire the collection into the Python lane**

Three edits in `sdk-py/tests/test_spec_registry.py`.

(a) at `:7-9`, replace:

```python
  - tamper-detection/vectors.json   (verify-stage outcomes)
  - malformed-layout/vectors.json   (open-stage reasons + verify-stage)
  - signing-input.json              (byte-level signing/hashing pins)
```

with:

```python
  - tamper-detection/vectors.json   (verify-stage outcomes)
  - malformed-layout/vectors.json   (open-stage reasons + verify-stage)
  - malformed-shape/vectors.json    (open-stage reasons + verify-stage)
  - signing-input.json              (byte-level signing/hashing pins)
```

(b) at `:30-31`, replace:

```python
MALFORMED = VECTORS / "malformed-layout" / "vectors.json"
SIGNING_INPUT = VECTORS / "signing-input.json"
```

with:

```python
MALFORMED = VECTORS / "malformed-layout" / "vectors.json"
MALFORMED_SHAPE = VECTORS / "malformed-shape" / "vectors.json"
SIGNING_INPUT = VECTORS / "signing-input.json"
```

(c) at `:38-39`, replace:

```python
    "invalid_json": r"parse",
    "duplicate_entry": r"duplicate entry",
```

with:

```python
    "invalid_json": r"parse",
    # Every manifest shape error from reader._validate_manifest_shape is
    # prefixed with the offending field path.
    "invalid_manifest_shape": r"^manifest\.",
    "duplicate_entry": r"duplicate entry",
```

- [ ] **Step 9: Parametrize the Python registry test over both collections**

In `sdk-py/tests/test_spec_registry.py:101-113` (shifted by Step 8), replace:

```python
@pytest.mark.parametrize("doc,vector,base", _collection_params(MALFORMED))
def test_malformed_registry_outcomes(doc: dict, vector: dict, base: pathlib.Path):
    data = (base / vector["capsule_file"]).read_bytes()
    expected = vector["expected"]
    if expected.get("stage") == "open":
        pattern = OPEN_REASON_PATTERNS.get(expected["reason"])
        assert pattern is not None, f"unknown open-stage reason {expected['reason']!r}"
        with pytest.raises(ValueError, match=pattern):
            CapsuleReader.from_bytes(data)
        return
    reader = CapsuleReader.from_bytes(data)
    result = verify_capsule(reader, allowlist=_allowlist(doc, base))
    _assert_verify_outcome(vector["name"], expected, result)
```

with:

```python
def _assert_registry_vector(doc: dict, vector: dict, base: pathlib.Path) -> None:
    """Open-stage vectors must be refused by the reader; the rest verify."""
    data = (base / vector["capsule_file"]).read_bytes()
    expected = vector["expected"]
    if expected.get("stage") == "open":
        pattern = OPEN_REASON_PATTERNS.get(expected["reason"])
        assert pattern is not None, f"unknown open-stage reason {expected['reason']!r}"
        with pytest.raises(ValueError, match=pattern):
            CapsuleReader.from_bytes(data)
        # verify_capsule is total: the same bytes must fail closed, not raise.
        result = verify_capsule(data, allowlist=_allowlist(doc, base))
        assert result["ok"] is False, f"{vector['name']}: expected a fail-closed result"
        return
    reader = CapsuleReader.from_bytes(data)
    result = verify_capsule(reader, allowlist=_allowlist(doc, base))
    _assert_verify_outcome(vector["name"], expected, result)


@pytest.mark.parametrize("doc,vector,base", _collection_params(MALFORMED))
def test_malformed_registry_outcomes(doc: dict, vector: dict, base: pathlib.Path):
    _assert_registry_vector(doc, vector, base)


@pytest.mark.parametrize("doc,vector,base", _collection_params(MALFORMED_SHAPE))
def test_malformed_shape_registry_outcomes(doc: dict, vector: dict, base: pathlib.Path):
    _assert_registry_vector(doc, vector, base)
```

- [ ] **Step 10: Run the Python registry test to verify it passes**

Run: `cd sdk-py && PYTHONPATH=src python3 -m pytest tests/test_spec_registry.py -v`

Expected: PASS — `22 passed` (17 before, plus the 5 new `malformed-shape` params, listed as `test_malformed_shape_registry_outcomes[manifest-not-object]` … `[uppercase-event-hash]`)

- [ ] **Step 11: Add the regeneration-drift target to the conformance harness**

In `tools/run-conformance.mjs:90-93`, replace:

```js
    test_cmd: "node sdk-js/tools/generate-malformed-fixtures.mjs --check",
    pass_signal: { type: "exit_code", value: 0 },
  },
  {
    id: "spec-vectors",
```

with:

```js
    test_cmd: "node sdk-js/tools/generate-malformed-fixtures.mjs --check",
    pass_signal: { type: "exit_code", value: 0 },
  },
  {
    id: "malformed-shape-fixtures-regen",
    name: "malformed-shape fixture regeneration check",
    language: "javascript",
    kind: "check",
    cwd: ".",
    install_cmd: "true",
    test_cmd: "node sdk-js/tools/generate-malformed-shape-fixtures.mjs --check",
    pass_signal: { type: "exit_code", value: 0 },
  },
  {
    id: "spec-vectors",
```

- [ ] **Step 12: Document the collection**

Two edits in `spec/vectors/README.md`.

(a) at `:27-34`, replace:

```markdown
     See `malformed-layout/vectors.json`, whose `reasons` map documents the
     category vocabulary (including reserved categories that do not have
     checked-in fixtures yet).

   Independent implementations SHOULD reproduce these outcomes; the Python
   (`sdk-py/tests/test_spec_registry.py`) and Rust
   (`verifier-rust/tests/spec_registry.rs`) lanes consume both collections
   directly.
```

with:

```markdown
     See `malformed-layout/vectors.json`, whose `reasons` map documents the
     category vocabulary (including reserved categories that do not have
     checked-in fixtures yet).

   `malformed-shape/vectors.json` uses both stages for capsules whose ZIP
   container is well-formed but whose manifest or chain documents violate
   the required field shapes. No fixture in that collection may make a
   verifier raise an unhandled exception: verification is a total function.

   Independent implementations SHOULD reproduce these outcomes; the Python
   (`sdk-py/tests/test_spec_registry.py`) lane consumes all three
   collections and the Rust (`verifier-rust/tests/spec_registry.rs`) lane
   consumes `tamper-detection` and `malformed-layout`.
```

(b) at `:59-60`, replace:

```markdown
- `sdk-js/tools/generate-malformed-fixtures.mjs` → `malformed-layout/output/`
  (derived from the tamper-detection clean fixture)
```

with:

```markdown
- `sdk-js/tools/generate-malformed-fixtures.mjs` → `malformed-layout/output/`
  (derived from the tamper-detection clean fixture)
- `sdk-js/tools/generate-malformed-shape-fixtures.mjs` →
  `malformed-shape/output/` (derived from the same clean fixture)
```

- [ ] **Step 13: Run the full JS conformance harness**

Run: `node tools/run-conformance.mjs`

Expected: `PASS · 11/11 passed`, including `[5/11] malformed-shape-fixtures-regen ... PASS` and `[6/11] spec-vectors ... PASS`

- [ ] **Step 14: Run the full Python lane for regressions**

Run: `cd sdk-py && PYTHONPATH=src python3 -m pytest`

Expected: `197 passed`

- [ ] **Step 15: Commit**
```bash
git add spec/vectors/malformed-shape spec/vectors/README.md \
        sdk-js/tools/generate-malformed-shape-fixtures.mjs \
        tools/check-spec-vectors.mjs tools/run-conformance.mjs \
        sdk-py/tests/test_spec_registry.py
git commit -m "feat(conformance): add malformed-shape vectors pinning verifier totality"
```


# C1 — sdk-js container entry-set integrity (F01, F11, F58, F67)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Part of:** [Capsules pre-release remediation](./README.md) · Tier 1 (release-blocking)

**Findings closed:** F01, F11, F58, F67

**Lanes touched:** sdk-js, sdk-py, verifier-rust, spec

**Tasks:** 6

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

Cross-lane coordination — the three new malformed-layout vectors are open-stage, and the malformed registry is consumed by THREE harnesses (tools/check-spec-vectors.mjs, sdk-py/tests/test_spec_registry.py, verifier-rust/tests/spec_registry.rs). Task 6 must land after Tasks 3, 4 and 5 or all three lanes go red. Swift and Kotlin do NOT read malformed-layout/vectors.json (verified: they only consume tamper-detection and jcs-numbers), so those lanes are unaffected by this cluster — but they almost certainly have the same directory-marker/local-name gap and should be covered by whichever cluster owns sdk-swift/sdk-kotlin container parity. Recommend they adopt the same three checks and then opt into the malformed registry.

Scope note — Task 5 touches sdk-py, which is not nominally this cluster's lane. It is included because the new vectors cannot be open-stage without it, and because measurement showed sdk-py currently returns `verify ok = True` for the dir-marker-with-content shape (an independent live smuggle, not merely a parity gap). If another cluster is also editing sdk-py/src/capsule/zip_io.py, coordinate on the `unpack_zip` loop body.

What could break: (1) `scanCentralDirectory` is public API (exported from sdk-js/src/index.js and declared in index.d.ts) and its return shape gains four fields plus an optional second argument — additive, but index.d.ts must be updated in the same commit or downstream TS consumers see a stale type. (2) Requiring the local-header name to equal the central name will reject archives from sloppy third-party packers that write backslash variants in one header; capsules are only ever produced by the SDKs' own packers, and the full example/CLI suites pass, but it is a real strictness increase. (3) The Rust change replaces `name.ends_with('/') && entry.size() == 0` with a name-only test, which is only safe because `scan_central_directory` now rejects `/`-with-content first — do not land the `unpack_zip` half without the scan half. (4) `packZip` gains an optional options arg; it is positional-second so no existing call site changes (verified: builder.js:225,264,360 and all examples pass). (5) Editing spec/format.md invalidates skills/capsule/skill.json — the regen step is mandatory or the first conformance target fails.

Existing tests likely to fail if a step is skipped: none observed — all 63 sdk-js, 188 sdk-py, 105+ Rust, and 10/10 conformance targets pass with the full cluster applied.

## Validation performed while specifying this plan

The steps below were applied to a **copy of the repository outside the working tree** and executed. This is the real output from that run, not a prediction.

<details>
<summary>Expand validation log</summary>

```
Applied the entire cluster on a copy at /tmp/work-c1 (outside the repo) and ran every affected lane. Real output:

REPRODUCTION (pre-fix, /tmp/work-c1/repro.mjs against the checked-in clean fixture):
'''
F01 unpackZip keys: [ 'chain/events.jsonl','manifest.json','program.md','provenance/envelope.json' ]
F01 verify ok = true []
$ unzip -l smuggle.capsule   ->   ... 17  01-01-1980 00:00   smuggled.md ... 5 files
$ python3 zipfile infolist   ->   [... ('smuggled.md', False, 17)]
'''
F11 (repro2.mjs): central names include 'notes.md'; JS extracted 'program.md' whose body was '"# EVIL program\n"'; and a local name of '../../evil.md' surfaced as a third key 'evil.md' in 'unpackZip' output.

POST-FIX, exact errors:
'''
Error: zip unpack: directory attribute on non-directory name: smuggled.md
Error: zip unpack: local/central name mismatch: central "notes.md", local "program.md"
'''

sdk-js — the 6 new tests fail against the unmodified src/zip.js:
'''
$ node --test test/strictness.test.js      (original zip.js restored)
# tests 21 / # pass 15 / # fail 6
not ok 16 - a DOS-dir-bit entry cannot smuggle a file past verifyCapsule
not ok 17 - unpackZip rejects a directory marker with nonzero size
not ok 18 - unpackZip rejects a local/central file-name mismatch
not ok 19 - unpackZip rejects a local name that resolves to a third path
not ok 20 - unpackZip honors caller-supplied reader limits
not ok 21 - reader limits must be positive integers
   error: 'Missing expected rejection.'
'''
and pass after: 'npm test' -> '# tests 63 / # pass 63 / # fail 0'.

verifier-rust — the 3 new tests fail against the unmodified zip_reader.rs (spliced in, compiles because they assert on 'to_string()'):
'''
test zip_reader::tests::rejects_dos_directory_attribute_on_file_name ... FAILED
test zip_reader::tests::rejects_directory_marker_with_content ... FAILED
test zip_reader::tests::rejects_local_central_name_mismatch ... FAILED
panicked: must reject DOS dir bit on a file name: {"smuggled.md": [104, 101, 108, 108, 111]}
test result: FAILED. 102 passed; 3 failed
'''
and after the fix: 'cargo test --offline --workspace' -> 'test result: ok. 105 passed; 0 failed' (plus 7 + 3 + 0 in the other targets). Rust CLI on the new fixture now prints '[✗] container / parse  directory marker shape for "smuggled.md": DOS directory attribute on a name that does not end in '/'' and the clean fixture still prints 'Result: PASS'.

sdk-py — the 3 new tests fail against the unmodified zip_io.py ('Failed: DID NOT RAISE <class 'ValueError'>' for the two directory shapes; 'zipfile.BadZipFile' — not a ValueError — for the name mismatch), and after the fix 'PYTHONPATH=src python3 -m pytest tests/' -> '188 passed in 0.23s'.

Pre-fix Python behaviour on the new fixtures, measured: 'dir-marker-with-content' -> 'verify ok = True' (a live smuggle in the Python lane, not just JS), 'dir-bit-smuggle' -> opens and fails only at content_index, 'local-name-mismatch' -> BadZipFile.

Registry / cross-lane:
'''
$ node tools/check-spec-vectors.mjs        -> spec vectors: ok (283 vectors)
$ node sdk-js/tools/generate-malformed-fixtures.mjs --check -> ok for all 13 incl. the 3 new
$ pytest sdk-py/tests/test_spec_registry.py -> 20 passed
$ cargo test ... malformed_registry_outcomes ... ok
$ node tools/run-conformance.mjs           -> PASS · 10/10 passed · 3.0s total
'''
Fixture bytes are deterministic (regen --check byte-identical on a second run): dir-bit-smuggle 2716 B sha256 af603fe2…, dir-marker-with-content 2706 B sha256 c305aa30…, local-name-mismatch 2710 B sha256 99f13668….

One gotcha found by running it: editing spec/format.md breaks 'skill-capsule-regen' ('skills/capsule/skill.json is out of date') until 'node tools/regen-capsule-skill.mjs' is run — Task 6 includes that step. Existing fixture bytes are unchanged by the rawzip.mjs extension (all 10 pre-existing fixtures still byte-identical).
```

</details>

---

## C1 — sdk-js container entry-set integrity (F01, F11, F58, F67)

The unifying fix: the raw central-directory scan becomes the single authoritative source of the entry set. `unpackZip` rejects the shapes that let two parsers disagree (DOS directory bit on a non-`/` name; a `/`-terminated name with nonzero size; a local-header name that differs from the central name), and then asserts the extracted key set equals the scanned set exactly. verifier-rust gets the same three checks plus name-only directory skipping (F67), sdk-py gets them because the new conformance vectors gate its lane too, and reader limits become configurable per `spec/format.md` (F58).

Task order matters: **Task 6 must land last** — it adds registry vectors that three lanes' harnesses execute.

---

### Task 1: Make sdk-js reader limits configurable

**Files:**
- Modify: `sdk-js/src/zip.js:13-15` (constants), `sdk-js/src/zip.js:31`, `sdk-js/src/zip.js:69`, `sdk-js/src/zip.js:99`, `sdk-js/src/zip.js:122-123`, `sdk-js/src/zip.js:141-142`, `sdk-js/src/zip.js:163-185`
- Modify: `sdk-js/src/index.js:47`
- Modify: `sdk-js/src/index.d.ts:266-270`
- Test: `sdk-js/test/strictness.test.js`

**Interfaces:**
- Consumes: none
- Produces: `DEFAULT_ZIP_LIMITS` (frozen `{maxEntries, maxTotalBytes}`); `resolveLimits(options) -> {maxEntries, maxTotalBytes}`; `scanCentralDirectory(bytes, options?)`, `packZip(files, options?)`, `unpackZip(bytes, options?)` all accepting `{maxEntries?, maxTotalBytes?}`; `assertStrictEntries(bytes, limits)`

- [ ] **Step 1: Write the failing test**

Append to the end of `sdk-js/test/strictness.test.js` (currently 244 lines). `packZip`/`unpackZip` are already imported at line 19.

```js

// --- Configurable reader limits (finding F58) ------------------------------
// spec/format.md: "File-count and total-uncompressed-size limits are
// configurable on the reader; defaults are 10,000 entries and 1 GiB."
// The module constants are defaults, not a ceiling baked into the code.

test("unpackZip honors caller-supplied reader limits", async () => {
  const packed = await packZip(
    new Map([
      ["a.txt", Buffer.from("aaa")],
      ["b.txt", Buffer.from("bbb")],
    ]),
  );
  await assert.rejects(() => unpackZip(packed, { maxEntries: 1 }), /too many entries \(2\)/);
  await assert.rejects(
    () => unpackZip(packed, { maxTotalBytes: 4 }),
    /total-size limit exceeded/,
  );
  const ok = await unpackZip(packed, { maxEntries: 2, maxTotalBytes: 6 });
  assert.deepEqual([...ok.keys()], ["a.txt", "b.txt"]);
});

test("reader limits must be positive integers", async () => {
  const packed = await packZip(new Map([["a.txt", Buffer.from("aaa")]]));
  await assert.rejects(() => unpackZip(packed, { maxEntries: 0 }), /maxEntries must be a positive integer/);
  await assert.rejects(
    () => unpackZip(packed, { maxTotalBytes: 1.5 }),
    /maxTotalBytes must be a positive integer/,
  );
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-js && node --test test/strictness.test.js`

Expected: FAIL with `not ok - unpackZip honors caller-supplied reader limits` and `not ok - reader limits must be positive integers`, both `error: 'Missing expected rejection.'` (the extra options argument is ignored today), `# fail 2`.

- [ ] **Step 3: Replace the module constants with defaults plus a resolver**

In `sdk-js/src/zip.js`, replace lines 13-20:

```js
const FIXED_DATE = new Date(Date.UTC(1980, 0, 1, 0, 0, 0));
const MAX_ENTRIES = 10_000;
const MAX_TOTAL_BYTES = 1024 * 1024 * 1024; // 1 GiB

const EOCD_SIG = 0x06054b50; // end of central directory
const CDH_SIG = 0x02014b50; // central directory file header
const EOCD_MIN = 22; // EOCD size with empty comment
const MAX_COMMENT = 0xffff;
```

with:

```js
const FIXED_DATE = new Date(Date.UTC(1980, 0, 1, 0, 0, 0));

/** Default reader limits. spec/format.md: configurable, with these defaults. */
export const DEFAULT_ZIP_LIMITS = Object.freeze({
  maxEntries: 10_000,
  maxTotalBytes: 1024 * 1024 * 1024, // 1 GiB
});

const EOCD_SIG = 0x06054b50; // end of central directory
const CDH_SIG = 0x02014b50; // central directory file header
const EOCD_MIN = 22; // EOCD size with empty comment
const MAX_COMMENT = 0xffff;

/** Normalize caller-supplied reader limits against the defaults. */
function resolveLimits(options) {
  const { maxEntries = DEFAULT_ZIP_LIMITS.maxEntries, maxTotalBytes = DEFAULT_ZIP_LIMITS.maxTotalBytes } =
    options ?? {};
  if (!Number.isInteger(maxEntries) || maxEntries < 1) {
    throw new Error(`zip limits: maxEntries must be a positive integer, got ${maxEntries}`);
  }
  if (!Number.isInteger(maxTotalBytes) || maxTotalBytes < 1) {
    throw new Error(`zip limits: maxTotalBytes must be a positive integer, got ${maxTotalBytes}`);
  }
  return { maxEntries, maxTotalBytes };
}
```

- [ ] **Step 4: Thread the limits through `scanCentralDirectory`**

Replace (was line 31):

```js
export function scanCentralDirectory(bytes) {
  const buf = Buffer.isBuffer(bytes)
```

with:

```js
export function scanCentralDirectory(bytes, options) {
  const { maxEntries } = resolveLimits(options);
  const buf = Buffer.isBuffer(bytes)
```

Then replace the two `MAX_ENTRIES` references inside it. Was line 69:

```js
  if (totalEntries > MAX_ENTRIES) {
    throw new Error(`zip scan: too many entries (${totalEntries})`);
  }
```

with:

```js
  if (totalEntries > maxEntries) {
    throw new Error(`zip scan: too many entries (${totalEntries})`);
  }
```

and was line 99:

```js
    if (entries.length > MAX_ENTRIES) {
      throw new Error(`zip scan: too many entries (${entries.length})`);
    }
```

with:

```js
    if (entries.length > maxEntries) {
      throw new Error(`zip scan: too many entries (${entries.length})`);
    }
```

- [ ] **Step 5: Thread the limits through `assertStrictEntries` and `packZip`**

Replace (was lines 122-123):

```js
function assertStrictEntries(bytes) {
  const entries = scanCentralDirectory(bytes);
```

with:

```js
function assertStrictEntries(bytes, limits) {
  const entries = scanCentralDirectory(bytes, limits);
```

Replace (was lines 141-142):

```js
export async function packZip(files) {
  if (files.size > MAX_ENTRIES) throw new Error(`zip pack: too many entries (${files.size})`);
```

with:

```js
export async function packZip(files, options) {
  const { maxEntries } = resolveLimits(options);
  if (files.size > maxEntries) throw new Error(`zip pack: too many entries (${files.size})`);
```

- [ ] **Step 6: Thread the limits through `unpackZip`**

Replace (was lines 164-165):

```js
export async function unpackZip(bytes) {
  assertStrictEntries(bytes);
```

with:

```js
export async function unpackZip(bytes, options) {
  const limits = resolveLimits(options);
  assertStrictEntries(bytes, limits);
```

Replace (was line 171):

```js
  if (entries.length > MAX_ENTRIES) throw new Error(`zip unpack: too many entries (${entries.length})`);
```

with:

```js
  if (entries.length > limits.maxEntries) {
    throw new Error(`zip unpack: too many entries (${entries.length})`);
  }
```

Replace (was lines 180-181):

```js
    if (count > MAX_ENTRIES) throw new Error("zip unpack: entry-count limit exceeded");
    if (total > MAX_TOTAL_BYTES) throw new Error("zip unpack: total-size limit exceeded");
```

with:

```js
    if (count > limits.maxEntries) throw new Error("zip unpack: entry-count limit exceeded");
    if (total > limits.maxTotalBytes) throw new Error("zip unpack: total-size limit exceeded");
```

- [ ] **Step 7: Export the new constant and update the TypeScript declarations**

In `sdk-js/src/index.js`, replace line 47:

```js
export { packZip, unpackZip, scanCentralDirectory } from "./zip.js";
```

with:

```js
export { packZip, unpackZip, scanCentralDirectory, DEFAULT_ZIP_LIMITS } from "./zip.js";
```

In `sdk-js/src/index.d.ts`, replace lines 266-270:

```ts
export function packZip(files: Map<string, Uint8Array>): Promise<Uint8Array>;
export function unpackZip(bytes: Uint8Array): Promise<Map<string, Uint8Array>>;
export function scanCentralDirectory(
  bytes: Uint8Array,
): Array<{ name: string; method: number; externalAttrs: number }>;
```

with:

```ts
/** Reader limits; see spec/format.md "Container properties". */
export interface ZipLimits {
  maxEntries?: number;
  maxTotalBytes?: number;
}
export const DEFAULT_ZIP_LIMITS: Readonly<{ maxEntries: number; maxTotalBytes: number }>;
export function packZip(files: Map<string, Uint8Array>, options?: ZipLimits): Promise<Uint8Array>;
export function unpackZip(
  bytes: Uint8Array,
  options?: ZipLimits,
): Promise<Map<string, Uint8Array>>;
export function scanCentralDirectory(
  bytes: Uint8Array,
  options?: ZipLimits,
): Array<{ name: string; method: number; externalAttrs: number }>;
```

- [ ] **Step 8: Run the test to verify it passes**

Run: `cd sdk-js && node --test test/strictness.test.js`

Expected: PASS — `# tests 23 / # pass 23 / # fail 0`

- [ ] **Step 9: Run the full lane suite for regressions**

Run: `cd sdk-js && npm test`

Expected: `# tests 59 / # pass 59 / # fail 0`

- [ ] **Step 10: Commit**

```bash
git add sdk-js/src/zip.js sdk-js/src/index.js sdk-js/src/index.d.ts sdk-js/test/strictness.test.js
git commit -m "feat(sdk-js): make ZIP reader entry/size limits configurable

spec/format.md already declares the 10,000-entry and 1 GiB caps as
reader-configurable defaults; they were hard-coded module constants.
packZip/unpackZip/scanCentralDirectory now take an optional
{maxEntries, maxTotalBytes}, validated as positive integers, with
DEFAULT_ZIP_LIMITS exported. Closes F58."
```

---

### Task 2: Reject ambiguous directory markers in sdk-js (F01)

**Files:**
- Modify: `sdk-js/tools/rawzip.mjs:36-55`, `sdk-js/tools/rawzip.mjs` (extAttrs line)
- Modify: `sdk-js/src/zip.js` (constants block, `scanCentralDirectory` record read, `assertStrictEntries`)
- Test: `sdk-js/test/strictness.test.js`

**Interfaces:**
- Consumes: `resolveLimits`, `assertStrictEntries(bytes, limits)`, `scanCentralDirectory(bytes, options)` from Task 1
- Produces: `writeRawZip` entries accept `dosAttrs?: number`; `scanCentralDirectory` records gain `compressedSize` and `size`; `DOS_DIR_ATTR` constant

- [ ] **Step 1: Give the hostile ZIP writer control of the DOS attribute byte**

`sdk-js/tools/rawzip.mjs` is the guardrail-free writer used by strictness tests and the vector generator. Replace, in the `writeRawZip` doc comment:

```js
 *     mode?: number  // Unix mode bits for external attrs, e.g. 0o120777
 *   }
```

with:

```js
 *     mode?: number,     // Unix mode bits for external attrs, e.g. 0o120777
 *     dosAttrs?: number  // low 16 bits of external attrs (the DOS attribute
 *                        // byte); 0x10 is the DOS "directory" flag, which
 *                        // JSZip trusts over the entry name
 *   }
```

and replace:

```js
    const extAttrs = e.mode !== undefined ? (e.mode << 16) >>> 0 : 0;
```

with:

```js
    const extAttrs = ((((e.mode ?? 0) << 16) | (e.dosAttrs ?? 0)) & 0xffffffff) >>> 0;
```

This is byte-identical for every existing caller (`mode` unset and `dosAttrs` unset both yield 0).

- [ ] **Step 2: Write the failing test**

Append to `sdk-js/test/strictness.test.js`. All identifiers used (`CapsuleBuilder`, `CapsuleReader`, `verifyCapsule`, `generateEd25519`, `unpackZip`, `TS`) are already imported/declared at lines 11-21.

```js

// --- Authoritative entry set (findings F01 / F11) --------------------------
// The raw central-directory scan is the single source of truth for which
// entries a capsule contains. JSZip derives entry.dir from the DOS directory
// attribute (node_modules/jszip/lib/zipEntry.js processAttributes) and
// re-keys entries by their LOCAL header name, so both must be pinned to the
// central directory or a signed capsule can hide a file from the JS reader
// that unzip(1) and python zipfile happily extract.

function sealedEntries(files) {
  return [...files.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([name, data]) => ({ name, data: Buffer.from(data) }));
}

async function sealedCapsule() {
  const ed = generateEd25519();
  const b = new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex, label: "Acme" },
    participants: [{ actor_id: "human:alice", role: "originator", label: "Alice" }],
    createdAt: TS,
  });
  b.setProgram("# Program\n");
  b.appendEvent({
    actor: "human:alice",
    kind: "decision",
    action: "submit",
    target: "program.md",
    timestamp: TS,
    payload: {},
  });
  const bytes = await b.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  return { bytes, ed };
}

test("a DOS-dir-bit entry cannot smuggle a file past verifyCapsule", async () => {
  const { writeRawZip } = await import("../tools/rawzip.mjs");
  const { bytes, ed } = await sealedCapsule();
  const entries = sealedEntries(await unpackZip(bytes));
  // externalAttrs = 0x10 is the DOS "directory" bit. JSZip reports
  // entry.dir === true for it regardless of the name; unzip(1) and python
  // zipfile see a plain 17-byte file called smuggled.md.
  const forged = writeRawZip([
    ...entries,
    { name: "smuggled.md", data: Buffer.from("# hidden payload\n", "utf8"), dosAttrs: 0x10 },
  ]);
  await assert.rejects(
    () => unpackZip(forged),
    /directory attribute on non-directory name: smuggled\.md/,
  );
  await assert.rejects(() => CapsuleReader.fromBytes(forged), /smuggled\.md/);
  // And the capsule must never verify ok with a trusted signer.
  let verified = null;
  try {
    verified = await verifyCapsule(await CapsuleReader.fromBytes(forged), {
      allowlist: [ed.publicKeyHex],
    });
  } catch {
    verified = null;
  }
  assert.equal(verified, null, "forged capsule must not open, let alone verify");
});

test("unpackZip rejects a directory marker with nonzero size", async () => {
  const { writeRawZip } = await import("../tools/rawzip.mjs");
  const forged = writeRawZip([
    { name: "a.txt", data: "a" },
    { name: "dir/", data: Buffer.from("not really a directory\n", "utf8"), dosAttrs: 0x10 },
  ]);
  await assert.rejects(() => unpackZip(forged), /directory marker with nonzero size: dir\//);
});
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd sdk-js && node --test test/strictness.test.js`

Expected: FAIL with `not ok - a DOS-dir-bit entry cannot smuggle a file past verifyCapsule` and `not ok - unpackZip rejects a directory marker with nonzero size`, both `error: 'Missing expected rejection.'`, `# fail 2`.

- [ ] **Step 4: Add the DOS directory-attribute constant**

In `sdk-js/src/zip.js`, replace:

```js
const EOCD_MIN = 22; // EOCD size with empty comment
const MAX_COMMENT = 0xffff;
```

with:

```js
const EOCD_MIN = 22; // EOCD size with empty comment
const MAX_COMMENT = 0xffff;
const DOS_DIR_ATTR = 0x10; // DOS "directory" bit in the low external attrs
```

- [ ] **Step 5: Surface the declared sizes from the central-directory scan**

In `scanCentralDirectory`, replace:

```js
    const method = buf.readUInt16LE(p + 10);
    const nameLen = buf.readUInt16LE(p + 28);
```

with:

```js
    const method = buf.readUInt16LE(p + 10);
    const compressedSize = buf.readUInt32LE(p + 20);
    const size = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
```

and replace:

```js
    entries.push({ name, method, externalAttrs });
```

with:

```js
    entries.push({ name, method, compressedSize, size, externalAttrs });
```

Update the function's doc comment: replace

```js
 * Returns [{ name, method, externalAttrs }] for every central-directory
 * record (including directory markers). Throws on structural problems:
```

with

```js
 * Returns [{ name, method, compressedSize, size, externalAttrs }] for every
 * central-directory record (including directory markers). Throws on
 * structural problems:
```

- [ ] **Step 6: Reject both ambiguous directory shapes**

In `assertStrictEntries`, replace:

```js
    assertSafePath(e.name);
    if (e.name.endsWith("/")) continue; // directory marker
    if (e.method !== 0) {
```

with:

```js
    assertSafePath(e.name);
    const isDirName = e.name.endsWith("/");
    // JSZip derives entry.dir from the DOS directory attribute, not the
    // name, so a dir-bit entry with a plain file name is silently dropped
    // by JSZip while unzip(1) and python zipfile extract it as a file.
    if ((e.externalAttrs & DOS_DIR_ATTR) !== 0 && !isDirName) {
      throw new Error(`zip unpack: directory attribute on non-directory name: ${e.name}`);
    }
    if (isDirName) {
      // A "/"-terminated name carrying content is the mirror image of the
      // same differential: readers that key on the name drop the body.
      if (e.size !== 0 || e.compressedSize !== 0) {
        throw new Error(`zip unpack: directory marker with nonzero size: ${e.name}`);
      }
      continue; // directory marker
    }
    if (e.method !== 0) {
```

Also extend the `assertStrictEntries` doc comment: replace

```js
 *   - symlink entries (Unix mode bits in external attrs)
 */
```

with

```js
 *   - symlink entries (Unix mode bits in external attrs)
 *   - ambiguous directory markers (DOS dir bit on a non-"/" name, or a
 *     "/"-terminated name carrying content)
 */
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `cd sdk-js && node --test test/strictness.test.js`

Expected: PASS — `# tests 25 / # pass 25 / # fail 0`

- [ ] **Step 8: Run the full lane suite for regressions**

Run: `cd sdk-js && npm test`

Expected: `# tests 61 / # pass 61 / # fail 0`

- [ ] **Step 9: Commit**

```bash
git add sdk-js/src/zip.js sdk-js/tools/rawzip.mjs sdk-js/test/strictness.test.js
git commit -m "fix(sdk-js): reject ambiguous ZIP directory markers

JSZip sets entry.dir from the DOS directory attribute (0x10) rather than
the entry name, so an entry named smuggled.md with that bit set was
dropped before content-index recomputation while unzip(1) and python
zipfile extracted it — verifyCapsule returned ok:true with a trusted
signer over a capsule containing an unindexed file. Reject the DOS dir
bit on a non-'/' name, and the mirror shape of a '/'-terminated name
declaring a nonzero size. Closes F01."
```

---

### Task 3: Bind the extracted entry set to the central directory in sdk-js (F11)

**Files:**
- Modify: `sdk-js/tools/rawzip.mjs` (doc comment, `localNameBytes`, LFH write, offset accounting)
- Modify: `sdk-js/src/zip.js` (`LFH_SIG`, `readLocalName`, `scanCentralDirectory` record read, `assertStrictEntries`, `unpackZip`)
- Modify: `sdk-js/src/index.d.ts` (`scanCentralDirectory` return type)
- Test: `sdk-js/test/strictness.test.js`

**Interfaces:**
- Consumes: `resolveLimits` (Task 1), `DOS_DIR_ATTR` and the size fields (Task 2)
- Produces: `readLocalName(buf, offset, index) -> string`; `scanCentralDirectory` records gain `localName` and `localHeaderOffset`; `assertStrictEntries(bytes, limits) -> Set<string>` (the authoritative non-directory name set)

- [ ] **Step 1: Give the hostile ZIP writer an independent local-header name**

In `sdk-js/tools/rawzip.mjs`, replace:

```js
 *     dosAttrs?: number  // low 16 bits of external attrs (the DOS attribute
 *                        // byte); 0x10 is the DOS "directory" flag, which
 *                        // JSZip trusts over the entry name
 *   }
```

with:

```js
 *     dosAttrs?: number, // low 16 bits of external attrs (the DOS attribute
 *                        // byte); 0x10 is the DOS "directory" flag, which
 *                        // JSZip trusts over the entry name
 *     localName?: string // name written in the LOCAL file header when it must
 *                        // differ from the central-directory name; defaults
 *                        // to `name`
 *   }
```

Replace:

```js
    const nameBytes = Buffer.from(e.name, "utf8");
    const data = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data ?? "");
```

with:

```js
    const nameBytes = Buffer.from(e.name, "utf8");
    const localNameBytes = Buffer.from(e.localName ?? e.name, "utf8");
    const data = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data ?? "");
```

Replace:

```js
    lfh.writeUInt16LE(nameBytes.length, 26);
    lfh.writeUInt16LE(0, 28); // extra len
    locals.push(lfh, nameBytes, body);
```

with:

```js
    lfh.writeUInt16LE(localNameBytes.length, 26);
    lfh.writeUInt16LE(0, 28); // extra len
    locals.push(lfh, localNameBytes, body);
```

Replace:

```js
    offset += 30 + nameBytes.length + body.length;
```

with:

```js
    offset += 30 + localNameBytes.length + body.length;
```

- [ ] **Step 2: Write the failing test**

Append to `sdk-js/test/strictness.test.js` (uses `sealedCapsule`/`sealedEntries` from Task 2):

```js

test("unpackZip rejects a local/central file-name mismatch", async () => {
  const { writeRawZip } = await import("../tools/rawzip.mjs");
  const { bytes } = await sealedCapsule();
  const entries = sealedEntries(await unpackZip(bytes));
  // Central directory says notes.md; the local header says program.md.
  // JSZip keys zip.files by the LOCAL name, so without this check the real
  // program.md is silently replaced by the attacker's body.
  const forged = writeRawZip([
    ...entries,
    { name: "notes.md", localName: "program.md", data: Buffer.from("# EVIL\n", "utf8") },
  ]);
  await assert.rejects(
    () => unpackZip(forged),
    /local\/central name mismatch: central "notes\.md", local "program\.md"/,
  );
});

test("unpackZip rejects a local name that resolves to a third path", async () => {
  const { writeRawZip } = await import("../tools/rawzip.mjs");
  const forged = writeRawZip([
    { name: "a.txt", data: "a" },
    { name: "notes.md", localName: "../../evil.md", data: "pwned\n" },
  ]);
  await assert.rejects(
    () => unpackZip(forged),
    /local\/central name mismatch: central "notes\.md", local "\.\.\/\.\.\/evil\.md"/,
  );
});
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd sdk-js && node --test test/strictness.test.js`

Expected: FAIL with `not ok - unpackZip rejects a local/central file-name mismatch` and `not ok - unpackZip rejects a local name that resolves to a third path`, both `error: 'Missing expected rejection.'`, `# fail 2`.

- [ ] **Step 4: Add the local-file-header signature and reader**

In `sdk-js/src/zip.js`, replace:

```js
const CDH_SIG = 0x02014b50; // central directory file header
const EOCD_MIN = 22; // EOCD size with empty comment
```

with:

```js
const CDH_SIG = 0x02014b50; // central directory file header
const LFH_SIG = 0x04034b50; // local file header
const EOCD_MIN = 22; // EOCD size with empty comment
```

Insert this function immediately above the `assertStrictEntries` doc comment (i.e. after `scanCentralDirectory`'s closing brace):

```js
/**
 * Read the file name out of the LOCAL file header at `offset`.
 *
 * JSZip overwrites each entry's name from the local header (see
 * zipEntry.js readLocalPart) and keys `zip.files` by that name, so the
 * central directory alone does not tell us what JSZip will extract. We
 * read the local name here so the strictness pass can require the two to
 * agree.
 */
function readLocalName(buf, offset, index) {
  if (offset + 30 > buf.length || buf.readUInt32LE(offset) !== LFH_SIG) {
    throw new Error(`zip scan: missing local file header for record ${index}`);
  }
  const nameLen = buf.readUInt16LE(offset + 26);
  const end = offset + 30 + nameLen;
  if (end > buf.length) {
    throw new Error(`zip scan: truncated local file header for record ${index}`);
  }
  return buf.toString("utf8", offset + 30, end);
}
```

- [ ] **Step 5: Surface the local name from the central-directory scan**

In `scanCentralDirectory`, replace:

```js
    const externalAttrs = buf.readUInt32LE(p + 38);
    const next = p + 46 + nameLen + extraLen + commentLen;
```

with:

```js
    const externalAttrs = buf.readUInt32LE(p + 38);
    const localHeaderOffset = buf.readUInt32LE(p + 42);
    const next = p + 46 + nameLen + extraLen + commentLen;
```

and replace:

```js
    const name = buf.toString("utf8", p + 46, p + 46 + nameLen);
    entries.push({ name, method, compressedSize, size, externalAttrs });
```

with:

```js
    const name = buf.toString("utf8", p + 46, p + 46 + nameLen);
    const localName = readLocalName(buf, localHeaderOffset, i);
    entries.push({ name, localName, method, compressedSize, size, externalAttrs, localHeaderOffset });
```

Update the doc comment: replace

```js
 * Returns [{ name, method, compressedSize, size, externalAttrs }] for every
 * central-directory record (including directory markers). Throws on
 * structural problems:
```

with

```js
 * Returns [{ name, localName, method, compressedSize, size, externalAttrs,
 * localHeaderOffset }] for every central-directory record (including
 * directory markers); `localName` is read from the entry's local file
 * header. Throws on structural problems:
```

- [ ] **Step 6: Require name agreement and return the authoritative set**

In `assertStrictEntries`, replace:

```js
function assertStrictEntries(bytes, limits) {
  const entries = scanCentralDirectory(bytes, limits);
  const seen = new Set();
  for (const e of entries) {
    if (seen.has(e.name)) throw new Error(`zip unpack: duplicate entry: ${e.name}`);
    seen.add(e.name);
    assertSafePath(e.name);
    const isDirName = e.name.endsWith("/");
```

with:

```js
function assertStrictEntries(bytes, limits) {
  const entries = scanCentralDirectory(bytes, limits);
  const seen = new Set();
  const expected = new Set();
  for (const e of entries) {
    if (seen.has(e.name)) throw new Error(`zip unpack: duplicate entry: ${e.name}`);
    seen.add(e.name);
    assertSafePath(e.name);
    // The central directory is authoritative. JSZip re-reads the name from
    // the local header and keys zip.files by it, so any disagreement means
    // the two parsers see different entry sets.
    if (e.localName !== e.name) {
      throw new Error(
        `zip unpack: local/central name mismatch: central ${JSON.stringify(e.name)}, ` +
          `local ${JSON.stringify(e.localName)}`,
      );
    }
    const isDirName = e.name.endsWith("/");
```

and replace the tail of the same function:

```js
    const mode = (e.externalAttrs >>> 16) & 0xffff;
    if ((mode & 0o170000) === 0o120000) {
      throw new Error(`zip entry is a symlink: ${e.name}`);
    }
  }
}
```

with:

```js
    const mode = (e.externalAttrs >>> 16) & 0xffff;
    if ((mode & 0o170000) === 0o120000) {
      throw new Error(`zip entry is a symlink: ${e.name}`);
    }
    expected.add(e.name);
  }
  return expected;
}
```

Extend the doc comment: replace

```js
 *   - ambiguous directory markers (DOS dir bit on a non-"/" name, or a
 *     "/"-terminated name carrying content)
 */
```

with

```js
 *   - local/central file-name disagreement
 *   - ambiguous directory markers (DOS dir bit on a non-"/" name, or a
 *     "/"-terminated name carrying content)
 *
 * Returns the authoritative Set of non-directory entry names.
 */
```

- [ ] **Step 7: Assert the extracted set equals the authoritative set**

In `unpackZip`, replace:

```js
  const limits = resolveLimits(options);
  assertStrictEntries(bytes, limits);
```

with:

```js
  const limits = resolveLimits(options);
  // The raw central-directory scan is the single authoritative source of
  // the entry set; `expected` is the set of file names it admits.
  const expected = assertStrictEntries(bytes, limits);
```

Replace:

```js
    if (entry.dir) continue;
    assertSafePath(path);
    const data = await entry.async("uint8array");
```

with:

```js
    if (entry.dir) continue;
    assertSafePath(path);
    if (!expected.has(path)) {
      throw new Error(`zip unpack: entry not in central directory: ${path}`);
    }
    const data = await entry.async("uint8array");
```

Replace:

```js
    out.set(path, data);
  }
  return out;
}
```

with:

```js
    out.set(path, data);
  }
  // Every central-directory file entry must have been extracted. A name the
  // scan admitted but JSZip dropped is the smuggling direction of the same
  // parser differential.
  if (out.size !== expected.size) {
    const missing = [...expected].filter((n) => !out.has(n)).sort();
    throw new Error(`zip unpack: central-directory entry not extracted: ${missing.join(", ")}`);
  }
  return out;
}
```

Finally, update the module header comment: replace

```js
// directory before JSZip parses anything).
```

with

```js
// directory before JSZip parses anything).
//
// The raw central-directory scan is the AUTHORITATIVE entry set. JSZip
// decides directory-ness from the DOS attribute bit and re-keys entries
// by their local-header name, so unpackZip both rejects the shapes that
// let the two parsers disagree and asserts that what it extracted is
// exactly what the scan admitted.
```

- [ ] **Step 8: Update the `scanCentralDirectory` declaration**

In `sdk-js/src/index.d.ts`, replace:

```ts
export function scanCentralDirectory(
  bytes: Uint8Array,
  options?: ZipLimits,
): Array<{ name: string; method: number; externalAttrs: number }>;
```

with:

```ts
export function scanCentralDirectory(
  bytes: Uint8Array,
  options?: ZipLimits,
): Array<{
  name: string;
  localName: string;
  method: number;
  compressedSize: number;
  size: number;
  externalAttrs: number;
  localHeaderOffset: number;
}>;
```

- [ ] **Step 9: Run the test to verify it passes**

Run: `cd sdk-js && node --test test/strictness.test.js`

Expected: PASS — `# tests 27 / # pass 27 / # fail 0`

- [ ] **Step 10: Run the full lane suite for regressions**

Run: `cd sdk-js && npm test`

Expected: `# tests 63 / # pass 63 / # fail 0`

- [ ] **Step 11: Run the JS conformance harness**

Run: `node tools/run-conformance.mjs`

Expected: `PASS · 10/10 passed`

- [ ] **Step 12: Commit**

```bash
git add sdk-js/src/zip.js sdk-js/src/index.d.ts sdk-js/tools/rawzip.mjs sdk-js/test/strictness.test.js
git commit -m "fix(sdk-js): make the central directory the authoritative entry set

JSZip overwrites each entry name from the LOCAL file header
(zipEntry.js readLocalPart) and keys zip.files by it, so the
central-directory strictness scan and extraction ran over different name
sets: colliding local names replaced a real file last-wins, and a local
name of ../../evil.md silently resolved to a third path. The scan now
requires local and central names to agree and returns the authoritative
name set, and unpackZip asserts the extracted keys match it exactly.
Closes F11."
```

---

### Task 4: Bring verifier-rust to the same entry-set contract (F67)

**Files:**
- Modify: `verifier-rust/crates/capsule-verify/src/zip_reader.rs:90-92` (error enum), `:144-147` (constants), `:157-168` (scan doc + signature), `:187`, `:284-311` (record body), `:317` (return), `:280`, `:299-305` (dir skip), `:317-319`, `:367-372` (post-loop)
- Test: `verifier-rust/crates/capsule-verify/src/zip_reader.rs` (in-file `mod tests`, above `safe_path_predicate_unit_cases` at line 636)

**Interfaces:**
- Consumes: none (mirrors the sdk-js contract, no code dependency)
- Produces: `scan_central_directory(bytes) -> Result<BTreeSet<String>, ZipError>` (replaces `scan_duplicate_names`); `ZipError::DirectoryMarkerShape`, `ZipError::LocalCentralNameMismatch`, `ZipError::EntrySetMismatch`

- [ ] **Step 1: Write the failing test**

In `verifier-rust/crates/capsule-verify/src/zip_reader.rs`, insert immediately above `    #[test]\n    fn safe_path_predicate_unit_cases() {` (line 636). These assert on `to_string()` so they compile against the current API.

```rust
    /// Locate `(cd_offset, cd_size)` in an archive with no trailing comment.
    fn central_dir_span(bytes: &[u8]) -> (usize, usize) {
        let eocd = bytes.len() - 22;
        let cd_size = u32::from_le_bytes(bytes[eocd + 12..eocd + 16].try_into().unwrap()) as usize;
        let cd_offset = u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
        (cd_offset, cd_size)
    }

    #[test]
    fn rejects_dos_directory_attribute_on_file_name() {
        // The zip crate's writer never sets the DOS directory bit on a plain
        // file, so forge it: OR 0x10 into the first central record's external
        // attributes. JSZip reports entry.dir == true for this shape and drops
        // the entry; unzip(1) and python zipfile extract it as a 5-byte file.
        let mut bytes = make_zip(&[("smuggled.md", b"hello", CompressionMethod::Stored)]);
        let (cd_offset, _) = central_dir_span(&bytes);
        bytes[cd_offset + 38] |= 0x10;

        let err = unpack_zip(&bytes).expect_err("must reject DOS dir bit on a file name");
        let msg = err.to_string();
        assert!(
            msg.contains("directory marker shape") && msg.contains("smuggled.md"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn rejects_directory_marker_with_content() {
        // Write "notesx" (6 bytes) then rename both copies of the name to
        // "notes/" in place, so the archive keeps every offset valid while
        // declaring a `/`-terminated entry that carries 5 content bytes.
        let mut bytes = make_zip(&[("notesx", b"hello", CompressionMethod::Stored)]);
        let (cd_offset, _) = central_dir_span(&bytes);
        bytes[30..36].copy_from_slice(b"notes/");
        bytes[cd_offset + 46..cd_offset + 52].copy_from_slice(b"notes/");

        let err = unpack_zip(&bytes).expect_err("must reject a sized directory marker");
        let msg = err.to_string();
        assert!(
            msg.contains("directory marker shape") && msg.contains("5 content bytes"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn rejects_local_central_name_mismatch() {
        // Same-length rename of the LOCAL header only, so all offsets stay
        // valid: central says "notes.md", local says "evilx.md".
        let mut bytes = make_zip(&[("notes.md", b"hello", CompressionMethod::Stored)]);
        bytes[30..38].copy_from_slice(b"evilx.md");

        let err = unpack_zip(&bytes).expect_err("must reject local/central name mismatch");
        let msg = err.to_string();
        assert!(
            msg.contains("local/central name mismatch")
                && msg.contains("notes.md")
                && msg.contains("evilx.md"),
            "unexpected error: {msg}"
        );
    }

```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd verifier-rust && cargo test --workspace`

Expected: FAIL — `test result: FAILED. 102 passed; 3 failed`, with `panicked at ...: must reject DOS dir bit on a file name: {"smuggled.md": [104, 101, 108, 108, 111]}` and the two other `expect_err` panics.

- [ ] **Step 3: Add the three new error variants**

In `zip_reader.rs`, replace lines 90-92:

```rust
    /// Total uncompressed bytes exceeds `MAX_TOTAL_BYTES`.
    #[error("archive too large: {total} bytes (max {MAX_TOTAL_BYTES})")]
    TooLarge { total: u64 },
```

with:

```rust
    /// Total uncompressed bytes exceeds `MAX_TOTAL_BYTES`.
    #[error("archive too large: {total} bytes (max {MAX_TOTAL_BYTES})")]
    TooLarge { total: u64 },

    /// The entry's shape makes ZIP readers disagree about whether it is a
    /// directory: the DOS directory attribute is set on a name that does
    /// not end in `/`, or a `/`-terminated name declares a nonzero size.
    #[error("directory marker shape for {path:?}: {detail}")]
    DirectoryMarkerShape { path: String, detail: String },

    /// The entry's LOCAL file-header name differs from its
    /// central-directory name, so readers that key on the local header see
    /// a different entry set.
    #[error("local/central name mismatch: central {central:?}, local {local:?}")]
    LocalCentralNameMismatch { central: String, local: String },

    /// The set of entries actually extracted does not match the set the
    /// central-directory scan admitted.
    #[error("entry set mismatch: {0}")]
    EntrySetMismatch(String),
```

- [ ] **Step 4: Add the local-header signature and DOS attribute constants**

Replace lines 144-147:

```rust
const EOCD_SIG: u32 = 0x0605_4b50;
const CDH_SIG: u32 = 0x0201_4b50;
const EOCD_MIN: usize = 22;
const MAX_COMMENT: usize = 0xffff;
```

with:

```rust
const EOCD_SIG: u32 = 0x0605_4b50;
const CDH_SIG: u32 = 0x0201_4b50;
const LFH_SIG: u32 = 0x0403_4b50;
const EOCD_MIN: usize = 22;
const MAX_COMMENT: usize = 0xffff;
/// DOS "directory" attribute, the low bit ZIP readers such as JSZip use to
/// decide directory-ness instead of the entry name.
const DOS_DIR_ATTR: u32 = 0x10;
```

- [ ] **Step 5: Add the local-name reader and rename the scan to return the entry set**

Replace lines 157-171 (the doc comment and signature of `scan_duplicate_names` through its `bytes.len() < EOCD_MIN` guard):

```rust
/// Detect duplicate entry names by walking the RAW central directory.
///
/// The `zip` crate indexes entries by name and silently keeps one copy
/// when an archive contains duplicates, so the duplicate never surfaces
/// through `ZipArchive` — exactly the parser differential the spec must
/// reject. This scan runs before the crate parses anything.
///
/// Structural errors (no EOCD, truncated directory) return `Ok(())` and
/// are left for `ZipArchive` to report with its own diagnostics; ZIP64
/// sentinel values are rejected here because a capsule can never
/// legitimately need ZIP64 under the entry/size caps.
fn scan_duplicate_names(bytes: &[u8]) -> Result<(), ZipError> {
    if bytes.len() < EOCD_MIN {
        return Ok(());
    }
```

with:

```rust
/// Read the file name out of the LOCAL file header at `offset`.
///
/// The central directory is authoritative for the entry set, but some ZIP
/// readers (JSZip in the JS reference lane) re-key entries by the name in
/// the local header. Reading it here lets the scan require the two to
/// agree, so no reader can be shown a different entry set.
fn read_local_name(bytes: &[u8], offset: usize, index: usize) -> Result<Vec<u8>, ZipError> {
    if offset.saturating_add(30) > bytes.len() || read_u32(bytes, offset) != LFH_SIG {
        return Err(ZipError::InvalidContainer(format!(
            "missing local file header for record {index}"
        )));
    }
    let name_len = read_u16(bytes, offset + 26) as usize;
    let end = offset + 30 + name_len;
    if end > bytes.len() {
        return Err(ZipError::InvalidContainer(format!(
            "truncated local file header for record {index}"
        )));
    }
    Ok(bytes[offset + 30..end].to_vec())
}

/// Walk the RAW central directory and return the authoritative set of
/// non-directory entry names.
///
/// The `zip` crate indexes entries by name and silently keeps one copy
/// when an archive contains duplicates, so the duplicate never surfaces
/// through `ZipArchive` — exactly the parser differential the spec must
/// reject. This scan runs before the crate parses anything, and it is also
/// where the entry set is decided: `unpack_zip` asserts that what it
/// extracted matches this set exactly.
///
/// Structural errors (no EOCD, truncated directory) return an empty set
/// and are left for `ZipArchive` to report with its own diagnostics; ZIP64
/// sentinel values are rejected here because a capsule can never
/// legitimately need ZIP64 under the entry/size caps.
fn scan_central_directory(bytes: &[u8]) -> Result<std::collections::BTreeSet<String>, ZipError> {
    let mut names = std::collections::BTreeSet::new();
    if bytes.len() < EOCD_MIN {
        return Ok(names);
    }
```

Then replace the early return (was line 187):

```rust
    let Some(eocd) = eocd else { return Ok(()) };
```

with:

```rust
    let Some(eocd) = eocd else { return Ok(names) };
```

and the final return (was line 317):

```rust
    Ok(())
}
```

with:

```rust
    Ok(names)
}
```

- [ ] **Step 6: Enforce the three checks inside the record loop**

Replace (was lines 284-310, from `let name_len` through `p = next;`):

```rust
        let name_len = read_u16(bytes, p + 28) as usize;
        let extra_len = read_u16(bytes, p + 30) as usize;
        let comment_len = read_u16(bytes, p + 32) as usize;
        let next = p
```

with:

```rust
        let compressed_size = read_u32(bytes, p + 20);
        let uncompressed_size = read_u32(bytes, p + 24);
        let name_len = read_u16(bytes, p + 28) as usize;
        let extra_len = read_u16(bytes, p + 30) as usize;
        let comment_len = read_u16(bytes, p + 32) as usize;
        let external_attrs = read_u32(bytes, p + 38);
        let local_header_offset = read_u32(bytes, p + 42) as usize;
        let next = p
```

and replace:

```rust
        let name = &bytes[p + 46..p + 46 + name_len];
        if !seen.insert(name) {
            return Err(ZipError::DuplicateEntry(
                String::from_utf8_lossy(name).into_owned(),
            ));
        }
        actual_entries += 1;
```

with:

```rust
        let name = &bytes[p + 46..p + 46 + name_len];
        if !seen.insert(name) {
            return Err(ZipError::DuplicateEntry(
                String::from_utf8_lossy(name).into_owned(),
            ));
        }
        let name_str = String::from_utf8_lossy(name).into_owned();

        // The central directory is authoritative. A reader that keys entries
        // by the LOCAL header name sees a different set, so require equality.
        let local_name = read_local_name(bytes, local_header_offset, actual_entries)?;
        if local_name != name {
            return Err(ZipError::LocalCentralNameMismatch {
                central: name_str,
                local: String::from_utf8_lossy(&local_name).into_owned(),
            });
        }

        // Directory-ness must be unambiguous: readers disagree about whether
        // it comes from the DOS attribute bit or the trailing `/`.
        let is_dir_name = name_str.ends_with('/');
        if external_attrs & DOS_DIR_ATTR != 0 && !is_dir_name {
            return Err(ZipError::DirectoryMarkerShape {
                path: name_str,
                detail: "DOS directory attribute on a name that does not end in '/'".to_string(),
            });
        }
        if is_dir_name && (uncompressed_size != 0 || compressed_size != 0) {
            return Err(ZipError::DirectoryMarkerShape {
                path: name_str,
                detail: format!("directory name declares {uncompressed_size} content bytes"),
            });
        }
        if !is_dir_name {
            names.insert(name_str);
        }

        actual_entries += 1;
```

- [ ] **Step 7: Bind `unpack_zip` to the scanned set and fix the directory skip**

Replace (was line 280):

```rust
    scan_duplicate_names(bytes)?;
```

with:

```rust
    let expected = scan_central_directory(bytes)?;
```

Replace (was lines 299-305) — this is the F67 divergence:

```rust
        // Skip pure directory markers: name ends with `/` and zero size.
        // We deliberately do NOT use `entry.is_dir()` alone, since the JS
        // reference treats directory-ness as a name suffix; pairing it with
        // size==0 keeps the contract identical to JS.
        if name.ends_with('/') && entry.size() == 0 {
            continue;
        }
```

with:

```rust
        // Skip directory markers by NAME only, matching the JS reference
        // (sdk-js/src/zip.js assertStrictEntries). The old `&& entry.size()
        // == 0` guard diverged from JS: a `/`-terminated entry carrying
        // content was skipped there and read here. That shape is now
        // rejected outright by `scan_central_directory`, so the name test
        // alone is both sufficient and identical across the two lanes.
        if name.ends_with('/') {
            continue;
        }
```

Replace:

```rust
        if let Err(reason) = check_safe_path(&name) {
            return Err(ZipError::UnsafePath { path: name, reason });
        }

        let method = entry.compression();
```

with:

```rust
        if let Err(reason) = check_safe_path(&name) {
            return Err(ZipError::UnsafePath { path: name, reason });
        }

        // The raw scan already decided the entry set; anything else the
        // crate surfaces here is a parser disagreement.
        if !expected.contains(&name) {
            return Err(ZipError::EntrySetMismatch(format!(
                "entry not in central directory: {name}"
            )));
        }

        let method = entry.compression();
```

Replace (was lines 367-372):

```rust
        if out.insert(name.clone(), buf).is_some() {
            return Err(ZipError::DuplicateEntry(name));
        }
    }

    Ok(out)
}
```

with:

```rust
        if out.insert(name.clone(), buf).is_some() {
            return Err(ZipError::DuplicateEntry(name));
        }
    }

    // Every central-directory file entry must have been extracted. A name
    // the scan admitted but the crate dropped is the smuggling direction of
    // the same parser differential.
    if out.len() != expected.len() {
        let missing: Vec<&str> = expected
            .iter()
            .filter(|n| !out.contains_key(n.as_str()))
            .map(|n| n.as_str())
            .collect();
        return Err(ZipError::EntrySetMismatch(format!(
            "central-directory entries not extracted: {}",
            missing.join(", ")
        )));
    }

    Ok(out)
}
```

- [ ] **Step 8: Run the test to verify it passes**

Run: `cd verifier-rust && cargo test --workspace zip_reader`

Expected: PASS — `rejects_dos_directory_attribute_on_file_name ... ok`, `rejects_directory_marker_with_content ... ok`, `rejects_local_central_name_mismatch ... ok`

- [ ] **Step 9: Run the full lane suite for regressions**

Run: `cd verifier-rust && cargo test --workspace`

Expected: `test result: ok. 105 passed; 0 failed` for the `capsule_verify` unit target, and `ok` (7 passed / 3 passed / 0 failed) for the parity and registry integration targets.

- [ ] **Step 10: Commit**

```bash
git add verifier-rust/crates/capsule-verify/src/zip_reader.rs
git commit -m "fix(verifier-rust): match the JS entry-set contract exactly

The reader skipped a directory marker only when the name ended in '/'
AND the declared size was 0, so a '/'-terminated entry carrying content
was read here and skipped by JS. Reject that shape (and the DOS
directory bit on a non-'/' name, and a local/central name mismatch) in
the raw central-directory scan, make the scan return the authoritative
entry-name set, assert the extracted map matches it, and skip directory
markers by name only. Closes F67."
```

---

### Task 5: Enforce the same entry-set contract in sdk-py

Required by Task 6: the new open-stage vectors are executed by `sdk-py/tests/test_spec_registry.py`. Measured today, sdk-py returns `verify ok = True` for the `dir-marker-with-content` shape, so this is an independent smuggle, not only a parity gap.

**Files:**
- Modify: `sdk-py/src/capsule/zip_io.py:9-15` (constants + helper), `sdk-py/src/capsule/zip_io.py:63-66` (loop head)
- Test: `sdk-py/tests/test_zip_io.py`

**Interfaces:**
- Consumes: none
- Produces: `_assert_local_name(data: bytes, zi: zipfile.ZipInfo) -> None`; `_LFH_SIG`, `_DOS_DIR_ATTR` module constants

- [ ] **Step 1: Write the failing test**

Append to `sdk-py/tests/test_zip_io.py`. `io`, `zipfile`, `pytest` and `unpack_zip` are already imported at the top of the file.

```python


def test_unpack_rejects_dos_directory_attribute_on_file_name():
    # external_attr bit 0x10 is the DOS "directory" flag. Readers that decide
    # directory-ness from it (JSZip) drop the entry; python zipfile and
    # unzip(1) extract it as a real file. Reject the disagreement.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zi = zipfile.ZipInfo("smuggled.md")
        zi.compress_type = zipfile.ZIP_STORED
        zi.external_attr = 0x10
        zf.writestr(zi, "# hidden payload\n")
    with pytest.raises(
        ValueError, match=r"directory attribute on non-directory name: smuggled\.md"
    ):
        unpack_zip(buf.getvalue())


def test_unpack_rejects_directory_marker_with_content():
    # The mirror image: a "/"-terminated name that carries content.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zi = zipfile.ZipInfo("notes/")
        zi.compress_type = zipfile.ZIP_STORED
        zi.external_attr = 0x10
        zf.writestr(zi, "# hidden payload\n")
    with pytest.raises(ValueError, match=r"directory marker with nonzero size: notes/"):
        unpack_zip(buf.getvalue())


def test_unpack_rejects_local_central_name_mismatch():
    # Same-length rename of the LOCAL header only, so every offset stays
    # valid: central says "notes.md", local says "evilx.md". Readers that
    # key entries by the local header see a different entry set.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("notes.md", "hello")
    raw = bytearray(buf.getvalue())
    raw[30:38] = b"evilx.md"
    with pytest.raises(
        ValueError, match=r"local/central name mismatch: central 'notes.md', local 'evilx.md'"
    ):
        unpack_zip(bytes(raw))
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest sdk-py/tests/test_zip_io.py`

Expected: FAIL — `3 failed, 14 passed`. The two directory tests report `Failed: DID NOT RAISE <class 'ValueError'>`; the name-mismatch test raises `zipfile.BadZipFile: File name in directory 'notes.md' and header b'evilx.md' differ.`, which is not a `ValueError` and so is not caught.

- [ ] **Step 3: Add the constants and the local-name assertion**

In `sdk-py/src/capsule/zip_io.py`, replace lines 9-15:

```python
MAX_ENTRIES = 10_000
MAX_TOTAL_BYTES = 1024 * 1024 * 1024  # 1 GiB
_FIXED_DATE = (1980, 1, 1, 0, 0, 0)


class UnsafeZipPathError(ValueError):
    """Raised when a ZIP entry's path would escape, contain a NUL, or be absolute."""
```

with:

```python
MAX_ENTRIES = 10_000
MAX_TOTAL_BYTES = 1024 * 1024 * 1024  # 1 GiB
_FIXED_DATE = (1980, 1, 1, 0, 0, 0)
_LFH_SIG = b"PK\x03\x04"
# DOS "directory" attribute. Some readers (JSZip) decide directory-ness from
# this bit rather than from the trailing "/" in the name.
_DOS_DIR_ATTR = 0x10


class UnsafeZipPathError(ValueError):
    """Raised when a ZIP entry's path would escape, contain a NUL, or be absolute."""


def _assert_local_name(data: bytes, zi: zipfile.ZipInfo) -> None:
    """Require the LOCAL file-header name to equal the central-directory name.

    CPython's zipfile raises BadZipFile for this on read, but BadZipFile is
    not a ValueError and the check is an implementation detail. Do it here so
    every lane rejects the shape with the same category of error.
    """
    off = zi.header_offset
    if off + 30 > len(data) or data[off : off + 4] != _LFH_SIG:
        raise ValueError(f"zip unpack: missing local file header for {zi.filename}")
    name_len = int.from_bytes(data[off + 26 : off + 28], "little")
    end = off + 30 + name_len
    if end > len(data):
        raise ValueError(f"zip unpack: truncated local file header for {zi.filename}")
    local = data[off + 30 : end].decode("utf-8", "replace")
    if local != zi.orig_filename:
        raise ValueError(
            f"zip unpack: local/central name mismatch: "
            f"central {zi.orig_filename!r}, local {local!r}"
        )
```

- [ ] **Step 4: Enforce the checks in the unpack loop**

Replace lines 63-66:

```python
        for zi in sorted(infos, key=lambda x: x.filename):
            if zi.is_dir():
                continue
            _assert_safe_path(zi.filename)
```

with:

```python
        for zi in sorted(infos, key=lambda x: x.filename):
            # The central directory is authoritative for the entry set.
            # Readers disagree about directory-ness (name suffix vs the DOS
            # 0x10 attribute) and about which header supplies the name, so
            # reject every shape where they could disagree.
            _assert_local_name(data, zi)
            is_dir_name = zi.filename.endswith("/")
            if zi.external_attr & _DOS_DIR_ATTR and not is_dir_name:
                raise ValueError(
                    f"zip unpack: directory attribute on non-directory name: {zi.filename}"
                )
            if is_dir_name:
                if zi.file_size != 0 or zi.compress_size != 0:
                    raise ValueError(
                        f"zip unpack: directory marker with nonzero size: {zi.filename}"
                    )
                continue
            _assert_safe_path(zi.filename)
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `python -m pytest sdk-py/tests/test_zip_io.py`

Expected: PASS — `17 passed`

- [ ] **Step 6: Run the full lane suite for regressions**

Run: `python -m pytest sdk-py/tests/`

Expected: `185 passed`

- [ ] **Step 7: Commit**

```bash
git add sdk-py/src/capsule/zip_io.py sdk-py/tests/test_zip_io.py
git commit -m "fix(sdk-py): reject ambiguous directory markers and local-name mismatch

zipfile.ZipInfo.is_dir() is a pure name test, so a '/'-terminated entry
carrying content was skipped here and read by other lanes — a capsule
with that shape verified ok=True. Reject it, reject the DOS directory
attribute on a non-'/' name, and check the LOCAL file-header name
explicitly so the failure is a ValueError rather than CPython's
BadZipFile. Brings sdk-py to the sdk-js entry-set contract."
```

---

### Task 6: Add malformed-layout vectors for both smuggles

Must land after Tasks 3, 4 and 5 — three lanes execute this registry.

**Files:**
- Modify: `sdk-js/tools/generate-malformed-fixtures.mjs:94-98`
- Create: `spec/vectors/malformed-layout/output/dir-bit-smuggle.capsule`
- Create: `spec/vectors/malformed-layout/output/dir-marker-with-content.capsule`
- Create: `spec/vectors/malformed-layout/output/local-name-mismatch.capsule`
- Modify: `spec/vectors/malformed-layout/vectors.json:16`, `spec/vectors/malformed-layout/vectors.json:69-74`
- Modify: `tools/check-spec-vectors.mjs:146`
- Modify: `sdk-py/tests/test_spec_registry.py:42`
- Modify: `verifier-rust/tests/spec_registry.rs:144`
- Modify: `spec/format.md:92-98`
- Modify: `skills/capsule/skill.json` (regenerated)

**Interfaces:**
- Consumes: `writeRawZip` `dosAttrs`/`localName` (Tasks 2, 3); the open-stage rejections from Tasks 3, 4, 5
- Produces: reason categories `directory_marker_shape` and `local_central_name_mismatch`; vectors `dir-bit-smuggle`, `dir-marker-with-content`, `local-name-mismatch`

- [ ] **Step 1: Write the failing test (the registry entries)**

In `spec/vectors/malformed-layout/vectors.json`, replace line 16:

```json
    "symlink_entry": "an entry's Unix mode bits mark it as a symlink",
```

with:

```json
    "symlink_entry": "an entry's Unix mode bits mark it as a symlink",
    "directory_marker_shape": "an entry sets the DOS directory attribute (0x10) on a name that does not end in '/', or a '/'-terminated name declares a nonzero size; either shape makes readers disagree about whether the entry is a file",
    "local_central_name_mismatch": "an entry's LOCAL file-header name differs from its central-directory name, so readers that key entries by the local header extract a different entry set",
```

and replace lines 69-74 (the `symlink-entry` vector and the array close):

```json
    {
      "name": "symlink-entry",
      "capsule_file": "output/symlink-entry.capsule",
      "expected": { "ok": false, "stage": "open", "reason": "symlink_entry", "detail": "link" }
    }
  ]
```

with:

```json
    {
      "name": "symlink-entry",
      "capsule_file": "output/symlink-entry.capsule",
      "expected": { "ok": false, "stage": "open", "reason": "symlink_entry", "detail": "link" }
    },
    {
      "name": "dir-bit-smuggle",
      "capsule_file": "output/dir-bit-smuggle.capsule",
      "expected": { "ok": false, "stage": "open", "reason": "directory_marker_shape", "detail": "smuggled.md" }
    },
    {
      "name": "dir-marker-with-content",
      "capsule_file": "output/dir-marker-with-content.capsule",
      "expected": { "ok": false, "stage": "open", "reason": "directory_marker_shape", "detail": "notes/" }
    },
    {
      "name": "local-name-mismatch",
      "capsule_file": "output/local-name-mismatch.capsule",
      "expected": { "ok": false, "stage": "open", "reason": "local_central_name_mismatch", "detail": "notes.md" }
    }
  ]
```

- [ ] **Step 2: Run the check to verify it fails**

Run: `node tools/check-spec-vectors.mjs`

Expected: FAIL with `spec/vectors/malformed-layout/vectors.json [dir-bit-smuggle]: capsule_file unreadable: ENOENT: no such file or directory, open '.../output/dir-bit-smuggle.capsule'` (and the same for the other two), exit code 1.

- [ ] **Step 3: Add the three fixtures to the deterministic generator**

In `sdk-js/tools/generate-malformed-fixtures.mjs`, replace lines 94-99:

```js
    // Symlink mode bits in external attrs: must reject.
    "symlink-entry.capsule": [
      ...base,
      { name: "link", data: Buffer.from("program.md", "utf8"), mode: 0o120777 },
    ],
  };
```

with:

```js
    // Symlink mode bits in external attrs: must reject.
    "symlink-entry.capsule": [
      ...base,
      { name: "link", data: Buffer.from("program.md", "utf8"), mode: 0o120777 },
    ],

    // DOS directory attribute (0x10) on a name that is not "/"-terminated.
    // Readers that decide directory-ness from the attribute bit (JSZip)
    // drop the entry; readers that decide from the name (unzip(1), python
    // zipfile) extract a 17-byte smuggled.md. Must reject.
    "dir-bit-smuggle.capsule": [
      ...base,
      { name: "smuggled.md", data: Buffer.from("# hidden payload\n", "utf8"), dosAttrs: 0x10 },
    ],

    // A "/"-terminated name carrying content: the mirror image of the same
    // differential. Must reject.
    "dir-marker-with-content.capsule": [
      ...base,
      { name: "notes/", data: Buffer.from("# hidden payload\n", "utf8"), dosAttrs: 0x10 },
    ],

    // Central-directory name and LOCAL file-header name disagree. Readers
    // that key on the local header (JSZip) silently replace program.md with
    // the attacker's body; readers that key on the central directory see an
    // extra notes.md. Must reject.
    "local-name-mismatch.capsule": [
      ...base,
      { name: "notes.md", localName: "program.md", data: Buffer.from("# EVIL program\n", "utf8") },
    ],
  };
```

- [ ] **Step 4: Generate the fixture bytes**

Run: `node sdk-js/tools/generate-malformed-fixtures.mjs`

Expected: `wrote dir-bit-smuggle.capsule (2716 bytes)`, `wrote dir-marker-with-content.capsule (2706 bytes)`, `wrote local-name-mismatch.capsule (2710 bytes)`, plus the ten pre-existing fixtures rewritten byte-identically.

- [ ] **Step 5: Map the new reason categories in the JavaScript harness**

In `tools/check-spec-vectors.mjs`, replace line 146:

```js
  symlink_entry: /symlink/,
};
```

with:

```js
  symlink_entry: /symlink/,
  directory_marker_shape: /directory (attribute on non-directory name|marker with nonzero size)/,
  local_central_name_mismatch: /local\/central name mismatch/,
};
```

- [ ] **Step 6: Map the new reason categories in the Python harness**

In `sdk-py/tests/test_spec_registry.py`, replace line 42:

```python
    "symlink_entry": r"symlink",
}
```

with:

```python
    "symlink_entry": r"symlink",
    "directory_marker_shape": r"directory (attribute on non-directory name|marker with nonzero size)",
    "local_central_name_mismatch": r"local/central name mismatch",
}
```

- [ ] **Step 7: Map the new reason categories in the Rust harness**

In `verifier-rust/tests/spec_registry.rs`, replace line 144:

```rust
        "symlink_entry" => &["symlink"],
```

with:

```rust
        "symlink_entry" => &["symlink"],
        "directory_marker_shape" => &["directory marker shape"],
        "local_central_name_mismatch" => &["local/central name mismatch"],
```

- [ ] **Step 8: Make the rules normative in the spec**

In `spec/format.md`, replace lines 92-98:

```markdown
- Entry-name and entry-shape checks apply to the names as stored in the
  archive's central directory. A reader whose ZIP library sanitizes or
  deduplicates names on load must check the raw central directory
  itself, or it will silently accept archives that other readers reject.
- File-count and total-uncompressed-size limits are configurable on the
  reader; defaults are 10,000 entries and 1 GiB. Exceeding either is a
  rejection.
```

with:

```markdown
- Entry-name and entry-shape checks apply to the names as stored in the
  archive's central directory. A reader whose ZIP library sanitizes or
  deduplicates names on load must check the raw central directory
  itself, or it will silently accept archives that other readers reject.
- The central directory is the authoritative entry set. After extraction
  a reader MUST assert that the set of entries it produced is exactly the
  set of non-directory names the central-directory scan admitted. A name
  the scan admitted but the extractor dropped, or a name the extractor
  produced that the scan never saw, is a rejection.
- Directory-ness MUST be unambiguous. An entry whose external attributes
  set the DOS directory bit (`0x10`) on a name that does not end in `/`
  is rejected, and so is a `/`-terminated name that declares a nonzero
  uncompressed or compressed size. Readers disagree about which signal
  wins, so a signed capsule must never contain either shape.
- An entry's name in the LOCAL file header MUST equal its
  central-directory name. Some ZIP libraries re-key entries by the local
  name, so a mismatch lets two conforming readers extract different
  content under the same path.
- File-count and total-uncompressed-size limits are configurable on the
  reader; defaults are 10,000 entries and 1 GiB. Exceeding either is a
  rejection.
```

- [ ] **Step 9: Regenerate the canonical capsule skill**

Editing `spec/format.md` invalidates `skills/capsule/skill.json`, which the first conformance target checks.

Run: `node tools/regen-capsule-skill.mjs`

Expected: `Wrote skills/capsule/skill.json`

- [ ] **Step 10: Run the check to verify it passes**

Run: `node tools/check-spec-vectors.mjs`

Expected: PASS — `spec vectors: ok (283 vectors)`

- [ ] **Step 11: Verify the fixtures are byte-deterministic**

Run: `node sdk-js/tools/generate-malformed-fixtures.mjs --check`

Expected: `ok` for all 13 fixtures, including `ok dir-bit-smuggle.capsule (2716 bytes)`, `ok dir-marker-with-content.capsule (2706 bytes)`, `ok local-name-mismatch.capsule (2710 bytes)`; exit code 0.

- [ ] **Step 12: Run the full lane suite for regressions (all three consuming lanes)**

Run: `node tools/run-conformance.mjs && python -m pytest sdk-py/tests/ && cd verifier-rust && cargo test --workspace`

Expected: `PASS · 10/10 passed` from the JS harness; `188 passed` from pytest; `test result: ok. 105 passed; 0 failed` plus `malformed_registry_outcomes ... ok` from cargo.

- [ ] **Step 13: Commit**

```bash
git add spec/vectors/malformed-layout/vectors.json \
        spec/vectors/malformed-layout/output/dir-bit-smuggle.capsule \
        spec/vectors/malformed-layout/output/dir-marker-with-content.capsule \
        spec/vectors/malformed-layout/output/local-name-mismatch.capsule \
        sdk-js/tools/generate-malformed-fixtures.mjs \
        tools/check-spec-vectors.mjs \
        sdk-py/tests/test_spec_registry.py \
        verifier-rust/tests/spec_registry.rs \
        spec/format.md skills/capsule/skill.json
git commit -m "spec: pin entry-set integrity as conformance vectors

Adds three malformed-layout fixtures — dir-bit-smuggle (DOS directory
attribute on a file name), dir-marker-with-content (a '/'-terminated
name carrying bytes), and local-name-mismatch (local vs central header
name) — behind two new normative reason categories, mapped into the JS,
Python, and Rust registry harnesses. spec/format.md now states that the
central directory is the authoritative entry set, that directory-ness
must be unambiguous, and that local and central names must agree."
```


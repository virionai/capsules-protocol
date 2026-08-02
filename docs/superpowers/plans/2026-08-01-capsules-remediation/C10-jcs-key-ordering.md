# C10 — JCS object-key ordering: UTF-16 code units in Python and Swift

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Part of:** [Capsules pre-release remediation](./README.md) · Tier 2 (v0.7 correctness)

**Findings closed:** F30, F31, F35

**Lanes touched:** sdk-js, sdk-py, sdk-swift, sdk-kotlin, verifier-rust, spec, tools

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

CHECKED-IN FIXTURES DO NOT MOVE. Every existing capsule fixture (plain-basic.json, tamper-detection/, malformed-layout/, signing-input.json) uses ASCII-only keys and ASCII-only paths, where UTF-16, code-point and UTF-8 byte order all coincide. That is why all 186 Python tests, 58 JS tests, 113 Rust tests and the 10/10 conformance harness pass unchanged after the fix — no hash in the repo changes. The fix is purely forward-looking correctness for keys/paths outside ASCII.

Behaviour change to watch in sdk-py: utf16_sort_key raises UnicodeEncodeError on a lone surrogate, so a dict whose key is a lone surrogate (reachable via json.loads on a document containing an unpaired \ud800 escape) now fails during the sort rather than at the final .encode("utf-8"). Same exception class, a few frames earlier, and such a string could never produce canonical UTF-8 output anyway. If any caller currently catches UnicodeEncodeError around jcs(), the traceback origin moves.

zip_io.py gains an import of capsule.canonical. Verified acyclic: canonical.py imports only hashlib, math and typing.

OUT OF SCOPE BUT ADJACENT — flag to whoever owns the Rust builder cluster: verifier-rust/crates/capsule-verify/src/manifest.rs:110 sorts content-index entries with `a.path.cmp(&b.path)`, which is Rust String Ord = UTF-8 byte order = code-point order. That is the same divergence class as F30 for the same array, in a lane C10 does not otherwise touch. It only bites if that code path builds an index over a non-ASCII path. Rust's JCS itself (serde_jcs) is correct; this is the manifest sort, not the canonicalizer. Someone should apply an encode_utf16().collect::<Vec<u16>>() comparator there. I deliberately did not fold it into C10 because it is a builder change, not a canonicalization change, and would collide with whichever cluster is editing manifest.rs.

Cross-lane coordination: Task 1 must land before Tasks 5, 6 and 7 — those three lanes read spec/vectors/jcs-key-order.json and fail with file-not-found until it exists. Tasks 2 and 3 (Python) are order-dependent on each other (Task 3's manifest.py imports the helper Task 2 adds) but independent of Task 1 except for the vector-driven test in Task 2 Step 1. Tasks 4 and 5 are order-dependent (Task 5 asserts JCS.utf16Less, added in Task 4). Task 8 is independent and should go last so the prose describes shipped behaviour.

Task 5 cannot be verified in a Command-Line-Tools-only environment; whoever executes it needs a full Xcode toolchain for `swift test`. Task 6 needs a JDK 17 toolchain for `./gradlew :core:test`. Both were validated as far as this machine allows (see validation).

spec/manifest.md:74 and spec/format.md:81 currently say "ASCII order", which is not merely imprecise — it is what licensed the divergent implementations. Task 8 replaces it. If any downstream doc or third-party implementer quoted "ASCII order", they need the same correction.

## Validation performed while specifying this plan

The steps below were applied to a **copy of the repository outside the working tree** and executed. This is the real output from that run, not a prediction.

<details>
<summary>Expand validation log</summary>

```
Everything below was applied and run on a copy at /tmp/work-c10 (rsync of the repo, verifier-rust/target copied in, sdk-py installed into a fresh venv). The repo itself was never modified.

REAL OUTPUT, in task order:

Task 1 — new vector + JS lane. Test written first, vector file absent:
  $ cd sdk-js && npm test
  not ok 30 - JCS object-member ordering matches spec vectors
    error: "ENOENT: no such file or directory, open '/private/tmp/work-c10/spec/vectors/jcs-key-order.json'"
  $ node tools/generate-jcs-key-order-vector.mjs   (from sdk-js/)
  wrote /private/tmp/work-c10/spec/vectors/jcs-key-order.json (8 vectors)
  $ npm test  ->  # tests 58 / # pass 58 / # fail 0
  $ node tools/check-spec-vectors.mjs  ->  spec vectors: ok (288 vectors)   [was 280 before]

Task 2 — sdk-py JCS comparator. Before the fix:
  $ python -m pytest sdk-py/tests/test_canonical.py -q
  FAILED sdk-py/tests/test_canonical.py::test_jcs_sorts_object_keys_by_utf16_code_units
  FAILED sdk-py/tests/test_canonical.py::test_jcs_key_order_matches_spec_vectors
  E   AssertionError: supplementary-vs-high-bmp
  E   - 7b227a223a332c22f09f9880223a312c22ee8080223a322c22efbfbf223a307d
  E   + 7b227a223a332c22ee8080223a322c22efbfbf223a302c22f09f9880223a317d
After the fix: test_canonical.py 26 passed; full lane 'python -m pytest sdk-py/tests/' -> 184 passed in 0.24s.

Task 3 — sdk-py content-index + ZIP ordering. Before the fix:
  FAILED sdk-py/tests/test_manifest.py::test_build_content_index_orders_paths_by_utf16_code_units
  FAILED sdk-py/tests/test_zip_io.py::test_pack_emits_utf16_code_unit_ordered_entries
  E   At index 1 diff: '.txt' != '\U0001f600.txt'
After the fix: 'python -m pytest sdk-py/tests/' -> 186 passed in 0.25s; 'ruff check sdk-py/' -> All checks passed!
The pinned index_hash 49e4bccd112720dad9125d366459e2d4893cb1ffd58d99dc75ea40cc6aa04976 was produced by running sdk-js buildContentIndex over the identical file map.

Tasks 4/5 — sdk-swift. 'swift test' CANNOT run in this environment (Command Line Tools only: "error: no such module 'XCTest'"), so I validated differently and honestly:
  $ cd sdk-swift && swift build   ->  Build complete! (12.79s)   [all 4 targets compile with JCS.utf16Less, Manifest.swift and Zip.swift call sites]
  Then a throwaway executable target (deleted afterwards, NOT part of this plan) ran all 8 vectors through JCS.bytes(.object(pairs)):
    ok ascii-basic / ok empty-and-prefix / ok escaped-chars-sort-on-raw-code-units / ok supplementary-vs-high-bmp / ok surrogate-boundary / ok supplementary-vs-supplementary / ok canonically-equivalent-keys-are-distinct / ok cjk-and-private-use
    ALL 8 KEY-ORDER VECTORS PASS
  Reverting only the comparator to 'pairs.sorted { $0.0 < $1.0 }' and re-running: 4 FAILURES (supplementary-vs-high-bmp, surrogate-boundary, canonically-equivalent-keys-are-distinct, cjk-and-private-use). The canonically-equivalent case emitted {"f":2,"é":0,"é":1} — Swift's '<' put "f" first, proving it treats the two é spellings as EQUAL, not merely mis-ordered.
  The XCTest file in Task 5 is therefore verified by inspection against the real API (JCS.bytes, JCSValue.integer, Bytes.toHex at Crypto.swift:26, Hash.sha256Hex at Crypto.swift:20, JSONDecoder), not executed.

Task 6 — sdk-kotlin. No JVM on this machine ("Unable to locate a Java Runtime"; ~/.gradle/jdks is empty), so the Kotlin test is verified by inspection only. The AUDIT VERDICT is nonetheless definitive by construction, not by guess: 'sortedBy { it.first }' = 'sortedWith(compareBy(selector))', whose comparator body is 'compareValues(a, b)' = '(a as Comparable<Any>).compareTo(b)'; for String that is 'java.lang.String.compareTo', specified to compare 'char' values, i.e. UTF-16 code units. Kotlin is CORRECT and needs no source change — at Canonical.kt:43 (JCS members), Manifest.kt:27 (content index) and Zip.kt:15 (ZIP entries), all three.

Task 7 — verifier-rust. Ran for real:
  $ cargo test -p capsule-verify --lib jcs
  test jcs::vector_tests::key_order_matches_spec_vectors ... ok
  test result: ok. 22 passed; 0 failed
  $ cargo test --workspace   ->  103 passed (capsule-verify lib) + 7 passed (parity_against_js_sdk) + 3 passed (spec_registry); 0 failed
  I also read the serde_jcs 0.2.0 source (~/.cargo/registry/.../serde_jcs-0.2.0/src/lib.rs:96-133): keys are wrapped in a Utf16Key whose Ord compares 'Vec<u16>' from 'encode_utf16()'. Rust is correct by construction; the vector pins it.

Task 8 — spec wording only, no executable check.

Whole-repo gate with every change in place:
  $ node tools/run-conformance.mjs
  PASS · 10/10 passed · 3.1s total   (skill-capsule-regen, sdk-js, cli, malformed-fixtures-regen, spec-vectors, example-quickstart, example-generic-report, example-generic-table-graph, example-generic-react-render, examples-generic-hygiene)
```

</details>

---

## C10 — JCS object-key ordering: UTF-16 code units in Python and Swift

RFC 8785 §3.2.3 sorts object members on their **UTF-16 code-unit sequences**. Three of five lanes get this right; two do not.

| Lane | Site | Comparator | Correct? |
|---|---|---|---|
| sdk-js | `canonicalize` npm pkg | JS `<` on strings **is** UTF-16 order | yes |
| verifier-rust | `serde_jcs` 0.2.0 | `Utf16Key.cmp` over `Vec<u16>` from `encode_utf16()` (lib.rs:96–133) | yes |
| sdk-kotlin | `Canonical.kt:43` `sortedBy` | `compareValues` → `java.lang.String.compareTo` = `char` (UTF-16 code unit) order | **yes — audited, see Task 6** |
| sdk-py | `canonical.py:36` `sorted(v.keys())` | Unicode **code point** order | **no (F30/F31)** |
| sdk-swift | `JCS.swift:58` `pairs.sorted { $0.0 < $1.0 }` | Swift `String <`: normalization-aware, scalar-ordered | **no (F35)** |

Two distinct failure modes, both proven on the working copy:

1. **Supplementary vs. high BMP.** U+1F600 encodes as `D83D DE00`, so it sorts *below* U+E000..U+FFFF in UTF-16 but *above* them by code point. `{"￿":0,"\u{1F600}":1,"":2,"z":3}` canonicalizes to `…22f09f9880…22ee8080…22efbfbf…` in JS/Rust/Kotlin and `…22ee8080…22efbfbf…22f09f9880…` in Python and Swift. Different bytes → different hash → cross-lane verification failure.
2. **Swift only: canonically equivalent keys compare equal.** `"e" + U+0301` and precomposed `U+00E9` are distinct JSON members, but Swift's `<` reports them equal, so their relative order falls to the sort's unspecified stability. Observed pre-fix Swift output: `{"f":2,"é":0,"é":1}` — `"f"` first, i.e. the whole ordering was collation-driven, not just the surrogate case.

The same comparator governs `content_index.files` (a JSON **array**, so its order is inside the hashed bytes) and ZIP entry order (which is what "deterministic ZIP" means across lanes). Both must move with the JCS fix in the affected lane — Task 3 for Python, Task 4 for Swift.

Tasks 2–8 all depend on Task 1's vector file; do Task 1 first.

---

### Task 1: Pin RFC 8785 §3.2.3 member ordering as a spec vector

**Files:**
- Create: `sdk-js/tools/generate-jcs-key-order-vector.mjs`
- Create: `spec/vectors/jcs-key-order.json`
- Create: `sdk-js/test/jcs-key-order.test.js`
- Modify: `tools/check-spec-vectors.mjs:19-23`, `tools/check-spec-vectors.mjs:265-269`, `tools/check-spec-vectors.mjs:404-405`, `tools/check-spec-vectors.mjs:409-412`
- Modify: `spec/vectors/README.md:3`, `spec/vectors/README.md:50-62`
- Test: `sdk-js/test/jcs-key-order.test.js`

**Interfaces:**
- Consumes: `jcs(obj) -> Uint8Array`, `sha256(bytes) -> Buffer`, `bytesToHex(b) -> string` from `sdk-js/src/canonical.js` (all already imported at `tools/check-spec-vectors.mjs:35-41`)
- Produces: `spec/vectors/jcs-key-order.json` — a doc with `meta.kind === "jcs-key-order"` and a `vectors` array of `{ name, note, keys: string[], expected_key_order: string[], canonical_utf8_hex: string, sha256_hex: string }`. Consumed by Tasks 2, 5, 6, 7.

- [ ] **Step 1: Write the failing test**

Create `sdk-js/test/jcs-key-order.test.js`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { bytesToHex, jcs, sha256 } from "../src/canonical.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, "..", "..", "spec", "vectors", "jcs-key-order.json");

test("JCS object-member ordering matches spec vectors", () => {
  const { vectors } = JSON.parse(readFileSync(vectorsPath, "utf8"));
  assert.ok(vectors.length > 0, "vector file is empty");
  for (const v of vectors) {
    const obj = {};
    v.keys.forEach((k, i) => {
      obj[k] = i;
    });
    const canonical = jcs(obj);
    assert.equal(bytesToHex(canonical), v.canonical_utf8_hex, v.name);
    assert.equal(bytesToHex(sha256(canonical)), v.sha256_hex, v.name);
    const order = Object.keys(JSON.parse(Buffer.from(canonical).toString("utf8")));
    assert.deepEqual(order, v.expected_key_order, v.name);
  }
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-js && npm test`

Expected: FAIL with `not ok 30 - JCS object-member ordering matches spec vectors` and `error: "ENOENT: no such file or directory, open '<repo>/spec/vectors/jcs-key-order.json'"`

- [ ] **Step 3: Write the generator**

Create `sdk-js/tools/generate-jcs-key-order-vector.mjs`. Keys are spelled with `String.fromCodePoint` so this source file stays pure ASCII and no key depends on how an editor re-encodes invisible characters:

```js
#!/usr/bin/env node
// generate-jcs-key-order-vector.mjs
//
// Emits spec/vectors/jcs-key-order.json: normative object-member ordering
// vectors for RFC 8785 section 3.2.3, which sorts members on their UTF-16
// code-unit sequences.
//
// UTF-16 order is NOT Unicode code-point order. They disagree whenever a
// supplementary-plane key (>= U+10000, whose UTF-16 lead surrogate is
// 0xD800..0xDBFF) meets a BMP key in U+E000..U+FFFF: by code point the BMP
// key sorts first, by UTF-16 code units the supplementary key does. They
// also disagree with any normalization- or collation-aware comparator
// (e.g. Swift's `String <`), which reports canonically equivalent keys as
// equal and leaves their order unspecified.
//
// The reference lane (the `canonicalize` npm package used by
// sdk-js/src/canonical.js) is the oracle. Regeneration is an intentional
// spec change; review the byte-level diff.

import { writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { bytesToHex, jcs, sha256 } from "../src/canonical.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS = join(__dirname, "..", "..", "spec", "vectors");

// Keys are spelled by code point so this source file stays pure ASCII and
// no key depends on how an editor re-encodes invisible characters.
const cp = (...codes) => String.fromCodePoint(...codes);

// Each case lists keys in *input* order. The object under test maps each
// key to its 0-based index in that list, so the serialized values make the
// resulting member order readable with no number-format interplay.
const CASES = [
  {
    name: "ascii-basic",
    note: "Sanity: plain ASCII keys, out of order on input.",
    keys: ["b", "a", "c"],
  },
  {
    name: "empty-and-prefix",
    note: "Empty key sorts first; a proper prefix sorts before its extension.",
    keys: ["aa", "", "a", "ab"],
  },
  {
    name: "escaped-chars-sort-on-raw-code-units",
    note:
      "Keys order by RAW code units, not by their escaped JSON spelling: " +
      "U+0001 < U+0022 (quote) < U+005C (backslash) < U+007E (tilde).",
    keys: [cp(0x7e), cp(0x5c), cp(0x22), cp(0x01)],
  },
  {
    name: "supplementary-vs-high-bmp",
    note:
      "THE divergence case. U+1F600 encodes as D83D DE00, so it sorts BELOW " +
      "U+E000 and U+FFFF in UTF-16 order and ABOVE them in code-point order.",
    keys: [cp(0xffff), cp(0x1f600), cp(0xe000), "z"],
  },
  {
    name: "surrogate-boundary",
    note:
      "U+D7FF is the last BMP scalar below the surrogate block; U+10000 is " +
      "the first supplementary scalar (D800 DC00) and must sort between " +
      "U+D7FF and U+E000.",
    keys: [cp(0xe000), cp(0x10000), cp(0xd7ff)],
  },
  {
    name: "supplementary-vs-supplementary",
    note:
      "Two supplementary keys order by lead surrogate then trail surrogate, " +
      "which here agrees with code-point order.",
    keys: [cp(0x1f600), cp(0x10000), cp(0x10ffff)],
  },
  {
    name: "canonically-equivalent-keys-are-distinct",
    note:
      "U+0065 U+0301 and precomposed U+00E9 are distinct JSON members and " +
      "must NOT compare equal. UTF-16 puts 0x0065 before 0x00E9. A " +
      "normalization- or collation-aware comparator calls them equal and " +
      "leaves the order unspecified.",
    keys: [cp(0x00e9), cp(0x0065, 0x0301), "f"],
  },
  {
    name: "cjk-and-private-use",
    note:
      "Mixed BMP blocks plus a supplementary CJK ideograph (U+20000 -> " +
      "D840 DC00), which must sort below every U+E000..U+FFFF key.",
    keys: [cp(0xfb00), cp(0x20000), cp(0x4e00), cp(0xf8ff), "A"],
  },
];

function buildObject(keys) {
  const obj = {};
  keys.forEach((k, i) => {
    obj[k] = i;
  });
  return obj;
}

async function main() {
  const vectors = CASES.map((c) => {
    const canonical = jcs(buildObject(c.keys));
    const parsed = JSON.parse(Buffer.from(canonical).toString("utf8"));
    return {
      name: c.name,
      note: c.note,
      keys: c.keys,
      expected_key_order: Object.keys(parsed),
      canonical_utf8_hex: bytesToHex(canonical),
      sha256_hex: bytesToHex(sha256(canonical)),
    };
  });

  const doc = {
    meta: { kind: "jcs-key-order" },
    description:
      "RFC 8785 section 3.2.3 object-member ordering vectors. For each entry, " +
      "build a JSON object whose members are `keys` (in any insertion order), " +
      "each mapped to the integer index it has in `keys`, canonicalize it, and " +
      "reproduce `canonical_utf8_hex` byte-for-byte. Members MUST be sorted on " +
      "their UTF-16 code-unit sequences: not Unicode code-point order (the two " +
      "disagree once a supplementary-plane key meets a key in U+E000..U+FFFF) " +
      "and not a normalization- or collation-aware order (which can call " +
      "canonically equivalent keys equal). `expected_key_order` is the same " +
      "information in readable form; `sha256_hex` is SHA-256 over the bytes in " +
      "`canonical_utf8_hex`.",
    oracle:
      "Node.js 22 with the `canonicalize` npm package, via sdk-js/src/canonical.js " +
      "(the JavaScript reference lane). Generated by " +
      "sdk-js/tools/generate-jcs-key-order-vector.mjs.",
    vectors,
  };

  // Emit pure ASCII. String#split("") yields UTF-16 code units, so
  // surrogate halves are escaped individually -- the six-character
  // backslash-u spelling every JSON parser recombines. Keeps the
  // checked-in vector file readable in diffs and immune to editor
  // re-encoding.
  const ascii = JSON.stringify(doc, null, 2)
    .split("")
    .map((ch) => {
      const code = ch.charCodeAt(0);
      return code > 0x7f ? "\\u" + code.toString(16).padStart(4, "0") : ch;
    })
    .join("");

  const out = join(VECTORS, "jcs-key-order.json");
  await writeFile(out, ascii + "\n", "utf8");
  console.log(`wrote ${out} (${vectors.length} vectors)`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
```

- [ ] **Step 4: Run the generator to produce the vector file**

Run: `cd sdk-js && node tools/generate-jcs-key-order-vector.mjs`

Expected: `wrote <repo>/spec/vectors/jcs-key-order.json (8 vectors)`

The generated file is reproduced below **for review only — do not hand-type it**, since the escaped surrogate halves are easy to corrupt. Re-run the generator instead. Confirm the file is pure ASCII with `LC_ALL=C grep -c '[^ -~]' spec/vectors/jcs-key-order.json` → `0`.

```json
{
  "meta": {
    "kind": "jcs-key-order"
  },
  "description": "RFC 8785 section 3.2.3 object-member ordering vectors. For each entry, build a JSON object whose members are `keys` (in any insertion order), each mapped to the integer index it has in `keys`, canonicalize it, and reproduce `canonical_utf8_hex` byte-for-byte. Members MUST be sorted on their UTF-16 code-unit sequences: not Unicode code-point order (the two disagree once a supplementary-plane key meets a key in U+E000..U+FFFF) and not a normalization- or collation-aware order (which can call canonically equivalent keys equal). `expected_key_order` is the same information in readable form; `sha256_hex` is SHA-256 over the bytes in `canonical_utf8_hex`.",
  "oracle": "Node.js 22 with the `canonicalize` npm package, via sdk-js/src/canonical.js (the JavaScript reference lane). Generated by sdk-js/tools/generate-jcs-key-order-vector.mjs.",
  "vectors": [
    {
      "name": "ascii-basic",
      "note": "Sanity: plain ASCII keys, out of order on input.",
      "keys": ["b", "a", "c"],
      "expected_key_order": ["a", "b", "c"],
      "canonical_utf8_hex": "7b2261223a312c2262223a302c2263223a327d",
      "sha256_hex": "010eb91283f26c0461e7ac35cc3a1ff37409b7f80fbcb078c63fb361863434fe"
    },
    {
      "name": "empty-and-prefix",
      "note": "Empty key sorts first; a proper prefix sorts before its extension.",
      "keys": ["aa", "", "a", "ab"],
      "expected_key_order": ["", "a", "aa", "ab"],
      "canonical_utf8_hex": "7b22223a312c2261223a322c226161223a302c226162223a337d",
      "sha256_hex": "0138aec9344eb5cc093e75463086ca7c46e9ab9ffa3221c2cf0610e3a42cc569"
    },
    {
      "name": "escaped-chars-sort-on-raw-code-units",
      "note": "Keys order by RAW code units, not by their escaped JSON spelling: U+0001 < U+0022 (quote) < U+005C (backslash) < U+007E (tilde).",
      "keys": ["~", "\\", "\"", ""],
      "expected_key_order": ["", "\"", "\\", "~"],
      "canonical_utf8_hex": "7b225c7530303031223a332c225c22223a322c225c5c223a312c227e223a307d",
      "sha256_hex": "b233eab64524560b9812f1b0999d5e41c8ccca8e40886990d6ef5ef22831a6af"
    },
    {
      "name": "supplementary-vs-high-bmp",
      "note": "THE divergence case. U+1F600 encodes as D83D DE00, so it sorts BELOW U+E000 and U+FFFF in UTF-16 order and ABOVE them in code-point order.",
      "keys": ["￿", "😀", "", "z"],
      "expected_key_order": ["z", "😀", "", "￿"],
      "canonical_utf8_hex": "7b227a223a332c22f09f9880223a312c22ee8080223a322c22efbfbf223a307d",
      "sha256_hex": "b4aad4bf8ee91f66e8d24fdf951e401556399681a815d864ade4761617fa3503"
    },
    {
      "name": "surrogate-boundary",
      "note": "U+D7FF is the last BMP scalar below the surrogate block; U+10000 is the first supplementary scalar (D800 DC00) and must sort between U+D7FF and U+E000.",
      "keys": ["", "𐀀", "퟿"],
      "expected_key_order": ["퟿", "𐀀", ""],
      "canonical_utf8_hex": "7b22ed9fbf223a322c22f0908080223a312c22ee8080223a307d",
      "sha256_hex": "84d5cb6d6e1803e7f9663e06835e8270b6e70db2d15448f314f577ee74ec081a"
    },
    {
      "name": "supplementary-vs-supplementary",
      "note": "Two supplementary keys order by lead surrogate then trail surrogate, which here agrees with code-point order.",
      "keys": ["😀", "𐀀", "􏿿"],
      "expected_key_order": ["𐀀", "😀", "􏿿"],
      "canonical_utf8_hex": "7b22f0908080223a312c22f09f9880223a302c22f48fbfbf223a327d",
      "sha256_hex": "ec4e596191046833cff7a9eab8b8cf625791545fe2a71532c31a2ba6910b8a12"
    },
    {
      "name": "canonically-equivalent-keys-are-distinct",
      "note": "U+0065 U+0301 and precomposed U+00E9 are distinct JSON members and must NOT compare equal. UTF-16 puts 0x0065 before 0x00E9. A normalization- or collation-aware comparator calls them equal and leaves the order unspecified.",
      "keys": ["é", "é", "f"],
      "expected_key_order": ["é", "f", "é"],
      "canonical_utf8_hex": "7b2265cc81223a312c2266223a322c22c3a9223a307d",
      "sha256_hex": "a76a22ee3109ea7bbad4f33957ad96a911b706416fae89dd91d11c4b03ed4550"
    },
    {
      "name": "cjk-and-private-use",
      "note": "Mixed BMP blocks plus a supplementary CJK ideograph (U+20000 -> D840 DC00), which must sort below every U+E000..U+FFFF key.",
      "keys": ["ﬀ", "𠀀", "一", "", "A"],
      "expected_key_order": ["A", "一", "𠀀", "", "ﬀ"],
      "canonical_utf8_hex": "7b2241223a342c22e4b880223a322c22f0a08080223a312c22efa3bf223a332c22efac80223a307d",
      "sha256_hex": "13d7f3746e441e3c110265571b862b758199308368eb5788e690931de1c973d6"
    }
  ]
}
```

(The generator writes this with `JSON.stringify(doc, null, 2)`, so each array element is on its own line; the compacted arrays above are for readability only. Trust the generator's output, not this listing's whitespace.)

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd sdk-js && npm test`

Expected: PASS — `# tests 58` / `# pass 58` / `# fail 0`, including `ok 30 - JCS object-member ordering matches spec vectors`

- [ ] **Step 6: Teach the spec-vector checker the new shape**

`tools/check-spec-vectors.mjs` fails closed on unrecognized JSON under `spec/vectors/`, so the new file must be wired in or the whole `spec-vectors` conformance lane goes red. Four edits.

(a) At `tools/check-spec-vectors.mjs:19-23`, after the shape-3 comment block ending `...bit pattern (not the expected string) and serialize it.`, append:

```js
//
//   4. A JCS key-ordering vector set (meta.kind === "jcs-key-order"): a
//      `vectors` array of `{ name, keys, expected_key_order,
//      canonical_utf8_hex, sha256_hex }` entries. Build an object mapping
//      each key to its index in `keys`, canonicalize, and reproduce the
//      pinned bytes. RFC 8785 3.2.3 sorts members on UTF-16 code units,
//      which is neither code-point order nor a collation-aware order.
```

(b) Insert the checker immediately before the `// Byte-level signing-input vector` comment at `tools/check-spec-vectors.mjs:266` (i.e. between `checkNumberVectors`'s closing brace on line 264 and that comment):

```js
// Array-index-like keys ("0", "1", ...) are reordered by JS engines when a
// canonical object is reparsed, which would make expected_key_order
// unverifiable here. Vectors must not use them.
const ARRAY_INDEX_KEY = /^(0|[1-9][0-9]*)$/;

function checkKeyOrderVectors(path, doc) {
  if (!Array.isArray(doc.vectors) || doc.vectors.length === 0) {
    fail(`${path}: vectors must be a non-empty array`);
    return;
  }
  for (const entry of doc.vectors) {
    checked++;
    const label = `${path} [${entry?.name}]`;
    const keys = entry?.keys;
    if (!Array.isArray(keys) || keys.length === 0 || keys.some((k) => typeof k !== "string")) {
      fail(`${label}: keys must be a non-empty array of strings`);
      continue;
    }
    if (new Set(keys).size !== keys.length) {
      fail(`${label}: keys must be distinct`);
      continue;
    }
    if (keys.some((k) => ARRAY_INDEX_KEY.test(k))) {
      fail(`${label}: array-index-like keys are not allowed in ordering vectors`);
      continue;
    }
    const obj = {};
    keys.forEach((k, i) => {
      obj[k] = i;
    });
    const canonical = jcs(obj);
    const gotHex = bytesToHex(canonical);
    if (gotHex !== entry.canonical_utf8_hex) {
      fail(`${label}: JS SDK canonicalizes to ${gotHex}, vector says ${entry.canonical_utf8_hex}`);
      continue;
    }
    if (bytesToHex(sha256(canonical)) !== entry.sha256_hex) {
      fail(`${label}: sha256_hex does not match SHA-256 of canonical_utf8_hex`);
    }
    const order = Object.keys(JSON.parse(Buffer.from(canonical).toString("utf8")));
    if (JSON.stringify(order) !== JSON.stringify(entry.expected_key_order)) {
      fail(`${label}: expected_key_order ${JSON.stringify(entry.expected_key_order)} != ${JSON.stringify(order)}`);
    }
  }
}
```

(c) In `checkFile`, replace `tools/check-spec-vectors.mjs:404-405`

```js
  if (isNumberVectorSet(path, doc)) checkNumberVectors(path, doc);
  else if (isSigningInputVector(doc)) await checkSigningInput(path, doc);
```

with

```js
  if (isNumberVectorSet(path, doc)) checkNumberVectors(path, doc);
  else if (doc?.meta?.kind === "jcs-key-order") checkKeyOrderVectors(path, doc);
  else if (isSigningInputVector(doc)) await checkSigningInput(path, doc);
```

The branch must sit before `isCollection`, which would otherwise swallow the file (it also has a `vectors` array).

(d) Replace the fall-through message at `tools/check-spec-vectors.mjs:409-412`

```js
    fail(
      `${path}: unrecognized vector document (expected capsule_bytes_b64 + expected, ` +
        `an outcome-vector collection, a signing-input doc, or a jcs number set)`
    );
```

with

```js
    fail(
      `${path}: unrecognized vector document (expected capsule_bytes_b64 + expected, ` +
        `an outcome-vector collection, a signing-input doc, a jcs number set, ` +
        `or a jcs key-order set)`
    );
```

- [ ] **Step 7: Run the spec-vector checker**

Run: `node tools/check-spec-vectors.mjs`

Expected: PASS — `spec vectors: ok (288 vectors)` (280 before this task; the 8 new key-order vectors take it to 288)

- [ ] **Step 8: Document the new vector shape**

In `spec/vectors/README.md:3`, replace `This directory contains checked-in protocol vectors. Four shapes exist, all` with `This directory contains checked-in protocol vectors. Five shapes exist, all`.

After the shape-4 paragraph (ends `spec/vectors/README.md:50` with `...bit pattern (not the expected string) and serialize it.`), insert:

```markdown

5. **JCS key-ordering set** (`jcs-key-order.json`, detected by
   `meta.kind: "jcs-key-order"`): a `vectors` array of `{ name, note, keys,
   expected_key_order, canonical_utf8_hex, sha256_hex }` entries. Build a
   JSON object whose members are `keys`, each mapped to its 0-based index in
   `keys`, canonicalize it, and reproduce `canonical_utf8_hex` byte-for-byte.
   RFC 8785 §3.2.3 sorts members on their **UTF-16 code-unit sequences** —
   not Unicode code-point order (the two disagree once a supplementary-plane
   key meets a key in U+E000..U+FFFF) and not a normalization- or
   collation-aware order (which can report canonically equivalent keys as
   equal). All five lanes consume this set.
```

And in the "Generators" list at the end of that file, after the
`generate-signing-input-vector.mjs` bullet, add:

```markdown
- `sdk-js/tools/generate-jcs-key-order-vector.mjs` → `jcs-key-order.json`
  (self-contained; the case list lives in the generator)
```

- [ ] **Step 9: Run the full lane suite for regressions**

Run: `node tools/run-conformance.mjs`

Expected: `PASS · 10/10 passed` — all of `skill-capsule-regen`, `sdk-js`, `cli`, `malformed-fixtures-regen`, `spec-vectors`, `example-quickstart`, `example-generic-report`, `example-generic-table-graph`, `example-generic-react-render`, `examples-generic-hygiene`

- [ ] **Step 10: Commit**

```bash
git add spec/vectors/jcs-key-order.json spec/vectors/README.md sdk-js/tools/generate-jcs-key-order-vector.mjs sdk-js/test/jcs-key-order.test.js tools/check-spec-vectors.mjs
git commit -m "feat(conformance): pin RFC 8785 UTF-16 object-key ordering as a spec vector"
```

---

### Task 2: sdk-py — sort JCS object members on UTF-16 code units

**Files:**
- Modify: `sdk-py/src/capsule/canonical.py:12-15`, `sdk-py/src/capsule/canonical.py:36`
- Test: `sdk-py/tests/test_canonical.py`

**Interfaces:**
- Consumes: `spec/vectors/jcs-key-order.json` (Task 1)
- Produces: `capsule.canonical.utf16_sort_key(s: str) -> bytes` — the module-level comparator key. Task 3 imports it.

**Why `s.encode("utf-16-be")` and not an explicit code-unit expansion.** Both are correct; the encode wins on every axis that matters here. Every UTF-16 code unit occupies exactly two bytes at a fixed offset in the BE encoding, so byte-lexicographic comparison of the encoded form is *identical* to code-unit-lexicographic comparison — no alignment hazard, no proof obligation beyond that one sentence. It runs in CPython's C codec rather than a per-character Python loop, which matters because this runs on every object of every JCS call. And it is one line, where the manual expansion (`0xD800 + ((cp - 0x10000) >> 10)`, `0xDC00 + ((cp - 0x10000) & 0x3FF)`) is four lines of surrogate arithmetic that a future reader has to re-derive. The one behavioural difference is that the encode raises `UnicodeEncodeError` on a lone surrogate; that is fine and arguably better, because the final `.encode("utf-8")` in `jcs()` raises the same exception class on the same input anyway — the fix moves the failure a few frames earlier, it does not create one.

**Scope of the comparator in this lane:** it must also govern content-index and ZIP path ordering. That is Task 3, split out so this commit is reviewable as a pure canonicalization change.

- [ ] **Step 1: Write the failing test**

Append to `sdk-py/tests/test_canonical.py` (currently ends at line 157 with the `jcs-numbers.json` vector test):

```python


# UTF-16 code-unit ordering probes, spelled by code point so no source
# escape can be mis-transcribed. EMOJI is supplementary (D83D DE00);
# PUA and NONCHAR are BMP and sort AFTER it in UTF-16 but BEFORE it by
# code point.
EMOJI = chr(0x1F600)
PUA = chr(0xE000)
NONCHAR = chr(0xFFFF)


def test_jcs_sorts_object_keys_by_utf16_code_units():
    obj = {NONCHAR: 0, EMOJI: 1, PUA: 2, "z": 3}
    expected = ('{"z":3,"' + EMOJI + '":1,"' + PUA + '":2,"' + NONCHAR + '":0}').encode("utf-8")
    assert jcs(obj) == expected


def test_jcs_key_order_matches_spec_vectors():
    import json
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "spec" / "vectors" / "jcs-key-order.json"
    doc = json.loads(path.read_text())
    vectors = doc["vectors"]
    assert vectors, "vector file is empty"
    for entry in vectors:
        obj = {key: i for i, key in enumerate(entry["keys"])}
        canon = jcs(obj)
        assert bytes_to_hex(canon) == entry["canonical_utf8_hex"], entry["name"]
        assert sha256_hex(canon) == entry["sha256_hex"], entry["name"]
        order = list(json.loads(canon.decode("utf-8")).keys())
        assert order == entry["expected_key_order"], entry["name"]
```

`bytes_to_hex` and `sha256_hex` are already imported at the top of the file (lines 3-10).

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest sdk-py/tests/test_canonical.py -q`

Expected: FAIL with

```
FAILED sdk-py/tests/test_canonical.py::test_jcs_sorts_object_keys_by_utf16_code_units
FAILED sdk-py/tests/test_canonical.py::test_jcs_key_order_matches_spec_vectors
E   AssertionError: supplementary-vs-high-bmp
E   - 7b227a223a332c22f09f9880223a312c22ee8080223a322c22efbfbf223a307d
E   + 7b227a223a332c22ee8080223a322c22efbfbf223a302c22f09f9880223a317d
```

- [ ] **Step 3: Add the comparator helper**

In `sdk-py/src/capsule/canonical.py`, between `jcs()` (ends line 12) and `def _jcs_value(v: Any) -> str:` (line 15), insert:

```python
def utf16_sort_key(s: str) -> bytes:
    """RFC 8785 §3.2.3 sort key: the string's UTF-16 code units, big-endian.

    Comparing UTF-16BE byte strings lexicographically is identical to
    comparing UTF-16 code-unit sequences, because every code unit occupies
    exactly two bytes at a fixed offset. Python's default ``str`` ordering
    is Unicode *code point* order, which disagrees whenever a
    supplementary-plane character (>= U+10000, UTF-16 lead surrogate
    0xD800..0xDBFF) is compared against a BMP character in U+E000..U+FFFF:
    by code point the BMP character sorts first, by UTF-16 code units the
    supplementary one does.

    Raises UnicodeEncodeError on a lone surrogate — which could never reach
    canonical output anyway, since UTF-8 cannot encode one either.
    """
    return s.encode("utf-16-be")
```

so the file reads:

```python
def jcs(value: Any) -> bytes:
    """JCS-canonicalize a JSON-compatible value to UTF-8 bytes."""
    return _jcs_value(value).encode("utf-8")


def utf16_sort_key(s: str) -> bytes:
    ...
    return s.encode("utf-16-be")


def _jcs_value(v: Any) -> str:
    if v is None:
        return "null"
```

- [ ] **Step 4: Use the comparator in the object branch**

In `sdk-py/src/capsule/canonical.py`, replace line 36 (now shifted by the insertion above):

```python
    if isinstance(v, dict):
        keys = sorted(v.keys())
        parts = [_jcs_string(k) + ":" + _jcs_value(v[k]) for k in keys]
        return "{" + ",".join(parts) + "}"
```

with

```python
    if isinstance(v, dict):
        keys = sorted(v.keys(), key=utf16_sort_key)
        parts = [_jcs_string(k) + ":" + _jcs_value(v[k]) for k in keys]
        return "{" + ",".join(parts) + "}"
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `python -m pytest sdk-py/tests/test_canonical.py -q`

Expected: PASS — `26 passed`

- [ ] **Step 6: Run the full lane suite for regressions**

Run: `python -m pytest sdk-py/tests/ -q && python -m ruff check sdk-py/`

Expected: `184 passed`, then `All checks passed!`. Nothing else moves: every checked-in fixture uses ASCII-only keys, where UTF-16 and code-point order coincide.

- [ ] **Step 7: Commit**

```bash
git add sdk-py/src/capsule/canonical.py sdk-py/tests/test_canonical.py
git commit -m "fix(sdk-py): sort JCS object members on UTF-16 code units per RFC 8785 3.2.3"
```

---

### Task 3: sdk-py — apply the same comparator to content-index and ZIP path ordering

**Files:**
- Modify: `sdk-py/src/capsule/manifest.py:7-14`, `sdk-py/src/capsule/manifest.py:59`
- Modify: `sdk-py/src/capsule/zip_io.py:5-7`, `sdk-py/src/capsule/zip_io.py:36`, `sdk-py/src/capsule/zip_io.py:63`
- Test: `sdk-py/tests/test_manifest.py`, `sdk-py/tests/test_zip_io.py`

**Interfaces:**
- Consumes: `capsule.canonical.utf16_sort_key(s: str) -> bytes` (Task 2)
- Produces: none

**Why these two sites and not just JCS.** `content_index.files` is a JSON **array**, and JCS preserves array order, so `content_index_hash = SHA-256(JCS(files))` depends on the sort — `manifest.py:59` is as load-bearing as `canonical.py:36`. The JS reference lane at `sdk-js/src/manifest.js:62` sorts with `(a < b ? -1 : a > b ? 1 : 0)`, which on JS strings *is* UTF-16 order, so Python currently diverges. ZIP entry order (`zip_io.py:36`) feeds no hash, but "deterministic ZIP" across lanes is a documented container property (`spec/format.md:4`, `:81`) and `sdk-js/src/zip.js:144` uses the same UTF-16 comparator; a Python-built and a JS-built capsule with identical contents must be byte-identical. `zip_io.py:63` sets the returned dict's insertion order and is aligned for consistency.

- [ ] **Step 1: Write the failing test**

Append to `sdk-py/tests/test_manifest.py`:

```python


def test_build_content_index_orders_paths_by_utf16_code_units():
    # content_index.files is a JSON array, so its order is hashed. It must
    # match the JS reference lane, which sorts with `a < b` on JS strings
    # (UTF-16 code units). Python's default str ordering is code-point
    # order and would put the U+1F600 path last.
    emoji, pua, nonchar = chr(0x1F600), chr(0xE000), chr(0xFFFF)
    files = {
        nonchar + ".txt": b"a",
        emoji + ".txt": b"b",
        pua + ".txt": b"c",
        "z.txt": b"d",
    }
    index = build_content_index(files)
    assert [e["path"] for e in index["files"]] == [
        "z.txt",
        emoji + ".txt",
        pua + ".txt",
        nonchar + ".txt",
    ]
    # Pinned from the JS reference lane over the same file map:
    #   buildContentIndex(new Map([...])).index_hash
    assert index["index_hash"] == (
        "49e4bccd112720dad9125d366459e2d4893cb1ffd58d99dc75ea40cc6aa04976"
    )
```

and append to `sdk-py/tests/test_zip_io.py`:

```python


def test_pack_emits_utf16_code_unit_ordered_entries():
    # Deterministic packing must agree byte-for-byte with the JS reference
    # lane, which sorts entry names with `a < b` (UTF-16 code units).
    emoji, pua, nonchar = chr(0x1F600), chr(0xE000), chr(0xFFFF)
    files = {
        nonchar + ".txt": b"a",
        emoji + ".txt": b"b",
        pua + ".txt": b"c",
        "z.txt": b"d",
    }
    expected = ["z.txt", emoji + ".txt", pua + ".txt", nonchar + ".txt"]
    zip_bytes = pack_zip(files)
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        assert zf.namelist() == expected
    assert list(unpack_zip(zip_bytes).keys()) == expected
```

`build_content_index` is imported at `test_manifest.py:7`; `io`, `zipfile`, `pack_zip`, `unpack_zip` at `test_zip_io.py:1-13`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest sdk-py/tests/test_manifest.py sdk-py/tests/test_zip_io.py -q`

Expected: FAIL with

```
FAILED sdk-py/tests/test_manifest.py::test_build_content_index_orders_paths_by_utf16_code_units
FAILED sdk-py/tests/test_zip_io.py::test_pack_emits_utf16_code_unit_ordered_entries
E   AssertionError: assert ['z.txt', '.txt', ...] == ['z.txt', '\U0001f600.txt', ...]
E     At index 1 diff: '.txt' != '\U0001f600.txt'
```

- [ ] **Step 3: Sort content-index entries with the shared comparator**

In `sdk-py/src/capsule/manifest.py`, extend the import block at lines 7-14 by adding `utf16_sort_key` after `sha256_hex`:

```python
from .canonical import (
    bytes_to_hex,
    concat_bytes,
    hex_to_bytes,
    jcs,
    sha256,
    sha256_hex,
    utf16_sort_key,
)
```

and replace line 59:

```python
    entries.sort(key=lambda e: e["path"])
```

with

```python
    # content_index.files is a JSON *array*: JCS preserves array order, so
    # this sort is part of the hashed bytes. Use the same UTF-16 code-unit
    # comparator JCS uses for object members, and that the JS reference lane
    # gets for free from `a < b` on JS strings.
    entries.sort(key=lambda e: utf16_sort_key(e["path"]))
```

- [ ] **Step 4: Sort ZIP entries with the shared comparator**

In `sdk-py/src/capsule/zip_io.py`, after the import block at lines 5-7 (`import io` / `import zipfile` / `from collections.abc import Mapping`) and before `MAX_ENTRIES`, add:

```python

from .canonical import utf16_sort_key
```

(acyclic: `canonical.py` imports only `hashlib`, `math`, `typing`.)

Then replace line 36:

```python
    sorted_items = sorted(files.items(), key=lambda kv: kv[0])
```

with

```python
    sorted_items = sorted(files.items(), key=lambda kv: utf16_sort_key(kv[0]))
```

and line 63:

```python
        for zi in sorted(infos, key=lambda x: x.filename):
```

with

```python
        for zi in sorted(infos, key=lambda x: utf16_sort_key(x.filename)):
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `python -m pytest sdk-py/tests/test_manifest.py sdk-py/tests/test_zip_io.py -q`

Expected: PASS — `27 passed`

- [ ] **Step 6: Run the full lane suite for regressions**

Run: `python -m pytest sdk-py/tests/ -q && python -m ruff check sdk-py/`

Expected: `186 passed`, then `All checks passed!`. This includes `test_parity_jssdk.py`, which builds a capsule in Python and verifies it with the JS SDK — the direct guard that these two sorts still agree with the reference lane.

- [ ] **Step 7: Commit**

```bash
git add sdk-py/src/capsule/manifest.py sdk-py/src/capsule/zip_io.py sdk-py/tests/test_manifest.py sdk-py/tests/test_zip_io.py
git commit -m "fix(sdk-py): order content-index and ZIP entries by UTF-16 code units"
```

---

### Task 4: sdk-swift — replace `String <` with a UTF-16 comparator in JCS, content-index, and ZIP

**Files:**
- Modify: `sdk-swift/Sources/Capsule/JCS.swift:1-5`, `sdk-swift/Sources/Capsule/JCS.swift:53-58`, `sdk-swift/Sources/Capsule/JCS.swift:64-66`
- Modify: `sdk-swift/Sources/Capsule/Manifest.swift:36`
- Modify: `sdk-swift/Sources/Capsule/Zip.swift:13`
- Test: `sdk-swift/Tests/CapsuleTests/JCSKeyOrderVectorTests.swift` (created in Task 5)

**Interfaces:**
- Consumes: none
- Produces: `JCS.utf16Less(_ a: String, _ b: String) -> Bool` (internal to module `Capsule`). Used by `Manifest.swift`, `Zip.swift`, and Task 5's test.

The current comment at `JCS.swift:55-57` claims "chain keys are ASCII so this is exact". That is a scoping assumption, not a correctness argument, and it is what let the bug in. `String.utf16.lexicographicallyPrecedes(_:)` is the exact comparator RFC 8785 asks for: `String.UTF16View.Element` is `UInt16`, which is `Comparable`, so the lexicographic comparison is over code units directly.

Note this lane fails **two** ways, not one: the supplementary-plane case *and* canonical equivalence (Swift's `<` calls `"e" + U+0301` and `U+00E9` equal, so their order falls to the sort's unspecified stability). Both are covered by the vectors.

- [ ] **Step 1: Write the failing test**

This task's test is the vector suite created in Task 5. Do Task 5 Step 1 now (create `sdk-swift/Tests/CapsuleTests/JCSKeyOrderVectorTests.swift` exactly as listed there), then continue here.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-swift && swift test --filter JCSKeyOrderVectorTests`

Expected: FAIL — compile error `value of type 'JCS' has no member 'utf16Less'` on `testUtf16LessDisagreesWithSwiftStringOrdering`. Comment out that one method and re-run to see the data failure: `testKeyOrderMatchesSpecVectors` fails on 4 of 8 vectors — `supplementary-vs-high-bmp` (got `7b227a223a332c22ee8080223a322c22efbfbf223a302c22f09f9880223a317d`, want `7b227a223a332c22f09f9880223a312c22ee8080223a322c22efbfbf223a307d`), `surrogate-boundary`, `canonically-equivalent-keys-are-distinct` (got `7b2266223a322c22c3a9223a302c2265cc81223a317d` — Swift put `"f"` first, proving the two é spellings compared equal), and `cjk-and-private-use`.

- [ ] **Step 3: Add the comparator**

In `sdk-swift/Sources/Capsule/JCS.swift`, after `bytes(_:)` at lines 64-66:

```swift
    public static func bytes(_ v: JCSValue) -> Data {
        return Data(canonical(v).utf8)
    }
```

insert:

```swift

    /// Strict UTF-16 code-unit ordering, per RFC 8785 §3.2.3.
    ///
    /// Also the comparator for content-index entry order and ZIP entry
    /// order, both of which must agree byte-for-byte with the JS reference
    /// lane (where `a < b` on a JS string already *is* UTF-16 order).
    internal static func utf16Less(_ a: String, _ b: String) -> Bool {
        return a.utf16.lexicographicallyPrecedes(b.utf16)
    }
```

- [ ] **Step 4: Use it for object members**

In `sdk-swift/Sources/Capsule/JCS.swift`, replace lines 53-58:

```swift
        case .object(let pairs):
            // Sort by key; UTF-16 code-unit order is the default for Swift's
            // String comparison when both sides are pure-BMP. For correctness
            // beyond BMP we'd compare code-unit views explicitly; chain keys
            // are ASCII so this is exact.
            let sorted = pairs.sorted { $0.0 < $1.0 }
```

with

```swift
        case .object(let pairs):
            // RFC 8785 §3.2.3: members sort on their UTF-16 code-unit
            // sequences. Swift's `String <` compares by Unicode canonical
            // equivalence over normalized scalars and disagrees twice over:
            // a supplementary-plane key (U+10000+, lead surrogate
            // 0xD800..0xDBFF) sorts BELOW U+E000..U+FFFF in UTF-16 but above
            // it by scalar value, and canonically equivalent keys ("e" +
            // U+0301 vs U+00E9) compare EQUAL, leaving their relative order
            // to the sort's unspecified stability.
            let sorted = pairs.sorted { utf16Less($0.0, $1.0) }
```

and fix the now-stale file header at lines 1-5, replacing

```swift
// Object keys sorted by UTF-16 code units. Numbers via shortest-roundtrip,
```

with

```swift
// Object keys sorted by UTF-16 code units (JCS.utf16Less, NOT Swift's
// `String <`). Numbers via shortest-roundtrip,
```

- [ ] **Step 5: Use it for content-index and ZIP entry order**

In `sdk-swift/Sources/Capsule/Manifest.swift`, replace line 36:

```swift
        entries.sort { $0.path < $1.path }
```

with

```swift
        // content_index.files is a JSON array, so this order is hashed.
        // Same UTF-16 comparator JCS uses for object members.
        entries.sort { JCS.utf16Less($0.path, $1.path) }
```

In `sdk-swift/Sources/Capsule/Zip.swift`, replace line 13:

```swift
        let entries = files.sorted { $0.path < $1.path }
```

with

```swift
        let entries = files.sorted { JCS.utf16Less($0.path, $1.path) }
```

Both files are in module `Capsule`, so `internal` access is fine.

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd sdk-swift && swift test --filter JCSKeyOrderVectorTests`

Expected: PASS — `Executed 2 tests, with 0 failures`

- [ ] **Step 7: Run the full lane suite for regressions**

Run: `cd sdk-swift && swift build && swift test`

Expected: `Build complete!` followed by all `CapsuleTests` passing with 0 failures — `ParityTests`, `RoundTripTests`, `EncryptionTests`, `JCSNumbersVectorTests`, `JCSKeyOrderVectorTests`. Nothing else moves: every existing fixture is ASCII-keyed and ASCII-pathed.

- [ ] **Step 8: Commit**

```bash
git add sdk-swift/Sources/Capsule/JCS.swift sdk-swift/Sources/Capsule/Manifest.swift sdk-swift/Sources/Capsule/Zip.swift
git commit -m "fix(sdk-swift): sort JCS members, content-index, and ZIP entries by UTF-16 code units"
```

---

### Task 5: sdk-swift — consume the key-order vector in XCTest

**Files:**
- Create: `sdk-swift/Tests/CapsuleTests/JCSKeyOrderVectorTests.swift`
- Test: `sdk-swift/Tests/CapsuleTests/JCSKeyOrderVectorTests.swift`

**Interfaces:**
- Consumes: `spec/vectors/jcs-key-order.json` (Task 1); `JCS.bytes(_:) -> Data`, `JCSValue.object([(String, JCSValue)])`, `JCSValue.integer(Int64)`, `JCS.utf16Less(_:_:) -> Bool` (Task 4); `Bytes.toHex(_ data: Data) -> String` (`Crypto.swift:26`), `Hash.sha256Hex(_ data: Data) -> String` (`Crypto.swift:20`)
- Produces: none

The repo-root walk mirrors `JCSNumbersVectorTests.swift:26-34` and `ParityTests`.

- [ ] **Step 1: Write the failing test**

Create `sdk-swift/Tests/CapsuleTests/JCSKeyOrderVectorTests.swift`:

```swift
// Vector-driven check that object-member ordering matches the normative
// JCS vectors in spec/vectors/jcs-key-order.json (the `canonicalize` npm
// package, via sdk-js/src/canonical.js, is the oracle).
//
// RFC 8785 §3.2.3 sorts members on their UTF-16 code-unit sequences.
// Swift's `String <` is normalization-aware and scalar-ordered, so it
// disagrees on supplementary-plane keys and calls canonically equivalent
// keys equal — this suite is what pins JCS.utf16Less in place.
//
// Mirrors sdk-js/test/jcs-key-order.test.js, the Python
// test_jcs_key_order_matches_spec_vectors, the Kotlin
// JcsKeyOrderVectorTest, and the Rust jcs::vector_tests.

import Foundation
import XCTest
@testable import Capsule

final class JCSKeyOrderVectorTests: XCTestCase {

    private struct Vector: Decodable {
        let name: String
        let keys: [String]
        let expected_key_order: [String]
        let canonical_utf8_hex: String
        let sha256_hex: String
    }

    private struct VectorFile: Decodable {
        let vectors: [Vector]
    }

    /// Walks up from this file to the repo root, matching ParityTests.
    private static let vectorsURL: URL = {
        let testFile = URL(fileURLWithPath: #file)
        return testFile
            .deletingLastPathComponent()  // CapsuleTests/
            .deletingLastPathComponent()  // Tests/
            .deletingLastPathComponent()  // sdk-swift/
            .deletingLastPathComponent()  // <repo-root>/
            .appendingPathComponent("spec/vectors/jcs-key-order.json")
    }()

    func testKeyOrderMatchesSpecVectors() throws {
        let data = try Data(contentsOf: Self.vectorsURL)
        let file = try JSONDecoder().decode(VectorFile.self, from: data)
        XCTAssertFalse(file.vectors.isEmpty, "vector file is empty")
        for vector in file.vectors {
            let pairs = vector.keys.enumerated().map { (i, key) in
                (key, JCSValue.integer(Int64(i)))
            }
            let canonical = JCS.bytes(.object(pairs))
            XCTAssertEqual(Bytes.toHex(canonical), vector.canonical_utf8_hex, vector.name)
            XCTAssertEqual(Hash.sha256Hex(canonical), vector.sha256_hex, vector.name)
        }
    }

    /// The comparator itself, on the two cases Swift's `String <` gets wrong.
    func testUtf16LessDisagreesWithSwiftStringOrdering() {
        // U+1F600 is D83D DE00, so it precedes U+E000 in UTF-16 order even
        // though its scalar value is far larger.
        XCTAssertTrue(JCS.utf16Less("\u{1F600}", "\u{E000}"))
        XCTAssertFalse(JCS.utf16Less("\u{E000}", "\u{1F600}"))
        // Canonically equivalent keys are distinct and strictly ordered.
        XCTAssertTrue(JCS.utf16Less("e\u{0301}", "\u{00E9}"))
        XCTAssertFalse(JCS.utf16Less("\u{00E9}", "e\u{0301}"))
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-swift && swift test --filter JCSKeyOrderVectorTests`

Expected: FAIL. If Task 4 is not yet applied: compile error `value of type 'JCS' has no member 'utf16Less'`. If Task 4 is applied, this step is a no-op confirmation and both tests pass — the failing-first evidence for this file is recorded in Task 4 Step 2.

- [ ] **Step 3: Confirm the vector file resolves from the test bundle**

No code change; verify the path walk lands on the repo root rather than the build directory:

```bash
cd sdk-swift && swift test --filter JCSKeyOrderVectorTests 2>&1 | grep -E "vectors|error"
```

If the file is not found, XCTest reports `The file "jcs-key-order.json" couldn't be opened` — in that case check that `spec/vectors/jcs-key-order.json` exists (Task 1 Step 4) before touching the path walk, since the walk is copied verbatim from the already-working `JCSNumbersVectorTests`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd sdk-swift && swift test --filter JCSKeyOrderVectorTests`

Expected: PASS — `Executed 2 tests, with 0 failures`

- [ ] **Step 5: Run the full lane suite for regressions**

Run: `cd sdk-swift && swift test`

Expected: all `CapsuleTests` pass with 0 failures (`ParityTests`, `RoundTripTests`, `EncryptionTests`, `JCSNumbersVectorTests`, `JCSKeyOrderVectorTests`)

- [ ] **Step 6: Commit**

```bash
git add sdk-swift/Tests/CapsuleTests/JCSKeyOrderVectorTests.swift
git commit -m "test(sdk-swift): consume the JCS key-order spec vectors"
```

---

### Task 6: sdk-kotlin — pin `sortedBy` as UTF-16 order (audit verdict: already correct)

**Files:**
- Create: `sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/JcsKeyOrderVectorTest.kt`
- Modify: `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Canonical.kt:1-5`
- Test: `sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/JcsKeyOrderVectorTest.kt`

**Interfaces:**
- Consumes: `spec/vectors/jcs-key-order.json` (Task 1); `JCS.bytes(v: JCSValue): ByteArray`, `JCSValue.Obj(pairs: List<Pair<String, JCSValue>>)`, `JCSValue.Integer(v: Long)`, `CapsuleCrypto.bytesToHex(b: ByteArray): String` (`Crypto.kt:28`), `CapsuleCrypto.sha256Hex(data: ByteArray): String` (`Crypto.kt:26`)
- Produces: none

**AUDIT VERDICT — CONFIRMED CORRECT, NO SOURCE FIX NEEDED.** All three ordering sites in this lane are already UTF-16 code-unit order:

- `Canonical.kt:43` — `v.pairs.sortedBy { it.first }` (JCS object members)
- `Manifest.kt:27` — `.sortedBy { it.first }` (content-index entries)
- `Zip.kt:15` — `files.sortedBy { it.first }` (ZIP entries)

The chain is: `sortedBy(selector)` is `sortedWith(compareBy(selector))`; `compareBy`'s comparator body is `compareValues(selector(a), selector(b))`; `compareValues` casts to `Comparable<Any?>` and calls `compareTo`; for `String` that is `java.lang.String.compareTo`, which is specified to compare the strings' `char` values — and a Java `char` *is* a UTF-16 code unit. So Kotlin's default `String` ordering is exactly RFC 8785 §3.2.3's ordering, with no normalization, no collation, and no code-point re-interpretation. (Contrast Rust, where `String: Ord` is UTF-8 byte order = code-point order, and Swift, where `String: Comparable` is canonical-equivalence-aware — both differ from Java's.) Duplicate keys are not a stability concern because `String.compareTo` returns 0 only for equal strings, and JCS forbids duplicate members anyway.

This task therefore adds test coverage and a comment that records *why* the line is correct, so a future reader does not "improve" `sortedBy` into a `java.text.Collator` or a `compareBy { it.first.codePoints() }`.

- [ ] **Step 1: Write the failing test**

Create `sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/JcsKeyOrderVectorTest.kt`. Code points are spelled with `Character.toChars` so no source escape can be mis-transcribed:

```kotlin
package ai.virion.capsule.core

import com.google.gson.JsonParser
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Vector-driven check that object-member ordering matches the normative
 * JCS vectors in spec/vectors/jcs-key-order.json (the `canonicalize` npm
 * package, via sdk-js/src/canonical.js, is the oracle).
 *
 * AUDIT RESULT: this lane was already correct and needs no source change.
 * `sortedBy { it.first }` is `sortedWith(compareBy(selector))`, whose
 * comparator ends in `compareValues(a, b)` -> `Comparable<String>.compareTo`
 * -> `java.lang.String.compareTo`, specified to compare `char` values --
 * i.e. UTF-16 code units, exactly what RFC 8785 3.2.3 requires. Contrast
 * Rust (`String: Ord` is UTF-8 byte order) and Swift (`String: Comparable`
 * is canonical-equivalence-aware), both of which needed fixes.
 *
 * These vectors pin that so nobody "fixes" it into a locale Collator.
 *
 * Mirrors sdk-js/test/jcs-key-order.test.js, the Python
 * test_jcs_key_order_matches_spec_vectors, the Swift
 * JCSKeyOrderVectorTests, and the Rust jcs::vector_tests.
 */
class JcsKeyOrderVectorTest {

    @Test
    fun keyOrderMatchesSpecVectors() {
        val doc = JsonParser.parseString(vectorsFile().readText()).asJsonObject
        val vectors = doc.getAsJsonArray("vectors")
        assertTrue(vectors.size() > 0, "vector file is empty")
        for (entry in vectors) {
            val v = entry.asJsonObject
            val name = v.get("name").asString
            val keys = v.getAsJsonArray("keys").map { it.asString }
            val pairs: List<Pair<String, JCSValue>> =
                keys.mapIndexed { i, k -> k to JCSValue.Integer(i.toLong()) }
            val canon = JCS.bytes(JCSValue.Obj(pairs))
            assertEquals(
                v.get("canonical_utf8_hex").asString,
                CapsuleCrypto.bytesToHex(canon),
                name,
            )
            assertEquals(v.get("sha256_hex").asString, CapsuleCrypto.sha256Hex(canon), name)
        }
    }

    /** The comparator claim itself, independent of the vector file. */
    @Test
    fun stringCompareToIsUtf16CodeUnitOrder() {
        val emoji = String(Character.toChars(0x1F600))      // D83D DE00
        val privateUse = String(Character.toChars(0xE000))  // E000
        assertTrue(
            emoji < privateUse,
            "String.compareTo must be UTF-16 code-unit order (RFC 8785 3.2.3)",
        )
        assertTrue(
            emoji.codePointAt(0) > privateUse.codePointAt(0),
            "...and must NOT be code-point order",
        )
    }

    private fun vectorsFile(): File {
        var p: File? = File(System.getProperty("user.dir")).absoluteFile
        while (p != null) {
            val f = File(p, "spec/vectors/jcs-key-order.json")
            if (f.exists()) return f
            p = p.parentFile
        }
        error("spec/vectors/jcs-key-order.json not found above ${System.getProperty("user.dir")}")
    }
}
```

Gson is declared as `implementation` in `sdk-kotlin/core/build.gradle.kts`; Gradle's `testImplementation` extends `implementation`, so it is on the test compile classpath — same as the existing `JcsNumbersVectorTest`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-kotlin && ./gradlew --no-daemon :core:test --tests 'ai.virion.capsule.core.JcsKeyOrderVectorTest'`

Expected: FAIL — with `spec/vectors/jcs-key-order.json` absent, `keyOrderMatchesSpecVectors` throws `IllegalStateException: spec/vectors/jcs-key-order.json not found above <dir>`. This is the honest failing-first state for this lane: because Kotlin's comparator is already correct, once Task 1 has landed the vector assertions pass on the first run. `stringCompareToIsUtf16CodeUnitOrder` passes immediately and is the audit assertion, not a regression test.

- [ ] **Step 3: Record the audit result in the source comment**

In `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Canonical.kt`, replace lines 1-5:

```kotlin
// JCS — RFC 8785 canonicalization. Mirrors the JavaScript reference SDK.
//
// Object keys sorted by code-unit order. Numbers via shortest-roundtrip,
// rejecting NaN/Infinity. Strings escape RFC 8259 mandatory chars and
// U+0000..U+001F. Arrays preserve insertion order.
```

with

```kotlin
// JCS — RFC 8785 canonicalization. Mirrors the JavaScript reference SDK.
//
// Object keys sorted by UTF-16 code-unit order, per RFC 8785 §3.2.3. This
// lane gets that for free: `sortedBy` bottoms out in
// java.lang.String.compareTo, which compares `char` values — and a Java
// `char` IS a UTF-16 code unit. Do NOT replace it with a Collator, a
// locale-aware comparator, or a codePoints() comparison: code-point order
// disagrees with UTF-16 whenever a supplementary key (>= U+10000) meets a
// key in U+E000..U+FFFF. Pinned by JcsKeyOrderVectorTest.
//
// Numbers via shortest-roundtrip, rejecting NaN/Infinity. Strings escape
// RFC 8259 mandatory chars and U+0000..U+001F. Arrays preserve insertion
// order.
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd sdk-kotlin && ./gradlew --no-daemon :core:test --tests 'ai.virion.capsule.core.JcsKeyOrderVectorTest'`

Expected: PASS — `BUILD SUCCESSFUL`, 2 tests, 0 failures

- [ ] **Step 5: Run the full lane suite for regressions**

Run: `cd sdk-kotlin && ./gradlew --no-daemon :core:test`

Expected: `BUILD SUCCESSFUL` — `EnvelopeTest`, `JcsNumbersVectorTest`, `JcsKeyOrderVectorTest`, `ParityTest`, `RoundTripTest` all green, 0 failures

- [ ] **Step 6: Commit**

```bash
git add sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/JcsKeyOrderVectorTest.kt sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Canonical.kt
git commit -m "test(sdk-kotlin): pin sortedBy as UTF-16 code-unit order with the JCS key-order vectors"
```

---

### Task 7: verifier-rust — consume the key-order vector

**Files:**
- Modify: `verifier-rust/crates/capsule-verify/src/jcs.rs:214-217`, `verifier-rust/crates/capsule-verify/src/jcs.rs:243-246`
- Test: `verifier-rust/crates/capsule-verify/src/jcs.rs`

**Interfaces:**
- Consumes: `spec/vectors/jcs-key-order.json` (Task 1); `jcs(&Value) -> Vec<u8>`, `crate::sha256_hex(&[u8]) -> String`, the `hex` crate (already a dependency in `capsule-verify/Cargo.toml`)
- Produces: none

Rust is correct by construction — `serde_jcs` 0.2.0 wraps keys in a `Utf16Key` whose `Ord` compares `Vec<u16>` built from `encode_utf16()` (lib.rs:96-133). That is *not* obvious from `jcs.rs`, whose doc comment at lines 17-18 and 27-32 hand-waves it as "ASCII-only keys in our use case make this equivalent to `&str` byte order". This task replaces the hand-wave with an executable pin.

- [ ] **Step 1: Write the failing test**

In `verifier-rust/crates/capsule-verify/src/jcs.rs`, extend the `vector_tests` module. First widen its imports at lines 214-217:

```rust
#[cfg(test)]
mod vector_tests {
    use super::jcs;
    use serde_json::Value;
```

to

```rust
#[cfg(test)]
mod vector_tests {
    use super::jcs;
    use crate::sha256_hex;
    use serde_json::Value;
```

Then, after `numbers_match_spec_vectors` ends (lines 243-245: `assert_eq!(got, expected, "bits {hex}");` / `}` / `}`) and before the module's closing brace on line 246, insert:

```rust

    /// Vector-driven check against the normative object-member ordering
    /// vectors in spec/vectors/jcs-key-order.json. RFC 8785 section 3.2.3
    /// sorts members on their UTF-16 code-unit sequences, which is NOT
    /// Rust's `str` ordering (UTF-8 bytes == code points). `serde_jcs`
    /// sorts on `encode_utf16().collect::<Vec<u16>>()`, so this lane is
    /// correct by construction; the vector pins that fact.
    #[test]
    fn key_order_matches_spec_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../spec/vectors/jcs-key-order.json"
        );
        let doc: Value = serde_json::from_str(
            &std::fs::read_to_string(path).expect("read spec/vectors/jcs-key-order.json"),
        )
        .expect("parse jcs-key-order.json");
        let vectors = doc["vectors"].as_array().expect("vectors array");
        assert!(!vectors.is_empty(), "vector file is empty");
        for entry in vectors {
            let name = entry["name"].as_str().expect("name");
            let keys = entry["keys"].as_array().expect("keys");
            let mut map = serde_json::Map::new();
            for (i, k) in keys.iter().enumerate() {
                map.insert(
                    k.as_str().expect("key is a string").to_string(),
                    Value::from(i),
                );
            }
            let canon = jcs(&Value::Object(map));
            assert_eq!(
                hex::encode(&canon),
                entry["canonical_utf8_hex"].as_str().expect("canonical_utf8_hex"),
                "{name}: canonical bytes"
            );
            assert_eq!(
                sha256_hex(&canon),
                entry["sha256_hex"].as_str().expect("sha256_hex"),
                "{name}: sha256"
            );
        }
    }
```

The `concat!(env!("CARGO_MANIFEST_DIR"), "/../../../spec/vectors/...")` path form is copied verbatim from `numbers_match_spec_vectors` at lines 225-228. `serde_json::Map` defaults to a `BTreeMap`, so insertion order is irrelevant — `serde_jcs` re-sorts on UTF-16 regardless.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd verifier-rust && cargo test -p capsule-verify --lib key_order_matches_spec_vectors`

Expected: FAIL — with `spec/vectors/jcs-key-order.json` absent, the test panics with `read spec/vectors/jcs-key-order.json: No such file or directory (os error 2)`. Once Task 1 has landed the vectors, it passes on the first run: this lane needs no source fix, and the test's purpose is to lock in `serde_jcs`'s UTF-16 comparator against a future dependency bump.

- [ ] **Step 3: Replace the stale hand-wave in the module docs**

In `verifier-rust/crates/capsule-verify/src/jcs.rs`, replace lines 17-18:

```rust
//! - object keys sorted by code-unit order (ASCII-only keys in our use case
//!   make this equivalent to `&str` byte order; documented for posterity)
```

with

```rust
//! - object keys sorted by UTF-16 code-unit order. This is NOT `&str` byte
//!   order: Rust's `str: Ord` is UTF-8 byte order == code-point order, and
//!   the two disagree once a supplementary key (>= U+10000) meets a key in
//!   U+E000..U+FFFF. `serde_jcs` sorts on
//!   `encode_utf16().collect::<Vec<u16>>()`, which is correct; pinned by
//!   `vector_tests::key_order_matches_spec_vectors`.
```

and replace lines 27-32:

```rust
/// Object keys are sorted in UTF-16 code-unit order. For ASCII-only keys —
/// which covers all manifest, envelope, and chain-record keys in the v0.6
/// capsule format — this coincides with the byte order of UTF-8 strings. If
/// the schema ever introduces keys containing supplementary (non-BMP)
/// characters, the underlying `serde_jcs` crate already handles UTF-16
/// ordering correctly.
```

with

```rust
/// Object keys are sorted in UTF-16 code-unit order (RFC 8785 §3.2.3). All
/// v0.6 manifest, envelope, and chain-record keys are ASCII, where that
/// coincides with UTF-8 byte order — but the guarantee does not rest on
/// that: `serde_jcs` compares `Vec<u16>` from `encode_utf16()`, so
/// supplementary-plane keys are ordered correctly too. Do not swap in a
/// canonicalizer that sorts `&str` directly.
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd verifier-rust && cargo test -p capsule-verify --lib jcs`

Expected: PASS — `test jcs::vector_tests::key_order_matches_spec_vectors ... ok` and `test result: ok. 22 passed; 0 failed`

- [ ] **Step 5: Run the full lane suite for regressions**

Run: `cd verifier-rust && cargo test --workspace`

Expected: `test result: ok. 103 passed; 0 failed` (capsule-verify lib), `7 passed` (`tests/parity_against_js_sdk.rs`), `3 passed` (`tests/spec_registry.rs`), 0 failures overall

- [ ] **Step 6: Commit**

```bash
git add verifier-rust/crates/capsule-verify/src/jcs.rs
git commit -m "test(verifier-rust): consume the JCS key-order spec vectors and drop the ASCII hand-wave"
```

---

### Task 8: spec — replace "ASCII order" with the normative UTF-16 path-ordering rule

**Files:**
- Modify: `spec/manifest.md:74`
- Modify: `spec/format.md:81`
- Test: none (normative prose; enforced by the tests in Tasks 2-7)

**Interfaces:**
- Consumes: none
- Produces: none

`spec/manifest.md:74` says `- Sorted by \`path\`, ASCII order.` and `spec/format.md:81` says `- File entries are sorted by path, ASCII order.` "ASCII order" is undefined for non-ASCII paths, and is precisely the licence under which Python and Swift picked different comparators. Fix the wording so the next implementer cannot make the same choice.

- [ ] **Step 1: Write the failing test**

None — this is normative prose with no executable assertion of its own. The behaviour it describes is already covered by `test_build_content_index_orders_paths_by_utf16_code_units` (Task 3), `test_pack_emits_utf16_code_unit_ordered_entries` (Task 3), and the Swift/Kotlin/Rust vector suites. Do this task last, after those are green, so the prose describes shipped behaviour.

- [ ] **Step 2: Verify the current wording is what you think it is**

Run: `grep -n "ASCII order" spec/*.md`

Expected: exactly two hits —

```
spec/format.md:81:- File entries are sorted by path, ASCII order.
spec/manifest.md:74:  - Sorted by `path`, ASCII order.
```

- [ ] **Step 3: Fix `spec/manifest.md:74`**

Replace

```markdown
  - Sorted by `path`, ASCII order.
```

with

```markdown
  - Sorted by `path` on UTF-16 code-unit sequences — the same ordering
    RFC 8785 §3.2.3 applies to object members. `content_index.files` is a
    JSON array, so this order is inside the bytes `index_hash` covers.
    Note this is NOT Unicode code-point order: the two disagree whenever a
    supplementary-plane path (>= U+10000, UTF-16 lead surrogate
    0xD800..0xDBFF) is compared against a path in U+E000..U+FFFF. For
    ASCII-only paths all candidate orderings coincide.
```

- [ ] **Step 4: Fix `spec/format.md:81`**

Replace

```markdown
- File entries are sorted by path, ASCII order.
```

with

```markdown
- File entries are sorted by path on UTF-16 code-unit sequences — the same
  ordering RFC 8785 §3.2.3 applies to object members, so a capsule built by
  any conforming implementation is byte-identical. NOT Unicode code-point
  order; the two disagree once a supplementary-plane path (>= U+10000) is
  compared against a path in U+E000..U+FFFF.
```

- [ ] **Step 5: Run the full lane suite for regressions**

Run: `node tools/run-conformance.mjs`

Expected: `PASS · 10/10 passed` (`examples-generic-hygiene` is the lane that reads spec prose; the change is additive text and does not affect it)

- [ ] **Step 6: Commit**

```bash
git add spec/manifest.md spec/format.md
git commit -m "docs(spec): specify path ordering as UTF-16 code units, not \"ASCII order\""
```

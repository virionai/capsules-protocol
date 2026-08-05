# C12 — Semantic binding: tie manifest claims to envelope and chain facts, and create the spec/vectors/semantic-binding registry

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Part of:** [Capsules pre-release remediation](./README.md) · Tier 2 (v0.7 correctness)

**Findings closed:** F37, F43, F38, F33, F42, F29

**Lanes touched:** sdk-js, sdk-py, verifier-rust, sdk-swift, sdk-kotlin, spec, tools

**Tasks:** 14

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

WHAT THIS BLOCKS FOR OTHERS: Tasks 4 and 5 create `spec/vectors/semantic-binding/` — the registry, its generator, its `vectors.json` schema, and the harness wiring. Any other cluster that wants to add a semantic vector must land after Task 5 and should extend, not redefine, the schema: `expected.{ok, failing[], reason, error_includes, trusted_signer_count, decryptable_with}` plus a top-level `requires[]` on the vector. Adding a new `reason` category means adding it to `reasons{}` in vectors.json AND to the five per-lane needle tables (tools/check-spec-vectors.mjs `VERIFY_REASON`, sdk-py `VERIFY_REASON_NEEDLES`, verifier-rust `verify_reason_needle`, sdk-swift `verifyReasonNeedles`, sdk-kotlin `verifyReasonNeedles`) — the Rust and Swift/Kotlin tables panic/error on an unknown category, which is deliberate so a new category cannot be silently skipped.

FIXTURE FRAGILITY: all six fixtures are derived from `spec/vectors/tamper-detection/output/{clean,clean-encrypted,tampered-chain}.capsule` and re-signed with the throwaway key in that lane's `keys.json`. If any cluster re-baselines the tamper-detection fixtures (`generate-tamper-fixtures.mjs` mints a fresh keypair every run), the semantic-binding fixtures must be regenerated in the same commit or `semantic-binding-fixtures-regen` fails. Sequence those two regenerations together.

SHARED FILES / MERGE CONFLICTS: `tools/check-spec-vectors.mjs` and `tools/run-conformance.mjs` are repo-wide; other clusters adding checks or targets will conflict textually. `sdk-py/tests/test_spec_registry.py` and `verifier-rust/tests/spec_registry.rs` are likewise shared registry consumers.

EXISTING TESTS THAT COULD FAIL: (a) `sdk-swift` ParityTests `testDecryptCleanEncryptedWithJsRecipientKey` asserts `trustedSignerCount == 2` for outer+inner signed by the SAME key — Task 13 therefore dedups *per envelope* and sums outer+inner rather than deduping across both; deduping globally would break that test and would also disagree with the Rust doc comment on `VerifyResult::trusted_signer_count`. (b) Rust `encrypted_blob_with_cipher_none_rejected` still passes because the shape block keeps keying off `blob_present`, not the new `is_encrypted`; only the chain-skip decision moved. (c) Rust `every_category_is_exercisable` is a superset assertion, so the new ChainAnchor/Encryption errors are harmless. (d) Python `test_is_encrypted_when_manifest_has_encryption` still passes because that fixture sets cipher AND content.enc as well as manifest.encryption. All verified green.

KNOWN ADJACENT DEFECT LEFT ALONE: sdk-swift `Manifest.CONTENT_INDEX_EXCLUDED` (Manifest.swift:7-11) and sdk-kotlin `Manifest.CONTENT_INDEX_EXCLUDED` (Manifest.kt:6-8) exclude `content.enc` *unconditionally*, where JS/Py/Rust key the exclusion off the signed `envelope.cipher`. That means a clean plain capsule with a smuggled `content.enc` still verifies in those two lanes. It is the container/content-index cluster's call, not C12's, and the `smuggled-blob-broken-chain` vector does not depend on it (its chain bytes are corrupt, so both lanes fail on `chain` and `content_index_hash` regardless). Flag it so it is not lost.

OPERATIONAL: running `node tools/run-conformance.mjs` rewrites `output/conformance-report.{json,md}`; CI auto-commits those on push to main, so leave them out of the manual `git add` lists below. `sdk-py` tests need `pip install -e "sdk-py[dev]"` (or `PYTHONPATH=sdk-py/src`) — a bare `python -m pytest` in `sdk-py/` fails with `ModuleNotFoundError: No module named 'capsule'`.

## Validation performed while specifying this plan

The steps below were applied to a **copy of the repository outside the working tree** and executed. This is the real output from that run, not a prediction.

<details>
<summary>Expand validation log</summary>

```
Applied the entire cluster on a copy at /tmp/work-c12 (repo copied out; the pristine tree was never written to) and ran every lane the machine can run.

FINAL STATE (all fixes + all tests applied):
- 'node tools/run-conformance.mjs' → 'PASS · 11/11 passed · 2.9s total', with the new target '[5/11] semantic-binding-fixtures-regen ... PASS (50ms)' and '[6/11] spec-vectors ... PASS (66ms)'.
- 'cd sdk-js && npm test' → '# tests 61 / # pass 61 / # fail 0' (baseline 57; +4 from test/semantic-binding.test.js).
- 'node tools/check-spec-vectors.mjs' → 'spec vectors: ok (286 vectors)' (baseline 280; +6 semantic-binding vectors).
- 'node sdk-js/tools/generate-semantic-binding-fixtures.mjs --check' → 'ok first-event-hash-drift.capsule (2601 bytes)' … 'ok duplicate-signer.capsule (2880 bytes)' (all 6 byte-identical on regeneration).
- 'cd sdk-py && python -m pytest' → '192 passed in 0.23s' (baseline 182; +4 unit tests, +6 registry params).
- 'cd verifier-rust && cargo test --workspace' → 'test result: ok. 107 passed' (lib, baseline 102), 'ok. 4 passed' (tests/spec_registry.rs, baseline 3), 'ok. 7 passed' (parity), 0 failures anywhere.
- 'cd sdk-swift && DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test' → 'Executed 27 tests, with 0 failures' (baseline 26). Plain 'swift test' fails in this environment with 'no such module 'XCTest'' because xcode-select points at CommandLineTools; DEVELOPER_DIR is a per-process override and changed nothing on the system. CI's 'swift test' on macos-15 has a full Xcode and needs no override.

RED STATE (tests written, fixes reverted) — every test was proven to fail first:
- sdk-js pre-fix: all 4 new tests fail, e.g. 'not ok 1 - verifier rejects manifest.first_event_hash that disagrees with the envelope' / 'decoy manifest.first_event_hash must not verify / true !== false'; 'trustedSignerCount' case fails with 'expected: 1 / actual: 2'.
- 'node tools/check-spec-vectors.mjs' against the unfixed JS verifier printed 7 FAIL lines including '[first-event-hash-drift]: expected ok=false, got ok=true' and '[duplicate-signer]: expected trusted_signer_count=1, got 2', exit 1.
- sdk-py pre-fix: 'FAILED tests/test_verifier.py::test_manifest_first_event_hash_must_match_envelope', '::test_manifest_encryption_must_agree_with_envelope_cipher' (raises 'capsule.reader.MalformedCapsuleError: missing content.enc' — today verify_capsule *throws* on that capsule), '::test_trusted_signer_count_is_distinct_by_key' ('assert 2 == 1'), 'FAILED tests/test_reader.py::test_is_encrypted_ignores_a_smuggled_content_enc' ('assert True is False where True = is_encrypted()'); and 5 of the 6 registry params failed, with the F33 smoking gun printed verbatim: 'smuggled-blob-broken-chain: expected area 'chain' to fail; got {... 'chain': {'ok': True, 'errors': [], 'note': 'deferred to L3 (encrypted outer)'} ...}'.
- verifier-rust pre-fix, hunk by hunk: with 'is_encrypted = files.contains_key("content.enc")' → 'smuggled_blob_does_not_skip_the_chain_walk' fails with 'chain must be walked, not deferred; got note Some("deferred to L3 (encrypted outer)")' (Rust has the same F33-shaped defect as Python, which the finding did not call out); with the original decrypt.rs → 'l3_follows_manifest_declared_metadata_path' fails with 'relocated metadata_path must still decrypt at L3; errors: [TopError { category: Encryption, scope: Inner, message: "L3: decryption failed: decryption metadata missing: skills/decryption/decryption.json" }]' (F42 confirmed); reverting the binding/shape/count hunks failed 'manifest_first_event_hash_must_match_envelope', 'manifest_encryption_must_agree_with_envelope_cipher', and 'trusted_signer_count_is_distinct_by_key' ('left: 2 / right: 1'). 'tests/spec_registry.rs::semantic_binding_registry_outcomes' failed with 'first-event-hash-drift: expected ok=false; errors: []'.
- sdk-swift pre-fix: 'SpecRegistryTests.testSemanticBindingRegistryOutcomes' failed with 6 assertions, including 'encryption-declared-plain: expected reason encryption_shape; got parse:Capsule malformed: encrypted outer missing content.enc' (Swift decides encryption from the manifest and so refuses the capsule for the wrong reason) and 'duplicate-signer: trusted_signer_count must count DISTINCT keys ("2") is not equal to ("1")'.

NOT RUN: sdk-kotlin. 'java -version' in this environment reports "Unable to locate a Java Runtime", so './gradlew :core:test' cannot execute. Tasks 14's Kotlin code was verified by inspection only, against the real API surface I read (JCSValue.Obj(pairs) / Arr(items) / Str(v) / Null in Canonical.kt:14-23, CapsuleReader.lookupString in Reader.kt:53, CapsuleVerification.SignerCheck.publicKey in Verifier.kt:18-23, gson as a 'implementation' dep of :core in core/build.gradle.kts). I removed the two constructs whose Kotlin smart-cast behaviour I was not fully certain of ('String?.isNullOrEmpty()' contract propagation across 'when' branches, and 'kotlin.test.assertNotNull''s contract) in favour of '?: ""' and '?: error(...)', so nothing in the Kotlin patch relies on a contract-based smart cast. It has not been compiled — treat Task 14 as the one task that needs a real './gradlew --no-daemon :core:test' before it is trusted.
```

</details>

---

## C12 — Semantic binding: manifest claims vs envelope and chain facts

Every lane pins the *bytes* of a capsule (container layout, hashes, signatures) and none of them check that the manifest's **claims** agree with the signed envelope, the chain, or the files. A correctly-signed capsule can therefore say `first_event_hash = X` (making `capsule_id = f(X)`, the identity federation attestations bind to) while the envelope and chain say `Y`; can declare encryption it does not have; and can hand one key an M-of-N quorum by repeating its `signers[]` entry. This section closes those and creates `spec/vectors/semantic-binding/` — the registry that pins the layer for every future implementation.

Order matters: Tasks 1–3 fix the JS reference, Task 4 mints fixtures against it, Task 5 wires the registry, Tasks 6–14 bring the other four lanes to the same behaviour using those fixtures.

---

### Task 1: sdk-js — reject manifest.first_event_hash that disagrees with the envelope

**Files:**
- Create: `sdk-js/test/semantic-binding.test.js`
- Modify: `sdk-js/src/verifier.js:114-118`
- Test: `sdk-js/test/semantic-binding.test.js`

**Interfaces:**
- Consumes: `verifyCapsule(readerOrBytes, options) -> Promise<{ok, level, errors, chain, contentIndex, envelope, trustedSignerCount, notes}>`; `signEnvelope(envelope, signers)`; `computeCapsuleId(originatorPubKeyRaw, firstEventHashHex)`; `manifestBytes(manifest)`; `manifestHash(manifest)`; `packZip(files)`; `unpackZip(bytes)`
- Produces: `sealedCapsule({recipients})` and `resign(bytes, ed, mutate)` test helpers in `sdk-js/test/semantic-binding.test.js` (reused by Tasks 2 and 3); a top-level verifier error matching `/manifest\.first_event_hash mismatch/`

- [ ] **Step 1: Write the failing test**

Create `sdk-js/test/semantic-binding.test.js`:

```js
// Semantic-binding tests: the manifest's CLAIMS must agree with the signed
// envelope, the chain, and the files. Each capsule below is well-formed,
// internally consistent, and correctly signed — only its semantics are wrong,
// so nothing but an explicit cross-check catches it.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CapsuleBuilder,
  CapsuleReader,
  verifyCapsule,
  generateEd25519,
  generateX25519,
} from "../src/index.js";
import { hexToBytes } from "../src/canonical.js";
import { signEnvelope } from "../src/envelope.js";
import { computeCapsuleId, manifestBytes, manifestHash } from "../src/manifest.js";
import { packZip, unpackZip } from "../src/zip.js";

const TS = "2026-05-07T12:00:00Z";
const dec = new TextDecoder();

async function sealedCapsule({ recipients = [] } = {}) {
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
    payload: { amount: 1 },
  });
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
    recipients,
  });
  return { bytes: Buffer.from(bytes), ed };
}

/** Mutate manifest/envelope, re-derive every writer-derived value, re-sign. */
async function resign(bytes, ed, mutate) {
  const files = await unpackZip(bytes);
  const manifest = JSON.parse(dec.decode(files.get("manifest.json")));
  const envelope = JSON.parse(dec.decode(files.get("provenance/envelope.json")));
  mutate({ manifest, envelope, files });
  manifest.id = computeCapsuleId(
    hexToBytes(manifest.originator.public_key),
    manifest.first_event_hash,
  );
  envelope.capsule_id = manifest.id;
  files.set("manifest.json", manifestBytes(manifest));
  envelope.manifest_hash = manifestHash(manifest);
  envelope.signers = [];
  signEnvelope(envelope, [
    { role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey },
  ]);
  files.set("provenance/envelope.json", Buffer.from(JSON.stringify(envelope, null, 2), "utf8"));
  return Buffer.from(await packZip(files));
}

test("verifier rejects manifest.first_event_hash that disagrees with the envelope", async () => {
  const { bytes, ed } = await sealedCapsule();
  const drifted = await resign(bytes, ed, ({ manifest }) => {
    manifest.first_event_hash = "de".repeat(32);
  });
  const reader = await CapsuleReader.fromBytes(drifted);
  const result = await verifyCapsule(reader, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, false, "decoy manifest.first_event_hash must not verify");
  assert.ok(
    result.errors.some((e) => /manifest\.first_event_hash mismatch/.test(e)),
    `expected a first_event_hash binding error, got: ${JSON.stringify(result.errors)}`,
  );
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-js && node --test test/semantic-binding.test.js`

Expected: FAIL with `not ok 1 - verifier rejects manifest.first_event_hash that disagrees with the envelope` and error body `decoy manifest.first_event_hash must not verify` / `true !== false` (`expected: false`, `actual: true`).

- [ ] **Step 3: Add the binding check to the verifier**

In `sdk-js/src/verifier.js`, the capsule-identity block ends at line 116 and `// Manifest hash` starts at line 118. Replace:

```js
  } catch (err) {
    errors.push(`capsule_id derivation failed: ${err.message}`);
  }

  // Manifest hash
```

with:

```js
  } catch (err) {
    errors.push(`capsule_id derivation failed: ${err.message}`);
  }

  // Semantic binding: manifest.first_event_hash is the capsule_id input;
  // envelope.first_event_hash is what the chain walk below is checked
  // against. spec/manifest.md and spec/envelope.md both pin them to the
  // hash of chain event 1, so they must be equal — otherwise capsule_id
  // (the identity federation attestations bind to) names a chain the
  // capsule does not carry.
  if (manifest.first_event_hash !== envelope.first_event_hash) {
    errors.push(
      `manifest.first_event_hash mismatch: ${manifest.first_event_hash} vs envelope.first_event_hash ${envelope.first_event_hash}`,
    );
  }

  // Manifest hash
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd sdk-js && node --test test/semantic-binding.test.js`

Expected: PASS

- [ ] **Step 5: Run the full lane suite for regressions**

Run: `cd sdk-js && npm test`

Expected: `# tests 58`, `# pass 58`, `# fail 0`

- [ ] **Step 6: Commit**
```bash
git add sdk-js/src/verifier.js sdk-js/test/semantic-binding.test.js
git commit -m "fix(sdk-js): bind manifest.first_event_hash to envelope.first_event_hash

capsule_id is derived from manifest.first_event_hash, but only
envelope.first_event_hash was ever compared to the recomputed chain
anchor. A correctly-signed capsule could therefore carry a capsule_id
naming a chain it does not contain."
```

---

### Task 2: sdk-js — require manifest.encryption to agree with the signed envelope.cipher

**Files:**
- Modify: `sdk-js/src/verifier.js:182-189`
- Test: `sdk-js/test/semantic-binding.test.js`

**Interfaces:**
- Consumes: `sealedCapsule({recipients})`, `resign(bytes, ed, mutate)` from Task 1; `generateX25519()`; `reader.files_() -> Map<string, Uint8Array>` (already bound to `files` at `sdk-js/src/verifier.js:140`)
- Produces: verifier errors matching `/manifest\.encryption must be/` and `/manifest\.encryption\.metadata_path/`

- [ ] **Step 1: Write the failing test**

Append to `sdk-js/test/semantic-binding.test.js`:

```js
test("verifier rejects manifest.encryption declared on a cipher='none' capsule", async () => {
  const { bytes, ed } = await sealedCapsule();
  const lying = await resign(bytes, ed, ({ manifest }) => {
    manifest.encryption = {
      metadata_path: "skills/decryption/decryption.json",
      cipher: "ChaCha20-Poly1305",
    };
  });
  const reader = await CapsuleReader.fromBytes(lying);
  const result = await verifyCapsule(reader, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, false, "plain capsule declaring encryption must not verify");
  assert.ok(
    result.errors.some((e) => /manifest\.encryption must be null/.test(e)),
    `expected an encryption-shape error, got: ${JSON.stringify(result.errors)}`,
  );
});

test("verifier rejects a metadata_path that is not in the package", async () => {
  const recipient = generateX25519();
  const { bytes, ed } = await sealedCapsule({ recipients: [{ publicKey: recipient.publicKey }] });
  const dangling = await resign(bytes, ed, ({ manifest }) => {
    manifest.encryption.metadata_path = "skills/decryption/absent.json";
  });
  const reader = await CapsuleReader.fromBytes(dangling);
  const result = await verifyCapsule(reader, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, false, "dangling metadata_path must not verify");
  assert.ok(
    result.errors.some((e) => /metadata_path missing from capsule/.test(e)),
    `expected a metadata_path error, got: ${JSON.stringify(result.errors)}`,
  );
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-js && node --test test/semantic-binding.test.js`

Expected: FAIL with `not ok 2 - verifier rejects manifest.encryption declared on a cipher='none' capsule` (`plain capsule declaring encryption must not verify` / `true !== false`) and `not ok 3 - verifier rejects a metadata_path that is not in the package` (`dangling metadata_path must not verify` / `true !== false`).

- [ ] **Step 3: Add the encryption-declaration check**

In `sdk-js/src/verifier.js`, the plain-capsule branch ends at line 187 and `// Chain` starts at line 189. Replace:

```js
    if (envelope.cipher !== "none") {
      errors.push(`plain capsule must have cipher='none', got '${envelope.cipher}'`);
    }
  }

  // Chain
```

with:

```js
    if (envelope.cipher !== "none") {
      errors.push(`plain capsule must have cipher='none', got '${envelope.cipher}'`);
    }
  }

  // Encryption declaration. spec/manifest.md fixes manifest.encryption as
  // null for plain capsules and { metadata_path, cipher } for encrypted
  // ones. The SIGNED envelope.cipher is authoritative; the manifest
  // declaration must agree with it, and the declared metadata_path must
  // resolve to a file that exists AND is covered by the content index.
  const declaredEncryption = manifest.encryption ?? null;
  if (envelope.cipher === "none") {
    if (declaredEncryption !== null) {
      errors.push("manifest.encryption must be null when envelope.cipher is 'none'");
    }
  } else if (declaredEncryption === null || typeof declaredEncryption !== "object") {
    errors.push(
      `manifest.encryption must be an object when envelope.cipher is '${envelope.cipher}'`,
    );
  } else {
    if (declaredEncryption.cipher !== envelope.cipher) {
      errors.push(
        `manifest.encryption.cipher mismatch: ${JSON.stringify(declaredEncryption.cipher)} vs envelope.cipher '${envelope.cipher}'`,
      );
    }
    const metadataPath = declaredEncryption.metadata_path;
    if (typeof metadataPath !== "string" || metadataPath.length === 0) {
      errors.push("manifest.encryption.metadata_path must be a non-empty string");
    } else if (!files.has(metadataPath)) {
      errors.push(`manifest.encryption.metadata_path missing from capsule: ${metadataPath}`);
    } else if (!manifest.content_index.files.some((f) => f.path === metadataPath)) {
      errors.push(
        `manifest.encryption.metadata_path not covered by content index: ${metadataPath}`,
      );
    }
  }

  // Chain
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd sdk-js && node --test test/semantic-binding.test.js`

Expected: PASS

- [ ] **Step 5: Run the full lane suite for regressions**

Run: `cd sdk-js && npm test`

Expected: `# tests 60`, `# pass 60`, `# fail 0`

- [ ] **Step 6: Commit**
```bash
git add sdk-js/src/verifier.js sdk-js/test/semantic-binding.test.js
git commit -m "fix(sdk-js): cross-check manifest.encryption against the signed cipher

manifest.encryption was never compared to envelope.cipher, and a declared
metadata_path was never required to exist or to be covered by the content
index. The signed cipher is authoritative; the declaration must match it."
```

---

### Task 3: sdk-js — count distinct trusted keys, not signers[] entries

**Files:**
- Modify: `sdk-js/src/verifier.js:228`
- Test: `sdk-js/test/semantic-binding.test.js`

**Interfaces:**
- Consumes: `sealedCapsule()` from Task 1; `result.envelope.signers[] = {role, public_key, valid, trusted}`
- Produces: `result.trustedSignerCount` = number of distinct lowercase trusted public keys

- [ ] **Step 1: Write the failing test**

Append to `sdk-js/test/semantic-binding.test.js`:

```js
test("trustedSignerCount counts distinct keys, not signers[] entries", async () => {
  const { bytes, ed } = await sealedCapsule();
  const files = await unpackZip(bytes);
  const envelope = JSON.parse(dec.decode(files.get("provenance/envelope.json")));
  // The signed payload is the envelope minus signers, so a verbatim copy of
  // an existing entry carries a signature that still verifies.
  envelope.signers.push({ ...envelope.signers[0] });
  files.set("provenance/envelope.json", Buffer.from(JSON.stringify(envelope, null, 2), "utf8"));
  const doubled = Buffer.from(await packZip(files));

  const reader = await CapsuleReader.fromBytes(doubled);
  const result = await verifyCapsule(reader, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.envelope.signers.length, 2, "both signer entries are present");
  assert.ok(result.envelope.signers.every((s) => s.valid), "both copies verify");
  assert.equal(result.trustedSignerCount, 1, "one key must count once");
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-js && node --test test/semantic-binding.test.js`

Expected: FAIL with `not ok 4 - trustedSignerCount counts distinct keys, not signers[] entries`, `expected: 1`, `actual: 2`.

- [ ] **Step 3: Dedup the count by public key**

In `sdk-js/src/verifier.js`, replace line 228:

```js
  result.trustedSignerCount = result.envelope.signers.filter((s) => s.trusted).length;
```

with:

```js
  // Count DISTINCT trusted public keys. The signed payload is the envelope
  // minus signers, so a duplicated signers[] entry carries a signature that
  // still verifies; counting entries would let one key satisfy an M-of-N
  // policy by appending a copy of itself.
  result.trustedSignerCount = new Set(
    result.envelope.signers.filter((s) => s.trusted).map((s) => s.public_key.toLowerCase()),
  ).size;
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd sdk-js && node --test test/semantic-binding.test.js`

Expected: PASS

- [ ] **Step 5: Run the full lane suite for regressions**

Run: `cd sdk-js && npm test`

Expected: `# tests 61`, `# pass 61`, `# fail 0`

- [ ] **Step 6: Commit**
```bash
git add sdk-js/src/verifier.js sdk-js/test/semantic-binding.test.js
git commit -m "fix(sdk-js): count distinct trusted keys in trustedSignerCount

A duplicated signers[] entry re-verifies against the same signing input,
so counting entries let a single key satisfy an M-of-N trust policy."
```

---

### Task 4: spec/vectors/semantic-binding — fixture generator and fixture bytes

**Files:**
- Create: `sdk-js/tools/generate-semantic-binding-fixtures.mjs`
- Create: `spec/vectors/semantic-binding/output/first-event-hash-drift.capsule` (generated)
- Create: `spec/vectors/semantic-binding/output/encryption-declared-plain.capsule` (generated)
- Create: `spec/vectors/semantic-binding/output/encryption-metadata-path-dangling.capsule` (generated)
- Create: `spec/vectors/semantic-binding/output/encryption-metadata-path-relocated.capsule` (generated)
- Create: `spec/vectors/semantic-binding/output/smuggled-blob-broken-chain.capsule` (generated)
- Create: `spec/vectors/semantic-binding/output/duplicate-signer.capsule` (generated)
- Test: `node sdk-js/tools/generate-semantic-binding-fixtures.mjs --check` (self-checking generator, same contract as `sdk-js/tools/generate-malformed-fixtures.mjs`)

**Interfaces:**
- Consumes: `spec/vectors/tamper-detection/output/{clean,clean-encrypted,tampered-chain}.capsule` and `keys.json`; `signEnvelope`, `buildContentIndex(files, excluded)`, `contentIndexExclusions(encrypted)`, `computeCapsuleId`, `manifestBytes`, `manifestHash`, `packZip`, `unpackZip`
- Produces: the six fixture files above, consumed by Tasks 5–14

- [ ] **Step 1: Write the failing test**

The generator is its own test: `--check` regenerates deterministically and byte-compares. Create the directory and confirm the check has nothing to compare against yet.

Run: `mkdir -p spec/vectors/semantic-binding/output && ls spec/vectors/semantic-binding/output`

Expected: empty listing — no fixtures exist, so `--check` cannot pass.

- [ ] **Step 2: Run the test to verify it fails**

Run: `node sdk-js/tools/generate-semantic-binding-fixtures.mjs --check`

Expected: FAIL with `Error: Cannot find module '/…/sdk-js/tools/generate-semantic-binding-fixtures.mjs'` (the generator does not exist yet).

- [ ] **Step 3: Write the generator**

Create `sdk-js/tools/generate-semantic-binding-fixtures.mjs`:

```js
#!/usr/bin/env node
// generate-semantic-binding-fixtures.mjs
//
// Generates the semantic-binding conformance fixtures under
// spec/vectors/semantic-binding/output/. Every fixture is derived
// deterministically from the checked-in tamper-detection fixtures
// (clean.capsule, clean-encrypted.capsule, tampered-chain.capsule) and,
// where the mutation touches signed bytes, RE-SIGNED with the throwaway
// fixture key in ../tamper-detection/output/keys.json.
//
// These are the capsules a well-formed container and a valid signature
// cannot catch: the manifest is internally consistent and correctly
// signed, it just does not agree with the envelope, the chain, or the
// files. Fixture -> expected outcome lives in
// spec/vectors/semantic-binding/vectors.json (the language-neutral
// registry); this script only (re)generates the capsule bytes.
// Regeneration is an intentional spec change; review the byte-level diff.
// Pass --check to compare generated bytes with the checked-in fixtures.

import { readFile, mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { hexToBytes } from "../src/canonical.js";
import { signEnvelope } from "../src/envelope.js";
import {
  buildContentIndex,
  computeCapsuleId,
  contentIndexExclusions,
  manifestBytes,
  manifestHash,
} from "../src/manifest.js";
import { packZip, unpackZip } from "../src/zip.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..");
const TAMPER_DIR = join(REPO_ROOT, "spec", "vectors", "tamper-detection", "output");
const OUT_DIR = join(REPO_ROOT, "spec", "vectors", "semantic-binding", "output");
const CHECK = process.argv.includes("--check");

// Obviously-fake 64-hex value: no chain event hashes to it.
const DECOY_FIRST_EVENT_HASH = "de".repeat(32);
// Deterministic filler for the smuggled blob — never a real ciphertext.
const FAKE_BLOB = Buffer.from("not a ChaCha20-Poly1305 ciphertext\n", "utf8");

const dec = new TextDecoder();

/** Sorted Map<path, Uint8Array> for a checked-in tamper-detection fixture. */
async function loadCapsule(name) {
  return unpackZip(await readFile(join(TAMPER_DIR, name)));
}

/** The throwaway conformance signer shared with the tamper-detection lane. */
async function fixtureSigner() {
  const keys = JSON.parse(await readFile(join(TAMPER_DIR, "keys.json"), "utf8"));
  return {
    role: "originator",
    publicKey: hexToBytes(keys.originator.publicKey),
    privateKey: hexToBytes(keys.originator.privateKey),
  };
}

function readJson(files, path) {
  return JSON.parse(dec.decode(files.get(path)));
}

function writeJson(files, path, value) {
  files.set(path, Buffer.from(JSON.stringify(value, null, 2), "utf8"));
}

/**
 * Apply `mutate({ manifest, envelope, files })`, then re-derive everything a
 * conforming writer derives (capsule_id, manifest_hash, optionally the
 * content index) and re-sign the envelope. The result is a capsule that is
 * self-consistent and correctly signed — only its *semantics* are wrong.
 */
async function resign(files, signer, { encrypted = false, rebuildIndex = false, mutate }) {
  const manifest = readJson(files, "manifest.json");
  const envelope = readJson(files, "provenance/envelope.json");
  mutate({ manifest, envelope, files });
  if (rebuildIndex) {
    manifest.content_index = buildContentIndex(files, contentIndexExclusions(encrypted));
    envelope.content_index_hash = manifest.content_index.index_hash;
  }
  manifest.id = computeCapsuleId(
    hexToBytes(manifest.originator.public_key),
    manifest.first_event_hash,
  );
  envelope.capsule_id = manifest.id;
  files.set("manifest.json", manifestBytes(manifest));
  envelope.manifest_hash = manifestHash(manifest);
  envelope.signers = [];
  signEnvelope(envelope, [signer]);
  writeJson(files, "provenance/envelope.json", envelope);
  return Buffer.from(await packZip(files));
}

async function main() {
  await mkdir(OUT_DIR, { recursive: true });
  const signer = await fixtureSigner();

  const fixtures = {
    // manifest.first_event_hash (the capsule_id input) drifts away from
    // envelope.first_event_hash (which still matches chain event 1), so
    // capsule_id names a chain this capsule does not carry.
    "first-event-hash-drift.capsule": await resign(await loadCapsule("clean.capsule"), signer, {
      mutate: ({ manifest }) => {
        manifest.first_event_hash = DECOY_FIRST_EVENT_HASH;
      },
    }),

    // Plain capsule (signed cipher "none", no content.enc) that declares
    // encryption in the manifest. Readers that answer "is this encrypted?"
    // from the manifest skip the chain walk on a plain capsule.
    "encryption-declared-plain.capsule": await resign(
      await loadCapsule("clean.capsule"),
      signer,
      {
        mutate: ({ manifest }) => {
          manifest.encryption = {
            metadata_path: "skills/decryption/decryption.json",
            cipher: "ChaCha20-Poly1305",
          };
        },
      },
    ),

    // Encrypted capsule whose declared metadata_path is not in the package.
    "encryption-metadata-path-dangling.capsule": await resign(
      await loadCapsule("clean-encrypted.capsule"),
      signer,
      {
        encrypted: true,
        mutate: ({ manifest }) => {
          manifest.encryption.metadata_path = "skills/decryption/absent.json";
        },
      },
    ),

    // Encrypted capsule whose decryption metadata really does live at a
    // non-default path. This one MUST verify, and any lane that decrypts
    // must resolve the path through manifest.encryption.metadata_path.
    "encryption-metadata-path-relocated.capsule": await resign(
      await loadCapsule("clean-encrypted.capsule"),
      signer,
      {
        encrypted: true,
        rebuildIndex: true,
        mutate: ({ manifest, files }) => {
          const meta = files.get("skills/decryption/decryption.json");
          files.delete("skills/decryption/decryption.json");
          files.set("skills/decryption/keys-v2.json", meta);
          manifest.encryption.metadata_path = "skills/decryption/keys-v2.json";
        },
      },
    ),

    // Broken chain plus a smuggled content.enc. The signed cipher is still
    // "none", so the chain MUST still be walked (and must still fail); a
    // reader that switches to encrypted mode on file presence reports
    // chain.ok=true for a chain it never looked at.
    "smuggled-blob-broken-chain.capsule": await (async () => {
      const files = await loadCapsule("tampered-chain.capsule");
      files.set("content.enc", FAKE_BLOB);
      return Buffer.from(await packZip(files));
    })(),

    // The single originator signer entry, duplicated verbatim. Both copies
    // verify (the signed payload is the envelope minus signers), so a
    // count of entries reports two trusted signers for one key.
    "duplicate-signer.capsule": await (async () => {
      const files = await loadCapsule("clean.capsule");
      const envelope = readJson(files, "provenance/envelope.json");
      envelope.signers.push({ ...envelope.signers[0] });
      writeJson(files, "provenance/envelope.json", envelope);
      return Buffer.from(await packZip(files));
    })(),
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

- [ ] **Step 4: Generate the fixture bytes**

Run: `node sdk-js/tools/generate-semantic-binding-fixtures.mjs`

Expected:
```
wrote first-event-hash-drift.capsule (2601 bytes)
wrote encryption-declared-plain.capsule (2679 bytes)
wrote encryption-metadata-path-dangling.capsule (5369 bytes)
wrote encryption-metadata-path-relocated.capsule (5361 bytes)
wrote smuggled-blob-broken-chain.capsule (2734 bytes)
wrote duplicate-signer.capsule (2880 bytes)
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `node sdk-js/tools/generate-semantic-binding-fixtures.mjs --check`

Expected: PASS — six `ok <name> (<n> bytes)` lines, exit 0 (regeneration is byte-identical).

- [ ] **Step 6: Run the full lane suite for regressions**

Run: `cd sdk-js && npm test`

Expected: `# tests 61`, `# pass 61`, `# fail 0` (unchanged — the generator adds no runtime code)

- [ ] **Step 7: Commit**
```bash
git add sdk-js/tools/generate-semantic-binding-fixtures.mjs spec/vectors/semantic-binding/output
git commit -m "feat(spec): add semantic-binding conformance fixtures

Six capsules whose container, hashes and signatures are all well-formed
but whose manifest claims disagree with the envelope, the chain, or the
files. Derived deterministically from the tamper-detection fixtures and
re-signed with that lane's throwaway key."
```

---

### Task 5: spec/vectors/semantic-binding — vectors.json, checker wiring, harness target

**Files:**
- Create: `spec/vectors/semantic-binding/vectors.json`
- Modify: `tools/check-spec-vectors.mjs:147` (add `VERIFY_REASON` + `KNOWN_REQUIREMENTS` after `OPEN_REASON`)
- Modify: `tools/check-spec-vectors.mjs:154-164` (keep the parsed keys doc)
- Modify: `tools/check-spec-vectors.mjs:169-172` (validate `requires`)
- Modify: `tools/check-spec-vectors.mjs:225-234` (hoist the haystack; add `reason` / `trusted_signer_count` / `decryptable_with`)
- Modify: `tools/run-conformance.mjs:92-93` (new `semantic-binding-fixtures-regen` target)
- Test: `node tools/check-spec-vectors.mjs`

**Interfaces:**
- Consumes: the six fixtures from Task 4; `CapsuleReader.decrypt({recipientPublicKey, recipientPrivateKey})`
- Produces: the registry schema every other lane consumes — `expected.{ok, failing[], reason, error_includes, trusted_signer_count, decryptable_with}`, vector-level `requires[]`, doc-level `reasons{}` / `keys_file` / `generator`

- [ ] **Step 1: Write the failing test**

Create `spec/vectors/semantic-binding/vectors.json`:

```json
{
  "meta": {
    "name": "semantic-binding",
    "spec_version": "0.6",
    "description": "Language-neutral expected outcomes for capsules whose container, hashes, and signatures are all well-formed, but whose manifest CLAIMS disagree with the signed envelope, the chain, or the files on disk. Every fixture here opens cleanly and (where the mutation touched signed bytes) carries a valid originator signature over its own manifest — the defect is semantic, not structural. Unless a vector says otherwise the stage is 'verify': the capsule opens and verification must report ok=false.",
    "no_warranty": "Conformance fixtures only; not production templates or advice."
  },
  "generator": "sdk-js/tools/generate-semantic-binding-fixtures.mjs (derived from ../tamper-detection/output/clean.capsule, clean-encrypted.capsule and tampered-chain.capsule; re-signed with the throwaway key in ../tamper-detection/output/keys.json)",
  "keys_file": "../tamper-detection/output/keys.json",
  "reasons": {
    "first_event_hash_binding": "manifest.first_event_hash, envelope.first_event_hash and the hash of chain event 1 do not all agree. manifest.first_event_hash is the capsule_id preimage, so a drift here means capsule_id names a chain the capsule does not carry",
    "encryption_shape": "manifest.encryption disagrees with the SIGNED envelope.cipher: non-null on a cipher='none' capsule, null on an encrypted one, or naming a different cipher",
    "encryption_metadata_path": "manifest.encryption.metadata_path does not resolve to a file that is present in the package AND covered by manifest.content_index"
  },
  "notes": [
    "The 'reason' field is normative when present: an implementation must reject the fixture for the named reason category. Exact error strings are implementation-defined.",
    "'failing' names the result areas that must be reported failed, using the same area vocabulary as tamper-detection/vectors.json (content_index, chain, envelope, encrypted_blob).",
    "'trusted_signer_count' is normative when present: it is the number of DISTINCT allowlisted public keys whose signature verified, not the number of signers[] entries.",
    "'decryptable_with' names a keypair in keys_file. Lanes that implement L3 decryption MUST decrypt the fixture using that keypair, resolving the decryption metadata through manifest.encryption.metadata_path rather than a hardcoded path. Lanes with no decryption support skip it.",
    "'requires' lists optional capabilities a lane must implement before the vector is meaningful. The only value defined today is 'encryption'. A lane that does not implement a listed capability SKIPS the vector rather than asserting on it — the Kotlin core is a plain-capsule L2 verifier and refuses encrypted capsules at open time."
  ],
  "vectors": [
    {
      "name": "first-event-hash-drift",
      "capsule_file": "output/first-event-hash-drift.capsule",
      "expected": { "ok": false, "reason": "first_event_hash_binding" },
      "note": "manifest.first_event_hash is a decoy; manifest.id and envelope.capsule_id are correctly derived from it and the envelope is validly signed, while envelope.first_event_hash still matches chain event 1."
    },
    {
      "name": "encryption-declared-plain",
      "capsule_file": "output/encryption-declared-plain.capsule",
      "expected": { "ok": false, "reason": "encryption_shape" },
      "note": "Signed cipher is 'none' and there is no content.enc, but the manifest declares encryption. A reader that answers 'is this encrypted?' from the manifest skips the chain walk on a plain capsule."
    },
    {
      "name": "encryption-metadata-path-dangling",
      "capsule_file": "output/encryption-metadata-path-dangling.capsule",
      "requires": ["encryption"],
      "expected": { "ok": false, "reason": "encryption_metadata_path" },
      "note": "Encrypted capsule whose declared metadata_path names a file that is not in the package."
    },
    {
      "name": "encryption-metadata-path-relocated",
      "capsule_file": "output/encryption-metadata-path-relocated.capsule",
      "requires": ["encryption"],
      "expected": { "ok": true, "decryptable_with": "recipient" },
      "note": "Positive control: the decryption metadata really lives at skills/decryption/keys-v2.json and is covered by the content index. Verification must pass, and L3 decryption must follow manifest.encryption.metadata_path."
    },
    {
      "name": "smuggled-blob-broken-chain",
      "capsule_file": "output/smuggled-blob-broken-chain.capsule",
      "expected": { "ok": false, "failing": ["chain", "content_index"] },
      "note": "Signed cipher is 'none' but a content.enc was appended, and chain/events.jsonl is corrupt. Encrypted-mode detection must key off the signed cipher, not file presence, or the chain is never walked and chain.ok is reported true for a broken chain."
    },
    {
      "name": "duplicate-signer",
      "capsule_file": "output/duplicate-signer.capsule",
      "expected": { "ok": true, "trusted_signer_count": 1 },
      "note": "The originator signer entry is duplicated verbatim. Both copies verify because the signed payload is the envelope minus signers, so counting entries would let one key satisfy an M-of-N policy."
    }
  ]
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node tools/check-spec-vectors.mjs`

Expected: FAIL with `FAIL: …/semantic-binding/vectors.json [first-event-hash-drift]: unknown failing area` — no; concretely, the checker does not yet understand `reason`, `trusted_signer_count` or `decryptable_with`, so it silently accepts them and reports `spec vectors: ok (286 vectors)` **without asserting any of the new fields**. Confirm the gap explicitly instead:

Run: `node -e "const d=require('./spec/vectors/semantic-binding/vectors.json'); const src=require('fs').readFileSync('tools/check-spec-vectors.mjs','utf8'); for (const k of ['reason','trusted_signer_count','decryptable_with','requires']) if (!src.includes('expected.'+k) && !src.includes('v.'+k)) { console.error('checker ignores expected.'+k); process.exitCode=1; }"`

Expected: FAIL with `checker ignores expected.reason`, `checker ignores expected.trusted_signer_count`, `checker ignores expected.decryptable_with`, `checker ignores expected.requires`, exit 1.

- [ ] **Step 3: Teach the checker the new reason and requirement vocabularies**

In `tools/check-spec-vectors.mjs`, after the `OPEN_REASON` table (ends line 147) insert:

```js
// Map a verify-stage `reason` category (semantic-binding/vectors.json) to
// the JS reference lane's error message. Same contract as OPEN_REASON: the
// category is normative, the string is implementation-defined per lane.
const VERIFY_REASON = {
  first_event_hash_binding: /manifest\.first_event_hash mismatch/,
  encryption_shape: /manifest\.encryption must be/,
  encryption_metadata_path: /manifest\.encryption\.metadata_path/,
};

// Optional lane capabilities a vector may require. The JS reference lane
// implements all of them and therefore skips nothing; the list exists so a
// typo in a vector's `requires` cannot silently make other lanes skip it.
const KNOWN_REQUIREMENTS = new Set(["encryption"]);
```

- [ ] **Step 4: Keep the parsed keys document for decryption vectors**

In `checkCollection` (lines 154-164), replace:

```js
  let allowlist = [];
  if (doc.originator_public_key_hex) {
    allowlist = [doc.originator_public_key_hex];
  } else if (doc.keys_file) {
    try {
      const keys = JSON.parse(await readFile(join(base, doc.keys_file), "utf8"));
      if (keys.originator?.publicKey) allowlist = [keys.originator.publicKey];
```

with:

```js
  let allowlist = [];
  let keys = null;
  if (doc.originator_public_key_hex) {
    allowlist = [doc.originator_public_key_hex];
  } else if (doc.keys_file) {
    try {
      keys = JSON.parse(await readFile(join(base, doc.keys_file), "utf8"));
      if (keys.originator?.publicKey) allowlist = [keys.originator.publicKey];
```

- [ ] **Step 5: Validate `requires` on every vector**

In `checkCollection`, replace lines 169-172:

```js
    if (!v.capsule_file || !v.expected) {
      fail(`${label}: vector requires capsule_file and expected`);
      continue;
    }
```

with:

```js
    if (!v.capsule_file || !v.expected) {
      fail(`${label}: vector requires capsule_file and expected`);
      continue;
    }
    for (const req of v.requires ?? []) {
      if (!KNOWN_REQUIREMENTS.has(req)) fail(`${label}: unknown requirement '${req}'`);
    }
```

- [ ] **Step 6: Assert reason, trusted_signer_count and decryptable_with**

Replace lines 225-234:

```js
    if (v.expected.error_includes) {
      const haystack = [
        ...result.errors,
        ...result.contentIndex.errors,
        ...(result.chain.errors ?? []).map((e) => (typeof e === "string" ? e : e.message ?? "")),
      ].join(" ");
      if (!haystack.includes(v.expected.error_includes)) {
        fail(`${label}: expected an error containing '${v.expected.error_includes}'`);
      }
    }
```

with:

```js
    const haystack = [
      ...result.errors,
      ...result.contentIndex.errors,
      ...(result.chain.errors ?? []).map((e) => (typeof e === "string" ? e : e.message ?? "")),
    ].join(" ");
    if (v.expected.error_includes && !haystack.includes(v.expected.error_includes)) {
      fail(`${label}: expected an error containing '${v.expected.error_includes}'`);
    }
    if (v.expected.reason) {
      const pattern = VERIFY_REASON[v.expected.reason];
      if (!pattern) {
        fail(`${label}: unknown verify-stage reason '${v.expected.reason}'`);
      } else if (!pattern.test(haystack)) {
        fail(`${label}: expected an error for reason '${v.expected.reason}'; got: ${haystack}`);
      }
    }
    if (typeof v.expected.trusted_signer_count === "number") {
      if (result.trustedSignerCount !== v.expected.trusted_signer_count) {
        fail(
          `${label}: expected trusted_signer_count=${v.expected.trusted_signer_count}, ` +
            `got ${result.trustedSignerCount}`,
        );
      }
    }
    if (v.expected.decryptable_with) {
      const pair = keys?.[v.expected.decryptable_with];
      if (!pair?.publicKey || !pair?.privateKey) {
        fail(`${label}: keys_file has no keypair '${v.expected.decryptable_with}'`);
      } else {
        try {
          const inner = await reader.decrypt({
            recipientPublicKey: pair.publicKey,
            recipientPrivateKey: pair.privateKey,
          });
          const innerResult = await verifyCapsule(inner, { allowlist });
          if (!innerResult.ok) {
            fail(`${label}: inner capsule does not verify: ${innerResult.errors.join("; ")}`);
          }
        } catch (err) {
          fail(`${label}: decrypt with '${v.expected.decryptable_with}' failed: ${err.message}`);
        }
      }
    }
```

- [ ] **Step 7: Add the regeneration target to the conformance harness**

In `tools/run-conformance.mjs`, the `malformed-fixtures-regen` entry ends at line 92 and `spec-vectors` starts at line 93. Replace:

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
    id: "semantic-binding-fixtures-regen",
    name: "semantic-binding fixture regeneration check",
    language: "javascript",
    kind: "check",
    cwd: ".",
    install_cmd: "true",
    test_cmd: "node sdk-js/tools/generate-semantic-binding-fixtures.mjs --check",
    pass_signal: { type: "exit_code", value: 0 },
  },
  {
    id: "spec-vectors",
```

- [ ] **Step 8: Run the test to verify it passes**

Run: `node tools/check-spec-vectors.mjs`

Expected: PASS — `spec vectors: ok (286 vectors)` (280 before this task; the six semantic-binding vectors are now asserted, not just parsed).

- [ ] **Step 9: Run the full lane suite for regressions**

Run: `node tools/run-conformance.mjs`

Expected: `PASS · 11/11 passed`, with `[5/11] semantic-binding-fixtures-regen ... PASS` and `[6/11] spec-vectors ... PASS`.

- [ ] **Step 10: Commit**
```bash
git add spec/vectors/semantic-binding/vectors.json tools/check-spec-vectors.mjs tools/run-conformance.mjs
git commit -m "feat(spec): add the semantic-binding outcome registry

Language-neutral expectations for manifest-vs-envelope-vs-chain binding.
Extends the collection schema with a verify-stage reason vocabulary, a
distinct-key trusted_signer_count assertion, an L3 decryptable_with hint,
and a per-vector requires[] so plain-only lanes can skip encrypted
fixtures instead of hardcoding names."
```

---

### Task 6: sdk-py — is_encrypted uses AND semantics, keyed off the signed cipher

**Files:**
- Modify: `sdk-py/src/capsule/reader.py:48-53`
- Test: `sdk-py/tests/test_reader.py` (append)

**Interfaces:**
- Consumes: `spec/vectors/semantic-binding/output/smuggled-blob-broken-chain.capsule` (Task 4)
- Produces: `CapsuleReader.is_encrypted() -> bool` == `envelope.cipher != "none" and "content.enc" in files` (parity with `sdk-js/src/reader.js:79-81`)

- [ ] **Step 1: Write the failing test**

Append to `sdk-py/tests/test_reader.py`:

```python
def test_is_encrypted_ignores_a_smuggled_content_enc():
    """The SIGNED envelope.cipher decides, not file presence.

    smuggled-blob-broken-chain.capsule is a plain (cipher="none") capsule
    with a content.enc appended and a corrupt chain. OR-semantics here
    flip the reader into encrypted mode, and verify_capsule then defers the
    chain to L3 and reports chain.ok=True for a chain nobody walked.
    """
    import pathlib

    from capsule.verifier import verify_capsule

    path = (
        pathlib.Path(__file__).resolve().parents[2]
        / "spec/vectors/semantic-binding/output/smuggled-blob-broken-chain.capsule"
    )
    reader = CapsuleReader.from_bytes(path.read_bytes())
    assert reader.envelope()["cipher"] == "none"
    assert "content.enc" in reader.files()
    assert reader.is_encrypted() is False

    result = verify_capsule(reader)
    assert "note" not in result["chain"], "the chain must be walked, not deferred"
    assert result["chain"]["ok"] is False, "the corrupt chain must fail"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest sdk-py/tests/test_reader.py::test_is_encrypted_ignores_a_smuggled_content_enc -q`

Expected: FAIL with `assert True is False` / `+  where True = is_encrypted()` / `+    where is_encrypted = <capsule.reader.CapsuleReader object …>.is_encrypted`

- [ ] **Step 3: Replace the OR-semantics with AND semantics**

In `sdk-py/src/capsule/reader.py`, replace lines 48-53:

```python
    def is_encrypted(self) -> bool:
        if isinstance(self._manifest.get("encryption"), dict):
            return True
        if self._envelope.get("cipher") not in (None, "none"):
            return True
        return "content.enc" in self._files
```

with:

```python
    def is_encrypted(self) -> bool:
        """True only for a genuine encrypted-outer capsule.

        Mirrors ``sdk-js/src/reader.js``: the SIGNED ``envelope.cipher``
        AND the presence of ``content.enc``. The manifest's ``encryption``
        declaration is deliberately NOT an input — it is cross-checked by
        ``verify_capsule`` instead. With OR-semantics an attacker who
        merely appends a ``content.enc`` flips the capsule into
        encrypted mode, and chain verification is skipped.
        """
        return self._envelope.get("cipher") != "none" and "content.enc" in self._files
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest sdk-py/tests/test_reader.py::test_is_encrypted_ignores_a_smuggled_content_enc -q`

Expected: PASS

- [ ] **Step 5: Run the full lane suite for regressions**

Run: `python -m pytest sdk-py/tests/ -q`

Expected: `183 passed` (182 before, +1). In particular `test_is_encrypted_when_manifest_has_encryption` still passes — its fixture sets `cipher` and `content.enc` as well as `manifest.encryption`.

- [ ] **Step 6: Commit**
```bash
git add sdk-py/src/capsule/reader.py sdk-py/tests/test_reader.py
git commit -m "fix(sdk-py): is_encrypted requires the signed cipher AND content.enc

OR-semantics let anyone who appends a content.enc flip the reader into
encrypted mode; verify_capsule then skipped the chain walk entirely and
reported chain.ok=True for a broken chain."
```

---

### Task 7: sdk-py — first_event_hash binding and manifest.encryption agreement

**Files:**
- Modify: `sdk-py/src/capsule/verifier.py:117-120`
- Modify: `sdk-py/src/capsule/verifier.py:192-195`
- Test: `sdk-py/tests/test_verifier.py` (append)

**Interfaces:**
- Consumes: fixtures from Task 4; `files` (bound at `sdk-py/src/capsule/verifier.py:137`) and `stored_files` (bound at line 145) are already in scope at the insertion point
- Produces: error strings `manifest.first_event_hash mismatch: …`, `manifest.encryption must be …`, `manifest.encryption.metadata_path …`; test helpers `_semantic(name)` and `_fixture_originator()` reused by Task 8

- [ ] **Step 1: Write the failing test**

Append to `sdk-py/tests/test_verifier.py`:

```python
def _semantic(name: str) -> bytes:
    import pathlib

    return (
        pathlib.Path(__file__).resolve().parents[2]
        / "spec/vectors/semantic-binding/output"
        / name
    ).read_bytes()


def _fixture_originator() -> str:
    import pathlib

    keys = json.loads(
        (
            pathlib.Path(__file__).resolve().parents[2]
            / "spec/vectors/tamper-detection/output/keys.json"
        ).read_text()
    )
    return keys["originator"]["publicKey"]


def test_manifest_first_event_hash_must_match_envelope():
    # manifest.first_event_hash is the capsule_id preimage; the fixture's
    # manifest.id and envelope.capsule_id are derived from a decoy value and
    # the envelope is validly signed, so only the cross-check catches it.
    reader = CapsuleReader.from_bytes(_semantic("first-event-hash-drift.capsule"))
    result = verify_capsule(reader, allowlist=[_fixture_originator()])
    assert result["ok"] is False
    assert any("manifest.first_event_hash mismatch" in e for e in result["errors"]), result[
        "errors"
    ]


def test_manifest_encryption_must_agree_with_envelope_cipher():
    declared = verify_capsule(
        CapsuleReader.from_bytes(_semantic("encryption-declared-plain.capsule")),
        allowlist=[_fixture_originator()],
    )
    assert declared["ok"] is False
    assert any("manifest.encryption must be" in e for e in declared["errors"]), declared["errors"]

    dangling = verify_capsule(
        CapsuleReader.from_bytes(_semantic("encryption-metadata-path-dangling.capsule")),
        allowlist=[_fixture_originator()],
    )
    assert dangling["ok"] is False
    assert any("manifest.encryption.metadata_path" in e for e in dangling["errors"]), dangling[
        "errors"
    ]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest sdk-py/tests/test_verifier.py -q -k "first_event_hash_must_match or encryption_must_agree"`

Expected: FAIL — `test_manifest_first_event_hash_must_match_envelope` with `assert True is False`; `test_manifest_encryption_must_agree_with_envelope_cipher` with `capsule.reader.MalformedCapsuleError: missing content.enc` (today `is_encrypted()` is true for that capsule, so `verify_capsule` raises instead of returning a result).

- [ ] **Step 3: Add the first_event_hash binding check**

In `sdk-py/src/capsule/verifier.py`, replace lines 117-120:

```python
    except (KeyError, ValueError, TypeError) as e:
        errors.append(f"capsule_id derivation failed: {e}")

    # Manifest hash
```

with:

```python
    except (KeyError, ValueError, TypeError) as e:
        errors.append(f"capsule_id derivation failed: {e}")

    # Semantic binding: manifest.first_event_hash is the capsule_id input;
    # envelope.first_event_hash is what the chain walk below is checked
    # against. spec/manifest.md and spec/envelope.md both pin them to the
    # hash of chain event 1, so they must be equal — otherwise capsule_id
    # names a chain the capsule does not carry.
    if manifest.get("first_event_hash") != envelope.get("first_event_hash"):
        errors.append(
            "manifest.first_event_hash mismatch: "
            f"{manifest.get('first_event_hash')} vs envelope.first_event_hash "
            f"{envelope.get('first_event_hash')}"
        )

    # Manifest hash
```

- [ ] **Step 4: Add the encryption-declaration check**

In `sdk-py/src/capsule/verifier.py`, replace lines 192-195:

```python
        if envelope.get("cipher") != "none":
            errors.append(f"plain capsule must have cipher='none', got {envelope.get('cipher')!r}")

    # Chain
```

with:

```python
        if envelope.get("cipher") != "none":
            errors.append(f"plain capsule must have cipher='none', got {envelope.get('cipher')!r}")

    # Encryption declaration. spec/manifest.md fixes manifest.encryption as
    # null for plain capsules and {metadata_path, cipher} for encrypted ones.
    # The SIGNED envelope.cipher is authoritative; the manifest declaration
    # must agree with it, and the declared metadata_path must resolve to a
    # file that exists AND is covered by the content index.
    declared_encryption = manifest.get("encryption")
    if envelope.get("cipher") == "none":
        if declared_encryption is not None:
            errors.append("manifest.encryption must be null when envelope.cipher is 'none'")
    elif not isinstance(declared_encryption, dict):
        errors.append(
            "manifest.encryption must be an object when envelope.cipher is "
            f"{envelope.get('cipher')!r}"
        )
    else:
        if declared_encryption.get("cipher") != envelope.get("cipher"):
            errors.append(
                f"manifest.encryption.cipher mismatch: {declared_encryption.get('cipher')!r} "
                f"vs envelope.cipher {envelope.get('cipher')!r}"
            )
        metadata_path = declared_encryption.get("metadata_path")
        if not isinstance(metadata_path, str) or not metadata_path:
            errors.append("manifest.encryption.metadata_path must be a non-empty string")
        elif metadata_path not in files:
            errors.append(
                f"manifest.encryption.metadata_path missing from capsule: {metadata_path}"
            )
        elif not any(f["path"] == metadata_path for f in stored_files):
            errors.append(
                "manifest.encryption.metadata_path not covered by content index: "
                f"{metadata_path}"
            )

    # Chain
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `python -m pytest sdk-py/tests/test_verifier.py -q -k "first_event_hash_must_match or encryption_must_agree"`

Expected: PASS

- [ ] **Step 6: Run the full lane suite for regressions**

Run: `python -m pytest sdk-py/tests/ -q`

Expected: `185 passed`

- [ ] **Step 7: Commit**
```bash
git add sdk-py/src/capsule/verifier.py sdk-py/tests/test_verifier.py
git commit -m "fix(sdk-py): bind manifest first_event_hash and encryption to the envelope

Mirrors sdk-js: manifest.first_event_hash must equal
envelope.first_event_hash, and manifest.encryption must agree with the
signed cipher and point at an indexed, present metadata file."
```

---

### Task 8: sdk-py — count distinct trusted keys

**Files:**
- Modify: `sdk-py/src/capsule/verifier.py:249`
- Test: `sdk-py/tests/test_verifier.py` (append)

**Interfaces:**
- Consumes: `_semantic(name)`, `_fixture_originator()` from Task 7
- Produces: `result["trusted_signer_count"]` = number of distinct lowercase trusted public keys

- [ ] **Step 1: Write the failing test**

Append to `sdk-py/tests/test_verifier.py`:

```python
def test_trusted_signer_count_is_distinct_by_key():
    # The signed payload is the envelope minus signers, so a verbatim copy
    # of an existing entry still verifies.
    reader = CapsuleReader.from_bytes(_semantic("duplicate-signer.capsule"))
    result = verify_capsule(reader, allowlist=[_fixture_originator()])
    assert len(result["envelope"]["signers"]) == 2
    assert all(s["valid"] for s in result["envelope"]["signers"])
    assert result["trusted_signer_count"] == 1
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest sdk-py/tests/test_verifier.py::test_trusted_signer_count_is_distinct_by_key -q`

Expected: FAIL with `assert 2 == 1`

- [ ] **Step 3: Dedup the count by public key**

In `sdk-py/src/capsule/verifier.py`, replace lines 248-249:

```python
    result["envelope"]["signers"] = signers
    result["trusted_signer_count"] = sum(1 for s in signers if s["trusted"])
```

with:

```python
    result["envelope"]["signers"] = signers
    # Count DISTINCT trusted public keys. The signed payload is the envelope
    # minus signers, so a duplicated signers[] entry carries a signature that
    # still verifies; counting entries would let one key satisfy an M-of-N
    # policy by appending a copy of itself.
    result["trusted_signer_count"] = len(
        {(s["public_key"] or "").lower() for s in signers if s["trusted"]}
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest sdk-py/tests/test_verifier.py::test_trusted_signer_count_is_distinct_by_key -q`

Expected: PASS

- [ ] **Step 5: Run the full lane suite for regressions**

Run: `python -m pytest sdk-py/tests/ -q`

Expected: `186 passed`

- [ ] **Step 6: Commit**
```bash
git add sdk-py/src/capsule/verifier.py sdk-py/tests/test_verifier.py
git commit -m "fix(sdk-py): count distinct trusted keys in trusted_signer_count"
```

---

### Task 9: sdk-py — consume the semantic-binding registry

**Files:**
- Modify: `sdk-py/tests/test_spec_registry.py:30-31`
- Modify: `sdk-py/tests/test_spec_registry.py:45`
- Modify: `sdk-py/tests/test_spec_registry.py:116`
- Test: `sdk-py/tests/test_spec_registry.py`

**Interfaces:**
- Consumes: `_collection_params(path)`, `_allowlist(doc, base)`, `_assert_verify_outcome(name, expected, result)`, `_error_haystack(result)`, `_load(path)` — all already defined in this file; `reader.decrypt(recipient_public_key=…, recipient_private_key=…)`
- Produces: `test_semantic_binding_registry_outcomes` (6 parametrized cases)

- [ ] **Step 1: Write the failing test**

Three edits to `sdk-py/tests/test_spec_registry.py`.

(a) After line 30 (`MALFORMED = …`), add the registry path:

```python
MALFORMED = VECTORS / "malformed-layout" / "vectors.json"
SEMANTIC = VECTORS / "semantic-binding" / "vectors.json"
SIGNING_INPUT = VECTORS / "signing-input.json"
```

(b) Immediately before `AREA_PREDICATES = {` (line 45), add the per-lane needle table:

```python
# Per-lane mapping of the registry's normative verify-stage reason
# categories (semantic-binding/vectors.json) onto this SDK's error strings.
VERIFY_REASON_NEEDLES = {
    "first_event_hash_binding": "manifest.first_event_hash mismatch",
    "encryption_shape": "manifest.encryption must be",
    "encryption_metadata_path": "manifest.encryption.metadata_path",
}

AREA_PREDICATES = {
```

(c) Immediately before `def test_signing_input_pins():` (line 116), add the test:

```python
@pytest.mark.parametrize("doc,vector,base", _collection_params(SEMANTIC))
def test_semantic_binding_registry_outcomes(doc: dict, vector: dict, base: pathlib.Path):
    data = (base / vector["capsule_file"]).read_bytes()
    expected = vector["expected"]
    name = vector["name"]
    reader = CapsuleReader.from_bytes(data)
    result = verify_capsule(reader, allowlist=_allowlist(doc, base))
    _assert_verify_outcome(name, expected, result)

    if expected.get("reason"):
        needle = VERIFY_REASON_NEEDLES.get(expected["reason"])
        assert needle is not None, f"{name}: unknown verify-stage reason {expected['reason']!r}"
        assert needle in _error_haystack(result), (
            f"{name}: expected an error for reason {expected['reason']!r}; got {result['errors']}"
        )

    if "trusted_signer_count" in expected:
        assert result["trusted_signer_count"] == expected["trusted_signer_count"], (
            f"{name}: trusted_signer_count must count DISTINCT allowlisted keys"
        )

    if expected.get("decryptable_with"):
        keys = _load((base / doc["keys_file"]).resolve())
        pair = keys[expected["decryptable_with"]]
        inner = reader.decrypt(
            recipient_public_key=pair["publicKey"],
            recipient_private_key=pair["privateKey"],
        )
        inner_result = verify_capsule(inner, allowlist=_allowlist(doc, base))
        assert inner_result["ok"] is True, f"{name}: inner capsule must verify; got {inner_result}"


def test_signing_input_pins():
```

- [ ] **Step 2: Run the test to verify it fails**

Temporarily `git stash` the Task 6–8 source changes, then run:

Run: `python -m pytest sdk-py/tests/test_spec_registry.py -q -k semantic_binding`

Expected: FAIL — 5 of 6 params fail, including `smuggled-blob-broken-chain: expected area 'chain' to fail; got {… 'chain': {'ok': True, 'errors': [], 'note': 'deferred to L3 (encrypted outer)'} …}` and `duplicate-signer: trusted_signer_count must count DISTINCT allowlisted keys / assert 2 == 1`. Restore with `git stash pop`.

- [ ] **Step 3: Confirm the registry is wired (no source change needed)**

The fixes landed in Tasks 6–8; this task only adds the consumer. Verify the parametrization discovered all six vectors.

Run: `python -m pytest sdk-py/tests/test_spec_registry.py --collect-only -q -k semantic_binding`

Expected: six collected ids — `…[first-event-hash-drift]`, `…[encryption-declared-plain]`, `…[encryption-metadata-path-dangling]`, `…[encryption-metadata-path-relocated]`, `…[smuggled-blob-broken-chain]`, `…[duplicate-signer]`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest sdk-py/tests/test_spec_registry.py -q`

Expected: PASS — `23 passed`

- [ ] **Step 5: Run the full lane suite for regressions**

Run: `python -m pytest sdk-py/tests/ -q`

Expected: `192 passed`

- [ ] **Step 6: Commit**
```bash
git add sdk-py/tests/test_spec_registry.py
git commit -m "test(sdk-py): consume the semantic-binding vector registry"
```

---

### Task 10: verifier-rust — encrypted-mode detection requires the signed cipher AND the blob

**Files:**
- Modify: `verifier-rust/crates/capsule-verify/src/verifier.rs:494-517`
- Modify: `verifier-rust/crates/capsule-verify/src/verifier.rs:524`
- Modify: `verifier-rust/crates/capsule-verify/src/test_support.rs:52` (insert helpers above)
- Modify: `verifier-rust/crates/capsule-verify/src/verifier.rs:918-921` (test imports)
- Test: `verifier-rust/crates/capsule-verify/src/verifier.rs` (`mod tests`)

**Interfaces:**
- Consumes: `spec/vectors/semantic-binding/output/*.capsule` (Task 4)
- Produces: `test_support::semantic_binding_capsule_bytes(name) -> Vec<u8>`, `test_support::originator_ed25519_public_key_hex() -> String` (used by Tasks 11–12); `blob_present` / `is_encrypted` split in `verify_capsule`

- [ ] **Step 1: Write the failing test**

(a) In `verifier-rust/crates/capsule-verify/src/test_support.rs`, immediately before line 52 (`/// Reads the recipient's X25519 32-byte secret from`), insert:

```rust
/// Resolve a capsule fixture by name under
/// `spec/vectors/semantic-binding/output` and read it into memory. These
/// fixtures are well-formed, correctly signed capsules whose manifest
/// claims disagree with the envelope, the chain, or the files; regenerate
/// them with `node sdk-js/tools/generate-semantic-binding-fixtures.mjs`.
pub fn semantic_binding_capsule_bytes(name: &str) -> Vec<u8> {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = crate_dir
        .join("..")
        .join("..")
        .join("..")
        .join("spec/vectors/semantic-binding/output")
        .join(name)
        .canonicalize()
        .unwrap_or_else(|_| {
            panic!("semantic-binding fixture {name:?} missing; run node sdk-js/tools/generate-semantic-binding-fixtures.mjs")
        });
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {name:?} failed: {e}"))
}

/// Reads the originator's Ed25519 public key (lowercase hex) from
/// `spec/vectors/tamper-detection/output/keys.json` — the allowlist entry
/// every checked-in fixture is signed against.
pub fn originator_ed25519_public_key_hex() -> String {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = crate_dir
        .join("..")
        .join("..")
        .join("..")
        .join("spec/vectors/tamper-detection/output/keys.json")
        .canonicalize()
        .expect("keys.json missing; populate spec/vectors before running parity tests");
    let bytes = std::fs::read(&path).expect("read keys.json");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("keys.json is valid JSON");
    v.pointer("/originator/publicKey")
        .and_then(|x| x.as_str())
        .expect("keys.json contains originator.publicKey")
        .to_string()
}
```

(b) In `verifier-rust/crates/capsule-verify/src/verifier.rs`, replace the test import block at lines 918-921:

```rust
    use crate::test_support::{
        clean_capsule_bytes, recipient_x25519_private_key,
        synthesize_capsule_with_envelope_mutation, tampered_capsule_bytes,
    };
```

with:

```rust
    use crate::test_support::{
        clean_capsule_bytes, originator_ed25519_public_key_hex, recipient_x25519_private_key,
        semantic_binding_capsule_bytes, synthesize_capsule_with_envelope_mutation,
        tampered_capsule_bytes,
    };

    /// A plain capsule (signed cipher "none") with a `content.enc` appended
    /// and a corrupt chain. Encrypted-mode detection must key off the signed
    /// cipher, not file presence — otherwise the chain walk is skipped and
    /// `chain.ok` is reported true for a chain nobody looked at.
    #[test]
    fn smuggled_blob_does_not_skip_the_chain_walk() {
        let bytes = semantic_binding_capsule_bytes("smuggled-blob-broken-chain.capsule");
        let result = verify_capsule(&bytes, &VerifyOptions::default());

        assert!(!result.ok, "smuggled blob + broken chain must not verify");
        assert!(
            result.chain.note.is_none(),
            "chain must be walked, not deferred; got note {:?}",
            result.chain.note
        );
        assert!(
            !result.chain.ok,
            "the corrupt chain must fail; got {:?}",
            result.chain
        );
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd verifier-rust && cargo test -p capsule-verify --lib smuggled_blob_does_not_skip_the_chain_walk`

Expected: FAIL with `chain must be walked, not deferred; got note Some("deferred to L3 (encrypted outer)")`

- [ ] **Step 3: Split blob presence from encrypted mode**

In `verifier-rust/crates/capsule-verify/src/verifier.rs`, replace lines 515-517:

```rust
    // Anything else is an Encryption-category error.
    let is_encrypted = files.contains_key("content.enc");
    if is_encrypted {
```

with:

```rust
    // Anything else is an Encryption-category error.
    //
    // `is_encrypted` requires BOTH the signed cipher declaration and the
    // blob. Keying it off file presence alone lets an attacker who appends
    // a `content.enc` to a plain capsule switch the verifier into encrypted
    // mode, which skips the chain walk in step 9 and reports chain.ok=true
    // for a chain that was never looked at.
    let blob_present = files.contains_key("content.enc");
    let is_encrypted = blob_present && envelope.cipher != "none";
    if blob_present {
```

- [ ] **Step 4: Fix the now-stale internal-error message**

Replace line 524:

```rust
                        "internal: is_encrypted set but content.enc absent",
```

with:

```rust
                        "internal: blob_present set but content.enc absent",
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd verifier-rust && cargo test -p capsule-verify --lib smuggled_blob_does_not_skip_the_chain_walk`

Expected: PASS

- [ ] **Step 6: Run the full lane suite for regressions**

Run: `cd verifier-rust && cargo test --workspace`

Expected: `test result: ok. 103 passed; 0 failed` (lib), `ok. 3 passed` (spec_registry), `ok. 7 passed` (parity). In particular `encrypted_blob_with_cipher_none_rejected` still passes — the shape block still keys off `blob_present`; only the chain-skip decision moved.

- [ ] **Step 7: Commit**
```bash
git add verifier-rust/crates/capsule-verify/src/verifier.rs verifier-rust/crates/capsule-verify/src/test_support.rs
git commit -m "fix(verifier-rust): encrypted mode needs the signed cipher, not just a blob

A content.enc appended to a plain capsule made the verifier skip the chain
walk and report chain.ok=true with a 'deferred to L3' note — the same
defect the Python reader had."
```

---

### Task 11: verifier-rust — first_event_hash binding and manifest.encryption agreement

**Files:**
- Modify: `verifier-rust/crates/capsule-verify/src/verifier.rs:471` (insert step 5b above)
- Modify: `verifier-rust/crates/capsule-verify/src/verifier.rs:558-567` (append step 8b after the plain branch)
- Test: `verifier-rust/crates/capsule-verify/src/verifier.rs` (`mod tests`)

**Interfaces:**
- Consumes: `semantic_binding_capsule_bytes` (Task 10); `Manifest.encryption: Option<Encryption>` with `metadata_path: String` / `cipher: String` (`schemas.rs:95-99, 116`)
- Produces: `TopErrorCategory::ChainAnchor` error `manifest.first_event_hash mismatch: …`; `TopErrorCategory::Encryption` errors `manifest.encryption must be …` and `manifest.encryption.metadata_path …`

- [ ] **Step 1: Write the failing test**

Append to `mod tests` in `verifier-rust/crates/capsule-verify/src/verifier.rs`:

```rust
    /// `manifest.first_event_hash` (the capsule_id preimage) disagrees with
    /// `envelope.first_event_hash` (which still matches chain event 1). The
    /// capsule is correctly signed over its own manifest, so only an
    /// explicit cross-check catches it.
    #[test]
    fn manifest_first_event_hash_must_match_envelope() {
        let bytes = semantic_binding_capsule_bytes("first-event-hash-drift.capsule");
        let result = verify_capsule(&bytes, &VerifyOptions::default());

        assert!(!result.ok, "first_event_hash drift must not verify");
        assert!(
            result.errors.iter().any(|e| e.category
                == TopErrorCategory::ChainAnchor
                && e.message.contains("manifest.first_event_hash mismatch")),
            "expected a ChainAnchor error naming manifest.first_event_hash; got: {:?}",
            result.errors
        );
    }

    /// `manifest.encryption` must agree with the signed `envelope.cipher`,
    /// and its `metadata_path` must resolve to a file in the package.
    #[test]
    fn manifest_encryption_must_agree_with_envelope_cipher() {
        let declared = verify_capsule(
            &semantic_binding_capsule_bytes("encryption-declared-plain.capsule"),
            &VerifyOptions::default(),
        );
        assert!(!declared.ok, "plain capsule declaring encryption must fail");
        assert!(
            declared.errors.iter().any(|e| e.category == TopErrorCategory::Encryption
                && e.message.contains("manifest.encryption must be")),
            "expected an encryption-shape error; got: {:?}",
            declared.errors
        );

        let dangling = verify_capsule(
            &semantic_binding_capsule_bytes("encryption-metadata-path-dangling.capsule"),
            &VerifyOptions::default(),
        );
        assert!(!dangling.ok, "dangling metadata_path must fail");
        assert!(
            dangling.errors.iter().any(|e| e.category == TopErrorCategory::Encryption
                && e.message.contains("manifest.encryption.metadata_path")),
            "expected a metadata_path error; got: {:?}",
            dangling.errors
        );
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd verifier-rust && cargo test -p capsule-verify --lib manifest_first_event_hash_must_match_envelope`

Expected: FAIL with `first_event_hash drift must not verify` (panic at the `assert!(!result.ok, …)`). Then `cargo test -p capsule-verify --lib manifest_encryption_must_agree_with_envelope_cipher` FAILs with `plain capsule declaring encryption must fail`.

- [ ] **Step 3: Add the first_event_hash binding (step 5b)**

In `verifier-rust/crates/capsule-verify/src/verifier.rs`, insert immediately before line 471 (`    // ---- (6) manifest_hash check ---…`):

```rust
    // ---- (5b) first_event_hash binding ----------------------------------
    // `manifest.first_event_hash` is the capsule_id preimage;
    // `envelope.first_event_hash` is what the chain walk in step 9 is
    // checked against. `manifest.md` and `envelope.md` both pin them to the
    // hash of chain event 1, so a drift means capsule_id names a chain this
    // capsule does not carry.
    if manifest.first_event_hash != envelope.first_event_hash {
        errors.push(TopError::outer(
            TopErrorCategory::ChainAnchor,
            format!(
                "manifest.first_event_hash mismatch: {} vs envelope.first_event_hash {}",
                manifest.first_event_hash, envelope.first_event_hash
            ),
        ));
    }

```

- [ ] **Step 4: Add the manifest.encryption agreement (step 8b)**

Immediately after the closing `}` of the plain-capsule `else` branch (line 567, just before `    // ---- (9) chain walk ---…`), insert:

```rust
    // ---- (8b) manifest.encryption agreement -----------------------------
    // `manifest.md` fixes `encryption` as null for plain capsules and
    // {metadata_path, cipher} for encrypted ones. The SIGNED
    // `envelope.cipher` is authoritative; the manifest declaration must
    // agree with it, and the declared metadata_path must resolve to a file
    // that is present AND covered by the content index.
    match (envelope.cipher.as_str(), manifest.encryption.as_ref()) {
        ("none", None) => {}
        ("none", Some(_)) => {
            errors.push(TopError::outer(
                TopErrorCategory::Encryption,
                "manifest.encryption must be null when envelope.cipher='none'",
            ));
        }
        (cipher, None) => {
            errors.push(TopError::outer(
                TopErrorCategory::Encryption,
                format!("manifest.encryption must be set when envelope.cipher='{cipher}'"),
            ));
        }
        (cipher, Some(enc)) => {
            if enc.cipher != cipher {
                errors.push(TopError::outer(
                    TopErrorCategory::Encryption,
                    format!(
                        "manifest.encryption.cipher mismatch: '{}' vs envelope.cipher '{cipher}'",
                        enc.cipher
                    ),
                ));
            }
            if enc.metadata_path.is_empty() {
                errors.push(TopError::outer(
                    TopErrorCategory::Encryption,
                    "manifest.encryption.metadata_path must be a non-empty string",
                ));
            } else if !files.contains_key(&enc.metadata_path) {
                errors.push(TopError::outer(
                    TopErrorCategory::Encryption,
                    format!(
                        "manifest.encryption.metadata_path missing from capsule: {}",
                        enc.metadata_path
                    ),
                ));
            } else if !manifest
                .content_index
                .files
                .iter()
                .any(|f| f.path == enc.metadata_path)
            {
                errors.push(TopError::outer(
                    TopErrorCategory::Encryption,
                    format!(
                        "manifest.encryption.metadata_path not covered by content index: {}",
                        enc.metadata_path
                    ),
                ));
            }
        }
    }

```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd verifier-rust && cargo test -p capsule-verify --lib manifest_`

Expected: PASS — both `manifest_first_event_hash_must_match_envelope` and `manifest_encryption_must_agree_with_envelope_cipher` (plus the pre-existing `manifest_*` tests).

- [ ] **Step 6: Run the full lane suite for regressions**

Run: `cd verifier-rust && cargo test --workspace`

Expected: `test result: ok. 105 passed; 0 failed` (lib), `ok. 3 passed` (spec_registry), `ok. 7 passed` (parity). `every_category_is_exercisable` is a superset assertion so the new categories are harmless.

- [ ] **Step 7: Commit**
```bash
git add verifier-rust/crates/capsule-verify/src/verifier.rs
git commit -m "fix(verifier-rust): bind manifest first_event_hash and encryption to the envelope"
```

---

### Task 12: verifier-rust — resolve metadata_path from the manifest, and count distinct trusted keys

**Files:**
- Modify: `verifier-rust/crates/capsule-verify/src/decrypt.rs:166-169`
- Modify: `verifier-rust/crates/capsule-verify/src/verifier.rs:622-623`
- Modify: `verifier-rust/crates/capsule-verify/src/verifier.rs:892`
- Modify: `verifier-rust/crates/capsule-verify/src/verifier.rs:861` (insert helper above `assemble_result`)
- Test: `verifier-rust/crates/capsule-verify/src/verifier.rs` (`mod tests`)

**Interfaces:**
- Consumes: `decrypt_inner_zip(envelope, manifest, files, recipient_private_key)` already receives the parsed `manifest`; `semantic_binding_capsule_bytes`, `originator_ed25519_public_key_hex`, `recipient_x25519_private_key`
- Produces: `count_distinct_trusted(&EnvelopeCheck) -> usize`

- [ ] **Step 1: Write the failing test**

Append to `mod tests` in `verifier-rust/crates/capsule-verify/src/verifier.rs`:

```rust
    /// L3 decryption must resolve the decryption metadata through
    /// `manifest.encryption.metadata_path`, not a hardcoded default path.
    #[test]
    fn l3_follows_manifest_declared_metadata_path() {
        let bytes = semantic_binding_capsule_bytes("encryption-metadata-path-relocated.capsule");
        let result = verify_capsule(
            &bytes,
            &VerifyOptions {
                allowlist: vec![],
                recipient_private_key: Some(recipient_x25519_private_key()),
            },
        );

        assert!(
            result.ok,
            "relocated metadata_path must still decrypt at L3; errors: {:?}",
            result.errors
        );
        assert_eq!(result.level, "L3", "level must upgrade to L3");
    }

    /// A duplicated `signers[]` entry carries a signature that still
    /// verifies, so `trusted_signer_count` must count DISTINCT keys.
    #[test]
    fn trusted_signer_count_is_distinct_by_key() {
        let bytes = semantic_binding_capsule_bytes("duplicate-signer.capsule");
        let result = verify_capsule(
            &bytes,
            &VerifyOptions {
                allowlist: vec![originator_ed25519_public_key_hex()],
                recipient_private_key: None,
            },
        );

        assert_eq!(result.envelope.signers.len(), 2, "both entries present");
        assert!(
            result.envelope.signers.iter().all(|s| s.valid),
            "both copies must verify"
        );
        assert_eq!(
            result.trusted_signer_count, 1,
            "one key must count once, got {}",
            result.trusted_signer_count
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd verifier-rust && cargo test -p capsule-verify --lib l3_follows_manifest_declared_metadata_path`

Expected: FAIL with `relocated metadata_path must still decrypt at L3; errors: [TopError { category: Encryption, scope: Inner, message: "L3: decryption failed: decryption metadata missing: skills/decryption/decryption.json" }]`. Then `cargo test -p capsule-verify --lib trusted_signer_count_is_distinct_by_key` FAILs with `left: 2 / right: 1`.

- [ ] **Step 3: Resolve the metadata path from the manifest**

In `verifier-rust/crates/capsule-verify/src/decrypt.rs`, replace lines 166-169:

```rust
    // Step 3: locate decryption metadata.
    let meta_bytes = files
        .get("skills/decryption/decryption.json")
        .ok_or(DecryptError::DecryptionMetadataMissing)?;
```

with:

```rust
    // Step 3: locate decryption metadata. The path is whatever
    // `manifest.encryption.metadata_path` declares — the reference reader
    // (sdk-js/src/reader.js) resolves it that way, so hardcoding the
    // default location makes this verifier reject capsules the reference
    // implementation reads. The spec default is only the fallback for a
    // manifest that omits the block; `verify_capsule` separately rejects
    // an encrypted capsule whose manifest.encryption is missing or points
    // at a path that is not in the package.
    let meta_path = manifest
        .encryption
        .as_ref()
        .map(|e| e.metadata_path.as_str())
        .filter(|p| !p.is_empty())
        .unwrap_or("skills/decryption/decryption.json");
    let meta_bytes = files
        .get(meta_path)
        .ok_or(DecryptError::DecryptionMetadataMissing)?;
```

- [ ] **Step 4: Add the distinct-key counting helper**

In `verifier-rust/crates/capsule-verify/src/verifier.rs`, insert immediately before line 861 (`/// Build a final \`VerifyResult\` from the accumulated state. …`):

```rust
/// Number of DISTINCT trusted public keys in an [`EnvelopeCheck`].
///
/// The signed payload is the envelope minus `signers`, so a duplicated
/// `signers[]` entry carries a signature that still verifies. Counting
/// entries would let one key satisfy an M-of-N policy by appending a copy
/// of itself, so we count keys instead (case-insensitively, matching the
/// allowlist comparison in [`verify_envelope_signatures`]).
pub(crate) fn count_distinct_trusted(envelope_check: &EnvelopeCheck) -> usize {
    envelope_check
        .signers
        .iter()
        .filter(|s| s.trusted)
        .map(|s| s.public_key.to_lowercase())
        .collect::<std::collections::BTreeSet<String>>()
        .len()
}

```

- [ ] **Step 5: Use the helper at both count sites**

Replace line 623 (inside `verify_capsule`, under `// ---- (11) trusted_signer_count ---…`):

```rust
    let trusted_signer_count = envelope_check.signers.iter().filter(|s| s.trusted).count();
```

with:

```rust
    let trusted_signer_count = count_distinct_trusted(&envelope_check);
```

and replace the identical line inside `assemble_result` (line 892) with the same call:

```rust
    let trusted_signer_count = count_distinct_trusted(&envelope_check);
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd verifier-rust && cargo test -p capsule-verify --lib l3_follows_manifest_declared_metadata_path trusted_signer_count_is_distinct_by_key`

Expected: PASS (run them one at a time if the harness rejects two filters).

- [ ] **Step 7: Run the full lane suite for regressions**

Run: `cd verifier-rust && cargo test --workspace`

Expected: `test result: ok. 107 passed; 0 failed` (lib), `ok. 3 passed` (spec_registry), `ok. 7 passed` (parity). `encrypted_clean_capsule_passes_l3_with_recipient_key` still passes — the default path is retained as the fallback.

- [ ] **Step 8: Commit**
```bash
git add verifier-rust/crates/capsule-verify/src/decrypt.rs verifier-rust/crates/capsule-verify/src/verifier.rs
git commit -m "fix(verifier-rust): follow manifest metadata_path; count distinct trusted keys

decrypt.rs hardcoded skills/decryption/decryption.json, so any capsule the
reference reader decrypts through manifest.encryption.metadata_path failed
here. trusted_signer_count now counts keys, not signers[] entries."
```

---

### Task 13: verifier-rust — consume the semantic-binding registry

**Files:**
- Modify: `verifier-rust/tests/spec_registry.rs:176` (insert above `#[test] fn signing_input_pins`)
- Test: `verifier-rust/tests/spec_registry.rs`

**Interfaces:**
- Consumes: `vectors_dir()`, `load_json(path)`, `registry_allowlist(doc, base)`, `all_error_messages(result)`, `assert_verify_outcome(name, expected, result)`, `verify_fixture(base, allowlist, vector)` — all already in this file
- Produces: `semantic_binding_registry_outcomes` test

- [ ] **Step 1: Write the failing test**

In `verifier-rust/tests/spec_registry.rs`, insert immediately before line 176 (`#[test]` above `fn signing_input_pins()`):

```rust
/// Per-lane mapping of the registry's normative verify-stage reason
/// categories (semantic-binding/vectors.json) onto this verifier's error
/// messages.
fn verify_reason_needle(reason: &str) -> &'static str {
    match reason {
        "first_event_hash_binding" => "manifest.first_event_hash mismatch",
        "encryption_shape" => "manifest.encryption must be",
        "encryption_metadata_path" => "manifest.encryption.metadata_path",
        other => panic!("unknown verify-stage reason {other:?}"),
    }
}

#[test]
fn semantic_binding_registry_outcomes() {
    let path = vectors_dir().join("semantic-binding/vectors.json");
    let doc = load_json(&path);
    let base = path.parent().unwrap().to_path_buf();
    let allowlist = registry_allowlist(&doc, &base);
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty());
    for v in vectors {
        let name = v["name"].as_str().expect("name");
        let expected = &v["expected"];
        let result = verify_fixture(&base, &allowlist, v);
        assert_verify_outcome(name, expected, &result);

        if let Some(reason) = expected["reason"].as_str() {
            let needle = verify_reason_needle(reason);
            let haystack = all_error_messages(&result).join(" ");
            assert!(
                haystack.contains(needle),
                "{name}: expected an error for reason {reason:?} ({needle:?}); got {haystack:?}"
            );
        }

        if let Some(want) = expected["trusted_signer_count"].as_u64() {
            assert_eq!(
                result.trusted_signer_count as u64, want,
                "{name}: trusted_signer_count must count DISTINCT allowlisted keys"
            );
        }

        if let Some(key_name) = expected["decryptable_with"].as_str() {
            let keys = load_json(&base.join(doc["keys_file"].as_str().expect("keys_file")));
            let priv_hex = keys
                .pointer(&format!("/{key_name}/privateKey"))
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("{name}: keys_file has no {key_name}/privateKey"));
            let priv_bytes: [u8; 32] = hex::decode(priv_hex)
                .expect("private key hex")
                .try_into()
                .expect("private key must be 32 bytes");
            let file = v["capsule_file"].as_str().expect("capsule_file");
            let bytes = std::fs::read(base.join(file)).expect("read fixture");
            let l3 = verify_capsule(
                &bytes,
                &VerifyOptions {
                    allowlist: allowlist.clone(),
                    recipient_private_key: Some(priv_bytes),
                },
            );
            assert!(
                l3.ok,
                "{name}: L3 decrypt must follow manifest.encryption.metadata_path; errors: {:?}",
                l3.errors
            );
            assert_eq!(l3.level, "L3", "{name}: level must upgrade to L3");
        }
    }
}

```

- [ ] **Step 2: Run the test to verify it fails**

Temporarily `git stash` the Task 10–12 source changes, then run:

Run: `cd verifier-rust && cargo test --test spec_registry semantic_binding_registry_outcomes`

Expected: FAIL with `assertion \`left == right\` failed: first-event-hash-drift: expected ok=false; errors: []; chain: []; content_index: []` / `left: true / right: false`. Restore with `git stash pop`.

- [ ] **Step 3: Confirm the registry is wired (no source change needed)**

The fixes landed in Tasks 10–12; this task only adds the consumer.

Run: `cd verifier-rust && cargo test --test spec_registry -- --list`

Expected: four tests listed — `malformed_registry_outcomes`, `semantic_binding_registry_outcomes`, `signing_input_pins`, `tamper_registry_outcomes`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd verifier-rust && cargo test --test spec_registry`

Expected: PASS — `test result: ok. 4 passed; 0 failed`

- [ ] **Step 5: Run the full lane suite for regressions**

Run: `cd verifier-rust && cargo test --workspace`

Expected: `ok. 107 passed` (lib), `ok. 4 passed` (spec_registry), `ok. 7 passed` (parity), 0 failures.

- [ ] **Step 6: Commit**
```bash
git add verifier-rust/tests/spec_registry.rs
git commit -m "test(verifier-rust): consume the semantic-binding vector registry"
```

---

### Task 14: sdk-swift — detect encryption from the signed cipher, bind manifest claims, dedup trust

**Files:**
- Create: `sdk-swift/Tests/CapsuleTests/SpecRegistryTests.swift`
- Modify: `sdk-swift/Sources/Capsule/Reader.swift:29-36`
- Modify: `sdk-swift/Sources/Capsule/Reader.swift:96-110`
- Modify: `sdk-swift/Sources/Capsule/Verifier.swift:197`
- Modify: `sdk-swift/Sources/Capsule/Verifier.swift:234-236`
- Modify: `sdk-swift/Sources/Capsule/Verifier.swift:252-255`
- Modify: `sdk-swift/Sources/Capsule/Verifier.swift:276`
- Modify: `sdk-swift/Sources/Capsule/Verifier.swift:150`
- Test: `sdk-swift/Tests/CapsuleTests/SpecRegistryTests.swift`

**Interfaces:**
- Consumes: `CapsuleVerifier.verify(_:allowlist:)`, `CapsuleVerifier.verify(_:recipientPrivateKey:recipientPublicKey:allowlist:)`, `Bytes.fromHex(_:)`, `JCSValue.{object,array,string,null}`
- Produces: `ParsedCapsule.isEncrypted` == signed cipher AND blob; checks named `first_event_hash_binding` and `manifest_encryption`; `contentIndexPaths(_:)` private helper; per-envelope distinct trusted counts

- [ ] **Step 1: Write the failing test**

Create `sdk-swift/Tests/CapsuleTests/SpecRegistryTests.swift`:

```swift
// Registry-driven conformance against spec/vectors/semantic-binding.
//
// Unlike ParityTests (which pins Swift-specific check names per fixture),
// this file reads the language-neutral outcome registry directly, so the
// Swift lane tracks the same normative expectations as the JS reference
// lane (tools/check-spec-vectors.mjs) without hand-copied assertions.
//
// Fixture loading walks up from #file to the repo root, matching the
// Python, Rust and Kotlin registry tests.

import Foundation
import XCTest
@testable import Capsule

final class SpecRegistryTests: XCTestCase {

    private static let repoRoot: URL = URL(fileURLWithPath: #file)
        .deletingLastPathComponent()  // CapsuleTests/
        .deletingLastPathComponent()  // Tests/
        .deletingLastPathComponent()  // sdk-swift/
        .deletingLastPathComponent()  // <repo-root>/

    /// Per-lane mapping of the registry's normative verify-stage reason
    /// categories onto this SDK's check details.
    private static let verifyReasonNeedles: [String: String] = [
        "first_event_hash_binding": "manifest.first_event_hash mismatch",
        "encryption_shape": "manifest.encryption must be",
        "encryption_metadata_path": "manifest.encryption.metadata_path",
    ]

    /// Registry `failing` area names -> this lane's check names.
    private static let areaChecks: [String: [String]] = [
        "content_index": ["content_index_hash"],
        "chain": ["chain"],
        "envelope": ["envelope_signature"],
        "encrypted_blob": ["encrypted_blob_hash"],
    ]

    private func loadJSON(_ url: URL) throws -> [String: Any] {
        let data = try Data(contentsOf: url)
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw CocoaError(.fileReadCorruptFile)
        }
        return obj
    }

    func testSemanticBindingRegistryOutcomes() throws {
        let base = Self.repoRoot.appendingPathComponent("spec/vectors/semantic-binding")
        let doc = try loadJSON(base.appendingPathComponent("vectors.json"))
        let keys = try loadJSON(
            base.appendingPathComponent(doc["keys_file"] as! String).standardizedFileURL
        )
        let originator = (keys["originator"] as! [String: Any])["publicKey"] as! String
        let allowlist: Set<String> = [originator]

        let vectors = doc["vectors"] as! [[String: Any]]
        XCTAssertFalse(vectors.isEmpty, "registry must carry vectors")

        for vector in vectors {
            let name = vector["name"] as! String
            let expected = vector["expected"] as! [String: Any]
            let bytes = try Data(
                contentsOf: base.appendingPathComponent(vector["capsule_file"] as! String)
            )
            let v = CapsuleVerifier.verify(bytes, allowlist: allowlist)
            let haystack = v.checks.map { "\($0.name):\($0.detail)" }.joined(separator: " ")

            XCTAssertEqual(v.ok, expected["ok"] as! Bool,
                           "\(name): unexpected ok; checks: \(haystack)")

            for area in (expected["failing"] as? [String]) ?? [] {
                let names = Self.areaChecks[area]
                XCTAssertNotNil(names, "\(name): unknown failing area \(area)")
                let failed = v.checks.contains { (names ?? []).contains($0.name) && !$0.ok }
                XCTAssertTrue(failed, "\(name): expected area \(area) to fail; got \(haystack)")
            }

            if let reason = expected["reason"] as? String {
                let needle = Self.verifyReasonNeedles[reason]
                XCTAssertNotNil(needle, "\(name): unknown verify-stage reason \(reason)")
                XCTAssertTrue(haystack.contains(needle ?? "\u{0}"),
                              "\(name): expected reason \(reason); got \(haystack)")
            }

            if let want = expected["trusted_signer_count"] as? Int {
                XCTAssertEqual(v.trustedSignerCount, want,
                               "\(name): trusted_signer_count must count DISTINCT keys")
            }

            if let keyName = expected["decryptable_with"] as? String {
                let pair = keys[keyName] as! [String: Any]
                let pub = Bytes.fromHex(pair["publicKey"] as! String)
                let priv = Bytes.fromHex(pair["privateKey"] as! String)
                let l3 = CapsuleVerifier.verify(
                    bytes,
                    recipientPrivateKey: priv,
                    recipientPublicKey: pub,
                    allowlist: allowlist
                )
                XCTAssertTrue(
                    l3.ok,
                    "\(name): L3 must follow manifest.encryption.metadata_path; failing: "
                    + l3.checks.filter { !$0.ok }.map { "\($0.name):\($0.detail)" }
                        .joined(separator: ", ")
                )
                XCTAssertEqual(l3.level, "L3", "\(name): level must be L3")
            }
        }
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-swift && swift test --filter SpecRegistryTests`

Expected: FAIL with six assertions, including `first-event-hash-drift: unexpected ok; checks: … first_event_hash: entry_hash: envelope_cipher:none envelope_signature:originator:ok (trusted)` (`("true") is not equal to ("false")`), `encryption-declared-plain: expected reason encryption_shape; got parse:Capsule malformed: encrypted outer missing content.enc`, and `duplicate-signer: trusted_signer_count must count DISTINCT keys ("2") is not equal to ("1")`.

- [ ] **Step 3: Key `ParsedCapsule.isEncrypted` off the signed cipher**

In `sdk-swift/Sources/Capsule/Reader.swift`, replace lines 29-36:

```swift
    /// True when the outer manifest carries a non-null `encryption` field.
    /// Plain capsules return false; encrypted-outer capsules return true.
    public var isEncrypted: Bool {
        guard case .object(let pairs) = manifest,
              let enc = pairs.first(where: { $0.0 == "encryption" })
        else { return false }
        return enc.1 != .null
    }
```

with:

```swift
    /// True only for a genuine encrypted-outer capsule: the SIGNED
    /// `envelope.cipher` is not "none" AND `content.enc` is present.
    /// Mirrors sdk-js/src/reader.js. The manifest's `encryption` block is
    /// deliberately not an input here — it is cross-checked by
    /// `CapsuleVerifier` instead, so a manifest that merely claims
    /// encryption cannot steer the reader away from the chain.
    public var isEncrypted: Bool {
        guard case .object(let pairs) = envelope,
              let cipherVal = pairs.first(where: { $0.0 == "cipher" })?.1,
              case .string(let cipher) = cipherVal
        else { return false }
        return cipher != "none" && files["content.enc"] != nil
    }
```

- [ ] **Step 4: Key `CapsuleReader.parse` off the signed cipher too**

In `sdk-swift/Sources/Capsule/Reader.swift`, replace lines 96-110:

```swift
        // Detect encrypted-outer. The chain/program/agents files live
        // inside the encrypted blob, not the outer zip.
        let encrypted: Bool = {
            guard case .object(let pairs) = manifest,
                  let enc = pairs.first(where: { $0.0 == "encryption" })
            else { return false }
            return enc.1 != .null
        }()

        if encrypted {
            // Outer must carry the ciphertext blob.
            if files["content.enc"] == nil {
                throw CapsuleError.malformed("encrypted outer missing content.enc")
            }
            return ParsedCapsule(
```

with:

```swift
        // Detect encrypted-outer from the SIGNED envelope.cipher plus the
        // presence of the blob — never from the manifest's own claim. The
        // chain/program/agents files live inside the ciphertext, not the
        // outer zip, so getting this wrong either hides the chain or makes
        // a manifest claim enough to skip verifying it.
        let encrypted: Bool = {
            guard case .object(let pairs) = envelope,
                  let cipherVal = pairs.first(where: { $0.0 == "cipher" })?.1,
                  case .string(let cipher) = cipherVal
            else { return false }
            return cipher != "none" && files["content.enc"] != nil
        }()

        if encrypted {
            return ParsedCapsule(
```

- [ ] **Step 5: Add the first_event_hash binding check**

In `sdk-swift/Sources/Capsule/Verifier.swift`, replace lines 197-198:

```swift
        // manifest hash
        let mh = Manifest.hash(parsed.manifest)
```

with:

```swift
        // Semantic binding: manifest.first_event_hash is the capsule_id
        // preimage; envelope.first_event_hash is what the chain anchor
        // check below compares against. manifest.md and envelope.md both
        // pin them to the hash of chain event 1, so they must agree —
        // otherwise capsule_id names a chain this capsule does not carry.
        let mfFirst = lookupString(parsed.manifest, ["first_event_hash"])
        let envFirstDeclared = lookupString(parsed.envelope, ["first_event_hash"])
        if mfFirst != nil, mfFirst == envFirstDeclared {
            record("first_event_hash_binding", true)
        } else {
            record("first_event_hash_binding", false,
                   "manifest.first_event_hash mismatch: \(mfFirst ?? "nil") "
                   + "vs envelope \(envFirstDeclared ?? "nil")")
        }

        // manifest hash
        let mh = Manifest.hash(parsed.manifest)
```

- [ ] **Step 6: Drop the narrow `manifest_cipher` check (superseded)**

In the encrypted branch, delete lines 234-236:

```swift
            let mfCipher = lookupString(parsed.manifest, ["encryption", "cipher"]) ?? ""
            record("manifest_cipher", mfCipher == "ChaCha20-Poly1305",
                   mfCipher.isEmpty ? "missing" : mfCipher)
```

- [ ] **Step 7: Add the full encryption-declaration check**

Replace the end of the plain branch (lines 252-255) plus the following blank line:

```swift
            let envCipher = lookupString(parsed.envelope, ["cipher"]) ?? ""
            record("envelope_cipher", envCipher == "none",
                   envCipher.isEmpty ? "missing" : envCipher)
        }

        // envelope signatures + trust attribution
```

with:

```swift
            let envCipher = lookupString(parsed.envelope, ["cipher"]) ?? ""
            record("envelope_cipher", envCipher == "none",
                   envCipher.isEmpty ? "missing" : envCipher)
        }

        // Encryption declaration. manifest.md fixes manifest.encryption as
        // null for plain capsules and {metadata_path, cipher} for encrypted
        // ones. The SIGNED envelope.cipher is authoritative; the manifest
        // must agree with it, and the declared metadata_path must resolve
        // to a file that is present AND covered by the content index.
        let declaredCipher = lookupString(parsed.envelope, ["cipher"]) ?? ""
        let mfEncryptionPresent: Bool = {
            guard case .object(let pairs) = parsed.manifest,
                  let enc = pairs.first(where: { $0.0 == "encryption" })?.1
            else { return false }
            return enc != .null
        }()
        let mfCipher = lookupString(parsed.manifest, ["encryption", "cipher"])
        let mfMetadataPath = lookupString(parsed.manifest, ["encryption", "metadata_path"])
        if declaredCipher == "none" {
            record("manifest_encryption", !mfEncryptionPresent,
                   mfEncryptionPresent
                     ? "manifest.encryption must be null when envelope.cipher is 'none'"
                     : "null")
        } else if !mfEncryptionPresent {
            record("manifest_encryption", false,
                   "manifest.encryption must be set when envelope.cipher is '\(declaredCipher)'")
        } else if mfCipher != declaredCipher {
            record("manifest_encryption", false,
                   "manifest.encryption.cipher \(mfCipher ?? "nil") "
                   + "vs envelope.cipher '\(declaredCipher)'")
        } else if let path = mfMetadataPath, !path.isEmpty {
            if parsed.files[path] == nil {
                record("manifest_encryption", false,
                       "manifest.encryption.metadata_path missing from capsule: \(path)")
            } else if !contentIndexPaths(parsed.manifest).contains(path) {
                record("manifest_encryption", false,
                       "manifest.encryption.metadata_path not covered by content index: \(path)")
            } else {
                record("manifest_encryption", true, path)
            }
        } else {
            record("manifest_encryption", false,
                   "manifest.encryption.metadata_path must be a non-empty string")
        }

        // envelope signatures + trust attribution
```

- [ ] **Step 8: Dedup the per-envelope trusted count and add the index helper**

Replace lines 272-281 (the tail of `verifyParsed` plus the `lookupString` declaration):

```swift
        let ok = checks.allSatisfy { $0.ok }
        return CapsuleVerification(
            ok: ok, level: level, checks: checks,
            signers: signers,
            trustedSignerCount: signers.filter { $0.trusted }.count,
            notes: notes
        )
    }

    private static func lookupString(_ v: JCSValue, _ path: [String]) -> String? {
```

with:

```swift
        let ok = checks.allSatisfy { $0.ok }
        return CapsuleVerification(
            ok: ok, level: level, checks: checks,
            signers: signers,
            // Count DISTINCT trusted keys: the signed payload is the
            // envelope minus signers, so a duplicated entry carries a
            // signature that still verifies and would otherwise let one
            // key satisfy an M-of-N policy.
            trustedSignerCount: Set(
                signers.filter { $0.trusted }.map { $0.publicKey.lowercased() }
            ).count,
            notes: notes
        )
    }

    /// Paths listed in `manifest.content_index.files[]`.
    private static func contentIndexPaths(_ manifest: JCSValue) -> Set<String> {
        guard case .object(let pairs) = manifest,
              let ci = pairs.first(where: { $0.0 == "content_index" })?.1,
              case .object(let ciPairs) = ci,
              let filesVal = ciPairs.first(where: { $0.0 == "files" })?.1,
              case .array(let items) = filesVal
        else { return [] }
        var out = Set<String>()
        for item in items {
            if case .object(let entry) = item,
               let pathVal = entry.first(where: { $0.0 == "path" })?.1,
               case .string(let path) = pathVal {
                out.insert(path)
            }
        }
        return out
    }

    private static func lookupString(_ v: JCSValue, _ path: [String]) -> String? {
```

- [ ] **Step 9: Keep the L3 aggregate as a sum of per-envelope distinct counts**

Replace line 150 and its surrounding return (lines 146-152):

```swift
        let ok = checks.allSatisfy { $0.ok }
        return CapsuleVerification(
            ok: ok, level: "L3", checks: checks,
            signers: allSigners,
            trustedSignerCount: allSigners.filter { $0.trusted }.count,
            notes: outer.notes
        )
```

with:

```swift
        let ok = checks.allSatisfy { $0.ok }
        return CapsuleVerification(
            ok: ok, level: "L3", checks: checks,
            signers: allSigners,
            // Each envelope is deduped by key on its own, then summed:
            // outer and inner trust are separate attestations, but one key
            // must not count twice inside a single envelope.
            trustedSignerCount: outer.trustedSignerCount + innerResult.trustedSignerCount,
            notes: outer.notes
        )
```

- [ ] **Step 10: Run the test to verify it passes**

Run: `cd sdk-swift && swift test --filter SpecRegistryTests`

Expected: PASS — `Test Case '-[CapsuleTests.SpecRegistryTests testSemanticBindingRegistryOutcomes]' passed`

- [ ] **Step 11: Run the full lane suite for regressions**

Run: `cd sdk-swift && swift test`

Expected: `Executed 27 tests, with 0 failures (0 unexpected)`. `ParityTests.testDecryptCleanEncryptedWithJsRecipientKey` still asserts `trustedSignerCount == 2` and still passes — Step 9 sums per-envelope distinct counts rather than deduping across outer and inner.

- [ ] **Step 12: Commit**
```bash
git add sdk-swift/Sources/Capsule/Reader.swift sdk-swift/Sources/Capsule/Verifier.swift sdk-swift/Tests/CapsuleTests/SpecRegistryTests.swift
git commit -m "fix(sdk-swift): bind manifest claims to the signed envelope

isEncrypted now keys off envelope.cipher AND content.enc instead of the
manifest's own claim; adds the first_event_hash binding and
manifest.encryption agreement checks; dedups trustedSignerCount per
envelope. Consumes the semantic-binding registry."
```

---

### Task 15: sdk-kotlin — detect encryption from the signed cipher, bind manifest claims, dedup trust

**Files:**
- Create: `sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/SpecRegistryTest.kt`
- Modify: `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Reader.kt:23-49`
- Modify: `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Verifier.kt:56`
- Modify: `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Verifier.kt:84`
- Modify: `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Verifier.kt:100`
- Modify: `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Verifier.kt:105`
- Test: `sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/SpecRegistryTest.kt`

**Interfaces:**
- Consumes: `CapsuleVerifier.verify(bytes, allowlist)`, `CapsuleReader.lookupString(v, path)`, `JCSValue.{Obj(pairs), Arr(items), Str(v), Null}`, gson (already an `implementation` dep of `:core`)
- Produces: checks named `first_event_hash_binding` and `manifest_encryption`; `contentIndexPaths(manifest)` private helper; distinct-key `trustedSignerCount`

- [ ] **Step 1: Write the failing test**

Create `sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/SpecRegistryTest.kt`:

```kotlin
// Registry-driven conformance against spec/vectors/semantic-binding.
//
// Unlike ParityTest (which pins per-fixture assertions), this file reads
// the language-neutral outcome registry directly, so the Kotlin lane
// tracks the same normative expectations as the JS reference lane
// (tools/check-spec-vectors.mjs) without hand-copied assertions.
//
// The core module is a plain-capsule (L2) verifier: it has no X25519 /
// ChaCha20 path and refuses encrypted capsules at open time. Vectors
// tagged `"requires": ["encryption"]` are therefore skipped here, as the
// registry's notes allow.

package ai.virion.capsule.core

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SpecRegistryTest {

    /** Registry verify-stage reason categories -> this lane's check details. */
    private val verifyReasonNeedles = mapOf(
        "first_event_hash_binding" to "manifest.first_event_hash mismatch",
        "encryption_shape" to "manifest.encryption must be",
        "encryption_metadata_path" to "manifest.encryption.metadata_path",
    )

    /** Registry `failing` area names -> this lane's check names. */
    private val areaChecks = mapOf(
        "content_index" to listOf("content_index_hash"),
        "chain" to listOf("chain"),
        "envelope" to listOf("envelope_signature"),
    )

    @Test
    fun semanticBindingRegistryOutcomes() {
        val base = File(repoRoot(), "spec/vectors/semantic-binding")
        val doc = JsonParser.parseString(File(base, "vectors.json").readText()).asJsonObject
        val keys = JsonParser
            .parseString(File(base, doc.get("keys_file").asString).readText())
            .asJsonObject
        val allowlist = setOf(keys.getAsJsonObject("originator").get("publicKey").asString)

        val vectors = doc.getAsJsonArray("vectors")
        assertTrue(vectors.size() > 0, "registry must carry vectors")

        for (element in vectors) {
            val vector = element.asJsonObject
            val name = vector.get("name").asString
            if (requiresEncryption(vector)) continue // plain-only lane
            val expected = vector.getAsJsonObject("expected")
            val bytes = File(base, vector.get("capsule_file").asString).readBytes()

            val v = CapsuleVerifier.verify(bytes = bytes, allowlist = allowlist)
            val haystack = v.checks.joinToString(" ") { "${it.name}:${it.detail}" }

            assertEquals(
                expected.get("ok").asBoolean, v.ok,
                "$name: unexpected ok; checks: $haystack",
            )

            expected.getAsJsonArray("failing")?.forEach { area ->
                val names = areaChecks[area.asString]
                    ?: error("$name: unknown failing area ${area.asString}")
                assertTrue(
                    v.checks.any { it.name in names && !it.ok },
                    "$name: expected area ${area.asString} to fail; got $haystack",
                )
            }

            expected.get("reason")?.let { reason ->
                val needle = verifyReasonNeedles[reason.asString]
                    ?: error("$name: unknown verify-stage reason ${reason.asString}")
                assertTrue(
                    haystack.contains(needle),
                    "$name: expected reason ${reason.asString}; got $haystack",
                )
            }

            expected.get("trusted_signer_count")?.let { want ->
                assertEquals(
                    want.asInt, v.trustedSignerCount,
                    "$name: trusted_signer_count must count DISTINCT keys",
                )
            }
        }
    }

    private fun requiresEncryption(vector: JsonObject): Boolean =
        vector.getAsJsonArray("requires")?.any { it.asString == "encryption" } ?: false

    companion object {
        /** Walk up from the gradle module dir until we find the vector registry. */
        private fun repoRoot(): File {
            var p: File? = File(System.getProperty("user.dir")).absoluteFile
            while (p != null) {
                if (File(p, "spec/vectors/semantic-binding/vectors.json").exists()) return p
                p = p.parentFile
            }
            error(
                "could not locate repo root containing " +
                    "spec/vectors/semantic-binding/vectors.json " +
                    "starting from ${System.getProperty("user.dir")}",
            )
        }
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-kotlin && ./gradlew --no-daemon :core:test --tests "ai.virion.capsule.core.SpecRegistryTest"`

Expected: FAIL. Four vectors are evaluated (two are skipped by `requires`): `first-event-hash-drift: unexpected ok` (`expected:<false> but was:<true>`), `encryption-declared-plain: expected reason encryption_shape; got parse:encrypted capsule; v0 reader supports plain only`, and `duplicate-signer: trusted_signer_count must count DISTINCT keys expected:<1> but was:<2>`.

- [ ] **Step 3: Key the reader's encrypted-capsule refusal off the signed cipher**

In `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Reader.kt`, replace lines 28-48:

```kotlin
        val envelopeBytes = files["provenance/envelope.json"]
            ?: throw CapsuleException("missing envelope")
        val eventsBytes = files["chain/events.jsonl"]
            ?: throw CapsuleException("missing chain")
        val programBytes = files["program.md"]
            ?: throw CapsuleException("missing program.md")

        val manifest = parseJson(manifestBytes)
        val envelope = parseJson(envelopeBytes)
        val events = String(eventsBytes, Charsets.UTF_8)
            .split('\n').filter { it.isNotEmpty() }
            .map { parseJson(it.toByteArray(Charsets.UTF_8)) }
        val programMd = String(programBytes, Charsets.UTF_8)
        val agentsMd = files["agents.md"]?.let { String(it, Charsets.UTF_8) }

        val encryption = (manifest as? JCSValue.Obj)?.pairs
            ?.firstOrNull { it.first == "encryption" }?.second
        if (encryption != null && encryption != JCSValue.Null) {
            throw CapsuleException("encrypted capsule; v0 reader supports plain only")
        }
        return ParsedCapsule(manifest, envelope, events, programMd, agentsMd, files)
```

with:

```kotlin
        val envelopeBytes = files["provenance/envelope.json"]
            ?: throw CapsuleException("missing envelope")

        val manifest = parseJson(manifestBytes)
        val envelope = parseJson(envelopeBytes)

        // Encrypted-outer detection keys off the SIGNED envelope.cipher plus
        // the presence of content.enc — never the manifest's own encryption
        // claim. A manifest that merely claims encryption on a cipher="none"
        // capsule must still be read (and then rejected by CapsuleVerifier),
        // not waved through as "encrypted, nothing here to check".
        val cipher = lookupString(envelope, listOf("cipher"))
        if (cipher != null && cipher != "none" && files.containsKey("content.enc")) {
            throw CapsuleException("encrypted capsule; v0 reader supports plain only")
        }

        val eventsBytes = files["chain/events.jsonl"]
            ?: throw CapsuleException("missing chain")
        val programBytes = files["program.md"]
            ?: throw CapsuleException("missing program.md")

        val events = String(eventsBytes, Charsets.UTF_8)
            .split('\n').filter { it.isNotEmpty() }
            .map { parseJson(it.toByteArray(Charsets.UTF_8)) }
        val programMd = String(programBytes, Charsets.UTF_8)
        val agentsMd = files["agents.md"]?.let { String(it, Charsets.UTF_8) }

        return ParsedCapsule(manifest, envelope, events, programMd, agentsMd, files)
```

- [ ] **Step 4: Add the first_event_hash binding check**

In `sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Verifier.kt`, replace line 56:

```kotlin
        val mh = Manifest.hash(parsed.manifest)
```

with:

```kotlin
        // Semantic binding: manifest.first_event_hash is the capsule_id
        // preimage; envelope.first_event_hash is what the chain anchor check
        // below compares against. manifest.md and envelope.md both pin them
        // to the hash of chain event 1, so they must agree.
        val envFirstDeclared = CapsuleReader.lookupString(parsed.envelope, listOf("first_event_hash"))
        rec(
            "first_event_hash_binding",
            firstHash != null && firstHash == envFirstDeclared,
            if (firstHash == envFirstDeclared) "" else
                "manifest.first_event_hash mismatch: $firstHash vs envelope $envFirstDeclared",
        )

        val mh = Manifest.hash(parsed.manifest)
```

- [ ] **Step 5: Add the encryption-declaration check**

Replace line 84:

```kotlin
        val env = Envelope.verifySignatures(parsed.envelope)
```

with:

```kotlin
        // Encryption declaration. manifest.md fixes manifest.encryption as
        // null for plain capsules and {metadata_path, cipher} for encrypted
        // ones. The SIGNED envelope.cipher is authoritative; the manifest
        // must agree with it, and the declared metadata_path must resolve to
        // a file that is present AND covered by the content index.
        val declaredCipher = CapsuleReader.lookupString(parsed.envelope, listOf("cipher")) ?: ""
        val mfEncryption = (parsed.manifest as? JCSValue.Obj)?.pairs
            ?.firstOrNull { it.first == "encryption" }?.second
        val mfEncryptionPresent = mfEncryption != null && mfEncryption != JCSValue.Null
        val mfCipher = CapsuleReader.lookupString(parsed.manifest, listOf("encryption", "cipher"))
        val mfMetadataPath =
            CapsuleReader.lookupString(parsed.manifest, listOf("encryption", "metadata_path")) ?: ""
        when {
            declaredCipher == "none" -> rec(
                "manifest_encryption",
                !mfEncryptionPresent,
                if (mfEncryptionPresent)
                    "manifest.encryption must be null when envelope.cipher is 'none'"
                else "null",
            )
            !mfEncryptionPresent -> rec(
                "manifest_encryption", false,
                "manifest.encryption must be set when envelope.cipher is '$declaredCipher'",
            )
            mfCipher != declaredCipher -> rec(
                "manifest_encryption", false,
                "manifest.encryption.cipher $mfCipher vs envelope.cipher '$declaredCipher'",
            )
            mfMetadataPath.isEmpty() -> rec(
                "manifest_encryption", false,
                "manifest.encryption.metadata_path must be a non-empty string",
            )
            !parsed.files.containsKey(mfMetadataPath) -> rec(
                "manifest_encryption", false,
                "manifest.encryption.metadata_path missing from capsule: $mfMetadataPath",
            )
            mfMetadataPath !in contentIndexPaths(parsed.manifest) -> rec(
                "manifest_encryption", false,
                "manifest.encryption.metadata_path not covered by content index: $mfMetadataPath",
            )
            else -> rec("manifest_encryption", true, mfMetadataPath)
        }

        val env = Envelope.verifySignatures(parsed.envelope)
```

- [ ] **Step 6: Dedup the trusted count**

Replace line 100:

```kotlin
            signers = signers, trustedSignerCount = signers.count { it.trusted },
```

with:

```kotlin
            signers = signers,
            // Count DISTINCT trusted keys: the signed payload is the envelope
            // minus signers, so a duplicated entry carries a signature that
            // still verifies and would otherwise let one key satisfy an
            // M-of-N policy.
            trustedSignerCount = signers.filter { it.trusted }
                .map { it.publicKey.lowercase() }.toSet().size,
```

- [ ] **Step 7: Add the content-index path helper**

Replace line 105:

```kotlin
    private fun verifyChain(events: List<JCSValue>): Boolean {
```

with:

```kotlin
    /** Paths listed in `manifest.content_index.files[]`. */
    private fun contentIndexPaths(manifest: JCSValue): Set<String> {
        val ci = (manifest as? JCSValue.Obj)?.pairs
            ?.firstOrNull { it.first == "content_index" }?.second as? JCSValue.Obj
            ?: return emptySet()
        val files = ci.pairs.firstOrNull { it.first == "files" }?.second as? JCSValue.Arr
            ?: return emptySet()
        return files.items.mapNotNull { entry ->
            ((entry as? JCSValue.Obj)?.pairs?.firstOrNull { it.first == "path" }?.second
                as? JCSValue.Str)?.v
        }.toSet()
    }

    private fun verifyChain(events: List<JCSValue>): Boolean {
```

- [ ] **Step 8: Run the test to verify it passes**

Run: `cd sdk-kotlin && ./gradlew --no-daemon :core:test --tests "ai.virion.capsule.core.SpecRegistryTest"`

Expected: PASS

- [ ] **Step 9: Run the full lane suite for regressions**

Run: `cd sdk-kotlin && ./gradlew --no-daemon :core:test`

Expected: BUILD SUCCESSFUL. `ParityTest.jsTamperedBlobCapsuleFailsUnderKotlin` still passes — `tampered-blob.capsule` is a real encrypted capsule (cipher `ChaCha20-Poly1305` + `content.enc`), so the reader still refuses it.

- [ ] **Step 10: Commit**
```bash
git add sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Reader.kt sdk-kotlin/core/src/main/kotlin/ai/virion/capsule/core/Verifier.kt sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/SpecRegistryTest.kt
git commit -m "fix(sdk-kotlin): bind manifest claims to the signed envelope

The reader refused any capsule whose manifest claimed encryption, so a
plain capsule with a false claim was never verified at all. Detection now
keys off envelope.cipher AND content.enc; adds the first_event_hash
binding and manifest.encryption agreement checks; dedups
trustedSignerCount. Consumes the semantic-binding registry."
```

---

### Final gate

Run the five lane commands the CI workflow runs, in this order:

```bash
node tools/run-conformance.mjs                       # PASS · 11/11
python -m pytest sdk-py/tests/ -v --tb=short         # 192 passed
cd verifier-rust && cargo test --workspace           # 107 + 4 + 7 passed
cd sdk-kotlin && ./gradlew --no-daemon :core:test    # BUILD SUCCESSFUL
cd sdk-swift && swift test                           # Executed 27 tests, 0 failures
```

Leave `output/conformance-report.{json,md}` out of every commit above — the harness rewrites them and CI auto-commits them on push to main.


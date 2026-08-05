# C8 — verifier-rust: empty chain passes, chain-hash preimage rebuilt from the typed struct, unvalidated allowlist

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Part of:** [Capsules pre-release remediation](./README.md) · Tier 2 (v0.7 correctness)

**Findings closed:** F22, F41, F44

**Lanes touched:** verifier-rust, spec, sdk-js

**Tasks:** 4

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

Behaviour changes that could surprise:
- Task 3/4 tighten allowlist entries to STRICT 64-char lowercase hex. Today `verify_envelope_signatures` lowercases both sides, so an UPPERCASE 64-hex allowlist entry currently matches; after Task 3 it is dropped with a note, and after Task 4 the CLI rejects it with exit 2. This is deliberate (it matches the documented `VerifyOptions::allowlist` contract and the CLI's existing strict `is_lower_hex_64` used by `--decryption-key`), but it is a real break for anyone passing uppercase hex. No fixture, vector, or test in the repo uses uppercase keys (`spec/vectors/tamper-detection/output/keys.json` is lowercase), so nothing in-tree regresses.
- Task 2 changes three public signatures of the `capsule-verify` crate: `parse_chain_jsonl` now returns `Vec<ChainRecord>`, and `verify_chain` / `first_and_entry_hash` now take `&[ChainRecord]`. `ChainRecord: Deref<Target = ChainEvent>` keeps every read-only field access (`e.seq`, `e.hash`, `e.actor`) compiling unchanged; only mutation sites and explicit `Vec<ChainEvent>` annotations need edits, and all of them are inside this crate (verified by grep: chain.rs, schemas.rs, verifier.rs, l3.rs, lib.rs only — `tests/parity_against_js_sdk.rs` and `tests/spec_registry.rs` do not name these types).
- Task 3 changes the internal `l3_attempt_decrypt_and_verify` signature from `options: &VerifyOptions` to `allowlist: &[String]` and drops `VerifyOptions` from l3.rs's import list. It is `pub(crate)`, single call site.

Existing tests that must be edited (they will fail to compile or assert otherwise, and the plan edits them explicitly): `chain.rs::first_and_entry_hash_empty` (type annotation), `chain.rs::detects_seq_skew` (mutation now goes through `.event`, and its comment about the hash also failing is no longer true), `chain.rs::detects_hash_tampering` (must mutate `raw`, not the typed view — mutating the typed view is now invisible to the recompute), `schemas.rs::chain_event_round_trip` (`.cloned()` -> `.map(|r| r.event.clone())`).

Cross-lane coordination:
- The new `empty-chain` vector is picked up automatically by three lanes: `verifier-rust/tests/spec_registry.rs::malformed_registry_outcomes`, `sdk-py/tests/test_spec_registry.py::test_malformed_registry_outcomes`, and `tools/check-spec-vectors.mjs`. JS (`sdk-js/src/verifier.js:198-202`) and Python (`sdk-py/src/capsule/verifier.py:206-212`) already emit `chain/events.jsonl missing or empty` for a zero-event chain, so both were green on the new vector without any change — verified by running them. sdk-swift and sdk-kotlin do not consume this registry, so no action there; if another cluster wires them into it, this vector becomes a new obligation for those lanes.
- `tools/run-conformance.mjs` runs `node sdk-js/tools/generate-malformed-fixtures.mjs --check` as the `malformed-fixtures-regen` lane. The new fixture must be committed together with the generator edit or that lane goes red.
- File-level conflict risk: the settled chain.md step-6 actor rule lives in `chain_walk_into` (verifier.rs:783-790 pristine), the same function Task 1 edits (its top) and Task 2 re-signatures. Rust already enforces that rule, so that cluster should not need to touch verifier-rust — but if it does, land C8 first or expect a small manual merge in `chain_walk_into`.
- Signer-set binding is out of scope here and untouched.

## Validation performed while specifying this plan

The steps below were applied to a **copy of the repository outside the working tree** and executed. This is the real output from that run, not a prediction.

<details>
<summary>Expand validation log</summary>

```
Applied all four tasks on a copy at /private/tmp/.../scratchpad/work-c8 (cp -Rc of the repo, incl. verifier-rust/target) and ran everything for real. Nothing was written inside the repo.

RED (F22, registry vector, before the chain_walk_into guard):
'''
$ cargo test --manifest-path verifier-rust/Cargo.toml --test spec_registry
---- malformed_registry_outcomes stdout ----
thread 'malformed_registry_outcomes' panicked at tests/spec_registry.rs:73:28:
empty-chain: chain must fail; got ChainCheck { ok: true, errors: [], event_count: 0, note: None }
test result: FAILED. 0 passed; 1 failed; 2 filtered out
'''
RED (F22, unit test): 'chain check must fail closed on an empty chain; got: ChainCheck { ok: true, errors: [], event_count: 0, note: None }'
RED (F41): 'an event whose stored bytes omit untrusted_payload_fields must still verify; got: [ChainErr { seq: 1, message: "hash mismatch: stored 207148ed1723b7e7500047cd8be43befb0e7d63f525bf156ca5e3b0ca68ed673, recomputed b98053708ce1526bf3bb2d77d37abf73d0b684d6c34c14cd0708e7b805fa6271" }]'
RED (F44 lib): 'expected a malformed-allowlist note; got: []' (both new tests)
RED (F44 CLI): 'error[E0425]: cannot find function \'validate_allowlist\' in this scope'

GREEN after all four tasks:
'''
$ cargo test --manifest-path verifier-rust/Cargo.toml --workspace
test result: ok. 106 passed; 0 failed  (capsule-verify lib)
test result: ok. 3 passed; 0 failed    (capsule-verify-cli)
test result: ok. 7 passed; 0 failed    (tests/parity_against_js_sdk.rs)
test result: ok. 3 passed; 0 failed    (tests/spec_registry.rs)
$ cargo clippy --workspace --all-targets
# only the 2 pre-existing zip_reader.rs unnecessary_cast warnings; none in the touched files
'''
Fixture generation is deterministic and did not perturb the checked-in fixtures:
'''
$ node sdk-js/tools/generate-malformed-fixtures.mjs
wrote empty-chain.capsule (2214 bytes)   # + the 10 existing ones
$ diff -rq <work copy output> <repo output>
Only in <work copy>: empty-chain.capsule    # every pre-existing fixture byte-identical
$ node sdk-js/tools/generate-malformed-fixtures.mjs --check   -> ok, all 11
'''
Cross-lane, with the new vector in place:
'''
$ node tools/check-spec-vectors.mjs        -> spec vectors: ok (281 vectors)
$ (sdk-js) npm test                        -> # pass 57  # fail 0
$ (sdk-py) PYTHONPATH=src pytest -q        -> 183 passed
'''
End-to-end CLI on the new fixture (after the fix):
'''
$ ./target/debug/capsule-verify-cli verify spec/vectors/malformed-layout/output/empty-chain.capsule
  [x] chain
        seq 0: chain/events.jsonl missing or empty
Result: FAIL     (exit=1)
$ ./target/debug/capsule-verify-cli verify .../clean.capsule --allowlist cc76ce271ed61e515b598d73290a2b39
error: --allowlist entry must be 64 lowercase hex chars (a 32-byte Ed25519 public key); got: cc76ce271ed61e515b598d73290a2b39   (exit=2)
'''
All line numbers in the plan were derived by replaying the tasks in order onto a pristine copy of the sources and re-grepping the anchors at each stage, so each task's numbers are correct for the tree state that task starts from.
```

</details>

---

## C8 — verifier-rust: empty chain passes, chain-hash preimage rebuilt from the typed struct, unvalidated allowlist

Four tasks. Task 1 closes F22 (HIGH) and ships the negative conformance vector. Task 2 closes F41. Tasks 3 and 4 close F44 at the library and CLI boundaries respectively.

All commands are run from the repository root; `--manifest-path verifier-rust/Cargo.toml` avoids any `cd`.

---

### Task 1: Fail closed on an empty chain, with a conformance vector

**Files:**
- Create: `spec/vectors/malformed-layout/output/empty-chain.capsule` (generated, not hand-written)
- Modify: `sdk-js/tools/generate-malformed-fixtures.mjs:66-70`
- Modify: `spec/vectors/malformed-layout/vectors.json:20-22` and `spec/vectors/malformed-layout/vectors.json:49-53`
- Modify: `verifier-rust/crates/capsule-verify/src/test_support.rs:123` (append at EOF)
- Modify: `verifier-rust/crates/capsule-verify/src/verifier.rs:769-770`
- Test: `verifier-rust/crates/capsule-verify/src/verifier.rs:918-921` (test imports) and `verifier-rust/crates/capsule-verify/src/verifier.rs:2316` (append before the closing brace of `mod tests`)
- Test: `verifier-rust/tests/spec_registry.rs` (registry-driven; no edit needed — it enumerates `vectors.json`)

**Interfaces:**
- Consumes: `crate::test_support::tampered_capsule_bytes(name: &str) -> Vec<u8>`; `crate::zip_reader::unpack_zip(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, ZipError>`; `chain_walk_into(events, manifest, envelope, chain_check, errors, scope)`
- Produces: `test_support::synthesize_capsule_with_file_replacement(base: &str, path: &str, content: Vec<u8>) -> Vec<u8>`; the chain-error string `"seq 0: chain/events.jsonl missing or empty"` (byte-identical to the JS and Python lanes); fixture `spec/vectors/malformed-layout/output/empty-chain.capsule` and registry vector `empty-chain`

- [ ] **Step 1: Add the empty-chain fixture to the generator**

In `sdk-js/tools/generate-malformed-fixtures.mjs`, the `invalid-chain-json.capsule` entry currently ends at line 70. Insert the new entry immediately after it:

```js
    "invalid-chain-json.capsule": replaceData(
      base,
      "chain/events.jsonl",
      Buffer.from("{ this is not json\n", "utf8"),
    ),

    // Chain file present but zero-length. With no events there is no first or
    // entry hash to compare against the envelope, so a verifier that treats an
    // empty chain as "nothing to complain about" leaves the envelope entirely
    // unbound to the chain. An empty chain is also never legal per
    // spec/chain.md: the host emits a backstop event before sealing.
    "empty-chain.capsule": replaceData(base, "chain/events.jsonl", Buffer.alloc(0)),
```

- [ ] **Step 2: Register the vector and generate the fixture bytes**

In `spec/vectors/malformed-layout/vectors.json`, extend the `notes` array (currently lines 20-22) and insert the new vector between `invalid-chain-json` and `duplicate-entry` (currently line 49). The two edited regions in full:

```json
  "notes": [
    "The 'reason' field is normative: an implementation must reject the fixture for the named reason category. Exact error strings are implementation-defined.",
    "'empty-chain' has a present-but-zero-length chain/events.jsonl. Verifiers MUST fail the chain check closed: with no events there is no first_event_hash / entry_hash to bind the envelope to the chain, and spec/chain.md requires a host-emitted backstop event when a session produced none."
  ],
```

```json
    {
      "name": "invalid-chain-json",
      "capsule_file": "output/invalid-chain-json.capsule",
      "expected": { "ok": false, "failing": ["content_index", "chain"] }
    },
    {
      "name": "empty-chain",
      "capsule_file": "output/empty-chain.capsule",
      "expected": { "ok": false, "failing": ["content_index", "chain"] }
    },
    {
      "name": "duplicate-entry",
```

Then generate the bytes (deterministic; the 10 pre-existing fixtures are rewritten byte-identically):

```bash
node sdk-js/tools/generate-malformed-fixtures.mjs
node sdk-js/tools/generate-malformed-fixtures.mjs --check
git status --short spec/vectors/malformed-layout/output   # must show ONLY the new empty-chain.capsule
```

- [ ] **Step 3: Run the registry test to verify it fails**
Run: `cargo test --manifest-path verifier-rust/Cargo.toml --test spec_registry`
Expected: FAIL with `empty-chain: chain must fail; got ChainCheck { ok: true, errors: [], event_count: 0, note: None }` (panic at `tests/spec_registry.rs:73:28`), `test result: FAILED. 0 passed; 1 failed`

- [ ] **Step 4: Add the fixture helper the unit test needs**

Append to the end of `verifier-rust/crates/capsule-verify/src/test_support.rs` (after line 123, which is the closing `}` of `synthesize_capsule_with_envelope_mutation`). Note it must go *after* that function, not before it — inserting it above would orphan that function's doc comment:

```rust
/// Read a base capsule fixture, replace ONE entry's bytes, and re-pack the
/// modified file set as a STORED-only ZIP. Used by tests that need a single
/// artifact to be malformed (e.g. a present-but-empty `chain/events.jsonl`)
/// without depending on a JS-side generator run.
///
/// Every other file is copied through unchanged. The capsule is NOT re-signed
/// and the manifest's `content_index` is NOT recomputed, so the content-index
/// check will also fail — callers should assert only on the check they are
/// exercising.
pub fn synthesize_capsule_with_file_replacement(
    base: &str,
    path: &str,
    content: Vec<u8>,
) -> Vec<u8> {
    let bytes = tampered_capsule_bytes(base);
    let mut files: BTreeMap<String, Vec<u8>> =
        unpack_zip(&bytes).expect("base fixture must unzip");
    assert!(
        files.contains_key(path),
        "base fixture {base:?} has no entry {path:?}"
    );
    files.insert(path.to_string(), content);

    let buf = Cursor::new(Vec::<u8>::new());
    let mut zw = ZipWriter::new(buf);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, data) in &files {
        zw.start_file(name, opts).expect("zip start_file");
        zw.write_all(data).expect("zip write_all");
    }
    zw.finish().expect("zip finish").into_inner()
}
```

- [ ] **Step 5: Write the failing unit test**

First widen the test-module import at `verifier-rust/crates/capsule-verify/src/verifier.rs:918-921`:

```rust
    use crate::test_support::{
        clean_capsule_bytes, recipient_x25519_private_key,
        synthesize_capsule_with_envelope_mutation, synthesize_capsule_with_file_replacement,
        tampered_capsule_bytes,
    };
```

Then append the test at the end of `mod tests`, immediately before the file's final `}` (line 2316):

```rust
    /// A plain capsule whose `chain/events.jsonl` is present but zero-length
    /// must fail closed. With no events, `first_and_entry_hash` returns
    /// `None`, so the `envelope.first_event_hash` / `envelope.entry_hash`
    /// cross-checks — the only thing binding the envelope to the chain in a
    /// plain capsule — never execute. An empty chain also defeats
    /// `spec/chain.md`'s backstop-event rule. The chain check must therefore
    /// reject it outright instead of reporting `ok = true`.
    #[test]
    fn empty_chain_fails_closed() {
        let bytes = synthesize_capsule_with_file_replacement(
            "clean.capsule",
            "chain/events.jsonl",
            Vec::new(),
        );
        let result = verify_capsule(&bytes, &VerifyOptions::default());

        assert!(!result.ok, "an empty chain must not verify");
        assert!(
            !result.chain.ok,
            "chain check must fail closed on an empty chain; got: {:?}",
            result.chain
        );
        assert_eq!(result.chain.event_count, 0, "no events were parsed");
        assert!(
            result
                .chain
                .errors
                .iter()
                .any(|e| e.contains("chain/events.jsonl missing or empty")),
            "expected the JS-parity empty-chain message; got: {:?}",
            result.chain.errors
        );
    }
```

- [ ] **Step 6: Run the unit test to verify it fails**
Run: `cargo test --manifest-path verifier-rust/Cargo.toml -p capsule-verify empty_chain_fails_closed`
Expected: FAIL with `chain check must fail closed on an empty chain; got: ChainCheck { ok: true, errors: [], event_count: 0, note: None }`

- [ ] **Step 7: Guard the empty case in `chain_walk_into`**

In `verifier-rust/crates/capsule-verify/src/verifier.rs`, lines 769-770 currently read:

```rust
    chain_check.event_count = events.len();
    let walk_errors = verify_chain(events);
```

Replace with (the guard sits in `chain_walk_into` rather than at the `verify_capsule` call site so the L3 inner-chain walk in `l3.rs` is covered by the same rule):

```rust
    chain_check.event_count = events.len();

    // Fail closed on an empty chain. With zero events there is nothing for
    // `first_and_entry_hash` to return, so the `envelope.first_event_hash` /
    // `envelope.entry_hash` cross-checks below silently do not run — leaving
    // the envelope completely unbound to the chain. An empty chain is also
    // never legal per `spec/chain.md`: the host emits a backstop event before
    // sealing when a session produced none. Message matches the JS reference
    // (`sdk-js/src/verifier.js`) and the Python SDK.
    if events.is_empty() {
        chain_check
            .errors
            .push("seq 0: chain/events.jsonl missing or empty".to_string());
        chain_check.ok = false;
        return;
    }

    let walk_errors = verify_chain(events);
```

- [ ] **Step 8: Run both tests to verify they pass**
Run: `cargo test --manifest-path verifier-rust/Cargo.toml -p capsule-verify empty_chain_fails_closed && cargo test --manifest-path verifier-rust/Cargo.toml --test spec_registry`
Expected: PASS — `test verifier::tests::empty_chain_fails_closed ... ok`, then `test result: ok. 3 passed; 0 failed` for `spec_registry`

- [ ] **Step 9: Run the full lane suite for regressions**
Run: `cargo test --manifest-path verifier-rust/Cargo.toml --workspace`
Expected: `103 passed; 0 failed` (capsule-verify lib), `7 passed` (parity_against_js_sdk), `3 passed` (spec_registry), `0 failed` everywhere

- [ ] **Step 10: Run the other two lanes that consume the new vector**
Run: `node tools/check-spec-vectors.mjs && node sdk-js/tools/generate-malformed-fixtures.mjs --check`
Expected: `spec vectors: ok (281 vectors)`, then `ok empty-chain.capsule (2214 bytes)` among the 11 `ok` lines. Then run the Python registry lane: `cd sdk-py && PYTHONPATH=src python3 -m pytest tests/test_spec_registry.py -q` — expected `18 passed`.

- [ ] **Step 11: Commit**
```bash
git add spec/vectors/malformed-layout/vectors.json \
        spec/vectors/malformed-layout/output/empty-chain.capsule \
        sdk-js/tools/generate-malformed-fixtures.mjs \
        verifier-rust/crates/capsule-verify/src/verifier.rs \
        verifier-rust/crates/capsule-verify/src/test_support.rs
git commit -m "fix(verifier-rust): fail closed on an empty chain (F22)

A present-but-empty chain/events.jsonl produced chain.ok=true and skipped
the envelope.first_event_hash / entry_hash cross-checks entirely, so a
plain capsule had no envelope-to-chain binding at all and the CLI reported
PASS. chain_walk_into now rejects a zero-event chain with the same message
the JS and Python lanes use, covering the L3 inner walk as well. Adds the
empty-chain negative vector to spec/vectors/malformed-layout."
```

---

### Task 2: Rebuild the chain-hash preimage from the stored line, not the typed struct

**Files:**
- Modify: `verifier-rust/crates/capsule-verify/src/schemas.rs:182` (insert `ChainRecord` before it), `:199-224` (`parse_chain_jsonl`), `:409` (test)
- Modify: `verifier-rust/crates/capsule-verify/src/chain.rs:16`, `:71-75`, `:113-127`, `:171`, `:212`, `:222-225`, `:237-240`
- Modify: `verifier-rust/crates/capsule-verify/src/verifier.rs:46`, `:762`
- Modify: `verifier-rust/crates/capsule-verify/src/l3.rs:26`, `:144`
- Modify: `verifier-rust/crates/capsule-verify/src/lib.rs:28-31`
- Test: `verifier-rust/crates/capsule-verify/src/chain.rs:247` (append before the closing brace of `mod tests`)

(Line numbers are for the tree **after Task 1**; Task 1 does not touch chain.rs, schemas.rs, l3.rs or lib.rs, and its verifier.rs edits are all below line 769 or inside `mod tests`, so `verifier.rs:46` and `:762` are unmoved.)

**Interfaces:**
- Consumes: `schemas::ChainEvent`; `chain::hash_event_value(event_minus_hash: &serde_json::Value) -> Option<[u8; 32]>`; `crypto::bytes_to_hex`
- Produces: `schemas::ChainRecord { pub event: ChainEvent, pub raw: serde_json::Value }` implementing `Deref<Target = ChainEvent>`; `parse_chain_jsonl(bytes: &[u8]) -> Result<Vec<ChainRecord>, ChainParseError>`; `verify_chain(events: &[ChainRecord]) -> Vec<ChainErr>`; `first_and_entry_hash(events: &[ChainRecord]) -> Option<(&str, &str)>`; `chain_walk_into(events: &[ChainRecord], ...)`

- [ ] **Step 1: Write the failing test**

Append to the end of `mod tests` in `verifier-rust/crates/capsule-verify/src/chain.rs`, immediately before the final `}` (line 247). It compiles against the *current* signatures, so it runs and fails on the assertion rather than on a compile error:

```rust
    /// The hash preimage must be rebuilt from the ORIGINAL stored line, not
    /// from a re-serialization of the typed [`ChainEvent`].
    /// `untrusted_payload_fields` carries `#[serde(default)]` and no
    /// `skip_serializing_if`, so an event whose stored bytes omit the key is
    /// re-emitted with `"untrusted_payload_fields":[]` injected — different
    /// JCS bytes, and a spurious hash mismatch on a chain that is intact.
    #[test]
    fn recomputes_hash_from_stored_line_not_typed_struct() {
        // Stored event bytes: note the absence of `untrusted_payload_fields`.
        let mut event = serde_json::json!({
            "seq": 1,
            "event_id": "evt_001",
            "actor": "system:host",
            "kind": "observation",
            "action": "session_ended",
            "target": "capsule",
            "timestamp": "2026-01-01T00:00:00Z",
            "payload": {},
            "prev_hash": "0".repeat(64)
        });
        let hash = bytes_to_hex(&hash_event_value(&event).expect("event is hashable"));
        event["hash"] = serde_json::Value::String(hash);
        let line = format!("{}\n", serde_json::to_string(&event).expect("serialize"));

        let events = parse_chain_jsonl(line.as_bytes()).expect("chain parses");
        let errors = verify_chain(&events);
        assert!(
            errors.is_empty(),
            "an event whose stored bytes omit untrusted_payload_fields must still \
             verify; got: {errors:?}"
        );
    }
```

- [ ] **Step 2: Run the test to verify it fails**
Run: `cargo test --manifest-path verifier-rust/Cargo.toml -p capsule-verify recomputes_hash_from_stored_line_not_typed_struct`
Expected: FAIL with `an event whose stored bytes omit untrusted_payload_fields must still verify; got: [ChainErr { seq: 1, message: "hash mismatch: stored 207148ed1723b7e7500047cd8be43befb0e7d63f525bf156ca5e3b0ca68ed673, recomputed b98053708ce1526bf3bb2d77d37abf73d0b684d6c34c14cd0708e7b805fa6271" }]`

- [ ] **Step 3: Add `ChainRecord` to schemas.rs**

Insert immediately before `/// Errors returned by [\`parse_chain_jsonl\`].` (line 182), i.e. between the end of the `ChainEvent` struct and the `ChainParseError` enum:

```rust
/// One parsed line of `chain/events.jsonl`: the typed [`ChainEvent`] view
/// plus `raw`, the untouched `serde_json::Value` that line deserialized to.
///
/// The chain hash preimage MUST be rebuilt from `raw`, never from a
/// re-serialization of `event`. Round-tripping through the typed struct is
/// lossy in both directions: a field carrying `#[serde(default)]` (today
/// `untrusted_payload_fields`) is re-emitted even when the stored bytes
/// omitted it, and any key the struct does not model is dropped. Either
/// change flips the JCS canonical bytes and produces a spurious
/// `hash mismatch` on a chain that is intact.
///
/// `Deref` to `ChainEvent` so read-only field access (`record.seq`,
/// `record.hash`, `record.actor`, ...) reads exactly as it did when the
/// parser returned bare events; mutation and preimage construction go
/// through the explicit `event` / `raw` fields.
#[derive(Debug, Clone, PartialEq)]
pub struct ChainRecord {
    pub event: ChainEvent,
    pub raw: serde_json::Value,
}

impl std::ops::Deref for ChainRecord {
    type Target = ChainEvent;
    fn deref(&self) -> &ChainEvent {
        &self.event
    }
}
```

- [ ] **Step 4: Make `parse_chain_jsonl` keep the raw value**

Replace `verifier-rust/crates/capsule-verify/src/schemas.rs:199-224` (the doc comment plus the whole function) with:

```rust
/// Parse `chain/events.jsonl` bytes into a [`ChainRecord`] vector.
///
/// Splits on `\n`, skips empty lines (so a trailing newline — or two — is
/// fine), and deserializes each non-empty line twice: once as an untyped
/// `serde_json::Value` (kept verbatim as [`ChainRecord::raw`], which is what
/// the hash preimage is rebuilt from) and once as a typed [`ChainEvent`]
/// (used for the structural checks). The line number reported on parse
/// failure is the 1-based index in the original input, which matches
/// `nl`/editor numbering for the underlying file.
///
/// Mirrors `eventsFromJsonl` in `sdk-js/src/chain.js`.
pub fn parse_chain_jsonl(bytes: &[u8]) -> Result<Vec<ChainRecord>, ChainParseError> {
    let text = std::str::from_utf8(bytes)?;
    let mut events = Vec::new();
    for (i, line) in text.split('\n').enumerate() {
        if line.is_empty() {
            // Skip blank lines — including the trailing one produced by
            // `eventsToJsonl`'s `lines.join("\n") + "\n"`. Note we keep
            // `enumerate` over the *unfiltered* iterator so the 1-based
            // `line` number reported in errors matches the file's actual
            // line numbering.
            continue;
        }
        let raw: serde_json::Value = serde_json::from_str(line)
            .map_err(|source| ChainParseError::LineParse { line: i + 1, source })?;
        let event: ChainEvent = serde_json::from_value(raw.clone())
            .map_err(|source| ChainParseError::LineParse { line: i + 1, source })?;
        events.push(ChainRecord { event, raw });
    }
    Ok(events)
}
```

- [ ] **Step 5: Point `verify_chain` at the raw value**

In `verifier-rust/crates/capsule-verify/src/chain.rs`, change the import at line 16:

```rust
use crate::schemas::ChainRecord;
```

Change the signature and loop head (lines 71-75) from `pub fn verify_chain(events: &[ChainEvent])` / `for (i, event) in events.iter().enumerate() {` to:

```rust
pub fn verify_chain(events: &[ChainRecord]) -> Vec<ChainErr> {
    let mut errors: Vec<ChainErr> = Vec::new();
    let mut prev: [u8; 32] = GENESIS_PREV;

    for (i, record) in events.iter().enumerate() {
        let event = &record.event;
        let expected_seq = (i as u64) + 1;
```

Replace the recompute block at lines 113-127 (`// Recompute the hash. Strip \`hash\` from the serialized form, then` … through the `if let Some(map) = event_value.as_object_mut() { map.remove("hash"); }`) with:

```rust
        // Recompute the hash from the ORIGINAL line's JSON — never from a
        // re-serialization of the typed struct, which would inject
        // `#[serde(default)]` fields the stored bytes omitted and drop keys
        // the struct does not model. Strip only `hash`, then hash
        // `prev_raw || JCS(rest)`.
        let mut event_value = record.raw.clone();
        match event_value.as_object_mut() {
            Some(map) => {
                map.remove("hash");
            }
            None => {
                errors.push(ChainErr {
                    seq: seq_for_msg,
                    message: "recompute failed: event is not a JSON object".to_string(),
                });
                continue;
            }
        }
```

And change the signature at line 171 (the body is unchanged — `events.first()?.hash` resolves through `Deref`):

```rust
pub fn first_and_entry_hash(events: &[ChainRecord]) -> Option<(&str, &str)> {
```

- [ ] **Step 6: Update the three chain.rs tests that name or mutate the typed view**

Line 212, in `first_and_entry_hash_empty`:

```rust
        let events: Vec<ChainRecord> = Vec::new();
```

Lines 222-225, in `detects_seq_skew` (the old comment claimed the hash recompute would also fail; with the preimage taken from `raw`, mutating the typed view no longer affects it):

```rust
        // Bump the first event's TYPED seq from 1 → 99. The hash preimage is
        // rebuilt from the stored line (`raw`), which we leave alone, so the
        // ordering check is the only thing that fires here.
        events[0].event.seq = 99;
```

Lines 237-240, in `detects_hash_tampering`:

```rust
        // Mutate the first event's STORED bytes by replacing its payload
        // entirely with an empty object. The chain hash MUST then fail to
        // recompute. (Mutating only the typed view would be invisible now
        // that the preimage is rebuilt from `raw`.)
        events[0].raw["payload"] = serde_json::json!({});
```

- [ ] **Step 7: Thread `ChainRecord` through the callers and the re-export**

`verifier-rust/crates/capsule-verify/src/verifier.rs:46`:

```rust
use crate::schemas::{parse_chain_jsonl, ChainRecord, Envelope, Manifest};
```

`verifier-rust/crates/capsule-verify/src/verifier.rs:762` (first parameter of `chain_walk_into`; the actor loop below it needs no edit — `e.actor` and `e.seq` resolve through `Deref`):

```rust
    events: &[ChainRecord],
```

`verifier-rust/crates/capsule-verify/src/l3.rs:26`:

```rust
use crate::schemas::{parse_chain_jsonl, ChainRecord, Envelope, Manifest};
```

`verifier-rust/crates/capsule-verify/src/l3.rs:144`:

```rust
    let inner_events: Vec<ChainRecord> = match inner_files.get("chain/events.jsonl") {
```

`verifier-rust/crates/capsule-verify/src/lib.rs:28-31`:

```rust
pub use schemas::{
    parse_chain_jsonl, ChainEvent, ChainParseError, ChainRecord, ContentIndex, ContentIndexEntry,
    Encryption, Envelope, FormatBlock, Manifest, Originator, Participant, Signer,
};
```

- [ ] **Step 8: Fix the one schemas.rs test that clones a record into a `ChainEvent`**

At `verifier-rust/crates/capsule-verify/src/schemas.rs:409`, inside `chain_event_round_trip`, replace:

```rust
        let event = events
            .first()
            .map(|r| r.event.clone())
            .expect("at least one event");
```

- [ ] **Step 9: Run the test to verify it passes**
Run: `cargo test --manifest-path verifier-rust/Cargo.toml -p capsule-verify recomputes_hash_from_stored_line_not_typed_struct`
Expected: PASS — `test chain::tests::recomputes_hash_from_stored_line_not_typed_struct ... ok`, `test result: ok. 1 passed; 0 failed`

- [ ] **Step 10: Run the full lane suite for regressions**
Run: `cargo test --manifest-path verifier-rust/Cargo.toml --workspace && cargo clippy --manifest-path verifier-rust/Cargo.toml --workspace --all-targets`
Expected: `104 passed; 0 failed` (capsule-verify lib), `7 passed` (parity), `3 passed` (spec_registry); clippy emits only the two pre-existing `unnecessary_cast` warnings in `zip_reader.rs:205-206` and none in the touched files

- [ ] **Step 11: Commit**
```bash
git add verifier-rust/crates/capsule-verify/src/schemas.rs \
        verifier-rust/crates/capsule-verify/src/chain.rs \
        verifier-rust/crates/capsule-verify/src/verifier.rs \
        verifier-rust/crates/capsule-verify/src/l3.rs \
        verifier-rust/crates/capsule-verify/src/lib.rs
git commit -m "fix(verifier-rust): hash chain events from their stored bytes (F41)

verify_chain rebuilt the hash preimage with serde_json::to_value on the
deserialized ChainEvent. untrusted_payload_fields is #[serde(default)] with
no skip_serializing_if, so an event whose stored line omits the key was
re-serialized with \"untrusted_payload_fields\":[] injected, changing the JCS
bytes and reporting a spurious hash mismatch on an intact chain; unmodelled
keys were dropped for the same effect. parse_chain_jsonl now returns
ChainRecord { event, raw } and the recompute strips only \`hash\` from the
original line's JSON."
```

---

### Task 3: Validate allowlist entries in the library and report the bad ones

**Files:**
- Modify: `verifier-rust/crates/capsule-verify/src/verifier.rs:152-155` (doc), `:264-265` (step 0), `:295`, `:319`, `:341`, `:364`, `:386` (early returns), `:609` (L3 call), `:620` (step 10), `:626` (step 12), `:877` (insert helpers before)
- Modify: `verifier-rust/crates/capsule-verify/src/l3.rs:27-30`, `:67`, `:243`
- Test: `verifier-rust/crates/capsule-verify/src/verifier.rs:2367` (append before the closing brace of `mod tests`)

(Line numbers are for the tree **after Tasks 1 and 2**. l3.rs numbers are unchanged from pristine — Task 2 edited lines 26 and 144 in place.)

**Interfaces:**
- Consumes: `verify_envelope_signatures(envelope: &Envelope, allowlist: &[String]) -> EnvelopeCheck`; `l3_attempt_decrypt_and_verify(...)`
- Produces: `verifier::partition_allowlist(allowlist: &[String]) -> (Vec<String>, Vec<String>)` (`pub(crate)`); `l3_attempt_decrypt_and_verify(..., allowlist: &[String], ...)` replacing the `options: &VerifyOptions` parameter; the note prefix `"ignoring malformed allowlist entry (expected 64 lowercase hex chars): "`

- [ ] **Step 1: Write the failing tests**

Append at the end of `mod tests` in `verifier-rust/crates/capsule-verify/src/verifier.rs`, immediately before the final `}` (line 2367). `unpack_zip` and `Manifest` are already in scope via `use super::*` (the existing `clean_capsule_with_allowlist` test uses both):

```rust
    /// A truncated or otherwise malformed allowlist entry can never match a
    /// 32-byte Ed25519 public key, but because the vector is non-empty the
    /// "no allowlist provided" advisory used to be suppressed — leaving a
    /// PASS with `trusted=false` and no diagnostic anywhere in the result.
    /// Malformed entries must be reported in `notes` and must not count as
    /// an allowlist for the purposes of the advisory.
    #[test]
    fn malformed_allowlist_entry_is_reported() {
        let bytes = clean_capsule_bytes();
        let result = verify_capsule(
            &bytes,
            &VerifyOptions {
                // Truncated: 32 hex chars where 64 are required.
                allowlist: vec!["cc76ce271ed61e515b598d73290a2b39".to_string()],
                recipient_private_key: None,
            },
        );

        assert!(
            result.ok,
            "a malformed allowlist must not fail the capsule itself; errors: {:?}",
            result.errors
        );
        assert_eq!(result.trusted_signer_count, 0, "nothing can be trusted");
        assert!(
            result
                .notes
                .iter()
                .any(|n| n.contains("malformed allowlist entry")),
            "expected a malformed-allowlist note; got: {:?}",
            result.notes
        );
        assert!(
            result.notes.iter().any(|n| n.contains("no allowlist")),
            "an all-malformed allowlist must still raise the no-allowlist \
             advisory; got: {:?}",
            result.notes
        );
    }

    /// The sibling of `malformed_allowlist_entry_is_reported`: a well-formed
    /// entry alongside a malformed one still trusts the good key, and only
    /// the bad entry is reported.
    #[test]
    fn malformed_allowlist_entry_does_not_suppress_valid_one() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).unwrap();
        let manifest: Manifest =
            serde_json::from_slice(map.get("manifest.json").unwrap()).unwrap();
        let pk = manifest.originator.public_key.clone();

        let result = verify_capsule(
            &bytes,
            &VerifyOptions {
                allowlist: vec!["not-hex".to_string(), pk],
                recipient_private_key: None,
            },
        );

        assert!(result.ok, "errors: {:?}", result.errors);
        assert!(
            result.trusted_signer_count >= 1,
            "the well-formed key must still be honoured, got {}",
            result.trusted_signer_count
        );
        assert!(
            result
                .notes
                .iter()
                .any(|n| n.contains("malformed allowlist entry")),
            "expected a malformed-allowlist note; got: {:?}",
            result.notes
        );
        assert!(
            !result.notes.iter().any(|n| n.contains("no allowlist")),
            "one valid entry means the allowlist is NOT empty; got: {:?}",
            result.notes
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**
Run: `cargo test --manifest-path verifier-rust/Cargo.toml -p capsule-verify malformed_allowlist`
Expected: FAIL — both tests panic with `expected a malformed-allowlist note; got: []`, `test result: FAILED. 0 passed; 2 failed`

- [ ] **Step 3: Add the validation helpers**

Insert into `verifier-rust/crates/capsule-verify/src/verifier.rs` immediately before `/// Build a final \`VerifyResult\` from the accumulated state.` (line 877), i.e. between `verify_envelope_signatures` and `assemble_result`:

```rust
/// Split a caller-supplied allowlist into the entries this verifier will
/// actually match against and one human-readable note per rejected entry.
///
/// An Ed25519 public key is 32 raw bytes, i.e. exactly 64 lowercase hex
/// characters. Anything else — a truncated paste, a `0x` prefix, a base64
/// blob, a file path — can never equal a signer's `public_key`, so keeping it
/// would silently mean "allowlist supplied, nothing trusted, no explanation".
pub(crate) fn partition_allowlist(allowlist: &[String]) -> (Vec<String>, Vec<String>) {
    let mut valid: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    for entry in allowlist {
        if is_ed25519_public_key_hex(entry) {
            valid.push(entry.clone());
        } else {
            notes.push(format!(
                "ignoring malformed allowlist entry (expected 64 lowercase hex chars): {entry:?}"
            ));
        }
    }
    (valid, notes)
}

/// True iff `s` is exactly 64 characters drawn from `0-9a-f`. Mirrors
/// `is_lower_hex_64` in the CLI's `--decryption-key` parser.
fn is_ed25519_public_key_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
```

- [ ] **Step 4: Partition the allowlist at the top of `verify_capsule`**

Lines 264-265 currently read `let mut notes: Vec<String> = Vec::new();` followed by `let mut chain_check = ChainCheck::default();`. Insert the new block between them:

```rust
    let mut errors: Vec<TopError> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    // ---- (0) allowlist hygiene ------------------------------------------
    // A caller-supplied key that is not 64 lowercase hex chars can never
    // match a signer's public key. Silently keeping it in the vector loses
    // the operator's intent AND suppresses the "no allowlist provided"
    // advisory in step 12 (the vector is non-empty), so a truncated
    // `--allowlist` would report PASS with `trusted=false` and no diagnostic
    // at all. Report each bad entry and match only the well-formed ones.
    let (allowlist, allowlist_notes) = partition_allowlist(&options.allowlist);
    notes.extend(allowlist_notes);
    let no_allowlist = allowlist.is_empty();

    let mut chain_check = ChainCheck::default();
```

Also extend the `VerifyOptions::allowlist` doc comment at lines 152-155 so the contract is stated where callers read it:

```rust
    /// Trusted Ed25519 public keys (lowercase hex, 64 chars). A signer is
    /// marked `trusted` only when its key appears here AND its signature
    /// verifies. An empty allowlist surfaces an advisory note in
    /// [`VerifyResult::notes`].
    ///
    /// Entries are validated: anything that is not exactly 64 lowercase hex
    /// characters cannot match a 32-byte Ed25519 key, so it is dropped and
    /// reported in [`VerifyResult::notes`]. The "no allowlist provided"
    /// advisory is keyed off the *well-formed* entries, so an allowlist made
    /// up entirely of malformed values still raises it.
    pub allowlist: Vec<String>,
```

- [ ] **Step 5: Route every consumer through the filtered list**

Replace all five occurrences of `options.allowlist.is_empty(),` (the `no_allowlist` argument of `assemble_result` on the early-return paths, at lines 295, 319, 341, 364, 386) with:

```rust
                no_allowlist,
```

At line 609, the L3 call's fifth argument, replace `options,` with `&allowlist,`:

```rust
            l3_attempt_decrypt_and_verify(
                priv_key,
                &envelope,
                &manifest,
                &files,
                &allowlist,
                &mut chain_check,
```

At line 620:

```rust
    envelope_check = verify_envelope_signatures(&envelope, &allowlist);
```

At line 626, drop the now-shadowing re-computation and explain the source of truth:

```rust
    // ---- (12) advisory note ---------------------------------------------
    // `no_allowlist` came from step 0 and counts only well-formed entries, so
    // an allowlist made up entirely of malformed keys still gets the advisory
    // on top of its per-entry notes.
    if no_allowlist {
```

- [ ] **Step 6: Narrow the L3 helper's parameter**

`l3_attempt_decrypt_and_verify` only ever read `options.allowlist`, so take the slice directly. In `verifier-rust/crates/capsule-verify/src/l3.rs`, lines 27-30:

```rust
use crate::verifier::{
    chain_walk_into, verify_content_index, verify_envelope_signatures, ChainCheck,
    ContentIndexCheck, EnvelopeCheck, TopError, TopErrorCategory, TopErrorScope,
};
```

Line 67:

```rust
    allowlist: &[String],
```

Line 243:

```rust
    let inner_check = verify_envelope_signatures(&inner_envelope, allowlist);
```

- [ ] **Step 7: Run the tests to verify they pass**
Run: `cargo test --manifest-path verifier-rust/Cargo.toml -p capsule-verify malformed_allowlist`
Expected: PASS — `test result: ok. 2 passed; 0 failed`

- [ ] **Step 8: Run the full lane suite for regressions**
Run: `cargo test --manifest-path verifier-rust/Cargo.toml --workspace`
Expected: `106 passed; 0 failed` (capsule-verify lib), `7 passed` (parity), `3 passed` (spec_registry) — in particular `clean_capsule_with_allowlist` and `encrypted_clean_capsule_l3_inner_envelope_verifies` still pass, proving the filtered list still reaches both the outer and the inner envelope check

- [ ] **Step 9: Commit**
```bash
git add verifier-rust/crates/capsule-verify/src/verifier.rs \
        verifier-rust/crates/capsule-verify/src/l3.rs
git commit -m "fix(verifier-rust): validate allowlist entries and report bad ones (F44)

A truncated or mangled allowlist entry never matched a signer, and because
the vector was non-empty the 'no allowlist provided' advisory was suppressed
too, so the run reported PASS with trusted=false and an empty notes array.
verify_capsule now partitions the allowlist up front: malformed entries are
dropped with a per-entry note, and the advisory is keyed off the well-formed
ones. l3_attempt_decrypt_and_verify takes the filtered slice directly."
```

---

### Task 4: Reject a malformed `--allowlist` at the CLI boundary

**Files:**
- Modify: `verifier-rust/crates/capsule-verify-cli/src/main.rs:91` (insert before), `:445` (insert before)
- Test: `verifier-rust/crates/capsule-verify-cli/src/main.rs:461` (append a `#[cfg(test)] mod tests` at EOF)

(main.rs is untouched by Tasks 1-3, so these are pristine line numbers.)

**Interfaces:**
- Consumes: `is_lower_hex_64(s: &str) -> bool` (already in main.rs at line 446)
- Produces: `validate_allowlist(allowlist: &[String]) -> Result<(), String>`; CLI exit code `2` with `error: --allowlist entry must be 64 lowercase hex chars (a 32-byte Ed25519 public key); got: <value>` on stderr

- [ ] **Step 1: Write the failing test**

Append at the end of `verifier-rust/crates/capsule-verify-cli/src/main.rs` (after line 461, the closing `}` of `decode_hex_32`):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// The originator key from `spec/vectors/tamper-detection/output/keys.json`
    /// is the canonical well-formed shape: 64 lowercase hex chars.
    #[test]
    fn validate_allowlist_accepts_64_lowercase_hex() {
        let good =
            vec!["cc76ce271ed61e515b598d73290a2b3905f40f280fa1548ed7f0513bdbe0c2bc".to_string()];
        assert!(validate_allowlist(&good).is_ok());
        assert!(validate_allowlist(&[]).is_ok(), "no allowlist is not an error");
    }

    /// A truncated paste is the exact failure this guard exists for: it can
    /// never match, yet it suppresses the "no allowlist provided" advisory.
    #[test]
    fn validate_allowlist_rejects_truncated_entry() {
        let truncated = vec!["cc76ce271ed61e515b598d73290a2b39".to_string()];
        let err = validate_allowlist(&truncated).expect_err("truncated key must be rejected");
        assert!(err.contains("--allowlist"), "message must name the flag; got: {err}");
        assert!(
            err.contains("64 lowercase hex"),
            "message must state the expected shape; got: {err}"
        );
    }

    /// Non-hex characters and uppercase hex are both rejected: the CLI's
    /// documented key form is lowercase hex, matching `--decryption-key`.
    #[test]
    fn validate_allowlist_rejects_non_lowercase_hex() {
        let uppercase =
            vec!["CC76CE271ED61E515B598D73290A2B3905F40F280FA1548ED7F0513BDBE0C2BC".to_string()];
        assert!(validate_allowlist(&uppercase).is_err());
        let non_hex =
            vec!["zz76ce271ed61e515b598d73290a2b3905f40f280fa1548ed7f0513bdbe0c2bc".to_string()];
        assert!(validate_allowlist(&non_hex).is_err());
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**
Run: `cargo test --manifest-path verifier-rust/Cargo.toml -p capsule-verify-cli`
Expected: FAIL to compile with `error[E0425]: cannot find function \`validate_allowlist\` in this scope` (five occurrences, first at `crates/capsule-verify-cli/src/main.rs:473:17`), ending in `error: could not compile \`capsule-verify-cli\` (bin "capsule-verify-cli" test)`

- [ ] **Step 3: Add `validate_allowlist`**

Insert immediately before `/// True iff \`s\` is exactly 64 ASCII characters drawn from \`0-9a-f\`.` (line 445), i.e. between `parse_decryption_key` and `is_lower_hex_64`:

```rust
/// Reject any `--allowlist` entry that cannot be an Ed25519 public key.
///
/// An Ed25519 public key is 32 raw bytes — exactly 64 lowercase hex
/// characters. A truncated or mangled entry simply never matches a signer,
/// and because the allowlist is then non-empty the library's "no allowlist
/// provided" advisory does not fire either, so the operator sees a PASS with
/// `trusted=false` and no diagnostic. Fail loudly at the argument boundary
/// instead (exit 2), the same way an unparseable `--decryption-key` does.
///
/// On the first bad entry, returns the formatted error string ready to print
/// to stderr.
fn validate_allowlist(allowlist: &[String]) -> Result<(), String> {
    for entry in allowlist {
        if !is_lower_hex_64(entry) {
            return Err(format!(
                "error: --allowlist entry must be 64 lowercase hex chars (a 32-byte Ed25519 public key); got: {entry}"
            ));
        }
    }
    Ok(())
}
```

- [ ] **Step 4: Call it from `run_verify`**

Insert immediately before the `// Resolve --decryption-key (if given) into a 32-byte X25519 private key.` comment (line 91), i.e. right after the `std::fs::read(path)` match closes:

```rust
    // Reject a malformed --allowlist before verification runs: a value that
    // is not a 32-byte Ed25519 public key can never match a signer, so the
    // run would otherwise report `trusted=false` with no explanation.
    if let Err(msg) = validate_allowlist(&allowlist) {
        eprintln!("{msg}");
        return ExitCode::from(2);
    }
```

- [ ] **Step 5: Run the test to verify it passes**
Run: `cargo test --manifest-path verifier-rust/Cargo.toml -p capsule-verify-cli`
Expected: PASS — `test result: ok. 3 passed; 0 failed`

- [ ] **Step 6: Verify the exit code end to end**
Run: `cargo build --manifest-path verifier-rust/Cargo.toml -p capsule-verify-cli && verifier-rust/target/debug/capsule-verify-cli verify spec/vectors/tamper-detection/output/clean.capsule --allowlist cc76ce271ed61e515b598d73290a2b39; echo "exit=$?"`
Expected: `error: --allowlist entry must be 64 lowercase hex chars (a 32-byte Ed25519 public key); got: cc76ce271ed61e515b598d73290a2b39` on stderr and `exit=2`

- [ ] **Step 7: Run the full lane suite for regressions**
Run: `cargo test --manifest-path verifier-rust/Cargo.toml --workspace && cargo clippy --manifest-path verifier-rust/Cargo.toml --workspace --all-targets`
Expected: `106 passed` (capsule-verify lib), `3 passed` (capsule-verify-cli), `7 passed` (parity), `3 passed` (spec_registry), `0 failed` everywhere; clippy emits only the two pre-existing `zip_reader.rs` `unnecessary_cast` warnings

- [ ] **Step 8: Commit**
```bash
git add verifier-rust/crates/capsule-verify-cli/src/main.rs
git commit -m "fix(verifier-rust): reject a malformed --allowlist with exit 2 (F44)

A truncated --allowlist value silently never matched, leaving the operator
with a PASS, trusted=false, and no diagnostic. The CLI now validates each
entry as 64 lowercase hex chars before verification runs and exits 2 with a
precise message, mirroring how an unparseable --decryption-key is handled."
```


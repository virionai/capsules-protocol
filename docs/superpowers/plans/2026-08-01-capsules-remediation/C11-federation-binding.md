# C11 — Federation identity attestations bind to nothing

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Part of:** [Capsules pre-release remediation](./README.md) · Tier 2 (v0.7 correctness)

**Findings closed:** F07, F19, F28, F27, F39, F54, F53, F63

**Lanes touched:** sdk-js, spec

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

Ordering is strict: all ten tasks touch `sdk-js/src/federation/` and `sdk-js/test/federation.test.js`, so they must run in sequence in one lane. Line numbers cited are from the pre-plan files; each code step quotes enough surrounding context that the replacement is unambiguous after earlier tasks shift lines.

Breaking API changes (intended, pre-release): `verifyIdentityAttestation` now throws `TypeError` unless `capsuleId`, `signerPublicKeyHex`, and `expectedIssuer` are supplied (plus `audience` for the JWT profile); `verifyJwt` throws unless `issuer` and `audience` are supplied; `evaluateSignerPolicy` takes a required fourth argument `{ capsuleId }` and its `attestedSigners` entries must carry `capsule_id`. Every one of these is a loud failure at the call site, never a silent behaviour change.

Existing tests that break by design and are updated inside the task that breaks them: `sdk-js/test/federation.test.js:103` and `:119` (Task 1), `:80-85`, `:135-137`, `:152`, `:171`, `:178`, `:184`, `:201-203`, `:305-308` (Tasks 1-2), `:42-48` `makeClerkInstance` (Task 4), `:242-256` policy test (Task 7).

Also newly rejected, deliberately: an attestation with no `expires_at` (previously "never expires"), and a JWT attestation with no `aud`. Any issuer minting attestation JWTs must now set `aud`; `spec/profiles/clerk.md` is updated to say so (Task 10).

Nothing outside `sdk-js/src/federation/` imports federation code (`grep -rl federation` over `cli/`, `examples/`, `tools/`, and the other four SDK lanes returns nothing but docs), so no other lane's tests are touched. The new `spec/vectors/identity-attestation/` directory is safe for the Python/Rust/Swift/Kotlin registry tests because each of those loads named vector files explicitly (`tamper-detection`, `malformed-layout`, `signing-input`) rather than walking the tree — but `tools/check-spec-vectors.mjs` DOES walk the tree and fails closed on unrecognized JSON, which is why Task 9 adds the recognizer in the same commit as the vectors.

Not addressed here, by instruction or scope: signer-set binding (separate design spike); typed declarations for `federation` in `sdk-js/src/index.d.ts` (still `Record<string, unknown>`, so none of the new required options are enforced at the type level); an HTTPS-only rule for issuer document fetches (`spec/federation.md` says "HTTPS only" but the reference adapter still accepts whatever `fetchLike` is given — origin binding is enforced, scheme is not); JWT-profile conformance vectors (ECDSA signatures are randomized so the fixture would not regenerate byte-identically — only the native `ed25519-jcs` profile is pinned).

## Validation performed while specifying this plan

The steps below were applied to a **copy of the repository outside the working tree** and executed. This is the real output from that run, not a prediction.

<details>
<summary>Expand validation log</summary>

```
Applied every code change on a copy outside the repo ('/tmp/work-c11/', holding 'sdk-js/', 'spec/', 'tools/') and kept a pristine copy ('/tmp/work-c11/sdk-js-pristine/') to prove each test fails before its fix. Real output:

1. Reproduced F07 against the UNMODIFIED source before writing anything — a validly-signed ES256 JWT with no 'cap' claim and no binding options:
'''
F07 no-binding-claims: { "ok": true, "subject": { "clerk_user_id": "user_attacker", "org_role": "admin" }, ... "errors": [] }
'''

2. Every new test run against the pristine (unfixed) source, all 22 of them appended to the original suite:
'''
$ cd /tmp/work-c11/sdk-js-pristine && node --test test/binding.test.js
not ok 13 - a validly-signed token with NO cap binding claim is rejected
not ok 14 - an ed25519-jcs attestation with an empty binding claim is rejected
not ok 15 - verifyIdentityAttestation refuses to run without binding options
not ok 16 - a JWT attestation is rejected when iss is not the caller's expected issuer
not ok 17 - a JWT attestation minted for another audience is rejected
not ok 18 - ed25519-jcs attestation issuer must match the caller's expected issuer
not ok 19 - verifyJwt refuses to run without an expected issuer and audience
not ok 20 - an unparseable expires_at is an error, not an absent expiry
not ok 21 - an unparseable issued_at is an error, not an absent freshness check
not ok 22 - an attestation with no expiry is rejected
not ok 23 - an unknown kid fails closed instead of trying every cached key
not ok 24 - ed25519-jcs: an unknown kid does not fall back to another issuer's key
not ok 25 - a native trust root published as a standard Ed25519 OKP JWK is consumable
not ok 27 - status distinguishes unverified (unknown) from rejected (negative)
not ok 28 - a malformed attestation reports attestation_rejected
not ok 29 - evaluateSignerPolicy rejects an attestation bound to another capsule
not ok 30 - evaluateSignerPolicy refuses to run without a capsule id
not ok 31 - issuer metadata whose 'issuer' does not match the fetch origin is refused
not ok 33 - loadTrustRoots refuses a jwks_uri off the issuer origin
# tests 34
# pass 15
# fail 19
'''
Two of those are exploit confirmations, not just missing-error-string failures — pristine returns 'ok: true' for both:
'''
not ok 23 - an unknown kid fails closed instead of trying every cached key
    kid selects the key; an unknown kid resolves to nothing
    true !== false
not ok 29 - evaluateSignerPolicy rejects an attestation bound to another capsule
    a cross-capsule attestation must not satisfy policy
    true !== false
'''
F27 confirmed the other direction (a conforming issuer is locked out):
'''
not ok 25 - a native trust root published as a standard Ed25519 OKP JWK is consumable
    ["no trust-root key for kid=issuer-key-1"]
    false !== true
'''

3. Baseline of the untouched lane, for the regression numbers each task cites:
'''
$ cd /tmp/work-c11/sdk-js-pristine && npm test
# tests 57
# pass 57
# fail 0
'''

4. Full lane suite after all fixes (57 original + 22 new):
'''
$ cd /tmp/work-c11/sdk-js && npm test
# tests 79
# pass 79
# fail 0
'''

5. New conformance vector set, generated and checked:
'''
$ node sdk-js/tools/generate-attestation-vectors.mjs
wrote identity-attestation/vectors.json (11 vectors)
$ node tools/check-spec-vectors.mjs
spec vectors: ok (291 vectors)          # was 280
$ node sdk-js/tools/generate-attestation-vectors.mjs --check
ok identity-attestation/vectors.json (11 vectors)
'''
And the red state for Task 9 step 3, running the UNMODIFIED checker against the new vectors (it is 'isCollection' that grabs the doc first):
'''
$ node tools/check-spec-vectors.mjs   # pre-recognizer
FAIL: .../spec/vectors/identity-attestation/vectors.json [valid]: vector requires capsule_file and expected
... (11 lines, one per vector)
exit=1
'''

6. Task 10's doc-drift check, before and after the spec edits:
'''
$ sh check-doc.sh   # against the real repo
ORIGINAL exit=1
$ sh check-doc.sh   # against /tmp/work-c11
federation spec text: ok
FIXED exit=0
'''

Not run: the full 'node tools/run-conformance.mjs' harness (it installs and builds every example lane). The two targets this cluster touches were run directly, as shown above. The Python/Rust/Swift/Kotlin lanes were not run — verified by inspection that each loads 'spec/vectors/' by explicit filename ('sdk-py/tests/test_spec_registry.py:29-32', 'verifier-rust/tests/spec_registry.rs:24-30', 'sdk-swift/Tests/CapsuleTests/ParityTests.swift:44', 'sdk-kotlin/core/src/test/kotlin/ai/virion/capsule/core/ParityTest.kt:117') and therefore cannot see the new directory.
```

</details>

---

## C11 — Federation identity attestations bind to nothing

The federation overlay is the least-reviewed code in the repo and it currently accepts a validly-signed provider session token as a capsule attestation. Ten tasks, all in the `sdk-js` lane plus `spec/`, executed in order (they share two files).

Reproduced before any change, against the unmodified source: a correctly-signed ES256 JWT carrying **no** `cap` claim, verified with no binding options, returns `ok: true` with a fully populated subject and an empty `errors` array.

---

### Task 1: Make the capsule/signer binding mandatory

**Files:**
- Modify: `sdk-js/src/federation/attestation.js:165-179` (JSDoc + option guards)
- Modify: `sdk-js/src/federation/attestation.js:234-243` (binding block)
- Test: `sdk-js/test/federation.test.js`

**Interfaces:**
- Consumes: `verifyIdentityAttestation(attestation, options)`, `signIdentityAttestation({claims, issuer, kid, ed25519PrivateKeyHex})`
- Produces: `verifyIdentityAttestation` now throws `TypeError` unless `options.capsuleId` and `options.signerPublicKeyHex` are non-empty strings; new error strings `attestation missing required binding claim '<field>'`

- [ ] **Step 1: Write the failing test**

Append to `sdk-js/test/federation.test.js`:

```js
// --------------------------------------------------------------------------
// Binding is mandatory (spec/federation.md "Identity attestation")
// --------------------------------------------------------------------------

test("a validly-signed token with NO cap binding claim is rejected", () => {
  const clerk = makeClerkInstance();
  const signer = generateEd25519();
  const capsuleId = "c".repeat(64);
  const nowSec = Math.floor(Date.parse(TS) / 1000);
  // A raw Clerk session token: correctly signed by the instance key, but it
  // binds no capsule at all. spec/profiles/clerk.md forbids embedding one.
  const jwt = clerk.mintJwt({
    iss: "https://clerk.acme.example", sub: "user_attacker", org_id: "org_9",
    org_role: "admin", email: "e@acme.example", iat: nowSec, exp: nowSec + 3600,
  });
  const att = { typ: "capsule-identity-attestation", spec_version: "0.6", alg: "ES256", issuer: "https://clerk.acme.example", jwt };
  const res = verifyIdentityAttestation(att, {
    trustRoots: clerk.jwks, now: new Date(TS),
    capsuleId, signerPublicKeyHex: signer.publicKeyHex,
  });
  assert.equal(res.ok, false, "an unbound token must never verify");
  assert.ok(res.errors.some((e) => e.includes("missing required binding claim 'capsule_id'")));
  assert.ok(res.errors.some((e) => e.includes("missing required binding claim 'signer_public_key'")));
});

test("an ed25519-jcs attestation with an empty binding claim is rejected", () => {
  const { issuer, kid, ed, trustRoots } = makeIssuer();
  const signer = generateEd25519();
  const att = signIdentityAttestation({
    issuer, kid, ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "", subject: {}, issued_at: TS, expires_at: "2027-05-07T12:00:00Z",
    },
  });
  const res = verifyIdentityAttestation(att, {
    trustRoots, now: new Date(TS),
    capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
  });
  assert.equal(res.ok, false);
  assert.ok(res.errors.some((e) => e.includes("missing required binding claim 'signer_role'")));
});

test("verifyIdentityAttestation refuses to run without binding options", () => {
  const { issuer, kid, ed, trustRoots } = makeIssuer();
  const signer = generateEd25519();
  const att = signIdentityAttestation({
    issuer, kid, ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "originator", subject: {}, issued_at: TS, expires_at: "2027-05-07T12:00:00Z",
    },
  });
  assert.throws(
    () => verifyIdentityAttestation(att, { trustRoots, now: new Date(TS) }),
    /requires options\.capsuleId/,
  );
  assert.throws(
    () => verifyIdentityAttestation(att, { trustRoots, now: new Date(TS), capsuleId: "a".repeat(64) }),
    /requires options\.signerPublicKeyHex/,
  );
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-js && node --test test/federation.test.js`

Expected: FAIL — three tests fail:
```
not ok 13 - a validly-signed token with NO cap binding claim is rejected
    The expression evaluated to a falsy value:
      assert.ok(res.errors.some((e) => e.includes("missing required binding claim 'capsule_id'")))
not ok 14 - an ed25519-jcs attestation with an empty binding claim is rejected
    Expected values to be strictly equal:
    true !== false
not ok 15 - verifyIdentityAttestation refuses to run without binding options
    error: 'Missing expected exception.'
# fail 3
```

- [ ] **Step 3: Require the binding options**

In `sdk-js/src/federation/attestation.js`, replace the JSDoc option list and the first three lines of the function (lines 169-178) —

```js
 * options:
 *   trustRoots          issuer public keys / JWKS (required for a real check)
 *   now                 Date | ms | undefined (defaults to Date.now)
 *   capsuleId           expected capsule_id the attestation must bind
 *   signerPublicKeyHex  expected signer key the attestation must bind
 *   jwtBindingClaim     for JWT profile: claim key holding the capsule binding
 *                       object (default "cap")
 */
export function verifyIdentityAttestation(attestation, options = {}) {
  const errors = [];
```

— with:

```js
 * options (capsuleId and signerPublicKeyHex are REQUIRED — an attestation
 * that is not checked against a specific capsule and signer binds nothing;
 * see spec/federation.md "Identity attestation"):
 *   trustRoots          issuer public keys / JWKS (required for a real check)
 *   now                 Date | ms | undefined (defaults to Date.now)
 *   capsuleId           expected capsule_id the attestation MUST bind
 *   signerPublicKeyHex  expected signer key the attestation MUST bind
 *   jwtBindingClaim     for JWT profile: claim key holding the capsule binding
 *                       object (default "cap")
 */
export function verifyIdentityAttestation(attestation, options = {}) {
  if (typeof options.capsuleId !== "string" || options.capsuleId.length === 0) {
    throw new TypeError(
      "verifyIdentityAttestation requires options.capsuleId: an attestation is only meaningful against a specific capsule (spec/federation.md)",
    );
  }
  if (typeof options.signerPublicKeyHex !== "string" || options.signerPublicKeyHex.length === 0) {
    throw new TypeError(
      "verifyIdentityAttestation requires options.signerPublicKeyHex: an attestation is only meaningful against a specific signer (spec/federation.md)",
    );
  }
  const errors = [];
```

- [ ] **Step 4: Require the binding claims themselves**

In the same file, replace the binding block (lines 234-243) —

```js
  // Binding checks: the attestation must be for THIS capsule and signer.
  if (options.capsuleId && claims.capsule_id !== options.capsuleId) {
    errors.push(`capsule_id binding mismatch: ${claims.capsule_id} vs ${options.capsuleId}`);
  }
  if (
    options.signerPublicKeyHex &&
    claims.signer_public_key?.toLowerCase() !== options.signerPublicKeyHex.toLowerCase()
  ) {
    errors.push("signer_public_key binding mismatch");
  }
```

— with:

```js
  // The binding claims are MANDATORY (spec/federation.md "Identity
  // attestation"): an attestation whose claims omit them binds nothing. A raw
  // provider session token — which carries no `cap` object at all — lands
  // here and is rejected (spec/profiles/clerk.md "Security notes").
  let bindingComplete = true;
  for (const field of ["capsule_id", "signer_public_key", "signer_role"]) {
    const value = claims?.[field];
    if (typeof value !== "string" || value.length === 0) {
      errors.push(`attestation missing required binding claim '${field}'`);
      bindingComplete = false;
    }
  }

  // Binding checks: the attestation MUST be for THIS capsule and signer.
  if (bindingComplete) {
    if (claims.capsule_id !== options.capsuleId) {
      errors.push(`capsule_id binding mismatch: ${claims.capsule_id} vs ${options.capsuleId}`);
    }
    if (claims.signer_public_key.toLowerCase() !== options.signerPublicKeyHex.toLowerCase()) {
      errors.push("signer_public_key binding mismatch");
    }
  }
```

- [ ] **Step 5: Update the four existing tests that now call the API wrong**

In `sdk-js/test/federation.test.js`, four calls omit the now-required options. Replace line 103:

```js
  const res = verifyIdentityAttestation(att, { trustRoots, now: new Date(TS) });
```

with:

```js
  const res = verifyIdentityAttestation(att, {
    trustRoots, now: new Date(TS),
    capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
  });
```

Replace line 119:

```js
  const res = verifyIdentityAttestation(att, { trustRoots, now: new Date("2026-06-01T00:00:00Z") });
```

with:

```js
  const res = verifyIdentityAttestation(att, {
    trustRoots, now: new Date("2026-06-01T00:00:00Z"),
    capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
  });
```

Replace lines 135-137:

```js
  const wrong = verifyIdentityAttestation(att, {
    trustRoots, now: new Date(TS), capsuleId: "b".repeat(64),
  });
```

with:

```js
  const wrong = verifyIdentityAttestation(att, {
    trustRoots, now: new Date(TS), capsuleId: "b".repeat(64),
    signerPublicKeyHex: signer.publicKeyHex,
  });
```

Replace line 152:

```js
  const res = verifyIdentityAttestation(att, { trustRoots: { keys: [] }, now: new Date(TS) });
```

with:

```js
  const res = verifyIdentityAttestation(att, {
    trustRoots: { keys: [] }, now: new Date(TS),
    capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
  });
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd sdk-js && node --test test/federation.test.js`

Expected: PASS — `# tests 15`, `# pass 15`, `# fail 0`

- [ ] **Step 7: Run the full lane suite for regressions**

Run: `cd sdk-js && npm test`

Expected: `# tests 60`, `# pass 60`, `# fail 0` (57 before this task, +3)

- [ ] **Step 8: Commit**
```bash
git add sdk-js/src/federation/attestation.js sdk-js/test/federation.test.js
git commit -m "fix(sdk-js): require capsule and signer binding on every identity attestation"
```

---

### Task 2: Bind attestation issuer and audience to caller-supplied trust configuration

**Files:**
- Create: `sdk-js/src/federation/issuer.js`
- Modify: `sdk-js/src/federation/attestation.js:20-22` (import), `:120-121` (verifyJwt guards), `:157-161` (iss/aud checks), `:177-182` (expectedIssuer guard + wrapper check), `:201-207` (JWT branch)
- Test: `sdk-js/test/federation.test.js`

**Interfaces:**
- Consumes: `verifyJwt(compact, {trustRoots, now, issuer, audience})`
- Produces: `normalizeIssuer(value) => string | null` (exported from `./issuer.js`); `verifyJwt` throws `TypeError` unless `issuer` and `audience` are supplied; `verifyIdentityAttestation` requires `options.expectedIssuer` always and `options.audience` for the JWT profile

- [ ] **Step 1: Write the failing test**

Append to `sdk-js/test/federation.test.js`, and add the shared audience constant next to `const TS` (line 23) — `const AUD = "capsule-attestation";`:

```js
test("a JWT attestation is rejected when iss is not the caller's expected issuer", () => {
  const clerk = makeClerkInstance();
  const signer = generateEd25519();
  const capsuleId = "c".repeat(64);
  const nowSec = Math.floor(Date.parse(TS) / 1000);
  // The attacker controls BOTH the token's `iss` and the wrapper's `issuer`.
  // Checking one against the other proves nothing.
  const jwt = clerk.mintJwt({
    iss: "https://clerk.evil.example", sub: "user_42", org_id: "org_9",
    org_role: "admin", aud: AUD, iat: nowSec, exp: nowSec + 3600,
    cap: { capsule_id: capsuleId, signer_public_key: signer.publicKeyHex, signer_role: "originator" },
  });
  const att = { typ: "capsule-identity-attestation", spec_version: "0.6", alg: "ES256", issuer: "https://clerk.evil.example", jwt };
  const res = verifyIdentityAttestation(att, {
    trustRoots: clerk.jwks, now: new Date(TS), capsuleId,
    signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: "https://clerk.acme.example", audience: AUD,
  });
  assert.equal(res.ok, false);
  assert.ok(res.errors.some((e) => e.includes("jwt: issuer mismatch")));
  assert.ok(res.errors.some((e) => e.includes("attestation issuer mismatch")));
});

test("a JWT attestation minted for another audience is rejected", () => {
  const clerk = makeClerkInstance();
  const signer = generateEd25519();
  const capsuleId = "c".repeat(64);
  const nowSec = Math.floor(Date.parse(TS) / 1000);
  const jwt = clerk.mintJwt({
    iss: "https://clerk.acme.example", sub: "user_42", aud: "some-other-app",
    iat: nowSec, exp: nowSec + 3600,
    cap: { capsule_id: capsuleId, signer_public_key: signer.publicKeyHex, signer_role: "originator" },
  });
  const att = { typ: "capsule-identity-attestation", spec_version: "0.6", alg: "ES256", issuer: "https://clerk.acme.example", jwt };
  const res = verifyIdentityAttestation(att, {
    trustRoots: clerk.jwks, now: new Date(TS), capsuleId,
    signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: "https://clerk.acme.example", audience: AUD,
  });
  assert.equal(res.ok, false);
  assert.ok(res.errors.some((e) => e.includes("jwt: audience mismatch")));
});

test("ed25519-jcs attestation issuer must match the caller's expected issuer", () => {
  const { kid, ed, trustRoots } = makeIssuer();
  const signer = generateEd25519();
  const att = signIdentityAttestation({
    issuer: "https://Capsules.Acme.Example/", kid, ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "originator", subject: {}, issued_at: TS, expires_at: "2027-05-07T12:00:00Z",
    },
  });
  const base = {
    trustRoots, now: new Date(TS),
    capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
  };
  const wrong = verifyIdentityAttestation(att, { ...base, expectedIssuer: "other.example" });
  assert.equal(wrong.ok, false);
  assert.ok(wrong.errors.some((e) => e.includes("attestation issuer mismatch")));

  // Origin form and bare DNS form are the same issuer (federation.md).
  const right = verifyIdentityAttestation(att, { ...base, expectedIssuer: "capsules.acme.example" });
  assert.equal(right.ok, true, JSON.stringify(right.errors));
});

test("verifyJwt refuses to run without an expected issuer and audience", () => {
  const clerk = makeClerkInstance();
  const nowSec = Math.floor(Date.parse(TS) / 1000);
  const jwt = clerk.mintJwt({ iss: "https://clerk.acme.example", sub: "u", aud: AUD, iat: nowSec, exp: nowSec + 3600 });
  assert.throws(() => verifyJwt(jwt, { trustRoots: clerk.jwks, now: new Date(TS) }), /requires an expected issuer/);
  assert.throws(
    () => verifyJwt(jwt, { trustRoots: clerk.jwks, now: new Date(TS), issuer: "https://clerk.acme.example" }),
    /requires an expected audience/,
  );
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-js && node --test test/federation.test.js`

Expected: FAIL — four tests fail:
```
not ok 16 - a JWT attestation is rejected when iss is not the caller's expected issuer
    Expected values to be strictly equal:
    true !== false
not ok 17 - a JWT attestation minted for another audience is rejected
    true !== false
not ok 18 - ed25519-jcs attestation issuer must match the caller's expected issuer
not ok 19 - verifyJwt refuses to run without an expected issuer and audience
    error: 'Missing expected exception.'
# fail 4
```

- [ ] **Step 3: Create the shared issuer normalizer**

Create `sdk-js/src/federation/issuer.js`:

```js
// Issuer identity normalization, shared by the attestation and discovery
// layers.
//
// spec/federation.md "Vocabulary": an issuer is canonically identified by a
// lowercase DNS name. Fields that are URLs by convention (issuer metadata
// `issuer`, JWT `iss`) carry the origin form; fields inside signer documents
// and envelopes carry the bare DNS name. "Verifiers MUST treat the two forms
// as the same issuer after normalization (strip scheme, lowercase, drop
// trailing slash)."

/**
 * Reduce an issuer identifier — origin form (`https://acme.example/`), bare
 * DNS form (`acme.example`), or a URL under the issuer origin
 * (`https://acme.example/.well-known/jwks.json`) — to its lowercase DNS
 * identity. Returns null for anything unparseable, so callers fail closed.
 */
export function normalizeIssuer(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (trimmed.length === 0) return null;
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    const host = new URL(withScheme).host.toLowerCase();
    return host.length > 0 ? host : null;
  } catch {
    return null;
  }
}
```

- [ ] **Step 4: Make verifyJwt demand an issuer and audience**

In `sdk-js/src/federation/attestation.js`, add the import after line 22:

```js
import { createPublicKey, verify as nodeVerify } from "node:crypto";
import { normalizeIssuer } from "./issuer.js";
```

Replace lines 120-121:

```js
export function verifyJwt(compact, { trustRoots, now, issuer, audience } = {}) {
  const errors = [];
```

with:

```js
export function verifyJwt(compact, { trustRoots, now, issuer, audience } = {}) {
  if (typeof issuer !== "string" || issuer.length === 0) {
    throw new TypeError(
      "verifyJwt requires an expected issuer: `iss` is checked against caller-supplied trust configuration, never against the token that carries it",
    );
  }
  if (typeof audience !== "string" || audience.length === 0) {
    throw new TypeError(
      "verifyJwt requires an expected audience: an attestation JWT is scoped to the verifying host (spec/profiles/clerk.md)",
    );
  }
  const errors = [];
```

Replace lines 157-161:

```js
  if (issuer && claims.iss !== issuer) errors.push(`jwt: issuer mismatch (${claims.iss})`);
  if (audience) {
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!aud.includes(audience)) errors.push(`jwt: audience mismatch (${claims.aud})`);
  }
```

with:

```js
  if (normalizeIssuer(claims.iss) !== normalizeIssuer(issuer)) {
    errors.push(`jwt: issuer mismatch (${claims.iss})`);
  }
  const aud = Array.isArray(claims.aud) ? claims.aud : claims.aud == null ? [] : [claims.aud];
  if (!aud.includes(audience)) errors.push(`jwt: audience mismatch (${claims.aud})`);
```

And update the JSDoc above `verifyJwt` (lines 113-119), replacing:

```js
 * Verify a compact JWT (Clerk-issued or compatible) against trust roots /
 * a JWKS. Fully offline given the JWKS. Returns { ok, claims, errors }.
 *
 * Checks signature, alg/kid selection, and (when present) exp/nbf plus the
 * caller-supplied issuer/audience.
 */
```

with:

```js
 * Verify a compact JWT (Clerk-issued or compatible) against trust roots /
 * a JWKS. Fully offline given the JWKS. Returns
 * { ok, claims, errors, trustRootMissing? }.
 *
 * Checks signature, alg/kid selection, exp/nbf when present, and the
 * caller-supplied issuer and audience — both REQUIRED. `trustRootMissing`
 * marks the "no cached key for this kid" case, which is unknown rather than
 * negative (spec/federation.md "Failure reporting").
 */
```

- [ ] **Step 5: Require expectedIssuer in verifyIdentityAttestation and stop the self-referential iss check**

In the same file, after the `signerPublicKeyHex` guard added in Task 1, add a third guard and a wrapper-issuer check. Replace:

```js
      "verifyIdentityAttestation requires options.signerPublicKeyHex: an attestation is only meaningful against a specific signer (spec/federation.md)",
    );
  }
  const errors = [];
  const now = options.now instanceof Date ? options.now.getTime() : options.now ?? Date.now();
  if (!attestation || attestation.typ !== ATTESTATION_TYP) {
    return { ok: false, subject: null, claims: null, errors: ["not a capsule identity attestation"] };
  }
```

with:

```js
      "verifyIdentityAttestation requires options.signerPublicKeyHex: an attestation is only meaningful against a specific signer (spec/federation.md)",
    );
  }
  if (typeof options.expectedIssuer !== "string" || options.expectedIssuer.length === 0) {
    throw new TypeError(
      "verifyIdentityAttestation requires options.expectedIssuer: the issuer is caller-supplied trust configuration, never read from the attestation being checked (spec/federation.md)",
    );
  }
  const errors = [];
  const now = options.now instanceof Date ? options.now.getTime() : options.now ?? Date.now();
  if (!attestation || attestation.typ !== ATTESTATION_TYP) {
    return { ok: false, subject: null, claims: null, errors: ["not a capsule identity attestation"] };
  }
  if (normalizeIssuer(attestation.issuer) !== normalizeIssuer(options.expectedIssuer)) {
    errors.push(`attestation issuer mismatch: ${attestation.issuer} vs ${options.expectedIssuer}`);
  }
```

Then replace the JWT branch head (lines 201-207):

```js
  } else if (attestation.jwt) {
    // JWT profile (Clerk): the binding lives inside the verified token.
    const res = verifyJwt(attestation.jwt, {
      trustRoots: options.trustRoots,
      now,
      issuer: attestation.issuer,
    });
```

with:

```js
  } else if (attestation.jwt) {
    // JWT profile (Clerk): the binding lives inside the verified token.
    if (typeof options.audience !== "string" || options.audience.length === 0) {
      throw new TypeError(
        "verifyIdentityAttestation requires options.audience for the JWT profile: the attestation JWT is scoped to the verifying host (spec/profiles/clerk.md)",
      );
    }
    const res = verifyJwt(attestation.jwt, {
      trustRoots: options.trustRoots,
      now,
      // The expected issuer is caller trust configuration. Reading it from
      // `attestation.issuer` — a field on the same untrusted wrapper — would
      // make the `iss` check self-referential and therefore vacuous.
      issuer: options.expectedIssuer,
      audience: options.audience,
    });
```

Finally add the two new options to the JSDoc option list, replacing:

```js
 *   jwtBindingClaim     for JWT profile: claim key holding the capsule binding
 *                       object (default "cap")
 */
```

with:

```js
 *   expectedIssuer      REQUIRED issuer identity (origin or bare DNS form)
 *   audience            REQUIRED for the JWT profile: expected `aud`
 *   jwtBindingClaim     for JWT profile: claim key holding the capsule binding
 *                       object (default "cap")
 */
```

- [ ] **Step 6: Update every existing call site in the test file**

Seven existing calls now need `expectedIssuer` (and `audience`/`aud` on the JWT path). In `sdk-js/test/federation.test.js`:

Lines 80-85 — add `expectedIssuer: issuer,` to the options object:

```js
  const res = verifyIdentityAttestation(att, {
    trustRoots,
    now: new Date(TS),
    capsuleId,
    signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: issuer,
  });
```

Add `expectedIssuer: issuer,` to the three calls edited in Task 1 (the tampered-claim, expired, and binding-mismatch tests) and to the no-trust-root call, e.g.:

```js
  const res = verifyIdentityAttestation(att, {
    trustRoots: { keys: [] }, now: new Date(TS),
    capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: issuer,
  });
```

Lines 164-171 — mint with `aud` and verify with both:

```js
  const jwt = clerk.mintJwt({
    iss: "https://clerk.acme.example",
    sub: "user_42",
    org_id: "org_9",
    aud: AUD,
    iat: nowSec,
    exp: nowSec + 3600,
  });
  const ok = verifyJwt(jwt, {
    trustRoots: clerk.jwks, now: new Date(TS),
    issuer: "https://clerk.acme.example", audience: AUD,
  });
```

Lines 177-178:

```js
  const badPayload = b64u(JSON.stringify({ iss: "https://clerk.acme.example", sub: "user_ADMIN", aud: AUD, iat: nowSec, exp: nowSec + 3600 }));
  const bad = verifyJwt(`${h}.${badPayload}.${s}`, {
    trustRoots: clerk.jwks, now: new Date(TS),
    issuer: "https://clerk.acme.example", audience: AUD,
  });
```

Lines 183-184:

```js
  const expired = clerk.mintJwt({
    iss: "https://clerk.acme.example", sub: "u", aud: AUD,
    iat: nowSec - 7200, exp: nowSec - 3600,
  });
  const exp = verifyJwt(expired, {
    trustRoots: clerk.jwks, now: new Date(TS),
    issuer: "https://clerk.acme.example", audience: AUD,
  });
```

Lines 196-203:

```js
    sub: "user_42", org_id: "org_9", email: "z@acme.example", org_role: "admin",
    aud: AUD, iat: nowSec, exp: nowSec + 3600,
    cap: { capsule_id: capsuleId, signer_public_key: signer.publicKeyHex, signer_role: "originator" },
  });
  const att = { typ: "capsule-identity-attestation", spec_version: "0.6", alg: "ES256", issuer: "https://clerk.acme.example", jwt };
  const res = verifyIdentityAttestation(att, {
    trustRoots: clerk.jwks, now: new Date(TS), capsuleId, signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: "https://clerk.acme.example", audience: AUD,
  });
```

Lines 305-308 (the portability-firewall test):

```js
  const overlay = verifyIdentityAttestation(embedded, {
    trustRoots: issuer.trustRoots, now: new Date(TS),
    capsuleId, signerPublicKeyHex: ed.publicKeyHex,
    expectedIssuer: issuer.issuer,
  });
```

And in the Task-1 test `a validly-signed token with NO cap binding claim is rejected`, add `aud: AUD,` to the minted claims and `expectedIssuer: "https://clerk.acme.example", audience: AUD,` to the verify options; add `expectedIssuer: issuer,` to the empty-binding-claim test; add a third `assert.throws` to the required-options test:

```js
  assert.throws(
    () =>
      verifyIdentityAttestation(att, {
        trustRoots, now: new Date(TS),
        capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
      }),
    /requires options\.expectedIssuer/,
  );
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `cd sdk-js && node --test test/federation.test.js`

Expected: PASS — `# tests 19`, `# pass 19`, `# fail 0`

- [ ] **Step 8: Run the full lane suite for regressions**

Run: `cd sdk-js && npm test`

Expected: `# tests 64`, `# pass 64`, `# fail 0`

- [ ] **Step 9: Commit**
```bash
git add sdk-js/src/federation/issuer.js sdk-js/src/federation/attestation.js sdk-js/test/federation.test.js
git commit -m "fix(sdk-js): check attestation iss and aud against caller-supplied trust config"
```

---

### Task 3: Treat unparseable and absent attestation timestamps as errors

**Files:**
- Modify: `sdk-js/src/federation/attestation.js:228-232`
- Test: `sdk-js/test/federation.test.js`

**Interfaces:**
- Consumes: `verifyIdentityAttestation` claims projection (`claims.issued_at`, `claims.expires_at`)
- Produces: internal `parseInstant(value) => number | null`; new error strings `attestation expires_at is not an RFC 3339 instant: <value>`, `attestation issued_at is not an RFC 3339 instant: <value>`, `attestation missing required claim 'expires_at'`

- [ ] **Step 1: Write the failing test**

Append to `sdk-js/test/federation.test.js`:

```js
test("an unparseable expires_at is an error, not an absent expiry", () => {
  const { issuer, kid, ed, trustRoots } = makeIssuer();
  const signer = generateEd25519();
  const att = signIdentityAttestation({
    issuer, kid, ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "originator", subject: {},
      issued_at: TS, expires_at: "whenever",
    },
  });
  const res = verifyIdentityAttestation(att, {
    trustRoots, now: new Date(TS),
    capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: issuer,
  });
  assert.equal(res.ok, false, "NaN must never read as 'never expires'");
  assert.ok(res.errors.some((e) => e.includes("expires_at is not an RFC 3339 instant")));
});

test("an unparseable issued_at is an error, not an absent freshness check", () => {
  const { issuer, kid, ed, trustRoots } = makeIssuer();
  const signer = generateEd25519();
  const att = signIdentityAttestation({
    issuer, kid, ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "originator", subject: {},
      issued_at: "2026-13-45T99:99:99Z", expires_at: "2027-05-07T12:00:00Z",
    },
  });
  const res = verifyIdentityAttestation(att, {
    trustRoots, now: new Date(TS),
    capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: issuer,
  });
  assert.equal(res.ok, false);
  assert.ok(res.errors.some((e) => e.includes("issued_at is not an RFC 3339 instant")));
});

test("an attestation with no expiry is rejected", () => {
  const { issuer, kid, ed, trustRoots } = makeIssuer();
  const signer = generateEd25519();
  const att = signIdentityAttestation({
    issuer, kid, ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "originator", subject: {}, issued_at: TS,
    },
  });
  const res = verifyIdentityAttestation(att, {
    trustRoots, now: new Date(TS),
    capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: issuer,
  });
  assert.equal(res.ok, false);
  assert.ok(res.errors.some((e) => e.includes("missing required claim 'expires_at'")));
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-js && node --test test/federation.test.js`

Expected: FAIL — three tests fail, the first with:
```
not ok 20 - an unparseable expires_at is an error, not an absent expiry
    NaN must never read as 'never expires'
    true !== false
# fail 3
```

- [ ] **Step 3: Add a strict RFC 3339 parser**

In `sdk-js/src/federation/attestation.js`, insert immediately above the `normalizeIssuer` import site's first use — i.e. just before the `selectKey` comment block (originally line 100):

```js
// Claim timestamps are RFC 3339 instants (spec/federation.md: "issued_at /
// expires_at are ISO-8601 UTC"). `Date.parse` returns NaN for garbage and
// every comparison against NaN is false — so an unparseable `expires_at`
// silently becomes "never expires". Parse strictly and fail closed.
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
function parseInstant(value) {
  if (typeof value !== "string" || !RFC3339.test(value)) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}
```

- [ ] **Step 4: Replace the expiry block**

Replace lines 228-232:

```js
  // Expiry (ed25519-jcs carries ISO timestamps in claims).
  if (claims.expires_at && now >= Date.parse(claims.expires_at)) errors.push("attestation expired");
  if (claims.issued_at && Date.parse(claims.issued_at) - now > 5 * 60 * 1000) {
    errors.push("attestation issued in the future");
  }
```

with:

```js
  // Expiry (ed25519-jcs carries ISO instants in claims; the JWT profile
  // reprojects iat/exp). An attestation with no expiry, or with an
  // unparseable one, is REJECTED — never treated as "never expires".
  if (claims.expires_at == null) {
    errors.push("attestation missing required claim 'expires_at'");
  } else {
    const expiresAt = parseInstant(claims.expires_at);
    if (expiresAt === null) {
      errors.push(`attestation expires_at is not an RFC 3339 instant: ${claims.expires_at}`);
    } else if (now >= expiresAt) {
      errors.push("attestation expired");
    }
  }
  if (claims.issued_at != null) {
    const issuedAt = parseInstant(claims.issued_at);
    if (issuedAt === null) {
      errors.push(`attestation issued_at is not an RFC 3339 instant: ${claims.issued_at}`);
    } else if (issuedAt - now > 5 * 60 * 1000) {
      errors.push("attestation issued in the future");
    }
  }
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd sdk-js && node --test test/federation.test.js`

Expected: PASS — `# tests 22`, `# pass 22`, `# fail 0`

- [ ] **Step 6: Run the full lane suite for regressions**

Run: `cd sdk-js && npm test`

Expected: `# tests 67`, `# pass 67`, `# fail 0`

- [ ] **Step 7: Commit**
```bash
git add sdk-js/src/federation/attestation.js sdk-js/test/federation.test.js
git commit -m "fix(sdk-js): reject attestations with missing or unparseable expiry"
```

---

### Task 4: Make trust-root key selection fail closed on an unknown kid

**Files:**
- Modify: `sdk-js/src/federation/attestation.js:100-104`
- Modify: `sdk-js/test/federation.test.js:42-48` (mock instance takes a kid)
- Test: `sdk-js/test/federation.test.js`

**Interfaces:**
- Consumes: `normalizeTrustRoots(trustRoots) => Array<{kid, alg, public_key_hex?, jwk?}>`
- Produces: `selectKey(roots, kid, alg)` returns a key only on an unambiguous match; `null` for an unknown kid, an ambiguous kid, or a kid-less lookup against a multi-key set

- [ ] **Step 1: Write the failing test**

First make the mock instance able to claim a kid it did not sign with. Replace `sdk-js/test/federation.test.js:42-48`:

```js
function makeClerkInstance() {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const kid = "clerk-key-abc";
  const jwk = { ...publicKey.export({ format: "jwk" }), kid, alg: "ES256", use: "sig" };
  const jwks = { keys: [jwk] };
  function mintJwt(claims) {
    const header = b64u(JSON.stringify({ alg: "ES256", typ: "JWT", kid }));
```

with:

```js
function makeClerkInstance(kid = "clerk-key-abc") {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = { ...publicKey.export({ format: "jwk" }), kid, alg: "ES256", use: "sig" };
  const jwks = { keys: [jwk] };
  // `headerKid` lets a test claim a kid it did not sign with.
  function mintJwt(claims, headerKid = kid) {
    const header = b64u(JSON.stringify({ alg: "ES256", typ: "JWT", kid: headerKid }));
```

Then append:

```js
test("an unknown kid fails closed instead of trying every cached key", () => {
  const clerkA = makeClerkInstance("clerk-key-A");
  const clerkB = makeClerkInstance("clerk-key-B");
  // One cached JWKS holding two keys, as a host that refreshes a multi-key
  // (or multi-issuer) set would have.
  const cached = { keys: [...clerkA.jwks.keys, ...clerkB.jwks.keys] };
  const signer = generateEd25519();
  const capsuleId = "c".repeat(64);
  const nowSec = Math.floor(Date.parse(TS) / 1000);
  const jwt = clerkA.mintJwt(
    {
      iss: "https://clerk.acme.example", sub: "user_42", org_role: "admin",
      aud: AUD, iat: nowSec, exp: nowSec + 3600,
      cap: { capsule_id: capsuleId, signer_public_key: signer.publicKeyHex, signer_role: "originator" },
    },
    "rotated-out-99", // a kid that is NOT in the cached set
  );
  const att = { typ: "capsule-identity-attestation", spec_version: "0.6", alg: "ES256", issuer: "https://clerk.acme.example", jwt };
  const res = verifyIdentityAttestation(att, {
    trustRoots: cached, now: new Date(TS), capsuleId,
    signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: "https://clerk.acme.example", audience: AUD,
  });
  assert.equal(res.ok, false, "kid selects the key; an unknown kid resolves to nothing");
  assert.ok(res.errors.some((e) => e.includes("no trust-root key for kid=rotated-out-99")));
});

test("ed25519-jcs: an unknown kid does not fall back to another issuer's key", () => {
  const a = makeIssuer();
  const b = makeIssuer();
  const cached = { keys: [...a.trustRoots.keys, { ...b.trustRoots.keys[0], kid: "issuer-key-2" }] };
  const signer = generateEd25519();
  const att = signIdentityAttestation({
    issuer: a.issuer, kid: "issuer-key-retired", ed25519PrivateKeyHex: a.ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "originator", subject: {}, issued_at: TS, expires_at: "2027-05-07T12:00:00Z",
    },
  });
  const res = verifyIdentityAttestation(att, {
    trustRoots: cached, now: new Date(TS),
    capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: a.issuer,
  });
  assert.equal(res.ok, false);
  assert.ok(res.errors.some((e) => e.includes("no trust-root key for kid=issuer-key-retired")));
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-js && node --test test/federation.test.js`

Expected: FAIL — both tests fail because the attestation is **accepted**:
```
not ok 23 - an unknown kid fails closed instead of trying every cached key
    kid selects the key; an unknown kid resolves to nothing
    true !== false
not ok 24 - ed25519-jcs: an unknown kid does not fall back to another issuer's key
    Expected values to be strictly equal:
    true !== false
# fail 2
```

- [ ] **Step 3: Replace selectKey**

In `sdk-js/src/federation/attestation.js`, replace lines 100-104:

```js
function selectKey(roots, kid, alg) {
  const byKid = roots.filter((k) => k.kid === kid);
  const pool = byKid.length ? byKid : roots;
  return pool.find((k) => k.alg === alg) ?? null;
}
```

with:

```js
// `kid` selects the key (spec/profiles/clerk.md "Security notes"). A cached
// trust-root set may hold several keys — possibly from several issuers — so
// an unknown or ambiguous kid MUST fail closed. Falling back to "any cached
// key whose alg matches" would accept an attestation signed by any key in
// the set. A kid-less attestation resolves only when the set holds exactly
// one key of the requested algorithm.
function selectKey(roots, kid, alg) {
  const byAlg = roots.filter((k) => k.alg === alg);
  if (kid == null || kid === "") return byAlg.length === 1 ? byAlg[0] : null;
  const matches = byAlg.filter((k) => k.kid === kid);
  return matches.length === 1 ? matches[0] : null;
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd sdk-js && node --test test/federation.test.js`

Expected: PASS — `# tests 24`, `# pass 24`, `# fail 0`

- [ ] **Step 5: Run the full lane suite for regressions**

Run: `cd sdk-js && npm test`

Expected: `# tests 69`, `# pass 69`, `# fail 0`

- [ ] **Step 6: Commit**
```bash
git add sdk-js/src/federation/attestation.js sdk-js/test/federation.test.js
git commit -m "fix(sdk-js): fail closed when kid does not select exactly one trust root"
```

---

### Task 5: Decode Ed25519 OKP JWK trust roots for the native profile

**Files:**
- Modify: `sdk-js/src/federation/attestation.js:88-98`
- Test: `sdk-js/test/federation.test.js`

**Interfaces:**
- Consumes: `b64uToBuf(s) => Buffer`, `bytesToHex(bytes) => string`
- Produces: `normalizeTrustRoots` now emits `{kid, alg: "ed25519-jcs", public_key_hex, jwk}` for an RFC 8037 `kty: "OKP", crv: "Ed25519"` JWK, and silently drops entries that are not usable attestation keys (so `selectKey` returns null and the caller fails closed)

- [ ] **Step 1: Write the failing test**

Append to `sdk-js/test/federation.test.js`:

```js
test("a native trust root published as a standard Ed25519 OKP JWK is consumable", () => {
  const { issuer, kid, ed } = makeIssuer();
  const signer = generateEd25519();
  // What loadTrustRoots() hands back when a conforming issuer publishes its
  // native attestation key as an RFC 8037 OKP JWK.
  const jwks = {
    keys: [
      {
        kty: "OKP", crv: "Ed25519", alg: "EdDSA", use: "sig", kid,
        x: Buffer.from(ed.publicKeyHex, "hex").toString("base64url"),
      },
    ],
  };
  const att = signIdentityAttestation({
    issuer, kid, ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "originator", subject: { clerk_user_id: "user_1" },
      issued_at: TS, expires_at: "2027-05-07T12:00:00Z",
    },
  });
  const res = verifyIdentityAttestation(att, {
    trustRoots: jwks, now: new Date(TS),
    capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: issuer,
  });
  assert.equal(res.ok, true, JSON.stringify(res.errors));
  assert.equal(res.subject.clerk_user_id, "user_1");
});

test("an X25519 OKP JWK is never usable as an attestation key", () => {
  const { issuer, kid, ed } = makeIssuer();
  const signer = generateEd25519();
  const jwks = {
    keys: [
      {
        kty: "OKP", crv: "X25519", kid,
        x: Buffer.from(ed.publicKeyHex, "hex").toString("base64url"),
      },
    ],
  };
  const att = signIdentityAttestation({
    issuer, kid, ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "originator", subject: {}, issued_at: TS, expires_at: "2027-05-07T12:00:00Z",
    },
  });
  const res = verifyIdentityAttestation(att, {
    trustRoots: jwks, now: new Date(TS),
    capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: issuer,
  });
  assert.equal(res.ok, false);
  assert.ok(res.errors.some((e) => e.includes("no trust-root key")));
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-js && node --test test/federation.test.js`

Expected: FAIL — a conforming issuer's own trust root is unusable:
```
not ok 25 - a native trust root published as a standard Ed25519 OKP JWK is consumable
    ["no trust-root key for kid=issuer-key-1"]
    false !== true
# fail 1
```

- [ ] **Step 3: Rewrite normalizeTrustRoots**

In `sdk-js/src/federation/attestation.js`, replace lines 88-98:

```js
function normalizeTrustRoots(trustRoots) {
  if (!trustRoots) return [];
  const keys = Array.isArray(trustRoots) ? trustRoots : trustRoots.keys ?? [];
  return keys.map((k) => {
    // A raw JWKS entry (from Clerk's /.well-known/jwks.json) has kty/kid/alg.
    if (k.kty && !k.public_key_hex && !k.jwk) {
      return { kid: k.kid, alg: k.alg ?? (k.kty === "OKP" ? "ed25519-jcs" : "ES256"), jwk: k };
    }
    return k;
  });
}
```

with:

```js
function normalizeTrustRoots(trustRoots) {
  if (!trustRoots) return [];
  const keys = Array.isArray(trustRoots) ? trustRoots : trustRoots.keys ?? [];
  const out = [];
  for (const k of keys) {
    if (!k || typeof k !== "object") continue;
    // Already a native entry ({kid, alg, public_key_hex}) or a pre-wrapped
    // JWK entry ({kid, alg, jwk}).
    if (k.public_key_hex || k.jwk) {
      out.push(k);
      continue;
    }
    if (!k.kty) continue;
    // A raw JWKS entry: Clerk's /.well-known/jwks.json, or a conforming
    // issuer publishing its NATIVE ed25519-jcs trust root as a standard
    // RFC 8037 OKP JWK. The native verify path needs raw key bytes, so
    // decode the base64url `x` coordinate into public_key_hex here.
    if (k.kty === "OKP") {
      if (k.crv !== "Ed25519") continue; // X25519/Ed448 are not attestation keys
      const raw = b64uToBuf(typeof k.x === "string" ? k.x : "");
      if (raw.length !== 32) continue;
      out.push({ kid: k.kid, alg: "ed25519-jcs", public_key_hex: bytesToHex(raw), jwk: k });
      continue;
    }
    out.push({ kid: k.kid, alg: k.alg ?? "ES256", jwk: k });
  }
  return out;
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd sdk-js && node --test test/federation.test.js`

Expected: PASS — `# tests 26`, `# pass 26`, `# fail 0`

- [ ] **Step 5: Run the full lane suite for regressions**

Run: `cd sdk-js && npm test`

Expected: `# tests 71`, `# pass 71`, `# fail 0`

- [ ] **Step 6: Commit**
```bash
git add sdk-js/src/federation/attestation.js sdk-js/test/federation.test.js
git commit -m "fix(sdk-js): accept an Ed25519 OKP JWK as a native attestation trust root"
```

---

### Task 6: Report the machine-readable attestation status vocabulary

**Files:**
- Modify: `sdk-js/src/federation/attestation.js:24` (status constants), `:137-139` (verifyJwt trust-root signal), `:178` (flag), `:180-182` and `:224-226` (early returns), `:208` (propagate), `:245` (final return)
- Modify: `sdk-js/src/federation/index.js:15-21`
- Test: `sdk-js/test/federation.test.js`

**Interfaces:**
- Consumes: `verifyIdentityAttestation` error accumulation
- Produces: exported constants `ATTESTATION_VERIFIED = "attestation_verified"`, `ATTESTATION_UNVERIFIED = "attestation_unverified"`, `ATTESTATION_REJECTED = "attestation_rejected"`; `verifyIdentityAttestation` returns `{ ok, status, subject, claims, errors }`; `verifyJwt` returns `trustRootMissing: true` when no cached key matches the kid

- [ ] **Step 1: Write the failing test**

Append to `sdk-js/test/federation.test.js`:

```js
test("status distinguishes unverified (unknown) from rejected (negative)", () => {
  const { issuer, kid, ed, trustRoots } = makeIssuer();
  const signer = generateEd25519();
  const att = signIdentityAttestation({
    issuer, kid, ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "originator", subject: {}, issued_at: TS, expires_at: "2027-05-07T12:00:00Z",
    },
  });
  const base = {
    now: new Date(TS), capsuleId: "a".repeat(64),
    signerPublicKeyHex: signer.publicKeyHex, expectedIssuer: issuer,
  };

  // Trust roots present and everything checks out.
  const good = verifyIdentityAttestation(att, { ...base, trustRoots });
  assert.equal(good.ok, true, JSON.stringify(good.errors));
  assert.equal(good.status, "attestation_verified");

  // No trust roots cached: UNKNOWN, not negative (federation.md).
  const unknown = verifyIdentityAttestation(att, { ...base, trustRoots: { keys: [] } });
  assert.equal(unknown.ok, false);
  assert.equal(unknown.status, "attestation_unverified");

  // Trust roots present, binding does not match: STRONG NEGATIVE.
  const rejected = verifyIdentityAttestation(att, {
    ...base, trustRoots, capsuleId: "b".repeat(64),
  });
  assert.equal(rejected.ok, false);
  assert.equal(rejected.status, "attestation_rejected");
});

test("a malformed attestation reports attestation_rejected", () => {
  const res = verifyIdentityAttestation(
    { typ: "something-else" },
    {
      capsuleId: "a".repeat(64), signerPublicKeyHex: "0".repeat(64),
      expectedIssuer: "capsules.acme.example",
    },
  );
  assert.equal(res.ok, false);
  assert.equal(res.status, "attestation_rejected");
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-js && node --test test/federation.test.js`

Expected: FAIL — two tests fail:
```
not ok 27 - status distinguishes unverified (unknown) from rejected (negative)
    Expected values to be strictly equal:
    + undefined
    - 'attestation_verified'
not ok 28 - a malformed attestation reports attestation_rejected
# fail 2
```

- [ ] **Step 3: Add the status constants**

In `sdk-js/src/federation/attestation.js`, replace line 24:

```js
export const ATTESTATION_TYP = "capsule-identity-attestation";
```

with:

```js
export const ATTESTATION_TYP = "capsule-identity-attestation";

// Attestation-layer outcome vocabulary (spec/federation.md "Failure
// reporting"). These are the machine-readable statuses a host policy keys
// off; `attestation_unverified` is "unknown", not "negative".
export const ATTESTATION_VERIFIED = "attestation_verified";
export const ATTESTATION_UNVERIFIED = "attestation_unverified";
export const ATTESTATION_REJECTED = "attestation_rejected";
```

- [ ] **Step 4: Thread the trust-root-missing signal and the status through**

Replace the verifyJwt no-key return (lines 137-139):

```js
  if (!match || !match.jwk) {
    return { ok: false, claims, errors: [`jwt: no trust-root key for kid=${header.kid}`] };
  }
```

with:

```js
  if (!match || !match.jwk) {
    // Not a negative signal: the host simply holds no key for this kid.
    return {
      ok: false,
      claims,
      errors: [`jwt: no trust-root key for kid=${header.kid}`],
      trustRootMissing: true,
    };
  }
```

Replace `const errors = [];` inside `verifyIdentityAttestation` (line 178, the one immediately followed by the `const now = ...` line):

```js
  const errors = [];
  const now = options.now instanceof Date ? options.now.getTime() : options.now ?? Date.now();
```

with:

```js
  const errors = [];
  let trustRootMissing = false;
  const now = options.now instanceof Date ? options.now.getTime() : options.now ?? Date.now();
```

Replace the typ early return (lines 180-182):

```js
  if (!attestation || attestation.typ !== ATTESTATION_TYP) {
    return { ok: false, subject: null, claims: null, errors: ["not a capsule identity attestation"] };
  }
```

with:

```js
  if (!attestation || attestation.typ !== ATTESTATION_TYP) {
    return {
      ok: false,
      status: ATTESTATION_REJECTED,
      subject: null,
      claims: null,
      errors: ["not a capsule identity attestation"],
    };
  }
```

In the ed25519-jcs branch, replace:

```js
    if (!key || !key.public_key_hex) {
      errors.push(`no trust-root key for kid=${attestation.kid}`);
    } else if (typeof attestation.signature !== "string") {
```

with:

```js
    if (!key || !key.public_key_hex) {
      errors.push(`no trust-root key for kid=${attestation.kid}`);
      trustRootMissing = true;
    } else if (typeof attestation.signature !== "string") {
```

In the JWT branch, replace line 208:

```js
    errors.push(...res.errors);
```

with:

```js
    errors.push(...res.errors);
    if (res.trustRootMissing) trustRootMissing = true;
```

Replace the unsupported-alg early return (line 225):

```js
    return { ok: false, subject: null, claims: null, errors: [`unsupported attestation alg ${attestation.alg}`] };
```

with:

```js
    return {
      ok: false,
      status: ATTESTATION_REJECTED,
      subject: null,
      claims: null,
      errors: [`unsupported attestation alg ${attestation.alg}`],
    };
```

Replace the final return (line 245):

```js
  return { ok: errors.length === 0, subject: claims.subject ?? null, claims, errors };
```

with:

```js
  // spec/federation.md "Failure reporting" distinguishes two oppositely
  // signed outcomes: `attestation_unverified` (no trust roots cached — the
  // signer is valid but identity-unverified, NOT a negative signal) from
  // `attestation_rejected` (a strong negative: bad signature, expiry, or
  // binding mismatch). Collapsing both into ok:false loses that sign.
  const ok = errors.length === 0;
  const status = ok
    ? ATTESTATION_VERIFIED
    : trustRootMissing && errors.length === 1
      ? ATTESTATION_UNVERIFIED
      : ATTESTATION_REJECTED;
  return { ok, status, subject: claims.subject ?? null, claims, errors };
```

And update the function's JSDoc first line, replacing:

```js
 * Verify an identity attestation offline and confirm it binds THIS capsule's
 * signer. Returns { ok, subject, claims, errors }.
 *
```

with:

```js
 * Verify an identity attestation offline and confirm it binds THIS capsule's
 * signer. Returns { ok, status, subject, claims, errors }, where status is
 * one of ATTESTATION_VERIFIED / ATTESTATION_UNVERIFIED / ATTESTATION_REJECTED
 * (spec/federation.md "Failure reporting").
 *
```

- [ ] **Step 5: Export the constants**

In `sdk-js/src/federation/index.js`, replace lines 15-17:

```js
export {
  ATTESTATION_TYP,
  ATTESTATION_DOMAIN,
```

with:

```js
export {
  ATTESTATION_TYP,
  ATTESTATION_DOMAIN,
  ATTESTATION_VERIFIED,
  ATTESTATION_UNVERIFIED,
  ATTESTATION_REJECTED,
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd sdk-js && node --test test/federation.test.js`

Expected: PASS — `# tests 28`, `# pass 28`, `# fail 0`

- [ ] **Step 7: Run the full lane suite for regressions**

Run: `cd sdk-js && npm test`

Expected: `# tests 73`, `# pass 73`, `# fail 0`

- [ ] **Step 8: Commit**
```bash
git add sdk-js/src/federation/attestation.js sdk-js/src/federation/index.js sdk-js/test/federation.test.js
git commit -m "feat(sdk-js): report attestation_verified/unverified/rejected on every attestation result"
```

---

### Task 7: Re-check the capsule binding at the policy layer

**Files:**
- Modify: `sdk-js/src/federation/policy.js:9-30` (signature + guard), `:39-42` (attestation map), `:73` (return)
- Modify: `sdk-js/test/federation.test.js:242-256` (existing policy test)
- Test: `sdk-js/test/federation.test.js`

**Interfaces:**
- Consumes: `verifyResult.envelope.signers[]`, attested-signer claims
- Produces: `evaluateSignerPolicy(verifyResult, attestedSigners, policy, options)` — fourth argument with a required `capsuleId`; entries in `attestedSigners` must carry `capsule_id`; `satisfied` is now `unmet.length === 0 && errors.length === 0`

- [ ] **Step 1: Write the failing test**

First update the existing policy test (`sdk-js/test/federation.test.js:242-256`). Replace:

```js
  const attested = [
    { signer_public_key: admin, signer_role: "originator", subject: { org_role: "admin" } },
    { signer_public_key: reviewer, signer_role: "reviewer", subject: { org_role: "member" } },
  ];
  const ok = evaluateSignerPolicy(verifyResult, attested, {
    required: [
      { role: "originator", org_role: "admin" },
      { role: "reviewer", quorum: 1 },
    ],
  });
  assert.equal(ok.satisfied, true, JSON.stringify(ok.errors));

  const unmet = evaluateSignerPolicy(verifyResult, attested, {
    required: [{ role: "reviewer", quorum: 2 }],
  });
```

with:

```js
  const capsuleId = "a".repeat(64);
  const attested = [
    { capsule_id: capsuleId, signer_public_key: admin, signer_role: "originator", subject: { org_role: "admin" } },
    { capsule_id: capsuleId, signer_public_key: reviewer, signer_role: "reviewer", subject: { org_role: "member" } },
  ];
  const ok = evaluateSignerPolicy(
    verifyResult,
    attested,
    {
      required: [
        { role: "originator", org_role: "admin" },
        { role: "reviewer", quorum: 1 },
      ],
    },
    { capsuleId },
  );
  assert.equal(ok.satisfied, true, JSON.stringify(ok.errors));

  const unmet = evaluateSignerPolicy(
    verifyResult,
    attested,
    { required: [{ role: "reviewer", quorum: 2 }] },
    { capsuleId },
  );
```

Then append:

```js
test("evaluateSignerPolicy rejects an attestation bound to another capsule", () => {
  const admin = "1".repeat(64);
  const capsuleId = "a".repeat(64);
  const verifyResult = {
    envelope: { signers: [{ public_key: admin, valid: true, trusted: true }] },
  };
  // A validly-signed attestation for a DIFFERENT capsule, replayed here.
  const replayed = [
    { capsule_id: "b".repeat(64), signer_public_key: admin, signer_role: "originator", subject: { org_role: "admin" } },
  ];
  const res = evaluateSignerPolicy(
    verifyResult,
    replayed,
    { required: [{ role: "originator", org_role: "admin" }] },
    { capsuleId },
  );
  assert.equal(res.satisfied, false, "a cross-capsule attestation must not satisfy policy");
  assert.ok(res.errors.some((e) => e.includes("is bound to capsule_id")));
  assert.equal(res.matched.length, 0);
});

test("evaluateSignerPolicy refuses to run without a capsule id", () => {
  const verifyResult = { envelope: { signers: [] } };
  assert.throws(
    () => evaluateSignerPolicy(verifyResult, [], { required: [] }),
    /requires options\.capsuleId/,
  );
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-js && node --test test/federation.test.js`

Expected: FAIL — the replay is accepted and the guard is missing:
```
not ok 29 - evaluateSignerPolicy rejects an attestation bound to another capsule
    a cross-capsule attestation must not satisfy policy
    true !== false
not ok 30 - evaluateSignerPolicy refuses to run without a capsule id
    error: 'Missing expected exception.'
# fail 2
```

- [ ] **Step 3: Take a required capsuleId**

In `sdk-js/src/federation/policy.js`, replace lines 10-30:

```js
 * evaluateSignerPolicy(verifyResult, attestedSigners, policy)
 *
 * verifyResult    the object returned by verifyCapsule()
 * attestedSigners [{ signer_public_key, signer_role, subject }] — the claims
 *                 of attestations already verified with
 *                 verifyIdentityAttestation() (ok === true only)
 * policy          {
 *                   issuer,                       // informational
 *                   required: [
 *                     { role, org_role?, quorum = 1 }
 *                   ]
 *                 }
 *
 * Returns { satisfied, matched: [...], unmet: [...], errors: [...] }.
 *
 * A signer counts toward a requirement only if its key is both a trusted
 * signer in verifyResult (valid signature + on the allowlist) AND covered by
 * an attestation matching the required role (and org_role, when specified).
 */
export function evaluateSignerPolicy(verifyResult, attestedSigners, policy) {
  const errors = [];
```

with:

```js
 * evaluateSignerPolicy(verifyResult, attestedSigners, policy, options)
 *
 * verifyResult    the object returned by verifyCapsule()
 * attestedSigners [{ capsule_id, signer_public_key, signer_role, subject }] —
 *                 the claims of attestations already verified with
 *                 verifyIdentityAttestation() (ok === true only)
 * policy          {
 *                   issuer,                       // informational
 *                   required: [
 *                     { role, org_role?, quorum = 1 }
 *                   ]
 *                 }
 * options         { capsuleId }  REQUIRED — the capsule these attestations
 *                 must be bound to. Matching a signer by public key alone
 *                 makes a cross-capsule replay invisible at this layer.
 *
 * Returns { satisfied, matched: [...], unmet: [...], errors: [...] }.
 *
 * A signer counts toward a requirement only if its key is a trusted signer in
 * verifyResult (valid signature + on the allowlist) AND covered by an
 * attestation bound to THIS capsule_id matching the required role (and
 * org_role, when specified).
 */
export function evaluateSignerPolicy(verifyResult, attestedSigners, policy, options = {}) {
  if (typeof options.capsuleId !== "string" || options.capsuleId.length === 0) {
    throw new TypeError(
      "evaluateSignerPolicy requires options.capsuleId: an attestation counts only for the capsule it was bound to (spec/federation.md)",
    );
  }
  const errors = [];
```

- [ ] **Step 4: Drop attestations bound elsewhere, and fail the policy on them**

Replace lines 39-42:

```js
  const attestByKey = new Map();
  for (const a of attestedSigners ?? []) {
    if (a?.signer_public_key) attestByKey.set(a.signer_public_key.toLowerCase(), a);
  }
```

with:

```js
  const attestByKey = new Map();
  for (const a of attestedSigners ?? []) {
    if (!a?.signer_public_key) continue;
    const key = a.signer_public_key.toLowerCase();
    // Cross-capsule replay: an attestation whose binding names a different
    // capsule proves nothing here, however valid its signature.
    if (a.capsule_id !== options.capsuleId) {
      errors.push(
        `policy: attestation for signer ${key} is bound to capsule_id ` +
          `${a.capsule_id ?? "(none)"}, not ${options.capsuleId}`,
      );
      continue;
    }
    attestByKey.set(key, a);
  }
```

And replace line 73:

```js
  return { satisfied: unmet.length === 0, matched, unmet, errors };
```

with:

```js
  // An attestation bound to another capsule is a strong negative signal
  // (spec/federation.md "Failure reporting": attestation_rejected), so it
  // fails the policy even when the remaining signers satisfy every
  // requirement.
  return { satisfied: unmet.length === 0 && errors.length === 0, matched, unmet, errors };
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd sdk-js && node --test test/federation.test.js`

Expected: PASS — `# tests 30`, `# pass 30`, `# fail 0`

- [ ] **Step 6: Run the full lane suite for regressions**

Run: `cd sdk-js && npm test`

Expected: `# tests 75`, `# pass 75`, `# fail 0`

- [ ] **Step 7: Commit**
```bash
git add sdk-js/src/federation/policy.js sdk-js/test/federation.test.js
git commit -m "fix(sdk-js): re-check capsule binding when evaluating signer policy"
```

---

### Task 8: Bind issuer identity and JWKS location to the fetch origin

**Files:**
- Modify: `sdk-js/src/federation/discovery.js:9-11` (import), `:17-25` (fetchIssuerMetadata), `:32-41` (loadTrustRoots)
- Modify: `sdk-js/test/federation.test.js:14-21` (destructure discovery exports)
- Test: `sdk-js/test/federation.test.js`

**Interfaces:**
- Consumes: `normalizeIssuer(value)` from `./issuer.js` (Task 2)
- Produces: `fetchIssuerMetadata` throws when `meta.issuer` does not resolve to the fetch origin; `loadTrustRoots` throws when `trust_roots.jwks_uri` is not on the issuer origin

- [ ] **Step 1: Write the failing test**

First make the discovery helpers available. Replace `sdk-js/test/federation.test.js:18-21`:

```js
  resolveRecipientKeys,
  clerkRecipientDirectory,
  evaluateSignerPolicy,
} = federation;
```

with:

```js
  resolveRecipientKeys,
  clerkRecipientDirectory,
  evaluateSignerPolicy,
  fetchIssuerMetadata,
  loadTrustRoots,
} = federation;
```

Then append:

```js
// --------------------------------------------------------------------------
// Issuer discovery: identity is bound to the origin it was fetched from
// --------------------------------------------------------------------------

function fakeFetch(routes) {
  return async (url) => {
    if (!(url in routes)) return { ok: false, async json() { return {}; } };
    return { ok: true, async json() { return routes[url]; } };
  };
}

test("issuer metadata whose 'issuer' does not match the fetch origin is refused", async () => {
  const fetchLike = fakeFetch({
    "https://evil.example/.well-known/capsule-issuer.json": {
      issuer: "https://capsules.acme.example",
      spec_version: "0.6",
      profiles: ["ed25519-jcs"],
      trust_roots: { jwks: { keys: [] } },
    },
  });
  await assert.rejects(
    () => fetchIssuerMetadata(fetchLike, "https://evil.example"),
    /does not match the origin it was fetched from/,
  );
});

test("issuer metadata is accepted when 'issuer' matches the fetch origin", async () => {
  const doc = {
    issuer: "https://capsules.acme.example/",
    spec_version: "0.6",
    profiles: ["ed25519-jcs"],
    trust_roots: { jwks: { keys: [] } },
  };
  const fetchLike = fakeFetch({
    "https://capsules.acme.example/.well-known/capsule-issuer.json": doc,
  });
  const meta = await fetchIssuerMetadata(fetchLike, "https://capsules.acme.example");
  assert.equal(meta.issuer, "https://capsules.acme.example/");
});

test("loadTrustRoots refuses a jwks_uri off the issuer origin", async () => {
  const meta = {
    issuer: "https://capsules.acme.example",
    profiles: ["ed25519-jcs"],
    trust_roots: { jwks_uri: "https://evil.example/jwks.json" },
  };
  const fetchLike = fakeFetch({
    "https://evil.example/jwks.json": { keys: [{ kid: "k", alg: "ed25519-jcs", public_key_hex: "0".repeat(64) }] },
  });
  await assert.rejects(
    () => loadTrustRoots(meta, fetchLike),
    /is not on the issuer origin/,
  );
});

test("loadTrustRoots fetches a jwks_uri on the issuer origin", async () => {
  const jwks = { keys: [{ kid: "k", alg: "ed25519-jcs", public_key_hex: "0".repeat(64) }] };
  const meta = {
    issuer: "capsules.acme.example",
    profiles: ["ed25519-jcs"],
    trust_roots: { jwks_uri: "https://capsules.acme.example/.well-known/jwks.json" },
  };
  const fetchLike = fakeFetch({ "https://capsules.acme.example/.well-known/jwks.json": jwks });
  assert.deepEqual(await loadTrustRoots(meta, fetchLike), jwks);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sdk-js && node --test test/federation.test.js`

Expected: FAIL — two tests fail:
```
not ok 31 - issuer metadata whose 'issuer' does not match the fetch origin is refused
    error: 'Missing expected rejection.'
not ok 33 - loadTrustRoots refuses a jwks_uri off the issuer origin
    error: 'Missing expected rejection.'
# fail 2
```

- [ ] **Step 3: Bind the metadata document's issuer to the fetch origin**

In `sdk-js/src/federation/discovery.js`, add the import after line 10:

```js
// Every network dependency is injected (a `fetchLike` or a directory object),
// so the reference implementation and its tests run fully offline.

import { normalizeIssuer } from "./issuer.js";
```

Replace lines 17-25:

```js
export async function fetchIssuerMetadata(fetchLike, issuerBaseUrl) {
  const url = new URL("/.well-known/capsule-issuer.json", issuerBaseUrl).toString();
  const res = await fetchLike(url);
  if (!res || !res.ok) throw new Error(`issuer metadata fetch failed: ${issuerBaseUrl}`);
  const meta = await res.json();
  if (!meta.issuer) throw new Error("issuer metadata missing 'issuer'");
  if (!Array.isArray(meta.profiles)) throw new Error("issuer metadata missing 'profiles'");
  return meta;
}
```

with:

```js
export async function fetchIssuerMetadata(fetchLike, issuerBaseUrl) {
  const expected = normalizeIssuer(issuerBaseUrl);
  if (!expected) throw new Error(`not a usable issuer base URL: ${issuerBaseUrl}`);
  const url = new URL("/.well-known/capsule-issuer.json", issuerBaseUrl).toString();
  const res = await fetchLike(url);
  if (!res || !res.ok) throw new Error(`issuer metadata fetch failed: ${issuerBaseUrl}`);
  const meta = await res.json();
  if (!meta.issuer) throw new Error("issuer metadata missing 'issuer'");
  if (!Array.isArray(meta.profiles)) throw new Error("issuer metadata missing 'profiles'");
  // spec/federation.md: `issuer` MUST equal the domain the document was
  // fetched from; a mismatch is a hard discovery failure
  // (`issuer_document_invalid`). Without this, a document served anywhere
  // can name any issuer and the fetch origin means nothing.
  if (normalizeIssuer(meta.issuer) !== expected) {
    throw new Error(
      `issuer metadata 'issuer' (${meta.issuer}) does not match the origin it was fetched from (${expected})`,
    );
  }
  return meta;
}
```

- [ ] **Step 4: Keep the JWKS on the issuer origin**

Replace lines 32-41:

```js
export async function loadTrustRoots(metadata, fetchLike) {
  const tr = metadata.trust_roots ?? {};
  if (tr.jwks) return tr.jwks;
  if (tr.jwks_uri) {
    const res = await fetchLike(tr.jwks_uri);
    if (!res || !res.ok) throw new Error(`jwks fetch failed: ${tr.jwks_uri}`);
    return await res.json();
  }
  throw new Error("issuer metadata has no trust_roots.jwks or jwks_uri");
}
```

with:

```js
export async function loadTrustRoots(metadata, fetchLike) {
  const tr = metadata?.trust_roots ?? {};
  if (tr.jwks) return tr.jwks;
  if (tr.jwks_uri) {
    // Trust roots are the keys everything else is checked against. Fetching
    // them from an origin the issuer does not control would let a redirected
    // or attacker-authored metadata document swap the entire trust anchor.
    const issuer = normalizeIssuer(metadata?.issuer);
    if (!issuer || normalizeIssuer(tr.jwks_uri) !== issuer) {
      throw new Error(
        `trust_roots.jwks_uri (${tr.jwks_uri}) is not on the issuer origin (${metadata?.issuer})`,
      );
    }
    const res = await fetchLike(tr.jwks_uri);
    if (!res || !res.ok) throw new Error(`jwks fetch failed: ${tr.jwks_uri}`);
    return await res.json();
  }
  throw new Error("issuer metadata has no trust_roots.jwks or jwks_uri");
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd sdk-js && node --test test/federation.test.js`

Expected: PASS — `# tests 34`, `# pass 34`, `# fail 0`

- [ ] **Step 6: Run the full lane suite for regressions**

Run: `cd sdk-js && npm test`

Expected: `# tests 79`, `# pass 79`, `# fail 0`

- [ ] **Step 7: Commit**
```bash
git add sdk-js/src/federation/discovery.js sdk-js/test/federation.test.js
git commit -m "fix(sdk-js): bind issuer identity and jwks_uri to the fetch origin"
```

---

### Task 9: Pin the attestation outcomes as a conformance vector set

**Files:**
- Create: `sdk-js/tools/generate-attestation-vectors.mjs`
- Create: `spec/vectors/identity-attestation/vectors.json` (generated)
- Modify: `tools/check-spec-vectors.mjs:1-28` (header), `:34` (import), `:389-391` (recognizer), `:398-408` (dispatch)
- Modify: `spec/vectors/README.md:3-5`, `:45-51`, `:60-64`
- Modify: `tools/run-conformance.mjs:93` (new target before `spec-vectors`)
- Test: `spec/vectors/identity-attestation/vectors.json` (registry, run by `tools/check-spec-vectors.mjs`)

**Interfaces:**
- Consumes: `signIdentityAttestation`, `ed25519PrivateFromRaw`, `ed25519PublicToRaw`, `bytesToHex`, `hexToBytes`, `verifyIdentityAttestation`
- Produces: vector shape `meta.kind === "identity-attestation"` with top-level `trust_roots`/`context` and per-vector overrides; `node sdk-js/tools/generate-attestation-vectors.mjs [--check]`

- [ ] **Step 1: Write the deterministic generator**

Create `sdk-js/tools/generate-attestation-vectors.mjs`:

```js
#!/usr/bin/env node
// generate-attestation-vectors.mjs
//
// Deterministically regenerates the identity-attestation outcome registry at
// spec/vectors/identity-attestation/vectors.json.
//
// The registry pins the ATTESTATION-LAYER outcome vocabulary of
// spec/federation.md ("Failure reporting"): `attestation_verified`,
// `attestation_unverified` (unknown — no trust roots cached), and
// `attestation_rejected` (strong negative — signature, expiry, or binding
// failure). Independent implementations SHOULD reproduce ok + status.
//
// Only the native `ed25519-jcs` profile appears here: Ed25519 signatures are
// deterministic, so the file regenerates byte-identically. ECDSA (the JWT
// profile) is randomized and cannot be pinned this way.
//
// The TEST issuer seed below is an intentional throwaway conformance
// fixture — never a production key.
//
// Pass --check to compare generated JSON with the checked-in file.

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { createPublicKey } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { signIdentityAttestation } from "../src/federation/attestation.js";
import { ed25519PrivateFromRaw, ed25519PublicToRaw } from "../src/crypto.js";
import { bytesToHex, hexToBytes } from "../src/canonical.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..");
const OUT_DIR = join(REPO_ROOT, "spec", "vectors", "identity-attestation");
const OUT_PATH = join(OUT_DIR, "vectors.json");
const CHECK = process.argv.includes("--check");

// Fixed test material — deterministic, throwaway.
const ISSUER_SEED_HEX = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";
const OTHER_SEED_HEX = "2f2e2d2c2b2a292827262524232221201f1e1d1c1b1a19181716151413121110";
const SIGNER_PUBLIC_KEY = "aa".repeat(32);
const CAPSULE_ID = "bb".repeat(32);
const OTHER_CAPSULE_ID = "cc".repeat(32);
const ISSUER = "https://capsules.example";
const KID = "issuer-key-1";
const NOW = "2026-05-07T12:00:00Z";

function publicKeyHexFromSeed(seedHex) {
  const priv = ed25519PrivateFromRaw(hexToBytes(seedHex));
  return bytesToHex(ed25519PublicToRaw(createPublicKey(priv)));
}

function attest(claims, { seedHex = ISSUER_SEED_HEX, issuer = ISSUER, kid = KID } = {}) {
  return signIdentityAttestation({
    issuer,
    kid,
    ed25519PrivateKeyHex: seedHex,
    claims: {
      signer_public_key: SIGNER_PUBLIC_KEY,
      signer_role: "originator",
      subject: { clerk_user_id: "user_1", org_role: "admin" },
      issued_at: NOW,
      expires_at: "2027-05-07T12:00:00Z",
      ...claims,
    },
  });
}

async function main() {
  const issuerPublicKeyHex = publicKeyHexFromSeed(ISSUER_SEED_HEX);
  const otherPublicKeyHex = publicKeyHexFromSeed(OTHER_SEED_HEX);

  const tampered = attest({ capsule_id: CAPSULE_ID });
  tampered.claims.subject.org_role = "superadmin";

  const doc = {
    meta: {
      kind: "identity-attestation",
      name: "identity-attestation",
      spec_version: "0.6",
      description:
        "Language-neutral attestation-layer outcomes for the native ed25519-jcs profile. " +
        "Implementations SHOULD reproduce ok and status; status is the vocabulary of " +
        "spec/federation.md 'Failure reporting'.",
      generator: "sdk-js/tools/generate-attestation-vectors.mjs",
      no_warranty: "Conformance fixtures only; not production templates or advice.",
    },
    trust_roots: {
      keys: [{ kid: KID, alg: "ed25519-jcs", public_key_hex: issuerPublicKeyHex }],
    },
    context: {
      capsule_id: CAPSULE_ID,
      signer_public_key: SIGNER_PUBLIC_KEY,
      expected_issuer: ISSUER,
      now: NOW,
    },
    vectors: [
      {
        name: "valid",
        attestation: attest({ capsule_id: CAPSULE_ID }),
        expected: { ok: true, status: "attestation_verified" },
      },
      {
        name: "valid-okp-jwk-trust-root",
        note: "The same attestation, with the issuer's trust root published as an RFC 8037 Ed25519 OKP JWK.",
        trust_roots: {
          keys: [
            {
              kty: "OKP",
              crv: "Ed25519",
              alg: "EdDSA",
              use: "sig",
              kid: KID,
              x: Buffer.from(issuerPublicKeyHex, "hex").toString("base64url"),
            },
          ],
        },
        attestation: attest({ capsule_id: CAPSULE_ID }),
        expected: { ok: true, status: "attestation_verified" },
      },
      {
        name: "no-binding-claims",
        note: "Binding claims are mandatory; an attestation without them binds nothing.",
        attestation: (() => {
          const a = attest({ capsule_id: CAPSULE_ID });
          delete a.claims.capsule_id;
          delete a.claims.signer_public_key;
          return a;
        })(),
        expected: {
          ok: false,
          status: "attestation_rejected",
          error_includes: "missing required binding claim 'capsule_id'",
        },
      },
      {
        name: "capsule-id-replay",
        note: "Validly signed, but bound to a different capsule.",
        attestation: attest({ capsule_id: OTHER_CAPSULE_ID }),
        expected: {
          ok: false,
          status: "attestation_rejected",
          error_includes: "capsule_id binding mismatch",
        },
      },
      {
        name: "signer-key-mismatch",
        attestation: attest({ capsule_id: CAPSULE_ID, signer_public_key: "dd".repeat(32) }),
        expected: {
          ok: false,
          status: "attestation_rejected",
          error_includes: "signer_public_key binding mismatch",
        },
      },
      {
        name: "expired",
        attestation: attest({ capsule_id: CAPSULE_ID, expires_at: "2026-05-06T12:00:00Z" }),
        expected: { ok: false, status: "attestation_rejected", error_includes: "attestation expired" },
      },
      {
        name: "expires-at-unparseable",
        note: "NaN must never read as 'never expires'.",
        attestation: attest({ capsule_id: CAPSULE_ID, expires_at: "whenever" }),
        expected: {
          ok: false,
          status: "attestation_rejected",
          error_includes: "expires_at is not an RFC 3339 instant",
        },
      },
      {
        name: "tampered-claims",
        note: "A subject claim edited after signing.",
        attestation: tampered,
        expected: {
          ok: false,
          status: "attestation_rejected",
          error_includes: "attestation signature invalid",
        },
      },
      {
        name: "issuer-mismatch",
        note: "Signed by a key the host holds, but issued under another issuer identity.",
        attestation: attest({ capsule_id: CAPSULE_ID }, { issuer: "https://other.example" }),
        expected: {
          ok: false,
          status: "attestation_rejected",
          error_includes: "attestation issuer mismatch",
        },
      },
      {
        name: "unknown-kid",
        note: "kid selects the key; an unknown kid resolves to no key rather than falling back.",
        trust_roots: {
          keys: [
            { kid: "issuer-key-1", alg: "ed25519-jcs", public_key_hex: issuerPublicKeyHex },
            { kid: "issuer-key-2", alg: "ed25519-jcs", public_key_hex: otherPublicKeyHex },
          ],
        },
        attestation: attest({ capsule_id: CAPSULE_ID }, { kid: "issuer-key-retired" }),
        expected: {
          ok: false,
          status: "attestation_unverified",
          error_includes: "no trust-root key for kid=issuer-key-retired",
        },
      },
      {
        name: "no-trust-roots",
        note: "Unknown, NOT negative: the host caches no key for this issuer.",
        trust_roots: { keys: [] },
        attestation: attest({ capsule_id: CAPSULE_ID }),
        expected: {
          ok: false,
          status: "attestation_unverified",
          error_includes: "no trust-root key",
        },
      },
    ],
  };

  const json = `${JSON.stringify(doc, null, 2)}\n`;
  if (CHECK) {
    let checkedIn;
    try {
      checkedIn = await readFile(OUT_PATH, "utf8");
    } catch (err) {
      throw new Error(`identity-attestation vectors missing or unreadable: ${err.message}`);
    }
    if (checkedIn !== json) {
      throw new Error("identity-attestation vectors differ from deterministic generator output");
    }
    console.log(`ok identity-attestation/vectors.json (${doc.vectors.length} vectors)`);
  } else {
    await mkdir(OUT_DIR, { recursive: true });
    await writeFile(OUT_PATH, json);
    console.log(`wrote identity-attestation/vectors.json (${doc.vectors.length} vectors)`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
```

- [ ] **Step 2: Generate the vector file**

Run: `node sdk-js/tools/generate-attestation-vectors.mjs`

Expected: `wrote identity-attestation/vectors.json (11 vectors)` — a 357-line `spec/vectors/identity-attestation/vectors.json` whose first vector is exactly:

```json
    {
      "name": "valid",
      "attestation": {
        "typ": "capsule-identity-attestation",
        "spec_version": "0.6",
        "alg": "ed25519-jcs",
        "issuer": "https://capsules.example",
        "kid": "issuer-key-1",
        "claims": {
          "signer_public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "signer_role": "originator",
          "subject": {
            "clerk_user_id": "user_1",
            "org_role": "admin"
          },
          "issued_at": "2026-05-07T12:00:00Z",
          "expires_at": "2027-05-07T12:00:00Z",
          "capsule_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        },
        "signature": "7a54edefdc3d9141b19e21b86031c7f8baab534e133d0240c2d53cb7a80e5362e282b992a63174c51fad9bbbbebea937b91c589a571de990ea1140f5f00c0c03"
      },
      "expected": {
        "ok": true,
        "status": "attestation_verified"
      }
    },
```

with the issuer trust root pinned as `"public_key_hex": "712651f450ba05b63898b99ef5f7ba45632e8e2527f7f715cd671ec4024cc51e"` (and its OKP form `"x": "cSZR9FC6BbY4mLme9fe6RWMujiUn9_cVzWcexAJMxR4"`).

- [ ] **Step 3: Run the registry checker to verify it fails**

Run: `node tools/check-spec-vectors.mjs`

Expected: FAIL (exit 1) — the checker's `isCollection` predicate claims the doc and cannot find capsule files:
```
FAIL: /…/spec/vectors/identity-attestation/vectors.json [valid]: vector requires capsule_file and expected
FAIL: /…/spec/vectors/identity-attestation/vectors.json [valid-okp-jwk-trust-root]: vector requires capsule_file and expected
… (11 lines, one per vector)
```

- [ ] **Step 4: Teach the checker the new shape**

In `tools/check-spec-vectors.mjs`, add the import after line 34:

```js
import { CapsuleReader, verifyCapsule } from "../sdk-js/src/index.js";
import { verifyIdentityAttestation } from "../sdk-js/src/federation/attestation.js";
```

Then, immediately after `isSigningInputVector` (line 391), add:

```js
function isAttestationVectorSet(doc) {
  return doc && typeof doc === "object" && doc.meta?.kind === "identity-attestation";
}

// Attestation-layer outcome registry (spec/federation.md "Failure
// reporting"). Each vector carries a complete attestation document plus the
// verification context it must be checked against; `expected.status` pins the
// machine-readable outcome, which is what separates "unknown" from "negative".
function checkAttestationVectors(path, doc) {
  if (!Array.isArray(doc.vectors) || doc.vectors.length === 0) {
    fail(`${path}: vectors must be a non-empty array`);
    return;
  }
  for (const v of doc.vectors) {
    checked++;
    const label = `${path} [${v.name}]`;
    if (!v.attestation || !v.expected) {
      fail(`${label}: vector requires attestation and expected`);
      continue;
    }
    const ctx = { ...(doc.context ?? {}), ...(v.context ?? {}) };
    const trustRoots = v.trust_roots ?? doc.trust_roots;
    let result;
    try {
      result = verifyIdentityAttestation(v.attestation, {
        trustRoots,
        now: new Date(ctx.now),
        capsuleId: ctx.capsule_id,
        signerPublicKeyHex: ctx.signer_public_key,
        expectedIssuer: ctx.expected_issuer,
        audience: ctx.audience,
      });
    } catch (err) {
      fail(`${label}: verification threw: ${err.message}`);
      continue;
    }
    if (typeof v.expected.ok === "boolean" && result.ok !== v.expected.ok) {
      fail(`${label}: expected ok=${v.expected.ok}, got ok=${result.ok} (${result.errors.join("; ")})`);
    }
    if (v.expected.status && result.status !== v.expected.status) {
      fail(`${label}: expected status '${v.expected.status}', got '${result.status}'`);
    }
    if (v.expected.error_includes && !result.errors.join(" ").includes(v.expected.error_includes)) {
      fail(`${label}: expected an error containing '${v.expected.error_includes}', got ${result.errors.join("; ")}`);
    }
  }
}
```

Replace the dispatch in `checkFile`:

```js
  if (isNumberVectorSet(path, doc)) checkNumberVectors(path, doc);
  else if (isSigningInputVector(doc)) await checkSigningInput(path, doc);
  else if (isCollection(doc)) await checkCollection(path, doc);
```

with:

```js
  if (isNumberVectorSet(path, doc)) checkNumberVectors(path, doc);
  else if (isSigningInputVector(doc)) await checkSigningInput(path, doc);
  else if (isAttestationVectorSet(doc)) checkAttestationVectors(path, doc);
  else if (isCollection(doc)) await checkCollection(path, doc);
```

Replace the fail-closed message:

```js
      `${path}: unrecognized vector document (expected capsule_bytes_b64 + expected, ` +
        `an outcome-vector collection, a signing-input doc, or a jcs number set)`
```

with:

```js
      `${path}: unrecognized vector document (expected capsule_bytes_b64 + expected, ` +
        `an outcome-vector collection, a signing-input doc, an identity-attestation ` +
        `set, or a jcs number set)`
```

And in the file header comment, insert before the `3. A JCS number-serialization vector set` bullet (renumbering it to 4):

```js
//   3. An identity-attestation outcome set (meta.kind ===
//      "identity-attestation"): inline attestation documents plus the
//      verification context they must be checked against, with an expected
//      `{ ok, status, error_includes? }`. `status` is the attestation-layer
//      vocabulary of spec/federation.md "Failure reporting".
//
//   4. A JCS number-serialization vector set (jcs-numbers.json): a `vectors`
```

- [ ] **Step 5: Run the registry checker to verify it passes**

Run: `node tools/check-spec-vectors.mjs`

Expected: PASS — `spec vectors: ok (291 vectors)` (280 before, +11)

- [ ] **Step 6: Wire the drift check into the conformance harness**

In `tools/run-conformance.mjs`, insert a target immediately before the `spec-vectors` entry (line 93):

```js
  {
    id: "attestation-vectors-regen",
    name: "identity-attestation vector regeneration check",
    language: "javascript",
    kind: "check",
    cwd: ".",
    install_cmd: "true",
    test_cmd: "node sdk-js/tools/generate-attestation-vectors.mjs --check",
    pass_signal: { type: "exit_code", value: 0 },
  },
  {
    id: "spec-vectors",
    name: "spec/vectors registry",
```

- [ ] **Step 7: Document the new shape**

In `spec/vectors/README.md`, change `Four shapes exist` to `Five shapes exist` in the opening paragraph, insert a new item 4 before the JCS number-serialization set (renumbering it to 5):

```markdown
4. **Identity-attestation outcome set**
   (`identity-attestation/vectors.json`, detected by
   `meta.kind: "identity-attestation"`) — inline attestation documents for
   the native `ed25519-jcs` profile, the trust-root set and verification
   context each is checked against (`capsule_id`, `signer_public_key`,
   `expected_issuer`, `now`; per-vector `trust_roots`/`context` override the
   top-level ones), and an expected `{ ok, status, error_includes? }`.
   `status` is the attestation-layer vocabulary of `spec/federation.md`
   *Failure reporting*: `attestation_verified`, `attestation_unverified`
   (unknown — no trust roots cached), `attestation_rejected` (strong
   negative). Only the native profile is pinned: Ed25519 signatures are
   deterministic, ECDSA (the JWT profile) is not.

5. **JCS number-serialization set** (`jcs-numbers.json`): a `vectors` array
```

and add a generator line at the end of the generators list:

```markdown
- `sdk-js/tools/generate-attestation-vectors.mjs` →
  `identity-attestation/vectors.json`
```

- [ ] **Step 8: Verify the drift check**

Run: `node sdk-js/tools/generate-attestation-vectors.mjs --check`

Expected: PASS — `ok identity-attestation/vectors.json (11 vectors)`

- [ ] **Step 9: Run the full lane suite for regressions**

Run: `cd sdk-js && npm test && cd .. && node tools/check-spec-vectors.mjs`

Expected: `# tests 79`, `# pass 79`, `# fail 0`, then `spec vectors: ok (291 vectors)`

- [ ] **Step 10: Commit**
```bash
git add sdk-js/tools/generate-attestation-vectors.mjs spec/vectors/identity-attestation/vectors.json tools/check-spec-vectors.mjs tools/run-conformance.mjs spec/vectors/README.md
git commit -m "test(spec): pin identity-attestation outcomes as a language-neutral vector set"
```

---

### Task 10: Make the federation spec say what the code now enforces

**Files:**
- Modify: `spec/federation.md:142-143` (issuer document origin rules), `:243-248` (identity attestation), `:355-357` (policy item 4), `:385-387` (failure reporting)
- Modify: `spec/profiles/clerk.md:33-48` (JWT example), `:54-63` (verification), `:94-104` (policy), `:108-111` (security notes)
- Modify: `CHANGELOG.md:52` (Unreleased → Changed)
- Test: `/tmp/check-federation-normative.sh` (doc-drift assertion, run from the repo root; not checked in)

**Interfaces:**
- Consumes: nothing
- Produces: nothing (documentation)

- [ ] **Step 1: Write the failing check**

Write `/tmp/check-federation-normative.sh` (outside the repo):

```bash
#!/bin/sh
# Doc-drift assertion: the normative sentences the C11 code now enforces must
# exist in the spec. Run from the repo root. Exits 1 on the first miss.
set -e
grep -q "Binding claims present" spec/federation.md
grep -q "Key selection is closed" spec/federation.md
grep -q "MUST be on that same origin" spec/federation.md
grep -q "MUST stay distinguishable" spec/federation.md
grep -q '"aud":' spec/profiles/clerk.md
grep -q "an unknown \`kid\` resolves to no key" spec/profiles/clerk.md
grep -q "identity-attestation" spec/vectors/README.md
echo "federation spec text: ok"
```

- [ ] **Step 2: Run the check to verify it fails**

Run: `sh /tmp/check-federation-normative.sh`

Expected: FAIL — exit code 1, no output (the first `grep -q "Binding claims present"` misses)

- [ ] **Step 3: Tighten the identity-attestation section**

In `spec/federation.md`, replace lines 243-248:

```markdown
An attestation is a signed statement binding **one capsule** and **one
signer key** to an external subject. Its binding claims MUST include
`capsule_id`, `signer_public_key`, and `signer_role`; verifiers MUST
reject an attestation whose `capsule_id`/`signer_public_key` do not
match the capsule and signer being checked, and MUST reject an expired
attestation.
```

with:

```markdown
An attestation is a signed statement binding **one capsule** and **one
signer key** to an external subject. Its binding claims MUST include
`capsule_id`, `signer_public_key`, and `signer_role`.

A verifier checking an attestation MUST be supplied the capsule id, the
signer key, and the expected issuer out-of-band: they are host trust
configuration and are never read from the artifact being checked. The
verifier MUST reject the attestation unless **all** of the following
hold.

1. **Binding claims present.** `capsule_id`, `signer_public_key`, and
   `signer_role` are each present and non-empty. An attestation missing
   any of them binds nothing, however valid its signature — a raw
   provider session token is exactly this case.
2. **Binding matches.** `capsule_id` and `signer_public_key` equal the
   capsule and signer being checked (`signer_public_key` compared as
   case-insensitive hex).
3. **Issuer matches.** The attestation's issuer equals the caller's
   expected issuer after the normalization in *Vocabulary*. For the JWT
   profile the token's `iss` is checked against that same
   caller-supplied value — never against a field of the attestation
   wrapper, which whoever produced the wrapper also controls — and the
   token's `aud` MUST match the verifying host's expected audience.
4. **Key selection is closed.** `kid` selects the trust-root key. An
   unknown or ambiguous `kid` resolves to *no* key; a verifier MUST NOT
   fall back to trying the other keys in a cached set. A `kid`-less
   attestation resolves only when the set holds exactly one key of the
   requested algorithm.
5. **Time is parseable and current.** `expires_at` MUST be present, MUST
   be an RFC 3339 instant, and MUST be in the future. An unparseable
   timestamp is a rejection, never an absent constraint.

For the `ed25519-jcs` profile a verifier MUST accept an issuer trust
root published as an RFC 8037 Ed25519 OKP JWK (`kty: "OKP"`,
`crv: "Ed25519"`, base64url `x`), which is what a JWKS-publishing issuer
serves.
```

- [ ] **Step 4: Bind the issuer document and JWKS to the origin, and the policy layer to the capsule**

In `spec/federation.md`, replace lines 142-143:

```markdown
`trust_roots` MAY instead carry `jwks_uri`. The document is cacheable; a
verifier that already holds the trust roots never fetches it.
```

with:

```markdown
`trust_roots` MAY instead carry `jwks_uri`. The document is cacheable; a
verifier that already holds the trust roots never fetches it.

`issuer` MUST equal the domain the document was fetched from, and
`jwks_uri` MUST be on that same origin. A reader MUST treat either
mismatch as `issuer_document_invalid` and compute no trust from the
document: trust roots are the keys every other check is made against, so
a document that can name any issuer and point anywhere is not a trust
anchor at all.
```

Replace lines 355-357:

```markdown
4. **Attested identity** — where the requirement is identity-scoped,
   the signer is covered by a verified identity attestation for the
   required role (and, if scoped, the required provider role).
```

with:

```markdown
4. **Attested identity** — where the requirement is identity-scoped,
   the signer is covered by a verified identity attestation for the
   required role (and, if scoped, the required provider role). The
   attestation MUST be one whose `capsule_id` binds **this** capsule:
   policy evaluation re-checks the binding rather than matching
   attestations to signers by public key alone, so a cross-capsule
   replay cannot satisfy a requirement.
```

Replace lines 385-387:

```markdown
- `attestation_rejected` — trust roots present but the attestation is
  expired, its signature fails, or its `capsule_id`/`signer_public_key`
  binding does not match. Strong negative signal.
```

with:

```markdown
- `attestation_rejected` — trust roots present but the attestation is
  expired, its signature fails, its binding claims are absent, or its
  `capsule_id`/`signer_public_key`/issuer binding does not match. Strong
  negative signal.

These two outcomes are oppositely signed and MUST stay distinguishable
in an implementation's result: an adapter that collapses both into a
bare "not ok" destroys the distinction this vocabulary exists to draw.
The reference adapter reports `attestation_verified`,
`attestation_unverified`, or `attestation_rejected` on every result, and
`spec/vectors/identity-attestation/vectors.json` pins those outcomes.
```

- [ ] **Step 5: Update the Clerk profile**

In `spec/profiles/clerk.md`, add `aud` to the minted-JWT example (line 34, immediately after `"iss"`):

```jsonc
  "iss": "https://clerk.<instance>",   // or the app issuer
  "aud": "<verifying host's attestation audience>",
  "sub": "user_123",                    // Clerk user id
```

Replace lines 54-63 (the verification paragraph and the session-token callout):

```markdown
Verifying (offline, given the cached Clerk JWKS): `verifyIdentityAttestation`
verifies the JWT signature against the JWKS and requires the caller to supply
the capsule id, the signer key, the expected issuer, and the expected
audience. It then checks `exp`, checks `iss`/`aud` against those
caller-supplied values, and requires the `cap` binding to be present and to
match the capsule and signer being verified:

```js
const res = federation.verifyIdentityAttestation(attestation, {
  trustRoots: clerkJwks,          // cached out-of-band
  capsuleId,                      // the capsule being verified
  signerPublicKeyHex,             // the signer being checked
  expectedIssuer: "https://clerk.<instance>",
  audience: "<this host's attestation audience>",
});
// res.status is "attestation_verified" | "attestation_unverified" | "attestation_rejected"
```

A verifier without the JWKS still verifies the capsule math and reports
`attestation_unverified` — *unknown*, not a negative signal.

> Clerk session tokens are short-lived and audience-bound to the app; they are
> not themselves capsule attestations. The backend mints a **purpose-scoped**
> attestation JWT (a Clerk JWT template, or the app's own issuer key published
> in the issuer metadata JWKS) carrying `cap` and an `aud` naming the
> verifying host. Never embed a raw end-user session token: it has no `cap`
> binding, so verification rejects it.
```

Replace the policy snippet and its paragraph (lines 94-104):

```markdown
```js
const policy = { issuer, required: [
  { role: "originator", org_role: "admin" },
  { role: "reviewer",  quorum: 2 },
]};
const decision = federation.evaluateSignerPolicy(
  verifyResult, attestedSigners, policy, { capsuleId });
```

`attestedSigners` are the claims of attestations already verified with
`verifyIdentityAttestation`, including their `capsule_id`. Policy re-checks
that binding against `capsuleId`, so an attestation minted for another
capsule cannot satisfy a requirement here. The check is offline and does not
alter the cryptographic verification result.
```

Replace the first two security notes (lines 108-111):

```markdown
- The JWKS is a **trust root**: obtain it out-of-band and pin/cache it. Clerk
  rotates signing keys; refresh on the host's schedule. `kid` selects the key
  and selection fails closed: an unknown `kid` resolves to no key rather than
  falling back to another key in the cached set, so a cached multi-key or
  multi-issuer JWKS cannot be used to accept an attestation signed by any key
  in it.
- Attestations bind exactly one `capsule_id` + `signer_public_key`, and both
  the attestation check and the policy check re-verify that binding against
  the capsule in hand; they cannot be replayed onto another capsule.
```

- [ ] **Step 6: Record the change in the changelog**

In `CHANGELOG.md`, add to the `## Unreleased` → `### Changed` section (after line 52):

```markdown
- **Federation identity attestations now bind to something.**
  `verifyIdentityAttestation` requires the caller to supply `capsuleId`,
  `signerPublicKeyHex`, and `expectedIssuer` (plus `audience` for the JWT
  profile) and rejects any attestation whose `capsule_id` /
  `signer_public_key` / `signer_role` binding claims are absent — a raw
  provider session token, which carries no `cap` object, previously
  verified with a fully populated subject. `verifyJwt` requires an
  expected issuer and audience instead of checking `iss` against a field
  of the same untrusted wrapper. `kid` now selects exactly one trust root
  or none, instead of falling back to any cached key with a matching
  `alg`. An Ed25519 OKP JWK is decoded into raw key bytes, so an issuer
  publishing its native trust root as a standard JWKS is consumable. An
  unparseable or absent `expires_at` is a rejection rather than "never
  expires". `evaluateSignerPolicy` takes a required `{ capsuleId }` and
  drops attestations bound to another capsule. Every result carries a
  machine-readable `status` from `spec/federation.md`'s own vocabulary
  (`attestation_verified` / `attestation_unverified` /
  `attestation_rejected`), pinned by the new
  `spec/vectors/identity-attestation/` registry. `fetchIssuerMetadata`
  requires `issuer` to match the fetch origin and `loadTrustRoots`
  requires `jwks_uri` to share it. `spec/federation.md` and
  `spec/profiles/clerk.md` state these as normative verifier rules. Wire
  format unchanged; the overlay API is a breaking change.
```

- [ ] **Step 7: Run the check to verify it passes**

Run: `sh /tmp/check-federation-normative.sh`

Expected: PASS — `federation spec text: ok` (exit 0)

- [ ] **Step 8: Run the full lane suite for regressions**

Run: `cd sdk-js && npm test && cd .. && node tools/check-spec-vectors.mjs && node tools/regen-capsule-skill.mjs --check`

Expected: `# tests 79`, `# pass 79`, `# fail 0`; then `spec vectors: ok (291 vectors)`; then the skill regeneration check passes unchanged (`spec/federation.md` and `spec/profiles/clerk.md` are not part of the skill bundle — `tools/regen-capsule-skill.mjs:33-39` lists only README/format/manifest/chain/envelope/trust/pith)

- [ ] **Step 9: Commit**
```bash
git add spec/federation.md spec/profiles/clerk.md CHANGELOG.md
git commit -m "docs(spec): make attestation binding, key selection, and issuer origin normative"
```

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

Two simpler-looking rules were considered and rejected:

- *"Reject every number with |n| > 2^53 − 1."* This would refuse `1e+21`,
  `1.5e300`, and every ordinary scientific-notation magnitude — none of
  which can lose digits, because their canonical token carries an `e` and
  no implementation can read it back as anything but a double. The rule
  would amputate the number line for nothing.
- *"Accept large integer literals; require arbitrary-precision parsing."*
  This makes conformance depend on a JSON-parser property no mainstream
  library exposes uniformly, and it contradicts RFC 8785 §3.2.2.3, whose
  serialization is defined over doubles. A capsule is a portable artifact:
  the acceptance boundary must be checkable by an implementation that has
  only a binary64 parser, which is every implementation.

The token rule is what remains. It is exactly the set of values on which
"parse, canonicalize, hash" is implementation-independent, and it can be
decided from the value alone with two comparisons.

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

This is an **integrity invariant**, not a policy knob: it is unconditional
in every profile, because a value outside the boundary is a value whose
hashed bytes cannot be re-derived, and no profile tolerates that. It is
equally not a claim about the *content* of the capsule. Refusing one says
nothing about the honesty of its author — only that the artifact is not
portable — and the report must say so.

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

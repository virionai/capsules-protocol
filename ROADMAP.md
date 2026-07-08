# Capsule Spec Roadmap — v0.6 to v1.0

This roadmap tracks protocol stabilization only: the portable file shape,
verifier semantics, profile system, federation model, and conformance
suite required for a durable v1.0 spec.

Status labels:

- `Complete in v0.6`: specified and implemented in the current profile.
- `Partial`: specified or implemented in part, but not enough for v1.0.
- `Open`: not yet specified.

## Spec Work

| Area | Status | Current repo evidence | Remaining v1.0 work |
|---|---|---|---|
| File layout and required artifacts | Complete in v0.6 | `spec/format.md`; SDK readers/builders handle `manifest.json`, `program.md`, `agents.md`, `chain/events.jsonl`, `payload/`, and `provenance/envelope.json` | Review wording for ambiguity; add malformed-layout vectors |
| Current cryptographic profile | Complete in v0.6 | `spec/envelope.md`; JS/Python/Swift/Rust cover JCS, SHA-256, Ed25519, X25519, HKDF-SHA256, and ChaCha20-Poly1305; Kotlin covers the plain JCS/SHA-256/Ed25519 path and rejects encrypted capsules | Independent review; signed vectors for every cryptographic input |
| Capsule identity | Complete in v0.6 | `spec/manifest.md`; SDKs derive `capsule_id` from domain separator, originator public key, and first event hash | Add identity test vectors and collision/mis-binding negative cases |
| Envelope signing and verification | Complete in v0.6 | `spec/envelope.md`; SDK/verifier tests cover canonical payload, domain separation, role mismatch, unknown versions, and unknown ciphers | Lock vector format; external review of byte-level signing inputs |
| Event-chain integrity | Complete in v0.6 | `spec/chain.md`; SDK tests cover raw previous-hash linkage and tamper detection | Add canonical chain vectors, malformed sequence vectors, and cross-language expected errors |
| Encrypted capsule L2/L3 model | Complete in v0.6 | `spec/envelope.md`; JS/Python/Swift/Rust cover encrypted outer verification and decrypted inner verification | Add recipient-bundle vectors and negative vectors for AAD/key-wrap mistakes |
| Verifier result vocabulary | Partial | JS/Python/Kotlin/Swift/Rust expose `valid`, `trusted`, allowlists, and `trustedSignerCount`; `spec/trust.md` states math-vs-trust boundary | Normalize result field names, error categories, and required renderer language |
| Normative conformance suite | Partial | `tools/run-conformance.mjs`; `.github/workflows/conformance.yml`; SDK tests and parity tests exist | Replace ad hoc/example-dependent fixtures with checked-in signed vectors and expected-result manifests |
| Tool export conformance diagnostic | Open | Operators can produce an experimental package that passes the current JS verifier while still exposing stricter spec-schema questions; no dedicated diagnostic reports tool/app export issues yet | Build a CLI/report tool that accepts capsule exports from external tools, runs verifier plus strict schema/profile checks, groups issues by spec area, labels severity and fix/waiver options, and records whether failures indicate an implementation bug or possible spec narrowness |
| Independent implementation parity | Partial | JS, Python, Swift, Kotlin plain, and Rust lanes exist; Rust verifier, Python tests, Swift tests, and Kotlin plain tests compare against JS-built fixtures | Tie all lanes to the normative vector registry and publish pass/fail criteria |
| Resource-limit and malformed-archive behavior | Partial | `spec/format.md`; JS/Python ZIP readers reject traversal and enforce limits; strictness tests exist | Make limits/profile names normative; add vectors for size, entry count, compression, symlink, and path edge cases |
| Untrusted-content projection | Partial | `spec/chain.md`, `spec/trust.md`; JS/Python chain code marks common narrative fields untrusted | Define projection rules for host/model contexts and add conformance cases |
| Regulated-work profile wedge | Open | README names regulated packets, investigations, project records, and correspondence as candidate domains, but no domain profile exists | Define one narrow reference profile for regulated AI-assisted work packets, including required artifacts, signer roles, renderer language, and negative conformance cases |
| Signer-role policy and quorum | Open | Current spec supports multiple signers but leaves policy to hosts | Define policy expression for required roles, quorum, and failure reporting |
| Federation vocabulary | Partial | `spec/federation.md` (informative draft): issuer identifiers, `.well-known/capsule-signers` signer document, discovery methods, failure vocabulary | Review the draft, resolve its open questions, make it normative for v0.7 |
| Key lifecycle semantics | Open | `spec/federation.md` drafts key `status` (`active`/`retired`/`revoked`) and validity windows in the signer document | Specify verifier treatment of lifecycle status against sealing-time evidence, and historical validation |
| Temporal anchoring profile | Open | `signed_at` is self-attested; `spec/federation.md` drafts bundled `anchors` (Rekor / RFC 3161) with an offline-verification requirement | Define anchor proof formats and verifier treatment; add anchor vectors |
| Alternate profile declaration | Open | `spec/README.md`, `spec/envelope.md`, and `spec/trust.md` describe extension points conceptually | Specify profile identifiers, negotiation, required fields, and fail-closed behavior |
| Encrypted outer metadata minimization | Open | v0.6 intentionally exposes outer metadata needed for L2 verification | Define optional profiles for reducing recipient and issuer metadata exposure |
| Pith protocol boundary | Open | `spec/pith.md` describes Pith as a context-style discipline and helper normalizer, but it remains easy to confuse with canonical protocol semantics | Move Pith requirements into an explicit authoring/profile layer; keep cryptographic verification independent from lossy narrative normalization |
| Ecosystem adapter contracts | Open | README names runtime modes conceptually, but there are no stable adapter contracts for MCP, A2A, OpenLineage, C2PA, SLSA/in-toto, or LangChain/LlamaIndex export paths | Define non-normative adapter mappings that preserve capsule verification semantics and clarify what data is translated, referenced, or intentionally omitted |

## v1.0 Gates

| Gate | Exit criterion |
|---|---|
| Wire-shape freeze | No unresolved ambiguity in bytes being signed, hashed, identified, encrypted, or canonicalized |
| Vector registry | Every required verifier behavior has a checked-in vector and expected result |
| Tool conformance diagnostics | External tool exports receive clear pass/fail/waiver reports that separate cryptographic failure, schema/profile failure, host-policy failure, and possible spec-fit feedback |
| Cross-implementation parity | At least two independently maintained implementations pass the normative suite without reference-code exceptions |
| Trust semantics | Hosts can distinguish valid math, trusted signers, policy failure, and unsupported profile without out-of-band wording |
| Profile and federation model | Alternate verification, encryption, identity, authorization, and key-management profiles can be declared and rejected safely |
| Reference deployment wedge | One narrow regulated-work profile can be implemented end-to-end without private Virion assumptions |
| Ecosystem compatibility | At least two adapter mappings demonstrate Capsules can interoperate with adjacent AI/provenance systems without becoming a runtime framework |

## Operating Principle

The file format must stand on its own:

```text
portable file -> deterministic verification -> explicit trust policy -> optional host integrations
```

If a roadmap item does not change the portable file, verifier semantics,
profile system, federation model, or conformance suite, it belongs outside
the spec roadmap.

## Strategic Emphasis

For v1.0, prefer depth over surface area:

- Lead with a narrow regulated-work profile before generalizing the
  protocol language to every AI work artifact.
- Prioritize trust, federation, key lifecycle, and temporal anchoring
  before adding more SDK surface area.
- Treat Pith as an authoring/profile discipline, not as a verifier or
  canonicalization primitive.
- Expand implementation breadth only after the normative vector registry
  is strong enough to catch cross-language drift.
- Add diagnostic tooling for real tool exports before treating ecosystem
  friction as either implementation error or spec failure.
- Build adapter contracts so Capsules can ride alongside MCP, A2A,
  OpenLineage, C2PA, SLSA/in-toto, LangChain, and LlamaIndex instead of
  competing with them as another runtime framework.

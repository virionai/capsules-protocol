# Capsule Spec Roadmap — v0.7 to v1.0

This roadmap tracks protocol stabilization only: the portable file shape,
verifier semantics, profile system, federation model, and conformance
suite required for a durable v1.0 spec.

Status labels:

- `Complete in v0.6`: specified and implemented in the current profile (the v0.6 redesign baseline, carried forward unchanged by v0.7).
- `Complete in v0.7`: specified and implemented by the v0.7 remediation.
- `Complete in v0.7.1`: normatively specified, implemented in all five
  lanes and both reference CLIs, and pinned by registered vectors that
  every lane consumes.
- `Complete in v0.7.1 (spec + reference lane)`: normatively specified,
  implemented by the sdk-js reference lane, and pinned by registered
  vectors; the remaining lane ports are tracked in the row's remaining
  work and in the vector registry's explicit per-lane exemptions.
- `Partial`: specified or implemented in part, but not enough for v1.0.
- `Open`: not yet specified.

## Spec Work

| Area | Status | Current repo evidence | Remaining v1.0 work |
|---|---|---|---|
| File layout and required artifacts | Complete in v0.6 | `spec/format.md`; SDK readers/builders handle `manifest.json`, `program.md`, `agents.md`, `chain/events.jsonl`, `payload/`, and `provenance/envelope.json`; `spec/vectors/malformed-layout/` pins open-stage rejection outcomes across JS/Python/Rust | Review wording for ambiguity |
| Current cryptographic profile | Complete in v0.6 | `spec/envelope.md`; JS/Python/Swift/Rust cover JCS, SHA-256, Ed25519, X25519, HKDF-SHA256, and ChaCha20-Poly1305; Kotlin covers the plain JCS/SHA-256/Ed25519 path and refuses encrypted capsules as a reported capability limit (`unsupported`/`unsupported_capability`, spec/results.md) | Independent review; signed vectors for every cryptographic input |
| Capsule identity | Complete in v0.6 | `spec/manifest.md`; SDKs derive `capsule_id` from domain separator, originator public key, and first event hash; `spec/vectors/signing-input.json` pins the identity preimage byte-for-byte | Add collision/mis-binding negative cases |
| Envelope signing and verification | Complete in v0.6 | `spec/envelope.md`; SDK/verifier tests cover canonical payload, domain separation, role mismatch, unknown versions, and unknown ciphers; `spec/vectors/signing-input.json` pins the canonical payload, signing domain, and full signing input, reproduced by JS/Python/Rust | External review of byte-level signing inputs |
| Version compatibility / archival opening | Complete in v0.6 | `spec/versioning.md` (normative): known versions open forever under their era's rules with version-keyed domain strings; unknown versions fail closed with non-tamper diagnoses; the observed version and the v0.6 algorithm-suite identifier are reported facts on every lane's verify result; host accepted-version policy is reported, never decided; `spec/vectors/version-compat/` consumed by all five lanes; the 0.6 → 0.7 bump is DONE — the known table carries both rows and a frozen genuine v0.6 capsule proves the archival guarantee | Keep the frozen v0.6 evidence byte-stable; repeat the drill at the next bump |
| Event-chain integrity | Complete in v0.6 | `spec/chain.md`; SDK tests cover raw previous-hash linkage and tamper detection | Add canonical chain vectors, malformed sequence vectors, and cross-language expected errors |
| Encrypted capsule L2/L3 model | Complete in v0.6 | `spec/envelope.md`; JS/Python/Swift/Rust cover encrypted outer verification and decrypted inner verification | Add recipient-bundle vectors and negative vectors for AAD/key-wrap mistakes |
| Verifier result vocabulary | Complete in v0.7.1 | `spec/results.md` (normative): derived `verdict`/`verdict_reason`/`qualifiers` with `ok == (verdict=='valid')` invariant, the ten-name qualifier vocabulary, canonical note strings, renderer minimum substrings, and the 0/1/2 CLI exit contract; all five lanes emit the surface (Kotlin's plain-only refusal of encrypted capsules reports `unsupported_capability`), and BOTH reference CLIs render the verdict-first Result block with `--accept-versions` and the shared requested-policy exit rule (P1/P2/P7 — an unmatched `--allowlist` or a capsule the CLI cannot open exits 1 in either lane); `spec/vectors/result-vocabulary/` + additive assertions on signer-set/chain-rules/chain-binding/version-compat pin exact qualifier arrays | Legacy field-NAME normalization (`ok`, per-lane casing, Swift/Kotlin flat `checks[]`) deferred to v0.8 planning |
| Normative conformance suite | Partial | `tools/run-conformance.mjs`; `.github/workflows/conformance.yml`; checked-in registries (`tamper-detection`, `malformed-layout`, `signing-input`, `jcs-numbers`, `plain-basic`) with expected outcomes, consumed directly by the JS checker and the Python/Rust registry tests | Extend registries with envelope/identity negative vectors; wire Swift/Kotlin to the outcome registries |
| Tool export conformance diagnostic | Open | Operators can produce an experimental package that passes the current JS verifier while still exposing stricter spec-schema questions; no dedicated diagnostic reports tool/app export issues yet | Build a CLI/report tool that accepts capsule exports from external tools, runs verifier plus strict schema/profile checks, groups issues by spec area, labels severity and fix/waiver options, and records whether failures indicate an implementation bug or possible spec narrowness |
| Independent implementation parity | Partial | JS, Python, Swift, Kotlin plain, and Rust lanes exist; Rust verifier, Python tests, Swift tests, and Kotlin plain tests compare against JS-built fixtures | Tie all lanes to the normative vector registry and publish pass/fail criteria |
| Resource-limit and malformed-archive behavior | Partial | `spec/format.md` (STORED-only, duplicate-entry rejection, raw-central-directory checks now normative); JS/Python/Rust readers reject traversal, absolute paths, duplicates, compression, and symlinks, with checked-in fixtures in `spec/vectors/malformed-layout/` | Make limit/profile names normative; add over-limit archive vectors; bring Swift/Kotlin readers to the same contract |
| Untrusted-content projection | Partial | `spec/chain.md`, `spec/trust.md`; JS/Python chain code marks common narrative fields untrusted | Define projection rules for host/model contexts and add conformance cases |
| Regulated-work profile wedge | Open | README names regulated packets, investigations, project records, and correspondence as candidate domains, but no domain profile exists | Define one narrow reference profile for regulated AI-assisted work packets, including required artifacts, signer roles, renderer language, and negative conformance cases |
| Signer-role policy and quorum | Partial | `spec/federation.md` defines a minimal required-role/quorum expression; `sdk-js` `federation.evaluateSignerPolicy` evaluates it offline over trusted+attested signers | Make the policy expression normative; add failure-reporting categories and conformance cases |
| Federation vocabulary | Partial | `spec/federation.md` (informative draft) defines the portability firewall, issuer metadata document, `.well-known/capsule-signers` signer document, trust roots, identity attestations (`ed25519-jcs` + JWT), key discovery methods, and a discovery failure vocabulary; `sdk-js/src/federation/` is a working reference adapter with tests | Review the draft and resolve its open questions; freeze the attestation/issuer-metadata wire shapes; add attestation vectors and negative cases; specify profile discovery/negotiation; make it normative for v0.7 |
| Key lifecycle semantics | Open | `spec/federation.md` drafts key `status` (`active`/`retired`/`revoked`) and validity windows in the signer document | Specify verifier treatment of lifecycle status against sealing-time evidence, and historical validation |
| Temporal anchoring profile | Open | `signed_at` is self-attested; `spec/federation.md` drafts bundled `anchors` (Rekor / RFC 3161) with an offline-verification requirement | Define anchor proof formats and verifier treatment; add anchor vectors |
| Alternate profile declaration | Complete in v0.7.1 | `spec/profiles.md` (normative): the `format.profile`/`envelope.profile` dyad, identifier grammar, default profile `v0.6-suite`/`1.0` + absence rule, normalized-dyad equality, fail-closed `unsupported_profile`/`profile_mismatch` refusals with refusal exclusivity, the Profile Authoring Contract (incl. the profile-keyed domain-separation MUST and the invariant core), and offline negotiation facts; all five lanes implement the open-stage gate + profile channel (sdk-swift and verifier-rust also gate the L3 inner capsule), and both reference CLIs print the `Profile:` line; `spec/vectors/profile-declaration/` pins 17 outcomes | Federation `capsule_profiles` discovery when federation freezes |
| Encrypted outer metadata minimization | Open | v0.7 intentionally exposes outer metadata needed for L2 verification | Define optional profiles for reducing recipient and issuer metadata exposure |
| Pith protocol boundary | Complete in v0.7 | `spec/pith.md` is an explicit authoring/profile layer: the normalizer is opt-in at the builder (JS/Python), sentence selection is meaning-preserving (a dot inside an identifier, decimal, version, or URL is never a boundary), a rewrite that changed a field is declared in-chain via `pith_normalized_fields` (`spec/chain.md`), and cryptographic verification is independent of narrative normalization; `spec/vectors/pith-authoring/` is consumed by all five lanes | Keep the authoring layer out of verifier semantics; benchmark the discipline's readability claim before any stronger wording |
| Ecosystem adapter contracts | Partial | `spec/profiles/clerk.md` + `sdk-js/src/federation/` demonstrate the first adapter contract: an external identity/auth provider (Clerk) rides alongside capsules for identity binding, encrypted-recipient discovery, and policy while core verification stays offline. Other targets (MCP, A2A, OpenLineage, C2PA, SLSA/in-toto, LangChain/LlamaIndex) remain conceptual | Add adapter mappings for the remaining targets following the same portability-firewall pattern; clarify translated vs referenced vs omitted data per adapter |

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

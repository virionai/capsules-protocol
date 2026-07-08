# TODO

Protocol-focused backlog for this repository. `ROADMAP.md` holds the
strategic path to v1.0; this file tracks concrete engineering work that
keeps the spec, SDKs, CLI, verifier, and conformance harness aligned.

Priority legend:

- **P0** blocks a credible v0.6 protocol lock.
- **P1** should land before the next public release candidate.
- **P2** is useful, but can wait for adoption signal or external review.

---

## Capsule v0.6 Spec

- [ ] **P0** - Create a checked-in normative vector registry under
      `spec/vectors/` with capsule bytes, expected hashes, verifier
      results, and negative cases.
- [ ] **P0** - Add explicit malformed-layout vectors for missing required
      files, duplicate entries, unsafe paths, compressed entries, over-limit
      archives, and invalid JSON.
- [ ] **P0** - Pin byte-level signing and hashing examples for JCS payloads,
      chain event hashes, envelope signing input, and capsule identity.
- [ ] **P1** - Normalize verifier result field names and error categories
      across JS, Python, Swift, Kotlin, Rust, and the CLI.
- [ ] **P1** - Make resource-limit profile names normative: max entries,
      max total bytes, compressed-entry rejection, symlink rejection, and
      path validation.
- [ ] **P1** - Define untrusted-content projection rules for host/model
      contexts and add conformance cases.
- [ ] **P1** - Freeze the federation wire shapes (issuer metadata,
      identity attestation `ed25519-jcs` + JWT) and add attestation vectors
      plus negative cases to `spec/vectors/`. Reference: `spec/federation.md`,
      `spec/profiles/clerk.md`, `sdk-js/src/federation/`.
- [ ] **P2** - Specify signer-role policy and quorum language. A minimal
      reference exists (`federation.evaluateSignerPolicy`); make it normative.
- [ ] **P2** - Specify key lifecycle records: rotation, retirement,
      revocation, and historical validation.
- [ ] **P2** - Specify temporal anchoring profiles such as RFC 3161 or Rekor.
- [ ] **P2** - Specify federation/profile discovery vocabulary.

## SDKs And Verifiers

- [ ] **P0** - Keep the JavaScript SDK as the reference implementation and
      require all behavior changes to update `spec/` in the same change.
- [ ] **P0** - Run Python, Rust, Swift, and Kotlin lanes against the
      checked-in vector registry once `spec/vectors/` lands.
- [ ] **P1** - Compile-test Swift with SwiftPM/Xcode and add any missing
      package ceremony.
- [ ] **P1** - Compile-test Kotlin with Gradle and add any missing module
      ceremony.
- [ ] **P1** - Add cross-implementation parity tests for `manifest_hash`,
      `content_index_hash`, `first_event_hash`, `entry_hash`, and encrypted
      L2/L3 anchors.
- [ ] **P1** - Add negative vectors for uppercase hex, unknown versions,
      unknown ciphers, role mismatch, bad envelope signatures, and broken
      chain linkage.
- [ ] **P2** - Add multi-signer builder surfaces where the lower-level
      envelope support already exists.

## CLI And Conformance

- [x] **P0** - Make `tools/run-conformance.mjs` fail closed for required
      repo-local targets. Missing required lanes must not produce an overall
      PASS. (Harness fails closed on missing dir / failing lane; the CI
      workflow's `HARNESS_EXIT` capture no longer swallows a red harness.)
- [ ] **P0** - Keep CLI smoke tests self-contained. They should generate
      local fixtures or use `spec/vectors/`, not require a sibling checkout.
- [ ] **P1** - Add CLI coverage for encrypted L2 verification and explicit
      encrypted-content inspection errors.
- [ ] **P1** - Publish conformance output that distinguishes required,
      optional, skipped, and unavailable targets.
- [ ] **P2** - Add machine-readable conformance metadata for consumers that
      want to gate package releases.

## Release Hygiene

- [ ] **P0** - Keep package license metadata aligned with the root
      `LICENSE` file.
- [ ] **P0** - Keep public docs free of workstation paths, sibling-checkout
      assumptions, private backlog items, and project-specific demo plans.
- [ ] **P1** - Add a lightweight repository hygiene check for absolute paths,
      common token formats, generated output drift, and stale external paths.
- [ ] **P1** - Document the release process for npm, PyPI, crates.io,
      SwiftPM tags, and Maven packages.
- [ ] **P2** - Add signed release attestations once the protocol vectors are
      stable enough to verify independently.

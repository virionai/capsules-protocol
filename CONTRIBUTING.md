# Contributing to Capsule

Capsule is a portable, signed, append-only unit of intelligence. This
repository holds the protocol spec, reference SDKs, the Rust verifier,
CLI, and generic examples. Examples under `examples/` are illustrative
only and carry no warranty.

Before contributing, please skim
[`AGENTS.md`](AGENTS.md) — it documents the deterministic-output and
fail-closed-verification invariants you must preserve.

## Local development

The JavaScript SDK is the reference implementation:

```sh
cd sdk-js
npm install
npm test
```

A peer language SDK (Python, Kotlin, Swift) or the Rust verifier:

```sh
cd sdk-py && python -m pytest    # or sdk-kotlin / sdk-swift
cd verifier-rust && cargo test
```

The full conformance run:

```sh
node tools/run-conformance.mjs
```

It writes both a JSON and a Markdown report under `output/`. CI runs
this on every push to `main`.

## Adding a new SDK

A new language SDK is admitted to the conformance matrix once it:

1. **Implements the primitives in `spec/`.** Every section of every
   spec file is a behavior contract — manifest schema, JCS canonical
   serialization, ed25519 signing input, the v0.6 capsule-id derivation,
   ChaCha20-Poly1305 encryption (and explicit rejection of `none` and
   unknown ciphers), the event chain, the envelope.
2. **Passes the test vectors in `spec/vectors/` once they exist.**
   Until the vector set lands, an SDK passes by round-tripping the
   generic local examples with bit-identical sealed bytes against the
   JavaScript SDK.
3. **Is added to the conformance matrix.** Open a PR that extends
   `tools/run-conformance.mjs` with the new target. The matrix is the
   gate: only SDKs that pass land in the report.

If the new SDK exposes a verification API, also export a
`verifyCapsule` (or `verify`) entry point that returns `{ ok, ... }`
or a truthy value on success — the conformance harness wires its
verifier step against that shape.

## Proposing a spec change

The spec is treated as a contract between independent implementations.
Changes are not free.

1. **Open an issue with rationale.** What invariant is wrong, what
   property does the new wording give us, and what does it cost the
   existing SDKs?
2. **Show at least one implementation's behavior diff.** Either a
   working branch of one of the reference SDKs that adopts the change,
   or a worked example of the old vs. new wire format on an existing
   example capsule. "Spec change with no implementation" is not
   enough.
3. **Bump the version, not the meaning, of pinned constants.** The
   format is at `0.6` on purpose. Changes that break sealed-byte
   compatibility ship as `0.7` (and onward) — never silently inside
   `0.6`.

## Pull requests

- Keep changes small and reviewable. One concern per PR.
- Conventional Commits in the title (`feat:`, `fix:`, `chore:`,
  `docs:`, `ci:`, etc.). Squash on merge.
- All CI checks must pass. The conformance matrix is non-negotiable —
  if your change makes an SDK fail conformance, fix the SDK or update
  the spec (with rationale), don't bypass the gate.
- Update `CHANGELOG.md` for anything user-visible.

## Security

Do not file security issues as PRs or public issues. See
[`SECURITY.md`](SECURITY.md).

## License

By contributing, you agree your contribution is licensed under the
[MIT License](LICENSE).

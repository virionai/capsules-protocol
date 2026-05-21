# Capsule Protocol Agent Notes

Scope: this file applies to the entire `capsules-protocol` repository.

This repository is the canonical Capsule protocol/spec/SDK workspace. Treat
the checked-out repository root as the working directory; do not assume any
specific parent folder, workstation path, or sibling archive checkout exists.

## Orientation

- `README.md` explains the v0.6 redesign and current package layout.
- `ROADMAP.md` records the path to protocol lock and kill criteria.
- `spec/` is the protocol contract.
- `sdk-js/` is the reference JavaScript SDK.
- `cli/` is the command-line verifier/inspector.
- `sdk-py/`, `sdk-kotlin/`, `sdk-swift/`, and `verifier-rust/` are peer implementation or verification lanes.

## Working Rules

- Treat this repository as the active source of truth for v0.6 protocol,
  SDK, CLI, verifier, and conformance work.
- Do not copy legacy architecture from external or archived repositories
  into the SDKs without an explicit design decision recorded in the issue,
  PR, or docs change.
- Keep spec/docs updates with behavior changes.
- Preserve deterministic capsule semantics: canonical JSON, event-chain integrity, stable zip packaging, and fail-closed verification.
- Do not hand-edit generated capsule outputs unless the task is specifically about fixtures or examples.

## Useful Checks

```bash
cd sdk-js && npm test
cd ../cli && npm test
cd ../verifier-rust && cargo test
```

Run the narrowest relevant check first, then broaden when protocol, verifier, or cross-lane contracts change.

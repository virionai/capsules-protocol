# Capsule Protocol Agent Notes

Scope: this file applies to `virion/capsule/capsules-protocol`.

This repo is the active Capsule protocol/spec/SDK workspace. It was renamed from `new-design`; legacy protocol material now lives under `virion/capsule/archive/`.

## Orientation

- `README.md` explains the v0.6 redesign and current package layout.
- `ROADMAP.md` records the path to protocol lock and kill criteria.
- `spec/` is the protocol contract.
- `sdk-js/` is the reference JavaScript SDK.
- `cli/` is the command-line verifier/inspector.
- `sdk-py/`, `sdk-kotlin/`, `sdk-swift/`, and `verifier-rust/` are peer implementation or verification lanes.

## Working Rules

- Treat archived repos as reference material, not active source of truth.
- Do not copy legacy Python architecture from `archive/capsule-standard` into the JavaScript SDK without an explicit design decision.
- Keep spec/docs updates with behavior changes.
- Preserve deterministic capsule semantics: canonical JSON, event-chain integrity, stable zip packaging, and fail-closed verification.
- Do not hand-edit generated capsule outputs unless the task is specifically about fixtures or examples.

## Useful Checks

```bash
cd virion/capsule/capsules-protocol/sdk-js && npm test
cd virion/capsule/capsules-protocol/cli && npm test
cd virion/capsule/capsules-protocol/verifier-rust && cargo test
```

Run the narrowest relevant check first, then broaden when protocol, verifier, or cross-lane contracts change.

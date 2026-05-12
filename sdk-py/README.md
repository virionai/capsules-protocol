# Capsule v0.6 — Python SDK

Third independent implementation of the Capsule v0.6 portable
AI-context format. Sibling to the [JS reference SDK](../sdk/) and the
[Rust verifier](../verifier-rust/).

## Status

- **v0.1:** plain (L2) capsules — full build + read + verify.
- **v0.2 (this release):** encrypted (L3) capsules — multi-recipient
  X25519 + HKDF-SHA256 + ChaCha20-Poly1305. Python builds, reads,
  decrypts, and verifies (L2 outer + L3 inner) the same encrypted
  shape the JS SDK produces.

`EncryptedCapsulesNotSupportedError` is retained as an exported type so
caller code can still pattern-match against future, not-yet-supported
encrypted formats — but no first-party path raises it as of v0.2.

## Install

```sh
cd sdk-py
pip install -e ".[dev]"
```

## Develop

```sh
pytest                       # 110 tests
ruff check src tests         # lint
ruff format src tests        # format (in place)
ruff format --check src tests  # CI-style formatter check
```

## Use

```python
from capsule import (
    CapsuleBuilder, CapsuleReader,
    generate_ed25519, generate_x25519,
    verify_capsule,
)

# Patient signs + encrypts to the clinician's X25519 public key.
patient = generate_ed25519()
clinic = generate_x25519()  # in practice, comes from the clinic's published trust anchor
builder = CapsuleBuilder(
    originator={"public_key": patient.public_key_hex, "label": "Patient"},
    participants=[{"actor_id": "human:patient", "role": "originator", "label": "Patient"}],
)
builder.set_program("# Symptom journal\n2026-05-08: itchy patch on left forearm.\n")
builder.append_event({
    "actor": "human:patient", "kind": "observation", "action": "logged_symptom",
    "target": "program.md", "timestamp": "2026-05-08T12:00:00Z",
    "payload": {"severity": 5},
})
capsule_bytes = builder.seal(
    signers=[{"role": "originator",
              "public_key": patient.public_key,
              "private_key": patient.private_key}],
    signed_at="2026-05-08T12:00:00Z",
    recipients=[clinic.public_key],  # encrypts to the clinician
)

# Clinician opens, decrypts, verifies.
outer = CapsuleReader.from_bytes(capsule_bytes)
l2 = verify_capsule(outer, allowlist=[patient.public_key_hex])
assert l2["ok"] and l2["level"] == "L2"

inner = outer.decrypt(
    recipient_public_key=clinic.public_key,
    recipient_private_key=clinic.private_key,
)
l3 = verify_capsule(inner, allowlist=[patient.public_key_hex],
                    outer_envelope=outer.envelope())
assert l3["ok"] and l3["level"] == "L3"
print(inner.program())
```

## Parity

`tests/test_parity_jssdk.py` runs both directions:

1. **JS → Python.** Reads each plain fixture under
   `examples/tamper-detection/output/` and asserts the Python verifier
   reaches the same PASS / FAIL outcome the JS reference does, with
   the failure attributed to the same check (content_index, chain, or
   envelope). Encrypted fixtures are rejected with a clear v0.2-status
   error.

2. **Python → JS.** Builds a plain capsule entirely in Python, hands
   the bytes to the JS SDK's `verifyCapsule()` via a Node subprocess,
   and asserts `ok: true, trustedSignerCount: 1, level: "L2"`. This
   pins the build path against the reference verifier on the same
   bytes Python wrote.

Run both with `pytest tests/test_parity_jssdk.py -v`. The first run
builds the JS fixtures via `npm install && npm run build` in
`examples/tamper-detection`; subsequent runs reuse them. Set
`CAPSULE_PY_SKIP_JS_BUILD=1` to skip if Node tooling is unavailable.

## Module map (mirrors `sdk/src/`)

| Python | JS reference | Responsibility |
|---|---|---|
| `capsule.canonical` | `sdk/src/canonical.js` | JCS RFC 8785, SHA-256, hex |
| `capsule.crypto` | `sdk/src/crypto.js` | Ed25519, X25519, HKDF-SHA256, ChaCha20-Poly1305 |
| `capsule.zip_io` | `sdk/src/zip.js` | Deterministic STORED ZIP + safety |
| `capsule.pith` | `sdk/src/pith.js` | Narrative-field normalizer |
| `capsule.chain` | `sdk/src/chain.js` | Event hashing + chain verify |
| `capsule.manifest` | `sdk/src/manifest.js` | Manifest, capsule_id, content_index |
| `capsule.envelope` | `sdk/src/envelope.js` | Envelope build + sign + verify |
| `capsule.builder` | `sdk/src/builder.js` | CapsuleBuilder (plain + encrypted multi-recipient) |
| `capsule.reader` | `sdk/src/reader.js` | CapsuleReader (plain + decrypt) |
| `capsule.verifier` | `sdk/src/verifier.js` | verify_capsule (L2 plain, L2 encrypted-aware, L3) |

## License

Apache-2.0 (matches the rest of this repo).

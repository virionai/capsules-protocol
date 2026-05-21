# Capsule v0.6 — Python SDK

Third independent implementation of the Capsule v0.6 portable
AI-context format. Sibling to the [JS reference SDK](../sdk-js/) and
the [Rust verifier](../verifier-rust/).

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

# The originator signs and encrypts to a recipient's X25519 public key.
originator = generate_ed25519()
recipient = generate_x25519()
builder = CapsuleBuilder(
    originator={"public_key": originator.public_key_hex, "label": "Originator"},
    participants=[{"actor_id": "human:originator", "role": "originator", "label": "Originator"}],
)
builder.set_program("# Work packet\n\nInitial verified work surface.\n")
builder.append_event({
    "actor": "human:originator", "kind": "observation", "action": "created",
    "target": "program.md", "timestamp": "2026-05-08T12:00:00Z",
    "payload": {"summary": "created packet"},
})
capsule_bytes = builder.seal(
    signers=[{"role": "originator",
              "public_key": originator.public_key,
              "private_key": originator.private_key}],
    signed_at="2026-05-08T12:00:00Z",
    recipients=[recipient.public_key],
)

# Recipient opens, decrypts, verifies.
outer = CapsuleReader.from_bytes(capsule_bytes)
l2 = verify_capsule(outer, allowlist=[originator.public_key_hex])
assert l2["ok"] and l2["level"] == "L2"

inner = outer.decrypt(
    recipient_public_key=recipient.public_key,
    recipient_private_key=recipient.private_key,
)
l3 = verify_capsule(inner, allowlist=[originator.public_key_hex],
                    outer_envelope=outer.envelope())
assert l3["ok"] and l3["level"] == "L3"
print(inner.program())
```

## Parity

`tests/test_parity_jssdk.py` runs both directions:

1. **JS → Python.** Reads shared vector fixtures and asserts the Python
   verifier reaches the same PASS / FAIL outcome the JS reference does,
   with the failure attributed to the same check.

2. **Python → JS.** Builds a plain capsule entirely in Python, hands
   the bytes to the JS SDK's `verifyCapsule()` via a Node subprocess,
   and asserts `ok: true, trustedSignerCount: 1, level: "L2"`. This
   pins the build path against the reference verifier on the same
   bytes Python wrote.

Run both with `pytest tests/test_parity_jssdk.py -v`. Until
`spec/vectors/` is checked in, fixture-backed parity tests are expected
to be treated as optional local checks.

## Module map (mirrors `sdk-js/src/`)

| Python | JS reference | Responsibility |
|---|---|---|
| `capsule.canonical` | `sdk-js/src/canonical.js` | JCS RFC 8785, SHA-256, hex |
| `capsule.crypto` | `sdk-js/src/crypto.js` | Ed25519, X25519, HKDF-SHA256, ChaCha20-Poly1305 |
| `capsule.zip_io` | `sdk-js/src/zip.js` | Deterministic STORED ZIP + safety |
| `capsule.pith` | `sdk-js/src/pith.js` | Narrative-field normalizer |
| `capsule.chain` | `sdk-js/src/chain.js` | Event hashing + chain verify |
| `capsule.manifest` | `sdk-js/src/manifest.js` | Manifest, capsule_id, content_index |
| `capsule.envelope` | `sdk-js/src/envelope.js` | Envelope build + sign + verify |
| `capsule.builder` | `sdk-js/src/builder.js` | CapsuleBuilder (plain + encrypted multi-recipient) |
| `capsule.reader` | `sdk-js/src/reader.js` | CapsuleReader (plain + decrypt) |
| `capsule.verifier` | `sdk-js/src/verifier.js` | verify_capsule (L2 plain, L2 encrypted-aware, L3) |

## License

MIT. See [../LICENSE](../LICENSE).

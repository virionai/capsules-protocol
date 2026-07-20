# Capsule v0.6 — Python SDK

Independent Python implementation of the Capsule v0.6 portable,
signed, verifiable work-artifact format. Sibling to the
[JS reference SDK](../sdk-js/) and the [Rust verifier](../verifier-rust/);
same wire format, same verification semantics, same ergonomics.

Prototype, not production. See [../spec/](../spec/) for the protocol.

## Add it to your app

Not yet published to PyPI. Install from a checkout of this repository:

```sh
pip install /path/to/capsules-protocol/sdk-py
# or for development:  pip install -e /path/to/capsules-protocol/sdk-py
```

Requirements: Python >= 3.11. The only runtime dependency is
[`cryptography`](https://pypi.org/project/cryptography/) (Ed25519,
X25519, HKDF-SHA256, ChaCha20-Poly1305).

## Quickstart

Create, save, verify, and read a capsule. This flow is pinned by
`tests/test_dx.py`, so it cannot silently rot:

```python
from capsule import CapsuleBuilder, CapsuleReader, generate_ed25519, verify_capsule

# 1. One keypair for your app (persist keys.private_key_hex somewhere
#    safe; in a real app you generate this once, not per capsule).
keys = generate_ed25519()

# 2. Build and seal a capsule: a portable, signed unit of work.
builder = CapsuleBuilder(originator=keys)  # or {"public_key": ..., "label": "MyApp"}
builder.set_program("# Quarterly report\n\nDraft written by Alice, reviewed by AI.\n")
builder.append_event({"actor": "human:alice", "action": "wrote_draft"})
builder.append_event({"actor": "ai:assistant", "action": "suggested_edits", "payload": {"count": 3}})
data = builder.seal(signers=keys)

with open("quickstart.capsule", "wb") as f:
    f.write(data)

# 3. Anywhere else (another process, another machine): open and verify.
#    The allowlist is your trust decision — which signer keys you accept.
with open("quickstart.capsule", "rb") as f:
    file_bytes = f.read()

result = verify_capsule(file_bytes, allowlist=[keys.public_key_hex])
print("verified:", result["ok"])                        # True — math checks out
print("trusted signers:", result["trusted_signer_count"])  # 1 — and you trust the key

# 4. Read the contents.
reader = CapsuleReader.from_bytes(file_bytes)
print("capsule id:", reader.manifest()["id"])
print(reader.program())
for event in reader.events():
    print(f"event {event['seq']}: {event['actor']} {event['action']}")
```

Sensible defaults keep the happy path short: `seal()` timestamps with
now (pass `signed_at` for reproducible builds), events default to
`kind="observation"` / `target="capsule"`, a signer's role defaults to
`"originator"`, and `verify_capsule(bytes)` on unopenable input returns
a fail-closed result (`ok: False`) instead of raising.

## Keys: hex or bytes, your choice

Every place the API takes a key accepts either a hex string (any case)
or 32 raw bytes — including the keypair objects from
`generate_ed25519()` / `generate_x25519()` as-is:

```python
keys = generate_ed25519()
# keys = Ed25519KeyPair(public_key=b"...", private_key=b"...",
#                       public_key_hex="...", private_key_hex="...")

CapsuleBuilder(originator=keys)                      # keypair object
CapsuleBuilder(originator={"public_key": "b440d9e6..."})  # hex
builder.seal(signers=keys)                           # role defaults to "originator"
builder.seal(signers=[{"role": "reviewer", "public_key": pub_hex, "private_key": priv_hex}])
verify_capsule(data, allowlist=[keys.public_key])     # bytes
verify_capsule(data, allowlist=[keys.public_key_hex]) # hex
```

The wire format stays lowercase hex regardless of input form.

Persist the private key (e.g. `keys.private_key_hex`) in your secret
store; publish the public key to whoever needs to verify your capsules.
The allowlist is a *trust policy*, not cryptography — `result["ok"]`
says the math checks out; `result["trusted_signer_count"]` says a
signer is one you accept (see [../spec/trust.md](../spec/trust.md)).
Treat a capsule as good when
`result["ok"] and result["trusted_signer_count"] >= 1` (or your own
stricter policy).

## Encrypt for specific recipients

Pass `recipients` at seal time to encrypt the capsule body
(ChaCha20-Poly1305; per-recipient X25519 key wrap). Anyone can still
verify the outer signatures (L2); only recipients can decrypt and fully
verify the content (L3):

```python
from capsule import generate_x25519

recipient = generate_x25519()  # recipient generates; shares public_key_hex

data = builder.seal(signers=keys, recipients=[recipient.public_key_hex])

# Recipient side:
outer = CapsuleReader.from_bytes(data)
l2 = verify_capsule(outer, allowlist=[keys.public_key_hex])  # no key needed
inner = outer.decrypt(recipient)  # keypair object works as-is
l3 = verify_capsule(inner, allowlist=[keys.public_key_hex],
                    outer_envelope=outer.envelope())
print(inner.program())
```

## Develop

```sh
cd sdk-py
pip install -e ".[dev]"
pytest                         # full suite, incl. registry + parity lanes
ruff check src tests           # lint
ruff format --check src tests  # formatter check
```

## Parity and conformance

- `tests/test_spec_registry.py` consumes the language-neutral outcome
  registries (`spec/vectors/tamper-detection/`, `malformed-layout/`)
  and the byte-level `signing-input.json` pins directly.
- `tests/test_parity_jssdk.py` runs both directions: Python verifies
  JS-built fixtures, and JS verifies Python-built capsules via a Node
  subprocess.

## Module map (mirrors `sdk-js/src/`)

| Python | JS reference | Responsibility |
|---|---|---|
| `capsule.canonical` | `sdk-js/src/canonical.js` | JCS RFC 8785, SHA-256, hex |
| `capsule.crypto` | `sdk-js/src/crypto.js` | Ed25519, X25519, HKDF-SHA256, ChaCha20-Poly1305 |
| `capsule.keys` | `sdk-js/src/keys.js` | API-boundary key-input normalization |
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

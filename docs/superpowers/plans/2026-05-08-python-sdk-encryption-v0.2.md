# Capsule v0.6 Python SDK — Encryption (v0.2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lift the v0.1 plain-only boundary in `sdk-py/` so encrypted (L3) capsules can be built, read, and verified — multi-recipient X25519 + HKDF-SHA256 + ChaCha20-Poly1305 — and parity-tested both directions against the JS reference.

**Architecture:** Extend the existing modules rather than create new ones. `crypto.py` gains X25519 / HKDF / ChaCha20-Poly1305 wrappers (the `cryptography` package already has all three). `envelope.py` lifts the `cipher="ChaCha20-Poly1305"` block. `builder.py` adds an `recipients=[...]` path that produces the outer/inner shape per `spec/format.md`. `reader.py` adds `encrypted_blob_bytes()`, `decryption_metadata()`, and an async-free `decrypt(recipient_public_key, recipient_private_key) -> CapsuleReader` returning an inner reader. `verifier.py` adds the encrypted-aware L2 path and accepts `outer_envelope=` for L3. `EncryptedCapsulesNotSupportedError` is retained as a type but no longer raised by these paths.

**Tech Stack:** Python 3.11+, `cryptography>=42` (already pinned). No new deps.

**Reference sources** (treat as ground truth):
- Spec: `spec/envelope.md` § Encryption + § L2/L3, `spec/format.md` § Encrypted capsule (outer layer)
- JS SDK: `sdk/src/crypto.js` (X25519/HKDF/ChaCha20 portion), `sdk/src/builder.js` (encrypted branch lines 192-318), `sdk/src/reader.js` lines 39-142, `sdk/src/verifier.js` lines 127-189
- JS fixtures: `examples/tamper-detection/output/clean-encrypted.capsule`, `tampered-blob.capsule`, `keys.json`

---

## File Structure

```
sdk-py/src/capsule/
├── crypto.py        # extend: X25519, HKDF-SHA256, ChaCha20-Poly1305
├── envelope.py      # modify: lift cipher="ChaCha20-Poly1305" block
├── builder.py       # modify: recipients= encrypted-seal path
├── reader.py        # modify: encrypted_blob_bytes/decryption_metadata/decrypt
├── verifier.py      # modify: L2 encrypted-aware + L3 with outer_envelope
└── __init__.py      # modify: re-export new helpers
sdk-py/tests/
├── test_crypto.py            # extend with new helpers
├── test_envelope.py          # extend
├── test_builder.py           # extend
├── test_reader.py            # extend
├── test_verifier.py          # extend
└── test_parity_jssdk.py      # extend with encrypted fixtures + Python→JS encrypted round-trip
```

Working directory throughout: `/Users/complex/repo/virion/capsule/new-design/sdk-py/`. The venv is at `sdk-py/venv/` — every command below is wrapped in `source venv/bin/activate 2>/dev/null` for the implementer's convenience.

**This repo is NOT under git.** Skip all git commit steps in this plan; the comments are illustrative.

---

## Task 1: crypto.py — X25519, HKDF-SHA256, ChaCha20-Poly1305

**Files:**
- Modify: `sdk-py/src/capsule/crypto.py`
- Modify: `sdk-py/tests/test_crypto.py`

**Reference:** `sdk/src/crypto.js` lines 87-188.

**Public surface to add** (alongside the existing Ed25519 surface):
- `class X25519KeyPair` (frozen dataclass: `public_key: bytes (32)`, `private_key: bytes (32)`, `public_key_hex: str`, `private_key_hex: str`)
- `generate_x25519() -> X25519KeyPair`
- `x25519_dh(private_key_raw: bytes, peer_public_key_raw: bytes) -> bytes` — 32-byte shared secret
- `hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes`
- `chacha20_poly1305_encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes` — returns `ciphertext || 16-byte tag`
- `chacha20_poly1305_decrypt(key: bytes, nonce: bytes, aad: bytes, ciphertext_with_tag: bytes) -> bytes` — raises on auth failure
- `random_key32() -> bytes` (32 random bytes)
- `random_nonce12() -> bytes` (12 random bytes)

- [ ] **Step 1: Add failing tests**

Append the following to `sdk-py/tests/test_crypto.py` (keep all existing tests intact):

```python
import pytest

from capsule.crypto import (
    X25519KeyPair,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
    generate_x25519,
    hkdf_sha256,
    random_key32,
    random_nonce12,
    x25519_dh,
)


def test_generate_x25519_returns_32_byte_keys():
    kp = generate_x25519()
    assert isinstance(kp, X25519KeyPair)
    assert len(kp.public_key) == 32
    assert len(kp.private_key) == 32
    assert isinstance(kp.public_key_hex, str) and len(kp.public_key_hex) == 64
    assert isinstance(kp.private_key_hex, str) and len(kp.private_key_hex) == 64


def test_x25519_dh_is_symmetric():
    a = generate_x25519()
    b = generate_x25519()
    sa = x25519_dh(a.private_key, b.public_key)
    sb = x25519_dh(b.private_key, a.public_key)
    assert sa == sb
    assert len(sa) == 32


def test_x25519_dh_rejects_wrong_lengths():
    a = generate_x25519()
    with pytest.raises(ValueError):
        x25519_dh(b"\x00" * 31, a.public_key)
    with pytest.raises(ValueError):
        x25519_dh(a.private_key, b"\x00" * 31)


def test_hkdf_sha256_known_vector_length():
    out = hkdf_sha256(b"shared" * 8, b"salt", b"info", 32)
    assert len(out) == 32
    assert isinstance(out, bytes)


def test_hkdf_sha256_deterministic():
    a = hkdf_sha256(b"ikm", b"salt", b"info", 32)
    b = hkdf_sha256(b"ikm", b"salt", b"info", 32)
    assert a == b


def test_hkdf_sha256_diverges_on_different_salt():
    a = hkdf_sha256(b"ikm", b"salt-1", b"info", 32)
    b = hkdf_sha256(b"ikm", b"salt-2", b"info", 32)
    assert a != b


def test_chacha20_poly1305_roundtrip():
    key = b"k" * 32
    nonce = b"n" * 12
    aad = b"aad-bytes"
    plaintext = b"hello world"
    ct = chacha20_poly1305_encrypt(key, nonce, aad, plaintext)
    assert ct != plaintext
    assert len(ct) == len(plaintext) + 16  # tag
    pt = chacha20_poly1305_decrypt(key, nonce, aad, ct)
    assert pt == plaintext


def test_chacha20_poly1305_empty_aad_roundtrip():
    key = b"k" * 32
    nonce = b"n" * 12
    plaintext = b"hello"
    ct = chacha20_poly1305_encrypt(key, nonce, b"", plaintext)
    pt = chacha20_poly1305_decrypt(key, nonce, b"", ct)
    assert pt == plaintext


def test_chacha20_poly1305_tampered_ciphertext_raises():
    key = b"k" * 32
    nonce = b"n" * 12
    aad = b"aad"
    ct = chacha20_poly1305_encrypt(key, nonce, aad, b"hello world")
    bad = bytearray(ct)
    bad[0] ^= 0x01
    with pytest.raises(Exception):
        chacha20_poly1305_decrypt(key, nonce, aad, bytes(bad))


def test_chacha20_poly1305_aad_mismatch_raises():
    key = b"k" * 32
    nonce = b"n" * 12
    ct = chacha20_poly1305_encrypt(key, nonce, b"aad-1", b"hello")
    with pytest.raises(Exception):
        chacha20_poly1305_decrypt(key, nonce, b"aad-2", ct)


def test_chacha20_poly1305_rejects_wrong_key_length():
    with pytest.raises(ValueError):
        chacha20_poly1305_encrypt(b"k" * 31, b"n" * 12, b"", b"x")
    with pytest.raises(ValueError):
        chacha20_poly1305_decrypt(b"k" * 31, b"n" * 12, b"", b"x" * 17)


def test_chacha20_poly1305_rejects_wrong_nonce_length():
    with pytest.raises(ValueError):
        chacha20_poly1305_encrypt(b"k" * 32, b"n" * 11, b"", b"x")
    with pytest.raises(ValueError):
        chacha20_poly1305_decrypt(b"k" * 32, b"n" * 11, b"", b"x" * 17)


def test_random_key32_and_random_nonce12():
    a = random_key32()
    b = random_key32()
    assert len(a) == 32 and len(b) == 32
    assert a != b
    n = random_nonce12()
    assert len(n) == 12
```

- [ ] **Step 2: Run the new tests, expect ImportError**

```sh
cd /Users/complex/repo/virion/capsule/new-design/sdk-py
source venv/bin/activate 2>/dev/null
pytest tests/test_crypto.py -v
```
Expected: ImportError on the new symbols.

- [ ] **Step 3: Extend `crypto.py`**

Append (after the existing Ed25519 block) — keep the existing `Ed25519KeyPair`, `generate_ed25519`, `ed25519_sign`, `ed25519_verify` unchanged:

```python
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass(frozen=True)
class X25519KeyPair:
    public_key: bytes  # 32 raw bytes
    private_key: bytes  # 32 raw bytes
    public_key_hex: str
    private_key_hex: str


def generate_x25519() -> X25519KeyPair:
    sk = X25519PrivateKey.generate()
    priv_raw = sk.private_bytes_raw()
    pub_raw = sk.public_key().public_bytes_raw()
    return X25519KeyPair(
        public_key=pub_raw,
        private_key=priv_raw,
        public_key_hex=bytes_to_hex(pub_raw),
        private_key_hex=bytes_to_hex(priv_raw),
    )


def x25519_dh(private_key_raw: bytes, peer_public_key_raw: bytes) -> bytes:
    if len(private_key_raw) != 32:
        raise ValueError("X25519 private key must be 32 bytes")
    if len(peer_public_key_raw) != 32:
        raise ValueError("X25519 peer public key must be 32 bytes")
    sk = X25519PrivateKey.from_private_bytes(private_key_raw)
    pk = X25519PublicKey.from_public_bytes(peer_public_key_raw)
    return sk.exchange(pk)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(ikm)


def chacha20_poly1305_encrypt(
    key: bytes, nonce: bytes, aad: bytes, plaintext: bytes
) -> bytes:
    if len(key) != 32:
        raise ValueError("ChaCha20-Poly1305 key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("ChaCha20-Poly1305 nonce must be 12 bytes")
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad if aad else None)


def chacha20_poly1305_decrypt(
    key: bytes, nonce: bytes, aad: bytes, ciphertext_with_tag: bytes
) -> bytes:
    if len(key) != 32:
        raise ValueError("ChaCha20-Poly1305 key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("ChaCha20-Poly1305 nonce must be 12 bytes")
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext_with_tag, aad if aad else None)


def random_key32() -> bytes:
    return os.urandom(32)


def random_nonce12() -> bytes:
    return os.urandom(12)
```

- [ ] **Step 4: Run new tests + full suite**

```sh
pytest tests/test_crypto.py -v
pytest -q  # full suite — should reach 110 → 123 passing (added 13)
ruff check src tests
ruff format --check src tests
```
Expected: 13 new tests pass; full suite ≥ 123; lint + format clean.

- [ ] **Step 5: Commit (skip — no git)**

---

## Task 2: envelope.py — lift cipher="ChaCha20-Poly1305" block

**Files:**
- Modify: `sdk-py/src/capsule/envelope.py`
- Modify: `sdk-py/tests/test_envelope.py`

**Reference:** `sdk/src/envelope.js` (no v0.1 block — `cipher` is enumerated).

The current `build_envelope` raises `EncryptedCapsulesNotSupportedError` when `cipher="ChaCha20-Poly1305"`. v0.2 lifts this; the function now accepts `"none"` and `"ChaCha20-Poly1305"`. The `EncryptedCapsulesNotSupportedError` class is retained for backward compatibility (importable from the module) but no longer raised by `build_envelope`.

Validation rules added/kept:
- `cipher="none"` and `encrypted_blob_hash != None` → `ValueError`
- `cipher="ChaCha20-Poly1305"` and (`encrypted_blob_hash` is None or not 64-hex) → `ValueError("encrypted capsule requires encrypted_blob_hash (64-hex)")`
- Any other cipher value → `ValueError("unsupported cipher: ...")`

`verify_envelope_signatures` already handles both ciphers correctly (the existing `_SUPPORTED_CIPHERS_PLAIN` only included `"none"`; we widen it to a single `_SUPPORTED_CIPHERS` set).

- [ ] **Step 1: Add failing tests**

Append to `sdk-py/tests/test_envelope.py`:

```python
def _make_encrypted_envelope():
    return build_envelope(
        capsule_id="a" * 64,
        first_event_hash="b" * 64,
        entry_hash="c" * 64,
        manifest_hash="d" * 64,
        content_index_hash="e" * 64,
        encrypted_blob_hash="f" * 64,
        cipher="ChaCha20-Poly1305",
        signed_at="2026-05-07T12:00:00Z",
    )


def test_build_envelope_accepts_chacha_cipher():
    env = _make_encrypted_envelope()
    assert env["cipher"] == "ChaCha20-Poly1305"
    assert env["encrypted_blob_hash"] == "f" * 64


def test_build_envelope_chacha_requires_blob_hash():
    with pytest.raises(ValueError, match="encrypted_blob_hash"):
        build_envelope(
            capsule_id="a" * 64, first_event_hash="b" * 64,
            entry_hash="c" * 64, manifest_hash="d" * 64,
            content_index_hash="e" * 64,
            encrypted_blob_hash=None,
            cipher="ChaCha20-Poly1305",
            signed_at="2026-05-07T12:00:00Z",
        )


def test_build_envelope_unknown_cipher_rejected():
    with pytest.raises(ValueError, match="unsupported cipher"):
        build_envelope(
            capsule_id="a" * 64, first_event_hash="b" * 64,
            entry_hash="c" * 64, manifest_hash="d" * 64,
            content_index_hash="e" * 64,
            encrypted_blob_hash=None,
            cipher="aes-gcm",
            signed_at="2026-05-07T12:00:00Z",
        )


def test_sign_and_verify_encrypted_envelope():
    env = _make_encrypted_envelope()
    kp = generate_ed25519()
    sign_envelope(env, [{
        "role": "originator",
        "public_key": kp.public_key,
        "private_key": kp.private_key,
    }])
    res = verify_envelope_signatures(env)
    assert res["ok"] is True
    assert res["signers"][0]["valid"] is True
```

The existing test `test_build_envelope_rejects_encrypted_for_v0_1` is now wrong — encrypted capsules are supported. **Delete that test** in this step (find by name and remove the function, ~10 lines).

- [ ] **Step 2: Run tests, expect failures**

```sh
pytest tests/test_envelope.py -v
```
Expected: the 4 new tests fail (ValueError raises but messages may differ, or `EncryptedCapsulesNotSupportedError` raises). The deleted-test slot now passes (zero failures from it).

- [ ] **Step 3: Modify `envelope.py`**

Replace the current `_SUPPORTED_CIPHERS_PLAIN` and the `build_envelope` body:

```python
# at module top
_SUPPORTED_CIPHERS = {"none", "ChaCha20-Poly1305"}
```

Replace `build_envelope`:

```python
def build_envelope(
    *,
    capsule_id: str,
    first_event_hash: str,
    entry_hash: str,
    manifest_hash: str,
    content_index_hash: str,
    encrypted_blob_hash: str | None,
    cipher: str = "none",
    signed_at: str,
) -> dict:
    if cipher not in _SUPPORTED_CIPHERS:
        raise ValueError(f"unsupported cipher: {cipher}")
    if cipher == "none" and encrypted_blob_hash is not None:
        raise ValueError("plain capsule must have encrypted_blob_hash=None")
    if cipher != "none":
        if not isinstance(encrypted_blob_hash, str) or len(encrypted_blob_hash) != 64:
            raise ValueError("encrypted capsule requires encrypted_blob_hash (64-hex)")
    return {
        "version": ENVELOPE_VERSION,
        "capsule_id": capsule_id,
        "first_event_hash": first_event_hash,
        "entry_hash": entry_hash,
        "manifest_hash": manifest_hash,
        "content_index_hash": content_index_hash,
        "encrypted_blob_hash": encrypted_blob_hash,
        "cipher": cipher,
        "signed_at": signed_at,
        "signers": [],
    }
```

Replace `verify_envelope_signatures`'s cipher gate (the `if cipher not in _SUPPORTED_CIPHERS_PLAIN` block) with `if cipher not in _SUPPORTED_CIPHERS`.

`EncryptedCapsulesNotSupportedError` stays defined at module top (other modules still import it; we leave the import path stable). It's no longer raised by `build_envelope`.

- [ ] **Step 4: Run tests + full suite**

```sh
pytest tests/test_envelope.py -v
pytest -q
ruff check src tests
ruff format --check src tests
```
Expected: envelope tests pass with 4 new tests added and 1 stale test removed (net +3 → 15 envelope tests); full suite at ≥126; lint+format clean.

- [ ] **Step 5: Commit (skip — no git)**

---

## Task 3: builder.py — recipients= encrypted-seal path

**Files:**
- Modify: `sdk-py/src/capsule/builder.py`
- Modify: `sdk-py/tests/test_builder.py`

**Reference:** `sdk/src/builder.js` lines 192-318.

`CapsuleBuilder.seal` gains a kwarg: `recipients: list[bytes] | None = None`. Each `recipients[i]` is a 32-byte X25519 raw public key. When `recipients` is provided and non-empty, the sealer produces an encrypted (outer/inner) capsule per the algorithm in `sdk/src/builder.js`:

1. Build inner ZIP exactly as the plain path would, except:
   - `inner_envelope.cipher = "none"`, `encrypted_blob_hash = None` (it's the *inner* envelope; useful for L3)
   - Sign with the same `signers`
2. Generate `content_key = random_key32()`, `content_nonce = random_nonce12()`
3. Build AAD: `jcs({"version": "0.6", "capsule_id": ..., "first_event_hash": ..., "originator_public_key": ..., "cipher": "ChaCha20-Poly1305"})` — keys sorted, no whitespace
4. `content_enc = chacha20_poly1305_encrypt(content_key, content_nonce, aad, inner_zip_bytes)`
5. `encrypted_blob_hash = sha256_hex(content_enc)`
6. For each recipient pubkey:
   - `eph = generate_x25519()`
   - `shared = x25519_dh(eph.private_key, recipient_pub)`
   - `wrap_key = hkdf_sha256(ikm=shared, salt=recipient_pub, info=b"capsule-key-wrap-v0.6", length=32)`
   - `wrap_nonce = random_nonce12()`
   - `wrapped_key = chacha20_poly1305_encrypt(wrap_key, wrap_nonce, b"", content_key)`
   - bundle = `{"recipient_public_key": hex(recipient_pub), "ephemeral_public_key": eph.public_key_hex, "wrap_nonce": hex(wrap_nonce), "wrapped_key": hex(wrapped_key)}`
7. `decryption.json` = `{"cipher": "ChaCha20-Poly1305", "content_nonce": hex(content_nonce), "key_bundles": [...]}` — written pretty (`json.dumps(indent=2, ensure_ascii=False)`)
8. Outer files = `{"skills/decryption/decryption.json": <pretty JSON bytes>, "content.enc": <bytes>}`
9. Outer content_index = `build_content_index(outer_files)` — note `content.enc` is in `CONTENT_INDEX_EXCLUDED` so the index covers only `skills/decryption/decryption.json`
10. Outer manifest = `build_manifest(..., encryption={"metadata_path": "skills/decryption/decryption.json", "cipher": "ChaCha20-Poly1305"})`, `manifest.id = capsule_id`
11. Outer envelope = `build_envelope(..., encrypted_blob_hash=encrypted_blob_hash, cipher="ChaCha20-Poly1305")`, signed with the same `signers`
12. Pack outer ZIP

**Public surface change:** `seal(*, signers, signed_at, recipients=None) -> bytes`. The plain branch is unchanged when `recipients is None or len(recipients) == 0`.

- [ ] **Step 1: Add failing tests**

Append to `sdk-py/tests/test_builder.py`:

```python
import json
import zipfile
import io

from capsule.crypto import generate_x25519
from capsule.zip_io import unpack_zip


def _build_encrypted(*, recipient_count=1):
    kp = generate_ed25519()
    recipient_kps = [generate_x25519() for _ in range(recipient_count)]
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": "Acme"},
        participants=[{"actor_id": "human:alice", "role": "originator", "label": "A"}],
    )
    builder.set_program("# Loan\nApproved.\n")
    builder.append_event({
        "actor": "human:alice", "kind": "decision", "action": "approved",
        "target": "program.md", "timestamp": "2026-05-07T12:00:00Z",
        "payload": {"amount": 50000},
    })
    zip_bytes = builder.seal(
        signers=[{"role": "originator",
                  "public_key": kp.public_key,
                  "private_key": kp.private_key}],
        signed_at="2026-05-07T12:00:00Z",
        recipients=[r.public_key for r in recipient_kps],
    )
    return zip_bytes, kp, recipient_kps


def test_encrypted_seal_emits_outer_layout():
    zip_bytes, _, _ = _build_encrypted()
    files = unpack_zip(zip_bytes)
    assert sorted(files.keys()) == sorted([
        "manifest.json",
        "provenance/envelope.json",
        "skills/decryption/decryption.json",
        "content.enc",
    ])
    # No inner-only files leak through
    assert "program.md" not in files
    assert "chain/events.jsonl" not in files


def test_encrypted_seal_outer_envelope_and_manifest():
    zip_bytes, _, _ = _build_encrypted()
    files = unpack_zip(zip_bytes)
    manifest = json.loads(files["manifest.json"].decode())
    envelope = json.loads(files["provenance/envelope.json"].decode())
    assert envelope["cipher"] == "ChaCha20-Poly1305"
    assert isinstance(envelope["encrypted_blob_hash"], str)
    assert len(envelope["encrypted_blob_hash"]) == 64
    assert manifest["encryption"] == {
        "metadata_path": "skills/decryption/decryption.json",
        "cipher": "ChaCha20-Poly1305",
    }


def test_encrypted_seal_decryption_metadata_one_recipient():
    zip_bytes, _, recipients = _build_encrypted(recipient_count=1)
    files = unpack_zip(zip_bytes)
    meta = json.loads(files["skills/decryption/decryption.json"].decode())
    assert meta["cipher"] == "ChaCha20-Poly1305"
    assert isinstance(meta["content_nonce"], str) and len(meta["content_nonce"]) == 24
    assert len(meta["key_bundles"]) == 1
    bundle = meta["key_bundles"][0]
    assert bundle["recipient_public_key"] == recipients[0].public_key_hex
    assert len(bundle["ephemeral_public_key"]) == 64
    assert len(bundle["wrap_nonce"]) == 24
    # wrapped_key = ChaCha20-Poly1305(content_key) → 32 + 16-byte tag = 48 bytes → 96-hex
    assert len(bundle["wrapped_key"]) == 96


def test_encrypted_seal_decryption_metadata_multiple_recipients():
    zip_bytes, _, recipients = _build_encrypted(recipient_count=3)
    files = unpack_zip(zip_bytes)
    meta = json.loads(files["skills/decryption/decryption.json"].decode())
    assert len(meta["key_bundles"]) == 3
    pubkeys = {b["recipient_public_key"] for b in meta["key_bundles"]}
    assert pubkeys == {r.public_key_hex for r in recipients}


def test_encrypted_seal_no_recipients_falls_through_to_plain():
    kp = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": ""},
        participants=[],
    )
    builder.set_program("# x\n")
    zip_bytes = builder.seal(
        signers=[{"role": "originator",
                  "public_key": kp.public_key,
                  "private_key": kp.private_key}],
        signed_at="2026-05-07T12:00:00Z",
        recipients=[],
    )
    files = unpack_zip(zip_bytes)
    assert "program.md" in files
    assert "content.enc" not in files


def test_encrypted_seal_rejects_wrong_recipient_pubkey_length():
    kp = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": ""},
        participants=[],
    )
    with pytest.raises(ValueError):
        builder.seal(
            signers=[{"role": "originator",
                      "public_key": kp.public_key,
                      "private_key": kp.private_key}],
            signed_at="2026-05-07T12:00:00Z",
            recipients=[b"\x00" * 31],
        )
```

`pytest` is already imported at the top of the test file from earlier tasks; if not, add `import pytest`.

- [ ] **Step 2: Run tests, expect failures**

```sh
pytest tests/test_builder.py -v
```
Expected: the 6 new tests fail (recipients kwarg unrecognized or feature missing).

- [ ] **Step 3: Modify `builder.py`**

Update imports:

```python
import json
from .canonical import bytes_to_hex, hex_to_bytes, jcs, sha256_hex
from .crypto import (
    chacha20_poly1305_encrypt,
    generate_x25519,
    hkdf_sha256,
    random_key32,
    random_nonce12,
    x25519_dh,
)
```

Add a private helper at the end of the file:

```python
def _build_decryption_metadata(
    content_key: bytes,
    recipients: list[bytes],
) -> tuple[bytes, dict]:
    """Returns (content_nonce, decryption_meta_dict). content_nonce is reused below."""
    content_nonce = random_nonce12()
    key_bundles = []
    for r_pub in recipients:
        if not isinstance(r_pub, (bytes, bytearray, memoryview)) or len(r_pub) != 32:
            raise ValueError("recipient public key must be 32 bytes")
        r_pub_bytes = bytes(r_pub)
        eph = generate_x25519()
        shared = x25519_dh(eph.private_key, r_pub_bytes)
        wrap_key = hkdf_sha256(
            ikm=shared,
            salt=r_pub_bytes,
            info=b"capsule-key-wrap-v0.6",
            length=32,
        )
        wrap_nonce = random_nonce12()
        wrapped_key = chacha20_poly1305_encrypt(wrap_key, wrap_nonce, b"", content_key)
        key_bundles.append({
            "recipient_public_key": bytes_to_hex(r_pub_bytes),
            "ephemeral_public_key": eph.public_key_hex,
            "wrap_nonce": bytes_to_hex(wrap_nonce),
            "wrapped_key": bytes_to_hex(wrapped_key),
        })
    return content_nonce, {
        "cipher": "ChaCha20-Poly1305",
        "content_nonce": bytes_to_hex(content_nonce),
        "key_bundles": key_bundles,
    }
```

Update `seal` signature and body. The existing plain-path is preserved when `recipients` is None or empty; when set, take the encrypted branch:

```python
def seal(
    self,
    *,
    signers: list[dict],
    signed_at: str,
    recipients: list[bytes] | None = None,
) -> bytes:
    if not signers:
        raise ValueError("seal requires at least one signer")
    if not signed_at:
        raise ValueError("seal requires signed_at")

    if self.program_md is None:
        self.program_md = "# Program\n"
    if not self.bare_events:
        self.bare_events.append({
            "actor": "system:host",
            "kind": "observation",
            "action": "session_ended",
            "target": "capsule",
            "timestamp": signed_at,
            "payload": {"note": "host emitted backstop event before seal"},
        })

    # 1) Chain
    events = build_chain_events(self.bare_events)
    first_event_hash, entry_hash = first_and_entry_hash(events)
    events_jsonl = events_to_jsonl(events)

    # 2) Inner files (same as plain build)
    inner: dict[str, bytes] = {
        "program.md": self.program_md.encode("utf-8"),
        "chain/events.jsonl": events_jsonl,
    }
    if self.agents_md is not None:
        inner["agents.md"] = self.agents_md.encode("utf-8")
    skill_trust: dict[str, str] = {}
    for sid, entry in self.skills.items():
        if entry.json is not None:
            inner[f"skills/{sid}/skill.json"] = json.dumps(
                entry.json, indent=2, ensure_ascii=False
            ).encode("utf-8")
        if entry.markdown is not None:
            inner[f"skills/{sid}/SKILL.md"] = entry.markdown.encode("utf-8")
        skill_trust[sid] = "signed" if entry.signed else "unsigned"
    inner.update(self.payload)

    # 3) Capsule id (deterministic from originator + first event)
    originator_pub_raw = hex_to_bytes(self.originator["public_key"])
    capsule_id = compute_capsule_id(originator_pub_raw, first_event_hash)

    # 4) Inner manifest + envelope (always built; in encrypted mode this is the
    #    package the recipient sees after decrypt, used by L3.)
    inner_content_index = build_content_index(inner)
    inner_manifest = build_manifest(
        originator=self.originator,
        participants=self.participants,
        content_index=inner_content_index,
        first_event_hash=first_event_hash,
        skill_trust=skill_trust,
        encryption=None,
        created_at=self.created_at,
    )
    inner_manifest["id"] = capsule_id
    inner_mf_hash = manifest_hash(inner_manifest)
    inner_envelope = build_envelope(
        capsule_id=capsule_id,
        first_event_hash=first_event_hash,
        entry_hash=entry_hash,
        manifest_hash=inner_mf_hash,
        content_index_hash=inner_content_index["index_hash"],
        encrypted_blob_hash=None,
        cipher="none",
        signed_at=signed_at,
    )
    sign_envelope(inner_envelope, signers)

    inner_all_files = dict(inner)
    inner_all_files["manifest.json"] = manifest_bytes(inner_manifest)
    inner_all_files["provenance/envelope.json"] = json.dumps(
        inner_envelope, indent=2, ensure_ascii=False
    ).encode("utf-8")

    if not recipients:
        # Plain path — return the inner zip as the capsule.
        return pack_zip(inner_all_files)

    # 5) Encrypted path — encrypt the inner ZIP and produce outer layout.
    inner_zip_bytes = pack_zip(inner_all_files)

    content_key = random_key32()
    content_nonce, decryption_meta = _build_decryption_metadata(content_key, recipients)
    aad = jcs({
        "version": "0.6",
        "capsule_id": capsule_id,
        "first_event_hash": first_event_hash,
        "originator_public_key": self.originator["public_key"],
        "cipher": "ChaCha20-Poly1305",
    })
    content_enc = chacha20_poly1305_encrypt(content_key, content_nonce, aad, inner_zip_bytes)
    encrypted_blob_hash = sha256_hex(content_enc)

    outer_sidecars: dict[str, bytes] = {
        "skills/decryption/decryption.json": json.dumps(
            decryption_meta, indent=2, ensure_ascii=False
        ).encode("utf-8"),
        "content.enc": content_enc,
    }
    outer_content_index = build_content_index(outer_sidecars)

    outer_manifest = build_manifest(
        originator=self.originator,
        participants=self.participants,
        content_index=outer_content_index,
        first_event_hash=first_event_hash,
        skill_trust={},  # decryption is metadata, not a skill
        encryption={
            "metadata_path": "skills/decryption/decryption.json",
            "cipher": "ChaCha20-Poly1305",
        },
        created_at=self.created_at,
    )
    outer_manifest["id"] = capsule_id
    outer_mf_hash = manifest_hash(outer_manifest)

    outer_envelope = build_envelope(
        capsule_id=capsule_id,
        first_event_hash=first_event_hash,
        entry_hash=entry_hash,
        manifest_hash=outer_mf_hash,
        content_index_hash=outer_content_index["index_hash"],
        encrypted_blob_hash=encrypted_blob_hash,
        cipher="ChaCha20-Poly1305",
        signed_at=signed_at,
    )
    sign_envelope(outer_envelope, signers)

    outer_all_files = dict(outer_sidecars)
    outer_all_files["manifest.json"] = manifest_bytes(outer_manifest)
    outer_all_files["provenance/envelope.json"] = json.dumps(
        outer_envelope, indent=2, ensure_ascii=False
    ).encode("utf-8")
    return pack_zip(outer_all_files)
```

- [ ] **Step 4: Run tests + full suite**

```sh
pytest tests/test_builder.py -v
pytest -q
ruff check src tests
ruff format --check src tests
```
Expected: 6 new builder tests pass; full suite passes; lint+format clean.

- [ ] **Step 5: Commit (skip — no git)**

---

## Task 4: reader.py — encrypted helpers + decrypt

**Files:**
- Modify: `sdk-py/src/capsule/reader.py`
- Modify: `sdk-py/tests/test_reader.py`

**Reference:** `sdk/src/reader.js` lines 39-142.

**Methods to add to `CapsuleReader`:**
- `encrypted_blob_bytes() -> bytes` — returns the bytes of `content.enc`. Raises `MalformedCapsuleError` if absent.
- `decryption_metadata() -> dict | None` — returns the parsed `skills/decryption/decryption.json` (or whatever path `manifest.encryption.metadata_path` says). None if not encrypted.
- `decrypt(*, recipient_public_key: bytes, recipient_private_key: bytes) -> CapsuleReader` — produces a new reader over the inner capsule.

**Methods that should **stop** raising `EncryptedCapsulesNotSupportedError`:** none. The existing `_require_plain` keeps gating `events()` and `program()` on the *outer* (encrypted) reader — encrypted callers should call `decrypt()` first and then use the inner reader. Behavior is unchanged for callers that don't decrypt.

**Decrypt algorithm** (mirrors `sdk/src/reader.js`):

```python
1. assert is_encrypted()
2. validate recipient_*_key lengths (32 bytes each)
3. meta = decryption_metadata(); reject cipher != "ChaCha20-Poly1305"
4. find the bundle whose recipient_public_key == hex(recipient_public_key); raise on miss
5. shared = x25519_dh(recipient_private_key, hex_to_bytes(bundle.ephemeral_public_key))
6. wrap_key = hkdf_sha256(shared, recipient_public_key, b"capsule-key-wrap-v0.6", 32)
7. content_key = chacha20_poly1305_decrypt(wrap_key, hex_to_bytes(bundle.wrap_nonce), b"", hex_to_bytes(bundle.wrapped_key))
8. aad = jcs({version, capsule_id, first_event_hash, originator_public_key, cipher: "ChaCha20-Poly1305"})
9. inner_zip_bytes = chacha20_poly1305_decrypt(content_key, hex_to_bytes(meta.content_nonce), aad, encrypted_blob_bytes())
10. inner_files = unpack_zip(inner_zip_bytes); construct + return inner CapsuleReader
```

- [ ] **Step 1: Add failing tests**

Append to `sdk-py/tests/test_reader.py`:

```python
import pytest

from capsule.builder import CapsuleBuilder
from capsule.crypto import generate_ed25519, generate_x25519


def _build_enc_capsule(*, recipient_count=1):
    kp = generate_ed25519()
    recipients = [generate_x25519() for _ in range(recipient_count)]
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": "Acme"},
        participants=[{"actor_id": "human:alice", "role": "originator", "label": "A"}],
    )
    builder.set_program("# encrypted loan\n")
    builder.set_agents("# agents\n")
    builder.append_event({
        "actor": "human:alice", "kind": "decision", "action": "approved",
        "target": "program.md", "timestamp": "2026-05-07T12:00:00Z",
        "payload": {"amount": 1234},
    })
    zip_bytes = builder.seal(
        signers=[{"role": "originator",
                  "public_key": kp.public_key,
                  "private_key": kp.private_key}],
        signed_at="2026-05-07T12:00:00Z",
        recipients=[r.public_key for r in recipients],
    )
    return zip_bytes, kp, recipients


def test_encrypted_blob_bytes_returns_content_enc():
    zip_bytes, _, _ = _build_enc_capsule()
    reader = CapsuleReader.from_bytes(zip_bytes)
    assert reader.is_encrypted() is True
    blob = reader.encrypted_blob_bytes()
    assert isinstance(blob, bytes) and len(blob) > 0


def test_encrypted_blob_bytes_raises_when_plain():
    # Build a plain capsule then check.
    kp = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": ""},
        participants=[],
    )
    builder.set_program("# x\n")
    plain_zip = builder.seal(
        signers=[{"role": "originator",
                  "public_key": kp.public_key,
                  "private_key": kp.private_key}],
        signed_at="2026-05-07T12:00:00Z",
    )
    reader = CapsuleReader.from_bytes(plain_zip)
    with pytest.raises(MalformedCapsuleError):
        reader.encrypted_blob_bytes()


def test_decryption_metadata_returns_dict_for_encrypted():
    zip_bytes, _, recipients = _build_enc_capsule(recipient_count=1)
    reader = CapsuleReader.from_bytes(zip_bytes)
    meta = reader.decryption_metadata()
    assert meta is not None
    assert meta["cipher"] == "ChaCha20-Poly1305"
    assert any(b["recipient_public_key"] == recipients[0].public_key_hex
               for b in meta["key_bundles"])


def test_decryption_metadata_none_for_plain():
    kp = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": ""}, participants=[]
    )
    builder.set_program("# x\n")
    plain_zip = builder.seal(
        signers=[{"role": "originator",
                  "public_key": kp.public_key,
                  "private_key": kp.private_key}],
        signed_at="2026-05-07T12:00:00Z",
    )
    reader = CapsuleReader.from_bytes(plain_zip)
    assert reader.decryption_metadata() is None


def test_decrypt_returns_inner_reader_with_program_and_chain():
    zip_bytes, _, recipients = _build_enc_capsule()
    reader = CapsuleReader.from_bytes(zip_bytes)
    inner = reader.decrypt(
        recipient_public_key=recipients[0].public_key,
        recipient_private_key=recipients[0].private_key,
    )
    assert isinstance(inner, CapsuleReader)
    assert inner.is_encrypted() is False
    assert inner.program() == "# encrypted loan\n"
    events = inner.events()
    assert len(events) == 1
    assert events[0]["action"] == "approved"


def test_decrypt_rejects_when_plain():
    kp = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": ""}, participants=[]
    )
    builder.set_program("# x\n")
    plain_zip = builder.seal(
        signers=[{"role": "originator",
                  "public_key": kp.public_key,
                  "private_key": kp.private_key}],
        signed_at="2026-05-07T12:00:00Z",
    )
    reader = CapsuleReader.from_bytes(plain_zip)
    a = generate_x25519()
    with pytest.raises(ValueError, match="not encrypted"):
        reader.decrypt(recipient_public_key=a.public_key, recipient_private_key=a.private_key)


def test_decrypt_rejects_bad_key_lengths():
    zip_bytes, _, recipients = _build_enc_capsule()
    reader = CapsuleReader.from_bytes(zip_bytes)
    with pytest.raises(ValueError, match="32 bytes"):
        reader.decrypt(
            recipient_public_key=b"\x00" * 31,
            recipient_private_key=recipients[0].private_key,
        )
    with pytest.raises(ValueError, match="32 bytes"):
        reader.decrypt(
            recipient_public_key=recipients[0].public_key,
            recipient_private_key=b"\x00" * 31,
        )


def test_decrypt_rejects_unmatched_recipient():
    zip_bytes, _, _ = _build_enc_capsule(recipient_count=1)
    reader = CapsuleReader.from_bytes(zip_bytes)
    other = generate_x25519()
    with pytest.raises(ValueError, match="no matching recipient"):
        reader.decrypt(
            recipient_public_key=other.public_key,
            recipient_private_key=other.private_key,
        )


def test_decrypt_with_wrong_private_key_raises_on_aead():
    # Match the recipient slot by pubkey but supply a wrong private key —
    # ChaCha20-Poly1305 should fail authentication on the wrapped key.
    zip_bytes, _, recipients = _build_enc_capsule(recipient_count=1)
    reader = CapsuleReader.from_bytes(zip_bytes)
    other = generate_x25519()
    with pytest.raises(Exception):  # cryptography's InvalidTag, or wrapped
        reader.decrypt(
            recipient_public_key=recipients[0].public_key,
            recipient_private_key=other.private_key,
        )


def test_decrypt_third_of_three_recipients():
    zip_bytes, _, recipients = _build_enc_capsule(recipient_count=3)
    reader = CapsuleReader.from_bytes(zip_bytes)
    third = recipients[2]
    inner = reader.decrypt(
        recipient_public_key=third.public_key,
        recipient_private_key=third.private_key,
    )
    assert inner.program() == "# encrypted loan\n"
```

- [ ] **Step 2: Run tests, expect failures**

```sh
pytest tests/test_reader.py -v
```
Expected: 10 new tests fail (`AttributeError: encrypted_blob_bytes` etc.).

- [ ] **Step 3: Modify `reader.py`**

Add imports at top:

```python
from .canonical import bytes_to_hex, hex_to_bytes, jcs
from .crypto import chacha20_poly1305_decrypt, hkdf_sha256, x25519_dh
```

Add methods inside `CapsuleReader` (between `is_encrypted` and `events`):

```python
def encrypted_blob_bytes(self) -> bytes:
    blob = self._files.get("content.enc")
    if blob is None:
        raise MalformedCapsuleError("missing content.enc")
    return blob

def decryption_metadata(self) -> dict | None:
    if not self.is_encrypted():
        return None
    path = (
        self._manifest.get("encryption", {}).get("metadata_path")
        if isinstance(self._manifest.get("encryption"), dict)
        else None
    ) or "skills/decryption/decryption.json"
    raw = self._files.get(path)
    if raw is None:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise MalformedCapsuleError(f"decryption metadata parse: {e}") from e

def decrypt(
    self,
    *,
    recipient_public_key: bytes,
    recipient_private_key: bytes,
) -> "CapsuleReader":
    if not self.is_encrypted():
        raise ValueError("capsule is not encrypted")
    if (
        not isinstance(recipient_public_key, (bytes, bytearray, memoryview))
        or len(recipient_public_key) != 32
    ):
        raise ValueError("recipient_public_key must be 32 bytes")
    if (
        not isinstance(recipient_private_key, (bytes, bytearray, memoryview))
        or len(recipient_private_key) != 32
    ):
        raise ValueError("recipient_private_key must be 32 bytes")

    meta = self.decryption_metadata()
    if meta is None:
        raise MalformedCapsuleError("missing decryption metadata")
    if meta.get("cipher") != "ChaCha20-Poly1305":
        raise ValueError(f"unsupported cipher: {meta.get('cipher')}")

    recipient_pub_hex = bytes_to_hex(recipient_public_key)
    bundle = next(
        (b for b in (meta.get("key_bundles") or [])
         if b.get("recipient_public_key") == recipient_pub_hex),
        None,
    )
    if bundle is None:
        raise ValueError("no matching recipient bundle")

    eph_pub = hex_to_bytes(bundle["ephemeral_public_key"])
    wrap_nonce = hex_to_bytes(bundle["wrap_nonce"])
    wrapped_key = hex_to_bytes(bundle["wrapped_key"])

    shared = x25519_dh(bytes(recipient_private_key), eph_pub)
    wrap_key = hkdf_sha256(
        ikm=shared,
        salt=bytes(recipient_public_key),
        info=b"capsule-key-wrap-v0.6",
        length=32,
    )
    content_key = chacha20_poly1305_decrypt(wrap_key, wrap_nonce, b"", wrapped_key)

    aad = jcs({
        "version": "0.6",
        "capsule_id": self._envelope["capsule_id"],
        "first_event_hash": self._envelope["first_event_hash"],
        "originator_public_key": self._manifest["originator"]["public_key"],
        "cipher": "ChaCha20-Poly1305",
    })
    content_nonce = hex_to_bytes(meta["content_nonce"])
    content_enc = self.encrypted_blob_bytes()
    inner_zip_bytes = chacha20_poly1305_decrypt(content_key, content_nonce, aad, content_enc)

    inner_files = unpack_zip(inner_zip_bytes)
    if "manifest.json" not in inner_files or "provenance/envelope.json" not in inner_files:
        raise MalformedCapsuleError("decrypted inner capsule missing manifest or envelope")
    inner_manifest = json.loads(inner_files["manifest.json"].decode("utf-8"))
    inner_envelope = json.loads(inner_files["provenance/envelope.json"].decode("utf-8"))
    return CapsuleReader(inner_files, inner_manifest, inner_envelope)
```

- [ ] **Step 4: Run tests + full suite**

```sh
pytest tests/test_reader.py -v
pytest -q
ruff check src tests
ruff format --check src tests
```
Expected: 10 new reader tests pass; full suite green; lint+format clean.

- [ ] **Step 5: Commit (skip — no git)**

---

## Task 5: verifier.py — L2 encrypted-aware + L3 with outer_envelope

**Files:**
- Modify: `sdk-py/src/capsule/verifier.py`
- Modify: `sdk-py/tests/test_verifier.py`

**Reference:** `sdk/src/verifier.js` lines 1-203 (the full thing).

**Two changes:**
1. **L2 encrypted-aware:** When `reader.is_encrypted()` is True, the verifier checks the encrypted-blob hash + ensures `cipher != "none"` and `encrypted_blob_hash` is present. Chain verification is **deferred** to L3 — it returns `{"ok": True, "errors": [], "note": "deferred to L3 (encrypted outer)"}`. The current code adds an `errors.append("encrypted capsules require v0.2 of this SDK")` — **remove that** and replace with the proper L2 path.
2. **L3 cross-check:** Add `outer_envelope: dict | None = None` kwarg to `verify_capsule`. When provided, after running the standard verification on the (inner) reader, cross-check that `outer.capsule_id == inner.capsule_id`, `outer.first_event_hash == inner.first_event_hash`, `outer.entry_hash == inner.entry_hash`. Set `result["level"] = "L3"` when `outer_envelope` is provided.

The outer-envelope cross-check matches the JS reference (`sdk/src/verifier.js` lines 179-190).

- [ ] **Step 1: Add failing tests**

Append to `sdk-py/tests/test_verifier.py`:

```python
import io
import json
import zipfile

from capsule.builder import CapsuleBuilder
from capsule.crypto import generate_ed25519, generate_x25519


def _build_enc():
    kp = generate_ed25519()
    rec = generate_x25519()
    b = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": "Acme"},
        participants=[],
    )
    b.set_program("# Loan\n")
    b.append_event({
        "actor": "human:alice", "kind": "decision", "action": "approved",
        "target": "program.md", "timestamp": "2026-05-07T12:00:00Z",
        "payload": {}})
    zip_bytes = b.seal(
        signers=[{"role": "originator",
                  "public_key": kp.public_key,
                  "private_key": kp.private_key}],
        signed_at="2026-05-07T12:00:00Z",
        recipients=[rec.public_key],
    )
    return zip_bytes, kp, rec


def test_encrypted_outer_passes_l2_with_allowlist():
    zip_bytes, kp, _ = _build_enc()
    reader = CapsuleReader.from_bytes(zip_bytes)
    result = verify_capsule(reader, allowlist=[kp.public_key_hex])
    assert result["ok"] is True
    assert result["level"] == "L2"
    assert result["envelope"]["ok"] is True
    assert result["chain"]["ok"] is True  # deferred-but-OK note
    assert "deferred" in (result["chain"].get("note") or "")


def test_encrypted_outer_detects_blob_tamper():
    zip_bytes, kp, _ = _build_enc()
    # Flip a byte inside content.enc.
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as src, zipfile.ZipFile(
        buf, "w", compression=zipfile.ZIP_STORED
    ) as dst:
        for zi in src.infolist():
            data = src.read(zi)
            if zi.filename == "content.enc":
                bad = bytearray(data)
                bad[0] ^= 0x01
                data = bytes(bad)
            new_zi = zipfile.ZipInfo(zi.filename, date_time=(1980, 1, 1, 0, 0, 0))
            new_zi.compress_type = zipfile.ZIP_STORED
            dst.writestr(new_zi, data)
    reader = CapsuleReader.from_bytes(buf.getvalue())
    result = verify_capsule(reader, allowlist=[kp.public_key_hex])
    assert result["ok"] is False
    assert any("encrypted_blob_hash mismatch" in e for e in result["errors"])


def test_l3_inner_verifies_with_outer_envelope():
    zip_bytes, kp, rec = _build_enc()
    outer = CapsuleReader.from_bytes(zip_bytes)
    outer_envelope = outer.envelope()
    inner = outer.decrypt(
        recipient_public_key=rec.public_key,
        recipient_private_key=rec.private_key,
    )
    result = verify_capsule(inner, allowlist=[kp.public_key_hex], outer_envelope=outer_envelope)
    assert result["ok"] is True
    assert result["level"] == "L3"


def test_l3_detects_cross_envelope_mismatch():
    # Build two unrelated encrypted capsules; pass one's outer envelope while
    # verifying the other's inner. capsule_id/first_event_hash mismatch should fail.
    a_zip, a_kp, a_rec = _build_enc()
    b_zip, _, _ = _build_enc()
    b_outer = CapsuleReader.from_bytes(b_zip)
    a_outer = CapsuleReader.from_bytes(a_zip)
    a_inner = a_outer.decrypt(
        recipient_public_key=a_rec.public_key,
        recipient_private_key=a_rec.private_key,
    )
    result = verify_capsule(
        a_inner,
        allowlist=[a_kp.public_key_hex],
        outer_envelope=b_outer.envelope(),
    )
    assert result["ok"] is False
    assert any("L3" in e for e in result["errors"])
```

- [ ] **Step 2: Run tests, expect failures**

```sh
pytest tests/test_verifier.py -v
```
Expected: 4 new tests fail (`outer_envelope` kwarg unknown, encrypted path returns errors today, etc.).

- [ ] **Step 3: Modify `verifier.py`**

Replace the encrypted-aware section. Find:

```python
# Encrypted blob hash sanity (plain side)
if reader.is_encrypted():
    errors.append("encrypted capsules require v0.2 of this SDK")
else:
    if envelope.get("encrypted_blob_hash") is not None:
        errors.append("plain capsule must have envelope.encrypted_blob_hash=null")
    if envelope.get("cipher") != "none":
        errors.append(f"plain capsule must have cipher='none', got {envelope.get('cipher')!r}")
```

Replace with:

```python
# Encrypted blob hash sanity (matches sdk/src/verifier.js lines 127-145)
if reader.is_encrypted():
    blob = reader.encrypted_blob_bytes()
    recomputed = sha256_hex(blob)
    if recomputed != envelope.get("encrypted_blob_hash"):
        errors.append(
            "envelope.encrypted_blob_hash mismatch: "
            f"{envelope.get('encrypted_blob_hash')} vs recomputed {recomputed}"
        )
    if envelope.get("cipher") == "none":
        errors.append("encrypted blob present but envelope.cipher is 'none'")
else:
    if envelope.get("encrypted_blob_hash") is not None:
        errors.append("plain capsule must have envelope.encrypted_blob_hash=null")
    if envelope.get("cipher") != "none":
        errors.append(f"plain capsule must have cipher='none', got {envelope.get('cipher')!r}")
```

Add `sha256_hex` to the imports at top of `verifier.py`:

```python
from .canonical import hex_to_bytes, sha256_hex
```

Replace the chain section. Find:

```python
# Chain
if not reader.is_encrypted():
    events = reader.events()
    chain_result = verify_chain(events)
    result["chain"] = chain_result
    if events:
        first_eh, entry_h = first_and_entry_hash(events)
        if first_eh != envelope.get("first_event_hash"):
            ...
        if entry_h != envelope.get("entry_hash"):
            ...
```

Replace with:

```python
# Chain
if not reader.is_encrypted():
    events = reader.events()
    chain_result = verify_chain(events)
    result["chain"] = chain_result
    if events:
        first_eh, entry_h = first_and_entry_hash(events)
        if first_eh != envelope.get("first_event_hash"):
            errors.append(
                "envelope.first_event_hash mismatch: "
                f"{envelope.get('first_event_hash')} vs {first_eh}"
            )
        if entry_h != envelope.get("entry_hash"):
            errors.append(
                f"envelope.entry_hash mismatch: {envelope.get('entry_hash')} vs {entry_h}"
            )
else:
    # Encrypted outer — chain verification deferred to L3.
    result["chain"] = {
        "ok": True,
        "errors": [],
        "note": "deferred to L3 (encrypted outer)",
    }
```

Update the function signature and add the L3 cross-check. Replace `def verify_capsule(reader, *, allowlist: list[str] | None = None) -> VerifyResult:` with:

```python
def verify_capsule(
    reader,
    *,
    allowlist: list[str] | None = None,
    outer_envelope: dict | None = None,
) -> VerifyResult:
```

Update the result init:

```python
result: VerifyResult = {
    "ok": False,
    "level": "L3" if outer_envelope is not None else "L2",
    ...
}
```

Add the L3 cross-check just before the final `result["ok"] = ...` assignment:

```python
# L3: cross-check inner envelope against the supplied outer envelope.
if outer_envelope is not None:
    if outer_envelope.get("capsule_id") != envelope.get("capsule_id"):
        errors.append("L3: inner.capsule_id does not match outer.capsule_id")
    if outer_envelope.get("first_event_hash") != envelope.get("first_event_hash"):
        errors.append("L3: inner.first_event_hash does not match outer.first_event_hash")
    if outer_envelope.get("entry_hash") != envelope.get("entry_hash"):
        errors.append("L3: inner.entry_hash does not match outer.entry_hash")
```

Update `VerifyResult` TypedDict (top of file) — `chain` field can now carry `note`. Easiest fix: change `chain: dict` (already permissive). Verify it's already typed `dict` and not the stricter `ChainResult`. If stricter, widen to `dict`.

- [ ] **Step 4: Run tests + full suite**

```sh
pytest tests/test_verifier.py -v
pytest -q
ruff check src tests
ruff format --check src tests
```
Expected: 4 new verifier tests pass; full suite green.

- [ ] **Step 5: Commit (skip — no git)**

---

## Task 6: Public surface + cross-impl parity for encrypted capsules

**Files:**
- Modify: `sdk-py/src/capsule/__init__.py`
- Modify: `sdk-py/tests/test_parity_jssdk.py`
- Modify: `sdk-py/README.md`

The existing parity tests reject `clean-encrypted.capsule` and `tampered-blob.capsule` with the v0.1 error. v0.2 lifts that — the encrypted JS fixtures must now verify cleanly, and a Python-built encrypted capsule must round-trip through the JS SDK's verifier + decrypt path.

**Public surface additions** in `__init__.py` `__all__`:
- `X25519KeyPair`
- `chacha20_poly1305_decrypt`, `chacha20_poly1305_encrypt`
- `generate_x25519`, `hkdf_sha256`, `x25519_dh`
- `random_key32`, `random_nonce12`

Plus the existing `EncryptedCapsulesNotSupportedError` stays exported (it's still a valid exception type for callers that want to handle "future encrypted formats not yet supported" — even though v0.2 doesn't raise it from any first-party path).

- [ ] **Step 1: Update `__init__.py`**

In the `from .crypto import (...)` block, add the new names:

```python
from .crypto import (
    Ed25519KeyPair,
    X25519KeyPair,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
    ed25519_sign,
    ed25519_verify,
    generate_ed25519,
    generate_x25519,
    hkdf_sha256,
    random_key32,
    random_nonce12,
    x25519_dh,
)
```

Append to `__all__` (alphabetically):

```python
"X25519KeyPair",
"chacha20_poly1305_decrypt",
"chacha20_poly1305_encrypt",
"generate_x25519",
"hkdf_sha256",
"random_key32",
"random_nonce12",
"x25519_dh",
```

Run ruff format afterwards to sort the lists if needed.

- [ ] **Step 2: Update parity tests**

In `sdk-py/tests/test_parity_jssdk.py`:

Replace `test_clean_encrypted_capsule_rejected_with_clear_message` with:

```python
def test_clean_encrypted_capsule_l2_passes(
    tamper_fixtures: pathlib.Path, js_originator_pubkey: str
):
    """The JS-built encrypted clean capsule passes Python's L2 verifier."""
    data = (tamper_fixtures / "clean-encrypted.capsule").read_bytes()
    reader = CapsuleReader.from_bytes(data)
    assert reader.is_encrypted() is True
    result = verify_capsule(reader, allowlist=[js_originator_pubkey])
    assert result["ok"] is True
    assert result["level"] == "L2"
    assert result["trusted_signer_count"] == 1
```

Replace `test_tampered_blob_capsule_rejected_with_clear_message` with:

```python
def test_tampered_blob_capsule_fails_at_encrypted_blob_hash(
    tamper_fixtures: pathlib.Path, js_originator_pubkey: str
):
    """JS-built capsule with tampered content.enc fails Python's L2."""
    data = (tamper_fixtures / "tampered-blob.capsule").read_bytes()
    reader = CapsuleReader.from_bytes(data)
    assert reader.is_encrypted() is True
    result = verify_capsule(reader, allowlist=[js_originator_pubkey])
    assert result["ok"] is False
    assert any("encrypted_blob_hash" in e for e in result["errors"])
```

Add a new test that decrypts the JS-built clean-encrypted fixture using the recipient key from `keys.json`:

```python
def test_decrypt_clean_encrypted_with_js_recipient_key(
    tamper_fixtures: pathlib.Path, js_originator_pubkey: str
):
    """Python decrypts a JS-built encrypted capsule using the JS recipient key from keys.json,
    then runs L3 verification against the outer envelope."""
    keys = json.loads((tamper_fixtures / "keys.json").read_text())
    rec = keys["recipient"]
    rec_pub = bytes.fromhex(rec["publicKey"])
    rec_priv = bytes.fromhex(rec["privateKey"])

    data = (tamper_fixtures / "clean-encrypted.capsule").read_bytes()
    outer = CapsuleReader.from_bytes(data)
    inner = outer.decrypt(recipient_public_key=rec_pub, recipient_private_key=rec_priv)

    assert inner.is_encrypted() is False
    assert "# " in inner.program()  # has at least one heading; content varies

    result = verify_capsule(
        inner,
        allowlist=[js_originator_pubkey],
        outer_envelope=outer.envelope(),
    )
    assert result["ok"] is True
    assert result["level"] == "L3"
```

Add a Python→JS encrypted round-trip test:

```python
def test_python_built_encrypted_capsule_verifies_and_decrypts_under_js_sdk(
    tmp_path: pathlib.Path,
):
    """Python builds an encrypted capsule with two recipients; JS SDK verifies + decrypts it."""
    from capsule import generate_x25519
    sk = generate_ed25519()
    r1 = generate_x25519()
    r2 = generate_x25519()
    builder = CapsuleBuilder(
        originator={"public_key": sk.public_key_hex, "label": "PythonBuilder"},
        participants=[{"actor_id": "human:py", "role": "originator", "label": "Py"}],
    )
    builder.set_program("# Python-built encrypted\n")
    builder.append_event({
        "actor": "human:py", "kind": "decision", "action": "approved",
        "target": "program.md", "timestamp": "2026-05-08T12:00:00Z",
        "payload": {"amount": 9999},
    })
    zip_bytes = builder.seal(
        signers=[{"role": "originator",
                  "public_key": sk.public_key,
                  "private_key": sk.private_key}],
        signed_at="2026-05-08T12:00:00Z",
        recipients=[r1.public_key, r2.public_key],
    )
    capsule_path = tmp_path / "py-enc.capsule"
    capsule_path.write_bytes(zip_bytes)

    sdk_dir = pathlib.Path(__file__).resolve().parents[2] / "sdk"
    if not (sdk_dir / "node_modules").exists():
        subprocess.run(
            ["npm", "install", "--no-audit", "--no-fund"], cwd=sdk_dir, check=True
        )

    # Drive the JS SDK's verifyCapsule (L2) + decrypt + verifyCapsule (L3).
    script = f"""
import {{ CapsuleReader, verifyCapsule, hexToBytes }} from "./src/index.js";
import {{ readFileSync }} from "node:fs";
const bytes = readFileSync({json.dumps(str(capsule_path))});
const outer = await CapsuleReader.fromBytes(bytes);
const allowlist = [{json.dumps(sk.public_key_hex)}];
const l2 = await verifyCapsule(outer, {{ allowlist }});
const inner = await outer.decrypt({{
  recipientPublicKey: hexToBytes({json.dumps(r2.public_key_hex)}),
  recipientPrivateKey: hexToBytes({json.dumps(r2.private_key_hex)}),
}});
const l3 = await verifyCapsule(inner, {{
  allowlist,
  outerEnvelope: outer.envelope(),
}});
process.stdout.write(JSON.stringify({{
  l2_ok: l2.ok, l2_level: l2.level, l2_trustedSignerCount: l2.trustedSignerCount,
  l2_errors: l2.errors,
  l3_ok: l3.ok, l3_level: l3.level, l3_trustedSignerCount: l3.trustedSignerCount,
  l3_errors: l3.errors,
}}));
"""
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        cwd=sdk_dir, check=False, capture_output=True, text=True,
    )
    assert proc.returncode == 0, f"node failed: {proc.stderr}"
    result = json.loads(proc.stdout)
    assert result["l2_ok"] is True and result["l2_level"] == "L2"
    assert result["l2_trustedSignerCount"] == 1
    assert result["l3_ok"] is True and result["l3_level"] == "L3"
    assert result["l3_trustedSignerCount"] == 1
    assert result["l2_errors"] == []
    assert result["l3_errors"] == []
```

Verify the existing `test_python_built_capsule_verifies_under_js_sdk` (plain) still works — it shouldn't need changes.

- [ ] **Step 3: Run tests**

```sh
cd /Users/complex/repo/virion/capsule/new-design/sdk-py
source venv/bin/activate 2>/dev/null
pytest tests/test_parity_jssdk.py -v
pytest -q  # full suite
ruff check src tests
ruff format --check src tests
```
Expected: every parity test passes (the 2 modified + 1 new + 1 new round-trip = 4 of the 7 changed; 3 plain ones unchanged); full suite green; lint+format clean.

- [ ] **Step 4: Update README**

Replace the `## Status` section in `sdk-py/README.md`:

```markdown
## Status

- **v0.1:** plain (L2) capsules — full build + read + verify.
- **v0.2 (this release):** encrypted (L3) capsules — multi-recipient
  X25519 + HKDF-SHA256 + ChaCha20-Poly1305. Python builds, reads,
  decrypts, and verifies (L2 outer + L3 inner) the same encrypted
  shape the JS SDK produces.

`EncryptedCapsulesNotSupportedError` is retained as an exported type so
caller code can still pattern-match against future, not-yet-supported
encrypted formats — but no first-party path raises it as of v0.2.
```

Replace the `## Use` example with one that shows both plain and encrypted:

````markdown
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
````

Update the `## Module map` table — change the `crypto` row's responsibility:

```markdown
| `capsule.crypto` | `sdk/src/crypto.js` | Ed25519, X25519, HKDF-SHA256, ChaCha20-Poly1305 |
```

- [ ] **Step 5: Commit (skip — no git)**

---

## Self-review checklist

- [x] **Spec coverage:** every section of `spec/envelope.md` § Encryption + § L2/L3 maps to a task. Encryption builder logic = Task 3; decryption = Task 4; L2 outer + L3 inner verifier = Task 5; cross-impl parity (both encrypted directions) = Task 6.
- [x] **No placeholders:** every step contains the actual code, exact paths, exact pytest commands, exact expected outputs.
- [x] **Type consistency:** `recipients=` is `list[bytes]` (32-byte X25519 raw pubkeys) everywhere — builder param, builder helper, parity tests. Reader's `decrypt` always takes `recipient_public_key` and `recipient_private_key` kwargs (snake_case in Python; matches `recipientPublicKey`/`recipientPrivateKey` in JS). The `decryption.json` field names — `cipher`, `content_nonce`, `key_bundles`, and within bundles `recipient_public_key`, `ephemeral_public_key`, `wrap_nonce`, `wrapped_key` — match the JS reference verbatim.
- [x] **TDD:** every task is "write failing tests → run → implement → run → commit-skip."
- [x] **EncryptedCapsulesNotSupportedError:** retained as an exported type (back-compat); no first-party path raises it after v0.2 ships. Documented in README.

## Execution

Per the user's explicit `/subagent-driven-development` invocation, execution proceeds via subagents in this session — fresh subagent per task, two-stage review (spec compliance, then code quality) after each, six tasks total.

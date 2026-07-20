"""Registry-driven conformance against spec/vectors.

These tests read the language-neutral outcome registries directly, so the
Python lane tracks the same normative expectations as the JS reference
lane (tools/check-spec-vectors.mjs) without hand-copied assertions:

  - tamper-detection/vectors.json   (verify-stage outcomes)
  - malformed-layout/vectors.json   (open-stage reasons + verify-stage)
  - signing-input.json              (byte-level signing/hashing pins)

The `reason` categories are normative; the regexes below map each
category onto this lane's error messages.
"""

from __future__ import annotations

import base64
import json
import pathlib

import pytest

from capsule import CapsuleReader, verify_capsule
from capsule.canonical import bytes_to_hex, concat_bytes, hex_to_bytes, jcs, sha256_hex
from capsule.crypto import ed25519_verify
from capsule.envelope import envelope_canonical_payload, envelope_signing_input

VECTORS = pathlib.Path(__file__).resolve().parents[2] / "spec" / "vectors"
TAMPER = VECTORS / "tamper-detection" / "vectors.json"
MALFORMED = VECTORS / "malformed-layout" / "vectors.json"
SIGNING_INPUT = VECTORS / "signing-input.json"

# Per-lane mapping of the registry's normative open-stage reason
# categories onto this SDK's error messages. Every reader error here is a
# ValueError subclass (MalformedCapsuleError, UnsafeZipPathError).
OPEN_REASON_PATTERNS = {
    "missing_required_file": r"missing (manifest\.json|provenance/envelope\.json)",
    "invalid_json": r"parse",
    "duplicate_entry": r"duplicate entry",
    "unsafe_path": r"(parent traversal|absolute)",
    "unsupported_compression": r"only STORED",
    "symlink_entry": r"symlink",
}

AREA_PREDICATES = {
    "content_index": lambda r: r["content_index"]["ok"] is False,
    "chain": lambda r: r["chain"]["ok"] is False,
    "envelope": lambda r: r["envelope"]["ok"] is False,
    "encrypted_blob": lambda r: any("encrypted_blob_hash" in e for e in r["errors"]),
}


def _load(path: pathlib.Path) -> dict:
    return json.loads(path.read_text())


def _allowlist(doc: dict, base: pathlib.Path) -> list[str]:
    if doc.get("originator_public_key_hex"):
        return [doc["originator_public_key_hex"]]
    if doc.get("keys_file"):
        keys = _load((base / doc["keys_file"]).resolve())
        return [keys["originator"]["publicKey"]]
    return []


def _collection_params(path: pathlib.Path):
    if not path.exists():
        return []
    doc = _load(path)
    return [pytest.param(doc, v, path.parent, id=v["name"]) for v in doc["vectors"]]


def _error_haystack(result: dict) -> str:
    parts = list(result["errors"])
    parts.extend(result["content_index"]["errors"])
    for e in result["chain"].get("errors", []):
        parts.append(e["message"] if isinstance(e, dict) else str(e))
    return " ".join(parts)


def _assert_verify_outcome(name: str, expected: dict, result: dict) -> None:
    assert result["ok"] is expected["ok"], f"{name}: expected ok={expected['ok']}, got {result}"
    for area in expected.get("failing", []):
        pred = AREA_PREDICATES.get(area)
        assert pred is not None, f"{name}: unknown failing area {area!r}"
        assert pred(result), f"{name}: expected area {area!r} to fail; got {result}"
    if expected.get("error_includes"):
        assert expected["error_includes"] in _error_haystack(result), (
            f"{name}: expected an error containing {expected['error_includes']!r}"
        )


@pytest.mark.parametrize("doc,vector,base", _collection_params(TAMPER))
def test_tamper_registry_outcomes(doc: dict, vector: dict, base: pathlib.Path):
    data = (base / vector["capsule_file"]).read_bytes()
    reader = CapsuleReader.from_bytes(data)
    result = verify_capsule(reader, allowlist=_allowlist(doc, base))
    _assert_verify_outcome(vector["name"], vector["expected"], result)


@pytest.mark.parametrize("doc,vector,base", _collection_params(MALFORMED))
def test_malformed_registry_outcomes(doc: dict, vector: dict, base: pathlib.Path):
    data = (base / vector["capsule_file"]).read_bytes()
    expected = vector["expected"]
    if expected.get("stage") == "open":
        pattern = OPEN_REASON_PATTERNS.get(expected["reason"])
        assert pattern is not None, f"unknown open-stage reason {expected['reason']!r}"
        with pytest.raises(ValueError, match=pattern):
            CapsuleReader.from_bytes(data)
        return
    reader = CapsuleReader.from_bytes(data)
    result = verify_capsule(reader, allowlist=_allowlist(doc, base))
    _assert_verify_outcome(vector["name"], expected, result)


def test_signing_input_pins():
    """Reproduce every byte-level pin from the capsule in capsule_ref."""
    doc = _load(SIGNING_INPUT)
    ref = _load(VECTORS / doc["meta"]["capsule_ref"])
    reader = CapsuleReader.from_bytes(base64.b64decode(ref["capsule_bytes_b64"]))
    manifest = reader.manifest()
    envelope = reader.envelope()

    # capsule_id = SHA-256(domain || originator_pub_raw || first_event_hash_raw)
    cid = doc["capsule_id"]
    assert cid["domain_utf8"].encode("utf-8").hex() == cid["domain_hex"]
    derived = sha256_hex(
        concat_bytes(
            hex_to_bytes(cid["domain_hex"]),
            hex_to_bytes(cid["originator_public_key_hex"]),
            hex_to_bytes(cid["first_event_hash_hex"]),
        )
    )
    assert derived == cid["capsule_id_hex"] == manifest["id"]
    assert cid["originator_public_key_hex"] == manifest["originator"]["public_key"]
    assert cid["first_event_hash_hex"] == manifest["first_event_hash"]

    # events: hash = SHA-256(prev_hash_raw || JCS(event minus hash))
    events = reader.events()
    assert len(events) == len(doc["events"])
    for pin, event in zip(doc["events"], events, strict=True):
        stored_hash = event["hash"]
        stripped = {k: v for k, v in event.items() if k != "hash"}
        canon = jcs(stripped)
        assert bytes_to_hex(canon) == pin["canonical_bytes_hex"], f"event {pin['seq']}"
        assert stripped["prev_hash"] == pin["prev_hash_hex"]
        recomputed = sha256_hex(concat_bytes(hex_to_bytes(pin["prev_hash_hex"]), canon))
        assert recomputed == pin["hash_hex"] == stored_hash

    # manifest_hash = SHA-256(JCS(manifest))
    manifest_canon = jcs(manifest)
    assert bytes_to_hex(manifest_canon) == doc["manifest"]["canonical_bytes_hex"]
    assert sha256_hex(manifest_canon) == doc["manifest"]["sha256_hex"]
    assert doc["manifest"]["sha256_hex"] == envelope["manifest_hash"]

    # content_index_hash = SHA-256(JCS(content_index.files))
    index_canon = jcs(manifest["content_index"]["files"])
    assert bytes_to_hex(index_canon) == doc["content_index"]["canonical_bytes_hex"]
    assert sha256_hex(index_canon) == doc["content_index"]["sha256_hex"]
    assert doc["content_index"]["sha256_hex"] == envelope["content_index_hash"]

    # envelope canonical payload + per-role signing input + signature
    env_canon = envelope_canonical_payload(envelope)
    assert bytes_to_hex(env_canon) == doc["envelope"]["canonical_payload_hex"]
    assert sha256_hex(env_canon) == doc["envelope"]["canonical_payload_sha256"]
    assert len(doc["envelope"]["signers"]) == len(envelope["signers"])
    for pin, stored in zip(doc["envelope"]["signers"], envelope["signers"], strict=True):
        assert pin["role"] == stored["role"]
        assert pin["public_key_hex"] == stored["public_key"]
        assert pin["signature_hex"] == stored["signature"]
        assert pin["domain_utf8"].encode("utf-8").hex() == pin["domain_hex"]
        signing_input = envelope_signing_input(envelope, pin["role"])
        domain_len = len(hex_to_bytes(pin["domain_hex"]))
        assert bytes_to_hex(signing_input[:domain_len]) == pin["domain_hex"]
        assert bytes_to_hex(signing_input[domain_len:]) == doc["envelope"]["canonical_payload_hex"]
        assert sha256_hex(signing_input) == pin["signing_input_sha256"]
        assert ed25519_verify(
            hex_to_bytes(pin["public_key_hex"]),
            signing_input,
            hex_to_bytes(pin["signature_hex"]),
        )

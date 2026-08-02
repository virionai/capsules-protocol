"""verify_capsule is a total function; CapsuleReader shape-checks its input.

Mirrors sdk-js/test/totality.test.js:
  - CapsuleReader.from_bytes rejects a malformed manifest at parse time
  - verify_chain reports non-canonical hex / non-object events instead of raising
  - verify_capsule converts any unexpected exception into the fail-closed result
  - an invalid envelope signature produces a displayable error
"""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from capsule.builder import CapsuleBuilder
from capsule.crypto import generate_ed25519
from capsule.reader import CapsuleReader, MalformedCapsuleError
from capsule.verifier import verify_capsule

TS = "2026-05-07T12:00:00Z"


def _sealed():
    kp = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": "Acme"},
        participants=[],
    )
    builder.set_program("# Program\n")
    builder.append_event(
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "approved",
            "target": "program.md",
            "timestamp": TS,
            "payload": {},
        }
    )
    return builder.seal(
        signers=[
            {"role": "originator", "public_key": kp.public_key, "private_key": kp.private_key}
        ],
        signed_at=TS,
    ), kp


def _repack(zip_bytes: bytes, mutate) -> bytes:
    """Rewrite every entry through `mutate(name, data) -> data | None` (None drops)."""
    buf = io.BytesIO()
    with (
        zipfile.ZipFile(io.BytesIO(zip_bytes)) as src,
        zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as dst,
    ):
        for zi in src.infolist():
            data = mutate(zi.filename, src.read(zi))
            if data is None:
                continue
            new_zi = zipfile.ZipInfo(zi.filename, date_time=(1980, 1, 1, 0, 0, 0))
            new_zi.compress_type = zipfile.ZIP_STORED
            dst.writestr(new_zi, data)
    return buf.getvalue()


def _edit_manifest(mutate):
    def _fn(name: str, data: bytes) -> bytes:
        if name != "manifest.json":
            return data
        m = json.loads(data.decode("utf-8"))
        mutate(m)
        return json.dumps(m, indent=2).encode("utf-8")

    return _fn


def _assert_fail_closed_shape(result: dict) -> None:
    assert result["ok"] is False
    assert isinstance(result["errors"], list) and result["errors"]
    assert result["chain"]["ok"] is False
    assert isinstance(result["chain"]["errors"], list)
    assert result["content_index"]["ok"] is False
    assert isinstance(result["content_index"]["errors"], list)
    assert result["envelope"]["ok"] is False
    assert result["envelope"]["signers"] == []
    assert result["signer_set"]["bound"] is False
    assert isinstance(result["signer_set"]["errors"], list)
    assert result["trusted_signer_count"] == 0
    assert isinstance(result["notes"], list)


def test_manifest_not_an_object_is_refused_at_open():
    zip_bytes, _ = _sealed()
    tampered = _repack(zip_bytes, lambda n, d: b"[]" if n == "manifest.json" else d)
    with pytest.raises(MalformedCapsuleError, match=r"manifest\.json is not a JSON object"):
        CapsuleReader.from_bytes(tampered)


def test_missing_content_index_fails_closed():
    zip_bytes, kp = _sealed()
    tampered = _repack(zip_bytes, _edit_manifest(lambda m: m.pop("content_index")))
    result = verify_capsule(tampered, allowlist=[kp.public_key_hex])
    _assert_fail_closed_shape(result)
    assert "manifest.content_index must be a JSON object" in result["errors"][0]


def test_content_index_files_not_a_list_fails_closed():
    zip_bytes, kp = _sealed()
    tampered = _repack(
        zip_bytes, _edit_manifest(lambda m: m["content_index"].__setitem__("files", {}))
    )
    result = verify_capsule(tampered, allowlist=[kp.public_key_hex])
    _assert_fail_closed_shape(result)
    assert "manifest.content_index.files must be an array" in result["errors"][0]


def test_content_index_entry_without_sha256_fails_closed():
    zip_bytes, kp = _sealed()

    def _strip(m):
        m["content_index"]["files"] = [{"path": f["path"]} for f in m["content_index"]["files"]]

    tampered = _repack(zip_bytes, _edit_manifest(_strip))
    result = verify_capsule(tampered, allowlist=[kp.public_key_hex])
    _assert_fail_closed_shape(result)
    assert "manifest.content_index.files[0].sha256" in result["errors"][0]

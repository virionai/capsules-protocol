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
from capsule.chain import verify_chain
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


def test_verify_chain_reports_non_canonical_hash():
    result = verify_chain([{"seq": 1, "prev_hash": "0" * 64, "hash": "A" * 64}])
    assert result["ok"] is False
    assert any("hash is not canonical lowercase hex" in e["message"] for e in result["errors"])


def test_verify_chain_reports_non_object_event():
    result = verify_chain(["not an event"])
    assert result["ok"] is False
    assert result["errors"] == [{"seq": 1, "message": "event is not a JSON object"}]


def test_uppercase_stored_event_hash_fails_closed():
    zip_bytes, kp = _sealed()

    def _upper(name: str, data: bytes) -> bytes:
        if name != "chain/events.jsonl":
            return data
        lines = [ln for ln in data.decode("utf-8").split("\n") if ln]
        first = json.loads(lines[0])
        first["hash"] = first["hash"].upper()
        return ("\n".join([json.dumps(first), *lines[1:]]) + "\n").encode("utf-8")

    tampered = _repack(zip_bytes, _upper)
    result = verify_capsule(tampered, allowlist=[kp.public_key_hex])
    assert result["ok"] is False
    assert result["chain"]["ok"] is False
    assert any(
        "hash is not canonical lowercase hex" in e["message"] for e in result["chain"]["errors"]
    )


def test_non_object_chain_event_fails_closed():
    zip_bytes, kp = _sealed()
    tampered = _repack(
        zip_bytes,
        lambda n, d: b'"not an event"\n' if n == "chain/events.jsonl" else d,
    )
    result = verify_capsule(tampered, allowlist=[kp.public_key_hex])
    assert result["ok"] is False
    assert result["chain"]["ok"] is False
    assert any("event is not a JSON object" in e["message"] for e in result["chain"]["errors"])


class _ManifestIsAnArrayReader:
    """A hand-built reader whose manifest is a JSON array.

    from_bytes now refuses this shape, so the only way in is a reader
    constructed by hand — which verify_capsule accepts. Without the
    total-function wrapper this raises AttributeError on manifest.get().
    """

    def manifest(self):
        return []

    def envelope(self):
        return {}

    def files(self):
        return {}

    def is_encrypted(self):
        return False


def test_unexpected_exception_becomes_fail_closed_result():
    result = verify_capsule(_ManifestIsAnArrayReader(), allowlist=[])
    _assert_fail_closed_shape(result)
    assert result["errors"][0].startswith("verification failed: AttributeError")


def test_invalid_envelope_signature_produces_a_displayable_error():
    zip_bytes, kp = _sealed()

    def _flip(name: str, data: bytes) -> bytes:
        if name != "provenance/envelope.json":
            return data
        env = json.loads(data.decode("utf-8"))
        sig = env["signers"][0]["signature"]
        env["signers"][0]["signature"] = ("1" if sig[0] == "0" else "0") + sig[1:]
        return json.dumps(env, indent=2).encode("utf-8")

    tampered = _repack(zip_bytes, _flip)
    result = verify_capsule(tampered, allowlist=[kp.public_key_hex])
    assert result["ok"] is False
    assert result["envelope"]["ok"] is False
    assert result["envelope"]["signers"][0]["valid"] is False
    assert any("envelope.signers[0] signature invalid" in e for e in result["errors"])


def test_hostile_number_in_unknown_manifest_member_fails_closed():
    # 1e999 parses as float('inf'); JCS refuses non-finite numbers, so the
    # manifest-hash recompute cannot succeed. It must report, not raise.
    zip_bytes, kp = _sealed()

    def _inject(name: str, data: bytes) -> bytes:
        if name != "manifest.json":
            return data
        text = data.decode("utf-8")
        return text.replace("{", '{"x-hostile":1e999,', 1).encode("utf-8")

    tampered = _repack(zip_bytes, _inject)
    result = verify_capsule(tampered, allowlist=[kp.public_key_hex])
    assert result["ok"] is False
    assert any("manifest hash recompute failed" in e for e in result["errors"])


def test_verify_capsule_is_total_over_a_corpus_of_malformed_inputs():
    zip_bytes, kp = _sealed()

    def _raw(name: str, payload: bytes):
        return _repack(zip_bytes, lambda n, d: payload if n == name else d)

    def _drop(name: str):
        return _repack(zip_bytes, lambda n, d: None if n == name else d)

    def _edit_env(mutate):
        def _fn(n: str, d: bytes) -> bytes:
            if n != "provenance/envelope.json":
                return d
            env = json.loads(d.decode("utf-8"))
            mutate(env)
            return json.dumps(env, indent=2).encode("utf-8")

        return _repack(zip_bytes, _fn)

    corpus = [
        # container-level garbage
        b"",
        b"PK\x03\x04",
        bytes((i * 37) % 256 for i in range(512)),
        zip_bytes[:10],
        zip_bytes[:-7],
        # valid JSON, wrong shape
        _raw("manifest.json", b"null"),
        _raw("manifest.json", b"123"),
        _raw("manifest.json", b'"str"'),
        _raw("manifest.json", b"[]"),
        _raw("manifest.json", b"{}"),
        _repack(zip_bytes, _edit_manifest(lambda m: m["content_index"].__setitem__("index_hash", 5))),
        _repack(zip_bytes, _edit_manifest(lambda m: m["content_index"].__setitem__("files", [None]))),
        _repack(
            zip_bytes,
            _edit_manifest(
                lambda m: m["content_index"].__setitem__("files", [{"path": "", "sha256": "a" * 64}])
            ),
        ),
        # hostile numbers
        _raw(
            "chain/events.jsonl",
            ('{"seq":1,"prev_hash":"' + "0" * 64 + '","x":1e999}\n').encode("utf-8"),
        ),
        # malformed chain documents
        _raw("chain/events.jsonl", b'"not an event"\n'),
        _raw("chain/events.jsonl", b"[]\n"),
        _raw(
            "chain/events.jsonl",
            ('{"seq":1,"prev_hash":"' + "Z" * 64 + '","hash":"' + "f" * 64 + '"}\n').encode("utf-8"),
        ),
        _drop("chain/events.jsonl"),
        # malformed envelope signer rows
        _edit_env(lambda env: env["signers"][0].__setitem__("public_key", None)),
        _edit_env(lambda env: env["signers"][0].__setitem__("signature", "zz")),
        _edit_env(lambda env: env.__setitem__("signers", [42])),
    ]

    for i, data in enumerate(corpus):
        result = verify_capsule(data, allowlist=[kp.public_key_hex])
        assert result["ok"] is False, f"corpus[{i}] must fail closed"
        assert isinstance(result["errors"], list), f"corpus[{i}] must report errors"

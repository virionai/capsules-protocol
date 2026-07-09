import pytest

from capsule.canonical import jcs, sha256_hex
from capsule.manifest import (
    CONTENT_INDEX_EXCLUDED,
    STRUCTURAL_EXCLUDED,
    build_content_index,
    build_manifest,
    compute_capsule_id,
    content_index_exclusions,
    manifest_bytes,
    manifest_hash,
)


def test_compute_capsule_id_known_vector():
    pub = bytes(32)
    feh = "a" * 64
    cid = compute_capsule_id(pub, feh)
    # 64-hex; deterministic
    assert isinstance(cid, str) and len(cid) == 64
    assert cid == compute_capsule_id(pub, feh)


def test_compute_capsule_id_different_pub_changes_id():
    pub_a = bytes(32)
    pub_b = b"\x01" + bytes(31)
    feh = "a" * 64
    assert compute_capsule_id(pub_a, feh) != compute_capsule_id(pub_b, feh)


def test_compute_capsule_id_rejects_bad_pubkey_length():
    with pytest.raises(ValueError):
        compute_capsule_id(b"x" * 31, "a" * 64)


def test_compute_capsule_id_rejects_bad_first_event_hash():
    with pytest.raises(ValueError):
        compute_capsule_id(bytes(32), "abc")


def test_build_content_index_sorts_and_hashes():
    files = {
        "z.txt": b"z",
        "a.txt": b"a",
        "manifest.json": b"excluded",
        "provenance/envelope.json": b"excluded",
    }
    # Default (plain profile) excludes only the structural files.
    ci = build_content_index(files)
    paths = [f["path"] for f in ci["files"]]
    assert paths == ["a.txt", "z.txt"]
    assert ci["files"][0]["sha256"] == sha256_hex(b"a")
    assert ci["files"][1]["sha256"] == sha256_hex(b"z")
    assert ci["index_hash"] == sha256_hex(jcs(ci["files"]))


def test_build_content_index_indexes_content_enc_in_plain_profile():
    # In a plain capsule a stray content.enc MUST be indexed (structural
    # exclusion only), so it cannot be smuggled past the verifier.
    files = {"a.txt": b"a", "content.enc": b"smuggled"}
    ci = build_content_index(files)
    assert [f["path"] for f in ci["files"]] == ["a.txt", "content.enc"]


def test_build_content_index_excludes_content_enc_for_encrypted_profile():
    files = {"a.txt": b"a", "content.enc": b"blob"}
    ci = build_content_index(files, CONTENT_INDEX_EXCLUDED)
    assert [f["path"] for f in ci["files"]] == ["a.txt"]


def test_content_index_excluded_sets():
    assert STRUCTURAL_EXCLUDED == {
        "manifest.json",
        "provenance/envelope.json",
    }
    assert CONTENT_INDEX_EXCLUDED == {
        "manifest.json",
        "provenance/envelope.json",
        "content.enc",
    }
    assert content_index_exclusions(False) == STRUCTURAL_EXCLUDED
    assert content_index_exclusions(True) == CONTENT_INDEX_EXCLUDED


def test_build_manifest_shape():
    ci = {"files": [], "index_hash": "0" * 64}
    m = build_manifest(
        originator={"public_key": "a" * 64, "label": "Acme"},
        participants=[],
        content_index=ci,
        first_event_hash="b" * 64,
        skill_trust={},
        encryption=None,
        created_at="2026-05-07T12:00:00Z",
    )
    assert m["format"]["version"] == "0.6"
    assert m["format"]["container"] == "zip"
    assert m["format"]["canonicalization"] == "JCS-RFC8785"
    assert m["format"]["hash_algorithm"] == "SHA-256"
    assert m["id"] == ""
    assert m["originator"] == {"public_key": "a" * 64, "label": "Acme"}
    assert m["first_event_hash"] == "b" * 64
    assert m["content_index"] is ci
    assert m["skill_trust"] == {}
    assert m["encryption"] is None
    assert m["created_at"] == "2026-05-07T12:00:00Z"


def test_manifest_hash_recomputable():
    ci = {"files": [], "index_hash": "0" * 64}
    m = build_manifest(
        originator={"public_key": "a" * 64, "label": ""},
        participants=[],
        content_index=ci,
        first_event_hash="b" * 64,
        skill_trust={},
        encryption=None,
        created_at="2026-05-07T12:00:00Z",
    )
    m["id"] = "c" * 64
    h = manifest_hash(m)
    assert h == sha256_hex(jcs(m))


def test_manifest_bytes_is_jcs():
    ci = {"files": [], "index_hash": "0" * 64}
    m = build_manifest(
        originator={"public_key": "a" * 64, "label": ""},
        participants=[],
        content_index=ci,
        first_event_hash="b" * 64,
        skill_trust={},
        encryption=None,
        created_at="2026-05-07T12:00:00Z",
    )
    m["id"] = "c" * 64
    assert manifest_bytes(m) == jcs(m)

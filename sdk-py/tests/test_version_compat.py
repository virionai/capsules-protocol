"""Version-compatibility policy (spec/versioning.md). Mirrors
sdk-js/test/version-compat.test.js.

The defect being closed: the reader raised unless manifest.format.version
and envelope.version were exactly "0.6", so a version bump would make
every capsule sealed today unopenable — not because the capsule is bad,
but because time passed. Known versions open forever under their own
era's rules; unknown versions fail closed with a diagnosis distinct from
tamper detection; the observed version is a reported fact; hosts declare
acceptance policy and the SDK reports, never decides.
"""

from __future__ import annotations

import json

import pytest

from capsule import (
    CURRENT_VERSION,
    KNOWN_VERSIONS,
    CapsuleBuilder,
    CapsuleReader,
    UnsupportedCapsuleVersionError,
    classify_version,
    compute_capsule_id,
    verify_capsule,
)
from capsule.canonical import bytes_to_hex, concat_bytes, jcs, sha256
from capsule.chain import build_chain_events, events_to_jsonl, first_and_entry_hash
from capsule.crypto import ed25519_sign, generate_ed25519
from capsule.envelope import build_envelope
from capsule.manifest import build_content_index, build_manifest, manifest_bytes, manifest_hash
from capsule.versions import SUITES, id_domain, key_wrap_info, provenance_domain
from capsule.zip_io import pack_zip

TS = "2026-05-07T12:00:00Z"


def _sealed_current_capsule():
    keys = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": keys.public_key_hex, "label": "Acme"},
        participants=[{"actor_id": "human:alice", "role": "originator", "label": "Alice"}],
        created_at=TS,
    )
    builder.set_program("# Version compat\n")
    builder.append_event(
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "submit",
            "target": "program.md",
            "timestamp": TS,
            "payload": {"summary": "submitted"},
        }
    )
    data = builder.seal(
        signers=[
            {
                "role": "originator",
                "public_key": keys.public_key,
                "private_key": keys.private_key,
            }
        ],
        signed_at=TS,
    )
    return data, keys


def _capsule_declaring_version(version: str, *, envelope_version: str | None = None) -> bytes:
    """Internally coherent under the DECLARED version's domain strings.

    Hand-rolls the domains instead of using the SDK's version-keyed
    helpers, so this test cannot be satisfied by a helper that ignores
    its version argument.
    """
    envelope_version = envelope_version or version
    keys = generate_ed25519()
    events = build_chain_events(
        [
            {
                "actor": "human:alice",
                "kind": "decision",
                "action": "submit",
                "target": "program.md",
                "timestamp": TS,
                "payload": {"summary": "submitted"},
            }
        ]
    )
    first_event_hash, entry_hash = first_and_entry_hash(events)
    files = {
        "program.md": b"# Version compat\n",
        "chain/events.jsonl": events_to_jsonl(events),
    }
    content_index = build_content_index(files)
    manifest = build_manifest(
        originator={"public_key": keys.public_key_hex, "label": "Acme"},
        participants=[{"actor_id": "human:alice", "role": "originator", "label": "Alice"}],
        content_index=content_index,
        first_event_hash=first_event_hash,
        encryption=None,
        created_at=TS,
    )
    manifest["format"]["version"] = version
    manifest["id"] = bytes_to_hex(
        sha256(
            concat_bytes(
                f"capsule-id-v{version}\x00".encode(),
                keys.public_key,
                bytes.fromhex(first_event_hash),
            )
        )
    )
    envelope = build_envelope(
        capsule_id=manifest["id"],
        first_event_hash=first_event_hash,
        entry_hash=entry_hash,
        manifest_hash=manifest_hash(manifest),
        content_index_hash=content_index["index_hash"],
        encrypted_blob_hash=None,
        cipher="none",
        signed_at=TS,
    )
    envelope["version"] = envelope_version
    payload = {k: v for k, v in envelope.items() if k != "signers"}
    signing_input = concat_bytes(
        f"capsule-provenance-v{envelope_version}:originator\x00".encode(),
        jcs(payload),
    )
    envelope["signers"].append(
        {
            "role": "originator",
            "public_key": keys.public_key_hex,
            "signature": bytes_to_hex(ed25519_sign(keys.private_key, signing_input)),
        }
    )
    all_files = dict(files)
    all_files["manifest.json"] = manifest_bytes(manifest)
    all_files["provenance/envelope.json"] = json.dumps(envelope, indent=2).encode()
    return pack_zip(all_files)


def test_sealed_current_capsule_reports_observed_version():
    data, keys = _sealed_current_capsule()
    result = verify_capsule(data, allowlist=[keys.public_key_hex])
    assert result["ok"] is True, result["errors"]
    assert result["format_version"]["observed"] == CURRENT_VERSION
    assert result["format_version"]["supported"] is True
    assert result["format_version"]["status"] == "known"
    # 0.7 adopts the v0.6 algorithm suite unchanged (spec/versioning.md).
    assert result["format_version"]["suite"] == SUITES[CURRENT_VERSION]
    assert result["format_version"]["accepted_by_policy"] is None


def test_unknown_newer_version_fails_closed_distinguishably():
    data = _capsule_declaring_version("9.9")
    with pytest.raises(UnsupportedCapsuleVersionError, match="newer than this verifier supports"):
        CapsuleReader.from_bytes(data)
    result = verify_capsule(data)
    assert result["ok"] is False
    assert result["format_version"]["observed"] == "9.9"
    assert result["format_version"]["supported"] is False
    assert result["format_version"]["status"] == "unknown_newer"
    assert any("newer than this verifier supports" in e for e in result["errors"])
    # Distinct from tamper: no hash-mismatch noise from applying the
    # wrong era's rules to a capsule we cannot understand.
    assert not any("mismatch" in e or "signature invalid" in e for e in result["errors"]), result[
        "errors"
    ]


def test_unknown_older_version_fails_closed_with_its_own_reason():
    data = _capsule_declaring_version("0.1")
    with pytest.raises(
        UnsupportedCapsuleVersionError, match="older than any version this verifier supports"
    ):
        CapsuleReader.from_bytes(data)
    result = verify_capsule(data)
    assert result["ok"] is False
    assert result["format_version"]["observed"] == "0.1"
    assert result["format_version"]["status"] == "unknown_older"


def test_non_grammar_version_is_malformed_not_a_support_gap():
    data = _capsule_declaring_version("banana")
    with pytest.raises(ValueError, match=r"^manifest\.format\.version"):
        CapsuleReader.from_bytes(data)
    result = verify_capsule(data)
    assert result["ok"] is False
    assert result["format_version"]["status"] == "invalid"
    assert result["format_version"]["observed"] == "banana"


def test_unknown_envelope_version_is_gated_identically():
    data = _capsule_declaring_version("0.6", envelope_version="9.9")
    with pytest.raises(UnsupportedCapsuleVersionError, match="envelope.version"):
        CapsuleReader.from_bytes(data)
    assert verify_capsule(data)["ok"] is False


def test_host_policy_is_reported_never_decided():
    data, keys = _sealed_current_capsule()
    accepted = verify_capsule(
        data, allowlist=[keys.public_key_hex], accept_versions=[CURRENT_VERSION]
    )
    assert accepted["ok"] is True
    assert accepted["format_version"]["accepted_by_policy"] is True

    rejected = verify_capsule(data, allowlist=[keys.public_key_hex], accept_versions=["0.6"])
    # Integrity intact: ok stays True. The verdict is REPORTED; the host
    # decides — exactly the signer-allowlist shape.
    assert rejected["ok"] is True
    assert rejected["format_version"]["accepted_by_policy"] is False
    assert any("accepted" in n for n in rejected["notes"])


def test_domain_strings_are_keyed_by_declared_version():
    assert CURRENT_VERSION in KNOWN_VERSIONS
    assert id_domain("0.6") == b"capsule-id-v0.6\x00"
    assert id_domain("0.7") == b"capsule-id-v0.7\x00"
    assert provenance_domain("0.7", "notary") == b"capsule-provenance-v0.7:notary\x00"
    assert key_wrap_info("0.7") == b"capsule-key-wrap-v0.7"
    pub = bytes([7]) * 32
    feh = "ab" * 32
    assert compute_capsule_id(pub, feh, "0.6") != compute_capsule_id(pub, feh, "0.7")
    # The default is the CURRENT sealing version.
    assert compute_capsule_id(pub, feh) == compute_capsule_id(pub, feh, CURRENT_VERSION)


def test_classify_version_vocabulary():
    assert classify_version("0.6") == {"observed": "0.6", "status": "known"}
    assert classify_version("9.9") == {"observed": "9.9", "status": "unknown_newer"}
    assert classify_version("0.1") == {"observed": "0.1", "status": "unknown_older"}
    assert classify_version("1.0") == {"observed": "1.0", "status": "unknown_newer"}
    # Numeric ordering, not lexicographic: 0.10 > 0.6.
    assert classify_version("0.10") == {"observed": "0.10", "status": "unknown_newer"}
    assert classify_version("banana") == {"observed": "banana", "status": "invalid"}
    assert classify_version("0.6.1") == {"observed": "0.6.1", "status": "invalid"}
    assert classify_version("06.1") == {"observed": "06.1", "status": "invalid"}
    assert classify_version(None) == {"observed": None, "status": "invalid"}
    assert classify_version(6) == {"observed": None, "status": "invalid"}

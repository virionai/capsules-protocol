"""Signer-set binding (manifest.signer_commitment), duplicate rejection,
distinct trusted-key counting, and originator binding.

Mirrors sdk-js/test/signer-set.test.js. Rule: PRESENCE BINDS, ABSENCE
REPORTS — a present commitment must match the signer set exactly (fail
closed); an absent one verifies at an assurance level that visibly
excludes signer-set integrity (result["signer_set"]["bound"] is False).
"""

from __future__ import annotations

import json

import pytest

from capsule import (
    CapsuleBuilder,
    CapsuleReader,
    ed25519_sign,
    envelope_signing_input,
    generate_ed25519,
    verify_capsule,
)
from capsule.canonical import bytes_to_hex, hex_to_bytes
from capsule.chain import build_chain_events, events_to_jsonl, first_and_entry_hash
from capsule.envelope import build_envelope, sign_envelope
from capsule.manifest import (
    build_content_index,
    build_manifest,
    compute_capsule_id,
    manifest_bytes,
    manifest_hash,
)
from capsule.zip_io import pack_zip, unpack_zip

TS = "2026-05-07T12:00:00Z"


def _two_signer_builder():
    originator = generate_ed25519()
    approver = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": originator.public_key_hex, "label": "Acme"},
        participants=[
            {"actor_id": "human:alice", "role": "originator", "label": "Alice"},
            {"actor_id": "human:bob", "role": "approver", "label": "Bob"},
        ],
        created_at=TS,
    )
    builder.set_program("# Loan file\n")
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
    return builder, originator, approver


def _seal_two_signers():
    builder, originator, approver = _two_signer_builder()
    data = builder.seal(
        signers=[
            {"role": "originator", "public_key": originator.public_key, "private_key": originator.private_key},
            {"role": "approver", "public_key": approver.public_key, "private_key": approver.private_key},
        ],
        signed_at=TS,
    )
    return data, originator, approver


def _rewrite_envelope(capsule_bytes: bytes, mutate) -> bytes:
    files = unpack_zip(capsule_bytes)
    env = json.loads(files["provenance/envelope.json"].decode("utf-8"))
    mutate(env)
    files["provenance/envelope.json"] = json.dumps(env, indent=2).encode("utf-8")
    return pack_zip(files)


# --- Emission ---------------------------------------------------------------


def test_seal_emits_sorted_signer_commitment():
    data, originator, approver = _seal_two_signers()
    manifest = CapsuleReader.from_bytes(data).manifest()
    commitment = manifest.get("signer_commitment")
    assert isinstance(commitment, list)
    expected = sorted(
        [
            {"role": "originator", "public_key": originator.public_key_hex},
            {"role": "approver", "public_key": approver.public_key_hex},
        ],
        key=lambda m: (m["public_key"], m["role"]),
    )
    assert commitment == expected


def test_seal_rejects_duplicate_signers():
    builder, originator, _ = _two_signer_builder()
    with pytest.raises(ValueError, match="duplicate signer"):
        builder.seal(
            signers=[
                {"role": "originator", "public_key": originator.public_key, "private_key": originator.private_key},
                {"role": "originator", "public_key": originator.public_key, "private_key": originator.private_key},
            ],
            signed_at=TS,
        )


# --- Positive control -------------------------------------------------------


def test_positive_control_bound_two_signers_verifies():
    data, originator, approver = _seal_two_signers()
    result = verify_capsule(
        CapsuleReader.from_bytes(data),
        allowlist=[originator.public_key_hex, approver.public_key_hex],
    )
    assert result["ok"] is True, result["errors"]
    assert result["signer_set"] == {"bound": True, "ok": True, "errors": []}
    assert result["trusted_signer_count"] == 2


# --- Strip / append / duplicate --------------------------------------------


def test_stripped_signer_fails_closed():
    data, originator, approver = _seal_two_signers()

    def strip(env):
        env["signers"] = [s for s in env["signers"] if s["role"] != "approver"]

    result = verify_capsule(
        CapsuleReader.from_bytes(_rewrite_envelope(data, strip)),
        allowlist=[originator.public_key_hex, approver.public_key_hex],
    )
    assert result["ok"] is False
    assert result["signer_set"]["bound"] is True
    assert result["signer_set"]["ok"] is False
    joined = " ".join(result["errors"])
    assert "signer_commitment" in joined
    assert approver.public_key_hex in joined


def test_appended_signer_in_chosen_role_fails_closed():
    data, originator, approver = _seal_two_signers()
    attacker = generate_ed25519()

    def append(env):
        message = envelope_signing_input(env, "notary")
        sig = ed25519_sign(attacker.private_key, message)
        env["signers"].append(
            {
                "role": "notary",
                "public_key": attacker.public_key_hex,
                "signature": bytes_to_hex(sig),
            }
        )

    result = verify_capsule(
        CapsuleReader.from_bytes(_rewrite_envelope(data, append)),
        allowlist=[originator.public_key_hex, approver.public_key_hex],
    )
    assert result["ok"] is False
    assert result["envelope"]["ok"] is True  # the forged signature itself verifies
    assert result["signer_set"]["ok"] is False
    assert "signer_commitment" in " ".join(result["errors"])


def test_duplicate_signer_entry_is_malformed():
    data, originator, approver = _seal_two_signers()

    def duplicate(env):
        env["signers"].append(dict(env["signers"][0]))

    result = verify_capsule(
        CapsuleReader.from_bytes(_rewrite_envelope(data, duplicate)),
        allowlist=[originator.public_key_hex, approver.public_key_hex],
    )
    assert result["ok"] is False
    assert result["envelope"]["ok"] is False
    assert "duplicate signer" in " ".join(result["errors"])
    assert result["trusted_signer_count"] <= 2


# --- Distinct-key counting --------------------------------------------------


def test_trusted_signer_count_is_distinct_keys():
    builder, originator, _ = _two_signer_builder()
    data = builder.seal(
        signers=[
            {"role": "originator", "public_key": originator.public_key, "private_key": originator.private_key},
            {"role": "notary", "public_key": originator.public_key, "private_key": originator.private_key},
        ],
        signed_at=TS,
    )
    result = verify_capsule(
        CapsuleReader.from_bytes(data), allowlist=[originator.public_key_hex]
    )
    assert result["ok"] is True, result["errors"]
    assert len(result["envelope"]["signers"]) == 2
    assert result["trusted_signer_count"] == 1


# --- Absence reports --------------------------------------------------------


def _seal_without_commitment(keys, role="originator", signer_commitment=None):
    events = build_chain_events(
        [
            {
                "actor": "human:alice",
                "kind": "decision",
                "action": "submit",
                "target": "program.md",
                "timestamp": TS,
                "payload": {},
            }
        ]
    )
    first_hash, entry_hash = first_and_entry_hash(events)
    files = {
        "program.md": b"# Program\n",
        "chain/events.jsonl": events_to_jsonl(events),
    }
    content_index = build_content_index(files)
    manifest = build_manifest(
        originator={"public_key": keys.public_key_hex, "label": "Legacy"},
        participants=[{"actor_id": "human:alice", "role": "originator", "label": "Alice"}],
        content_index=content_index,
        first_event_hash=first_hash,
        skill_trust={},
        encryption=None,
        created_at=TS,
        signer_commitment=signer_commitment,
    )
    manifest["id"] = compute_capsule_id(hex_to_bytes(keys.public_key_hex), first_hash)
    envelope = build_envelope(
        capsule_id=manifest["id"],
        first_event_hash=first_hash,
        entry_hash=entry_hash,
        manifest_hash=manifest_hash(manifest),
        content_index_hash=content_index["index_hash"],
        encrypted_blob_hash=None,
        cipher="none",
        signed_at=TS,
    )
    sign_envelope(
        envelope, [{"role": role, "public_key": keys.public_key, "private_key": keys.private_key}]
    )
    all_files = dict(files)
    all_files["manifest.json"] = manifest_bytes(manifest)
    all_files["provenance/envelope.json"] = json.dumps(envelope, indent=2).encode("utf-8")
    return pack_zip(all_files)


def test_absent_commitment_verifies_and_reports_unbound():
    keys = generate_ed25519()
    data = _seal_without_commitment(keys)
    result = verify_capsule(CapsuleReader.from_bytes(data), allowlist=[keys.public_key_hex])
    assert result["ok"] is True, result["errors"]
    assert result["signer_set"]["bound"] is False
    assert result["signer_set"]["ok"] is True
    assert "signer_commitment absent" in " ".join(result["notes"])


def test_unsorted_commitment_fails_closed():
    keys = generate_ed25519()
    other = generate_ed25519()
    members = sorted(
        [
            {"role": "originator", "public_key": keys.public_key_hex},
            {"role": "witness", "public_key": other.public_key_hex},
        ],
        key=lambda m: (m["public_key"], m["role"]),
        reverse=True,  # deliberately wrong order
    )
    events = build_chain_events(
        [
            {
                "actor": "human:alice",
                "kind": "decision",
                "action": "submit",
                "target": "program.md",
                "timestamp": TS,
                "payload": {},
            }
        ]
    )
    first_hash, entry_hash = first_and_entry_hash(events)
    files = {
        "program.md": b"# Program\n",
        "chain/events.jsonl": events_to_jsonl(events),
    }
    content_index = build_content_index(files)
    manifest = build_manifest(
        originator={"public_key": keys.public_key_hex, "label": "Acme"},
        participants=[{"actor_id": "human:alice", "role": "originator", "label": "Alice"}],
        content_index=content_index,
        first_event_hash=first_hash,
        skill_trust={},
        encryption=None,
        created_at=TS,
        signer_commitment=members,
    )
    manifest["id"] = compute_capsule_id(hex_to_bytes(keys.public_key_hex), first_hash)
    envelope = build_envelope(
        capsule_id=manifest["id"],
        first_event_hash=first_hash,
        entry_hash=entry_hash,
        manifest_hash=manifest_hash(manifest),
        content_index_hash=content_index["index_hash"],
        encrypted_blob_hash=None,
        cipher="none",
        signed_at=TS,
    )
    sign_envelope(
        envelope,
        [
            {"role": "originator", "public_key": keys.public_key, "private_key": keys.private_key},
            {"role": "witness", "public_key": other.public_key, "private_key": other.private_key},
        ],
    )
    all_files = dict(files)
    all_files["manifest.json"] = manifest_bytes(manifest)
    all_files["provenance/envelope.json"] = json.dumps(envelope, indent=2).encode("utf-8")
    result = verify_capsule(
        CapsuleReader.from_bytes(pack_zip(all_files)), allowlist=[keys.public_key_hex]
    )
    assert result["ok"] is False
    assert result["signer_set"]["ok"] is False
    assert "sorted" in " ".join(result["errors"])


# --- Originator binding -----------------------------------------------------


def test_originator_never_signed_as_originator_fails_closed():
    keys = generate_ed25519()
    data = _seal_without_commitment(keys, role="creator")
    result = verify_capsule(CapsuleReader.from_bytes(data), allowlist=[keys.public_key_hex])
    assert result["ok"] is False
    assert "originator binding" in " ".join(result["errors"])


def test_originator_role_signed_by_different_key_fails_closed():
    builder, originator, _ = _two_signer_builder()
    impostor = generate_ed25519()
    data = builder.seal(
        signers=[
            {"role": "originator", "public_key": impostor.public_key, "private_key": impostor.private_key}
        ],
        signed_at=TS,
    )
    result = verify_capsule(
        CapsuleReader.from_bytes(data),
        allowlist=[originator.public_key_hex, impostor.public_key_hex],
    )
    assert result["ok"] is False
    assert "originator binding" in " ".join(result["errors"])

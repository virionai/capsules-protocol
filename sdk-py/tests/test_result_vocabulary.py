"""Normalized result vocabulary (spec/results.md). Mirrors sdk-js/test/result-vocabulary.test.js.

Policy under test:
  1. Every result carries verdict / verdict_reason / qualifiers, with
     ok == (verdict == "valid") as an invariant.
  2. "unsupported" partitions refusals that are a limitation of THIS
     verifier (unknown version — both directions — and unsupported
     profile); verdict_reason is non-null iff verdict is "unsupported".
  3. qualifiers restate the weaker-claim facts of a VALID verdict in the
     spec-defined order, each a pure derivation of an already-reported
     fact; empty on invalid/unsupported.
  4. The two trust qualifiers are host-relative and mutually exclusive;
     encrypted_outer_only is per-result (never on the inner L3 result);
     version_not_accepted_by_policy exists only when the host declared a
     policy.
  5. The canonical advisory notes back the qualifiers byte-for-byte —
     the wording is the cross-lane contract, not a lane's phrasing.
"""

from __future__ import annotations

import json

from capsule import CapsuleBuilder, CapsuleReader, verify_capsule
from capsule.canonical import jcs
from capsule.crypto import generate_ed25519, generate_x25519
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


def _sealed_capsule():
    """The strongest honest shape the builder emits: committed and bound."""
    keys = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": keys.public_key_hex, "label": "Acme"},
        participants=[{"actor_id": "human:alice", "role": "originator", "label": "Alice"}],
        created_at=TS,
    )
    builder.set_program("# Result vocabulary\n")
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
    return builder.seal(signers=keys, signed_at=TS), keys


def _weakest_honest_capsule():
    """Zero events, no signer_commitment, no participants.

    Every one of those is a weaker claim made HONESTLY — the capsule
    verifies, and each reduced assurance must reach the verdict as a
    qualifier. The SDK builder always commits, so the shape is
    hand-rolled.
    """
    keys = generate_ed25519()
    files = {"program.md": b"# Weakest honest shape\n", "chain/events.jsonl": b""}
    content_index = build_content_index(files)
    manifest = build_manifest(
        originator={"public_key": keys.public_key_hex, "label": "Acme"},
        participants=[],
        content_index=content_index,
        first_event_hash=None,
        encryption=None,
        created_at=TS,
    )
    manifest["id"] = compute_capsule_id(keys.public_key, None)
    envelope = build_envelope(
        capsule_id=manifest["id"],
        first_event_hash=None,
        entry_hash=None,
        manifest_hash=manifest_hash(manifest),
        content_index_hash=content_index["index_hash"],
        encrypted_blob_hash=None,
        cipher="none",
        signed_at=TS,
    )
    sign_envelope(
        envelope,
        [
            {
                "role": "originator",
                "public_key": keys.public_key,
                "private_key": keys.private_key,
            }
        ],
    )
    packed = dict(files)
    packed["manifest.json"] = manifest_bytes(manifest)
    packed["provenance/envelope.json"] = json.dumps(envelope, indent=2).encode("utf-8")
    return pack_zip(packed), keys


def test_unqualified_valid_has_an_empty_qualifiers_array():
    data, keys = _sealed_capsule()
    result = verify_capsule(data, allowlist=[keys.public_key_hex])
    assert result["ok"] is True, result["errors"]
    assert result["verdict"] == "valid"
    assert result["verdict_reason"] is None
    # The strongest honest shape: committed signer set, bound actors,
    # walked chain, matching allowlist. Nothing to qualify.
    assert result["qualifiers"] == []


def test_ok_equals_verdict_valid_across_outcome_classes():
    valid, keys = _sealed_capsule()
    outcomes = [
        verify_capsule(valid, allowlist=[keys.public_key_hex]),
        verify_capsule(b"this is not a capsule"),
        verify_capsule(_tampered(valid), allowlist=[keys.public_key_hex]),
    ]
    for result in outcomes:
        assert (result["verdict"] == "valid") is result["ok"], result
        assert (result["verdict_reason"] is not None) == (result["verdict"] == "unsupported")
        assert result["verdict"] == "valid" or result["qualifiers"] == []


def _tampered(data: bytes) -> bytes:
    files = unpack_zip(data)
    files["program.md"] = b"# Rewritten after the seal\n"
    return pack_zip(files)


def test_maximally_qualified_valid_reaches_the_verdict_in_order():
    data, _keys = _weakest_honest_capsule()
    result = verify_capsule(data, allowlist=[])
    assert result["ok"] is True, result["errors"]
    assert result["verdict"] == "valid"
    # Spec-defined emission order (spec/results.md). A host that says
    # just "verified" about this capsule is the failure mode the
    # vocabulary exists to kill.
    assert result["qualifiers"] == [
        "signer_set_unbound",
        "actor_set_unbound",
        "empty_chain_not_walked",
        "trust_not_evaluated",
    ]
    notes = " ".join(result["notes"])
    # The canonical note strings, byte-for-byte (spec/results.md).
    assert "manifest.signer_commitment absent: the signer set is not bound by the seal" in notes
    assert (
        "manifest.participants empty: chain actors are not bound to a declared participant set"
        in notes
    )
    assert "empty chain: no events to walk; envelope anchors checked to be null instead" in notes
    assert (
        "no allowlist provided; trusted=false for all signers regardless of signature validity"
        in notes
    )


def test_trust_qualifiers_are_host_relative_and_mutually_exclusive():
    data, keys = _sealed_capsule()
    stranger = generate_ed25519()

    no_policy = verify_capsule(data, allowlist=[])
    assert no_policy["qualifiers"] == ["trust_not_evaluated"]
    assert any("no allowlist" in n for n in no_policy["notes"])

    no_match = verify_capsule(data, allowlist=[stranger.public_key_hex])
    # Valid math, zero trusted signers: a PASS that must never be silent
    # about why trusted=false everywhere.
    assert no_match["ok"] is True, no_match["errors"]
    assert no_match["qualifiers"] == ["no_trusted_signer"]
    assert (
        "allowlist provided but matched no signer; trusted=false for all signers"
        in no_match["notes"]
    )

    matched = verify_capsule(data, allowlist=[keys.public_key_hex])
    assert matched["qualifiers"] == []


def test_version_not_accepted_by_policy_exists_only_when_the_host_declared_one():
    data, keys = _sealed_capsule()
    silent = verify_capsule(data, allowlist=[keys.public_key_hex])
    assert "version_not_accepted_by_policy" not in silent["qualifiers"]
    assert silent["format_version"]["accepted_by_policy"] is None

    excluded = verify_capsule(
        data, allowlist=[keys.public_key_hex], accept_versions=["0.6"]
    )
    # Integrity is intact — the SDK reports, the host decides — and the
    # policy verdict is a qualifier a renderer must not hide.
    assert excluded["ok"] is True, excluded["errors"]
    assert excluded["qualifiers"] == ["version_not_accepted_by_policy"]
    assert any("not in the declared accepted set" in n for n in excluded["notes"])


def test_encrypted_outer_only_is_per_result_never_on_the_inner_l3():
    keys = generate_ed25519()
    recipient = generate_x25519()
    builder = CapsuleBuilder(
        originator={"public_key": keys.public_key_hex, "label": "Acme"},
        participants=[{"actor_id": "human:alice", "role": "originator", "label": "Alice"}],
        created_at=TS,
    )
    builder.set_program("# Encrypted scope\n")
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
    data = builder.seal(signers=keys, recipients=[recipient], signed_at=TS)
    reader = CapsuleReader.from_bytes(data)
    outer = verify_capsule(reader, allowlist=[keys.public_key_hex])
    assert outer["ok"] is True, outer["errors"]
    assert outer["level"] == "L2"
    # The seal is verified, the content unread, the chain deferred — a
    # scope fact the verdict must carry.
    assert outer["qualifiers"] == ["encrypted_outer_only"]

    inner = reader.decrypt(recipient)
    inner_result = verify_capsule(
        inner, allowlist=[keys.public_key_hex], outer_envelope=reader.envelope()
    )
    assert inner_result["ok"] is True, inner_result["errors"]
    assert inner_result["level"] == "L3"
    assert "encrypted_outer_only" not in inner_result["qualifiers"]


def test_unsupported_carries_a_machine_readable_reason_in_both_directions():
    for declared, reason in (("9.9", "unsupported_version_newer"), ("0.1", "unsupported_version_older")):
        data, _keys = _sealed_capsule()
        files = unpack_zip(data)
        manifest = json.loads(files["manifest.json"])
        manifest["format"]["version"] = declared
        files["manifest.json"] = jcs(manifest)
        result = verify_capsule(pack_zip(files))
        # The capsule is not corrupt to a verifier that knows the era:
        # the refusal names THIS verifier's limitation, at the normalized
        # surface (no substring matching on lane-specific errors).
        assert result["verdict"] == "unsupported"
        assert result["verdict_reason"] == reason
        assert result["qualifiers"] == []
        assert result["format_version"]["observed"] == declared


def test_invalid_carries_no_reason_and_no_qualifiers():
    data, keys = _sealed_capsule()
    tampered = verify_capsule(_tampered(data), allowlist=[keys.public_key_hex])
    assert tampered["ok"] is False
    assert tampered["verdict"] == "invalid"
    assert tampered["verdict_reason"] is None
    assert tampered["qualifiers"] == []

    garbage = verify_capsule(b"this is not a capsule")
    assert garbage["verdict"] == "invalid"
    assert garbage["verdict_reason"] is None
    assert garbage["qualifiers"] == []
    # The fail-closed result still carries every channel.
    assert garbage["profile"]["status"] == "unread"
    assert garbage["format_version"]["status"] == "unread"

"""Profile declaration policy (spec/profiles.md). Mirrors sdk-js/test/profile-declaration.test.js.

Policy under test:
  1. ABSENCE of a declaration means the default profile v0.6-suite/1.0,
     permanently; explicit declaration of the default is legal and
     exactly equivalent — in both documents or, via normalization, one.
  2. A declared (id, version) outside the table refuses at OPEN with
     unsupported_profile — a limitation of the verifier, never a defect
     of the capsule — and the refusal is EXCLUSIVE: the profile
     diagnosis is the only error, every other channel fail-closed,
     format_version.suite nulled (no suite fact for refused rules).
  3. Disagreeing normalized declarations refuse with profile_mismatch
     BEFORE any table lookup (a capsule defect: verdict "invalid").
  4. Shape/grammar violations are MALFORMED documents, never
     "unsupported".
  5. The version gate runs FIRST: unknown-version capsules report the
     declaration with profile.status "unevaluated".
  6. Only the reserved members have force (x- members inert), and the
     declaration is sealed bytes (stripping it post-seal is tamper).
  7. accept_profiles is host policy: reported, never decided.
"""

from __future__ import annotations

import json

import pytest

from capsule import (
    DEFAULT_PROFILE,
    SUPPORTED_PROFILES,
    CapsuleBuilder,
    CapsuleReader,
    InvalidProfileError,
    ProfileMismatchError,
    UnsupportedProfileError,
    classify_profile,
    is_valid_profile_id,
    verify_capsule,
)
from capsule.canonical import bytes_to_hex, concat_bytes, hex_to_bytes, jcs, sha256
from capsule.chain import build_chain_events, events_to_jsonl, first_and_entry_hash
from capsule.crypto import ed25519_sign, generate_ed25519, generate_x25519
from capsule.envelope import build_envelope
from capsule.manifest import build_content_index, build_manifest, manifest_bytes, manifest_hash
from capsule.profiles import ABSENT
from capsule.zip_io import pack_zip, unpack_zip

TS = "2026-05-07T12:00:00Z"
DEFAULT_DECL = {"id": "v0.6-suite", "version": "1.0"}
VENDOR_DECL = {"id": "x-test-kms-1", "version": "1.0"}


def _capsule_declaring_profile(
    *,
    version: str = "0.7",
    manifest_profile=ABSENT,
    envelope_profile=ABSENT,
    extra_manifest_members: dict | None = None,
):
    """A capsule internally coherent under its declared version's DEFAULT rules.

    Only the declaration under test is unusual, so nothing but the
    profile gate can refuse it — the same construction the conformance
    fixtures use. Domains are hand-rolled so the test pins the spec's
    strings rather than the SDK helpers.
    """
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
        "program.md": b"# Profile declaration\n",
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
    if manifest_profile is not ABSENT:
        manifest["format"]["profile"] = manifest_profile
    if extra_manifest_members:
        manifest.update(extra_manifest_members)
    manifest["id"] = bytes_to_hex(
        sha256(
            concat_bytes(
                f"capsule-id-v{version}\x00".encode(),
                keys.public_key,
                hex_to_bytes(first_event_hash),
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
    envelope["version"] = version
    if envelope_profile is not ABSENT:
        envelope["profile"] = envelope_profile
    payload = {k: v for k, v in envelope.items() if k != "signers"}
    signing_input = concat_bytes(
        f"capsule-provenance-v{version}:originator\x00".encode(), jcs(payload)
    )
    envelope["signers"].append(
        {
            "role": "originator",
            "public_key": keys.public_key_hex,
            "signature": bytes_to_hex(ed25519_sign(keys.private_key, signing_input)),
        }
    )
    packed = dict(files)
    packed["manifest.json"] = manifest_bytes(manifest)
    packed["provenance/envelope.json"] = json.dumps(envelope, indent=2).encode("utf-8")
    return pack_zip(packed), keys


def test_default_table_row_is_the_frozen_default_profile_pin():
    # Frozen forever: the absence rule makes this spelling permanent.
    assert DEFAULT_PROFILE == {"id": "v0.6-suite", "version": "1.0"}
    assert DEFAULT_PROFILE in SUPPORTED_PROFILES


def test_absence_means_the_default_profile_reported_as_an_effective_fact():
    data, keys = _capsule_declaring_profile()
    result = verify_capsule(data, allowlist=[keys.public_key_hex])
    assert result["ok"] is True, result["errors"]
    # The absence rule made machine-visible: the result SAYS what absence
    # meant rather than leaving it folklore.
    assert result["profile"] == {
        "observed": None,
        "observed_version": None,
        "declared": False,
        "effective": "v0.6-suite",
        "effective_version": "1.0",
        "supported": True,
        "status": "default",
        "accepted_by_policy": None,
    }
    assert result["format_version"]["suite"] == "v0.6"


def test_explicit_default_in_both_documents_is_equivalent_to_absence():
    data, keys = _capsule_declaring_profile(
        manifest_profile=DEFAULT_DECL, envelope_profile=DEFAULT_DECL
    )
    result = verify_capsule(data, allowlist=[keys.public_key_hex])
    assert result["ok"] is True, result["errors"]
    assert result["profile"]["declared"] is True
    assert result["profile"]["status"] == "default"
    assert result["profile"]["effective"] == "v0.6-suite"


def test_explicit_default_in_one_document_normalizes_coherently():
    # Absence means the default, so both readings agree: a truthful
    # statement in one document is not a mismatch.
    data, keys = _capsule_declaring_profile(manifest_profile=DEFAULT_DECL)
    result = verify_capsule(data, allowlist=[keys.public_key_hex])
    assert result["ok"] is True, result["errors"]
    assert result["profile"]["status"] == "default"


def test_unsupported_profile_refuses_at_open_as_a_verifier_limitation():
    data, keys = _capsule_declaring_profile(
        manifest_profile=VENDOR_DECL, envelope_profile=VENDOR_DECL
    )
    with pytest.raises(UnsupportedProfileError) as excinfo:
        CapsuleReader.from_bytes(data)
    message = str(excinfo.value)
    # The cross-lane needles: an operator must be able to route the
    # capsule instead of declaring it corrupt.
    assert "profile 'x-test-kms-1' version '1.0' is not supported by this verifier" in message
    assert (
        "this is a limitation of the verifier, not corruption of the capsule — "
        "verify it with an implementation of that profile" in message
    )

    result = verify_capsule(data, allowlist=[keys.public_key_hex])
    assert result["ok"] is False
    assert result["verdict"] == "unsupported"
    assert result["verdict_reason"] == "unsupported_profile"
    assert result["qualifiers"] == []
    assert result["profile"]["status"] == "unsupported"
    assert result["profile"]["observed"] == "x-test-kms-1"
    assert result["profile"]["observed_version"] == "1.0"
    assert result["profile"]["effective"] is None
    # Suite honesty: reporting v0.6 about rules this verifier refused
    # would be a false fact.
    assert result["format_version"]["suite"] is None
    # Refusal exclusivity: no channel is evaluated under refused rules.
    assert result["signer_set"] == {"bound": False, "ok": False, "errors": []}
    assert result["skill_trust"] == {"capsule_signed": False, "skills": {}}
    assert result["trusted_signer_count"] == 0


def test_exact_match_on_the_id_version_pair():
    # A known id with an unknown version is not understood, period —
    # partial recognition is the wrong-rules hazard the gate kills.
    decl = {"id": "v0.6-suite", "version": "9.9"}
    data, _keys = _capsule_declaring_profile(manifest_profile=decl, envelope_profile=decl)
    result = verify_capsule(data)
    assert result["verdict_reason"] == "unsupported_profile"
    assert result["profile"]["observed_version"] == "9.9"


def test_the_gate_is_era_keyed_not_a_hardcoded_0_7_check():
    data, _keys = _capsule_declaring_profile(
        version="0.6", manifest_profile=VENDOR_DECL, envelope_profile=VENDOR_DECL
    )
    result = verify_capsule(data)
    assert result["verdict"] == "unsupported"
    assert result["verdict_reason"] == "unsupported_profile"
    assert result["format_version"]["observed"] == "0.6"
    assert result["format_version"]["suite"] is None


def test_mismatched_declarations_refuse_before_table_lookup_as_a_capsule_defect():
    data, _keys = _capsule_declaring_profile(
        manifest_profile=VENDOR_DECL, envelope_profile=DEFAULT_DECL
    )
    with pytest.raises(ProfileMismatchError) as excinfo:
        CapsuleReader.from_bytes(data)
    message = str(excinfo.value)
    assert "envelope.profile does not match manifest.format.profile" in message
    assert "'x-test-kms-1' version '1.0'" in message
    assert "'v0.6-suite' version '1.0'" in message

    result = verify_capsule(data)
    # A self-contradiction is a DEFECT, so verdict "invalid" and no
    # verdict_reason — "unsupported" would hand the auditor a false
    # remediation ("find a better verifier" for a broken capsule).
    assert result["verdict"] == "invalid"
    assert result["verdict_reason"] is None
    assert result["profile"]["status"] == "mismatched"
    assert result["format_version"]["suite"] is None


def test_presence_mismatch_is_the_same_defect():
    data, _keys = _capsule_declaring_profile(manifest_profile=VENDOR_DECL)
    with pytest.raises(ProfileMismatchError):
        CapsuleReader.from_bytes(data)
    assert verify_capsule(data)["profile"]["status"] == "mismatched"


@pytest.mark.parametrize(
    "manifest_profile,envelope_profile,needle",
    [
        (None, ABSENT, "manifest.format.profile must be an object"),
        ("v0.6-suite", ABSENT, "manifest.format.profile must be an object"),
        ({"id": "Acme KMS!", "version": "1.0"}, ABSENT, "manifest.format.profile.id"),
        (
            {"id": "v0.6-suite", "version": "1.0", "critical": ["id"]},
            ABSENT,
            "manifest.format.profile.critical is not a member of the closed profile object",
        ),
        (
            DEFAULT_DECL,
            {"id": "v0.6-suite", "version": "1.0", "params": {"issuer": "acme"}},
            "envelope.profile.params is not allowed",
        ),
    ],
    ids=["null", "not-object", "id-grammar", "closed-object", "envelope-params"],
)
def test_shape_violations_are_malformed_documents_never_unsupported(
    manifest_profile, envelope_profile, needle
):
    data, _keys = _capsule_declaring_profile(
        manifest_profile=manifest_profile, envelope_profile=envelope_profile
    )
    with pytest.raises(InvalidProfileError) as excinfo:
        CapsuleReader.from_bytes(data)
    message = str(excinfo.value)
    assert needle in message
    # Malformed is a defect of the capsule; unsupported is a limitation
    # of the verifier. Three facts, three remediations, kept distinct.
    assert "unsupported" not in message
    result = verify_capsule(data)
    assert result["verdict"] == "invalid"
    assert result["verdict_reason"] is None
    assert result["profile"]["status"] == "invalid"


def test_params_in_the_manifest_are_legal_on_a_well_formed_declaration():
    data, keys = _capsule_declaring_profile(
        manifest_profile={
            "id": "v0.6-suite",
            "version": "1.0",
            "params": {"issuer": "https://capsules.acme.example"},
        },
        envelope_profile=DEFAULT_DECL,
    )
    result = verify_capsule(data, allowlist=[keys.public_key_hex])
    assert result["ok"] is True, result["errors"]
    assert result["profile"]["status"] == "default"


def test_gate_ordering_version_first_declaration_reported_unevaluated():
    data, _keys = _capsule_declaring_profile(
        version="9.9", manifest_profile=VENDOR_DECL, envelope_profile=VENDOR_DECL
    )
    result = verify_capsule(data)
    # The version diagnosis is the ONLY error: profile semantics are
    # era-scoped, so an unknown era means the declaration cannot even be
    # classified — but it is still reported.
    assert result["verdict_reason"] == "unsupported_version_newer"
    assert result["profile"]["status"] == "unevaluated"
    assert result["profile"]["observed"] == "x-test-kms-1"
    assert result["profile"]["declared"] is True


def test_an_x_manifest_member_named_like_a_profile_is_inert():
    data, keys = _capsule_declaring_profile(
        extra_manifest_members={"x-test-profile": {"id": "x-test-kms-1", "version": "1.0"}}
    )
    result = verify_capsule(data, allowlist=[keys.public_key_hex])
    assert result["ok"] is True, result["errors"]
    assert result["profile"]["declared"] is False
    assert result["profile"]["status"] == "default"


def test_declarations_are_sealed_bytes_stripping_one_post_seal_is_tamper():
    data, keys = _capsule_declaring_profile(
        manifest_profile=DEFAULT_DECL, envelope_profile=DEFAULT_DECL
    )
    files = unpack_zip(data)
    manifest = json.loads(files["manifest.json"])
    del manifest["format"]["profile"]
    files["manifest.json"] = jcs(manifest)
    result = verify_capsule(pack_zip(files), allowlist=[keys.public_key_hex])
    assert result["ok"] is False
    assert any("manifest_hash" in e for e in result["errors"]), result["errors"]


def test_accept_profiles_is_host_policy_reported_never_decided():
    data, keys = _capsule_declaring_profile()
    accepted = verify_capsule(
        data, allowlist=[keys.public_key_hex], accept_profiles=["v0.6-suite"]
    )
    assert accepted["ok"] is True
    assert accepted["profile"]["accepted_by_policy"] is True

    rejected = verify_capsule(
        data, allowlist=[keys.public_key_hex], accept_profiles=["x-acme-kms-es256"]
    )
    assert rejected["ok"] is True, "policy never fails an otherwise-valid capsule"
    assert rejected["profile"]["accepted_by_policy"] is False
    assert any("not in the declared accepted set" in n for n in rejected["notes"]), rejected["notes"]


def test_the_l3_inner_capsule_is_gated_independently():
    # Both layers are default-profile; the inner reader construction
    # inside decrypt() runs the same open-stage gate — pinned here by the
    # happy path (no inner/outer equality rule exists).
    keys = generate_ed25519()
    recipient = generate_x25519()
    builder = CapsuleBuilder(
        originator={"public_key": keys.public_key_hex, "label": "Acme"},
        participants=[{"actor_id": "human:alice", "role": "originator", "label": "Alice"}],
        created_at=TS,
    )
    builder.set_program("# Encrypted profile gate\n")
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
    assert outer["profile"]["status"] == "default"
    inner = reader.decrypt(recipient)
    inner_result = verify_capsule(
        inner, allowlist=[keys.public_key_hex], outer_envelope=reader.envelope()
    )
    assert inner_result["ok"] is True, inner_result["errors"]
    assert inner_result["profile"]["status"] == "default"


@pytest.mark.parametrize(
    "value,expected",
    [
        ("v0.6-suite", True),
        ("x-acme-kms-es256", True),
        ("a", True),
        ("a" * 64, True),
        ("a" * 65, False),  # cap is 64 bytes
        ("Acme", False),  # lowercase only
        ("0abc", False),  # first byte is a letter
        ("abc-", False),  # no trailing dash
        ("abc.", False),  # no trailing dot
        ("x-acme", False),  # x- ids are vendor-scoped x-<vendor>-<name>
        ("", False),
        (None, False),
    ],
)
def test_identifier_grammar_bounds_charset_and_the_vendor_fence(value, expected):
    assert is_valid_profile_id(value) is expected


@pytest.mark.parametrize(
    "manifest_decl,envelope_decl,status",
    [
        (ABSENT, ABSENT, "default"),
        (DEFAULT_DECL, ABSENT, "default"),
        (ABSENT, DEFAULT_DECL, "default"),
        (DEFAULT_DECL, DEFAULT_DECL, "default"),
        (VENDOR_DECL, VENDOR_DECL, "unsupported"),
        (VENDOR_DECL, DEFAULT_DECL, "mismatched"),
        (VENDOR_DECL, ABSENT, "mismatched"),
        (None, ABSENT, "invalid"),
        ({"id": "x-a-b", "version": "1.0"}, {"id": "x-a-b", "version": "2.0"}, "mismatched"),
    ],
)
def test_classify_profile_closed_status_vocabulary_over_the_dyad(
    manifest_decl, envelope_decl, status
):
    assert classify_profile(manifest_decl, envelope_decl)["status"] == status

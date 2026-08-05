"""Rewrap writer obligations (spec/lineage.md "Continuing a capsule", W1-W9).

Entry derivation, carry/reset policy, the pinned custody event, refusals
and the loud override, reproducibility, re-rewrap, laundering
equivalence, encrypted successors, and the explicit-values declaration
path. Test ids T1-T10 mirror sdk-js/test/rewrap.test.js; P1 is the
cross-lane fixture-parity check this lane owns.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from capsule import (
    CapsuleBuilder,
    CapsuleReader,
    PredecessorError,
    compute_capsule_id,
    derive_predecessor_entry,
    generate_ed25519,
    generate_x25519,
    manifest_hash,
    rewrap_capsule,
    sha256_hex,
    verify_capsule,
)
from capsule.canonical import hex_to_bytes
from capsule.zip_io import pack_zip, unpack_zip

TS = "2026-05-07T12:00:00Z"
LATER = "2026-05-07T13:00:00Z"

LINEAGE_VECTORS = (
    pathlib.Path(__file__).resolve().parents[2] / "spec" / "vectors" / "lineage" / "output"
)


def _alice_builder(alice) -> CapsuleBuilder:
    builder = CapsuleBuilder(
        originator={"public_key": alice.public_key_hex, "label": "Alice"},
        participants=[
            {"actor_id": "human:alice", "role": "originator"},
            {"actor_id": "ai:assistant", "role": "advisor"},
        ],
        created_at=TS,
    )
    builder.set_program("# Loan Review\n\nStep one complete.\n")
    builder.set_agents("# Agents\n- human:alice\n")
    builder.add_payload("payload/evidence.csv", b"k,v\nrate,0.07\n")
    builder.add_skill("review", json={"name": "review"}, markdown="# Review skill\n")
    builder.append_event(
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "approved",
            "target": "program.md",
            "timestamp": TS,
            "payload": {"note": "approved step one"},
        }
    )
    builder.append_event(
        {
            "actor": "ai:assistant",
            "kind": "observation",
            "action": "summarized",
            "target": "program.md",
            "timestamp": TS,
            "payload": {"note": "summary recorded"},
        }
    )
    return builder


def _sealed_alice(alice) -> bytes:
    return _alice_builder(alice).seal(
        signers=[
            {
                "role": "originator",
                "public_key": alice.public_key,
                "private_key": alice.private_key,
            }
        ],
        signed_at=TS,
    )


def _bob_originator(bob) -> dict:
    return {
        "public_key": bob.public_key_hex,
        "private_key": bob.private_key_hex,
        "label": "Bob",
    }


def _tampered_copy(data: bytes) -> bytes:
    files = unpack_zip(data)
    program = bytearray(files["program.md"])
    program[0] ^= 0x01
    files["program.md"] = bytes(program)
    return pack_zip(files)


def test_t1_entry_derivation_recomputes_and_never_copies_the_envelope_claim():
    alice = generate_ed25519()
    bob = generate_ed25519()
    data = _sealed_alice(alice)
    reader = CapsuleReader.from_bytes(data)
    entry = derive_predecessor_entry(reader)
    manifest = reader.manifest()
    envelope = reader.envelope()
    assert entry == {
        "capsule_id": compute_capsule_id(
            hex_to_bytes(manifest["originator"]["public_key"]),
            manifest["first_event_hash"],
            "0.7",
        ),
        "format_version": "0.7",
        "originator_public_key": alice.public_key_hex,
        "first_event_hash": manifest["first_event_hash"],
        "entry_hash": envelope["entry_hash"],
        "manifest_hash": manifest_hash(manifest),
    }
    # W1: recomputed from the stored manifest, never copied from the
    # envelope's claim — poison the claim and the derivation is unmoved.
    files = unpack_zip(data)
    env = json.loads(files["provenance/envelope.json"])
    env["manifest_hash"] = "f" * 64
    files["provenance/envelope.json"] = json.dumps(env, indent=2).encode("utf-8")
    poisoned = CapsuleReader.from_files(files)
    assert derive_predecessor_entry(poisoned)["manifest_hash"] == entry["manifest_hash"]
    assert derive_predecessor_entry(poisoned)["manifest_hash"] != env["manifest_hash"]
    # The same derivation continue_from performs.
    wrap = rewrap_capsule(data, originator=_bob_originator(bob), created_at=LATER, signed_at=LATER)
    assert wrap["predecessor_entry"] == entry


def test_t2_carry_and_reset_files_travel_byte_identically_claims_do_not():
    alice = generate_ed25519()
    bob = generate_ed25519()
    pred_bytes = _sealed_alice(alice)
    pred_files = unpack_zip(pred_bytes)
    wrap = rewrap_capsule(
        pred_bytes,
        originator=_bob_originator(bob),
        participants=[{"actor_id": "human:bob", "role": "custodian"}],
        created_at=LATER,
        signed_at=LATER,
    )
    successor = CapsuleReader.from_bytes(wrap["bytes"])
    succ_files = successor.files()
    assert wrap["carried_paths"] == [
        "agents.md",
        "payload/evidence.csv",
        "program.md",
        "skills/review/SKILL.md",
        "skills/review/skill.json",
    ]
    for path in wrap["carried_paths"]:
        assert sha256_hex(succ_files[path]) == sha256_hex(pred_files[path]), path
    # Claims reset: fresh chain; the successor manifest carries the
    # CALLER's participants, its own signer_commitment, and no echo of
    # the predecessor's claims.
    manifest = successor.manifest()
    assert manifest["participants"] == [{"actor_id": "human:bob", "role": "custodian"}]
    assert manifest["created_at"] == LATER
    assert manifest["originator"]["public_key"] == bob.public_key_hex
    # custody event only — the predecessor's history stays behind.
    assert len(successor.events()) == 1
    # carry predicate filters.
    filtered = rewrap_capsule(
        pred_bytes,
        originator=_bob_originator(bob),
        created_at=LATER,
        signed_at=LATER,
        carry=lambda path: not path.startswith("skills/"),
    )
    assert filtered["carried_paths"] == ["agents.md", "payload/evidence.csv", "program.md"]


def test_t3_custody_event_is_template_exact_optional_and_actor_validated():
    alice = generate_ed25519()
    bob = generate_ed25519()
    pred_bytes = _sealed_alice(alice)
    pred_id = derive_predecessor_entry(CapsuleReader.from_bytes(pred_bytes))["capsule_id"]
    wrap = rewrap_capsule(
        pred_bytes, originator=_bob_originator(bob), created_at=LATER, signed_at=LATER
    )
    events = CapsuleReader.from_bytes(wrap["bytes"]).events()
    assert len(events) == 1
    bare = {k: v for k, v in events[0].items() if k not in ("seq", "event_id", "prev_hash", "hash")}
    assert bare == {
        "actor": "system:host",
        "kind": "observation",
        "action": "custody_received",
        "target": f"capsule:{pred_id}",
        "timestamp": LATER,
        "payload": {
            "note": (
                f"custody received from capsule {pred_id}; "
                f"lineage is declared in manifest.predecessors"
            )
        },
        "untrusted_payload_fields": [],
    }
    # Opt-out: no custody event; seal's backstop covers the empty chain.
    opt_out = rewrap_capsule(
        pred_bytes,
        originator=_bob_originator(bob),
        created_at=LATER,
        signed_at=LATER,
        custody_event=False,
    )
    assert opt_out["custody_event_emitted"] is False
    assert CapsuleReader.from_bytes(opt_out["bytes"]).events()[0]["action"] == "session_ended"
    # custody_actor: a declared participant passes; an undeclared one
    # fails at the call site (the append_event actor rule, never a reader).
    declared = rewrap_capsule(
        pred_bytes,
        originator=_bob_originator(bob),
        created_at=LATER,
        signed_at=LATER,
        participants=[{"actor_id": "human:bob", "role": "custodian"}],
        custody_actor="human:bob",
    )
    assert CapsuleReader.from_bytes(declared["bytes"]).events()[0]["actor"] == "human:bob"
    with pytest.raises(ValueError, match="not a declared participant"):
        rewrap_capsule(
            pred_bytes,
            originator=_bob_originator(bob),
            created_at=LATER,
            signed_at=LATER,
            participants=[{"actor_id": "human:bob", "role": "custodian"}],
            custody_actor="human:mallory",
        )


def test_t4_refusals_tampered_unknown_era_encrypted_and_the_decrypt_path():
    alice = generate_ed25519()
    bob = generate_ed25519()
    recipient = generate_x25519()
    pred_bytes = _sealed_alice(alice)
    # Tampered predecessor: verification_failed with the full verify
    # result attached.
    with pytest.raises(PredecessorError) as excinfo:
        rewrap_capsule(_tampered_copy(pred_bytes), originator=_bob_originator(bob))
    assert excinfo.value.reason == "verification_failed"
    assert excinfo.value.verification["ok"] is False
    assert "allow_invalid_predecessor" in str(excinfo.value)
    # Unknown era: unsupported_version, versioning.md vocabulary, no
    # override honored.
    files = unpack_zip(pred_bytes)
    manifest = json.loads(files["manifest.json"])
    manifest["format"]["version"] = "9.9"
    files["manifest.json"] = json.dumps(manifest).encode("utf-8")
    future_bytes = pack_zip(files)
    with pytest.raises(PredecessorError) as excinfo:
        rewrap_capsule(
            future_bytes,
            originator=_bob_originator(bob),
            allow_invalid_predecessor=True,  # must NOT rescue an unknown era
        )
    assert excinfo.value.reason == "unsupported_version"
    assert "newer than this verifier supports" in str(excinfo.value)
    # Encrypted outer: encrypted_predecessor, message names the decrypt
    # path; decrypt-then-rewrap of the inner succeeds (the inner IS a
    # plain capsule).
    encrypted = _alice_builder(alice).seal(
        signers=[
            {
                "role": "originator",
                "public_key": alice.public_key,
                "private_key": alice.private_key,
            }
        ],
        signed_at=TS,
        recipients=[recipient],
    )
    with pytest.raises(PredecessorError) as excinfo:
        rewrap_capsule(encrypted, originator=_bob_originator(bob))
    assert excinfo.value.reason == "encrypted_predecessor"
    assert excinfo.value.verification is None
    assert "decrypt" in str(excinfo.value).lower()
    inner = CapsuleReader.from_bytes(encrypted).decrypt(recipient)
    via_inner = rewrap_capsule(
        inner, originator=_bob_originator(bob), created_at=LATER, signed_at=LATER
    )
    assert verify_capsule(via_inner["bytes"])["ok"] is True


def test_t5_override_seals_and_linkage_reports_predecessor_invalid():
    alice = generate_ed25519()
    bob = generate_ed25519()
    tampered = _tampered_copy(_sealed_alice(alice))
    wrap = rewrap_capsule(
        tampered,
        originator=_bob_originator(bob),
        created_at=LATER,
        signed_at=LATER,
        allow_invalid_predecessor=True,
    )
    assert wrap["predecessor_verification"]["ok"] is False
    result = verify_capsule(wrap["bytes"], predecessors=[tampered])
    # The successor itself is a valid capsule.
    assert result["ok"] is True
    assert result["lineage"]["entries"][0]["status"] == "predecessor_invalid"


def test_t6_reproducibility_pinned_timestamps_are_byte_identical():
    alice = generate_ed25519()
    bob = generate_ed25519()
    pred_bytes = _sealed_alice(alice)
    opts = {"originator": _bob_originator(bob), "created_at": LATER, "signed_at": LATER}
    a = rewrap_capsule(pred_bytes, **opts)
    b = rewrap_capsule(pred_bytes, **opts)
    assert a["bytes"] == b["bytes"]
    # Distinct timestamps → distinct genesis → distinct capsule ids: two
    # genuine successors, both honest (the rival-continuations row).
    c = rewrap_capsule(
        pred_bytes,
        originator=_bob_originator(bob),
        created_at="2026-05-07T14:00:00Z",
        signed_at=LATER,
    )
    assert a["capsule_id"] != c["capsule_id"]


def test_t7_re_rewrap_declares_one_entry_and_the_pool_verifies_depth_2():
    alice = generate_ed25519()
    bob = generate_ed25519()
    carol = generate_ed25519()
    alice_bytes = _sealed_alice(alice)
    bob_wrap = rewrap_capsule(
        alice_bytes, originator=_bob_originator(bob), created_at=LATER, signed_at=LATER
    )
    carol_wrap = rewrap_capsule(
        bob_wrap["bytes"],
        originator={
            "public_key": carol.public_key_hex,
            "private_key": carol.private_key_hex,
            "label": "Carol",
        },
        created_at=LATER,
        signed_at=LATER,
    )
    carol_manifest = CapsuleReader.from_bytes(carol_wrap["bytes"]).manifest()
    assert len(carol_manifest["predecessors"]) == 1
    assert carol_manifest["predecessors"][0]["capsule_id"] == bob_wrap["capsule_id"]
    result = verify_capsule(carol_wrap["bytes"], predecessors=[bob_wrap["bytes"], alice_bytes])
    assert result["lineage"]["verified_depth"] == 2


def test_t8_laundering_equivalence_the_override_changes_no_emitted_byte():
    alice = generate_ed25519()
    bob = generate_ed25519()
    pred_bytes = _sealed_alice(alice)
    opts = {"originator": _bob_originator(bob), "created_at": LATER, "signed_at": LATER}
    normal = rewrap_capsule(pred_bytes, **opts)
    overridden = rewrap_capsule(pred_bytes, allow_invalid_predecessor=True, **opts)
    # The flag is UX at the writer, not a security boundary: byte-for-byte
    # identical output, so no reader could ever distinguish the paths.
    assert normal["bytes"] == overridden["bytes"]


def test_t9_encrypted_successor_placement_and_placement_validation():
    alice = generate_ed25519()
    bob = generate_ed25519()
    recipient = generate_x25519()
    pred_bytes = _sealed_alice(alice)
    wrap = rewrap_capsule(
        pred_bytes,
        originator=_bob_originator(bob),
        created_at=LATER,
        signed_at=LATER,
        recipients=[recipient],
        lineage_placement="both",
    )
    outer = CapsuleReader.from_bytes(wrap["bytes"])
    assert outer.is_encrypted() is True
    inner = outer.decrypt(recipient)
    # "both" emits the two copies byte-equal (reader check 4 by
    # construction).
    assert outer.manifest()["predecessors"] == inner.manifest()["predecessors"]
    inner_result = verify_capsule(
        inner, outer_envelope=outer.envelope(), outer_manifest=outer.manifest()
    )
    assert inner_result["ok"] is True
    with pytest.raises(ValueError, match="lineage_placement"):
        rewrap_capsule(
            pred_bytes,
            originator=_bob_originator(bob),
            recipients=[recipient],
            lineage_placement="sideways",
        )


def test_t10_declare_predecessor_entry_accepts_coherent_rejects_malformed():
    alice = generate_ed25519()
    bob = generate_ed25519()
    entry = derive_predecessor_entry(CapsuleReader.from_bytes(_sealed_alice(alice)))

    def fresh() -> CapsuleBuilder:
        return CapsuleBuilder(originator={"public_key": bob.public_key_hex})

    # Coherent explicit entry accepted; duplicate manifest_hash rejected.
    builder = fresh().declare_predecessor_entry(entry)
    with pytest.raises(ValueError, match="cited twice"):
        builder.declare_predecessor_entry(dict(entry))
    # Unknown-era explicit entry IS expressible (the archivist case):
    # identity coherence is validated only for known eras.
    fresh().declare_predecessor_entry({**entry, "format_version": "0.9"})
    # Check-1/2/3 malformations rejected with the shared diagnoses.
    with pytest.raises(ValueError, match=r"predecessors\[0\]\.capsule_id"):
        fresh().declare_predecessor_entry({**entry, "capsule_id": entry["capsule_id"].upper()})
    with pytest.raises(ValueError, match="cannot exist"):
        fresh().declare_predecessor_entry({**entry, "first_event_hash": None})
    with pytest.raises(ValueError, match="does not derive"):
        fresh().declare_predecessor_entry({**entry, "capsule_id": "0" * 64})
    with pytest.raises(ValueError, match=r"predecessors\[0\]\.note"):
        fresh().declare_predecessor_entry({**entry, "note": "advisory text"})


@pytest.mark.parametrize(
    "successor_file,predecessor_file",
    [
        ("bob.capsule", "alice.capsule"),
        ("carol.capsule", "bob.capsule"),
        ("successor-of-v06.capsule", "known-previous-version-0.6.capsule"),
        ("successor-of-template.capsule", "template.capsule"),
    ],
)
def test_p1_derived_entries_are_json_equal_to_the_js_built_fixtures(
    successor_file: str, predecessor_file: str
):
    """Cross-lane derivation parity (the design's P1).

    Derivation is deterministic — six members read or recomputed from
    predecessor bytes — so the entry this lane derives must be JSON-equal
    to the one the JS reference lane sealed into the checked-in successor
    fixture. A difference here is a cross-lane disagreement about what a
    capsule's identity or manifest hash IS, not a fixture nit. Covers the
    cross-era (v0.6) and zero-event (null/null anchors) corners.
    """
    predecessor = CapsuleReader.from_bytes((LINEAGE_VECTORS / predecessor_file).read_bytes())
    successor = CapsuleReader.from_bytes((LINEAGE_VECTORS / successor_file).read_bytes())
    declared = successor.manifest()["predecessors"]
    assert len(declared) == 1
    assert derive_predecessor_entry(predecessor) == declared[0]


def test_p1_python_built_successor_of_a_js_fixture_verifies_and_links():
    """A py-built successor of a JS-built predecessor links to depth 1.

    Byte equality across implementations is NOT promised (the format.md
    determinism boundary), but the declaration and the linkage verdict
    are — the successor this lane seals cites the JS fixture with the
    exact members the JS lane derived, and verifies to depth 1 against
    the checked-in predecessor bytes.
    """
    bob = generate_ed25519()
    alice_bytes = (LINEAGE_VECTORS / "alice.capsule").read_bytes()
    js_declared = CapsuleReader.from_bytes(
        (LINEAGE_VECTORS / "bob.capsule").read_bytes()
    ).manifest()["predecessors"][0]
    wrap = rewrap_capsule(
        alice_bytes,
        originator=_bob_originator(bob),
        participants=[{"actor_id": "human:bob", "role": "custodian"}],
        created_at=LATER,
        signed_at=LATER,
    )
    assert wrap["predecessor_entry"] == js_declared
    result = verify_capsule(wrap["bytes"], predecessors=[alice_bytes])
    assert result["ok"] is True
    assert result["lineage"]["verified_depth"] == 1
    assert result["lineage"]["entries"][0]["status"] == "verified"
    # A clean custody claim adds NO lineage qualifier (spec/results.md);
    # what remains is this verification's own host-relative fact — the
    # successor declares participants, and no allowlist was supplied.
    assert result["qualifiers"] == ["trust_not_evaluated"]

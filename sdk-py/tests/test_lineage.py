"""Lineage verification (spec/lineage.md).

The ``manifest.predecessors`` standalone checks (fail-closed), the
report-only supplied-bytes linkage, the era-keyed recursive walk, the
``result["lineage"]`` area, the three emitted lineage qualifiers, and the
pinned report phrases. Mirrors sdk-js/test/lineage.test.js.
"""

from __future__ import annotations

import json

import pytest

from capsule import (
    CapsuleBuilder,
    CapsuleReader,
    compute_capsule_id,
    generate_ed25519,
    generate_x25519,
    manifest_hash,
    predecessors_problems,
    rewrap_capsule,
    verify_capsule,
)
from capsule.canonical import concat_bytes, jcs, sha256
from capsule.chain import build_chain_events, events_to_jsonl, first_and_entry_hash
from capsule.crypto import ed25519_sign
from capsule.envelope import build_envelope, sign_envelope
from capsule.manifest import (
    build_content_index,
    build_manifest,
    build_signer_commitment,
    manifest_bytes,
)
from capsule.zip_io import pack_zip, unpack_zip

TS = "2026-05-07T12:00:00Z"
LATER = "2026-05-07T13:00:00Z"


def _pred_builder(ed, events: int = 2) -> CapsuleBuilder:
    builder = CapsuleBuilder(
        originator={"public_key": ed.public_key_hex, "label": "Alice"},
        participants=[{"actor_id": "human:alice", "role": "originator"}],
        created_at=TS,
    )
    builder.set_program("# Work\n\nStep one.\n")
    builder.add_payload("payload/data.csv", b"a,b\n1,2\n")
    for i in range(events):
        builder.append_event(
            {
                "actor": "human:alice",
                "kind": "decision",
                "action": f"step_{i + 1}",
                "target": "program.md",
                "timestamp": TS,
                "payload": {"note": f"step {i + 1}"},
            }
        )
    return builder


def _sealed_pred(ed, events: int = 2) -> bytes:
    return _pred_builder(ed, events).seal(
        signers=[
            {
                "role": "originator",
                "public_key": ed.public_key,
                "private_key": ed.private_key,
            }
        ],
        signed_at=TS,
    )


def _seal_with_predecessors(
    ed, predecessors_value, *, mutate_manifest=None, mutate_envelope=None
) -> bytes:
    """Seal a minimal capsule with an arbitrary (possibly malformed) value.

    The builder rightly refuses to emit these shapes, so the fixtures are
    constructed low-level — and SIGNED, so only the lineage checks decide
    them.
    """
    events = build_chain_events(
        [
            {
                "actor": "human:alice",
                "kind": "observation",
                "action": "noted",
                "target": "capsule",
                "timestamp": TS,
                "payload": {},
            }
        ]
    )
    first_event_hash, entry_hash = first_and_entry_hash(events)
    files = {
        "program.md": b"# Program\n",
        "chain/events.jsonl": events_to_jsonl(events),
    }
    content_index = build_content_index(files)
    manifest = build_manifest(
        originator={"public_key": ed.public_key_hex, "label": "Alice"},
        participants=[{"actor_id": "human:alice", "role": "originator"}],
        content_index=content_index,
        first_event_hash=first_event_hash,
        encryption=None,
        created_at=TS,
        signer_commitment=build_signer_commitment(
            [{"role": "originator", "public_key": ed.public_key_hex}]
        ),
    )
    if predecessors_value is not None:
        manifest["predecessors"] = predecessors_value
    if mutate_manifest is not None:
        mutate_manifest(manifest)
    manifest["id"] = compute_capsule_id(ed.public_key, first_event_hash)
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
    # Before signing: the envelope declaration sits inside the canonical
    # payload every signature covers (spec/profiles.md).
    if mutate_envelope is not None:
        mutate_envelope(envelope)
    sign_envelope(
        envelope,
        [
            {
                "role": "originator",
                "public_key": ed.public_key,
                "private_key": ed.private_key,
            }
        ],
    )
    all_files = dict(files)
    all_files["manifest.json"] = manifest_bytes(manifest)
    all_files["provenance/envelope.json"] = json.dumps(
        envelope, indent=2, ensure_ascii=False
    ).encode("utf-8")
    return pack_zip(all_files)


def _seal_at_era_with_predecessors(ed, era: str, predecessors_value) -> bytes:
    """Seal a capsule under an EARLIER era carrying a ``predecessors`` value.

    Byte-coherent under that era: identity from ``capsule-id-v<era>\\0``
    and the signature over ``capsule-provenance-v<era>:originator\\0``,
    the domain strings that era's verifier reconstructs — so the ONLY
    thing under test is whether a v0.7.1 reader interprets a member that
    era's rules do not define.
    """
    events = build_chain_events(
        [
            {
                "actor": "human:alice",
                "kind": "observation",
                "action": "noted",
                "target": "capsule",
                "timestamp": TS,
                "payload": {},
            }
        ]
    )
    first_event_hash, entry_hash = first_and_entry_hash(events)
    files = {
        "program.md": b"# Program\n",
        "chain/events.jsonl": events_to_jsonl(events),
    }
    content_index = build_content_index(files)
    manifest = build_manifest(
        originator={"public_key": ed.public_key_hex, "label": "Alice"},
        participants=[{"actor_id": "human:alice", "role": "originator"}],
        content_index=content_index,
        first_event_hash=first_event_hash,
        encryption=None,
        created_at=TS,
        signer_commitment=build_signer_commitment(
            [{"role": "originator", "public_key": ed.public_key_hex}]
        ),
    )
    manifest["format"]["version"] = era
    manifest["predecessors"] = predecessors_value
    manifest["id"] = sha256(
        concat_bytes(
            f"capsule-id-v{era}\x00".encode(),
            ed.public_key,
            bytes.fromhex(first_event_hash),
        )
    ).hex()
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
    envelope["version"] = era
    payload = {k: v for k, v in envelope.items() if k != "signers"}
    envelope["signers"].append(
        {
            "role": "originator",
            "public_key": ed.public_key_hex,
            "signature": ed25519_sign(
                ed.private_key,
                concat_bytes(
                    f"capsule-provenance-v{era}:originator\x00".encode(),
                    jcs(payload),
                ),
            ).hex(),
        }
    )
    all_files = dict(files)
    all_files["manifest.json"] = manifest_bytes(manifest)
    all_files["provenance/envelope.json"] = json.dumps(
        envelope, indent=2, ensure_ascii=False
    ).encode("utf-8")
    return pack_zip(all_files)


def test_pre_lineage_era_member_is_inert_not_shape_checked():
    alice = generate_ed25519()
    # The SAME value that fails a 0.7 capsule closed.
    malformed: list = []
    v07 = verify_capsule(_seal_with_predecessors(alice, malformed))
    assert v07["ok"] is False
    assert any(e.startswith("manifest.predecessors") for e in v07["errors"])

    v06 = verify_capsule(_seal_at_era_with_predecessors(alice, "0.6", malformed))
    assert v06["ok"] is True, v06["errors"]
    assert v06["format_version"]["observed"] == "0.6"
    assert v06["lineage"] == {
        "declared": False,
        "ok": True,
        "verified_depth": 0,
        "entries": [],
    }
    # No LINEAGE qualifier: the member was never interpreted. The base
    # qualifier is the verification's own host-relative fact (no
    # allowlist was supplied), spec/results.md order.
    assert v06["qualifiers"] == ["trust_not_evaluated"]
    assert any("unknown member under that era" in n for n in v06["notes"])


def test_pre_lineage_era_well_formed_declaration_is_equally_uninterpreted():
    alice = generate_ed25519()
    bob = generate_ed25519()
    pred_bytes = _sealed_pred(alice)
    wrap = rewrap_capsule(
        pred_bytes,
        originator={
            "public_key": bob.public_key_hex,
            "private_key": bob.private_key_hex,
            "label": "Bob",
        },
        created_at=LATER,
        signed_at=LATER,
    )
    entry = CapsuleReader.from_bytes(wrap["bytes"]).manifest()["predecessors"][0]
    result = verify_capsule(
        _seal_at_era_with_predecessors(bob, "0.6", [entry]),
        predecessors=[pred_bytes],
    )
    # Even with the predecessor bytes in hand: no era rules, no claim.
    assert result["ok"] is True, result["errors"]
    assert result["lineage"]["declared"] is False
    assert result["lineage"]["entries"] == []


def test_l3_inner_outer_equality_runs_without_the_outer_manifest_argument():
    alice = generate_ed25519()
    bob = generate_ed25519()
    recipient = generate_x25519()
    wrap = rewrap_capsule(
        _sealed_pred(alice),
        originator={
            "public_key": bob.public_key_hex,
            "private_key": bob.private_key_hex,
            "label": "Bob",
        },
        created_at=LATER,
        signed_at=LATER,
        recipients=[recipient],
        lineage_placement="both",
    )
    # A capsule asserting one origin to the world and another to its
    # recipients: rewrite the OUTER declaration only.
    files = unpack_zip(wrap["bytes"])
    outer_manifest = json.loads(files["manifest.json"].decode("utf-8"))
    outer_manifest["predecessors"] = [
        {**outer_manifest["predecessors"][0], "manifest_hash": "e" * 64}
    ]
    files["manifest.json"] = json.dumps(outer_manifest).encode("utf-8")
    outer = CapsuleReader.from_bytes(pack_zip(files))
    inner = outer.decrypt(recipient)
    # The reader carries the layer it came out of, so the fail-closed
    # MUST is not opt-in.
    assert inner.outer_manifest() is outer.manifest()
    result = verify_capsule(inner, outer_envelope=outer.envelope())
    assert result["ok"] is False
    assert any(
        "predecessors differs between the inner and outer" in e for e in result["errors"]
    )


def test_no_predecessors_member_declares_false_and_emits_no_qualifier():
    alice = generate_ed25519()
    result = verify_capsule(_sealed_pred(alice))
    assert result["ok"] is True
    assert result["lineage"] == {
        "declared": False,
        "ok": True,
        "verified_depth": 0,
        "entries": [],
    }
    # No lineage qualifier — absence is no claim. The base entry is this
    # verification's own host-relative fact (no allowlist supplied).
    assert result["qualifiers"] == ["trust_not_evaluated"]


def test_declared_without_pool_reports_pinned_phrases_and_qualifier():
    alice = generate_ed25519()
    bob = generate_ed25519()
    wrap = rewrap_capsule(
        _sealed_pred(alice),
        originator={
            "public_key": bob.public_key_hex,
            "private_key": bob.private_key_hex,
            "label": "Bob",
        },
        created_at=LATER,
        signed_at=LATER,
    )
    result = verify_capsule(wrap["bytes"])
    assert result["ok"] is True
    assert result["lineage"]["declared"] is True
    assert result["lineage"]["ok"] is True
    assert result["lineage"]["verified_depth"] == 0
    entries = result["lineage"]["entries"]
    assert len(entries) == 1
    assert entries[0]["status"] == "unverified"
    assert entries[0]["hop"] == 1
    assert entries[0]["identity_checked"] is True
    assert entries[0]["artifact"] is None
    notes = " | ".join(result["notes"])
    # Pinned phrases: an unchecked custody claim must never quietly
    # disappear, and no report may imply a consent bit exists.
    assert "declared, not verified" in notes
    assert "not countersigned" in notes
    # The ten-name vocabulary of spec/results.md in emission order: the
    # successor carries no participants and is verified with no
    # allowlist, so the two base facts ride alongside the custody one.
    assert result["qualifiers"] == [
        "actor_set_unbound",
        "trust_not_evaluated",
        "lineage_declared_unverified",
    ]


def test_linkage_verified_to_depth_1_names_two_identities():
    alice = generate_ed25519()
    bob = generate_ed25519()
    pred_bytes = _sealed_pred(alice)
    wrap = rewrap_capsule(
        pred_bytes,
        originator={
            "public_key": bob.public_key_hex,
            "private_key": bob.private_key_hex,
            "label": "Bob",
        },
        created_at=LATER,
        signed_at=LATER,
    )
    result = verify_capsule(wrap["bytes"], predecessors=[pred_bytes])
    assert result["ok"] is True
    assert result["lineage"]["ok"] is True
    assert result["lineage"]["verified_depth"] == 1
    entry = result["lineage"]["entries"][0]
    assert entry["status"] == "verified"
    assert entry["artifact"]["ok"] is True
    assert entry["artifact"]["observed_version"] == "0.7"
    # Distinct identities: the successor is never presented as BEING the
    # predecessor.
    assert wrap["capsule_id"] != wrap["predecessor_entry"]["capsule_id"]
    notes = " | ".join(result["notes"])
    assert "successor of capsule" in notes
    assert "verified to depth 1" in notes
    # A clean custody claim adds NO lineage qualifier; what remains is
    # this verification's own host-relative facts.
    assert result["qualifiers"] == ["actor_set_unbound", "trust_not_evaluated"]


def test_recursive_walk_reaches_depth_2_and_rerewrap_declares_one_entry():
    alice = generate_ed25519()
    bob = generate_ed25519()
    carol = generate_ed25519()
    alice_bytes = _sealed_pred(alice)
    bob_wrap = rewrap_capsule(
        alice_bytes,
        originator={
            "public_key": bob.public_key_hex,
            "private_key": bob.private_key_hex,
            "label": "Bob",
        },
        created_at=LATER,
        signed_at=LATER,
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
    # Re-rewrap never accumulates: the hop-2 successor declares exactly
    # one entry (its immediate parent); ancestry never flattens inline.
    carol_reader = CapsuleReader.from_bytes(carol_wrap["bytes"])
    assert len(carol_reader.manifest()["predecessors"]) == 1
    result = verify_capsule(carol_wrap["bytes"], predecessors=[bob_wrap["bytes"], alice_bytes])
    assert result["ok"] is True
    assert result["lineage"]["verified_depth"] == 2
    assert [(e["hop"], e["status"]) for e in result["lineage"]["entries"]] == [
        (1, "verified"),
        (2, "verified"),
    ]


def test_merge_declares_two_parents_one_supplied():
    alice = generate_ed25519()
    dana = generate_ed25519()
    bob = generate_ed25519()
    alice_bytes = _sealed_pred(alice)
    dana_bytes = _sealed_pred(dana, 1)
    builder = CapsuleBuilder.continue_from(
        alice_bytes,
        originator={"public_key": bob.public_key_hex, "label": "Bob"},
        created_at=LATER,
    )
    builder.declare_predecessor(dana_bytes)
    data = builder.seal(signers=[bob], signed_at=LATER)
    result = verify_capsule(data, predecessors=[alice_bytes])
    assert result["ok"] is True
    assert len(result["lineage"]["entries"]) == 2
    assert sorted(e["status"] for e in result["lineage"]["entries"]) == [
        "unverified",
        "verified",
    ]
    # Depth counts only when EVERY declared entry within the hop is
    # verified — an operator legitimately holds one branch of a merge.
    assert result["lineage"]["verified_depth"] == 0
    assert result["qualifiers"] == [
        "actor_set_unbound",
        "trust_not_evaluated",
        "lineage_declared_unverified",
    ]


def test_mismatch_is_report_only_and_never_flips_ok():
    alice = generate_ed25519()
    bob = generate_ed25519()
    two_events = _sealed_pred(alice, 2)
    # A later genuine seal of the same line: same key, same genesis event,
    # one more event — same capsule_id, different manifest_hash.
    later_seal = _pred_builder(alice, 3).seal(
        signers=[
            {
                "role": "originator",
                "public_key": alice.public_key,
                "private_key": alice.private_key,
            }
        ],
        signed_at=LATER,
    )
    wrap = rewrap_capsule(
        two_events,
        originator={
            "public_key": bob.public_key_hex,
            "private_key": bob.private_key_hex,
            "label": "Bob",
        },
        created_at=LATER,
        signed_at=LATER,
    )
    assert (
        CapsuleReader.from_bytes(later_seal).manifest()["id"]
        == CapsuleReader.from_bytes(two_events).manifest()["id"]
    )
    result = verify_capsule(wrap["bytes"], predecessors=[later_seal])
    # The anti-framing pin: a host's file handling never flips the
    # successor's own verdict.
    assert result["ok"] is True
    assert result["lineage"]["ok"] is False
    entry = result["lineage"]["entries"][0]
    assert entry["status"] == "mismatch"
    errs = " | ".join(entry["errors"])
    assert "different sealed state of the declared predecessor" in errs
    # The versioning.md diagnosis style: the honest cause is named and
    # tamper vocabulary appears only negated.
    assert "not evidence of tampering" in errs
    assert "corrupt" not in errs.lower()
    assert result["qualifiers"] == [
        "actor_set_unbound",
        "trust_not_evaluated",
        "lineage_mismatch",
    ]


def test_predecessor_invalid_keeps_the_two_facts_apart():
    alice = generate_ed25519()
    bob = generate_ed25519()
    pred_bytes = _sealed_pred(alice)
    wrap = rewrap_capsule(
        pred_bytes,
        originator={
            "public_key": bob.public_key_hex,
            "private_key": bob.private_key_hex,
            "label": "Bob",
        },
        created_at=LATER,
        signed_at=LATER,
    )
    # Tamper with a content file: the manifest (and thus the declared
    # manifest_hash) is untouched, so the artifact still pair-matches.
    files = unpack_zip(pred_bytes)
    program = bytearray(files["program.md"])
    program[0] ^= 0x01
    files["program.md"] = bytes(program)
    tampered = pack_zip(files)
    result = verify_capsule(wrap["bytes"], predecessors=[tampered])
    assert result["ok"] is True
    assert result["lineage"]["ok"] is False
    entry = result["lineage"]["entries"][0]
    assert entry["status"] == "predecessor_invalid"
    assert entry["artifact"]["ok"] is False
    assert "property of the supplied artifact" in " ".join(entry["errors"])
    assert result["qualifiers"] == [
        "actor_set_unbound",
        "trust_not_evaluated",
        "lineage_predecessor_invalid",
    ]


def test_unmatched_supplied_artifact_is_named_in_notes():
    alice = generate_ed25519()
    stranger = generate_ed25519()
    bob = generate_ed25519()
    wrap = rewrap_capsule(
        _sealed_pred(alice),
        originator={
            "public_key": bob.public_key_hex,
            "private_key": bob.private_key_hex,
            "label": "Bob",
        },
        created_at=LATER,
        signed_at=LATER,
    )
    # A stranger's genuine capsule and a byte blob that is no capsule at
    # all: both are named. A mistyped path must be visible, never
    # silently ignored.
    result = verify_capsule(
        wrap["bytes"], predecessors=[_sealed_pred(stranger), b"not a capsule at all"]
    )
    assert result["ok"] is True
    notes = " | ".join(result["notes"])
    assert "matched no declared entry" in notes
    assert "could not be read as a capsule" in notes


def test_hop_cap_bounds_the_walk_and_reports_the_stop():
    alice = generate_ed25519()
    bob = generate_ed25519()
    carol = generate_ed25519()
    alice_bytes = _sealed_pred(alice)
    bob_wrap = rewrap_capsule(
        alice_bytes,
        originator={
            "public_key": bob.public_key_hex,
            "private_key": bob.private_key_hex,
            "label": "Bob",
        },
        created_at=LATER,
        signed_at=LATER,
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
    pool = [bob_wrap["bytes"], alice_bytes]
    # A resource limit like the reader's file-count and size caps, not a
    # protocol rule: the walk stops and SAYS it stopped.
    capped = verify_capsule(carol_wrap["bytes"], predecessors=pool, lineage_hop_cap=1)
    assert capped["ok"] is True
    assert [e["hop"] for e in capped["lineage"]["entries"]] == [1]
    assert capped["lineage"]["verified_depth"] == 1
    assert "hop cap 1 reached" in " | ".join(capped["notes"])
    # Uncapped, the same pool reaches depth 2.
    assert verify_capsule(carol_wrap["bytes"], predecessors=pool)["lineage"]["verified_depth"] == 2


def test_encrypted_supplied_predecessor_is_unverifiable_not_mismatch():
    alice = generate_ed25519()
    bob = generate_ed25519()
    recipient = generate_x25519()
    # The encrypted twin shares identity and (inner) manifest with the
    # plain seal, so the declaration derived from the plain twin names it.
    plain_bytes = _sealed_pred(alice)
    encrypted_bytes = _pred_builder(alice, 2).seal(
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
    wrap = rewrap_capsule(
        plain_bytes,
        originator={
            "public_key": bob.public_key_hex,
            "private_key": bob.private_key_hex,
            "label": "Bob",
        },
        created_at=LATER,
        signed_at=LATER,
    )
    result = verify_capsule(wrap["bytes"], predecessors=[encrypted_bytes])
    assert result["ok"] is True
    entry = result["lineage"]["entries"][0]
    assert entry["status"] == "predecessor_unverifiable"
    assert entry["reason"] == "encrypted_predecessor"
    assert "declared, not verified" in " | ".join(result["notes"])
    assert result["qualifiers"] == [
        "actor_set_unbound",
        "trust_not_evaluated",
        "lineage_declared_unverified",
    ]


def test_alternate_profile_supplied_predecessor_is_a_scope_limitation():
    alice = generate_ed25519()
    bob = generate_ed25519()
    # A predecessor declaring an alternate profile (default math,
    # non-default declaration — the default-profile scope case). Both
    # documents declare it: a declaration in only one is a capsule
    # self-contradiction (profile_mismatch, spec/profiles.md), which is a
    # different diagnosis from the verifier limitation under test.
    alt_profile = {"id": "acme-postquantum", "version": "1.0"}
    alt_pred = _seal_with_predecessors(
        alice,
        None,
        mutate_manifest=lambda m: m["format"].update({"profile": dict(alt_profile)}),
        mutate_envelope=lambda e: e.update({"profile": dict(alt_profile)}),
    )
    # Read the declaration WITHOUT the reader: the open-stage profile gate
    # (spec/profiles.md) refuses this capsule, which is precisely the
    # limitation under test — an archivist who cannot open the predecessor
    # still holds its members and cites them via the explicit-values path.
    alt_files = unpack_zip(alt_pred)
    alt_manifest = json.loads(alt_files["manifest.json"])
    alt_envelope = json.loads(alt_files["provenance/envelope.json"])
    with pytest.raises(ValueError, match="is not supported by this verifier"):
        CapsuleReader.from_bytes(alt_pred)
    entry = {
        "capsule_id": alt_manifest["id"],
        "format_version": alt_manifest["format"]["version"],
        "originator_public_key": alt_manifest["originator"]["public_key"],
        "first_event_hash": alt_manifest["first_event_hash"],
        "entry_hash": alt_envelope["entry_hash"],
        "manifest_hash": manifest_hash(alt_manifest),
    }
    # The successor cites it via the explicit-values path (continue_from
    # refuses alternate-profile predecessors at the writer).
    builder = CapsuleBuilder(
        originator={"public_key": bob.public_key_hex, "label": "Bob"}, created_at=LATER
    )
    builder.declare_predecessor_entry(entry)
    builder.append_event(
        {
            "actor": "system:host",
            "action": "custody_received",
            "target": f"capsule:{entry['capsule_id']}",
            "timestamp": LATER,
            "payload": {},
        }
    )
    data = builder.seal(signers=[bob], signed_at=LATER)
    result = verify_capsule(data, predecessors=[alt_pred])
    assert result["ok"] is True
    got = result["lineage"]["entries"][0]
    # A verifier/scope limitation — never mismatch, never
    # predecessor_invalid (the diagnosis-discipline pin).
    assert got["status"] == "predecessor_unverifiable"
    assert got["reason"] == "unsupported_profile"


def _good_entry(ed) -> dict:
    return {
        "capsule_id": compute_capsule_id(ed.public_key, None, "0.7"),
        "format_version": "0.7",
        "originator_public_key": ed.public_key_hex,
        "first_event_hash": None,
        "entry_hash": None,
        "manifest_hash": "a" * 64,
    }


@pytest.mark.parametrize(
    "case,value,needle",
    [
        ("not-array", "capsule:not-an-array", "predecessors must be an array"),
        ("empty", [], "predecessors must not be empty"),
        ("missing-manifest-hash", "missing", "predecessors[0].manifest_hash"),
        ("uppercase-hex", "uppercase", "predecessors[0].capsule_id"),
        ("version-grammar", "grammar", "predecessors[0].format_version"),
        ("null-incoherent", "null-incoherent", "cannot exist"),
        ("duplicate-manifest-hash", "duplicate", "cited twice"),
        ("unknown-member", "unknown-member", "predecessors[0].label"),
    ],
)
def test_standalone_malformation_fails_closed_with_shared_diagnoses(case, value, needle):
    alice = generate_ed25519()
    good = _good_entry(alice)
    if value == "missing":
        value = [{k: v for k, v in good.items() if k != "manifest_hash"}]
    elif value == "uppercase":
        value = [{**good, "capsule_id": good["capsule_id"].upper()}]
    elif value == "grammar":
        value = [{**good, "format_version": "v0.7"}]
    elif value == "null-incoherent":
        value = [{**good, "first_event_hash": None, "entry_hash": "b" * 64}]
    elif value == "duplicate":
        value = [good, dict(good)]
    elif value == "unknown-member":
        value = [{**good, "label": "official continuation"}]
    result = verify_capsule(_seal_with_predecessors(alice, value))
    assert result["ok"] is False, case
    assert result["lineage"]["declared"] is True, case
    assert result["lineage"]["ok"] is False, case
    assert needle in " | ".join(result["errors"]), case
    # No qualifiers on an invalid verdict.
    assert result["qualifiers"] == [], case


def test_identity_coherence_fails_closed_known_era_and_skips_unknown():
    alice = generate_ed25519()
    entry = _good_entry(alice)
    # Known era, underivable id: fail closed (self-assertion, not linkage).
    first = "1" if entry["capsule_id"][0] == "0" else "0"
    bad = {**entry, "capsule_id": first + entry["capsule_id"][1:]}
    bad_result = verify_capsule(_seal_with_predecessors(alice, [bad]))
    assert bad_result["ok"] is False
    assert "does not derive" in " ".join(bad_result["errors"])
    # Unknown declared era: the check SKIPS (this verifier is too old for
    # that era's formula) and the skip is reported — never a failure.
    future_result = verify_capsule(
        _seal_with_predecessors(alice, [{**entry, "format_version": "0.9"}])
    )
    assert future_result["ok"] is True
    assert future_result["lineage"]["entries"][0]["identity_checked"] is False
    assert future_result["lineage"]["entries"][0]["status"] == "unverified"


def _seal_zero_event(ed, *, predecessors=None) -> bytes:
    """Zero-event template built low-level (seal() inserts a backstop)."""
    files = {"program.md": b"# Template\n", "chain/events.jsonl": b""}
    content_index = build_content_index(files)
    manifest = build_manifest(
        originator={"public_key": ed.public_key_hex, "label": "Template"},
        participants=[],
        content_index=content_index,
        first_event_hash=None,
        encryption=None,
        created_at=TS,
        signer_commitment=build_signer_commitment(
            [{"role": "originator", "public_key": ed.public_key_hex}]
        ),
        predecessors=predecessors,
    )
    manifest["id"] = compute_capsule_id(ed.public_key, None)
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
                "public_key": ed.public_key,
                "private_key": ed.private_key,
            }
        ],
    )
    all_files = dict(files)
    all_files["manifest.json"] = manifest_bytes(manifest)
    all_files["provenance/envelope.json"] = json.dumps(
        envelope, indent=2, ensure_ascii=False
    ).encode("utf-8")
    return pack_zip(all_files)


def test_zero_event_predecessor_verifies_with_null_anchors():
    alice = generate_ed25519()
    bob = generate_ed25519()
    template_bytes = _seal_zero_event(alice)
    wrap = rewrap_capsule(
        template_bytes,
        originator={
            "public_key": bob.public_key_hex,
            "private_key": bob.private_key_hex,
            "label": "Bob",
        },
        created_at=LATER,
        signed_at=LATER,
    )
    assert wrap["predecessor_entry"]["first_event_hash"] is None
    assert wrap["predecessor_entry"]["entry_hash"] is None
    result = verify_capsule(wrap["bytes"], predecessors=[template_bytes])
    assert result["ok"] is True
    assert result["lineage"]["entries"][0]["status"] == "verified"
    assert result["lineage"]["verified_depth"] == 1


def test_version_refused_capsule_holds_the_not_evaluated_lineage_default():
    alice = generate_ed25519()
    # A capsule this verifier cannot open holds the fail-closed
    # not-evaluated lineage default; the refusal is the only diagnosis.
    data = _seal_with_predecessors(alice, None)
    files = unpack_zip(data)
    manifest = json.loads(files["manifest.json"])
    manifest["format"]["version"] = "9.9"
    files["manifest.json"] = json.dumps(manifest).encode("utf-8")
    result = verify_capsule(pack_zip(files))
    assert result["ok"] is False
    assert result["lineage"] == {
        "declared": False,
        "ok": False,
        "verified_depth": 0,
        "entries": [],
    }
    assert result["qualifiers"] == []


def test_no_self_reference_rule_same_key_zero_event_declaration_is_legal():
    alice = generate_ed25519()
    zero_event_id = compute_capsule_id(alice.public_key, None, "0.7")
    # A same-key zero-event template rewrap honestly declares a
    # predecessor id equal to its own (two zero-event capsules from one
    # originator share a capsule_id). No rule fails it.
    assert (
        predecessors_problems(
            [
                {
                    "capsule_id": zero_event_id,
                    "format_version": "0.7",
                    "originator_public_key": alice.public_key_hex,
                    "first_event_hash": None,
                    "entry_hash": None,
                    "manifest_hash": "c" * 64,
                }
            ]
        )
        == []
    )


def test_same_capsule_id_with_different_manifest_hash_is_a_legal_merge_shape():
    alice = generate_ed25519()
    base = {
        "capsule_id": compute_capsule_id(alice.public_key, None, "0.7"),
        "format_version": "0.7",
        "originator_public_key": alice.public_key_hex,
        "first_event_hash": None,
        "entry_hash": None,
    }
    assert (
        predecessors_problems(
            [
                {**base, "manifest_hash": "a" * 64},
                {**base, "manifest_hash": "b" * 64},
            ]
        )
        == []
    )


def test_vendor_members_inside_entries_are_legal():
    alice = generate_ed25519()
    assert (
        predecessors_problems(
            [
                {
                    "capsule_id": compute_capsule_id(alice.public_key, None, "0.7"),
                    "format_version": "0.7",
                    "originator_public_key": alice.public_key_hex,
                    "first_event_hash": None,
                    "entry_hash": None,
                    "manifest_hash": "d" * 64,
                    "x-acme-relation": "fork",
                }
            ]
        )
        == []
    )


def test_encrypted_successor_inner_outer_equality_at_l3():
    alice = generate_ed25519()
    bob = generate_ed25519()
    recipient = generate_x25519()
    pred_bytes = _sealed_pred(alice)
    wrap = rewrap_capsule(
        pred_bytes,
        originator={
            "public_key": bob.public_key_hex,
            "private_key": bob.private_key_hex,
            "label": "Bob",
        },
        created_at=LATER,
        signed_at=LATER,
        recipients=[recipient],
        lineage_placement="both",
    )
    outer = CapsuleReader.from_bytes(wrap["bytes"])
    assert isinstance(outer.manifest()["predecessors"], list)
    inner = outer.decrypt(recipient)
    assert isinstance(inner.manifest()["predecessors"], list)
    inner_result = verify_capsule(
        inner, outer_envelope=outer.envelope(), outer_manifest=outer.manifest()
    )
    assert inner_result["ok"] is True
    # Single-layer placements are each a weaker claim made honestly.
    for placement, has_outer, has_inner in (("inner", False, True), ("outer", True, False)):
        wrapped = rewrap_capsule(
            pred_bytes,
            originator={
                "public_key": bob.public_key_hex,
                "private_key": bob.private_key_hex,
                "label": "Bob",
            },
            created_at=LATER,
            signed_at=LATER,
            recipients=[recipient],
            lineage_placement=placement,
        )
        o = CapsuleReader.from_bytes(wrapped["bytes"])
        assert ("predecessors" in o.manifest()) is has_outer, placement
        i = o.decrypt(recipient)
        assert ("predecessors" in i.manifest()) is has_inner, placement
        r = verify_capsule(i, outer_envelope=o.envelope(), outer_manifest=o.manifest())
        assert r["ok"] is True, placement


def test_encrypted_successor_l3_fails_closed_when_the_two_layers_disagree():
    alice = generate_ed25519()
    bob = generate_ed25519()
    recipient = generate_x25519()
    pred_bytes = _sealed_pred(alice)
    wrap = rewrap_capsule(
        pred_bytes,
        originator={
            "public_key": bob.public_key_hex,
            "private_key": bob.private_key_hex,
            "label": "Bob",
        },
        created_at=LATER,
        signed_at=LATER,
        recipients=[recipient],
        lineage_placement="both",
    )
    outer = CapsuleReader.from_bytes(wrap["bytes"])
    inner = outer.decrypt(recipient)
    # A capsule asserting one origin to the world and another to its
    # recipients is lying about itself across layers.
    forged_outer = dict(outer.manifest())
    forged_outer["predecessors"] = [{**forged_outer["predecessors"][0], "manifest_hash": "e" * 64}]
    result = verify_capsule(inner, outer_envelope=outer.envelope(), outer_manifest=forged_outer)
    assert result["ok"] is False
    assert any("predecessors differs between the inner and outer" in e for e in result["errors"])

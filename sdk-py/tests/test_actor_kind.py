"""spec/chain.md step-6 actor rule + the closed ``kind`` enum.

Mirrors sdk-js/test/actor-kind.test.js:

  - The actor rule is CONDITIONAL on the manifest's claim: when
    ``manifest.participants[]`` is non-empty, every event actor must be a
    declared participant or the literal ``"system:host"`` (fail-closed).
    When participants is empty, the capsule has made no claim about who
    is involved — verification succeeds and the verifier REPORTS the
    unbound actor set (``actor_set["bound"] is False`` plus a note),
    mirroring the signer_commitment "presence binds, absence reports"
    shape. Safe because participants is covered by manifest_hash inside
    the signed payload.
  - ``kind`` is a closed enum in every tier: both the verifier and the
    builder reject out-of-enum kinds unconditionally.
  - Error strings match the Rust verifier's shape verbatim (minus the
    ``seq N:`` prefix, which this lane carries as ``{"seq", "message"}``).
"""

from __future__ import annotations

import pytest

from capsule import (
    EVENT_KINDS,
    CapsuleBuilder,
    CapsuleReader,
    build_chain_events,
    generate_ed25519,
    verify_capsule,
    verify_chain,
)

TS = "2026-05-07T12:00:00Z"
PARTICIPANTS = [{"actor_id": "human:alice", "role": "originator", "label": "Alice"}]


def _bare(**overrides) -> list[dict]:
    event = {
        "actor": "human:alice",
        "kind": "decision",
        "action": "a",
        "target": "t",
        "timestamp": TS,
        "payload": {},
    }
    event.update(overrides)
    return [event]


def _builder(kp, participants=None) -> CapsuleBuilder:
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": "Acme"},
        participants=PARTICIPANTS if participants is None else participants,
        created_at=TS,
    )
    builder.set_program("# Actor rule\n")
    return builder


def _seal(builder, kp) -> bytes:
    return builder.seal(
        signers=[
            {"role": "originator", "public_key": kp.public_key, "private_key": kp.private_key}
        ],
        signed_at=TS,
    )


def _append_alice(builder) -> None:
    builder.append_event(
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "submit",
            "target": "program.md",
            "timestamp": TS,
        }
    )


# --- verify_chain: the per-event walk --------------------------------------


def test_verify_chain_flags_actor_not_in_participants():
    events = build_chain_events(_bare(actor="human:mallory"))
    result = verify_chain(events, participants=PARTICIPANTS)
    assert result["ok"] is False
    assert result["errors"] == [
        {
            "seq": 1,
            "message": 'actor "human:mallory" not in manifest.participants and not system:host',
        }
    ]


def test_verify_chain_accepts_any_actor_without_declared_participants():
    # Empty participants = the manifest makes no claim about who acted.
    events = build_chain_events(_bare(actor="human:anyone"))
    assert verify_chain(events, participants=[])["ok"] is True
    assert verify_chain(events)["ok"] is True


def test_verify_chain_accepts_system_host_either_way():
    events = build_chain_events(
        _bare(actor="system:host", kind="observation", action="session_ended")
    )
    assert verify_chain(events, participants=[])["ok"] is True
    assert verify_chain(events, participants=PARTICIPANTS)["ok"] is True


def test_verify_chain_rejects_unknown_kind():
    events = build_chain_events(_bare(kind="gossip"))
    result = verify_chain(events, participants=PARTICIPANTS)
    assert result["ok"] is False
    assert result["errors"] == [
        {
            "seq": 1,
            "message": (
                'kind "gossip" is not one of decision, observation, mutation, '
                "session, checkpoint"
            ),
        }
    ]


def test_verify_chain_rejects_unknown_kind_even_with_empty_participants():
    events = build_chain_events(_bare(kind="gossip"))
    result = verify_chain(events, participants=[])
    assert result["ok"] is False
    assert 'kind "gossip" is not one of' in result["errors"][0]["message"]


def test_verify_chain_accepts_every_enum_kind():
    for kind in EVENT_KINDS:
        events = build_chain_events(_bare(kind=kind))
        result = verify_chain(events, participants=PARTICIPANTS)
        assert result["ok"] is True, f"kind {kind} must be accepted: {result['errors']}"


# --- verify_capsule: wiring manifest participants through ------------------


def test_verify_capsule_enforces_actor_rule_against_declared_participants():
    kp = generate_ed25519()
    builder = _builder(kp)
    _append_alice(builder)
    # Swap the declared participant AFTER appending: the sealed manifest
    # still declares a NON-EMPTY set — just not the actor the chain
    # names. Every other commitment is recomputed at seal, so only the
    # actor rule can catch this.
    builder.participants = [{"actor_id": "human:bob", "role": "originator", "label": "Bob"}]
    data = _seal(builder, kp)

    result = verify_capsule(CapsuleReader.from_bytes(data), allowlist=[kp.public_key_hex])
    assert result["ok"] is False
    assert result["chain"]["ok"] is False
    assert result["actor_set"]["bound"] is True
    assert any(
        e["message"] == 'actor "human:alice" not in manifest.participants and not system:host'
        for e in result["chain"]["errors"]
    ), result["chain"]["errors"]


def test_verify_capsule_reports_unbound_actor_set_for_empty_participants():
    kp = generate_ed25519()
    builder = _builder(kp, participants=[])
    _append_alice(builder)
    result = verify_capsule(_seal(builder, kp), allowlist=[kp.public_key_hex])
    assert result["ok"] is True, result["errors"]
    assert result["actor_set"]["bound"] is False
    assert any(
        "chain actors are not bound to a declared participant set" in n
        for n in result["notes"]
    ), result["notes"]


def test_verify_capsule_green_when_actor_is_declared():
    kp = generate_ed25519()
    builder = _builder(kp)
    _append_alice(builder)
    result = verify_capsule(_seal(builder, kp), allowlist=[kp.public_key_hex])
    assert result["ok"] is True, result
    assert result["actor_set"]["bound"] is True
    assert not any("chain actors are not bound" in n for n in result["notes"])


def test_verify_capsule_rejects_unknown_kind_sealed_into_chain():
    kp = generate_ed25519()
    builder = _builder(kp)
    # append_event rejects this by design; push the bare event directly to
    # synthesize what a non-conformant writer would produce.
    builder.bare_events.append(_bare(kind="gossip")[0])
    result = verify_capsule(_seal(builder, kp), allowlist=[kp.public_key_hex])
    assert result["ok"] is False
    assert result["chain"]["ok"] is False
    assert any(
        'kind "gossip" is not one of' in e["message"] for e in result["chain"]["errors"]
    ), result["chain"]["errors"]


# --- CapsuleBuilder.append_event: writer obligations -----------------------


def test_append_event_rejects_actor_outside_declared_participants():
    kp = generate_ed25519()
    builder = _builder(kp)
    with pytest.raises(ValueError, match='event actor "human:mallory" is not a declared'):
        builder.append_event({"actor": "human:mallory", "action": "sneak"})


def test_append_event_accepts_any_actor_without_declared_participants():
    kp = generate_ed25519()
    builder = _builder(kp, participants=[])
    builder.append_event({"actor": "human:anyone", "action": "created_note"})
    assert builder.bare_events[0]["actor"] == "human:anyone"


def test_append_event_accepts_system_host_without_participant():
    kp = generate_ed25519()
    builder = _builder(kp)
    builder.append_event({"actor": "system:host", "action": "session_ended"})
    assert builder.bare_events[0]["actor"] == "system:host"


def test_append_event_rejects_unknown_kind():
    kp = generate_ed25519()
    builder = _builder(kp)
    with pytest.raises(ValueError, match='event kind "gossip" is not one of'):
        builder.append_event({"actor": "human:alice", "kind": "gossip", "action": "a"})


def test_append_event_rejects_unknown_kind_even_with_empty_participants():
    kp = generate_ed25519()
    builder = _builder(kp, participants=[])
    with pytest.raises(ValueError, match='event kind "gossip" is not one of'):
        builder.append_event({"actor": "human:anyone", "kind": "gossip", "action": "a"})

import pytest

from capsule.chain import (
    build_chain_events,
    events_from_jsonl,
    events_to_jsonl,
    first_and_entry_hash,
    hash_event,
    verify_chain,
)

GENESIS_PREV_HEX = "0" * 64


def test_hash_event_rejects_event_with_hash():
    with pytest.raises(ValueError):
        hash_event({"prev_hash": GENESIS_PREV_HEX, "hash": "x", "seq": 1})


def test_hash_event_rejects_bad_prev_hash():
    with pytest.raises(ValueError):
        hash_event({"prev_hash": "abc", "seq": 1})


def test_hash_event_returns_32_bytes():
    out = hash_event(
        {
            "seq": 1,
            "event_id": "evt_001",
            "actor": "human:alice",
            "kind": "decision",
            "action": "approved",
            "target": "program.md#step-3",
            "timestamp": "2026-05-07T12:00:00Z",
            "payload": {},
            "untrusted_payload_fields": [],
            "prev_hash": GENESIS_PREV_HEX,
        }
    )
    assert isinstance(out, bytes) and len(out) == 32


def test_build_chain_events_assigns_seq_and_links():
    bare = [
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "approved",
            "target": "program.md",
            "timestamp": "2026-05-07T12:00:00Z",
            "payload": {},
        },
        {
            "actor": "human:alice",
            "kind": "observation",
            "action": "noted",
            "target": "program.md",
            "timestamp": "2026-05-07T12:01:00Z",
            "payload": {},
        },
    ]
    events = build_chain_events(bare)
    assert len(events) == 2
    assert events[0]["seq"] == 1
    assert events[1]["seq"] == 2
    assert events[0]["event_id"] == "evt_001"
    assert events[1]["event_id"] == "evt_002"
    assert events[0]["prev_hash"] == GENESIS_PREV_HEX
    assert events[1]["prev_hash"] == events[0]["hash"]
    assert all(len(e["hash"]) == 64 for e in events)


def test_build_chain_events_default_untrusted_for_summary_and_statement():
    bare = [
        {
            "actor": "ai:claude",
            "kind": "observation",
            "action": "summarized",
            "target": "program.md",
            "timestamp": "2026-05-07T12:00:00Z",
            "payload": {"summary": "the patient reports …", "statement": "X is Y"},
        }
    ]
    [e] = build_chain_events(bare)
    assert sorted(e["untrusted_payload_fields"]) == [
        "payload.statement",
        "payload.summary",
    ]


def test_build_chain_events_explicit_untrusted_overrides_default():
    bare = [
        {
            "actor": "ai:claude",
            "kind": "observation",
            "action": "summarized",
            "target": "program.md",
            "timestamp": "2026-05-07T12:00:00Z",
            "payload": {"summary": "x"},
            "untrusted_payload_fields": [],
        }
    ]
    [e] = build_chain_events(bare)
    assert e["untrusted_payload_fields"] == []


def test_events_to_jsonl_and_back():
    bare = [
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "approved",
            "target": "program.md",
            "timestamp": "2026-05-07T12:00:00Z",
            "payload": {},
        }
    ]
    events = build_chain_events(bare)
    jsonl = events_to_jsonl(events)
    assert isinstance(jsonl, bytes)
    assert jsonl.endswith(b"\n")
    parsed = events_from_jsonl(jsonl)
    assert parsed == events


def test_events_from_jsonl_skips_blank_lines():
    raw = b'{"a":1}\n\n{"b":2}\n'
    out = events_from_jsonl(raw)
    assert out == [{"a": 1}, {"b": 2}]


def test_verify_chain_clean_passes():
    bare = [
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "approved",
            "target": "program.md",
            "timestamp": "2026-05-07T12:00:00Z",
            "payload": {},
        },
        {
            "actor": "human:alice",
            "kind": "observation",
            "action": "noted",
            "target": "program.md",
            "timestamp": "2026-05-07T12:01:00Z",
            "payload": {},
        },
    ]
    events = build_chain_events(bare)
    result = verify_chain(events)
    assert result["ok"] is True
    assert result["errors"] == []


def test_verify_chain_detects_hash_tampering():
    bare = [
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "approved",
            "target": "program.md",
            "timestamp": "2026-05-07T12:00:00Z",
            "payload": {},
        }
    ]
    events = build_chain_events(bare)
    events[0]["hash"] = "f" * 64
    result = verify_chain(events)
    assert result["ok"] is False
    assert any("hash mismatch" in err["message"] for err in result["errors"])


def test_verify_chain_detects_seq_skip():
    bare = [
        {
            "actor": "h:a",
            "kind": "decision",
            "action": "x",
            "target": "p",
            "timestamp": "2026-05-07T12:00:00Z",
            "payload": {},
        },
        {
            "actor": "h:a",
            "kind": "decision",
            "action": "x",
            "target": "p",
            "timestamp": "2026-05-07T12:01:00Z",
            "payload": {},
        },
    ]
    events = build_chain_events(bare)
    events[1]["seq"] = 5
    result = verify_chain(events)
    assert result["ok"] is False
    assert any("seq" in err["message"] for err in result["errors"])


def test_first_and_entry_hash():
    bare = [
        {
            "actor": "h:a",
            "kind": "decision",
            "action": "x",
            "target": "p",
            "timestamp": "2026-05-07T12:00:00Z",
            "payload": {},
        },
        {
            "actor": "h:a",
            "kind": "decision",
            "action": "y",
            "target": "p",
            "timestamp": "2026-05-07T12:01:00Z",
            "payload": {},
        },
    ]
    events = build_chain_events(bare)
    first, entry = first_and_entry_hash(events)
    assert first == events[0]["hash"]
    assert entry == events[-1]["hash"]

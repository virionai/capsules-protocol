"""Event chain build + verify. Mirrors sdk/src/chain.js."""

from __future__ import annotations

import json
from typing import TypedDict

from .canonical import bytes_to_hex, concat_bytes, hex_to_bytes, jcs, sha256

GENESIS_PREV_BYTES: bytes = b"\x00" * 32
GENESIS_PREV_HEX: str = "0" * 64


class ChainError(TypedDict):
    seq: int
    message: str


class ChainResult(TypedDict):
    ok: bool
    errors: list[ChainError]


def hash_event(event: dict) -> bytes:
    """Compute event hash. event must NOT include 'hash'; prev_hash must be 64-hex.
    Returns 32 bytes."""
    if "hash" in event:
        raise ValueError("hash_event: event must not include 'hash'")
    prev_hex = event.get("prev_hash")
    if not isinstance(prev_hex, str) or len(prev_hex) != 64:
        raise ValueError("hash_event: prev_hash must be 64-hex")
    prev_raw = hex_to_bytes(prev_hex)
    canonical = jcs(event)
    return sha256(concat_bytes(prev_raw, canonical))


def build_chain_events(bare_events: list[dict]) -> list[dict]:
    """Walk a list of bare events and assign prev_hash + hash + seq + event_id."""
    out: list[dict] = []
    prev = GENESIS_PREV_BYTES
    for i, bare in enumerate(bare_events):
        seq = i + 1
        event_id = bare.get("event_id") or f"evt_{seq:03d}"
        e: dict = {
            "seq": seq,
            "event_id": event_id,
            **{k: v for k, v in bare.items() if k != "event_id"},
            "prev_hash": bytes_to_hex(prev),
        }
        if "payload" not in e or e["payload"] is None:
            e["payload"] = {}
        if not isinstance(e.get("untrusted_payload_fields"), list):
            cands: list[str] = []
            payload = e["payload"]
            if isinstance(payload, dict):
                if isinstance(payload.get("summary"), str):
                    cands.append("payload.summary")
                if isinstance(payload.get("statement"), str):
                    cands.append("payload.statement")
            e["untrusted_payload_fields"] = cands
        h = hash_event(e)
        e["hash"] = bytes_to_hex(h)
        out.append(e)
        prev = h
    return out


def events_to_jsonl(events: list[dict]) -> bytes:
    """Serialize built events into JSONL bytes."""
    lines = [json.dumps(e, separators=(",", ":"), ensure_ascii=False) for e in events]
    return ("\n".join(lines) + "\n").encode("utf-8")


def events_from_jsonl(data: bytes) -> list[dict]:
    """Parse JSONL bytes into events."""
    text = data.decode("utf-8")
    out = []
    for i, line in enumerate(text.split("\n")):
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError as ex:
            raise ValueError(f"chain line {i + 1}: invalid JSON: {ex.msg}") from ex
    return out


def verify_chain(events: list[dict]) -> ChainResult:
    """Verify a chain. Returns ChainResult with ok and collected errors."""
    errors: list[ChainError] = []
    prev = GENESIS_PREV_BYTES
    for i, e in enumerate(events):
        seq = e.get("seq", i + 1)
        if e.get("seq") != i + 1:
            errors.append({"seq": seq, "message": f"seq {e.get('seq')} expected {i + 1}"})
        if not isinstance(e.get("prev_hash"), str) or len(e["prev_hash"]) != 64:
            errors.append({"seq": seq, "message": "prev_hash missing or wrong length"})
            continue
        expected_prev = bytes_to_hex(prev)
        if e["prev_hash"] != expected_prev:
            errors.append(
                {
                    "seq": seq,
                    "message": f"prev_hash mismatch: got {e['prev_hash']}, expected {expected_prev}",
                }
            )
        if not isinstance(e.get("hash"), str) or len(e["hash"]) != 64:
            errors.append({"seq": seq, "message": "hash missing or wrong length"})
            continue
        rest = {k: v for k, v in e.items() if k != "hash"}
        try:
            recomputed = bytes_to_hex(hash_event(rest))
        except ValueError as ex:
            errors.append({"seq": seq, "message": f"recompute failed: {ex}"})
            continue
        if recomputed != e["hash"]:
            errors.append(
                {
                    "seq": seq,
                    "message": f"hash mismatch: stored {e['hash']}, recomputed {recomputed}",
                }
            )
        prev = hex_to_bytes(e["hash"])
    return {"ok": len(errors) == 0, "errors": errors}


def first_and_entry_hash(events: list[dict]) -> tuple[str, str]:
    """Return (first_event_hash, entry_hash) for the chain."""
    if not events:
        raise ValueError("chain is empty")
    return events[0]["hash"], events[-1]["hash"]

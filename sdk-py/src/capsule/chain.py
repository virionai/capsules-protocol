"""Event chain build + verify. Mirrors sdk/src/chain.js."""

from __future__ import annotations

import json
import re
from typing import TypedDict

from .canonical import bytes_to_hex, concat_bytes, hex_to_bytes, jcs, loads_strict, sha256

GENESIS_PREV_BYTES: bytes = b"\x00" * 32
GENESIS_PREV_HEX: str = "0" * 64

#: The closed ``kind`` enum from spec/chain.md "Field rules". Readers reject
#: unknown kinds and builders refuse to append them — in every tier, because
#: a custom kind is not a weaker claim, it is unreadable to the foreign LLM
#: reader the format serves.
EVENT_KINDS: tuple[str, ...] = (
    "decision",
    "observation",
    "mutation",
    "session",
    "checkpoint",
)

_EVENT_KIND_SET = frozenset(EVENT_KINDS)

#: The one actor a chain event may always name without a matching manifest
#: participant — backstop events emitted by the host runtime.
HOST_ACTOR = "system:host"


def is_valid_event_kind(kind: object) -> bool:
    """True when ``kind`` is one of the five values spec/chain.md allows."""
    return isinstance(kind, str) and kind in _EVENT_KIND_SET


#: The normative ``untrusted_payload_fields`` path grammar from spec/chain.md
#: "Untrusted content"::
#:
#:     path    = "payload" 1*( "." segment )
#:     segment = 1*( ALPHA / DIGIT / "_" / "-" )
#:
#: A marking outside the grammar has no defined resolution -- a host cannot
#: tell which payload member the author marked untrusted -- so writers refuse
#: to emit it and verifiers reject it fail-closed.
_UNTRUSTED_PAYLOAD_PATH = re.compile(r"^payload(\.[A-Za-z0-9_-]+)+$")


def is_valid_untrusted_payload_path(path: object) -> bool:
    """True when ``path`` is a well-formed untrusted-payload path."""
    return isinstance(path, str) and _UNTRUSTED_PAYLOAD_PATH.match(path) is not None


#: The CLOSED actor-id namespace set from spec/manifest.md "Field rules":
#: ``participants[].actor_id`` must match ``human:<id>``, ``ai:<id>``,
#: ``system:<id>``, or ``capsule:<id>`` with a non-empty ``<id>``.
ACTOR_NAMESPACES: tuple[str, ...] = ("human", "ai", "system", "capsule")

_ACTOR_NAMESPACE_SET = frozenset(ACTOR_NAMESPACES)


def is_valid_actor_id(actor_id: object) -> bool:
    """True when ``actor_id`` is ``<namespace>:<id>`` with a known namespace
    and non-empty id. Case-sensitive; no surrounding whitespace allowed."""
    if not isinstance(actor_id, str):
        return False
    namespace, sep, ident = actor_id.partition(":")
    return sep == ":" and namespace in _ACTOR_NAMESPACE_SET and len(ident) > 0


def participant_actor_id_problems(participants: object) -> list[str]:
    """Validate a manifest ``participants[]`` list against the actor-id
    namespace grammar. Returns a list of problem strings (empty =
    well-formed); each is prefixed ``participants[i]`` so callers can add
    their own context (``manifest.`` in the verifier). Accepts the same
    shapes ``participant_actor_ids`` does — bare actor-id strings or
    mappings with ``actor_id`` — and, unlike it, FLAGS entries it cannot
    interpret: a declared set that cannot be interpreted is not a weaker
    claim, it is a malformed one. A non-list participants value is
    outside this function's scope.
    """
    problems: list[str] = []
    if not isinstance(participants, (list, tuple)):
        return problems
    grammar = "(human:, ai:, system:, capsule:)"
    for i, p in enumerate(participants):
        actor_id = p if isinstance(p, str) else (p.get("actor_id") if isinstance(p, dict) else None)
        if not isinstance(actor_id, str):
            problems.append(
                f"participants[{i}].actor_id must be a string in an allowed namespace {grammar}"
            )
        elif not is_valid_actor_id(actor_id):
            problems.append(
                f"participants[{i}].actor_id {json.dumps(actor_id)} "
                f"does not match an allowed namespace {grammar}"
            )
    return problems


def participant_actor_ids(participants: object) -> set[str]:
    """Normalize a manifest ``participants[]`` list into a set of actor ids.

    Accepts participant mappings (``{"actor_id": ...}``) or bare actor-id
    strings; anything else is ignored.
    """
    out: set[str] = set()
    if not isinstance(participants, (list, tuple)):
        return out
    for p in participants:
        if isinstance(p, str):
            out.add(p)
        elif isinstance(p, dict) and isinstance(p.get("actor_id"), str):
            out.add(p["actor_id"])
    return out

# Chain-bound hex is lowercase per spec/chain.md. verify_chain feeds a
# stored hash straight into hex_to_bytes to seed the next link, so the
# canonical-form check has to happen before that call, not inside it.
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _is_hex64(value) -> bool:
    return isinstance(value, str) and _HEX64.match(value) is not None


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
            # Strict parse: the duplicate-member gate runs during parsing
            # (spec/canonicalization.md "Objects") before the value can
            # reach a hash comparison.
            out.append(loads_strict(line))
        except json.JSONDecodeError as ex:
            raise ValueError(f"chain line {i + 1}: invalid JSON: {ex.msg}") from ex
    return out


def verify_chain(events: list[dict], *, participants: object = None) -> ChainResult:
    """Verify a chain. Returns ChainResult with ok and collected errors.

    ``participants`` is the manifest's ``participants[]``. The
    spec/chain.md step-6 actor rule is CONDITIONAL on that claim: when the
    set is non-empty, every event actor must be a member or the literal
    ``"system:host"`` (fail-closed); when it is empty or absent, the
    manifest binds no actor set and the walk accepts any actor — the
    CALLER (``verify_capsule``) reports the reduced assurance. The
    ``kind`` enum is enforced unconditionally.
    """
    errors: list[ChainError] = []
    participant_ids = participant_actor_ids(participants)
    prev = GENESIS_PREV_BYTES
    for i, e in enumerate(events):
        if not isinstance(e, dict):
            errors.append({"seq": i + 1, "message": "event is not a JSON object"})
            continue
        seq = e.get("seq", i + 1)
        # spec/chain.md step 6 — when the manifest declares participants,
        # the actor must be one of them or the host. An empty set is no
        # claim.
        actor = e.get("actor")
        if participant_ids and actor != HOST_ACTOR and actor not in participant_ids:
            errors.append(
                {
                    "seq": seq,
                    "message": (
                        f"actor {json.dumps(actor)} not in manifest.participants "
                        "and not system:host"
                    ),
                }
            )
        # spec/chain.md "Field rules" — `kind` is a closed enum.
        if not is_valid_event_kind(e.get("kind")):
            errors.append(
                {
                    "seq": seq,
                    "message": (
                        f"kind {json.dumps(e.get('kind'))} is not one of "
                        + ", ".join(EVENT_KINDS)
                    ),
                }
            )
        if e.get("seq") != i + 1:
            errors.append({"seq": seq, "message": f"seq {e.get('seq')} expected {i + 1}"})
        # spec/chain.md "Untrusted content" -- when present, every marking
        # must match the path grammar. An unparseable marking silently
        # unmarks LLM-authored content for every downstream host.
        if "untrusted_payload_fields" in e:
            upf = e["untrusted_payload_fields"]
            if not isinstance(upf, list):
                errors.append(
                    {
                        "seq": seq,
                        "message": "untrusted_payload_fields must be an array of payload paths",
                    }
                )
            else:
                for idx, path in enumerate(upf):
                    if not is_valid_untrusted_payload_path(path):
                        errors.append(
                            {
                                "seq": seq,
                                "message": (
                                    f"untrusted_payload_fields[{idx}] is not a valid "
                                    f"payload path: {json.dumps(path)}"
                                ),
                            }
                        )
        if not isinstance(e.get("prev_hash"), str) or len(e["prev_hash"]) != 64:
            errors.append({"seq": seq, "message": "prev_hash missing or wrong length"})
            continue
        if not _is_hex64(e["prev_hash"]):
            errors.append({"seq": seq, "message": "prev_hash is not canonical lowercase hex"})
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
        if not _is_hex64(e["hash"]):
            errors.append({"seq": seq, "message": "hash is not canonical lowercase hex"})
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


def first_and_entry_hash(events: list[dict]) -> tuple[str | None, str | None]:
    """Return (first_event_hash, entry_hash) for the chain.

    Returns None for an event that is not an object or carries no hash,
    matching sdk-js: the caller compares against the envelope and reports
    a mismatch rather than raising.
    """
    if not events:
        raise ValueError("chain is empty")

    def _hash_of(e):
        return e.get("hash") if isinstance(e, dict) else None

    return _hash_of(events[0]), _hash_of(events[-1])

"""manifest.json construction + capsule_id + content_index. Mirrors sdk/src/manifest.js."""

from __future__ import annotations

from collections.abc import Mapping

from .canonical import (
    bytes_to_hex,
    concat_bytes,
    hex_to_bytes,
    jcs,
    sha256,
    sha256_hex,
)

_ID_DOMAIN = b"capsule-id-v0.6\x00"

CONTENT_INDEX_EXCLUDED: frozenset[str] = frozenset(
    {
        "manifest.json",
        "provenance/envelope.json",
        "content.enc",
    }
)


def compute_capsule_id(originator_pub_raw: bytes, first_event_hash_hex: str) -> str:
    if len(originator_pub_raw) != 32:
        raise ValueError("originator pubkey must be 32 bytes")
    if not isinstance(first_event_hash_hex, str) or len(first_event_hash_hex) != 64:
        raise ValueError("first_event_hash must be 64-hex")
    feh_raw = hex_to_bytes(first_event_hash_hex)
    out = sha256(concat_bytes(_ID_DOMAIN, bytes(originator_pub_raw), feh_raw))
    return bytes_to_hex(out)


def build_content_index(files: Mapping[str, bytes]) -> dict:
    entries = [
        {"path": path, "sha256": sha256_hex(data)}
        for path, data in files.items()
        if path not in CONTENT_INDEX_EXCLUDED
    ]
    entries.sort(key=lambda e: e["path"])
    return {"files": entries, "index_hash": sha256_hex(jcs(entries))}


def build_manifest(
    *,
    originator: dict,
    participants: list[dict],
    content_index: dict,
    first_event_hash: str,
    skill_trust: dict | None = None,
    encryption: dict | None = None,
    created_at: str,
) -> dict:
    return {
        "format": {
            "version": "0.6",
            "container": "zip",
            "canonicalization": "JCS-RFC8785",
            "hash_algorithm": "SHA-256",
        },
        "id": "",
        "originator": originator,
        "participants": participants,
        "first_event_hash": first_event_hash,
        "content_index": content_index,
        "skill_trust": skill_trust if skill_trust is not None else {},
        "encryption": encryption,
        "created_at": created_at,
    }


def manifest_hash(manifest: dict) -> str:
    return sha256_hex(jcs(manifest))


def manifest_bytes(manifest: dict) -> bytes:
    return jcs(manifest)

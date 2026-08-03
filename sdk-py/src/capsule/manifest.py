"""manifest.json construction + capsule_id + content_index. Mirrors sdk/src/manifest.js."""

from __future__ import annotations

import re
from collections.abc import Mapping

from .canonical import (
    bytes_to_hex,
    concat_bytes,
    hex_to_bytes,
    jcs,
    sha256,
    sha256_hex,
    utf16_sort_key,
)
from .versions import CURRENT_VERSION, id_domain



# Excluded from the content index by structural necessity, for every capsule:
# manifest.json holds the index (circular) and provenance/envelope.json commits
# to the index hash (circular).
STRUCTURAL_EXCLUDED: frozenset[str] = frozenset(
    {
        "manifest.json",
        "provenance/envelope.json",
    }
)

# content.enc is excluded ONLY for encrypted capsules, where it is bound by
# envelope.encrypted_blob_hash. In a plain capsule a stray content.enc must be
# indexed (and will therefore fail verification), so a signed plain capsule
# cannot smuggle an unaccounted-for blob past the verifier.
CONTENT_INDEX_EXCLUDED: frozenset[str] = STRUCTURAL_EXCLUDED | {"content.enc"}


def content_index_exclusions(encrypted: bool) -> frozenset[str]:
    """Choose the content-index exclusion set for the capsule's profile."""
    return CONTENT_INDEX_EXCLUDED if encrypted else STRUCTURAL_EXCLUDED


def compute_capsule_id(
    originator_pub_raw: bytes,
    first_event_hash_hex: str | None,
    version: str = CURRENT_VERSION,
) -> str:
    """Derive capsule_id; all inputs are raw bytes, no hex strings.

    A zero-event capsule (spec/chain.md "Empty chains") has no first
    event: its manifest carries ``first_event_hash: null``, and the
    derivation uses 32 zero bytes — the genesis prev-hash value — in
    place of ``first_event_hash_raw`` (spec/manifest.md "id").

    The hash domain embeds the capsule's format version
    (``capsule-id-v<version>\0``), so derivation is KEYED by the
    DECLARED version (spec/versioning.md): a verifier checking a v0.6
    capsule uses the v0.6 domain forever, whatever version it seals at.
    """
    if len(originator_pub_raw) != 32:
        raise ValueError("originator pubkey must be 32 bytes")
    if first_event_hash_hex is None:
        feh_raw = b"\x00" * 32  # genesis stand-in for an empty chain
    elif isinstance(first_event_hash_hex, str) and len(first_event_hash_hex) == 64:
        feh_raw = hex_to_bytes(first_event_hash_hex)
    else:
        raise ValueError("first_event_hash must be 64-hex or null (empty chain)")
    out = sha256(concat_bytes(id_domain(version), bytes(originator_pub_raw), feh_raw))
    return bytes_to_hex(out)


def build_content_index(
    files: Mapping[str, bytes],
    excluded: frozenset[str] = STRUCTURAL_EXCLUDED,
) -> dict:
    entries = [
        {"path": path, "sha256": sha256_hex(data)}
        for path, data in files.items()
        if path not in excluded
    ]
    # content_index.files is a JSON *array*: JCS preserves array order, so
    # this sort is part of the hashed bytes. Use the same UTF-16 code-unit
    # comparator JCS uses for object members, and that the JS reference lane
    # gets for free from `a < b` on JS strings.
    entries.sort(key=lambda e: utf16_sort_key(e["path"]))
    return {"files": entries, "index_hash": sha256_hex(jcs(entries))}


# ---------------------------------------------------------------------------
# Signer-set commitment (manifest.signer_commitment).
#
# The envelope's signing input is JCS(envelope minus signers), so signers[]
# is not an input to any signature — and provenance/envelope.json is
# structurally excluded from the content index. The commitment closes that
# gap: the manifest stores the exact (role, public_key) membership of the
# seal-time signer set, and manifest_hash IS inside every signature, so the
# set is transitively signed by every signer. See spec/manifest.md.
# ---------------------------------------------------------------------------

_SIGNER_KEY_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def commitment_member_key(member: dict) -> tuple[str, str]:
    """Sort key: ascending by public_key, then role (byte order)."""
    return (member["public_key"], member["role"])


def signer_commitment_problems(commitment) -> list[str]:
    """Validate a stored signer_commitment value; [] means well-formed.

    Rules (spec/manifest.md): non-empty array; each member is an object
    with exactly `role` (non-empty string) and `public_key` (lowercase
    64-hex); members sorted ascending by (public_key, role); pairs unique.
    """
    if not isinstance(commitment, list):
        return ["must be a non-empty array of {role, public_key}"]
    if len(commitment) == 0:
        return ["must not be empty when present"]
    problems: list[str] = []
    for i, m in enumerate(commitment):
        if not isinstance(m, dict):
            problems.append(f"member {i} is not an object")
            continue
        if sorted(m.keys()) != ["public_key", "role"]:
            problems.append(f"member {i} must carry exactly {{role, public_key}}")
            continue
        if not isinstance(m["role"], str) or not m["role"]:
            problems.append(f"member {i}: role must be a non-empty string")
        if not isinstance(m["public_key"], str) or not _SIGNER_KEY_HEX_RE.match(m["public_key"]):
            problems.append(f"member {i}: public_key must be lowercase 64-hex")
    if problems:
        return problems
    for i in range(1, len(commitment)):
        prev = commitment_member_key(commitment[i - 1])
        cur = commitment_member_key(commitment[i])
        if prev == cur:
            problems.append(
                f"duplicate member (role={commitment[i]['role']}, "
                f"public_key={commitment[i]['public_key']})"
            )
        elif prev > cur:
            problems.append("members not sorted ascending by (public_key, role)")
            break
    return problems


def build_signer_commitment(members: list[dict]) -> list[dict]:
    """Build a well-formed signer_commitment from seal-time members.

    Sorts ascending by (public_key, role) and raises on duplicate
    (role, public_key) pairs — the same key under different roles is
    permitted as distinct members.
    """
    out = sorted(
        ({"role": m["role"], "public_key": m["public_key"].lower()} for m in members),
        key=commitment_member_key,
    )
    for i in range(1, len(out)):
        if commitment_member_key(out[i - 1]) == commitment_member_key(out[i]):
            raise ValueError(
                f"duplicate signer (role={out[i]['role']}, public_key={out[i]['public_key']})"
            )
    return out


def build_manifest(
    *,
    originator: dict,
    participants: list[dict],
    content_index: dict,
    first_event_hash: str,
    encryption: dict | None = None,
    created_at: str,
    signer_commitment: list[dict] | None = None,
) -> dict:
    """Build a v0.6 manifest object (without ``id`` populated).

    Deliberately absent: any ``skill_trust`` member. Skill trust is
    host-relative and DERIVED at verify time (spec/trust.md); a capsule
    from an earlier draft that carries the member is treated as having an
    inert unknown member — preserved and hashed, never read as authority.
    """
    manifest = {
        "format": {
            "version": CURRENT_VERSION,
            "container": "zip",
            "canonicalization": "JCS-RFC8785",
            "hash_algorithm": "SHA-256",
        },
        "id": "",
        "originator": originator,
        "participants": participants,
        "first_event_hash": first_event_hash,
        "content_index": content_index,
        "encryption": encryption,
        "created_at": created_at,
    }
    # Optional: templates and other unsigned tiers legitimately omit it.
    # JCS sorts keys at serialization time, so insertion position is
    # irrelevant to the canonical bytes.
    if signer_commitment is not None:
        manifest["signer_commitment"] = signer_commitment
    return manifest


def manifest_hash(manifest: dict) -> str:
    return sha256_hex(jcs(manifest))


def manifest_bytes(manifest: dict) -> bytes:
    return jcs(manifest)

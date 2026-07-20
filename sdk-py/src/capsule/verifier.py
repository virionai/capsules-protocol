"""verify_capsule (L2 plain). Mirrors sdk/src/verifier.js."""

from __future__ import annotations

from typing import TypedDict
from zipfile import BadZipFile

from .canonical import hex_to_bytes, sha256_hex
from .chain import first_and_entry_hash, verify_chain
from .envelope import verify_envelope_signatures
from .keys import to_key_hex
from .manifest import (
    build_content_index,
    compute_capsule_id,
    content_index_exclusions,
    manifest_hash,
)
from .reader import CapsuleReader


class _ContentIndexResult(TypedDict):
    ok: bool
    errors: list[str]


class _EnvelopeSummary(TypedDict):
    ok: bool
    signers: list[dict]


class VerifyResult(TypedDict):
    ok: bool
    level: str
    errors: list[str]
    chain: dict
    content_index: _ContentIndexResult
    envelope: _EnvelopeSummary
    trusted_signer_count: int
    notes: list[str]


def verify_capsule(
    reader,
    *,
    allowlist: list | None = None,
    outer_envelope: dict | None = None,
) -> VerifyResult:
    """Verify a capsule.

    Accepts a ``CapsuleReader`` or the raw ``.capsule`` bytes. Given
    bytes, a container that cannot even be opened (malformed ZIP,
    missing or invalid manifest/envelope) returns a fail-closed result
    instead of raising, so app code has a single failure path.

    ``allowlist`` entries may be hex strings (any case) or 32 raw bytes.
    """
    if isinstance(reader, (bytes, bytearray, memoryview)):
        try:
            reader = CapsuleReader.from_bytes(bytes(reader))
        except (ValueError, BadZipFile) as e:
            return {
                "ok": False,
                "level": "L2",
                "errors": [f"capsule cannot be opened: {e}"],
                "chain": {"ok": False, "errors": []},
                "content_index": {"ok": False, "errors": []},
                "envelope": {"ok": False, "signers": []},
                "trusted_signer_count": 0,
                "notes": [],
            }
    allow = {to_key_hex(k, f"allowlist[{i}]") for i, k in enumerate(allowlist or [])}
    errors: list[str] = []
    notes: list[str] = []
    result: VerifyResult = {
        "ok": False,
        "level": "L3" if outer_envelope is not None else "L2",
        "errors": errors,
        "chain": {"ok": False, "errors": []},
        "content_index": {"ok": False, "errors": []},
        "envelope": {"ok": False, "signers": []},
        "trusted_signer_count": 0,
        "notes": notes,
    }

    manifest = reader.manifest()
    envelope = reader.envelope()

    # Format / version checks
    if manifest.get("format", {}).get("version") != "0.6":
        errors.append(
            f"unsupported manifest format.version: {manifest.get('format', {}).get('version')}"
        )
    if envelope.get("version") != "0.6":
        errors.append(f"unsupported envelope version: {envelope.get('version')}")

    # Capsule identity
    try:
        expected_id = compute_capsule_id(
            hex_to_bytes(manifest["originator"]["public_key"]),
            manifest["first_event_hash"],
        )
        if expected_id != manifest.get("id"):
            errors.append(
                f"manifest.id mismatch: stored {manifest.get('id')}, expected {expected_id}"
            )
        if expected_id != envelope.get("capsule_id"):
            errors.append(
                f"envelope.capsule_id mismatch: {envelope.get('capsule_id')} vs derived {expected_id}"
            )
    except (KeyError, ValueError, TypeError) as e:
        errors.append(f"capsule_id derivation failed: {e}")

    # Manifest hash
    try:
        recomputed_mf_hash = manifest_hash(manifest)
        if recomputed_mf_hash != envelope.get("manifest_hash"):
            errors.append(
                "envelope.manifest_hash mismatch: "
                f"{envelope.get('manifest_hash')} vs recomputed {recomputed_mf_hash}"
            )
    except Exception as e:
        errors.append(f"manifest hash recompute failed: {e}")

    # Content index. content.enc is excluded only when the capsule declares a
    # cipher (bound instead by envelope.encrypted_blob_hash). Key off the signed
    # envelope.cipher, not file presence: a stray content.enc injected into a
    # plain (cipher="none") capsule is indexed here and therefore fails
    # verification, and forcing its exclusion would break the envelope signature.
    excluded = content_index_exclusions(envelope.get("cipher") not in (None, "none"))
    files = reader.files()
    index_files = {p: b for p, b in files.items() if p not in excluded}
    try:
        recomputed = build_content_index(index_files, excluded)
    except Exception as e:
        result["content_index"]["errors"].append(f"recompute failed: {e}")
        recomputed = {"files": [], "index_hash": ""}

    stored_files = manifest.get("content_index", {}).get("files", [])
    stored_map = {f["path"]: f["sha256"] for f in stored_files}

    ci_ok = True
    if recomputed["index_hash"] != manifest.get("content_index", {}).get("index_hash"):
        ci_ok = False
        result["content_index"]["errors"].append(
            "manifest.content_index.index_hash does not match recomputed"
        )
    for f in recomputed["files"]:
        if f["path"] not in stored_map:
            ci_ok = False
            result["content_index"]["errors"].append(
                f"file present but not in manifest index: {f['path']}"
            )
        elif stored_map[f["path"]] != f["sha256"]:
            ci_ok = False
            result["content_index"]["errors"].append(f"file hash mismatch: {f['path']}")
    recomputed_paths = {f["path"] for f in recomputed["files"]}
    for f in stored_files:
        if f["path"] not in recomputed_paths:
            ci_ok = False
            result["content_index"]["errors"].append(
                f"file in manifest index but missing from package: {f['path']}"
            )
    if recomputed["index_hash"] != envelope.get("content_index_hash"):
        ci_ok = False
        result["content_index"]["errors"].append(
            "envelope.content_index_hash mismatch: "
            f"{envelope.get('content_index_hash')} vs recomputed {recomputed['index_hash']}"
        )
    result["content_index"]["ok"] = ci_ok and not result["content_index"]["errors"]

    # Encrypted blob hash sanity (matches sdk/src/verifier.js lines 127-145)
    if reader.is_encrypted():
        blob = reader.encrypted_blob_bytes()
        recomputed = sha256_hex(blob)
        if recomputed != envelope.get("encrypted_blob_hash"):
            errors.append(
                "envelope.encrypted_blob_hash mismatch: "
                f"{envelope.get('encrypted_blob_hash')} vs recomputed {recomputed}"
            )
        if envelope.get("cipher") == "none":
            errors.append("encrypted blob present but envelope.cipher is 'none'")
    else:
        if envelope.get("encrypted_blob_hash") is not None:
            errors.append("plain capsule must have envelope.encrypted_blob_hash=null")
        if envelope.get("cipher") != "none":
            errors.append(f"plain capsule must have cipher='none', got {envelope.get('cipher')!r}")

    # Chain
    if not reader.is_encrypted():
        # Fail closed, matching the Rust verifier: a plain capsule with no
        # chain file surfaces as a chain error in the result rather than an
        # exception out of verify_capsule.
        try:
            events = reader.events()
        except ValueError as e:  # MalformedCapsuleError is a ValueError
            events = []
            result["chain"] = {"ok": False, "errors": [{"seq": 0, "message": str(e)}]}
        else:
            chain_result = verify_chain(events)
            result["chain"] = chain_result
        if events:
            first_eh, entry_h = first_and_entry_hash(events)
            if first_eh != envelope.get("first_event_hash"):
                errors.append(
                    "envelope.first_event_hash mismatch: "
                    f"{envelope.get('first_event_hash')} vs {first_eh}"
                )
            if entry_h != envelope.get("entry_hash"):
                errors.append(
                    f"envelope.entry_hash mismatch: {envelope.get('entry_hash')} vs {entry_h}"
                )
    else:
        # Encrypted outer — chain verification deferred to L3.
        result["chain"] = {
            "ok": True,
            "errors": [],
            "note": "deferred to L3 (encrypted outer)",
        }

    # Envelope signatures
    env_result = verify_envelope_signatures(envelope)
    if not env_result["ok"] and env_result.get("note"):
        errors.append(env_result["note"])
    result["envelope"]["ok"] = env_result["ok"]
    signers = []
    for s in env_result.get("signers", []):
        trusted = bool(s.get("valid")) and ((s.get("public_key") or "").lower() in allow)
        signers.append(
            {
                "role": s.get("role"),
                "public_key": s.get("public_key"),
                "valid": s.get("valid"),
                "trusted": trusted,
            }
        )
    result["envelope"]["signers"] = signers
    result["trusted_signer_count"] = sum(1 for s in signers if s["trusted"])

    if not allow:
        notes.append(
            "no allowlist provided; trusted=False for all signers regardless of signature validity"
        )

    # L3: cross-check inner envelope against the supplied outer envelope.
    if outer_envelope is not None:
        if outer_envelope.get("capsule_id") != envelope.get("capsule_id"):
            errors.append("L3: inner.capsule_id does not match outer.capsule_id")
        if outer_envelope.get("first_event_hash") != envelope.get("first_event_hash"):
            errors.append("L3: inner.first_event_hash does not match outer.first_event_hash")
        if outer_envelope.get("entry_hash") != envelope.get("entry_hash"):
            errors.append("L3: inner.entry_hash does not match outer.entry_hash")

    result["ok"] = (
        not errors
        and result["content_index"]["ok"]
        and result["chain"]["ok"]
        and result["envelope"]["ok"]
    )
    return result

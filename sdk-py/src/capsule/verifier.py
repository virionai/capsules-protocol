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
    commitment_member_key,
    compute_capsule_id,
    content_index_exclusions,
    manifest_hash,
    signer_commitment_problems,
)
from .reader import CapsuleReader


class _ContentIndexResult(TypedDict):
    ok: bool
    errors: list[str]


class _EnvelopeSummary(TypedDict):
    ok: bool
    signers: list[dict]


class _SignerSetResult(TypedDict):
    bound: bool
    ok: bool
    errors: list[str]


class VerifyResult(TypedDict):
    ok: bool
    level: str
    errors: list[str]
    chain: dict
    content_index: _ContentIndexResult
    envelope: _EnvelopeSummary
    signer_set: _SignerSetResult
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
                "signer_set": {"bound": False, "ok": False, "errors": []},
                "trusted_signer_count": 0,
                "notes": [],
            }
    errors: list[str] = []
    notes: list[str] = []
    allow: set[str] = set()
    for i, key in enumerate(allowlist or []):
        try:
            allow.add(to_key_hex(key, f"allowlist[{i}]"))
        except (TypeError, ValueError) as e:
            # Trust configuration is external to capsule validity. Reject
            # malformed keys from the trust set without raising from verify.
            notes.append(f"ignored invalid allowlist[{i}]: {e}")
    result: VerifyResult = {
        "ok": False,
        "level": "L3" if outer_envelope is not None else "L2",
        "errors": errors,
        "chain": {"ok": False, "errors": []},
        "content_index": {"ok": False, "errors": []},
        "envelope": {"ok": False, "signers": []},
        "signer_set": {"bound": False, "ok": True, "errors": []},
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
            if events:
                result["chain"] = verify_chain(events)
            else:
                result["chain"] = {
                    "ok": False,
                    "errors": [{"seq": 0, "message": "chain/events.jsonl missing or empty"}],
                }
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
    # DISTINCT trusted keys, never rows: the same key signing under two
    # roles is one trusted key, and duplicate rows must never inflate a
    # quorum.
    result["trusted_signer_count"] = len(
        {(s["public_key"] or "").lower() for s in signers if s["trusted"]}
    )

    # Signer-set binding: PRESENCE BINDS, ABSENCE REPORTS.
    # A present manifest.signer_commitment must equal the normalized
    # envelope signer set exactly (integrity invariant, fail-closed). An
    # absent commitment downgrades the reported assurance — it never fails
    # verification, because a capsule that does not assert signer-set
    # binding is making a weaker claim honestly (templates, other writers).
    if "signer_commitment" not in manifest:
        notes.append(
            "manifest.signer_commitment absent: the signer set is not bound by the seal"
        )
    else:
        result["signer_set"]["bound"] = True
        commitment = manifest["signer_commitment"]
        sc_errors: list[str] = []
        problems = signer_commitment_problems(commitment)
        if problems:
            sc_errors.extend(f"manifest.signer_commitment malformed: {p}" for p in problems)
        else:
            raw_signers = envelope.get("signers")
            actual = sorted(
                (
                    {
                        "role": s.get("role") if isinstance(s.get("role"), str) else "",
                        "public_key": (
                            s.get("public_key").lower()
                            if isinstance(s.get("public_key"), str)
                            else ""
                        ),
                    }
                    for s in (raw_signers if isinstance(raw_signers, list) else [])
                    if isinstance(s, dict)
                ),
                key=commitment_member_key,
            )
            # Merge-walk both sorted member lists; name every difference.
            i = j = 0
            while i < len(commitment) or j < len(actual):
                if i >= len(commitment):
                    cmp = 1
                elif j >= len(actual):
                    cmp = -1
                else:
                    a, b = commitment_member_key(commitment[i]), commitment_member_key(actual[j])
                    cmp = -1 if a < b else (1 if a > b else 0)
                if cmp == 0:
                    i += 1
                    j += 1
                elif cmp < 0:
                    m = commitment[i]
                    i += 1
                    sc_errors.append(
                        "signer_commitment mismatch: no envelope signer matches committed "
                        f"member (role={m['role']}, public_key={m['public_key']})"
                    )
                else:
                    m = actual[j]
                    j += 1
                    sc_errors.append(
                        "signer_commitment mismatch: envelope signer not committed "
                        f"(role={m['role']}, public_key={m['public_key']})"
                    )
        if sc_errors:
            result["signer_set"]["ok"] = False
            result["signer_set"]["errors"] = sc_errors
            errors.extend(sc_errors)

    # Originator binding (invariant): the manifest names an originator key —
    # that key must actually have sealed the capsule with a valid envelope
    # signature under role "originator". A manifest naming an originator who
    # never signed is the capsule asserting something false about itself.
    originator_key = manifest.get("originator", {}).get("public_key")
    originator_key = originator_key.lower() if isinstance(originator_key, str) else None
    originator_signed = any(
        s.get("role") == "originator"
        and s.get("valid")
        and isinstance(s.get("public_key"), str)
        and s["public_key"].lower() == originator_key
        for s in env_result.get("signers", [])
    )
    if not originator_signed:
        errors.append(
            f"originator binding: manifest.originator.public_key {originator_key or '(missing)'} "
            "has no valid envelope signature with role 'originator'"
        )

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

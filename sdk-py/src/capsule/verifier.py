"""verify_capsule (L2 plain). Mirrors sdk/src/verifier.js."""

from __future__ import annotations

import re
from typing import TypedDict
from zipfile import BadZipFile

from .canonical import hex_to_bytes, sha256_hex
from .chain import (
    first_and_entry_hash,
    participant_actor_id_problems,
    participant_actor_ids,
    verify_chain,
)
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
from .profiles import (
    DEFAULT_PROFILE,
    ProfileError,
    classify_capsule_profile,
    profile_mismatch_message,
    unsupported_profile_message,
)
from .reader import CapsuleReader
from .versions import (
    SUITES,
    UnsupportedCapsuleVersionError,
    classify_version,
    unsupported_version_message,
)
from .zip_io import unpack_zip

_SKILL_PATH_RE = re.compile(r"^skills/([^/]+)/(skill\.json|SKILL\.md)$")

# Canonical cross-lane note strings (spec/results.md) that back the
# qualifier derivations below. The chain-note markers double as the
# derivational facts for empty_chain_not_walked / encrypted_outer_only.
_EMPTY_CHAIN_NOTE = "empty chain: no events to walk; envelope anchors checked to be null instead"
_DEFERRED_CHAIN_NOTE = "deferred to L3 (encrypted outer)"


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


class _ActorSetResult(TypedDict):
    bound: bool


class _FormatVersionResult(TypedDict):
    observed: str | None
    supported: bool
    status: str
    suite: str | None
    accepted_by_policy: bool | None


class _ProfileResult(TypedDict):
    """The profile declaration channel (spec/profiles.md).

    ``observed``/``observed_version`` report the declaration as read —
    even on refusal (an unauthenticated observation, which is what lets
    an auditor route the capsule to a capable verifier instead of
    declaring it corrupt). ``effective``/``effective_version`` name the
    profile actually applied (``v0.6-suite``/``1.0`` on every successful
    default path — the absence rule made machine-visible); both are None
    whenever no profile's rules were applied. ``status`` is the closed
    vocabulary ``default | supported | unsupported | mismatched |
    invalid | unevaluated | unread``.
    """

    observed: str | None
    observed_version: str | None
    declared: bool
    effective: str | None
    effective_version: str | None
    supported: bool
    status: str
    accepted_by_policy: bool | None


class _SkillTrustResult(TypedDict):
    """Derived skill classification (spec/trust.md "Skill trust").

    ``capsule_signed`` is the single capsule-level fact — ok (the overall
    verdict) and content_index.ok and envelope.ok and
    trusted_signer_count > 0 — because ONE envelope
    signature covers the whole content index. ``skills[id]`` is "signed"
    iff ``capsule_signed`` and ``skills/<id>/skill.json`` is listed in the
    content index. Hosts MUST take the tier from here: the format has no
    ``skill_trust`` manifest member, and any encountered one is an inert
    unknown member, never authority.
    """

    capsule_signed: bool
    skills: dict[str, str]


class VerifyResult(TypedDict):
    ok: bool
    verdict: str
    verdict_reason: str | None
    qualifiers: list[str]
    level: str
    errors: list[str]
    chain: dict
    content_index: _ContentIndexResult
    envelope: _EnvelopeSummary
    signer_set: _SignerSetResult
    actor_set: _ActorSetResult
    format_version: _FormatVersionResult
    profile: _ProfileResult
    skill_trust: _SkillTrustResult
    trusted_signer_count: int
    notes: list[str]


def _unread_format_version() -> _FormatVersionResult:
    """The unread (fail-closed) format_version channel."""
    return {
        "observed": None,
        "supported": False,
        "status": "unread",
        "suite": None,
        "accepted_by_policy": None,
    }


def _unread_profile() -> _ProfileResult:
    """The unread (fail-closed) profile channel (spec/profiles.md)."""
    return {
        "observed": None,
        "observed_version": None,
        "declared": False,
        "effective": None,
        "effective_version": None,
        "supported": False,
        "status": "unread",
        "accepted_by_policy": None,
    }


def _fail_closed(message: str, level: str) -> VerifyResult:
    """The documented fail-closed result: every channel present, nothing trusted."""
    return {
        "ok": False,
        "level": level,
        "errors": [message],
        "chain": {"ok": False, "errors": []},
        "content_index": {"ok": False, "errors": []},
        "envelope": {"ok": False, "signers": []},
        "signer_set": {"bound": False, "ok": False, "errors": []},
        "actor_set": {"bound": False},
        "format_version": _unread_format_version(),
        "profile": _unread_profile(),
        "skill_trust": {"capsule_signed": False, "skills": {}},
        "trusted_signer_count": 0,
        "notes": [],
    }


def _derive_verdict(
    result: VerifyResult,
    *,
    version_refusal: str | None = None,
    allowlist_size: int | None = None,
) -> VerifyResult:
    """Derive the normalized verdict surface (spec/results.md).

    ``verdict``, ``verdict_reason`` and ``qualifiers`` are report-only:
    every member restates facts the result already carries, and
    ``ok == (verdict == "valid")`` is an invariant. Mutates and returns
    ``result``.

    ``version_refusal`` is ``unknown_newer``/``unknown_older`` when the
    refusal was an unsupported-version refusal the format_version channel
    alone cannot show (the envelope-side refusal: the manifest's observed
    version can be known while envelope.version is not).
    ``allowlist_size`` is the effective (well-formed) allowlist entry
    count, for the two host-relative trust qualifiers; only results that
    can reach verdict "valid" need it.
    """
    version_status = version_refusal or result["format_version"]["status"]
    reason: str | None = None
    if version_status in ("unknown_newer", "unknown_older"):
        # Refused because the verifier cannot understand what the capsule
        # DECLARES — a different verifier may verify it. Not corruption.
        verdict = "unsupported"
        reason = (
            "unsupported_version_older"
            if version_status == "unknown_older"
            else "unsupported_version_newer"
        )
    elif result["profile"]["status"] == "unsupported":
        verdict = "unsupported"
        reason = "unsupported_profile"
    elif result["ok"] is True:
        verdict = "valid"
    else:
        verdict = "invalid"

    qualifiers: list[str] = []
    if verdict == "valid":
        # Spec-defined emission order (spec/results.md). Each entry is a
        # pure restatement of one already-reported fact.
        if result["signer_set"]["bound"] is False:
            qualifiers.append("signer_set_unbound")
        if result["actor_set"]["bound"] is False:
            qualifiers.append("actor_set_unbound")
        if result["chain"].get("note") == _EMPTY_CHAIN_NOTE:
            qualifiers.append("empty_chain_not_walked")
        if result["level"] == "L2" and result["chain"].get("note") == _DEFERRED_CHAIN_NOTE:
            qualifiers.append("encrypted_outer_only")
        if result["format_version"]["accepted_by_policy"] is False:
            qualifiers.append("version_not_accepted_by_policy")
        # Mutually exclusive by construction: no allowlist vs an allowlist
        # that matched no distinct signer key.
        if allowlist_size == 0:
            qualifiers.append("trust_not_evaluated")
        elif allowlist_size and result["trusted_signer_count"] == 0:
            qualifiers.append("no_trusted_signer")
    result["verdict"] = verdict
    result["verdict_reason"] = reason
    result["qualifiers"] = qualifiers
    return result


def _peek_format_version(files: dict) -> _FormatVersionResult:
    """Best-effort read of the DECLARED version from an unopenable capsule.

    The observed version is a reported fact even when the reader refuses
    the capsule — that is what lets an auditor tell "this verifier is
    too old for the capsule" apart from "this capsule is corrupt"
    (spec/versioning.md).
    """
    try:
        import json as _json

        manifest = _json.loads(files["manifest.json"])
        fmt = manifest.get("format") if isinstance(manifest, dict) else None
        cls = classify_version(fmt.get("version") if isinstance(fmt, dict) else None)
        return {
            "observed": cls["observed"],
            "supported": cls["status"] == "known",
            "status": cls["status"],
            "suite": SUITES.get(cls["observed"]) if cls["status"] == "known" else None,
            "accepted_by_policy": None,
        }
    except Exception:
        return _unread_format_version()


def _peek_profile(files: dict, err: Exception) -> _ProfileResult:
    """Best-effort profile channel for a capsule the reader refused.

    The observed declaration is a reported fact even on refusal
    (spec/profiles.md obligation 8) — it is what lets an auditor route
    the capsule to a capable verifier instead of declaring it corrupt.

    A typed ProfileError carries its own classification. A version-gate
    refusal reports the declaration with status "unevaluated" (read but
    not classified: profile semantics are era-scoped, so an unknown era
    means the declaration cannot be classified). Any other open failure
    never reached the gate either: the channel stays at the fail-closed
    "unread" default, with the declaration surfaced best-effort when the
    documents parse.
    """
    if isinstance(err, ProfileError):
        cls = err.classification
        return {
            "observed": cls["observed"],
            "observed_version": cls["observed_version"],
            "declared": cls["declared"],
            "effective": None,
            "effective_version": None,
            "supported": False,
            "status": cls["status"],
            "accepted_by_policy": None,
        }
    import json as _json

    observed: str | None = None
    observed_version: str | None = None
    declared = False
    try:
        manifest = _json.loads(files["manifest.json"])
        fmt = manifest.get("format") if isinstance(manifest, dict) else None
        decl = fmt.get("profile") if isinstance(fmt, dict) else None
        declared = isinstance(fmt, dict) and "profile" in fmt
        if isinstance(decl, dict):
            observed = decl.get("id") if isinstance(decl.get("id"), str) else None
            observed_version = (
                decl.get("version") if isinstance(decl.get("version"), str) else None
            )
        if not declared:
            try:
                envelope = _json.loads(files["provenance/envelope.json"])
                if isinstance(envelope, dict) and "profile" in envelope:
                    declared = True
                    e = envelope["profile"]
                    if isinstance(e, dict):
                        observed = e.get("id") if isinstance(e.get("id"), str) else None
                        observed_version = (
                            e.get("version") if isinstance(e.get("version"), str) else None
                        )
            except Exception:
                pass  # envelope unreadable: the manifest-side observation stands
    except Exception:
        return _unread_profile()
    return {
        "observed": observed,
        "observed_version": observed_version,
        "declared": declared,
        "effective": None,
        "effective_version": None,
        "supported": False,
        "status": "unevaluated" if isinstance(err, UnsupportedCapsuleVersionError) else "unread",
        "accepted_by_policy": None,
    }


def verify_capsule(
    reader,
    *,
    allowlist: list | None = None,
    outer_envelope: dict | None = None,
    accept_versions: list | None = None,
    accept_profiles: list | None = None,
) -> VerifyResult:
    """Verify a capsule.

    Accepts a ``CapsuleReader`` or the raw ``.capsule`` bytes. Given
    bytes, a container that cannot even be opened (malformed ZIP,
    missing or invalid manifest/envelope) returns a fail-closed result
    instead of raising, so app code has a single failure path.

    Verification is total: no input produces an exception. Anything the
    checks below fail to anticipate comes back as a fail-closed result
    with the underlying message in ``errors``.

    ``allowlist`` entries may be hex strings (any case) or 32 raw bytes.
    ``accept_versions`` / ``accept_profiles`` are host policy: reported
    in ``format_version.accepted_by_policy`` / ``profile
    .accepted_by_policy``, never decided here.

    The result also carries the normalized verdict surface
    (spec/results.md): ``verdict`` (``valid``/``invalid``/
    ``unsupported``, with ``ok == (verdict == "valid")`` an invariant),
    ``verdict_reason`` (non-null iff ``unsupported`` — a limitation of
    THIS verifier, not a defect of the capsule), and ``qualifiers`` (the
    weaker-claim facts a renderer must not hide), all DERIVED from the
    facts below.
    """
    level = "L3" if outer_envelope is not None else "L2"
    try:
        result = _verify_capsule_impl(
            reader,
            allowlist=allowlist,
            outer_envelope=outer_envelope,
            accept_versions=accept_versions,
            accept_profiles=accept_profiles,
        )
    except Exception as e:
        # The docstring promises callers a result, not an exception, for
        # every input. Anything that escapes the checks below is a capsule
        # we could not fully evaluate, which is a verification failure.
        result = _fail_closed(f"verification failed: {type(e).__name__}: {e}", level)
    # Paths with refusal context (unsupported version/profile, the valid
    # path with its allowlist) derive the verdict surface themselves;
    # everything else is an ordinary failure.
    return result if "verdict" in result else _derive_verdict(result)


def _verify_capsule_impl(
    reader,
    *,
    allowlist: list | None = None,
    outer_envelope: dict | None = None,
    accept_versions: list | None = None,
    accept_profiles: list | None = None,
) -> VerifyResult:
    if isinstance(reader, (bytes, bytearray, memoryview)):
        try:
            files = unpack_zip(bytes(reader))
        except (ValueError, BadZipFile) as e:
            return _fail_closed(f"capsule cannot be opened: {e}", "L2")
        try:
            reader = CapsuleReader.from_files(files)
        except (ValueError, BadZipFile) as e:
            # Report the observed version and profile declaration even
            # when open is refused: an unknown-version or
            # unsupported-profile refusal must stay distinguishable from
            # tamper (spec/versioning.md, spec/profiles.md).
            failed = _fail_closed(f"capsule cannot be opened: {e}", "L2")
            failed["format_version"] = _peek_format_version(files)
            failed["profile"] = _peek_profile(files, e)
            if isinstance(e, ProfileError):
                # Suite honesty (spec/profiles.md obligation 6): the suite
                # fact is a statement about the rules governing THIS
                # capsule; after a profile-gate refusal none is known.
                failed["format_version"]["suite"] = None
            return _derive_verdict(
                failed,
                # The envelope-side version refusal: the manifest's
                # observed version can be known while envelope.version is
                # not, so the format_version channel alone cannot carry
                # the refusal class.
                version_refusal=e.status if isinstance(e, UnsupportedCapsuleVersionError) else None,
            )
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
        "actor_set": {"bound": False},
        "format_version": _unread_format_version(),
        "profile": _unread_profile(),
        "skill_trust": {"capsule_signed": False, "skills": {}},
        "trusted_signer_count": 0,
        "notes": notes,
    }

    manifest = reader.manifest()
    envelope = reader.envelope()

    # The observed profile declaration is a reported fact from here on.
    # Until BOTH documents pass the version gate the declaration cannot be
    # classified (the absence rule is era-keyed), so the channel starts
    # "unevaluated" and the version-gate early returns below carry it
    # as-is — the version diagnosis stays the only error.
    observed_profile = classify_capsule_profile(manifest, envelope)
    result["profile"] = {
        "observed": observed_profile["observed"],
        "observed_version": observed_profile["observed_version"],
        "declared": observed_profile["declared"],
        "effective": None,
        "effective_version": None,
        "supported": False,
        "status": "unevaluated",
        "accepted_by_policy": None,
    }

    # Actor-set binding: like signer_commitment, PRESENCE BINDS, ABSENCE
    # REPORTS. A non-empty manifest.participants[] binds every chain event
    # actor to the declared set (enforced in the chain walk below,
    # fail-closed — participants is covered by manifest_hash inside the
    # signed payload, so an attacker cannot empty it without breaking the
    # signature). An empty set is a visibly weaker claim made honestly:
    # verification proceeds and the reduced assurance is reported.
    # Shape defense for hand-constructed readers (the bytes path already
    # rejects this at open): a PRESENT non-array participants is malformed,
    # never a silent no-op of the actor rules (spec/manifest.md).
    if (
        isinstance(manifest, dict)
        and "participants" in manifest
        and not isinstance(manifest["participants"], list)
    ):
        errors.append("manifest.participants must be an array of participant objects")
    result["actor_set"]["bound"] = bool(participant_actor_ids(manifest.get("participants")))
    if not result["actor_set"]["bound"]:
        notes.append(
            "manifest.participants empty: chain actors are not bound to a "
            "declared participant set"
        )
    # spec/manifest.md field rules (A06): every DECLARED actor_id must sit
    # in the closed namespace set (human/ai/system/capsule, non-empty id).
    # Unlike an empty participants[], an uninterpretable declared entry is
    # not a weaker claim — it is a malformed one, rejected fail-closed.
    # Conformance vector: spec/vectors/chain-rules (invalid-actor-namespace).
    for problem in participant_actor_id_problems(manifest.get("participants")):
        errors.append(f"manifest.{problem}")

    # Format / version gate (spec/versioning.md). The observed version is
    # a REPORTED FACT; whether it is acceptable to this deployment is host
    # policy (accept_versions), reported and never decided here. An
    # unknown version fails closed EARLY with only the version diagnosis —
    # running the wrong era's rules would bury "this verifier is too old"
    # under hash-mismatch noise indistinguishable from tampering.
    fmt = manifest.get("format")
    declared = fmt.get("version") if isinstance(fmt, dict) else None
    version_class = classify_version(declared)
    capsule_version = declared if version_class["status"] == "known" else None
    result["format_version"] = {
        "observed": version_class["observed"],
        "supported": version_class["status"] == "known",
        "status": version_class["status"],
        "suite": SUITES.get(declared) if version_class["status"] == "known" else None,
        "accepted_by_policy": None,
    }
    if version_class["status"] == "invalid":
        errors.append(
            f"manifest.format.version: not a '<major>.<minor>' version string, got {declared!r}"
        )
        return result
    if version_class["status"] != "known":
        errors.append(
            unsupported_version_message(
                "manifest.format.version", declared, version_class["status"]
            )
        )
        return result
    env_version_class = classify_version(envelope.get("version"))
    if env_version_class["status"] != "known":
        if env_version_class["status"] == "invalid":
            errors.append(
                "envelope.version: not a '<major>.<minor>' version string, got "
                f"{envelope.get('version')!r}"
            )
        else:
            errors.append(
                unsupported_version_message(
                    "envelope.version", envelope.get("version"), env_version_class["status"]
                )
            )
        # The format_version channel reports the MANIFEST's observed
        # version (possibly known); the refusal class rides explicitly.
        return _derive_verdict(
            result,
            version_refusal=(
                None if env_version_class["status"] == "invalid" else env_version_class["status"]
            ),
        )
    if envelope.get("version") != capsule_version:
        # Two KNOWN versions that disagree: the capsule is ambiguous
        # about which era's rules bind it. Fail closed before applying
        # either.
        errors.append(
            f"envelope.version {envelope.get('version')!r} does not match "
            f"manifest.format.version {capsule_version!r}"
        )
        return result

    # Profile gate (spec/profiles.md): version gate first, profile gate
    # second, nothing else until both pass. CapsuleReader enforces this at
    # open; re-deriving it here keeps verification total over
    # hand-constructed readers and pins refusal exclusivity — after a
    # profile refusal the profile diagnosis is the only error carried and
    # every other channel holds its fail-closed default.
    profile_class = classify_capsule_profile(manifest, envelope)
    result["profile"] = {
        "observed": profile_class["observed"],
        "observed_version": profile_class["observed_version"],
        "declared": profile_class["declared"],
        "effective": profile_class["effective"],
        "effective_version": profile_class["effective_version"],
        "supported": profile_class["supported"],
        "status": profile_class["status"],
        "accepted_by_policy": None,
    }
    if profile_class["status"] not in ("default", "supported"):
        if profile_class["status"] == "invalid":
            errors.extend(profile_class["problems"])
        elif profile_class["status"] == "mismatched":
            errors.append(
                profile_mismatch_message(
                    profile_class["normalized"]["manifest"],
                    profile_class["normalized"]["envelope"],
                )
            )
        else:
            errors.append(
                unsupported_profile_message(
                    profile_class["observed"], profile_class["observed_version"]
                )
            )
        # Suite honesty: the suite fact is a statement about the rules
        # governing THIS capsule; after a profile-gate refusal none is
        # known.
        result["format_version"]["suite"] = None
        return _derive_verdict(result)
    if (
        profile_class["effective"] != DEFAULT_PROFILE["id"]
        or profile_class["effective_version"] != DEFAULT_PROFILE["version"]
    ):
        # Unreachable while the reference table holds one row; kept so a
        # grown table cannot report the default suite under alternate
        # rules.
        result["format_version"]["suite"] = None
    # Host policy: DECLARED accepted profiles. Reported, never decided —
    # same shape as accept_versions and signer allowlists.
    if accept_profiles is not None:
        result["profile"]["accepted_by_policy"] = profile_class["effective"] in accept_profiles
        if not result["profile"]["accepted_by_policy"]:
            notes.append(
                f"host policy: effective profile {profile_class['effective']}/"
                f"{profile_class['effective_version']} is not in the declared accepted set "
                f"{sorted(accept_profiles)!r}"
            )
    # Host policy: DECLARED accepted versions. Reported, never decided —
    # integrity ok is unaffected, exactly as with signer allowlists.
    if accept_versions is not None:
        result["format_version"]["accepted_by_policy"] = capsule_version in accept_versions
        if not result["format_version"]["accepted_by_policy"]:
            notes.append(
                f"host policy: observed format version {capsule_version} is not in the "
                f"declared accepted set {sorted(accept_versions)!r}"
            )

    # Capsule identity
    try:
        expected_id = compute_capsule_id(
            hex_to_bytes(manifest["originator"]["public_key"]),
            manifest["first_event_hash"],
            capsule_version,
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

    # Semantic binding: manifest.first_event_hash is the capsule_id input;
    # envelope.first_event_hash is what the chain walk below is checked
    # against. spec/manifest.md and spec/envelope.md both pin them to the
    # hash of chain event 1, so they must be equal — otherwise capsule_id
    # (the identity federation attestations bind to) names a chain the
    # capsule does not carry. None==None is the legal empty-chain shape;
    # the chain walk enforces anchor/event-count consistency separately.
    if manifest.get("first_event_hash") != envelope.get("first_event_hash"):
        errors.append(
            "manifest.first_event_hash mismatch: "
            f"{manifest.get('first_event_hash')} vs envelope.first_event_hash "
            f"{envelope.get('first_event_hash')}"
        )

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
    # envelope.cipher, not file presence: a stray content.enc in a plain
    # (cipher="none") capsule is indexed here like any other file, and forcing
    # its exclusion would break the envelope signature. Indexing alone is
    # accounting, not the rejection — a fully re-derived index can cover the
    # blob — the blob-shape check below rejects any content.enc the signed
    # envelope does not account for, indexed or not.
    excluded = content_index_exclusions(envelope.get("cipher") not in (None, "none"))
    files = reader.files()
    index_files = {p: b for p, b in files.items() if p not in excluded}
    try:
        recomputed = build_content_index(index_files, excluded)
    except Exception as e:
        result["content_index"]["errors"].append(f"recompute failed: {e}")
        recomputed = {"files": [], "index_hash": ""}

    # A reader built by from_bytes has already shape-checked these, but
    # verify_capsule also accepts hand-constructed readers, so read the
    # stored index defensively and report rather than raise.
    stored_index = manifest.get("content_index")
    if not isinstance(stored_index, dict):
        stored_index = {}
        result["content_index"]["errors"].append("manifest.content_index is not a JSON object")
    stored_files = stored_index.get("files")
    if not isinstance(stored_files, list):
        if stored_index:
            result["content_index"]["errors"].append("manifest.content_index.files is not an array")
        stored_files = []
    stored_files = [f for f in stored_files if isinstance(f, dict)]
    stored_map = {f.get("path"): f.get("sha256") for f in stored_files}

    ci_ok = True
    if recomputed["index_hash"] != stored_index.get("index_hash"):
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
        if f.get("path") not in recomputed_paths:
            ci_ok = False
            result["content_index"]["errors"].append(
                f"file in manifest index but missing from package: {f.get('path')}"
            )
    if recomputed["index_hash"] != envelope.get("content_index_hash"):
        ci_ok = False
        result["content_index"]["errors"].append(
            "envelope.content_index_hash mismatch: "
            f"{envelope.get('content_index_hash')} vs recomputed {recomputed['index_hash']}"
        )
    result["content_index"]["ok"] = ci_ok and not result["content_index"]["errors"]

    # Encrypted-blob shape (mirrors verifier-rust). Two legal shapes:
    #   - Plain:     no content.enc, cipher == "none", encrypted_blob_hash null.
    #   - Encrypted: content.enc present, cipher != "none",
    #                encrypted_blob_hash == sha256(content.enc).
    # The checks are deliberately keyed off blob PRESENCE, never off
    # reader.is_encrypted() (the signed cipher AND the blob): that
    # conjunction is false exactly when the two halves disagree — a smuggled
    # content.enc on a cipher='none' capsule, or a declared cipher with no
    # blob — which are precisely the capsules that must fail here.
    blob = files.get("content.enc")
    if blob is not None:
        stored_blob_hash = envelope.get("encrypted_blob_hash")
        if stored_blob_hash is None:
            errors.append("encrypted blob present but envelope.encrypted_blob_hash=null")
        else:
            recomputed_blob_hash = sha256_hex(blob)
            if recomputed_blob_hash != stored_blob_hash:
                errors.append(
                    "envelope.encrypted_blob_hash mismatch: "
                    f"{stored_blob_hash} vs recomputed {recomputed_blob_hash}"
                )
        if envelope.get("cipher") == "none":
            errors.append("encrypted blob present but envelope.cipher='none'")
    else:
        if envelope.get("encrypted_blob_hash") is not None:
            errors.append("plain capsule must have envelope.encrypted_blob_hash=null")
        if envelope.get("cipher") != "none":
            errors.append(f"plain capsule must have cipher='none', got {envelope.get('cipher')!r}")

    # Encryption declaration. spec/manifest.md fixes manifest.encryption as
    # null for plain capsules and {metadata_path, cipher} for encrypted ones.
    # The SIGNED envelope.cipher is authoritative; the manifest declaration
    # must agree with it, and the declared metadata_path must resolve to a
    # file that exists AND is covered by the content index.
    declared_encryption = manifest.get("encryption")
    if envelope.get("cipher") == "none":
        if declared_encryption is not None:
            errors.append("manifest.encryption must be null when envelope.cipher is 'none'")
    elif not isinstance(declared_encryption, dict):
        errors.append(
            "manifest.encryption must be an object when envelope.cipher is "
            f"{envelope.get('cipher')!r}"
        )
    else:
        if declared_encryption.get("cipher") != envelope.get("cipher"):
            errors.append(
                f"manifest.encryption.cipher mismatch: {declared_encryption.get('cipher')!r} "
                f"vs envelope.cipher {envelope.get('cipher')!r}"
            )
        metadata_path = declared_encryption.get("metadata_path")
        if not isinstance(metadata_path, str) or not metadata_path:
            errors.append("manifest.encryption.metadata_path must be a non-empty string")
        elif metadata_path not in files:
            errors.append(
                f"manifest.encryption.metadata_path missing from capsule: {metadata_path}"
            )
        elif not any(f.get("path") == metadata_path for f in stored_files):
            errors.append(
                "manifest.encryption.metadata_path not covered by content index: "
                f"{metadata_path}"
            )

    # Chain
    if not reader.is_encrypted():
        # Fail closed, matching the Rust verifier: a plain capsule with no
        # chain file surfaces as a chain error in the result rather than an
        # exception out of verify_capsule.
        try:
            events = reader.events()
        except ValueError as e:  # MalformedCapsuleError is a ValueError
            events = None
            result["chain"] = {"ok": False, "errors": [{"seq": 0, "message": str(e)}]}
        if events is not None and not events:
            # Empty chain is LEGAL — the weakest honest shape (a template
            # or draft capsule with no events yet). But the capsule must
            # not claim chain anchors it does not have: with zero events
            # all three anchor claims MUST be null. Claiming an anchor
            # over an empty chain is the capsule lying about its own
            # bytes — rejected fail-closed (spec/chain.md "Empty chains").
            result["chain"] = {"ok": True, "errors": [], "note": _EMPTY_CHAIN_NOTE}
            notes.append(_EMPTY_CHAIN_NOTE)
            if envelope.get("first_event_hash") is not None:
                errors.append(
                    "envelope.first_event_hash must be null when the chain has no "
                    f"events; got {envelope.get('first_event_hash')}"
                )
            if envelope.get("entry_hash") is not None:
                errors.append(
                    "envelope.entry_hash must be null when the chain has no "
                    f"events; got {envelope.get('entry_hash')}"
                )
            if manifest.get("first_event_hash") is not None:
                errors.append(
                    "manifest.first_event_hash must be null when the chain has no "
                    f"events; got {manifest.get('first_event_hash')}"
                )
        elif events is not None:
            result["chain"] = verify_chain(
                events, participants=manifest.get("participants")
            )
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
            if manifest.get("first_event_hash") is None:
                errors.append(
                    "manifest.first_event_hash must not be null when the chain has events"
                )
    else:
        # Encrypted outer — chain verification deferred to L3.
        result["chain"] = {"ok": True, "errors": [], "note": _DEFERRED_CHAIN_NOTE}

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
    # A bad signature is otherwise only visible as valid=False nested in
    # envelope.signers[i]; every other failure class produces a displayable
    # message, so give this one an error too.
    for i, s in enumerate(signers):
        if not s["valid"]:
            errors.append(
                f"envelope.signers[{i}] signature invalid "
                f"(role {s['role']!r}, public_key {s['public_key']})"
            )
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

    # Advisory notes: a PASS with trusted=false is never silent about why.
    # The unmatched case must never get LESS warning than the no-policy
    # case (canonical wording, spec/results.md).
    if not allow:
        notes.append(
            "no allowlist provided; trusted=false for all signers regardless of signature validity"
        )
    elif result["trusted_signer_count"] == 0:
        notes.append("allowlist provided but matched no signer; trusted=false for all signers")

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

    # Skill trust: DERIVED from this verification, never read from the
    # capsule. A ``skill_trust`` manifest member does not exist in v0.6 —
    # when present (earlier drafts, hostile authors) it is an inert
    # unknown member (spec/trust.md "Skill trust"). Derived AFTER the
    # overall verdict so it is an input: a capsule that FAILS verification
    # never classifies anything signed, whatever the allowlist says —
    # without it, a capsule broken in a way that spares content_index and
    # the envelope signatures (e.g. a signer_commitment naming a key that
    # never signed) still tells the host its skills are trustworthy.
    # content_index.ok / envelope.ok stay in the conjunction for
    # fail-closed redundancy. Capsule-level in reality: one envelope
    # signature covers the whole content index, so every skill under one
    # seal shares capsule_signed; per-id variation only reflects whether
    # that skill ships an indexed skill.json at all.
    capsule_signed = bool(
        result["ok"]
        and result["content_index"]["ok"]
        and result["envelope"]["ok"]
        and result["trusted_signer_count"] > 0
    )
    indexed_paths = {f.get("path") for f in stored_files}
    skill_map: dict[str, str] = {}
    for path in files:
        m = _SKILL_PATH_RE.match(path)
        if m is None:
            continue
        sid = m.group(1)
        if sid == "decryption":  # encryption metadata, not a skill
            continue
        skill_map[sid] = (
            "signed"
            if capsule_signed and f"skills/{sid}/skill.json" in indexed_paths
            else "unsigned"
        )
    result["skill_trust"] = {"capsule_signed": capsule_signed, "skills": skill_map}

    # Normalized verdict surface (spec/results.md): derived last, from the
    # facts above — the only path that can reach verdict "valid".
    return _derive_verdict(result, allowlist_size=len(allow))

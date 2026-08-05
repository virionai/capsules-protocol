"""Lineage verification (spec/lineage.md). Mirrors sdk-js/src/lineage.js.

Two groups of obligations. STANDALONE checks are properties of the
successor artifact alone and fail it closed (the caller pushes the
problems into ``result["errors"]``). LINKAGE checks depend on evidence
the host supplied at verify time (the ``predecessors`` verify kwarg) and
are REPORT-ONLY: the successor's ``ok`` must remain a function of the
capsule, never of the invocation — otherwise a third party flips a valid
capsule's verdict by handing the verifier the wrong file.
"""

from __future__ import annotations

import re

from .canonical import hex_to_bytes, loads_strict
from .manifest import (
    compute_capsule_id,
    declared_alternate_profile_id,
    manifest_hash,
    predecessor_identity_checkable,
    predecessors_problems,
)
from .reader import CapsuleReader
from .versions import classify_version
from .zip_io import unpack_zip

#: Eras whose rule sets define lineage semantics. ``predecessors`` is a
#: CLAIM member, not a rule selector, so it follows per-era rule sets:
#: inside a capsule declaring an earlier era (e.g. 0.6) it stays an
#: unknown member even to a v0.7.1 reader — preserved, hashed, never
#: shape-checked (spec/versioning.md "In-era tightening and cross-era
#: force"; spec/lineage.md "No retroactive interpretation of sealed
#: eras"). The gate is the SAME whether the capsule is the verification
#: subject or a hop reached through the walk — one artifact, one rule
#: set.
LINEAGE_ERAS: frozenset[str] = frozenset({"0.7"})

#: Resource limit, not a protocol rule (like the reader's file-count and
#: size caps): the walk never fetches — depth is bounded by the supplied
#: pool — and the cap bounds pathological pools.
LINEAGE_HOP_CAP_DEFAULT = 256

_HEX64_LOWER = re.compile(r"^[0-9a-f]{64}$")


def era_defines_lineage(version) -> bool:
    """Whether an observed ``<major>.<minor>`` era interprets ``predecessors``.

    An unknown era never reaches here (the version gate fails closed
    first), so ``False`` means "known era, pre-lineage rules".
    """
    return version in LINEAGE_ERAS


def verification_error_count(result: dict) -> int:
    """How many problems a verify result actually diagnosed.

    ``result["errors"]`` carries the cross-cutting diagnoses only — area
    failures live in their own channels (a tampered payload is a
    ``content_index`` error, a broken link a ``chain`` error, a forged
    signature an invalid signer row) — so counting the top-level list
    alone reports a failing capsule as having zero errors. Every report
    that says "N error(s)" about someone else's artifact uses this count.
    """
    envelope = result.get("envelope") or {}
    invalid_signatures = sum(1 for s in envelope.get("signers") or [] if s.get("valid") is False)
    return (
        len(result.get("errors") or [])
        + len((result.get("content_index") or {}).get("errors") or [])
        + len((result.get("chain") or {}).get("errors") or [])
        + invalid_signatures
    )


def default_lineage() -> dict:
    """The fail-closed / not-evaluated lineage shape.

    ``declared: False`` here means "not evaluated OR no member present"
    — after an open-stage or version-gate refusal the channel holds this
    default and the refusal diagnosis is the only error carried (refusal
    exclusivity).
    """
    return {"declared": False, "ok": False, "verified_depth": 0, "entries": []}


def _make_entry(declared: dict, hop: int) -> dict:
    """One reported entry: the declared six members echoed, plus the facts."""
    return {
        "capsule_id": declared.get("capsule_id"),
        "format_version": declared.get("format_version"),
        "originator_public_key": declared.get("originator_public_key"),
        "first_event_hash": declared.get("first_event_hash"),
        "entry_hash": declared.get("entry_hash"),
        "manifest_hash": declared.get("manifest_hash"),
        "hop": hop,
        "identity_checked": predecessor_identity_checkable(declared),
        "status": "unverified",
        "reason": None,
        "errors": [],
        "artifact": None,
    }


def _is_hex64_lower(value) -> bool:
    return isinstance(value, str) and _HEX64_LOWER.match(value) is not None


def _classify_artifact(artifact, verify, allowlist, accept_versions) -> dict:
    """Classify one supplied pool artifact.

    ``kind`` is one of:
      "verifiable"          — plain, known era, default profile; carries
                              the full own-era verification + recomputes
      "encrypted"           — encrypted capsule (v0.7.1 declarations
                              commit to plain members; never guessed at)
      "unsupported_version" — declared era outside the known table
      "unsupported_profile" — declares a profile this verifier does not
                              implement (default-profile scope)
      "unreadable"          — not openable as a capsule at all

    Matching for the unverifiable kinds uses the artifact's own CLAIMED
    id (nothing can be recomputed); their status says so explicitly.
    """
    record = {
        "kind": "unreadable",
        "manifest": None,
        "envelope": None,
        "claimed_id": None,
        "version": None,
        "recomputed_id": None,
        "recomputed_mh": None,
        "originator_key": None,
        "first_event_hash": None,
        "entry_hash": None,
        "verification": None,
        "summary": None,
        "assigned": False,
        "open_error": None,
    }
    verify_input = artifact
    try:
        if isinstance(artifact, CapsuleReader):
            files = artifact.files()
        else:
            data = bytes(artifact)
            verify_input = data
            files = unpack_zip(data)
        if "manifest.json" not in files:
            raise ValueError("missing manifest.json")
        record["manifest"] = loads_strict(files["manifest.json"].decode("utf-8"))
        env_bytes = files.get("provenance/envelope.json")
        record["envelope"] = (
            loads_strict(env_bytes.decode("utf-8")) if env_bytes is not None else None
        )
    except Exception as e:  # unreadable is a reported fact, never a raise
        record["open_error"] = str(e)
        return record

    manifest = record["manifest"] if isinstance(record["manifest"], dict) else {}
    envelope = record["envelope"] if isinstance(record["envelope"], dict) else None
    stored_id = manifest.get("id")
    record["claimed_id"] = stored_id if _is_hex64_lower(stored_id) else None
    fmt = manifest.get("format")
    version_class = classify_version(fmt.get("version") if isinstance(fmt, dict) else None)
    record["version"] = version_class["observed"]
    if envelope is None or envelope.get("cipher") != "none" or "content.enc" in files:
        record["kind"] = "encrypted"
        return record
    if version_class["status"] != "known":
        record["kind"] = "unsupported_version"
        return record
    if declared_alternate_profile_id(manifest) is not None:
        record["kind"] = "unsupported_profile"
        return record
    record["kind"] = "verifiable"
    # Recomputed values ONLY, never the artifact's own claims: identity
    # under the artifact's declared era's domain string, manifest hash
    # from the stored manifest document.
    originator = manifest.get("originator")
    try:
        record["recomputed_id"] = compute_capsule_id(
            hex_to_bytes(originator.get("public_key", "") if isinstance(originator, dict) else ""),
            manifest.get("first_event_hash"),
            record["version"],
        )
    except Exception:
        record["recomputed_id"] = None
    try:
        record["recomputed_mh"] = manifest_hash(manifest)
    except Exception:
        record["recomputed_mh"] = None
    key = originator.get("public_key") if isinstance(originator, dict) else None
    record["originator_key"] = key.lower() if isinstance(key, str) else None
    record["first_event_hash"] = manifest.get("first_event_hash")
    record["entry_hash"] = envelope.get("entry_hash")
    # The predecessor is verified fully as a capsule under ITS declared
    # version's rules, with the same host options as the main
    # verification (allowlist, version policy) — never the pool, which
    # belongs to this walk.
    verification = verify(verify_input, allowlist=allowlist, accept_versions=accept_versions)
    record["verification"] = verification
    record["summary"] = {
        "ok": verification["ok"],
        "observed_version": verification["format_version"]["observed"] or record["version"],
        "level": verification["level"],
        "error_count": verification_error_count(verification),
    }
    return record


def _equality_diffs(entry: dict, record: dict) -> list[str]:
    """The six equalities of spec/lineage.md linkage.

    Returns member-precise difference strings (empty = the supplied
    artifact IS the declared sealed state). Wording never uses
    tamper/corruption vocabulary: the supplied file being a different
    genuine seal is the common honest cause, and "wrong file supplied"
    versus "successor lied" is genuinely indistinguishable here — the
    verifier reports the precise fact and never decides.
    """
    pairs = [
        ("format_version", entry["format_version"], record["version"]),
        ("capsule_id", entry["capsule_id"], record["recomputed_id"]),
        ("originator_public_key", entry["originator_public_key"], record["originator_key"]),
        ("first_event_hash", entry["first_event_hash"], record["first_event_hash"]),
        ("entry_hash", entry["entry_hash"], record["entry_hash"]),
        ("manifest_hash", entry["manifest_hash"], record["recomputed_mh"]),
    ]
    diffs = []
    for name, declared, supplied in pairs:
        if declared != supplied:
            diffs.append(
                f"{name}: declared {declared if declared is not None else 'null'}, "
                f"supplied artifact has {supplied if supplied is not None else 'null'}"
            )
    return diffs


def evaluate_lineage(
    *,
    manifest,
    version,
    verify,
    errors: list[str],
    notes: list[str],
    predecessors=None,
    allowlist=None,
    accept_versions=None,
    hop_cap: int | None = None,
) -> dict:
    """Evaluate the lineage area for one manifest.

    Standalone problems are pushed into ``errors`` (fail-closed, overall
    verdict); linkage facts live only in the returned area and ``notes``
    (report-only).

    ``verify`` is the caller's ``verify_capsule`` (passed in, not
    imported, to keep the module graph acyclic). ``version`` is the
    capsule's OBSERVED format version — the era whose rule set decides
    whether the member means anything at all.
    """
    lineage = default_lineage()
    present = isinstance(manifest, dict) and "predecessors" in manifest
    if not present:
        # No claim, nothing checked. ok=True: unchecked is not failed.
        lineage["ok"] = True
        return lineage
    if not era_defines_lineage(version):
        # Present, but this capsule's era defines no lineage semantics:
        # the member is an unknown member under those rules — preserved
        # and hashed, never shape-checked. Interpreting it would
        # retroactively rewrite a sealed era's verdict.
        notes.append(
            f"lineage: this capsule declares era {version}, whose rule set defines no "
            "lineage semantics; its predecessors member is an unknown member under "
            "that era and was not interpreted"
        )
        lineage["ok"] = True
        return lineage
    lineage["declared"] = True

    # Standalone checks 1-3, fail-closed (spec/lineage.md).
    problems = predecessors_problems(manifest["predecessors"])
    if problems:
        for p in problems:
            errors.append(f"manifest.{p}")
        lineage["ok"] = False
        return lineage

    # Pinned phrase: no report may imply a consent bit exists before the
    # v0.8+ countersignature artifact.
    notes.append(
        "lineage: manifest.predecessors is the successor's one-way declaration; "
        "the predecessor's originator has not countersigned it"
    )

    lineage["entries"] = [_make_entry(e, 1) for e in manifest["predecessors"]]

    # Linkage (report-only) over the supplied pool.
    pool = list(predecessors) if isinstance(predecessors, (list, tuple)) else []
    cap = LINEAGE_HOP_CAP_DEFAULT if hop_cap is None else hop_cap
    records = [_classify_artifact(a, verify, allowlist, accept_versions) for a in pool]

    # Seen-set on recomputed manifest_hash bounds pathological pools (a
    # true commitment cycle is a hash fixpoint and cannot verify).
    walked: set[str] = set()

    def open_entry(predicate):
        for e in lineage["entries"]:
            if e["status"] == "unverified" and predicate(e):
                return e
        return None

    changed = True
    while changed:
        changed = False
        for record in records:
            if record["assigned"] or record["kind"] == "unreadable":
                continue

            if record["kind"] != "verifiable":
                # Bytes in hand but rules unavailable: match by the
                # artifact's claimed id (status says explicitly that
                # nothing was verified).
                entry = (
                    None
                    if record["claimed_id"] is None
                    else open_entry(lambda e, cid=record["claimed_id"]: e["capsule_id"] == cid)
                )
                if entry is None:
                    continue
                record["assigned"] = True
                changed = True
                entry["status"] = "predecessor_unverifiable"
                entry["reason"] = (
                    "encrypted_predecessor" if record["kind"] == "encrypted" else record["kind"]
                )
                if record["kind"] == "encrypted":
                    notes.append(
                        f"lineage: supplied predecessor for capsule {entry['capsule_id']} is an "
                        f"encrypted capsule; v0.7.1 lineage declarations commit to a plain "
                        f"capsule's members — decrypt the inner capsule and supply it instead. "
                        f"The entry stays declared, not verified"
                    )
                elif record["kind"] == "unsupported_version":
                    notes.append(
                        f"lineage: supplied predecessor for capsule {entry['capsule_id']} "
                        f"declares format version '{record['version']}', which this verifier "
                        f"does not support — a limitation of the verifier, not a defect of "
                        f"either capsule. The entry stays declared, not verified"
                    )
                else:
                    notes.append(
                        f"lineage: supplied predecessor for capsule {entry['capsule_id']} "
                        f"declares profile "
                        f"'{declared_alternate_profile_id(record['manifest'])}', which this "
                        f"verifier does not implement (v0.7.1 lineage declarations commit to "
                        f"default-profile predecessors) — a limitation of the verifier, not a "
                        f"defect of either capsule. The entry stays declared, not verified"
                    )
                continue

            # Matching uses recomputed values only. Pair match first; an
            # id-only match is a different sealed state of the same identity.
            entry = None
            if record["recomputed_id"] is not None and record["recomputed_mh"] is not None:
                entry = open_entry(
                    lambda e, rid=record["recomputed_id"], rmh=record["recomputed_mh"]: (
                        e["capsule_id"] == rid and e["manifest_hash"] == rmh
                    )
                )
            if entry is None and record["recomputed_id"] is not None:
                entry = open_entry(lambda e, rid=record["recomputed_id"]: e["capsule_id"] == rid)
            if entry is None:
                continue
            record["assigned"] = True
            changed = True
            entry["artifact"] = record["summary"]
            diffs = _equality_diffs(entry, record)

            if not record["verification"]["ok"]:
                # Two facts, never collapsed: "is this the declared
                # artifact" vs "does it verify internally". Takes
                # precedence over mismatch; the equalities are still
                # reported informatively.
                entry["status"] = "predecessor_invalid"
                entry["errors"].append(
                    f"supplied predecessor fails its own verification under era "
                    f"{record['version']} ({record['summary']['error_count']} error(s)); "
                    f"this is a property of the supplied artifact, not of the successor's "
                    f"declaration"
                )
                entry["errors"].extend(diffs)
            elif diffs:
                entry["status"] = "mismatch"
                entry["errors"].append(
                    "supplied artifact is a different sealed state of the declared "
                    "predecessor (same capsule identity, different seal) — not evidence of "
                    "tampering; re-seals of a growing line legitimately share a capsule_id"
                )
                entry["errors"].extend(diffs)
            else:
                entry["status"] = "verified"

            # Recursive walk: a hop whose manifest matches the declared
            # manifest_hash contributes ITS OWN first-person declaration
            # to the frontier — even when its event chain is broken (the
            # commitment chain authenticates the declaration bytes). A
            # mismatched artifact is NOT the declared artifact and never
            # contributes.
            if (
                record["recomputed_mh"] is not None
                and entry["manifest_hash"] == record["recomputed_mh"]
                and record["recomputed_mh"] not in walked
            ):
                walked.add(record["recomputed_mh"])
                child_manifest = record["manifest"] if isinstance(record["manifest"], dict) else {}
                if "predecessors" in child_manifest:
                    child_declared = child_manifest["predecessors"]
                    if record["version"] not in LINEAGE_ERAS:
                        notes.append(
                            f"lineage: predecessor {entry['capsule_id']} declares era "
                            f"{record['version']}, whose rule set defines no lineage "
                            f"semantics; its predecessors member is an unknown member under "
                            f"that era and terminates the walk"
                        )
                    elif not predecessors_problems(child_declared):
                        # A malformed hop declaration is diagnosed by that
                        # hop's own verification (predecessor_invalid);
                        # nothing to walk.
                        if entry["hop"] + 1 <= cap:
                            for d in child_declared:
                                lineage["entries"].append(_make_entry(d, entry["hop"] + 1))
                        else:
                            notes.append(
                                f"lineage: hop cap {cap} reached; deeper declarations were "
                                f"not walked"
                            )

    # Unmatched supplied artifacts are named, never silently ignored — a
    # mistyped path must be visible.
    for i, record in enumerate(records):
        if record["assigned"]:
            continue
        if record["kind"] == "unreadable":
            notes.append(
                f"lineage: supplied predecessor artifact #{i + 1} could not be read as a "
                f"capsule ({record['open_error']}); it matched no declared entry"
            )
        else:
            label = record["claimed_id"] or record["recomputed_id"] or "(unknown id)"
            notes.append(
                f"lineage: supplied predecessor artifact #{i + 1} (capsule {label}) "
                f"matched no declared entry"
            )

    # Pinned phrase: a custody claim must never quietly disappear when
    # bytes are missing — that is how a citation gets read as an
    # endorsement.
    for entry in lineage["entries"]:
        if entry["status"] in ("unverified", "predecessor_unverifiable"):
            notes.append(
                f"lineage: predecessor {entry['capsule_id']} (hop {entry['hop']}): "
                f"declared, not verified"
            )

    # verified_depth: the largest N such that every declared entry within
    # N hops has status "verified".
    depth = 0
    hop = 1
    while any(e["hop"] == hop for e in lineage["entries"]):
        if not all(e["status"] == "verified" for e in lineage["entries"] if e["hop"] <= hop):
            break
        depth = hop
        hop += 1
    lineage["verified_depth"] = depth
    if depth >= 1:
        parents = ", ".join(e["capsule_id"] for e in lineage["entries"] if e["hop"] == 1)
        # Two distinct identities, always: the successor is never
        # presented as BEING the predecessor or as its endorsed
        # continuation.
        notes.append(f"lineage: successor of capsule {parents}; lineage verified to depth {depth}")

    # Area verdict: standalone passed (or we returned above) AND nothing
    # checked contradicts. Unchecked is not failed.
    lineage["ok"] = not any(
        e["status"] in ("mismatch", "predecessor_invalid") for e in lineage["entries"]
    )
    return lineage

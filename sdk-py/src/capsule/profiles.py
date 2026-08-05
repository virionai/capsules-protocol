"""Profile declaration policy (spec/profiles.md). Mirrors sdk-js/src/profiles.js.

A capsule may DECLARE the verification profile that governs it —
``manifest.format.profile`` and ``envelope.profile``, mirroring the
``format.version`` / ``envelope.version`` dyad. A verifier keeps a table
of the profiles it implements (keyed selection, exactly like the
known-version table) and:

- treats ABSENCE of a declaration in a 0.6/0.7 capsule as the default
  profile ``v0.6-suite`` version ``1.0``, permanently — the mirror of
  the algorithm-suite pin in spec/versioning.md;
- requires the two documents' NORMALIZED declarations (absence =
  default) to agree; a capsule whose pairs differ is ambiguous about
  which rules bind it and fails closed BEFORE any profile's rules are
  applied (``profile_mismatch`` — a defect of the capsule);
- FAILS CLOSED on a declared (id, version) pair outside the table, with
  a diagnosis distinct from both tampering and malformation:
  ``unsupported_profile`` is a limitation of the verifier, never a
  defect of the capsule;
- treats a present declaration that violates the closed object shape or
  the identifier grammar as a MALFORMED document
  (``invalid_manifest_shape``), not a support gap.

The gate runs at OPEN stage, after the version gate and before anything
else: a reader that cannot establish its governing rules cannot
meaningfully construct at all, and applying the wrong profile's rules
would manufacture mismatch errors indistinguishable from tampering —
versioning.md's confusion, reproduced on the profile axis.
"""

from __future__ import annotations

import re

#: The default profile: the envelope.md verification/encryption procedure
#: of the capsule's declared era with the v0.6 algorithm suite of
#: versioning.md. The id deliberately matches the suite fact (``v0.6``)
#: verifiers already report. Frozen forever — the absence rule makes this
#: spelling permanent.
DEFAULT_PROFILE: dict[str, str] = {"id": "v0.6-suite", "version": "1.0"}

#: Every (id, version) profile row this implementation applies. Exact-
#: match on the pair — no ranges, no compatibility semantics. A profile
#: once supported is supported forever (the archival rule applied to
#: profiles), and the default row of every known era is always present.
SUPPORTED_PROFILES: tuple[dict[str, str], ...] = (DEFAULT_PROFILE,)


class _Absent:
    """A member that is not present. JSON ``null`` is a DIFFERENT thing.

    The absence rule keys off this distinction: an omitted declaration
    means the era default, while a present ``null`` is a malformed
    declaration (a second spelling of absence is a known typed-decoder
    divergence across lanes).
    """

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "ABSENT"


#: Sentinel for "the member is not present" (distinct from JSON null).
ABSENT = _Absent()

# profile-id = lowletter *63( lowletter / DIGIT / "-" / "." )
# 1..64 bytes, lowercase-only, no trailing "-" or "." (no leading one by
# construction: the first byte is a letter).
_PROFILE_ID_GRAMMAR = re.compile(r"^[a-z][a-z0-9.-]{0,63}$")
# The vendor fence: an id beginning `x-` MUST be vendor-scoped
# `x-<vendor>-<name>`; ids not beginning `x-` are reserved to the spec,
# exactly like non-`x-` member keys.
_VENDOR_ID_GRAMMAR = re.compile(r"^x-[a-z0-9.]+-[a-z0-9.-]+$")
# profile-ver: the SAME grammar as format versions (spec/versioning.md).
_PROFILE_VERSION_GRAMMAR = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


def is_valid_profile_id(value) -> bool:
    """True iff ``value`` satisfies the spec/profiles.md identifier grammar."""
    if not isinstance(value, str) or _PROFILE_ID_GRAMMAR.match(value) is None:
        return False
    if value.endswith("-") or value.endswith("."):
        return False
    if value.startswith("x-") and _VENDOR_ID_GRAMMAR.match(value) is None:
        return False
    return True


def is_valid_profile_version(value) -> bool:
    """True iff ``value`` satisfies the profile-version grammar."""
    return isinstance(value, str) and _PROFILE_VERSION_GRAMMAR.match(value) is not None


def profile_declaration_problems(value, path: str, *, envelope: bool = False) -> list[str]:
    """Shape problems for ONE document's present profile declaration.

    Returns ``[]`` for a well-formed declaration; every message is
    prefixed with the offending field path (the invalid_manifest_shape
    idiom). ``envelope=True`` applies the envelope-copy rules (no
    ``params``: params are single-sourced in the manifest so no second
    copy can diverge).
    """
    members = "{ id, version }" if envelope else "{ id, version, params? }"
    if value is None:
        # null is NOT a declaration: the honest way to not declare is to
        # omit, and a second spelling of absence is a known typed-decoder
        # divergence across lanes.
        return [
            f"{path} must be an object {members}; null is not a declaration — "
            "omit the member to not declare"
        ]
    if not isinstance(value, dict):
        return [f"{path} must be an object {members}, got {value!r}"]
    problems: list[str] = []
    # The object is CLOSED: an uninterpretable member in the rule SELECTOR
    # is the capsule asserting something meaningless about what governs
    # it. Vendor freight rides in manifest params or x- members.
    allowed = ("id", "version") if envelope else ("id", "version", "params")
    for key in value:
        if key in allowed:
            continue
        if key == "params" and envelope:
            problems.append(
                f"{path}.params is not allowed: params are single-sourced in "
                "manifest.format.profile"
            )
        else:
            problems.append(
                f"{path}.{key} is not a member of the closed profile object "
                f"(exactly: {', '.join(allowed)})"
            )
    if not is_valid_profile_id(value.get("id")):
        problems.append(
            f"{path}.id must be a profile identifier (1-64 bytes, lowercase letter first, "
            "then lowercase letters, digits, '-' or '.'; 'x-' ids vendor-scoped as "
            f"x-<vendor>-<name>), got {value.get('id')!r}"
        )
    if not is_valid_profile_version(value.get("version")):
        problems.append(
            f"{path}.version must be a '<major>.<minor>' version string, "
            f"got {value.get('version')!r}"
        )
    if not envelope and "params" in value and not isinstance(value["params"], dict):
        problems.append(f"{path}.params must be a JSON object, got {value['params']!r}")
    return problems


def _best_effort_observed(manifest_decl, envelope_decl) -> tuple[str | None, str | None]:
    # The declared id/version as read — reported even on refusal and even
    # when invalid (the observed fact). On a dyad mismatch these are the
    # manifest values; when the manifest is silent, the envelope's.
    source = None
    for decl in (manifest_decl, envelope_decl):
        if isinstance(decl, dict):
            source = decl
            break
    if source is None:
        return None, None
    observed = source.get("id") if isinstance(source.get("id"), str) else None
    version = source.get("version") if isinstance(source.get("version"), str) else None
    return observed, version


def classify_profile(manifest_decl=ABSENT, envelope_decl=ABSENT) -> dict:
    """Classify the (manifest, envelope) declaration dyad against the table.

    Pass the raw member values, or ``ABSENT`` when the member is not
    present. Pure and total; never raises.

    Returns ``{status, observed, observed_version, declared, effective,
    effective_version, supported, problems}`` (plus ``normalized`` on a
    mismatch), where ``status`` is one of the closed vocabulary of
    spec/profiles.md:

    ``default``
        no declaration, or the explicit era default: default rules apply
        (explicit default is exactly equivalent to absence — a redundant
        claim made honestly).
    ``supported``
        declared alternate profile this reader implements (unreachable
        in-era: the reference table holds one row).
    ``unsupported``
        declared alternate the reader does not implement: a limitation of
        the verifier, not a defect of the capsule.
    ``mismatched``
        normalized declarations disagree: the capsule is ambiguous about
        which rules bind it (a defect).
    ``invalid``
        a present member violates the closed shape or the grammar: a
        malformed document.

    The caller is responsible for gate ORDER: classify only after both
    documents pass the version gate (the absence rule is era-keyed).
    """
    manifest_present = not isinstance(manifest_decl, _Absent)
    envelope_present = not isinstance(envelope_decl, _Absent)
    observed, observed_version = _best_effort_observed(
        manifest_decl if manifest_present else None,
        envelope_decl if envelope_present else None,
    )
    base = {
        "observed": observed,
        "observed_version": observed_version,
        "declared": manifest_present or envelope_present,
        "effective": None,
        "effective_version": None,
        "supported": False,
        "problems": [],
    }

    problems: list[str] = []
    if manifest_present:
        problems.extend(profile_declaration_problems(manifest_decl, "manifest.format.profile"))
    if envelope_present:
        problems.extend(
            profile_declaration_problems(envelope_decl, "envelope.profile", envelope=True)
        )
    if problems:
        return {**base, "status": "invalid", "problems": problems}

    # Normalized dyad equality: absence means the era default, so the
    # default declared in exactly one document is coherent (both readings
    # mean the default) — refusing it would punish a truthful statement.
    m = (
        {"id": manifest_decl["id"], "version": manifest_decl["version"]}
        if manifest_present
        else dict(DEFAULT_PROFILE)
    )
    e = (
        {"id": envelope_decl["id"], "version": envelope_decl["version"]}
        if envelope_present
        else dict(DEFAULT_PROFILE)
    )
    if m != e:
        # Mismatch BEFORE table lookup: the effective declaration does not
        # exist until the documents agree, and reporting a mismatched
        # capsule as "unsupported" would hand the auditor a false
        # remediation ("find a better verifier" for a defective capsule).
        return {**base, "status": "mismatched", "normalized": {"manifest": m, "envelope": e}}

    known = any(row == m for row in SUPPORTED_PROFILES)
    if not known:
        return {
            **base,
            "observed": m["id"],
            "observed_version": m["version"],
            "status": "unsupported",
        }
    is_default = m == DEFAULT_PROFILE
    return {
        **base,
        "status": "default" if is_default else "supported",
        "effective": m["id"],
        "effective_version": m["version"],
        "supported": True,
    }


def manifest_profile_declaration(manifest):
    """The manifest's declaration, or ABSENT. Never raises on a shape."""
    fmt = manifest.get("format") if isinstance(manifest, dict) else None
    if not isinstance(fmt, dict) or "profile" not in fmt:
        return ABSENT
    return fmt["profile"]


def envelope_profile_declaration(envelope):
    """The envelope's declaration, or ABSENT. Never raises on a shape."""
    if not isinstance(envelope, dict) or "profile" not in envelope:
        return ABSENT
    return envelope["profile"]


def classify_capsule_profile(manifest, envelope) -> dict:
    """``classify_profile`` over the two whole documents."""
    return classify_profile(
        manifest_profile_declaration(manifest), envelope_profile_declaration(envelope)
    )


def unsupported_profile_message(observed, observed_version) -> str:
    """Cross-lane refusal wording (spec/profiles.md, spec/results.md)."""
    supported = ", ".join(f"{p['id']}/{p['version']}" for p in SUPPORTED_PROFILES)
    return (
        f"profile '{observed}' version '{observed_version}' is not supported by this verifier "
        f"(supported: {supported}); this is a limitation of the verifier, not corruption of the "
        "capsule — verify it with an implementation of that profile"
    )


def profile_mismatch_message(manifest_pair: dict, envelope_pair: dict) -> str:
    """Cross-lane mismatch wording: both NORMALIZED pairs quoted."""

    def fmt(pair: dict) -> str:
        return f"'{pair['id']}' version '{pair['version']}'"

    return (
        "envelope.profile does not match manifest.format.profile: "
        f"manifest normalizes to {fmt(manifest_pair)}, envelope normalizes to "
        f"{fmt(envelope_pair)} (absence means the era default "
        f"{DEFAULT_PROFILE['id']}/{DEFAULT_PROFILE['version']}); "
        "the capsule is ambiguous about which rules bind it"
    )


class ProfileError(ValueError):
    """Common base for typed profile-gate refusals.

    Every subclass carries the full classification so a fail-closed
    verify result can populate its profile channel from the error alone.
    A ValueError like the other reader refusals, so callers keep one
    failure path.
    """

    def __init__(self, message: str, classification: dict) -> None:
        super().__init__(message)
        self.observed = classification["observed"]
        self.observed_version = classification["observed_version"]
        self.classification = classification


class UnsupportedProfileError(ProfileError):
    """A declared (id, version) pair outside this verifier's table.

    Distinct from UnsupportedCapsuleVersionError and from malformed-shape
    errors on purpose: an operator must be able to tell "verify this with
    an implementation of that profile" apart from both "this verifier is
    too old" and "this capsule is corrupt".
    """


class ProfileMismatchError(ProfileError):
    """The two documents' normalized declarations disagree (a capsule defect)."""


class InvalidProfileError(ProfileError):
    """A present declaration violating the closed shape or grammar (malformed)."""


def require_supported_profile(manifest, envelope) -> dict:
    """The open-stage profile gate. Call AFTER both version-gate checks.

    Raises a typed ProfileError subclass on refusal; returns the
    classification when the capsule's effective profile is one this
    implementation applies.
    """
    cls = classify_capsule_profile(manifest, envelope)
    if cls["status"] == "invalid":
        # Field-path-prefixed shape wording (the invalid_manifest_shape
        # idiom) — never the word "unsupported": malformed is a defect of
        # the capsule, unsupported a limitation of the verifier.
        raise InvalidProfileError("; ".join(cls["problems"]), cls)
    if cls["status"] == "mismatched":
        raise ProfileMismatchError(
            profile_mismatch_message(cls["normalized"]["manifest"], cls["normalized"]["envelope"]),
            cls,
        )
    if cls["status"] == "unsupported":
        raise UnsupportedProfileError(
            unsupported_profile_message(cls["observed"], cls["observed_version"]), cls
        )
    return cls

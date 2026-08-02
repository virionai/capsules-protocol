"""Version-compatibility policy (spec/versioning.md). Mirrors sdk-js/src/versions.js.

A capsule DECLARES its format era (manifest.format.version and
envelope.version), and every domain-separation string embeds that
version. This module is the known-version table and the version-keyed
selectors:

- any KNOWN version opens and verifies under that era's rules and
  constants, forever (the archival profile), with the observed version
  reported as a fact on the verify result;
- an UNKNOWN version fails closed with a diagnosis distinct from tamper
  detection ("this verifier is too old" is not "this capsule is
  corrupt");
- a version string violating the <major>.<minor> grammar is a malformed
  document, not a support gap.
"""

from __future__ import annotations

import re

#: Every format version this implementation knows, oldest -> newest. A
#: version is never removed (spec/versioning.md: dropping a version a
#: verifier once knew is a conformance violation).
KNOWN_VERSIONS: tuple[str, ...] = ("0.6",)

#: The version this implementation SEALS at.
CURRENT_VERSION = "0.6"

#: Per-era algorithm suite identifiers (spec/versioning.md "Algorithm
#: suites"): a v0.6 capsule names no algorithm anywhere in its bytes;
#: absence means the v0.6 suite (Ed25519 / SHA-256 / JCS RFC 8785 /
#: X25519 + HKDF-SHA-256 + ChaCha20-Poly1305), permanently.
SUITES: dict[str, str] = {"0.6": "v0.6"}

# <major>.<minor>, decimal, no leading zeros.
_VERSION_GRAMMAR = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")

_NEWEST_KNOWN = KNOWN_VERSIONS[-1]
_OLDEST_KNOWN = KNOWN_VERSIONS[0]


def _parse_version(v) -> tuple[int, int] | None:
    if not isinstance(v, str):
        return None
    m = _VERSION_GRAMMAR.match(v)
    return (int(m.group(1)), int(m.group(2))) if m else None


def classify_version(v) -> dict:
    """Classify a declared version against the known-version table.

    Returns ``{"observed", "status"}`` with status one of the closed
    vocabulary ``known | unknown_newer | unknown_older | invalid``.
    ``observed`` is the declared string when it IS a string (reported
    even for invalid values — it is still the observed fact), else None.
    """
    observed = v if isinstance(v, str) else None
    parsed = _parse_version(v)
    if parsed is None:
        return {"observed": observed, "status": "invalid"}
    if v in KNOWN_VERSIONS:
        return {"observed": observed, "status": "known"}
    newest = _parse_version(_NEWEST_KNOWN)
    status = "unknown_newer" if parsed > newest else "unknown_older"
    return {"observed": observed, "status": status}


class UnsupportedCapsuleVersionError(ValueError):
    """A well-formed format version this verifier does not know.

    Deliberately distinct from MalformedCapsuleError: an operator and an
    auditor must be able to tell "this verifier is too old / the era is
    unknown" apart from "this capsule is corrupt".
    """

    def __init__(self, message: str, *, observed: str | None, status: str) -> None:
        super().__init__(message)
        self.observed = observed
        self.status = status


def unsupported_version_message(field: str, observed, status: str) -> str:
    """Standard diagnosis wording; the needles are the cross-lane contract."""
    if status == "unknown_newer":
        return (
            f"{field} {observed!r} is newer than this verifier supports "
            f"(newest known: {_NEWEST_KNOWN}); this is a limitation of the verifier, "
            f"not corruption of the capsule — verify it with a newer implementation"
        )
    return (
        f"{field} {observed!r} is older than any version this verifier supports "
        f"(oldest known: {_OLDEST_KNOWN}); this is not evidence of tampering — "
        f"verify it with an implementation that retains the {observed} rules"
    )


def require_known_version(field: str, v) -> str:
    """Reader gate: return the version when known; raise otherwise.

    Grammar violations raise a field-path-prefixed ValueError (mapping
    to the registry's invalid_manifest_shape reason); well-formed unknown
    versions raise UnsupportedCapsuleVersionError with the standard,
    distinguishable diagnosis.
    """
    cls = classify_version(v)
    if cls["status"] == "known":
        return v
    if cls["status"] == "invalid":
        raise ValueError(f"{field}: not a '<major>.<minor>' version string, got {v!r}")
    raise UnsupportedCapsuleVersionError(
        unsupported_version_message(field, v, cls["status"]),
        observed=cls["observed"],
        status=cls["status"],
    )


# ---------------------------------------------------------------------------
# Version-keyed domain-separation strings. A verifier that accepts a
# v0.6 capsule must retain the v0.6 strings forever, selected by the
# capsule's DECLARED version — never a single current constant.
# ---------------------------------------------------------------------------


def id_domain(version: str) -> bytes:
    """``capsule-id-v<version>\\0`` — the capsule_id hash domain."""
    return f"capsule-id-v{version}\x00".encode()


def provenance_domain(version: str, role: str) -> bytes:
    """``capsule-provenance-v<version>:<role>\\0`` — the signing domain."""
    return f"capsule-provenance-v{version}:{role}\x00".encode()


def key_wrap_info(version: str) -> bytes:
    """``capsule-key-wrap-v<version>`` — the HKDF info for key wrap."""
    return f"capsule-key-wrap-v{version}".encode()

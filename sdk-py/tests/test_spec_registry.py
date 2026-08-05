"""Registry-driven conformance against spec/vectors.

These tests read the language-neutral outcome registries directly, so the
Python lane tracks the same normative expectations as the JS reference
lane (tools/check-spec-vectors.mjs) without hand-copied assertions:

  - tamper-detection/vectors.json   (verify-stage outcomes)
  - malformed-layout/vectors.json   (open-stage reasons + verify-stage)
  - malformed-shape/vectors.json    (open-stage reasons + verify-stage)
  - unknown-fields/vectors.json     (unknown-member preservation outcomes)
  - signer-set/vectors.json         (signer-set binding outcomes)
  - chain-binding/vectors.json      (empty-chain anchor + stored-line hashing)
  - chain-rules/vectors.json        (per-event actor + kind field rules)
  - signing-input.json              (byte-level signing/hashing pins)
  - jcs-key-order.json              (RFC 8785 §3.2.3 member ordering)
  - ijson-acceptance.json           (the I-JSON canonicalization input domain)
  - unicode-boundary/vectors.json   (Pith-truncated astral text verifies)
  - pith-authoring/vectors.json     (verbatim technical prose + the
                                     pith_normalized_fields marker verify)
  - version-compat/vectors.json     (version gates: known opens, unknown fails
                                     closed with a non-tamper diagnosis)
  - profile-declaration/vectors.json (the profile gate: absence means the
                                     default profile, declared alternates
                                     fail closed as a verifier limitation)
  - result-vocabulary/vectors.json  (the normalized verdict surface:
                                     verdict / verdict_reason / qualifiers)

The `reason` categories are normative; the regexes below map each
category onto this lane's error messages.
"""

from __future__ import annotations

import base64
import json
import pathlib

import pytest

from capsule import CapsuleReader, verify_capsule
from capsule.canonical import (
    bytes_to_hex,
    concat_bytes,
    hex_to_bytes,
    jcs,
    loads_strict,
    sha256_hex,
)
from capsule.crypto import ed25519_verify
from capsule.envelope import envelope_canonical_payload, envelope_signing_input

VECTORS = pathlib.Path(__file__).resolve().parents[2] / "spec" / "vectors"
TAMPER = VECTORS / "tamper-detection" / "vectors.json"
MALFORMED = VECTORS / "malformed-layout" / "vectors.json"
MALFORMED_SHAPE = VECTORS / "malformed-shape" / "vectors.json"
UNKNOWN_FIELDS = VECTORS / "unknown-fields" / "vectors.json"
SIGNER_SET = VECTORS / "signer-set" / "vectors.json"
CHAIN_BINDING = VECTORS / "chain-binding" / "vectors.json"
SEMANTIC = VECTORS / "semantic-binding" / "vectors.json"
CHAIN_RULES = VECTORS / "chain-rules" / "vectors.json"
SKILL_TRUST = VECTORS / "skill-trust" / "vectors.json"
SIGNING_INPUT = VECTORS / "signing-input.json"
KEY_VALIDATION = VECTORS / "ed25519-key-validation.json"
KEY_ORDER = VECTORS / "jcs-key-order.json"
IJSON_ACCEPTANCE = VECTORS / "ijson-acceptance.json"
UNICODE_BOUNDARY = VECTORS / "unicode-boundary" / "vectors.json"
PITH_AUTHORING = VECTORS / "pith-authoring" / "vectors.json"
VERSION_COMPAT = VECTORS / "version-compat" / "vectors.json"
PROFILE_DECLARATION = VECTORS / "profile-declaration" / "vectors.json"
RESULT_VOCABULARY = VECTORS / "result-vocabulary" / "vectors.json"

# Normative reject-reason vocabulary from ijson-acceptance.json.
IJSON_REASONS = {"integer_out_of_range", "unpaired_surrogate", "duplicate_member"}

# Per-lane mapping of the registry's normative open-stage reason
# categories onto this SDK's error messages. Every reader error here is a
# ValueError subclass (MalformedCapsuleError, UnsafeZipPathError).
OPEN_REASON_PATTERNS = {
    "missing_required_file": r"missing (manifest\.json|provenance/envelope\.json)",
    "invalid_json": r"parse",
    # Every manifest shape error from reader._validate_manifest_shape is
    # prefixed with the offending field path — as is every profile
    # declaration shape error, which can name either document
    # (spec/profiles.md: the closed profile object).
    "invalid_manifest_shape": r"^(manifest|envelope)\.",
    "duplicate_entry": r"duplicate entry",
    "unsafe_path": r"(parent traversal|absolute)",
    "unsupported_compression": r"only STORED",
    "symlink_entry": r"symlink",
    "directory_marker_shape": r"directory (attribute on non-directory name|marker with nonzero size)",
    "local_central_name_mismatch": r"local/central name mismatch",
    # spec/versioning.md: unknown versions fail closed with a diagnosis
    # DISTINCT from malformation or tampering.
    "unsupported_version_newer": r"newer than this verifier supports",
    "unsupported_version_older": r"older than any version this verifier supports",
    # spec/profiles.md: a declared profile outside the verifier's table is
    # a LIMITATION OF THE VERIFIER (never corruption); disagreeing
    # manifest/envelope declarations are a capsule defect, diagnosed
    # before any table lookup.
    "unsupported_profile": r"is not supported by this verifier",
    "profile_mismatch": r"envelope\.profile does not match manifest\.format\.profile",
}

# expected.profile sub-assertion keys (spec/profiles.md). This lane's
# profile channel is snake_case throughout, so the registry's wire names
# ARE the member names.
PROFILE_EXPECTED_KEYS = (
    "observed",
    "observed_version",
    "declared",
    "effective",
    "effective_version",
    "supported",
    "status",
)

# Per-lane mapping of the registry's normative verify-stage reason
# categories (semantic-binding/vectors.json) onto this SDK's error strings.
VERIFY_REASON_NEEDLES = {
    "first_event_hash_binding": "manifest.first_event_hash mismatch",
    "encryption_shape": "manifest.encryption must be",
    "encryption_metadata_path": "manifest.encryption.metadata_path",
    "cipher_without_blob": "plain capsule must have cipher='none'",
    "blob_without_cipher": "encrypted blob present but envelope.",
}

# Optional lane capabilities a semantic-binding vector may declare in
# requires[]. This SDK implements all of them, so nothing is skipped; the
# set exists so an unknown requirement fails loudly instead of silently
# skipping a vector.
KNOWN_REQUIREMENTS = {"encryption"}

AREA_PREDICATES = {
    "content_index": lambda r: r["content_index"]["ok"] is False,
    "chain": lambda r: r["chain"]["ok"] is False,
    "envelope": lambda r: r["envelope"]["ok"] is False,
    "encrypted_blob": lambda r: any("encrypted_blob_hash" in e for e in r["errors"]),
    "signer_set": lambda r: r["signer_set"]["ok"] is False,
    "originator_binding": lambda r: any("originator binding" in e for e in r["errors"]),
}


def _load(path: pathlib.Path) -> dict:
    return json.loads(path.read_text())


def _allowlist(doc: dict, base: pathlib.Path) -> list[str]:
    if doc.get("originator_public_key_hex"):
        return [doc["originator_public_key_hex"]]
    if doc.get("keys_file"):
        keys = _load((base / doc["keys_file"]).resolve())
        return [keys["originator"]["publicKey"]]
    return []


def _vector_allowlist(doc: dict, vector: dict, base: pathlib.Path) -> list[str]:
    """The trust configuration for ONE vector.

    A vector may pin its own: ``allowlist`` names keypairs in the
    collection's keys_file (``[]`` = verify with no allowlist). The
    host-relative facts (skill trust, the two trust qualifiers) are facts
    about THIS verification, so the same capsule bytes appear under
    several configurations — which a doc-level allowlist cannot express.
    """
    if not isinstance(vector.get("allowlist"), list):
        return _allowlist(doc, base)
    keys = _load((base / doc["keys_file"]).resolve())
    out = []
    for name in vector["allowlist"]:
        assert name in keys, f"{vector['name']}: allowlist entry {name!r} not in keys_file"
        out.append(keys[name]["publicKey"])
    return out


def _collection_params(path: pathlib.Path):
    """Load an outcome collection, failing LOUDLY on absence or emptiness.

    Returning ``[]`` for a missing registry file (the old behavior) makes
    pytest silently collect zero tests — a deleted or renamed collection
    would pass this lane forever. Absence and emptiness are both hard
    errors (F40): they surface as a collection error for the whole module.
    """
    if not path.exists():
        raise FileNotFoundError(f"vector registry missing: {path}")
    doc = _load(path)
    if not doc["vectors"]:
        raise ValueError(f"vector registry is empty: {path}")
    return [pytest.param(doc, v, path.parent, id=v["name"]) for v in doc["vectors"]]


def _error_haystack(result: dict) -> str:
    parts = list(result["errors"])
    parts.extend(result["content_index"]["errors"])
    for e in result["chain"].get("errors", []):
        parts.append(e["message"] if isinstance(e, dict) else str(e))
    return " ".join(parts)


def _assert_result_vocabulary(name: str, expected: dict, result: dict) -> None:
    """The normalized verdict surface + profile channel on ANY result.

    spec/results.md: ``verdict``/``verdict_reason``/``qualifiers`` are
    derived from facts the result already carries, so their invariants
    hold on every vector in every collection and are asserted
    unconditionally; the per-vector pins (exact qualifier array after
    stripping ``x-`` vendor entries, profile channel members, the suite
    fact) are asserted when the vector declares them.
    """
    assert result["verdict"] in ("valid", "invalid", "unsupported"), (
        f"{name}: verdict {result['verdict']!r} outside the closed vocabulary"
    )
    assert (result["verdict"] == "valid") is result["ok"], (
        f"{name}: ok == (verdict == 'valid') is an invariant; got ok={result['ok']}, "
        f"verdict={result['verdict']!r}"
    )
    assert (result["verdict_reason"] is not None) == (result["verdict"] == "unsupported"), (
        f"{name}: verdict_reason is non-null iff verdict is 'unsupported'; got "
        f"verdict={result['verdict']!r}, verdict_reason={result['verdict_reason']!r}"
    )
    assert result["verdict"] == "valid" or result["qualifiers"] == [], (
        f"{name}: qualifiers only ever qualify a VALID verdict; got {result['qualifiers']!r}"
    )

    if "verdict" in expected:
        assert result["verdict"] == expected["verdict"], (
            f"{name}: expected verdict={expected['verdict']!r}, got {result['verdict']!r}"
        )
    if "verdict_reason" in expected:
        assert result["verdict_reason"] == expected["verdict_reason"], (
            f"{name}: expected verdict_reason={expected['verdict_reason']!r}, "
            f"got {result['verdict_reason']!r}"
        )
    if isinstance(expected.get("qualifiers"), list):
        # Exact array in the spec-defined order, compared after stripping
        # x- vendor entries: emission cannot drift by omission OR by
        # invention (this lane emits no x- entries).
        got = [q for q in result["qualifiers"] if not q.startswith("x-")]
        assert got == expected["qualifiers"], (
            f"{name}: expected qualifiers={expected['qualifiers']!r}, got {got!r}"
        )
    if "observed_profile" in expected:
        assert result["profile"]["observed"] == expected["observed_profile"], (
            f"{name}: expected profile.observed={expected['observed_profile']!r}, "
            f"got {result['profile']!r}"
        )
    if "observed_profile_version" in expected:
        assert result["profile"]["observed_version"] == expected["observed_profile_version"], (
            f"{name}: expected profile.observed_version="
            f"{expected['observed_profile_version']!r}, got {result['profile']!r}"
        )
    for key, want in (expected.get("profile") or {}).items():
        assert key in PROFILE_EXPECTED_KEYS, f"{name}: unknown expected profile member {key!r}"
        assert result["profile"][key] == want, (
            f"{name}: expected profile.{key}={want!r}, got {result['profile'][key]!r}"
        )
    if "suite" in expected:
        # Suite honesty (spec/profiles.md): the suite fact nulls whenever
        # the effective profile is not the era default — including on
        # every profile-gate refusal.
        assert result["format_version"]["suite"] == expected["suite"], (
            f"{name}: expected format_version.suite={expected['suite']!r}, "
            f"got {result['format_version']!r}"
        )


def _assert_decryptable(
    name: str, doc: dict, base: pathlib.Path, reader, expected: dict, allowlist: list[str]
) -> None:
    """L3 pin: decrypt with the named keypair; the inner must verify.

    The metadata is resolved through manifest.encryption.metadata_path,
    never a hardcoded path. spec/results.md: ``encrypted_outer_only`` is
    PER-RESULT — the inner L3 result is a plain-capsule verification and
    never carries it.
    """
    keys = _load((base / doc["keys_file"]).resolve())
    pair = keys[expected["decryptable_with"]]
    inner = reader.decrypt(
        recipient_public_key=pair["publicKey"], recipient_private_key=pair["privateKey"]
    )
    inner_result = verify_capsule(inner, allowlist=allowlist, outer_envelope=reader.envelope())
    assert inner_result["ok"] is True, (
        f"{name}: inner capsule must verify; got {inner_result['errors']}"
    )
    assert "encrypted_outer_only" not in inner_result["qualifiers"], (
        f"{name}: inner L3 result must not carry the encrypted_outer_only qualifier; "
        f"got {inner_result['qualifiers']!r}"
    )


def _assert_verify_outcome(name: str, expected: dict, result: dict) -> None:
    assert result["ok"] is expected["ok"], f"{name}: expected ok={expected['ok']}, got {result}"
    _assert_result_vocabulary(name, expected, result)
    for area in expected.get("failing", []):
        pred = AREA_PREDICATES.get(area)
        assert pred is not None, f"{name}: unknown failing area {area!r}"
        assert pred(result), f"{name}: expected area {area!r} to fail; got {result}"
    if expected.get("error_includes"):
        assert expected["error_includes"] in _error_haystack(result), (
            f"{name}: expected an error containing {expected['error_includes']!r}"
        )
    if "signer_set_bound" in expected:
        assert result["signer_set"]["bound"] is expected["signer_set_bound"], (
            f"{name}: expected signer_set.bound={expected['signer_set_bound']}, "
            f"got {result['signer_set']}"
        )
    if "actor_set_bound" in expected:
        # Actor-set binding (chain.md step 6) follows the signer-set
        # contract: a non-empty manifest.participants[] binds the chain's
        # actors; an empty one must be REPORTED as unbound, never rejected.
        assert result["actor_set"]["bound"] is expected["actor_set_bound"], (
            f"{name}: expected actor_set.bound={expected['actor_set_bound']}, "
            f"got {result['actor_set']}"
        )
    if expected.get("notes_includes"):
        # Honest-reporting pin: the verifier must REPORT the weaker claim
        # machine-readably (e.g. a zero-event chain that was not walked).
        assert expected["notes_includes"] in " ".join(result["notes"]), (
            f"{name}: expected a note containing {expected['notes_includes']!r}; "
            f"got {result['notes']!r}"
        )
    if expected.get("observed_version"):
        # spec/versioning.md: the observed format version is a REPORTED
        # fact on the verify result, not merely enforced internally.
        assert result["format_version"]["observed"] == expected["observed_version"], (
            f"{name}: expected format_version.observed="
            f"{expected['observed_version']!r}, got {result['format_version']!r}"
        )
    if "skill_trust" in expected:
        # Skill-trust derivation (spec/trust.md "Skill trust"): the tier
        # MUST come from the verify result — capsule_signed plus the exact
        # per-id map — never from any skill_trust member in the capsule.
        want = expected["skill_trust"]
        assert result["skill_trust"]["capsule_signed"] is want["capsule_signed"], (
            f"{name}: expected skill_trust.capsule_signed={want['capsule_signed']}, "
            f"got {result['skill_trust']}"
        )
        assert result["skill_trust"]["skills"] == want.get("skills", {}), (
            f"{name}: expected skill_trust.skills={want.get('skills')}, "
            f"got {result['skill_trust']['skills']}"
        )


@pytest.mark.parametrize("doc,vector,base", _collection_params(TAMPER))
def test_tamper_registry_outcomes(doc: dict, vector: dict, base: pathlib.Path):
    data = (base / vector["capsule_file"]).read_bytes()
    reader = CapsuleReader.from_bytes(data)
    result = verify_capsule(reader, allowlist=_allowlist(doc, base))
    _assert_verify_outcome(vector["name"], vector["expected"], result)


@pytest.mark.parametrize("doc,vector,base", _collection_params(UNKNOWN_FIELDS))
def test_unknown_fields_registry_outcomes(doc: dict, vector: dict, base: pathlib.Path):
    """Unknown members in the hashed documents MUST be preserved and hashed.

    The positive vector carries x- extension members in manifest.json,
    provenance/envelope.json, and a chain event, all covered by the seal;
    it must verify ok=true. The tampered variants mutate an unknown member
    post-seal and must fail in the pinned area — proving the members are
    inside the integrity envelope, not decoration.
    """
    data = (base / vector["capsule_file"]).read_bytes()
    reader = CapsuleReader.from_bytes(data)
    result = verify_capsule(reader, allowlist=_allowlist(doc, base))
    _assert_verify_outcome(vector["name"], vector["expected"], result)


@pytest.mark.parametrize("doc,vector,base", _collection_params(SIGNER_SET))
def test_signer_set_registry_outcomes(doc: dict, vector: dict, base: pathlib.Path):
    """Signer-set binding: PRESENCE BINDS, ABSENCE REPORTS.

    A present manifest.signer_commitment must equal the normalized
    envelope signer set exactly (strip / add / role-swap / unsorted all
    fail closed); an absent one verifies with signer_set.bound=False.
    Duplicate (role, public_key) signers are malformed, and the manifest
    originator must have a valid role-'originator' signature.
    """
    data = (base / vector["capsule_file"]).read_bytes()
    reader = CapsuleReader.from_bytes(data)
    result = verify_capsule(reader, allowlist=_allowlist(doc, base))
    _assert_verify_outcome(vector["name"], vector["expected"], result)


@pytest.mark.parametrize("doc,vector,base", _collection_params(CHAIN_BINDING))
def test_chain_binding_registry_outcomes(doc: dict, vector: dict, base: pathlib.Path):
    """Empty-chain anchor rule + stored-line hashing (spec/chain.md).

    A chain with zero events is legal — the weakest honest shape — and
    then manifest.first_event_hash, envelope.first_event_hash and
    envelope.entry_hash MUST all be null (claiming an anchor over zero
    events fails closed; those anchors are the only envelope-to-chain
    binding in a plain capsule). The verifier must REPORT that no events
    were walked (notes pin). And an event whose stored bytes omit the
    optional untrusted_payload_fields member must verify: the hash
    preimage is the stored line, never a typed-struct round-trip.
    """
    data = (base / vector["capsule_file"]).read_bytes()
    reader = CapsuleReader.from_bytes(data)
    result = verify_capsule(reader, allowlist=_allowlist(doc, base))
    _assert_verify_outcome(vector["name"], vector["expected"], result)



@pytest.mark.parametrize("doc,vector,base", _collection_params(CHAIN_RULES))
def test_chain_rule_registry_outcomes(doc: dict, vector: dict, base: pathlib.Path):
    """chain.md per-event field rules (verification steps 6 and 7).

    The actor rule is conditional on the manifest's own claim: a
    non-empty participants[] binds every event actor to the declared set
    or system:host (fail-closed); an empty one verifies with
    actor_set.bound=False plus a note — absence is a weaker claim made
    honestly. The kind enum is closed in every tier. All three fixtures
    are cryptographically well-formed, so only these rules decide them.
    """
    data = (base / vector["capsule_file"]).read_bytes()
    reader = CapsuleReader.from_bytes(data)
    result = verify_capsule(reader, allowlist=_allowlist(doc, base))
    _assert_verify_outcome(vector["name"], vector["expected"], result)


@pytest.mark.parametrize("doc,vector,base", _collection_params(SKILL_TRUST))
def test_skill_trust_registry_outcomes(doc: dict, vector: dict, base: pathlib.Path):
    """Skill trust is DERIVED, never read from the capsule (spec/trust.md).

    The same capsule bytes classify differently at hosts with different
    allowlists, so each vector pins its own trust configuration: the
    per-vector ``allowlist`` names keypairs in keys_file ([] = verify
    with no allowlist). A lane that surfaces the fixture's own
    ``skill_trust`` manifest member as trust hands prompt-injection text
    to a host LLM as trusted instructions — that is the defect (A01)
    this collection exists to keep closed.
    """
    data = (base / vector["capsule_file"]).read_bytes()
    reader = CapsuleReader.from_bytes(data)
    result = verify_capsule(reader, allowlist=_vector_allowlist(doc, vector, base))
    _assert_verify_outcome(vector["name"], vector["expected"], result)


def _assert_registry_vector(doc: dict, vector: dict, base: pathlib.Path) -> None:
    """Open-stage vectors must be refused by the reader; the rest verify."""
    for req in vector.get("requires", []):
        assert req in KNOWN_REQUIREMENTS, f"{vector['name']}: unknown requirement {req!r}"
    data = (base / vector["capsule_file"]).read_bytes()
    expected = vector["expected"]
    allowlist = _vector_allowlist(doc, vector, base)
    if expected.get("stage") == "open":
        pattern = OPEN_REASON_PATTERNS.get(expected["reason"])
        assert pattern is not None, f"unknown open-stage reason {expected['reason']!r}"
        with pytest.raises(ValueError, match=pattern):
            CapsuleReader.from_bytes(data)
        # verify_capsule is total: the same bytes must fail closed, not raise.
        result = verify_capsule(data, allowlist=allowlist)
        assert result["ok"] is False, f"{vector['name']}: expected a fail-closed result"
        if expected.get("observed_version"):
            # spec/versioning.md: even when open is refused, the observed
            # version stays a reported fact — it is what lets an auditor
            # tell "this verifier is too old" apart from "corrupt".
            assert result["format_version"]["observed"] == expected["observed_version"], (
                f"{vector['name']}: expected format_version.observed="
                f"{expected['observed_version']!r}, got {result['format_version']!r}"
            )
        # The observed profile declaration and the normalized verdict
        # surface are reported facts on the SAME fail-closed result
        # (spec/profiles.md obligation 8, spec/results.md).
        _assert_result_vocabulary(vector["name"], expected, result)
        return
    reader = CapsuleReader.from_bytes(data)
    options = {"allowlist": allowlist}
    if isinstance(vector.get("accept_versions"), list):
        # Host policy, reported and never decided (spec/versioning.md).
        options["accept_versions"] = vector["accept_versions"]
    result = verify_capsule(reader, **options)
    _assert_verify_outcome(vector["name"], expected, result)
    if expected.get("decryptable_with"):
        _assert_decryptable(vector["name"], doc, base, reader, expected, allowlist)


@pytest.mark.parametrize("doc,vector,base", _collection_params(UNICODE_BOUNDARY))
def test_unicode_boundary_registry_outcomes(doc: dict, vector: dict, base: pathlib.Path):
    """A JS-built capsule carrying Pith-truncated astral text must verify here.

    A failure means this lane's canonicalization disagrees on well-formed
    astral text, not that the capsule was tampered with
    (spec/canonicalization.md, spec/pith.md).
    """
    _assert_registry_vector(doc, vector, base)


@pytest.mark.parametrize("doc,vector,base", _collection_params(PITH_AUTHORING))
def test_pith_authoring_registry_outcomes(doc: dict, vector: dict, base: pathlib.Path):
    """Pith is opt-in authoring (spec/pith.md); its marker is an ordinary member.

    technical-prose-verbatim: a default-built capsule whose summary holds
    dots inside an identifier and decimals, stored byte-identical, no
    marker. pith-normalized-marker: a pith-enabled capsule whose event
    carries pith_normalized_fields (spec/chain.md), covered by the event
    hash like any other member. Both MUST verify ok:true; a failure means
    this lane rejects or re-projects an optional event member, not that a
    capsule was tampered with.
    """
    _assert_registry_vector(doc, vector, base)


@pytest.mark.parametrize("doc,vector,base", _collection_params(VERSION_COMPAT))
def test_version_compat_registry_outcomes(doc: dict, vector: dict, base: pathlib.Path):
    """spec/versioning.md: known versions open and report; unknown fail closed.

    A capsule declaring a KNOWN format version verifies under that era's
    rules with the observed version reported machine-readably. A
    well-formed unknown version is refused with a diagnosis distinct
    from tamper detection (verifier-too-old vs unknown-older), and a
    grammar-violating version is a malformed document, not a support
    gap. The unknown-version fixtures are internally coherent under
    their declared version's domain strings, so only the version gate
    refuses them.
    """
    _assert_registry_vector(doc, vector, base)


@pytest.mark.parametrize("doc,vector,base", _collection_params(PROFILE_DECLARATION))
def test_profile_declaration_registry_outcomes(doc: dict, vector: dict, base: pathlib.Path):
    """spec/profiles.md: absence means the default profile; declarations gate.

    ABSENCE of a declaration in a 0.6/0.7 capsule means profile
    v0.6-suite/1.0, permanently, and the result SAYS so (effective) —
    explicit declaration of the default is legal and exactly equivalent,
    in both documents or (via normalization) in one. A declared
    (id, version) outside this verifier's table is refused at open with
    unsupported_profile — a limitation of the verifier, never a defect of
    the capsule, with the suite fact nulled because no suite governs a
    capsule whose rules were refused. Disagreeing normalized declarations
    are refused BEFORE any table lookup (profile_mismatch, a capsule
    defect: verdict "invalid"), and shape/grammar violations are
    malformed documents, never "unsupported". Every negative fixture is
    internally coherent under default rules except the declaration under
    test, so a lane that skips the gate verifies it ok=true and fails
    here.
    """
    _assert_registry_vector(doc, vector, base)


@pytest.mark.parametrize("doc,vector,base", _collection_params(RESULT_VOCABULARY))
def test_result_vocabulary_registry_outcomes(doc: dict, vector: dict, base: pathlib.Path):
    """spec/results.md: the derived verdict surface, pinned exactly.

    verdict / verdict_reason / qualifiers restate facts this verifier
    already computes: ok == (verdict == "valid"), "unsupported" names a
    limitation of THIS verifier (never corruption), and the qualifier
    array is exact and ordered — the weaker-claim facts a renderer must
    not hide. Several vectors verify the SAME capsule bytes under
    different host configurations (per-vector allowlist, accept_versions)
    because the host-relative qualifiers are facts about THIS
    verification, which is exactly why they can never be capsule members.
    """
    _assert_registry_vector(doc, vector, base)


@pytest.mark.parametrize("doc,vector,base", _collection_params(MALFORMED))
def test_malformed_registry_outcomes(doc: dict, vector: dict, base: pathlib.Path):
    _assert_registry_vector(doc, vector, base)


@pytest.mark.parametrize("doc,vector,base", _collection_params(MALFORMED_SHAPE))
def test_malformed_shape_registry_outcomes(doc: dict, vector: dict, base: pathlib.Path):
    _assert_registry_vector(doc, vector, base)


def _ijson_params():
    if not IJSON_ACCEPTANCE.exists():
        raise FileNotFoundError(f"vector registry missing: {IJSON_ACCEPTANCE}")
    doc = _load(IJSON_ACCEPTANCE)
    if not doc["vectors"]:
        raise ValueError(f"vector registry is empty: {IJSON_ACCEPTANCE}")
    return [pytest.param(v, id=v["name"]) for v in doc["vectors"]]


@pytest.mark.parametrize("vector", _ijson_params())
def test_ijson_acceptance_boundary(vector: dict):
    """spec/canonicalization.md: identical accept/reject boundary in every lane.

    A reject vector is satisfied by refusal at parse time OR at
    canonicalization time — whichever this lane reaches first.
    """
    name = vector["name"]
    try:
        # The SDK's strict document parse: json.loads plus the
        # duplicate-member gate. Rejection here IS the parse-time refusal
        # the vector contract allows.
        parsed = loads_strict(vector["input_json"])
    except ValueError:
        assert vector["expect"] == "reject", f"{name}: an accept vector must parse"
        return
    if vector["expect"] == "accept":
        assert jcs(parsed).decode("utf-8") == vector["canonical"], name
        return
    assert vector["reason"] in IJSON_REASONS, f"{name}: unknown reason {vector['reason']!r}"
    with pytest.raises(ValueError):
        jcs(parsed)


@pytest.mark.parametrize("doc,vector,base", _collection_params(SEMANTIC))
def test_semantic_binding_registry_outcomes(doc: dict, vector: dict, base: pathlib.Path):
    """Manifest claims must agree with the signed envelope, chain, and files.

    Every fixture is well-formed and correctly signed; only its semantics
    are wrong, so nothing but an explicit cross-check catches it
    (manifest.first_event_hash vs envelope vs chain event 1;
    manifest.encryption vs the signed cipher; encrypted-mode detection off
    the signed cipher, never file presence).
    """
    for req in vector.get("requires", []):
        assert req in KNOWN_REQUIREMENTS, f"{vector['name']}: unknown requirement {req!r}"
    data = (base / vector["capsule_file"]).read_bytes()
    expected = vector["expected"]
    name = vector["name"]
    reader = CapsuleReader.from_bytes(data)
    result = verify_capsule(reader, allowlist=_allowlist(doc, base))
    _assert_verify_outcome(name, expected, result)

    if expected.get("reason"):
        needle = VERIFY_REASON_NEEDLES.get(expected["reason"])
        assert needle is not None, f"{name}: unknown verify-stage reason {expected['reason']!r}"
        assert needle in _error_haystack(result), (
            f"{name}: expected an error for reason {expected['reason']!r}; got {result['errors']}"
        )

    if expected.get("decryptable_with"):
        _assert_decryptable(name, doc, base, reader, expected, _allowlist(doc, base))


def test_signing_input_pins():
    """Reproduce every byte-level pin from the capsule in capsule_ref."""
    doc = _load(SIGNING_INPUT)
    ref = _load(VECTORS / doc["meta"]["capsule_ref"])
    reader = CapsuleReader.from_bytes(base64.b64decode(ref["capsule_bytes_b64"]))
    manifest = reader.manifest()
    envelope = reader.envelope()

    # capsule_id = SHA-256(domain || originator_pub_raw || first_event_hash_raw)
    cid = doc["capsule_id"]
    assert cid["domain_utf8"].encode("utf-8").hex() == cid["domain_hex"]
    derived = sha256_hex(
        concat_bytes(
            hex_to_bytes(cid["domain_hex"]),
            hex_to_bytes(cid["originator_public_key_hex"]),
            hex_to_bytes(cid["first_event_hash_hex"]),
        )
    )
    assert derived == cid["capsule_id_hex"] == manifest["id"]
    assert cid["originator_public_key_hex"] == manifest["originator"]["public_key"]
    assert cid["first_event_hash_hex"] == manifest["first_event_hash"]

    # events: hash = SHA-256(prev_hash_raw || JCS(event minus hash))
    events = reader.events()
    assert len(events) == len(doc["events"])
    for pin, event in zip(doc["events"], events, strict=True):
        stored_hash = event["hash"]
        stripped = {k: v for k, v in event.items() if k != "hash"}
        canon = jcs(stripped)
        assert bytes_to_hex(canon) == pin["canonical_bytes_hex"], f"event {pin['seq']}"
        assert stripped["prev_hash"] == pin["prev_hash_hex"]
        recomputed = sha256_hex(concat_bytes(hex_to_bytes(pin["prev_hash_hex"]), canon))
        assert recomputed == pin["hash_hex"] == stored_hash

    # manifest_hash = SHA-256(JCS(manifest))
    manifest_canon = jcs(manifest)
    assert bytes_to_hex(manifest_canon) == doc["manifest"]["canonical_bytes_hex"]
    assert sha256_hex(manifest_canon) == doc["manifest"]["sha256_hex"]
    assert doc["manifest"]["sha256_hex"] == envelope["manifest_hash"]

    # content_index_hash = SHA-256(JCS(content_index.files))
    index_canon = jcs(manifest["content_index"]["files"])
    assert bytes_to_hex(index_canon) == doc["content_index"]["canonical_bytes_hex"]
    assert sha256_hex(index_canon) == doc["content_index"]["sha256_hex"]
    assert doc["content_index"]["sha256_hex"] == envelope["content_index_hash"]

    # envelope canonical payload + per-role signing input + signature
    env_canon = envelope_canonical_payload(envelope)
    assert bytes_to_hex(env_canon) == doc["envelope"]["canonical_payload_hex"]
    assert sha256_hex(env_canon) == doc["envelope"]["canonical_payload_sha256"]
    assert len(doc["envelope"]["signers"]) == len(envelope["signers"])
    for pin, stored in zip(doc["envelope"]["signers"], envelope["signers"], strict=True):
        assert pin["role"] == stored["role"]
        assert pin["public_key_hex"] == stored["public_key"]
        assert pin["signature_hex"] == stored["signature"]
        assert pin["domain_utf8"].encode("utf-8").hex() == pin["domain_hex"]
        signing_input = envelope_signing_input(envelope, pin["role"])
        domain_len = len(hex_to_bytes(pin["domain_hex"]))
        assert bytes_to_hex(signing_input[:domain_len]) == pin["domain_hex"]
        assert bytes_to_hex(signing_input[domain_len:]) == doc["envelope"]["canonical_payload_hex"]
        assert sha256_hex(signing_input) == pin["signing_input_sha256"]
        assert ed25519_verify(
            hex_to_bytes(pin["public_key_hex"]),
            signing_input,
            hex_to_bytes(pin["signature_hex"]),
        )


def _key_validation_params():
    if not KEY_VALIDATION.exists():
        raise FileNotFoundError(f"vector registry missing: {KEY_VALIDATION}")
    doc = json.loads(KEY_VALIDATION.read_text())
    if not doc["vectors"]:
        raise ValueError(f"vector registry is empty: {KEY_VALIDATION}")
    return [pytest.param(v, id=v["name"]) for v in doc["vectors"]]


@pytest.mark.parametrize("vector", _key_validation_params())
def test_ed25519_key_validation_registry(vector: dict):
    """Small-order / non-canonical keys and non-reduced S must be refused."""
    got = ed25519_verify(
        hex_to_bytes(vector["public_key_hex"]),
        hex_to_bytes(vector["message_hex"]),
        hex_to_bytes(vector["signature_hex"]),
    )
    assert got is vector["expected"]["valid"], (
        f"{vector['name']}: expected valid={vector['expected']['valid']} "
        f"({vector['reason']}), got {got}"
    )


def _key_order_params():
    doc = json.loads(KEY_ORDER.read_text())
    if not doc["vectors"]:
        raise ValueError(f"vector registry is empty: {KEY_ORDER}")
    return [pytest.param(v, id=v["name"]) for v in doc["vectors"]]


@pytest.mark.parametrize("vector", _key_order_params())
def test_jcs_key_order_registry(vector: dict):
    """RFC 8785 §3.2.3: members sort on their UTF-16 code-unit sequences.

    Python's default ``str`` ordering is Unicode *code point* order, which
    is a different order: the two disagree whenever a supplementary-plane
    key (>= U+10000, UTF-16 lead surrogate 0xD800..0xDBFF) meets a key in
    U+E000..U+FFFF. Those entries are the negative witnesses — a lane that
    sorts by code point produces different canonical bytes, a different
    hash, and a cross-lane verification failure on an honest capsule.
    """
    obj = {key: i for i, key in enumerate(vector["keys"])}
    canon = jcs(obj)
    assert bytes_to_hex(canon) == vector["canonical_utf8_hex"], vector["name"]
    assert sha256_hex(canon) == vector["sha256_hex"], vector["name"]
    order = list(json.loads(canon.decode("utf-8")).keys())
    assert order == vector["expected_key_order"], vector["name"]

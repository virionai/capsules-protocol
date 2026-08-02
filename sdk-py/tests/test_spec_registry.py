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

# Normative reject-reason vocabulary from ijson-acceptance.json.
IJSON_REASONS = {"integer_out_of_range", "unpaired_surrogate", "duplicate_member"}

# Per-lane mapping of the registry's normative open-stage reason
# categories onto this SDK's error messages. Every reader error here is a
# ValueError subclass (MalformedCapsuleError, UnsafeZipPathError).
OPEN_REASON_PATTERNS = {
    "missing_required_file": r"missing (manifest\.json|provenance/envelope\.json)",
    "invalid_json": r"parse",
    # Every manifest shape error from reader._validate_manifest_shape is
    # prefixed with the offending field path.
    "invalid_manifest_shape": r"^manifest\.",
    "duplicate_entry": r"duplicate entry",
    "unsafe_path": r"(parent traversal|absolute)",
    "unsupported_compression": r"only STORED",
    "symlink_entry": r"symlink",
    "directory_marker_shape": r"directory (attribute on non-directory name|marker with nonzero size)",
    "local_central_name_mismatch": r"local/central name mismatch",
}

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


def _assert_verify_outcome(name: str, expected: dict, result: dict) -> None:
    assert result["ok"] is expected["ok"], f"{name}: expected ok={expected['ok']}, got {result}"
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
    keys = _load((base / doc["keys_file"]).resolve())
    allowlist = []
    for key_name in vector.get("allowlist", []):
        assert key_name in keys, f"{vector['name']}: allowlist entry {key_name!r} not in keys_file"
        allowlist.append(keys[key_name]["publicKey"])
    data = (base / vector["capsule_file"]).read_bytes()
    reader = CapsuleReader.from_bytes(data)
    result = verify_capsule(reader, allowlist=allowlist)
    _assert_verify_outcome(vector["name"], vector["expected"], result)


def _assert_registry_vector(doc: dict, vector: dict, base: pathlib.Path) -> None:
    """Open-stage vectors must be refused by the reader; the rest verify."""
    data = (base / vector["capsule_file"]).read_bytes()
    expected = vector["expected"]
    if expected.get("stage") == "open":
        pattern = OPEN_REASON_PATTERNS.get(expected["reason"])
        assert pattern is not None, f"unknown open-stage reason {expected['reason']!r}"
        with pytest.raises(ValueError, match=pattern):
            CapsuleReader.from_bytes(data)
        # verify_capsule is total: the same bytes must fail closed, not raise.
        result = verify_capsule(data, allowlist=_allowlist(doc, base))
        assert result["ok"] is False, f"{vector['name']}: expected a fail-closed result"
        return
    reader = CapsuleReader.from_bytes(data)
    result = verify_capsule(reader, allowlist=_allowlist(doc, base))
    _assert_verify_outcome(vector["name"], expected, result)


@pytest.mark.parametrize("doc,vector,base", _collection_params(UNICODE_BOUNDARY))
def test_unicode_boundary_registry_outcomes(doc: dict, vector: dict, base: pathlib.Path):
    """A JS-built capsule carrying Pith-truncated astral text must verify here.

    A failure means this lane's canonicalization disagrees on well-formed
    astral text, not that the capsule was tampered with
    (spec/canonicalization.md, spec/pith.md).
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
        # L3 pin: decrypt with the named keypair — resolving the metadata
        # through manifest.encryption.metadata_path, never a hardcoded
        # path — and the inner capsule must verify against the outer.
        keys = _load((base / doc["keys_file"]).resolve())
        pair = keys[expected["decryptable_with"]]
        inner = reader.decrypt(
            recipient_public_key=pair["publicKey"],
            recipient_private_key=pair["privateKey"],
        )
        inner_result = verify_capsule(
            inner, allowlist=_allowlist(doc, base), outer_envelope=reader.envelope()
        )
        assert inner_result["ok"] is True, (
            f"{name}: inner capsule must verify; got {inner_result['errors']}"
        )


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

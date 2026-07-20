import json

import pytest

from capsule.builder import CapsuleBuilder
from capsule.crypto import generate_ed25519, generate_x25519
from capsule.zip_io import unpack_zip


def _make_signed_capsule(*, signed_at="2026-05-07T12:00:00Z"):
    kp = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": "Acme"},
        participants=[{"actor_id": "human:alice", "role": "originator", "label": "Alice"}],
    )
    builder.set_program("# Loan application\nApproved.\n")
    builder.set_agents("# Agents\n- human:alice\n")
    builder.append_event(
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "approved_application",
            "target": "program.md",
            "timestamp": "2026-05-07T12:00:00Z",
            "payload": {"amount": 50000},
        }
    )
    bytes_out = builder.seal(
        signers=[
            {"role": "originator", "public_key": kp.public_key, "private_key": kp.private_key}
        ],
        signed_at=signed_at,
    )
    return bytes_out, kp


def test_seal_emits_required_files():
    zip_bytes, _ = _make_signed_capsule()
    files = unpack_zip(zip_bytes)
    assert "manifest.json" in files
    assert "program.md" in files
    assert "agents.md" in files
    assert "chain/events.jsonl" in files
    assert "provenance/envelope.json" in files


def test_seal_emits_no_program_default_creates_minimal_program():
    kp = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": ""},
        participants=[],
    )
    builder.append_event(
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "x",
            "target": "p",
            "timestamp": "2026-05-07T12:00:00Z",
            "payload": {},
        }
    )
    zip_bytes = builder.seal(
        signers=[
            {"role": "originator", "public_key": kp.public_key, "private_key": kp.private_key}
        ],
        signed_at="2026-05-07T12:00:00Z",
    )
    files = unpack_zip(zip_bytes)
    assert files["program.md"] == b"# Program\n"


def test_seal_emits_backstop_event_when_chain_empty():
    kp = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": ""},
        participants=[],
    )
    zip_bytes = builder.seal(
        signers=[
            {"role": "originator", "public_key": kp.public_key, "private_key": kp.private_key}
        ],
        signed_at="2026-05-07T12:00:00Z",
    )
    files = unpack_zip(zip_bytes)
    chain_text = files["chain/events.jsonl"].decode("utf-8")
    assert "session_ended" in chain_text
    assert "system:host" in chain_text


def test_seal_requires_signers():
    kp = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": ""},
        participants=[],
    )
    with pytest.raises(ValueError, match="at least one signer"):
        builder.seal(signers=[], signed_at="2026-05-07T12:00:00Z")


def test_seal_defaults_signed_at_to_now():
    # signed_at is optional (defaults to now, second precision); pass an
    # explicit value for reproducible builds.
    import re

    from capsule import CapsuleReader

    kp = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": ""},
        participants=[],
    )
    data = builder.seal(
        signers=[
            {"role": "originator", "public_key": kp.public_key, "private_key": kp.private_key}
        ],
    )
    envelope = CapsuleReader.from_bytes(data).envelope()
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", envelope["signed_at"])


def test_add_skill_rejects_invalid_id():
    builder = CapsuleBuilder(originator={"public_key": "a" * 64, "label": ""}, participants=[])
    with pytest.raises(ValueError):
        builder.add_skill("bad/id", markdown="x")


def test_add_skill_rejects_decryption_reserved():
    builder = CapsuleBuilder(originator={"public_key": "a" * 64, "label": ""}, participants=[])
    with pytest.raises(ValueError):
        builder.add_skill("decryption", markdown="x")


def test_add_payload_requires_payload_prefix():
    builder = CapsuleBuilder(originator={"public_key": "a" * 64, "label": ""}, participants=[])
    with pytest.raises(ValueError, match="payload/"):
        builder.add_payload("not-payload/file", b"x")


def test_skill_files_land_in_capsule():
    kp = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": ""},
        participants=[],
    )
    builder.add_skill("foo", json={"name": "foo", "version": "1"}, markdown="# foo\n")
    builder.append_event(
        {
            "actor": "h:a",
            "kind": "decision",
            "action": "x",
            "target": "p",
            "timestamp": "2026-05-07T12:00:00Z",
            "payload": {},
        }
    )
    zip_bytes = builder.seal(
        signers=[
            {"role": "originator", "public_key": kp.public_key, "private_key": kp.private_key}
        ],
        signed_at="2026-05-07T12:00:00Z",
    )
    files = unpack_zip(zip_bytes)
    assert "skills/foo/skill.json" in files
    assert "skills/foo/SKILL.md" in files


def test_payload_files_land_in_capsule():
    kp = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": ""},
        participants=[],
    )
    builder.add_payload("payload/photo.jpg", b"\xff\xd8jpeg")
    builder.append_event(
        {
            "actor": "h:a",
            "kind": "decision",
            "action": "x",
            "target": "p",
            "timestamp": "2026-05-07T12:00:00Z",
            "payload": {},
        }
    )
    zip_bytes = builder.seal(
        signers=[
            {"role": "originator", "public_key": kp.public_key, "private_key": kp.private_key}
        ],
        signed_at="2026-05-07T12:00:00Z",
    )
    files = unpack_zip(zip_bytes)
    assert files["payload/photo.jpg"] == b"\xff\xd8jpeg"


# ---------------------------------------------------------------------------
# Encrypted capsule tests
# ---------------------------------------------------------------------------


def _make_encrypted_capsule(recipients, *, signed_at="2026-05-07T12:00:00Z"):
    kp = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": "Acme"},
        participants=[],
    )
    builder.set_program("# Encrypted program\n")
    builder.append_event(
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "approved",
            "target": "program.md",
            "timestamp": signed_at,
            "payload": {"secret": "data"},
        }
    )
    zip_bytes = builder.seal(
        signers=[
            {"role": "originator", "public_key": kp.public_key, "private_key": kp.private_key}
        ],
        signed_at=signed_at,
        recipients=recipients,
    )
    return zip_bytes, kp


def test_encrypted_outer_files_present():
    from capsule.crypto import generate_x25519

    r = generate_x25519()
    zip_bytes, _ = _make_encrypted_capsule([r.public_key])
    files = unpack_zip(zip_bytes)
    assert "manifest.json" in files
    assert "content.enc" in files
    assert "skills/decryption/decryption.json" in files
    assert "provenance/envelope.json" in files
    # Inner files must NOT be in the outer ZIP
    assert "program.md" not in files
    assert "chain/events.jsonl" not in files


def test_encrypted_outer_files_absent_from_content_index():
    from capsule.crypto import generate_x25519

    r = generate_x25519()
    zip_bytes, _ = _make_encrypted_capsule([r.public_key])
    files = unpack_zip(zip_bytes)
    manifest = json.loads(files["manifest.json"])
    indexed_paths = {e["path"] for e in manifest["content_index"]["files"]}
    # content.enc is excluded; decryption.json IS indexed
    assert "content.enc" not in indexed_paths
    assert "skills/decryption/decryption.json" in indexed_paths


def test_encrypted_manifest_encryption_field():
    from capsule.crypto import generate_x25519

    r = generate_x25519()
    zip_bytes, _ = _make_encrypted_capsule([r.public_key])
    files = unpack_zip(zip_bytes)
    manifest = json.loads(files["manifest.json"])
    enc = manifest["encryption"]
    assert enc["cipher"] == "ChaCha20-Poly1305"
    assert enc["metadata_path"] == "skills/decryption/decryption.json"


def test_encrypted_decryption_json_structure():
    from capsule.crypto import generate_x25519

    r = generate_x25519()
    zip_bytes, _ = _make_encrypted_capsule([r.public_key])
    files = unpack_zip(zip_bytes)
    meta = json.loads(files["skills/decryption/decryption.json"])
    assert meta["cipher"] == "ChaCha20-Poly1305"
    assert len(meta["content_nonce"]) == 24  # 12 bytes -> 24 hex chars
    assert len(meta["key_bundles"]) == 1
    bundle = meta["key_bundles"][0]
    assert bundle["recipient_public_key"] == r.public_key_hex
    assert len(bundle["ephemeral_public_key"]) == 64  # 32 bytes hex
    assert len(bundle["wrap_nonce"]) == 24  # 12 bytes hex
    assert len(bundle["wrapped_key"]) == 96  # 32-byte key + 16-byte tag = 48 bytes -> 96 hex chars


def test_encrypted_round_trip_decryption():
    from capsule.canonical import hex_to_bytes
    from capsule.crypto import (
        chacha20_poly1305_decrypt,
        generate_x25519,
        hkdf_sha256,
        x25519_dh,
    )
    from capsule.zip_io import unpack_zip as unzip

    r = generate_x25519()
    zip_bytes, _ = _make_encrypted_capsule([r.public_key])
    outer = unzip(zip_bytes)
    meta = json.loads(outer["skills/decryption/decryption.json"])
    outer_manifest = json.loads(outer["manifest.json"])
    capsule_id = outer_manifest["id"]

    # find bundle for our recipient
    bundle = next(b for b in meta["key_bundles"] if b["recipient_public_key"] == r.public_key_hex)
    eph_pub = hex_to_bytes(bundle["ephemeral_public_key"])
    wrap_nonce = hex_to_bytes(bundle["wrap_nonce"])
    wrapped_key = hex_to_bytes(bundle["wrapped_key"])

    # unwrap content key
    shared = x25519_dh(r.private_key, eph_pub)
    wrap_key = hkdf_sha256(
        shared,
        r.public_key,  # salt = recipient pub
        b"capsule-key-wrap-v0.6",
        32,
    )
    content_key = chacha20_poly1305_decrypt(wrap_key, wrap_nonce, b"", wrapped_key)
    assert len(content_key) == 32

    # decrypt content.enc
    content_nonce = hex_to_bytes(meta["content_nonce"])
    first_event_hash = outer_manifest["first_event_hash"]
    originator_pub = outer_manifest["originator"]["public_key"]
    aad_obj = {
        "capsule_id": capsule_id,
        "cipher": "ChaCha20-Poly1305",
        "first_event_hash": first_event_hash,
        "originator_public_key": originator_pub,
        "version": "0.6",
    }
    from capsule.canonical import jcs

    aad = jcs(aad_obj)
    inner_zip = chacha20_poly1305_decrypt(content_key, content_nonce, aad, outer["content.enc"])
    inner_files = unzip(inner_zip)
    assert "program.md" in inner_files
    assert "chain/events.jsonl" in inner_files


def test_plain_path_unchanged_when_no_recipients():
    """recipients=None must produce byte-identical output to calling without recipients."""
    kp = generate_ed25519()
    builder1 = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": "Acme"},
        participants=[],
    )
    builder1.set_program("# Test\n")
    builder1.append_event(
        {
            "actor": "h:a",
            "kind": "decision",
            "action": "x",
            "target": "p",
            "timestamp": "2026-05-07T12:00:00Z",
            "payload": {},
        }
    )
    zip1 = builder1.seal(
        signers=[
            {"role": "originator", "public_key": kp.public_key, "private_key": kp.private_key}
        ],
        signed_at="2026-05-07T12:00:00Z",
        recipients=None,
    )

    builder2 = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": "Acme"},
        participants=[],
    )
    builder2.set_program("# Test\n")
    builder2.append_event(
        {
            "actor": "h:a",
            "kind": "decision",
            "action": "x",
            "target": "p",
            "timestamp": "2026-05-07T12:00:00Z",
            "payload": {},
        }
    )
    zip2 = builder2.seal(
        signers=[
            {"role": "originator", "public_key": kp.public_key, "private_key": kp.private_key}
        ],
        signed_at="2026-05-07T12:00:00Z",
    )

    files1 = unpack_zip(zip1)
    files2 = unpack_zip(zip2)
    assert set(files1.keys()) == set(files2.keys())
    for path in files1:
        assert files1[path] == files2[path], f"mismatch at {path}"


def test_encrypted_seal_decryption_metadata_multiple_recipients():
    """3 recipients → 3 distinct key bundles, each pubkey present exactly once."""
    kp = generate_ed25519()
    recipients = [generate_x25519() for _ in range(3)]
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": ""},
        participants=[],
    )
    builder.set_program("# multi\n")
    builder.append_event(
        {
            "actor": "h:a",
            "kind": "decision",
            "action": "x",
            "target": "p",
            "timestamp": "2026-05-07T12:00:00Z",
            "payload": {},
        }
    )
    zip_bytes = builder.seal(
        signers=[
            {"role": "originator", "public_key": kp.public_key, "private_key": kp.private_key}
        ],
        signed_at="2026-05-07T12:00:00Z",
        recipients=[r.public_key for r in recipients],
    )
    files = unpack_zip(zip_bytes)
    meta = json.loads(files["skills/decryption/decryption.json"].decode("utf-8"))
    assert len(meta["key_bundles"]) == 3
    bundle_pubkeys = {b["recipient_public_key"] for b in meta["key_bundles"]}
    assert bundle_pubkeys == {r.public_key_hex for r in recipients}
    # Each bundle has its own ephemeral pubkey + wrap nonce (no sharing).
    eph_keys = {b["ephemeral_public_key"] for b in meta["key_bundles"]}
    wrap_nonces = {b["wrap_nonce"] for b in meta["key_bundles"]}
    assert len(eph_keys) == 3
    assert len(wrap_nonces) == 3


def test_encrypted_seal_rejects_wrong_recipient_pubkey_length():
    """A 31-byte recipient public key must raise ValueError before any sealing."""
    kp = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": ""},
        participants=[],
    )
    with pytest.raises(ValueError, match="32 bytes"):
        builder.seal(
            signers=[
                {
                    "role": "originator",
                    "public_key": kp.public_key,
                    "private_key": kp.private_key,
                }
            ],
            signed_at="2026-05-07T12:00:00Z",
            recipients=[b"\x00" * 31],
        )

import json

import pytest

from capsule.builder import CapsuleBuilder
from capsule.crypto import generate_ed25519, generate_x25519
from capsule.envelope import EncryptedCapsulesNotSupportedError
from capsule.reader import CapsuleReader, MalformedCapsuleError


def _build():
    kp = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": "Acme"},
        participants=[],
    )
    builder.set_program("# Loan\n")
    builder.set_agents("# Agents\n")
    builder.append_event(
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "approved",
            "target": "program.md",
            "timestamp": "2026-05-07T12:00:00Z",
            "payload": {"amount": 1},
        }
    )
    return builder.seal(
        signers=[
            {"role": "originator", "public_key": kp.public_key, "private_key": kp.private_key}
        ],
        signed_at="2026-05-07T12:00:00Z",
    ), kp


def test_from_bytes_loads_manifest_envelope_chain_and_program():
    zip_bytes, kp = _build()
    reader = CapsuleReader.from_bytes(zip_bytes)
    m = reader.manifest()
    assert m["format"]["version"] == "0.6"
    assert m["originator"]["public_key"] == kp.public_key_hex
    env = reader.envelope()
    assert env["version"] == "0.6"
    assert env["cipher"] == "none"
    events = reader.events()
    assert len(events) == 1
    assert events[0]["action"] == "approved"
    assert reader.program() == "# Loan\n"
    assert reader.agents_md() == "# Agents\n"
    assert "manifest.json" in reader.files()
    assert reader.is_encrypted() is False


def test_from_bytes_rejects_missing_manifest():
    # Manually craft a ZIP missing manifest.json.
    from capsule.zip_io import pack_zip

    bad = pack_zip({"program.md": b"hi", "chain/events.jsonl": b""})
    with pytest.raises(MalformedCapsuleError, match=r"manifest\.json"):
        CapsuleReader.from_bytes(bad)


def test_from_bytes_rejects_missing_envelope():
    from capsule.zip_io import pack_zip

    bad = pack_zip(
        {
            "manifest.json": json.dumps({"format": {"version": "0.6"}}).encode(),
            "program.md": b"hi",
            "chain/events.jsonl": b"",
        }
    )
    with pytest.raises(MalformedCapsuleError, match=r"envelope\.json"):
        CapsuleReader.from_bytes(bad)


def test_is_encrypted_when_manifest_has_encryption():
    # We don't have an encrypted capsule writer (v0.2), but we can fake
    # the manifest to test the read-side gate.
    from capsule.zip_io import pack_zip

    manifest = {
        "format": {"version": "0.6"},
        "encryption": {"metadata_path": "x", "cipher": "ChaCha20-Poly1305"},
    }
    envelope = {"version": "0.6", "cipher": "ChaCha20-Poly1305", "signers": []}
    zip_bytes = pack_zip(
        {
            "manifest.json": json.dumps(manifest).encode(),
            "provenance/envelope.json": json.dumps(envelope).encode(),
            "content.enc": b"opaque",
        }
    )
    reader = CapsuleReader.from_bytes(zip_bytes)
    assert reader.is_encrypted() is True
    with pytest.raises(EncryptedCapsulesNotSupportedError):
        _ = reader.events()
    with pytest.raises(EncryptedCapsulesNotSupportedError):
        _ = reader.program()


# ---------------------------------------------------------------------------
# Encrypted helpers + decrypt
# ---------------------------------------------------------------------------


def _build_enc_capsule(*, recipient_count=1):
    kp = generate_ed25519()
    recipients = [generate_x25519() for _ in range(recipient_count)]
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": "Acme"},
        participants=[{"actor_id": "human:alice", "role": "originator", "label": "A"}],
    )
    builder.set_program("# encrypted loan\n")
    builder.set_agents("# agents\n")
    builder.append_event(
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "approved",
            "target": "program.md",
            "timestamp": "2026-05-07T12:00:00Z",
            "payload": {"amount": 1234},
        }
    )
    zip_bytes = builder.seal(
        signers=[
            {
                "role": "originator",
                "public_key": kp.public_key,
                "private_key": kp.private_key,
            }
        ],
        signed_at="2026-05-07T12:00:00Z",
        recipients=[r.public_key for r in recipients],
    )
    return zip_bytes, kp, recipients


def test_encrypted_blob_bytes_returns_content_enc():
    zip_bytes, _, _ = _build_enc_capsule()
    reader = CapsuleReader.from_bytes(zip_bytes)
    assert reader.is_encrypted() is True
    blob = reader.encrypted_blob_bytes()
    assert isinstance(blob, bytes) and len(blob) > 0


def test_encrypted_blob_bytes_raises_when_plain():
    kp = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": ""},
        participants=[],
    )
    builder.set_program("# x\n")
    plain_zip = builder.seal(
        signers=[
            {
                "role": "originator",
                "public_key": kp.public_key,
                "private_key": kp.private_key,
            }
        ],
        signed_at="2026-05-07T12:00:00Z",
    )
    reader = CapsuleReader.from_bytes(plain_zip)
    with pytest.raises(MalformedCapsuleError):
        reader.encrypted_blob_bytes()


def test_decryption_metadata_returns_dict_for_encrypted():
    zip_bytes, _, recipients = _build_enc_capsule(recipient_count=1)
    reader = CapsuleReader.from_bytes(zip_bytes)
    meta = reader.decryption_metadata()
    assert meta is not None
    assert meta["cipher"] == "ChaCha20-Poly1305"
    assert any(
        b["recipient_public_key"] == recipients[0].public_key_hex for b in meta["key_bundles"]
    )


def test_decryption_metadata_none_for_plain():
    kp = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": ""}, participants=[]
    )
    builder.set_program("# x\n")
    plain_zip = builder.seal(
        signers=[
            {
                "role": "originator",
                "public_key": kp.public_key,
                "private_key": kp.private_key,
            }
        ],
        signed_at="2026-05-07T12:00:00Z",
    )
    reader = CapsuleReader.from_bytes(plain_zip)
    assert reader.decryption_metadata() is None


def test_decrypt_returns_inner_reader_with_program_and_chain():
    zip_bytes, _, recipients = _build_enc_capsule()
    reader = CapsuleReader.from_bytes(zip_bytes)
    inner = reader.decrypt(
        recipient_public_key=recipients[0].public_key,
        recipient_private_key=recipients[0].private_key,
    )
    assert isinstance(inner, CapsuleReader)
    assert inner.is_encrypted() is False
    assert inner.program() == "# encrypted loan\n"
    events = inner.events()
    assert len(events) == 1
    assert events[0]["action"] == "approved"


def test_decrypt_rejects_when_plain():
    kp = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": ""}, participants=[]
    )
    builder.set_program("# x\n")
    plain_zip = builder.seal(
        signers=[
            {
                "role": "originator",
                "public_key": kp.public_key,
                "private_key": kp.private_key,
            }
        ],
        signed_at="2026-05-07T12:00:00Z",
    )
    reader = CapsuleReader.from_bytes(plain_zip)
    a = generate_x25519()
    with pytest.raises(ValueError, match="not encrypted"):
        reader.decrypt(recipient_public_key=a.public_key, recipient_private_key=a.private_key)


def test_decrypt_rejects_bad_key_lengths():
    zip_bytes, _, recipients = _build_enc_capsule()
    reader = CapsuleReader.from_bytes(zip_bytes)
    with pytest.raises(ValueError, match="32 bytes"):
        reader.decrypt(
            recipient_public_key=b"\x00" * 31,
            recipient_private_key=recipients[0].private_key,
        )
    with pytest.raises(ValueError, match="32 bytes"):
        reader.decrypt(
            recipient_public_key=recipients[0].public_key,
            recipient_private_key=b"\x00" * 31,
        )


def test_decrypt_rejects_unmatched_recipient():
    zip_bytes, _, _ = _build_enc_capsule(recipient_count=1)
    reader = CapsuleReader.from_bytes(zip_bytes)
    other = generate_x25519()
    with pytest.raises(ValueError, match="no matching recipient"):
        reader.decrypt(
            recipient_public_key=other.public_key,
            recipient_private_key=other.private_key,
        )


def test_decrypt_with_wrong_private_key_raises_on_aead():
    # Match the recipient slot by pubkey but supply a wrong private key —
    # ChaCha20-Poly1305 should fail authentication on the wrapped key.
    zip_bytes, _, recipients = _build_enc_capsule(recipient_count=1)
    reader = CapsuleReader.from_bytes(zip_bytes)
    other = generate_x25519()
    with pytest.raises(Exception):  # cryptography's InvalidTag, or wrapped  # noqa: B017
        reader.decrypt(
            recipient_public_key=recipients[0].public_key,
            recipient_private_key=other.private_key,
        )


def test_decrypt_third_of_three_recipients():
    zip_bytes, _, recipients = _build_enc_capsule(recipient_count=3)
    reader = CapsuleReader.from_bytes(zip_bytes)
    third = recipients[2]
    inner = reader.decrypt(
        recipient_public_key=third.public_key,
        recipient_private_key=third.private_key,
    )
    assert inner.program() == "# encrypted loan\n"

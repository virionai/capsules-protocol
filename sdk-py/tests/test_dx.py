"""Developer-experience surface tests. Mirrors sdk-js/test/dx.test.js.

Pins the quickstart path in the README: keypair objects work directly as
originator / signers / recipients / decrypt arguments, every key input
accepts hex or bytes, seal()/append_event() apply defaults, and
verify_capsule() accepts raw bytes and fails closed on garbage.
"""

from __future__ import annotations

import re

import pytest

from capsule import (
    CapsuleBuilder,
    CapsuleReader,
    generate_ed25519,
    generate_x25519,
    verify_capsule,
)

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def test_quickstart_keypair_object_end_to_end_with_defaults():
    keys = generate_ed25519()

    builder = CapsuleBuilder(originator=keys)
    builder.set_program("# Hello capsule\n")
    builder.append_event({"actor": "human:me", "action": "created_note"})
    data = builder.seal(signers=keys)

    result = verify_capsule(data, allowlist=[keys.public_key])
    assert result["ok"] is True, result["errors"]
    assert result["trusted_signer_count"] == 1

    reader = CapsuleReader.from_bytes(data)
    (event,) = reader.events()
    assert event["kind"] == "observation"
    assert event["target"] == "capsule"
    assert _TS_RE.match(event["timestamp"])
    assert reader.envelope()["signers"][0]["role"] == "originator"
    assert _TS_RE.match(reader.envelope()["signed_at"])


def test_hex_keys_accepted_everywhere_bytes_are():
    keys = generate_ed25519()

    builder = CapsuleBuilder(
        originator={"public_key": keys.public_key_hex.upper(), "label": "HexApp"}
    )
    builder.set_program("# Hex\n")
    builder.append_event({"actor": "human:me", "action": "noted"})
    data = builder.seal(
        signers=[
            {
                "role": "originator",
                "public_key": keys.public_key_hex,
                "private_key": keys.private_key_hex,
            }
        ],
    )

    result = verify_capsule(data, allowlist=[keys.public_key_hex.upper()])
    assert result["ok"] is True, result["errors"]
    assert result["trusted_signer_count"] == 1
    # wire format stays lowercase regardless of input case
    reader = CapsuleReader.from_bytes(data)
    assert reader.manifest()["originator"]["public_key"] == keys.public_key_hex


def test_verify_capsule_on_garbage_bytes_fails_closed():
    result = verify_capsule(b"this is not a capsule")
    assert result["ok"] is False
    assert result["trusted_signer_count"] == 0
    assert "cannot be opened" in result["errors"][0]


def test_encrypt_decrypt_round_trip_with_keypair_objects_only():
    signer = generate_ed25519()
    recipient = generate_x25519()

    builder = CapsuleBuilder(originator=signer)
    builder.set_program("# Secret\n")
    builder.append_event({"actor": "human:me", "action": "wrote_secret"})
    data = builder.seal(signers=signer, recipients=recipient)

    outer = CapsuleReader.from_bytes(data)
    assert outer.is_encrypted() is True

    l2 = verify_capsule(data, allowlist=[signer.public_key_hex])
    assert l2["ok"] is True, l2["errors"]
    assert l2["level"] == "L2"

    inner = outer.decrypt(recipient)
    assert inner.program() == "# Secret\n"

    l3 = verify_capsule(
        inner,
        allowlist=[signer.public_key_hex],
        outer_envelope=outer.envelope(),
    )
    assert l3["ok"] is True, l3["errors"]
    assert l3["level"] == "L3"


def test_recipient_as_bare_hex_string_and_hex_decrypt():
    signer = generate_ed25519()
    recipient = generate_x25519()

    builder = CapsuleBuilder(originator=signer)
    builder.set_program("# Secret\n")
    builder.append_event({"actor": "human:me", "action": "wrote_secret"})
    data = builder.seal(signers=signer, recipients=[recipient.public_key_hex])

    outer = CapsuleReader.from_bytes(data)
    inner = outer.decrypt(
        recipient_public_key=recipient.public_key_hex,
        recipient_private_key=recipient.private_key_hex,
    )
    assert inner.program() == "# Secret\n"


def test_helpful_errors_on_missing_signer_material():
    keys = generate_ed25519()
    builder = CapsuleBuilder(originator=keys)
    builder.set_program("# X\n")
    with pytest.raises(ValueError, match="at least one signer"):
        builder.seal(signers=[])
    with pytest.raises(ValueError, match="public_key and private_key"):
        builder.seal(signers=[{"role": "originator"}])

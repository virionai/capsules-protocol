import pytest

from capsule.canonical import jcs
from capsule.crypto import generate_ed25519
from capsule.envelope import (
    build_envelope,
    envelope_canonical_payload,
    envelope_signing_input,
    sign_envelope,
    verify_envelope_signatures,
)


def _make_plain_envelope():
    return build_envelope(
        capsule_id="a" * 64,
        first_event_hash="b" * 64,
        entry_hash="c" * 64,
        manifest_hash="d" * 64,
        content_index_hash="e" * 64,
        encrypted_blob_hash=None,
        cipher="none",
        signed_at="2026-05-07T12:00:00Z",
    )


def test_build_envelope_default_cipher_none():
    env = _make_plain_envelope()
    assert env["version"] == "0.6"
    assert env["cipher"] == "none"
    assert env["encrypted_blob_hash"] is None
    assert env["signers"] == []


def test_build_envelope_plain_with_blob_hash_rejected():
    with pytest.raises(ValueError):
        build_envelope(
            capsule_id="a" * 64,
            first_event_hash="b" * 64,
            entry_hash="c" * 64,
            manifest_hash="d" * 64,
            content_index_hash="e" * 64,
            encrypted_blob_hash="f" * 64,
            cipher="none",
            signed_at="2026-05-07T12:00:00Z",
        )


def test_canonical_payload_excludes_signers():
    env = _make_plain_envelope()
    rest = {k: v for k, v in env.items() if k != "signers"}
    assert envelope_canonical_payload(env) == jcs(rest)


def test_signing_input_is_domain_sep_then_canonical():
    env = _make_plain_envelope()
    out = envelope_signing_input(env, "originator")
    expected = b"capsule-provenance-v0.6:originator\x00" + envelope_canonical_payload(env)
    assert out == expected


def test_signing_input_rejects_empty_role():
    env = _make_plain_envelope()
    with pytest.raises(ValueError):
        envelope_signing_input(env, "")


def test_sign_and_verify_roundtrip():
    env = _make_plain_envelope()
    kp = generate_ed25519()
    sign_envelope(
        env,
        [
            {
                "role": "originator",
                "public_key": kp.public_key,
                "private_key": kp.private_key,
            }
        ],
    )
    assert len(env["signers"]) == 1
    res = verify_envelope_signatures(env)
    assert res["ok"] is True
    assert res["signers"][0]["role"] == "originator"
    assert res["signers"][0]["valid"] is True


def test_verify_detects_tampered_signature():
    env = _make_plain_envelope()
    kp = generate_ed25519()
    sign_envelope(
        env,
        [
            {
                "role": "originator",
                "public_key": kp.public_key,
                "private_key": kp.private_key,
            }
        ],
    )
    sig_hex = env["signers"][0]["signature"]
    bad_hex = ("0" if sig_hex[0] != "0" else "1") + sig_hex[1:]
    env["signers"][0]["signature"] = bad_hex
    res = verify_envelope_signatures(env)
    assert res["ok"] is False
    assert res["signers"][0]["valid"] is False


def test_verify_detects_wrong_role_replay():
    env = _make_plain_envelope()
    kp = generate_ed25519()
    sign_envelope(
        env,
        [
            {
                "role": "originator",
                "public_key": kp.public_key,
                "private_key": kp.private_key,
            }
        ],
    )
    # Re-label the role; domain-sep mismatch should fail verification.
    env["signers"][0]["role"] = "notary"
    res = verify_envelope_signatures(env)
    assert res["ok"] is False


def test_sign_envelope_already_signed_rejects():
    env = _make_plain_envelope()
    kp = generate_ed25519()
    sign_envelope(
        env,
        [
            {
                "role": "originator",
                "public_key": kp.public_key,
                "private_key": kp.private_key,
            }
        ],
    )
    with pytest.raises(ValueError):
        sign_envelope(
            env,
            [
                {
                    "role": "creator",
                    "public_key": kp.public_key,
                    "private_key": kp.private_key,
                }
            ],
        )


def test_verify_rejects_unknown_version():
    env = _make_plain_envelope()
    kp = generate_ed25519()
    sign_envelope(
        env,
        [
            {
                "role": "originator",
                "public_key": kp.public_key,
                "private_key": kp.private_key,
            }
        ],
    )
    env["version"] = "0.7"
    res = verify_envelope_signatures(env)
    assert res["ok"] is False
    assert "unsupported envelope version" in res.get("note", "")


def test_verify_rejects_no_signers():
    env = _make_plain_envelope()
    res = verify_envelope_signatures(env)
    assert res["ok"] is False
    assert "no signers" in res.get("note", "")


def _make_encrypted_envelope():
    return build_envelope(
        capsule_id="a" * 64,
        first_event_hash="b" * 64,
        entry_hash="c" * 64,
        manifest_hash="d" * 64,
        content_index_hash="e" * 64,
        encrypted_blob_hash="f" * 64,
        cipher="ChaCha20-Poly1305",
        signed_at="2026-05-07T12:00:00Z",
    )


def test_build_envelope_accepts_chacha_cipher():
    env = _make_encrypted_envelope()
    assert env["cipher"] == "ChaCha20-Poly1305"
    assert env["encrypted_blob_hash"] == "f" * 64


def test_build_envelope_chacha_requires_blob_hash():
    with pytest.raises(ValueError, match="encrypted_blob_hash"):
        build_envelope(
            capsule_id="a" * 64,
            first_event_hash="b" * 64,
            entry_hash="c" * 64,
            manifest_hash="d" * 64,
            content_index_hash="e" * 64,
            encrypted_blob_hash=None,
            cipher="ChaCha20-Poly1305",
            signed_at="2026-05-07T12:00:00Z",
        )


def test_build_envelope_unknown_cipher_rejected():
    with pytest.raises(ValueError, match="unsupported cipher"):
        build_envelope(
            capsule_id="a" * 64,
            first_event_hash="b" * 64,
            entry_hash="c" * 64,
            manifest_hash="d" * 64,
            content_index_hash="e" * 64,
            encrypted_blob_hash=None,
            cipher="aes-gcm",
            signed_at="2026-05-07T12:00:00Z",
        )


def test_sign_and_verify_encrypted_envelope():
    env = _make_encrypted_envelope()
    kp = generate_ed25519()
    sign_envelope(
        env,
        [
            {
                "role": "originator",
                "public_key": kp.public_key,
                "private_key": kp.private_key,
            }
        ],
    )
    res = verify_envelope_signatures(env)
    assert res["ok"] is True
    assert res["signers"][0]["valid"] is True

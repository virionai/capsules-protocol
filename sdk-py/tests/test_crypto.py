import pytest
from cryptography.exceptions import InvalidTag

from capsule.crypto import (
    Ed25519KeyPair,
    X25519KeyPair,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
    ed25519_sign,
    ed25519_verify,
    generate_ed25519,
    generate_x25519,
    hkdf_sha256,
    random_key32,
    random_nonce12,
    x25519_dh,
)


def test_generate_returns_32_byte_keys():
    kp = generate_ed25519()
    assert isinstance(kp, Ed25519KeyPair)
    assert len(kp.public_key) == 32
    assert len(kp.private_key) == 32
    assert isinstance(kp.public_key_hex, str) and len(kp.public_key_hex) == 64
    assert isinstance(kp.private_key_hex, str) and len(kp.private_key_hex) == 64


def test_sign_returns_64_byte_signature():
    kp = generate_ed25519()
    sig = ed25519_sign(kp.private_key, b"hello")
    assert isinstance(sig, bytes)
    assert len(sig) == 64


def test_sign_then_verify():
    kp = generate_ed25519()
    msg = b"capsule-provenance-v0.6:originator\x00<canonical>"
    sig = ed25519_sign(kp.private_key, msg)
    assert ed25519_verify(kp.public_key, msg, sig) is True


def test_verify_rejects_tampered_message():
    kp = generate_ed25519()
    sig = ed25519_sign(kp.private_key, b"hello")
    assert ed25519_verify(kp.public_key, b"hellp", sig) is False


def test_verify_rejects_tampered_signature():
    kp = generate_ed25519()
    sig = ed25519_sign(kp.private_key, b"hello")
    bad = bytearray(sig)
    bad[0] ^= 0x01
    assert ed25519_verify(kp.public_key, b"hello", bytes(bad)) is False


def test_verify_with_wrong_pubkey_fails_cleanly():
    a = generate_ed25519()
    b = generate_ed25519()
    sig = ed25519_sign(a.private_key, b"hello")
    assert ed25519_verify(b.public_key, b"hello", sig) is False


def test_sign_rejects_wrong_key_length():
    with pytest.raises(ValueError):
        ed25519_sign(b"\x00" * 31, b"x")


def test_verify_returns_false_on_garbage_inputs():
    # Don't raise; mirror the JS verify which catches and returns False.
    assert ed25519_verify(b"\x00" * 32, b"x", b"\x00" * 64) is False


def test_generate_x25519_returns_32_byte_keys():
    kp = generate_x25519()
    assert isinstance(kp, X25519KeyPair)
    assert len(kp.public_key) == 32
    assert len(kp.private_key) == 32
    assert isinstance(kp.public_key_hex, str) and len(kp.public_key_hex) == 64
    assert isinstance(kp.private_key_hex, str) and len(kp.private_key_hex) == 64


def test_x25519_dh_is_symmetric():
    a = generate_x25519()
    b = generate_x25519()
    sa = x25519_dh(a.private_key, b.public_key)
    sb = x25519_dh(b.private_key, a.public_key)
    assert sa == sb
    assert len(sa) == 32


def test_x25519_dh_rejects_wrong_lengths():
    a = generate_x25519()
    with pytest.raises(ValueError):
        x25519_dh(b"\x00" * 31, a.public_key)
    with pytest.raises(ValueError):
        x25519_dh(a.private_key, b"\x00" * 31)


def test_hkdf_sha256_known_vector_length():
    out = hkdf_sha256(b"shared" * 8, b"salt", b"info", 32)
    assert len(out) == 32
    assert isinstance(out, bytes)


def test_hkdf_sha256_deterministic():
    a = hkdf_sha256(b"ikm", b"salt", b"info", 32)
    b = hkdf_sha256(b"ikm", b"salt", b"info", 32)
    assert a == b


def test_hkdf_sha256_diverges_on_different_salt():
    a = hkdf_sha256(b"ikm", b"salt-1", b"info", 32)
    b = hkdf_sha256(b"ikm", b"salt-2", b"info", 32)
    assert a != b


def test_chacha20_poly1305_roundtrip():
    key = b"k" * 32
    nonce = b"n" * 12
    aad = b"aad-bytes"
    plaintext = b"hello world"
    ct = chacha20_poly1305_encrypt(key, nonce, aad, plaintext)
    assert ct != plaintext
    assert len(ct) == len(plaintext) + 16  # tag
    pt = chacha20_poly1305_decrypt(key, nonce, aad, ct)
    assert pt == plaintext


def test_chacha20_poly1305_empty_aad_roundtrip():
    key = b"k" * 32
    nonce = b"n" * 12
    plaintext = b"hello"
    ct = chacha20_poly1305_encrypt(key, nonce, b"", plaintext)
    pt = chacha20_poly1305_decrypt(key, nonce, b"", ct)
    assert pt == plaintext


def test_chacha20_poly1305_tampered_ciphertext_raises():
    key = b"k" * 32
    nonce = b"n" * 12
    aad = b"aad"
    ct = chacha20_poly1305_encrypt(key, nonce, aad, b"hello world")
    bad = bytearray(ct)
    bad[0] ^= 0x01
    with pytest.raises(InvalidTag):
        chacha20_poly1305_decrypt(key, nonce, aad, bytes(bad))


def test_chacha20_poly1305_aad_mismatch_raises():
    key = b"k" * 32
    nonce = b"n" * 12
    ct = chacha20_poly1305_encrypt(key, nonce, b"aad-1", b"hello")
    with pytest.raises(InvalidTag):
        chacha20_poly1305_decrypt(key, nonce, b"aad-2", ct)


def test_chacha20_poly1305_rejects_wrong_key_length():
    with pytest.raises(ValueError):
        chacha20_poly1305_encrypt(b"k" * 31, b"n" * 12, b"", b"x")
    with pytest.raises(ValueError):
        chacha20_poly1305_decrypt(b"k" * 31, b"n" * 12, b"", b"x" * 17)


def test_chacha20_poly1305_rejects_wrong_nonce_length():
    with pytest.raises(ValueError):
        chacha20_poly1305_encrypt(b"k" * 32, b"n" * 11, b"", b"x")
    with pytest.raises(ValueError):
        chacha20_poly1305_decrypt(b"k" * 32, b"n" * 11, b"", b"x" * 17)


def test_random_key32_and_random_nonce12():
    a = random_key32()
    b = random_key32()
    assert len(a) == 32 and len(b) == 32
    assert a != b
    n = random_nonce12()
    assert len(n) == 12

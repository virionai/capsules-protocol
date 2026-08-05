"""Cross-curve key confusion at the API boundary (finding A04).

Ed25519 and X25519 keypair objects are structurally identical (public_key,
private_key, and hex twins), and X25519 clamps and accepts any 32-byte
u-coordinate, so ECDH against an Ed25519 public key "succeeds" and
produces a wrapped key the holder of the Ed25519 private key can never
unwrap. Nothing errors until a decryption attempt — potentially years
after sealing. Seal-time round-trip verification cannot catch it and the
key types are indistinguishable from bytes, so the only fix is typed key
material: keypair objects carry a ``curve`` tag at generation, and the
normalizers reject a mismatched (or, for recipients, missing) tag on the
object path. Raw hex and raw bytes stay untagged and accepted — the
caller who extracts bytes is asserting the curve themselves.

Mirrors sdk-js/test/key-curve.test.js.
"""

from __future__ import annotations

import pytest

from capsule import CapsuleBuilder, CapsuleReader
from capsule.crypto import generate_ed25519, generate_x25519
from capsule.keys import to_recipient, to_signer


def _draft_builder(keys):
    builder = CapsuleBuilder(originator=keys)
    builder.set_program("# Secret\n")
    builder.append_event({"actor": "human:me", "action": "wrote_secret"})
    return builder


def test_generated_keypairs_carry_a_curve_tag():
    assert generate_ed25519().curve == "ed25519"
    assert generate_x25519().curve == "x25519"


def test_ed25519_keypair_rejected_as_encryption_recipient():
    ed = generate_ed25519()
    # The exact CHANGELOG-advertised path: keypair objects work as-is as
    # recipients. Sealing to an Ed25519 key would encrypt to a key that
    # can never decrypt — unrecoverable content, no error until then.
    with pytest.raises(ValueError, match="ed25519"):
        to_recipient(ed)
    with pytest.raises(ValueError, match="ed25519"):
        _draft_builder(ed).seal(signers=ed, recipients=[ed])


def test_x25519_keypair_rejected_as_signer():
    ed = generate_ed25519()
    x = generate_x25519()
    with pytest.raises(ValueError, match="x25519"):
        to_signer(x)
    with pytest.raises(ValueError, match="x25519"):
        _draft_builder(ed).seal(signers=x)


def test_untagged_keypair_shaped_object_rejected_as_recipient():
    # A keypair object with the tag stripped (e.g. round-tripped through
    # JSON serialized before tagging existed) is indistinguishable from
    # the Ed25519 hazard, so the branded path is the ONLY object path:
    # full keypair objects must carry curve="x25519".
    x = generate_x25519()
    with pytest.raises(ValueError, match="curve"):
        to_recipient({"public_key": x.public_key, "private_key": x.private_key})
    with pytest.raises(ValueError, match="curve"):
        to_recipient({"public_key_hex": x.public_key_hex, "private_key_hex": x.private_key_hex})


def test_public_key_only_and_raw_forms_stay_accepted():
    x = generate_x25519()
    # {"public_key": ...} without private material is equivalent to
    # handing over raw bytes: the caller extracted the key, asserting
    # the curve.
    assert to_recipient({"public_key": x.public_key}) == x.public_key
    assert to_recipient(x.public_key_hex) == x.public_key
    assert to_recipient(x.public_key) == x.public_key


def test_untagged_signer_dicts_stay_accepted():
    # The documented dict form for signers. A cross-curve mistake here
    # fails loudly at first verification (the stored public key does not
    # match the signature), so the untagged form is not a silent hazard.
    ed = generate_ed25519()
    signer = to_signer(
        {"role": "approver", "public_key": ed.public_key_hex, "private_key": ed.private_key_hex}
    )
    assert signer["role"] == "approver"


def test_tagged_x25519_keypair_still_seals_and_decrypts():
    ed = generate_ed25519()
    x = generate_x25519()
    data = _draft_builder(ed).seal(signers=ed, recipients=[x])
    outer = CapsuleReader.from_bytes(data)
    inner = outer.decrypt(x)
    assert inner.program() == "# Secret\n"

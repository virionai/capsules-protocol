import io
import json
import zipfile

from capsule.builder import CapsuleBuilder
from capsule.crypto import generate_ed25519, generate_x25519
from capsule.reader import CapsuleReader
from capsule.verifier import verify_capsule


def _clean():
    kp = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": "Acme"},
        participants=[],
    )
    builder.set_program("# Loan\n")
    builder.append_event(
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "approved",
            "target": "program.md",
            "timestamp": "2026-05-07T12:00:00Z",
            "payload": {},
        }
    )
    return builder.seal(
        signers=[
            {"role": "originator", "public_key": kp.public_key, "private_key": kp.private_key}
        ],
        signed_at="2026-05-07T12:00:00Z",
    ), kp


def test_clean_capsule_passes_with_allowlist():
    zip_bytes, kp = _clean()
    reader = CapsuleReader.from_bytes(zip_bytes)
    result = verify_capsule(reader, allowlist=[kp.public_key_hex])
    assert result["ok"] is True
    assert result["level"] == "L2"
    assert result["chain"]["ok"] is True
    assert result["content_index"]["ok"] is True
    assert result["envelope"]["ok"] is True
    assert result["trusted_signer_count"] == 1
    [signer] = result["envelope"]["signers"]
    assert signer["role"] == "originator"
    assert signer["valid"] is True
    assert signer["trusted"] is True


def test_clean_capsule_passes_but_untrusted_with_empty_allowlist():
    zip_bytes, _ = _clean()
    reader = CapsuleReader.from_bytes(zip_bytes)
    result = verify_capsule(reader, allowlist=[])
    assert result["ok"] is True
    assert result["trusted_signer_count"] == 0
    assert any("no allowlist" in n for n in result["notes"])


def test_tampered_program_fails_at_content_index():
    zip_bytes, kp = _clean()
    # Flip a byte inside program.md without touching anything else.
    buf = io.BytesIO()
    with (
        zipfile.ZipFile(io.BytesIO(zip_bytes)) as src,
        zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as dst,
    ):
        for zi in src.infolist():
            data = src.read(zi)
            if zi.filename == "program.md":
                data = b"# Loan!\n"
            new_zi = zipfile.ZipInfo(zi.filename, date_time=(1980, 1, 1, 0, 0, 0))
            new_zi.compress_type = zipfile.ZIP_STORED
            dst.writestr(new_zi, data)
    reader = CapsuleReader.from_bytes(buf.getvalue())
    result = verify_capsule(reader, allowlist=[kp.public_key_hex])
    assert result["ok"] is False
    assert result["content_index"]["ok"] is False


def test_tampered_envelope_signature_fails_at_envelope():
    zip_bytes, kp = _clean()
    # Flip the originator signature.
    buf = io.BytesIO()
    with (
        zipfile.ZipFile(io.BytesIO(zip_bytes)) as src,
        zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as dst,
    ):
        for zi in src.infolist():
            data = src.read(zi)
            if zi.filename == "provenance/envelope.json":
                env = json.loads(data.decode("utf-8"))
                sig = env["signers"][0]["signature"]
                env["signers"][0]["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
                data = json.dumps(env, indent=2).encode("utf-8")
            new_zi = zipfile.ZipInfo(zi.filename, date_time=(1980, 1, 1, 0, 0, 0))
            new_zi.compress_type = zipfile.ZIP_STORED
            dst.writestr(new_zi, data)
    reader = CapsuleReader.from_bytes(buf.getvalue())
    result = verify_capsule(reader, allowlist=[kp.public_key_hex])
    assert result["ok"] is False
    assert result["envelope"]["ok"] is False
    assert all(not s["valid"] for s in result["envelope"]["signers"])


def test_capsule_id_mismatch_recorded_as_error():
    zip_bytes, kp = _clean()
    buf = io.BytesIO()
    with (
        zipfile.ZipFile(io.BytesIO(zip_bytes)) as src,
        zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as dst,
    ):
        for zi in src.infolist():
            data = src.read(zi)
            if zi.filename == "manifest.json":
                m = json.loads(data.decode("utf-8"))
                m["id"] = "f" * 64
                data = json.dumps(m).encode("utf-8")
            new_zi = zipfile.ZipInfo(zi.filename, date_time=(1980, 1, 1, 0, 0, 0))
            new_zi.compress_type = zipfile.ZIP_STORED
            dst.writestr(new_zi, data)
    reader = CapsuleReader.from_bytes(buf.getvalue())
    result = verify_capsule(reader, allowlist=[kp.public_key_hex])
    assert result["ok"] is False
    assert any("manifest.id mismatch" in e for e in result["errors"])


def test_smuggled_content_enc_in_plain_capsule_fails():
    # A signed plain capsule (cipher="none") must not be able to carry an
    # unaccounted-for content.enc blob past verification. content.enc is only
    # excluded from the content index for capsules that declare a cipher.
    zip_bytes, kp = _clean()
    buf = io.BytesIO()
    with (
        zipfile.ZipFile(io.BytesIO(zip_bytes)) as src,
        zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as dst,
    ):
        for zi in src.infolist():
            data = src.read(zi)
            new_zi = zipfile.ZipInfo(zi.filename, date_time=(1980, 1, 1, 0, 0, 0))
            new_zi.compress_type = zipfile.ZIP_STORED
            dst.writestr(new_zi, data)
        # Inject an unindexed blob, leaving the signed envelope/manifest intact.
        smuggle = zipfile.ZipInfo("content.enc", date_time=(1980, 1, 1, 0, 0, 0))
        smuggle.compress_type = zipfile.ZIP_STORED
        dst.writestr(smuggle, b"smuggled payload, covered by no hash")
    reader = CapsuleReader.from_bytes(buf.getvalue())
    result = verify_capsule(reader, allowlist=[kp.public_key_hex])
    assert result["ok"] is False
    assert result["content_index"]["ok"] is False
    assert any("content.enc" in e for e in result["content_index"]["errors"])


def _build_enc():
    kp = generate_ed25519()
    rec = generate_x25519()
    b = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": "Acme"},
        participants=[],
    )
    b.set_program("# Loan\n")
    b.append_event(
        {
            "actor": "human:alice",
            "kind": "decision",
            "action": "approved",
            "target": "program.md",
            "timestamp": "2026-05-07T12:00:00Z",
            "payload": {},
        }
    )
    zip_bytes = b.seal(
        signers=[
            {"role": "originator", "public_key": kp.public_key, "private_key": kp.private_key}
        ],
        signed_at="2026-05-07T12:00:00Z",
        recipients=[rec.public_key],
    )
    return zip_bytes, kp, rec


def test_encrypted_outer_passes_l2_with_allowlist():
    zip_bytes, kp, _ = _build_enc()
    reader = CapsuleReader.from_bytes(zip_bytes)
    result = verify_capsule(reader, allowlist=[kp.public_key_hex])
    assert result["ok"] is True
    assert result["level"] == "L2"
    assert result["envelope"]["ok"] is True
    assert result["chain"]["ok"] is True  # deferred-but-OK note
    assert "deferred" in (result["chain"].get("note") or "")


def test_encrypted_outer_detects_blob_tamper():
    zip_bytes, kp, _ = _build_enc()
    # Flip a byte inside content.enc.
    buf = io.BytesIO()
    with (
        zipfile.ZipFile(io.BytesIO(zip_bytes)) as src,
        zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as dst,
    ):
        for zi in src.infolist():
            data = src.read(zi)
            if zi.filename == "content.enc":
                bad = bytearray(data)
                bad[0] ^= 0x01
                data = bytes(bad)
            new_zi = zipfile.ZipInfo(zi.filename, date_time=(1980, 1, 1, 0, 0, 0))
            new_zi.compress_type = zipfile.ZIP_STORED
            dst.writestr(new_zi, data)
    reader = CapsuleReader.from_bytes(buf.getvalue())
    result = verify_capsule(reader, allowlist=[kp.public_key_hex])
    assert result["ok"] is False
    assert any("encrypted_blob_hash mismatch" in e for e in result["errors"])


def test_l3_inner_verifies_with_outer_envelope():
    zip_bytes, kp, rec = _build_enc()
    outer = CapsuleReader.from_bytes(zip_bytes)
    outer_envelope = outer.envelope()
    inner = outer.decrypt(
        recipient_public_key=rec.public_key,
        recipient_private_key=rec.private_key,
    )
    result = verify_capsule(inner, allowlist=[kp.public_key_hex], outer_envelope=outer_envelope)
    assert result["ok"] is True
    assert result["level"] == "L3"


def test_l3_detects_cross_envelope_mismatch():
    # Build two unrelated encrypted capsules; pass one's outer envelope while
    # verifying the other's inner. capsule_id/first_event_hash mismatch should fail.
    a_zip, a_kp, a_rec = _build_enc()
    b_zip, _, _ = _build_enc()
    b_outer = CapsuleReader.from_bytes(b_zip)
    a_outer = CapsuleReader.from_bytes(a_zip)
    a_inner = a_outer.decrypt(
        recipient_public_key=a_rec.public_key,
        recipient_private_key=a_rec.private_key,
    )
    result = verify_capsule(
        a_inner,
        allowlist=[a_kp.public_key_hex],
        outer_envelope=b_outer.envelope(),
    )
    assert result["ok"] is False
    assert any("L3" in e for e in result["errors"])

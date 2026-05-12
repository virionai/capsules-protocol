"""Cross-implementation parity against the JS reference's tamper-detection corpus.

The JS SDK's `examples/tamper-detection/build.mjs` produces six fixtures.
Four are plain (this SDK's v0.1 scope); two are encrypted (v0.2 scope).
"""

from __future__ import annotations

import json
import pathlib
import subprocess

from capsule import CapsuleBuilder, CapsuleReader, generate_ed25519, generate_x25519, verify_capsule

# --- Plain fixtures: Python verifies what JS produced ---


def test_clean_capsule_passes(tamper_fixtures: pathlib.Path, js_originator_pubkey: str):
    data = (tamper_fixtures / "clean.capsule").read_bytes()
    reader = CapsuleReader.from_bytes(data)
    result = verify_capsule(reader, allowlist=[js_originator_pubkey])
    assert result["ok"] is True
    assert result["trusted_signer_count"] == 1


def test_tampered_payload_fails_at_content_index(
    tamper_fixtures: pathlib.Path, js_originator_pubkey: str
):
    data = (tamper_fixtures / "tampered-payload.capsule").read_bytes()
    reader = CapsuleReader.from_bytes(data)
    result = verify_capsule(reader, allowlist=[js_originator_pubkey])
    assert result["ok"] is False
    assert result["content_index"]["ok"] is False


def test_tampered_chain_fails(tamper_fixtures: pathlib.Path, js_originator_pubkey: str):
    data = (tamper_fixtures / "tampered-chain.capsule").read_bytes()
    reader = CapsuleReader.from_bytes(data)
    result = verify_capsule(reader, allowlist=[js_originator_pubkey])
    assert result["ok"] is False
    # Tampering an event payload changes both the chain hash and the
    # content_index hash for chain/events.jsonl. Either being unhappy is
    # the spec-correct outcome.
    assert (not result["chain"]["ok"]) or (not result["content_index"]["ok"])


def test_tampered_envelope_fails_at_envelope(
    tamper_fixtures: pathlib.Path, js_originator_pubkey: str
):
    data = (tamper_fixtures / "tampered-envelope.capsule").read_bytes()
    reader = CapsuleReader.from_bytes(data)
    result = verify_capsule(reader, allowlist=[js_originator_pubkey])
    assert result["ok"] is False
    assert result["envelope"]["ok"] is False


# --- Encrypted fixtures: v0.2 verify + decrypt ---


def test_clean_encrypted_capsule_l2_passes(
    tamper_fixtures: pathlib.Path, js_originator_pubkey: str
):
    """The JS-built encrypted clean capsule passes Python's L2 verifier."""
    data = (tamper_fixtures / "clean-encrypted.capsule").read_bytes()
    reader = CapsuleReader.from_bytes(data)
    assert reader.is_encrypted() is True
    result = verify_capsule(reader, allowlist=[js_originator_pubkey])
    assert result["ok"] is True
    assert result["level"] == "L2"
    assert result["trusted_signer_count"] == 1


def test_tampered_blob_capsule_fails_at_encrypted_blob_hash(
    tamper_fixtures: pathlib.Path, js_originator_pubkey: str
):
    """JS-built capsule with tampered content.enc fails Python's L2."""
    data = (tamper_fixtures / "tampered-blob.capsule").read_bytes()
    reader = CapsuleReader.from_bytes(data)
    assert reader.is_encrypted() is True
    result = verify_capsule(reader, allowlist=[js_originator_pubkey])
    assert result["ok"] is False
    assert any("encrypted_blob_hash" in e for e in result["errors"])


def test_decrypt_clean_encrypted_with_js_recipient_key(
    tamper_fixtures: pathlib.Path, js_originator_pubkey: str
):
    """Python decrypts a JS-built encrypted capsule using the JS recipient key from keys.json,
    then runs L3 verification against the outer envelope."""
    keys = json.loads((tamper_fixtures / "keys.json").read_text())
    rec = keys["recipient"]
    rec_pub = bytes.fromhex(rec["publicKey"])
    rec_priv = bytes.fromhex(rec["privateKey"])

    data = (tamper_fixtures / "clean-encrypted.capsule").read_bytes()
    outer = CapsuleReader.from_bytes(data)
    inner = outer.decrypt(recipient_public_key=rec_pub, recipient_private_key=rec_priv)

    assert inner.is_encrypted() is False
    assert "# " in inner.program()  # has at least one heading; content varies

    result = verify_capsule(
        inner,
        allowlist=[js_originator_pubkey],
        outer_envelope=outer.envelope(),
    )
    assert result["ok"] is True
    assert result["level"] == "L3"


def test_python_built_encrypted_capsule_verifies_and_decrypts_under_js_sdk(
    tmp_path: pathlib.Path,
):
    """Python builds an encrypted capsule with two recipients; JS SDK verifies + decrypts it."""
    sk = generate_ed25519()
    r1 = generate_x25519()
    r2 = generate_x25519()
    builder = CapsuleBuilder(
        originator={"public_key": sk.public_key_hex, "label": "PythonBuilder"},
        participants=[{"actor_id": "human:py", "role": "originator", "label": "Py"}],
    )
    builder.set_program("# Python-built encrypted\n")
    builder.append_event(
        {
            "actor": "human:py",
            "kind": "decision",
            "action": "approved",
            "target": "program.md",
            "timestamp": "2026-05-08T12:00:00Z",
            "payload": {"amount": 9999},
        }
    )
    zip_bytes = builder.seal(
        signers=[
            {
                "role": "originator",
                "public_key": sk.public_key,
                "private_key": sk.private_key,
            }
        ],
        signed_at="2026-05-08T12:00:00Z",
        recipients=[r1.public_key, r2.public_key],
    )
    capsule_path = tmp_path / "py-enc.capsule"
    capsule_path.write_bytes(zip_bytes)

    sdk_dir = pathlib.Path(__file__).resolve().parents[2] / "sdk"
    if not (sdk_dir / "node_modules").exists():
        subprocess.run(["npm", "install", "--no-audit", "--no-fund"], cwd=sdk_dir, check=True)

    # Drive the JS SDK's verifyCapsule (L2) + decrypt + verifyCapsule (L3).
    script = f"""
import {{ CapsuleReader, verifyCapsule, hexToBytes }} from "./src/index.js";
import {{ readFileSync }} from "node:fs";
const bytes = readFileSync({json.dumps(str(capsule_path))});
const outer = await CapsuleReader.fromBytes(bytes);
const allowlist = [{json.dumps(sk.public_key_hex)}];
const l2 = await verifyCapsule(outer, {{ allowlist }});
const inner = await outer.decrypt({{
  recipientPublicKey: hexToBytes({json.dumps(r2.public_key_hex)}),
  recipientPrivateKey: hexToBytes({json.dumps(r2.private_key_hex)}),
}});
const l3 = await verifyCapsule(inner, {{
  allowlist,
  outerEnvelope: outer.envelope(),
}});
process.stdout.write(JSON.stringify({{
  l2_ok: l2.ok, l2_level: l2.level, l2_trustedSignerCount: l2.trustedSignerCount,
  l2_errors: l2.errors,
  l3_ok: l3.ok, l3_level: l3.level, l3_trustedSignerCount: l3.trustedSignerCount,
  l3_errors: l3.errors,
}}));
"""
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        cwd=sdk_dir,
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"node failed: {proc.stderr}"
    result = json.loads(proc.stdout)
    assert result["l2_ok"] is True and result["l2_level"] == "L2"
    assert result["l2_trustedSignerCount"] == 1
    assert result["l3_ok"] is True and result["l3_level"] == "L3"
    assert result["l3_trustedSignerCount"] == 1
    assert result["l2_errors"] == []
    assert result["l3_errors"] == []


# --- Reverse: Python builds, JS verifies ---


def test_python_built_capsule_verifies_under_js_sdk(tmp_path: pathlib.Path):
    """Build a plain capsule with Python; have the JS SDK verify it."""
    kp = generate_ed25519()
    builder = CapsuleBuilder(
        originator={"public_key": kp.public_key_hex, "label": "PythonBuilder"},
        participants=[{"actor_id": "human:py", "role": "originator", "label": "Py"}],
    )
    builder.set_program("# Python-built capsule\n")
    builder.append_event(
        {
            "actor": "human:py",
            "kind": "decision",
            "action": "approved",
            "target": "program.md",
            "timestamp": "2026-05-08T12:00:00Z",
            "payload": {"amount": 1234},
        }
    )
    zip_bytes = builder.seal(
        signers=[
            {"role": "originator", "public_key": kp.public_key, "private_key": kp.private_key}
        ],
        signed_at="2026-05-08T12:00:00Z",
    )
    capsule_path = tmp_path / "py.capsule"
    capsule_path.write_bytes(zip_bytes)

    sdk_dir = pathlib.Path(__file__).resolve().parents[2] / "sdk"
    if not (sdk_dir / "node_modules").exists():
        subprocess.run(["npm", "install", "--no-audit", "--no-fund"], cwd=sdk_dir, check=True)

    # Drive the JS SDK's verifier from a tiny inline script.
    script = f"""
import {{ CapsuleReader, verifyCapsule }} from "./src/index.js";
import {{ readFileSync }} from "node:fs";
const bytes = readFileSync({json.dumps(str(capsule_path))});
const reader = await CapsuleReader.fromBytes(bytes);
const result = await verifyCapsule(reader, {{ allowlist: [{json.dumps(kp.public_key_hex)}] }});
process.stdout.write(JSON.stringify({{
  ok: result.ok,
  level: result.level,
  trustedSignerCount: result.trustedSignerCount,
  errors: result.errors,
}}));
"""
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        cwd=sdk_dir,
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"node failed: {proc.stderr}"
    result = json.loads(proc.stdout)
    assert result["ok"] is True
    assert result["trustedSignerCount"] == 1
    assert result["level"] == "L2"
    assert result["errors"] == []

"""CapsuleBuilder — plain and encrypted capsule build paths. Mirrors sdk/src/builder.js."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC

from .canonical import bytes_to_hex, hex_to_bytes, jcs, sha256_hex
from .chain import build_chain_events, events_to_jsonl, first_and_entry_hash
from .crypto import (
    chacha20_poly1305_encrypt,
    generate_x25519,
    hkdf_sha256,
    random_key32,
    random_nonce12,
    x25519_dh,
)
from .envelope import build_envelope, sign_envelope
from .manifest import (
    build_content_index,
    build_manifest,
    compute_capsule_id,
    manifest_bytes,
    manifest_hash,
)
from .pith import compress_event_payload
from .zip_io import pack_zip

_SKILL_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


@dataclass
class _SkillEntry:
    json: dict | None
    markdown: str | None
    signed: bool


class CapsuleBuilder:
    def __init__(
        self,
        *,
        originator: dict,
        participants: list[dict] | None = None,
        created_at: str | None = None,
        pith: bool = True,
    ) -> None:
        if not isinstance(originator, dict) or not isinstance(originator.get("public_key"), str):
            raise ValueError("originator.public_key (hex) required")
        self.originator = {
            "public_key": originator["public_key"],
            "label": originator.get("label", ""),
        }
        self.participants = participants or []
        self.created_at = created_at or _now_no_fractional()
        self.program_md: str | None = None
        self.agents_md: str | None = None
        self.skills: dict[str, _SkillEntry] = {}
        self.payload: dict[str, bytes] = {}
        self.bare_events: list[dict] = []
        self.pith = bool(pith)

    def set_program(self, md: str) -> CapsuleBuilder:
        self.program_md = md
        return self

    def set_agents(self, md: str) -> CapsuleBuilder:
        self.agents_md = md
        return self

    def add_skill(
        self,
        id: str,
        *,
        json: dict | None = None,
        markdown: str | None = None,
        signed: bool = False,
    ) -> CapsuleBuilder:
        if not isinstance(id, str) or not _SKILL_ID_RE.match(id):
            raise ValueError(f"invalid skill id: {id}")
        if id == "decryption":
            raise ValueError("'decryption' is reserved for encryption metadata; not a skill")
        self.skills[id] = _SkillEntry(json=json, markdown=markdown, signed=bool(signed))
        return self

    def add_payload(self, path: str, data: bytes) -> CapsuleBuilder:
        if not isinstance(path, str) or not path.startswith("payload/"):
            raise ValueError(f"payload path must start with 'payload/': {path}")
        self.payload[path] = bytes(data)
        return self

    def append_event(self, event: dict, *, pith: bool | None = None) -> CapsuleBuilder:
        for required in ("actor", "kind", "action", "target"):
            if required not in event:
                raise ValueError(f"event requires {required}")
        apply_pith = self.pith if pith is None else (self.pith and pith)
        raw_payload = event.get("payload", {})
        payload = compress_event_payload(raw_payload) if apply_pith else raw_payload
        bare = {
            "actor": event["actor"],
            "kind": event["kind"],
            "action": event["action"],
            "target": event["target"],
            "timestamp": event.get("timestamp", self.created_at),
            "payload": payload,
        }
        if "untrusted_payload_fields" in event:
            bare["untrusted_payload_fields"] = event["untrusted_payload_fields"]
        self.bare_events.append(bare)
        return self

    def seal(
        self,
        *,
        signers: list[dict],
        signed_at: str,
        recipients: list[bytes] | None = None,
    ) -> bytes:
        if not signers:
            raise ValueError("seal requires at least one signer")
        if not signed_at:
            raise ValueError("seal requires signed_at")

        if self.program_md is None:
            self.program_md = "# Program\n"
        if not self.bare_events:
            self.bare_events.append(
                {
                    "actor": "system:host",
                    "kind": "observation",
                    "action": "session_ended",
                    "target": "capsule",
                    "timestamp": signed_at,
                    "payload": {"note": "host emitted backstop event before seal"},
                }
            )

        # Chain
        events = build_chain_events(self.bare_events)
        first_event_hash, entry_hash = first_and_entry_hash(events)
        events_jsonl = events_to_jsonl(events)

        # Inner files
        inner: dict[str, bytes] = {
            "program.md": self.program_md.encode("utf-8"),
            "chain/events.jsonl": events_jsonl,
        }
        if self.agents_md is not None:
            inner["agents.md"] = self.agents_md.encode("utf-8")
        skill_trust: dict[str, str] = {}
        for sid, entry in self.skills.items():
            if entry.json is not None:
                inner[f"skills/{sid}/skill.json"] = json.dumps(
                    entry.json, indent=2, ensure_ascii=False
                ).encode("utf-8")
            if entry.markdown is not None:
                inner[f"skills/{sid}/SKILL.md"] = entry.markdown.encode("utf-8")
            skill_trust[sid] = "signed" if entry.signed else "unsigned"
        inner.update(self.payload)

        # Manifest
        originator_pub_raw = hex_to_bytes(self.originator["public_key"])
        capsule_id = compute_capsule_id(originator_pub_raw, first_event_hash)

        # ---- Plain path ----
        if not recipients:
            content_index = build_content_index(inner)
            manifest = build_manifest(
                originator=self.originator,
                participants=self.participants,
                content_index=content_index,
                first_event_hash=first_event_hash,
                skill_trust=skill_trust,
                encryption=None,
                created_at=self.created_at,
            )
            manifest["id"] = capsule_id
            mf_hash = manifest_hash(manifest)

            envelope = build_envelope(
                capsule_id=capsule_id,
                first_event_hash=first_event_hash,
                entry_hash=entry_hash,
                manifest_hash=mf_hash,
                content_index_hash=content_index["index_hash"],
                encrypted_blob_hash=None,
                cipher="none",
                signed_at=signed_at,
            )
            sign_envelope(envelope, signers)

            all_files = dict(inner)
            all_files["manifest.json"] = manifest_bytes(manifest)
            all_files["provenance/envelope.json"] = json.dumps(
                envelope, indent=2, ensure_ascii=False
            ).encode("utf-8")
            return pack_zip(all_files)

        # ---- Encrypted path ----

        # 3a) Build inner ZIP
        inner_content_index = build_content_index(inner)
        inner_manifest = build_manifest(
            originator=self.originator,
            participants=self.participants,
            content_index=inner_content_index,
            first_event_hash=first_event_hash,
            skill_trust=skill_trust,
            encryption=None,
            created_at=self.created_at,
        )
        inner_manifest["id"] = capsule_id
        inner_mf_hash = manifest_hash(inner_manifest)

        inner_envelope = build_envelope(
            capsule_id=capsule_id,
            first_event_hash=first_event_hash,
            entry_hash=entry_hash,
            manifest_hash=inner_mf_hash,
            content_index_hash=inner_content_index["index_hash"],
            encrypted_blob_hash=None,
            cipher="none",
            signed_at=signed_at,
        )
        sign_envelope(inner_envelope, signers)

        inner_all_files = dict(inner)
        inner_all_files["manifest.json"] = manifest_bytes(inner_manifest)
        inner_all_files["provenance/envelope.json"] = json.dumps(
            inner_envelope, indent=2, ensure_ascii=False
        ).encode("utf-8")
        inner_zip_bytes = pack_zip(inner_all_files)

        # 3b) Encrypt inner ZIP
        content_key = random_key32()
        content_nonce = random_nonce12()

        aad_obj = {
            "capsule_id": capsule_id,
            "cipher": "ChaCha20-Poly1305",
            "first_event_hash": first_event_hash,
            "originator_public_key": self.originator["public_key"],
            "version": "0.6",
        }
        aad = jcs(aad_obj)
        content_enc = chacha20_poly1305_encrypt(content_key, content_nonce, aad, inner_zip_bytes)
        encrypted_blob_hash = sha256_hex(content_enc)

        # 3c) Build recipient bundles
        _content_nonce_hex, decryption_meta = _build_decryption_metadata(
            content_key, content_nonce, recipients
        )

        # 3d) Outer files
        outer_sidecars: dict[str, bytes] = {
            "skills/decryption/decryption.json": json.dumps(
                decryption_meta, indent=2, ensure_ascii=False
            ).encode("utf-8"),
            "content.enc": content_enc,
        }

        outer_content_index = build_content_index(outer_sidecars)

        outer_manifest = build_manifest(
            originator=self.originator,
            participants=self.participants,
            content_index=outer_content_index,
            first_event_hash=first_event_hash,
            skill_trust={},
            encryption={
                "metadata_path": "skills/decryption/decryption.json",
                "cipher": "ChaCha20-Poly1305",
            },
            created_at=self.created_at,
        )
        outer_manifest["id"] = capsule_id
        outer_mf_hash = manifest_hash(outer_manifest)

        outer_envelope = build_envelope(
            capsule_id=capsule_id,
            first_event_hash=first_event_hash,
            entry_hash=entry_hash,
            manifest_hash=outer_mf_hash,
            content_index_hash=outer_content_index["index_hash"],
            encrypted_blob_hash=encrypted_blob_hash,
            cipher="ChaCha20-Poly1305",
            signed_at=signed_at,
        )
        sign_envelope(outer_envelope, signers)

        outer_all_files = dict(outer_sidecars)
        outer_all_files["manifest.json"] = manifest_bytes(outer_manifest)
        outer_all_files["provenance/envelope.json"] = json.dumps(
            outer_envelope, indent=2, ensure_ascii=False
        ).encode("utf-8")
        return pack_zip(outer_all_files)


def _build_decryption_metadata(
    content_key: bytes,
    content_nonce: bytes,
    recipients: list[bytes],
) -> tuple[str, dict]:
    """Build the decryption.json dict for the given recipients.

    Returns ``(content_nonce_hex, decryption_meta_dict)``.
    """
    key_bundles = []
    for recipient_pub in recipients:
        if len(recipient_pub) != 32:
            raise ValueError("recipient public key must be 32 bytes (X25519 raw)")
        eph = generate_x25519()
        shared = x25519_dh(eph.private_key, recipient_pub)
        wrap_key = hkdf_sha256(
            shared,
            recipient_pub,  # salt = recipient public key
            b"capsule-key-wrap-v0.6",
            32,
        )
        wrap_nonce = random_nonce12()
        wrapped_key = chacha20_poly1305_encrypt(wrap_key, wrap_nonce, b"", content_key)
        key_bundles.append(
            {
                "recipient_public_key": bytes_to_hex(recipient_pub),
                "ephemeral_public_key": eph.public_key_hex,
                "wrap_nonce": bytes_to_hex(wrap_nonce),
                "wrapped_key": bytes_to_hex(wrapped_key),
            }
        )

    decryption_meta = {
        "cipher": "ChaCha20-Poly1305",
        "content_nonce": bytes_to_hex(content_nonce),
        "key_bundles": key_bundles,
    }
    return bytes_to_hex(content_nonce), decryption_meta


def _now_no_fractional() -> str:
    from datetime import datetime

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

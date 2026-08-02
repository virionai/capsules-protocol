"""CapsuleBuilder — plain and encrypted capsule build paths. Mirrors sdk/src/builder.js."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from .canonical import bytes_to_hex, hex_to_bytes, jcs, sha256_hex
from .chain import (
    EVENT_KINDS,
    HOST_ACTOR,
    build_chain_events,
    events_to_jsonl,
    first_and_entry_hash,
    is_valid_event_kind,
    is_valid_untrusted_payload_path,
    participant_actor_id_problems,
    participant_actor_ids,
)
from .crypto import (
    chacha20_poly1305_encrypt,
    generate_x25519,
    hkdf_sha256,
    random_key32,
    random_nonce12,
    x25519_dh,
)
from .envelope import build_envelope, sign_envelope
from .keys import _field, now_iso, to_key_hex, to_recipient, to_signer
from .manifest import (
    CONTENT_INDEX_EXCLUDED,
    build_content_index,
    build_manifest,
    build_signer_commitment,
    compute_capsule_id,
    manifest_bytes,
    manifest_hash,
)
from .pith import compress_event_payload
from .zip_io import pack_zip

_SKILL_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


def _assert_valid_participants(participants: object) -> None:
    """Raise when a declared ``participants`` list fails the actor-id grammar."""
    problems = participant_actor_id_problems(participants)
    if problems:
        raise ValueError("; ".join(problems))


@dataclass
class _SkillEntry:
    json: dict | None
    markdown: str | None
    signed: bool


class CapsuleBuilder:
    def __init__(
        self,
        *,
        originator,
        participants: list[dict] | None = None,
        created_at: str | None = None,
        pith: bool = True,
    ) -> None:
        # `originator` accepts {"public_key": ..., "label"?} with the key
        # as a hex string or 32 raw bytes — or the Ed25519KeyPair returned
        # by generate_ed25519() directly.
        originator_key = _field(originator, "public_key", "public_key_hex")
        if originator_key is None:
            raise ValueError("originator.public_key required (hex string or 32 bytes)")
        self.originator = {
            "public_key": to_key_hex(originator_key, "originator.public_key"),
            "label": _field(originator, "label") or "",
        }
        # spec/manifest.md field rules: every declared actor_id must sit in
        # the closed namespace set. Refuse the shape at the call site that
        # introduced it — a capsule declaring an uninterpretable participant
        # fails every conformant verifier. Re-checked at seal() because
        # builder.participants is a mutable attribute.
        _assert_valid_participants(participants or [])
        self.participants = participants or []
        self.created_at = created_at or now_iso()
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
        """Append a chain event.

        ``actor`` and ``action`` are required; ``kind`` defaults to
        "observation", ``target`` to "capsule", and ``timestamp`` to the
        builder's ``created_at`` value.

        Rejects (spec/chain.md):
          - a ``kind`` outside the closed enum, always, and
          - when the builder declares a non-empty ``participants``, an
            ``actor`` that is neither ``"system:host"`` nor a declared
            participant. The builder never auto-registers participants —
            declaring who may act is the caller's decision. A builder
            with NO declared participants accepts any actor: that capsule
            makes a visibly weaker claim (verifiers report the actor set
            as unbound).
        """
        for required in ("actor", "action"):
            if not event.get(required):
                raise ValueError(f"event requires {required}")
        kind = event.get("kind", "observation")
        if not is_valid_event_kind(kind):
            raise ValueError(
                f"event kind {json.dumps(kind)} is not one of " + ", ".join(EVENT_KINDS)
            )
        actor = event["actor"]
        # Recomputed on every call so mutating builder.participants between
        # appends behaves predictably.
        declared = participant_actor_ids(self.participants)
        if declared and actor != HOST_ACTOR and actor not in declared:
            raise ValueError(
                f"event actor {json.dumps(actor)} is not a declared participant: add "
                f'{{"actor_id": {json.dumps(actor)}, "role": "..."}} to the builder\'s '
                'participants[] (only "system:host" may appear without one)'
            )
        apply_pith = self.pith if pith is None else (self.pith and pith)
        raw_payload = event.get("payload", {})
        payload = compress_event_payload(raw_payload) if apply_pith else raw_payload
        bare = {
            "actor": actor,
            "kind": kind,
            "action": event["action"],
            "target": event.get("target", "capsule"),
            "timestamp": (
                event.get("timestamp") if event.get("timestamp") is not None else self.created_at
            ),
            "payload": payload,
        }
        if "untrusted_payload_fields" in event:
            # Writer obligation (spec/chain.md "Untrusted content"): a
            # marking outside the path grammar has no defined resolution,
            # so refuse it at the call site that introduced it rather than
            # at some future reader.
            upf = event["untrusted_payload_fields"]
            if not isinstance(upf, list):
                raise ValueError(
                    "append_event: untrusted_payload_fields must be an array of payload paths"
                )
            for path in upf:
                if not is_valid_untrusted_payload_path(path):
                    raise ValueError(
                        f"append_event: untrusted_payload_fields entry {json.dumps(path)} "
                        'is not a valid payload path (expected "payload.<segment>" '
                        "per spec/chain.md)"
                    )
            bare["untrusted_payload_fields"] = upf
        self.bare_events.append(bare)
        return self

    def seal(
        self,
        *,
        signers,
        signed_at: str | None = None,
        recipients=None,
    ) -> bytes:
        """Seal and emit the capsule bytes.

        ``signers``: one signer or a list. Each signer is
        ``{"role"?, "public_key", "private_key"}`` with keys as hex
        strings or bytes; the ``Ed25519KeyPair`` returned by
        ``generate_ed25519()`` works as-is (role defaults to
        "originator").

        ``recipients``: optional; presence enables encryption. One
        recipient or a list; each is an X25519 public key (hex or
        bytes), ``{"public_key": ...}``, or a ``generate_x25519()``
        keypair.

        ``signed_at``: optional ISO 8601 UTC string; defaults to now.
        Pass an explicit value for reproducible builds.
        """
        # builder.participants is mutable between construction and seal;
        # never emit a manifest that fails the namespace grammar.
        _assert_valid_participants(self.participants)
        if signers is None:
            signer_items = []
        elif isinstance(signers, (list, tuple)):
            signer_items = list(signers)
        else:
            signer_items = [signers]
        signers = [to_signer(s, i) for i, s in enumerate(signer_items)]
        if not signers:
            raise ValueError("seal requires at least one signer")
        if recipients is None:
            recipient_items = []
        elif isinstance(recipients, (list, tuple)):
            recipient_items = list(recipients)
        else:
            recipient_items = [recipients]
        recipients = [to_recipient(r, i) for i, r in enumerate(recipient_items)]
        signed_at = signed_at or now_iso()

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

        # Signer-set commitment: the exact (role, public_key) membership of
        # the seal-time signer set, bound into the manifest (and therefore
        # into every signature via manifest_hash). Plain and encrypted paths
        # share one signer list, so one commitment serves inner and outer.
        signer_commitment = build_signer_commitment(
            [{"role": s["role"], "public_key": bytes_to_hex(s["public_key"])} for s in signers]
        )

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
                signer_commitment=signer_commitment,
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
            signer_commitment=signer_commitment,
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

        # Encrypted profile: content.enc is bound by envelope.encrypted_blob_hash,
        # so it is excluded from the content index here.
        outer_content_index = build_content_index(outer_sidecars, CONTENT_INDEX_EXCLUDED)

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
            signer_commitment=signer_commitment,
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

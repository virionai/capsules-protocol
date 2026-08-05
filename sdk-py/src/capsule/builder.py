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
from .lineage import verification_error_count
from .manifest import (
    CONTENT_INDEX_EXCLUDED,
    build_content_index,
    build_manifest,
    build_signer_commitment,
    compute_capsule_id,
    declared_alternate_profile_id,
    manifest_bytes,
    manifest_hash,
    predecessors_problems,
)
from .pith import normalize_event_payload
from .reader import CapsuleReader
from .verifier import verify_capsule
from .zip_io import pack_zip
from .versions import CURRENT_VERSION, UnsupportedCapsuleVersionError, key_wrap_info

_SKILL_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")

_LINEAGE_PLACEMENTS = ("both", "inner", "outer")


def _assert_valid_participants(participants: object) -> None:
    """Raise when a declared ``participants`` list fails the actor-id grammar."""
    problems = participant_actor_id_problems(participants)
    if problems:
        raise ValueError("; ".join(problems))


class PredecessorError(ValueError):
    """Refusal to build on a predecessor (spec/lineage.md W3-W5).

    ``reason`` is the closed machine-readable vocabulary, identical in
    both builder lanes:

      ``verification_failed``   the predecessor fails its own
                                verification (override:
                                ``allow_invalid_predecessor``)
      ``unsupported_version``   declared era outside the known table; the
                                entry members cannot be honestly derived,
                                so there is no override
      ``encrypted_predecessor`` v0.7.1 defines no declaration mapping
                                onto an encrypted outer/inner pair;
                                decrypt the inner and rewrap that
      ``unsupported_profile``   the predecessor declares a profile this
                                implementation does not implement
                                (v0.7.1 lineage commits to
                                default-profile predecessors)

    ``verification`` carries the full ``verify_capsule`` result where one
    was produced (``None`` for ``encrypted_predecessor``).
    """

    def __init__(self, message: str, *, reason: str, verification: dict | None = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.verification = verification


def derive_predecessor_entry(reader: CapsuleReader) -> dict:
    """Derive the six-member lineage entry from opened predecessor bytes.

    spec/lineage.md W1 "derive, never copy claims": ``format_version``,
    the originator key, and the two chain anchors are reads;
    ``capsule_id`` is RECOMPUTED under the predecessor's declared era's
    domain string, and ``manifest_hash`` is RECOMPUTED from the stored
    manifest document — never taken from the envelope's claim.
    """
    manifest = reader.manifest()
    envelope = reader.envelope()
    version = manifest.get("format", {}).get("version")
    return {
        "capsule_id": compute_capsule_id(
            hex_to_bytes(manifest["originator"]["public_key"]),
            manifest.get("first_event_hash"),
            version,
        ),
        "format_version": version,
        "originator_public_key": manifest["originator"]["public_key"],
        "first_event_hash": manifest.get("first_event_hash"),
        "entry_hash": envelope.get("entry_hash"),
        "manifest_hash": manifest_hash(manifest),
    }


def _open_predecessor_for_build(
    predecessor, *, allow_invalid_predecessor: bool = False
) -> tuple[CapsuleReader, dict]:
    """Open + gate a predecessor for building (W3-W5).

    Returns ``(reader, verification)``; raises ``PredecessorError``
    otherwise. The refusal order is scope before validity: an encrypted
    or alternate-profile predecessor is an input class this operation
    does not take, whatever its verification verdict would be.
    """
    reader = None
    verify_input = predecessor
    if isinstance(predecessor, CapsuleReader):
        reader = predecessor
    elif isinstance(predecessor, (bytes, bytearray, memoryview)):
        data = bytes(predecessor)
        verify_input = data
        try:
            reader = CapsuleReader.from_bytes(data)
        except UnsupportedCapsuleVersionError as e:
            # W4: no override — the identity recompute needs that era's
            # domain string, so an "entry" would be a fabricated
            # commitment wearing derived members' clothes. The diagnosis
            # keeps the versioning.md vocabulary, distinct from tamper.
            raise PredecessorError(f"predecessor {e}", reason="unsupported_version") from e
        except Exception:
            # Every other open failure is reported through the total
            # verify path below, so one diagnosis reaches the caller.
            reader = None
    else:
        raise ValueError("predecessor must be a CapsuleReader or the raw .capsule bytes")
    verification = verify_capsule(reader if reader is not None else verify_input)
    if reader is None:
        first = verification["errors"][0] if verification["errors"] else "unreadable"
        raise PredecessorError(
            f"predecessor cannot be opened as a capsule: {first}",
            reason="verification_failed",
            verification=verification,
        )
    if reader.is_encrypted():
        # W5. Privacy note (spec/lineage.md): declaring a decrypted inner
        # publishes existence-evidence of confidential work — the
        # successor author's disclosure choice.
        raise PredecessorError(
            "predecessor is an encrypted capsule; v0.7.1 defines no declaration mapping "
            "onto an encrypted capsule's outer/inner pair. Decrypt the inner capsule "
            "(reader.decrypt(...)) and continue from that — the inner IS a plain capsule. "
            "Note that declaring a decrypted inner publishes existence-evidence of "
            "confidential work",
            reason="encrypted_predecessor",
        )
    alternate_profile = declared_alternate_profile_id(reader.manifest())
    if alternate_profile is not None:
        raise PredecessorError(
            f"predecessor declares profile '{alternate_profile}', which this implementation "
            f"does not implement; v0.7.1 lineage declarations commit to default-profile "
            f"(v0.6-suite) predecessors — a limitation of the tool, not a defect of the capsule",
            reason="unsupported_profile",
            verification=verification,
        )
    if not verification["ok"] and not allow_invalid_predecessor:
        # W3: refuse by default at the call site that introduced the
        # problem; the override still derives an exact, honest citation —
        # linkage verification reports the artifact predecessor_invalid
        # whichever path sealed the successor.
        raise PredecessorError(
            f"predecessor fails its own verification "
            f"({verification_error_count(verification)} error(s)); "
            f"pass allow_invalid_predecessor=True to declare it anyway — the declaration "
            f"cites this exact artifact, and linkage verification will report it "
            f"predecessor_invalid",
            reason="verification_failed",
            verification=verification,
        )
    return reader, verification


#: Carry/reset rule (spec/lineage.md "Continuing a capsule"): files are
#: content and carry byte-identically; manifest members are the
#: predecessor originator's claims and reset. The chain resets to a
#: fresh genesis — predecessor history stays where it is signed.
_RESET_PATHS = frozenset({"manifest.json", "provenance/envelope.json", "chain/events.jsonl"})


def _is_carriable_path(path: str) -> bool:
    if path in _RESET_PATHS:
        return False
    # Cannot occur in the plain predecessor this path accepts; defensive.
    if path == "content.enc" or path.startswith("skills/decryption/"):
        return False
    return True


@dataclass
class _SkillEntry:
    json: dict | None
    markdown: str | None


class CapsuleBuilder:
    def __init__(
        self,
        *,
        originator,
        participants: list[dict] | None = None,
        created_at: str | None = None,
        pith: bool = False,
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
        # Lineage declaration entries (spec/lineage.md), appended via
        # declare_predecessor / declare_predecessor_entry / continue_from.
        self.predecessors: list[dict] = []
        # Files carried byte-identically from a predecessor
        # (continue_from). Merged into the inner file map at seal, under
        # any set_program/set_agents/add_skill/add_payload the caller
        # applies on top.
        self._carried_files: dict[str, bytes] = {}
        # Reports set by continue_from; None/[] for a from-scratch build.
        self.predecessor_verification: dict | None = None
        self.carried_paths: list[str] = []
        # Pith is OPT-IN (v0.7): lossy narrative normalization lands inside
        # the hash chain where the original is not preserved, so an author
        # who writes prose gets their prose unless they ask for the rewrite
        # (spec/pith.md; ROADMAP "Pith protocol boundary").
        self.pith = pith is True

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
    ) -> CapsuleBuilder:
        """Add a skill (skills/<id>/skill.json + SKILL.md).

        There is no trust declaration here: skill trust is host-relative
        and DERIVED at verify time (``verify_capsule(...)["skill_trust"]``),
        so an author cannot assert it. The removed draft-era ``signed``
        flag raises TypeError like any unknown keyword.
        """
        if not isinstance(id, str) or not _SKILL_ID_RE.match(id):
            raise ValueError(f"invalid skill id: {id}")
        if id == "decryption":
            raise ValueError("'decryption' is reserved for encryption metadata; not a skill")
        self.skills[id] = _SkillEntry(json=json, markdown=markdown)
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
        builder's ``created_at`` value. Pith normalization follows the
        builder setting (opt-in, default off); a per-call ``pith=True``
        or ``pith=False`` overrides it for this event only. When
        normalization actually changed a field, the event records the
        affected payload members in ``pith_normalized_fields``
        (spec/chain.md) — a lossy rewrite inside the hash chain is
        never silent.

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
        # Caller-declared Pith provenance (an LLM applying Pith as practice
        # may honestly mark the fields it rewrote). Same writer obligation
        # as untrusted_payload_fields: refuse an out-of-grammar entry here,
        # at the call site that introduced it.
        pith_marks: list[str] = []
        declared_marks = "pith_normalized_fields" in event
        if declared_marks:
            marks = event["pith_normalized_fields"]
            if not isinstance(marks, list):
                raise ValueError(
                    "append_event: pith_normalized_fields must be an array of payload paths"
                )
            for path in marks:
                if not is_valid_untrusted_payload_path(path):
                    raise ValueError(
                        f"append_event: pith_normalized_fields entry {json.dumps(path)} "
                        'is not a valid payload path (expected "payload.<segment>" '
                        "per spec/chain.md)"
                    )
            pith_marks = list(marks)
        apply_pith = self.pith if pith is None else pith is True
        raw_payload = event.get("payload", {})
        payload = raw_payload
        if apply_pith:
            normalized = normalize_event_payload(raw_payload)
            payload = normalized["payload"]
            for field in normalized["normalized_fields"]:
                if field not in pith_marks:
                    pith_marks.append(field)
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
        # Present when the caller declared marks OR the normalizer changed
        # a field; an event whose narrative was rewritten says so in-chain.
        if declared_marks or pith_marks:
            bare["pith_normalized_fields"] = pith_marks
        self.bare_events.append(bare)
        return self

    @classmethod
    def continue_from(
        cls,
        predecessor,
        *,
        originator,
        participants: list[dict] | None = None,
        created_at: str | None = None,
        pith: bool = False,
        custody_event: bool = True,
        custody_actor: str = HOST_ACTOR,
        carry=None,
        allow_invalid_predecessor: bool = False,
    ) -> CapsuleBuilder:
        """Open a successor builder from a sealed predecessor.

        The hand-off made one operation (spec/lineage.md "Continuing a
        capsule"). ``predecessor`` is a ``CapsuleReader`` or the raw
        ``.capsule`` bytes. The predecessor is verified under its own
        era's rules (refusals W3-W5, raised as ``PredecessorError``), the
        six-member declaration entry is derived (W1), content files are
        carried byte-identically per the carry/reset rule, and the
        conventional ``custody_received`` genesis event is queued
        (default on, opt-out). The successor's ``participants`` is the
        CALLER's claim — never inherited: the predecessor's list
        described its own chain, which stays behind.
        """
        if originator is None:
            raise ValueError('continue_from requires the NEW originator ({"public_key", "label"?})')
        reader, verification = _open_predecessor_for_build(
            predecessor, allow_invalid_predecessor=allow_invalid_predecessor
        )
        entry = derive_predecessor_entry(reader)
        builder = cls(
            originator=originator,
            participants=participants,
            created_at=created_at,
            pith=pith,
        )
        builder.declare_predecessor_entry(entry)
        carried: list[str] = []
        for path, data in reader.files().items():
            if not _is_carriable_path(path):
                continue
            if carry is not None and not carry(path):
                continue
            builder._carried_files[path] = bytes(data)
            carried.append(path)
        carried.sort()
        if custody_event:
            # The pinned custody-event template: visible custody for the
            # cold reader, in the existing capsule: namespace. Advisory —
            # never a verifier rule; the manifest declaration is the
            # binding claim.
            builder.append_event(
                {
                    "actor": custody_actor,
                    "kind": "observation",
                    "action": "custody_received",
                    "target": f"capsule:{entry['capsule_id']}",
                    "timestamp": builder.created_at,
                    "payload": {
                        "note": (
                            f"custody received from capsule {entry['capsule_id']}; "
                            f"lineage is declared in manifest.predecessors"
                        )
                    },
                }
            )
        builder.predecessor_verification = verification
        builder.carried_paths = carried
        return builder

    def declare_predecessor(
        self, predecessor, *, allow_invalid_predecessor: bool = False
    ) -> CapsuleBuilder:
        """Verify + derive + append one lineage entry.

        Merges: call once per parent. Same refusal contract as
        ``continue_from`` (W3-W5, raised as ``PredecessorError``). Never
        emits an event.
        """
        reader, _ = _open_predecessor_for_build(
            predecessor, allow_invalid_predecessor=allow_invalid_predecessor
        )
        return self.declare_predecessor_entry(derive_predecessor_entry(reader))

    def declare_predecessor_entry(self, entry: dict) -> CapsuleBuilder:
        """Explicit-values path (the archivist case).

        Lineage reconstructed from records — hashes in hand, bytes gone.
        Validates grammar, null coherence, and identity coherence (reader
        checks 1-3; identity only for KNOWN declared eras, mirroring the
        reader's unknown-era skip), and appends. Validates form, never
        truth — the builder cannot know whether the cited artifact
        exists. Vendor ``x-`` members inside the entry are preserved
        verbatim.
        """
        if not isinstance(entry, dict):
            raise ValueError("declare_predecessor_entry requires an entry object")
        candidate = [*self.predecessors, dict(entry)]
        problems = predecessors_problems(candidate)
        if problems:
            raise ValueError("declare_predecessor_entry: " + "; ".join(problems))
        self.predecessors = candidate
        return self

    def seal(
        self,
        *,
        signers,
        signed_at: str | None = None,
        recipients=None,
        lineage_placement: str = "both",
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

        ``lineage_placement``: encrypted successors only (ignored for
        plain): where a declared ``predecessors`` member lands — "both"
        (default: the strongest symmetric claim, the signer_commitment
        posture; the two copies are emitted byte-equal), "inner" (private
        citation), or "outer" (public-outer citation) — each single-layer
        choice a weaker claim made honestly (spec/lineage.md).
        """
        # builder.participants is mutable between construction and seal;
        # never emit a manifest that fails the namespace grammar.
        _assert_valid_participants(self.participants)
        if lineage_placement not in _LINEAGE_PLACEMENTS:
            raise ValueError(
                f'lineage_placement must be "both", "inner", or "outer", '
                f"got {json.dumps(lineage_placement)}"
            )
        # builder.predecessors is mutable too; never emit a declaration a
        # reader would fail closed (spec/lineage.md W2).
        if self.predecessors:
            predecessor_problems = predecessors_problems(self.predecessors)
            if predecessor_problems:
                raise ValueError("seal: " + "; ".join(predecessor_problems))
        predecessors = self.predecessors if self.predecessors else None
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

        # Inner files. Carried predecessor files first, byte-identical
        # (never rewritten — no re-encoding, no normalization); everything
        # the caller set on the builder lands on top. Legacy
        # content-indexed files a predecessor carried (e.g. a pre-v0.7
        # surface.md) survive here — silently dropping them would make a
        # rewrap a lossy copy.
        inner: dict[str, bytes] = dict(self._carried_files)
        if self.program_md is not None:
            inner["program.md"] = self.program_md.encode("utf-8")
        elif "program.md" not in inner:
            inner["program.md"] = b"# Program\n"
        inner["chain/events.jsonl"] = events_jsonl
        if self.agents_md is not None:
            inner["agents.md"] = self.agents_md.encode("utf-8")
        for sid, entry in self.skills.items():
            if entry.json is not None:
                inner[f"skills/{sid}/skill.json"] = json.dumps(
                    entry.json, indent=2, ensure_ascii=False
                ).encode("utf-8")
            if entry.markdown is not None:
                inner[f"skills/{sid}/SKILL.md"] = entry.markdown.encode("utf-8")
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
                encryption=None,
                created_at=self.created_at,
                signer_commitment=signer_commitment,
                predecessors=predecessors,
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
            encryption=None,
            created_at=self.created_at,
            signer_commitment=signer_commitment,
            # The author's placement choice (spec/lineage.md "Encrypted
            # successors"): "both" emits byte-equal copies, satisfying
            # the reader's inner/outer equality check by construction.
            predecessors=None if lineage_placement == "outer" else predecessors,
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
            "version": CURRENT_VERSION,
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
            encryption={
                "metadata_path": "skills/decryption/decryption.json",
                "cipher": "ChaCha20-Poly1305",
            },
            created_at=self.created_at,
            signer_commitment=signer_commitment,
            predecessors=None if lineage_placement == "inner" else predecessors,
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
            key_wrap_info(CURRENT_VERSION),
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


def rewrap_capsule(
    predecessor,
    *,
    originator,
    signers=None,
    participants: list[dict] | None = None,
    created_at: str | None = None,
    signed_at: str | None = None,
    custody_event: bool = True,
    custody_actor: str = HOST_ACTOR,
    carry=None,
    recipients=None,
    lineage_placement: str = "both",
    allow_invalid_predecessor: bool = False,
) -> dict:
    """The one-call custody transfer (spec/lineage.md "Continuing a capsule").

    ``continue_from`` + immediate seal under the NEW originator keypair.
    Pure hand-off — callers who want to continue the work before sealing
    use ``CapsuleBuilder.continue_from`` and seal later. Single
    predecessor by design (a hand-off has one subject); merges go through
    the builder path (``declare_predecessor`` per parent).

    Reproducibility: with pinned ``created_at``/``signed_at`` and the
    same keypair the output is byte-identical within this
    implementation; without them, two rewraps of the same predecessor
    are two distinct genuine successors (different genesis timestamp →
    different capsule_id) — both honest.

    Raises ``PredecessorError`` per W3-W5 (see ``continue_from``).
    """
    if originator is None:
        raise ValueError(
            "rewrap_capsule requires originator (the NEW keypair "
            '{"public_key", "private_key", "label"?})'
        )
    builder = CapsuleBuilder.continue_from(
        predecessor,
        originator=originator,
        participants=participants,
        created_at=created_at,
        custody_event=custody_event,
        custody_actor=custody_actor,
        carry=carry,
        allow_invalid_predecessor=allow_invalid_predecessor,
    )
    seal_signers = signers
    if seal_signers is None:
        seal_signers = [
            {
                "role": "originator",
                "public_key": _field(originator, "public_key", "public_key_hex"),
                "private_key": _field(originator, "private_key", "private_key_hex"),
            }
        ]
    data = builder.seal(
        signers=seal_signers,
        signed_at=signed_at,
        recipients=recipients,
        lineage_placement=lineage_placement,
    )
    sealed = CapsuleReader.from_bytes(data)
    return {
        "bytes": data,
        "capsule_id": sealed.manifest()["id"],
        "predecessor_entry": builder.predecessors[0],
        "predecessor_verification": builder.predecessor_verification,
        "carried_paths": builder.carried_paths,
        "custody_event_emitted": custody_event is True,
    }

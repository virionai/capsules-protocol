//! Strongly-typed serde schemas for the three JSON artifacts produced by the
//! JS reference SDK: `manifest.json`, `provenance/envelope.json`, and the
//! per-line records inside `chain/events.jsonl`.
//!
//! The point of these structs is *parse fidelity*: the verifier needs to walk
//! these blobs by name, not as untyped `serde_json::Value`, so a stale field
//! name or type mismatch fails fast at deserialization rather than silently
//! later in the pipeline.
//!
//! **These structs are VIEWS, never hashing inputs.** Unknown members in the
//! hashed documents (manifest, envelope, chain events) MUST be preserved
//! verbatim and included in canonicalization (spec/manifest.md "Unknown
//! members", spec/envelope.md, spec/chain.md). A typed struct silently drops
//! members it does not know, so anything that is canonicalised and hashed —
//! `manifest_hash`, the envelope canonical payload, the per-event chain hash
//! — is computed from the *preserved* `serde_json::Value` tree parsed from
//! the on-disk bytes, never from a struct round-trip. See [`ParsedEvent`],
//! `manifest::manifest_hash`, and `envelope::canonical_payload`.
//!
//! Notes that are easy to get wrong:
//!
//! - **Field names are snake_case across the board.** The JS SDK writes
//!   keys like `first_event_hash`, `content_index`, `actor_id`,
//!   `untrusted_payload_fields`, etc. We do not apply
//!   `#[serde(rename_all = "camelCase")]`; the Rust field names mirror the
//!   on-disk keys exactly.
//!
//! - **There is no `Manifest::skill_trust` field.** v0.6 removed the
//!   member from the format: skill trust is host-relative and DERIVED at
//!   verify time (spec/trust.md "Skill trust"). A capsule from an earlier
//!   draft that still carries the member parses fine — it lands in the
//!   preserved `serde_json::Value` tree as an unknown member (hashed,
//!   inert) and is never read as authority.
//!
//! - **`Envelope::encrypted_blob_hash` is `Option<String>`.** Plain (cipher
//!   == "none") capsules write `null` here; encrypted ones write a 64-hex
//!   string. The struct must accept either form without choking.
//!
//! - **`ChainEvent::untrusted_payload_fields` defaults to empty.** Older
//!   capsules (pre-feature) might omit the field entirely; `#[serde(default)]`
//!   yields an empty `Vec` rather than failing the parse.
//!
//! - **`ChainEvent::payload` is `serde_json::Value`.** Payloads are arbitrary
//!   JSON; the chain hash commits to the canonical bytes of the whole event,
//!   so we must preserve everything inside `payload` losslessly. Round-
//!   tripping through `Value` is fine for that — the JCS canonicalizer
//!   re-sorts keys at hash time anyway.

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

/// Lenient projection for ADVISORY string members (spec/manifest.md,
/// spec/chain.md field rules): `Some(s)` when the stored value is a JSON
/// string, `None` when it is absent or any other type. Advisory members
/// are never verification inputs — verifiers gate nothing on their
/// presence, absence, or type — so the typed VIEW must not refuse to
/// parse a spec-valid document over them (conformance vectors:
/// chain-rules `advisory-members-any-type`,
/// `absent-advisory-manifest-members`, `minimal-event-fields`). The
/// preserved `serde_json::Value` tree keeps the stored value verbatim for
/// hashing either way.
fn advisory_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(match value {
        serde_json::Value::String(s) => Some(s),
        _ => None,
    })
}

/// The `format` block at the top of every manifest. All four fields are
/// fixed-vocabulary strings (`"0.6"`/`"0.7"`, `"zip"`, `"JCS-RFC8785"`,
/// `"SHA-256"`); we keep them as `String` rather than enums so an unknown
/// future value fails at the *verifier* level (with a clear "unsupported
/// format" message) rather than at deserialization with a serde-internal
/// error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormatBlock {
    pub version: String,
    pub container: String,
    pub canonicalization: String,
    pub hash_algorithm: String,
}

/// Originator block: the entity that *created* the capsule.
///
/// `public_key` is 64 lowercase hex chars (32 raw bytes) and required —
/// the originator-binding invariant reads it. `label` is a free-form
/// display name: ADVISORY and optional (spec/manifest.md field rules), so
/// the lenient projection never refuses a capsule over it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Originator {
    pub public_key: String,
    #[serde(
        default,
        deserialize_with = "advisory_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub label: Option<String>,
}

/// One declared `manifest.participants[]` entry, as this lane interprets
/// it (spec/manifest.md field rules).
///
/// `actor_id` is the ONE member the spec interprets: `None` here means
/// the entry declared no interpretable actor id — a malformed declaration
/// the VERIFIER flags with the cross-lane `participants[i].actor_id`
/// diagnosis (conformance vector chain-rules/participant-missing-actor-id)
/// — never a parse refusal, which would present a spec-invalid entry as a
/// corrupt container. `role` and `label` are advisory attribution text:
/// optional, any-typed on the wire, never verification inputs (vectors
/// participant-without-label, participant-only-actor-id,
/// advisory-members-any-type).
///
/// The custom `Deserialize` also accepts the bare actor-id STRING entry —
/// the spec's shorthand for `{actor_id}` (vector participant-bare-string)
/// — and never fails: every entry shape projects onto this view, and the
/// verifier decides. This struct is a VIEW, never a hashing input, so
/// `skip_serializing_if` cannot change any hashed bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Participant {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl<'de> Deserialize<'de> for Participant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string_of = |v: Option<&serde_json::Value>| -> Option<String> {
            v.and_then(|x| x.as_str()).map(str::to_string)
        };
        Ok(match serde_json::Value::deserialize(deserializer)? {
            serde_json::Value::String(s) => Participant {
                actor_id: Some(s),
                role: None,
                label: None,
            },
            serde_json::Value::Object(m) => Participant {
                actor_id: string_of(m.get("actor_id")),
                role: string_of(m.get("role")),
                label: string_of(m.get("label")),
            },
            // Any other entry shape declares nothing bindable; the
            // verifier flags it (same diagnosis as a missing actor_id).
            _ => Participant {
                actor_id: None,
                role: None,
                label: None,
            },
        })
    }
}

/// One row of the content index: a path inside the capsule and the SHA-256
/// of its raw bytes (lowercase hex).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentIndexEntry {
    pub path: String,
    pub sha256: String,
}

/// The full content index: a sorted list of per-file entries plus the
/// SHA-256 of the JCS-canonical form of that list (lowercase hex).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentIndex {
    pub files: Vec<ContentIndexEntry>,
    pub index_hash: String,
}

/// Encryption metadata: present on encrypted capsules, absent (`null`) on
/// plain ones. `metadata_path` points at the in-zip JSON describing per-key
/// envelope-encrypted blob keys; `cipher` names the AEAD scheme (e.g.
/// `"ChaCha20-Poly1305"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Encryption {
    pub metadata_path: String,
    pub cipher: String,
}

/// One member of `manifest.signer_commitment`: a `(role, public_key)` pair
/// naming one seal-time signer. `public_key` is 64 lowercase hex chars.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerCommitmentEntry {
    pub role: String,
    pub public_key: String,
}

/// The full v0.6 manifest. Field names match the on-disk keys exactly.
///
/// `signer_commitment` is the exact seal-time signer set (spec/manifest.md
/// "signer_commitment"). It is OPTIONAL on the wire — presence binds,
/// absence reports — so `#[serde(default)]` keeps commitment-less capsules
/// parseable, and `skip_serializing_if` keeps round-trips from inventing the
/// member. NOTE this struct is a VIEW: the normative signer-set check runs
/// against the preserved `serde_json::Value` tree so that malformed shapes
/// (e.g. a `null` commitment) fail closed exactly like the JS reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: FormatBlock,
    pub id: String,
    pub originator: Originator,
    /// An ARRAY when present (spec/manifest.md). `#[serde(default)]`
    /// keeps a capsule with NO `participants` member parseable: absence
    /// is the same honest weaker claim as the empty array (unbound actor
    /// set, reported), never a rejection. A PRESENT non-array value still
    /// fails deserialization — the malformed-shape rule (conformance:
    /// malformed-shape `participants-not-array` / `participants-string`,
    /// chain-rules `absent-participants`).
    #[serde(default)]
    pub participants: Vec<Participant>,
    /// `None` is the legal zero-event shape (spec/chain.md "Empty
    /// chains"): a capsule with no events has no first event to hash, so
    /// the manifest writes `null` and `capsule_id` derives with 32 zero
    /// bytes standing in. The verifier enforces the null-anchor /
    /// event-count consistency in both directions.
    pub first_event_hash: Option<String>,
    pub content_index: ContentIndex,
    pub encryption: Option<Encryption>,
    /// Advisory only (spec/manifest.md field rules): MAY be absent, and
    /// never a verification input — authoritative time-binding is the
    /// envelope's `signed_at`. Conformance vector:
    /// chain-rules/absent-advisory-manifest-members.
    #[serde(
        default,
        deserialize_with = "advisory_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_commitment: Option<Vec<SignerCommitmentEntry>>,
}

/// One signature in the envelope's `signers` array. `role` namespaces the
/// signing input (see `envelope.md` for the domain-separation rule); the
/// public key is 32 raw bytes (64 hex) and the signature 64 raw bytes
/// (128 hex).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signer {
    pub role: String,
    pub public_key: String,
    pub signature: String,
}

/// Provenance envelope: the signed root of trust over a capsule.
///
/// The signed payload is `JCS(envelope minus signers)` per role. We model
/// `signers` as a plain `Vec` so re-serialization preserves the exact set of
/// fields and order from the original document. `encrypted_blob_hash` is an
/// `Option<String>` because the JS SDK writes literal `null` on plain
/// capsules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub version: String,
    pub capsule_id: String,
    /// `None` (stored `null`) is the legal zero-event shape — see
    /// [`Manifest::first_event_hash`]. In a plain capsule these two
    /// anchors are the only envelope-to-chain binding, so the verifier
    /// requires them null over an empty chain and matching over a
    /// non-empty one, fail-closed both ways.
    pub first_event_hash: Option<String>,
    pub entry_hash: Option<String>,
    pub manifest_hash: String,
    pub content_index_hash: String,
    pub encrypted_blob_hash: Option<String>,
    pub cipher: String,
    pub signed_at: String,
    pub signers: Vec<Signer>,
}

/// One event from `chain/events.jsonl`.
///
/// `payload` is `serde_json::Value` because event payloads are application-
/// defined and may carry arbitrary nested structure. The chain hash commits
/// to the JCS-canonical bytes of the entire event (excluding `hash`), so the
/// payload's exact contents must round-trip losslessly; `Value` does that by
/// construction.
///
/// `untrusted_payload_fields` carries the convention from `chain.md`: each
/// entry is a JSON-pointer-like path identifying a payload field whose
/// content is LLM-generated narrative and must not be treated as ground
/// truth by downstream consumers. `#[serde(default)]` allows older events
/// that pre-date this field; on round-trip we re-emit the field as `[]`,
/// which is harmless because verification ignores absent vs empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainEvent {
    pub seq: u64,
    /// Advisory (spec/chain.md field rules) — as are `action`, `target`,
    /// `timestamp`, and `payload` below. The event hash commits to the
    /// stored line, so an absent (or non-string) advisory member is a
    /// weaker claim made honestly, never a parse refusal: the members
    /// verification rules read are `seq`, `kind`, `prev_hash`, `hash`,
    /// and (only when the manifest binds an actor set) `actor`.
    /// Conformance vector: chain-rules/minimal-event-fields.
    #[serde(
        default,
        deserialize_with = "advisory_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub event_id: Option<String>,
    /// `None` when absent or non-string. Read ONLY by the conditional
    /// step-6 membership rule: with a bound actor set, `None` fails that
    /// rule (rendered `null`, mirroring the JS reference); with an
    /// unbound set it binds nothing.
    #[serde(
        default,
        deserialize_with = "advisory_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub actor: Option<String>,
    pub kind: String,
    #[serde(
        default,
        deserialize_with = "advisory_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub action: Option<String>,
    #[serde(
        default,
        deserialize_with = "advisory_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub target: Option<String>,
    #[serde(
        default,
        deserialize_with = "advisory_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub timestamp: Option<String>,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub payload: serde_json::Value,
    #[serde(default)]
    pub untrusted_payload_fields: Vec<String>,
    pub prev_hash: String,
    pub hash: String,
}

/// One chain event paired with its preserved JSON tree.
///
/// `event` is the typed view used for field access (seq/prev_hash structure
/// checks, the actor rule, anchor extraction). `raw` is the event exactly as
/// read from disk, unknown members included, and is the ONLY input to the
/// hash recompute: the chain hash commits to `JCS(event minus "hash")` over
/// the preserved tree, so an extension member a v0.6 struct does not know
/// still round-trips into the hash — and tampering with it still breaks the
/// chain.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedEvent {
    pub event: ChainEvent,
    pub raw: serde_json::Value,
}

/// Errors returned by [`parse_chain_jsonl`].
#[derive(Debug, Error)]
pub enum ChainParseError {
    /// A non-empty line failed JSON deserialization. `line` is 1-based and
    /// counts every line in the input — including blank ones — so it
    /// corresponds directly to what a text editor would show.
    #[error("chain line {line}: invalid JSON: {source}")]
    LineParse {
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    /// A line parsed as JSON but is not an object. Reported with the JS
    /// reference's per-event wording ("event is not a JSON object") so the
    /// registry's pinned `error_includes` reads identically across lanes.
    #[error("chain line {line}: event is not a JSON object")]
    NotAnObject { line: usize },
    /// The bytes were not valid UTF-8.
    #[error("chain bytes are not valid UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
}

/// Parse `chain/events.jsonl` bytes into a vector of [`ParsedEvent`]s.
///
/// Splits on `\n`, skips empty lines (so a trailing newline — or two — is
/// fine), and parses each non-empty line ONCE into a preserved
/// `serde_json::Value`, then projects the typed [`ChainEvent`] view from
/// that value. The preserved tree keeps unknown members; the typed view
/// still fails fast on a missing or mistyped known field. The line number
/// reported on parse failure is the 1-based index in the original input,
/// which matches `nl`/editor numbering for the underlying file.
///
/// Mirrors `eventsFromJsonl` in `sdk-js/src/chain.js`.
pub fn parse_chain_jsonl(bytes: &[u8]) -> Result<Vec<ParsedEvent>, ChainParseError> {
    let text = std::str::from_utf8(bytes)?;
    let mut events = Vec::new();
    for (i, raw) in text.split('\n').enumerate() {
        if raw.is_empty() {
            // Skip blank lines — including the trailing one produced by
            // `eventsToJsonl`'s `lines.join("\n") + "\n"`. Note we keep
            // `enumerate` over the *unfiltered* iterator so the 1-based
            // `line` number reported in errors matches the file's actual
            // line numbering.
            continue;
        }
        // Strict parse: the duplicate-member gate runs during
        // deserialization (spec/canonicalization.md "Objects") before the
        // value can reach a hash comparison.
        let value: serde_json::Value = crate::jcs::parse_json_strict(raw.as_bytes())
            .map_err(|source| ChainParseError::LineParse { line: i + 1, source })?;
        // A line that parses but is not an object gets the JS reference's
        // per-event wording rather than a serde type error, so the pinned
        // cross-lane message ("event is not a JSON object") holds here too.
        if !value.is_object() {
            return Err(ChainParseError::NotAnObject { line: i + 1 });
        }
        let event: ChainEvent = serde_json::from_value(value.clone())
            .map_err(|source| ChainParseError::LineParse { line: i + 1, source })?;
        events.push(ParsedEvent { event, raw: value });
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::clean_capsule_bytes;
    use crate::unpack_zip;

    /// Predicate: lowercase hex of exactly `expected` characters.
    fn is_hex_of_len(s: &str, expected: usize) -> bool {
        s.len() == expected
            && s.bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }

    #[test]
    fn parses_clean_manifest() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).expect("unzip");
        let manifest_bytes = map
            .get("manifest.json")
            .expect("manifest.json present in clean.capsule");

        let manifest: Manifest =
            serde_json::from_slice(manifest_bytes).expect("manifest deserializes");

        // The clean fixture is sealed by the current-era JS SDK; this pin
        // moves with each protocol bump (crate::versions::CURRENT_VERSION).
        assert_eq!(manifest.format.version, crate::versions::CURRENT_VERSION);
        assert_eq!(manifest.format.canonicalization, "JCS-RFC8785");
        assert_eq!(manifest.format.container, "zip");
        assert_eq!(manifest.format.hash_algorithm, "SHA-256");
        assert!(
            is_hex_of_len(&manifest.id, 64),
            "manifest.id must be 64 lowercase hex chars, got {:?}",
            manifest.id
        );
        assert!(
            manifest.encryption.is_none(),
            "clean.capsule is plain; encryption must be null"
        );
        assert!(
            !manifest.participants.is_empty(),
            "manifest must have at least one participant"
        );

        // The fixture must contain at least the two baseline files the
        // generator emits (a program and the event chain).
        let paths: Vec<&str> = manifest
            .content_index
            .files
            .iter()
            .map(|f| f.path.as_str())
            .collect();
        for required in ["program.md", "chain/events.jsonl"] {
            assert!(
                paths.contains(&required),
                "content_index must list {required}; got {paths:?}"
            );
        }
        assert!(
            manifest.content_index.files.len() >= 2,
            "expected at least 2 content_index entries, got {}",
            manifest.content_index.files.len()
        );

        // Sanity on originator pubkey shape.
        assert!(
            is_hex_of_len(&manifest.originator.public_key, 64),
            "originator.public_key must be 64 hex"
        );
    }

    #[test]
    fn parses_clean_envelope() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).expect("unzip");
        let envelope_bytes = map
            .get("provenance/envelope.json")
            .expect("envelope present in clean.capsule");

        let envelope: Envelope =
            serde_json::from_slice(envelope_bytes).expect("envelope deserializes");

        assert_eq!(envelope.version, crate::versions::CURRENT_VERSION);
        assert_eq!(envelope.cipher, "none");
        assert!(
            envelope.encrypted_blob_hash.is_none(),
            "plain capsule must have encrypted_blob_hash=null"
        );
        assert!(
            !envelope.signers.is_empty(),
            "envelope must have at least one signer"
        );
        for s in &envelope.signers {
            assert!(
                is_hex_of_len(&s.signature, 128),
                "signer.signature must be 128 hex, got {:?}",
                s.signature
            );
            assert!(
                is_hex_of_len(&s.public_key, 64),
                "signer.public_key must be 64 hex, got {:?}",
                s.public_key
            );
            assert!(!s.role.is_empty(), "signer.role must not be empty");
        }
    }

    #[test]
    fn parses_clean_chain() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).expect("unzip");
        let jsonl = map
            .get("chain/events.jsonl")
            .expect("chain present in clean.capsule");

        let events = parse_chain_jsonl(jsonl).expect("chain parses");

        assert!(!events.is_empty(), "chain must have at least one event");
        assert_eq!(events[0].event.seq, 1, "first event seq must be 1");
        assert_eq!(
            events[0].event.prev_hash,
            "0".repeat(64),
            "first event prev_hash must be the genesis (32 zero bytes hex)"
        );
        assert!(
            is_hex_of_len(&events[0].event.hash, 64),
            "events[0].hash must be 64 hex"
        );

        // For each subsequent event, prev_hash chains correctly and seq is 1-based.
        for (i, e) in events.iter().enumerate().skip(1) {
            assert_eq!(
                e.event.prev_hash,
                events[i - 1].event.hash,
                "events[{i}].prev_hash must equal events[{}].hash",
                i - 1
            );
            assert_eq!(
                e.event.seq,
                (i as u64) + 1,
                "events[{i}].seq must be {} (1-based)",
                i + 1
            );
            assert!(
                is_hex_of_len(&e.event.hash, 64),
                "events[{i}].hash must be 64 hex"
            );
        }
    }

    #[test]
    fn manifest_round_trip() {
        // parse → serialize → parse → struct equality. This proves no field
        // is silently dropped on round-trip; we do NOT require byte-equal
        // JSON output, since serde_json's writer ordering does not match
        // JCS's, and the JS reference itself outputs JCS bytes (which the
        // verifier will recompute via the JCS module, not via this writer).
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).expect("unzip");
        let manifest_bytes = map.get("manifest.json").expect("present");

        let parsed: Manifest = serde_json::from_slice(manifest_bytes).expect("first parse");
        let serialized = serde_json::to_string(&parsed).expect("serialize");
        let reparsed: Manifest = serde_json::from_str(&serialized).expect("second parse");
        assert_eq!(parsed, reparsed, "manifest round-trip must be lossless");
    }

    #[test]
    fn envelope_round_trip() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).expect("unzip");
        let envelope_bytes = map.get("provenance/envelope.json").expect("present");

        let parsed: Envelope = serde_json::from_slice(envelope_bytes).expect("first parse");
        let serialized = serde_json::to_string(&parsed).expect("serialize");
        let reparsed: Envelope = serde_json::from_str(&serialized).expect("second parse");
        assert_eq!(parsed, reparsed, "envelope round-trip must be lossless");
    }

    #[test]
    fn chain_event_round_trip() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).expect("unzip");
        let jsonl = map.get("chain/events.jsonl").expect("present");
        let events = parse_chain_jsonl(jsonl).expect("parse");
        let event = events.first().cloned().expect("at least one event");

        let serialized = serde_json::to_string(&event.event).expect("serialize");
        let reparsed: ChainEvent = serde_json::from_str(&serialized).expect("second parse");
        assert_eq!(event.event, reparsed, "chain event round-trip must be lossless");
    }

    /// Unknown members in a chain event line MUST survive into the
    /// preserved `raw` tree — that tree is what the hash recompute
    /// canonicalises, so dropping the member would diverge from the
    /// signed-over event hash.
    #[test]
    fn parse_chain_jsonl_preserves_unknown_members() {
        let line = concat!(
            r#"{"seq":1,"event_id":"evt_001","actor":"human:alice","kind":"decision","#,
            r#""action":"submitted","target":"program.md","timestamp":"2026-01-01T00:00:00Z","#,
            r#""payload":{},"x-acme-review-ticket":"ACME-1234","#,
            r#""prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","#,
            r#""untrusted_payload_fields":[],"#,
            r#""hash":"0000000000000000000000000000000000000000000000000000000000000001"}"#,
            "\n",
        );
        let events = parse_chain_jsonl(line.as_bytes()).expect("parse with unknown member");
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].raw.get("x-acme-review-ticket").and_then(|v| v.as_str()),
            Some("ACME-1234"),
            "unknown member must be preserved verbatim in the raw tree"
        );
        // The typed view still parses the known fields alongside.
        assert_eq!(events[0].event.seq, 1);
        assert_eq!(events[0].event.actor.as_deref(), Some("human:alice"));
    }

    /// spec/chain.md field rules: `event_id`, `actor`, `action`, `target`,
    /// `timestamp`, and `payload` are advisory — an event omitting all of
    /// them still parses into the typed view (chain-rules
    /// minimal-event-fields pins the full-pipeline outcome).
    #[test]
    fn chain_event_parses_without_advisory_members() {
        let line = concat!(
            r#"{"seq":1,"kind":"decision","#,
            r#""prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","#,
            r#""hash":"0000000000000000000000000000000000000000000000000000000000000001"}"#,
            "\n",
        );
        let events = parse_chain_jsonl(line.as_bytes())
            .expect("advisory members are optional in the typed view");
        assert_eq!(events.len(), 1);
        let e = &events[0].event;
        assert_eq!(e.seq, 1);
        assert_eq!(e.kind, "decision");
        assert!(e.event_id.is_none() && e.actor.is_none() && e.action.is_none());
        assert!(e.target.is_none() && e.timestamp.is_none());
        assert!(e.payload.is_null());
        // The preserved tree must NOT invent members: the hash preimage is
        // the stored line.
        assert!(events[0].raw.get("payload").is_none());
        assert!(events[0].raw.get("event_id").is_none());
    }

    /// spec/manifest.md field rules: every participants[] entry shape
    /// projects onto the typed view without a parse refusal — the bare
    /// actor-id string binds like `{actor_id}`, advisory members of any
    /// type project to `None`, and an uninterpretable entry yields
    /// `actor_id: None` for the VERIFIER to flag (never a parse error
    /// presenting a spec-invalid entry as a corrupt container).
    #[test]
    fn participant_entries_project_leniently() {
        let parsed: Vec<Participant> = serde_json::from_str(
            r#"["human:origin",
                {"actor_id":"ai:helper"},
                {"actor_id":"human:a","role":42,"label":{"x":1}},
                {"role":"advisor"},
                42]"#,
        )
        .expect("every entry shape must project, never refuse");
        assert_eq!(parsed[0].actor_id.as_deref(), Some("human:origin"));
        assert_eq!(parsed[1].actor_id.as_deref(), Some("ai:helper"));
        assert!(parsed[1].role.is_none() && parsed[1].label.is_none());
        // Advisory members of a non-string type are simply not display
        // text this view can show — never a refusal.
        assert_eq!(parsed[2].actor_id.as_deref(), Some("human:a"));
        assert!(parsed[2].role.is_none() && parsed[2].label.is_none());
        // Unbindable declarations: the verifier's grammar check flags
        // these; the view just reports there is no actor_id.
        assert!(parsed[3].actor_id.is_none());
        assert!(parsed[4].actor_id.is_none());
    }

    /// spec/manifest.md field rules: originator.label and created_at are
    /// advisory — a manifest omitting both still parses (chain-rules
    /// absent-advisory-manifest-members pins the full-pipeline outcome).
    #[test]
    fn manifest_parses_without_advisory_members() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).expect("unzip");
        let mut value: serde_json::Value =
            serde_json::from_slice(map.get("manifest.json").expect("manifest")).unwrap();
        value["originator"]
            .as_object_mut()
            .unwrap()
            .remove("label");
        value.as_object_mut().unwrap().remove("created_at");
        let manifest: Manifest = serde_json::from_value(value)
            .expect("advisory manifest members are optional in the typed view");
        assert!(manifest.originator.label.is_none());
        assert!(manifest.created_at.is_none());
    }

    #[test]
    fn untrusted_payload_fields_default_when_absent() {
        // Older capsules might predate the untrusted_payload_fields convention;
        // the field must default to empty rather than failing the parse. JSONL
        // is one event per line, so the test record is constructed on a single
        // line — `parse_chain_jsonl` splits on '\n'.
        let line = concat!(
            r#"{"seq":1,"event_id":"evt_001","actor":"human:alice","kind":"decision","#,
            r#""action":"submitted","target":"program.md","timestamp":"2026-01-01T00:00:00Z","#,
            r#""payload":{},"#,
            r#""prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","#,
            r#""hash":"0000000000000000000000000000000000000000000000000000000000000001"}"#,
            "\n",
        );
        let events = parse_chain_jsonl(line.as_bytes())
            .expect("parse must succeed without untrusted_payload_fields");
        assert_eq!(events.len(), 1);
        assert!(
            events[0].event.untrusted_payload_fields.is_empty(),
            "default for missing field must be empty Vec, got {:?}",
            events[0].event.untrusted_payload_fields
        );
        // The preserved tree must NOT invent the field: the hash recompute
        // canonicalises `raw`, and an event sealed without the field was
        // hashed without it.
        assert!(
            events[0].raw.get("untrusted_payload_fields").is_none(),
            "absent field must stay absent in the preserved tree"
        );
    }

    #[test]
    fn chain_jsonl_skips_blank_trailing_lines() {
        // Two events with a `\n\n` tail — second blank line must be skipped,
        // not parsed as an empty event.
        let mk = |seq: u64, hash: &str, prev: &str| -> String {
            format!(
                r#"{{"seq":{seq},"event_id":"evt_{seq:03}","actor":"a","kind":"k","action":"x","target":"t","timestamp":"2026-01-01T00:00:00Z","payload":{{}},"prev_hash":"{prev}","untrusted_payload_fields":[],"hash":"{hash}"}}"#
            )
        };
        let h1 = "1111111111111111111111111111111111111111111111111111111111111111";
        let h2 = "2222222222222222222222222222222222222222222222222222222222222222";
        let zero = "0".repeat(64);
        let mut s = String::new();
        s.push_str(&mk(1, h1, &zero));
        s.push('\n');
        s.push_str(&mk(2, h2, h1));
        s.push('\n');
        s.push('\n'); // extra blank trailing line

        let events = parse_chain_jsonl(s.as_bytes()).expect("parse");
        assert_eq!(
            events.len(),
            2,
            "blank trailing line must not produce an extra event"
        );
        assert_eq!(events[0].event.seq, 1);
        assert_eq!(events[1].event.seq, 2);
        assert_eq!(events[1].event.prev_hash, h1);
    }
}

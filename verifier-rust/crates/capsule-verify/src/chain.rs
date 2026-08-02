//! Chain walk + per-event hash recompute. Mirrors `verifyChain` and
//! `firstAndEntryHash` in `sdk-js/src/chain.js`.
//!
//! The chain commits to a sequence of events. Each event's `hash` is the
//! SHA-256 of `prev_hash_raw || JCS(event_minus_hash)`, where `prev_hash_raw`
//! is the previous event's `hash` decoded from hex (or 32 zero bytes for the
//! genesis case). The verifier walks the list, confirming `seq` is 1-based,
//! `prev_hash` chains correctly, and the recomputed `hash` matches the
//! stored value.
//!
//! Error message strings mirror the JS reference's `verifyChain` outputs so
//! that a verifier consumer can compare results across implementations.

use crate::crypto::{bytes_to_hex, hex_to_bytes, sha256};
use crate::jcs::jcs;
use crate::schemas::ParsedEvent;

/// Genesis previous-hash: 32 zero bytes.
const GENESIS_PREV: [u8; 32] = [0u8; 32];

/// One human-readable error from a chain walk. The message is prefixed with
/// the event sequence number to match the JS reference's error shape, which
/// reports `{ seq, message }` per error. Top-level callers concatenate as
/// `format!("seq {seq}: {message}")`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainErr {
    pub seq: u64,
    pub message: String,
}

impl ChainErr {
    /// Format as `"seq N: <message>"` for surface in `ChainCheck::errors`.
    pub fn into_string(self) -> String {
        format!("seq {}: {}", self.seq, self.message)
    }
}

/// Recompute the hash of a single event. Mirrors `hashEvent` in the JS SDK.
///
/// The event must NOT include a `hash` field — strip it before calling.
/// `prev_hash` must be 64-hex; the function does not validate the chain
/// position or that `prev_hash` matches the previous event. The caller (i.e.
/// [`verify_chain`]) is responsible for those structural checks.
///
/// Returns the 32-byte digest. On any input error (bad hex, wrong length),
/// returns `None`.
pub fn hash_event_value(event_minus_hash: &serde_json::Value) -> Option<[u8; 32]> {
    let prev_hash = event_minus_hash
        .as_object()?
        .get("prev_hash")?
        .as_str()?;
    if prev_hash.len() != 64 {
        return None;
    }
    let prev_raw = hex_to_bytes(prev_hash).ok()?;
    if prev_raw.len() != 32 {
        return None;
    }
    let canon = jcs(event_minus_hash);
    let mut input = Vec::with_capacity(prev_raw.len() + canon.len());
    input.extend_from_slice(&prev_raw);
    input.extend_from_slice(&canon);
    Some(sha256(&input))
}

/// Walk a slice of events, returning per-event errors (and a global ok bit).
///
/// Mirrors `verifyChain` in `sdk-js/src/chain.js`. The error messages here are
/// kept verbatim with the JS strings except for substitution syntax (Rust
/// `{}` vs JS template literal).
///
/// Structural checks (seq, prev_hash linkage, hash shape) read the typed
/// view; the hash recompute canonicalises the PRESERVED raw tree minus
/// `hash`, so unknown members an event carries are included exactly as the
/// signer hashed them — never a struct round-trip, which would drop them.
pub fn verify_chain(events: &[ParsedEvent]) -> Vec<ChainErr> {
    let mut errors: Vec<ChainErr> = Vec::new();
    let mut prev: [u8; 32] = GENESIS_PREV;

    for (i, parsed) in events.iter().enumerate() {
        let event = &parsed.event;
        let expected_seq = (i as u64) + 1;
        let seq_for_msg = if event.seq == 0 { expected_seq } else { event.seq };

        if event.seq != expected_seq {
            errors.push(ChainErr {
                seq: seq_for_msg,
                message: format!("seq {} expected {}", event.seq, expected_seq),
            });
        }

        if event.prev_hash.len() != 64 {
            errors.push(ChainErr {
                seq: seq_for_msg,
                message: "prev_hash missing or wrong length".to_string(),
            });
            continue;
        }

        let expected_prev_hex = bytes_to_hex(&prev);
        if event.prev_hash != expected_prev_hex {
            errors.push(ChainErr {
                seq: seq_for_msg,
                message: format!(
                    "prev_hash mismatch: got {}, expected {}",
                    event.prev_hash, expected_prev_hex
                ),
            });
        }

        if event.hash.len() != 64 {
            errors.push(ChainErr {
                seq: seq_for_msg,
                message: "hash missing or wrong length".to_string(),
            });
            continue;
        }

        // Recompute the hash. Strip `hash` from the PRESERVED raw tree,
        // then hash `prev_raw || JCS(rest)`. The raw tree (not the typed
        // struct) is the canonicalization input so unknown members and
        // absent optional fields round-trip exactly as sealed.
        let mut event_value = parsed.raw.clone();
        if let Some(map) = event_value.as_object_mut() {
            map.remove("hash");
        }
        // I-JSON acceptance boundary (spec/canonicalization.md). Reported as
        // its own error rather than folded into a hash mismatch, so an
        // out-of-range number reads as a canonicalization refusal instead of
        // looking like tampering.
        if let Err(message) = crate::jcs::check_ijson(&event_value) {
            errors.push(ChainErr {
                seq: seq_for_msg,
                message,
            });
            continue;
        }
        let recomputed = match hash_event_value(&event_value) {
            Some(h) => h,
            None => {
                errors.push(ChainErr {
                    seq: seq_for_msg,
                    message: "recompute failed: bad prev_hash".to_string(),
                });
                continue;
            }
        };
        let recomputed_hex = bytes_to_hex(&recomputed);
        if recomputed_hex != event.hash {
            errors.push(ChainErr {
                seq: seq_for_msg,
                message: format!(
                    "hash mismatch: stored {}, recomputed {}",
                    event.hash, recomputed_hex
                ),
            });
        }

        // Update prev for next iteration. Use the *stored* event.hash (not
        // the recomputed one) so subsequent prev_hash mismatches surface the
        // actual on-disk discrepancy, matching the JS behavior.
        match hex_to_bytes(&event.hash) {
            Ok(raw) if raw.len() == 32 => {
                prev.copy_from_slice(&raw);
            }
            _ => {
                // hash field has bad shape; the next event's prev_hash check
                // will fail naturally against zeroed bytes. Leave prev as-is
                // (it just keeps showing the previous good value).
            }
        }
    }

    errors
}

/// Return `(first_event_hash, entry_hash)` for non-empty event slices, or
/// `None` when empty. Mirrors `firstAndEntryHash` in the JS SDK except that
/// emptiness is reported via `Option` rather than a thrown error — the
/// top-level verifier already special-cases empty chains.
pub fn first_and_entry_hash(events: &[ParsedEvent]) -> Option<(&str, &str)> {
    let first = events.first()?;
    let last = events.last()?;
    Some((first.event.hash.as_str(), last.event.hash.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schemas::parse_chain_jsonl;
    use crate::test_support::clean_capsule_bytes;
    use crate::unpack_zip;

    #[test]
    fn verifies_clean_chain() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).unwrap();
        let jsonl = map.get("chain/events.jsonl").unwrap();
        let events = parse_chain_jsonl(jsonl).unwrap();

        let errors = verify_chain(&events);
        assert!(
            errors.is_empty(),
            "clean chain must verify cleanly, got: {errors:?}"
        );
    }

    #[test]
    fn first_and_entry_hash_match_envelope() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).unwrap();
        let jsonl = map.get("chain/events.jsonl").unwrap();
        let events = parse_chain_jsonl(jsonl).unwrap();

        let (first, last) = first_and_entry_hash(&events).expect("non-empty chain");
        assert_eq!(first, events[0].event.hash);
        assert_eq!(last, events.last().unwrap().event.hash);
    }

    #[test]
    fn first_and_entry_hash_empty() {
        let events: Vec<ParsedEvent> = Vec::new();
        assert!(first_and_entry_hash(&events).is_none());
    }

    #[test]
    fn detects_seq_skew() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).unwrap();
        let jsonl = map.get("chain/events.jsonl").unwrap();
        let mut events = parse_chain_jsonl(jsonl).unwrap();
        // Bump first event's seq from 1 → 99 in both the typed view and the
        // preserved tree (as an on-disk mutation would). The hash recompute
        // will also fail (the canonical bytes change), so we expect AT LEAST
        // a seq error; matching JS, both "seq" and "hash mismatch" lines
        // show up.
        events[0].event.seq = 99;
        events[0].raw["seq"] = serde_json::json!(99);
        let errors = verify_chain(&events);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.message.starts_with("seq 99 expected 1")));
        assert!(errors.iter().any(|e| e.message.starts_with("hash mismatch")));
    }

    #[test]
    fn rejects_event_payload_outside_ijson_acceptance_boundary() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).unwrap();
        let jsonl = map.get("chain/events.jsonl").unwrap();
        let mut events = parse_chain_jsonl(jsonl).unwrap();
        // A nanosecond timestamp: plausible payload, 19 digits, > 2^53 - 1.
        events[0].raw["payload"] = serde_json::json!({ "ts_ns": 1_700_000_000_000_000_000u64 });
        let errors = verify_chain(&events);
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("integer outside IEEE-754 exact range")),
            "expected an I-JSON acceptance error, got: {errors:?}"
        );
        assert!(
            !errors.iter().any(|e| e.message.starts_with("hash mismatch")),
            "a canonicalization refusal must not also be reported as tampering: {errors:?}"
        );
    }

    #[test]
    fn detects_hash_tampering() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).unwrap();
        let jsonl = map.get("chain/events.jsonl").unwrap();
        let mut events = parse_chain_jsonl(jsonl).unwrap();
        // Replace the first event's payload with an empty object in the
        // PRESERVED tree — the tree is the hash recompute's input, matching
        // an on-disk mutation. The chain hash MUST then fail to recompute.
        events[0].raw["payload"] = serde_json::json!({});
        let errors = verify_chain(&events);
        assert!(
            errors.iter().any(|e| e.message.starts_with("hash mismatch")),
            "expected a hash-mismatch error, got: {errors:?}"
        );
    }

    /// The hash preimage must be rebuilt from the ORIGINAL stored line,
    /// never from a re-serialization of the typed [`crate::schemas::ChainEvent`].
    /// `untrusted_payload_fields` carries `#[serde(default)]` and no
    /// `skip_serializing_if`, so a struct round-trip re-emits an event whose
    /// stored bytes omit the key with `"untrusted_payload_fields":[]`
    /// injected — different JCS bytes, and a spurious hash mismatch on a
    /// chain that is intact (amendment M06: such events pass the JS, Python
    /// and Swift lanes). Regression pin for F41; the recompute reads
    /// `ParsedEvent::raw`.
    #[test]
    fn recomputes_hash_from_stored_line_not_typed_struct() {
        // Stored event bytes: note the absence of `untrusted_payload_fields`.
        let mut event = serde_json::json!({
            "seq": 1,
            "event_id": "evt_001",
            "actor": "system:host",
            "kind": "observation",
            "action": "session_ended",
            "target": "capsule",
            "timestamp": "2026-01-01T00:00:00Z",
            "payload": {},
            "prev_hash": "0".repeat(64)
        });
        let hash = bytes_to_hex(&hash_event_value(&event).expect("event is hashable"));
        event["hash"] = serde_json::Value::String(hash);
        let line = format!("{}\n", serde_json::to_string(&event).expect("serialize"));

        let events = parse_chain_jsonl(line.as_bytes()).expect("chain parses");
        let errors = verify_chain(&events);
        assert!(
            errors.is_empty(),
            "an event whose stored bytes omit untrusted_payload_fields must still \
             verify; got: {errors:?}"
        );
    }

    /// An unknown member added to an event's preserved tree changes the
    /// recomputed hash — proving unknown members are canonicalised, i.e.
    /// they sit inside the integrity envelope rather than being dropped.
    #[test]
    fn unknown_member_mutation_breaks_hash() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).unwrap();
        let jsonl = map.get("chain/events.jsonl").unwrap();
        let mut events = parse_chain_jsonl(jsonl).unwrap();
        assert!(verify_chain(&events).is_empty(), "clean chain must walk");

        events[0].raw["x-acme-review-ticket"] = serde_json::json!("ACME-9999");
        let errors = verify_chain(&events);
        assert!(
            errors.iter().any(|e| e.message.starts_with("hash mismatch")),
            "post-seal unknown-member injection must break the event hash; got: {errors:?}"
        );
    }
}

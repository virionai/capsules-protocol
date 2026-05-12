//! Chain walk + per-event hash recompute. Mirrors `verifyChain` and
//! `firstAndEntryHash` in `sdk/src/chain.js`.
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
use crate::schemas::ChainEvent;

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
/// Mirrors `verifyChain` in `sdk/src/chain.js`. The error messages here are
/// kept verbatim with the JS strings except for substitution syntax (Rust
/// `{}` vs JS template literal).
pub fn verify_chain(events: &[ChainEvent]) -> Vec<ChainErr> {
    let mut errors: Vec<ChainErr> = Vec::new();
    let mut prev: [u8; 32] = GENESIS_PREV;

    for (i, event) in events.iter().enumerate() {
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

        // Recompute the hash. Strip `hash` from the serialized form, then
        // hash `prev_raw || JCS(rest)`.
        let mut event_value = match serde_json::to_value(event) {
            Ok(v) => v,
            Err(e) => {
                errors.push(ChainErr {
                    seq: seq_for_msg,
                    message: format!("recompute failed: {e}"),
                });
                continue;
            }
        };
        if let Some(map) = event_value.as_object_mut() {
            map.remove("hash");
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
pub fn first_and_entry_hash(events: &[ChainEvent]) -> Option<(&str, &str)> {
    let first = events.first()?;
    let last = events.last()?;
    Some((first.hash.as_str(), last.hash.as_str()))
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
        assert_eq!(first, events[0].hash);
        assert_eq!(last, events.last().unwrap().hash);
    }

    #[test]
    fn first_and_entry_hash_empty() {
        let events: Vec<ChainEvent> = Vec::new();
        assert!(first_and_entry_hash(&events).is_none());
    }

    #[test]
    fn detects_seq_skew() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).unwrap();
        let jsonl = map.get("chain/events.jsonl").unwrap();
        let mut events = parse_chain_jsonl(jsonl).unwrap();
        // Bump first event's seq from 1 → 99. The hash recompute will also
        // fail (the canonical bytes change), so we expect AT LEAST a seq
        // error; matching JS, both "seq" and "hash mismatch" lines show up.
        events[0].seq = 99;
        let errors = verify_chain(&events);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.message.starts_with("seq 99 expected 1")));
    }

    #[test]
    fn detects_hash_tampering() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).unwrap();
        let jsonl = map.get("chain/events.jsonl").unwrap();
        let mut events = parse_chain_jsonl(jsonl).unwrap();
        // Mutate one byte of the first event's payload by replacing the
        // payload entirely with an empty object. The chain hash MUST then
        // fail to recompute.
        events[0].payload = serde_json::json!({});
        let errors = verify_chain(&events);
        assert!(
            errors.iter().any(|e| e.message.starts_with("hash mismatch")),
            "expected a hash-mismatch error, got: {errors:?}"
        );
    }
}

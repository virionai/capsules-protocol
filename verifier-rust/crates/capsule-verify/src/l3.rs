//! L3 verification — decryption + inner plain-capsule verification.
//!
//! Promotes an encrypted-outer capsule from L2 to L3 by decrypting
//! `content.enc` (ChaCha20-Poly1305 via the recipient's X25519
//! private key + HKDF-SHA256 derived wrap key), opening the inner
//! ZIP, and running full plain-capsule verification on it:
//!
//! - inner format/version
//! - inner `capsule_id` derivation (against inner manifest + inner envelope)
//! - inner `manifest_hash` recompute (against inner envelope claim)
//! - inner `content_index` recompute (per-file SHA + index_hash rollup)
//! - inner envelope Ed25519 signature(s) over canonical inner-envelope-minus-signers
//! - inner chain walk (event hashes + prev_hash linkage)
//! - five cross-checks against the outer envelope's anchors
//!
//! Any failure surfaces via the existing `VerifyResult` fields
//! (`errors`, `chain`, `inner_envelope`, `inner_content_index`),
//! never panics, and leaves `level == "L2"` if the L3 attempt fails
//! before reaching the upgrade point.

use std::collections::BTreeMap;

use crate::crypto::hex_to_bytes;
use crate::decrypt::decrypt_inner_zip;
use crate::manifest::{compute_capsule_id, content_index_exclusions, manifest_hash};
use crate::schemas::{parse_chain_jsonl, Envelope, Manifest, ParsedEvent};
use crate::verifier::{
    anchor_or_null, chain_walk_into, check_signer_set, originator_binding_error,
    verify_content_index, verify_envelope_signatures, ChainCheck, ContentIndexCheck,
    EnvelopeCheck, TopError, TopErrorCategory, TopErrorScope, VerifyOptions,
};
use crate::zip_reader::unpack_zip;

/// L3 attempt: decrypt the inner ZIP, parse the inner manifest/envelope/chain,
/// walk the inner chain in place of the L2 chain skip, cross-check inner
/// anchors against the outer envelope, verify inner envelope signatures
/// using the same code path as the outer, and upgrade `level` to "L3" iff
/// the decrypt + inner parse succeeded.
///
/// Failure modes (any of which keep `*level == "L2"` and push an Encryption
/// error):
///   - decryption itself fails (wrong key, tampered blob, missing metadata, ...)
///   - the decrypted inner bytes do not unpack as a STORED-only ZIP
///   - the inner ZIP is missing manifest.json / envelope.json / chain
///
/// On full inner-parse success, we upgrade to "L3" even if the cross-checks
/// or inner-envelope signatures surface errors — the level reflects "we
/// walked the inner", not "the inner was clean". The caller's overall `ok`
/// still goes false when ChainAnchor errors or inner-envelope signature
/// failures are present.
///
/// `inner_envelope_check` and `inner_content_index_check` are set BEFORE
/// the cross-check error pushes so that even if the cross-checks fail, the
/// inner-envelope and inner content_index verification still surface in
/// `result.inner_envelope` / `result.inner_content_index`. Both remain
/// `None` when the L3 path returns early before reaching the inner schemas
/// (decryption or inner unpack/schemas failure).
///
/// Inner manifest_hash mismatches are surfaced via the top-level `errors`
/// vector with `category: ManifestHash` and message prefix `"L3 inner: "`,
/// mirroring the way outer manifest_hash mismatches are surfaced today.
#[allow(clippy::too_many_arguments)]
pub(crate) fn l3_attempt_decrypt_and_verify(
    recipient_private_key: &[u8; 32],
    outer_envelope: &Envelope,
    outer_manifest: &Manifest,
    outer_files: &BTreeMap<String, Vec<u8>>,
    options: &VerifyOptions,
    chain_check: &mut ChainCheck,
    inner_envelope_check: &mut Option<EnvelopeCheck>,
    inner_content_index_check: &mut Option<ContentIndexCheck>,
    errors: &mut Vec<TopError>,
    notes: &mut Vec<String>,
    level: &mut String,
) {
    // Step 1: decrypt content.enc.
    let inner_zip_bytes = match decrypt_inner_zip(
        outer_envelope,
        outer_manifest,
        outer_files,
        recipient_private_key,
    ) {
        Ok(bytes) => bytes,
        Err(e) => {
            errors.push(TopError::inner(
                TopErrorCategory::Encryption,
                format!("L3: decryption failed: {e}"),
            ));
            return;
        }
    };

    // Step 2: unpack the inner ZIP.
    let inner_files = match unpack_zip(&inner_zip_bytes) {
        Ok(map) => map,
        Err(e) => {
            errors.push(TopError::inner(
                TopErrorCategory::Encryption,
                format!("L3: decrypted inner ZIP failed to unpack: {e}"),
            ));
            return;
        }
    };

    // Step 3: parse inner manifest, envelope, chain. All three are required;
    // any missing or unparseable one is a single Encryption error so the user
    // sees a concise root cause.
    //
    // Same preserved-tree-then-view parse as the outer pipeline: the Value
    // trees are the hashing inputs (unknown members included); the typed
    // structs are field-access views projected from the same parse.
    let inner_manifest_value: serde_json::Value = match inner_files.get("manifest.json") {
        Some(b) => match serde_json::from_slice(b) {
            Ok(v) => v,
            Err(e) => {
                errors.push(TopError::inner(
                    TopErrorCategory::Encryption,
                    format!("L3: inner manifest.json parse failed: {e}"),
                ));
                return;
            }
        },
        None => {
            errors.push(TopError::inner(
                TopErrorCategory::Encryption,
                "L3: inner ZIP missing manifest.json",
            ));
            return;
        }
    };
    let inner_manifest: Manifest = match serde_json::from_value(inner_manifest_value.clone()) {
        Ok(m) => m,
        Err(e) => {
            errors.push(TopError::inner(
                TopErrorCategory::Encryption,
                format!("L3: inner manifest.json parse failed: {e}"),
            ));
            return;
        }
    };
    let inner_envelope_value: serde_json::Value =
        match inner_files.get("provenance/envelope.json") {
            Some(b) => match serde_json::from_slice(b) {
                Ok(v) => v,
                Err(e) => {
                    errors.push(TopError::inner(
                        TopErrorCategory::Encryption,
                        format!("L3: inner provenance/envelope.json parse failed: {e}"),
                    ));
                    return;
                }
            },
            None => {
                errors.push(TopError::inner(
                    TopErrorCategory::Encryption,
                    "L3: inner ZIP missing provenance/envelope.json",
                ));
                return;
            }
        };
    let inner_envelope: Envelope = match serde_json::from_value(inner_envelope_value.clone()) {
        Ok(e) => e,
        Err(e) => {
            errors.push(TopError::inner(
                TopErrorCategory::Encryption,
                format!("L3: inner provenance/envelope.json parse failed: {e}"),
            ));
            return;
        }
    };
    let inner_events: Vec<ParsedEvent> = match inner_files.get("chain/events.jsonl") {
        Some(b) => match parse_chain_jsonl(b) {
            Ok(events) => events,
            Err(e) => {
                errors.push(TopError::inner(
                    TopErrorCategory::Encryption,
                    format!("L3: inner chain parse failed: {e}"),
                ));
                return;
            }
        },
        None => {
            errors.push(TopError::inner(
                TopErrorCategory::Encryption,
                "L3: inner ZIP missing chain/events.jsonl",
            ));
            return;
        }
    };

    // Step 3a-i (v0.5): inner format/version check. Mirrors the outer
    // pipeline's step 3 — `inner_manifest.format.version` and
    // `inner_envelope.version` must both be exactly "0.6". Failures surface
    // via top-level `errors` with `category: FormatVersion` and the
    // `"L3 inner: "` message prefix so callers can disambiguate via
    // substring match on the message.
    if inner_manifest.format.version != "0.6" {
        errors.push(TopError::inner(
            TopErrorCategory::FormatVersion,
            format!(
                "L3 inner: unsupported manifest format.version: {}",
                inner_manifest.format.version
            ),
        ));
    }
    if inner_envelope.version != "0.6" {
        errors.push(TopError::inner(
            TopErrorCategory::FormatVersion,
            format!(
                "L3 inner: unsupported envelope version: {}",
                inner_envelope.version
            ),
        ));
    }

    // Step 3a-ii (v0.5): inner capsule_id derivation. Mirrors the outer
    // pipeline's step 5 — recompute `compute_capsule_id(originator_pubkey,
    // first_event_hash)` and compare to both `inner_manifest.id` and
    // `inner_envelope.capsule_id`. Each mismatch is a separate top-level
    // error tagged `CapsuleId` with the `"L3 inner: "` prefix.
    match hex_to_bytes(&inner_manifest.originator.public_key) {
        Ok(pk) if pk.len() == 32 => {
            match compute_capsule_id(&pk, inner_manifest.first_event_hash.as_deref()) {
                Ok(expected_id) => {
                    if expected_id != inner_manifest.id {
                        errors.push(TopError::inner(
                            TopErrorCategory::CapsuleId,
                            format!(
                                "L3 inner: manifest.id mismatch: stored {}, expected {}",
                                inner_manifest.id, expected_id
                            ),
                        ));
                    }
                    if expected_id != inner_envelope.capsule_id {
                        errors.push(TopError::inner(
                            TopErrorCategory::CapsuleId,
                            format!(
                                "L3 inner: envelope.capsule_id mismatch: {} vs derived {}",
                                inner_envelope.capsule_id, expected_id
                            ),
                        ));
                    }
                }
                Err(e) => {
                    errors.push(TopError::inner(
                        TopErrorCategory::CapsuleId,
                        format!("L3 inner: capsule_id derivation failed: {e}"),
                    ));
                }
            }
        }
        Ok(_) => {
            errors.push(TopError::inner(
                TopErrorCategory::CapsuleId,
                "L3 inner: manifest.originator.public_key must be 32 bytes (64 hex)",
            ));
        }
        Err(e) => {
            errors.push(TopError::inner(
                TopErrorCategory::Malformed,
                format!("L3 inner: manifest.originator.public_key hex decode failed: {e}"),
            ));
        }
    }

    // Step 3b: verify the inner envelope's signers using the same code path
    // as the outer envelope. We set `inner_envelope_check` BEFORE Step 4 so
    // that even if the chain walk or cross-checks push errors, the
    // inner-envelope verification still surfaces in `result.inner_envelope`.
    let inner_check =
        verify_envelope_signatures(&inner_envelope, &inner_envelope_value, &options.allowlist);
    // Inner signer-set invariants, mirroring outer steps 10-10c with the
    // "L3 inner: " message prefix. Inner commitment absence is reported
    // (not failed) by the signer-set semantics; inner duplicate signers
    // and a broken inner originator binding fail closed.
    if let Some(note) = inner_check.note.as_ref() {
        if note.starts_with("duplicate signer entry") {
            errors.push(TopError::inner(
                TopErrorCategory::SignerSet,
                format!("L3 inner: {note}"),
            ));
        }
    }
    let inner_signer_set = check_signer_set(&inner_manifest_value, &inner_envelope_value);
    for e in &inner_signer_set.errors {
        errors.push(TopError::inner(
            TopErrorCategory::SignerSet,
            format!("L3 inner: {e}"),
        ));
    }
    if let Some(msg) =
        originator_binding_error(&inner_manifest.originator.public_key, &inner_check.signers)
    {
        errors.push(TopError::inner(
            TopErrorCategory::OriginatorBinding,
            format!("L3 inner: {msg}"),
        ));
    }
    *inner_envelope_check = Some(inner_check);

    // Step 3c (v0.5): recompute the inner manifest_hash and compare to the
    // inner envelope's claim. Symmetrical with the outer manifest_hash check
    // (verify_capsule step 6) — outer goes via top-level `errors` with
    // `category: ManifestHash`, and we mirror that for inner with the
    // `"L3 inner: "` message prefix so the renderer can disambiguate via
    // substring match on the message.
    let recomputed_inner_manifest_hash = manifest_hash(&inner_manifest_value);
    if recomputed_inner_manifest_hash != inner_envelope.manifest_hash {
        errors.push(TopError::inner(
            TopErrorCategory::ManifestHash,
            format!(
                "L3 inner: envelope.manifest_hash mismatch: stored {} vs recomputed {}",
                inner_envelope.manifest_hash, recomputed_inner_manifest_hash,
            ),
        ));
    }

    // Step 3d (v0.5): recompute the inner content_index using the shared
    // helper, comparing per-file SHA-256s and the rollup index_hash against
    // the inner manifest and the inner envelope. Set `inner_content_index_check`
    // BEFORE Step 4 so even cross-check failures don't suppress the inner
    // content_index outcome in `result.inner_content_index`.
    // The decrypted inner capsule is plain (cipher "none"); key the exclusion
    // off its own envelope so any stray inner content.enc is indexed.
    let inner_ci = verify_content_index(
        &inner_files,
        &inner_manifest,
        Some(&inner_envelope.content_index_hash),
        content_index_exclusions(inner_envelope.cipher != "none"),
    );
    *inner_content_index_check = Some(inner_ci);

    // Step 4: replace the deferred chain skip with a real walk over the
    // inner chain. `chain_walk_into` reuses the per-event verifier and
    // emits ChainAnchor cross-checks against the *inner* envelope.
    let mut new_chain = ChainCheck::default();
    chain_walk_into(
        &inner_events,
        &inner_manifest,
        &inner_envelope,
        &mut new_chain,
        errors,
        notes,
        TopErrorScope::Inner,
    );
    let walked_empty = new_chain.note.is_some();
    *chain_check = new_chain;
    if !walked_empty {
        // The chain was actually walked — clear the L2 deferred note.
        // (A zero-event inner chain keeps its own empty-chain note: the
        // honest report that nothing was walked.)
        chain_check.note = None;
    }

    // Step 5: L3 cross-checks: inner manifest/envelope anchors must match
    // the outer envelope. Each mismatch is its own ChainAnchor error so
    // the renderer can attribute the failure precisely.
    if inner_manifest.id != outer_envelope.capsule_id {
        errors.push(TopError::inner(
            TopErrorCategory::ChainAnchor,
            format!(
                "L3: inner.capsule_id mismatch: inner {}, outer {}",
                inner_manifest.id, outer_envelope.capsule_id
            ),
        ));
    }
    if inner_envelope.first_event_hash != outer_envelope.first_event_hash {
        errors.push(TopError::inner(
            TopErrorCategory::ChainAnchor,
            format!(
                "L3: inner.first_event_hash mismatch: inner {}, outer {}",
                anchor_or_null(&inner_envelope.first_event_hash),
                anchor_or_null(&outer_envelope.first_event_hash)
            ),
        ));
    }
    if inner_envelope.entry_hash != outer_envelope.entry_hash {
        errors.push(TopError::inner(
            TopErrorCategory::ChainAnchor,
            format!(
                "L3: inner.entry_hash mismatch: inner {}, outer {}",
                anchor_or_null(&inner_envelope.entry_hash),
                anchor_or_null(&outer_envelope.entry_hash)
            ),
        ));
    }
    // Also cross-check inner first/entry events against the inner envelope
    // anchors — guards against an inner envelope whose anchors disagree with
    // its own chain. (The zero-event inner case is handled by
    // `chain_walk_into` above: anchors must be null, fail-closed.)
    if let (Some(first), Some(last)) = (inner_events.first(), inner_events.last()) {
        if inner_envelope.first_event_hash.as_deref() != Some(first.event.hash.as_str()) {
            errors.push(TopError::inner(
                TopErrorCategory::ChainAnchor,
                format!(
                    "L3: inner first event hash mismatch with inner envelope: chain {}, inner envelope {}",
                    first.event.hash,
                    anchor_or_null(&inner_envelope.first_event_hash)
                ),
            ));
        }
        if inner_envelope.entry_hash.as_deref() != Some(last.event.hash.as_str()) {
            errors.push(TopError::inner(
                TopErrorCategory::ChainAnchor,
                format!(
                    "L3: inner entry hash mismatch with inner envelope: chain {}, inner envelope {}",
                    last.event.hash,
                    anchor_or_null(&inner_envelope.entry_hash)
                ),
            ));
        }
    }

    // Decrypt + inner parse + chain walk all succeeded — upgrade to L3.
    // ChainAnchor mismatches surfaced above will still flip the overall
    // `ok` to false, but the level has earned the upgrade.
    *level = "L3".to_string();
}

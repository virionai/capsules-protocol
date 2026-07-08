//! Top-level verifier: orchestrates the chain, content-index, and envelope
//! checks against the on-disk artifacts in a Capsule ZIP. Mirrors
//! `verifyCapsule` in `sdk-js/src/verifier.js`.
//!
//! Behavior summary (in evaluation order):
//!   1. parse the ZIP
//!   2. extract `manifest.json` and `provenance/envelope.json`
//!   3. format / version checks
//!   4. cipher whitelist check
//!   5. capsule_id derivation
//!   6. manifest_hash check
//!   7. content_index check
//!   8. encryption-shape check (plain vs encrypted-outer)
//!   9. chain walk + first/entry hash checks (skipped on encrypted outers
//!      — chain commits are L3, not L2)
//!  10. envelope signature verification
//!  11. trusted_signer_count
//!  12. advisory note when no allowlist
//!  13. final ok = no top-level errors AND chain.ok AND content_index.ok AND envelope.ok
//!
//! Encrypted vs plain capsules: at L2 we verify the *outer* envelope only.
//! For an encrypted capsule that means: cipher is on the whitelist,
//! `content.enc` is present, and `envelope.encrypted_blob_hash` matches
//! `sha256(content.enc)`. The chain itself is sealed inside the encrypted
//! inner and is therefore not walked at L2 — `ChainCheck::note` records
//! that the chain check was deferred to L3 rather than failed.
//!
//! `verify_capsule` is total: any malformed input — invalid ZIP, missing
//! files, bad JSON, bad hex — surfaces as a top-level error rather than
//! a panic.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::chain::{first_and_entry_hash, verify_chain};
use crate::crypto::{hex_to_bytes, sha256_hex};
#[cfg(test)]
use crate::decrypt::decrypt_inner_zip;
use crate::envelope::verify_signatures;
use crate::l3::l3_attempt_decrypt_and_verify;
use crate::manifest::{
    build_content_index, compute_capsule_id, content_index_exclusions, manifest_hash,
};
use crate::schemas::{parse_chain_jsonl, ChainEvent, Envelope, Manifest};
use crate::zip_reader::unpack_zip;

/// Ciphers this verifier accepts in `envelope.cipher`.
///
/// `"none"` is the plain capsule case; `"ChaCha20-Poly1305"` is the only AEAD
/// scheme defined for v0.6 encrypted capsules. Any other value (including
/// reserved-but-not-implemented names like `"AES-256-GCM"`) is a hard
/// rejection — adding a cipher is a v0.7 schema change. Matches the
/// `envelope.md` cipher enum.
const SUPPORTED_CIPHERS: &[&str] = &["none", "ChaCha20-Poly1305"];

/// Coarse category for a top-level verifier error. Each category maps to
/// a single rendered section in the CLI's plain output and to a stable
/// JSON value so structured consumers can branch on the kind of failure
/// without parsing free-form English.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TopErrorCategory {
    /// `manifest.format.version` or `envelope.version` not "0.6"
    FormatVersion,
    /// `manifest.id` / `envelope.capsule_id` mismatch with derived value
    CapsuleId,
    /// `manifest_hash` (envelope vs recomputed)
    ManifestHash,
    /// chain cross-checks vs envelope (first_event_hash / entry_hash)
    ChainAnchor,
    /// cipher / encrypted-blob inconsistencies: unsupported cipher,
    /// `envelope.encrypted_blob_hash` mismatch with the recomputed
    /// `sha256(content.enc)`, or encrypted blob present with cipher='none'
    /// (and the symmetric plain-side checks).
    Encryption,
    /// container parse / json parse / hex decode failures
    Malformed,
}

/// Which envelope a `TopError` arose from. Lets JSON consumers branch on
/// "outer pipeline" vs "L3 inner verification" without substring-matching
/// the free-form `message` for the `"L3 inner: "` prefix. The default is
/// `Outer`, which keeps `#[serde(default)]` deserialization of v0.3-v0.5
/// JSON (which never carried this field) round-trip-equivalent to the
/// pre-v0.6 shape.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TopErrorScope {
    /// Errors arising from the outer (or only) envelope and its files.
    /// All v0.1-v0.5 outer-pipeline errors carry this scope.
    #[default]
    Outer,
    /// Errors arising from L3 inner verification — decryption, inner
    /// envelope/manifest/chain parse, inner-side recomputes, cross-checks
    /// against the outer envelope.
    Inner,
}

/// One categorized top-level error. `message` is the same free-form
/// English string the verifier always produced; `category` is the
/// stable, machine-readable kind; `scope` distinguishes outer-pipeline
/// failures from L3 inner-verification failures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopError {
    pub category: TopErrorCategory,
    /// Outer envelope vs L3 inner envelope. `#[serde(default)]` makes the
    /// field backward-compatible: v0.3-v0.5 JSON without a `scope` key
    /// deserializes as `scope: Outer`, which matches pre-v0.6 semantics
    /// (every error was outer-pipeline).
    #[serde(default)]
    pub scope: TopErrorScope,
    pub message: String,
}

impl TopError {
    /// Construct a new outer-scope error. Used by every call site in the
    /// outer pipeline (`verifier.rs`) and by `chain_walk_into` when called
    /// against the outer envelope.
    pub(crate) fn outer(category: TopErrorCategory, message: impl Into<String>) -> Self {
        Self {
            category,
            scope: TopErrorScope::Outer,
            message: message.into(),
        }
    }

    /// Construct a new inner-scope error. Used by every L3 call site
    /// (`l3.rs`) — decrypt/parse failures, inner-side recomputes
    /// (format/version, `capsule_id`, `manifest_hash`), inner cross-checks
    /// against the outer envelope, and the inner chain walk.
    pub(crate) fn inner(category: TopErrorCategory, message: impl Into<String>) -> Self {
        Self {
            category,
            scope: TopErrorScope::Inner,
            message: message.into(),
        }
    }
}

impl fmt::Display for TopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Delegate to the message so old log patterns keep working.
        f.write_str(&self.message)
    }
}

/// Caller-supplied verification configuration.
#[derive(Debug, Default, Clone)]
pub struct VerifyOptions {
    /// Trusted Ed25519 public keys (lowercase hex, 64 chars). A signer is
    /// marked `trusted` only when its key appears here AND its signature
    /// verifies. An empty allowlist surfaces an advisory note in
    /// [`VerifyResult::notes`].
    pub allowlist: Vec<String>,
    /// Recipient's X25519 32-byte secret. When `Some` and the capsule is
    /// encrypted, the verifier will decrypt `content.enc`, parse the inner
    /// ZIP, walk the inner chain, and cross-check inner anchors against the
    /// outer envelope (L3). When `None`, the v0.2 L2 behavior is preserved
    /// exactly. When `Some` but the capsule is plain, the flag is silently
    /// ignored — there's nothing to decrypt.
    pub recipient_private_key: Option<[u8; 32]>,
}

/// Top-level verifier result.
///
/// `ok` is `true` only when every embedded check passed AND the top-level
/// `errors` vector is empty. Callers that want fine-grained error display
/// can iterate the per-section structs.
///
/// `capsule_id` and `signed_at` are surfaced from the parsed manifest and
/// envelope respectively for display and JSON consumers. They are empty
/// strings when manifest/envelope parsing fails (early-return paths).
///
/// `inner_envelope` is `Some` only when L3 verification reached the inner
/// envelope (i.e. decryption succeeded, the inner ZIP unpacked, and the
/// inner envelope JSON parsed). It is `None` for plain capsules, for
/// L2-only paths (no recipient key), and for L3 paths that failed before
/// reaching the inner envelope (decrypt failure / inner ZIP unpack failure
/// / inner schemas parse failure). `Option<EnvelopeCheck>` serializes as
/// `null` when `None`, which is forward-compatible with v0.3 JSON
/// consumers that did not have this field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    pub ok: bool,
    pub level: String,
    pub capsule_id: String,
    pub signed_at: String,
    pub errors: Vec<TopError>,
    pub chain: ChainCheck,
    pub content_index: ContentIndexCheck,
    pub envelope: EnvelopeCheck,
    /// Inner envelope signature check, populated when L3 verification ran
    /// and the inner envelope was successfully parsed. None for plain
    /// capsules, L2-only paths (no recipient key), or when L3 failed
    /// before reaching the inner envelope (decrypt failure / inner ZIP
    /// unpack failure / inner schemas parse failure).
    pub inner_envelope: Option<EnvelopeCheck>,
    /// Inner content_index check, populated when L3 verification ran and
    /// the inner ZIP was successfully unpacked + parsed. None for plain
    /// capsules, L2-only paths (no recipient key), or when L3 failed
    /// before reaching the inner content_index step (decrypt failure /
    /// inner ZIP unpack failure / inner schemas parse failure). Mirrors
    /// `inner_envelope` for visual symmetry — see also
    /// [`VerifyResult::inner_envelope`].
    pub inner_content_index: Option<ContentIndexCheck>,
    /// Number of *outer-envelope* signers whose signature verifies AND whose
    /// public key appears in the caller-supplied allowlist. Inner-envelope
    /// trust is reported separately on `inner_envelope.signers[].trusted` —
    /// callers wanting a combined total can sum the two.
    pub trusted_signer_count: usize,
    pub notes: Vec<String>,
}

/// Per-event chain walk results.
///
/// `note` is `None` for plain capsules (the chain was actually walked).
/// On encrypted outers it is `Some("deferred to L3 (encrypted outer)")` to
/// signal that the chain check was *skipped* at L2 by design — the chain
/// commits to bytes inside the encrypted inner, which only L3 can see —
/// rather than failed. The CLI renders the line with `[\u{2713}]` (PASS)
/// when `note.is_some()`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ChainCheck {
    pub ok: bool,
    pub errors: Vec<String>,
    pub event_count: usize,
    pub note: Option<String>,
}

/// Per-file and aggregate content_index results.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ContentIndexCheck {
    pub ok: bool,
    pub errors: Vec<String>,
}

/// Aggregate envelope-signature results.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EnvelopeCheck {
    pub ok: bool,
    pub signers: Vec<SignerOutcome>,
    pub note: Option<String>,
}

/// One signer's per-key outcome. `trusted` is `true` only when the
/// signature verifies AND the public key is on the allowlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerOutcome {
    pub role: String,
    pub public_key: String,
    pub valid: bool,
    pub trusted: bool,
}

/// Run the full L2 verification pipeline against a capsule's raw bytes.
///
/// This function NEVER panics on input bytes. Any malformed ZIP, JSON,
/// hex, or missing file surfaces as a top-level error in
/// `VerifyResult::errors` with `ok = false`.
pub fn verify_capsule(bytes: &[u8], options: &VerifyOptions) -> VerifyResult {
    let mut errors: Vec<TopError> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut chain_check = ChainCheck::default();
    let mut content_index_check = ContentIndexCheck::default();
    let mut envelope_check = EnvelopeCheck::default();
    // Populated only on the L3-success path, when the inner envelope was
    // successfully parsed. Stays `None` for plain capsules, L2-only paths,
    // and L3 paths that fail before the inner envelope is reached.
    let mut inner_envelope_check: Option<EnvelopeCheck> = None;
    // Populated only on the L3-success path, after the inner manifest +
    // inner files are parsed and the inner content_index has been
    // recomputed. Stays `None` for the same reasons as `inner_envelope_check`.
    let mut inner_content_index_check: Option<ContentIndexCheck> = None;
    // `level` starts at "L2" and is upgraded to "L3" only after a fully
    // successful inner decrypt + parse + chain walk. Any L3 step that fails
    // surfaces an Encryption error and leaves `level` at "L2".
    let mut level = "L2".to_string();

    // ---- (1) parse the ZIP ----------------------------------------------
    let files: BTreeMap<String, Vec<u8>> = match unpack_zip(bytes) {
        Ok(f) => f,
        Err(e) => {
            // Cannot proceed — return early with a single top-level error.
            errors.push(TopError::outer(TopErrorCategory::Malformed, e.to_string()));
            return assemble_result(
                errors,
                notes,
                chain_check,
                content_index_check,
                envelope_check,
                None,
                None,
                options.allowlist.is_empty(),
                String::new(),
                String::new(),
                level,
            );
        }
    };

    // ---- (2) extract manifest & envelope --------------------------------
    let manifest_bytes = match files.get("manifest.json") {
        Some(b) => b,
        None => {
            errors.push(TopError::outer(
                TopErrorCategory::Malformed,
                "missing manifest.json",
            ));
            return assemble_result(
                errors,
                notes,
                chain_check,
                content_index_check,
                envelope_check,
                None,
                None,
                options.allowlist.is_empty(),
                String::new(),
                String::new(),
                level,
            );
        }
    };
    let manifest: Manifest = match serde_json::from_slice(manifest_bytes) {
        Ok(m) => m,
        Err(e) => {
            errors.push(TopError::outer(
                TopErrorCategory::Malformed,
                format!("failed to parse manifest.json: {e}"),
            ));
            return assemble_result(
                errors,
                notes,
                chain_check,
                content_index_check,
                envelope_check,
                None,
                None,
                options.allowlist.is_empty(),
                String::new(),
                String::new(),
                level,
            );
        }
    };

    let envelope_bytes = match files.get("provenance/envelope.json") {
        Some(b) => b,
        None => {
            errors.push(TopError::outer(
                TopErrorCategory::Malformed,
                "missing provenance/envelope.json",
            ));
            return assemble_result(
                errors,
                notes,
                chain_check,
                content_index_check,
                envelope_check,
                None,
                None,
                options.allowlist.is_empty(),
                manifest.id.clone(),
                String::new(),
                level,
            );
        }
    };
    let envelope: Envelope = match serde_json::from_slice(envelope_bytes) {
        Ok(e) => e,
        Err(e) => {
            errors.push(TopError::outer(
                TopErrorCategory::Malformed,
                format!("failed to parse provenance/envelope.json: {e}"),
            ));
            return assemble_result(
                errors,
                notes,
                chain_check,
                content_index_check,
                envelope_check,
                None,
                None,
                options.allowlist.is_empty(),
                manifest.id.clone(),
                String::new(),
                level,
            );
        }
    };

    // Manifest and envelope parsed — capture the display fields so they
    // appear in both the structured result and the plain CLI output.
    let capsule_id = manifest.id.clone();
    let signed_at = envelope.signed_at.clone();

    // ---- (3) format / version checks ------------------------------------
    if manifest.format.version != "0.6" {
        errors.push(TopError::outer(
            TopErrorCategory::FormatVersion,
            format!(
                "unsupported manifest format.version: {}",
                manifest.format.version
            ),
        ));
    }
    if envelope.version != "0.6" {
        errors.push(TopError::outer(
            TopErrorCategory::FormatVersion,
            format!("unsupported envelope version: {}", envelope.version),
        ));
    }

    // ---- (4) cipher whitelist -------------------------------------------
    // Run unconditionally (plain or encrypted): an unsupported cipher value
    // is always a hard error, and the encryption-shape check below assumes
    // we've already accepted the cipher token.
    if !SUPPORTED_CIPHERS.contains(&envelope.cipher.as_str()) {
        errors.push(TopError::outer(
            TopErrorCategory::Encryption,
            format!("unsupported cipher: {}", envelope.cipher),
        ));
    }

    // ---- (5) capsule_id derivation --------------------------------------
    match hex_to_bytes(&manifest.originator.public_key) {
        Ok(pk) if pk.len() == 32 => match compute_capsule_id(&pk, &manifest.first_event_hash) {
            Ok(expected_id) => {
                if expected_id != manifest.id {
                    errors.push(TopError::outer(
                        TopErrorCategory::CapsuleId,
                        format!(
                            "manifest.id mismatch: stored {}, expected {}",
                            manifest.id, expected_id
                        ),
                    ));
                }
                if expected_id != envelope.capsule_id {
                    errors.push(TopError::outer(
                        TopErrorCategory::CapsuleId,
                        format!(
                            "envelope.capsule_id mismatch: {} vs derived {}",
                            envelope.capsule_id, expected_id
                        ),
                    ));
                }
            }
            Err(e) => {
                errors.push(TopError::outer(
                    TopErrorCategory::CapsuleId,
                    format!("capsule_id derivation failed: {e}"),
                ));
            }
        },
        Ok(_) => {
            errors.push(TopError::outer(
                TopErrorCategory::CapsuleId,
                "manifest.originator.public_key must be 32 bytes (64 hex)",
            ));
        }
        Err(e) => {
            errors.push(TopError::outer(
                TopErrorCategory::Malformed,
                format!("manifest.originator.public_key hex decode failed: {e}"),
            ));
        }
    }

    // ---- (6) manifest_hash check ----------------------------------------
    let expected_mfhash = manifest_hash(&manifest);
    if expected_mfhash != envelope.manifest_hash {
        errors.push(TopError::outer(
            TopErrorCategory::ManifestHash,
            format!(
                "envelope.manifest_hash mismatch: stored {} vs recomputed {}",
                envelope.manifest_hash, expected_mfhash
            ),
        ));
    }

    // ---- (7) content_index check ----------------------------------------
    // Key the content.enc exclusion off the signed envelope.cipher, not file
    // presence: a stray content.enc injected into a plain (cipher="none")
    // capsule is indexed here and therefore fails verification.
    content_index_check = verify_content_index(
        &files,
        &manifest,
        Some(&envelope.content_index_hash),
        content_index_exclusions(envelope.cipher != "none"),
    );

    // ---- (8) encryption-shape check -------------------------------------
    // Two valid shapes:
    //   - Plain:     no `content.enc`, cipher == "none", encrypted_blob_hash == null.
    //   - Encrypted: `content.enc` present, cipher on the whitelist (and
    //                != "none"), encrypted_blob_hash matches sha256(content.enc).
    // Anything else is an Encryption-category error.
    let is_encrypted = files.contains_key("content.enc");
    if is_encrypted {
        match envelope.encrypted_blob_hash.as_deref() {
            None => {
                errors.push(TopError::outer(
                    TopErrorCategory::Encryption,
                    "encrypted blob present but envelope.encrypted_blob_hash=null",
                ));
            }
            Some(stored) => match files.get("content.enc") {
                Some(blob) => {
                    let recomputed = sha256_hex(blob);
                    if recomputed != stored {
                        errors.push(TopError::outer(
                            TopErrorCategory::Encryption,
                            format!(
                                "envelope.encrypted_blob_hash mismatch: stored {stored} vs recomputed {recomputed}",
                            ),
                        ));
                    }
                }
                None => {
                    errors.push(TopError::outer(
                        TopErrorCategory::Malformed,
                        "internal: is_encrypted set but content.enc absent",
                    ));
                }
            },
        }
        if envelope.cipher == "none" {
            errors.push(TopError::outer(
                TopErrorCategory::Encryption,
                "encrypted blob present but envelope.cipher='none'",
            ));
        }
    } else {
        if envelope.encrypted_blob_hash.is_some() {
            errors.push(TopError::outer(
                TopErrorCategory::Encryption,
                "plain capsule must have envelope.encrypted_blob_hash=null",
            ));
        }
        if envelope.cipher != "none" {
            errors.push(TopError::outer(
                TopErrorCategory::Encryption,
                format!(
                    "plain capsule must have cipher='none', got '{}'",
                    envelope.cipher
                ),
            ));
        }
    }

    // ---- (9) chain walk -------------------------------------------------
    // For encrypted outers the chain lives inside the encrypted inner — L3
    // territory. We surface chain.ok=true with a note rather than failing,
    // so users see "chain (deferred to L3)" in the renderer.
    if !is_encrypted {
        match files.get("chain/events.jsonl") {
            Some(jsonl) => match parse_chain_jsonl(jsonl) {
                Ok(events) => {
                    chain_walk_into(
                        &events,
                        &manifest,
                        &envelope,
                        &mut chain_check,
                        &mut errors,
                        TopErrorScope::Outer,
                    );
                }
                Err(e) => {
                    chain_check.errors.push(format!("chain parse: {e}"));
                    chain_check.ok = false;
                }
            },
            None => {
                // No chain file is treated as an error in this verifier;
                // the JS reference's reader returns [] silently, but the
                // top-level verifier's `firstAndEntryHash` would then never
                // run, leaving `envelope.first_event_hash` un-validated.
                // We surface it explicitly here.
                chain_check
                    .errors
                    .push("missing chain/events.jsonl".to_string());
                chain_check.ok = false;
            }
        }
    } else {
        chain_check.ok = true;
        chain_check.errors = Vec::new();
        chain_check.event_count = 0;
        chain_check.note = Some("deferred to L3 (encrypted outer)".to_string());
        // The first_event_hash / entry_hash anchor checks are part of L3.
        // We can't recompute them without the chain bytes, so we skip them
        // here as well — they'll surface when the inner is verified.
    }

    // ---- (9b) L3: decrypt + walk inner chain + cross-check anchors ------
    // Only attempted when the capsule is encrypted AND a recipient secret
    // was supplied. On full success the chain skip note is replaced with a
    // real walk and `level` is upgraded to "L3"; on any L3 failure we
    // surface an Encryption error and stay at L2.
    if is_encrypted {
        if let Some(priv_key) = options.recipient_private_key.as_ref() {
            l3_attempt_decrypt_and_verify(
                priv_key,
                &envelope,
                &manifest,
                &files,
                options,
                &mut chain_check,
                &mut inner_envelope_check,
                &mut inner_content_index_check,
                &mut errors,
                &mut level,
            );
        }
    }

    // ---- (10) envelope signature verification ---------------------------
    envelope_check = verify_envelope_signatures(&envelope, &options.allowlist);

    // ---- (11) trusted_signer_count --------------------------------------
    let trusted_signer_count = envelope_check.signers.iter().filter(|s| s.trusted).count();

    // ---- (12) advisory note ---------------------------------------------
    let no_allowlist = options.allowlist.is_empty();
    if no_allowlist {
        notes.push(
            "no allowlist provided; trusted=false for all signers regardless of signature validity"
                .to_string(),
        );
    }

    // ---- (13) final ok --------------------------------------------------
    // `inner_envelope_check` and `inner_content_index_check` only contribute
    // when populated (L3 success path with a parsed inner envelope + manifest).
    // For plain capsules and L2-only paths they are `None` and treated as
    // non-blockers.
    let ok = errors.is_empty()
        && content_index_check.ok
        && chain_check.ok
        && envelope_check.ok
        && inner_envelope_check.as_ref().is_none_or(|e| e.ok)
        && inner_content_index_check.as_ref().is_none_or(|ci| ci.ok);

    VerifyResult {
        ok,
        level,
        capsule_id,
        signed_at,
        errors,
        chain: chain_check,
        content_index: content_index_check,
        envelope: envelope_check,
        inner_envelope: inner_envelope_check,
        inner_content_index: inner_content_index_check,
        trusted_signer_count,
        notes,
    }
}

/// Verify a manifest's content_index against the actual files on disk.
///
/// Used by both the outer pipeline (every capsule, against the outer
/// manifest + outer envelope) and at L3 against the inner manifest + inner
/// envelope. Centralising the logic guarantees outer and inner verification
/// share the exact same per-file + index_hash semantics — no drift between
/// nesting levels.
///
/// Behavior:
/// - For each path in `files` not in `excluded`, recompute its SHA-256 and
///   compare to `manifest.content_index.files[].sha256`. Surfaces "file
///   present but not in manifest index" and "file hash mismatch" errors.
/// - For each entry in `manifest.content_index.files[]` not present in the
///   recomputed set, surface "file in manifest index but missing from
///   package".
/// - Recompute `index_hash = sha256(jcs(files_array))` and compare to both
///   `manifest.content_index.index_hash` and (if `Some`)
///   `envelope_content_index_hash`. Each mismatch surfaces a separate error
///   so the renderer can attribute the failure precisely.
///
/// `ContentIndexCheck::ok` is `true` iff `errors.is_empty()`.
///
/// `excluded` selects which files are outside the content index: pass
/// [`STRUCTURAL_EXCLUDED`] for a plain capsule and [`CONTENT_INDEX_EXCLUDED`]
/// for an encrypted one (see [`content_index_exclusions`]). Keying this on the
/// signed `envelope.cipher` is what stops a stray `content.enc` from being
/// smuggled into a plain capsule unindexed.
/// `envelope_content_index_hash` is `Option<&str>` so future call sites can
/// skip the envelope-side comparison if needed; outer and inner both pass
/// `Some`.
pub(crate) fn verify_content_index(
    files: &BTreeMap<String, Vec<u8>>,
    manifest: &Manifest,
    envelope_content_index_hash: Option<&str>,
    excluded: &[&str],
) -> ContentIndexCheck {
    let mut content_index_check = ContentIndexCheck::default();
    let recomputed = build_content_index(files, excluded);
    let ci_errors = &mut content_index_check.errors;

    // Per-file: present in ZIP but missing from manifest, or hash mismatch.
    let stored_by_path: BTreeMap<&str, &str> = manifest
        .content_index
        .files
        .iter()
        .map(|f| (f.path.as_str(), f.sha256.as_str()))
        .collect();
    for f in &recomputed.files {
        match stored_by_path.get(f.path.as_str()) {
            None => ci_errors.push(format!(
                "file present but not in manifest index: {}",
                f.path
            )),
            Some(stored_sha) if *stored_sha != f.sha256 => {
                ci_errors.push(format!(
                    "file hash mismatch: {}: stored {} vs recomputed {}",
                    f.path, stored_sha, f.sha256
                ));
            }
            Some(_) => {}
        }
    }
    // Per-file: in manifest but missing from ZIP.
    let recomputed_paths: std::collections::BTreeSet<&str> =
        recomputed.files.iter().map(|f| f.path.as_str()).collect();
    for f in &manifest.content_index.files {
        if !recomputed_paths.contains(f.path.as_str()) {
            ci_errors.push(format!(
                "file in manifest index but missing from package: {}",
                f.path
            ));
        }
    }
    // Aggregate index_hash mismatches.
    if recomputed.index_hash != manifest.content_index.index_hash {
        ci_errors.push(format!(
            "manifest.content_index.index_hash mismatch: stored {} vs recomputed {}",
            manifest.content_index.index_hash, recomputed.index_hash
        ));
    }
    if let Some(env_hash) = envelope_content_index_hash {
        if recomputed.index_hash != env_hash {
            ci_errors.push(format!(
                "envelope.content_index_hash mismatch: stored {} vs recomputed {}",
                env_hash, recomputed.index_hash
            ));
        }
    }
    content_index_check.ok = ci_errors.is_empty();
    content_index_check
}

/// Walk `events` against `manifest` + `envelope` and accumulate per-event
/// failures into `chain_check`. The two `ChainAnchor` cross-checks
/// (`envelope.first_event_hash` and `envelope.entry_hash` vs the recomputed
/// chain anchors) push into `errors` via the `scope`-aware constructor —
/// callers in the outer pipeline pass `TopErrorScope::Outer`; the L3 caller
/// pushes the same logical mismatches against the *inner* envelope and
/// therefore passes `TopErrorScope::Inner`.
pub(crate) fn chain_walk_into(
    events: &[ChainEvent],
    manifest: &Manifest,
    envelope: &Envelope,
    chain_check: &mut ChainCheck,
    errors: &mut Vec<TopError>,
    scope: TopErrorScope,
) {
    chain_check.event_count = events.len();
    let walk_errors = verify_chain(events);
    chain_check
        .errors
        .extend(walk_errors.into_iter().map(|e| e.into_string()));

    // Per-event actor whitelist. Each event's actor must appear in
    // manifest.participants[].actor_id OR equal "system:host" (matching the
    // JS reference's `chain.md` rule).
    let participant_ids: std::collections::BTreeSet<&str> = manifest
        .participants
        .iter()
        .map(|p| p.actor_id.as_str())
        .collect();
    for e in events {
        if e.actor != "system:host" && !participant_ids.contains(e.actor.as_str()) {
            chain_check.errors.push(format!(
                "seq {}: actor {:?} not in manifest.participants and not system:host",
                e.seq, e.actor
            ));
        }
    }

    chain_check.ok = chain_check.errors.is_empty();

    // Cross-check first/entry against envelope. Build the error via whichever
    // constructor the caller's scope dictates so the resulting `TopError`
    // carries the right `scope` for JSON consumers.
    let make_anchor = |msg: String| -> TopError {
        match scope {
            TopErrorScope::Outer => TopError::outer(TopErrorCategory::ChainAnchor, msg),
            TopErrorScope::Inner => TopError::inner(TopErrorCategory::ChainAnchor, msg),
        }
    };
    if let Some((first_hash, entry_hash)) = first_and_entry_hash(events) {
        if first_hash != envelope.first_event_hash {
            errors.push(make_anchor(format!(
                "envelope.first_event_hash mismatch: {} vs {}",
                envelope.first_event_hash, first_hash
            )));
        }
        if entry_hash != envelope.entry_hash {
            errors.push(make_anchor(format!(
                "envelope.entry_hash mismatch: {} vs {}",
                envelope.entry_hash, entry_hash
            )));
        }
    }
}

/// Verify every signer in `envelope` against the per-role signing input and
/// build the corresponding [`EnvelopeCheck`]. The same code path is used for
/// the outer envelope (top-level pipeline step 10) and for the inner
/// envelope (L3, when decryption + inner parsing succeeded).
///
/// `allowlist` is a list of trusted Ed25519 public keys (hex). Comparison is
/// case-insensitive: keys are lowercased on both sides before lookup. A
/// signer is marked `trusted` only when its signature verifies AND its key
/// is on the allowlist; an empty allowlist therefore yields `trusted=false`
/// for every signer.
///
/// `EnvelopeCheck::ok` is `true` only when there is at least one signer AND
/// every signer's signature verified. An envelope with zero signers is
/// reported as `ok=false` with a `note` of `"envelope has no signers"`.
pub(crate) fn verify_envelope_signatures(envelope: &Envelope, allowlist: &[String]) -> EnvelopeCheck {
    let mut envelope_check = EnvelopeCheck::default();
    let signer_outcomes = verify_signatures(envelope);
    let mut all_valid = !signer_outcomes.is_empty();
    let allowlist_lower: std::collections::BTreeSet<String> =
        allowlist.iter().map(|k| k.to_lowercase()).collect();
    for s in signer_outcomes.iter() {
        if !s.valid {
            all_valid = false;
        }
        let lower = s.public_key.to_lowercase();
        let trusted = s.valid && allowlist_lower.contains(&lower);
        envelope_check.signers.push(SignerOutcome {
            role: s.role.clone(),
            public_key: s.public_key.clone(),
            valid: s.valid,
            trusted,
        });
    }
    if envelope_check.signers.is_empty() {
        envelope_check.ok = false;
        envelope_check.note = Some("envelope has no signers".to_string());
    } else {
        envelope_check.ok = all_valid;
    }
    envelope_check
}

/// Build a final `VerifyResult` from the accumulated state. Used by the
/// early-return paths.
///
/// `capsule_id` and `signed_at` are passed in so early-return paths can
/// surface whatever was successfully parsed before the failure (e.g.
/// after manifest parsed but before envelope parsed). Pass empty strings
/// when neither is available. `level` is whichever level the verifier
/// ended at — "L2" by default, "L3" only after a fully-successful inner
/// decrypt + chain walk. `inner_envelope_check` and
/// `inner_content_index_check` are populated only on the L3-success path;
/// every early-return path passes `None` for both.
#[allow(clippy::too_many_arguments)]
fn assemble_result(
    errors: Vec<TopError>,
    mut notes: Vec<String>,
    chain_check: ChainCheck,
    content_index_check: ContentIndexCheck,
    envelope_check: EnvelopeCheck,
    inner_envelope_check: Option<EnvelopeCheck>,
    inner_content_index_check: Option<ContentIndexCheck>,
    no_allowlist: bool,
    capsule_id: String,
    signed_at: String,
    level: String,
) -> VerifyResult {
    if no_allowlist {
        notes.push(
            "no allowlist provided; trusted=false for all signers regardless of signature validity"
                .to_string(),
        );
    }
    let trusted_signer_count = envelope_check.signers.iter().filter(|s| s.trusted).count();
    let ok = errors.is_empty()
        && content_index_check.ok
        && chain_check.ok
        && envelope_check.ok
        && inner_envelope_check.as_ref().is_none_or(|e| e.ok)
        && inner_content_index_check.as_ref().is_none_or(|ci| ci.ok);
    VerifyResult {
        ok,
        level,
        capsule_id,
        signed_at,
        errors,
        chain: chain_check,
        content_index: content_index_check,
        envelope: envelope_check,
        inner_envelope: inner_envelope_check,
        inner_content_index: inner_content_index_check,
        trusted_signer_count,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        clean_capsule_bytes, recipient_x25519_private_key,
        synthesize_capsule_with_envelope_mutation, tampered_capsule_bytes,
    };

    /// L2 happy path. The clean fixture must verify cleanly with no errors,
    /// no chain or content_index issues, and every signature valid. With no
    /// allowlist, `trusted_signer_count` is 0 and the advisory note is set.
    #[test]
    fn clean_capsule_passes_l2() {
        let bytes = clean_capsule_bytes();
        let result = verify_capsule(&bytes, &VerifyOptions { allowlist: vec![], recipient_private_key: None });

        assert!(result.ok, "clean capsule must pass; errors: {:?}", result.errors);
        assert!(result.errors.is_empty(), "no top-level errors: {:?}", result.errors);
        assert!(result.chain.ok, "chain ok");
        assert!(result.chain.errors.is_empty(), "no chain errors: {:?}", result.chain.errors);
        assert!(
            result.chain.note.is_none(),
            "plain capsule must not carry a chain skip note; got: {:?}",
            result.chain.note
        );
        assert!(result.content_index.ok, "content_index ok");
        assert!(
            result.content_index.errors.is_empty(),
            "no content_index errors: {:?}",
            result.content_index.errors
        );
        assert!(result.envelope.ok, "envelope ok");
        assert!(
            result.envelope.signers.iter().all(|s| s.valid),
            "all signers valid"
        );
        assert_eq!(result.trusted_signer_count, 0, "no allowlist → 0 trusted");
        assert!(
            result.notes.iter().any(|n| n.contains("no allowlist")),
            "advisory note must be present, got: {:?}",
            result.notes
        );
    }

    /// With the originator's pubkey on the allowlist, at least one signer
    /// must be marked trusted.
    #[test]
    fn clean_capsule_with_allowlist() {
        let bytes = clean_capsule_bytes();
        // Read the originator pubkey out of the manifest so we don't hard
        // code a key that could change if the fixture is regenerated.
        let map = unpack_zip(&bytes).unwrap();
        let manifest_bytes = map.get("manifest.json").unwrap();
        let manifest: Manifest = serde_json::from_slice(manifest_bytes).unwrap();
        let pk = manifest.originator.public_key.clone();

        let result = verify_capsule(&bytes, &VerifyOptions { allowlist: vec![pk], recipient_private_key: None });

        assert!(result.ok, "must still pass with allowlist; errors: {:?}", result.errors);
        assert!(
            result.trusted_signer_count >= 1,
            "expected at least one trusted signer, got {}",
            result.trusted_signer_count
        );
    }

    /// Payload tampering must surface as a content-index hash mismatch.
    #[test]
    fn tampered_payload_fails_at_content_index() {
        let bytes = tampered_capsule_bytes("tampered-payload.capsule");
        let result = verify_capsule(&bytes, &VerifyOptions { allowlist: vec![], recipient_private_key: None });

        assert!(!result.ok, "tampered payload must fail");
        assert!(
            !result.content_index.errors.is_empty(),
            "expected content_index errors; got result: {result:?}"
        );
        // At least one error mentions a hash mismatch (per-file or aggregate)
        // and includes both the stored and recomputed values for forensics.
        assert!(
            result
                .content_index
                .errors
                .iter()
                .any(|e| (e.contains("hash mismatch") || e.contains("index_hash mismatch"))
                    && e.contains("stored")
                    && e.contains("recomputed")),
            "expected a hash-mismatch message naming stored+recomputed; got: {:?}",
            result.content_index.errors
        );
    }

    /// Chain tampering may surface either as a chain walk error or as a
    /// content-index hash mismatch (since the chain file is itself indexed).
    #[test]
    fn tampered_chain_fails_at_chain_or_content_index() {
        let bytes = tampered_capsule_bytes("tampered-chain.capsule");
        let result = verify_capsule(&bytes, &VerifyOptions { allowlist: vec![], recipient_private_key: None });

        assert!(!result.ok, "tampered chain must fail");
        assert!(
            !result.chain.errors.is_empty() || !result.content_index.errors.is_empty(),
            "expected at least one chain or content_index error; got result: {result:?}"
        );
    }

    /// Envelope tampering must invalidate at least one signature.
    #[test]
    fn tampered_envelope_fails_at_signature() {
        let bytes = tampered_capsule_bytes("tampered-envelope.capsule");
        let result = verify_capsule(&bytes, &VerifyOptions { allowlist: vec![], recipient_private_key: None });

        assert!(!result.ok, "tampered envelope must fail");
        assert!(
            result.envelope.signers.iter().any(|s| !s.valid),
            "expected at least one invalid signer; got: {:?}",
            result.envelope.signers
        );
        assert!(!result.envelope.ok, "envelope.ok must be false");
    }

    /// `tampered-blob.capsule` is encrypted and the encrypted blob bytes
    /// have been mutated; the recomputed sha256 of `content.enc` will not
    /// match `envelope.encrypted_blob_hash`, surfacing as an
    /// Encryption-category error mentioning "encrypted" (the
    /// `encrypted_blob_hash mismatch` substring is a superset of
    /// "encrypted"). `clean-encrypted.capsule` is now an L2-pass case and
    /// is asserted on separately in `clean_encrypted_passes_l2`.
    #[test]
    fn encrypted_capsule_rejected_with_clear_message() {
        let bytes = tampered_capsule_bytes("tampered-blob.capsule");
        let result = verify_capsule(&bytes, &VerifyOptions { allowlist: vec![], recipient_private_key: None });

        assert!(!result.ok, "tampered-blob.capsule must be rejected");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("encrypted") || e.message.contains("cipher")),
            "expected an 'encrypted' or 'cipher' error, got: {:?}",
            result.errors
        );
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.category == TopErrorCategory::Encryption),
            "expected at least one Encryption-category error, got: {:?}",
            result.errors
        );
    }

    /// A synthesized capsule with `format.version = "0.5"` must be
    /// rejected. This test builds a STORED-only ZIP from raw JSON bytes
    /// (no real signatures), so most other checks will also fail — but
    /// the format error must be present.
    #[test]
    fn format_version_mismatch_rejected() {
        use std::io::Cursor;
        use std::io::Write;
        use zip::write::{SimpleFileOptions, ZipWriter};
        use zip::CompressionMethod;

        // Minimal manifest with bogus values (we only care that the
        // format.version check fires; downstream checks will fail too,
        // and that's fine — we just don't want a panic and we want the
        // version error to be one of the surfaced errors).
        let manifest_json = serde_json::json!({
            "format": {
                "version": "0.5",
                "container": "zip",
                "canonicalization": "JCS-RFC8785",
                "hash_algorithm": "SHA-256"
            },
            "id": "0".repeat(64),
            "originator": {
                "public_key": "0".repeat(64),
                "label": "test"
            },
            "participants": [],
            "first_event_hash": "0".repeat(64),
            "content_index": {
                "files": [],
                "index_hash": "0".repeat(64)
            },
            "skill_trust": {},
            "encryption": null,
            "created_at": "2026-01-01T00:00:00Z"
        });
        let envelope_json = serde_json::json!({
            "version": "0.6",
            "capsule_id": "0".repeat(64),
            "first_event_hash": "0".repeat(64),
            "entry_hash": "0".repeat(64),
            "manifest_hash": "0".repeat(64),
            "content_index_hash": "0".repeat(64),
            "encrypted_blob_hash": null,
            "cipher": "none",
            "signed_at": "2026-01-01T00:00:00Z",
            "signers": []
        });

        let buf = Cursor::new(Vec::<u8>::new());
        let mut zw = ZipWriter::new(buf);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        zw.start_file("manifest.json", opts).unwrap();
        zw.write_all(serde_json::to_string(&manifest_json).unwrap().as_bytes())
            .unwrap();
        zw.start_file("provenance/envelope.json", opts).unwrap();
        zw.write_all(serde_json::to_string(&envelope_json).unwrap().as_bytes())
            .unwrap();
        zw.start_file("chain/events.jsonl", opts).unwrap();
        zw.write_all(b"").unwrap(); // empty chain
        let bytes = zw.finish().unwrap().into_inner();

        let result = verify_capsule(&bytes, &VerifyOptions { allowlist: vec![], recipient_private_key: None });

        assert!(!result.ok, "0.5 manifest must be rejected");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("unsupported manifest format.version")
                    && e.category == TopErrorCategory::FormatVersion),
            "expected an unsupported-version error tagged FormatVersion; got: {:?}",
            result.errors
        );
    }

    /// Truncated/garbage bytes must surface as a Malformed top-level
    /// error rather than a panic. This exercises the ZIP-parse failure
    /// path.
    #[test]
    fn malformed_zip_surfaces_as_malformed_category() {
        let bytes = b"not a zip at all".to_vec();
        let result = verify_capsule(&bytes, &VerifyOptions { allowlist: vec![], recipient_private_key: None });

        assert!(!result.ok, "garbage bytes must not verify");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.category == TopErrorCategory::Malformed),
            "expected a Malformed-category error, got: {:?}",
            result.errors
        );
    }

    /// Synthesize a capsule whose `manifest.id` doesn't match the derived
    /// id. The error must surface under the CapsuleId category.
    #[test]
    fn capsule_id_mismatch_surfaces_as_capsule_id_category() {
        use std::io::Cursor;
        use std::io::Write;
        use zip::write::{SimpleFileOptions, ZipWriter};
        use zip::CompressionMethod;

        let manifest_json = serde_json::json!({
            "format": {
                "version": "0.6",
                "container": "zip",
                "canonicalization": "JCS-RFC8785",
                "hash_algorithm": "SHA-256"
            },
            // Deliberately bogus id — does not match what we derive from
            // the (zero) public key + first_event_hash below.
            "id": "1".repeat(64),
            "originator": {
                "public_key": "0".repeat(64),
                "label": "test"
            },
            "participants": [],
            "first_event_hash": "0".repeat(64),
            "content_index": {
                "files": [],
                "index_hash": "0".repeat(64)
            },
            "skill_trust": {},
            "encryption": null,
            "created_at": "2026-01-01T00:00:00Z"
        });
        let envelope_json = serde_json::json!({
            "version": "0.6",
            "capsule_id": "1".repeat(64),
            "first_event_hash": "0".repeat(64),
            "entry_hash": "0".repeat(64),
            "manifest_hash": "0".repeat(64),
            "content_index_hash": "0".repeat(64),
            "encrypted_blob_hash": null,
            "cipher": "none",
            "signed_at": "2026-01-01T00:00:00Z",
            "signers": []
        });
        let buf = Cursor::new(Vec::<u8>::new());
        let mut zw = ZipWriter::new(buf);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        zw.start_file("manifest.json", opts).unwrap();
        zw.write_all(serde_json::to_string(&manifest_json).unwrap().as_bytes())
            .unwrap();
        zw.start_file("provenance/envelope.json", opts).unwrap();
        zw.write_all(serde_json::to_string(&envelope_json).unwrap().as_bytes())
            .unwrap();
        zw.start_file("chain/events.jsonl", opts).unwrap();
        zw.write_all(b"").unwrap();
        let bytes = zw.finish().unwrap().into_inner();

        let result = verify_capsule(&bytes, &VerifyOptions { allowlist: vec![], recipient_private_key: None });
        assert!(!result.ok);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.category == TopErrorCategory::CapsuleId
                    && e.message.contains("manifest.id mismatch")),
            "expected a CapsuleId-category mismatch error, got: {:?}",
            result.errors
        );
    }

    /// Smoke-test that every TopErrorCategory the CLI can render is
    /// reachable from somewhere in the test suite. The CLI has a renderer
    /// line for each category; if a category is silently dropped from the
    /// verifier (e.g. because a check is rewritten to use a different
    /// variant), the renderer line goes dead. This test makes that loud.
    ///
    /// The existing tamper fixtures only naturally exercise `Encryption`
    /// (tampered-blob is encrypted). The other categories
    /// (`FormatVersion`, `CapsuleId`, `ManifestHash`, `ChainAnchor`,
    /// `Malformed`) are exercised by the synthesized tests in this
    /// module — we cross-check that here by collecting the category set
    /// of each test's verifier output and asserting full coverage.
    #[test]
    fn every_category_is_exercisable() {
        use std::collections::HashSet;
        use std::io::{Cursor, Write};
        use zip::write::{SimpleFileOptions, ZipWriter};
        use zip::CompressionMethod;

        let opts = VerifyOptions::default();
        let mut categories: HashSet<TopErrorCategory> = HashSet::new();

        // Encryption — tampered-blob.capsule fails the
        // `envelope.encrypted_blob_hash` recomputation. (clean-encrypted
        // now passes L2 and so does NOT contribute an Encryption error.)
        let r = verify_capsule(&tampered_capsule_bytes("tampered-blob.capsule"), &opts);
        categories.extend(r.errors.into_iter().map(|e| e.category));

        // Malformed — garbage bytes can't parse as ZIP.
        let r = verify_capsule(b"not a zip", &opts);
        categories.extend(r.errors.into_iter().map(|e| e.category));

        // Helper: synthesize a STORED-only ZIP with the given manifest +
        // envelope JSON values, plus an empty chain. Used to exercise
        // FormatVersion / CapsuleId / ManifestHash / ChainAnchor without
        // depending on real signatures or fixtures.
        let synth = |manifest: serde_json::Value, envelope: serde_json::Value| -> Vec<u8> {
            let buf = Cursor::new(Vec::<u8>::new());
            let mut zw = ZipWriter::new(buf);
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            zw.start_file("manifest.json", opts).unwrap();
            zw.write_all(serde_json::to_string(&manifest).unwrap().as_bytes())
                .unwrap();
            zw.start_file("provenance/envelope.json", opts).unwrap();
            zw.write_all(serde_json::to_string(&envelope).unwrap().as_bytes())
                .unwrap();
            zw.start_file("chain/events.jsonl", opts).unwrap();
            zw.write_all(b"").unwrap();
            zw.finish().unwrap().into_inner()
        };

        // FormatVersion — manifest.format.version != "0.6".
        let bytes = synth(
            serde_json::json!({
                "format": {
                    "version": "0.5",
                    "container": "zip",
                    "canonicalization": "JCS-RFC8785",
                    "hash_algorithm": "SHA-256"
                },
                "id": "0".repeat(64),
                "originator": {"public_key": "0".repeat(64), "label": "test"},
                "participants": [],
                "first_event_hash": "0".repeat(64),
                "content_index": {"files": [], "index_hash": "0".repeat(64)},
                "skill_trust": {},
                "encryption": null,
                "created_at": "2026-01-01T00:00:00Z"
            }),
            serde_json::json!({
                "version": "0.6",
                "capsule_id": "0".repeat(64),
                "first_event_hash": "0".repeat(64),
                "entry_hash": "0".repeat(64),
                "manifest_hash": "0".repeat(64),
                "content_index_hash": "0".repeat(64),
                "encrypted_blob_hash": null,
                "cipher": "none",
                "signed_at": "2026-01-01T00:00:00Z",
                "signers": []
            }),
        );
        let r = verify_capsule(&bytes, &opts);
        categories.extend(r.errors.into_iter().map(|e| e.category));

        // CapsuleId / ManifestHash / ChainAnchor — synthesize a 0.6
        // capsule whose stored manifest.id and envelope.{capsule_id,
        // manifest_hash, first_event_hash, entry_hash} all use a single
        // bogus value that can't possibly match the recomputed ones.
        let bytes = synth(
            serde_json::json!({
                "format": {
                    "version": "0.6",
                    "container": "zip",
                    "canonicalization": "JCS-RFC8785",
                    "hash_algorithm": "SHA-256"
                },
                "id": "1".repeat(64),
                "originator": {"public_key": "0".repeat(64), "label": "test"},
                "participants": [],
                "first_event_hash": "2".repeat(64),
                "content_index": {"files": [], "index_hash": "0".repeat(64)},
                "skill_trust": {},
                "encryption": null,
                "created_at": "2026-01-01T00:00:00Z"
            }),
            serde_json::json!({
                "version": "0.6",
                "capsule_id": "1".repeat(64),
                "first_event_hash": "3".repeat(64),
                "entry_hash": "4".repeat(64),
                "manifest_hash": "5".repeat(64),
                "content_index_hash": "0".repeat(64),
                "encrypted_blob_hash": null,
                "cipher": "none",
                "signed_at": "2026-01-01T00:00:00Z",
                "signers": []
            }),
        );
        let r = verify_capsule(&bytes, &opts);
        categories.extend(r.errors.into_iter().map(|e| e.category));

        // ChainAnchor — flip a hex digit in `envelope.first_event_hash` on
        // the clean fixture. The chain itself still walks (we don't touch
        // chain bytes), but the envelope's anchor no longer matches the
        // recomputed first event's hash.
        let bytes = synthesize_capsule_with_envelope_mutation("clean.capsule", |envelope| {
            if let Some(serde_json::Value::String(ref mut s)) =
                envelope.get_mut("first_event_hash")
            {
                let mut chars: Vec<char> = s.chars().collect();
                let last = chars.len() - 1;
                chars[last] = if chars[last] == '0' { '1' } else { '0' };
                *s = chars.into_iter().collect();
            } else {
                panic!("envelope.first_event_hash missing or not a string");
            }
        });
        let r = verify_capsule(&bytes, &opts);
        categories.extend(r.errors.into_iter().map(|e| e.category));

        // Now assert every category the renderer cares about is reachable.
        for cat in [
            TopErrorCategory::FormatVersion,
            TopErrorCategory::CapsuleId,
            TopErrorCategory::ManifestHash,
            TopErrorCategory::ChainAnchor,
            TopErrorCategory::Encryption,
            TopErrorCategory::Malformed,
        ] {
            assert!(
                categories.contains(&cat),
                "category {cat:?} not exercised by the test suite (got: {categories:?}). \
                 If you removed a category, also remove its renderer line in the CLI."
            );
        }
    }

    /// Synthesize a capsule whose chain walks correctly (manifest, content
    /// index, and chain bytes all unchanged) but whose
    /// `envelope.first_event_hash` has a single hex digit flipped. That
    /// breaks the anchor cross-check between the envelope and the chain's
    /// first event, surfacing as a `ChainAnchor` top-level error. The
    /// envelope signature also stops verifying (we mutated envelope bytes
    /// without re-signing), but we only assert on the `ChainAnchor`
    /// category — the other failure is expected and not the focus here.
    #[test]
    fn chain_anchor_mismatch_surfaces_as_chain_anchor_category() {
        let bytes = synthesize_capsule_with_envelope_mutation("clean.capsule", |envelope| {
            // Flip a hex digit in first_event_hash — chain bytes unchanged so
            // the chain walks fine; but the envelope's anchor no longer matches.
            if let Some(serde_json::Value::String(ref mut s)) =
                envelope.get_mut("first_event_hash")
            {
                // Flip the last char (deterministic mutation).
                let mut chars: Vec<char> = s.chars().collect();
                let last = chars.len() - 1;
                chars[last] = if chars[last] == '0' { '1' } else { '0' };
                *s = chars.into_iter().collect();
            } else {
                panic!("envelope.first_event_hash missing or not a string");
            }
        });

        let opts = VerifyOptions::default();
        let result = verify_capsule(&bytes, &opts);

        assert!(!result.ok, "expected verification to fail");
        let chain_anchor_errors: Vec<&TopError> = result
            .errors
            .iter()
            .filter(|e| e.category == TopErrorCategory::ChainAnchor)
            .collect();
        assert!(
            !chain_anchor_errors.is_empty(),
            "expected at least one ChainAnchor error; got: {:?}",
            result.errors
        );
        assert!(
            chain_anchor_errors
                .iter()
                .any(|e| e.message.contains("first_event_hash")),
            "expected first_event_hash mismatch message; got: {:?}",
            chain_anchor_errors
        );
    }

    /// L2 happy path for an encrypted-outer capsule. The chain check is
    /// deferred to L3 (`note.is_some()`); content_index, encryption-shape,
    /// and signatures must all pass.
    #[test]
    fn clean_encrypted_passes_l2() {
        let bytes = tampered_capsule_bytes("clean-encrypted.capsule");
        let result = verify_capsule(&bytes, &VerifyOptions { allowlist: vec![], recipient_private_key: None });

        assert!(
            result.ok,
            "clean-encrypted must pass at L2; errors: {:?}",
            result.errors
        );
        assert!(result.errors.is_empty(), "no top-level errors: {:?}", result.errors);
        assert!(
            result.envelope.signers.iter().all(|s| s.valid),
            "all signers must be valid; got: {:?}",
            result.envelope.signers
        );
        assert!(result.chain.ok, "chain.ok must be true (deferred, not failed)");
        let note = result
            .chain
            .note
            .as_deref()
            .expect("chain.note must be set on encrypted outer");
        assert!(
            note.contains("deferred") || note.contains("encrypted"),
            "chain.note must mention deferral or encryption; got: {note:?}"
        );
        assert!(result.content_index.ok, "content_index must pass");
    }

    /// `tampered-blob.capsule` mutates a byte inside `content.enc`. The
    /// recomputed `sha256(content.enc)` will not match
    /// `envelope.encrypted_blob_hash`, surfacing as a precise
    /// `encrypted_blob_hash mismatch` error. The chain check is still
    /// deferred (the failure is at encryption, not at chain).
    #[test]
    fn tampered_blob_fails_at_encrypted_blob_hash() {
        let bytes = tampered_capsule_bytes("tampered-blob.capsule");
        let result = verify_capsule(&bytes, &VerifyOptions { allowlist: vec![], recipient_private_key: None });

        assert!(!result.ok, "tampered-blob must fail at L2");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.category == TopErrorCategory::Encryption),
            "expected an Encryption-category error; got: {:?}",
            result.errors
        );
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("encrypted_blob_hash mismatch")),
            "expected an 'encrypted_blob_hash mismatch' message; got: {:?}",
            result.errors
        );
        assert!(
            result.chain.ok,
            "chain.ok must be true (failure is at encryption, not chain)"
        );
        assert!(
            result.chain.note.is_some(),
            "chain.note must be set even when other checks fail; got: {:?}",
            result.chain.note
        );
    }

    /// Mutate `clean.capsule`'s envelope to use an unsupported cipher
    /// (`AES-256-GCM` — reserved but not implemented in v0.6). The cipher
    /// whitelist must reject it with a clear `unsupported cipher` error
    /// regardless of every other field. (The mutated envelope's signature
    /// no longer verifies, but we only assert on the cipher rejection.)
    #[test]
    fn unsupported_cipher_rejected() {
        let bytes = synthesize_capsule_with_envelope_mutation("clean.capsule", |env| {
            env["cipher"] = serde_json::Value::String("AES-256-GCM".to_string());
        });
        let result = verify_capsule(&bytes, &VerifyOptions { allowlist: vec![], recipient_private_key: None });

        assert!(!result.ok, "unsupported cipher must be rejected");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.category == TopErrorCategory::Encryption
                    && e.message.contains("unsupported cipher")
                    && e.message.contains("AES-256-GCM")),
            "expected an 'unsupported cipher: AES-256-GCM' Encryption error; got: {:?}",
            result.errors
        );
    }

    /// Synthesize an encrypted-outer capsule whose envelope claims
    /// `cipher: "none"`. That contradicts the presence of `content.enc` —
    /// "none" means plain, but a plain capsule has no encrypted blob. The
    /// verifier must call this out as an Encryption error.
    #[test]
    fn encrypted_blob_with_cipher_none_rejected() {
        let bytes =
            synthesize_capsule_with_envelope_mutation("clean-encrypted.capsule", |env| {
                env["cipher"] = serde_json::Value::String("none".to_string());
            });
        let result = verify_capsule(&bytes, &VerifyOptions { allowlist: vec![], recipient_private_key: None });

        assert!(!result.ok, "encrypted blob with cipher='none' must fail");
        assert!(
            result.errors.iter().any(|e| e.category
                == TopErrorCategory::Encryption
                && e.message.contains("encrypted blob present")
                && e.message.contains("cipher")),
            "expected an Encryption error mentioning 'encrypted blob present' and 'cipher'; got: {:?}",
            result.errors
        );
    }

    /// L3 happy path. With the recipient's X25519 secret supplied, the
    /// encrypted-outer fixture must pass at L3: the inner ZIP decrypts,
    /// the inner chain walks, and every cross-check matches the outer
    /// envelope. The chain skip note is replaced with a real walk.
    #[test]
    fn encrypted_clean_capsule_passes_l3_with_recipient_key() {
        let bytes = tampered_capsule_bytes("clean-encrypted.capsule");
        let result = verify_capsule(
            &bytes,
            &VerifyOptions {
                allowlist: vec![],
                recipient_private_key: Some(recipient_x25519_private_key()),
            },
        );

        assert!(
            result.ok,
            "L3 path must pass with recipient key; errors: {:?}",
            result.errors
        );
        assert_eq!(result.level, "L3", "level must upgrade to L3");
        assert!(
            result.chain.ok,
            "inner chain must walk cleanly; got errors: {:?}",
            result.chain.errors
        );
        assert!(
            result.chain.note.is_none(),
            "chain.note must be cleared after a real inner walk; got: {:?}",
            result.chain.note
        );
        assert!(
            result.chain.event_count >= 1,
            "inner chain must have at least one event; got {}",
            result.chain.event_count
        );
        assert!(
            result.errors.is_empty(),
            "no top-level errors at L3; got: {:?}",
            result.errors
        );
        // v0.4: the inner envelope must also be verified on the L3-success
        // path. Only the presence-and-ok assertion is here; the dedicated
        // `encrypted_clean_capsule_l3_inner_envelope_verifies` test covers
        // the per-signer details.
        assert!(
            result.inner_envelope.is_some(),
            "inner_envelope must be populated on L3 success"
        );
        assert!(
            result.inner_envelope.as_ref().unwrap().ok,
            "inner envelope must verify on L3 success"
        );
        // v0.5: the inner content_index must also be verified on the
        // L3-success path. Only the presence-and-ok assertion is here; the
        // dedicated `encrypted_clean_capsule_l3_inner_content_index_verifies`
        // test covers the per-file detail.
        assert!(
            result.inner_content_index.is_some(),
            "inner_content_index must be populated on L3 success"
        );
        assert!(
            result.inner_content_index.as_ref().unwrap().ok,
            "inner content_index must verify on L3 success"
        );
    }

    /// Without a recipient key, the v0.2 L2 behavior must be preserved
    /// exactly: the encrypted outer passes at L2 with the chain check
    /// deferred via `chain.note`.
    #[test]
    fn encrypted_clean_capsule_falls_back_to_l2_without_key() {
        let bytes = tampered_capsule_bytes("clean-encrypted.capsule");
        let result = verify_capsule(
            &bytes,
            &VerifyOptions {
                allowlist: vec![],
                recipient_private_key: None,
            },
        );

        assert!(
            result.ok,
            "L2 fallback must pass without a key; errors: {:?}",
            result.errors
        );
        assert_eq!(result.level, "L2", "no key → no L3 upgrade");
        assert!(result.chain.ok, "chain.ok must be true (deferred, not failed)");
        assert!(
            result.chain.note.is_some(),
            "chain.note must be set when chain is deferred to L3"
        );
    }

    /// `tampered-blob.capsule` mutates a byte inside `content.enc`. Even
    /// with the correct recipient secret, AEAD authentication on the
    /// content blob must fail. The verifier must surface an
    /// Encryption-category L3 error and stay at L2 (no upgrade because
    /// decryption failed).
    #[test]
    fn tampered_blob_l3_decryption_fails() {
        let bytes = tampered_capsule_bytes("tampered-blob.capsule");
        let result = verify_capsule(
            &bytes,
            &VerifyOptions {
                allowlist: vec![],
                recipient_private_key: Some(recipient_x25519_private_key()),
            },
        );

        assert!(!result.ok, "tampered-blob must fail under L3");
        assert_eq!(result.level, "L2", "decrypt failure must not upgrade level");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.category == TopErrorCategory::Encryption),
            "expected an Encryption-category error; got: {:?}",
            result.errors
        );
        assert!(
            result.errors.iter().any(|e| {
                let m = &e.message;
                m.contains("L3") || m.contains("decryption") || m.contains("auth")
            }),
            "expected an L3/decryption/auth-flavored message; got: {:?}",
            result.errors
        );
    }

    /// A bogus 32-byte X25519 secret derives a public key that is not in
    /// any bundle. The lookup must fail before any AEAD call, surfacing as
    /// an Encryption-category error mentioning `no key bundle` /
    /// `NoMatchingRecipient`. Level stays at L2.
    #[test]
    fn wrong_recipient_key_l3_no_match() {
        let bytes = tampered_capsule_bytes("clean-encrypted.capsule");
        let result = verify_capsule(
            &bytes,
            &VerifyOptions {
                allowlist: vec![],
                recipient_private_key: Some([0x42; 32]),
            },
        );

        assert!(!result.ok, "wrong key must fail at L3");
        assert_eq!(result.level, "L2", "no decryption → no L3 upgrade");
        assert!(
            result.errors.iter().any(|e| e.category
                == TopErrorCategory::Encryption
                && (e.message.contains("no key bundle")
                    || e.message.contains("NoMatchingRecipient"))),
            "expected an Encryption error mentioning 'no key bundle' or 'NoMatchingRecipient'; got: {:?}",
            result.errors
        );
    }

    /// A plain capsule passed alongside a recipient key must ignore the
    /// key (no encryption to decrypt) and verify as a normal L2 plain
    /// capsule — chain walked, no `chain.note`.
    #[test]
    fn plain_capsule_with_recipient_key_ignores_flag() {
        let bytes = clean_capsule_bytes();
        let result = verify_capsule(
            &bytes,
            &VerifyOptions {
                allowlist: vec![],
                recipient_private_key: Some(recipient_x25519_private_key()),
            },
        );

        assert!(
            result.ok,
            "plain capsule must still pass; errors: {:?}",
            result.errors
        );
        assert_eq!(
            result.level, "L2",
            "plain capsule + recipient key must stay at L2"
        );
        assert!(
            result.errors.is_empty(),
            "no top-level errors expected; got: {:?}",
            result.errors
        );
        assert!(
            result.chain.note.is_none(),
            "plain capsule must not carry a deferred chain note; got: {:?}",
            result.chain.note
        );
    }

    /// v0.4 L3 happy path: with the recipient secret supplied, the L3
    /// pipeline must verify the inner envelope's signers using the same
    /// code path as the outer envelope, surface the result as
    /// `result.inner_envelope`, and report every signer as `valid=true`.
    #[test]
    fn encrypted_clean_capsule_l3_inner_envelope_verifies() {
        let bytes = tampered_capsule_bytes("clean-encrypted.capsule");
        let result = verify_capsule(
            &bytes,
            &VerifyOptions {
                allowlist: vec![],
                recipient_private_key: Some(recipient_x25519_private_key()),
            },
        );

        assert!(
            result.ok,
            "L3 happy path must pass; errors: {:?}",
            result.errors
        );
        assert_eq!(result.level, "L3", "level must upgrade to L3");
        assert!(
            result.inner_envelope.is_some(),
            "inner_envelope must be populated when L3 reaches the inner envelope"
        );
        let inner = result.inner_envelope.as_ref().unwrap();
        assert!(inner.ok, "inner envelope must verify; got: {inner:?}");
        assert!(
            !inner.signers.is_empty(),
            "inner envelope must report at least one signer; got: {inner:?}"
        );
        assert!(
            inner.signers.iter().all(|s| s.valid),
            "every inner signer must be valid; got: {:?}",
            inner.signers
        );
    }

    /// Without a recipient key, the encrypted-outer fixture stays at L2 and
    /// no inner-envelope verification is attempted. `result.inner_envelope`
    /// must be `None`, matching the v0.3 JSON shape for L2-only paths.
    #[test]
    fn inner_envelope_check_absent_at_l2() {
        let bytes = tampered_capsule_bytes("clean-encrypted.capsule");
        let result = verify_capsule(
            &bytes,
            &VerifyOptions {
                allowlist: vec![],
                recipient_private_key: None,
            },
        );

        assert!(
            result.ok,
            "L2 fallback must pass; errors: {:?}",
            result.errors
        );
        assert_eq!(result.level, "L2", "no key → stays at L2");
        assert!(
            result.inner_envelope.is_none(),
            "L2-only paths must leave inner_envelope unset; got: {:?}",
            result.inner_envelope
        );
    }

    /// A plain capsule paired with a recipient key silently ignores the
    /// flag (no encryption to decrypt). There is no inner envelope, so
    /// `result.inner_envelope` must be `None`.
    #[test]
    fn inner_envelope_check_absent_for_plain() {
        let bytes = clean_capsule_bytes();
        let result = verify_capsule(
            &bytes,
            &VerifyOptions {
                allowlist: vec![],
                recipient_private_key: Some(recipient_x25519_private_key()),
            },
        );

        assert!(
            result.ok,
            "plain capsule must still pass; errors: {:?}",
            result.errors
        );
        assert_eq!(result.level, "L2", "plain capsule stays at L2");
        assert!(
            result.inner_envelope.is_none(),
            "plain capsule must leave inner_envelope unset; got: {:?}",
            result.inner_envelope
        );
    }

    /// Unit test on the inner-envelope verification helper itself: extract
    /// the inner envelope from `clean-encrypted.capsule`, mutate its first
    /// signer's signature, and confirm that `verify_envelope_signatures`
    /// reports `ok=false` and the mutated signer's `valid=false`.
    ///
    /// This documents that IF inner-envelope tampering is somehow injected
    /// (the v0.4 shipped tooling has no such builder, hence no full
    /// integration fixture), the verification code path would catch it. We
    /// drive `decrypt_inner_zip` directly rather than going through
    /// `verify_capsule` so the test does not depend on a tampered-inner
    /// fixture.
    #[test]
    fn mutated_inner_signature_unit_test() {
        // Step 1: unpack the outer ZIP and parse its manifest+envelope so
        // we have the inputs `decrypt_inner_zip` needs.
        let bytes = tampered_capsule_bytes("clean-encrypted.capsule");
        let outer_files = unpack_zip(&bytes).expect("outer zip must unpack");
        let outer_manifest: Manifest =
            serde_json::from_slice(outer_files.get("manifest.json").unwrap())
                .expect("outer manifest must parse");
        let outer_envelope: Envelope = serde_json::from_slice(
            outer_files.get("provenance/envelope.json").unwrap(),
        )
        .expect("outer envelope must parse");

        // Step 2: decrypt to inner ZIP bytes, then unpack and parse the
        // inner envelope.
        let inner_zip_bytes = decrypt_inner_zip(
            &outer_envelope,
            &outer_manifest,
            &outer_files,
            &recipient_x25519_private_key(),
        )
        .expect("decryption must succeed for clean-encrypted");
        let inner_files = unpack_zip(&inner_zip_bytes).expect("inner zip must unpack");
        let mut inner_envelope: Envelope = serde_json::from_slice(
            inner_files
                .get("provenance/envelope.json")
                .expect("inner envelope must be present"),
        )
        .expect("inner envelope JSON must parse");

        // Sanity check: the unmutated inner envelope verifies cleanly.
        let pre = verify_envelope_signatures(&inner_envelope, &[]);
        assert!(
            pre.ok,
            "inner envelope must verify before mutation; got: {pre:?}"
        );
        assert!(
            !inner_envelope.signers.is_empty(),
            "inner envelope must have signers"
        );

        // Step 3: flip the last hex char of the first signer's signature.
        let sig = &mut inner_envelope.signers[0].signature;
        let mut chars: Vec<char> = sig.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '0' { '1' } else { '0' };
        *sig = chars.into_iter().collect();

        // Step 4: re-run the helper. The mutated signer must be invalid,
        // and `EnvelopeCheck.ok` must be false.
        let post = verify_envelope_signatures(&inner_envelope, &[]);
        assert!(
            !post.ok,
            "mutated inner envelope must not verify; got: {post:?}"
        );
        assert!(
            !post.signers[0].valid,
            "mutated first signer must be invalid; got: {:?}",
            post.signers[0]
        );
    }

    /// v0.5 L3 happy path: with the recipient secret supplied, the L3
    /// pipeline must recompute the inner content_index and surface it as
    /// `result.inner_content_index` with `ok=true` and no per-entry errors.
    /// Symmetrically, the inner manifest_hash must verify, so no
    /// `ManifestHash`-category top-level error mentioning "L3 inner" should
    /// be present.
    #[test]
    fn encrypted_clean_capsule_l3_inner_content_index_verifies() {
        let bytes = tampered_capsule_bytes("clean-encrypted.capsule");
        let result = verify_capsule(
            &bytes,
            &VerifyOptions {
                allowlist: vec![],
                recipient_private_key: Some(recipient_x25519_private_key()),
            },
        );

        assert!(
            result.ok,
            "L3 happy path must pass; errors: {:?}",
            result.errors
        );
        assert_eq!(result.level, "L3", "level must upgrade to L3");
        assert!(
            result.inner_content_index.is_some(),
            "inner_content_index must be populated when L3 reaches the inner manifest"
        );
        let inner_ci = result.inner_content_index.as_ref().unwrap();
        assert!(
            inner_ci.ok,
            "inner content_index must verify; got errors: {:?}",
            inner_ci.errors
        );
        assert!(
            inner_ci.errors.is_empty(),
            "inner content_index must be error-free; got: {:?}",
            inner_ci.errors
        );
        // Inner manifest_hash must also verify — no ManifestHash-category
        // top-level error tagged with "L3 inner".
        let inner_mh_errors: Vec<&TopError> = result
            .errors
            .iter()
            .filter(|e| {
                e.category == TopErrorCategory::ManifestHash && e.message.contains("L3 inner")
            })
            .collect();
        assert!(
            inner_mh_errors.is_empty(),
            "inner manifest_hash must verify; got: {inner_mh_errors:?}"
        );
    }

    /// Without a recipient key, the encrypted-outer fixture stays at L2. The
    /// inner content_index check is gated on the L3 path, so
    /// `result.inner_content_index` must be `None` — matching the v0.4 JSON
    /// shape for L2-only paths and forward-compatible with consumers that
    /// haven't seen the field before.
    #[test]
    fn inner_content_index_check_absent_at_l2() {
        let bytes = tampered_capsule_bytes("clean-encrypted.capsule");
        let result = verify_capsule(
            &bytes,
            &VerifyOptions {
                allowlist: vec![],
                recipient_private_key: None,
            },
        );

        assert!(
            result.ok,
            "L2 fallback must pass; errors: {:?}",
            result.errors
        );
        assert!(
            result.inner_content_index.is_none(),
            "L2-only paths must leave inner_content_index unset; got: {:?}",
            result.inner_content_index
        );
    }

    /// A plain capsule paired with a recipient key silently ignores the
    /// flag. There is no inner ZIP and no inner content_index, so
    /// `result.inner_content_index` must be `None`.
    #[test]
    fn inner_content_index_check_absent_for_plain() {
        let bytes = clean_capsule_bytes();
        let result = verify_capsule(
            &bytes,
            &VerifyOptions {
                allowlist: vec![],
                recipient_private_key: Some(recipient_x25519_private_key()),
            },
        );

        assert!(
            result.ok,
            "plain capsule must still pass; errors: {:?}",
            result.errors
        );
        assert!(
            result.inner_content_index.is_none(),
            "plain capsule must leave inner_content_index unset; got: {:?}",
            result.inner_content_index
        );
    }

    /// Unit test on the inner content_index recompute helper itself: extract
    /// the decrypted inner files + inner manifest from `clean-encrypted.capsule`,
    /// mutate one byte of `inner_manifest.content_index.files[0].sha256`, and
    /// confirm that `verify_content_index(...)` reports `ok=false` and an
    /// error mentioning the mutated path.
    ///
    /// This documents that IF inner content_index tampering is somehow
    /// injected (the v0.5 shipped tooling has no such builder, hence no
    /// full integration fixture), the helper would catch it. We drive the
    /// helper directly so the test does not depend on a tampered-inner
    /// fixture.
    #[test]
    fn mutated_inner_manifest_content_index_unit_test() {
        // Step 1: unpack the outer ZIP and parse outer manifest+envelope so
        // we have the inputs `decrypt_inner_zip` needs.
        let bytes = tampered_capsule_bytes("clean-encrypted.capsule");
        let outer_files = unpack_zip(&bytes).expect("outer zip must unpack");
        let outer_manifest: Manifest =
            serde_json::from_slice(outer_files.get("manifest.json").unwrap())
                .expect("outer manifest must parse");
        let outer_envelope: Envelope = serde_json::from_slice(
            outer_files.get("provenance/envelope.json").unwrap(),
        )
        .expect("outer envelope must parse");

        // Step 2: decrypt → unpack inner ZIP → parse inner manifest +
        // inner envelope.
        let inner_zip_bytes = decrypt_inner_zip(
            &outer_envelope,
            &outer_manifest,
            &outer_files,
            &recipient_x25519_private_key(),
        )
        .expect("decryption must succeed for clean-encrypted");
        let inner_files = unpack_zip(&inner_zip_bytes).expect("inner zip must unpack");
        let mut inner_manifest: Manifest = serde_json::from_slice(
            inner_files
                .get("manifest.json")
                .expect("inner manifest must be present"),
        )
        .expect("inner manifest JSON must parse");
        let inner_envelope: Envelope = serde_json::from_slice(
            inner_files
                .get("provenance/envelope.json")
                .expect("inner envelope must be present"),
        )
        .expect("inner envelope JSON must parse");

        // Sanity check: the unmutated inner content_index verifies cleanly
        // against the inner manifest + inner envelope.
        let pre = verify_content_index(
            &inner_files,
            &inner_manifest,
            Some(&inner_envelope.content_index_hash),
            content_index_exclusions(inner_envelope.cipher != "none"),
        );
        assert!(
            pre.ok,
            "inner content_index must verify before mutation; got errors: {:?}",
            pre.errors
        );
        assert!(
            !inner_manifest.content_index.files.is_empty(),
            "inner manifest must have at least one content_index entry"
        );

        // Step 3: flip the last hex char of the first content_index
        // entry's sha256. This breaks the per-file hash check (and as a
        // consequence the rollup index_hash); we assert on the per-file
        // mismatch as the precise signal.
        let mutated_path = inner_manifest.content_index.files[0].path.clone();
        let sha = &mut inner_manifest.content_index.files[0].sha256;
        let mut chars: Vec<char> = sha.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '0' { '1' } else { '0' };
        *sha = chars.into_iter().collect();

        // Step 4: re-run the helper. The mutated entry must surface as a
        // file-hash mismatch, and `ContentIndexCheck.ok` must be false.
        let post = verify_content_index(
            &inner_files,
            &inner_manifest,
            Some(&inner_envelope.content_index_hash),
            content_index_exclusions(inner_envelope.cipher != "none"),
        );
        assert!(
            !post.ok,
            "mutated inner content_index must not verify; got: {post:?}"
        );
        assert!(
            post.errors.iter().any(|e| {
                e.contains("file hash mismatch") && e.contains(&mutated_path)
            }),
            "expected a 'file hash mismatch' error naming {mutated_path:?}; got: {:?}",
            post.errors
        );
    }

    /// v0.5 L3 happy path: with the recipient secret supplied, NONE of the
    /// inner-side recompute checks (format/version, capsule_id, manifest_hash,
    /// content_index) must surface a top-level error. The dedicated tests above
    /// cover each individual check; this test guards the combined "no L3 inner
    /// errors at all" property — if any inner check ever starts firing on the
    /// clean fixture, this test makes that loud.
    #[test]
    fn encrypted_clean_capsule_l3_inner_full_check_verifies() {
        let bytes = tampered_capsule_bytes("clean-encrypted.capsule");
        let result = verify_capsule(
            &bytes,
            &VerifyOptions {
                allowlist: vec![],
                recipient_private_key: Some(recipient_x25519_private_key()),
            },
        );

        assert!(
            result.ok,
            "L3 happy path must pass; errors: {:?}",
            result.errors
        );
        assert_eq!(result.level, "L3", "level must upgrade to L3");
        let l3_inner_errors: Vec<_> = result
            .errors
            .iter()
            .filter(|e| e.message.starts_with("L3 inner:"))
            .collect();
        assert!(
            l3_inner_errors.is_empty(),
            "no L3 inner errors expected; got: {l3_inner_errors:?}"
        );
    }

    /// v0.6 Task 2: `TopError.scope` discriminant must distinguish outer-
    /// pipeline failures from L3 inner-verification failures. We exercise
    /// both shapes:
    ///
    /// - `tampered-blob.capsule` *without* a recipient key: only the outer
    ///   pipeline runs, the `envelope.encrypted_blob_hash` mismatch surfaces
    ///   as a single `Encryption`-category top-level error, and every
    ///   `TopError` must carry `scope == Outer`.
    /// - `tampered-blob.capsule` *with* the recipient key: the outer
    ///   encrypted_blob_hash check still fails (`Outer`) AND L3 decryption
    ///   fails on the auth tag (`Inner`). At least one error must carry
    ///   `scope == Inner`, and the set must include both scopes.
    ///
    /// This locks in the JSON contract that consumers can branch on
    /// `scope == "inner"` instead of substring-matching the `"L3 inner: "`
    /// message prefix.
    #[test]
    fn top_error_scope_distinguishes_outer_from_inner() {
        // Outer-only failure: encrypted-outer fault, no recipient key →
        // only the outer pipeline runs.
        let bytes = tampered_capsule_bytes("tampered-blob.capsule");
        let result = verify_capsule(
            &bytes,
            &VerifyOptions {
                allowlist: vec![],
                recipient_private_key: None,
            },
        );
        assert!(
            !result.errors.is_empty(),
            "tampered-blob should fail at L2 with at least one top-level error"
        );
        assert!(
            result.errors.iter().all(|e| e.scope == TopErrorScope::Outer),
            "without a key, every error must be Outer-scope; got: {:?}",
            result.errors
        );

        // Inner-scope failure: same fixture, recipient key supplied → L3
        // decrypt failure (auth tag mismatch) is Inner-scope, in addition
        // to the outer encrypted_blob_hash failure that's Outer-scope.
        let bytes = tampered_capsule_bytes("tampered-blob.capsule");
        let result = verify_capsule(
            &bytes,
            &VerifyOptions {
                allowlist: vec![],
                recipient_private_key: Some(recipient_x25519_private_key()),
            },
        );
        let has_inner = result
            .errors
            .iter()
            .any(|e| e.scope == TopErrorScope::Inner);
        let has_outer = result
            .errors
            .iter()
            .any(|e| e.scope == TopErrorScope::Outer);
        assert!(
            has_inner,
            "tampered-blob L3 must surface at least one Inner-scope error; got: {:?}",
            result.errors
        );
        assert!(
            has_outer,
            "tampered-blob L3 still has the outer encrypted_blob_hash mismatch; got: {:?}",
            result.errors
        );
    }

    /// v0.6 backward-compat guarantee: a v0.3-v0.5 JSON shape (with no
    /// `scope` field) must deserialize cleanly into the new `TopError`
    /// struct with `scope == Outer`. `#[serde(default)]` on the field
    /// plus `#[default]` on `TopErrorScope::Outer` provide this, and
    /// this test locks in the contract.
    #[test]
    fn top_error_deserializes_v05_json_with_default_outer_scope() {
        // Pre-v0.6 shape: only `category` and `message`.
        let v05_json = r#"{"category":"encryption","message":"capsule is encrypted (cipher: ChaCha20-Poly1305)"}"#;
        let parsed: TopError = serde_json::from_str(v05_json).expect("pre-v0.6 JSON must deserialize");
        assert_eq!(parsed.category, TopErrorCategory::Encryption);
        assert_eq!(parsed.scope, TopErrorScope::Outer, "missing scope field must default to Outer");
        assert_eq!(parsed.message, "capsule is encrypted (cipher: ChaCha20-Poly1305)");

        // And v0.6 shape with an explicit scope round-trips.
        let v06_json = r#"{"category":"encryption","scope":"inner","message":"L3: decryption failed"}"#;
        let parsed: TopError = serde_json::from_str(v06_json).expect("v0.6 JSON must deserialize");
        assert_eq!(parsed.scope, TopErrorScope::Inner);
        let reserialized = serde_json::to_string(&parsed).expect("must reserialize");
        assert!(reserialized.contains(r#""scope":"inner""#));
    }

    /// Unit test on the inner manifest_hash recompute helper: extract the
    /// inner manifest from `clean-encrypted.capsule`, mutate
    /// `inner_manifest.created_at` (a field that affects JCS canonicalization
    /// but doesn't break parsing), recompute the manifest_hash via the
    /// existing helper, and confirm the result differs from the original
    /// `inner_envelope.manifest_hash`.
    ///
    /// This documents that IF inner manifest tampering is somehow injected
    /// (the v0.5 shipped tooling has no such builder, hence no full
    /// integration fixture), the helper would catch it. We drive the helper
    /// directly so the test does not depend on a tampered-inner fixture.
    #[test]
    fn mutated_inner_manifest_hash_unit_test() {
        // Step 1: unpack the outer ZIP and parse outer manifest+envelope so
        // we have the inputs `decrypt_inner_zip` needs.
        let bytes = tampered_capsule_bytes("clean-encrypted.capsule");
        let outer_files = unpack_zip(&bytes).expect("outer zip must unpack");
        let outer_manifest: Manifest =
            serde_json::from_slice(outer_files.get("manifest.json").unwrap())
                .expect("outer manifest must parse");
        let outer_envelope: Envelope = serde_json::from_slice(
            outer_files.get("provenance/envelope.json").unwrap(),
        )
        .expect("outer envelope must parse");

        // Step 2: decrypt → unpack inner ZIP → parse inner manifest +
        // inner envelope.
        let inner_zip_bytes = decrypt_inner_zip(
            &outer_envelope,
            &outer_manifest,
            &outer_files,
            &recipient_x25519_private_key(),
        )
        .expect("decryption must succeed for clean-encrypted");
        let inner_files = unpack_zip(&inner_zip_bytes).expect("inner zip must unpack");
        let mut inner_manifest: Manifest = serde_json::from_slice(
            inner_files
                .get("manifest.json")
                .expect("inner manifest must be present"),
        )
        .expect("inner manifest JSON must parse");
        let inner_envelope: Envelope = serde_json::from_slice(
            inner_files
                .get("provenance/envelope.json")
                .expect("inner envelope must be present"),
        )
        .expect("inner envelope JSON must parse");

        // Sanity check: the unmutated inner manifest_hash matches the inner
        // envelope's claim.
        let pre = manifest_hash(&inner_manifest);
        assert_eq!(
            pre, inner_envelope.manifest_hash,
            "inner manifest_hash must verify before mutation"
        );

        // Step 3: mutate `created_at` to a value that differs from the
        // original. Picking a fixed past date keeps the test deterministic
        // regardless of when the fixture was generated.
        inner_manifest.created_at = "1999-01-01T00:00:00Z".to_string();

        // Step 4: re-run the helper. The recomputed manifest_hash must
        // differ from the inner envelope's stored claim.
        let post = manifest_hash(&inner_manifest);
        assert_ne!(
            post, inner_envelope.manifest_hash,
            "mutated inner manifest_hash must differ from the inner envelope's claim"
        );
    }
}

//! `capsule-verify-cli` exposes the `capsule-verify` library as a small
//! command-line tool. The `verify` subcommand reads a Capsule artifact
//! from disk, runs [`capsule_verify::verify_capsule`] over its bytes, and
//! prints the result either as a human-readable plain-text report or as
//! pretty-printed JSON.
//!
//! Exit codes:
//!   0  PASS (the capsule verified cleanly)
//!   1  FAIL (verification ran but rejected the capsule)
//!   2  I/O / argument error (file not found, permission denied, etc.)

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine;
use capsule_verify::{
    verify_capsule, EnvelopeCheck, SignerOutcome, TopErrorCategory, VerifyOptions, VerifyResult,
};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "capsule-verify-cli",
    version,
    about = "Verify Capsule artifacts.",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Verify a Capsule artifact at FILE.
    Verify {
        /// Path to the Capsule artifact (.capsule / .zip).
        file: PathBuf,
        /// Trusted Ed25519 public keys (lowercase hex, 64 chars). May be
        /// repeated, or passed as a space-separated list. A signer is
        /// marked `trusted` only when its key appears here AND its
        /// signature verifies.
        #[arg(long = "allowlist", num_args = 1.., value_delimiter = ' ')]
        allowlist: Vec<String>,
        /// Recipient's X25519 private key for L3 (decrypted-content)
        /// verification. Accepts either a 64-character lowercase hex
        /// string OR a path to a file containing 32 raw bytes, a 64-char
        /// hex string, or a base64-encoded 32-byte key. When provided
        /// against an encrypted capsule, the verifier decrypts the inner
        /// ZIP and walks the inner chain. When provided against a plain
        /// capsule, the flag is silently ignored.
        #[arg(long = "decryption-key", value_name = "KEY")]
        decryption_key: Option<String>,
        /// Emit the full VerifyResult as pretty-printed JSON instead of
        /// the plain-text report. Hashes appear in full hex form in JSON
        /// mode.
        #[arg(long = "json", default_value_t = false)]
        json: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Verify {
            file,
            allowlist,
            decryption_key,
            json,
        } => run_verify(&file, allowlist, decryption_key, json),
    }
}

/// Read `path` and run [`verify_capsule`] over its contents. Print either
/// JSON or a plain-text report and return the appropriate exit code.
fn run_verify(
    path: &Path,
    allowlist: Vec<String>,
    decryption_key: Option<String>,
    json: bool,
) -> ExitCode {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read {}: {}", path.display(), e);
            return ExitCode::from(2);
        }
    };

    // Reject a malformed --allowlist before verification runs: a value
    // that is not a 32-byte Ed25519 public key can never match a signer,
    // so the run would otherwise report trusted=false with only a note
    // buried in the result to explain why.
    if let Err(msg) = validate_allowlist(&allowlist) {
        eprintln!("{msg}");
        return ExitCode::from(2);
    }

    // Resolve --decryption-key (if given) into a 32-byte X25519 private key.
    // Any parse / length failure exits 2 with a clear stderr message;
    // omitting the flag preserves v0.2 behavior exactly.
    let recipient_private_key = match decryption_key.as_deref() {
        None => None,
        Some(value) => match parse_decryption_key(value) {
            Ok(k) => Some(k),
            Err(msg) => {
                eprintln!("{msg}");
                return ExitCode::from(2);
            }
        },
    };

    let result = verify_capsule(
        &bytes,
        &VerifyOptions {
            allowlist,
            recipient_private_key,
        },
    );

    if json {
        match serde_json::to_string_pretty(&result) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("error: failed to serialize VerifyResult to JSON: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        print_plain(path, bytes.len(), &result);
    }

    if result.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Render a `VerifyResult` to stdout in a human-readable form.
///
/// Hashes are truncated for readability via [`short_hash`]; the full hex
/// is preserved in the embedded error messages and in the JSON output
/// (which is what forensics use).
fn print_plain(path: &Path, byte_len: usize, r: &VerifyResult) {
    // Best-effort lookup of the originator pubkey + signed_at out of the
    // first signer; the structured `VerifyResult` doesn't carry the raw
    // manifest, so we surface what's available without re-parsing.
    let originator = r
        .envelope
        .signers
        .iter()
        .find(|s| s.role == "originator")
        .map(|s| s.public_key.clone());

    println!("File:                   {} ({} bytes)", path.display(), byte_len);
    if !r.capsule_id.is_empty() {
        println!("Capsule ID:             {}", short_hash(&r.capsule_id));
    }
    if let Some(ref pk) = originator {
        println!("Originator (Ed25519):   {}", short_hash(pk));
    }
    if !r.signed_at.is_empty() {
        println!("Sealed at:              {}", r.signed_at);
    }
    println!("Level:                  {}", r.level);
    println!();

    println!("Checks:");

    // Each per-check line is driven directly by the categorized errors
    // produced by the verifier — no substring matching, no implicit
    // mapping. If the verifier adds a new error category later,
    // `errors_for` will return Vec::new() until a renderer line is added,
    // making the gap explicit.

    let format_msgs = strings_of(errors_for(r, TopErrorCategory::FormatVersion));
    print_check("format / version", format_msgs.is_empty(), format_msgs);

    // capsule_id and manifest_hash share a single "identity" line,
    // matching the previous CLI behavior.
    let mut id_msgs = strings_of(errors_for(r, TopErrorCategory::CapsuleId));
    id_msgs.extend(strings_of(errors_for(r, TopErrorCategory::ManifestHash)));
    print_check("capsule_id / manifest_hash", id_msgs.is_empty(), id_msgs);

    print_check(
        "content_index",
        r.content_index.ok,
        r.content_index.errors.clone(),
    );

    // Chain check. `chain.note` records a walk that legitimately did not
    // run: "deferred to L3 (encrypted outer)", or a zero-event chain whose
    // anchors were checked for null instead. The note always renders as
    // the indented sub-line so a not-walked chain is never presented as an
    // unqualified pass — but it does NOT force the glyph to PASS: anchor
    // violations (e.g. a claimed anchor over an empty chain) still render
    // the line as a failure with their messages underneath.
    let mut chain_msgs: Vec<String> = Vec::new();
    if let Some(note) = r.chain.note.as_deref() {
        chain_msgs.push(note.to_string());
    }
    chain_msgs.extend(r.chain.errors.clone());
    let anchor_msgs = strings_of(errors_for(r, TopErrorCategory::ChainAnchor));
    let chain_ok = r.chain.ok && r.chain.errors.is_empty() && anchor_msgs.is_empty();
    chain_msgs.extend(anchor_msgs);
    print_check("chain", chain_ok, chain_msgs);

    print_check(
        "envelope_signature",
        r.envelope.ok,
        format_envelope_messages(r),
    );

    // Signer-set binding: PRESENCE BINDS, ABSENCE REPORTS. An unbound set
    // renders as a PASS with an explicit sub-line so the lowered assurance
    // is visible; a bound-but-mismatched set renders the commitment errors
    // (also present under the SignerSet error category). Originator-binding
    // failures ride the same section — both are signer-set invariants.
    let mut signer_set_msgs = r.signer_set.errors.clone();
    signer_set_msgs.extend(strings_of(errors_for(r, TopErrorCategory::OriginatorBinding)));
    if !r.signer_set.bound && signer_set_msgs.is_empty() {
        print_check(
            "signer_set",
            r.signer_set.ok,
            vec!["unbound (manifest.signer_commitment absent)".to_string()],
        );
    } else {
        print_check(
            "signer_set",
            r.signer_set.ok && signer_set_msgs.is_empty(),
            signer_set_msgs,
        );
    }

    // Inner envelope signature check is rendered ONLY when L3 verification
    // reached the inner envelope and `inner_envelope` was populated. For
    // plain capsules, L2-only paths, and L3 paths that failed before the
    // inner envelope was parsed, the line is omitted entirely (no empty
    // section, no placeholder).
    if let Some(inner) = r.inner_envelope.as_ref() {
        print_check(
            "inner_envelope_signature",
            inner.ok,
            format_inner_envelope_messages(inner),
        );
    }

    // Inner content_index check is rendered ONLY when L3 verification reached
    // the inner content_index recompute and `inner_content_index` was
    // populated. For plain capsules, L2-only paths, and L3 paths that failed
    // before the inner content_index could be checked, the line is omitted
    // entirely — same gating shape as `inner_envelope_signature`.
    if let Some(inner_ci) = r.inner_content_index.as_ref() {
        print_check(
            "inner_content_index",
            inner_ci.ok,
            inner_ci.errors.clone(),
        );
    }

    // Declared-participant grammar violations (manifest.md actor_id
    // namespaces). Rendered only when present — a capsule with no
    // participants makes no claim for this line to report on.
    let actor_id_msgs = strings_of(errors_for(r, TopErrorCategory::ActorId));
    if !actor_id_msgs.is_empty() {
        print_check("participants", false, actor_id_msgs);
    }

    let enc_msgs = strings_of(errors_for(r, TopErrorCategory::Encryption));
    print_check("encryption_state", enc_msgs.is_empty(), enc_msgs);

    // Malformed errors (bad ZIP, bad JSON, bad hex). Most of these are
    // early-return paths so other checks won't have meaningful output,
    // but it's important to render them under their own line so the user
    // sees what went wrong.
    let malformed_msgs = strings_of(errors_for(r, TopErrorCategory::Malformed));
    if !malformed_msgs.is_empty() {
        print_check("container / parse", false, malformed_msgs);
    }

    println!();
    render_signers("Signers:", &r.envelope.signers);

    // Inner signers block is rendered ONLY when L3 verification reached the
    // inner envelope. Same shape as the outer Signers: block; omitted entirely
    // when `inner_envelope.is_none()` (plain capsule / L2-only / L3 failure
    // before inner envelope parse).
    if let Some(inner) = r.inner_envelope.as_ref() {
        render_signers("Inner signers:", &inner.signers);
    }

    if !r.notes.is_empty() {
        println!("Notes:");
        for n in &r.notes {
            println!("  - {n}");
        }
        println!();
    }

    if r.ok {
        println!("Result: PASS");
    } else {
        println!("Result: FAIL");
    }
}

/// Print a single `[✓]` or `[✗]` check line, indenting any error
/// messages underneath when the check failed. With every error now
/// categorized, OK checks have no messages to display, so the renderer
/// collapses to two cases.
fn print_check(name: &str, ok: bool, msgs: Vec<String>) {
    let glyph = if ok { "[\u{2713}]" } else { "[\u{2717}]" };
    if msgs.is_empty() {
        println!("  {glyph} {name}");
    } else {
        println!("  {glyph} {name}");
        for m in msgs {
            println!("        {m}");
        }
    }
}

/// Truncate a hex string to "first 12 + '\u{2026}'" for readable plain
/// output. Anything 12 chars or shorter is left alone.
fn short_hash(hex: &str) -> String {
    if hex.len() <= 12 {
        hex.to_string()
    } else {
        let prefix: String = hex.chars().take(12).collect();
        format!("{prefix}\u{2026}")
    }
}

/// Pull every error message belonging to `category` out of the result.
/// Drives the per-check renderer lines.
fn errors_for(result: &VerifyResult, category: TopErrorCategory) -> Vec<&str> {
    result
        .errors
        .iter()
        .filter(|e| e.category == category)
        .map(|e| e.message.as_str())
        .collect()
}

/// Convenience: collect a `Vec<&str>` into owned `Vec<String>` for the
/// renderer. Avoids ergonomic noise at every `errors_for` call site.
fn strings_of(refs: Vec<&str>) -> Vec<String> {
    refs.into_iter().map(|s| s.to_string()).collect()
}

fn format_envelope_messages(r: &VerifyResult) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(ref note) = r.envelope.note {
        out.push(note.clone());
    }
    for s in &r.envelope.signers {
        if !s.valid {
            out.push(format!(
                "signer {role} ({pk}) signature did not verify",
                role = s.role,
                pk = short_hash(&s.public_key),
            ));
        }
    }
    out
}

/// Build the indented message list for the `[✓/✗] inner_envelope_signature`
/// check line. Same shape as `format_envelope_messages` but driven by the
/// inner `EnvelopeCheck`. When the inner envelope has zero signers (`ok`
/// false with empty `signers`), a `note` may carry the explanatory string —
/// surface it so the operator sees *why* the line was marked failing.
fn format_inner_envelope_messages(inner: &EnvelopeCheck) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(ref note) = inner.note {
        out.push(note.clone());
    }
    for s in &inner.signers {
        if !s.valid {
            out.push(format!(
                "signer {role} ({pk}) signature did not verify",
                role = s.role,
                pk = short_hash(&s.public_key),
            ));
        }
    }
    out
}

/// Render a `Signers:` (or `Inner signers:`) block with the same per-signer
/// shape used everywhere in the plain output. Empty signer lists collapse
/// to no output at all (no header, no placeholder line) so encrypted-outer
/// L2 transcripts remain unchanged.
fn render_signers(label: &str, signers: &[SignerOutcome]) {
    if signers.is_empty() {
        return;
    }
    println!("{label}");
    for s in signers {
        println!(
            "  - {role:<12} {pubkey}  valid={valid}  trusted={trusted}",
            role = s.role,
            pubkey = short_hash(&s.public_key),
            valid = s.valid,
            trusted = s.trusted,
        );
    }
    println!();
}

/// Resolve a `--decryption-key <KEY>` argument into a 32-byte X25519
/// private key. Resolution order (mirrors README spec):
///
///   1. If `value` parses as exactly 64 lowercase hex chars → use as hex.
///   2. Else if `value` is a path that exists → read the file:
///         - 32 raw bytes              → use as raw.
///         - 64-char lowercase hex     → decode as hex.
///         - base64 yielding 32 bytes  → decode as base64.
///   3. Else → error.
///
/// On any failure, returns the formatted error string ready to print to
/// stderr (caller exits 2).
fn parse_decryption_key(value: &str) -> Result<[u8; 32], String> {
    // (1) Direct 64-char lowercase hex on the command line.
    if is_lower_hex_64(value) {
        return decode_hex_32(value).map_err(|_| {
            format!(
                "error: --decryption-key value is neither 64-char hex nor an existing file with a parseable key; got: {value}"
            )
        });
    }

    // (2) File path.
    let path = Path::new(value);
    if path.exists() {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                return Err(format!(
                    "error: --decryption-key cannot read file {}: {e}",
                    path.display()
                ));
            }
        };

        // 32 raw bytes.
        if bytes.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            return Ok(out);
        }

        // Trimmed text: try hex, then base64.
        let text = std::str::from_utf8(&bytes).unwrap_or("").trim();
        if is_lower_hex_64(text) {
            if let Ok(k) = decode_hex_32(text) {
                return Ok(k);
            }
        }
        if let Ok(decoded) = B64_STANDARD.decode(text) {
            if decoded.len() == 32 {
                let mut out = [0u8; 32];
                out.copy_from_slice(&decoded);
                return Ok(out);
            } else {
                return Err(format!(
                    "error: --decryption-key must be 32 bytes (64 hex chars or 32 raw bytes); got {} bytes",
                    decoded.len()
                ));
            }
        }

        // File exists but content didn't parse.
        return Err(format!(
            "error: --decryption-key value is neither 64-char hex nor an existing file with a parseable key; got: {value}"
        ));
    }

    // (3) No match.
    Err(format!(
        "error: --decryption-key value is neither 64-char hex nor an existing file with a parseable key; got: {value}"
    ))
}

/// Reject any `--allowlist` entry that cannot be an Ed25519 public key.
///
/// An Ed25519 public key is 32 raw bytes — exactly 64 hex characters
/// (any case; the library normalizes to lowercase, matching the JS
/// reference). A truncated or mangled entry simply never matches a
/// signer, and before F44 the non-empty vector also suppressed the
/// library's "no allowlist provided" advisory, so the operator saw a
/// PASS with `trusted=false` and no diagnostic. Fail loudly at the
/// argument boundary instead (exit 2), the same way an unparseable
/// `--decryption-key` does.
///
/// On the first bad entry, returns the formatted error string ready to
/// print to stderr.
fn validate_allowlist(allowlist: &[String]) -> Result<(), String> {
    for entry in allowlist {
        let well_formed = entry.len() == 64 && entry.bytes().all(|b| b.is_ascii_hexdigit());
        if !well_formed {
            return Err(format!(
                "error: --allowlist entry must be 64 hex chars (a 32-byte Ed25519 public key); got: {entry}"
            ));
        }
    }
    Ok(())
}

/// True iff `s` is exactly 64 ASCII characters drawn from `0-9a-f`.
fn is_lower_hex_64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Decode a 64-char lowercase hex string into a `[u8; 32]`.
fn decode_hex_32(s: &str) -> Result<[u8; 32], hex::FromHexError> {
    let bytes = hex::decode(s)?;
    if bytes.len() != 32 {
        return Err(hex::FromHexError::InvalidStringLength);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The originator key shape from the fixture registries: 64 hex chars.
    #[test]
    fn validate_allowlist_accepts_64_hex() {
        let good =
            vec!["cc76ce271ed61e515b598d73290a2b3905f40f280fa1548ed7f0513bdbe0c2bc".to_string()];
        assert!(validate_allowlist(&good).is_ok());
        assert!(validate_allowlist(&[]).is_ok(), "no allowlist is not an error");
        // The library accepts any-case hex (JS toKeyHex parity), so the
        // CLI boundary must not reject what the library would honour.
        let upper =
            vec!["CC76CE271ED61E515B598D73290A2B3905F40F280FA1548ED7F0513BDBE0C2BC".to_string()];
        assert!(validate_allowlist(&upper).is_ok());
    }

    /// A truncated paste is the exact failure this guard exists for: it
    /// can never match a signer, yet before F44 it also suppressed the
    /// "no allowlist provided" advisory — PASS, trusted=false, silence.
    #[test]
    fn validate_allowlist_rejects_truncated_entry() {
        let truncated = vec!["cc76ce271ed61e515b598d73290a2b39".to_string()];
        let err = validate_allowlist(&truncated).expect_err("truncated key must be rejected");
        assert!(err.contains("--allowlist"), "message must name the flag; got: {err}");
        assert!(
            err.contains("64 hex"),
            "message must state the expected shape; got: {err}"
        );
        assert!(
            err.contains("cc76ce271ed61e515b598d73290a2b39"),
            "message must name the offending entry; got: {err}"
        );
    }

    /// Non-hex garbage (a path, a 0x prefix, base64) is rejected outright.
    #[test]
    fn validate_allowlist_rejects_non_hex() {
        let non_hex =
            vec!["zz76ce271ed61e515b598d73290a2b3905f40f280fa1548ed7f0513bdbe0c2bc".to_string()];
        assert!(validate_allowlist(&non_hex).is_err());
        assert!(validate_allowlist(&["./keys.json".to_string()]).is_err());
    }
}

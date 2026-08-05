//! `capsule-verify-cli` exposes the `capsule-verify` library as a small
//! command-line tool. The `verify` subcommand reads a Capsule artifact
//! from disk, runs [`capsule_verify::verify_capsule`] over its bytes, and
//! prints the result either as a human-readable plain-text report or as
//! pretty-printed JSON.
//!
//! Exit codes (spec/results.md "CLI reference renderer"):
//!   0  VALID and every requested policy satisfied
//!   1  INVALID, UNSUPPORTED, or a requested policy failed
//!   2  usage / I-O error (file not found, permission denied, bad flag value)

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine;
use capsule_verify::{
    verify_capsule, EnvelopeCheck, SignerOutcome, TopErrorCategory, Verdict, VerifyOptions,
    VerifyResult,
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
        /// signature verifies. Supplying the flag REQUESTS a trust
        /// policy: a run whose allowlist matched no signer keeps its
        /// `valid` verdict — the math is unaffected — but exits 1.
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
        /// Format versions this deployment ACCEPTS (spec/versioning.md
        /// "Host policy"). May be repeated, or passed as a
        /// space-separated list. Reported, never decided: a capsule
        /// outside the set still verifies — its verdict carries the
        /// `version_not_accepted_by_policy` qualifier — but because the
        /// policy was REQUESTED on this command line, failing it exits 1.
        #[arg(long = "accept-versions", num_args = 1.., value_delimiter = ' ')]
        accept_versions: Vec<String>,
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
            accept_versions,
            json,
        } => ExitCode::from(run_verify(
            &file,
            allowlist,
            decryption_key,
            accept_versions,
            json,
        )),
    }
}

/// Read `path` and run [`verify_capsule`] over its contents. Print either
/// JSON or a plain-text report and return the appropriate exit code.
/// Returns the raw code rather than an `ExitCode` so the whole path —
/// flag handling included — is assertable from a unit test.
fn run_verify(
    path: &Path,
    allowlist: Vec<String>,
    decryption_key: Option<String>,
    accept_versions: Vec<String>,
    json: bool,
) -> u8 {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read {}: {}", path.display(), e);
            return 2;
        }
    };

    // Reject a malformed --allowlist before verification runs: a value
    // that is not a 32-byte Ed25519 public key can never match a signer,
    // so the run would otherwise report trusted=false with only a note
    // buried in the result to explain why.
    if let Err(msg) = validate_allowlist(&allowlist) {
        eprintln!("{msg}");
        return 2;
    }
    let allowlist_requested = !allowlist.is_empty();

    // Resolve --decryption-key (if given) into a 32-byte X25519 private key.
    // Any parse / length failure exits 2 with a clear stderr message;
    // omitting the flag preserves v0.2 behavior exactly.
    let recipient_private_key = match decryption_key.as_deref() {
        None => None,
        Some(value) => match parse_decryption_key(value) {
            Ok(k) => Some(k),
            Err(msg) => {
                eprintln!("{msg}");
                return 2;
            }
        },
    };

    let result = verify_capsule(
        &bytes,
        &VerifyOptions {
            allowlist,
            recipient_private_key,
            // Absent flag = no policy declared, which is not the same as
            // an empty accepted set.
            accept_versions: (!accept_versions.is_empty()).then_some(accept_versions),
        },
    );

    if json {
        match serde_json::to_string_pretty(&result) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("error: failed to serialize VerifyResult to JSON: {e}");
                return 2;
            }
        }
    } else {
        print_plain(path, bytes.len(), &result);
    }

    verify_exit_code(&result, allowlist_requested)
}

/// Exit code for a completed verification (spec/results.md "CLI reference
/// renderer"): `0` iff the verdict is VALID and every policy this
/// invocation REQUESTED is satisfied, `1` otherwise.
///
/// A failed policy is not corruption — the verdict stays `valid` and the
/// qualifier says why the exit code does not — but a demand the operator
/// typed on THIS command line and the capsule did not meet must fail the
/// run, identically in both reference CLIs (the Node CLI computes the
/// same two policies in `cli/src/commands/verify.mjs`). The report-never-
/// decide rule of spec/trust.md governs the verify RESULT, which still
/// reports per-signer `valid` and never `trusted`; the requested-policy
/// layer lives here, in the CLI.
///
/// `trusted_signer_count` counts DISTINCT keys that are both valid and
/// allowlisted, so duplicate signer rows cannot satisfy `--allowlist`.
fn verify_exit_code(r: &VerifyResult, allowlist_requested: bool) -> u8 {
    let version_policy_ok = r.format_version.accepted_by_policy != Some(false);
    let trust_policy_ok = !allowlist_requested || r.trusted_signer_count > 0;
    if r.verdict == Verdict::Valid && version_policy_ok && trust_policy_ok {
        0
    } else {
        1
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
    // The observed profile declaration is a reported fact on every result
    // (spec/profiles.md obligation 8) — including refusals, where it is
    // what lets an operator route the capsule to a capable verifier
    // instead of concluding it is corrupt.
    if let Some(line) = profile_line(r) {
        println!("Profile:                {line}");
    }
    println!();

    println!("Checks:");

    // Each per-check line is driven directly by the categorized errors
    // produced by the verifier — no substring matching, no implicit
    // mapping. If the verifier adds a new error category later,
    // `errors_for` will return Vec::new() until a renderer line is added,
    // making the gap explicit.

    let format_msgs = strings_of(errors_for(r, TopErrorCategory::FormatVersion));
    print_check("format / version", format_msgs.is_empty(), format_msgs);

    // Profile-gate refusals get their own line, carrying the cross-lane
    // refusal wording verbatim. Rendered only when present: a capsule that
    // declares nothing makes no claim for this line to report on, and the
    // `Profile:` header above already states what governed verification.
    let profile_msgs = strings_of(errors_for(r, TopErrorCategory::Profile));
    if !profile_msgs.is_empty() {
        print_check("profile", false, profile_msgs);
    }

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

    for line in result_block(r) {
        println!("{line}");
    }
}

/// The `Profile:` header line (spec/profiles.md "Reporting"): what
/// governed this verification, or what was declared and refused. `None`
/// only when nothing was read at all — a container this verifier could not
/// open declares nothing to report.
fn profile_line(r: &VerifyResult) -> Option<String> {
    let observed = || match (r.profile.observed.as_deref(), r.profile.observed_version.as_deref()) {
        (Some(id), Some(version)) => format!("{id} {version}"),
        (Some(id), None) => id.to_string(),
        _ => "(unreadable declaration)".to_string(),
    };
    let line = match r.profile.status.as_str() {
        "default" if r.profile.declared => format!(
            "{} (default, declared)",
            r.profile.effective.as_deref().unwrap_or("v0.6-suite")
        ),
        "default" => format!(
            "{} (default, undeclared)",
            r.profile.effective.as_deref().unwrap_or("v0.6-suite")
        ),
        "supported" => format!("{} (declared)", observed()),
        "unsupported" => format!("{} (not supported by this verifier)", observed()),
        "mismatched" => format!(
            "{} (manifest and envelope declarations disagree)",
            observed()
        ),
        "invalid" => "(declaration malformed)".to_string(),
        "unevaluated" if r.profile.declared => {
            format!("{} (not evaluated: the version gate refused first)", observed())
        }
        "unevaluated" => "(not evaluated: the version gate refused first)".to_string(),
        _ if r.profile.declared => format!("{} (unread)", observed()),
        _ => return None,
    };
    Some(line)
}

/// The verdict-first Result block (spec/results.md "CLI reference
/// renderer"). A conforming renderer MUST NOT present a valid verdict
/// without rendering every qualifier beside it — an unsurfaced qualifier
/// turns an honest weaker claim by the author into a false stronger claim
/// by the tooling. Returned as lines so the wording is unit-testable.
fn result_block(r: &VerifyResult) -> Vec<String> {
    match r.verdict {
        Verdict::Valid if r.qualifiers.is_empty() => {
            let n = r.trusted_signer_count;
            vec![format!(
                "Result: VALID (no qualifiers; {n} distinct trusted signer{})",
                if n == 1 { "" } else { "s" }
            )]
        }
        Verdict::Valid => {
            let mut lines = vec!["Result: VALID".to_string(), "  qualifiers:".to_string()];
            lines.extend(r.qualifiers.iter().map(|q| format!("    - {}", qualifier_line(q, r))));
            lines
        }
        Verdict::Invalid => vec!["Result: INVALID".to_string()],
        Verdict::Unsupported => {
            let reason = r.verdict_reason.as_deref().unwrap_or("unsupported");
            match refusal_message(r) {
                Some(message) => vec![format!("Result: UNSUPPORTED ({reason}: {message})")],
                None => vec![format!("Result: UNSUPPORTED ({reason})")],
            }
        }
    }
}

/// Human rendering for one qualifier. Each carries the minimum substring
/// spec/results.md requires of any conforming renderer. A qualifier this
/// renderer does not know — a later spec revision's name, or a vendor
/// `x-` entry — is surfaced VERBATIM and never silently dropped.
fn qualifier_line(qualifier: &str, r: &VerifyResult) -> String {
    match qualifier {
        "signer_set_unbound" => {
            "signer set is not bound by the seal (manifest.signer_commitment absent)".to_string()
        }
        "actor_set_unbound" => {
            "actors are not bound to a declared participant set (manifest.participants empty)"
                .to_string()
        }
        "empty_chain_not_walked" => {
            "empty chain: no events to walk; anchors checked null".to_string()
        }
        "encrypted_outer_only" => {
            "content is encrypted and was not read (L2 outer only; chain deferred to L3)"
                .to_string()
        }
        "version_not_accepted_by_policy" => format!(
            "format version {} is not in the declared accepted set of this host",
            r.format_version.observed.as_deref().unwrap_or("(unread)")
        ),
        "trust_not_evaluated" => "trust not evaluated: no allowlist supplied".to_string(),
        "no_trusted_signer" => {
            "allowlist matched no signer; trusted=false for all signers".to_string()
        }
        other => other.to_string(),
    }
}

/// The diagnosis behind an `unsupported` verdict: the version- or
/// profile-gate refusal message, which carries the cross-lane needles
/// ("newer than this verifier supports", "is not supported by this
/// verifier"). Both categories are exclusive diagnoses, so the first
/// message is the whole story.
fn refusal_message(r: &VerifyResult) -> Option<String> {
    r.errors
        .iter()
        .find(|e| {
            matches!(
                e.category,
                TopErrorCategory::FormatVersion | TopErrorCategory::Profile
            )
        })
        .map(|e| e.message.clone())
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
    use std::path::PathBuf;

    fn vectors_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec/vectors")
    }

    /// Verify a checked-in conformance fixture through the same entry
    /// point the binary uses.
    fn verify_vector(relative: &str, options: VerifyOptions) -> VerifyResult {
        let path = vectors_dir().join(relative);
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        verify_capsule(&bytes, &options)
    }

    /// The public key a collection's fixtures are signed with, read from
    /// its keys_file — never hardcoded, so a regenerated collection cannot
    /// leave a test asserting against a stale key.
    fn fixture_public_key(collection: &str) -> String {
        let path = vectors_dir().join(collection).join("output/keys.json");
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        let keys: serde_json::Value = serde_json::from_slice(&bytes).expect("keys.json parses");
        keys.pointer("/originator/publicKey")
            .and_then(|k| k.as_str())
            .expect("keys.json carries originator.publicKey")
            .to_string()
    }

    /// spec/results.md: a renderer MUST NOT present a valid verdict
    /// without rendering every qualifier beside it, each carrying its
    /// required minimum substring.
    #[test]
    fn result_block_renders_every_qualifier_with_its_required_substring() {
        let r = verify_vector(
            "chain-binding/output/empty-chain-null-anchors.capsule",
            VerifyOptions::default(),
        );
        assert_eq!(r.verdict, Verdict::Valid);
        let block = result_block(&r).join("\n");
        assert!(block.starts_with("Result: VALID\n  qualifiers:"), "{block}");
        for (qualifier, needle) in [
            ("empty_chain_not_walked", "no events to walk"),
            ("trust_not_evaluated", "no allowlist"),
        ] {
            assert!(
                r.qualifiers.iter().any(|q| q == qualifier),
                "{qualifier} must be derived; got {:?}",
                r.qualifiers
            );
            assert!(block.contains(needle), "{needle:?} missing from {block:?}");
        }
    }

    /// An unqualified valid verdict states its trust basis explicitly —
    /// "VALID" alone would be the report lying by omission about how much
    /// was actually checked.
    #[test]
    fn unqualified_valid_states_its_trust_basis() {
        let r = verify_vector(
            "result-vocabulary/output/unqualified-valid.capsule",
            VerifyOptions {
                allowlist: vec![fixture_public_key("result-vocabulary")],
                ..VerifyOptions::default()
            },
        );
        assert_eq!(r.verdict, Verdict::Valid);
        assert!(r.qualifiers.is_empty(), "got {:?}", r.qualifiers);
        assert_eq!(
            result_block(&r),
            vec!["Result: VALID (no qualifiers; 1 distinct trusted signer)".to_string()]
        );
    }

    /// The same bytes under an allowlist that matches nothing: valid math,
    /// zero trusted signers — a PASS that must never be silent about why.
    #[test]
    fn allowlist_that_matched_nothing_says_so() {
        let r = verify_vector(
            "result-vocabulary/output/unqualified-valid.capsule",
            VerifyOptions {
                allowlist: vec!["11".repeat(32)],
                ..VerifyOptions::default()
            },
        );
        assert_eq!(r.verdict, Verdict::Valid);
        assert_eq!(r.qualifiers, vec!["no_trusted_signer".to_string()]);
        assert!(result_block(&r).join("\n").contains("matched no signer"));
    }

    /// Drive the whole `verify` path — flag handling included — the way
    /// the binary does, so the exit code is asserted and not merely the
    /// text printed above it.
    fn exit_code_for(relative: &str, allowlist: Vec<String>, accept_versions: Vec<String>) -> u8 {
        run_verify(
            &vectors_dir().join(relative),
            allowlist,
            None,
            accept_versions,
            false,
        )
    }

    /// spec/results.md exit contract: `0` = VALID and every REQUESTED
    /// policy satisfied. Both policies are demands the operator typed on
    /// this command line, so an unmet one fails the run beside a verdict
    /// that stays `valid` — the same rule the Node CLI pins in
    /// `cli/test/smoke.mjs` ("unmatched allowlist exits 1"). Rendering the
    /// failed policy and then exiting 0 is how the two reference CLIs came
    /// to disagree about `--allowlist`.
    #[test]
    fn requested_policies_decide_the_exit_code() {
        const CAPSULE: &str = "result-vocabulary/output/unqualified-valid.capsule";
        let signer = fixture_public_key("result-vocabulary");

        assert_eq!(
            exit_code_for(CAPSULE, vec![], vec![]),
            0,
            "no flag, no demand: an unallowlisted run is qualified, not failed"
        );
        assert_eq!(
            exit_code_for(CAPSULE, vec![signer], vec![]),
            0,
            "the allowlisted signer satisfies the requested trust policy"
        );
        assert_eq!(
            exit_code_for(CAPSULE, vec!["11".repeat(32)], vec![]),
            1,
            "allowlist matched no signer: the operator's demand went unmet"
        );
        assert_eq!(
            exit_code_for(CAPSULE, vec![], vec!["0.6".to_string()]),
            1,
            "the declared accepted set excludes this capsule's version"
        );
        assert_eq!(
            exit_code_for(
                "profile-declaration/output/unsupported-vendor-profile.capsule",
                vec![],
                vec![]
            ),
            1,
            "UNSUPPORTED is a verdict about the capsule-verifier pair, never exit 2"
        );
        assert_eq!(
            exit_code_for("tamper-detection/output/tampered-payload.capsule", vec![], vec![]),
            1,
            "INVALID"
        );
        assert_eq!(
            exit_code_for("result-vocabulary/output/no-such-fixture.capsule", vec![], vec![]),
            2,
            "an unreadable file is an operator error, not a verdict"
        );
    }

    /// spec/profiles.md: the refusal is a limitation of the VERIFIER, and
    /// both the verdict line and the header line have to say so — the
    /// operator's remediation is "verify it with an implementation of that
    /// profile", not "this file is corrupt".
    #[test]
    fn unsupported_profile_renders_the_cross_lane_needles() {
        let r = verify_vector(
            "profile-declaration/output/unsupported-vendor-profile.capsule",
            VerifyOptions::default(),
        );
        assert_eq!(r.verdict, Verdict::Unsupported);
        let block = result_block(&r).join("\n");
        assert!(block.starts_with("Result: UNSUPPORTED (unsupported_profile:"), "{block}");
        assert!(block.contains("is not supported by this verifier"), "{block}");
        assert!(
            block.contains("not corruption of the capsule"),
            "the remediation must be visible: {block}"
        );
        assert_eq!(
            profile_line(&r).as_deref(),
            Some("x-test-kms-1 1.0 (not supported by this verifier)")
        );
    }

    /// A profile mismatch is a capsule SELF-CONTRADICTION — a defect —
    /// so it renders INVALID with no verdict_reason, never "unsupported"
    /// (which would hand the operator a false remediation).
    #[test]
    fn profile_mismatch_renders_invalid() {
        let r = verify_vector(
            "profile-declaration/output/profile-mismatch-value.capsule",
            VerifyOptions::default(),
        );
        assert_eq!(r.verdict, Verdict::Invalid);
        assert_eq!(r.verdict_reason, None);
        assert_eq!(result_block(&r), vec!["Result: INVALID".to_string()]);
    }

    /// The absence rule made visible: an undeclared capsule reports the
    /// default profile as what actually governed verification.
    #[test]
    fn undeclared_capsule_reports_the_default_profile() {
        let r = verify_vector(
            "tamper-detection/output/clean.capsule",
            VerifyOptions::default(),
        );
        assert_eq!(
            profile_line(&r).as_deref(),
            Some("v0.6-suite (default, undeclared)")
        );
    }

    /// --accept-versions is a REQUESTED policy: the capsule still verifies
    /// (the SDK reports, the host decides), and the qualifier says why the
    /// exit code will not be 0.
    #[test]
    fn declared_version_policy_is_reported_as_a_qualifier() {
        let r = verify_vector(
            "tamper-detection/output/clean.capsule",
            VerifyOptions {
                accept_versions: Some(vec!["0.6".to_string()]),
                ..VerifyOptions::default()
            },
        );
        assert!(r.ok, "host policy never decides integrity");
        assert_eq!(r.verdict, Verdict::Valid);
        assert!(
            r.qualifiers
                .iter()
                .any(|q| q == "version_not_accepted_by_policy"),
            "got {:?}",
            r.qualifiers
        );
        assert!(result_block(&r)
            .join("\n")
            .contains("not in the declared accepted set"));
        assert_eq!(r.format_version.accepted_by_policy, Some(false));
    }

    /// A qualifier this renderer does not know — a later spec revision's
    /// name, or a vendor `x-` entry — is surfaced VERBATIM. Treating an
    /// unknown qualifier as ignorable is the one consumer behavior
    /// spec/results.md forbids outright.
    #[test]
    fn unknown_qualifiers_are_surfaced_verbatim() {
        let r = verify_vector(
            "tamper-detection/output/clean.capsule",
            VerifyOptions::default(),
        );
        assert_eq!(qualifier_line("x-acme-policy-stale", &r), "x-acme-policy-stale");
        assert_eq!(
            qualifier_line("lineage_declared_unverified", &r),
            "lineage_declared_unverified"
        );
    }

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

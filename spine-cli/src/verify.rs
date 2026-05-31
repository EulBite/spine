// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite

//! CLI shim over [`spine_core::verify_wal_bytes_with_options`].

use std::fs;
use std::path::Path;

use spine_core::{
    verify_demo_wal, verify_wal_bytes_with_options, DemoRecordOutcome, DemoReport, DemoStatus,
    Keystore, LenientOptions, VerificationResult,
};

use crate::wal_io::{read_wal_bytes, WalIoError};
use crate::OutputFormat;

#[derive(Debug, thiserror::Error)]
pub enum VerifyCmdError {
    #[error("{0}")]
    Io(#[from] WalIoError),

    #[error("Keystore could not be loaded: {0}")]
    Keystore(String),

    /// Bad flag combination or a strict configuration the verifier
    /// could not run with (for example a malformed pinned pubkey).
    /// Maps to exit code 2.
    #[error("{0}")]
    Usage(String),

    #[error("Output write failed: {0}")]
    OutputWrite(std::io::Error),

    #[error("Report serialisation failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    wal_path: &Path,
    expected_root: Option<&str>,
    output_path: Option<&Path>,
    fail_fast: bool,
    keystore_path: Option<&Path>,
    trusted_pubkey: Option<&str>,
    strict: bool,
    manifest_version: u32,
    format: OutputFormat,
) -> Result<bool, VerifyCmdError> {
    let bytes = read_wal_bytes(wal_path)?;

    if strict {
        return run_strict(
            &bytes,
            expected_root,
            trusted_pubkey,
            keystore_path,
            manifest_version,
            output_path,
            format,
        );
    }

    let keystore = match keystore_path {
        Some(p) => {
            Some(Keystore::load_from_file(p).map_err(|e| VerifyCmdError::Keystore(e.to_string()))?)
        }
        None => None,
    };

    let opts = LenientOptions {
        expected_root,
        keystore: keystore.as_ref(),
        fail_fast,
        trusted_pubkey,
    };

    // verify_wal_bytes_with_options no longer returns Err: the
    // partial report (records up to a fail-fast halt, plus the
    // failing error in result.errors) is always emitted. We just
    // surface it as-is.
    let mut result = verify_wal_bytes_with_options(&bytes, &opts);
    maybe_add_profile_hint(&mut result);

    emit_report(&result, output_path, format)?;
    Ok(result.valid)
}

/// When every record fails signature verification under the lenient
/// profile, the likeliest cause is not tampering but a profile
/// mismatch: a strict-signed WAL (domain-separated signatures, e.g.
/// the published Spine demo WAL) fed to the lenient verifier. A wall
/// of identical `invalid_signature` errors reads as catastrophe; this
/// hint points the user at `--strict` instead. We only fire it when
/// the failure count covers EVERY verified record, which is the
/// fingerprint of a wrong-profile run rather than partial tampering.
fn maybe_add_profile_hint(result: &mut VerificationResult) {
    if result.valid || result.events_verified == 0 {
        return;
    }
    let sig_failures = result
        .errors
        .iter()
        .filter(|e| e.error_type == "invalid_signature")
        .count() as u64;
    if sig_failures > 0 && sig_failures == result.events_verified {
        result.warnings.push(
            "All records failed signature verification under the lenient profile. \
             If this is a strict-profile WAL (for example the Spine demo WAL), re-run \
             with --strict --trusted-pubkey <hex> --expected-root <hex>."
                .to_string(),
        );
    }
}

/// Strict-profile verification: a thin shim over
/// [`spine_core::verify_demo_wal`], the exact contract the browser
/// playground runs. The pinned key and expected root are mandatory;
/// `--keystore` is rejected because strict does not check receipts.
#[allow(clippy::too_many_arguments)]
fn run_strict(
    bytes: &[u8],
    expected_root: Option<&str>,
    trusted_pubkey: Option<&str>,
    keystore_path: Option<&Path>,
    manifest_version: u32,
    output_path: Option<&Path>,
    format: OutputFormat,
) -> Result<bool, VerifyCmdError> {
    if keystore_path.is_some() {
        return Err(VerifyCmdError::Usage(
            "--keystore is not used by the strict profile (receipts are not checked in strict mode)"
                .to_string(),
        ));
    }
    let pubkey = trusted_pubkey.ok_or_else(|| {
        VerifyCmdError::Usage(
            "strict profile requires --trusted-pubkey (the externally pinned signing key)"
                .to_string(),
        )
    })?;
    let root = expected_root.ok_or_else(|| {
        VerifyCmdError::Usage("strict profile requires --expected-root".to_string())
    })?;

    // Match the lenient path's tolerance for an optional `0x` prefix
    // and surrounding whitespace so the same root string works under
    // either profile.
    let pubkey = normalize_hex(pubkey);
    let root = normalize_hex(root);

    let report = verify_demo_wal(bytes, &pubkey, &root, manifest_version);
    emit_strict_report(&report, output_path, format)?;

    match report.status {
        DemoStatus::Valid => Ok(true),
        DemoStatus::Invalid => Ok(false),
        // A configuration error (malformed pinned pubkey or root) is
        // a usage problem, not a verdict on the WAL: surface it as
        // exit 2 rather than letting it masquerade as "invalid".
        DemoStatus::Error => {
            Err(VerifyCmdError::Usage(report.error.unwrap_or_else(|| {
                "strict verification could not run".to_string()
            })))
        }
    }
}

/// Trim, strip an optional `0x`/`0X` prefix, and lowercase a hex
/// string, mirroring the lenient verifier's `expected_root`
/// normalisation.
fn normalize_hex(s: &str) -> String {
    let t = s.trim();
    t.strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t)
        .to_lowercase()
}

fn emit_report(
    result: &VerificationResult,
    output_path: Option<&Path>,
    format: OutputFormat,
) -> Result<(), VerifyCmdError> {
    match format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(result)?;
            if let Some(out) = output_path {
                fs::write(out, &json).map_err(VerifyCmdError::OutputWrite)?;
            } else {
                println!("{json}");
            }
        }
        OutputFormat::Text => {
            if let Some(out) = output_path {
                // Documented in main.rs's --format docstring: when a
                // file destination is given, content is JSON
                // regardless of the format flag. The text rendering
                // is terminal-only.
                let json = serde_json::to_string_pretty(result)?;
                fs::write(out, &json).map_err(VerifyCmdError::OutputWrite)?;
            } else {
                print_text_report(result);
            }
        }
        OutputFormat::Quiet => {
            if let Some(out) = output_path {
                let json = serde_json::to_string_pretty(result)?;
                fs::write(out, &json).map_err(VerifyCmdError::OutputWrite)?;
            }
        }
    }
    Ok(())
}

fn emit_strict_report(
    report: &DemoReport,
    output_path: Option<&Path>,
    format: OutputFormat,
) -> Result<(), VerifyCmdError> {
    // File output is always JSON, regardless of --format, matching the
    // lenient path's contract (see main.rs's --format docstring).
    match format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(report)?;
            if let Some(out) = output_path {
                fs::write(out, &json).map_err(VerifyCmdError::OutputWrite)?;
            } else {
                println!("{json}");
            }
        }
        OutputFormat::Text => {
            if let Some(out) = output_path {
                let json = serde_json::to_string_pretty(report)?;
                fs::write(out, &json).map_err(VerifyCmdError::OutputWrite)?;
            } else {
                print_strict_text_report(report);
            }
        }
        OutputFormat::Quiet => {
            if let Some(out) = output_path {
                let json = serde_json::to_string_pretty(report)?;
                fs::write(out, &json).map_err(VerifyCmdError::OutputWrite)?;
            }
        }
    }
    Ok(())
}

fn print_strict_text_report(report: &DemoReport) {
    let status = match report.status {
        DemoStatus::Valid => "VALID",
        DemoStatus::Invalid => "INVALID",
        DemoStatus::Error => "ERROR",
    };
    println!("Status: {status}");
    println!("Profile:             strict");
    println!("Verifier version:    {}", report.verifier_version);
    println!("Events verified:     {}", report.events_verified);
    println!("Signatures verified: {}", report.signatures_verified);
    println!("Expected pubkey fp:  {}", report.expected_pubkey_fp);
    if !report.chain_root.is_empty() {
        let short = short_hex(&report.chain_root, 16);
        println!("Chain root:          {short}...");
    }
    if let Some(err) = &report.error {
        println!("\nError: {err}");
    }
    let problems: Vec<&spine_core::DemoRecordEntry> = report
        .records
        .iter()
        .filter(|r| !matches!(r.outcome, DemoRecordOutcome::Valid))
        .collect();
    if !problems.is_empty() {
        println!("\nRecords with issues:");
        for r in problems {
            println!("  [seq {}] {}", r.sequence, describe_outcome(&r.outcome));
        }
    }
}

/// Render a non-valid strict outcome as `<outcome>: <reason.kind>`
/// (for example `invalid: payload_hash_mismatch`). Driven off the
/// serde tags so it stays correct as reason variants evolve, rather
/// than hand-maintaining a match over every variant.
fn describe_outcome(outcome: &DemoRecordOutcome) -> String {
    let Ok(v) = serde_json::to_value(outcome) else {
        return "unprintable outcome".to_string();
    };
    let tag = v.get("outcome").and_then(|t| t.as_str()).unwrap_or("?");
    v.get("reason")
        .and_then(|r| r.get("kind"))
        .and_then(|k| k.as_str())
        .map_or_else(|| tag.to_string(), |kind| format!("{tag}: {kind}"))
}

fn print_text_report(result: &VerificationResult) {
    let status = if result.valid { "VALID" } else { "INVALID" };
    println!("Status: {status}");
    if result.halted_early {
        println!("(stopped early under --fail-fast; subsequent records were not inspected)");
    }
    println!("Events verified:     {}", result.events_verified);
    println!("Signatures verified: {}", result.signatures_verified);
    println!("Receipts verified:   {}", result.receipts_verified);
    if let (Some(first), Some(last)) = (result.first_sequence, result.last_sequence) {
        println!("Sequence range:      {first}..={last}");
    }
    if !result.chain_root.is_empty() {
        let short = short_hex(&result.chain_root, 16);
        println!("Chain root:          {short}...");
    }
    if !result.errors.is_empty() {
        println!("\nErrors:");
        for err in &result.errors {
            let seq = err
                .sequence
                .map_or_else(|| "-".to_string(), |s| s.to_string());
            println!("  [seq {seq}] {}: {}", err.error_type, err.details);
        }
    }
    if !result.warnings.is_empty() {
        println!("\nWarnings:");
        for w in &result.warnings {
            println!("  {w}");
        }
    }
}

/// Take the first `n` chars of `s` without panicking on a UTF-8
/// boundary. Hex hashes are ASCII so this rarely matters in
/// practice, but the CLI is not `#![deny(clippy::unwrap_used)]` and
/// must not panic on hostile input.
fn short_hex(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

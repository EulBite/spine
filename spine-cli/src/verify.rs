// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite

//! CLI shim over [`spine_core::verify_wal_bytes_with_options`].

use std::fs;
use std::path::Path;

use spine_core::{verify_wal_bytes_with_options, Keystore, LenientOptions, VerificationResult};

use crate::wal_io::{read_wal_bytes, WalIoError};
use crate::OutputFormat;

#[derive(Debug, thiserror::Error)]
pub enum VerifyCmdError {
    #[error("{0}")]
    Io(#[from] WalIoError),

    #[error("Keystore could not be loaded: {0}")]
    Keystore(String),

    #[error("Output write failed: {0}")]
    OutputWrite(std::io::Error),

    #[error("Report serialisation failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

pub fn run(
    wal_path: &Path,
    expected_root: Option<&str>,
    output_path: Option<&Path>,
    fail_fast: bool,
    keystore_path: Option<&Path>,
    trusted_pubkey: Option<&str>,
    format: OutputFormat,
) -> Result<bool, VerifyCmdError> {
    let bytes = read_wal_bytes(wal_path)?;

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
    let result = verify_wal_bytes_with_options(&bytes, &opts);

    emit_report(&result, output_path, format)?;
    Ok(result.valid)
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
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".to_string());
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

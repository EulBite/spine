// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite

//! Spine CLI: standalone offline auditor for Spine WAL files.
//!
//! Three subcommands:
//!
//! * `verify`: lenient verification of a WAL directory against
//!   `spine-core`. Optional `--keystore` enables receipt-signature
//!   verification; `--trusted-pubkey` pins the signing key.
//! * `inspect`: human-readable view of WAL contents. No verification.
//! * `export`: filter and export entries to JSONL, CSV or syslog. A
//!   `.manifest.json` sidecar is always written next to the output
//!   file when `--output` is set; JSONL exports also carry an inline
//!   `kind: "spine_export_manifest"` row as the last line.
//!
//! The CLI never signs and never recomputes cryptographic primitives
//! locally: every byte of crypto goes through `spine-core` so the
//! published vectors are the only ground truth.
//!
//! ## Exit codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0    | Subcommand reported success (`verify`: `valid=true`, `inspect`/`export`: produced output). |
//! | 1    | Subcommand completed but reported issues (`verify`: `valid=false`, `inspect`: not found, `export`: nothing exported when something was expected). |
//! | 2    | I/O or argument error; the subcommand could not run. |
//!
//! CI gates should treat exit `0` as pass and any other code as fail.
//!
//! ## --format text plus --output
//!
//! When both are provided, the on-disk file is JSON pretty-printed.
//! The "text" rendering is a terminal-only convenience; for file
//! output we always emit JSON so downstream tools can parse it. Use
//! `--format json --output file.json` if you want to make the choice
//! explicit.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod export;
mod inspect;
mod verify;
mod wal_io;

#[derive(Parser)]
#[command(name = "spine-cli")]
#[command(version, about = "Cryptographic audit trail tools for Spine WAL files")]
#[command(long_about = "Cryptographic audit trail tools for Spine WAL files.\n\
\n\
Exit codes:\n  \
  0  subcommand succeeded\n  \
  1  subcommand completed with issues (see output)\n  \
  2  I/O or argument error\n")]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format applied across subcommands.
    /// Note: with `--output FILE`, file content is always JSON
    /// regardless of this flag; "text" affects only terminal output.
    #[arg(short, long, default_value = "text", global = true)]
    format: OutputFormat,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify integrity of a WAL directory using the lenient profile.
    Verify {
        /// Path to WAL directory.
        #[arg(short, long)]
        wal: PathBuf,

        /// Expected chain root in lowercase hex (optional `0x`
        /// prefix). When omitted the verifier still computes the root
        /// but emits a warning. When set, even an EMPTY WAL fails the
        /// gate, closing the "empty the directory to bypass CI" hole.
        #[arg(long)]
        expected_root: Option<String>,

        /// Write the JSON verification report to this path. Without
        /// it the report goes to stdout under `--format json` or to
        /// the terminal under `--format text`.
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Stop at the first failure rather than accumulate. The
        /// partial report (everything seen up to the failure plus
        /// the failing error) is still emitted so SRE workflows can
        /// inspect what was processed before the halt.
        #[arg(long)]
        fail_fast: bool,

        /// Path to a JSON keystore mapping `server_key_id` to Ed25519
        /// pubkey hex. When supplied, `receipt_sig` on every entry
        /// carrying a receipt is verified against the matching key.
        /// Without it receipts pass through unchecked and a warning
        /// counts how many records carried receipts.
        #[arg(long)]
        keystore: Option<PathBuf>,

        /// 64-char lowercase hex of the Ed25519 pubkey that MUST have
        /// signed every record. When set, any record whose
        /// `public_key` differs is flagged as `untrusted_pubkey`
        /// instead of being silently trusted. Without this flag the
        /// lenient verifier trusts the record-declared pubkey (and
        /// warns about it), which is sufficient for offline audit
        /// but not for an enterprise CI gate.
        #[arg(long)]
        trusted_pubkey: Option<String>,
    },

    /// Export WAL records (JSONL, CSV or syslog) with optional time
    /// filter. CSV and syslog formats are lossy: they drop
    /// `signature`, `public_key`, `receipt`, `event_id`,
    /// `stream_id` and `payload`. Use `--export-format jsonl` (the
    /// default) for full record fidelity.
    Export {
        #[arg(short, long)]
        wal: PathBuf,

        /// Output file. Without it the records go to stdout and no
        /// sidecar manifest is written; the manifest line is still
        /// appended under JSONL.
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Export format.
        #[arg(long, default_value = "jsonl")]
        export_format: ExportFormat,

        /// Inclusive lower bound, RFC 3339 timestamp.
        #[arg(long)]
        from: Option<String>,

        /// Inclusive upper bound, RFC 3339 timestamp.
        #[arg(long)]
        to: Option<String>,

        /// Include the per-record `entry_hash` proof in the output.
        #[arg(long)]
        include_proofs: bool,

        /// Syslog facility number (0-23). Defaults to 16 (local0).
        /// Used only when `--export-format syslog`.
        #[arg(long, default_value_t = 16)]
        syslog_facility: u8,
    },

    /// Human-readable inspection of WAL contents (no verification).
    Inspect {
        #[arg(short, long)]
        wal: PathBuf,

        /// Show the last N events.
        #[arg(short = 'n', long, default_value = "10")]
        last: usize,

        /// Show a single event by sequence number.
        #[arg(long)]
        sequence: Option<u64>,

        /// Show aggregate chain statistics instead of individual events.
        #[arg(long)]
        stats: bool,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
pub enum OutputFormat {
    Json,
    Text,
    Quiet,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
pub enum ExportFormat {
    Jsonl,
    Csv,
    Syslog,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // RUST_LOG controls the tracing filter for debug builds. The
    // subscriber is initialised lazily so a quiet invocation does
    // not emit a stray init line.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".to_string()))
        .with_target(false)
        .try_init();

    let outcome: Result<bool, String> = match cli.command {
        Commands::Verify {
            wal,
            expected_root,
            output,
            fail_fast,
            keystore,
            trusted_pubkey,
        } => verify::run(
            &wal,
            expected_root.as_deref(),
            output.as_deref(),
            fail_fast,
            keystore.as_deref(),
            trusted_pubkey.as_deref(),
            cli.format,
        )
        .map_err(|e| e.to_string()),

        Commands::Export {
            wal,
            output,
            export_format,
            from,
            to,
            include_proofs,
            syslog_facility,
        } => export::run(
            &wal,
            output.as_deref(),
            export_format,
            from.as_deref(),
            to.as_deref(),
            include_proofs,
            syslog_facility,
            cli.format,
        )
        .map_err(|e| e.to_string()),

        Commands::Inspect {
            wal,
            last,
            sequence,
            stats,
        } => inspect::run(&wal, last, sequence, stats, cli.format).map_err(|e| e.to_string()),
    };

    match outcome {
        Ok(true) => {
            if cli.format != OutputFormat::Quiet {
                eprintln!("OK");
            }
            ExitCode::SUCCESS
        }
        Ok(false) => {
            if cli.format != OutputFormat::Quiet {
                eprintln!("Completed with issues. See output for details.");
            }
            ExitCode::from(1)
        }
        Err(msg) => {
            if cli.format != OutputFormat::Quiet {
                eprintln!("Error: {msg}");
            }
            ExitCode::from(2)
        }
    }
}

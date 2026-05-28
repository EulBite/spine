// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite

//! Export WAL entries to JSONL, CSV or syslog with optional time
//! filter.
//!
//! The export does not re-verify; pair it with the `verify`
//! subcommand when the output is being handed to an external auditor.
//!
//! ## Lossy formats
//!
//! CSV and syslog drop `signature`, `public_key`, `receipt`,
//! `event_id`, `stream_id`, and `payload`. They are summary formats,
//! not auditor-grade. JSONL is the only format that preserves enough
//! to re-verify the export via `spine-cli verify`.
//!
//! ## Manifest layout
//!
//! Every export produces a manifest carrying:
//!
//! * `kind = "spine_export_manifest"` (sentinel so parsers can
//!   discriminate it from a WAL row)
//! * `source_chain_root`: the BLAKE3 accumulator over EVERY entry in
//!   the source WAL, matches `spine-cli verify`.
//! * `filtered_export_digest`: BLAKE3 over only the entries that
//!   survived `--from`/`--to`. Equal to `source_chain_root` when no
//!   filter is in effect.
//! * `exported_count`, `from`, `to`.
//!
//! When `--output FILE` is set, the manifest is written to BOTH
//! places:
//!
//! 1. A sidecar `FILE.manifest.json` (pretty-printed) next to the
//!    output, regardless of format. This is the canonical reference
//!    for downstream tooling: it stays parseable even for CSV/syslog
//!    where inlining is impossible.
//! 2. Inline as the last JSONL row, but ONLY for `--export-format
//!    jsonl`. The `kind` sentinel lets a SIEM ignore it without a
//!    schema bump. CSV/syslog skip the inline copy because their
//!    grammars do not have a discriminated-union escape hatch.
//!
//! When `--output` is omitted, only the inline copy is emitted
//! (stdout has no place to put a sidecar).
//!
//! ## Atomic write
//!
//! File writes go to `FILE.tmp.<pid>.<counter>` first and are renamed
//! into place after the writer flushes successfully. A crash mid-
//! write leaves the partial bytes in the tmp file rather than
//! corrupting the destination. Sidecar manifest is written the same
//! way.

use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use blake3::Hasher;
use chrono::{DateTime, Utc};
use serde::Serialize;
use spine_core::{compute_entry_hash, WalEntry};

use crate::wal_io::{collect_wal_segments, WalIoError};
use crate::{ExportFormat, OutputFormat};

#[derive(Debug, thiserror::Error)]
pub enum ExportCmdError {
    #[error("{0}")]
    Io(#[from] WalIoError),

    #[error("Read error on {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Write error on {path}: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Parse error in {path} line {line}: {details}")]
    Parse {
        path: String,
        line: usize,
        details: String,
    },

    #[error("Invalid filter timestamp {input:?}: {details}")]
    BadFilter { input: String, details: String },

    #[error("--from is after --to: from={from:?} > to={to:?}")]
    InvertedRange { from: String, to: String },

    #[error("--syslog-facility must be 0..=23, got {0}")]
    BadFacility(u8),

    #[error("Serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),

    #[error("CSV serialization failed: {0}")]
    Csv(#[from] csv::Error),
}

/// Sentinel injected as the `kind` field so a downstream consumer
/// can distinguish a manifest row from a WAL row by string match
/// alone, without a schema bump.
const MANIFEST_KIND: &str = "spine_export_manifest";

#[derive(Debug, Serialize)]
pub struct ExportManifest {
    pub kind: &'static str,
    pub exported_count: u64,
    pub source_chain_root: String,
    pub filtered_export_digest: String,
    pub from: Option<String>,
    pub to: Option<String>,
}

pub struct ExportArgs<'a> {
    pub wal_path: &'a Path,
    pub output_path: Option<&'a Path>,
    pub export_format: ExportFormat,
    pub from: Option<&'a str>,
    pub to: Option<&'a str>,
    pub include_proofs: bool,
    pub syslog_facility: u8,
    pub format: OutputFormat,
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    wal_path: &Path,
    output_path: Option<&Path>,
    export_format: ExportFormat,
    from: Option<&str>,
    to: Option<&str>,
    include_proofs: bool,
    syslog_facility: u8,
    format: OutputFormat,
) -> Result<bool, ExportCmdError> {
    run_with_args(&ExportArgs {
        wal_path,
        output_path,
        export_format,
        from,
        to,
        include_proofs,
        syslog_facility,
        format,
    })
}

fn run_with_args(args: &ExportArgs<'_>) -> Result<bool, ExportCmdError> {
    let &ExportArgs {
        wal_path,
        output_path,
        export_format,
        from,
        to,
        include_proofs,
        syslog_facility,
        format,
    } = args;
    if syslog_facility > 23 {
        return Err(ExportCmdError::BadFacility(syslog_facility));
    }
    let from_ns = parse_filter(from)?;
    let to_ns = parse_filter(to)?;
    if let (Some(f), Some(t)) = (from_ns, to_ns) {
        if f > t {
            return Err(ExportCmdError::InvertedRange {
                from: from.unwrap_or("").to_string(),
                to: to.unwrap_or("").to_string(),
            });
        }
    }
    let segments = collect_wal_segments(wal_path)?;

    let mut sink = open_sink(output_path, export_format)?;
    let mut source_accum = Hasher::new();
    let mut filtered_accum = Hasher::new();
    let mut exported = 0u64;

    for seg in &segments {
        let file = File::open(seg).map_err(|e| ExportCmdError::Read {
            path: seg.display().to_string(),
            source: e,
        })?;
        let reader = BufReader::new(file);
        for (idx, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| ExportCmdError::Read {
                path: seg.display().to_string(),
                source: e,
            })?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: WalEntry =
                serde_json::from_str(&line).map_err(|e| ExportCmdError::Parse {
                    path: seg.display().to_string(),
                    line: idx + 1,
                    details: e.to_string(),
                })?;

            let entry_hash = compute_entry_hash(&entry);
            source_accum.update(entry_hash.as_bytes());

            if filter_keeps(&entry, from_ns, to_ns) {
                filtered_accum.update(entry_hash.as_bytes());
                emit(
                    &mut sink,
                    &entry,
                    include_proofs,
                    &entry_hash,
                    syslog_facility,
                )?;
                exported += 1;
            }
        }
    }

    let manifest = ExportManifest {
        kind: MANIFEST_KIND,
        exported_count: exported,
        source_chain_root: hex::encode(source_accum.finalize().as_bytes()),
        filtered_export_digest: hex::encode(filtered_accum.finalize().as_bytes()),
        from: from.map(str::to_string),
        to: to.map(str::to_string),
    };

    // Inline manifest only for JSONL, where the sentinel `kind`
    // discriminates it. CSV/syslog drop it (no room without breaking
    // their grammar) and rely on the sidecar.
    if matches!(export_format, ExportFormat::Jsonl) {
        write_manifest_inline(&mut sink, &manifest)?;
    }

    // Commit the main file. From here on out, partial state is the
    // user's problem because the bytes are on disk and named.
    sink.commit()?;

    // Sidecar manifest, regardless of format. Written only when
    // --output is set; stdout exports have no canonical place for it.
    if let Some(p) = output_path {
        let sidecar = sidecar_path(p);
        write_sidecar_manifest(&sidecar, &manifest)?;
    }

    if format != OutputFormat::Quiet {
        eprintln!("Exported {exported} records");
        eprintln!("  source_chain_root:      {}", manifest.source_chain_root);
        eprintln!(
            "  filtered_export_digest: {}",
            manifest.filtered_export_digest
        );
        if let Some(p) = output_path {
            eprintln!("  manifest sidecar:       {}", sidecar_path(p).display());
        }
    }
    Ok(true)
}

fn sidecar_path(output: &Path) -> PathBuf {
    let mut name = output.as_os_str().to_owned();
    name.push(".manifest.json");
    PathBuf::from(name)
}

fn parse_filter(input: Option<&str>) -> Result<Option<i64>, ExportCmdError> {
    match input {
        None => Ok(None),
        Some(s) => {
            let dt = DateTime::parse_from_rfc3339(s).map_err(|e| ExportCmdError::BadFilter {
                input: s.to_string(),
                details: e.to_string(),
            })?;
            dt.with_timezone(&Utc)
                .timestamp_nanos_opt()
                .map(Some)
                .ok_or_else(|| ExportCmdError::BadFilter {
                    input: s.to_string(),
                    details: "out of i64 nanoseconds range".to_string(),
                })
        }
    }
}

const fn filter_keeps(entry: &WalEntry, from_ns: Option<i64>, to_ns: Option<i64>) -> bool {
    if let Some(f) = from_ns {
        if entry.timestamp_ns < f {
            return false;
        }
    }
    if let Some(t) = to_ns {
        if entry.timestamp_ns > t {
            return false;
        }
    }
    true
}

// --- Sink: atomic file write or pass-through to stdout. ---

enum Sink {
    Stdout(StdoutFlavour),
    File(FileSink),
    CsvStdout(csv::Writer<std::io::Stdout>),
    CsvFile(CsvFileSink),
}

enum StdoutFlavour {
    Plain,
    Syslog,
}

struct FileSink {
    final_path: PathBuf,
    tmp_path: PathBuf,
    writer: BufWriter<File>,
}

struct CsvFileSink {
    final_path: PathBuf,
    tmp_path: PathBuf,
    writer: csv::Writer<File>,
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn tmp_for(final_path: &Path) -> PathBuf {
    let n = TMP_COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let mut name = final_path.as_os_str().to_owned();
    name.push(format!(".tmp.{pid}.{n}"));
    PathBuf::from(name)
}

impl Sink {
    fn commit(self) -> Result<(), ExportCmdError> {
        match self {
            Self::Stdout(_) => std::io::stdout()
                .flush()
                .map_err(|e| ExportCmdError::Write {
                    path: "<stdout>".to_string(),
                    source: e,
                }),
            Self::File(FileSink {
                final_path,
                tmp_path,
                writer,
            }) => {
                let mut w = writer;
                w.flush().map_err(|e| ExportCmdError::Write {
                    path: tmp_path.display().to_string(),
                    source: e,
                })?;
                drop(w);
                fs::rename(&tmp_path, &final_path).map_err(|e| ExportCmdError::Write {
                    path: final_path.display().to_string(),
                    source: e,
                })
            }
            Self::CsvStdout(mut w) => w.flush().map_err(|e| ExportCmdError::Write {
                path: "<stdout>".to_string(),
                source: e,
            }),
            Self::CsvFile(CsvFileSink {
                final_path,
                tmp_path,
                mut writer,
            }) => {
                writer.flush().map_err(|e| ExportCmdError::Write {
                    path: tmp_path.display().to_string(),
                    source: e,
                })?;
                // csv::Writer<File> does not expose the inner File for
                // an explicit fsync; we rely on the underlying File's
                // drop + the OS rename atomicity.
                drop(writer);
                fs::rename(&tmp_path, &final_path).map_err(|e| ExportCmdError::Write {
                    path: final_path.display().to_string(),
                    source: e,
                })
            }
        }
    }
}

fn open_sink(output: Option<&Path>, fmt: ExportFormat) -> Result<Sink, ExportCmdError> {
    match (fmt, output) {
        (ExportFormat::Jsonl, None) => Ok(Sink::Stdout(StdoutFlavour::Plain)),
        (ExportFormat::Syslog, None) => Ok(Sink::Stdout(StdoutFlavour::Syslog)),
        (ExportFormat::Jsonl | ExportFormat::Syslog, Some(p)) => {
            let tmp = tmp_for(p);
            let f = File::create(&tmp).map_err(|e| ExportCmdError::Write {
                path: tmp.display().to_string(),
                source: e,
            })?;
            Ok(Sink::File(FileSink {
                final_path: p.to_path_buf(),
                tmp_path: tmp,
                writer: BufWriter::new(f),
            }))
        }
        (ExportFormat::Csv, None) => {
            Ok(Sink::CsvStdout(csv::Writer::from_writer(std::io::stdout())))
        }
        (ExportFormat::Csv, Some(p)) => {
            let tmp = tmp_for(p);
            let f = File::create(&tmp).map_err(|e| ExportCmdError::Write {
                path: tmp.display().to_string(),
                source: e,
            })?;
            Ok(Sink::CsvFile(CsvFileSink {
                final_path: p.to_path_buf(),
                tmp_path: tmp,
                writer: csv::Writer::from_writer(f),
            }))
        }
    }
}

fn emit(
    sink: &mut Sink,
    entry: &WalEntry,
    include_proofs: bool,
    entry_hash: &str,
    syslog_facility: u8,
) -> Result<(), ExportCmdError> {
    match sink {
        Sink::Stdout(StdoutFlavour::Plain) | Sink::File(_) => {
            let line = jsonl_line_for(entry, include_proofs, entry_hash)?;
            write_line_text(sink, &line)
        }
        Sink::Stdout(StdoutFlavour::Syslog) => {
            let line = format_syslog(entry, syslog_facility);
            write_line_text(sink, &line)
        }
        Sink::CsvStdout(w) => write_csv_record(w, entry, include_proofs, entry_hash),
        Sink::CsvFile(CsvFileSink { writer, .. }) => {
            write_csv_record(writer, entry, include_proofs, entry_hash)
        }
    }
}

fn jsonl_line_for(
    entry: &WalEntry,
    include_proofs: bool,
    entry_hash: &str,
) -> Result<String, ExportCmdError> {
    let mut value = serde_json::to_value(entry)?;
    if include_proofs {
        if let serde_json::Value::Object(map) = &mut value {
            map.insert(
                "entry_hash".to_string(),
                serde_json::Value::String(entry_hash.to_string()),
            );
        }
    }
    Ok(serde_json::to_string(&value)?)
}

fn write_line_text(sink: &mut Sink, line: &str) -> Result<(), ExportCmdError> {
    match sink {
        Sink::Stdout(_) => {
            let stdout = std::io::stdout();
            let mut h = stdout.lock();
            writeln!(h, "{line}").map_err(|e| ExportCmdError::Write {
                path: "<stdout>".to_string(),
                source: e,
            })
        }
        Sink::File(FileSink {
            tmp_path, writer, ..
        }) => writeln!(writer, "{line}").map_err(|e| ExportCmdError::Write {
            path: tmp_path.display().to_string(),
            source: e,
        }),
        _ => Ok(()),
    }
}

fn write_csv_record<W: Write>(
    writer: &mut csv::Writer<W>,
    entry: &WalEntry,
    include_proofs: bool,
    entry_hash: &str,
) -> Result<(), ExportCmdError> {
    let signed = if entry.signature.is_some() {
        "yes"
    } else {
        "no"
    };
    let event_type = entry.event_type.clone().unwrap_or_default();
    let source = entry.source.clone().unwrap_or_default();
    if include_proofs {
        writer.write_record([
            entry.sequence.to_string().as_str(),
            entry.timestamp_ns.to_string().as_str(),
            &event_type,
            &source,
            &entry.payload_hash,
            &entry.prev_hash,
            signed,
            entry_hash,
        ])?;
    } else {
        writer.write_record([
            entry.sequence.to_string().as_str(),
            entry.timestamp_ns.to_string().as_str(),
            &event_type,
            &source,
            &entry.payload_hash,
            &entry.prev_hash,
            signed,
        ])?;
    }
    Ok(())
}

fn format_syslog(entry: &WalEntry, facility: u8) -> String {
    // Priority = facility * 8 + severity. Severity = 6 (info).
    let priority = u16::from(facility) * 8 + 6;
    let secs = entry.timestamp_ns.div_euclid(1_000_000_000);
    // `rem_euclid(1_000_000_000)` is always in `0..1_000_000_000`, which
    // fits a u32, so the truncation can never lose information.
    #[allow(clippy::cast_possible_truncation)]
    let sub_nanos = entry.timestamp_ns.rem_euclid(1_000_000_000) as u32;
    let ts = DateTime::<Utc>::from_timestamp(secs, sub_nanos)
        .map_or_else(|| format!("ns:{}", entry.timestamp_ns), |dt| dt.to_rfc3339());
    let event_type = entry.event_type.as_deref().unwrap_or("-");
    let source = entry.source.as_deref().unwrap_or("-");
    let hash_short: String = entry.payload_hash.chars().take(16).collect();
    // Escape `"` and `\` inside the msg="..." string so a SIEM parser
    // cannot be confused by a producer that put a quote in event_type.
    // We do NOT emit RFC 5424 STRUCTURED-DATA: simpler MSG keeps the
    // line readable without a PEN allocation. SIEMs that want
    // structured data can ingest the JSONL export instead.
    format!(
        "<{priority}>1 {ts} {host} spine-wal {seq} {msgid} - msg=\"seq={seq} type={etype} hash={hash}\"",
        priority = priority,
        ts = ts,
        host = syslog_token(source),
        seq = entry.sequence,
        msgid = syslog_token(event_type),
        etype = syslog_escape(event_type),
        hash = hash_short,
    )
}

/// Strip whitespace and quotes from values that land in the HEADER
/// portion of the syslog line (HOSTNAME and MSGID per RFC 5424).
/// These fields are not quoted; spaces would create extra tokens.
fn syslog_token(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_whitespace() { '_' } else { c })
        .filter(|c| *c != '"' && *c != '\\')
        .collect();
    if cleaned.is_empty() {
        "-".to_string()
    } else {
        cleaned
    }
}

/// Escape `"` and `\` for values that land inside the quoted MSG
/// portion. RFC 3164 / 5424 do not specify escaping; this matches
/// the convention most SIEMs (Splunk, ELK, `QRadar`) accept.
fn syslog_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out
}

fn write_manifest_inline(sink: &mut Sink, manifest: &ExportManifest) -> Result<(), ExportCmdError> {
    let line = serde_json::to_string(manifest)?;
    write_line_text(sink, &line)
}

fn write_sidecar_manifest(path: &Path, manifest: &ExportManifest) -> Result<(), ExportCmdError> {
    let pretty = serde_json::to_string_pretty(manifest)?;
    let tmp = tmp_for(path);
    fs::write(&tmp, &pretty).map_err(|e| ExportCmdError::Write {
        path: tmp.display().to_string(),
        source: e,
    })?;
    fs::rename(&tmp, path).map_err(|e| ExportCmdError::Write {
        path: path.display().to_string(),
        source: e,
    })
}

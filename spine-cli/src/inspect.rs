// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite

//! Human-readable WAL inspection.
//!
//! Inspect does not verify; it just parses and displays. The verifier
//! command is the right tool when correctness matters. Inspect is for
//! "what is in this directory?" exploration.

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::Serialize;
use spine_core::{compute_entry_hash, WalEntry, GENESIS_PREV_HASH};

use crate::wal_io::{collect_wal_segments, total_size, WalIoError};
use crate::OutputFormat;

#[derive(Debug, thiserror::Error)]
pub enum InspectCmdError {
    #[error("{0}")]
    Io(#[from] WalIoError),

    #[error("Read error on {path}: {source}")]
    Read {
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

    #[error("Serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

#[derive(Debug, Serialize)]
pub struct WalStats {
    pub segment_count: usize,
    pub total_events: u64,
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    pub first_timestamp_ns: Option<i64>,
    pub last_timestamp_ns: Option<i64>,
    pub total_size_bytes: u64,
    pub has_signatures: bool,
    /// Per-axis integrity flags. The CLI deliberately exposes one
    /// boolean per invariant rather than a single `chain_intact`
    /// summary, so a downstream consumer cannot read "intact: true"
    /// and conclude that signatures or timestamps were checked when
    /// only `prev_hash` linkage was. Each flag is independent; the
    /// combination of all-true is not equivalent to running
    /// `spine-cli verify`, which additionally validates
    /// `expected_root`, signatures, receipts and hash formats.
    pub integrity: WalIntegrity,
    pub stream_ids: Vec<String>,
    pub events_with_receipt: u64,
    pub events_without_receipt: u64,
    pub is_sdk_format: bool,
}

// Four independent integrity axes, each reported separately on
// purpose (see the `integrity` field docs above). Collapsing them into
// a state machine or enum would hide exactly the per-axis distinction
// this struct exists to preserve.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Serialize)]
pub struct WalIntegrity {
    pub prev_hash_links_ok: bool,
    pub sequence_contiguous: bool,
    pub timestamps_monotonic: bool,
    pub all_signed: bool,
}

#[derive(Debug, Serialize)]
pub struct EventDisplay {
    pub sequence: u64,
    pub timestamp: String,
    pub event_type: String,
    pub source: String,
    pub payload_hash_short: String,
    pub prev_hash_short: String,
    pub signed: bool,
    pub event_id: Option<String>,
    pub has_receipt: bool,
}

pub fn run(
    wal_path: &Path,
    last_n: usize,
    sequence: Option<u64>,
    show_stats: bool,
    format: OutputFormat,
) -> Result<bool, InspectCmdError> {
    let quiet = format == OutputFormat::Quiet;

    if show_stats {
        // `inspect --stats` is intentionally structured-only: the
        // value of the integrity flags is in the per-axis booleans,
        // not in a human paragraph. Both `--format json` and
        // `--format text` therefore emit the same pretty JSON. Use
        // `--format quiet` to suppress output and check the exit
        // code only.
        let stats = compute_stats(wal_path)?;
        if !quiet {
            println!("{}", serde_json::to_string_pretty(&stats)?);
        }
        return Ok(true);
    }

    if let Some(seq) = sequence {
        if let Some(entry) = find_event(wal_path, seq)? {
            if !quiet {
                println!("{}", serde_json::to_string_pretty(&entry)?);
            }
            Ok(true)
        } else {
            if !quiet {
                eprintln!("Event with sequence {seq} not found");
            }
            Ok(false)
        }
    } else {
        let events = last_events(wal_path, last_n)?;
        if events.is_empty() {
            if !quiet {
                eprintln!("No events found in WAL");
            }
            Ok(false)
        } else {
            if !quiet {
                match format {
                    OutputFormat::Json => {
                        println!("{}", serde_json::to_string_pretty(&events)?);
                    }
                    OutputFormat::Text => print_events(&events),
                    OutputFormat::Quiet => {}
                }
            }
            Ok(true)
        }
    }
}

fn compute_stats(wal_path: &Path) -> Result<WalStats, InspectCmdError> {
    let segments = collect_wal_segments(wal_path)?;
    let mut stats = WalStats {
        segment_count: segments.len(),
        total_events: 0,
        first_sequence: None,
        last_sequence: None,
        first_timestamp_ns: None,
        last_timestamp_ns: None,
        total_size_bytes: total_size(wal_path)?,
        has_signatures: false,
        integrity: WalIntegrity {
            prev_hash_links_ok: true,
            sequence_contiguous: true,
            timestamps_monotonic: true,
            all_signed: true,
        },
        stream_ids: Vec::new(),
        events_with_receipt: 0,
        events_without_receipt: 0,
        is_sdk_format: false,
    };

    let mut prev_hash: Option<String> = None;
    let mut prev_sequence: Option<u64> = None;
    let mut prev_timestamp: Option<i64> = None;
    let mut streams: HashSet<String> = HashSet::new();
    let mut saw_any = false;

    for_each_entry(&segments, |entry| {
        if stats.first_sequence.is_none() {
            stats.first_sequence = Some(entry.sequence);
            stats.first_timestamp_ns = Some(entry.timestamp_ns);
        }
        stats.last_sequence = Some(entry.sequence);
        stats.last_timestamp_ns = Some(entry.timestamp_ns);
        stats.total_events += 1;

        if entry.signature.is_some() {
            stats.has_signatures = true;
        } else {
            stats.integrity.all_signed = false;
        }
        if entry.event_id.is_some() || entry.stream_id.is_some() {
            stats.is_sdk_format = true;
        }
        if let Some(s) = &entry.stream_id {
            streams.insert(s.clone());
        }
        if entry.receipt.is_some() {
            stats.events_with_receipt += 1;
        } else {
            stats.events_without_receipt += 1;
        }
        let link_broken = match &prev_hash {
            Some(p) => entry.prev_hash != *p,
            None => entry.prev_hash != GENESIS_PREV_HASH,
        };
        if link_broken {
            stats.integrity.prev_hash_links_ok = false;
        }
        if let Some(prev_seq) = prev_sequence {
            if entry.sequence != prev_seq + 1 {
                stats.integrity.sequence_contiguous = false;
            }
        } else if entry.sequence != 1 {
            // First record but not at sequence 1: the chain is not
            // self-rooted from genesis; sequence_contiguous reflects
            // that too.
            stats.integrity.sequence_contiguous = false;
        }
        if let Some(prev_ts) = prev_timestamp {
            if entry.timestamp_ns < prev_ts {
                stats.integrity.timestamps_monotonic = false;
            }
        }
        prev_hash = Some(compute_entry_hash(&entry));
        prev_sequence = Some(entry.sequence);
        prev_timestamp = Some(entry.timestamp_ns);
        saw_any = true;
        Ok(())
    })?;

    // Zero records: all integrity flags collapse to "no claim made".
    // True flags would be a confusing default ("intact!") on an empty
    // directory; false is the honest signal.
    if !saw_any {
        stats.integrity.prev_hash_links_ok = false;
        stats.integrity.sequence_contiguous = false;
        stats.integrity.timestamps_monotonic = false;
        stats.integrity.all_signed = false;
    }

    stats.stream_ids = {
        let mut v: Vec<String> = streams.into_iter().collect();
        v.sort();
        v
    };
    Ok(stats)
}

fn find_event(wal_path: &Path, target: u64) -> Result<Option<WalEntry>, InspectCmdError> {
    let segments = collect_wal_segments(wal_path)?;
    let mut found = None;
    let mut overshoot = false;
    for_each_entry(&segments, |entry| {
        if overshoot {
            return Ok(());
        }
        match entry.sequence.cmp(&target) {
            std::cmp::Ordering::Equal => {
                found = Some(entry);
                overshoot = true;
            }
            std::cmp::Ordering::Greater => overshoot = true,
            std::cmp::Ordering::Less => {}
        }
        Ok(())
    })?;
    Ok(found)
}

fn last_events(wal_path: &Path, n: usize) -> Result<Vec<EventDisplay>, InspectCmdError> {
    if n == 0 {
        return Ok(Vec::new());
    }
    let segments = collect_wal_segments(wal_path)?;
    let mut buffer: std::collections::VecDeque<WalEntry> =
        std::collections::VecDeque::with_capacity(n);

    for_each_entry(&segments, |entry| {
        if buffer.len() >= n {
            buffer.pop_front();
        }
        buffer.push_back(entry);
        Ok(())
    })?;

    Ok(buffer
        .into_iter()
        .map(|e| EventDisplay {
            sequence: e.sequence,
            timestamp: format_ns(e.timestamp_ns),
            event_type: e.event_type.unwrap_or_else(|| "-".to_string()),
            source: e.source.unwrap_or_else(|| "-".to_string()),
            payload_hash_short: short_hash(&e.payload_hash),
            prev_hash_short: short_hash(&e.prev_hash),
            signed: e.signature.is_some(),
            event_id: e.event_id,
            has_receipt: e.receipt.is_some(),
        })
        .collect())
}

fn for_each_entry<F>(segments: &[std::path::PathBuf], mut visit: F) -> Result<(), InspectCmdError>
where
    F: FnMut(WalEntry) -> Result<(), InspectCmdError>,
{
    for seg in segments {
        let file = File::open(seg).map_err(|e| InspectCmdError::Read {
            path: seg.display().to_string(),
            source: e,
        })?;
        let reader = BufReader::new(file);
        for (idx, line_res) in reader.lines().enumerate() {
            let line = line_res.map_err(|e| InspectCmdError::Read {
                path: seg.display().to_string(),
                source: e,
            })?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: WalEntry =
                serde_json::from_str(&line).map_err(|e| InspectCmdError::Parse {
                    path: seg.display().to_string(),
                    line: idx + 1,
                    details: e.to_string(),
                })?;
            visit(entry)?;
        }
    }
    Ok(())
}

fn print_events(events: &[EventDisplay]) {
    println!(
        "\n{:>8} | {:^24} | {:^20} | {:^16} | {:^6}",
        "SEQ", "TIMESTAMP", "EVENT_TYPE", "PAYLOAD_HASH", "SIGNED"
    );
    println!("{}", "-".repeat(86));
    for e in events {
        println!(
            "{:>8} | {:^24} | {:^20} | {:^16} | {:^6}",
            e.sequence,
            short_str(&e.timestamp, 24),
            short_str(&e.event_type, 20),
            e.payload_hash_short,
            if e.signed { "yes" } else { "no" }
        );
    }
}

fn short_hash(h: &str) -> String {
    // Char-based slicing to stay safe on hostile non-ASCII input.
    // Hex hashes are ASCII in practice so byte-slicing would also
    // be fine, but the CLI is not no-panic-deny and must not crash
    // on a malformed WAL.
    let chars: Vec<char> = h.chars().collect();
    if chars.len() <= 16 {
        chars.into_iter().collect()
    } else {
        let prefix: String = chars.into_iter().take(16).collect();
        format!("{prefix}...")
    }
}

fn short_str(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn format_ns(ns: i64) -> String {
    // Map i64 nanoseconds into a DateTime. chrono refuses to build a
    // DateTime when the value overflows seconds, so we fall back to
    // the raw integer in that case rather than panic.
    let secs = ns.div_euclid(1_000_000_000);
    // `rem_euclid(1_000_000_000)` is always in `0..1_000_000_000`, which
    // fits a u32, so the truncation can never lose information.
    #[allow(clippy::cast_possible_truncation)]
    let sub_nanos = ns.rem_euclid(1_000_000_000) as u32;
    DateTime::<Utc>::from_timestamp(secs, sub_nanos)
        .map_or_else(|| format!("ns:{ns}"), |dt| dt.to_rfc3339())
}

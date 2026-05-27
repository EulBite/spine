// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite

//! Filesystem-level WAL helpers.
//!
//! `spine-core` is filesystem-free by contract: it takes bytes in and
//! reports out. Everything that touches the local disk lives here, in
//! the CLI layer. Splitting it this way keeps `spine-core` reusable in
//! the WASM playground (no `std::fs`) and lets us evolve segment
//! enumeration without forcing the verifier core to recompile.

use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// Files that share an extension with WAL segments but are metadata
/// sidecars. Including them in segment enumeration would surface a
/// confusing parse error on a file that was not even part of the
/// chain. Keep the list narrow on purpose: anything not listed here
/// is treated as a real segment and will fail loudly if it cannot be
/// parsed.
const NON_SEGMENT_SIDECARS: &[&str] = &["batch_ledger.jsonl"];

#[derive(Debug, Error)]
pub enum WalIoError {
    #[error("I/O error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Path is not a directory: {0}")]
    NotADirectory(String),

    #[error("WAL segment filenames are not lexicographically sortable: {offender}")]
    UnsortableNaming { offender: String },
}

/// Enumerate every `.wal` / `.jsonl` file under `dir`, sorted by
/// filename. Sidecars listed in [`NON_SEGMENT_SIDECARS`] are filtered
/// out.
///
/// The sort is lexicographic. Zero-padded (`00000001.wal`,
/// `00000002.wal`, ...) and timestamp-based naming (`wal_20260101_120000.jsonl`)
/// both round-trip cleanly under it. **Non-padded numeric naming
/// (`1.wal`, `2.wal`, ..., `10.wal`) does NOT**: lexicographic order
/// sorts it as `1, 10, 2, ...`, which the verifier sees as a chain
/// break starting at the second file. This function returns an error
/// when it detects that pattern; the user-facing message is more
/// useful than the cryptic chain_break the verifier would otherwise
/// surface.
pub fn collect_wal_segments(dir: &Path) -> Result<Vec<PathBuf>, WalIoError> {
    if !dir.is_dir() {
        return Err(WalIoError::NotADirectory(dir.display().to_string()));
    }
    let entries = fs::read_dir(dir).map_err(|e| WalIoError::Io {
        path: dir.display().to_string(),
        source: e,
    })?;
    let mut segments = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| WalIoError::Io {
            path: dir.display().to_string(),
            source: e,
        })?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let ext_ok = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| matches!(e, "wal" | "jsonl"))
            .unwrap_or(false);
        if !ext_ok {
            continue;
        }
        let name_ok = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| !NON_SEGMENT_SIDECARS.contains(&n))
            .unwrap_or(true);
        if !name_ok {
            continue;
        }
        segments.push(path);
    }
    segments.sort();

    if let Some(offender) = find_unpadded_numeric(&segments) {
        return Err(WalIoError::UnsortableNaming { offender });
    }

    Ok(segments)
}

/// Detect non-padded numeric filenames (`1.wal`, `10.wal`, ...) by
/// scanning for stems made entirely of decimal digits that have
/// different widths. Returns the offending pair so the error can
/// quote it. Pure-digit stems with uniform width (`001`, `010`,
/// `100`) are accepted; mixed-width digit-only stems are not.
fn find_unpadded_numeric(segments: &[PathBuf]) -> Option<String> {
    let mut widths: Vec<(String, usize)> = Vec::new();
    for p in segments {
        let stem = match p.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => continue,
        };
        if !stem.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        widths.push((stem.to_string(), stem.len()));
    }
    if widths.len() < 2 {
        return None;
    }
    let first_w = widths[0].1;
    for (stem, w) in widths.iter().skip(1) {
        if *w != first_w {
            return Some(format!(
                "{:?} (width {}) and {:?} (width {}) cannot be sorted lexicographically; \
                 rename files with consistent zero-padding (e.g. 00000001.wal)",
                widths[0].0, first_w, stem, w
            ));
        }
    }
    None
}

/// Concatenate every WAL segment under `dir` into a single byte
/// buffer suitable for handing to `spine_core::verify_wal_bytes*`. A
/// trailing newline is inserted between segments so concatenation is
/// safe even when a producer omits the final newline on a segment.
pub fn read_wal_bytes(dir: &Path) -> Result<Vec<u8>, WalIoError> {
    let segments = collect_wal_segments(dir)?;
    let mut buf = Vec::new();
    for seg in &segments {
        let bytes = fs::read(seg).map_err(|e| WalIoError::Io {
            path: seg.display().to_string(),
            source: e,
        })?;
        buf.extend_from_slice(&bytes);
        if !buf.is_empty() && *buf.last().unwrap_or(&0) != b'\n' {
            buf.push(b'\n');
        }
    }
    Ok(buf)
}

/// Total byte size of every WAL segment under `dir`. Useful for the
/// `inspect --stats` summary without requiring the bytes themselves
/// to be held in memory.
pub fn total_size(dir: &Path) -> Result<u64, WalIoError> {
    let segments = collect_wal_segments(dir)?;
    let mut total = 0u64;
    for seg in &segments {
        let meta = fs::metadata(seg).map_err(|e| WalIoError::Io {
            path: seg.display().to_string(),
            source: e,
        })?;
        total = total.saturating_add(meta.len());
    }
    Ok(total)
}

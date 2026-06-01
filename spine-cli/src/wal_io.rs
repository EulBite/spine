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
use std::io::{BufRead, BufReader};
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
/// useful than the cryptic `chain_break` the verifier would otherwise
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
            .is_some_and(|e| matches!(e, "wal" | "jsonl"));
        if !ext_ok {
            continue;
        }
        let name_ok = path
            .file_name()
            .and_then(|n| n.to_str())
            .map_or(true, |n| !NON_SEGMENT_SIDECARS.contains(&n));
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
        let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else {
            continue;
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

/// Stream every line of every WAL segment under `dir` to `visit`, in
/// segment-then-line order, without ever holding more than one line (plus
/// the read buffer) in memory.
///
/// This is the constant-memory counterpart to [`read_wal_bytes`]: where
/// that helper concatenates the entire WAL into one `Vec<u8>` (peak memory
/// scales with the WAL size, which does not work for a multi-gigabyte
/// production WAL), this walks segments with a `BufReader` and a single
/// reusable line buffer, so peak memory is flat regardless of total size.
///
/// Each line is passed WITHOUT its trailing `\n` (a trailing `\r` is left
/// in place; the verifier tolerates it). `visit` returns `true` to stop
/// early, which the lenient verifier uses for fail-fast.
///
/// Segment boundaries match [`read_wal_bytes`]: each segment's last line is
/// kept separate from the next segment's first line, so a producer that
/// omits the final newline on a segment cannot cause two records to merge.
pub fn for_each_wal_line<F>(dir: &Path, mut visit: F) -> Result<(), WalIoError>
where
    F: FnMut(&[u8]) -> bool,
{
    let segments = collect_wal_segments(dir)?;
    let mut line = Vec::new();
    for seg in &segments {
        let file = fs::File::open(seg).map_err(|e| WalIoError::Io {
            path: seg.display().to_string(),
            source: e,
        })?;
        let mut reader = BufReader::new(file);
        loop {
            line.clear();
            let read = reader
                .read_until(b'\n', &mut line)
                .map_err(|e| WalIoError::Io {
                    path: seg.display().to_string(),
                    source: e,
                })?;
            if read == 0 {
                break; // end of this segment
            }
            // `read_until` includes the delimiter; strip the trailing `\n`
            // so the slice matches what `bytes.split(b'\n')` yields on the
            // buffered path.
            let end = if line.last() == Some(&b'\n') {
                line.len() - 1
            } else {
                line.len()
            };
            if visit(&line[..end]) {
                return Ok(());
            }
        }
    }
    Ok(())
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

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite

//! End-to-end smoke tests for the `spine-cli` binary.
//!
//! These drive the compiled binary through `CARGO_BIN_EXE_spine-cli`
//! and assert on exit codes plus structured output, covering argument
//! parsing, all three subcommands, and each output format. The CLI is
//! a thin shim over `spine-core`, which is exercised exhaustively in
//! its own suite; here we only confirm the wiring around it: exit-code
//! mapping (0 ok / 1 issues / 2 error), JSON/CSV/JSONL emission, and
//! the export manifest.

use std::path::Path;
use std::process::{Command, Output};

use serde_json::{json, Value};
use spine_core::{compute_entry_hash, WalEntry, GENESIS_PREV_HASH};
use tempfile::TempDir;

const fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_spine-cli")
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("spine-cli binary should be runnable")
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("process should exit with a code")
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).expect("stdout should be UTF-8")
}

fn entry(seq: u64, ts: i64, prev: &str, payload_hash: &str) -> WalEntry {
    serde_json::from_value(json!({
        "sequence": seq,
        "timestamp_ns": ts,
        "prev_hash": prev,
        "payload_hash": payload_hash,
    }))
    .expect("fixture entry should deserialize")
}

/// Write a 3-entry, correctly-chained, unsigned WAL segment into `dir`
/// and return the directory back for chaining into a command.
fn write_valid_wal(dir: &Path) {
    let mut prev = GENESIS_PREV_HASH.to_string();
    let mut lines = String::new();
    let mut ts: i64 = 1_700_000_000_000_000_000;
    for seq in 1u64..=3 {
        ts += 1_000_000_000;
        let payload = format!("payload-{seq}");
        let payload_hash = hex::encode(blake3::hash(payload.as_bytes()).as_bytes());
        let e = entry(seq, ts, &prev, &payload_hash);
        prev = compute_entry_hash(&e);
        lines.push_str(&serde_json::to_string(&e).expect("entry should serialize"));
        lines.push('\n');
    }
    std::fs::write(dir.join("00000001.jsonl"), lines).expect("wal segment should write");
}

fn wal_dir() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir should be created");
    write_valid_wal(dir.path());
    dir
}

fn path_str(p: &Path) -> &str {
    p.to_str().expect("path should be valid UTF-8")
}

#[test]
fn version_flag_exits_zero() {
    let out = run(&["--version"]);
    assert_eq!(code(&out), 0);
    assert!(stdout(&out).contains("spine-cli"));
}

#[test]
fn help_flag_exits_zero() {
    let out = run(&["--help"]);
    assert_eq!(code(&out), 0);
}

#[test]
fn unknown_subcommand_is_a_usage_error() {
    // clap maps an unrecognised subcommand to its own usage-error exit
    // code (2), which lines up with our "could not run" convention.
    let out = run(&["definitely-not-a-subcommand"]);
    assert_eq!(code(&out), 2);
}

#[test]
fn verify_missing_directory_exits_two() {
    let out = run(&["verify", "--wal", "this/path/does/not/exist"]);
    assert_eq!(code(&out), 2);
}

#[test]
fn verify_valid_wal_reports_valid_json() {
    let dir = wal_dir();
    let out = run(&["verify", "--wal", path_str(dir.path()), "--format", "json"]);
    assert_eq!(code(&out), 0);

    let report: Value = serde_json::from_str(&stdout(&out)).expect("report should be JSON");
    assert_eq!(report["valid"], true);
    assert_eq!(report["events_verified"], 3);
    assert!(
        report["chain_root"]
            .as_str()
            .is_some_and(|r| r.len() == 64),
        "chain_root should be a 64-char hex digest"
    );
}

#[test]
fn verify_valid_wal_text_format_renders_human_report() {
    // The text rendering is the terminal-only path with no structured
    // consumer, so a JSON-only suite would never exercise it. Assert
    // its key lines so the human report cannot silently regress.
    let dir = wal_dir();
    let out = run(&["verify", "--wal", path_str(dir.path()), "--format", "text"]);
    assert_eq!(code(&out), 0);

    let text = stdout(&out);
    assert!(text.contains("Status: VALID"), "text report shows status");
    assert!(text.contains("Events verified:"), "text report shows event count");
    assert!(text.contains("Chain root:"), "text report shows chain root");
}

#[test]
fn verify_expected_root_gates_on_match() {
    let dir = wal_dir();

    // Learn the chain root the verifier computes for this WAL.
    let out = run(&["verify", "--wal", path_str(dir.path()), "--format", "json"]);
    let report: Value = serde_json::from_str(&stdout(&out)).expect("report should be JSON");
    let root = report["chain_root"]
        .as_str()
        .expect("chain_root should be present")
        .to_string();

    // Correct pin: gate passes.
    let ok = run(&[
        "verify",
        "--wal",
        path_str(dir.path()),
        "--expected-root",
        &root,
    ]);
    assert_eq!(code(&ok), 0, "matching expected-root should pass");

    // Wrong pin: gate fails with the "completed with issues" code.
    let wrong = "00".repeat(32);
    let bad = run(&[
        "verify",
        "--wal",
        path_str(dir.path()),
        "--expected-root",
        &wrong,
    ]);
    assert_eq!(code(&bad), 1, "mismatched expected-root should fail");
}

#[test]
fn inspect_stats_emits_integrity_object() {
    let dir = wal_dir();
    let out = run(&[
        "inspect",
        "--wal",
        path_str(dir.path()),
        "--stats",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 0);

    let stats: Value = serde_json::from_str(&stdout(&out)).expect("stats should be JSON");
    assert!(stats["integrity"].is_object());
    assert_eq!(stats["integrity"]["prev_hash_links_ok"], true);
    assert_eq!(stats["integrity"]["sequence_contiguous"], true);
}

#[test]
fn inspect_sequence_found_and_missing() {
    let dir = wal_dir();

    let found = run(&[
        "inspect",
        "--wal",
        path_str(dir.path()),
        "--sequence",
        "2",
        "--format",
        "json",
    ]);
    assert_eq!(code(&found), 0);
    let entry: Value = serde_json::from_str(&stdout(&found)).expect("entry should be JSON");
    assert_eq!(entry["sequence"], 2);

    let missing = run(&[
        "inspect",
        "--wal",
        path_str(dir.path()),
        "--sequence",
        "999",
    ]);
    assert_eq!(code(&missing), 1, "absent sequence should report issues");
}

#[test]
fn export_jsonl_writes_records_and_manifest() {
    let dir = wal_dir();
    let out_dir = tempfile::tempdir().expect("out tempdir");
    let out_file = out_dir.path().join("export.jsonl");

    let out = run(&[
        "export",
        "--wal",
        path_str(dir.path()),
        "--output",
        path_str(&out_file),
        "--export-format",
        "jsonl",
    ]);
    assert_eq!(code(&out), 0);

    let body = std::fs::read_to_string(&out_file).expect("export output should exist");
    let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 4, "3 records + 1 inline manifest");

    let last: Value = serde_json::from_str(lines[3]).expect("manifest line should be JSON");
    assert_eq!(last["kind"], "spine_export_manifest");
    assert_eq!(last["exported_count"], 3);

    // The sidecar manifest is written next to the output regardless of
    // format.
    let sidecar = out_dir.path().join("export.jsonl.manifest.json");
    let sidecar_body = std::fs::read_to_string(&sidecar).expect("sidecar manifest should exist");
    let sidecar_json: Value =
        serde_json::from_str(&sidecar_body).expect("sidecar should be JSON");
    assert!(sidecar_json["source_chain_root"]
        .as_str()
        .is_some_and(|r| r.len() == 64));
}

#[test]
fn export_csv_writes_one_row_per_record() {
    let dir = wal_dir();
    let out_dir = tempfile::tempdir().expect("out tempdir");
    let out_file = out_dir.path().join("export.csv");

    let out = run(&[
        "export",
        "--wal",
        path_str(dir.path()),
        "--output",
        path_str(&out_file),
        "--export-format",
        "csv",
    ]);
    assert_eq!(code(&out), 0);

    let body = std::fs::read_to_string(&out_file).expect("csv output should exist");
    let rows: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(rows.len(), 3, "one CSV row per exported record");
    assert!(rows[0].starts_with('1'), "first column is the sequence");
}

#[test]
fn export_inverted_time_range_exits_two() {
    let dir = wal_dir();
    let out = run(&[
        "export",
        "--wal",
        path_str(dir.path()),
        "--from",
        "2027-01-01T00:00:00Z",
        "--to",
        "2020-01-01T00:00:00Z",
    ]);
    assert_eq!(code(&out), 2, "from > to is an argument error");
}

#[test]
fn export_out_of_range_syslog_facility_exits_two() {
    let dir = wal_dir();
    let out = run(&[
        "export",
        "--wal",
        path_str(dir.path()),
        "--export-format",
        "syslog",
        "--syslog-facility",
        "99",
    ]);
    assert_eq!(code(&out), 2, "facility must be 0..=23");
}

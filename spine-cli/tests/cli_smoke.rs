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

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use spine_core::{
    canonical_json, compute_entry_hash, compute_entry_hash_for_signing, WalEntry,
    GENESIS_PREV_HASH, STRICT_DOMAIN_SEP,
};
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

/// Write a 3-entry strict-profile WAL into `dir`: every record carries
/// an inline payload and a domain-separated Ed25519 signature, exactly
/// the contract `verify --strict` (and the browser playground) runs.
/// Returns the pinned pubkey hex and the expected chain root hex.
fn write_strict_wal(dir: &Path) -> (String, String) {
    // Fixed seed: deterministic fixture, no randomness needed.
    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let pubkey_hex = hex::encode(signing.verifying_key().to_bytes());

    let mut prev = GENESIS_PREV_HASH.to_string();
    let mut accum = blake3::Hasher::new();
    let mut lines = String::new();
    let mut ts: i64 = 1_700_000_000_000_000_000;
    for seq in 1u64..=3 {
        ts += 1_000_000_000;
        let payload = json!({ "amount": "100.00", "seq": seq });
        let canonical = canonical_json(&payload).expect("payload should canonicalise");
        let payload_hash = hex::encode(blake3::hash(&canonical).as_bytes());

        let mut e: WalEntry = serde_json::from_value(json!({
            "format_version": 1,
            "sequence": seq,
            "timestamp_ns": ts,
            "prev_hash": prev,
            "payload_hash": payload_hash,
            "payload": payload,
        }))
        .expect("strict fixture entry should deserialize");

        // Sign STRICT_DOMAIN_SEP || sign_hash_hex, then chain on the
        // full entry hash (which folds in signature + pubkey presence).
        let sign_hash_hex = compute_entry_hash_for_signing(&e);
        let mut msg = Vec::with_capacity(STRICT_DOMAIN_SEP.len() + sign_hash_hex.len());
        msg.extend_from_slice(STRICT_DOMAIN_SEP);
        msg.extend_from_slice(sign_hash_hex.as_bytes());
        e.signature = Some(hex::encode(signing.sign(&msg).to_bytes()));
        e.public_key = Some(pubkey_hex.clone());

        let entry_hash = compute_entry_hash(&e);
        accum.update(entry_hash.as_bytes());
        prev = entry_hash;

        lines.push_str(&serde_json::to_string(&e).expect("entry should serialize"));
        lines.push('\n');
    }
    std::fs::write(dir.join("00000001.jsonl"), lines).expect("strict wal segment should write");
    let root = hex::encode(accum.finalize().as_bytes());
    (pubkey_hex, root)
}

/// Build `n` correctly-chained, lenient-signed records (Ed25519 over the
/// un-prefixed sign hash, the contract the default lenient verifier
/// checks). Returns the serialized JSONL lines and the pubkey hex so a
/// test can split them across segments however it likes.
fn signed_lenient_lines(n: u64) -> (Vec<String>, String) {
    let signing = SigningKey::from_bytes(&[9u8; 32]);
    let pubkey_hex = hex::encode(signing.verifying_key().to_bytes());
    let mut prev = GENESIS_PREV_HASH.to_string();
    let mut ts: i64 = 1_700_000_000_000_000_000;
    let mut out = Vec::new();
    for seq in 1..=n {
        ts += 1_000_000_000;
        let payload = format!("payload-{seq}");
        let payload_hash = hex::encode(blake3::hash(payload.as_bytes()).as_bytes());
        let mut e = entry(seq, ts, &prev, &payload_hash);
        // Sign hash ignores signature/public_key, so sign before setting them.
        let sign_hash_hex = compute_entry_hash_for_signing(&e);
        e.signature = Some(hex::encode(
            signing.sign(sign_hash_hex.as_bytes()).to_bytes(),
        ));
        e.public_key = Some(pubkey_hex.clone());
        prev = compute_entry_hash(&e);
        out.push(serde_json::to_string(&e).expect("entry should serialize"));
    }
    (out, pubkey_hex)
}

/// Write a 4-entry lenient-signed WAL into `dir` as a single segment.
fn write_signed_lenient_wal(dir: &Path) {
    let (lines, _pubkey) = signed_lenient_lines(4);
    let mut body = lines.join("\n");
    body.push('\n');
    std::fs::write(dir.join("00000001.jsonl"), body).expect("signed wal should write");
}

/// A non-valid strict record matching `outcome` and (optionally)
/// `reason.kind`, if present in a strict JSON report.
fn find_strict_record<'a>(report: &'a Value, outcome: &str, kind: &str) -> Option<&'a Value> {
    report["records"]
        .as_array()?
        .iter()
        .find(|r| r["outcome"] == outcome && r["reason"]["kind"] == kind)
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
        report["chain_root"].as_str().is_some_and(|r| r.len() == 64),
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
    assert!(
        text.contains("Events verified:"),
        "text report shows event count"
    );
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
    let sidecar_json: Value = serde_json::from_str(&sidecar_body).expect("sidecar should be JSON");
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

#[test]
fn verify_strict_valid_wal_passes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (pubkey, root) = write_strict_wal(dir.path());

    let out = run(&[
        "--format",
        "json",
        "verify",
        "--strict",
        "--wal",
        path_str(dir.path()),
        "--trusted-pubkey",
        &pubkey,
        "--expected-root",
        &root,
    ]);
    assert_eq!(code(&out), 0, "valid strict WAL should pass");

    let report: Value = serde_json::from_str(&stdout(&out)).expect("strict report should be JSON");
    assert_eq!(report["status"], "valid");
    assert_eq!(report["events_verified"], 3);
    assert_eq!(report["signatures_verified"], 3);
}

#[test]
fn verify_strict_detects_payload_tamper() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (pubkey, root) = write_strict_wal(dir.path());

    // Edit the amount inside the first payload without updating its
    // declared payload_hash: the strict recompute must catch it.
    let seg = dir.path().join("00000001.jsonl");
    let body = std::fs::read_to_string(&seg).expect("segment should read");
    std::fs::write(&seg, body.replacen("100.00", "999.99", 1)).expect("tamper write");

    let out = run(&[
        "--format",
        "json",
        "verify",
        "--strict",
        "--wal",
        path_str(dir.path()),
        "--trusted-pubkey",
        &pubkey,
        "--expected-root",
        &root,
    ]);
    assert_eq!(code(&out), 1, "tampered strict WAL should report issues");

    let report: Value = serde_json::from_str(&stdout(&out)).expect("strict report should be JSON");
    assert_eq!(report["status"], "invalid");
    assert!(
        find_strict_record(&report, "invalid", "payload_hash_mismatch").is_some(),
        "tamper must surface as payload_hash_mismatch"
    );
}

#[test]
fn verify_strict_wrong_pubkey_is_rejected_not_signature_failure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_pubkey, root) = write_strict_wal(dir.path());
    let wrong = "cc".repeat(32);

    let out = run(&[
        "--format",
        "json",
        "verify",
        "--strict",
        "--wal",
        path_str(dir.path()),
        "--trusted-pubkey",
        &wrong,
        "--expected-root",
        &root,
    ]);
    assert_eq!(code(&out), 1, "wrong pinned pubkey should report issues");

    let report: Value = serde_json::from_str(&stdout(&out)).expect("strict report should be JSON");
    assert_eq!(report["status"], "invalid");
    assert!(
        find_strict_record(&report, "rejected", "pubkey_mismatch").is_some(),
        "wrong key must be a pubkey_mismatch rejection, never a signature failure"
    );
}

#[test]
fn verify_strict_requires_pinned_pubkey_and_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (pubkey, root) = write_strict_wal(dir.path());

    // Missing --trusted-pubkey.
    let no_key = run(&[
        "verify",
        "--strict",
        "--wal",
        path_str(dir.path()),
        "--expected-root",
        &root,
    ]);
    assert_eq!(
        code(&no_key),
        2,
        "strict without a pinned pubkey is a usage error"
    );

    // Missing --expected-root.
    let no_root = run(&[
        "verify",
        "--strict",
        "--wal",
        path_str(dir.path()),
        "--trusted-pubkey",
        &pubkey,
    ]);
    assert_eq!(
        code(&no_root),
        2,
        "strict without an expected root is a usage error"
    );
}

#[test]
fn verify_strict_rejects_keystore_flag() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (pubkey, root) = write_strict_wal(dir.path());

    let out = run(&[
        "verify",
        "--strict",
        "--wal",
        path_str(dir.path()),
        "--trusted-pubkey",
        &pubkey,
        "--expected-root",
        &root,
        "--keystore",
        "unused.json",
    ]);
    assert_eq!(code(&out), 2, "--keystore is not supported under --strict");
}

#[test]
fn verify_lenient_on_strict_wal_emits_profile_hint() {
    // The whole point of the feature: a strict-signed WAL run through
    // the default lenient path fails every signature. Instead of a
    // bare wall of errors, the report must point the user at --strict.
    let dir = tempfile::tempdir().expect("tempdir");
    let (_pubkey, _root) = write_strict_wal(dir.path());

    let out = run(&["--format", "json", "verify", "--wal", path_str(dir.path())]);
    assert_eq!(
        code(&out),
        1,
        "strict WAL fails the lenient signature check"
    );

    let report: Value = serde_json::from_str(&stdout(&out)).expect("report should be JSON");
    assert_eq!(report["valid"], false);
    let warnings = report["warnings"].as_array().expect("warnings array");
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str().is_some_and(|s| s.contains("--strict"))),
        "lenient failure on a strict WAL must hint at --strict"
    );
}

#[test]
fn inspect_stats_on_max_sequence_does_not_panic() {
    // Regression: a record carrying sequence = u64::MAX overflowed the
    // `prev_seq + 1` contiguity check, panicking the binary (exit 101).
    // It must now report a non-contiguous chain and exit cleanly.
    let dir = tempfile::tempdir().expect("tempdir");
    let line1 = json!({
        "sequence": u64::MAX,
        "timestamp_ns": 1,
        "prev_hash": GENESIS_PREV_HASH,
        "payload_hash": "ab".repeat(32),
    });
    let line2 = json!({
        "sequence": 5,
        "timestamp_ns": 2,
        "prev_hash": "cd".repeat(32),
        "payload_hash": "ef".repeat(32),
    });
    let body = format!("{line1}\n{line2}\n");
    std::fs::write(dir.path().join("00000001.jsonl"), body).expect("write wal");

    let out = run(&[
        "inspect",
        "--wal",
        path_str(dir.path()),
        "--stats",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 0, "stats on a u64::MAX sequence must not panic");
    let stats: Value = serde_json::from_str(&stdout(&out)).expect("stats JSON");
    assert_eq!(stats["integrity"]["sequence_contiguous"], false);
}

#[test]
fn export_syslog_escapes_control_chars_in_event_type() {
    // A producer-controlled newline in event_type must not split the
    // syslog output into an extra forged record.
    let dir = tempfile::tempdir().expect("tempdir");
    let line = json!({
        "sequence": 1,
        "timestamp_ns": 1_700_000_000_000_000_000i64,
        "prev_hash": GENESIS_PREV_HASH,
        "payload_hash": "ab".repeat(32),
        "event_type": "login\n<13>1 forged",
        "source": "auth",
    });
    std::fs::write(dir.path().join("00000001.jsonl"), format!("{line}\n")).expect("write wal");

    let out = run(&[
        "export",
        "--wal",
        path_str(dir.path()),
        "--export-format",
        "syslog",
        "--format",
        "quiet",
    ]);
    assert_eq!(code(&out), 0);
    let body = stdout(&out);
    let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        lines.len(),
        1,
        "a newline in event_type must not add a syslog line"
    );
    assert!(
        body.contains("\\n"),
        "the newline must be escaped, not emitted raw"
    );
}

#[test]
fn verify_malformed_trusted_pubkey_is_a_usage_error() {
    // A fat-fingered --trusted-pubkey must fail as a usage error (exit 2),
    // not silently drop the pin and report the WAL as valid (exit 0).
    let dir = wal_dir();
    let out = run(&[
        "verify",
        "--wal",
        path_str(dir.path()),
        "--trusted-pubkey",
        "deadbeef", // 8 hex chars, not 64
    ]);
    assert_eq!(code(&out), 2, "malformed pin must be a usage error");

    // A well-formed (64-hex) pin still runs and, on this unsigned WAL,
    // reports issues (exit 1) rather than a usage error.
    let good_pin = "ab".repeat(32);
    let out2 = run(&[
        "verify",
        "--wal",
        path_str(dir.path()),
        "--trusted-pubkey",
        &good_pin,
    ]);
    assert_ne!(code(&out2), 2, "a well-formed pin is not a usage error");
}

#[test]
fn export_csv_neutralizes_formula_injection() {
    // event_type/source are attacker-controlled free text. A CSV cell that
    // begins with = + - @ is a spreadsheet formula; the exporter must prefix
    // such cells with a single quote so they render as literal text.
    let dir = tempfile::tempdir().expect("tempdir");
    let line = json!({
        "sequence": 1,
        "timestamp_ns": 1_700_000_000_000_000_000i64,
        "prev_hash": GENESIS_PREV_HASH,
        "payload_hash": "ab".repeat(32),
        "event_type": "=cmd|'/c calc'!A1",
        "source": "+SUM(1+1)",
    });
    std::fs::write(dir.path().join("00000001.jsonl"), format!("{line}\n")).expect("write wal");

    let out = run(&[
        "export",
        "--wal",
        path_str(dir.path()),
        "--export-format",
        "csv",
        "--format",
        "quiet",
    ]);
    assert_eq!(code(&out), 0);
    let body = stdout(&out);
    assert!(
        body.contains("'=cmd"),
        "event_type formula must be quote-prefixed: {body}"
    );
    assert!(
        body.contains("'+SUM"),
        "source formula must be quote-prefixed: {body}"
    );
}

#[test]
fn export_syslog_escapes_unicode_line_separators() {
    // U+2028 LINE SEPARATOR (and U+2029, U+0085) are line breaks outside the
    // C0 range; a Unicode-newline-aware SIEM could split on them and accept a
    // forged record. They must be escaped in the MSG body, not emitted raw,
    // and must not add a syslog line.
    let dir = tempfile::tempdir().expect("tempdir");
    let line = json!({
        "sequence": 1,
        "timestamp_ns": 1_700_000_000_000_000_000i64,
        "prev_hash": GENESIS_PREV_HASH,
        "payload_hash": "ab".repeat(32),
        "event_type": "login\u{2028}<13>1 forged",
        "source": "auth",
    });
    std::fs::write(dir.path().join("00000001.jsonl"), format!("{line}\n")).expect("write wal");

    let out = run(&[
        "export",
        "--wal",
        path_str(dir.path()),
        "--export-format",
        "syslog",
        "--format",
        "quiet",
    ]);
    assert_eq!(code(&out), 0);
    let body = stdout(&out);
    let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        lines.len(),
        1,
        "a U+2028 in event_type must not add a syslog line"
    );
    assert!(
        body.contains("\\u2028"),
        "U+2028 must be escaped, not raw: {body}"
    );
    assert!(
        !body.contains('\u{2028}'),
        "raw U+2028 must not survive in the output"
    );
}

#[test]
fn verify_chain_only_passes_and_warns_about_skipped_signatures() {
    // --chain-only walks the chain but verifies no signatures. On a
    // valid chain it passes (exit 0) and must warn that signatures were
    // not checked, so a green run can't be mistaken for a full verify.
    let dir = tempfile::tempdir().expect("tempdir");
    write_signed_lenient_wal(dir.path());

    let out = run(&[
        "verify",
        "--wal",
        path_str(dir.path()),
        "--chain-only",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 0);

    let report: Value = serde_json::from_str(&stdout(&out)).expect("report should be JSON");
    assert_eq!(report["valid"], true);
    assert_eq!(report["signatures_verified"], 0);
    assert_eq!(report["signatures_skipped"], 4);
    let warnings = report["warnings"].as_array().expect("warnings array");
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str().is_some_and(|s| s.contains("chain-only"))),
        "chain-only must warn that signatures were not verified: {warnings:?}"
    );
}

#[test]
fn verify_chain_only_still_detects_a_chain_break() {
    // Skipping signatures must NOT weaken chain tamper-evidence: a broken
    // prev_hash link still fails the run.
    let dir = tempfile::tempdir().expect("tempdir");
    let e1 = json!({
        "sequence": 1,
        "timestamp_ns": 1_700_000_000_000_000_000i64,
        "prev_hash": GENESIS_PREV_HASH,
        "payload_hash": "ab".repeat(32),
    });
    let e2 = json!({
        "sequence": 2,
        "timestamp_ns": 1_700_000_001_000_000_000i64,
        "prev_hash": "ff".repeat(32),
        "payload_hash": "cd".repeat(32),
    });
    std::fs::write(dir.path().join("00000001.jsonl"), format!("{e1}\n{e2}\n")).expect("write wal");

    let out = run(&[
        "verify",
        "--wal",
        path_str(dir.path()),
        "--chain-only",
        "--format",
        "json",
    ]);
    assert_eq!(
        code(&out),
        1,
        "a broken chain must fail even under chain-only"
    );
    let report: Value = serde_json::from_str(&stdout(&out)).expect("report should be JSON");
    assert_eq!(report["valid"], false);
}

#[test]
fn verify_chain_only_conflicts_with_pin_and_sample() {
    let dir = wal_dir();
    let pin = "ab".repeat(32);

    let with_pin = run(&[
        "verify",
        "--wal",
        path_str(dir.path()),
        "--chain-only",
        "--trusted-pubkey",
        &pin,
    ]);
    assert_eq!(
        code(&with_pin),
        2,
        "--chain-only with --trusted-pubkey is a usage error"
    );

    let with_sample = run(&[
        "verify",
        "--wal",
        path_str(dir.path()),
        "--chain-only",
        "--sample-signatures",
        "2",
    ]);
    assert_eq!(
        code(&with_sample),
        2,
        "--chain-only with --sample-signatures is a usage error"
    );
}

#[test]
fn verify_sample_signatures_checks_only_the_sampled_subset() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_signed_lenient_wal(dir.path()); // sequences 1..=4

    let out = run(&[
        "verify",
        "--wal",
        path_str(dir.path()),
        "--sample-signatures",
        "2",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 0);

    let report: Value = serde_json::from_str(&stdout(&out)).expect("report should be JSON");
    assert_eq!(report["valid"], true);
    // Sequences 2 and 4 are multiples of 2; 1 and 3 are skipped.
    assert_eq!(report["signatures_verified"], 2);
    assert_eq!(report["signatures_skipped"], 2);
    let warnings = report["warnings"].as_array().expect("warnings array");
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str().is_some_and(|s| s.contains("1-in-2"))),
        "sampling must disclose its partial coverage: {warnings:?}"
    );
}

#[test]
fn verify_sample_signatures_zero_is_a_usage_error() {
    let dir = wal_dir();
    let out = run(&[
        "verify",
        "--wal",
        path_str(dir.path()),
        "--sample-signatures",
        "0",
    ]);
    assert_eq!(code(&out), 2, "--sample-signatures 0 is a usage error");
}

#[test]
fn verify_streams_across_segments_without_merging_records() {
    // Streaming verification must keep segment boundaries: the last line
    // of segment 1 (written WITHOUT a trailing newline) must not merge
    // with the first line of segment 2. A full default verify over a
    // signed chain split across two segments must pass.
    let dir = tempfile::tempdir().expect("tempdir");
    let (lines, _pubkey) = signed_lenient_lines(4);
    std::fs::write(
        dir.path().join("00000001.jsonl"),
        format!("{}\n{}", lines[0], lines[1]), // no trailing newline
    )
    .expect("seg1 write");
    std::fs::write(
        dir.path().join("00000002.jsonl"),
        format!("{}\n{}\n", lines[2], lines[3]),
    )
    .expect("seg2 write");

    let out = run(&["verify", "--wal", path_str(dir.path()), "--format", "json"]);
    assert_eq!(code(&out), 0, "stdout: {}", stdout(&out));

    let report: Value = serde_json::from_str(&stdout(&out)).expect("report should be JSON");
    assert_eq!(report["valid"], true);
    assert_eq!(report["events_verified"], 4);
    assert_eq!(report["signatures_verified"], 4);
}

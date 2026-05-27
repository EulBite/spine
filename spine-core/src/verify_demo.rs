// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite

//! Strict WAL verifier for the WASM playground.
//!
//! Distinct from the lenient verifier in [`crate::verify`]: this one
//! is the high-stakes API. A single false positive (declaring a
//! tampered WAL valid) is end-of-credibility. The contract is therefore
//! narrower and more paranoid:
//!
//! 1. Every record MUST carry a signature; unsigned passes through in
//!    lenient mode, here it is rejected.
//! 2. The expected public key is pinned by the caller from outside the
//!    WAL. Records whose `public_key` differs from `expected_pubkey`
//!    are rejected before any signature check runs, so a forged
//!    signature under an attacker-chosen key never gets a chance to
//!    surface as "valid".
//! 3. `expected_root` is mandatory, not optional. The lenient verifier
//!    warns when it is missing; this one cannot run without it.
//! 4. `payload_hash` is recomputed from the canonical JSON of
//!    `payload`. The declared field is not trusted; mismatch is
//!    invalid. This catches the "edit the payload, forget to update
//!    the hash" tamper that the lenient pre-rollout path could miss.
//! 5. The signed bytes are `STRICT_DOMAIN_SEP || sign_hash_hex.as_bytes()`.
//!    The 13-byte version prefix makes the strict signature contract
//!    distinct from the lenient one, so a strict-issued signature
//!    cannot replay on top of a lenient envelope.
//! 6. All hash and pubkey comparisons that gate trust use
//!    `subtle::ConstantTimeEq`, not `==`.
//! 7. No-panic. Built under `#![deny(clippy::unwrap_used)]` plus
//!    `#![deny(clippy::expect_used)]`.
//! 8. Report bytes are deterministic for a given input. No HashMap,
//!    no internal timestamp, fail-fast at the first non-Valid
//!    outcome.
//! 9. The report carries three independent version axes: the strict
//!    verifier version, the highest format version seen across
//!    records, the manifest version echoed back to the caller.
//!
//! ## Strict-only invariants
//!
//! Beyond the strict-vs-lenient axis above, the strict verifier
//! enforces three invariants that the lenient path silently tolerates:
//!
//! * `format_version` must equal [`WAL_FORMAT_VERSION`]. A future
//!   bump requires re-publishing the manifest with a new
//!   `manifest_version`.
//! * `hash_alg`, when present, must equal `"blake3"`.
//! * `timestamp_ns` must be monotonically non-decreasing across
//!   records.
//!
//! ## DoS limits
//!
//! [`MAX_RECORDS_DEMO`] and [`MAX_PAYLOAD_BYTES`] cap the input. They
//! are public so the host page can pre-flight a fetch and abort
//! before invoking the verifier. They do NOT apply to the lenient CLI
//! path, where production WALs can be arbitrarily large.

use blake3::Hasher;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;
use subtle::ConstantTimeEq;

use crate::canonical::canonical_json;
use crate::wal_entry::{
    compute_entry_hash, compute_entry_hash_for_signing, validate_entry_hashes, WalEntry,
    GENESIS_PREV_HASH, WAL_FORMAT_VERSION,
};
use crate::VERIFIER_VERSION;

/// Domain-separation prefix for the strict signature.
pub const STRICT_DOMAIN_SEP: &[u8] = b"spine-wal-v1\x00";

/// Hard cap on records processed by the strict verifier. Exists to
/// bound the worst-case time the WASM playground can spend on a
/// pathologically large input. The lenient CLI path has no such cap.
pub const MAX_RECORDS_DEMO: usize = 100_000;

/// Hard cap on the canonical JSON byte length of any single payload.
/// Strict refuses anything larger so a malicious manifest cannot
/// freeze the host page on parse.
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DemoStatus {
    Valid,
    Invalid,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct DemoReport {
    pub status: DemoStatus,
    pub verifier_version: &'static str,
    pub wal_format_version_seen: u32,
    pub manifest_version_used: u32,
    pub events_verified: u64,
    pub signatures_verified: u64,
    pub expected_pubkey_fp: String,
    pub chain_root: String,
    pub records: Vec<DemoRecordEntry>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DemoRecordEntry {
    pub sequence: u64,
    #[serde(flatten)]
    pub outcome: DemoRecordOutcome,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum DemoRecordOutcome {
    Valid,
    Invalid { reason: InvalidReason },
    Rejected { reason: RejectedReason },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InvalidReason {
    InvalidGenesis { expected: String, found: String },
    ChainBreak { expected: String, found: String },
    SequenceGap { previous: u64, missing: u64 },
    TimestampRegression { previous: i64, current: i64 },
    PayloadHashMismatch { declared: String, computed: String },
    InvalidHashFormat { details: String },
    SignatureVerificationFailed,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RejectedReason {
    ParseError { line: usize, details: String },
    UnsupportedFormatVersion { found: u32 },
    UnsupportedHashAlg { found: String },
    UnsignedRecord,
    PubkeyMismatch,
    SignatureMalformed { details: String },
    PubkeyMalformed { details: String },
    NoPayload,
    PayloadTooLarge { bytes: usize, limit: usize },
    NonCanonicalPayload { details: String },
    TooManyRecords { limit: usize },
}

/// Verify a strict WAL. Always returns a [`DemoReport`]; configuration
/// errors (malformed `expected_pubkey`, `expected_root` not 64 hex
/// chars) surface as `status == Error` with `error` populated.
///
/// The function is infallible by construction: no panic path, no
/// `Result` return. Hosts can therefore wrap it for `wasm-bindgen`
/// without exception bridging.
pub fn verify_demo_wal(
    bytes: &[u8],
    expected_pubkey: &str,
    expected_root: &str,
    manifest_version: u32,
) -> DemoReport {
    let expected_pubkey_fp = fingerprint(expected_pubkey);

    let expected_pubkey_bytes = match parse_hex_32(expected_pubkey) {
        Ok(b) => b,
        Err(details) => {
            return error_report(
                manifest_version,
                &expected_pubkey_fp,
                format!("expected_pubkey not valid 32-byte hex: {details}"),
            );
        }
    };
    if VerifyingKey::from_bytes(&expected_pubkey_bytes).is_err() {
        return error_report(
            manifest_version,
            &expected_pubkey_fp,
            "expected_pubkey is not a valid Ed25519 verifying key".to_string(),
        );
    }

    // Strip an optional `0x` prefix before checking the length, so a
    // manifest authored by hand or by a tool that emits Ethereum-style
    // hex still parses. Matches the lenient verifier.
    let expected_root_trimmed = expected_root.trim();
    let expected_root_norm = expected_root_trimmed
        .strip_prefix("0x")
        .unwrap_or(expected_root_trimmed)
        .to_lowercase();
    if expected_root_norm.len() != 64 || !expected_root_norm.chars().all(|c| c.is_ascii_hexdigit())
    {
        return error_report(
            manifest_version,
            &expected_pubkey_fp,
            format!(
                "expected_root must be 64 hex chars (with optional 0x prefix), got {} chars after stripping",
                expected_root_norm.len()
            ),
        );
    }

    let mut report = DemoReport {
        status: DemoStatus::Valid,
        verifier_version: VERIFIER_VERSION,
        wal_format_version_seen: 0,
        manifest_version_used: manifest_version,
        events_verified: 0,
        signatures_verified: 0,
        expected_pubkey_fp: expected_pubkey_fp.clone(),
        chain_root: String::new(),
        records: Vec::new(),
        error: None,
    };

    let mut prev_hash: Option<String> = None;
    let mut prev_sequence: Option<u64> = None;
    let mut prev_timestamp: Option<i64> = None;
    let mut running_hash = Hasher::new();
    let mut record_count = 0usize;
    let mut halted = false;

    for (line_idx, line) in bytes.split(|&b| b == b'\n').enumerate() {
        let line = trim_trailing_cr(line);
        if line.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }
        record_count += 1;
        if record_count > MAX_RECORDS_DEMO {
            let seq = prev_sequence.map(|s| s + 1).unwrap_or(record_count as u64);
            report.records.push(DemoRecordEntry {
                sequence: seq,
                outcome: DemoRecordOutcome::Rejected {
                    reason: RejectedReason::TooManyRecords {
                        limit: MAX_RECORDS_DEMO,
                    },
                },
            });
            halted = true;
            break;
        }

        // Two-pass parse: first into Value to detect whether the
        // record explicitly declared format_version (the WalEntry
        // serde default would otherwise silently coerce a missing
        // field into 1, masking producer bugs in the strict profile).
        let raw_value: serde_json::Value = match serde_json::from_slice(line) {
            Ok(v) => v,
            Err(e) => {
                let seq = prev_sequence.map(|s| s + 1).unwrap_or(record_count as u64);
                report.records.push(DemoRecordEntry {
                    sequence: seq,
                    outcome: DemoRecordOutcome::Rejected {
                        reason: RejectedReason::ParseError {
                            line: line_idx + 1,
                            details: e.to_string(),
                        },
                    },
                });
                halted = true;
                break;
            }
        };
        let format_version_declared = raw_value
            .as_object()
            .is_some_and(|m| m.contains_key("format_version"));

        let entry: WalEntry = match serde_json::from_value(raw_value) {
            Ok(e) => e,
            Err(e) => {
                let seq = prev_sequence.map(|s| s + 1).unwrap_or(record_count as u64);
                report.records.push(DemoRecordEntry {
                    sequence: seq,
                    outcome: DemoRecordOutcome::Rejected {
                        reason: RejectedReason::ParseError {
                            line: line_idx + 1,
                            details: e.to_string(),
                        },
                    },
                });
                halted = true;
                break;
            }
        };

        if entry.format_version > report.wal_format_version_seen {
            report.wal_format_version_seen = entry.format_version;
        }

        let outcome = strict_check_record(
            &entry,
            format_version_declared,
            &expected_pubkey_bytes,
            prev_hash.as_deref(),
            prev_sequence,
            prev_timestamp,
        );

        match outcome {
            RecordResult::Valid => {
                // chain_root is BLAKE3 over the concatenated UTF-8
                // bytes of each entry's hex string, not the raw 32
                // bytes. Matches `verify_wal_bytes`, the cross-language
                // vectors, and the on-disk `prev_hash` form.
                let entry_hash = compute_entry_hash(&entry);
                running_hash.update(entry_hash.as_bytes());
                prev_hash = Some(entry_hash);
                prev_sequence = Some(entry.sequence);
                prev_timestamp = Some(entry.timestamp_ns);
                report.events_verified += 1;
                report.signatures_verified += 1;
                report.records.push(DemoRecordEntry {
                    sequence: entry.sequence,
                    outcome: DemoRecordOutcome::Valid,
                });
            }
            RecordResult::Invalid(reason) => {
                report.records.push(DemoRecordEntry {
                    sequence: entry.sequence,
                    outcome: DemoRecordOutcome::Invalid { reason },
                });
                halted = true;
                break;
            }
            RecordResult::Rejected(reason) => {
                report.records.push(DemoRecordEntry {
                    sequence: entry.sequence,
                    outcome: DemoRecordOutcome::Rejected { reason },
                });
                halted = true;
                break;
            }
        }
    }

    report.chain_root = hex::encode(running_hash.finalize().as_bytes());

    if halted {
        report.status = DemoStatus::Invalid;
    } else if !constant_time_hex_eq(&report.chain_root, &expected_root_norm) {
        report.status = DemoStatus::Invalid;
        report.error = Some(format!(
            "chain_root mismatch: expected {expected_root_norm}, computed {}",
            report.chain_root
        ));
    }

    report
}

enum RecordResult {
    Valid,
    Invalid(InvalidReason),
    Rejected(RejectedReason),
}

fn strict_check_record(
    entry: &WalEntry,
    format_version_declared: bool,
    expected_pubkey_bytes: &[u8; 32],
    prev_hash: Option<&str>,
    prev_sequence: Option<u64>,
    prev_timestamp: Option<i64>,
) -> RecordResult {
    // Strict refuses records that omit format_version, even though
    // serde would silently default it to 1. A producer that forgets
    // the field today might emit a v2 record tomorrow that the same
    // parser still maps to 1, producing a "valid" report on bytes
    // the producer never committed to.
    if !format_version_declared {
        return RecordResult::Rejected(RejectedReason::UnsupportedFormatVersion { found: 0 });
    }
    if entry.format_version != WAL_FORMAT_VERSION {
        return RecordResult::Rejected(RejectedReason::UnsupportedFormatVersion {
            found: entry.format_version,
        });
    }
    if let Some(alg) = entry.hash_alg.as_deref() {
        if alg != "blake3" {
            return RecordResult::Rejected(RejectedReason::UnsupportedHashAlg {
                found: alg.to_string(),
            });
        }
    }

    let (sig_hex, pk_hex) = match (entry.signature.as_deref(), entry.public_key.as_deref()) {
        (Some(s), Some(p)) => (s, p),
        _ => return RecordResult::Rejected(RejectedReason::UnsignedRecord),
    };

    let sig_bytes = match parse_hex_64(sig_hex) {
        Ok(b) => b,
        Err(details) => {
            return RecordResult::Rejected(RejectedReason::SignatureMalformed { details });
        }
    };
    let pk_bytes = match parse_hex_32(pk_hex) {
        Ok(b) => b,
        Err(details) => return RecordResult::Rejected(RejectedReason::PubkeyMalformed { details }),
    };

    if pk_bytes.ct_eq(expected_pubkey_bytes).unwrap_u8() != 1 {
        return RecordResult::Rejected(RejectedReason::PubkeyMismatch);
    }

    let verifying_key = match VerifyingKey::from_bytes(&pk_bytes) {
        Ok(k) => k,
        Err(e) => {
            return RecordResult::Rejected(RejectedReason::PubkeyMalformed {
                details: format!("not a valid Ed25519 point: {e}"),
            });
        }
    };

    let payload = match entry.payload.as_ref() {
        Some(p) => p,
        None => return RecordResult::Rejected(RejectedReason::NoPayload),
    };

    let canonical_bytes = match canonical_json(payload) {
        Ok(b) => b,
        Err(e) => {
            return RecordResult::Rejected(RejectedReason::NonCanonicalPayload {
                details: e.to_string(),
            });
        }
    };
    if canonical_bytes.len() > MAX_PAYLOAD_BYTES {
        return RecordResult::Rejected(RejectedReason::PayloadTooLarge {
            bytes: canonical_bytes.len(),
            limit: MAX_PAYLOAD_BYTES,
        });
    }

    let computed_payload_hash = hex::encode(blake3::hash(&canonical_bytes).as_bytes());
    if !constant_time_hex_eq(&computed_payload_hash, &entry.payload_hash) {
        return RecordResult::Invalid(InvalidReason::PayloadHashMismatch {
            declared: entry.payload_hash.clone(),
            computed: computed_payload_hash,
        });
    }

    if let Some(prev) = prev_hash {
        // Constant-time. prev_hash is not a secret on the WAL itself,
        // but the strict verifier promises constant-time on every
        // trust-gating comparison, and uniform discipline is cheaper
        // to audit than a per-field judgement call.
        if !constant_time_hex_eq(&entry.prev_hash, prev) {
            return RecordResult::Invalid(InvalidReason::ChainBreak {
                expected: prev.to_string(),
                found: entry.prev_hash.clone(),
            });
        }
    } else {
        // First record. Genesis must carry sequence=1 and the all-
        // zeros prev_hash. Either violation is a hard reject of the
        // entire WAL because a strict consumer cannot trust the rest
        // of the chain if the genesis is wrong.
        if entry.sequence != 1 {
            return RecordResult::Invalid(InvalidReason::InvalidGenesis {
                expected: "sequence=1".to_string(),
                found: format!("sequence={}", entry.sequence),
            });
        }
        if !constant_time_hex_eq(&entry.prev_hash, GENESIS_PREV_HASH) {
            return RecordResult::Invalid(InvalidReason::InvalidGenesis {
                expected: GENESIS_PREV_HASH.to_string(),
                found: entry.prev_hash.clone(),
            });
        }
    }

    if let Some(prev_seq) = prev_sequence {
        if entry.sequence != prev_seq + 1 {
            return RecordResult::Invalid(InvalidReason::SequenceGap {
                previous: prev_seq,
                missing: prev_seq + 1,
            });
        }
    }

    if let Some(prev_ts) = prev_timestamp {
        if entry.timestamp_ns < prev_ts {
            return RecordResult::Invalid(InvalidReason::TimestampRegression {
                previous: prev_ts,
                current: entry.timestamp_ns,
            });
        }
    }

    let format_errors = validate_entry_hashes(entry);
    if !format_errors.is_empty() {
        return RecordResult::Invalid(InvalidReason::InvalidHashFormat {
            details: format_errors.join("; "),
        });
    }

    let signature = Signature::from_bytes(&sig_bytes);
    let sign_hash = compute_entry_hash_for_signing(entry);
    let mut msg = Vec::with_capacity(STRICT_DOMAIN_SEP.len() + sign_hash.len());
    msg.extend_from_slice(STRICT_DOMAIN_SEP);
    msg.extend_from_slice(sign_hash.as_bytes());

    if verifying_key.verify(&msg, &signature).is_err() {
        return RecordResult::Invalid(InvalidReason::SignatureVerificationFailed);
    }

    RecordResult::Valid
}

fn error_report(manifest_version: u32, fp: &str, msg: String) -> DemoReport {
    DemoReport {
        status: DemoStatus::Error,
        verifier_version: VERIFIER_VERSION,
        wal_format_version_seen: 0,
        manifest_version_used: manifest_version,
        events_verified: 0,
        signatures_verified: 0,
        expected_pubkey_fp: fp.to_string(),
        chain_root: String::new(),
        records: Vec::new(),
        error: Some(msg),
    }
}

fn fingerprint(expected_pubkey: &str) -> String {
    // Always 16 lowercase hex chars: 8 raw bytes is enough to
    // identify a key across human displays without exposing the full
    // pin in the report. The full pubkey is never echoed back.
    //
    // When the input is malformed and would otherwise yield fewer
    // than 16 hex digits, right-pad with '0' so the report shape is
    // stable regardless of caller input. Downstream parsers that
    // assume `expected_pubkey_fp.length === 16` therefore stay valid
    // even on the error path.
    let collected: String = expected_pubkey
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(16)
        .collect::<String>()
        .to_lowercase();
    format!("{collected:0<16}")
}

fn trim_trailing_cr(line: &[u8]) -> &[u8] {
    if line.last() == Some(&b'\r') {
        &line[..line.len() - 1]
    } else {
        line
    }
}

fn parse_hex_32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    let raw = hex::decode(s).map_err(|e| e.to_string())?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn parse_hex_64(s: &str) -> Result<[u8; 64], String> {
    if s.len() != 128 {
        return Err(format!("expected 128 hex chars, got {}", s.len()));
    }
    let raw = hex::decode(s).map_err(|e| e.to_string())?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn constant_time_hex_eq(a: &str, b: &str) -> bool {
    // Both inputs are lowercase hex strings whose lengths match by
    // construction (both are 64 chars). Compare the underlying bytes
    // constant-time so a remote attacker cannot use response timing
    // to learn a prefix of the expected root or pubkey.
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).unwrap_u8() == 1
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::wal_entry::compute_entry_hash;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    const FAKE_ROOT_HEX: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    fn signer_keypair(seed: u8) -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        (sk, pk_hex)
    }

    fn build_entry(seq: u64, ts: i64, prev: &str, payload: serde_json::Value) -> WalEntry {
        let canonical = canonical_json(&payload).unwrap();
        let payload_hash = hex::encode(blake3::hash(&canonical).as_bytes());
        WalEntry {
            format_version: 1,
            sequence: seq,
            timestamp_ns: ts,
            prev_hash: prev.to_string(),
            payload_hash,
            event_type: None,
            source: None,
            signature: None,
            public_key: None,
            key_id: None,
            event_id: None,
            stream_id: None,
            hash_alg: Some("blake3".to_string()),
            payload: Some(payload),
            receipt: None,
        }
    }

    fn sign_strict(entry: &mut WalEntry, signing_key: &SigningKey) {
        let sign_hash = compute_entry_hash_for_signing(entry);
        let mut msg = Vec::new();
        msg.extend_from_slice(STRICT_DOMAIN_SEP);
        msg.extend_from_slice(sign_hash.as_bytes());
        let sig = signing_key.sign(&msg);
        entry.signature = Some(hex::encode(sig.to_bytes()));
        entry.public_key = Some(hex::encode(signing_key.verifying_key().to_bytes()));
    }

    fn to_jsonl(entries: &[WalEntry]) -> Vec<u8> {
        let mut buf = Vec::new();
        for e in entries {
            buf.extend_from_slice(serde_json::to_string(e).unwrap().as_bytes());
            buf.push(b'\n');
        }
        buf
    }

    fn build_chain(n: u64, signing_key: &SigningKey) -> (Vec<WalEntry>, String) {
        let mut entries = Vec::new();
        let mut prev = GENESIS_PREV_HASH.to_string();
        let mut accum = Hasher::new();
        for i in 1..=n {
            let mut e = build_entry(i, 1000 * i as i64, &prev, json!({"i": i, "kind": "demo"}));
            sign_strict(&mut e, signing_key);
            let h = compute_entry_hash(&e);
            accum.update(h.as_bytes());
            prev = h;
            entries.push(e);
        }
        let root = hex::encode(accum.finalize().as_bytes());
        (entries, root)
    }

    #[test]
    fn happy_path_validates_a_signed_chain() {
        let (sk, pk_hex) = signer_keypair(0x10);
        let (entries, root) = build_chain(3, &sk);
        let bytes = to_jsonl(&entries);

        let report = verify_demo_wal(&bytes, &pk_hex, &root, 1);
        assert_eq!(report.status, DemoStatus::Valid, "report: {report:?}");
        assert_eq!(report.events_verified, 3);
        assert_eq!(report.signatures_verified, 3);
        assert_eq!(report.chain_root, root);
        assert_eq!(report.records.len(), 3);
        for r in &report.records {
            assert!(matches!(r.outcome, DemoRecordOutcome::Valid));
        }
    }

    #[test]
    fn unsigned_record_is_rejected_with_record_rejected_not_signature_failure() {
        let (sk, pk_hex) = signer_keypair(0x11);
        let (mut entries, root) = build_chain(2, &sk);
        // Strip signature: lenient would skip, strict must REJECT.
        // The distinction matters: a "missing signature" UI hint that
        // talked about Ed25519 would mislead a visitor into thinking
        // the crypto failed, when in fact the record never carried
        // crypto to begin with.
        entries[1].signature = None;
        entries[1].public_key = None;

        let bytes = to_jsonl(&entries);
        let report = verify_demo_wal(&bytes, &pk_hex, &root, 1);
        assert_eq!(report.status, DemoStatus::Invalid);
        let last = report.records.last().unwrap();
        assert!(matches!(
            &last.outcome,
            DemoRecordOutcome::Rejected {
                reason: RejectedReason::UnsignedRecord
            }
        ));
    }

    #[test]
    fn wrong_pubkey_is_rejected_not_called_invalid_signature() {
        // A record signed under a key OTHER than the pinned one must
        // surface as Rejected/PubkeyMismatch, never as
        // SignatureVerificationFailed. That distinction is the entire
        // point of pubkey pinning.
        let (sk_signer, _) = signer_keypair(0x20);
        let (entries, root) = build_chain(1, &sk_signer);
        let bytes = to_jsonl(&entries);

        let (_, other_pk_hex) = signer_keypair(0x21);
        let report = verify_demo_wal(&bytes, &other_pk_hex, &root, 1);
        assert_eq!(report.status, DemoStatus::Invalid);
        let last = report.records.last().unwrap();
        assert!(matches!(
            &last.outcome,
            DemoRecordOutcome::Rejected {
                reason: RejectedReason::PubkeyMismatch
            }
        ));
    }

    #[test]
    fn payload_tamper_is_detected_via_recomputed_hash() {
        let (sk, pk_hex) = signer_keypair(0x30);
        let (mut entries, root) = build_chain(1, &sk);
        // Mutate payload but leave the (now stale) payload_hash and
        // signature untouched. The lenient verifier would still trust
        // the declared payload_hash and miss this; strict catches it
        // because it recomputes from canonical JSON.
        entries[0].payload = Some(json!({"i": 1, "kind": "tampered"}));

        let bytes = to_jsonl(&entries);
        let report = verify_demo_wal(&bytes, &pk_hex, &root, 1);
        assert_eq!(report.status, DemoStatus::Invalid);
        let last = report.records.last().unwrap();
        assert!(matches!(
            &last.outcome,
            DemoRecordOutcome::Invalid {
                reason: InvalidReason::PayloadHashMismatch { .. }
            }
        ));
    }

    #[test]
    fn missing_payload_is_rejected() {
        let (sk, pk_hex) = signer_keypair(0x31);
        let (mut entries, root) = build_chain(1, &sk);
        entries[0].payload = None;
        let bytes = to_jsonl(&entries);
        let report = verify_demo_wal(&bytes, &pk_hex, &root, 1);
        assert_eq!(report.status, DemoStatus::Invalid);
        assert!(matches!(
            &report.records.last().unwrap().outcome,
            DemoRecordOutcome::Rejected {
                reason: RejectedReason::NoPayload
            }
        ));
    }

    #[test]
    fn unsupported_format_version_is_rejected() {
        let (sk, pk_hex) = signer_keypair(0x32);
        let (mut entries, root) = build_chain(1, &sk);
        entries[0].format_version = 999;
        let bytes = to_jsonl(&entries);
        let report = verify_demo_wal(&bytes, &pk_hex, &root, 1);
        assert_eq!(report.status, DemoStatus::Invalid);
        assert!(matches!(
            &report.records.last().unwrap().outcome,
            DemoRecordOutcome::Rejected {
                reason: RejectedReason::UnsupportedFormatVersion { found: 999 }
            }
        ));
    }

    #[test]
    fn unsupported_hash_alg_is_rejected() {
        let (sk, pk_hex) = signer_keypair(0x33);
        let (mut entries, root) = build_chain(1, &sk);
        entries[0].hash_alg = Some("sha256".to_string());
        let bytes = to_jsonl(&entries);
        let report = verify_demo_wal(&bytes, &pk_hex, &root, 1);
        assert_eq!(report.status, DemoStatus::Invalid);
        assert!(matches!(
            &report.records.last().unwrap().outcome,
            DemoRecordOutcome::Rejected {
                reason: RejectedReason::UnsupportedHashAlg { .. }
            }
        ));
    }

    #[test]
    fn malformed_expected_pubkey_yields_error_status() {
        let bytes = b"";
        let report = verify_demo_wal(bytes, "not-hex", FAKE_ROOT_HEX, 1);
        assert_eq!(report.status, DemoStatus::Error);
        // Fingerprint shape stays stable even on the error path: 16
        // chars padded with '0' when the input lacks hex digits. JS
        // consumers can rely on the field width regardless of input.
        assert_eq!(report.expected_pubkey_fp.len(), 16);
        assert!(report.error.unwrap().contains("expected_pubkey"));
    }

    #[test]
    fn malformed_expected_root_yields_error_status() {
        let (_, pk_hex) = signer_keypair(0x40);
        let report = verify_demo_wal(b"", &pk_hex, "too-short", 1);
        assert_eq!(report.status, DemoStatus::Error);
        assert!(report.error.unwrap().contains("expected_root"));
    }

    #[test]
    fn root_mismatch_invalidates_otherwise_clean_wal() {
        let (sk, pk_hex) = signer_keypair(0x50);
        let (entries, _root) = build_chain(2, &sk);
        let bytes = to_jsonl(&entries);
        let report = verify_demo_wal(&bytes, &pk_hex, FAKE_ROOT_HEX, 1);
        assert_eq!(report.status, DemoStatus::Invalid);
        assert!(report.error.unwrap().contains("chain_root mismatch"));
    }

    #[test]
    fn report_is_deterministic_byte_for_byte() {
        let (sk, pk_hex) = signer_keypair(0x60);
        let (entries, root) = build_chain(2, &sk);
        let bytes = to_jsonl(&entries);
        let r1 = verify_demo_wal(&bytes, &pk_hex, &root, 7);
        let r2 = verify_demo_wal(&bytes, &pk_hex, &root, 7);

        let s1 = serde_json::to_string(&r1).unwrap();
        let s2 = serde_json::to_string(&r2).unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn report_carries_versioning() {
        let (sk, pk_hex) = signer_keypair(0x70);
        let (entries, root) = build_chain(1, &sk);
        let bytes = to_jsonl(&entries);
        let report = verify_demo_wal(&bytes, &pk_hex, &root, 42);
        assert_eq!(report.verifier_version, VERIFIER_VERSION);
        assert_eq!(report.wal_format_version_seen, WAL_FORMAT_VERSION);
        assert_eq!(report.manifest_version_used, 42);
        assert_eq!(report.expected_pubkey_fp.len(), 16);
    }

    #[test]
    fn fingerprint_does_not_leak_full_pubkey() {
        let (_, pk_hex) = signer_keypair(0x71);
        let report = verify_demo_wal(b"", &pk_hex, FAKE_ROOT_HEX, 1);
        // Whatever the status, the fingerprint must be the short
        // form. We never echo the full pin into the report.
        assert_eq!(report.expected_pubkey_fp.len(), 16);
        assert_ne!(report.expected_pubkey_fp, pk_hex);
    }

    #[test]
    fn lenient_signed_envelope_does_not_validate_strict() {
        // Strict adds the spine-wal-v1\0 prefix to the signed message.
        // A signature produced without that prefix (lenient signer)
        // must fail SignatureVerificationFailed under strict, never
        // be accepted as Valid. This catches a deploy that
        // accidentally points the playground at lenient-signed bytes.
        let (sk, pk_hex) = signer_keypair(0x80);
        let mut entries = build_chain(1, &sk).0;
        let lenient_sign_hash = compute_entry_hash_for_signing(&entries[0]);
        let sig = sk.sign(lenient_sign_hash.as_bytes());
        entries[0].signature = Some(hex::encode(sig.to_bytes()));

        let mut accum = Hasher::new();
        accum.update(compute_entry_hash(&entries[0]).as_bytes());
        let root = hex::encode(accum.finalize().as_bytes());
        let bytes = to_jsonl(&entries);
        let report = verify_demo_wal(&bytes, &pk_hex, &root, 1);
        assert_eq!(report.status, DemoStatus::Invalid);
        assert!(matches!(
            &report.records.last().unwrap().outcome,
            DemoRecordOutcome::Invalid {
                reason: InvalidReason::SignatureVerificationFailed
            }
        ));
    }

    #[test]
    fn empty_wal_is_invalid_because_root_cannot_match() {
        let (_, pk_hex) = signer_keypair(0x90);
        // Zero records produces an accumulator over an empty
        // sequence. That digest is well-defined but cannot match the
        // attacker-chosen expected_root we pass in.
        let report = verify_demo_wal(b"", &pk_hex, FAKE_ROOT_HEX, 1);
        assert_eq!(report.status, DemoStatus::Invalid);
        assert_eq!(report.events_verified, 0);
        assert!(report.error.unwrap().contains("chain_root mismatch"));
    }

    #[test]
    fn fail_fast_records_show_only_processed_records() {
        let (sk, pk_hex) = signer_keypair(0xA0);
        let (mut entries, _root) = build_chain(3, &sk);
        entries[1].payload = Some(json!({"tampered": true}));
        let bytes = to_jsonl(&entries);

        let report = verify_demo_wal(&bytes, &pk_hex, FAKE_ROOT_HEX, 1);
        assert_eq!(report.status, DemoStatus::Invalid);
        // Genesis (seq 1) Valid, seq 2 Invalid, seq 3 NOT processed.
        assert_eq!(report.records.len(), 2);
        assert!(matches!(
            report.records[0].outcome,
            DemoRecordOutcome::Valid
        ));
        assert!(matches!(
            report.records[1].outcome,
            DemoRecordOutcome::Invalid { .. }
        ));
    }
}

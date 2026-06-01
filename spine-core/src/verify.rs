// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite

//! Lenient WAL verifier, used by the CLI auditor.
//!
//! "Lenient" here means: tolerant of records that pre-date the signing
//! rollout. The verifier still detects every cryptographic tamper
//! (chain break, payload edit, signature swap) it can, but it does not
//! reject records that simply lack a signature, and it accepts
//! `expected_root` as optional. The strict counterpart in
//! [`crate::verify_demo`] enforces a much narrower contract suitable
//! for a public playground.
//!
//! ## What the lenient verifier checks
//!
//! Per record:
//!
//! * The genesis record (no predecessor) must carry sequence `1` and
//!   [`GENESIS_PREV_HASH`]. Chain-link enforcement reuses
//!   [`verify_chain_link`] so the rule lives in one place.
//! * Every other record's `prev_hash` must equal
//!   [`compute_entry_hash`] of its predecessor.
//! * `sequence` must be contiguous with the previous record.
//! * `timestamp_ns` must be non-decreasing.
//! * When BOTH `signature` and `public_key` are present, the
//!   signature must verify against [`compute_entry_hash_for_signing`]
//!   serialized as UTF-8 bytes. When NEITHER is present the record
//!   passes through (this is the lenient bit). A record carrying only
//!   one of the two is treated as malformed and reported as
//!   `unsigned_record` to match the strict verifier's terminology.
//! * If [`LenientOptions::trusted_pubkey`] is set, the record's
//!   `public_key` must match the trusted pin; mismatch produces an
//!   `untrusted_pubkey` error rather than a "valid signature".
//! * Hash hex shapes are validated via [`validate_entry_hashes`].
//! * If `hash_alg` is set and not `"blake3"`, the record contributes
//!   a `hash_alg_mismatch` warning (lenient does not refuse it; the
//!   strict verifier does).
//! * If a [`Keystore`] is supplied AND the record carries a receipt,
//!   the receipt signature is verified against the keystore.
//!
//! Per stream: `chain_root` is BLAKE3 over the concatenated UTF-8
//! bytes of each record's `compute_entry_hash` hex string (NOT the
//! raw 32 bytes). The hex form is the same byte sequence that
//! consumers see as `prev_hash` on disk, so the accumulator commits
//! to the same bytes the WAL writer produced. Cross-language
//! implementations that hash raw 32-byte digests instead silently
//! diverge; the cross-language vectors in `test-vectors/vectors.json`
//! pin this contract. `expected_root` is compared regardless of
//! whether any records were processed: an empty WAL must NOT pass an
//! `expected_root` gate, otherwise an attacker that empties the
//! segment directory bypasses the CI check.
//!
//! ## Failure-handling model
//!
//! `verify_wal_bytes*` always returns a [`VerificationResult`]. There
//! is no [`Result`] return: the lenient verifier never aborts, even
//! when [`LenientOptions::fail_fast`] is set. fail-fast affects only
//! the loop control flow: subsequent records are not processed, but
//! the partial report (records processed up to the failure,
//! `chain_root` of those records, warnings, the failing error in
//! `errors`) is still emitted. SRE workflows that need both "stopped
//! at the first error" and "what did we see before that" stay
//! usable.
//!
//! ## Signature contract reminder
//!
//! The signed bytes are the UTF-8 form of the sign hash hex string,
//! produced by [`compute_entry_hash_for_signing`]. NEVER pass
//! [`compute_entry_hash`] here: the chain hash includes
//! `signature`/`public_key` via presence framing, so reusing it as
//! the verification message produces a deterministic false negative
//! on every signed entry.
//!
//! Receipt failures observed inside the loop are translated to
//! [`VerificationError`] entries (via the internal `push_or_halt`)
//! rather than bubbling up as a dedicated error variant. Keystore
//! loading itself lives in the CLI layer that calls
//! [`Keystore::load_from_file`], which surfaces failures as
//! [`ReceiptError`] directly. Keep this surface narrow on purpose.

use blake3::Hasher;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;
// The trusted-pubkey pin is compared constant-time: the pin is a value
// a remote caller may probe, and timing on a short-circuiting `==` would
// leak how many leading bytes matched.
use subtle::ConstantTimeEq;

use crate::receipt::{verify_receipt_signature, Keystore, ReceiptError};
use crate::wal_entry::{
    compute_entry_hash, compute_entry_hash_for_signing, validate_entry_hashes, verify_chain_link,
    HashVerification, WalEntry,
};

/// Result of verifying a WAL byte stream.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub events_verified: u64,
    pub signatures_verified: u64,
    pub receipts_verified: u64,
    pub chain_root: String,
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    pub first_timestamp: Option<i64>,
    pub last_timestamp: Option<i64>,
    pub errors: Vec<VerificationError>,
    pub warnings: Vec<String>,
    /// Set when [`LenientOptions::fail_fast`] is active AND a record
    /// caused early termination. Consumers can use this to render
    /// "stopped early; the rest of the stream was not inspected" hints
    /// without having to re-derive the state from the error list.
    pub halted_early: bool,
}

/// A single non-fatal failure observed during verification.
///
/// The `error_type` strings are part of the public contract: external
/// tooling pattern-matches on them to triage failures. Adding a new
/// variant is a minor version bump; changing an existing string is
/// breaking.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationError {
    pub sequence: Option<u64>,
    pub error_type: String,
    pub details: String,
}

/// Knobs for the lenient verifier. `Default` gives the accumulate-all
/// behaviour with no keystore, no trusted pubkey pin, and no expected
/// root.
#[derive(Default, Debug, Clone, Copy)]
pub struct LenientOptions<'a> {
    pub expected_root: Option<&'a str>,
    pub keystore: Option<&'a Keystore>,
    pub fail_fast: bool,
    /// Hex-encoded Ed25519 pubkey to pin every record's
    /// `public_key` against. When `Some`, a record whose
    /// `public_key` differs (constant-time compare) is reported as
    /// `untrusted_pubkey` and its signature is NOT considered
    /// verified. When `None`, lenient trusts the record-declared
    /// pubkey; a warning is added to the result to make this
    /// explicit.
    pub trusted_pubkey: Option<&'a str>,
}

fn empty_result() -> VerificationResult {
    VerificationResult {
        valid: true,
        events_verified: 0,
        signatures_verified: 0,
        receipts_verified: 0,
        chain_root: String::new(),
        first_sequence: None,
        last_sequence: None,
        first_timestamp: None,
        last_timestamp: None,
        errors: Vec::new(),
        warnings: Vec::new(),
        halted_early: false,
    }
}

/// Verify the lenient policy with default options.
pub fn verify_wal_bytes(bytes: &[u8]) -> VerificationResult {
    verify_internal(bytes, &LenientOptions::default())
}

/// Verify with explicit options. Always returns a result, even when
/// `opts.fail_fast` halts early.
pub fn verify_wal_bytes_with_options(bytes: &[u8], opts: &LenientOptions) -> VerificationResult {
    verify_internal(bytes, opts)
}

fn verify_internal(bytes: &[u8], opts: &LenientOptions) -> VerificationResult {
    let mut result = empty_result();

    // Used by the trusted-pubkey gate. Decoded once so we don't pay
    // the hex-decode cost per record. Bad input here lands in the
    // result.warnings list and degrades to "no pin" semantics: the
    // alternative is failing every record with a config error, but
    // the warning path is friendlier for someone who fat-fingered
    // the flag.
    let trusted_pubkey_bytes: Option<[u8; 32]> = match opts.trusted_pubkey {
        Some(s) => match decode_hex_32(s) {
            Ok(b) => Some(b),
            Err(e) => {
                result.warnings.push(format!(
                    "trusted_pubkey is not a valid 32-byte hex string ({e}); falling back to record-declared pubkeys"
                ));
                None
            }
        },
        None => None,
    };

    let mut prev_entry: Option<WalEntry> = None;
    let mut prev_sequence: Option<u64> = None;
    let mut prev_timestamp: Option<i64> = None;
    let mut running_hash = Hasher::new();
    let mut receipts_seen: u64 = 0;
    let mut signatures_unpinned: u64 = 0;

    'outer: for (line_idx, line) in bytes.split(|&b| b == b'\n').enumerate() {
        let line_trim_end = trim_trailing_cr(line);
        if line_trim_end.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }
        let line_num = line_idx + 1;

        let entry: WalEntry = match serde_json::from_slice(line_trim_end) {
            Ok(e) => e,
            Err(e) => {
                let err = VerificationError {
                    sequence: None,
                    error_type: "parse_error".to_string(),
                    details: format!("line {line_num}: {e}"),
                };
                if push_or_halt(&mut result, err, opts.fail_fast) {
                    break 'outer;
                }
                continue;
            }
        };

        if result.first_sequence.is_none() {
            result.first_sequence = Some(entry.sequence);
            result.first_timestamp = Some(entry.timestamp_ns);
        }
        result.last_sequence = Some(entry.sequence);
        result.last_timestamp = Some(entry.timestamp_ns);

        // Chain-link rule reused from wal_entry::verify_chain_link so
        // a future refactor can't silently fork the lenient path from
        // the canonical contract.
        match verify_chain_link(&entry, prev_entry.as_ref()) {
            HashVerification::Valid => {}
            HashVerification::InvalidGenesis { reason } => {
                let err = VerificationError {
                    sequence: Some(entry.sequence),
                    error_type: "invalid_genesis".to_string(),
                    details: reason,
                };
                if push_or_halt(&mut result, err, opts.fail_fast) {
                    break 'outer;
                }
            }
            HashVerification::Mismatch { expected, actual } => {
                let err = VerificationError {
                    sequence: Some(entry.sequence),
                    error_type: "chain_break".to_string(),
                    details: format!("expected prev_hash {expected}, found {actual}"),
                };
                if push_or_halt(&mut result, err, opts.fail_fast) {
                    break 'outer;
                }
            }
        }

        if let Some(prev_seq) = prev_sequence {
            // saturating_add: a hostile record can carry sequence = u64::MAX
            // (it fails the genesis check, but in accumulate-all mode the
            // chain still advances and records it as prev_sequence), and a
            // bare `prev_seq + 1` would then overflow on the next record.
            // spine-core promises never to panic, so saturate instead.
            let expected = prev_seq.saturating_add(1);
            if entry.sequence != expected {
                let err = VerificationError {
                    sequence: Some(entry.sequence),
                    error_type: "sequence_gap".to_string(),
                    details: format!(
                        "expected sequence {expected} after {prev_seq}, found {}",
                        entry.sequence
                    ),
                };
                if push_or_halt(&mut result, err, opts.fail_fast) {
                    break 'outer;
                }
            }
        }

        if let Some(prev_ts) = prev_timestamp {
            if entry.timestamp_ns < prev_ts {
                let err = VerificationError {
                    sequence: Some(entry.sequence),
                    error_type: "timestamp_regression".to_string(),
                    details: format!("timestamp {} < previous {prev_ts}", entry.timestamp_ns),
                };
                if push_or_halt(&mut result, err, opts.fail_fast) {
                    break 'outer;
                }
            }
        }

        match (entry.signature.as_deref(), entry.public_key.as_deref()) {
            (Some(sig_hex), Some(pk_hex)) => {
                if let Some(ref pin) = trusted_pubkey_bytes {
                    match decode_hex_32(pk_hex) {
                        Ok(pk_bytes) if pk_bytes.ct_eq(pin).unwrap_u8() == 1 => {}
                        _ => {
                            let err = VerificationError {
                                sequence: Some(entry.sequence),
                                error_type: "untrusted_pubkey".to_string(),
                                details: "record public_key does not match trusted_pubkey pin"
                                    .to_string(),
                            };
                            if push_or_halt(&mut result, err, opts.fail_fast) {
                                break 'outer;
                            }
                            // Skip the signature math: it would either
                            // pass (and look "valid" under a wrong key)
                            // or fail (and surface as InvalidSignature,
                            // a misleading reason). Trusted-pubkey
                            // failures are reason enough on their own.
                            advance_chain(
                                &mut result,
                                &mut prev_entry,
                                &mut prev_sequence,
                                &mut prev_timestamp,
                                &mut running_hash,
                                entry,
                            );
                            continue;
                        }
                    }
                }
                match verify_entry_signature(&entry, sig_hex, pk_hex) {
                    Ok(true) => {
                        result.signatures_verified += 1;
                        if trusted_pubkey_bytes.is_none() {
                            signatures_unpinned += 1;
                        }
                    }
                    Ok(false) | Err(()) => {
                        let err = VerificationError {
                            sequence: Some(entry.sequence),
                            error_type: "invalid_signature".to_string(),
                            details: "Ed25519 verification failed".to_string(),
                        };
                        if push_or_halt(&mut result, err, opts.fail_fast) {
                            break 'outer;
                        }
                    }
                }
            }
            (None, None) => {
                // Lenient tolerates unsigned records by default, but when a
                // trusted pubkey is pinned the operator is asserting that
                // every record was signed by that key (see the
                // --trusted-pubkey docs). An unsigned record violates that,
                // so flag it instead of letting the gate pass.
                if trusted_pubkey_bytes.is_some() {
                    let err = VerificationError {
                        sequence: Some(entry.sequence),
                        error_type: "unsigned_record".to_string(),
                        details: "record is unsigned but trusted_pubkey requires every record \
                                  to be signed by the pinned key"
                            .to_string(),
                    };
                    if push_or_halt(&mut result, err, opts.fail_fast) {
                        break 'outer;
                    }
                }
            }
            _ => {
                // Asymmetric: signature OR pubkey set, not both.
                // Aligned with the strict verifier's terminology so
                // downstream triage by error_type is uniform across
                // the two profiles. The "the producer half-set the
                // signature material" case is fundamentally an
                // unsigned record, not a failed verification.
                let err = VerificationError {
                    sequence: Some(entry.sequence),
                    error_type: "unsigned_record".to_string(),
                    details: "signature and public_key must both be present or both absent"
                        .to_string(),
                };
                if push_or_halt(&mut result, err, opts.fail_fast) {
                    break 'outer;
                }
            }
        }

        if let Some(alg) = entry.hash_alg.as_deref() {
            if alg != "blake3" {
                result.warnings.push(format!(
                    "sequence {}: hash_alg = {alg:?} but lenient verifier assumes blake3; \
                     payload integrity is unchecked",
                    entry.sequence
                ));
            }
        }

        if entry.receipt.is_some() {
            receipts_seen += 1;
        }

        if let Some(ks) = opts.keystore {
            match verify_receipt_signature(&entry, ks) {
                Ok(true) => result.receipts_verified += 1,
                Ok(false) => {}
                Err(err) => {
                    let (etype, details) = match &err {
                        ReceiptError::KeyUnknown { .. } => ("receipt_key_unknown", err.to_string()),
                        ReceiptError::UnsupportedAlg { .. } => {
                            ("receipt_unsupported_alg", err.to_string())
                        }
                        ReceiptError::SigMalformed { .. } => {
                            ("receipt_sig_malformed", err.to_string())
                        }
                        ReceiptError::SignatureInvalid { .. } => {
                            ("receipt_signature_invalid", err.to_string())
                        }
                        ReceiptError::EntryMismatch { .. } => {
                            ("receipt_entry_mismatch", err.to_string())
                        }
                        ReceiptError::CanonicalSerialize { .. } => {
                            ("receipt_canonical_failed", err.to_string())
                        }
                        // Unreachable here: load happens in the CLI,
                        // not inside the loop. Reflect anyway rather
                        // than swallow.
                        ReceiptError::KeystoreLoad { .. } => {
                            ("keystore_load_failed", err.to_string())
                        }
                    };
                    let v_err = VerificationError {
                        sequence: Some(entry.sequence),
                        error_type: etype.to_string(),
                        details,
                    };
                    if push_or_halt(&mut result, v_err, opts.fail_fast) {
                        break 'outer;
                    }
                }
            }
        }

        for msg in validate_entry_hashes(&entry) {
            let err = VerificationError {
                sequence: Some(entry.sequence),
                error_type: "invalid_hash_format".to_string(),
                details: msg,
            };
            if push_or_halt(&mut result, err, opts.fail_fast) {
                break 'outer;
            }
        }

        advance_chain(
            &mut result,
            &mut prev_entry,
            &mut prev_sequence,
            &mut prev_timestamp,
            &mut running_hash,
            entry,
        );
    }

    result.chain_root = hex::encode(running_hash.finalize().as_bytes());

    if result.events_verified == 0 {
        result.warnings.push("No WAL records found".to_string());
    }

    // Always check expected_root, even when no records were processed.
    // An attacker who empties the segment directory must not be able
    // to claim "valid: true" by virtue of producing zero records that
    // also produce zero failures.
    //
    // A root that normalizes to empty (whitespace-only, or a bare `0x`) is
    // treated as "no anchor supplied", matching the wasm facade so the same
    // operator input is verified identically on the CLI and in the browser.
    let normalized_root = opts
        .expected_root
        .map(crate::normalize_hex_anchor)
        .filter(|s| !s.is_empty());
    if let Some(normalized) = normalized_root {
        if result.chain_root != normalized {
            let computed = result.chain_root.clone();
            let err = VerificationError {
                sequence: None,
                error_type: "root_mismatch".to_string(),
                details: format!("expected {normalized}, computed {computed}"),
            };
            push_or_halt(&mut result, err, false);
        }
    } else if result.events_verified > 0 {
        result.warnings.push(
            "No expected root provided: verified internal consistency only. \
             For full tamper-detection, compare chain_root against an external anchor."
                .to_string(),
        );
    }

    if opts.trusted_pubkey.is_none() && signatures_unpinned > 0 {
        result.warnings.push(format!(
            "{signatures_unpinned} signatures were verified against record-declared pubkeys (no external pin). \
             Pass --trusted-pubkey on the CLI to require an externally pinned key, \
             or use the strict verifier (spine_core::verify_demo_wal)."
        ));
    }

    if opts.keystore.is_none() && receipts_seen > 0 {
        result.warnings.push(format!(
            "{receipts_seen} records carry server receipts but no keystore was supplied. \
             Pass --keystore on the CLI to verify receipt signatures."
        ));
    }

    result
}

fn advance_chain(
    result: &mut VerificationResult,
    prev_entry: &mut Option<WalEntry>,
    prev_sequence: &mut Option<u64>,
    prev_timestamp: &mut Option<i64>,
    running_hash: &mut Hasher,
    entry: WalEntry,
) {
    let entry_hash = compute_entry_hash(&entry);
    running_hash.update(entry_hash.as_bytes());
    *prev_sequence = Some(entry.sequence);
    *prev_timestamp = Some(entry.timestamp_ns);
    *prev_entry = Some(entry);
    result.events_verified += 1;
}

/// Push `err` into the result and return `true` when the caller
/// should break out of the per-record loop (fail-fast). Always sets
/// `result.valid = false`.
fn push_or_halt(result: &mut VerificationResult, err: VerificationError, fail_fast: bool) -> bool {
    result.valid = false;
    result.errors.push(err);
    if fail_fast {
        result.halted_early = true;
        true
    } else {
        false
    }
}

fn trim_trailing_cr(line: &[u8]) -> &[u8] {
    if line.last() == Some(&b'\r') {
        &line[..line.len() - 1]
    } else {
        line
    }
}

fn decode_hex_32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    let raw = hex::decode(s).map_err(|e| e.to_string())?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn verify_entry_signature(entry: &WalEntry, sig_hex: &str, pk_hex: &str) -> Result<bool, ()> {
    let sig_bytes = hex::decode(sig_hex).map_err(|_| ())?;
    if sig_bytes.len() != 64 {
        return Err(());
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    let pk_bytes = hex::decode(pk_hex).map_err(|_| ())?;
    if pk_bytes.len() != 32 {
        return Err(());
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let verifying_key = VerifyingKey::from_bytes(&pk_arr).map_err(|_| ())?;

    // CRITICAL: lenient signs over the UTF-8 bytes of the sign hash
    // (compute_entry_hash_for_signing), NOT the chain hash and NOT
    // with a domain-separation prefix. Strict adds the prefix; see
    // verify_demo.rs.
    let message = compute_entry_hash_for_signing(entry);
    Ok(verifying_key.verify(message.as_bytes(), &signature).is_ok())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::wal_entry::{compute_entry_hash_for_signing, GENESIS_PREV_HASH};
    use ed25519_dalek::{Signer, SigningKey};

    fn make_entry(seq: u64, ts: i64, prev: &str, payload: &str) -> WalEntry {
        WalEntry {
            format_version: 1,
            sequence: seq,
            timestamp_ns: ts,
            prev_hash: prev.to_string(),
            payload_hash: pad_hex(payload),
            event_type: None,
            source: None,
            signature: None,
            public_key: None,
            key_id: None,
            event_id: None,
            stream_id: None,
            hash_alg: None,
            payload: None,
            receipt: None,
        }
    }

    fn pad_hex(s: &str) -> String {
        let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        format!("{cleaned:0<64}")
    }

    fn to_jsonl(entries: &[WalEntry]) -> Vec<u8> {
        let mut buf = Vec::new();
        for e in entries {
            let line = serde_json::to_string(e).unwrap();
            buf.extend_from_slice(line.as_bytes());
            buf.push(b'\n');
        }
        buf
    }

    fn build_valid_chain(n: u64) -> Vec<WalEntry> {
        let mut entries = Vec::new();
        let mut prev = GENESIS_PREV_HASH.to_string();
        for i in 1..=n {
            let e = make_entry(i, 1000 * i as i64, &prev, &format!("payload{i}"));
            prev = compute_entry_hash(&e);
            entries.push(e);
        }
        entries
    }

    fn sign_entry(entry: &mut WalEntry, signing_key: &SigningKey) {
        let msg = compute_entry_hash_for_signing(entry);
        let sig = signing_key.sign(msg.as_bytes());
        entry.signature = Some(hex::encode(sig.to_bytes()));
        entry.public_key = Some(hex::encode(signing_key.verifying_key().to_bytes()));
    }

    #[test]
    fn empty_input_warns_and_passes_when_no_expected_root() {
        let r = verify_wal_bytes(b"");
        assert!(r.valid);
        assert_eq!(r.events_verified, 0);
        assert!(r.warnings.iter().any(|w| w.contains("No WAL records")));
    }

    #[test]
    fn empty_input_fails_when_expected_root_is_provided() {
        // Regression net for the "empty WAL bypasses expected_root"
        // bug: an attacker who empties the segment directory must
        // not be able to claim valid=true under a CI gate.
        let root = "a".repeat(64);
        let opts = LenientOptions {
            expected_root: Some(&root),
            keystore: None,
            fail_fast: false,
            trusted_pubkey: None,
        };
        let r = verify_wal_bytes_with_options(b"", &opts);
        assert!(!r.valid);
        assert!(r.errors.iter().any(|e| e.error_type == "root_mismatch"));
    }

    #[test]
    fn valid_chain_verifies() {
        let entries = build_valid_chain(3);
        let bytes = to_jsonl(&entries);
        let r = verify_wal_bytes(&bytes);
        assert!(r.valid, "errors: {:?}", r.errors);
        assert_eq!(r.events_verified, 3);
        assert_eq!(r.first_sequence, Some(1));
        assert_eq!(r.last_sequence, Some(3));
    }

    #[test]
    fn chain_break_detected() {
        let mut entries = build_valid_chain(2);
        entries[1].prev_hash = "f".repeat(64);
        let bytes = to_jsonl(&entries);
        let r = verify_wal_bytes(&bytes);
        assert!(!r.valid);
        assert!(r.errors.iter().any(|e| e.error_type == "chain_break"));
    }

    #[test]
    fn invalid_genesis_detected_on_wrong_prev_hash() {
        let mut entries = build_valid_chain(1);
        entries[0].prev_hash = "f".repeat(64);
        let bytes = to_jsonl(&entries);
        let r = verify_wal_bytes(&bytes);
        assert!(!r.valid);
        assert!(r.errors.iter().any(|e| e.error_type == "invalid_genesis"));
    }

    #[test]
    fn invalid_genesis_detected_on_wrong_sequence() {
        let mut entries = build_valid_chain(1);
        entries[0].sequence = 42;
        let bytes = to_jsonl(&entries);
        let r = verify_wal_bytes(&bytes);
        assert!(!r.valid);
        assert!(r
            .errors
            .iter()
            .any(|e| e.error_type == "invalid_genesis" && e.details.contains("42")));
    }

    #[test]
    fn sequence_gap_detected() {
        let mut entries = Vec::new();
        let e1 = make_entry(1, 1000, GENESIS_PREV_HASH, "p1");
        let h1 = compute_entry_hash(&e1);
        entries.push(e1);
        entries.push(make_entry(3, 3000, &h1, "p3"));

        let bytes = to_jsonl(&entries);
        let r = verify_wal_bytes(&bytes);
        assert!(!r.valid);
        assert!(r.errors.iter().any(|e| e.error_type == "sequence_gap"));
    }

    #[test]
    fn timestamp_regression_detected() {
        let mut entries = Vec::new();
        let e1 = make_entry(1, 2000, GENESIS_PREV_HASH, "p1");
        let h1 = compute_entry_hash(&e1);
        entries.push(e1);
        entries.push(make_entry(2, 1000, &h1, "p2"));

        let bytes = to_jsonl(&entries);
        let r = verify_wal_bytes(&bytes);
        assert!(!r.valid);
        assert!(r
            .errors
            .iter()
            .any(|e| e.error_type == "timestamp_regression"));
    }

    #[test]
    fn signature_check_passes_on_correct_sig() {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let mut entries = build_valid_chain(1);
        sign_entry(&mut entries[0], &signing_key);
        let bytes = to_jsonl(&entries);
        let r = verify_wal_bytes(&bytes);
        assert!(r.valid, "errors: {:?}", r.errors);
        assert_eq!(r.signatures_verified, 1);
        // No pin: should warn about unpinned signatures.
        assert!(r
            .warnings
            .iter()
            .any(|w| w.contains("record-declared pubkeys")));
    }

    #[test]
    fn signature_check_fails_on_tampered_payload() {
        let signing_key = SigningKey::from_bytes(&[0x43; 32]);
        let mut entries = build_valid_chain(1);
        sign_entry(&mut entries[0], &signing_key);
        entries[0].payload_hash = pad_hex("ff");

        let bytes = to_jsonl(&entries);
        let r = verify_wal_bytes(&bytes);
        assert!(!r.valid);
        assert!(r.errors.iter().any(|e| e.error_type == "invalid_signature"));
    }

    #[test]
    fn asymmetric_sig_pubkey_is_rejected_as_unsigned_record() {
        // Same terminology as strict (RejectedReason::UnsignedRecord).
        let mut entries = build_valid_chain(1);
        entries[0].signature = Some("a".repeat(128));
        let bytes = to_jsonl(&entries);
        let r = verify_wal_bytes(&bytes);
        assert!(!r.valid);
        assert!(r.errors.iter().any(|e| e.error_type == "unsigned_record"));
    }

    #[test]
    fn trusted_pubkey_match_does_not_warn_about_unpinned() {
        let signing_key = SigningKey::from_bytes(&[0x44; 32]);
        let pk_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let mut entries = build_valid_chain(1);
        sign_entry(&mut entries[0], &signing_key);
        let bytes = to_jsonl(&entries);
        let opts = LenientOptions {
            expected_root: None,
            keystore: None,
            fail_fast: false,
            trusted_pubkey: Some(&pk_hex),
        };
        let r = verify_wal_bytes_with_options(&bytes, &opts);
        assert!(r.valid, "errors: {:?}", r.errors);
        assert_eq!(r.signatures_verified, 1);
        assert!(!r
            .warnings
            .iter()
            .any(|w| w.contains("record-declared pubkeys")));
    }

    #[test]
    fn trusted_pubkey_mismatch_produces_untrusted_pubkey_error() {
        let signing_key = SigningKey::from_bytes(&[0x45; 32]);
        let mut entries = build_valid_chain(1);
        sign_entry(&mut entries[0], &signing_key);
        let bytes = to_jsonl(&entries);
        let other_pin = hex::encode([0xAAu8; 32]);
        let opts = LenientOptions {
            expected_root: None,
            keystore: None,
            fail_fast: false,
            trusted_pubkey: Some(&other_pin),
        };
        let r = verify_wal_bytes_with_options(&bytes, &opts);
        assert!(!r.valid);
        assert!(r.errors.iter().any(|e| e.error_type == "untrusted_pubkey"));
        // The verifier MUST NOT also report invalid_signature: pinning
        // failure short-circuits the signature math, otherwise a wrong
        // pin shows up as a "broken signature" and confuses triage.
        assert!(!r.errors.iter().any(|e| e.error_type == "invalid_signature"));
    }

    #[test]
    fn trusted_pubkey_flags_unsigned_records() {
        // With a pin set, the lenient verifier asserts every record is
        // signed by that key. A fully unsigned chain must NOT pass just
        // because its links and (optional) root are consistent.
        let entries = build_valid_chain(2); // unsigned
        let bytes = to_jsonl(&entries);
        let pin = hex::encode([0x55u8; 32]);
        let opts = LenientOptions {
            expected_root: None,
            keystore: None,
            fail_fast: false,
            trusted_pubkey: Some(&pin),
        };
        let r = verify_wal_bytes_with_options(&bytes, &opts);
        assert!(!r.valid);
        assert!(r.errors.iter().any(|e| e.error_type == "unsigned_record"));
    }

    #[test]
    fn hash_alg_other_than_blake3_emits_warning_in_lenient() {
        let mut entries = build_valid_chain(1);
        entries[0].hash_alg = Some("sha256".to_string());
        let bytes = to_jsonl(&entries);
        let r = verify_wal_bytes(&bytes);
        // Lenient does NOT refuse, but warns loudly so a downstream
        // operator can see the producer did not commit to blake3.
        assert!(r.valid);
        assert!(r.warnings.iter().any(|w| w.contains("hash_alg")));
    }

    #[test]
    fn expected_root_match_is_silent() {
        let entries = build_valid_chain(2);
        let bytes = to_jsonl(&entries);
        let r_no_root = verify_wal_bytes(&bytes);
        let computed = r_no_root.chain_root.clone();
        let opts = LenientOptions {
            expected_root: Some(&computed),
            keystore: None,
            fail_fast: false,
            trusted_pubkey: None,
        };
        let r = verify_wal_bytes_with_options(&bytes, &opts);
        assert!(r.valid);
        assert!(!r.warnings.iter().any(|w| w.contains("expected root")));
    }

    #[test]
    fn expected_root_mismatch_is_an_error() {
        let entries = build_valid_chain(2);
        let bytes = to_jsonl(&entries);
        let wrong = "f".repeat(64);
        let opts = LenientOptions {
            expected_root: Some(&wrong),
            keystore: None,
            fail_fast: false,
            trusted_pubkey: None,
        };
        let r = verify_wal_bytes_with_options(&bytes, &opts);
        assert!(!r.valid);
        assert!(r.errors.iter().any(|e| e.error_type == "root_mismatch"));
    }

    #[test]
    fn expected_root_missing_emits_warning_not_error() {
        let entries = build_valid_chain(2);
        let bytes = to_jsonl(&entries);
        let r = verify_wal_bytes(&bytes);
        assert!(r.valid);
        assert!(r.warnings.iter().any(|w| w.contains("No expected root")));
    }

    #[test]
    fn whitespace_only_expected_root_is_treated_as_no_anchor() {
        // A root that normalizes to empty (whitespace-only, or a bare 0x) is
        // treated as "no anchor", matching the wasm facade so the CLI and the
        // browser verify the same operator input identically. Previously the
        // CLI compared "" against the chain_root and reported root_mismatch
        // while the facade said valid.
        let entries = build_valid_chain(2);
        let bytes = to_jsonl(&entries);
        for ws in ["   ", "\t", "0x", "  0X  "] {
            let opts = LenientOptions {
                expected_root: Some(ws),
                keystore: None,
                fail_fast: false,
                trusted_pubkey: None,
            };
            let r = verify_wal_bytes_with_options(&bytes, &opts);
            assert!(
                r.valid,
                "whitespace root {ws:?} should not fail: {:?}",
                r.errors
            );
            assert!(!r.errors.iter().any(|e| e.error_type == "root_mismatch"));
            assert!(r.warnings.iter().any(|w| w.contains("No expected root")));
        }
    }

    #[test]
    fn fail_fast_halts_but_preserves_partial_report() {
        // The chain has one good record at seq=1 followed by a
        // chain break at seq=2. fail_fast must stop processing, AND
        // the report must still carry events_verified=1, the
        // chain_root over the first record, plus the error.
        let mut entries = build_valid_chain(3);
        entries[1].prev_hash = "f".repeat(64);
        let bytes = to_jsonl(&entries);
        let opts = LenientOptions {
            expected_root: None,
            keystore: None,
            fail_fast: true,
            trusted_pubkey: None,
        };
        let r = verify_wal_bytes_with_options(&bytes, &opts);
        assert!(!r.valid);
        assert!(r.halted_early);
        assert_eq!(r.events_verified, 1);
        assert!(!r.chain_root.is_empty());
        assert!(r.errors.iter().any(|e| e.error_type == "chain_break"));
    }

    #[test]
    fn handles_crlf_line_endings() {
        let entries = build_valid_chain(2);
        let bytes_lf = to_jsonl(&entries);
        let s = std::str::from_utf8(&bytes_lf).unwrap();
        let bytes_crlf = s.replace('\n', "\r\n").into_bytes();

        let r = verify_wal_bytes(&bytes_crlf);
        assert!(r.valid, "errors: {:?}", r.errors);
        assert_eq!(r.events_verified, 2);
    }

    #[test]
    fn parse_error_on_bad_json_is_accumulated() {
        let bytes = b"not-json\n".to_vec();
        let r = verify_wal_bytes(&bytes);
        assert!(!r.valid);
        assert!(r.errors.iter().any(|e| e.error_type == "parse_error"));
    }

    #[test]
    fn max_sequence_first_record_does_not_panic() {
        // Regression: a first record carrying sequence = u64::MAX used to
        // overflow `prev_seq + 1` on the following record (panic in debug,
        // silent wrap in release). It must now degrade to a normal failure
        // rather than abort the verifier.
        let a = make_entry(u64::MAX, 1, GENESIS_PREV_HASH, "p1");
        let h = compute_entry_hash(&a);
        let b = make_entry(5, 2, &h, "p2");
        let bytes = to_jsonl(&[a, b]);
        let r = verify_wal_bytes(&bytes);
        assert!(!r.valid); // genesis sequence is not 1
        assert_eq!(r.events_verified, 2);
        assert!(r.errors.iter().any(|e| e.error_type == "sequence_gap"));
    }

    #[test]
    fn receipts_without_keystore_emit_warning() {
        use crate::receipt::Receipt;
        let mut entries = build_valid_chain(1);
        entries[0].receipt = Some(Receipt {
            event_id: "e".to_string(),
            payload_hash: "ab".repeat(32),
            server_time: "2026-05-27T10:00:00Z".to_string(),
            server_seq: 1,
            receipt_sig: "00".repeat(64),
            server_key_id: "k".to_string(),
            sig_alg: "ed25519".to_string(),
            batch_id: None,
        });
        let bytes = to_jsonl(&entries);
        let r = verify_wal_bytes(&bytes);
        // Lenient does not fail receipts without a keystore, but warns.
        assert!(r.warnings.iter().any(|w| w.contains("receipts")));
    }
}

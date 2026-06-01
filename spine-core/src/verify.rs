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
//! [`VerificationError`] entries (via the internal `LenientVerifier::push`)
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
    /// Records that carried signature material but were NOT individually
    /// verified because a reduced [`SignaturePolicy`] was in effect
    /// (chain-only or sampling). Always `0` under the default
    /// [`SignaturePolicy::All`]. A non-zero value means signature
    /// coverage was deliberately partial; the result carries a warning
    /// spelling out what that means for the threat model.
    pub signatures_skipped: u64,
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

/// How aggressively the lenient verifier checks per-record Ed25519
/// signatures.
///
/// Signature verification dominates the cost of a large WAL: walking
/// the hash chain and parsing JSON is roughly an order of magnitude
/// cheaper than verifying one Ed25519 signature per record. An auditor
/// who only needs chain-and-root integrity, or a routine spot-check,
/// can trade signature coverage for speed with this knob.
///
/// It governs ONLY whether the Ed25519 math runs. The chain link,
/// sequence, timestamp, hash-format and `expected_root` checks always
/// run in full regardless of the policy: reducing signature coverage
/// never weakens the chain's own tamper-evidence.
///
/// This policy is selected through [`LenientVerifier::new`]. The
/// buffered convenience entry points ([`verify_wal_bytes`],
/// [`verify_wal_bytes_with_options`]) always use [`SignaturePolicy::All`]
/// so the WASM playground and the published cross-language vectors keep
/// verifying every signature.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SignaturePolicy {
    /// Verify every signed record's signature. The default, and the
    /// only policy that defends against a targeted forger.
    #[default]
    All,
    /// Verify no signatures: walk the chain, sequence, timestamps and
    /// root only. Fastest. Retains tamper-evidence only when paired
    /// with an authenticated `expected_root`; without one it proves
    /// internal self-consistency, nothing more.
    None,
    /// Verify one record in every `one_in` (those whose `sequence` is a
    /// multiple of `one_in`). A routine spot-check for accidental
    /// corruption or a wrong-key rollout, NOT a defense against a
    /// targeted forger who can simply avoid the sampled positions. A
    /// sampled signature that fails still fails the whole run. `one_in`
    /// of `0` checks nothing (treated as "no sampling").
    Sample { one_in: u64 },
}

impl SignaturePolicy {
    /// Whether the record at `sequence` should have its signature
    /// verified under this policy.
    fn should_check(self, sequence: u64) -> bool {
        match self {
            SignaturePolicy::All => true,
            SignaturePolicy::None => false,
            SignaturePolicy::Sample { one_in } => one_in != 0 && sequence % one_in == 0,
        }
    }
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
        signatures_skipped: 0,
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
    // The buffered entry points always verify every signature: the WASM
    // playground and the published cross-language vectors depend on it.
    // Streaming callers that want a reduced policy build a
    // `LenientVerifier` directly.
    let mut verifier = LenientVerifier::new(opts, SignaturePolicy::All);
    for line in bytes.split(|&b| b == b'\n') {
        if verifier.process_line(line) {
            break;
        }
    }
    verifier.finish()
}

/// Incremental lenient verifier for streaming a WAL one line at a time.
///
/// [`verify_wal_bytes`] / [`verify_wal_bytes_with_options`] materialise
/// the whole WAL as a byte slice, which is the right tool for the WASM
/// playground and small inputs. A multi-gigabyte production WAL does
/// not fit comfortably in memory, so the CLI feeds segments line by
/// line through this type: peak memory stays flat (one line buffer plus
/// the running chain state) instead of scaling with the WAL size.
///
/// Both surfaces drive this exact state machine, so the streaming and
/// buffered paths can never silently diverge: `verify_internal` is just
/// a `split('\n')` loop over [`process_line`].
///
/// Usage: [`LenientVerifier::new`], then call [`process_line`] for each
/// line (stop early when it returns `true`, the fail-fast signal), then
/// [`finish`] to obtain the [`VerificationResult`].
///
/// [`process_line`]: LenientVerifier::process_line
/// [`finish`]: LenientVerifier::finish
pub struct LenientVerifier<'a> {
    opts: LenientOptions<'a>,
    policy: SignaturePolicy,
    /// Decoded once in [`new`](LenientVerifier::new) so we do not pay
    /// the hex-decode cost per record. A malformed pin degrades to "no
    /// pin" semantics with a warning rather than failing every record.
    trusted_pubkey_bytes: Option<[u8; 32]>,
    result: VerificationResult,
    prev_entry: Option<WalEntry>,
    prev_sequence: Option<u64>,
    prev_timestamp: Option<i64>,
    running_hash: Hasher,
    receipts_seen: u64,
    signatures_unpinned: u64,
    /// 1-based index of the line most recently passed to
    /// [`process_line`](LenientVerifier::process_line), used to quote
    /// the offending line in `parse_error` details. Counts every line
    /// fed (including skipped whitespace lines) so the number matches
    /// the buffered path's `split('\n')` enumeration exactly.
    line_counter: usize,
}

impl<'a> LenientVerifier<'a> {
    /// Build a verifier for `opts` under `policy`. No bytes are
    /// processed yet; feed lines with
    /// [`process_line`](LenientVerifier::process_line).
    pub fn new(opts: &LenientOptions<'a>, policy: SignaturePolicy) -> Self {
        let mut result = empty_result();
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
        Self {
            opts: *opts,
            policy,
            trusted_pubkey_bytes,
            result,
            prev_entry: None,
            prev_sequence: None,
            prev_timestamp: None,
            running_hash: Hasher::new(),
            receipts_seen: 0,
            signatures_unpinned: 0,
            line_counter: 0,
        }
    }

    /// Process one line of the WAL. The line must NOT include its
    /// trailing newline; a trailing `\r` is tolerated (CRLF WALs).
    /// Whitespace-only lines are skipped.
    ///
    /// Returns `true` when the caller should stop feeding lines: this
    /// happens only under [`LenientOptions::fail_fast`] after the first
    /// failure. Under the default accumulate-all policy it always
    /// returns `false`.
    pub fn process_line(&mut self, line: &[u8]) -> bool {
        self.line_counter += 1;
        let line_num = self.line_counter;
        let line_trim_end = trim_trailing_cr(line);
        if line_trim_end.iter().all(|b| b.is_ascii_whitespace()) {
            return false;
        }

        let entry: WalEntry = match serde_json::from_slice(line_trim_end) {
            Ok(e) => e,
            Err(e) => {
                let err = VerificationError {
                    sequence: None,
                    error_type: "parse_error".to_string(),
                    details: format!("line {line_num}: {e}"),
                };
                return self.push(err);
            }
        };

        if self.result.first_sequence.is_none() {
            self.result.first_sequence = Some(entry.sequence);
            self.result.first_timestamp = Some(entry.timestamp_ns);
        }
        self.result.last_sequence = Some(entry.sequence);
        self.result.last_timestamp = Some(entry.timestamp_ns);

        // Chain-link rule reused from wal_entry::verify_chain_link so
        // a future refactor can't silently fork the lenient path from
        // the canonical contract.
        match verify_chain_link(&entry, self.prev_entry.as_ref()) {
            HashVerification::Valid => {}
            HashVerification::InvalidGenesis { reason } => {
                let err = VerificationError {
                    sequence: Some(entry.sequence),
                    error_type: "invalid_genesis".to_string(),
                    details: reason,
                };
                if self.push(err) {
                    return true;
                }
            }
            HashVerification::Mismatch { expected, actual } => {
                let err = VerificationError {
                    sequence: Some(entry.sequence),
                    error_type: "chain_break".to_string(),
                    details: format!("expected prev_hash {expected}, found {actual}"),
                };
                if self.push(err) {
                    return true;
                }
            }
        }

        if let Some(prev_seq) = self.prev_sequence {
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
                if self.push(err) {
                    return true;
                }
            }
        }

        if let Some(prev_ts) = self.prev_timestamp {
            if entry.timestamp_ns < prev_ts {
                let err = VerificationError {
                    sequence: Some(entry.sequence),
                    error_type: "timestamp_regression".to_string(),
                    details: format!("timestamp {} < previous {prev_ts}", entry.timestamp_ns),
                };
                if self.push(err) {
                    return true;
                }
            }
        }

        // The signature policy gates ONLY the Ed25519 math (the dominant
        // per-record cost). Every other check above and below runs in
        // full regardless, so a reduced policy never weakens the chain's
        // tamper-evidence, only the signature coverage.
        if self.policy.should_check(entry.sequence) {
            match (entry.signature.as_deref(), entry.public_key.as_deref()) {
                (Some(sig_hex), Some(pk_hex)) => {
                    if let Some(ref pin) = self.trusted_pubkey_bytes {
                        match decode_hex_32(pk_hex) {
                            Ok(pk_bytes) if pk_bytes.ct_eq(pin).unwrap_u8() == 1 => {}
                            _ => {
                                let err = VerificationError {
                                    sequence: Some(entry.sequence),
                                    error_type: "untrusted_pubkey".to_string(),
                                    details: "record public_key does not match trusted_pubkey pin"
                                        .to_string(),
                                };
                                if self.push(err) {
                                    return true;
                                }
                                // Skip the signature math: it would either
                                // pass (and look "valid" under a wrong key)
                                // or fail (and surface as InvalidSignature,
                                // a misleading reason). Trusted-pubkey
                                // failures are reason enough on their own.
                                self.advance_chain(entry);
                                return false;
                            }
                        }
                    }
                    match verify_entry_signature(&entry, sig_hex, pk_hex) {
                        Ok(true) => {
                            self.result.signatures_verified += 1;
                            if self.trusted_pubkey_bytes.is_none() {
                                self.signatures_unpinned += 1;
                            }
                        }
                        Ok(false) | Err(()) => {
                            let err = VerificationError {
                                sequence: Some(entry.sequence),
                                error_type: "invalid_signature".to_string(),
                                details: "Ed25519 verification failed".to_string(),
                            };
                            if self.push(err) {
                                return true;
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
                    if self.trusted_pubkey_bytes.is_some() {
                        let err = VerificationError {
                            sequence: Some(entry.sequence),
                            error_type: "unsigned_record".to_string(),
                            details: "record is unsigned but trusted_pubkey requires every record \
                                      to be signed by the pinned key"
                                .to_string(),
                        };
                        if self.push(err) {
                            return true;
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
                    if self.push(err) {
                        return true;
                    }
                }
            }
        } else if entry.signature.is_some() || entry.public_key.is_some() {
            // A reduced policy (chain-only or sampling) skipped this
            // record's signature math. Count it so finish() can be honest
            // about how much coverage was actually achieved.
            self.result.signatures_skipped += 1;
        }

        if let Some(alg) = entry.hash_alg.as_deref() {
            if alg != "blake3" {
                self.result.warnings.push(format!(
                    "sequence {}: hash_alg = {alg:?} but lenient verifier assumes blake3; \
                     payload integrity is unchecked",
                    entry.sequence
                ));
            }
        }

        if entry.receipt.is_some() {
            self.receipts_seen += 1;
        }

        if let Some(ks) = self.opts.keystore {
            match verify_receipt_signature(&entry, ks) {
                Ok(true) => self.result.receipts_verified += 1,
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
                    if self.push(v_err) {
                        return true;
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
            if self.push(err) {
                return true;
            }
        }

        self.advance_chain(entry);
        false
    }

    /// Finish verification and produce the report: compute the final
    /// `chain_root`, run the `expected_root` gate, and append the
    /// summary warnings (policy coverage, unpinned signatures, receipts
    /// without a keystore). Consumes the verifier.
    pub fn finish(mut self) -> VerificationResult {
        self.result.chain_root = hex::encode(self.running_hash.finalize().as_bytes());

        if self.result.events_verified == 0 {
            self.result
                .warnings
                .push("No WAL records found".to_string());
        }

        // Always check expected_root, even when no records were processed.
        // An attacker who empties the segment directory must not be able
        // to claim "valid: true" by virtue of producing zero records that
        // also produce zero failures.
        //
        // A root that normalizes to empty (whitespace-only, or a bare `0x`)
        // is treated as "no anchor supplied", matching the wasm facade so
        // the same operator input is verified identically on the CLI and in
        // the browser.
        let normalized_root = self
            .opts
            .expected_root
            .map(crate::normalize_hex_anchor)
            .filter(|s| !s.is_empty());
        if let Some(normalized) = normalized_root {
            if self.result.chain_root != normalized {
                let computed = self.result.chain_root.clone();
                let err = VerificationError {
                    sequence: None,
                    error_type: "root_mismatch".to_string(),
                    details: format!("expected {normalized}, computed {computed}"),
                };
                // Root mismatch always accumulates (never honors fail_fast):
                // it is the single most important verdict and must surface
                // even on a fail-fast run that already halted earlier.
                self.result.valid = false;
                self.result.errors.push(err);
            }
        } else if self.result.events_verified > 0 {
            self.result.warnings.push(
                "No expected root provided: verified internal consistency only. \
                 For full tamper-detection, compare chain_root against an external anchor."
                    .to_string(),
            );
        }

        // Be explicit about reduced signature coverage so a green run
        // under a reduced policy can never be mistaken for a full
        // signature verification.
        match self.policy {
            SignaturePolicy::All => {}
            SignaturePolicy::None => {
                if self.result.events_verified > 0 {
                    self.result.warnings.push(
                        "Signatures were NOT verified (chain-only policy). Chain linkage, \
                         sequence, timestamps and root were checked; per-record signatures were \
                         not. Provide an authenticated expected_root for tamper-evidence, or run \
                         full verification to check every signature."
                            .to_string(),
                    );
                }
            }
            SignaturePolicy::Sample { one_in } => {
                self.result.warnings.push(format!(
                    "Sampled signature verification (1-in-{one_in}): {} signatures checked, {} \
                     signed records left unchecked. Sampling is a routine spot-check for \
                     accidental corruption, NOT a defense against a targeted forger who can avoid \
                     the sampled positions. Use full verification or cryptographic inclusion \
                     proofs for adversarial completeness.",
                    self.result.signatures_verified, self.result.signatures_skipped
                ));
            }
        }

        if self.opts.trusted_pubkey.is_none() && self.signatures_unpinned > 0 {
            self.result.warnings.push(format!(
                "{} signatures were verified against record-declared pubkeys (no external pin). \
                 Pass --trusted-pubkey on the CLI to require an externally pinned key, \
                 or use the strict verifier (spine_core::verify_demo_wal).",
                self.signatures_unpinned
            ));
        }

        if self.opts.keystore.is_none() && self.receipts_seen > 0 {
            self.result.warnings.push(format!(
                "{} records carry server receipts but no keystore was supplied. \
                 Pass --keystore on the CLI to verify receipt signatures.",
                self.receipts_seen
            ));
        }

        self.result
    }

    /// Push `err` into the result and return `true` when the caller
    /// should stop feeding lines (fail-fast). Always sets
    /// `result.valid = false`.
    fn push(&mut self, err: VerificationError) -> bool {
        self.result.valid = false;
        self.result.errors.push(err);
        if self.opts.fail_fast {
            self.result.halted_early = true;
            true
        } else {
            false
        }
    }

    fn advance_chain(&mut self, entry: WalEntry) {
        let entry_hash = compute_entry_hash(&entry);
        self.running_hash.update(entry_hash.as_bytes());
        self.prev_sequence = Some(entry.sequence);
        self.prev_timestamp = Some(entry.timestamp_ns);
        self.prev_entry = Some(entry);
        self.result.events_verified += 1;
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

    /// Drive the streaming `LenientVerifier` one line at a time, the way
    /// the CLI feeds it from disk.
    fn run_streaming(
        bytes: &[u8],
        opts: &LenientOptions,
        policy: SignaturePolicy,
    ) -> VerificationResult {
        let mut v = LenientVerifier::new(opts, policy);
        for line in bytes.split(|&b| b == b'\n') {
            if v.process_line(line) {
                break;
            }
        }
        v.finish()
    }

    /// Build a correctly-chained, fully-signed WAL. The signature covers
    /// `prev_hash`, so `prev_hash` is set BEFORE signing and the full
    /// entry hash (which folds in the signature) is taken AFTER, to link
    /// the next record. This mirrors the production signing order.
    fn build_signed_chain(n: u64, key: &SigningKey) -> Vec<WalEntry> {
        let pk_hex = hex::encode(key.verifying_key().to_bytes());
        let mut entries = Vec::new();
        let mut prev = GENESIS_PREV_HASH.to_string();
        for i in 1..=n {
            let mut e = make_entry(i, 1000 * i as i64, &prev, &format!("payload{i}"));
            let msg = compute_entry_hash_for_signing(&e);
            e.signature = Some(hex::encode(key.sign(msg.as_bytes()).to_bytes()));
            e.public_key = Some(pk_hex.clone());
            prev = compute_entry_hash(&e);
            entries.push(e);
        }
        entries
    }

    #[test]
    fn streaming_matches_buffered_on_signed_chain() {
        // The streaming verifier and the buffered byte API share one
        // state machine; feeding line by line must yield an identical
        // verdict, root and counters.
        let signing_key = SigningKey::from_bytes(&[0x21; 32]);
        let entries = build_signed_chain(4, &signing_key);
        let bytes = to_jsonl(&entries);

        let buffered = verify_wal_bytes(&bytes);
        let streamed = run_streaming(&bytes, &LenientOptions::default(), SignaturePolicy::All);

        assert_eq!(buffered.valid, streamed.valid);
        assert_eq!(buffered.events_verified, streamed.events_verified);
        assert_eq!(buffered.signatures_verified, streamed.signatures_verified);
        assert_eq!(buffered.signatures_skipped, streamed.signatures_skipped);
        assert_eq!(buffered.chain_root, streamed.chain_root);
        assert_eq!(buffered.errors.len(), streamed.errors.len());
        assert!(streamed.valid, "errors: {:?}", streamed.errors);
        assert_eq!(streamed.signatures_verified, 4);
        assert_eq!(streamed.signatures_skipped, 0);
    }

    #[test]
    fn chain_only_skips_signatures_but_still_checks_the_chain() {
        let signing_key = SigningKey::from_bytes(&[0x22; 32]);
        let entries = build_signed_chain(3, &signing_key);
        let bytes = to_jsonl(&entries);

        let r = run_streaming(&bytes, &LenientOptions::default(), SignaturePolicy::None);
        assert!(
            r.valid,
            "chain-only over a valid chain passes: {:?}",
            r.errors
        );
        assert_eq!(
            r.signatures_verified, 0,
            "chain-only verifies no signatures"
        );
        assert_eq!(r.signatures_skipped, 3, "all 3 signed records were skipped");
        assert!(r
            .warnings
            .iter()
            .any(|w| w.contains("chain-only") || w.contains("NOT verified")));

        // Chain integrity is still enforced: break a link and chain-only
        // must catch it even though signatures are off.
        let mut tampered = entries.clone();
        tampered[1].prev_hash = "f".repeat(64);
        let bytes2 = to_jsonl(&tampered);
        let r2 = run_streaming(&bytes2, &LenientOptions::default(), SignaturePolicy::None);
        assert!(!r2.valid);
        assert!(r2.errors.iter().any(|e| e.error_type == "chain_break"));
    }

    #[test]
    fn sample_signatures_verifies_only_the_sampled_subset() {
        let signing_key = SigningKey::from_bytes(&[0x23; 32]);
        let entries = build_signed_chain(6, &signing_key);
        let bytes = to_jsonl(&entries);

        let r = run_streaming(
            &bytes,
            &LenientOptions::default(),
            SignaturePolicy::Sample { one_in: 3 },
        );
        assert!(r.valid, "errors: {:?}", r.errors);
        // sequences 3 and 6 are multiples of 3.
        assert_eq!(r.signatures_verified, 2);
        assert_eq!(r.signatures_skipped, 4);
        assert!(r.warnings.iter().any(|w| w.contains("1-in-3")));
    }

    #[test]
    fn sample_does_not_check_an_unsampled_tampered_signature() {
        // Tamper the LAST record's signature (no successor, so no chain
        // break). Under full verification it is an invalid_signature;
        // under sampling that skips it, the run stays valid. This is the
        // honest, documented cost of sampling: partial coverage.
        let signing_key = SigningKey::from_bytes(&[0x24; 32]);
        let mut entries = build_signed_chain(3, &signing_key);
        // Corrupt seq 3's signature to a valid-length but wrong value.
        entries[2].signature = Some("0".repeat(128));
        let bytes = to_jsonl(&entries);

        let full = run_streaming(&bytes, &LenientOptions::default(), SignaturePolicy::All);
        assert!(!full.valid, "full verification catches the bad signature");
        assert!(full
            .errors
            .iter()
            .any(|e| e.error_type == "invalid_signature"));

        // one_in = 2 samples seq 2 only; seq 3 is never checked.
        let sampled = run_streaming(
            &bytes,
            &LenientOptions::default(),
            SignaturePolicy::Sample { one_in: 2 },
        );
        assert!(
            sampled.valid,
            "sampling skips seq 3's signature: {:?}",
            sampled.errors
        );
        assert_eq!(sampled.signatures_verified, 1);
    }
}

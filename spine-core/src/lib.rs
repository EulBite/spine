// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite

//! Spine core verification primitives.
//!
//! This crate carries the cryptographic contract that every Spine WAL
//! verifier must agree on: chain-link hashing, signature verification,
//! receipt attestation, and canonical JSON. It exposes two distinct
//! verifier surfaces, and downstream consumers MUST pick the one that
//! matches their threat model:
//!
//! * [`verify::verify_wal_bytes`]: lenient. Tolerates unsigned
//!   records, treats `expected_root` as optional, accumulates errors,
//!   trusts the `public_key` declared in each entry. Use for offline
//!   auditing of production WAL files where some records pre-date the
//!   signing rollout.
//! * [`verify_demo::verify_demo_wal`]: strict. Refuses unsigned
//!   records, pins the `expected_pubkey` from outside, requires
//!   `expected_root` non-optional, recomputes `payload_hash` from the
//!   canonical JSON of `payload`, prepends a domain-separation tag
//!   to the signed message, compares hashes in constant time. Use for
//!   the public WASM playground where a single false positive ends
//!   the demo's credibility.
//!
//! ## No-panic policy
//!
//! Both `unwrap_used` and `expect_used` are denied at the crate root.
//! Test modules opt out per-block; production paths never panic. This
//! is load-bearing for the WASM build, where a panic surfaces as a
//! `RuntimeError` in the host page with no recovery path.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![forbid(unsafe_code)]

pub mod canonical;
pub mod receipt;
pub mod verify;
pub mod verify_demo;
pub mod wal_entry;

pub use canonical::{canonical_json, canonical_json_from_bytes, CanonicalError};
pub use receipt::{
    receipt_canonical_message, verify_receipt_against_keystore, verify_receipt_signature, Keystore,
    Receipt, ReceiptError, RECEIPT_DOMAIN_SEP,
};
pub use verify::{
    verify_wal_bytes, verify_wal_bytes_with_options, LenientOptions, LenientVerifier,
    SignaturePolicy, VerificationError, VerificationResult,
};
pub use verify_demo::{
    verify_demo_wal, DemoRecordEntry, DemoRecordOutcome, DemoReport, DemoStatus, InvalidReason,
    RejectedReason, MAX_LINE_BYTES, MAX_PAYLOAD_BYTES, MAX_RECORDS_DEMO, STRICT_DOMAIN_SEP,
};
pub use wal_entry::{
    compute_chain_root, compute_chain_root_from_entries, compute_entry_hash,
    compute_entry_hash_for_signing, compute_entry_hash_for_signing_raw, compute_entry_hash_raw,
    validate_entry_hashes, validate_hex_hash, verify_chain_link, HashVerification, HexValidation,
    WalEntry, GENESIS_PREV_HASH, WAL_FORMAT_VERSION,
};

/// Crate version, surfaced in [`DemoReport::verifier_version`] so a
/// strict-verifier consumer can pin the exact binary it expects.
pub const VERIFIER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Normalize a caller-supplied hex anchor (expected chain root or pinned
/// public key): trim surrounding whitespace, strip an optional `0x`/`0X`
/// prefix (case-insensitively), and lowercase.
///
/// This is the single normalization both verifier profiles apply to every
/// externally-supplied hex anchor, so the CLI, the wasm facade, and a direct
/// `spine-core` caller all accept exactly the same set of inputs. Without it
/// the surfaces diverged: the CLI stripped `0X` and trimmed the pinned pubkey
/// while the core/wasm path did not, so the same anchor string verified on
/// one surface and errored on another.
pub(crate) fn normalize_hex_anchor(s: &str) -> String {
    let t = s.trim();
    t.strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t)
        .to_lowercase()
}

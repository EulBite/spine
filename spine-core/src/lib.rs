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

pub mod audit_pack;
pub mod canonical;
pub mod checkpoint;
pub mod checkpoint_v2;
pub mod receipt;
pub mod verify;
pub mod verify_demo;
pub mod wal_entry;

pub use audit_pack::{
    audit_pack_id, audit_pack_message, verify_audit_pack, AuditPackCoreV1, AuditPackError,
    AuditPackIntervalV1, AuditPackPolicy, AuditPackReport, AuditPackSignatureV1, AuditPackV1,
    AUDIT_PACK_DOMAIN_V1, AUDIT_PACK_ID_DOMAIN_V1, AUDIT_PACK_SCHEMA_V1,
};
pub use canonical::{canonical_json, canonical_json_from_bytes, parse_json_strict, CanonicalError};
pub use checkpoint::{
    public_checkpoint_message, verify_public_checkpoint, CheckpointError, PublicCheckpoint,
    CHECKPOINT_DOMAIN_SEP, CHECKPOINT_SCHEMA,
};
pub use checkpoint_v2::{
    checkpoint_core_message, checkpoint_id, key_transition_message, operator_key_id, tenant_ref,
    verify_checkpoint, verify_checkpoint_history, verify_checkpoint_receipt,
    verify_operator_key_transition, witness_receipt_message, CheckpointCoreV2,
    CheckpointHistoryReport, CheckpointReceiptV2, CheckpointTrustPolicy, CheckpointV2Error,
    OperatorKeyTransitionV1, OperatorSignatureV2, TenantIntervalCommitment, TrustedWitness,
    WitnessReceiptV1, CHECKPOINT_CORE_DOMAIN_V2, CHECKPOINT_ID_DOMAIN_V2,
    CHECKPOINT_RECEIPT_SCHEMA_V2, KEY_TRANSITION_DOMAIN_V1, KEY_TRANSITION_SCHEMA_V1,
    OPERATOR_KEY_ID_DOMAIN_V1, TENANT_REF_DOMAIN_V1, WITNESS_RECEIPT_DOMAIN_V1,
    WITNESS_RECEIPT_SCHEMA_V1,
};
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
    compute_payload_hash_for_version, is_supported_format_version, validate_entry_hashes,
    validate_hex_hash, verify_chain_link, HashVerification, HexValidation, PayloadHashError,
    WalEntry, GENESIS_PREV_HASH, SUPPORTED_WAL_FORMAT_VERSIONS, WAL_FORMAT_VERSION,
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

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite

//! Verification of checkpoints emitted by the private Spine server.
//!
//! A checkpoint authenticates the chain root used by the lenient and
//! chain-only WAL verifier profiles. Its embedded key is deliberately not
//! trusted: callers must pin the expected checkpoint key out of band.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// Domain separator prepended to every signed checkpoint envelope.
pub const CHECKPOINT_DOMAIN_SEP: &[u8] = b"spine-public-checkpoint-v1\x00";

/// Only checkpoint schema currently accepted by the verifier.
pub const CHECKPOINT_SCHEMA: &str = "spine-public-checkpoint-v1";

/// Signed chain-root checkpoint returned by `GET /api/v1/checkpoint/public`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicCheckpoint {
    pub schema: String,
    pub chain_root: String,
    pub event_count: u64,
    pub last_sequence: u64,
    pub timestamp_ns: i64,
    pub signature: String,
    pub public_key: String,
    pub algorithm: String,
}

/// A checkpoint was malformed, untrusted, stale, or cryptographically invalid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointError {
    #[error("unsupported checkpoint schema {found:?}; expected {CHECKPOINT_SCHEMA:?}")]
    UnsupportedSchema { found: String },

    #[error("unsupported checkpoint signature algorithm {found:?}; expected \"ed25519\"")]
    UnsupportedAlgorithm { found: String },

    #[error("chain_root must be exactly 64 lowercase hex characters")]
    InvalidChainRoot,

    #[error("checkpoint public_key must be exactly 64 lowercase hex characters")]
    InvalidEmbeddedPublicKey,

    #[error("trusted checkpoint public key must be a 32-byte Ed25519 key in hex")]
    InvalidTrustedPublicKey,

    #[error("checkpoint public key does not match the externally pinned key")]
    PublicKeyMismatch,

    #[error("checkpoint signature must be exactly 128 lowercase hex characters")]
    InvalidSignature,

    #[error("checkpoint public key is not a valid Ed25519 verifying key")]
    InvalidEd25519PublicKey,

    #[error("checkpoint signature verification failed")]
    SignatureVerificationFailed,

    #[error("checkpoint timestamp {timestamp_ns} is in the future relative to {now_ns}")]
    FutureCheckpoint { timestamp_ns: i64, now_ns: i64 },

    #[error("checkpoint age exceeds the configured maximum of {max_age_secs} seconds")]
    StaleCheckpoint { max_age_secs: u64 },
}

fn push_len_prefixed(message: &mut Vec<u8>, field: &str) {
    message.extend_from_slice(&(field.len() as u64).to_le_bytes());
    message.extend_from_slice(field.as_bytes());
}

/// Build the exact byte sequence signed by the private Spine server.
///
/// All envelope fields except `signature` and `public_key` are covered. The
/// fixed domain separator prevents a valid signature from being replayed as a
/// different Spine message type.
#[must_use]
pub fn public_checkpoint_message(checkpoint: &PublicCheckpoint) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        CHECKPOINT_DOMAIN_SEP.len()
            + checkpoint.schema.len()
            + checkpoint.chain_root.len()
            + checkpoint.algorithm.len()
            + 48,
    );
    message.extend_from_slice(CHECKPOINT_DOMAIN_SEP);
    push_len_prefixed(&mut message, &checkpoint.schema);
    push_len_prefixed(&mut message, &checkpoint.chain_root);
    message.extend_from_slice(&checkpoint.event_count.to_le_bytes());
    message.extend_from_slice(&checkpoint.last_sequence.to_le_bytes());
    message.extend_from_slice(&checkpoint.timestamp_ns.to_le_bytes());
    push_len_prefixed(&mut message, &checkpoint.algorithm);
    message
}

fn is_canonical_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_32(value: &str) -> Result<[u8; 32], ()> {
    let bytes = hex::decode(value).map_err(|_| ())?;
    bytes.try_into().map_err(|_| ())
}

fn decode_64(value: &str) -> Result<[u8; 64], ()> {
    let bytes = hex::decode(value).map_err(|_| ())?;
    bytes.try_into().map_err(|_| ())
}

/// Verify a server checkpoint against an externally pinned Ed25519 key.
///
/// `trusted_pubkey` may contain surrounding whitespace or an optional `0x`
/// prefix. The checkpoint's own key remains canonical lowercase hex and must
/// match that pin in constant time. When `max_age_secs` is set, checkpoints in
/// the future or older than that limit are rejected relative to `now_ns`.
pub fn verify_public_checkpoint(
    checkpoint: &PublicCheckpoint,
    trusted_pubkey: &str,
    now_ns: i64,
    max_age_secs: Option<u64>,
) -> Result<(), CheckpointError> {
    if checkpoint.schema != CHECKPOINT_SCHEMA {
        return Err(CheckpointError::UnsupportedSchema {
            found: checkpoint.schema.clone(),
        });
    }
    if checkpoint.algorithm != "ed25519" {
        return Err(CheckpointError::UnsupportedAlgorithm {
            found: checkpoint.algorithm.clone(),
        });
    }
    if !is_canonical_hex(&checkpoint.chain_root, 64) {
        return Err(CheckpointError::InvalidChainRoot);
    }
    if !is_canonical_hex(&checkpoint.public_key, 64) {
        return Err(CheckpointError::InvalidEmbeddedPublicKey);
    }
    if !is_canonical_hex(&checkpoint.signature, 128) {
        return Err(CheckpointError::InvalidSignature);
    }

    let embedded_key = decode_32(&checkpoint.public_key)
        .map_err(|()| CheckpointError::InvalidEmbeddedPublicKey)?;
    let normalized_pin = crate::normalize_hex_anchor(trusted_pubkey);
    let trusted_key =
        decode_32(&normalized_pin).map_err(|()| CheckpointError::InvalidTrustedPublicKey)?;
    if embedded_key.ct_eq(&trusted_key).unwrap_u8() != 1 {
        return Err(CheckpointError::PublicKeyMismatch);
    }

    let verifying_key = VerifyingKey::from_bytes(&trusted_key)
        .map_err(|_| CheckpointError::InvalidEd25519PublicKey)?;
    let signature_bytes =
        decode_64(&checkpoint.signature).map_err(|()| CheckpointError::InvalidSignature)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(&public_checkpoint_message(checkpoint), &signature)
        .map_err(|_| CheckpointError::SignatureVerificationFailed)?;

    if let Some(max_age_secs) = max_age_secs {
        if checkpoint.timestamp_ns > now_ns {
            return Err(CheckpointError::FutureCheckpoint {
                timestamp_ns: checkpoint.timestamp_ns,
                now_ns,
            });
        }
        let age_ns = i128::from(now_ns) - i128::from(checkpoint.timestamp_ns);
        let max_age_ns = i128::from(max_age_secs) * 1_000_000_000_i128;
        if age_ns > max_age_ns {
            return Err(CheckpointError::StaleCheckpoint { max_age_secs });
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    const NOW_NS: i64 = 1_780_000_000_000_000_000;

    fn signed_checkpoint_at(seed: u8, timestamp_ns: i64) -> (PublicCheckpoint, String) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());
        let mut checkpoint = PublicCheckpoint {
            schema: CHECKPOINT_SCHEMA.to_string(),
            chain_root: "ab".repeat(32),
            event_count: 42,
            last_sequence: 42,
            timestamp_ns,
            signature: String::new(),
            public_key: public_key.clone(),
            algorithm: "ed25519".to_string(),
        };
        checkpoint.signature = hex::encode(
            signing_key
                .sign(&public_checkpoint_message(&checkpoint))
                .to_bytes(),
        );
        (checkpoint, public_key)
    }

    fn signed_checkpoint(seed: u8) -> (PublicCheckpoint, String) {
        signed_checkpoint_at(seed, NOW_NS - 5_000_000_000)
    }

    #[test]
    fn verifies_with_an_external_key_pin_and_freshness_limit() {
        let (checkpoint, pin) = signed_checkpoint(0x21);
        verify_public_checkpoint(&checkpoint, &format!("  0x{pin}  "), NOW_NS, Some(10)).unwrap();
    }

    #[test]
    fn rejects_every_tampered_signed_envelope_field() {
        let (checkpoint, pin) = signed_checkpoint(0x22);
        type CheckpointMutation = Box<dyn Fn(&mut PublicCheckpoint)>;
        let mutations: Vec<CheckpointMutation> = vec![
            Box::new(|value| value.schema.push('x')),
            Box::new(|value| value.chain_root.replace_range(0..2, "cd")),
            Box::new(|value| value.event_count += 1),
            Box::new(|value| value.last_sequence += 1),
            Box::new(|value| value.timestamp_ns += 1),
            Box::new(|value| value.algorithm.push('x')),
        ];

        for mutate in mutations {
            let mut tampered = checkpoint.clone();
            mutate(&mut tampered);
            assert!(verify_public_checkpoint(&tampered, &pin, NOW_NS, None).is_err());
        }
    }

    #[test]
    fn rejects_a_self_declared_replacement_key() {
        let (checkpoint, _) = signed_checkpoint(0x23);
        let (_, different_pin) = signed_checkpoint(0x24);
        assert_eq!(
            verify_public_checkpoint(&checkpoint, &different_pin, NOW_NS, None),
            Err(CheckpointError::PublicKeyMismatch)
        );
    }

    #[test]
    fn rejects_stale_and_future_checkpoints_when_freshness_is_requested() {
        let (checkpoint, pin) = signed_checkpoint(0x25);
        assert_eq!(
            verify_public_checkpoint(&checkpoint, &pin, NOW_NS, Some(4)),
            Err(CheckpointError::StaleCheckpoint { max_age_secs: 4 })
        );

        let (future, future_pin) = signed_checkpoint_at(0x26, NOW_NS + 1);
        assert!(matches!(
            verify_public_checkpoint(&future, &future_pin, NOW_NS, Some(60)),
            Err(CheckpointError::FutureCheckpoint { .. })
        ));
    }

    #[test]
    fn rejects_noncanonical_or_malformed_envelope_values() {
        let (checkpoint, pin) = signed_checkpoint(0x27);

        let mut uppercase_root = checkpoint.clone();
        uppercase_root.chain_root = uppercase_root.chain_root.to_uppercase();
        assert_eq!(
            verify_public_checkpoint(&uppercase_root, &pin, NOW_NS, None),
            Err(CheckpointError::InvalidChainRoot)
        );

        let mut malformed_signature = checkpoint.clone();
        malformed_signature.signature.pop();
        assert_eq!(
            verify_public_checkpoint(&malformed_signature, &pin, NOW_NS, None),
            Err(CheckpointError::InvalidSignature)
        );

        assert_eq!(
            verify_public_checkpoint(&checkpoint, "not-a-key", NOW_NS, None),
            Err(CheckpointError::InvalidTrustedPublicKey)
        );
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite

//! Pure verification for Spine checkpoint receipts, external witnesses and
//! cross-signed operator-key rotation. This module performs no I/O and never
//! signs: callers must provide trust anchors through [`CheckpointTrustPolicy`].

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

pub const CHECKPOINT_RECEIPT_SCHEMA_V2: &str = "spine-checkpoint-receipt-v2";
pub const CHECKPOINT_CORE_DOMAIN_V2: &[u8] = b"spine:checkpoint-core:v2\x00";
pub const CHECKPOINT_ID_DOMAIN_V2: &[u8] = b"spine:checkpoint-id:v2\x00";
pub const WITNESS_RECEIPT_SCHEMA_V1: &str = "spine-witness-receipt-v1";
pub const WITNESS_RECEIPT_DOMAIN_V1: &[u8] = b"spine:witness-receipt:v1\x00";
pub const KEY_TRANSITION_SCHEMA_V1: &str = "spine-operator-key-transition-v1";
pub const KEY_TRANSITION_DOMAIN_V1: &[u8] = b"spine:operator-key-transition:v1\x00";
pub const TENANT_REF_DOMAIN_V1: &[u8] = b"spine:tenant-ref:v1\x00";
pub const OPERATOR_KEY_ID_DOMAIN_V1: &[u8] = b"spine:operator-key-id:v1\x00";

pub const MAX_CHECKPOINTS: usize = 100_000;
pub const MAX_TENANT_COMMITMENTS: usize = 100_000;
pub const MAX_WITNESSES_PER_CHECKPOINT: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TenantIntervalCommitment {
    pub tenant_ref: String,
    pub event_count: u64,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub events_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorKeyTransitionV1 {
    pub schema: String,
    pub previous_key_id: String,
    pub previous_public_key: String,
    pub new_key_id: String,
    pub new_public_key: String,
    pub rotated_at_ns: i64,
    pub reason: String,
    pub previous_key_signature: String,
    pub new_key_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointCoreV2 {
    pub schema: String,
    pub chain_id: String,
    pub chain_root: String,
    pub total_event_count: u64,
    pub last_sequence: u64,
    pub interval_start_sequence: Option<u64>,
    pub interval_end_sequence: Option<u64>,
    pub created_at_ns: i64,
    pub previous_checkpoint_id: Option<String>,
    pub operator_key_id: String,
    pub operator_algorithm: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_transition: Option<OperatorKeyTransitionV1>,
    pub tenant_commitments: Vec<TenantIntervalCommitment>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorSignatureV2 {
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WitnessReceiptV1 {
    pub schema: String,
    pub witness_id: String,
    pub checkpoint_id: String,
    pub observed_at_ns: i64,
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointReceiptV2 {
    pub core: CheckpointCoreV2,
    pub checkpoint_id: String,
    pub operator_signature: OperatorSignatureV2,
    #[serde(default)]
    pub witnesses: Vec<WitnessReceiptV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustedWitness {
    pub witness_id: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointTrustPolicy {
    pub initial_operator_public_key: String,
    pub trusted_witness: Option<TrustedWitness>,
    pub allow_unwitnessed: bool,
    pub expected_chain_id: Option<String>,
    pub now_ns: Option<i64>,
    pub max_age_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointHistoryReport {
    pub checkpoint_count: usize,
    pub latest_checkpoint_id: String,
    pub chain_id: String,
    pub chain_root: String,
    pub last_sequence: u64,
    pub established_operator_public_key: String,
    pub established_operator_key_id: String,
    pub trusted_witness_observations: usize,
    pub latest_trusted_time_ns: i64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CheckpointV2Error {
    #[error("invalid checkpoint receipt: {0}")]
    Invalid(String),
    #[error("checkpoint signature verification failed: {0}")]
    Signature(String),
    #[error("checkpoint trust policy not satisfied: {0}")]
    Trust(String),
    #[error("checkpoint freshness policy not satisfied: {0}")]
    Freshness(String),
}

/// Signed message for a checkpoint core. The exact byte layout is public API.
#[must_use]
pub fn checkpoint_core_message(core: &CheckpointCoreV2) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(CHECKPOINT_CORE_DOMAIN_V2);
    push_string(&mut message, &core.schema);
    push_string(&mut message, &core.chain_id);
    push_string(&mut message, &core.chain_root);
    message.extend_from_slice(&core.total_event_count.to_le_bytes());
    message.extend_from_slice(&core.last_sequence.to_le_bytes());
    push_optional_u64(&mut message, core.interval_start_sequence);
    push_optional_u64(&mut message, core.interval_end_sequence);
    message.extend_from_slice(&core.created_at_ns.to_le_bytes());
    push_optional_string(&mut message, core.previous_checkpoint_id.as_deref());
    push_string(&mut message, &core.operator_key_id);
    push_string(&mut message, &core.operator_algorithm);
    match &core.key_transition {
        Some(transition) => {
            message.push(1);
            push_key_transition(&mut message, transition);
        }
        None => message.push(0),
    }
    message.extend_from_slice(&(core.tenant_commitments.len() as u64).to_le_bytes());
    for commitment in &core.tenant_commitments {
        push_string(&mut message, &commitment.tenant_ref);
        message.extend_from_slice(&commitment.event_count.to_le_bytes());
        message.extend_from_slice(&commitment.first_sequence.to_le_bytes());
        message.extend_from_slice(&commitment.last_sequence.to_le_bytes());
        push_string(&mut message, &commitment.events_root);
    }
    message
}

#[must_use]
pub fn key_transition_message(transition: &OperatorKeyTransitionV1) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(KEY_TRANSITION_DOMAIN_V1);
    push_string(&mut message, &transition.schema);
    push_string(&mut message, &transition.previous_key_id);
    push_string(&mut message, &transition.previous_public_key);
    push_string(&mut message, &transition.new_key_id);
    push_string(&mut message, &transition.new_public_key);
    message.extend_from_slice(&transition.rotated_at_ns.to_le_bytes());
    push_string(&mut message, &transition.reason);
    message
}

#[must_use]
pub fn witness_receipt_message(receipt: &WitnessReceiptV1) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(WITNESS_RECEIPT_DOMAIN_V1);
    push_string(&mut message, &receipt.witness_id);
    push_string(&mut message, &receipt.checkpoint_id);
    message.extend_from_slice(&receipt.observed_at_ns.to_le_bytes());
    push_string(&mut message, &receipt.algorithm);
    message
}

#[must_use]
pub fn checkpoint_id(message: &[u8], signature: &OperatorSignatureV2) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CHECKPOINT_ID_DOMAIN_V2);
    hasher.update(message);
    push_hash_string(&mut hasher, &signature.public_key);
    push_hash_string(&mut hasher, &signature.signature);
    hex::encode(hasher.finalize().as_bytes())
}

pub fn operator_key_id(public_key_hex: &str) -> Result<String, CheckpointV2Error> {
    let public_key = decode_canonical_32("operator public_key", public_key_hex)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(OPERATOR_KEY_ID_DOMAIN_V1);
    hasher.update(&public_key);
    Ok(format!(
        "ed25519:{}",
        hex::encode(&hasher.finalize().as_bytes()[..16])
    ))
}

#[must_use]
pub fn tenant_ref(tenant_id: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TENANT_REF_DOMAIN_V1);
    hasher.update(&(tenant_id.len() as u64).to_le_bytes());
    hasher.update(tenant_id.as_bytes());
    hex::encode(hasher.finalize().as_bytes())
}

/// Verify the cryptographic self-consistency of one receipt.
///
/// This does not establish trust in the embedded operator or witness keys.
pub fn verify_checkpoint_receipt(receipt: &CheckpointReceiptV2) -> Result<(), CheckpointV2Error> {
    validate_core(&receipt.core)?;
    decode_canonical_32(
        "operator public_key",
        &receipt.operator_signature.public_key,
    )?;
    decode_canonical_64("operator signature", &receipt.operator_signature.signature)?;
    decode_canonical_32("checkpoint_id", &receipt.checkpoint_id)?;

    let expected_key_id = operator_key_id(&receipt.operator_signature.public_key)?;
    if receipt.core.operator_key_id != expected_key_id {
        return Err(invalid("operator_key_id does not match the signing key"));
    }

    let message = checkpoint_core_message(&receipt.core);
    if receipt.checkpoint_id != checkpoint_id(&message, &receipt.operator_signature) {
        return Err(invalid(
            "checkpoint_id does not match the signed checkpoint",
        ));
    }
    verify_signature(
        &receipt.operator_signature.public_key,
        &receipt.operator_signature.signature,
        &message,
        "operator",
    )?;

    if let Some(transition) = &receipt.core.key_transition {
        verify_operator_key_transition(transition)?;
        if transition.new_key_id != receipt.core.operator_key_id
            || transition.new_public_key != receipt.operator_signature.public_key
            || transition.rotated_at_ns > receipt.core.created_at_ns
        {
            return Err(invalid(
                "key transition does not lead to the checkpoint signing key",
            ));
        }
    }

    if receipt.witnesses.len() > MAX_WITNESSES_PER_CHECKPOINT {
        return Err(invalid("checkpoint contains too many witness receipts"));
    }
    let mut witness_ids = BTreeSet::new();
    for witness in &receipt.witnesses {
        if !witness_ids.insert(witness.witness_id.as_str()) {
            return Err(invalid("checkpoint contains a duplicate witness_id"));
        }
        verify_witness_receipt_embedded(receipt, witness)?;
        if witness.observed_at_ns < receipt.core.created_at_ns {
            return Err(invalid("witness observation predates checkpoint creation"));
        }
    }
    Ok(())
}

pub fn verify_operator_key_transition(
    transition: &OperatorKeyTransitionV1,
) -> Result<(), CheckpointV2Error> {
    if transition.schema != KEY_TRANSITION_SCHEMA_V1 {
        return Err(invalid("unsupported operator key transition schema"));
    }
    validate_identifier("rotation reason", &transition.reason)?;
    decode_canonical_32(
        "previous transition public key",
        &transition.previous_public_key,
    )?;
    decode_canonical_32("new transition public key", &transition.new_public_key)?;
    decode_canonical_64(
        "previous transition signature",
        &transition.previous_key_signature,
    )?;
    decode_canonical_64("new transition signature", &transition.new_key_signature)?;
    if transition.previous_key_id != operator_key_id(&transition.previous_public_key)?
        || transition.new_key_id != operator_key_id(&transition.new_public_key)?
        || transition.previous_key_id == transition.new_key_id
    {
        return Err(invalid(
            "operator key transition ids do not match distinct public keys",
        ));
    }
    let message = key_transition_message(transition);
    verify_signature(
        &transition.previous_public_key,
        &transition.previous_key_signature,
        &message,
        "previous transition key",
    )?;
    verify_signature(
        &transition.new_public_key,
        &transition.new_key_signature,
        &message,
        "new transition key",
    )
}

pub fn verify_checkpoint(
    receipt: &CheckpointReceiptV2,
    policy: &CheckpointTrustPolicy,
) -> Result<CheckpointHistoryReport, CheckpointV2Error> {
    verify_checkpoint_receipt(receipt)?;
    validate_policy(policy)?;
    let trusted_operator = decode_anchor_32(
        "initial operator public key",
        &policy.initial_operator_public_key,
    )?;
    let embedded = decode_canonical_32(
        "operator public_key",
        &receipt.operator_signature.public_key,
    )?;
    if !bool::from(trusted_operator.ct_eq(&embedded)) {
        return Err(trust("operator public key does not match the external pin"));
    }
    verify_expected_chain(&receipt.core.chain_id, policy)?;
    let (observations, trusted_time) = verify_witness_policy(
        std::slice::from_ref(receipt),
        policy,
        receipt.core.created_at_ns,
    )?;
    Ok(report_for(
        std::slice::from_ref(receipt),
        &receipt.operator_signature.public_key,
        observations,
        trusted_time,
    ))
}

pub fn verify_checkpoint_history(
    receipts: &[CheckpointReceiptV2],
    policy: &CheckpointTrustPolicy,
) -> Result<CheckpointHistoryReport, CheckpointV2Error> {
    if receipts.is_empty() {
        return Err(invalid("checkpoint history is empty"));
    }
    if receipts.len() > MAX_CHECKPOINTS {
        return Err(invalid("checkpoint history exceeds the verification limit"));
    }
    validate_policy(policy)?;
    for receipt in receipts {
        verify_checkpoint_receipt(receipt)?;
    }

    let first = &receipts[0];
    if first.core.previous_checkpoint_id.is_some() || first.core.key_transition.is_some() {
        return Err(invalid(
            "checkpoint history must begin at genesis without a key transition",
        ));
    }
    verify_expected_chain(&first.core.chain_id, policy)?;
    let mut trusted_key = decode_anchor_32(
        "initial operator public key",
        &policy.initial_operator_public_key,
    )?;
    let first_key =
        decode_canonical_32("operator public_key", &first.operator_signature.public_key)?;
    if !bool::from(trusted_key.ct_eq(&first_key)) {
        return Err(trust(
            "genesis operator public key does not match the external pin",
        ));
    }
    validate_history_interval(first, 0)?;

    for pair in receipts.windows(2) {
        let previous = &pair[0];
        let current = &pair[1];
        if current.core.previous_checkpoint_id.as_deref() != Some(previous.checkpoint_id.as_str()) {
            return Err(invalid("checkpoint history link is broken"));
        }
        if current.core.chain_id != previous.core.chain_id {
            return Err(invalid("chain_id changed inside checkpoint history"));
        }
        if current.core.created_at_ns <= previous.core.created_at_ns {
            return Err(invalid("checkpoint timestamps are not strictly increasing"));
        }
        if current.core.last_sequence < previous.core.last_sequence {
            return Err(invalid("checkpoint history rolled back last_sequence"));
        }
        validate_history_interval(current, previous.core.last_sequence)?;

        let current_key = decode_canonical_32(
            "operator public_key",
            &current.operator_signature.public_key,
        )?;
        if bool::from(trusted_key.ct_eq(&current_key)) {
            if current.core.key_transition.is_some() {
                return Err(invalid("same-key checkpoint contains a key transition"));
            }
        } else {
            let transition =
                current.core.key_transition.as_ref().ok_or_else(|| {
                    trust("operator key changed without a cross-signed transition")
                })?;
            let previous_key = decode_canonical_32(
                "transition previous public key",
                &transition.previous_public_key,
            )?;
            if !bool::from(trusted_key.ct_eq(&previous_key))
                || transition.previous_key_id != previous.core.operator_key_id
                || transition.new_key_id != current.core.operator_key_id
                || transition.new_public_key != current.operator_signature.public_key
            {
                return Err(trust(
                    "operator key transition does not connect adjacent checkpoints",
                ));
            }
            trusted_key = current_key;
        }
    }

    let latest = receipts
        .last()
        .ok_or_else(|| invalid("checkpoint history is empty"))?;
    let (observations, trusted_time) =
        verify_witness_policy(receipts, policy, latest.core.created_at_ns)?;
    Ok(report_for(
        receipts,
        &latest.operator_signature.public_key,
        observations,
        trusted_time,
    ))
}

fn report_for(
    receipts: &[CheckpointReceiptV2],
    operator_public_key: &str,
    observations: usize,
    trusted_time: i64,
) -> CheckpointHistoryReport {
    let latest = &receipts[receipts.len() - 1];
    CheckpointHistoryReport {
        checkpoint_count: receipts.len(),
        latest_checkpoint_id: latest.checkpoint_id.clone(),
        chain_id: latest.core.chain_id.clone(),
        chain_root: latest.core.chain_root.clone(),
        last_sequence: latest.core.last_sequence,
        established_operator_public_key: operator_public_key.to_string(),
        established_operator_key_id: latest.core.operator_key_id.clone(),
        trusted_witness_observations: observations,
        latest_trusted_time_ns: trusted_time,
    }
}

fn verify_witness_policy(
    receipts: &[CheckpointReceiptV2],
    policy: &CheckpointTrustPolicy,
    fallback_time_ns: i64,
) -> Result<(usize, i64), CheckpointV2Error> {
    let mut observations = 0usize;
    let mut last_observed = None;
    if let Some(trusted) = &policy.trusted_witness {
        validate_identifier("trusted witness_id", &trusted.witness_id)?;
        let trusted_key = decode_anchor_32("trusted witness public key", &trusted.public_key)?;
        for receipt in receipts {
            let witness = receipt
                .witnesses
                .iter()
                .find(|candidate| candidate.witness_id == trusted.witness_id)
                .ok_or_else(|| {
                    trust(format!(
                        "checkpoint {} has no receipt from required witness {}",
                        receipt.checkpoint_id, trusted.witness_id
                    ))
                })?;
            let embedded = decode_canonical_32("witness public_key", &witness.public_key)?;
            if !bool::from(trusted_key.ct_eq(&embedded)) {
                return Err(trust("witness public key does not match the external pin"));
            }
            if last_observed.is_some_and(|previous| witness.observed_at_ns < previous) {
                return Err(freshness("trusted witness observation time regressed"));
            }
            if policy
                .now_ns
                .is_some_and(|now| witness.observed_at_ns > now)
            {
                return Err(freshness("trusted witness observation is in the future"));
            }
            last_observed = Some(witness.observed_at_ns);
            observations += 1;
        }
    } else if !policy.allow_unwitnessed {
        return Err(trust(
            "a pinned witness is required unless unwitnessed verification is explicitly allowed",
        ));
    }

    if policy.now_ns.is_some_and(|now| {
        receipts
            .iter()
            .any(|receipt| receipt.core.created_at_ns > now)
    }) {
        return Err(freshness("operator checkpoint timestamp is in the future"));
    }
    let trusted_time = last_observed.unwrap_or(fallback_time_ns);
    if let Some(max_age_secs) = policy.max_age_secs {
        let now = policy
            .now_ns
            .ok_or_else(|| freshness("max_age_secs requires now_ns"))?;
        let age_ns = i128::from(now) - i128::from(trusted_time);
        if age_ns < 0 {
            return Err(freshness("trusted checkpoint time is in the future"));
        }
        if age_ns > i128::from(max_age_secs) * 1_000_000_000 {
            return Err(freshness(format!(
                "trusted checkpoint age exceeds {max_age_secs} seconds"
            )));
        }
    }
    Ok((observations, trusted_time))
}

fn verify_witness_receipt_embedded(
    checkpoint: &CheckpointReceiptV2,
    witness: &WitnessReceiptV1,
) -> Result<(), CheckpointV2Error> {
    if witness.schema != WITNESS_RECEIPT_SCHEMA_V1 || witness.algorithm != "ed25519" {
        return Err(invalid("unsupported witness schema or algorithm"));
    }
    validate_identifier("witness_id", &witness.witness_id)?;
    if witness.checkpoint_id != checkpoint.checkpoint_id {
        return Err(invalid("witness receipt references another checkpoint"));
    }
    decode_canonical_32("witness public_key", &witness.public_key)?;
    decode_canonical_64("witness signature", &witness.signature)?;
    verify_signature(
        &witness.public_key,
        &witness.signature,
        &witness_receipt_message(witness),
        "witness",
    )
}

fn validate_core(core: &CheckpointCoreV2) -> Result<(), CheckpointV2Error> {
    if core.schema != CHECKPOINT_RECEIPT_SCHEMA_V2 || core.operator_algorithm != "ed25519" {
        return Err(invalid(
            "unsupported checkpoint schema or operator algorithm",
        ));
    }
    validate_identifier("chain_id", &core.chain_id)?;
    validate_identifier("operator_key_id", &core.operator_key_id)?;
    decode_canonical_32("chain_root", &core.chain_root)?;
    if core.created_at_ns < 0 {
        return Err(invalid("created_at_ns cannot be negative"));
    }
    if core.total_event_count != core.last_sequence {
        return Err(invalid(
            "total_event_count must equal last_sequence for a contiguous WAL",
        ));
    }
    if let Some(previous) = &core.previous_checkpoint_id {
        decode_canonical_32("previous_checkpoint_id", previous)?;
    }
    if core.tenant_commitments.len() > MAX_TENANT_COMMITMENTS {
        return Err(invalid("checkpoint contains too many tenant commitments"));
    }

    let interval_len = match (core.interval_start_sequence, core.interval_end_sequence) {
        (None, None) => 0,
        (Some(start), Some(end)) if start > 0 && end >= start && end == core.last_sequence => end
            .checked_sub(start)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| invalid("checkpoint interval length overflow"))?,
        _ => return Err(invalid("invalid checkpoint interval boundaries")),
    };
    let mut committed = 0u64;
    let mut previous_ref: Option<&str> = None;
    for commitment in &core.tenant_commitments {
        decode_canonical_32("tenant_ref", &commitment.tenant_ref)?;
        decode_canonical_32("tenant events_root", &commitment.events_root)?;
        if commitment.event_count == 0
            || commitment.first_sequence == 0
            || commitment.last_sequence < commitment.first_sequence
            || commitment.event_count > commitment.last_sequence - commitment.first_sequence + 1
            || match core.interval_start_sequence {
                Some(start) => {
                    commitment.first_sequence < start
                        || commitment.last_sequence > core.last_sequence
                }
                None => true,
            }
        {
            return Err(invalid("tenant commitment has an invalid range or count"));
        }
        if previous_ref.is_some_and(|previous| previous >= commitment.tenant_ref.as_str()) {
            return Err(invalid(
                "tenant commitments must be uniquely sorted by tenant_ref",
            ));
        }
        previous_ref = Some(&commitment.tenant_ref);
        committed = committed
            .checked_add(commitment.event_count)
            .ok_or_else(|| invalid("tenant commitment count overflow"))?;
    }
    if committed != interval_len {
        return Err(invalid(format!(
            "tenant commitments cover {committed} events but interval contains {interval_len}"
        )));
    }
    Ok(())
}

fn validate_history_interval(
    receipt: &CheckpointReceiptV2,
    previous_last_sequence: u64,
) -> Result<(), CheckpointV2Error> {
    let delta = receipt
        .core
        .last_sequence
        .checked_sub(previous_last_sequence)
        .ok_or_else(|| invalid("checkpoint last_sequence regressed"))?;
    match (
        receipt.core.interval_start_sequence,
        receipt.core.interval_end_sequence,
    ) {
        (None, None) if delta == 0 => Ok(()),
        (Some(start), Some(end))
            if delta > 0
                && previous_last_sequence
                    .checked_add(1)
                    .is_some_and(|expected| start == expected)
                && end == receipt.core.last_sequence =>
        {
            Ok(())
        }
        _ => Err(invalid(
            "checkpoint interval boundaries do not match history coverage",
        )),
    }
}

fn validate_policy(policy: &CheckpointTrustPolicy) -> Result<(), CheckpointV2Error> {
    decode_anchor_32(
        "initial operator public key",
        &policy.initial_operator_public_key,
    )?;
    if policy.max_age_secs.is_some() && policy.now_ns.is_none() {
        return Err(freshness("max_age_secs requires now_ns"));
    }
    if policy.trusted_witness.is_none() && !policy.allow_unwitnessed {
        return Err(trust(
            "a pinned witness is required unless unwitnessed verification is explicitly allowed",
        ));
    }
    Ok(())
}

fn verify_expected_chain(
    chain_id: &str,
    policy: &CheckpointTrustPolicy,
) -> Result<(), CheckpointV2Error> {
    if policy
        .expected_chain_id
        .as_deref()
        .is_some_and(|expected| expected != chain_id)
    {
        return Err(trust(format!("unexpected chain_id {chain_id:?}")));
    }
    Ok(())
}

pub(crate) fn verify_signature(
    public_key: &str,
    signature: &str,
    message: &[u8],
    label: &str,
) -> Result<(), CheckpointV2Error> {
    let key_bytes = decode_canonical_32(&format!("{label} public key"), public_key)?;
    let signature_bytes = decode_canonical_64(&format!("{label} signature"), signature)?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|error| CheckpointV2Error::Signature(format!("invalid {label} key: {error}")))?;
    key.verify(message, &Signature::from_bytes(&signature_bytes))
        .map_err(|_| CheckpointV2Error::Signature(format!("{label} signature is invalid")))
}

pub(crate) fn decode_canonical_32(field: &str, value: &str) -> Result<[u8; 32], CheckpointV2Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(invalid(format!(
            "{field} must be exactly 32 bytes of canonical lowercase hex"
        )));
    }
    let decoded = hex::decode(value).map_err(|_| invalid(format!("{field} is not valid hex")))?;
    decoded
        .try_into()
        .map_err(|_| invalid(format!("{field} must decode to 32 bytes")))
}

pub(crate) fn decode_canonical_64(field: &str, value: &str) -> Result<[u8; 64], CheckpointV2Error> {
    if value.len() != 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(invalid(format!(
            "{field} must be exactly 64 bytes of canonical lowercase hex"
        )));
    }
    let decoded = hex::decode(value).map_err(|_| invalid(format!("{field} is not valid hex")))?;
    decoded
        .try_into()
        .map_err(|_| invalid(format!("{field} must decode to 64 bytes")))
}

fn decode_anchor_32(field: &str, value: &str) -> Result<[u8; 32], CheckpointV2Error> {
    let trimmed = value.trim();
    let normalized = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed)
        .to_ascii_lowercase();
    decode_canonical_32(field, &normalized)
}

fn validate_identifier(field: &str, value: &str) -> Result<(), CheckpointV2Error> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
    {
        return Err(invalid(format!(
            "{field} must be 1-128 ASCII identifier characters"
        )));
    }
    Ok(())
}

fn push_string(message: &mut Vec<u8>, value: &str) {
    message.extend_from_slice(&(value.len() as u64).to_le_bytes());
    message.extend_from_slice(value.as_bytes());
}

fn push_optional_string(message: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            message.push(1);
            push_string(message, value);
        }
        None => message.push(0),
    }
}

fn push_optional_u64(message: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            message.push(1);
            message.extend_from_slice(&value.to_le_bytes());
        }
        None => message.push(0),
    }
}

fn push_key_transition(message: &mut Vec<u8>, transition: &OperatorKeyTransitionV1) {
    push_string(message, &transition.schema);
    push_string(message, &transition.previous_key_id);
    push_string(message, &transition.previous_public_key);
    push_string(message, &transition.new_key_id);
    push_string(message, &transition.new_public_key);
    message.extend_from_slice(&transition.rotated_at_ns.to_le_bytes());
    push_string(message, &transition.reason);
    push_string(message, &transition.previous_key_signature);
    push_string(message, &transition.new_key_signature);
}

fn push_hash_string(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn invalid(message: impl Into<String>) -> CheckpointV2Error {
    CheckpointV2Error::Invalid(message.into())
}

fn trust(message: impl Into<String>) -> CheckpointV2Error {
    CheckpointV2Error::Trust(message.into())
}

fn freshness(message: impl Into<String>) -> CheckpointV2Error {
    CheckpointV2Error::Freshness(message.into())
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite

//! Verification of tenant-scoped audit packs produced by the Spine server.
//!
//! An audit pack contains the checkpoint prefix required to establish trust
//! from an externally pinned operator key, plus only the selected tenant's
//! events. The signed per-tenant interval commitments make event deletion,
//! insertion and reordering detectable without disclosing other tenants.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::checkpoint_v2::{
    decode_canonical_32, decode_canonical_64, tenant_ref, verify_checkpoint_history,
    verify_signature, CheckpointReceiptV2, CheckpointTrustPolicy, CheckpointV2Error,
};
use crate::{
    compute_entry_hash, compute_payload_hash_for_version, is_supported_format_version,
    validate_entry_hashes, PayloadHashError, WalEntry,
};

pub const AUDIT_PACK_SCHEMA_V1: &str = "spine-audit-pack-v1";
pub const AUDIT_PACK_DOMAIN_V1: &[u8] = b"spine:audit-pack:v1\x00";
pub const AUDIT_PACK_ID_DOMAIN_V1: &[u8] = b"spine:audit-pack-id:v1\x00";
pub const MAX_AUDIT_PACK_EVENTS: usize = 1_000_000;
pub const MAX_AUDIT_PACK_INTERVALS: usize = 100_000;

const NODE_SCOPE: &str = "spine:node-wide";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditPackCoreV1 {
    pub schema: String,
    pub tenant_ref: String,
    pub chain_id: String,
    pub generated_at_ns: i64,
    pub first_checkpoint_id: String,
    pub last_checkpoint_id: String,
    pub checkpoint_ids: Vec<String>,
    pub covered_start_sequence: Option<u64>,
    pub covered_end_sequence: Option<u64>,
    pub tenant_event_count: u64,
    pub tenant_events_root: String,
    pub operator_key_id: String,
    pub operator_algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPackIntervalV1 {
    pub checkpoint_id: String,
    pub interval_start_sequence: Option<u64>,
    pub interval_end_sequence: Option<u64>,
    pub events: Vec<WalEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditPackSignatureV1 {
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPackV1 {
    pub core: AuditPackCoreV1,
    pub pack_id: String,
    pub checkpoints: Vec<CheckpointReceiptV2>,
    pub intervals: Vec<AuditPackIntervalV1>,
    pub operator_signature: AuditPackSignatureV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditPackPolicy {
    pub expected_tenant_id: String,
    pub checkpoint_policy: CheckpointTrustPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditPackReport {
    pub pack_id: String,
    pub tenant_ref: String,
    pub chain_id: String,
    pub proof_checkpoint_count: usize,
    pub selected_interval_count: usize,
    pub tenant_event_count: u64,
    pub first_checkpoint_id: String,
    pub last_checkpoint_id: String,
    pub established_operator_key_id: String,
    pub trusted_witness_observations: usize,
}

#[derive(Debug, Error)]
pub enum AuditPackError {
    #[error("invalid audit pack: {0}")]
    Invalid(String),
    #[error(transparent)]
    Checkpoint(#[from] CheckpointV2Error),
    #[error(transparent)]
    Payload(#[from] PayloadHashError),
}

#[must_use]
pub fn audit_pack_message(core: &AuditPackCoreV1) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(AUDIT_PACK_DOMAIN_V1);
    push_string(&mut message, &core.schema);
    push_string(&mut message, &core.tenant_ref);
    push_string(&mut message, &core.chain_id);
    message.extend_from_slice(&core.generated_at_ns.to_le_bytes());
    push_string(&mut message, &core.first_checkpoint_id);
    push_string(&mut message, &core.last_checkpoint_id);
    message.extend_from_slice(&(core.checkpoint_ids.len() as u64).to_le_bytes());
    for checkpoint_id in &core.checkpoint_ids {
        push_string(&mut message, checkpoint_id);
    }
    push_optional_u64(&mut message, core.covered_start_sequence);
    push_optional_u64(&mut message, core.covered_end_sequence);
    message.extend_from_slice(&core.tenant_event_count.to_le_bytes());
    push_string(&mut message, &core.tenant_events_root);
    push_string(&mut message, &core.operator_key_id);
    push_string(&mut message, &core.operator_algorithm);
    message
}

#[must_use]
pub fn audit_pack_id(message: &[u8], signature: &AuditPackSignatureV1) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(AUDIT_PACK_ID_DOMAIN_V1);
    hasher.update(message);
    push_hash_string(&mut hasher, &signature.public_key);
    push_hash_string(&mut hasher, &signature.signature);
    hex::encode(hasher.finalize().as_bytes())
}

pub fn verify_audit_pack(
    pack: &AuditPackV1,
    policy: &AuditPackPolicy,
) -> Result<AuditPackReport, AuditPackError> {
    validate_pack_core(pack)?;
    if policy
        .checkpoint_policy
        .now_ns
        .is_some_and(|now| pack.core.generated_at_ns > now)
    {
        return Err(invalid("audit pack generation time is in the future"));
    }
    if pack.checkpoints.is_empty() || pack.intervals.is_empty() {
        return Err(invalid(
            "pack must contain a checkpoint proof and at least one selected interval",
        ));
    }
    if pack.intervals.len() > MAX_AUDIT_PACK_INTERVALS {
        return Err(invalid("pack contains too many intervals"));
    }

    let expected_tenant_ref = tenant_ref(&policy.expected_tenant_id);
    let expected_tenant_bytes = decode_canonical_32("expected tenant_ref", &expected_tenant_ref)?;
    let embedded_tenant_bytes = decode_canonical_32("tenant_ref", &pack.core.tenant_ref)?;
    if !bool::from(expected_tenant_bytes.ct_eq(&embedded_tenant_bytes)) {
        return Err(invalid(
            "tenant_ref does not match the independently supplied tenant id",
        ));
    }

    let checkpoint_report =
        verify_checkpoint_history(&pack.checkpoints, &policy.checkpoint_policy)?;
    if pack.core.chain_id != checkpoint_report.chain_id {
        return Err(invalid(
            "audit pack chain_id does not match its checkpoint proof",
        ));
    }
    let checkpoint_ids: Vec<String> = pack
        .checkpoints
        .iter()
        .map(|checkpoint| checkpoint.checkpoint_id.clone())
        .collect();
    if pack.core.checkpoint_ids != checkpoint_ids {
        return Err(invalid(
            "checkpoint_ids do not match the embedded checkpoint proof",
        ));
    }

    let mut selected_indices = Vec::with_capacity(pack.intervals.len());
    let mut previous_index = None;
    for interval in &pack.intervals {
        let index = pack
            .checkpoints
            .iter()
            .position(|checkpoint| checkpoint.checkpoint_id == interval.checkpoint_id)
            .ok_or_else(|| invalid("an interval references an unknown checkpoint"))?;
        if previous_index.is_some_and(|previous| index != previous + 1) {
            return Err(invalid(
                "selected intervals are duplicated, missing or out of checkpoint order",
            ));
        }
        previous_index = Some(index);
        selected_indices.push(index);
    }

    let first_index = selected_indices
        .first()
        .copied()
        .ok_or_else(|| invalid("no selected checkpoint interval"))?;
    let last_index = selected_indices
        .last()
        .copied()
        .ok_or_else(|| invalid("no selected checkpoint interval"))?;
    let first_checkpoint = &pack.checkpoints[first_index];
    let last_checkpoint = &pack.checkpoints[last_index];
    if pack.core.first_checkpoint_id != first_checkpoint.checkpoint_id
        || pack.core.last_checkpoint_id != last_checkpoint.checkpoint_id
    {
        return Err(invalid(
            "selected checkpoint range metadata is inconsistent",
        ));
    }
    let covered_start = selected_indices
        .iter()
        .find_map(|index| pack.checkpoints[*index].core.interval_start_sequence);
    let covered_end = selected_indices
        .iter()
        .rev()
        .find_map(|index| pack.checkpoints[*index].core.interval_end_sequence);
    if pack.core.covered_start_sequence != covered_start
        || pack.core.covered_end_sequence != covered_end
    {
        return Err(invalid("covered sequence metadata is inconsistent"));
    }

    let mut aggregate = blake3::Hasher::new();
    let mut aggregate_count = 0u64;
    let mut parsed_event_count = 0usize;
    for (interval, checkpoint_index) in pack.intervals.iter().zip(selected_indices.iter()) {
        let checkpoint = &pack.checkpoints[*checkpoint_index];
        if interval.interval_start_sequence != checkpoint.core.interval_start_sequence
            || interval.interval_end_sequence != checkpoint.core.interval_end_sequence
        {
            return Err(invalid(
                "interval boundaries do not match the signed checkpoint",
            ));
        }

        let mut interval_hasher = blake3::Hasher::new();
        let mut first_sequence = None;
        let mut last_sequence = None;
        for event in &interval.events {
            parsed_event_count = parsed_event_count
                .checked_add(1)
                .ok_or_else(|| invalid("audit pack event count overflow"))?;
            if parsed_event_count > MAX_AUDIT_PACK_EVENTS {
                return Err(invalid("audit pack contains too many events"));
            }
            if !is_supported_format_version(event.format_version) {
                return Err(invalid(format!(
                    "event {} uses unsupported WAL format {}",
                    event.sequence, event.format_version
                )));
            }
            let field_errors = validate_entry_hashes(event);
            if !field_errors.is_empty() {
                return Err(invalid(format!(
                    "event {} has invalid fields: {}",
                    event.sequence,
                    field_errors.join("; ")
                )));
            }
            let (start, end) = interval
                .interval_start_sequence
                .zip(interval.interval_end_sequence)
                .ok_or_else(|| invalid("non-empty tenant interval has no sequence bounds"))?;
            if event.sequence < start || event.sequence > end {
                return Err(invalid(format!(
                    "event {} lies outside its checkpoint interval",
                    event.sequence
                )));
            }
            if last_sequence.is_some_and(|previous| event.sequence <= previous) {
                return Err(invalid(
                    "tenant events are duplicated or out of sequence order",
                ));
            }
            first_sequence.get_or_insert(event.sequence);
            last_sequence = Some(event.sequence);

            let payload = event.payload.as_ref().ok_or_else(|| {
                invalid(format!("event {} has no auditable payload", event.sequence))
            })?;
            if tenant_ref_for_entry(event) != pack.core.tenant_ref {
                return Err(invalid(format!(
                    "event {} belongs to another tenant",
                    event.sequence
                )));
            }
            if compute_payload_hash_for_version(payload, event.format_version)?
                != event.payload_hash
            {
                return Err(invalid(format!(
                    "event {} payload hash does not match its canonical payload",
                    event.sequence
                )));
            }
            let entry_hash = compute_entry_hash(event);
            interval_hasher.update(entry_hash.as_bytes());
            aggregate.update(entry_hash.as_bytes());
            aggregate_count = aggregate_count
                .checked_add(1)
                .ok_or_else(|| invalid("tenant event count overflow"))?;
        }

        let commitment = checkpoint
            .core
            .tenant_commitments
            .iter()
            .find(|commitment| commitment.tenant_ref == pack.core.tenant_ref);
        match (commitment, interval.events.is_empty()) {
            (None, true) => {}
            (Some(expected), false)
                if expected.event_count == interval.events.len() as u64
                    && Some(expected.first_sequence) == first_sequence
                    && Some(expected.last_sequence) == last_sequence
                    && expected.events_root
                        == hex::encode(interval_hasher.finalize().as_bytes()) => {}
            _ => {
                return Err(invalid(format!(
                    "tenant interval does not match checkpoint {}",
                    checkpoint.checkpoint_id
                )))
            }
        }
    }

    if aggregate_count != pack.core.tenant_event_count
        || hex::encode(aggregate.finalize().as_bytes()) != pack.core.tenant_events_root
    {
        return Err(invalid("aggregate tenant event commitment does not match"));
    }

    let message = audit_pack_message(&pack.core);
    if audit_pack_id(&message, &pack.operator_signature) != pack.pack_id {
        return Err(invalid("pack_id does not match the signed audit pack"));
    }
    let established_key = decode_canonical_32(
        "established operator public key",
        &checkpoint_report.established_operator_public_key,
    )?;
    let pack_key =
        decode_canonical_32("audit pack public key", &pack.operator_signature.public_key)?;
    decode_canonical_64("audit pack signature", &pack.operator_signature.signature)?;
    if !bool::from(established_key.ct_eq(&pack_key))
        || pack.core.operator_key_id != checkpoint_report.established_operator_key_id
    {
        return Err(invalid(
            "audit pack signer is not the operator key established by the proof",
        ));
    }
    verify_signature(
        &pack.operator_signature.public_key,
        &pack.operator_signature.signature,
        &message,
        "audit pack",
    )?;

    Ok(AuditPackReport {
        pack_id: pack.pack_id.clone(),
        tenant_ref: pack.core.tenant_ref.clone(),
        chain_id: pack.core.chain_id.clone(),
        proof_checkpoint_count: pack.checkpoints.len(),
        selected_interval_count: pack.intervals.len(),
        tenant_event_count: aggregate_count,
        first_checkpoint_id: pack.core.first_checkpoint_id.clone(),
        last_checkpoint_id: pack.core.last_checkpoint_id.clone(),
        established_operator_key_id: checkpoint_report.established_operator_key_id,
        trusted_witness_observations: checkpoint_report.trusted_witness_observations,
    })
}

fn validate_pack_core(pack: &AuditPackV1) -> Result<(), AuditPackError> {
    if pack.core.schema != AUDIT_PACK_SCHEMA_V1 || pack.core.operator_algorithm != "ed25519" {
        return Err(invalid("unsupported audit pack schema or algorithm"));
    }
    if pack.core.generated_at_ns < 0 {
        return Err(invalid("generated_at_ns cannot be negative"));
    }
    decode_canonical_32("pack_id", &pack.pack_id)?;
    decode_canonical_32("tenant_ref", &pack.core.tenant_ref)?;
    decode_canonical_32("tenant_events_root", &pack.core.tenant_events_root)?;
    decode_canonical_32("first_checkpoint_id", &pack.core.first_checkpoint_id)?;
    decode_canonical_32("last_checkpoint_id", &pack.core.last_checkpoint_id)?;
    for checkpoint_id in &pack.core.checkpoint_ids {
        decode_canonical_32("checkpoint_id", checkpoint_id)?;
    }
    if pack.core.checkpoint_ids.len() != pack.checkpoints.len() {
        return Err(invalid("checkpoint id count does not match proof length"));
    }
    if pack.core.tenant_event_count > MAX_AUDIT_PACK_EVENTS as u64 {
        return Err(invalid(
            "declared tenant event count exceeds the verification limit",
        ));
    }
    if generation_predates_last_checkpoint(pack) {
        return Err(invalid(
            "audit pack generation time predates its last selected checkpoint",
        ));
    }
    Ok(())
}

fn generation_predates_last_checkpoint(pack: &AuditPackV1) -> bool {
    pack.checkpoints
        .iter()
        .find(|checkpoint| checkpoint.checkpoint_id == pack.core.last_checkpoint_id)
        .is_some_and(|checkpoint| pack.core.generated_at_ns < checkpoint.core.created_at_ns)
}

fn tenant_ref_for_entry(entry: &WalEntry) -> String {
    let tenant_id = entry
        .payload
        .as_ref()
        .and_then(|payload| payload.get("spine_auth"))
        .and_then(|auth| auth.get("tenant_id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or(NODE_SCOPE);
    tenant_ref(tenant_id)
}

fn push_string(message: &mut Vec<u8>, value: &str) {
    message.extend_from_slice(&(value.len() as u64).to_le_bytes());
    message.extend_from_slice(value.as_bytes());
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

fn push_hash_string(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn invalid(message: impl Into<String>) -> AuditPackError {
    AuditPackError::Invalid(message.into())
}

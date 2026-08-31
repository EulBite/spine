// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite

use std::fs;
use std::path::Path;

use serde::Serialize;
use spine_core::{
    verify_audit_pack, verify_checkpoint, verify_checkpoint_history, AuditPackPolicy, AuditPackV1,
    CheckpointReceiptV2, CheckpointTrustPolicy, TrustedWitness,
};

use crate::OutputFormat;

const MAX_CHECKPOINT_INPUT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_AUDIT_PACK_INPUT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CHECKPOINT_LINE_BYTES: usize = 1024 * 1024;

#[derive(Serialize)]
struct EvidenceOutput<T: Serialize> {
    valid: bool,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<T>,
    errors: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
pub fn run_checkpoint(
    input: &Path,
    history: bool,
    operator_public_key: &str,
    witness_id: Option<&str>,
    witness_public_key: Option<&str>,
    allow_unwitnessed: bool,
    expected_chain_id: Option<&str>,
    max_age_secs: Option<u64>,
    format: OutputFormat,
) -> Result<bool, String> {
    let policy = build_policy(
        operator_public_key,
        witness_id,
        witness_public_key,
        allow_unwitnessed,
        expected_chain_id,
        max_age_secs,
    )?;
    let receipts = load_receipts(input, history)?;
    let result = if history {
        verify_checkpoint_history(&receipts, &policy)
    } else {
        let receipt = receipts
            .first()
            .ok_or_else(|| "checkpoint input is empty".to_string())?;
        verify_checkpoint(receipt, &policy)
    };
    match result {
        Ok(report) => {
            render(
                &EvidenceOutput {
                    valid: true,
                    kind: if history {
                        "checkpoint-history-v2"
                    } else {
                        "checkpoint-receipt-v2"
                    },
                    report: Some(report),
                    errors: Vec::new(),
                },
                format,
            )?;
            Ok(true)
        }
        Err(error) => {
            render(
                &EvidenceOutput::<serde_json::Value> {
                    valid: false,
                    kind: if history {
                        "checkpoint-history-v2"
                    } else {
                        "checkpoint-receipt-v2"
                    },
                    report: None,
                    errors: vec![error.to_string()],
                },
                format,
            )?;
            Ok(false)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_audit_pack(
    input: &Path,
    tenant_id: &str,
    operator_public_key: &str,
    witness_id: Option<&str>,
    witness_public_key: Option<&str>,
    allow_unwitnessed: bool,
    expected_chain_id: Option<&str>,
    max_age_secs: Option<u64>,
    format: OutputFormat,
) -> Result<bool, String> {
    ensure_file_size(input, MAX_AUDIT_PACK_INPUT_BYTES)?;
    let bytes = fs::read(input).map_err(|error| format!("read {}: {error}", input.display()))?;
    let pack: AuditPackV1 = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse {}: {error}", input.display()))?;
    let policy = AuditPackPolicy {
        expected_tenant_id: tenant_id.to_string(),
        checkpoint_policy: build_policy(
            operator_public_key,
            witness_id,
            witness_public_key,
            allow_unwitnessed,
            expected_chain_id,
            max_age_secs,
        )?,
    };
    match verify_audit_pack(&pack, &policy) {
        Ok(report) => {
            render(
                &EvidenceOutput {
                    valid: true,
                    kind: "tenant-audit-pack-v1",
                    report: Some(report),
                    errors: Vec::new(),
                },
                format,
            )?;
            Ok(true)
        }
        Err(error) => {
            render(
                &EvidenceOutput::<serde_json::Value> {
                    valid: false,
                    kind: "tenant-audit-pack-v1",
                    report: None,
                    errors: vec![error.to_string()],
                },
                format,
            )?;
            Ok(false)
        }
    }
}

fn build_policy(
    operator_public_key: &str,
    witness_id: Option<&str>,
    witness_public_key: Option<&str>,
    allow_unwitnessed: bool,
    expected_chain_id: Option<&str>,
    max_age_secs: Option<u64>,
) -> Result<CheckpointTrustPolicy, String> {
    if witness_id.is_some() != witness_public_key.is_some() {
        return Err(
            "--witness-id and --witness-public-key must always be supplied together".into(),
        );
    }
    if witness_id.is_none() && !allow_unwitnessed {
        return Err(
            "a pinned witness is required; otherwise explicitly pass --allow-unwitnessed".into(),
        );
    }
    let trusted_witness = witness_id
        .zip(witness_public_key)
        .map(|(id, key)| TrustedWitness {
            witness_id: id.to_string(),
            public_key: key.to_string(),
        });
    Ok(CheckpointTrustPolicy {
        initial_operator_public_key: operator_public_key.to_string(),
        trusted_witness,
        allow_unwitnessed,
        expected_chain_id: expected_chain_id.map(str::to_string),
        now_ns: Some(now_ns()),
        max_age_secs,
    })
}

fn load_receipts(input: &Path, history: bool) -> Result<Vec<CheckpointReceiptV2>, String> {
    ensure_file_size(input, MAX_CHECKPOINT_INPUT_BYTES)?;
    let text =
        fs::read_to_string(input).map_err(|error| format!("read {}: {error}", input.display()))?;
    if history {
        let mut receipts = Vec::new();
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            if line.len() > MAX_CHECKPOINT_LINE_BYTES {
                return Err(format!(
                    "{} line {} exceeds the 1 MiB receipt limit",
                    input.display(),
                    index + 1
                ));
            }
            let receipt = serde_json::from_str(line).map_err(|error| {
                format!("parse {} line {}: {error}", input.display(), index + 1)
            })?;
            receipts.push(receipt);
        }
        if receipts.is_empty() {
            return Err(format!(
                "{} contains no checkpoint receipts",
                input.display()
            ));
        }
        Ok(receipts)
    } else {
        let receipt = serde_json::from_str(&text)
            .map_err(|error| format!("parse {}: {error}", input.display()))?;
        Ok(vec![receipt])
    }
}

fn ensure_file_size(input: &Path, max: u64) -> Result<(), String> {
    let metadata =
        fs::metadata(input).map_err(|error| format!("inspect {}: {error}", input.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a regular file", input.display()));
    }
    if metadata.len() > max {
        return Err(format!(
            "{} is {} bytes; verifier limit is {max} bytes",
            input.display(),
            metadata.len()
        ));
    }
    Ok(())
}

fn now_ns() -> i64 {
    let now = chrono::Utc::now();
    now.timestamp()
        .saturating_mul(1_000_000_000)
        .saturating_add(i64::from(now.timestamp_subsec_nanos()))
}

fn render<T: Serialize>(output: &EvidenceOutput<T>, format: OutputFormat) -> Result<(), String> {
    match format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(output)
                .map_err(|error| format!("serialize verification report: {error}"))?
        ),
        OutputFormat::Text => {
            println!("Evidence type: {}", output.kind);
            println!("Status: {}", if output.valid { "VALID" } else { "INVALID" });
            if let Some(report) = &output.report {
                println!(
                    "{}",
                    serde_json::to_string_pretty(report)
                        .map_err(|error| format!("serialize verification report: {error}"))?
                );
            }
            for error in &output.errors {
                println!("Error: {error}");
            }
        }
        OutputFormat::Quiet => {}
    }
    Ok(())
}

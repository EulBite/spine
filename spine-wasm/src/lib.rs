// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite

//! WebAssembly facade over `spine-core`.
//!
//! `spine-core` itself is target-agnostic. This crate wraps the two
//! verifier surfaces in JSON-string-returning shapes that JavaScript
//! callers can consume without serde-wasm-bindgen overhead.
//!
//! ## Primary entrypoint (strict)
//!
//! [`verify_demo_wal_json`] mirrors `spine_core::verify_demo_wal`
//! exactly: externally pinned public key, mandatory expected root,
//! payload-hash recompute from canonical JSON, domain-separated
//! signing. The host playground UI is allowed to call only this one.
//!
//! ## Secondary entrypoint (lenient, debug-only)
//!
//! [`verify_wal_bytes_json`] mirrors the lenient
//! `spine_core::verify_wal_bytes`. Exposed so an auditor with a
//! legacy WAL can replay it in the browser without spinning up the
//! CLI. Do NOT use from the playground UI: strict pinning is the
//! contract Spine sells.
//!
//! ## Output shape
//!
//! Both functions return a single JSON string:
//!
//! ```json
//! { "ok": true,  "report": { ... } }
//! ```
//!
//! `ok` is always `true` once the wasm crate parses its inputs; any
//! cryptographic failure lives inside `report.status` ("invalid" or
//! "error") so the JS side has one shape to walk, not two.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use spine_core::{
    verify_audit_pack, verify_checkpoint, verify_checkpoint_history, verify_demo_wal,
    verify_wal_bytes, verify_wal_bytes_with_options, AuditPackPolicy, AuditPackV1,
    CheckpointReceiptV2, CheckpointTrustPolicy, LenientOptions,
};

const MAX_WASM_EVIDENCE_JSON_BYTES: usize = 16 * 1024 * 1024;

/// JS-callable strict verifier.
///
/// Returns a JSON string with shape
/// `{ "ok": true, "report": <DemoReport> }`. The report itself
/// carries `status` ("valid", "invalid", "error") so the JS side
/// branches on it without parsing the human-readable error message.
#[must_use]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn verify_demo_wal_json(
    wal_bytes: &[u8],
    expected_pubkey_hex: &str,
    expected_root_hex: &str,
    manifest_version: u32,
) -> String {
    let report = verify_demo_wal(
        wal_bytes,
        expected_pubkey_hex,
        expected_root_hex,
        manifest_version,
    );
    serialize_envelope(&serde_json::to_string(&report))
}

/// JS-callable lenient verifier (debug-only, see module docs).
///
/// `expected_root_hex` is passed through as an optional string: JS
/// passes either the 64-char hex string or an empty value, and the
/// empty case is treated as "no expected root" with a warning in the
/// resulting report.
// `expected_root_hex` is taken by value because wasm-bindgen marshals a
// JS `string | undefined` argument into an owned `Option<String>`; a
// borrowed `Option<&str>` is not expressible across that ABI.
#[must_use]
#[allow(clippy::needless_pass_by_value)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn verify_wal_bytes_json(wal_bytes: &[u8], expected_root_hex: Option<String>) -> String {
    let trimmed = expected_root_hex.as_deref().and_then(|s| {
        let t = s.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    });
    let report = trimmed.as_deref().map_or_else(
        || verify_wal_bytes(wal_bytes),
        |root| {
            let opts = LenientOptions {
                expected_root: Some(root),
                keystore: None,
                fail_fast: false,
                trusted_pubkey: None,
            };
            verify_wal_bytes_with_options(wal_bytes, &opts)
        },
    );
    serialize_envelope(&serde_json::to_string(&report))
}

/// Verify one v2 checkpoint receipt using caller-supplied trust anchors.
#[must_use]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn verify_checkpoint_v2_json(receipt_json: &str, policy_json: &str) -> String {
    if let Err(error) = check_evidence_input_sizes(receipt_json, policy_json) {
        return error_envelope("InputLimitExceeded", &error);
    }
    let receipt: CheckpointReceiptV2 = match serde_json::from_str(receipt_json) {
        Ok(receipt) => receipt,
        Err(error) => return error_envelope("InvalidCheckpointJson", &error.to_string()),
    };
    let policy: CheckpointTrustPolicy = match serde_json::from_str(policy_json) {
        Ok(policy) => policy,
        Err(error) => return error_envelope("InvalidTrustPolicyJson", &error.to_string()),
    };
    evidence_result(verify_checkpoint(&receipt, &policy))
}

/// Verify a complete v2 checkpoint history supplied as a JSON array.
#[must_use]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn verify_checkpoint_history_v2_json(history_json: &str, policy_json: &str) -> String {
    if let Err(error) = check_evidence_input_sizes(history_json, policy_json) {
        return error_envelope("InputLimitExceeded", &error);
    }
    let history: Vec<CheckpointReceiptV2> = match serde_json::from_str(history_json) {
        Ok(history) => history,
        Err(error) => return error_envelope("InvalidCheckpointHistoryJson", &error.to_string()),
    };
    let policy: CheckpointTrustPolicy = match serde_json::from_str(policy_json) {
        Ok(policy) => policy,
        Err(error) => return error_envelope("InvalidTrustPolicyJson", &error.to_string()),
    };
    evidence_result(verify_checkpoint_history(&history, &policy))
}

/// Verify a tenant-scoped audit pack and its embedded checkpoint proof.
#[must_use]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn verify_audit_pack_v1_json(pack_json: &str, policy_json: &str) -> String {
    if let Err(error) = check_evidence_input_sizes(pack_json, policy_json) {
        return error_envelope("InputLimitExceeded", &error);
    }
    let pack: AuditPackV1 = match serde_json::from_str(pack_json) {
        Ok(pack) => pack,
        Err(error) => return error_envelope("InvalidAuditPackJson", &error.to_string()),
    };
    let policy: AuditPackPolicy = match serde_json::from_str(policy_json) {
        Ok(policy) => policy,
        Err(error) => return error_envelope("InvalidAuditPackPolicyJson", &error.to_string()),
    };
    evidence_result(verify_audit_pack(&pack, &policy))
}

fn check_evidence_input_sizes(evidence: &str, policy: &str) -> Result<(), String> {
    if evidence.len() > MAX_WASM_EVIDENCE_JSON_BYTES {
        return Err(format!(
            "evidence JSON exceeds the {MAX_WASM_EVIDENCE_JSON_BYTES} byte browser limit"
        ));
    }
    if policy.len() > 64 * 1024 {
        return Err("trust policy JSON exceeds the 65536 byte browser limit".into());
    }
    Ok(())
}

fn evidence_result<T: serde::Serialize, E: std::fmt::Display>(result: Result<T, E>) -> String {
    let value = match result {
        Ok(report) => serde_json::json!({"ok": true, "valid": true, "report": report}),
        Err(error) => serde_json::json!({
            "ok": true,
            "valid": false,
            "errors": [error.to_string()]
        }),
    };
    match serde_json::to_string(&value) {
        Ok(json) => json,
        Err(error) => error_envelope("ReportSerializationFailed", &error.to_string()),
    }
}

fn error_envelope(kind: &str, message: &str) -> String {
    format!(
        r#"{{"ok":false,"error":{{"kind":"{}","message":"{}"}}}}"#,
        escape_json_string(kind),
        escape_json_string(message)
    )
}

fn serialize_envelope(inner: &Result<String, serde_json::Error>) -> String {
    // Wrap a serialized report into the envelope. A serialization
    // failure on the report would be a contract bug in spine-core,
    // not a user-input issue; we still return a parseable JSON
    // string rather than panic, so the JS side has one shape to
    // handle.
    match inner {
        Ok(s) => format!(r#"{{"ok":true,"report":{s}}}"#),
        Err(e) => format!(
            r#"{{"ok":false,"error":{{"kind":"ReportSerializationFailed","message":"{}"}}}}"#,
            escape_json_string(&e.to_string())
        ),
    }
}

fn escape_json_string(s: &str) -> String {
    use std::fmt::Write as _;
    // Minimal JSON string escaper for the fallback path. Production
    // strings flow through serde_json::to_string and never touch
    // this helper.
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                // Writing into a String is infallible.
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn parse(s: &str) -> serde_json::Value {
        serde_json::from_str(s).expect("envelope must be valid JSON")
    }

    #[test]
    fn strict_with_malformed_pubkey_surfaces_error_status_inside_report() {
        let s = verify_demo_wal_json(b"", "not-hex", &"00".repeat(32), 1);
        let v = parse(&s);
        assert_eq!(v["ok"], true);
        assert_eq!(v["report"]["status"], "error");
        assert!(v["report"]["error"]
            .as_str()
            .unwrap()
            .contains("expected_pubkey"));
    }

    #[test]
    fn lenient_empty_returns_warning_envelope() {
        let s = verify_wal_bytes_json(b"", None);
        let v = parse(&s);
        assert_eq!(v["ok"], true);
        assert_eq!(v["report"]["valid"], true);
        assert!(v["report"]["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap().contains("No WAL records")));
    }

    #[test]
    fn lenient_treats_empty_root_string_as_none() {
        let s = verify_wal_bytes_json(b"", Some(String::new()));
        let v = parse(&s);
        assert_eq!(v["ok"], true);
        // No root supplied means the missing-expected-root warning
        // fires rather than a root-mismatch error.
        assert!(v["report"]["warnings"].as_array().unwrap().iter().any(|w| w
            .as_str()
            .unwrap()
            .contains("No expected root")
            || w.as_str().unwrap().contains("No WAL records")));
    }

    fn evidence_fixture() -> serde_json::Value {
        serde_json::from_str(include_str!("../../test-vectors/evidence-vectors.json"))
            .expect("evidence fixture must parse")
    }

    fn checkpoint_policy(fixture: &serde_json::Value) -> String {
        serde_json::json!({
            "initial_operator_public_key": fixture["operator_initial_public_key"],
            "trusted_witness": {
                "witness_id": fixture["witness_id"],
                "public_key": fixture["witness_public_key"]
            },
            "allow_unwitnessed": false,
            "expected_chain_id": "primary-eu",
            "now_ns": 1_780_000_063_000_000_000_i64,
            "max_age_secs": 120
        })
        .to_string()
    }

    #[test]
    fn checkpoint_history_wrapper_accepts_server_fixture() {
        let fixture = evidence_fixture();
        let result = verify_checkpoint_history_v2_json(
            &fixture["checkpoint_history"].to_string(),
            &checkpoint_policy(&fixture),
        );
        let envelope = parse(&result);
        assert_eq!(envelope["ok"], true);
        assert_eq!(envelope["valid"], true);
        assert_eq!(envelope["report"]["checkpoint_count"], 2);
    }

    #[test]
    fn audit_pack_wrapper_accepts_server_fixture() {
        let fixture = evidence_fixture();
        let policy = serde_json::json!({
            "expected_tenant_id": "tenant-a",
            "checkpoint_policy": serde_json::from_str::<serde_json::Value>(
                &checkpoint_policy(&fixture)
            )
            .expect("policy must parse")
        });
        let result =
            verify_audit_pack_v1_json(&fixture["audit_pack"].to_string(), &policy.to_string());
        let envelope = parse(&result);
        assert_eq!(envelope["ok"], true);
        assert_eq!(envelope["valid"], true);
        assert_eq!(envelope["report"]["tenant_event_count"], 2);
    }

    #[test]
    fn evidence_wrapper_separates_parse_errors_from_invalid_proofs() {
        let malformed = verify_checkpoint_history_v2_json("not-json", "{}");
        let malformed = parse(&malformed);
        assert_eq!(malformed["ok"], false);

        let fixture = evidence_fixture();
        let mut policy: serde_json::Value =
            serde_json::from_str(&checkpoint_policy(&fixture)).expect("policy must parse");
        policy["initial_operator_public_key"] = serde_json::Value::String("00".repeat(32));
        let invalid = verify_checkpoint_history_v2_json(
            &fixture["checkpoint_history"].to_string(),
            &policy.to_string(),
        );
        let invalid = parse(&invalid);
        assert_eq!(invalid["ok"], true);
        assert_eq!(invalid["valid"], false);
    }
}

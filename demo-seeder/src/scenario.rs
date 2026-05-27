// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite

//! The 20-record banking scenario shipped to the playground.
//!
//! The narrative is meant to read in 30 seconds for someone who has never
//! seen Spine before: an account is opened, a few logins and transfers
//! happen, a privileged config change goes through, an audit export
//! closes the day. Record 11 (a wire transfer of 100.00 EUR to "Service
//! Provider Ltd") is the **edit target** — the playground UI lets the
//! visitor change the amount string and re-run verification.
//!
//! All amount fields are JSON strings, never numbers, in keeping with the
//! canonical-JSON subset documented in `spine-core/src/canonical.rs`.

use serde_json::{json, Value};

/// One record in the WAL, BEFORE signing. The seeder fills in `prev_hash`,
/// `payload_hash`, `signature`, and `public_key` based on the chain state.
pub struct ScenarioRecord {
    pub event_type: &'static str,
    pub source: &'static str,
    pub payload: Value,
}

/// The fixed 20-record banking narrative.
///
/// Sequence numbers are implicit (1..=20, in the order returned). The
/// timestamp_ns of record N is `BASE_TIMESTAMP_NS + (N - 1) * SECOND_NS`
/// — see `seeder.rs`.
///
/// Editing this array changes the demo WAL produced by `demo-seeder` and
/// therefore the manifest pinned in the playground. Don't touch it lightly.
pub fn build_scenario() -> Vec<ScenarioRecord> {
    let account = "IT60X0542811101000000123456";

    vec![
        ScenarioRecord {
            event_type: "account.opened",
            source: "core-banking",
            payload: json!({
                "actor": "admin@bank",
                "account": account,
                "currency": "EUR",
            }),
        },
        ScenarioRecord {
            event_type: "login.success",
            source: "auth-svc",
            payload: json!({"actor": "teller@bank"}),
        },
        ScenarioRecord {
            event_type: "wire_transfer.initiated",
            source: "payments",
            payload: json!({
                "actor": "teller@bank",
                "from": account,
                "to": "ACME Corp",
                "amount": "50.00 EUR",
            }),
        },
        ScenarioRecord {
            event_type: "wire_transfer.approved",
            source: "payments",
            payload: json!({"actor": "teller@bank", "ref_seq": 3}),
        },
        ScenarioRecord {
            event_type: "wire_transfer.completed",
            source: "payments",
            payload: json!({"ref_seq": 3, "status": "settled"}),
        },
        ScenarioRecord {
            event_type: "account.balance_inquiry",
            source: "core-banking",
            payload: json!({
                "actor": "teller@bank",
                "account": account,
                "balance": "9950.00 EUR",
            }),
        },
        ScenarioRecord {
            event_type: "login.success",
            source: "auth-svc",
            payload: json!({"actor": "manager@bank"}),
        },
        ScenarioRecord {
            event_type: "audit.scheduled_review",
            source: "audit",
            payload: json!({"actor": "manager@bank", "scope": "daily"}),
        },
        ScenarioRecord {
            event_type: "login.failed",
            source: "auth-svc",
            payload: json!({
                "actor": "unknown",
                "ip": "203.0.113.42",
                "reason": "bad_credentials",
            }),
        },
        ScenarioRecord {
            event_type: "login.success",
            source: "auth-svc",
            payload: json!({"actor": "teller@bank"}),
        },
        // === seq=11: the edit target ===
        ScenarioRecord {
            event_type: "wire_transfer.initiated",
            source: "payments",
            payload: json!({
                "actor": "teller@bank",
                "from": account,
                "to": "Service Provider Ltd",
                "amount": "100.00 EUR",
            }),
        },
        // === end edit target ===
        ScenarioRecord {
            event_type: "wire_transfer.approved",
            source: "payments",
            payload: json!({"actor": "teller@bank", "ref_seq": 11}),
        },
        ScenarioRecord {
            event_type: "wire_transfer.completed",
            source: "payments",
            payload: json!({"ref_seq": 11, "status": "settled"}),
        },
        ScenarioRecord {
            event_type: "account.balance_inquiry",
            source: "core-banking",
            payload: json!({
                "actor": "teller@bank",
                "account": account,
                "balance": "9850.00 EUR",
            }),
        },
        ScenarioRecord {
            event_type: "login.success",
            source: "auth-svc",
            payload: json!({"actor": "admin@bank"}),
        },
        ScenarioRecord {
            event_type: "config.policy_change",
            source: "config-svc",
            payload: json!({
                "actor": "admin@bank",
                "field": "daily_limit",
                "from": "5000",
                "to": "10000",
            }),
        },
        ScenarioRecord {
            event_type: "config.policy_approved",
            source: "config-svc",
            payload: json!({"actor": "manager@bank", "ref_seq": 16}),
        },
        ScenarioRecord {
            event_type: "login.success",
            source: "auth-svc",
            payload: json!({"actor": "auditor@bank"}),
        },
        ScenarioRecord {
            event_type: "audit.export_initiated",
            source: "audit",
            payload: json!({
                "actor": "auditor@bank",
                "scope": "full_day",
            }),
        },
        ScenarioRecord {
            event_type: "audit.export_completed",
            source: "audit",
            payload: json!({
                "actor": "auditor@bank",
                "records": 19,
                "status": "ok",
            }),
        },
    ]
}

/// Sequence number of the record the playground UI lets the visitor edit.
/// Used by the manifest skeleton so the front-end knows which row to make
/// editable without re-encoding the narrative.
pub const EDIT_TARGET_SEQUENCE: u64 = 11;

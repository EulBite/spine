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
    verify_demo_wal, verify_wal_bytes, verify_wal_bytes_with_options, LenientOptions,
};

/// JS-callable strict verifier. Returns a JSON string with shape
/// `{ "ok": true, "report": <DemoReport> }`. The report itself
/// carries `status` ("valid", "invalid", "error") so the JS side
/// branches on it without parsing the human-readable error message.
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
    let report = match trimmed.as_deref() {
        Some(root) => {
            let opts = LenientOptions {
                expected_root: Some(root),
                keystore: None,
                fail_fast: false,
                trusted_pubkey: None,
            };
            verify_wal_bytes_with_options(wal_bytes, &opts)
        }
        None => verify_wal_bytes(wal_bytes),
    };
    serialize_envelope(&serde_json::to_string(&report))
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
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
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
}

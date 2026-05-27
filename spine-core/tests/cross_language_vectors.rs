// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite

//! Cross-language vector test.
//!
//! Loads `../test-vectors/vectors.json` and asserts that the Rust
//! implementation reproduces every pinned value. Any divergence here
//! means a downstream re-implementation (Node SDK, Go client, in-house
//! verifier) that follows the README will disagree with Rust, which is
//! a credibility-ending bug for the "single source of truth" pitch.
//!
//! Re-generate the file via
//! `cargo run --example gen_fixture -- --output ../test-vectors/vectors.json`
//! and re-run this test after any contract change.

use blake3::Hasher;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use spine_core::{
    canonical_json, compute_entry_hash, compute_entry_hash_for_signing, receipt_canonical_message,
    Receipt, WalEntry, GENESIS_PREV_HASH, STRICT_DOMAIN_SEP, WAL_FORMAT_VERSION,
};

const VECTORS_JSON: &str = include_str!("../../test-vectors/vectors.json");

#[derive(Deserialize)]
struct Vectors {
    schema_version: u32,
    wal_format_version: u32,
    canonical_json: Section<CanonicalCase>,
    entry_hash: Section<EntryHashCase>,
    sign_hash: Section<SignHashCase>,
    chain_root: Section<ChainRootCase>,
    receipt_canonical_message: Section<ReceiptCase>,
    signature: Section<SignatureCase>,
}

#[derive(Deserialize)]
struct Section<T> {
    cases: Vec<T>,
}

#[derive(Deserialize)]
struct CanonicalCase {
    name: String,
    input: Value,
    expected_canonical_json_utf8: String,
    expected_payload_hash_blake3: String,
}

#[derive(Deserialize)]
struct EntryHashCase {
    name: String,
    input: WalEntryFixture,
    expected_entry_hash: String,
}

#[derive(Deserialize)]
struct SignHashCase {
    name: String,
    input: WalEntryFixture,
    expected_sign_hash: String,
}

#[derive(Deserialize)]
struct ChainRootCase {
    name: String,
    inputs: Vec<WalEntryFixture>,
    expected_entry_hashes: Vec<String>,
    expected_root: String,
}

#[derive(Deserialize)]
struct ReceiptCase {
    name: String,
    input: Receipt,
    expected_canonical_message_hex: String,
    expected_canonical_message_utf8: String,
}

#[derive(Deserialize)]
struct SignatureCase {
    name: String,
    profile: String,
    input: WalEntryFixture,
    public_key_hex: String,
    signed_message_hex: String,
    signature_hex: String,
}

#[derive(Deserialize, Clone)]
struct WalEntryFixture {
    sequence: u64,
    timestamp_ns: i64,
    prev_hash: String,
    payload_hash: String,
    event_type: Option<String>,
    source: Option<String>,
    signature: Option<String>,
    public_key: Option<String>,
}

fn fixture_to_entry(f: &WalEntryFixture) -> WalEntry {
    WalEntry {
        format_version: 1,
        sequence: f.sequence,
        timestamp_ns: f.timestamp_ns,
        prev_hash: f.prev_hash.clone(),
        payload_hash: f.payload_hash.clone(),
        event_type: f.event_type.clone(),
        source: f.source.clone(),
        signature: f.signature.clone(),
        public_key: f.public_key.clone(),
        key_id: None,
        event_id: None,
        stream_id: None,
        hash_alg: None,
        payload: None,
        receipt: None,
    }
}

fn load_vectors() -> Vectors {
    serde_json::from_str(VECTORS_JSON)
        .expect("vectors.json must be valid JSON of the expected shape")
}

#[test]
fn header_pins_schema_and_format_version() {
    let v = load_vectors();
    assert_eq!(v.schema_version, 1);
    assert_eq!(v.wal_format_version, WAL_FORMAT_VERSION);
    // sanity touch
    let _ = (GENESIS_PREV_HASH, STRICT_DOMAIN_SEP.len());
}

#[test]
fn canonical_json_matches_every_case() {
    let v = load_vectors();
    for case in &v.canonical_json.cases {
        let actual = canonical_json(&case.input)
            .unwrap_or_else(|e| panic!("canonical_json failed for {}: {e}", case.name));
        let actual_utf8 = String::from_utf8(actual.clone())
            .unwrap_or_else(|e| panic!("canonical for {} not utf8: {e}", case.name));
        assert_eq!(
            actual_utf8, case.expected_canonical_json_utf8,
            "canonical_json mismatch on case {}",
            case.name
        );
        let payload_hash = hex::encode(blake3::hash(&actual).as_bytes());
        assert_eq!(
            payload_hash, case.expected_payload_hash_blake3,
            "payload_hash mismatch on case {}",
            case.name
        );
    }
}

#[test]
fn entry_hash_matches_every_case() {
    let v = load_vectors();
    for case in &v.entry_hash.cases {
        let entry = fixture_to_entry(&case.input);
        let actual = compute_entry_hash(&entry);
        assert_eq!(
            actual, case.expected_entry_hash,
            "entry_hash mismatch on case {}",
            case.name
        );
    }
}

#[test]
fn sign_hash_matches_every_case() {
    let v = load_vectors();
    for case in &v.sign_hash.cases {
        let entry = fixture_to_entry(&case.input);
        let actual = compute_entry_hash_for_signing(&entry);
        assert_eq!(
            actual, case.expected_sign_hash,
            "sign_hash mismatch on case {}",
            case.name
        );
    }
}

#[test]
fn chain_root_matches_every_case() {
    let v = load_vectors();
    for case in &v.chain_root.cases {
        let mut accum = Hasher::new();
        let mut computed_hashes = Vec::new();
        for fix in &case.inputs {
            let entry = fixture_to_entry(fix);
            let h = compute_entry_hash(&entry);
            accum.update(h.as_bytes());
            computed_hashes.push(h);
        }
        let root = hex::encode(accum.finalize().as_bytes());
        assert_eq!(
            computed_hashes, case.expected_entry_hashes,
            "per-entry hash list mismatch on case {}",
            case.name
        );
        assert_eq!(
            root, case.expected_root,
            "chain_root mismatch on case {}",
            case.name
        );
    }
}

#[test]
fn receipt_canonical_message_matches_every_case() {
    let v = load_vectors();
    for case in &v.receipt_canonical_message.cases {
        let actual = receipt_canonical_message(&case.input)
            .unwrap_or_else(|e| panic!("receipt_canonical_message failed for {}: {e}", case.name));
        assert_eq!(
            hex::encode(&actual),
            case.expected_canonical_message_hex,
            "receipt canonical message hex mismatch on case {}",
            case.name
        );
        assert_eq!(
            String::from_utf8_lossy(&actual),
            case.expected_canonical_message_utf8,
            "receipt canonical message utf8 mismatch on case {}",
            case.name
        );
    }
}

#[test]
fn signature_cases_verify_under_their_declared_profile() {
    let v = load_vectors();
    for case in &v.signature.cases {
        let entry = fixture_to_entry(&case.input);
        let sign_hash_hex = compute_entry_hash_for_signing(&entry);

        let expected_message = match case.profile.as_str() {
            "lenient" => sign_hash_hex.as_bytes().to_vec(),
            "strict" => {
                let mut m = Vec::new();
                m.extend_from_slice(STRICT_DOMAIN_SEP);
                m.extend_from_slice(sign_hash_hex.as_bytes());
                m
            }
            other => panic!("unknown profile {other} in case {}", case.name),
        };
        let recorded_message = hex::decode(&case.signed_message_hex)
            .unwrap_or_else(|e| panic!("hex decode signed_message for {}: {e}", case.name));
        assert_eq!(
            expected_message, recorded_message,
            "recorded signed_message does not match computed one for case {}",
            case.name
        );

        let pk_bytes = hex::decode(&case.public_key_hex)
            .unwrap_or_else(|e| panic!("hex decode pubkey for {}: {e}", case.name));
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);
        let vk = VerifyingKey::from_bytes(&pk_arr).expect("vector pubkey must be on curve");

        let sig_bytes = hex::decode(&case.signature_hex)
            .unwrap_or_else(|e| panic!("hex decode sig for {}: {e}", case.name));
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(&sig_arr);

        vk.verify(&recorded_message, &sig).unwrap_or_else(|_| {
            panic!(
                "signature does not verify for case {} under profile {}",
                case.name, case.profile
            );
        });
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite

//! Generate `test-vectors/vectors.json`. Run as:
//!
//! ```text
//! cargo run --example gen_fixture -- --output ../test-vectors/vectors.json
//! ```
//!
//! The output is the byte-pinned cross-language fixture every Spine
//! implementation reproduces. Re-running on a fresh checkout MUST
//! produce identical bytes: the test in
//! `tests/cross_language_vectors.rs` re-loads this file and asserts
//! the Rust impl still matches every recorded value.

use std::env;
use std::fs;
use std::path::PathBuf;

use blake3::Hasher;
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use serde_json::{json, Value};
use spine_core::{
    canonical_json, compute_entry_hash, compute_entry_hash_for_signing, receipt_canonical_message,
    Receipt, WalEntry, GENESIS_PREV_HASH, STRICT_DOMAIN_SEP, WAL_FORMAT_VERSION,
};

#[derive(Serialize)]
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

#[derive(Serialize)]
struct Section<T> {
    cases: Vec<T>,
}

#[derive(Serialize)]
struct CanonicalCase {
    name: String,
    input: Value,
    expected_canonical_json_utf8: String,
    expected_payload_hash_blake3: String,
}

#[derive(Serialize)]
struct EntryHashCase {
    name: String,
    input: WalEntryFixture,
    expected_entry_hash: String,
}

#[derive(Serialize)]
struct SignHashCase {
    name: String,
    input: WalEntryFixture,
    expected_sign_hash: String,
}

#[derive(Serialize)]
struct ChainRootCase {
    name: String,
    inputs: Vec<WalEntryFixture>,
    expected_entry_hashes: Vec<String>,
    expected_root: String,
}

#[derive(Serialize)]
struct ReceiptCase {
    name: String,
    input: Receipt,
    expected_canonical_message_hex: String,
    expected_canonical_message_utf8: String,
}

#[derive(Serialize)]
struct SignatureCase {
    name: String,
    profile: String,
    input: WalEntryFixture,
    signing_key_seed_hex: String,
    public_key_hex: String,
    signed_message_hex: String,
    signature_hex: String,
}

#[derive(Serialize, Clone)]
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

impl From<&WalEntry> for WalEntryFixture {
    fn from(e: &WalEntry) -> Self {
        Self {
            sequence: e.sequence,
            timestamp_ns: e.timestamp_ns,
            prev_hash: e.prev_hash.clone(),
            payload_hash: e.payload_hash.clone(),
            event_type: e.event_type.clone(),
            source: e.source.clone(),
            signature: e.signature.clone(),
            public_key: e.public_key.clone(),
        }
    }
}

fn canonical_cases() -> Vec<CanonicalCase> {
    let inputs: Vec<(&str, Value)> = vec![
        ("empty_object", json!({})),
        ("empty_array", json!([])),
        ("flat_object_unsorted_keys", json!({"b": 1, "a": 2, "c": 3})),
        ("nested_object", json!({"outer": {"d": 4, "c": 3}, "a": 1})),
        ("array_preserves_order", json!([3, 1, 2])),
        ("ascii_string", json!({"s": "hello world"})),
        (
            "named_escapes",
            json!({"s": "tab\there\nnewline\\back\"quote"}),
        ),
        ("unicode_literal_utf8", json!({"s": "café 日本 emoji🎉"})),
        (
            "nfc_normalization",
            json!({"key": "cafe\u{0301}", "cafe\u{0301}": 1}),
        ),
        ("supplementary_sort", {
            let mut m = serde_json::Map::new();
            m.insert("\u{FFFF}".to_string(), json!(2));
            m.insert("\u{10000}".to_string(), json!(1));
            Value::Object(m)
        }),
        (
            "banking_payload",
            json!({
                "amount": "100.00",
                "currency": "EUR",
                "ts": "2026-05-27T10:00:00Z",
                "from": "acct-1",
                "to": "acct-2"
            }),
        ),
    ];

    inputs
        .into_iter()
        .map(|(name, input)| {
            let canonical = canonical_json(&input).unwrap_or_else(|e| {
                panic!("canonical_json failed for case {name}: {e}");
            });
            let canonical_utf8 = String::from_utf8(canonical.clone())
                .unwrap_or_else(|e| panic!("canonical for {name} is not UTF-8: {e}"));
            let payload_hash = hex::encode(blake3::hash(&canonical).as_bytes());
            CanonicalCase {
                name: name.to_string(),
                input,
                expected_canonical_json_utf8: canonical_utf8,
                expected_payload_hash_blake3: payload_hash,
            }
        })
        .collect()
}

fn entry_hash_cases() -> Vec<EntryHashCase> {
    let base = WalEntry {
        format_version: 1,
        sequence: 1,
        timestamp_ns: 1_700_000_000_000_000_000,
        prev_hash: GENESIS_PREV_HASH.to_string(),
        payload_hash: "ab".repeat(32),
        event_type: None,
        source: None,
        signature: None,
        public_key: None,
        key_id: None,
        event_id: None,
        stream_id: None,
        hash_alg: None,
        payload: None,
        receipt: None,
    };

    let mut cases: Vec<EntryHashCase> = Vec::new();

    cases.push(EntryHashCase {
        name: "genesis_all_optional_none".to_string(),
        input: WalEntryFixture::from(&base),
        expected_entry_hash: compute_entry_hash(&base),
    });

    let mut with_empty_event_type = base.clone();
    with_empty_event_type.event_type = Some(String::new());
    cases.push(EntryHashCase {
        name: "event_type_some_empty_distinct_from_none".to_string(),
        input: WalEntryFixture::from(&with_empty_event_type),
        expected_entry_hash: compute_entry_hash(&with_empty_event_type),
    });

    let mut with_event_type = base.clone();
    with_event_type.event_type = Some("user.login".to_string());
    cases.push(EntryHashCase {
        name: "event_type_some_value".to_string(),
        input: WalEntryFixture::from(&with_event_type),
        expected_entry_hash: compute_entry_hash(&with_event_type),
    });

    let mut with_source = base.clone();
    with_source.source = Some("auth-service".to_string());
    cases.push(EntryHashCase {
        name: "source_some_value".to_string(),
        input: WalEntryFixture::from(&with_source),
        expected_entry_hash: compute_entry_hash(&with_source),
    });

    let mut with_sig = base.clone();
    with_sig.signature = Some("a".repeat(128));
    with_sig.public_key = Some("b".repeat(64));
    cases.push(EntryHashCase {
        name: "signed_record_all_four_optional_set".to_string(),
        input: WalEntryFixture::from(&with_sig),
        expected_entry_hash: compute_entry_hash(&with_sig),
    });

    let mut subsequent = base.clone();
    subsequent.sequence = 2;
    subsequent.timestamp_ns = 1_700_000_001_000_000_000;
    subsequent.prev_hash = compute_entry_hash(&base);
    subsequent.payload_hash = "cd".repeat(32);
    cases.push(EntryHashCase {
        name: "subsequent_chain_link".to_string(),
        input: WalEntryFixture::from(&subsequent),
        expected_entry_hash: compute_entry_hash(&subsequent),
    });

    cases
}

fn sign_hash_cases() -> Vec<SignHashCase> {
    let mut entry = WalEntry {
        format_version: 1,
        sequence: 1,
        timestamp_ns: 1_700_000_000_000_000_000,
        prev_hash: GENESIS_PREV_HASH.to_string(),
        payload_hash: "ab".repeat(32),
        event_type: Some("user.login".to_string()),
        source: Some("auth-service".to_string()),
        signature: None,
        public_key: None,
        key_id: None,
        event_id: None,
        stream_id: None,
        hash_alg: None,
        payload: None,
        receipt: None,
    };

    let unsigned = SignHashCase {
        name: "unsigned_entry_matches_chain_hash".to_string(),
        input: WalEntryFixture::from(&entry),
        expected_sign_hash: compute_entry_hash_for_signing(&entry),
    };

    entry.signature = Some("a".repeat(128));
    entry.public_key = Some("b".repeat(64));
    let signed = SignHashCase {
        name: "signed_entry_invariant_under_sig_and_pubkey".to_string(),
        input: WalEntryFixture::from(&entry),
        expected_sign_hash: compute_entry_hash_for_signing(&entry),
    };

    vec![unsigned, signed]
}

fn chain_root_cases() -> Vec<ChainRootCase> {
    let mut entries = Vec::new();
    let mut prev = GENESIS_PREV_HASH.to_string();
    for i in 1..=3u64 {
        let e = WalEntry {
            format_version: 1,
            sequence: i,
            timestamp_ns: 1_700_000_000_000_000_000 + (i as i64) * 1_000_000_000,
            prev_hash: prev.clone(),
            payload_hash: hex::encode(blake3::hash(format!("payload-{i}").as_bytes()).as_bytes()),
            event_type: None,
            source: None,
            signature: None,
            public_key: None,
            key_id: None,
            event_id: None,
            stream_id: None,
            hash_alg: None,
            payload: None,
            receipt: None,
        };
        prev = compute_entry_hash(&e);
        entries.push(e);
    }

    let mut accum = Hasher::new();
    let mut hashes = Vec::new();
    for e in &entries {
        let h = compute_entry_hash(e);
        accum.update(h.as_bytes());
        hashes.push(h);
    }
    let root = hex::encode(accum.finalize().as_bytes());

    let case = ChainRootCase {
        name: "three_entry_unsigned_chain".to_string(),
        inputs: entries.iter().map(WalEntryFixture::from).collect(),
        expected_entry_hashes: hashes,
        expected_root: root,
    };

    vec![case]
}

fn receipt_cases() -> Vec<ReceiptCase> {
    let cases: Vec<(&str, Receipt)> = vec![
        (
            "with_batch_id",
            Receipt {
                event_id: "evt-42".to_string(),
                payload_hash: "ab".repeat(32),
                server_time: "2026-05-27T10:00:00Z".to_string(),
                server_seq: 7,
                receipt_sig: String::new(),
                server_key_id: "primary-2025".to_string(),
                sig_alg: "ed25519".to_string(),
                batch_id: Some("batch-9".to_string()),
            },
        ),
        (
            "batch_id_null",
            Receipt {
                event_id: "evt-43".to_string(),
                payload_hash: "cd".repeat(32),
                server_time: "2026-05-27T10:00:01Z".to_string(),
                server_seq: 8,
                receipt_sig: String::new(),
                server_key_id: "primary-2025".to_string(),
                sig_alg: "ed25519".to_string(),
                batch_id: None,
            },
        ),
    ];

    cases
        .into_iter()
        .map(|(name, r)| {
            let msg = receipt_canonical_message(&r).unwrap_or_else(|e| {
                panic!("receipt_canonical_message failed for case {name}: {e}");
            });
            let utf8 = String::from_utf8_lossy(&msg).to_string();
            ReceiptCase {
                name: name.to_string(),
                input: r,
                expected_canonical_message_hex: hex::encode(&msg),
                expected_canonical_message_utf8: utf8,
            }
        })
        .collect()
}

fn signature_cases() -> Vec<SignatureCase> {
    let seed = [0x42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());

    let entry = WalEntry {
        format_version: 1,
        sequence: 1,
        timestamp_ns: 1_700_000_000_000_000_000,
        prev_hash: GENESIS_PREV_HASH.to_string(),
        payload_hash: "ab".repeat(32),
        event_type: Some("user.login".to_string()),
        source: Some("auth-service".to_string()),
        signature: None,
        public_key: None,
        key_id: None,
        event_id: None,
        stream_id: None,
        hash_alg: None,
        payload: None,
        receipt: None,
    };

    let sign_hash_hex = compute_entry_hash_for_signing(&entry);

    let lenient_msg = sign_hash_hex.as_bytes().to_vec();
    let lenient_sig = sk.sign(&lenient_msg);

    let mut strict_msg = Vec::new();
    strict_msg.extend_from_slice(STRICT_DOMAIN_SEP);
    strict_msg.extend_from_slice(sign_hash_hex.as_bytes());
    let strict_sig = sk.sign(&strict_msg);

    vec![
        SignatureCase {
            name: "lenient_no_domain_prefix".to_string(),
            profile: "lenient".to_string(),
            input: WalEntryFixture::from(&entry),
            signing_key_seed_hex: hex::encode(seed),
            public_key_hex: pk_hex.clone(),
            signed_message_hex: hex::encode(&lenient_msg),
            signature_hex: hex::encode(lenient_sig.to_bytes()),
        },
        SignatureCase {
            name: "strict_with_spine_wal_v1_prefix".to_string(),
            profile: "strict".to_string(),
            input: WalEntryFixture::from(&entry),
            signing_key_seed_hex: hex::encode(seed),
            public_key_hex: pk_hex,
            signed_message_hex: hex::encode(&strict_msg),
            signature_hex: hex::encode(strict_sig.to_bytes()),
        },
    ]
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut output_path: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--output" => {
                if i + 1 >= args.len() {
                    eprintln!("--output requires a path argument");
                    std::process::exit(2);
                }
                output_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    let vectors = Vectors {
        schema_version: 1,
        wal_format_version: WAL_FORMAT_VERSION,
        canonical_json: Section {
            cases: canonical_cases(),
        },
        entry_hash: Section {
            cases: entry_hash_cases(),
        },
        sign_hash: Section {
            cases: sign_hash_cases(),
        },
        chain_root: Section {
            cases: chain_root_cases(),
        },
        receipt_canonical_message: Section {
            cases: receipt_cases(),
        },
        signature: Section {
            cases: signature_cases(),
        },
    };

    let mut json = serde_json::to_string_pretty(&vectors).expect("vectors must serialize");
    json.push('\n');

    match output_path {
        Some(p) => fs::write(&p, &json).unwrap_or_else(|e| {
            panic!("write {}: {e}", p.display());
        }),
        None => print!("{json}"),
    }
}

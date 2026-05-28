// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite

//! Parity test: the lenient and strict verifiers must compute
//! identical `chain_root` for any WAL they can both parse.
//!
//! This is the regression net under [`compute_entry_hash`] and the
//! chain accumulator. The two verifiers exist for different threat
//! models, but they sit on top of the SAME chain primitive. If a
//! future change shifts one side without the other, both verifiers
//! still produce a "chain root" each, but the two values silently
//! diverge, and "verify" the same WAL into different states. That
//! is a credibility-ending bug class for a product whose pitch is
//! "the verifier in your browser is the same verifier as the CLI".
//!
//! What this file does NOT check: signature verification parity.
//! Lenient signs over the UTF-8 hex bytes of the sign hash; strict
//! prepends `b"spine-wal-v1\x00"` first. A strict-signed WAL fails
//! lenient signature verification on purpose. That divergence is
//! pinned at the unit-test level inside `verify_demo`.

use blake3::Hasher;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use spine_core::{
    canonical_json, compute_entry_hash, compute_entry_hash_for_signing, verify_demo_wal,
    verify_wal_bytes, DemoStatus, WalEntry, GENESIS_PREV_HASH, STRICT_DOMAIN_SEP,
};

fn build_entry(seq: u64, ts: i64, prev: &str, payload: serde_json::Value) -> WalEntry {
    let canonical = canonical_json(&payload).expect("canonical_json");
    let payload_hash = hex::encode(blake3::hash(&canonical).as_bytes());
    WalEntry {
        format_version: 1,
        sequence: seq,
        timestamp_ns: ts,
        prev_hash: prev.to_string(),
        payload_hash,
        event_type: None,
        source: None,
        signature: None,
        public_key: None,
        key_id: None,
        event_id: None,
        stream_id: None,
        hash_alg: Some("blake3".to_string()),
        payload: Some(payload),
        receipt: None,
    }
}

fn sign_strict(entry: &mut WalEntry, sk: &SigningKey) {
    let sign_hash = compute_entry_hash_for_signing(entry);
    let mut msg = Vec::new();
    msg.extend_from_slice(STRICT_DOMAIN_SEP);
    msg.extend_from_slice(sign_hash.as_bytes());
    let sig = sk.sign(&msg);
    entry.signature = Some(hex::encode(sig.to_bytes()));
    entry.public_key = Some(hex::encode(sk.verifying_key().to_bytes()));
}

fn jsonl(entries: &[WalEntry]) -> Vec<u8> {
    let mut buf = Vec::new();
    for e in entries {
        let line = serde_json::to_string(e).expect("serialize WalEntry");
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
    }
    buf
}

fn build_chain(n: u64, sk: &SigningKey) -> (Vec<WalEntry>, String) {
    let mut entries = Vec::new();
    let mut prev = GENESIS_PREV_HASH.to_string();
    let mut accum = Hasher::new();
    for i in 1..=n {
        let mut e = build_entry(i, 1000 * i as i64, &prev, json!({"i": i, "kind": "parity"}));
        sign_strict(&mut e, sk);
        let h = compute_entry_hash(&e);
        accum.update(h.as_bytes());
        prev = h;
        entries.push(e);
    }
    let root = hex::encode(accum.finalize().as_bytes());
    (entries, root)
}

#[test]
fn chain_root_agrees_between_lenient_and_strict_on_strict_signed_wal() {
    let sk = SigningKey::from_bytes(&[0x11; 32]);
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());
    let (entries, expected_root) = build_chain(5, &sk);
    let bytes = jsonl(&entries);

    let strict = verify_demo_wal(&bytes, &pk_hex, &expected_root, 1);
    assert_eq!(
        strict.status,
        DemoStatus::Valid,
        "strict report: {strict:?}"
    );

    let lenient = verify_wal_bytes(&bytes);
    // Lenient WILL fail signature verification on a strict-signed WAL
    // because the strict prefix is missing from the lenient sign
    // message. The chain_root is the parity we care about here.
    assert_eq!(
        strict.chain_root, lenient.chain_root,
        "chain_root must match across verifiers"
    );
}

#[test]
fn chain_root_matches_manual_accumulator() {
    let sk = SigningKey::from_bytes(&[0x22; 32]);
    let (entries, manual_root) = build_chain(3, &sk);
    let bytes = jsonl(&entries);

    let lenient = verify_wal_bytes(&bytes);
    assert_eq!(
        lenient.chain_root, manual_root,
        "verifier-computed root must equal externally-computed root"
    );
}

#[test]
fn chain_root_is_deterministic_across_repeated_runs() {
    let sk = SigningKey::from_bytes(&[0x33; 32]);
    let (entries, _) = build_chain(4, &sk);
    let bytes = jsonl(&entries);

    let r1 = verify_wal_bytes(&bytes);
    let r2 = verify_wal_bytes(&bytes);
    assert_eq!(r1.chain_root, r2.chain_root);
    assert_eq!(r1.events_verified, r2.events_verified);
}

#[test]
fn chain_root_shifts_when_a_single_byte_of_payload_changes() {
    // A useful negative parity: equal-shaped WALs with different
    // payloads produce different roots. Catches a degenerate
    // accumulator (e.g. one that hashed the same constant for each
    // entry).
    let sk = SigningKey::from_bytes(&[0x44; 32]);
    let (mut entries_a, _) = build_chain(2, &sk);
    let (entries_b, _) = build_chain(2, &sk);
    // Mutate payload in entries_a; re-sign to keep both sides
    // independently coherent. This proves the chain root genuinely
    // commits to payload content.
    entries_a[1].payload = Some(json!({"i": 2, "kind": "tampered"}));
    let canonical = canonical_json(entries_a[1].payload.as_ref().unwrap()).unwrap();
    entries_a[1].payload_hash = hex::encode(blake3::hash(&canonical).as_bytes());
    // Re-link entry 2 to the (unchanged) hash of entry 1, then re-sign.
    sign_strict(&mut entries_a[1], &sk);

    let ra = verify_wal_bytes(&jsonl(&entries_a));
    let rb = verify_wal_bytes(&jsonl(&entries_b));
    assert_ne!(ra.chain_root, rb.chain_root);
}

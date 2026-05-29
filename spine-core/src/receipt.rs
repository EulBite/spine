// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite

//! Server receipt: shape, canonical signing message, keystore, verification.
//!
//! ## What a receipt proves
//!
//! A [`Receipt`] is the server's signed acknowledgement that an event was
//! accepted into its append-only ledger. The chain-link hash on a
//! [`WalEntry`] proves the entry was written in a specific position by
//! whoever held the WAL signing key. The receipt is a separate, layered
//! attestation: only a holder of the server's private key can produce a
//! valid `receipt_sig`. The two attestations are independent on purpose,
//! so swapping a stored receipt without re-signing it is detectable as
//! [`ReceiptError::SignatureInvalid`] even when the chain hash still
//! checks out.
//!
//! ## Canonical sign message
//!
//! [`receipt_canonical_message`] is the byte-for-byte contract any signer
//! and any verifier must agree on. The shape is:
//!
//! ```text
//! RECEIPT_DOMAIN_SEP || serde_json(BTreeMap<&str, Value>)
//! ```
//!
//! The map carries seven keys, sorted alphabetically by `BTreeMap`:
//! `batch_id` (JSON `null` when [`Receipt::batch_id`] is `None`),
//! `event_id`, `payload_hash`, `server_key_id`, `server_seq`,
//! `server_time`, `sig_alg`. `receipt_sig` is intentionally excluded
//! because a signature cannot reference its own output. The
//! [`RECEIPT_DOMAIN_SEP`] prefix prevents this signature from ever being
//! reused on top of a different signed envelope (WAL entry, keystore
//! attestation, future schemas).
//!
//! Determinism guarantee: `BTreeMap` iterates keys in sorted order and
//! `serde_json::to_string` writes them in that order, so the same
//! [`Receipt`] produces identical bytes across platforms and rust
//! versions. The cross-language vectors in `test-vectors/vectors.json`
//! pin this contract so any independent implementation can reproduce it.
//!
//! ## Keystore
//!
//! Receipt verification needs a `server_key_id -> VerifyingKey` lookup.
//! The on-disk schema is:
//!
//! ```json
//! { "schema": "spine-keystore-v1", "keys": { "<id>": "<64 hex>" } }
//! ```
//!
//! `Keystore::load_from_file` refuses any unknown `schema` value: a new
//! key format must bump the schema string so an old verifier loudly
//! rejects records it does not understand, rather than silently
//! interpreting them.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::wal_entry::WalEntry;

/// Domain-separation prefix for the receipt signature. The trailing
/// NUL byte makes it impossible to ambiguously concatenate this prefix
/// with another domain by truncation, and the version tag lets a future
/// schema bump be rejected loudly rather than reinterpreted.
pub const RECEIPT_DOMAIN_SEP: &[u8] = b"spine-receipt-v1\x00";

fn default_sig_alg() -> String {
    "ed25519".to_string()
}

/// Server-issued attestation that an event was accepted.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Receipt {
    pub event_id: String,
    pub payload_hash: String,
    pub server_time: String,
    pub server_seq: i64,
    pub receipt_sig: String,
    pub server_key_id: String,

    #[serde(default = "default_sig_alg")]
    pub sig_alg: String,

    /// Identifier of the sealed batch the event landed in. JSON `null`
    /// for receipts issued before sealing; the canonical message
    /// encodes that case as the literal `null` token, not as omission.
    #[serde(default)]
    pub batch_id: Option<String>,
}

/// Errors raised by receipt verification and keystore handling.
#[derive(Debug, Error)]
pub enum ReceiptError {
    #[error("Keystore file {path} could not be read or parsed: {details}")]
    KeystoreLoad { path: String, details: String },

    #[error(
        "Receipt at sequence {sequence} references server_key_id={server_key_id} which is not in the keystore"
    )]
    KeyUnknown {
        sequence: u64,
        server_key_id: String,
    },

    #[error(
        "Receipt at sequence {sequence} has an unsupported signature algorithm {sig_alg:?} (only ed25519 is implemented)"
    )]
    UnsupportedAlg { sequence: u64, sig_alg: String },

    #[error("Receipt at sequence {sequence}: malformed receipt_sig: {details}")]
    SigMalformed { sequence: u64, details: String },

    #[error("Receipt at sequence {sequence} failed Ed25519 signature verification")]
    SignatureInvalid { sequence: u64 },

    #[error("Receipt at sequence {sequence}: failed to serialize canonical message: {details}")]
    CanonicalSerialize { sequence: u64, details: String },
}

/// Build the bytes that an Ed25519 signer must sign to produce
/// [`Receipt::receipt_sig`].
///
/// Returns the underlying `serde_json::Error` on the (vanishingly rare)
/// path where the primitive-typed BTreeMap fails to serialize. The
/// no-panic guarantee on `spine-core` forbids the legacy `.expect`
/// shortcut even on logically unreachable branches.
pub fn receipt_canonical_message(receipt: &Receipt) -> Result<Vec<u8>, serde_json::Error> {
    let mut map: BTreeMap<&'static str, Value> = BTreeMap::new();
    map.insert(
        "batch_id",
        match &receipt.batch_id {
            Some(s) => Value::String(s.clone()),
            None => Value::Null,
        },
    );
    map.insert("event_id", Value::String(receipt.event_id.clone()));
    map.insert("payload_hash", Value::String(receipt.payload_hash.clone()));
    map.insert(
        "server_key_id",
        Value::String(receipt.server_key_id.clone()),
    );
    map.insert(
        "server_seq",
        Value::Number(serde_json::Number::from(receipt.server_seq)),
    );
    map.insert("server_time", Value::String(receipt.server_time.clone()));
    map.insert("sig_alg", Value::String(receipt.sig_alg.clone()));

    let body = serde_json::to_string(&map)?;
    let mut out = Vec::with_capacity(RECEIPT_DOMAIN_SEP.len() + body.len());
    out.extend_from_slice(RECEIPT_DOMAIN_SEP);
    out.extend_from_slice(body.as_bytes());
    Ok(out)
}

/// In-memory map of `server_key_id -> VerifyingKey`, populated from a
/// JSON file or from a programmatic iterator. Immutable after load.
#[derive(Debug, Default, Clone)]
pub struct Keystore {
    keys: BTreeMap<String, VerifyingKey>,
}

#[derive(Deserialize)]
struct KeystoreFile {
    schema: String,
    keys: BTreeMap<String, String>,
}

impl Keystore {
    /// Load a keystore from a JSON file. See module docs for the schema.
    pub fn load_from_file(path: &Path) -> Result<Self, ReceiptError> {
        let bytes = fs::read(path).map_err(|e| ReceiptError::KeystoreLoad {
            path: path.display().to_string(),
            details: e.to_string(),
        })?;

        let parsed: KeystoreFile =
            serde_json::from_slice(&bytes).map_err(|e| ReceiptError::KeystoreLoad {
                path: path.display().to_string(),
                details: format!("invalid JSON: {e}"),
            })?;

        if parsed.schema != "spine-keystore-v1" {
            return Err(ReceiptError::KeystoreLoad {
                path: path.display().to_string(),
                details: format!(
                    "unsupported keystore schema {:?} (expected spine-keystore-v1)",
                    parsed.schema
                ),
            });
        }

        let mut keys = BTreeMap::new();
        for (key_id, hex_pub) in parsed.keys {
            let raw = hex::decode(&hex_pub).map_err(|e| ReceiptError::KeystoreLoad {
                path: path.display().to_string(),
                details: format!("pubkey for {key_id} is not valid hex: {e}"),
            })?;
            if raw.len() != 32 {
                return Err(ReceiptError::KeystoreLoad {
                    path: path.display().to_string(),
                    details: format!("pubkey for {key_id} must be 32 bytes, got {}", raw.len()),
                });
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&raw);
            let vk = VerifyingKey::from_bytes(&arr).map_err(|e| ReceiptError::KeystoreLoad {
                path: path.display().to_string(),
                details: format!("pubkey for {key_id} is not a valid Ed25519 point: {e}"),
            })?;
            keys.insert(key_id, vk);
        }

        Ok(Self { keys })
    }

    /// Construct a keystore from an iterator of pairs. Used by tests and
    /// by callers that source keys from a transport other than the file
    /// format above (network fetch, embedded constant, etc.).
    pub fn from_keys(iter: impl IntoIterator<Item = (String, VerifyingKey)>) -> Self {
        Self {
            keys: iter.into_iter().collect(),
        }
    }

    pub fn lookup(&self, key_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(key_id)
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }
}

/// Verify the receipt carried by a WAL entry, if any.
///
/// Returns `Ok(true)` when a receipt was present and verified,
/// `Ok(false)` when the entry has no receipt (nothing to do, not an
/// error), and `Err` for every failure mode an auditor should see.
pub fn verify_receipt_signature(
    entry: &WalEntry,
    keystore: &Keystore,
) -> Result<bool, ReceiptError> {
    match &entry.receipt {
        None => Ok(false),
        Some(receipt) => {
            verify_receipt_against_keystore(entry.sequence, receipt, keystore)?;
            Ok(true)
        }
    }
}

/// Verify a receipt against the keystore, given the sequence number
/// of the entry it attests to. Exposed for callers that hand the
/// verifier a single receipt without a surrounding [`WalEntry`].
pub fn verify_receipt_against_keystore(
    sequence: u64,
    receipt: &Receipt,
    keystore: &Keystore,
) -> Result<(), ReceiptError> {
    if receipt.sig_alg != "ed25519" {
        return Err(ReceiptError::UnsupportedAlg {
            sequence,
            sig_alg: receipt.sig_alg.clone(),
        });
    }

    let pubkey =
        keystore
            .lookup(&receipt.server_key_id)
            .ok_or_else(|| ReceiptError::KeyUnknown {
                sequence,
                server_key_id: receipt.server_key_id.clone(),
            })?;

    let sig_bytes = hex::decode(&receipt.receipt_sig).map_err(|e| ReceiptError::SigMalformed {
        sequence,
        details: format!("receipt_sig is not valid hex: {e}"),
    })?;
    if sig_bytes.len() != 64 {
        return Err(ReceiptError::SigMalformed {
            sequence,
            details: format!("receipt_sig must be 64 bytes, got {}", sig_bytes.len()),
        });
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    let message =
        receipt_canonical_message(receipt).map_err(|e| ReceiptError::CanonicalSerialize {
            sequence,
            details: e.to_string(),
        })?;

    pubkey
        .verify(&message, &signature)
        .map_err(|_| ReceiptError::SignatureInvalid { sequence })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sample_receipt() -> Receipt {
        Receipt {
            event_id: "evt-7".to_string(),
            payload_hash: "abcd".repeat(16),
            server_time: "2026-05-27T10:00:00Z".to_string(),
            server_seq: 42,
            receipt_sig: String::new(),
            server_key_id: "primary-2025".to_string(),
            sig_alg: "ed25519".to_string(),
            batch_id: Some("b-9".to_string()),
        }
    }

    fn signing_key_seed(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn sign_receipt(receipt: &mut Receipt, signing_key: &SigningKey) {
        let msg = receipt_canonical_message(receipt).unwrap();
        let sig = signing_key.sign(&msg);
        receipt.receipt_sig = hex::encode(sig.to_bytes());
    }

    #[test]
    fn canonical_message_is_stable_and_domain_separated() {
        // Pin the byte-for-byte shape. If a future refactor reorders
        // keys, drops the domain prefix, or changes the null encoding
        // of batch_id, every existing receipt signature stops
        // verifying, and the cross-language vectors stop matching.
        let receipt = sample_receipt();
        let bytes = receipt_canonical_message(&receipt).unwrap();
        assert!(bytes.starts_with(RECEIPT_DOMAIN_SEP));
        assert_eq!(bytes, receipt_canonical_message(&receipt).unwrap());

        let body = &bytes[RECEIPT_DOMAIN_SEP.len()..];
        let s = std::str::from_utf8(body).unwrap();
        let key_positions: Vec<_> = [
            "batch_id",
            "event_id",
            "payload_hash",
            "server_key_id",
            "server_seq",
            "server_time",
            "sig_alg",
        ]
        .iter()
        .map(|k| s.find(&format!("\"{k}\"")).unwrap())
        .collect();
        let mut sorted = key_positions.clone();
        sorted.sort();
        assert_eq!(key_positions, sorted, "canonical JSON keys must be sorted");
    }

    #[test]
    fn canonical_message_encodes_none_batch_id_as_json_null() {
        // The on-the-wire bytes must distinguish "no batch" (null) from
        // omission. A signer that emits {...,"batch_id":null,...} must
        // disagree byte-for-byte with a signer that emits a string,
        // because the receipt commits to both states distinctly.
        let mut receipt = sample_receipt();
        receipt.batch_id = None;
        let bytes = receipt_canonical_message(&receipt).unwrap();
        let body = std::str::from_utf8(&bytes[RECEIPT_DOMAIN_SEP.len()..]).unwrap();
        assert!(body.contains(r#""batch_id":null"#));
    }

    #[test]
    fn verify_receipt_accepts_a_correctly_signed_receipt() {
        let signing_key = signing_key_seed(0x11);
        let verifying_key = signing_key.verifying_key();

        let mut receipt = sample_receipt();
        sign_receipt(&mut receipt, &signing_key);

        let keystore = Keystore::from_keys(std::iter::once((
            receipt.server_key_id.clone(),
            verifying_key,
        )));
        verify_receipt_against_keystore(7, &receipt, &keystore)
            .expect("valid signature must verify");
    }

    #[test]
    fn verify_receipt_rejects_tampered_payload_hash() {
        // Mutating any signed field after signing must invalidate the
        // signature. This is the whole point of the receipt layer.
        let signing_key = signing_key_seed(0x22);
        let verifying_key = signing_key.verifying_key();

        let mut receipt = sample_receipt();
        sign_receipt(&mut receipt, &signing_key);
        receipt.payload_hash = "ffff".repeat(16);

        let keystore = Keystore::from_keys(std::iter::once((
            receipt.server_key_id.clone(),
            verifying_key,
        )));
        match verify_receipt_against_keystore(7, &receipt, &keystore) {
            Err(ReceiptError::SignatureInvalid { sequence: 7 }) => {}
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn verify_receipt_rejects_unknown_server_key_id() {
        // Keystore lookup must fail loudly when the receipt references
        // a key id we have not seen, rather than fall back to
        // "any valid key in the store" matching.
        let signing_key = signing_key_seed(0x33);
        let mut receipt = sample_receipt();
        sign_receipt(&mut receipt, &signing_key);

        let other_key = signing_key_seed(0x44).verifying_key();
        let keystore =
            Keystore::from_keys(std::iter::once(("some-other-key".to_string(), other_key)));
        match verify_receipt_against_keystore(7, &receipt, &keystore) {
            Err(ReceiptError::KeyUnknown {
                sequence: 7,
                server_key_id,
            }) => {
                assert_eq!(server_key_id, "primary-2025");
            }
            other => panic!("expected KeyUnknown, got {other:?}"),
        }
    }

    #[test]
    fn verify_receipt_rejects_unsupported_sig_alg() {
        let signing_key = signing_key_seed(0x55);
        let verifying_key = signing_key.verifying_key();

        let mut receipt = sample_receipt();
        receipt.sig_alg = "schnorr-secp256k1".to_string();
        sign_receipt(&mut receipt, &signing_key);

        let keystore = Keystore::from_keys(std::iter::once((
            receipt.server_key_id.clone(),
            verifying_key,
        )));
        match verify_receipt_against_keystore(9, &receipt, &keystore) {
            Err(ReceiptError::UnsupportedAlg {
                sequence: 9,
                sig_alg,
            }) => {
                assert_eq!(sig_alg, "schnorr-secp256k1");
            }
            other => panic!("expected UnsupportedAlg, got {other:?}"),
        }
    }

    #[test]
    fn verify_receipt_rejects_malformed_sig_hex() {
        let signing_key = signing_key_seed(0x66);
        let verifying_key = signing_key.verifying_key();

        let mut receipt = sample_receipt();
        receipt.receipt_sig = "not-hex!!".to_string();

        let keystore = Keystore::from_keys(std::iter::once((
            receipt.server_key_id.clone(),
            verifying_key,
        )));
        match verify_receipt_against_keystore(11, &receipt, &keystore) {
            Err(ReceiptError::SigMalformed { sequence: 11, .. }) => {}
            other => panic!("expected SigMalformed, got {other:?}"),
        }
    }

    #[test]
    fn verify_receipt_signature_via_walentry_returns_false_when_no_receipt() {
        use crate::wal_entry::{WalEntry, GENESIS_PREV_HASH};
        let entry = WalEntry {
            format_version: 1,
            sequence: 1,
            timestamp_ns: 1000,
            prev_hash: GENESIS_PREV_HASH.to_string(),
            payload_hash: "abc".repeat(22) + "ab",
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
        let keystore = Keystore::default();
        let got = verify_receipt_signature(&entry, &keystore).unwrap();
        assert!(!got);
    }

    #[test]
    fn keystore_load_from_file_round_trip() {
        let signing_key = signing_key_seed(0x77);
        let pub_hex = hex::encode(signing_key.verifying_key().to_bytes());

        let dir = tempdir();
        let path = dir.join("keystore.json");
        let json = format!(
            r#"{{"schema": "spine-keystore-v1", "keys": {{"primary-2025": "{pub_hex}"}}}}"#
        );
        fs::write(&path, json).unwrap();

        let ks = Keystore::load_from_file(&path).unwrap();
        assert!(ks.lookup("primary-2025").is_some());
        assert!(ks.lookup("not-there").is_none());
        assert_eq!(ks.len(), 1);
    }

    #[test]
    fn keystore_load_rejects_unknown_schema() {
        let dir = tempdir();
        let path = dir.join("keystore.json");
        fs::write(&path, r#"{"schema": "spine-keystore-v999", "keys": {}}"#).unwrap();

        match Keystore::load_from_file(&path) {
            Err(ReceiptError::KeystoreLoad { details, .. }) => {
                assert!(details.contains("unsupported keystore schema"));
            }
            other => panic!("expected KeystoreLoad error, got {other:?}"),
        }
    }

    #[test]
    fn keystore_load_rejects_wrong_pubkey_length() {
        let dir = tempdir();
        let path = dir.join("keystore.json");
        fs::write(
            &path,
            r#"{"schema": "spine-keystore-v1", "keys": {"k": "abcd"}}"#,
        )
        .unwrap();

        match Keystore::load_from_file(&path) {
            Err(ReceiptError::KeystoreLoad { details, .. }) => {
                assert!(details.contains("must be 32 bytes"));
            }
            other => panic!("expected KeystoreLoad error, got {other:?}"),
        }
    }

    // tempfile crate is not in the spine-core dep graph (it would
    // bring rand and friends into the wasm-bound build). The keystore
    // tests need a writable directory, so we roll a minimal scratch
    // helper that scopes the path to the OS temp dir and cleans up on
    // Drop. Test-only, never shipped.
    struct ScratchDir(std::path::PathBuf);
    impl ScratchDir {
        fn join(&self, name: &str) -> std::path::PathBuf {
            self.0.join(name)
        }
    }
    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn tempdir() -> ScratchDir {
        // Counter alone is not enough across parallel test binaries on
        // the same machine; mix in the process id to keep paths unique
        // and avoid the rare collision between two test runs scheduled
        // back-to-back.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("spine-core-receipt-{pid}-{n}"));
        fs::create_dir_all(&path).unwrap();
        ScratchDir(path)
    }
}

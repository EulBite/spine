// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite

//! WAL entry shape and canonical chain primitives.
//!
//! ## Entry hash contract (chain link)
//!
//! [`compute_entry_hash`] covers eight fields in this exact order:
//!
//! 1. `sequence`, 8 bytes little-endian u64
//! 2. `timestamp_ns`, 8 bytes little-endian i64
//! 3. `prev_hash`, UTF-8 bytes of the hex string
//! 4. `payload_hash`, UTF-8 bytes of the hex string
//! 5. `event_type`, 1 presence byte (`0x00` for `None`, `0x01` then UTF-8 bytes for `Some`)
//! 6. `source`, same presence-byte framing as `event_type`
//! 7. `signature`, same presence-byte framing as `event_type`
//! 8. `public_key`, same presence-byte framing as `event_type`
//!
//! Why the presence byte: a producer flipping an optional field from
//! `None` to `Some("")` would otherwise leave the digest unchanged,
//! which lets an editor add semantic content to an already-chained
//! entry without breaking the link. The `0x00` vs `0x01 || bytes`
//! framing makes those two states distinct.
//!
//! The output is BLAKE3 hex-encoded. The chain link compares the
//! hex form because every existing `prev_hash` field on disk is the
//! hex form.
//!
//! ## Sign hash contract
//!
//! [`compute_entry_hash_for_signing`] is the chain-link hash with the
//! two signing fields (`signature`, `public_key`) forced to `None`.
//! Why a separate function: a signer cannot include its own output
//! in the bytes it is about to sign. The signing contract is
//! `Ed25519::sign(signing_key, compute_entry_hash_for_signing(entry).as_bytes())`,
//! so the signature covers the UTF-8 bytes of the hex string of the
//! sign hash. The strict verifier additionally prepends a
//! `b"spine-wal-v1\x00"` domain separator before signing.
//!
//! The verifier MUST call [`compute_entry_hash_for_signing`] (never
//! [`compute_entry_hash`]) when checking a signature on an entry that
//! already carries `signature` and `public_key`. Mixing the two
//! produces a deterministic false negative on every signed entry,
//! which the parity test in `tests/` catches.
//!
//! ## Format version
//!
//! Bump [`WAL_FORMAT_VERSION`] on any breaking change to either hash
//! contract. Verifiers continue to support every prior version.
//!
//! Version history:
//!   1 - Initial 8-field schema with presence framing (2026-05)

use blake3::Hasher;
use serde::{Deserialize, Deserializer, Serialize};

use crate::receipt::Receipt;

/// Genesis block must carry this `prev_hash`: 64 zeros, the hex of 32 null bytes.
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Current WAL format version. Bump on any breaking change to the
/// entry hash contract or to the WalEntry struct shape.
pub const WAL_FORMAT_VERSION: u32 = 1;

#[cfg(feature = "iso-timestamps")]
fn deserialize_timestamp<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum TimestampValue {
        Nanos(i64),
        IsoString(String),
    }

    // The CLI enables this feature so it can read records produced by
    // SDKs that emit ISO 8601 strings. The wasm playground does NOT
    // enable it: demo records are signed offline with i64 nanoseconds,
    // and avoiding chrono keeps the bundle small.
    //
    // Naive timestamps without an explicit timezone are REFUSED.
    // Silently assuming UTC on `"2026-05-27T10:00:00"` would shift a
    // producer in Europe/Rome by 1-2 hours and the verifier would
    // never notice. Producers must emit either RFC 3339 (`...Z` or
    // `...+02:00`) or i64 nanoseconds.
    match TimestampValue::deserialize(deserializer)? {
        TimestampValue::Nanos(ns) => Ok(ns),
        TimestampValue::IsoString(s) => {
            let dt = chrono::DateTime::parse_from_rfc3339(&s).map_err(|e| {
                D::Error::custom(format!(
                    "Invalid timestamp {s:?}: {e}. Naive timestamps without a timezone are refused; \
                     emit either RFC 3339 (with Z or numeric offset) or i64 nanoseconds."
                ))
            })?;

            dt.timestamp_nanos_opt().ok_or_else(|| {
                D::Error::custom(format!(
                    "Timestamp out of range for nanoseconds: {s} (valid range: ~1677-2262 AD)"
                ))
            })
        }
    }
}

#[cfg(not(feature = "iso-timestamps"))]
fn deserialize_timestamp<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    i64::deserialize(deserializer)
}

fn default_format_version() -> u32 {
    1
}

/// Validation result for hex-encoded strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexValidation {
    Valid,
    InvalidLength { expected: usize, actual: usize },
    InvalidChars { position: usize, char: char },
    NonLowercase { position: usize, char: char },
}

/// Validate a hex hash. BLAKE3 hashes are 32 bytes, so 64 hex chars.
/// Lowercase is required: cross-language test vectors emit lowercase
/// and the chain-link compares byte-equal, so an uppercase-emitting
/// producer would silently break verification on every downstream
/// hop. Better to flag the producer than to normalise behind their
/// back.
#[inline]
pub fn validate_hex_hash(hash: &str) -> HexValidation {
    const EXPECTED_LEN: usize = 64;

    if hash.len() != EXPECTED_LEN {
        return HexValidation::InvalidLength {
            expected: EXPECTED_LEN,
            actual: hash.len(),
        };
    }

    for (pos, ch) in hash.chars().enumerate() {
        if !ch.is_ascii_hexdigit() {
            return HexValidation::InvalidChars {
                position: pos,
                char: ch,
            };
        }
        if ch.is_ascii_uppercase() {
            return HexValidation::NonLowercase {
                position: pos,
                char: ch,
            };
        }
    }

    HexValidation::Valid
}

/// Validate the hex fields on an entry: `prev_hash`, `payload_hash`,
/// and (when present) `signature` (128 hex chars for Ed25519) and
/// `public_key` (64 hex chars for an Ed25519 verifying key). Returns
/// a list of human-readable errors, empty when everything checks out.
pub fn validate_entry_hashes(entry: &WalEntry) -> Vec<String> {
    let mut errors = Vec::new();

    match validate_hex_hash(&entry.prev_hash) {
        HexValidation::Valid => {}
        HexValidation::InvalidLength { expected, actual } => {
            errors.push(format!(
                "prev_hash invalid length: expected {expected} chars, got {actual}"
            ));
        }
        HexValidation::InvalidChars { position, char } => {
            errors.push(format!(
                "prev_hash contains invalid char '{char}' at position {position}"
            ));
        }
        HexValidation::NonLowercase { position, char } => {
            errors.push(format!(
                "prev_hash uses uppercase '{char}' at position {position}; lowercase hex required"
            ));
        }
    }

    match validate_hex_hash(&entry.payload_hash) {
        HexValidation::Valid => {}
        HexValidation::InvalidLength { expected, actual } => {
            errors.push(format!(
                "payload_hash invalid length: expected {expected} chars, got {actual}"
            ));
        }
        HexValidation::InvalidChars { position, char } => {
            errors.push(format!(
                "payload_hash contains invalid char '{char}' at position {position}"
            ));
        }
        HexValidation::NonLowercase { position, char } => {
            errors.push(format!(
                "payload_hash uses uppercase '{char}' at position {position}; lowercase hex required"
            ));
        }
    }

    if let Some(ref sig) = entry.signature {
        if sig.len() != 128 {
            errors.push(format!(
                "signature invalid length: expected 128 chars, got {}",
                sig.len()
            ));
        } else if !sig
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            errors.push("signature must be lowercase hex (0-9, a-f)".to_string());
        }
    }

    if let Some(ref pk) = entry.public_key {
        if pk.len() != 64 {
            errors.push(format!(
                "public_key invalid length: expected 64 chars, got {}",
                pk.len()
            ));
        } else if !pk
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            errors.push("public_key must be lowercase hex (0-9, a-f)".to_string());
        }
    }

    errors
}

/// WAL entry as stored on disk.
///
/// Supports both the Spine server WAL format and SDK-shaped records
/// via serde aliases on the canonical fields. The aliases exist so a
/// verifier can ingest records from heterogeneous producers without
/// every producer agreeing on field names upfront.
///
/// ## Alias precedence and last-wins
///
/// When a record contains BOTH the canonical field name and one of
/// its aliases (e.g. both `sequence` and `seq`), serde keeps the
/// LAST occurrence in JSON document order. This is undocumented in
/// serde but stable; a producer that accidentally emits both will
/// see the second value win silently. Lenient verifiers MUST NOT
/// rely on this for security: a record carrying conflicting copies
/// of `payload_hash` and `hash` is a producer bug, and the strict
/// verifier rejects the record outright via the canonical-JSON
/// payload-hash recompute.
///
/// The complete alias set, for reference:
///
/// | Canonical       | Aliases                              |
/// |-----------------|--------------------------------------|
/// | `sequence`      | `seq`                                |
/// | `timestamp_ns`  | `ts_ns`, `ts`, `timestamp`, `ts_client` |
/// | `prev_hash`     | `previous_hash`, `prev`              |
/// | `payload_hash`  | `hash`, `event_hash`                 |
/// | `signature`     | `sig`, `sig_client`                  |
/// | `public_key`    | `pubkey`, `pk`                       |
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WalEntry {
    /// Format version, defaults to 1 for records that predate the field.
    #[serde(default = "default_format_version")]
    pub format_version: u32,

    /// Monotonically increasing sequence number, 1-indexed.
    #[serde(alias = "seq")]
    pub sequence: u64,

    /// Unix timestamp in nanoseconds (or ISO string under the
    /// `iso-timestamps` feature).
    #[serde(
        alias = "ts_ns",
        alias = "ts",
        alias = "timestamp",
        alias = "ts_client"
    )]
    #[serde(deserialize_with = "deserialize_timestamp")]
    pub timestamp_ns: i64,

    /// Hash of the previous entry. The first entry must carry
    /// [`GENESIS_PREV_HASH`].
    #[serde(alias = "previous_hash", alias = "prev")]
    pub prev_hash: String,

    /// Hash of the event payload (hex-encoded BLAKE3).
    #[serde(alias = "hash", alias = "event_hash")]
    pub payload_hash: String,

    /// Optional event type (`user.login`, `auth.failure`, ...).
    /// Part of the chain hash via presence framing.
    #[serde(default)]
    pub event_type: Option<String>,

    /// Optional source system identifier. Part of the chain hash.
    #[serde(default)]
    pub source: Option<String>,

    /// Optional Ed25519 signature over
    /// [`compute_entry_hash_for_signing`] (hex-encoded, 128 chars).
    /// Part of the chain hash via presence framing.
    #[serde(default, alias = "sig", alias = "sig_client")]
    pub signature: Option<String>,

    /// Optional Ed25519 public key that produced `signature`
    /// (hex-encoded, 64 chars). Part of the chain hash via presence
    /// framing.
    #[serde(default, alias = "pubkey", alias = "pk")]
    pub public_key: Option<String>,

    /// Short identifier for the signing key, SDK metadata only,
    /// NOT in the chain hash.
    #[serde(default)]
    pub key_id: Option<String>,

    /// Unique event identifier, SDK metadata only, NOT in the chain hash.
    #[serde(default)]
    pub event_id: Option<String>,

    /// Stream identifier, SDK metadata only, NOT in the chain hash.
    #[serde(default)]
    pub stream_id: Option<String>,

    /// Hash algorithm tag (e.g. `blake3`). NOT part of the chain
    /// hash. Lenient verifier ignores it; the strict verifier in
    /// [`crate::verify_demo`] treats it as a hard gate and rejects
    /// any value other than `"blake3"` (`None` is accepted as
    /// "unspecified, assume blake3").
    #[serde(default)]
    pub hash_alg: Option<String>,

    /// The actual event payload. SDK records carry it; server WAL
    /// records do not. NOT in the chain hash; only `payload_hash` is.
    #[serde(default)]
    pub payload: Option<serde_json::Value>,

    /// Server receipt proving the event was accepted. SDK records
    /// carry it; the receipt itself is signed separately via
    /// [`crate::receipt::verify_receipt_signature`] and is NOT in the
    /// chain hash.
    #[serde(default)]
    pub receipt: Option<Receipt>,
}

// Why a helper rather than inline `if let` blocks: every optional
// field included in the chain hash must use identical framing or
// producer and verifier silently disagree on byte position. Funneling
// the four optional fields through one function makes it impossible
// to forget the presence byte on a future field.
#[inline]
fn hash_optional(hasher: &mut Hasher, field: Option<&str>) {
    match field {
        Some(s) => {
            hasher.update(b"\x01");
            hasher.update(s.as_bytes());
        }
        None => {
            hasher.update(b"\x00");
        }
    }
}

/// Compute the chain-link hash of a WAL entry, raw 32 bytes.
///
/// See module docs for the field-ordering contract. Output MUST stay
/// stable across versions: any change breaks chain verification for
/// every existing WAL file.
#[inline]
pub fn compute_entry_hash_raw(entry: &WalEntry) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&entry.sequence.to_le_bytes());
    hasher.update(&entry.timestamp_ns.to_le_bytes());
    hasher.update(entry.prev_hash.as_bytes());
    hasher.update(entry.payload_hash.as_bytes());
    hash_optional(&mut hasher, entry.event_type.as_deref());
    hash_optional(&mut hasher, entry.source.as_deref());
    hash_optional(&mut hasher, entry.signature.as_deref());
    hash_optional(&mut hasher, entry.public_key.as_deref());
    *hasher.finalize().as_bytes()
}

/// Hex view of [`compute_entry_hash_raw`].
///
/// Kept separate because the on-disk `prev_hash` field is the hex
/// form, so chain-link comparisons walk textual values.
#[inline]
pub fn compute_entry_hash(entry: &WalEntry) -> String {
    hex::encode(compute_entry_hash_raw(entry))
}

/// Compute the hash the signer signs, raw 32 bytes.
///
/// Same envelope as [`compute_entry_hash_raw`] but with `signature`
/// and `public_key` forced to `None` because a signature cannot
/// reference its own output. See module docs for the full contract.
#[inline]
pub fn compute_entry_hash_for_signing_raw(entry: &WalEntry) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&entry.sequence.to_le_bytes());
    hasher.update(&entry.timestamp_ns.to_le_bytes());
    hasher.update(entry.prev_hash.as_bytes());
    hasher.update(entry.payload_hash.as_bytes());
    hash_optional(&mut hasher, entry.event_type.as_deref());
    hash_optional(&mut hasher, entry.source.as_deref());
    // signature and public_key fed as None on purpose: see module docs.
    hash_optional(&mut hasher, None);
    hash_optional(&mut hasher, None);
    *hasher.finalize().as_bytes()
}

/// Hex view of [`compute_entry_hash_for_signing_raw`].
#[inline]
pub fn compute_entry_hash_for_signing(entry: &WalEntry) -> String {
    hex::encode(compute_entry_hash_for_signing_raw(entry))
}

/// Compute the chain root by streaming entry hashes (oldest first).
///
/// The caller must supply hashes in strict sequence order. A different
/// order produces a different root, which is intentional: the root
/// commits to both content and ordering.
pub fn compute_chain_root<I, S>(entry_hashes: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut hasher = Hasher::new();
    for hash in entry_hashes {
        hasher.update(hash.as_ref().as_bytes());
    }
    hex::encode(hasher.finalize().as_bytes())
}

/// Convenience: chain root directly from a slice of entries.
pub fn compute_chain_root_from_entries(entries: &[WalEntry]) -> String {
    let hashes = entries.iter().map(compute_entry_hash);
    compute_chain_root(hashes)
}

/// Result of a single chain-link verification step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashVerification {
    Valid,
    Mismatch { expected: String, actual: String },
    InvalidGenesis { reason: String },
}

/// Verify that `current.prev_hash` links back to `previous`.
///
/// For the first entry (no `previous`), enforces both `sequence == 1`
/// and `prev_hash == GENESIS_PREV_HASH`. The order of those two
/// checks affects which error the caller sees first, which is why
/// the test suite covers both.
pub fn verify_chain_link(current: &WalEntry, previous: Option<&WalEntry>) -> HashVerification {
    match previous {
        None => {
            if current.sequence != 1 {
                return HashVerification::InvalidGenesis {
                    reason: format!(
                        "genesis must have sequence=1, found sequence={}",
                        current.sequence
                    ),
                };
            }
            if current.prev_hash != GENESIS_PREV_HASH {
                return HashVerification::InvalidGenesis {
                    reason: format!(
                        "genesis prev_hash must be {}, found {}",
                        &GENESIS_PREV_HASH[..16],
                        &current.prev_hash
                    ),
                };
            }
            HashVerification::Valid
        }
        Some(prev) => {
            let expected = compute_entry_hash(prev);
            if current.prev_hash == expected {
                HashVerification::Valid
            } else {
                HashVerification::Mismatch {
                    expected,
                    actual: current.prev_hash.clone(),
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn make_entry(seq: u64, ts: i64, prev: &str, payload: &str) -> WalEntry {
        WalEntry {
            format_version: 1,
            sequence: seq,
            timestamp_ns: ts,
            prev_hash: prev.to_string(),
            payload_hash: payload.to_string(),
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
        }
    }

    #[test]
    fn entry_hash_is_deterministic() {
        let entry = make_entry(1, 1000, GENESIS_PREV_HASH, "payload");
        assert_eq!(compute_entry_hash(&entry), compute_entry_hash(&entry));
        assert_eq!(compute_entry_hash(&entry).len(), 64);
    }

    #[test]
    fn entry_hash_is_sensitive_to_every_core_field() {
        let base = make_entry(1, 1000, GENESIS_PREV_HASH, "payload");

        let mut bumped_seq = base.clone();
        bumped_seq.sequence = 2;
        assert_ne!(compute_entry_hash(&base), compute_entry_hash(&bumped_seq));

        let mut bumped_ts = base.clone();
        bumped_ts.timestamp_ns = 2000;
        assert_ne!(compute_entry_hash(&base), compute_entry_hash(&bumped_ts));

        let mut bumped_prev = base.clone();
        bumped_prev.prev_hash = "ff".repeat(32);
        assert_ne!(compute_entry_hash(&base), compute_entry_hash(&bumped_prev));

        let mut bumped_payload = base.clone();
        bumped_payload.payload_hash = "different".into();
        assert_ne!(
            compute_entry_hash(&base),
            compute_entry_hash(&bumped_payload)
        );
    }

    #[test]
    fn entry_hash_covers_all_four_optional_fields_independently() {
        // Each of event_type, source, signature, public_key must
        // contribute on its own. A regression that drops any of them
        // would let an editor mutate that field post-signature without
        // invalidating the chain link.
        let base = make_entry(1, 1000, GENESIS_PREV_HASH, "payload");
        let base_hash = compute_entry_hash(&base);

        for mutate in [
            |e: &mut WalEntry| e.event_type = Some("login".into()),
            |e: &mut WalEntry| e.source = Some("auth".into()),
            |e: &mut WalEntry| e.signature = Some("a".repeat(128)),
            |e: &mut WalEntry| e.public_key = Some("b".repeat(64)),
        ] {
            let mut variant = base.clone();
            mutate(&mut variant);
            assert_ne!(compute_entry_hash(&variant), base_hash);
        }
    }

    #[test]
    fn presence_byte_distinguishes_none_from_empty_string() {
        // A naive framing that emits zero bytes for both None and
        // Some("") would let a producer flip the two without changing
        // the digest, which is a chain-link forgery primitive. Pin
        // the distinction here.
        let mut none_entry = make_entry(1, 1000, GENESIS_PREV_HASH, "payload");
        none_entry.event_type = None;

        let mut empty_entry = make_entry(1, 1000, GENESIS_PREV_HASH, "payload");
        empty_entry.event_type = Some(String::new());

        assert_ne!(
            compute_entry_hash(&none_entry),
            compute_entry_hash(&empty_entry)
        );
    }

    #[test]
    fn sign_hash_ignores_signature_and_public_key() {
        // The sign hash MUST be invariant under signature and
        // public_key, otherwise the signer is asked to commit to its
        // own output and the verifier can never reproduce the message.
        let mut a = make_entry(1, 1000, GENESIS_PREV_HASH, "payload");
        a.event_type = Some("login".into());
        a.source = Some("auth".into());

        let mut b = a.clone();
        b.signature = Some("a".repeat(128));
        b.public_key = Some("b".repeat(64));

        assert_eq!(
            compute_entry_hash_for_signing(&a),
            compute_entry_hash_for_signing(&b)
        );
    }

    #[test]
    fn sign_hash_differs_from_chain_hash_when_signature_present() {
        // The whole point of the sign/chain split: when an entry is
        // signed, the two hashes diverge. When it is unsigned, they
        // coincide.
        let mut unsigned = make_entry(1, 1000, GENESIS_PREV_HASH, "payload");
        unsigned.event_type = Some("login".into());

        assert_eq!(
            compute_entry_hash(&unsigned),
            compute_entry_hash_for_signing(&unsigned),
            "unsigned entry: chain hash and sign hash must coincide"
        );

        let mut signed = unsigned.clone();
        signed.signature = Some("a".repeat(128));
        signed.public_key = Some("b".repeat(64));

        assert_ne!(
            compute_entry_hash(&signed),
            compute_entry_hash_for_signing(&signed),
            "signed entry: chain hash includes signature, sign hash does not"
        );
    }

    #[test]
    fn verify_genesis_accepts_correct_prev_hash_and_sequence() {
        let genesis = make_entry(1, 1000, GENESIS_PREV_HASH, "payload");
        assert_eq!(verify_chain_link(&genesis, None), HashVerification::Valid);
    }

    #[test]
    fn verify_genesis_rejects_non_zero_prev_hash() {
        let bad = make_entry(1, 1000, "not_zero", "payload");
        match verify_chain_link(&bad, None) {
            HashVerification::InvalidGenesis { reason } => assert!(reason.contains("prev_hash")),
            other => panic!("expected InvalidGenesis, got {other:?}"),
        }
    }

    #[test]
    fn verify_genesis_rejects_wrong_sequence() {
        let bad = make_entry(42, 1000, GENESIS_PREV_HASH, "payload");
        match verify_chain_link(&bad, None) {
            HashVerification::InvalidGenesis { reason } => {
                assert!(reason.contains("sequence"));
                assert!(reason.contains("42"));
            }
            other => panic!("expected InvalidGenesis, got {other:?}"),
        }
    }

    #[test]
    fn verify_chain_link_accepts_valid_link() {
        let e1 = make_entry(1, 1000, GENESIS_PREV_HASH, "payload1");
        let h1 = compute_entry_hash(&e1);
        let e2 = make_entry(2, 2000, &h1, "payload2");

        assert_eq!(verify_chain_link(&e2, Some(&e1)), HashVerification::Valid);
    }

    #[test]
    fn verify_chain_link_rejects_mismatch() {
        let e1 = make_entry(1, 1000, GENESIS_PREV_HASH, "payload1");
        let e2 = make_entry(2, 2000, "wrong_hash", "payload2");

        assert!(matches!(
            verify_chain_link(&e2, Some(&e1)),
            HashVerification::Mismatch { .. }
        ));
    }

    #[test]
    fn chain_root_is_deterministic_and_order_sensitive() {
        let hashes = vec!["a", "b", "c"];
        assert_eq!(compute_chain_root(&hashes), compute_chain_root(&hashes));
        assert_ne!(
            compute_chain_root(vec!["a", "b"]),
            compute_chain_root(vec!["b", "a"])
        );
    }

    #[test]
    fn chain_root_from_entries_matches_manual_pipeline() {
        let e1 = make_entry(1, 1000, GENESIS_PREV_HASH, "payload1");
        let h1 = compute_entry_hash(&e1);
        let e2 = make_entry(2, 2000, &h1, "payload2");

        let entries = vec![e1.clone(), e2.clone()];

        let root = compute_chain_root_from_entries(&entries);
        let manual = compute_chain_root(vec![compute_entry_hash(&e1), compute_entry_hash(&e2)]);

        assert_eq!(root, manual);
    }

    #[test]
    fn validate_hex_hash_accepts_canonical_inputs() {
        assert_eq!(validate_hex_hash(GENESIS_PREV_HASH), HexValidation::Valid);
        assert_eq!(
            validate_hex_hash("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
            HexValidation::Valid
        );
    }

    #[test]
    fn validate_hex_hash_rejects_wrong_length() {
        assert!(matches!(
            validate_hex_hash("abc"),
            HexValidation::InvalidLength { .. }
        ));
    }

    #[test]
    fn validate_hex_hash_rejects_non_hex_chars() {
        assert!(matches!(
            validate_hex_hash("ghij567890abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            HexValidation::InvalidChars {
                position: 0,
                char: 'g'
            }
        ));
    }

    #[test]
    fn validate_hex_hash_rejects_uppercase() {
        // Uppercase is valid hex but the chain compares byte-equal,
        // so a producer emitting uppercase silently breaks every
        // downstream verifier. Flag at the first uppercase character.
        assert!(matches!(
            validate_hex_hash("ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789"),
            HexValidation::NonLowercase {
                position: 0,
                char: 'A'
            }
        ));
    }

    #[test]
    fn validate_entry_hashes_clean_entry_has_no_errors() {
        let entry = make_entry(1, 1000, GENESIS_PREV_HASH, GENESIS_PREV_HASH);
        assert!(validate_entry_hashes(&entry).is_empty());
    }

    #[test]
    fn validate_entry_hashes_accumulates_multiple_field_errors() {
        let entry = make_entry(1, 1000, "bad_prev", "bad_payload");
        let errors = validate_entry_hashes(&entry);
        assert_eq!(errors.len(), 2);
    }
}

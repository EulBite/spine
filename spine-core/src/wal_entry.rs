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
//! 5. `event_type`, an optional field (framing depends on version)
//! 6. `source`, same framing as `event_type`
//! 7. `signature`, same framing as `event_type`
//! 8. `public_key`, same framing as `event_type`
//!
//! ## How an optional field is framed, and why it has two versions
//!
//! An optional field has to encode three distinct states without
//! collisions: absent, present-but-empty, and present-with-content.
//! `None` is encoded as a single `0x00` byte; `Some` as `0x01`
//! followed by the value. The presence byte exists because a producer
//! flipping a field from `None` to `Some("")` would otherwise leave
//! the digest unchanged, which lets an editor add semantic content to
//! an already-chained entry without breaking the link.
//!
//! The presence byte alone is not enough. In format version 1 a
//! `Some` field was encoded as `0x01 || value` with no length, so the
//! four optional fields were concatenated with nothing marking where
//! one ended and the next began. A value that itself contained a
//! `0x01` byte could imitate the presence marker of the field after
//! it, so two semantically different entries could hash to the same
//! digest. Concretely, `{event_type: "a", source: "b\u{1}c"}` and
//! `{event_type: "a\u{1}b", source: "c"}` produced identical bytes.
//! `event_type` and `source` carry arbitrary operator-supplied text,
//! so that collision was reachable from real ingest, not just a
//! theoretical edge case.
//!
//! Format version 2 fixes this by length-prefixing every `Some`
//! value: `0x01 || u64_LE(len) || value`. The length is read before
//! the bytes, so a `0x01` inside a value can never be mistaken for the
//! start of the next field. The width matches `sequence` and
//! `timestamp_ns` (both 8-byte little-endian) so a producer in any
//! language frames every variable-length field the same way.
//!
//! Verifiers keep both encodings: an entry is hashed with the encoding
//! that matches its own `format_version`, so version-1 WAL files
//! already on disk (and the published demo) keep verifying unchanged
//! while new producers emit the collision-free version-2 framing.
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
//! contract. Verifiers keep supporting every prior version listed in
//! [`SUPPORTED_WAL_FORMAT_VERSIONS`].
//!
//! Version history:
//!   1 - Initial 8-field schema, optional fields framed `0x01 || value`
//!       with no length prefix (2026-05). Retained for already-emitted
//!       WAL files; not collision-free, see above.
//!   2 - Optional fields length-prefixed `0x01 || u64_LE(len) || value`,
//!       which makes the entry hash injective (2026-06).

use blake3::Hasher;
use serde::{Deserialize, Deserializer, Serialize};

use crate::receipt::Receipt;

/// Genesis block must carry this `prev_hash`: 64 zeros, the hex of 32 null bytes.
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Current WAL format version that new producers should emit. Bump on
/// any breaking change to the entry hash contract or to the WalEntry
/// struct shape.
pub const WAL_FORMAT_VERSION: u32 = 2;

/// Every format version this build can verify. A WAL entry is hashed
/// with the encoding that matches its own `format_version`, so older
/// files keep verifying after a bump. Listed newest-first only for
/// readability; membership is what matters.
pub const SUPPORTED_WAL_FORMAT_VERSIONS: &[u32] = &[2, 1];

/// Whether this build can verify entries of the given format version.
#[inline]
#[must_use]
pub fn is_supported_format_version(version: u32) -> bool {
    SUPPORTED_WAL_FORMAT_VERSIONS.contains(&version)
}

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

/// Reject ASCII control characters in a free-text field that goes into
/// the entry hash. Returns the offending code point's position, or
/// `None` when the field is clean.
///
/// Why this gate exists even though version 2 framing is already
/// injective: a `U+0001` byte inside `event_type` or `source` is what
/// made the version-1 hash collide (it imitated the next field's
/// presence marker). Version-1 WAL files keep being verified for
/// backward compatibility, so without this check a forged version-1
/// collision would still pass. Control characters carry no legitimate
/// meaning in these short identifier fields (`user.login`, `auth`),
/// so refusing the whole C0 range plus DEL costs nothing and closes
/// the collision for every version, not just the new one.
fn first_control_char(value: &str) -> Option<(usize, char)> {
    value
        .chars()
        .enumerate()
        .find(|(_, c)| c.is_control() && (*c as u32) <= 0x7f)
}

/// Validate the hex fields on an entry (`prev_hash`, `payload_hash`,
/// and the optional `signature`/`public_key`) plus the free-text
/// `event_type`/`source` fields. Returns a list of human-readable
/// errors, empty when everything checks out.
pub fn validate_entry_hashes(entry: &WalEntry) -> Vec<String> {
    let mut errors = Vec::new();

    for (name, value) in [
        ("event_type", entry.event_type.as_deref()),
        ("source", entry.source.as_deref()),
    ] {
        if let Some(v) = value {
            if let Some((pos, ch)) = first_control_char(v) {
                errors.push(format!(
                    "{name} contains a control character U+{:04X} at position {pos}; \
                     control characters are refused because they can forge a hash \
                     collision in version-1 framing",
                    ch as u32
                ));
            }
        }
    }

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
// to forget the presence byte (or, in version 2, the length prefix)
// on a future field.
//
// `version` selects the framing: version 1 is the original
// `0x01 || value`, kept so already-emitted WAL files still verify;
// version 2 length-prefixes the value (`0x01 || u64_LE(len) || value`)
// so a `0x01` inside the value cannot be confused with the next
// field's presence marker. See module docs for the collision this
// closes.
#[inline]
fn hash_optional(hasher: &mut Hasher, field: Option<&str>, version: u32) {
    match field {
        Some(s) => {
            hasher.update(b"\x01");
            if version >= 2 {
                // `s.len()` is the UTF-8 byte length, which is exactly
                // how many bytes follow. Fixed 8-byte width keeps the
                // frame the same in every producer language.
                hasher.update(&(s.len() as u64).to_le_bytes());
            }
            hasher.update(s.as_bytes());
        }
        None => {
            hasher.update(b"\x00");
        }
    }
}

/// Compute the chain-link hash of a WAL entry, raw 32 bytes.
///
/// The optional-field framing is chosen by `entry.format_version` so a
/// verifier reproduces exactly the bytes the producer committed to:
/// version-1 records hash with the original framing, version-2 records
/// with the length-prefixed framing. See module docs for the contract.
/// The encoding for a given version MUST stay stable forever: changing
/// it breaks chain verification for every WAL file emitted under that
/// version.
#[inline]
pub fn compute_entry_hash_raw(entry: &WalEntry) -> [u8; 32] {
    let v = entry.format_version;
    let mut hasher = Hasher::new();
    hasher.update(&entry.sequence.to_le_bytes());
    hasher.update(&entry.timestamp_ns.to_le_bytes());
    hasher.update(entry.prev_hash.as_bytes());
    hasher.update(entry.payload_hash.as_bytes());
    hash_optional(&mut hasher, entry.event_type.as_deref(), v);
    hash_optional(&mut hasher, entry.source.as_deref(), v);
    hash_optional(&mut hasher, entry.signature.as_deref(), v);
    hash_optional(&mut hasher, entry.public_key.as_deref(), v);
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
    let v = entry.format_version;
    let mut hasher = Hasher::new();
    hasher.update(&entry.sequence.to_le_bytes());
    hasher.update(&entry.timestamp_ns.to_le_bytes());
    hasher.update(entry.prev_hash.as_bytes());
    hasher.update(entry.payload_hash.as_bytes());
    hash_optional(&mut hasher, entry.event_type.as_deref(), v);
    hash_optional(&mut hasher, entry.source.as_deref(), v);
    // signature and public_key fed as None on purpose: see module docs.
    hash_optional(&mut hasher, None, v);
    hash_optional(&mut hasher, None, v);
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

    fn make_entry_versioned(
        version: u32,
        seq: u64,
        ts: i64,
        prev: &str,
        payload: &str,
    ) -> WalEntry {
        WalEntry {
            format_version: version,
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

    // Default to the current emit version so new tests exercise the
    // version-2 framing; tests that care about a specific version call
    // `make_entry_versioned` directly.
    fn make_entry(seq: u64, ts: i64, prev: &str, payload: &str) -> WalEntry {
        make_entry_versioned(WAL_FORMAT_VERSION, seq, ts, prev, payload)
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

    #[test]
    fn version_1_framing_is_not_injective() {
        // The defect that motivated version 2: with `0x01 || value` and
        // no length prefix, a `U+0001` inside one field imitates the
        // presence marker of the next, so two semantically different
        // entries hash to the same digest. Pin the collision so we
        // never reintroduce this framing as the default.
        let mut a = make_entry_versioned(1, 1, 1000, GENESIS_PREV_HASH, "payload");
        a.event_type = Some("a".into());
        a.source = Some("b\u{1}c".into());

        let mut b = make_entry_versioned(1, 1, 1000, GENESIS_PREV_HASH, "payload");
        b.event_type = Some("a\u{1}b".into());
        b.source = Some("c".into());

        assert_eq!(
            compute_entry_hash(&a),
            compute_entry_hash(&b),
            "version-1 framing collides on the documented U+0001 input"
        );
    }

    #[test]
    fn version_2_framing_is_injective_on_the_version_1_collision() {
        // Same two entries as the collision above, now framed as
        // version 2: the length prefix records where `source` ends, so
        // the two distinct field splits produce distinct digests.
        let mut a = make_entry_versioned(2, 1, 1000, GENESIS_PREV_HASH, "payload");
        a.event_type = Some("a".into());
        a.source = Some("b\u{1}c".into());

        let mut b = make_entry_versioned(2, 1, 1000, GENESIS_PREV_HASH, "payload");
        b.event_type = Some("a\u{1}b".into());
        b.source = Some("c".into());

        assert_ne!(
            compute_entry_hash(&a),
            compute_entry_hash(&b),
            "version-2 length prefix must break the version-1 collision"
        );
    }

    #[test]
    fn version_1_and_version_2_hash_the_same_fields_differently() {
        // A bump must actually change the bytes, otherwise dispatching
        // on the version would be pointless. Use a value with no
        // control characters so the only difference is the framing.
        let mut v1 = make_entry_versioned(1, 1, 1000, GENESIS_PREV_HASH, "payload");
        v1.event_type = Some("login".into());

        let mut v2 = v1.clone();
        v2.format_version = 2;

        assert_ne!(compute_entry_hash(&v1), compute_entry_hash(&v2));
    }

    #[test]
    fn version_2_length_prefix_separates_otherwise_ambiguous_splits() {
        // A second, control-char-free witness that the length prefix is
        // what carries the field boundary: "ab" + "c" must not hash the
        // same as "a" + "bc" under version 2.
        let mut left = make_entry_versioned(2, 1, 1000, GENESIS_PREV_HASH, "payload");
        left.event_type = Some("ab".into());
        left.source = Some("c".into());

        let mut right = make_entry_versioned(2, 1, 1000, GENESIS_PREV_HASH, "payload");
        right.event_type = Some("a".into());
        right.source = Some("bc".into());

        assert_ne!(compute_entry_hash(&left), compute_entry_hash(&right));
    }

    #[test]
    fn validate_entry_hashes_rejects_control_chars_in_free_text() {
        // The defense-in-depth gate: even a version-1 entry carrying the
        // collision byte must be refused, so an attacker cannot exploit
        // the retained version-1 framing.
        let mut entry = make_entry(1, 1000, GENESIS_PREV_HASH, GENESIS_PREV_HASH);
        entry.source = Some("b\u{1}c".into());

        let errors = validate_entry_hashes(&entry);
        assert!(
            errors.iter().any(|e| e.contains("control character")),
            "expected a control-character error, got {errors:?}"
        );
    }

    #[test]
    fn validate_entry_hashes_allows_ordinary_identifiers() {
        // The gate must not flag legitimate event types or sources.
        let mut entry = make_entry(1, 1000, GENESIS_PREV_HASH, GENESIS_PREV_HASH);
        entry.event_type = Some("user.login".into());
        entry.source = Some("auth-service".into());

        assert!(validate_entry_hashes(&entry).is_empty());
    }

    #[test]
    fn supported_versions_cover_one_and_two() {
        assert!(is_supported_format_version(1));
        assert!(is_supported_format_version(2));
        assert!(!is_supported_format_version(0));
        assert!(!is_supported_format_version(3));
    }
}

# Spine Test Vectors

Language-independent test vectors for the Spine WAL verifier. Any
implementation that intends to talk to the public Spine envelope MUST
reproduce every value listed in `vectors.json` exactly.

The vectors are the regression net for the four primitives the
verifier stack depends on: canonical JSON, the chain-link entry
hash, the sign hash, and the receipt canonical message. Divergence
on any of them is a credibility-ending bug, so this file is the
first thing to update when the spec evolves and the last thing to
look at when a new implementation refuses to verify a known-good WAL.

## Two verifier profiles

Spine ships two verifiers with deliberately different threat models:

- **Lenient verifier** (`spine-core::verify_wal_bytes`). Used by the
  standalone CLI auditor on production WAL files. Tolerates unsigned
  records, treats `expected_root` as optional, and does not require
  external public-key pinning (an optional `trusted_pubkey` pin is
  available but off by default).
- **Strict demo verifier** (`spine-core::verify_demo_wal`). Used by
  the public WASM playground. Requires every record signed, an
  externally pinned public key, a mandatory `expected_root`, and a
  payload-hash recompute from canonical JSON.

When a section below applies to only one profile, it is labelled.

## Schema overview

`vectors.json` has the shape

```json
{
  "schema_version": 1,
  "wal_format_version": 1,
  "canonical_json": { "cases": [ ... ] },
  "entry_hash": { "cases": [ ... ] },
  "sign_hash": { "cases": [ ... ] },
  "chain_root": { "cases": [ ... ] },
  "receipt_canonical_message": { "cases": [ ... ] },
  "signature": { "cases": [ ... ] }
}
```

Each section pins a primitive. A case is the smallest input that
exercises a single rule of the contract. All hex strings are
lowercase. All byte counts assume UTF-8.

## 1. Canonical JSON (strict profile)

The strict verifier recomputes `payload_hash` from the canonical
form. The lenient verifier does NOT canonicalise: it trusts the
on-disk `payload_hash`. Cross-language parity therefore matters
mostly for strict-stack consumers and for SDKs that produce records
to be verified strictly.

Implementations MUST produce the byte-for-byte sequence in
`expected_canonical_json_utf8` for every case in
`canonical_json.cases`. Rules mirror `spine-core/src/canonical.rs`:

- Strings are normalised to Unicode NFC before serialisation, both
  for object keys and for string values.
- Object keys are sorted by UTF-16 code-unit order (matches
  `Array.prototype.sort()` in JavaScript). For BMP characters
  (U+0000 .. U+FFFF) this coincides with UTF-8 byte order. For
  supplementary characters (>= U+10000) it does not: supplementary
  characters sort before U+E000..U+FFFF.
- Strings are escaped per RFC 8259 (matches `JSON.stringify`).
- Forward slash `/` is not escaped.
- Integers in `i64` range and integer-valued floats (`2.0`, `-0`)
  serialise as decimal digits without a decimal point. Non-integer
  floats are rejected: payloads must encode monetary or fractional
  values as strings (`"amount":"100.00"`).
- No whitespace between tokens.

## 2. Payload hash (strict profile)

```
payload_hash = BLAKE3(canonical_json(payload))
```

Output: 64-char lowercase hex (256 bits). The strict verifier
rejects any record whose declared `payload_hash` field disagrees
with this recompute.

## 3. Entry hash (shared)

Both verifiers compute the chain-link hash identically. The
contract pins eight fields in order:

```
entry_hash_raw = BLAKE3(
    seq.to_le_bytes(8)             ||  // u64 little-endian
    timestamp_ns.to_le_bytes(8)    ||  // i64 little-endian
    prev_hash.as_utf8_bytes()      ||  // hex string of predecessor entry hash, UTF-8
    payload_hash.as_utf8_bytes()   ||  // hex string of payload hash, UTF-8
    presence(event_type)           ||
    presence(source)               ||
    presence(signature)            ||
    presence(public_key)
)
```

where the presence framing for an optional string field is

```
presence(None)         = b"\x00"
presence(Some(s))      = b"\x01" || s.as_utf8_bytes()
```

`entry_hash_raw` is 32 raw bytes. The hex form (64 chars lowercase)
is what gets stored as the next record's `prev_hash` field, and is
the per-record input the `chain_root` accumulator hashes over (§7).
It is not itself the `chain_root`.

The presence byte distinguishes `None` from `Some("")` so a producer
cannot flip the two without changing the digest. A regression that
drops the framing silently loses that distinction and re-opens the
chain-link forgery primitive the framing was introduced to close.

## 4. Sign hash (shared)

The hash that signers actually sign. Same envelope as the chain-link
hash but with the two signing fields forced to `None`:

```
sign_hash_raw = BLAKE3(
    seq.to_le_bytes(8)             ||
    timestamp_ns.to_le_bytes(8)    ||
    prev_hash.as_utf8_bytes()      ||
    payload_hash.as_utf8_bytes()   ||
    presence(event_type)           ||
    presence(source)               ||
    b"\x00"                        ||  // signature forced to None
    b"\x00"                            // public_key forced to None
)
```

Why a separate hash: a signer cannot include its own output in the
bytes it is about to sign. Verifiers MUST use this hash (never the
chain-link hash) when checking a signature on an entry that already
carries `signature` and `public_key`.

When an entry is unsigned the chain hash and sign hash coincide.
When an entry is signed they diverge by exactly the contribution of
the `signature` and `public_key` presence-framed bytes.

## 5. Signature

Both profiles use Ed25519. They differ on the message that gets
signed:

### 5a. Lenient

```
signed_message = sign_hash_hex.as_utf8_bytes()
```

Where `sign_hash_hex` is the 64-char lowercase hex of `sign_hash_raw`.
The signed message is therefore 64 UTF-8 bytes. No domain separator.

### 5b. Strict demo

```
signed_message = b"spine-wal-v1\x00" || sign_hash_hex.as_utf8_bytes()
```

A 13-byte version prefix followed by the same 64 UTF-8 bytes as in
the lenient case. Total signed length is 77 bytes.

The domain prefix is intentionally incompatible with the lenient
contract: a strict-issued signature does not validate in lenient
mode and a lenient-issued signature does not validate in strict
mode. Cross-protocol confusion attacks are not even theoretically
possible.

## 6. Receipt canonical message

The signed bytes that produce `Receipt::receipt_sig` are

```
receipt_canonical_message = b"spine-receipt-v1\x00" || serde_json(BTreeMap)
```

The map carries seven keys, sorted alphabetically by `BTreeMap`:
`batch_id`, `event_id`, `payload_hash`, `server_key_id`,
`server_seq`, `server_time`, `sig_alg`. `batch_id` encodes as JSON
`null` when `Receipt.batch_id` is `None`. `receipt_sig` is
intentionally excluded.

## 7. Chain root

```
chain_root = BLAKE3(entry_hash_hex_1 || entry_hash_hex_2 || ... || entry_hash_hex_N)
```

The accumulator commits to both content and ordering.

## Verification checklist

Your implementation matches the spec if, for every case in
`vectors.json`:

1. `canonical_json(case.input)` equals `case.expected_canonical_json_utf8`
2. `BLAKE3(canonical_json)` equals `case.expected_payload_hash`
3. `compute_entry_hash_raw(...)` equals the raw bytes of
   `case.expected_entry_hash`
4. `compute_entry_hash_for_signing_raw(...)` equals the raw bytes of
   `case.expected_sign_hash`
5. `receipt_canonical_message(...)` matches
   `case.expected_canonical_message_hex` byte-for-byte
6. `chain_root` over the listed entries matches
   `case.expected_root`
7. Both signature contracts verify on their respective
   `signature.cases`

## Regenerating

`vectors.json` is produced by the `gen_fixture` example in
`spine-core/`:

```
cd spine-core
cargo run --example gen_fixture -- --output ../test-vectors/vectors.json
```

The companion test `spine-core/tests/cross_language_vectors.rs`
re-loads the file and asserts that the Rust implementation still
matches every pinned value.

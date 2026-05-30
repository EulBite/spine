// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite

//! Canonical JSON serialization for the strict verifier.
//!
//! A deliberate **subset** of RFC 8785 (JCS). The strict verifier
//! recomputes `payload_hash` from this canonical form, so the emitted
//! byte sequence is a cryptographic contract: any drift changes a hash
//! and breaks verification. That is why the module is small, audited
//! carefully, and pinned by the cross-language test vectors in
//! `test-vectors/vectors.json`, which any independent implementation
//! must reproduce byte-for-byte.
//!
//! ## Supported subset
//!
//! - **Strings**: escaped per RFC 8259 (matches `JSON.stringify`); content is
//!   normalized to **Unicode NFC** before serialization.
//! - **Integers** in `i64` range, plus `u64` values above `i64::MAX`.
//!   Output: decimal digits, no leading sign for non-negative, no decimal
//!   point. Matches `String(integer)` in JavaScript.
//! - **Booleans**: `true` / `false`.
//! - **Null**: `null`.
//! - **Arrays**: `[item1,item2,…]`, no whitespace.
//! - **Objects**: keys NFC-normalized, then sorted by **UTF-16 code unit
//!   order** (matches `Array.prototype.sort()` in JS), serialized as
//!   `{"k1":v1,"k2":v2,…}`, no whitespace.
//!
//! Numbers must be integer-valued AND representable as an `i64`. A JSON
//! float with a whole value such as `2.0` or `-0` is accepted and
//! serialized without a decimal point (matching `Number.isInteger`), but
//! only when it maps to an `i64` exactly. A finite non-integer is rejected
//! with [`CanonicalError::NonIntegerNumber`]; an integer-valued float
//! outside `i64` range is rejected with [`CanonicalError::NumberOutOfRange`]
//! (saturating it would let two distinct payloads canonicalize to the same
//! bytes, so the canonical form would no longer be injective). NaN / Infinity
//! cannot occur because `serde_json::Value::Number` rejects them at parse
//! time. This is intentional: the demo WAL encodes monetary amounts as strings (e.g.
//! `"amount": "100.00"`), sidestepping ECMA-262 `NumberToString` quirks
//! entirely.
//!
//! ## Subtlety: UTF-16 vs UTF-8 key ordering
//!
//! For BMP code points (U+0000 .. U+FFFF) UTF-16 and UTF-8 byte ordering
//! coincide. For supplementary characters (≥ U+10000) they diverge: UTF-16
//! places the high surrogate in the [D800..DBFF] range, so a supplementary
//! character sorts between U+D7FF and U+E000, whereas in UTF-8 byte order it
//! would sort after U+FFFF. This module normalises everything through
//! `encode_utf16().collect::<Vec<u16>>()` and compares those, so the result
//! matches `Array.prototype.sort()` exactly.

use serde_json::Value;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CanonicalError {
    #[error("invalid JSON: {0}")]
    InvalidJson(String),

    #[error("non-integer number not supported in canonical JSON: {0}")]
    NonIntegerNumber(String),

    #[error("integer outside i64 range not supported in canonical JSON: {0}")]
    NumberOutOfRange(String),
}

/// Canonicalize a parsed JSON value to a UTF-8 byte sequence.
///
/// The output is suitable for hashing with BLAKE3 to produce `payload_hash`.
/// Returns [`CanonicalError::NonIntegerNumber`] if any number in the value
/// tree is a non-integer.
pub fn canonical_json(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    let mut out = Vec::with_capacity(64);
    write_value(value, &mut out)?;
    Ok(out)
}

/// Parse a JSON byte slice and canonicalize it in one shot.
pub fn canonical_json_from_bytes(bytes: &[u8]) -> Result<Vec<u8>, CanonicalError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| CanonicalError::InvalidJson(e.to_string()))?;
    canonical_json(&value)
}

fn write_value(value: &Value, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => write_number(n, out)?,
        Value::String(s) => write_string(s, out)?,
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // Collect (NFC-normalized key, original value) pairs, then sort
            // by UTF-16 code-unit order. We do not BTreeMap-sort because
            // BTreeMap uses String::cmp (UTF-8 byte order), which diverges
            // for supplementary characters.
            let mut entries: Vec<(String, Vec<u16>, &Value)> = map
                .iter()
                .map(|(k, v)| {
                    let nfc: String = k.nfc().collect();
                    let utf16: Vec<u16> = nfc.encode_utf16().collect();
                    (nfc, utf16, v)
                })
                .collect();
            entries.sort_by(|a, b| a.1.cmp(&b.1));

            out.push(b'{');
            for (i, (key, _, val)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(key, out)?;
                out.push(b':');
                write_value(val, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_number(n: &serde_json::Number, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    if let Some(i) = n.as_i64() {
        out.extend_from_slice(i.to_string().as_bytes());
        return Ok(());
    }
    if let Some(u) = n.as_u64() {
        // Only reachable for u64 > i64::MAX, which is outside JS safe range
        // and we'd refuse to roundtrip anyway. Match JavaScript's String(u)
        // for completeness.
        out.extend_from_slice(u.to_string().as_bytes());
        return Ok(());
    }
    // Last resort: serde_json parses `-0` and any integer-valued literal that
    // overflows i64/u64 as `f64`. Match `Number.isInteger(value)` semantics:
    // accept any finite whole-valued f64 (including -0.0, which JS renders
    // as "0"). Reject everything else (NaN/Inf cannot occur by construction
    // here, but `is_finite()` guards regardless).
    if let Some(f) = n.as_f64() {
        if f.is_finite() && f.fract() == 0.0 {
            // Accept an integer-valued float (e.g. `2.0`, `-0`) only when it
            // maps to an i64 exactly. A bare `f as i64` SATURATES at
            // i64::MIN/MAX for out-of-range inputs, so distinct values such as
            // 2e19 and 3e19 would both saturate to i64::MAX and lose their
            // distinctness. Refusing ambiguous values keeps the canonical form
            // injective, which is the property the hash relies on.
            #[allow(clippy::cast_possible_truncation)]
            let as_int = f as i64;
            // Exact round-trip check: the float comparison is intentional, it
            // verifies that no precision was lost (and that no saturation
            // happened) before we trust `as_int`.
            #[allow(clippy::cast_precision_loss, clippy::float_cmp)]
            let round_trips = as_int as f64 == f;
            if round_trips {
                out.extend_from_slice(as_int.to_string().as_bytes());
                return Ok(());
            }
            return Err(CanonicalError::NumberOutOfRange(n.to_string()));
        }
    }
    Err(CanonicalError::NonIntegerNumber(n.to_string()))
}

/// Serialize a string with NFC normalization and RFC 8259 escapes.
///
/// Reuses serde_json's escaping (which matches JavaScript's `JSON.stringify`
/// for this subset: no escape of forward slash, no `\u` for non-ASCII).
/// In practice the inner serialization can never fail (Vec<u8> is an
/// infallible sink and a String is always valid UTF-8), but we propagate
/// the error rather than `expect()` so the no-panic guarantee on
/// `spine-core` holds even under bizarre future refactors.
fn write_string(s: &str, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    let nfc: String = s.nfc().collect();
    let encoded = serde_json::to_vec(&nfc)
        .map_err(|e| CanonicalError::InvalidJson(format!("string serialization: {e}")))?;
    out.extend_from_slice(&encoded);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn canon(v: Value) -> String {
        String::from_utf8(canonical_json(&v).unwrap()).unwrap()
    }

    #[test]
    fn primitives() {
        assert_eq!(canon(Value::Null), "null");
        assert_eq!(canon(Value::Bool(true)), "true");
        assert_eq!(canon(Value::Bool(false)), "false");
        assert_eq!(canon(json!(0)), "0");
        assert_eq!(canon(json!(-1)), "-1");
        assert_eq!(canon(json!(42)), "42");
        assert_eq!(canon(json!(i64::MAX)), i64::MAX.to_string());
        assert_eq!(canon(json!(i64::MIN)), i64::MIN.to_string());
    }

    #[test]
    fn empty_collections() {
        assert_eq!(canon(json!({})), "{}");
        assert_eq!(canon(json!([])), "[]");
    }

    #[test]
    fn array_preserves_order() {
        assert_eq!(canon(json!([3, 1, 2])), "[3,1,2]");
        assert_eq!(canon(json!(["c", "a", "b"])), r#"["c","a","b"]"#);
    }

    #[test]
    fn object_keys_are_sorted() {
        assert_eq!(canon(json!({"b": 1, "a": 2})), r#"{"a":2,"b":1}"#);
        assert_eq!(
            canon(json!({"z": 1, "m": 2, "a": 3})),
            r#"{"a":3,"m":2,"z":1}"#
        );
    }

    #[test]
    fn nested_objects_are_recursively_canonicalized() {
        assert_eq!(
            canon(json!({"x": {"d": 1, "c": 2}})),
            r#"{"x":{"c":2,"d":1}}"#
        );
        assert_eq!(
            canon(json!({"outer": [{"b": 1, "a": 2}, {"d": 3, "c": 4}]})),
            r#"{"outer":[{"a":2,"b":1},{"c":4,"d":3}]}"#
        );
    }

    #[test]
    fn rejects_non_integer_numbers() {
        let result = canonical_json(&json!(1.5));
        assert!(matches!(result, Err(CanonicalError::NonIntegerNumber(_))));

        let result = canonical_json(&json!({"a": 0.1}));
        assert!(matches!(result, Err(CanonicalError::NonIntegerNumber(_))));

        let result = canonical_json(&json!(-3.7));
        assert!(matches!(result, Err(CanonicalError::NonIntegerNumber(_))));
    }

    #[test]
    fn accepts_integer_valued_floats_like_node_is_integer() {
        // serde_json parses bare `2.0` as f64; Node's Number.isInteger(2.0)
        // is true and String(2.0) is "2". We mirror that exactly so a Node-
        // produced canonical form and a Rust-produced one converge.
        let result = canonical_json(&json!([1, 2.0_f64])).unwrap();
        assert_eq!(String::from_utf8(result).unwrap(), "[1,2]");
    }

    #[test]
    fn rejects_integer_valued_floats_outside_i64_range() {
        // Regression: a saturating `f as i64` used to collapse every
        // out-of-range integer-valued float to i64::MIN/MAX, so two distinct
        // payloads (2e19 and 3e19) canonicalized to the same bytes, which the
        // round-trip check now refuses so the canonical form stays injective.
        assert!(matches!(
            canonical_json(&json!(2.0e19_f64)),
            Err(CanonicalError::NumberOutOfRange(_))
        ));
        assert!(matches!(
            canonical_json(&json!(3.0e19_f64)),
            Err(CanonicalError::NumberOutOfRange(_))
        ));
        assert!(matches!(
            canonical_json(&json!(-2.0e19_f64)),
            Err(CanonicalError::NumberOutOfRange(_))
        ));
    }

    #[test]
    fn string_escapes_match_rfc_8259() {
        assert_eq!(canon(json!("hello")), r#""hello""#);
        assert_eq!(canon(json!(r#"with "quote""#)), r#""with \"quote\"""#);
        assert_eq!(canon(json!("a\\b")), r#""a\\b""#);
        assert_eq!(canon(json!("line1\nline2")), r#""line1\nline2""#);
        assert_eq!(canon(json!("tab\there")), r#""tab\there""#);
        assert_eq!(canon(json!("cr\r")), r#""cr\r""#);
        assert_eq!(canon(json!("backspace\u{0008}")), r#""backspace\b""#);
        assert_eq!(canon(json!("formfeed\u{000C}")), r#""formfeed\f""#);
    }

    #[test]
    fn other_control_chars_get_unicode_escapes() {
        // U+0000 through U+001F that are not in the named-escape set get
        // the \u00XX form. Build the input strings via char literals and
        // compare to similarly-built expected strings, so this test source
        // file stays free of literal NUL bytes.
        let nul_input = format!("nul{}", '\u{0000}');
        let expected = format!("\"nul{}u0000\"", '\\');
        assert_eq!(canon(json!(nul_input)), expected);

        let ctrl_input = format!("ctrl{}", '\u{001F}');
        let expected = format!("\"ctrl{}u001f\"", '\\');
        assert_eq!(canon(json!(ctrl_input)), expected);
    }

    #[test]
    fn unicode_strings_emit_literal_utf8_not_escaped() {
        assert_eq!(canon(json!("café")), "\"café\"");
        assert_eq!(canon(json!("日本")), "\"日本\"");
        assert_eq!(canon(json!("emoji🎉")), "\"emoji🎉\"");
    }

    #[test]
    fn nfc_normalization_of_string_values() {
        // "café" decomposed: c, a, f, e, U+0301 (combining acute)
        let decomposed = "cafe\u{0301}";
        let composed = "café"; // NFC: c, a, f, U+00E9
        assert_ne!(decomposed.as_bytes(), composed.as_bytes());

        // Both must canonicalize to the same bytes.
        let from_decomposed = canon(json!(decomposed));
        let from_composed = canon(json!(composed));
        assert_eq!(from_decomposed, from_composed);
        assert_eq!(from_decomposed, "\"café\"");
    }

    #[test]
    fn nfc_normalization_of_object_keys() {
        let decomposed_key = "cafe\u{0301}";
        let composed_key = "café";
        let v1 = canon(json!({ decomposed_key: 1 }));
        let v2 = canon(json!({ composed_key: 1 }));
        assert_eq!(v1, v2);
        assert_eq!(v1, "{\"café\":1}");
    }

    #[test]
    fn deep_nesting_does_not_overflow() {
        // 50 levels of nesting, well within practical limits, well below
        // anything that would blow the stack on default settings.
        let mut v = json!(0);
        for _ in 0..50 {
            v = json!([v]);
        }
        let s = canon(v);
        assert_eq!(s.matches('[').count(), 50);
        assert_eq!(s.matches(']').count(), 50);
    }

    #[test]
    fn null_true_false_inside_object() {
        assert_eq!(
            canon(json!({"a": null, "b": true, "c": false})),
            r#"{"a":null,"b":true,"c":false}"#
        );
    }

    #[test]
    fn forward_slash_is_not_escaped() {
        // Matches both serde_json and JSON.stringify (which leave / as-is).
        assert_eq!(canon(json!("a/b")), "\"a/b\"");
    }

    #[test]
    fn utf16_key_ordering_for_supplementary_characters() {
        // U+10000 (Linear B Syllable B008 A) encodes as UTF-16 surrogate
        // pair D800 DC00. Its UTF-8 bytes are F0 90 80 80.
        // U+FFFF (BMP, last code point) encodes as UTF-16 unit FFFF, UTF-8
        // bytes EF BF BF.
        // - In UTF-16 unit order: D800 < FFFF, so U+10000 sorts BEFORE U+FFFF.
        // - In UTF-8 byte order:  EF < F0,  so U+FFFF  sorts BEFORE U+10000.
        // We MUST match Node's Array.prototype.sort() = UTF-16 unit order,
        // i.e. supplementary character first.
        let supp = "\u{10000}";
        let bmp = "\u{FFFF}";
        let mut m = serde_json::Map::new();
        m.insert(bmp.to_string(), json!(2));
        m.insert(supp.to_string(), json!(1));
        let s = canon(Value::Object(m));
        assert_eq!(
            s,
            format!("{{\"{supp}\":1,\"{bmp}\":2}}"),
            "supplementary char must sort before BMP-FFFF in UTF-16 order"
        );
    }

    #[test]
    fn idempotent_when_input_is_already_canonical() {
        let original = json!({"a": 1, "b": [2, {"c": 3, "d": 4}]});
        let first = canonical_json(&original).unwrap();
        let parsed: Value = serde_json::from_slice(&first).unwrap();
        let second = canonical_json(&parsed).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn input_key_order_does_not_affect_output() {
        // Property: any permutation of keys at any level produces the same
        // canonical bytes. Sample 4 different parses from semantically-equal
        // strings.
        let inputs = [
            r#"{"a":1,"b":2,"c":3}"#,
            r#"{"c":3,"b":2,"a":1}"#,
            r#"{"b":2,"a":1,"c":3}"#,
            r#"{"c":3,"a":1,"b":2}"#,
        ];
        let canonicals: Vec<Vec<u8>> = inputs
            .iter()
            .map(|s| canonical_json_from_bytes(s.as_bytes()).unwrap())
            .collect();
        for c in &canonicals[1..] {
            assert_eq!(c, &canonicals[0]);
        }
    }

    #[test]
    fn integer_values_serialize_without_decimal_point() {
        assert_eq!(canon(json!(0)), "0");
        assert_eq!(canon(json!(1)), "1");
        assert_eq!(canon(json!(-1)), "-1");
        assert_eq!(canon(json!(1000000)), "1000000");
        // Negative zero: serde_json parses to 0
        let v: Value = serde_json::from_str("-0").unwrap();
        assert_eq!(canon(v), "0");
    }

    #[test]
    fn duplicate_keys_in_input_resolve_to_last_wins() {
        // serde_json's default Map behaviour: later occurrence overwrites.
        // RFC 8785 forbids duplicate keys in inputs, but enforcement is the
        // caller's responsibility; we match JavaScript's `JSON.parse`
        // last-wins behaviour for predictability.
        let input = r#"{"a":1,"a":2}"#;
        let result = canonical_json_from_bytes(input.as_bytes()).unwrap();
        assert_eq!(String::from_utf8(result).unwrap(), r#"{"a":2}"#);
    }

    #[test]
    fn invalid_json_returns_error() {
        let result = canonical_json_from_bytes(b"{not json}");
        assert!(matches!(result, Err(CanonicalError::InvalidJson(_))));
    }
}

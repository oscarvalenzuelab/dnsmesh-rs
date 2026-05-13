//! Interop vector tests for the DMPv2 plaintext envelope.
//!
//! Each case in `tests/interop/vectors/dmpv2_envelope.json` is verified two
//! ways:
//!
//! 1. Encode: run [`envelope::encode`] on the recorded inputs and assert the
//!    output matches `expected_plaintext_hex`.
//! 2. Decode: run [`envelope::decode`] on `expected_plaintext_hex` and assert
//!    the returned `(body, from)` matches the recorded expectations.
//!
//! Decode-only cases (forward-compat extras, malformed envelopes, etc.)
//! supply `inputs.plaintext_hex` and skip the encode step.

use dnsmesh_core::envelope;
use serde::Deserialize;

const VECTORS_JSON: &str = include_str!("../tests/interop/vectors/dmpv2_envelope.json");

#[derive(Debug, Deserialize)]
struct Inputs {
    #[serde(default)]
    body_hex: Option<String>,
    #[serde(default)]
    sender_addr: Option<String>,
    #[serde(default)]
    plaintext_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Case {
    description: String,
    inputs: Inputs,
    #[serde(default)]
    expected_plaintext_hex: Option<String>,
    expected_decode_body_hex: String,
    #[serde(default)]
    expected_decode_from: Option<String>,
}

fn hex_to_bytes(label: &str, hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).unwrap_or_else(|e| panic!("{label}: hex decode: {e}"))
}

#[test]
fn dmpv2_envelope_vectors_match_python() {
    let cases: Vec<Case> = serde_json::from_str(VECTORS_JSON).expect("parse vectors json");

    for (idx, case) in cases.iter().enumerate() {
        let label = format!("case[{idx}] {}", case.description);

        // Pick the plaintext bytes from the right field. Encode cases
        // record it at the top level as `expected_plaintext_hex`;
        // decode-only cases record it under `inputs.plaintext_hex`.
        let plaintext_hex = case
            .expected_plaintext_hex
            .as_deref()
            .or(case.inputs.plaintext_hex.as_deref())
            .unwrap_or_else(|| panic!("{label}: no plaintext_hex on either field"));
        let plaintext = hex_to_bytes(&label, plaintext_hex);

        // --- decode side ---
        let (decoded_body, decoded_from) = envelope::decode(&plaintext);
        let expected_body = hex_to_bytes(&label, &case.expected_decode_body_hex);
        assert_eq!(
            decoded_body, expected_body,
            "{label}: decoded body must match expected_decode_body_hex",
        );
        assert_eq!(
            decoded_from.as_deref(),
            case.expected_decode_from.as_deref(),
            "{label}: decoded from must match expected_decode_from",
        );

        // --- encode side (encode roundtrip cases only) ---
        if let (Some(body_hex), Some(_)) = (
            case.inputs.body_hex.as_deref(),
            case.expected_plaintext_hex.as_deref(),
        ) {
            let body = hex_to_bytes(&label, body_hex);
            let sender_ref = case.inputs.sender_addr.as_deref();
            // serde maps a JSON null `sender_addr` to Option::None,
            // which is what we want — encode with no sender skips the
            // wrapper, mirroring Python's `sender_addr=None` path.
            let wrapped = envelope::encode(&body, sender_ref);
            assert_eq!(
                wrapped, plaintext,
                "{label}: re-encoded plaintext must match expected_plaintext_hex",
            );
        }
    }
}

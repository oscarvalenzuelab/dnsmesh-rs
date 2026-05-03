//! Byte-level interop check for [`dnsmesh_core::revocation::RevocationRecord`]
//! against the Python reference vectors.
//!
//! Each case in `tests/interop/vectors/revocation_record.json` is one of:
//!
//! - A fresh-sign case: holds full `inputs`, `revoked_seed_hex`, and the
//!   expected wire string as UTF-8 hex. Building the record and self-signing
//!   it with the seeded key must reproduce that exact wire string.
//! - A negative case: holds `expected_parse_result == "none"`.
//!   `expected_wire_hex` is the wire to feed into `parse_and_verify` —
//!   either with `verify_with_expected_revoked_spk_hex` set to a wrong key
//!   (binding failure) or with `verify_with_max_age_seconds` set so the
//!   freshness gate fires (the same wire would parse OK without the cap).
//!
//! Vectors are committed to the repo and serve as the M1 wire-format gate.

use dnsmesh_core::crypto::DmpCrypto;
use dnsmesh_core::revocation::{RevocationRecord, SPK_LEN};
use serde::Deserialize;

const VECTORS_JSON: &str = include_str!("interop/vectors/revocation_record.json");

#[derive(Debug, Deserialize)]
struct Inputs {
    reason_code: u8,
    revoked_spk_hex: String,
    subject: String,
    subject_type: u8,
    ts: u64,
}

#[derive(Debug, Deserialize)]
struct Case {
    description: String,
    #[serde(default)]
    expected_parse_reason_code: Option<u8>,
    #[serde(default)]
    expected_parse_subject: Option<String>,
    expected_wire_hex: String,
    #[serde(default)]
    expected_parse_result: Option<String>,
    #[serde(default)]
    inputs: Option<Inputs>,
    #[serde(default)]
    revoked_seed_hex: Option<String>,
    #[serde(default)]
    verify_with_expected_revoked_spk_hex: Option<String>,
    #[serde(default)]
    verify_with_max_age_seconds: Option<u64>,
    #[serde(default)]
    verify_with_now: Option<u64>,
    #[serde(default, rename = "wire_from_case")]
    #[allow(dead_code)]
    wire_source: Option<usize>,
}

fn decode_array<const N: usize>(hex_str: &str, label: &str, case: &str) -> [u8; N] {
    let bytes =
        hex::decode(hex_str).unwrap_or_else(|e| panic!("[{case}] {label} hex decode failed: {e}"));
    assert_eq!(
        bytes.len(),
        N,
        "[{case}] {label} expected {N} bytes, got {}",
        bytes.len(),
    );
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    out
}

fn run_fresh_case(case: &Case, inputs: &Inputs, label: &str) -> String {
    let seed_hex = case
        .revoked_seed_hex
        .as_deref()
        .unwrap_or_else(|| panic!("[{label}] fresh case missing revoked_seed_hex"));
    let seed = hex::decode(seed_hex)
        .unwrap_or_else(|e| panic!("[{label}] revoked_seed_hex decode failed: {e}"));
    let crypto = DmpCrypto::from_private_bytes(&seed)
        .unwrap_or_else(|e| panic!("[{label}] DmpCrypto::from_private_bytes failed: {e:?}"));

    let revoked_spk = decode_array::<SPK_LEN>(&inputs.revoked_spk_hex, "revoked_spk_hex", label);
    assert_eq!(
        revoked_spk,
        crypto.signing_public_key_bytes(),
        "[{label}] revoked_spk_hex does not match key derived from revoked_seed_hex",
    );

    let record = RevocationRecord {
        subject_type: inputs.subject_type,
        subject: inputs.subject.clone(),
        revoked_spk,
        reason_code: inputs.reason_code,
        ts: inputs.ts,
    };

    let wire = record
        .sign(&crypto)
        .unwrap_or_else(|e| panic!("[{label}] sign failed: {e:?}"));
    let wire_hex = hex::encode(wire.as_bytes());
    assert_eq!(
        wire_hex, case.expected_wire_hex,
        "[{label}] wire bytes do not match Python vector",
    );

    let now = case.verify_with_now.unwrap_or(inputs.ts);
    let expected_subject = case.expected_parse_subject.as_deref();
    let max_age = case.verify_with_max_age_seconds;

    if case.expected_parse_result.as_deref() == Some("none") {
        assert!(
            RevocationRecord::parse_and_verify(
                &wire,
                Some(&revoked_spk),
                expected_subject,
                Some(now),
                max_age,
            )
            .is_none(),
            "[{label}] parse_and_verify must reject this negative-case fresh wire"
        );
        // For the explicit-cap negative case: confirm that without the cap,
        // the same wire DOES parse successfully. This is the
        // permanent-assertion contract we promise.
        if max_age.is_some() {
            let parsed_without_cap = RevocationRecord::parse_and_verify(
                &wire,
                Some(&revoked_spk),
                expected_subject,
                Some(now),
                None,
            );
            assert!(
                parsed_without_cap.is_some(),
                "[{label}] without max_age_seconds the same wire must parse OK \
                 (permanent-assertion model)",
            );
        }
    } else {
        let parsed = RevocationRecord::parse_and_verify(
            &wire,
            Some(&revoked_spk),
            expected_subject,
            Some(now),
            max_age,
        )
        .unwrap_or_else(|| panic!("[{label}] parse_and_verify rejected fresh-signed wire"));
        assert_eq!(parsed, record, "[{label}] parsed record != original");
        if let Some(expected_reason) = case.expected_parse_reason_code {
            assert_eq!(
                parsed.reason_code, expected_reason,
                "[{label}] parsed reason_code mismatch",
            );
        }
        if let Some(expected_subj) = expected_subject {
            assert_eq!(
                parsed.subject, expected_subj,
                "[{label}] parsed subject mismatch (literal embedded subject)",
            );
        }
    }
    wire
}

fn run_negative_case(case: &Case, label: &str) {
    // The vector's expected_wire_hex IS the wire (often a copy of an earlier
    // case's valid wire) and the negative outcome comes from the verify-side
    // pin that follows: a wrong expected_revoked_spk, a max_age cap, etc.
    let wire_bytes = hex::decode(&case.expected_wire_hex)
        .unwrap_or_else(|e| panic!("[{label}] negative wire hex decode failed: {e}"));
    let wire_str = std::str::from_utf8(&wire_bytes)
        .unwrap_or_else(|e| panic!("[{label}] negative wire is not UTF-8: {e}"));

    let expected_spk_bytes = case
        .verify_with_expected_revoked_spk_hex
        .as_deref()
        .map(|h| {
            hex::decode(h).unwrap_or_else(|e| {
                panic!("[{label}] verify_with_expected_revoked_spk_hex decode failed: {e}")
            })
        });

    let now = case.verify_with_now.unwrap_or(0);
    let max_age = case.verify_with_max_age_seconds;
    let parsed = RevocationRecord::parse_and_verify(
        wire_str,
        expected_spk_bytes.as_deref(),
        case.expected_parse_subject.as_deref(),
        Some(now),
        max_age,
    );
    assert!(
        parsed.is_none(),
        "[{label}] parse_and_verify must reject this negative-case wire"
    );
}

#[test]
fn revocation_record_matches_python_vectors() {
    let cases: Vec<Case> =
        serde_json::from_str(VECTORS_JSON).expect("revocation_record.json must be valid JSON");

    let mut wires: Vec<Option<String>> = Vec::with_capacity(cases.len());

    for (idx, case) in cases.iter().enumerate() {
        let label = format!("case[{idx}]: {}", case.description);

        if let Some(inputs) = &case.inputs {
            let wire = run_fresh_case(case, inputs, &label);
            wires.push(Some(wire));
        } else {
            assert_eq!(
                case.expected_parse_result.as_deref(),
                Some("none"),
                "[{label}] non-fresh case must declare expected_parse_result=\"none\"",
            );
            // wire_from_case is informational; the explicit expected_wire_hex
            // is what we feed the parser.
            run_negative_case(case, &label);
            wires.push(None);
        }
    }
}

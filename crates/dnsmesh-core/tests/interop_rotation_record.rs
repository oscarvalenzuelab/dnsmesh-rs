//! Byte-level interop check for [`dnsmesh_core::rotation::RotationRecord`]
//! against the Python reference vectors.
//!
//! Each case in `tests/interop/vectors/rotation_record.json` is one of:
//!
//! - A fresh-sign case: holds full `inputs`, `old_seed_hex`, `new_seed_hex`,
//!   and the expected wire string as UTF-8 hex. Building the record and
//!   co-signing it with the seeded keys must reproduce that exact wire string.
//! - A tampered / negative case: holds `expected_parse_result == "none"`.
//!   `expected_wire_hex` is the full negative-case wire (e.g. forged sig_new,
//!   or expired record). `parse_and_verify` must return `None`.
//!
//! Vectors are committed to the repo and serve as the M1 wire-format gate.

use dnsmesh_core::crypto::DmpCrypto;
use dnsmesh_core::rotation::{RotationRecord, SPK_LEN};
use serde::Deserialize;

const VECTORS_JSON: &str = include_str!("interop/vectors/rotation_record.json");

#[derive(Debug, Deserialize)]
struct Inputs {
    exp: u64,
    new_spk_hex: String,
    old_spk_hex: String,
    seq: u64,
    subject: String,
    subject_type: u8,
    ts: u64,
}

#[derive(Debug, Deserialize)]
struct Case {
    description: String,
    #[serde(default)]
    expected_parse_seq: Option<u64>,
    #[serde(default)]
    expected_parse_subject: Option<String>,
    expected_wire_hex: String,
    #[serde(default)]
    expected_parse_result: Option<String>,
    #[serde(default)]
    inputs: Option<Inputs>,
    #[serde(default)]
    new_seed_hex: Option<String>,
    #[serde(default)]
    old_seed_hex: Option<String>,
    #[serde(default)]
    verify_with_now: Option<u64>,
    #[serde(default, rename = "wire_from_case")]
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
    let old_seed_hex = case
        .old_seed_hex
        .as_deref()
        .unwrap_or_else(|| panic!("[{label}] fresh case missing old_seed_hex"));
    let new_seed_hex = case
        .new_seed_hex
        .as_deref()
        .unwrap_or_else(|| panic!("[{label}] fresh case missing new_seed_hex"));
    let old_seed = hex::decode(old_seed_hex)
        .unwrap_or_else(|e| panic!("[{label}] old_seed_hex decode failed: {e}"));
    let new_seed = hex::decode(new_seed_hex)
        .unwrap_or_else(|e| panic!("[{label}] new_seed_hex decode failed: {e}"));
    let old_crypto = DmpCrypto::from_private_bytes(&old_seed)
        .unwrap_or_else(|e| panic!("[{label}] old DmpCrypto::from_private_bytes failed: {e:?}"));
    let new_crypto = DmpCrypto::from_private_bytes(&new_seed)
        .unwrap_or_else(|e| panic!("[{label}] new DmpCrypto::from_private_bytes failed: {e:?}"));

    let old_spk = decode_array::<SPK_LEN>(&inputs.old_spk_hex, "old_spk_hex", label);
    let new_spk = decode_array::<SPK_LEN>(&inputs.new_spk_hex, "new_spk_hex", label);

    assert_eq!(
        old_spk,
        old_crypto.signing_public_key_bytes(),
        "[{label}] old_spk_hex does not match key derived from old_seed_hex",
    );
    assert_eq!(
        new_spk,
        new_crypto.signing_public_key_bytes(),
        "[{label}] new_spk_hex does not match key derived from new_seed_hex",
    );

    let record = RotationRecord {
        subject_type: inputs.subject_type,
        subject: inputs.subject.clone(),
        old_spk,
        new_spk,
        seq: inputs.seq,
        ts: inputs.ts,
        exp: inputs.exp,
    };

    let wire = record
        .sign(&old_crypto, &new_crypto)
        .unwrap_or_else(|e| panic!("[{label}] sign failed: {e:?}"));
    let wire_hex = hex::encode(wire.as_bytes());
    assert_eq!(
        wire_hex, case.expected_wire_hex,
        "[{label}] wire bytes do not match Python vector",
    );

    let now = case.verify_with_now.unwrap_or(inputs.ts);
    let expected_subject = case.expected_parse_subject.as_deref();
    if case.expected_parse_result.as_deref() == Some("none") {
        assert!(
            RotationRecord::parse_and_verify(&wire, Some(&old_spk), expected_subject, Some(now))
                .is_none(),
            "[{label}] parse_and_verify must reject a negative-case wire"
        );
    } else {
        let parsed =
            RotationRecord::parse_and_verify(&wire, Some(&old_spk), expected_subject, Some(now))
                .unwrap_or_else(|| panic!("[{label}] parse_and_verify rejected fresh-signed wire"));
        assert_eq!(parsed, record, "[{label}] parsed record != original");
        if let Some(expected_seq) = case.expected_parse_seq {
            assert_eq!(parsed.seq, expected_seq, "[{label}] parsed seq mismatch");
        }
        if let Some(expected_subj) = expected_subject {
            assert_eq!(
                parsed.subject, expected_subj,
                "[{label}] parsed subject mismatch (note: this is the literal embedded subject)",
            );
        }
    }
    wire
}

fn run_negative_case(case: &Case, label: &str) {
    // The vector's expected_wire_hex IS the negative-case wire (the Python
    // generator either flipped a signature or built an expired record). We
    // do not need to cross-check against the source case here — just ensure
    // the documented wire actually fails verification.
    let tampered_bytes = hex::decode(&case.expected_wire_hex)
        .unwrap_or_else(|e| panic!("[{label}] negative wire hex decode failed: {e}"));
    let tampered_str = std::str::from_utf8(&tampered_bytes)
        .unwrap_or_else(|e| panic!("[{label}] negative wire is not UTF-8: {e}"));

    let now = case.verify_with_now.unwrap_or(0);
    assert!(
        RotationRecord::parse_and_verify(tampered_str, None, None, Some(now)).is_none(),
        "[{label}] parse_and_verify must reject negative-case wire"
    );
}

#[test]
fn rotation_record_matches_python_vectors() {
    let cases: Vec<Case> =
        serde_json::from_str(VECTORS_JSON).expect("rotation_record.json must be valid JSON");

    let mut wires: Vec<Option<String>> = Vec::with_capacity(cases.len());

    for (idx, case) in cases.iter().enumerate() {
        let label = format!("case[{idx}]: {}", case.description);

        if let Some(inputs) = &case.inputs {
            // Fresh case (may still be a negative case carrying an
            // explicit wire — e.g. expired records in the vectors).
            let wire = run_fresh_case(case, inputs, &label);
            wires.push(Some(wire));
        } else {
            // Pure tampered case (e.g. forged sig_new): no inputs, references
            // an earlier wire by index.
            assert_eq!(
                case.expected_parse_result.as_deref(),
                Some("none"),
                "[{label}] non-fresh case must declare expected_parse_result=\"none\"",
            );
            let _src_idx = case
                .wire_source
                .unwrap_or_else(|| panic!("[{label}] tampered case missing wire_from_case"));
            run_negative_case(case, &label);
            wires.push(None);
        }
    }
}

//! Byte-level interop tests for bootstrap records.
//!
//! Each case in `tests/interop/vectors/bootstrap_record.json` validates either:
//!   - the round-trip from `(signer_seed, inputs)` -> signed wire string
//!     equals the Python-emitted `expected_wire_hex` byte-for-byte; AND
//!   - `parse_and_verify` against the recorded signer key returns the
//!     expected `BootstrapRecord` (or `None` when `expected_parse_result`
//!     is `"none"`).

use dnsmesh_core::bootstrap::{BootstrapEntry, BootstrapRecord, OPERATOR_SPK_LEN, SIGNER_SPK_LEN};
use dnsmesh_core::crypto::DmpCrypto;
use serde::Deserialize;

const VECTORS_JSON: &str = include_str!("interop/vectors/bootstrap_record.json");

#[derive(Debug, Deserialize)]
struct InputEntry {
    cluster_base_domain: String,
    operator_spk_hex: String,
    priority: u16,
}

#[derive(Debug, Deserialize)]
struct Inputs {
    entries: Vec<InputEntry>,
    exp: u64,
    seq: u64,
    signer_spk_hex: String,
    user_domain: String,
}

#[allow(clippy::struct_field_names)]
#[derive(Debug, Deserialize)]
struct Case {
    description: String,
    #[serde(default)]
    expected_parse_seq: Option<u64>,
    #[serde(default)]
    expected_parse_user_domain: Option<String>,
    expected_wire_hex: String,
    #[serde(default)]
    #[allow(dead_code)]
    expected_multi_string: Option<bool>,
    #[serde(default)]
    expected_parse_result: Option<String>,
    #[serde(default)]
    inputs: Option<Inputs>,
    #[serde(default)]
    signer_seed_hex: Option<String>,
    #[serde(default)]
    verify_with_signer_spk_hex: Option<String>,
    #[serde(default)]
    verify_with_now: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    wire_from_case: Option<usize>,
}

fn decode_array_32<const N: usize>(label: &str, hex_str: &str) -> [u8; N] {
    let raw = hex::decode(hex_str).unwrap_or_else(|e| panic!("{label}: invalid hex: {e}"));
    assert_eq!(
        raw.len(),
        N,
        "{label}: expected {N} bytes, got {}",
        raw.len()
    );
    let mut out = [0u8; N];
    out.copy_from_slice(&raw);
    out
}

#[test]
fn bootstrap_record_interop_vectors() {
    let cases: Vec<Case> = serde_json::from_str(VECTORS_JSON).expect("parse bootstrap_record.json");
    assert!(
        !cases.is_empty(),
        "bootstrap_record.json must contain at least one case"
    );

    for (idx, case) in cases.iter().enumerate() {
        let label = format!("case[{idx}]: {}", case.description);
        let expected_wire_bytes = hex::decode(&case.expected_wire_hex)
            .unwrap_or_else(|e| panic!("[{label}] expected_wire_hex: {e}"));
        let expected_wire_str = std::str::from_utf8(&expected_wire_bytes)
            .unwrap_or_else(|e| panic!("[{label}] expected_wire_hex is not utf-8: {e}"));

        if let Some(inputs) = &case.inputs {
            let seed_hex = case
                .signer_seed_hex
                .as_ref()
                .unwrap_or_else(|| panic!("[{label}] missing signer_seed_hex"));
            let seed =
                hex::decode(seed_hex).unwrap_or_else(|e| panic!("[{label}] signer_seed_hex: {e}"));
            let crypto = DmpCrypto::from_private_bytes(&seed)
                .unwrap_or_else(|e| panic!("[{label}] DmpCrypto::from_private_bytes: {e:?}"));

            let signer_spk =
                decode_array_32::<SIGNER_SPK_LEN>("inputs.signer_spk_hex", &inputs.signer_spk_hex);
            assert_eq!(
                crypto.signing_public_key_bytes(),
                signer_spk,
                "[{label}] derived signer_spk does not match input vector",
            );

            let entries: Vec<BootstrapEntry> = inputs
                .entries
                .iter()
                .map(|e| BootstrapEntry {
                    priority: e.priority,
                    cluster_base_domain: e.cluster_base_domain.clone(),
                    operator_spk: decode_array_32::<OPERATOR_SPK_LEN>(
                        "entry.operator_spk_hex",
                        &e.operator_spk_hex,
                    ),
                })
                .collect();
            let mut record = BootstrapRecord {
                user_domain: inputs.user_domain.clone(),
                signer_spk,
                entries,
                seq: inputs.seq,
                exp: inputs.exp,
            };
            let wire = record
                .sign(&crypto)
                .unwrap_or_else(|e| panic!("[{label}] sign failed: {e:?}"));
            assert_eq!(
                wire.as_bytes(),
                expected_wire_bytes.as_slice(),
                "[{label}] signed wire does not match expected_wire_hex",
            );
        }

        let verify_spk = case
            .verify_with_signer_spk_hex
            .as_deref()
            .or(case.inputs.as_ref().map(|i| i.signer_spk_hex.as_str()));
        let verify_spk_bytes = verify_spk
            .map(|h| hex::decode(h).unwrap_or_else(|e| panic!("[{label}] verify spk hex: {e}")));
        let verify_spk_slice: Option<&[u8]> = verify_spk_bytes.as_deref();

        let now = case
            .verify_with_now
            .or_else(|| case.inputs.as_ref().map(|i| i.exp));

        let parsed =
            BootstrapRecord::parse_and_verify(expected_wire_str, verify_spk_slice, None, now);
        match case.expected_parse_result.as_deref() {
            Some("none") => {
                assert!(parsed.is_none(), "[{label}] parse_and_verify should fail");
            }
            None | Some("ok") => {
                let record =
                    parsed.unwrap_or_else(|| panic!("[{label}] parse_and_verify must succeed"));
                if let Some(expected_user) = &case.expected_parse_user_domain {
                    assert_eq!(
                        &record.user_domain, expected_user,
                        "[{label}] parsed user_domain mismatch",
                    );
                }
                if let Some(expected_seq) = case.expected_parse_seq {
                    assert_eq!(record.seq, expected_seq, "[{label}] parsed seq mismatch");
                }
            }
            Some(other) => panic!("[{label}] unknown expected_parse_result: {other}"),
        }
    }
}

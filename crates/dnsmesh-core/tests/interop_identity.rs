//! Interop vector tests for identity records.
//!
//! Each case in `tests/interop/vectors/identity_record.json` must produce a
//! byte-identical wire string when re-signed with the recorded inputs, and
//! `parse_and_verify` must agree with the recorded `expected_parse_result`.

use dnsmesh_core::crypto::DmpCrypto;
use dnsmesh_core::identity::IdentityRecord;
use serde::Deserialize;

const VECTORS_JSON: &str = include_str!("../tests/interop/vectors/identity_record.json");

#[derive(Debug, Deserialize)]
struct Inputs {
    ed25519_spk_hex: String,
    ts: u64,
    username: String,
    x25519_pk_hex: String,
}

#[allow(clippy::struct_field_names)]
#[derive(Debug, Deserialize)]
struct Case {
    description: String,
    expected_wire_hex: String,
    #[serde(default)]
    expected_parse_username: Option<String>,
    #[serde(default)]
    expected_parse_result: Option<String>,
    #[serde(default)]
    identity_seed_hex: Option<String>,
    #[serde(default)]
    inputs: Option<Inputs>,
    #[serde(default)]
    wire_from_case: Option<usize>,
    #[serde(default)]
    #[allow(dead_code)]
    notes: Option<String>,
}

fn decode_key32(label: &str, hex_str: &str) -> [u8; 32] {
    let raw = hex::decode(hex_str).unwrap_or_else(|e| panic!("{label}: hex decode: {e}"));
    let arr: [u8; 32] = raw
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("{label}: expected 32 bytes, got {}", v.len()));
    arr
}

#[test]
fn identity_record_vectors_match_python() {
    let cases: Vec<Case> = serde_json::from_str(VECTORS_JSON).expect("parse vectors json");

    for (idx, case) in cases.iter().enumerate() {
        let label = format!("case[{idx}] {}", case.description);

        let expected_wire_bytes = hex::decode(&case.expected_wire_hex)
            .unwrap_or_else(|e| panic!("{label}: expected_wire_hex: {e}"));
        let expected_wire_str = std::str::from_utf8(&expected_wire_bytes)
            .unwrap_or_else(|e| panic!("{label}: expected_wire_hex is not utf-8: {e}"));

        if let Some(inputs) = &case.inputs {
            let seed_hex = case
                .identity_seed_hex
                .as_ref()
                .unwrap_or_else(|| panic!("{label}: missing identity_seed_hex"));
            let seed = hex::decode(seed_hex).unwrap_or_else(|e| panic!("{label}: seed hex: {e}"));
            let crypto = DmpCrypto::from_private_bytes(&seed)
                .unwrap_or_else(|e| panic!("{label}: build crypto: {e}"));

            let x25519_pk = decode_key32("x25519_pk_hex", &inputs.x25519_pk_hex);
            let ed25519_spk = decode_key32("ed25519_spk_hex", &inputs.ed25519_spk_hex);
            assert_eq!(
                crypto.public_key_bytes(),
                x25519_pk,
                "{label}: crypto x25519 pubkey must match input vector",
            );
            assert_eq!(
                crypto.signing_public_key_bytes(),
                ed25519_spk,
                "{label}: crypto ed25519 pubkey must match input vector",
            );

            let record = IdentityRecord {
                username: inputs.username.clone(),
                x25519_pk,
                ed25519_spk,
                ts: inputs.ts,
            };
            let wire = record
                .sign(&crypto)
                .unwrap_or_else(|e| panic!("{label}: sign failed: {e}"));
            assert_eq!(
                wire.as_bytes(),
                expected_wire_bytes.as_slice(),
                "{label}: signed wire must match expected_wire_hex",
            );
        } else if let Some(src_idx) = case.wire_from_case {
            let src = &cases[src_idx];
            let src_bytes = hex::decode(&src.expected_wire_hex)
                .unwrap_or_else(|e| panic!("{label}: source case wire hex: {e}"));
            // Sanity: tampered case differs from source by at least one byte.
            assert_ne!(
                expected_wire_bytes, src_bytes,
                "{label}: tampered wire must differ from source",
            );
        }

        let parsed = IdentityRecord::parse_and_verify(expected_wire_str);
        if case.expected_parse_result.as_deref() == Some("none") {
            assert!(parsed.is_none(), "{label}: parse_and_verify should fail");
        } else {
            let (record, _sig) =
                parsed.unwrap_or_else(|| panic!("{label}: parse_and_verify must succeed"));
            if let Some(expected_user) = &case.expected_parse_username {
                assert_eq!(
                    &record.username, expected_user,
                    "{label}: parsed username mismatch",
                );
            }
        }
    }
}

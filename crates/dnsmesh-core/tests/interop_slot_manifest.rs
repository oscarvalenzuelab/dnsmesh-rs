//! Byte-level interop check for [`dnsmesh_core::manifest::SlotManifest`] against
//! the Python reference vectors.
//!
//! Each case in `tests/interop/vectors/slot_manifest.json` is one of:
//! - A fresh-sign case: holds full `inputs`, a `sender_seed_hex`, and the
//!   expected wire string as UTF-8 hex. Building the manifest and signing it
//!   with the seeded key must reproduce that exact wire string.
//! - A tampered case: holds `wire_from_case` and `expected_parse_result == "none"`.
//!   `expected_wire_hex` is the corrupted wire — we cross-check it differs
//!   from the named earlier wire by exactly one signature byte and assert
//!   `parse_and_verify` rejects it.
//!
//! Vectors are committed to the repo and serve as the M1 wire-format gate.

use dnsmesh_core::crypto::DmpCrypto;
use dnsmesh_core::manifest::{SlotManifest, MSG_ID_LEN, RECIPIENT_ID_LEN};
use serde::Deserialize;

const VECTORS_JSON: &str = include_str!("interop/vectors/slot_manifest.json");

#[derive(Debug, Deserialize)]
struct Inputs {
    data_chunks: u32,
    exp: u64,
    msg_id_hex: String,
    prekey_id: u32,
    recipient_id_hex: String,
    sender_spk_hex: String,
    total_chunks: u32,
    ts: u64,
}

#[derive(Debug, Deserialize)]
struct Case {
    description: String,
    #[serde(default)]
    expected_parse_total_chunks: Option<u32>,
    expected_wire_hex: String,
    #[serde(default)]
    expected_multi_string: Option<bool>,
    #[serde(default)]
    expected_parse_result: Option<String>,
    #[serde(default)]
    inputs: Option<Inputs>,
    #[serde(default)]
    sender_seed_hex: Option<String>,
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
    let seed_hex = case
        .sender_seed_hex
        .as_deref()
        .unwrap_or_else(|| panic!("[{label}] fresh case missing sender_seed_hex"));
    let seed = hex::decode(seed_hex)
        .unwrap_or_else(|e| panic!("[{label}] sender_seed_hex decode failed: {e}"));
    let crypto = DmpCrypto::from_private_bytes(&seed)
        .unwrap_or_else(|e| panic!("[{label}] DmpCrypto::from_private_bytes failed: {e:?}"));

    let msg_id = decode_array::<MSG_ID_LEN>(&inputs.msg_id_hex, "msg_id_hex", label);
    let recipient_id =
        decode_array::<RECIPIENT_ID_LEN>(&inputs.recipient_id_hex, "recipient_id_hex", label);
    let sender_spk = decode_array::<32>(&inputs.sender_spk_hex, "sender_spk_hex", label);

    // Sanity: the seeded crypto's signing pubkey must match the sender_spk
    // fed into the manifest, otherwise the produced wire cannot match the
    // Python vector.
    assert_eq!(
        sender_spk,
        crypto.signing_public_key_bytes(),
        "[{label}] sender_spk_hex does not match key derived from sender_seed_hex",
    );

    let manifest = SlotManifest {
        msg_id,
        sender_spk,
        recipient_id,
        total_chunks: inputs.total_chunks,
        data_chunks: inputs.data_chunks,
        prekey_id: inputs.prekey_id,
        ts: inputs.ts,
        exp: inputs.exp,
    };

    let wire = manifest
        .sign(&crypto)
        .unwrap_or_else(|e| panic!("[{label}] sign failed: {e:?}"));
    let wire_hex = hex::encode(wire.as_bytes());
    assert_eq!(
        wire_hex, case.expected_wire_hex,
        "[{label}] wire bytes do not match Python vector",
    );

    let (parsed, _sig) = SlotManifest::parse_and_verify(&wire)
        .unwrap_or_else(|| panic!("[{label}] parse_and_verify rejected fresh-signed wire"));
    assert_eq!(parsed, manifest, "[{label}] parsed manifest != original");
    if let Some(expected_total) = case.expected_parse_total_chunks {
        assert_eq!(
            parsed.total_chunks, expected_total,
            "[{label}] parsed total_chunks mismatch",
        );
    }
    // Silence dead-field warning on the optional multi-string flag.
    let _ = case.expected_multi_string;
    wire
}

fn run_tampered_case(case: &Case, src_wire: &str, label: &str) {
    // The vector's expected_wire_hex IS the tampered wire (the Python
    // generator flipped one byte of the signature trailer). Sanity-check
    // that interpretation: it must be the same length as the source and
    // differ by exactly one byte. Then assert verification rejects it.
    let src_hex = hex::encode(src_wire.as_bytes());
    let tampered_hex = &case.expected_wire_hex;
    assert_eq!(
        src_hex.len(),
        tampered_hex.len(),
        "[{label}] tampered wire length differs from source",
    );
    let differing: Vec<usize> = src_hex
        .as_bytes()
        .iter()
        .zip(tampered_hex.as_bytes().iter())
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        differing.len(),
        1,
        "[{label}] expected exactly one byte of difference vs source, found {} at {:?}",
        differing.len(),
        differing,
    );
    // The differing byte must be in the trailing signature region. In UTF-8
    // hex of the wire, the final base64 group covers the last 8 hex chars.
    let diff_pos = differing[0];
    assert!(
        diff_pos >= tampered_hex.len() - 8,
        "[{label}] tampered byte at hex position {diff_pos} is not in the trailing signature region",
    );

    let tampered_bytes = hex::decode(tampered_hex)
        .unwrap_or_else(|e| panic!("[{label}] tampered wire hex decode failed: {e}"));
    let tampered_str = std::str::from_utf8(&tampered_bytes)
        .unwrap_or_else(|e| panic!("[{label}] tampered wire is not UTF-8: {e}"));

    assert!(
        SlotManifest::parse_and_verify(tampered_str).is_none(),
        "[{label}] parse_and_verify must reject tampered signature",
    );
}

#[test]
fn slot_manifest_matches_python_vectors() {
    let cases: Vec<Case> =
        serde_json::from_str(VECTORS_JSON).expect("slot_manifest.json must be valid JSON");

    // Wire strings of fresh-sign cases, indexed by case position so tampered
    // cases can reference an earlier wire via `wire_from_case`.
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
            let src_idx = case
                .wire_source
                .unwrap_or_else(|| panic!("[{label}] tampered case missing wire_from_case"));
            let src_wire = wires
                .get(src_idx)
                .and_then(|w| w.as_ref())
                .unwrap_or_else(|| panic!("[{label}] wire_from_case={src_idx} not yet built"));
            run_tampered_case(case, src_wire, &label);
            wires.push(None);
        }
    }
}

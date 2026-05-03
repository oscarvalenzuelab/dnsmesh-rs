//! Byte-level interop tests for cluster manifests.
//!
//! Each case in `tests/interop/vectors/cluster_manifest.json` validates either:
//!   - the round-trip from `(operator_seed, inputs)` -> signed wire string
//!     equals the Python-emitted `expected_wire_hex` byte-for-byte; AND
//!   - `parse_and_verify` against the recorded operator key returns the
//!     expected `ClusterManifest` (or `None` when `expected_parse_result`
//!     is `"none"`).

use dnsmesh_core::cluster::{ClusterManifest, ClusterNode, OPERATOR_SPK_LEN};
use dnsmesh_core::crypto::DmpCrypto;
use serde::Deserialize;

const VECTORS_JSON: &str = include_str!("interop/vectors/cluster_manifest.json");

#[derive(Debug, Deserialize)]
struct InputNode {
    node_id: String,
    http_endpoint: String,
    #[serde(default)]
    dns_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Inputs {
    cluster_name: String,
    exp: u64,
    nodes: Vec<InputNode>,
    operator_spk_hex: String,
    seq: u64,
}

#[allow(clippy::struct_field_names)]
#[derive(Debug, Deserialize)]
struct Case {
    description: String,
    #[serde(default)]
    expected_parse_cluster_name: Option<String>,
    #[serde(default)]
    expected_parse_seq: Option<u64>,
    expected_wire_hex: String,
    #[serde(default)]
    #[allow(dead_code)]
    expected_multi_string: Option<bool>,
    #[serde(default)]
    expected_parse_result: Option<String>,
    #[serde(default)]
    inputs: Option<Inputs>,
    #[serde(default)]
    operator_seed_hex: Option<String>,
    #[serde(default)]
    verify_with_operator_spk_hex: Option<String>,
    #[serde(default)]
    verify_with_now: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    wire_from_case: Option<usize>,
}

fn decode_array_32(label: &str, hex_str: &str) -> [u8; OPERATOR_SPK_LEN] {
    let raw = hex::decode(hex_str).unwrap_or_else(|e| panic!("{label}: invalid hex: {e}"));
    assert_eq!(
        raw.len(),
        OPERATOR_SPK_LEN,
        "{label}: expected {OPERATOR_SPK_LEN} bytes, got {}",
        raw.len()
    );
    let mut out = [0u8; OPERATOR_SPK_LEN];
    out.copy_from_slice(&raw);
    out
}

#[test]
fn cluster_manifest_interop_vectors() {
    let cases: Vec<Case> = serde_json::from_str(VECTORS_JSON).expect("parse cluster_manifest.json");
    assert!(
        !cases.is_empty(),
        "cluster_manifest.json must contain at least one case"
    );

    for (idx, case) in cases.iter().enumerate() {
        let label = format!("case[{idx}]: {}", case.description);
        let expected_wire_bytes = hex::decode(&case.expected_wire_hex)
            .unwrap_or_else(|e| panic!("[{label}] expected_wire_hex: {e}"));
        let expected_wire_str = std::str::from_utf8(&expected_wire_bytes)
            .unwrap_or_else(|e| panic!("[{label}] expected_wire_hex is not utf-8: {e}"));

        // Fresh-sign branch: build the manifest from inputs and assert the
        // signed wire reproduces the Python vector byte-for-byte.
        if let Some(inputs) = &case.inputs {
            let seed_hex = case
                .operator_seed_hex
                .as_ref()
                .unwrap_or_else(|| panic!("[{label}] missing operator_seed_hex"));
            let seed = hex::decode(seed_hex)
                .unwrap_or_else(|e| panic!("[{label}] operator_seed_hex: {e}"));
            let crypto = DmpCrypto::from_private_bytes(&seed)
                .unwrap_or_else(|e| panic!("[{label}] DmpCrypto::from_private_bytes: {e:?}"));

            let operator_spk = decode_array_32("inputs.operator_spk_hex", &inputs.operator_spk_hex);
            assert_eq!(
                crypto.signing_public_key_bytes(),
                operator_spk,
                "[{label}] derived operator_spk does not match input vector",
            );

            let nodes: Vec<ClusterNode> = inputs
                .nodes
                .iter()
                .map(|n| ClusterNode {
                    node_id: n.node_id.clone(),
                    http_endpoint: n.http_endpoint.clone(),
                    dns_endpoint: n.dns_endpoint.clone(),
                })
                .collect();
            let mut manifest = ClusterManifest {
                cluster_name: inputs.cluster_name.clone(),
                operator_spk,
                nodes,
                seq: inputs.seq,
                exp: inputs.exp,
            };
            let wire = manifest
                .sign(&crypto)
                .unwrap_or_else(|e| panic!("[{label}] sign failed: {e:?}"));
            assert_eq!(
                wire.as_bytes(),
                expected_wire_bytes.as_slice(),
                "[{label}] signed wire does not match expected_wire_hex",
            );
        }

        // The pinned key for parse_and_verify: prefer the explicit
        // verify_with_operator_spk_hex (used by tampered cases) and fall
        // back to inputs.operator_spk_hex for fresh cases.
        let verify_spk = case
            .verify_with_operator_spk_hex
            .as_deref()
            .or(case.inputs.as_ref().map(|i| i.operator_spk_hex.as_str()));
        let verify_spk_bytes = verify_spk
            .map(|h| hex::decode(h).unwrap_or_else(|e| panic!("[{label}] verify spk hex: {e}")));
        let verify_spk_slice: Option<&[u8]> = verify_spk_bytes.as_deref();

        // Pick a "now" for expiry: explicit verify_with_now wins; otherwise
        // a value strictly less than inputs.exp; if no inputs at all (pure
        // tampered case verifying against a different pinned key), use 0.
        let now = case
            .verify_with_now
            .or_else(|| case.inputs.as_ref().map(|i| i.exp));

        let parsed =
            ClusterManifest::parse_and_verify(expected_wire_str, verify_spk_slice, None, now);
        match case.expected_parse_result.as_deref() {
            Some("none") => {
                assert!(parsed.is_none(), "[{label}] parse_and_verify should fail");
            }
            None | Some("ok") => {
                let manifest =
                    parsed.unwrap_or_else(|| panic!("[{label}] parse_and_verify must succeed"));
                if let Some(expected_name) = &case.expected_parse_cluster_name {
                    assert_eq!(
                        &manifest.cluster_name, expected_name,
                        "[{label}] parsed cluster_name mismatch",
                    );
                }
                if let Some(expected_seq) = case.expected_parse_seq {
                    assert_eq!(manifest.seq, expected_seq, "[{label}] parsed seq mismatch");
                }
            }
            Some(other) => panic!("[{label}] unknown expected_parse_result: {other}"),
        }
    }
}

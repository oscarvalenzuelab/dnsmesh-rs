//! Byte-level interop tests for `dnsmesh-core::prekeys` against the Python
//! reference vectors at `tests/interop/vectors/prekey.json`.
//!
//! Each case validates either:
//!   - the round-trip from `(seed, inputs)` -> signed wire string equals
//!     the Python-emitted `expected_wire_hex` byte-for-byte; AND/OR
//!   - `parse_and_verify` against `verify_with_signer_spk_hex` returns the
//!     expected `Prekey` (or `None` when `expected_parse_result == "none"`).
//!
//! Per the Python contract, `parse_and_verify` does NOT check expiry. The
//! "expired" vector therefore parses successfully; the test additionally
//! asserts `is_expired(Some(now))` is `true` for a current timestamp.

use dnsmesh_core::crypto::DmpCrypto;
use dnsmesh_core::prekeys::Prekey;
use serde::Deserialize;

const VECTORS: &str = include_str!("interop/vectors/prekey.json");

#[derive(Debug, Deserialize)]
struct Inputs {
    exp: u64,
    prekey_id: u32,
    public_key_hex: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    description: String,
    #[serde(default)]
    expected_parse_prekey_id: Option<u32>,
    expected_wire_hex: String,
    #[serde(default)]
    expected_parse_result: Option<String>,
    #[serde(default)]
    inputs: Option<Inputs>,
    signer_seed_hex: String,
    verify_with_signer_spk_hex: String,
    #[serde(default)]
    notes: Option<String>,
}

fn decode_array_32(label: &str, hex_str: &str) -> [u8; 32] {
    let raw = hex::decode(hex_str).unwrap_or_else(|e| panic!("{label}: invalid hex: {e}"));
    assert_eq!(
        raw.len(),
        32,
        "{label}: expected 32 bytes, got {}",
        raw.len()
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    out
}

#[test]
fn prekey_interop_vectors() {
    let cases: Vec<Case> = serde_json::from_str(VECTORS).expect("parse prekey.json");
    assert!(
        !cases.is_empty(),
        "prekey.json must contain at least one case"
    );

    for case in &cases {
        let label = &case.description;
        if let Some(notes) = &case.notes {
            eprintln!("[{label}] notes: {notes}");
        }

        let expected_wire_bytes =
            hex::decode(&case.expected_wire_hex).expect("expected_wire_hex must be valid hex");
        let expected_wire_str = std::str::from_utf8(&expected_wire_bytes)
            .expect("expected_wire_hex must decode to valid UTF-8");

        // If the case carries inputs, build the prekey from the signer seed and
        // assert sign() reproduces the Python wire bytes verbatim.
        if let Some(inputs) = &case.inputs {
            let seed = hex::decode(&case.signer_seed_hex).expect("signer_seed_hex valid hex");
            let crypto =
                DmpCrypto::from_private_bytes(&seed).expect("32-byte seed builds DmpCrypto");
            let public_key = decode_array_32("inputs.public_key_hex", &inputs.public_key_hex);

            let prekey = Prekey {
                prekey_id: inputs.prekey_id,
                public_key,
                exp: inputs.exp,
            };
            let wire = prekey.sign(&crypto).expect("sign must not fail");
            assert_eq!(
                wire, expected_wire_str,
                "[{label}] signed wire does not match expected bytes",
            );
        }

        // Always exercise parse_and_verify against the supplied verifier key.
        let verify_spk =
            hex::decode(&case.verify_with_signer_spk_hex).expect("verify_spk valid hex");
        let parsed = Prekey::parse_and_verify(expected_wire_str, &verify_spk);

        match case.expected_parse_result.as_deref() {
            Some("none") => {
                assert!(
                    parsed.is_none(),
                    "[{label}] parse_and_verify must return None",
                );
            }
            None | Some("ok") => {
                let parsed =
                    parsed.unwrap_or_else(|| panic!("[{label}] parse_and_verify must return Some"));
                if let Some(expected_id) = case.expected_parse_prekey_id {
                    assert_eq!(
                        parsed.prekey_id, expected_id,
                        "[{label}] parsed prekey_id mismatch",
                    );
                }
                if let Some(inputs) = &case.inputs {
                    assert_eq!(parsed.exp, inputs.exp, "[{label}] parsed exp mismatch");
                    let expected_pk =
                        decode_array_32("inputs.public_key_hex", &inputs.public_key_hex);
                    assert_eq!(
                        parsed.public_key, expected_pk,
                        "[{label}] parsed public_key mismatch",
                    );

                    // For the "expired" vector, assert is_expired() is true at "now".
                    // The Python comment says: parse_and_verify does NOT check expiry;
                    // the caller does. Use exp+1 as the clock so this is deterministic.
                    if inputs.exp < 1_000_000_000 {
                        assert!(
                            parsed.is_expired(Some(inputs.exp + 1)),
                            "[{label}] is_expired must be true past exp",
                        );
                    }
                }
            }
            Some(other) => panic!("[{label}] unknown expected_parse_result: {other}"),
        }
    }
}

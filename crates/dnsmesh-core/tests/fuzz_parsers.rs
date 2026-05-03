//! Property-based parser-robustness fuzz harness.
//!
//! Mirrors the Hypothesis suite under `tests/fuzz/` in the Python source of
//! truth. The invariant is the same across all record types: for ANY input
//! the per-module `parse_and_verify` entry point must return `None` (or a
//! valid record / record-plus-signature tuple) and must never panic. An
//! escaping panic is a DoS vector — every record type's parser sits on a
//! trust boundary that decodes peer-supplied DNS TXT bytes.
//!
//! Strategy budget per test is governed by `DMP_FUZZ_MAX_EXAMPLES` to match
//! the Python `conftest.py` knob; default 500 keeps local runs under a few
//! seconds, CI's weekly cron sets 5000 for deeper coverage.
//!
//! Each module gets coverage over:
//!   * arbitrary `text` up to ~2 KB
//!   * arbitrary binary blobs base64-wrapped behind the module's record prefix
//!   * arbitrary hex bodies after the prefix (subset of base64 alphabet —
//!     exercises the "valid b64, garbage body" path)
//!   * fuzz over the externally-supplied pinned arguments where the Rust API
//!     accepts them (signer/operator/old/revoked SPK pins, expected subject,
//!     `now`, `ts_skew_seconds`)
//!
//! For `heartbeat` we also exercise prefix variants (sampled from valid /
//! malformed / wrong-type prefixes) because the Python harness does so.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use dnsmesh_core::bootstrap::{BootstrapRecord, RECORD_PREFIX as BOOTSTRAP_PREFIX};
use dnsmesh_core::cluster::{ClusterManifest, RECORD_PREFIX as CLUSTER_PREFIX};
use dnsmesh_core::heartbeat::{
    HeartbeatRecord, DEFAULT_TS_SKEW_SECONDS as HEARTBEAT_TS_SKEW,
    RECORD_PREFIX as HEARTBEAT_PREFIX,
};
use dnsmesh_core::identity::{IdentityRecord, RECORD_PREFIX as IDENTITY_PREFIX};
use dnsmesh_core::manifest::{SlotManifest, RECORD_PREFIX as MANIFEST_PREFIX};
use dnsmesh_core::prekeys::{Prekey, RECORD_PREFIX as PREKEY_PREFIX};
use dnsmesh_core::revocation::{RevocationRecord, RECORD_PREFIX as REVOCATION_PREFIX};
use dnsmesh_core::rotation::{RotationRecord, RECORD_PREFIX as ROTATION_PREFIX};
use proptest::collection::vec;
use proptest::prelude::*;

/// Read `DMP_FUZZ_MAX_EXAMPLES` from the environment (mirrors Python's
/// `conftest.py`). Default 500.
fn cases() -> u32 {
    std::env::var("DMP_FUZZ_MAX_EXAMPLES")
        .ok()
        .and_then(|raw| raw.parse::<u32>().ok())
        .unwrap_or(500)
}

/// Wraps an arbitrary blob as `prefix || base64(blob)` — the synthetic-
/// but-prefixed wire shape the Python harness uses to defeat the prefix
/// guard and exercise the body parser directly.
fn b64_after(prefix: &str, blob: &[u8]) -> String {
    format!("{prefix}{}", BASE64_STANDARD.encode(blob))
}

/// Wraps a blob as `prefix || hex(blob)` — hex is a strict subset of the
/// base64 alphabet so the b64 decoder accepts it; this exercises the
/// "valid b64, garbage body" path (matches Python's
/// `test_parse_never_raises_on_truncated_prefix`).
fn hex_after(prefix: &str, blob: &[u8]) -> String {
    format!("{prefix}{}", hex::encode(blob))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]

    // ---- identity ---------------------------------------------------------

    #[test]
    fn identity_parse_never_panics_on_arbitrary_text(wire in ".{0,2048}") {
        let _ = IdentityRecord::parse_and_verify(&wire);
    }

    #[test]
    fn identity_parse_never_panics_on_synthetic_wire(blob in vec(any::<u8>(), 0..2048)) {
        let _ = IdentityRecord::parse_and_verify(&b64_after(IDENTITY_PREFIX, &blob));
    }

    #[test]
    fn identity_parse_never_panics_on_hex_body(trailing in vec(any::<u8>(), 0..64)) {
        let _ = IdentityRecord::parse_and_verify(&hex_after(IDENTITY_PREFIX, &trailing));
    }

    // ---- slot manifest ----------------------------------------------------

    #[test]
    fn manifest_parse_never_panics_on_arbitrary_text(wire in ".{0,2048}") {
        let _ = SlotManifest::parse_and_verify(&wire);
    }

    #[test]
    fn manifest_parse_never_panics_on_synthetic_wire(blob in vec(any::<u8>(), 0..2048)) {
        let _ = SlotManifest::parse_and_verify(&b64_after(MANIFEST_PREFIX, &blob));
    }

    #[test]
    fn manifest_parse_never_panics_on_hex_body(trailing in vec(any::<u8>(), 0..64)) {
        let _ = SlotManifest::parse_and_verify(&hex_after(MANIFEST_PREFIX, &trailing));
    }

    // ---- prekey -----------------------------------------------------------

    #[test]
    fn prekey_parse_never_panics_on_arbitrary_text(
        wire in ".{0,2048}",
        spk in vec(any::<u8>(), 0..64),
    ) {
        let _ = Prekey::parse_and_verify(&wire, &spk);
    }

    #[test]
    fn prekey_parse_never_panics_on_synthetic_wire(
        blob in vec(any::<u8>(), 0..2048),
        spk in vec(any::<u8>(), 0..64),
    ) {
        let _ = Prekey::parse_and_verify(&b64_after(PREKEY_PREFIX, &blob), &spk);
    }

    #[test]
    fn prekey_parse_never_panics_on_hex_body(
        trailing in vec(any::<u8>(), 0..64),
        spk in vec(any::<u8>(), 0..64),
    ) {
        let _ = Prekey::parse_and_verify(&hex_after(PREKEY_PREFIX, &trailing), &spk);
    }

    #[test]
    fn prekey_parse_never_panics_on_arbitrary_signer_spk(spk in vec(any::<u8>(), 0..64)) {
        let _ = Prekey::parse_and_verify(&format!("{PREKEY_PREFIX}AAAA"), &spk);
    }

    // ---- bootstrap --------------------------------------------------------

    #[test]
    fn bootstrap_parse_never_panics_on_arbitrary_text(
        wire in ".{0,2048}",
        spk in vec(any::<u8>(), 0..64),
        now in any::<u64>(),
    ) {
        let _ = BootstrapRecord::parse_and_verify(&wire, Some(&spk), None, Some(now));
    }

    #[test]
    fn bootstrap_parse_never_panics_on_synthetic_wire(
        blob in vec(any::<u8>(), 0..2048),
        spk in vec(any::<u8>(), 0..64),
        now in any::<u64>(),
    ) {
        let _ = BootstrapRecord::parse_and_verify(
            &b64_after(BOOTSTRAP_PREFIX, &blob),
            Some(&spk),
            None,
            Some(now),
        );
    }

    #[test]
    fn bootstrap_parse_never_panics_on_hex_body(
        trailing in vec(any::<u8>(), 0..64),
        spk in vec(any::<u8>(), 0..64),
        now in any::<u64>(),
    ) {
        let _ = BootstrapRecord::parse_and_verify(
            &hex_after(BOOTSTRAP_PREFIX, &trailing),
            Some(&spk),
            None,
            Some(now),
        );
    }

    #[test]
    fn bootstrap_parse_never_panics_on_arbitrary_signer_spk(
        spk in vec(any::<u8>(), 0..64),
    ) {
        let _ = BootstrapRecord::parse_and_verify(
            &format!("{BOOTSTRAP_PREFIX}AAAA"),
            Some(&spk),
            None,
            None,
        );
    }

    // ---- cluster manifest -------------------------------------------------

    #[test]
    fn cluster_parse_never_panics_on_arbitrary_text(
        wire in ".{0,2048}",
        op_spk in vec(any::<u8>(), 0..64),
        now in any::<u64>(),
    ) {
        let _ = ClusterManifest::parse_and_verify(&wire, Some(&op_spk), None, Some(now));
    }

    #[test]
    fn cluster_parse_never_panics_on_synthetic_wire(
        blob in vec(any::<u8>(), 0..2048),
        op_spk in vec(any::<u8>(), 0..64),
        now in any::<u64>(),
    ) {
        let _ = ClusterManifest::parse_and_verify(
            &b64_after(CLUSTER_PREFIX, &blob),
            Some(&op_spk),
            None,
            Some(now),
        );
    }

    #[test]
    fn cluster_parse_never_panics_on_hex_body(
        trailing in vec(any::<u8>(), 0..64),
        op_spk in vec(any::<u8>(), 0..64),
        now in any::<u64>(),
    ) {
        let _ = ClusterManifest::parse_and_verify(
            &hex_after(CLUSTER_PREFIX, &trailing),
            Some(&op_spk),
            None,
            Some(now),
        );
    }

    #[test]
    fn cluster_parse_never_panics_on_arbitrary_operator_spk(
        op_spk in vec(any::<u8>(), 0..64),
    ) {
        let _ = ClusterManifest::parse_and_verify(
            &format!("{CLUSTER_PREFIX}AAAA"),
            Some(&op_spk),
            None,
            None,
        );
    }

    // ---- heartbeat --------------------------------------------------------

    #[test]
    fn heartbeat_parse_never_panics_on_arbitrary_text(
        wire in ".{0,2048}",
        now in any::<u64>(),
        skew in any::<u64>(),
    ) {
        let _ = HeartbeatRecord::parse_and_verify(&wire, Some(now), skew);
    }

    #[test]
    fn heartbeat_parse_never_panics_on_synthetic_wire(
        blob in vec(any::<u8>(), 0..2048),
        now in any::<u64>(),
    ) {
        let _ = HeartbeatRecord::parse_and_verify(
            &b64_after(HEARTBEAT_PREFIX, &blob),
            Some(now),
            HEARTBEAT_TS_SKEW,
        );
    }

    #[test]
    fn heartbeat_parse_never_panics_on_hex_body(
        body in vec(any::<u8>(), 0..500),
        now in any::<u64>(),
    ) {
        let _ = HeartbeatRecord::parse_and_verify(
            &hex_after(HEARTBEAT_PREFIX, &body),
            Some(now),
            HEARTBEAT_TS_SKEW,
        );
    }

    #[test]
    fn heartbeat_parse_never_panics_on_prefix_variants(
        prefix_idx in 0usize..5,
        body in vec(any::<u8>(), 0..200),
        now in any::<u64>(),
    ) {
        let prefixes = [
            HEARTBEAT_PREFIX,
            "v=dmp1;t=heartbeat",
            "v=dmp1;t=rotation;",
            "",
            "v=dmp2;t=heartbeat;",
        ];
        let prefix = prefixes[prefix_idx];
        let wire = format!("{prefix}{}", BASE64_STANDARD.encode(&body));
        let _ = HeartbeatRecord::parse_and_verify(&wire, Some(now), HEARTBEAT_TS_SKEW);
    }

    // ---- rotation ---------------------------------------------------------

    #[test]
    fn rotation_parse_never_panics_on_arbitrary_text(
        wire in ".{0,2048}",
        old_spk in vec(any::<u8>(), 0..64),
        subject in ".{0,256}",
        now in any::<u64>(),
    ) {
        let _ = RotationRecord::parse_and_verify(
            &wire,
            Some(&old_spk),
            Some(&subject),
            Some(now),
        );
    }

    #[test]
    fn rotation_parse_never_panics_on_synthetic_wire(
        blob in vec(any::<u8>(), 0..2048),
        old_spk in vec(any::<u8>(), 0..64),
        subject in ".{0,256}",
        now in any::<u64>(),
    ) {
        let _ = RotationRecord::parse_and_verify(
            &b64_after(ROTATION_PREFIX, &blob),
            Some(&old_spk),
            Some(&subject),
            Some(now),
        );
    }

    #[test]
    fn rotation_parse_never_panics_on_hex_body(
        trailing in vec(any::<u8>(), 0..64),
        old_spk in vec(any::<u8>(), 0..64),
        subject in ".{0,256}",
        now in any::<u64>(),
    ) {
        let _ = RotationRecord::parse_and_verify(
            &hex_after(ROTATION_PREFIX, &trailing),
            Some(&old_spk),
            Some(&subject),
            Some(now),
        );
    }

    #[test]
    fn rotation_parse_never_panics_on_arbitrary_expected_old_spk(
        spk in vec(any::<u8>(), 0..64),
    ) {
        let _ = RotationRecord::parse_and_verify(
            &format!("{ROTATION_PREFIX}AAAA"),
            Some(&spk),
            None,
            None,
        );
    }

    #[test]
    fn rotation_parse_never_panics_on_arbitrary_expected_subject(
        subject in ".{0,256}",
    ) {
        let _ = RotationRecord::parse_and_verify(
            &format!("{ROTATION_PREFIX}AAAA"),
            None,
            Some(&subject),
            None,
        );
    }

    // ---- revocation -------------------------------------------------------

    #[test]
    fn revocation_parse_never_panics_on_arbitrary_text(
        wire in ".{0,2048}",
        revoked_spk in vec(any::<u8>(), 0..64),
        subject in ".{0,256}",
        now in any::<u64>(),
        max_age in any::<u64>(),
    ) {
        let _ = RevocationRecord::parse_and_verify(
            &wire,
            Some(&revoked_spk),
            Some(&subject),
            Some(now),
            Some(max_age),
        );
    }

    #[test]
    fn revocation_parse_never_panics_on_synthetic_wire(
        blob in vec(any::<u8>(), 0..2048),
        revoked_spk in vec(any::<u8>(), 0..64),
        subject in ".{0,256}",
        now in any::<u64>(),
    ) {
        let _ = RevocationRecord::parse_and_verify(
            &b64_after(REVOCATION_PREFIX, &blob),
            Some(&revoked_spk),
            Some(&subject),
            Some(now),
            None,
        );
    }

    #[test]
    fn revocation_parse_never_panics_on_hex_body(
        trailing in vec(any::<u8>(), 0..64),
        revoked_spk in vec(any::<u8>(), 0..64),
        subject in ".{0,256}",
        now in any::<u64>(),
    ) {
        let _ = RevocationRecord::parse_and_verify(
            &hex_after(REVOCATION_PREFIX, &trailing),
            Some(&revoked_spk),
            Some(&subject),
            Some(now),
            None,
        );
    }

    #[test]
    fn revocation_parse_never_panics_on_arbitrary_expected_revoked_spk(
        spk in vec(any::<u8>(), 0..64),
    ) {
        let _ = RevocationRecord::parse_and_verify(
            &format!("{REVOCATION_PREFIX}AAAA"),
            Some(&spk),
            None,
            None,
            None,
        );
    }

    #[test]
    fn revocation_parse_never_panics_on_arbitrary_expected_subject(
        subject in ".{0,256}",
    ) {
        let _ = RevocationRecord::parse_and_verify(
            &format!("{REVOCATION_PREFIX}AAAA"),
            None,
            Some(&subject),
            None,
            None,
        );
    }
}

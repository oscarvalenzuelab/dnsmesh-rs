//! DNS-name helpers shared by the send and receive paths.
//!
//! Ports the four naming primitives from the Python `DMPClient` (lines 325-341
//! of `dmp/client/client.py`) verbatim. Everything else in the client crate
//! routes through these so a future change to the addressing scheme has a
//! single edit point.

use sha2::{Digest, Sha256};

/// Length of every routing-label hash used in this module.
///
/// 12 hex chars = 48 bits = ample collision resistance for a per-mailbox label
/// while staying well under DNS's 63-byte label cap.
const HASH12_LEN: usize = 12;

/// 12-hex-char SHA-256 prefix of `bytes`.
///
/// Used for the recipient mailbox label (`mb-<hash12>`) and for the per-message
/// chunk-routing key. Matches Python `DMPClient._hash12`.
#[must_use]
pub fn hash12(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let hex_digest = hex::encode(digest);
    hex_digest[..HASH12_LEN].to_string()
}

/// Strip a single trailing dot from a domain literal.
///
/// DNS treats `mesh.local` and `mesh.local.` as the same name; senders / readers
/// in the client code work with the un-rooted form so concatenated labels do
/// not produce `slot-3.mb-….mesh.local..`.
fn trim_zone(zone: &str) -> &str {
    zone.trim_end_matches('.')
}

/// Mailbox slot DNS name for `recipient_id` under `zone`.
///
/// `recipient_id` is the SHA-256 of the recipient's X25519 public key (i.e.
/// [`dnsmesh_core::derive_user_id`] output). `slot` is in `0..SLOT_COUNT`.
/// Matches Python `DMPClient._slot_domain`.
#[must_use]
pub fn slot_domain(recipient_id: &[u8; 32], slot: u32, zone: &str) -> String {
    format!(
        "slot-{}.mb-{}.{}",
        slot,
        hash12(recipient_id),
        trim_zone(zone)
    )
}

/// 12-char per-message routing key derived from `(msg_id, recipient_id, sender_spk)`.
///
/// The recipient can compute the same key without knowing the sender's X25519
/// public key in advance; only the `sender_spk` (Ed25519 signing key) is needed.
/// Matches Python `DMPClient._msg_key`.
#[must_use]
pub fn msg_key(msg_id: &[u8; 16], recipient_id: &[u8; 32], sender_spk: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(msg_id);
    hasher.update(recipient_id);
    hasher.update(sender_spk);
    let digest = hasher.finalize();
    let hex_digest = hex::encode(digest);
    hex_digest[..HASH12_LEN].to_string()
}

/// Chunk DNS name for `chunk_num` of message `msg_key` under `zone`.
///
/// Matches Python `DMPClient._chunk_domain`. `chunk_num` is rendered with at
/// least four digits (`{chunk_num:04}`) so naive lex-sort over the chunk RRset
/// gives the natural chunk order.
#[must_use]
pub fn chunk_domain(msg_key: &str, chunk_num: u32, zone: &str) -> String {
    format!("chunk-{:04}-{}.{}", chunk_num, msg_key, trim_zone(zone))
}

/// Number of mailbox slots per recipient.
///
/// Matches Python `SLOT_COUNT`. Senders pick a slot deterministically from the
/// first 4 bytes of `msg_id` so receivers see a roughly-even RRset spread.
pub const SLOT_COUNT: u32 = 10;

/// Default message TTL in seconds.
///
/// Matches Python `DEFAULT_TTL_SECONDS` (5 minutes). The receive-side replay
/// cache and slot-manifest expiration are sized in concert with this constant.
pub const DEFAULT_TTL_SECONDS: u64 = 300;

/// Default prekey-pool TTL in seconds, matching Python `refresh_prekeys` (24h).
pub const DEFAULT_PREKEY_TTL_SECONDS: u64 = 86_400;

/// Pick a slot index from `msg_id`, matching Python's
/// `int.from_bytes(msg_id[:4], "big") % SLOT_COUNT`.
#[must_use]
pub fn slot_for_msg_id(msg_id: &[u8; 16]) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&msg_id[..4]);
    u32::from_be_bytes(buf) % SLOT_COUNT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash12_is_first_12_hex_chars_of_sha256() {
        // sha256(b"alice") = 2bd806c97f0e00af1a1fc3328fa763a9269723c8db8fac4f93af71db186d6e90
        assert_eq!(hash12(b"alice"), "2bd806c97f0e");
    }

    #[test]
    fn slot_domain_matches_python_layout() {
        let rid = [0xCDu8; 32];
        let got = slot_domain(&rid, 3, "mesh.example.com");
        let expected = format!("slot-3.mb-{}.mesh.example.com", hash12(&rid));
        assert_eq!(got, expected);
    }

    #[test]
    fn slot_domain_strips_trailing_dot() {
        let rid = [0u8; 32];
        let with_dot = slot_domain(&rid, 0, "mesh.example.com.");
        let without_dot = slot_domain(&rid, 0, "mesh.example.com");
        assert_eq!(with_dot, without_dot);
    }

    #[test]
    fn msg_key_combines_three_inputs_in_order() {
        let msg_id = [0x11u8; 16];
        let rid = [0x22u8; 32];
        let spk = [0x33u8; 32];
        let key = msg_key(&msg_id, &rid, &spk);
        // Independently derive the expected prefix.
        let mut hasher = Sha256::new();
        hasher.update(msg_id);
        hasher.update(rid);
        hasher.update(spk);
        let expected_full = hex::encode(hasher.finalize());
        assert_eq!(key, &expected_full[..12]);
    }

    #[test]
    fn chunk_domain_formats_with_four_digit_zero_pad() {
        let key = "abcdef012345";
        assert_eq!(
            chunk_domain(key, 7, "mesh.local"),
            "chunk-0007-abcdef012345.mesh.local",
        );
        assert_eq!(
            chunk_domain(key, 1234, "mesh.local"),
            "chunk-1234-abcdef012345.mesh.local",
        );
    }

    #[test]
    fn slot_for_msg_id_is_deterministic_modulo_slot_count() {
        // msg_id whose first 4 bytes are 0x00_00_00_05 → slot 5.
        let mut msg_id = [0u8; 16];
        msg_id[3] = 5;
        assert_eq!(slot_for_msg_id(&msg_id), 5 % SLOT_COUNT);
        // 0x00_00_00_0A → slot 0 (10 % 10).
        msg_id[3] = 10;
        assert_eq!(slot_for_msg_id(&msg_id), 0);
    }
}

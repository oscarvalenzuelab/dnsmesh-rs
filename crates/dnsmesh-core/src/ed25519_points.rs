//! Ed25519 low-order / small-subgroup public-key block list.
//!
//! Holding any of these as an Ed25519 public key lets an attacker forge a signature that
//! the permissive RFC-8032 verify accepts:
//!
//! - Identity point (`01 00..00`) with `sig = identity || 0^32` verifies on every message —
//!   a complete signature-forgery bypass.
//! - Other small-order points (orders 2, 4, 8) allow forgery on subsets of messages, which
//!   is still grindable.
//!
//! Reference: <https://pkg.go.dev/c2sp.org/CCTV/ed25519>.
//!
//! Every DMP wire-format consumer that builds a `VerifyingKey` from raw 32-byte input must
//! first reject keys in this set. Centralising the list here means a future addition only
//! needs to update one file.

const fn parse_hex(hex: &[u8; 64]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let hi = hex_nibble(hex[i * 2]);
        let lo = hex_nibble(hex[i * 2 + 1]);
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    out
}

const fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("invalid hex digit in low-order pubkey table"),
    }
}

/// Canonical encodings of small-order points (orders 1, 2, 4, 8) plus non-canonical aliases
/// that some Ed25519 implementations still accept as valid 32-byte pubkey encodings.
pub const LOW_ORDER_ED25519_PUBKEYS: &[[u8; 32]] = &[
    parse_hex(b"0100000000000000000000000000000000000000000000000000000000000000"),
    parse_hex(b"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    parse_hex(b"0000000000000000000000000000000000000000000000000000000000000080"),
    parse_hex(b"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    parse_hex(b"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    parse_hex(b"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    parse_hex(b"0000000000000000000000000000000000000000000000000000000000000000"),
    parse_hex(b"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
    parse_hex(b"0100000000000000000000000000000000000000000000000000000000000080"),
    parse_hex(b"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    parse_hex(b"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    parse_hex(b"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    parse_hex(b"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    parse_hex(b"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
];

/// Returns `true` iff `pubkey` is a known low-order / small-subgroup Ed25519 public-key
/// encoding that must be rejected before any verify.
///
/// Wrong-length inputs return `true` (fail closed).
#[must_use]
pub fn is_low_order(pubkey: &[u8]) -> bool {
    if pubkey.len() != 32 {
        return true;
    }
    LOW_ORDER_ED25519_PUBKEYS
        .iter()
        .any(|candidate| candidate.as_slice() == pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_length() {
        assert!(is_low_order(&[0u8; 31]));
        assert!(is_low_order(&[0u8; 33]));
        assert!(is_low_order(&[]));
    }

    #[test]
    fn rejects_identity_point() {
        let mut identity = [0u8; 32];
        identity[0] = 0x01;
        assert!(is_low_order(&identity));
    }

    #[test]
    fn rejects_all_zero() {
        assert!(is_low_order(&[0u8; 32]));
    }

    #[test]
    fn accepts_typical_random_pubkey() {
        // Sample of published interop-vector signing pubkey — real, non-low-order.
        let pk = hex::decode("293c1c181315c368e21344d717faef768dc1bbc5d1d2dcde62a2d77888441575")
            .unwrap();
        assert!(!is_low_order(&pk));
    }

    #[test]
    fn table_size_matches_python() {
        assert_eq!(LOW_ORDER_ED25519_PUBKEYS.len(), 14);
    }

    #[test]
    fn all_table_entries_are_unique() {
        let mut sorted: Vec<&[u8; 32]> = LOW_ORDER_ED25519_PUBKEYS.iter().collect();
        sorted.sort_unstable();
        for window in sorted.windows(2) {
            assert_ne!(window[0], window[1]);
        }
    }
}

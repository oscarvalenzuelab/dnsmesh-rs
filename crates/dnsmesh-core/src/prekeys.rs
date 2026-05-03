//! X3DH-style one-time prekeys: wire format only.
//!
//! Each user publishes a pool of single-use X25519 prekeys signed by their
//! Ed25519 identity. Senders pick an unused prekey, use it in ECDH instead of
//! the long-term key, and the recipient deletes the matching prekey_sk after
//! the first successful decrypt — that is the forward-secrecy property.
//!
//! This module mirrors the wire-format portion of Python `dmp/core/prekeys.py`.
//! The persistent `PrekeyStore` (sqlite-backed private key storage) lives in
//! `dnsmesh-storage`, not here.
//!
//! Wire format (one TXT record per prekey, all at the same RRset name):
//!
//! ```text
//! prekeys.id-<username_hash12>.<domain>  IN TXT  "v=dmp1;t=prekey;d=<b64>"
//!
//! body  = prekey_id(4 BE) || x25519_pub(32) || exp(8 BE)   = 44 bytes
//! sig   = Ed25519 signature over body                      = 64 bytes
//! total = 108 bytes; base64 = 144 chars; +18-char prefix   = 162-char wire
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use sha2::{Digest, Sha256};

use crate::crypto::{DmpCrypto, ED25519_SIG_LEN, X25519_KEY_LEN};

/// TXT record prefix carrying a signed prekey blob. Matches Python `RECORD_PREFIX`.
pub const RECORD_PREFIX: &str = "v=dmp1;t=prekey;d=";

/// Length of the signed body in bytes: `prekey_id(4) || public_key(32) || exp(8)`.
pub const BODY_LEN: usize = 4 + X25519_KEY_LEN + 8;

/// Length of the trailing Ed25519 signature.
pub const SIG_LEN: usize = ED25519_SIG_LEN;

/// Length of the full base64-decoded wire payload (`body || sig`).
pub const WIRE_LEN: usize = BODY_LEN + SIG_LEN;

/// Errors returned by prekey wire-format helpers.
#[derive(Debug, thiserror::Error)]
pub enum PrekeyError {
    /// `Prekey::to_body_bytes` was called with a `public_key` of the wrong length.
    /// Currently unreachable while `public_key` is `[u8; 32]`, but kept so the API
    /// matches the Python `ValueError("public_key must be 32 bytes")` shape.
    #[error("public_key must be {expected} bytes, got {actual}")]
    InvalidPublicKeyLength { expected: usize, actual: usize },
    /// `Prekey::from_body_bytes` was given a body of the wrong length.
    #[error("prekey body must be {expected} bytes, got {actual}")]
    InvalidBodyLength { expected: usize, actual: usize },
}

/// DNS RRset name at which a user's prekey pool is published.
///
/// Matches Python `prekey_rrset_name`: `prekeys.id-<sha256(username)[:12 hex]>.<base_domain>`.
/// Note: the prekey label uses 12 hex chars of the SHA-256 digest, which differs from the
/// 16-hex-char identity-record label.
#[must_use]
pub fn prekey_rrset_name(username: &str, base_domain: &str) -> String {
    let digest = Sha256::digest(username.as_bytes());
    let hex_digest = hex::encode(digest);
    let username_hash = &hex_digest[..12];
    let domain = base_domain.trim_end_matches('.');
    format!("prekeys.id-{username_hash}.{domain}")
}

/// A single one-time prekey record (public side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prekey {
    /// 32-bit unsigned id, unique within an identity's pool.
    pub prekey_id: u32,
    /// 32-byte X25519 public key.
    pub public_key: [u8; X25519_KEY_LEN],
    /// Unix seconds after which the recipient may drop this prekey.
    pub exp: u64,
}

impl Prekey {
    /// Serialize the signed body: `prekey_id(4 BE) || public_key(32) || exp(8 BE)`.
    pub fn to_body_bytes(&self) -> Result<Vec<u8>, PrekeyError> {
        // public_key is a fixed-size array, so its length is always correct. The check
        // is kept symmetric with Python's runtime guard on the bytes input.
        if self.public_key.len() != X25519_KEY_LEN {
            return Err(PrekeyError::InvalidPublicKeyLength {
                expected: X25519_KEY_LEN,
                actual: self.public_key.len(),
            });
        }
        let mut out = Vec::with_capacity(BODY_LEN);
        out.extend_from_slice(&self.prekey_id.to_be_bytes());
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.exp.to_be_bytes());
        Ok(out)
    }

    /// Parse a 44-byte body into a `Prekey`.
    pub fn from_body_bytes(body: &[u8]) -> Result<Self, PrekeyError> {
        if body.len() != BODY_LEN {
            return Err(PrekeyError::InvalidBodyLength {
                expected: BODY_LEN,
                actual: body.len(),
            });
        }
        let mut prekey_id_bytes = [0u8; 4];
        prekey_id_bytes.copy_from_slice(&body[0..4]);
        let prekey_id = u32::from_be_bytes(prekey_id_bytes);

        let mut public_key = [0u8; X25519_KEY_LEN];
        public_key.copy_from_slice(&body[4..4 + X25519_KEY_LEN]);

        let mut exp_bytes = [0u8; 8];
        exp_bytes.copy_from_slice(&body[4 + X25519_KEY_LEN..BODY_LEN]);
        let exp = u64::from_be_bytes(exp_bytes);

        Ok(Self {
            prekey_id,
            public_key,
            exp,
        })
    }

    /// Sign the body with `identity_crypto` and emit the full TXT record string.
    ///
    /// Returns `RECORD_PREFIX || base64(body || sig)`.
    pub fn sign(&self, identity_crypto: &DmpCrypto) -> Result<String, PrekeyError> {
        let body = self.to_body_bytes()?;
        let sig = identity_crypto.sign_data(&body);
        let mut wire = Vec::with_capacity(WIRE_LEN);
        wire.extend_from_slice(&body);
        wire.extend_from_slice(&sig);
        Ok(format!("{RECORD_PREFIX}{}", B64.encode(&wire)))
    }

    /// Parse and verify a prekey TXT record against `expected_signer_spk`.
    ///
    /// Returns `Some(prekey)` on success and `None` if the record is malformed,
    /// the base64 body is the wrong length, or the signature does not verify.
    /// Prekey records do NOT self-identify their signer (unlike identity records),
    /// so the caller must supply the right Ed25519 verifying key.
    ///
    /// **Note:** matches the Python contract — expiration is NOT checked here.
    /// Callers must invoke [`Prekey::is_expired`] separately.
    #[must_use]
    pub fn parse_and_verify(record: &str, expected_signer_spk: &[u8]) -> Option<Self> {
        let payload = record.strip_prefix(RECORD_PREFIX)?;
        let wire = B64.decode(payload).ok()?;
        if wire.len() != WIRE_LEN {
            return None;
        }
        let body = &wire[..BODY_LEN];
        let sig = &wire[BODY_LEN..];
        let prekey = Self::from_body_bytes(body).ok()?;
        if !DmpCrypto::verify_signature(body, sig, expected_signer_spk) {
            return None;
        }
        Some(prekey)
    }

    /// Returns `true` if `now > self.exp`. If `now` is `None`, the current Unix time is used.
    #[must_use]
    pub fn is_expired(&self, now: Option<u64>) -> bool {
        let now = now.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
        });
        now > self.exp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNER_SEED_HEX: &str =
        "45b6daf877b118ed4dc7a671a2c6c22a2f948128ae90a18b6ab79eb2376ef21f";
    const SIGNER_SPK_HEX: &str = "fb1d8e4b6d90111419e0f36b2e9acfc8d90737affcbe6bd552aa71b53021030c";
    const PREKEY_PUB_HEX: &str = "166224215e81ec9487c2c21064bfd9dee493413c29336e1a1f05a98ece191e76";

    fn signer() -> DmpCrypto {
        let seed = hex::decode(SIGNER_SEED_HEX).unwrap();
        DmpCrypto::from_private_bytes(&seed).unwrap()
    }

    fn pubkey() -> [u8; X25519_KEY_LEN] {
        let raw = hex::decode(PREKEY_PUB_HEX).unwrap();
        let mut pk = [0u8; X25519_KEY_LEN];
        pk.copy_from_slice(&raw);
        pk
    }

    fn sample_prekey() -> Prekey {
        Prekey {
            prekey_id: 1,
            public_key: pubkey(),
            exp: 2_051_222_400,
        }
    }

    #[test]
    fn body_round_trips_44_bytes() {
        let pk = sample_prekey();
        let body = pk.to_body_bytes().unwrap();
        assert_eq!(body.len(), BODY_LEN);
        let parsed = Prekey::from_body_bytes(&body).unwrap();
        assert_eq!(parsed, pk);
    }

    #[test]
    fn from_body_bytes_rejects_wrong_length() {
        assert!(matches!(
            Prekey::from_body_bytes(&[0u8; 43]),
            Err(PrekeyError::InvalidBodyLength {
                expected: 44,
                actual: 43
            }),
        ));
        assert!(matches!(
            Prekey::from_body_bytes(&[0u8; 45]),
            Err(PrekeyError::InvalidBodyLength {
                expected: 44,
                actual: 45
            }),
        ));
    }

    #[test]
    fn prekey_rrset_name_uses_12_hex_chars() {
        let name = prekey_rrset_name("alice", "example.com");
        // sha256("alice") = 2bd806c97f0e00af1a1fc3328fa763a9269723c8db8fac4f93af71db186d6e90
        assert_eq!(name, "prekeys.id-2bd806c97f0e.example.com");
        // Confirm exactly 12 hex chars between the prefix and the domain.
        let label = name
            .strip_prefix("prekeys.id-")
            .unwrap()
            .strip_suffix(".example.com")
            .unwrap();
        assert_eq!(label.len(), 12);
        assert!(label.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn prekey_rrset_name_strips_trailing_dot() {
        let with_dot = prekey_rrset_name("alice", "example.com.");
        let without_dot = prekey_rrset_name("alice", "example.com");
        assert_eq!(with_dot, without_dot);
    }

    #[test]
    fn sign_and_parse_verify_round_trip() {
        let crypto = signer();
        let pk = sample_prekey();
        let wire = pk.sign(&crypto).unwrap();
        let spk = crypto.signing_public_key_bytes();
        let parsed = Prekey::parse_and_verify(&wire, &spk).expect("verify must succeed");
        assert_eq!(parsed, pk);
    }

    #[test]
    fn parse_and_verify_rejects_missing_prefix() {
        let crypto = signer();
        let pk = sample_prekey();
        let wire = pk.sign(&crypto).unwrap();
        let stripped = wire.strip_prefix(RECORD_PREFIX).unwrap();
        let spk = crypto.signing_public_key_bytes();
        assert!(Prekey::parse_and_verify(stripped, &spk).is_none());
    }

    #[test]
    fn parse_and_verify_rejects_bad_base64() {
        let spk = hex::decode(SIGNER_SPK_HEX).unwrap();
        let bogus = format!("{RECORD_PREFIX}!!!not-base64!!!");
        assert!(Prekey::parse_and_verify(&bogus, &spk).is_none());
    }

    #[test]
    fn parse_and_verify_rejects_short_payload() {
        // Valid base64, but wrong wire length.
        let bogus = format!("{RECORD_PREFIX}{}", B64.encode([0u8; 10]));
        let spk = hex::decode(SIGNER_SPK_HEX).unwrap();
        assert!(Prekey::parse_and_verify(&bogus, &spk).is_none());
    }

    #[test]
    fn parse_and_verify_rejects_wrong_signer_spk() {
        let crypto = signer();
        let pk = sample_prekey();
        let wire = pk.sign(&crypto).unwrap();
        // A different identity's spk must not verify the signature.
        let other = DmpCrypto::from_private_bytes(&[7u8; 32]).unwrap();
        let other_spk = other.signing_public_key_bytes();
        assert!(Prekey::parse_and_verify(&wire, &other_spk).is_none());
    }

    #[test]
    fn is_expired_with_provided_now() {
        let pk = sample_prekey();
        // exp = 2_051_222_400; now=0 -> not expired; now=u64::MAX -> expired.
        assert!(!pk.is_expired(Some(0)));
        assert!(pk.is_expired(Some(u64::MAX)));
        // Boundary: now == exp is NOT expired (Python uses `now > exp`).
        assert!(!pk.is_expired(Some(pk.exp)));
        assert!(pk.is_expired(Some(pk.exp + 1)));
    }
}

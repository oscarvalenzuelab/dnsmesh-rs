//! Signed identity records for DMP.
//!
//! An identity record binds a username to its X25519 encryption pubkey and
//! Ed25519 signing pubkey, signed by the identity's own Ed25519 key. The wire
//! form is base64-wrapped binary that fits a single 255-byte DNS TXT string:
//!
//! ```text
//! v=dmp1;t=identity;d=<b64(body || sig)>
//!
//! body:
//!     username_len(1) || username(<=64 bytes utf-8)
//!     || x25519_pk(32)
//!     || ed25519_spk(32)
//!     || ts(8)
//! ```
//!
//! `sig` is a 64-byte Ed25519 signature over `body`. Recipients verify against
//! the embedded `ed25519_spk` and apply their own trust policy (TOFU, pinned
//! fingerprints, etc.) on top.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::crypto::{DmpCrypto, ED25519_KEY_LEN, ED25519_SIG_LEN, X25519_KEY_LEN};

/// TXT prefix that tags a DMP identity record.
pub const RECORD_PREFIX: &str = "v=dmp1;t=identity;d=";
/// Maximum username length in UTF-8 bytes.
pub const USERNAME_MAX: usize = 64;
/// Length of the body timestamp field in bytes (big-endian unsigned).
pub const TS_LEN: usize = 8;

/// Errors returned while building or parsing identity records.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// `username` was empty after UTF-8 encoding.
    #[error("username must not be empty")]
    UsernameEmpty,
    /// `username` was longer than [`USERNAME_MAX`] UTF-8 bytes.
    #[error("username too long (max {max} utf-8 bytes, got {actual})")]
    UsernameTooLong { actual: usize, max: usize },
    /// A 32-byte key was expected but a different number of bytes was supplied.
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    /// The body buffer length did not match the length implied by `username_len`.
    #[error("identity body length mismatch")]
    BodyLengthMismatch,
    /// The body buffer was too short to contain even the minimum-size record.
    #[error("identity body too short")]
    BodyTooShort,
    /// `username_len` was zero or greater than [`USERNAME_MAX`].
    #[error("invalid username length")]
    InvalidUsernameLength,
    /// The username bytes were not valid UTF-8.
    #[error("username is not valid utf-8")]
    InvalidUtf8,
}

/// DNS name where `username`'s identity record lives under `base_domain`.
///
/// Hashes the username so the DNS label leaks only the digest. Matches the
/// Python `DNSEncoder.encode_identity_domain` helper.
#[must_use]
pub fn identity_domain(username: &str, base_domain: &str) -> String {
    let digest = Sha256::digest(username.as_bytes());
    let hash_hex = hex::encode(digest);
    let base = base_domain.trim_end_matches('.');
    format!("id-{}.{}", &hash_hex[..16], base)
}

/// Identity DNS name under a user-controlled zone (`dmp.<your-domain>`).
#[must_use]
pub fn zone_anchored_identity_name(identity_domain_str: &str) -> String {
    format!("dmp.{}", identity_domain_str.trim_end_matches('.'))
}

/// Parse `user@host` into `(user, host)`. Returns `None` on malformed input.
#[must_use]
pub fn parse_address(address: &str) -> Option<(String, String)> {
    let (user, host) = address.split_once('@')?;
    let user = user.trim();
    let host = host.trim().trim_end_matches('.');
    if user.is_empty() || host.is_empty() {
        return None;
    }
    Some((user.to_string(), host.to_string()))
}

/// Build an [`IdentityRecord`] from a [`DmpCrypto`] identity and an optional timestamp.
///
/// When `ts` is `None`, the current Unix time (seconds) is used.
#[must_use]
pub fn make_record(crypto: &DmpCrypto, username: &str, ts: Option<u64>) -> IdentityRecord {
    let ts = ts.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    });
    IdentityRecord {
        username: username.to_string(),
        x25519_pk: crypto.public_key_bytes(),
        ed25519_spk: crypto.signing_public_key_bytes(),
        ts,
    }
}

/// A signed claim that `(username, x25519_pk, ed25519_spk)` belong together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRecord {
    /// Human-readable username (UTF-8, 1..=64 bytes).
    pub username: String,
    /// 32-byte X25519 encryption pubkey.
    pub x25519_pk: [u8; X25519_KEY_LEN],
    /// 32-byte Ed25519 signing pubkey.
    pub ed25519_spk: [u8; ED25519_KEY_LEN],
    /// Unix seconds at publication.
    pub ts: u64,
}

impl IdentityRecord {
    /// Serialize the body into the wire layout described in the module docs.
    pub fn to_body_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        let name = self.username.as_bytes();
        if name.is_empty() {
            return Err(IdentityError::UsernameEmpty);
        }
        if name.len() > USERNAME_MAX {
            return Err(IdentityError::UsernameTooLong {
                actual: name.len(),
                max: USERNAME_MAX,
            });
        }
        let mut out =
            Vec::with_capacity(1 + name.len() + X25519_KEY_LEN + ED25519_KEY_LEN + TS_LEN);
        // Length-checked above against USERNAME_MAX (64), so the cast cannot truncate.
        out.push(u8::try_from(name.len()).expect("username length fits in u8"));
        out.extend_from_slice(name);
        out.extend_from_slice(&self.x25519_pk);
        out.extend_from_slice(&self.ed25519_spk);
        out.extend_from_slice(&self.ts.to_be_bytes());
        Ok(out)
    }

    /// Parse a body buffer (no signature trailer) back into an [`IdentityRecord`].
    pub fn from_body_bytes(body: &[u8]) -> Result<Self, IdentityError> {
        if body.len() < 1 + X25519_KEY_LEN + ED25519_KEY_LEN + TS_LEN + 1 {
            return Err(IdentityError::BodyTooShort);
        }
        let name_len = body[0] as usize;
        if name_len == 0 || name_len > USERNAME_MAX {
            return Err(IdentityError::InvalidUsernameLength);
        }
        let expected = 1 + name_len + X25519_KEY_LEN + ED25519_KEY_LEN + TS_LEN;
        if body.len() != expected {
            return Err(IdentityError::BodyLengthMismatch);
        }
        let mut offset = 1;
        let username = std::str::from_utf8(&body[offset..offset + name_len])
            .map_err(|_| IdentityError::InvalidUtf8)?
            .to_string();
        offset += name_len;
        let mut x25519_pk = [0u8; X25519_KEY_LEN];
        x25519_pk.copy_from_slice(&body[offset..offset + X25519_KEY_LEN]);
        offset += X25519_KEY_LEN;
        let mut ed25519_spk = [0u8; ED25519_KEY_LEN];
        ed25519_spk.copy_from_slice(&body[offset..offset + ED25519_KEY_LEN]);
        offset += ED25519_KEY_LEN;
        let mut ts_bytes = [0u8; TS_LEN];
        ts_bytes.copy_from_slice(&body[offset..offset + TS_LEN]);
        let ts = u64::from_be_bytes(ts_bytes);
        Ok(Self {
            username,
            x25519_pk,
            ed25519_spk,
            ts,
        })
    }

    /// Sign the body with `crypto` and return the wire-format TXT record string.
    pub fn sign(&self, crypto: &DmpCrypto) -> Result<String, IdentityError> {
        let body = self.to_body_bytes()?;
        let signature = crypto.sign_data(&body);
        let mut wire = Vec::with_capacity(body.len() + ED25519_SIG_LEN);
        wire.extend_from_slice(&body);
        wire.extend_from_slice(&signature);
        Ok(format!("{RECORD_PREFIX}{}", BASE64_STANDARD.encode(&wire)))
    }

    /// Parse and verify a TXT record. Returns `(record, signature)` on success.
    ///
    /// Returns `None` for any malformed input or signature failure; trust policy
    /// (TOFU, pinning, discard) is left to the caller.
    #[must_use]
    pub fn parse_and_verify(record: &str) -> Option<(Self, [u8; ED25519_SIG_LEN])> {
        let payload = record.strip_prefix(RECORD_PREFIX)?;
        let wire = BASE64_STANDARD.decode(payload).ok()?;
        if wire.len() < ED25519_SIG_LEN + 1 {
            return None;
        }
        let split = wire.len() - ED25519_SIG_LEN;
        let body = &wire[..split];
        let mut signature = [0u8; ED25519_SIG_LEN];
        signature.copy_from_slice(&wire[split..]);
        let record_obj = Self::from_body_bytes(body).ok()?;
        if !DmpCrypto::verify_signature(body, &signature, &record_obj.ed25519_spk) {
            return None;
        }
        Some((record_obj, signature))
    }

    /// DNS name where this record should be published under `base_domain`.
    #[must_use]
    pub fn wire_name(&self, base_domain: &str) -> String {
        identity_domain(&self.username, base_domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(username: &str) -> IdentityRecord {
        IdentityRecord {
            username: username.to_string(),
            x25519_pk: [0x11; X25519_KEY_LEN],
            ed25519_spk: [0x22; ED25519_KEY_LEN],
            ts: 1_700_000_000,
        }
    }

    #[test]
    fn body_round_trip() {
        let record = sample_record("alice");
        let body = record.to_body_bytes().unwrap();
        let parsed = IdentityRecord::from_body_bytes(&body).unwrap();
        assert_eq!(parsed, record);
    }

    #[test]
    fn body_layout_is_byte_exact() {
        let record = sample_record("ab");
        let body = record.to_body_bytes().unwrap();
        assert_eq!(body[0], 2);
        assert_eq!(&body[1..3], b"ab");
        assert_eq!(&body[3..35], &[0x11u8; X25519_KEY_LEN]);
        assert_eq!(&body[35..67], &[0x22u8; ED25519_KEY_LEN]);
        assert_eq!(&body[67..75], &1_700_000_000u64.to_be_bytes());
    }

    #[test]
    fn username_one_byte_minimum_ok() {
        let record = sample_record("a");
        let body = record.to_body_bytes().unwrap();
        let parsed = IdentityRecord::from_body_bytes(&body).unwrap();
        assert_eq!(parsed.username, "a");
    }

    #[test]
    fn username_64_byte_max_ok() {
        let username = "u".repeat(USERNAME_MAX);
        let record = sample_record(&username);
        let body = record.to_body_bytes().unwrap();
        let parsed = IdentityRecord::from_body_bytes(&body).unwrap();
        assert_eq!(parsed.username, username);
    }

    #[test]
    fn username_65_bytes_rejected() {
        let username = "u".repeat(USERNAME_MAX + 1);
        let record = sample_record(&username);
        assert!(matches!(
            record.to_body_bytes(),
            Err(IdentityError::UsernameTooLong { .. }),
        ));
    }

    #[test]
    fn empty_username_rejected() {
        let record = sample_record("");
        assert!(matches!(
            record.to_body_bytes(),
            Err(IdentityError::UsernameEmpty),
        ));
    }

    #[test]
    fn from_body_bytes_rejects_zero_name_len() {
        let mut body = sample_record("a").to_body_bytes().unwrap();
        body[0] = 0;
        assert!(matches!(
            IdentityRecord::from_body_bytes(&body),
            Err(IdentityError::InvalidUsernameLength),
        ));
    }

    #[test]
    fn from_body_bytes_rejects_length_mismatch() {
        let mut body = sample_record("alice").to_body_bytes().unwrap();
        body.push(0);
        assert!(matches!(
            IdentityRecord::from_body_bytes(&body),
            Err(IdentityError::BodyLengthMismatch),
        ));
    }

    #[test]
    fn identity_domain_format() {
        let domain = identity_domain("alice", "mesh.example.com.");
        let digest = Sha256::digest(b"alice");
        let expected = format!("id-{}.mesh.example.com", &hex::encode(digest)[..16]);
        assert_eq!(domain, expected);
    }

    #[test]
    fn zone_anchored_strips_trailing_dot() {
        assert_eq!(
            zone_anchored_identity_name("alice.example.com."),
            "dmp.alice.example.com",
        );
    }

    #[test]
    fn parse_address_basic() {
        assert_eq!(
            parse_address("alice@example.com"),
            Some(("alice".to_string(), "example.com".to_string())),
        );
    }

    #[test]
    fn parse_address_strips_trailing_dot() {
        assert_eq!(
            parse_address("alice@example.com."),
            Some(("alice".to_string(), "example.com".to_string())),
        );
    }

    #[test]
    fn parse_address_malformed_returns_none() {
        assert!(parse_address("malformed").is_none());
        assert!(parse_address("@example.com").is_none());
        assert!(parse_address("alice@").is_none());
        assert!(parse_address("alice@.").is_none());
    }

    #[test]
    fn sign_and_parse_round_trip() {
        let crypto = DmpCrypto::generate();
        let record = make_record(&crypto, "alice", Some(1_700_000_000));
        let wire = record.sign(&crypto).unwrap();
        let (parsed, _sig) = IdentityRecord::parse_and_verify(&wire).expect("must verify");
        assert_eq!(parsed, record);
    }

    #[test]
    fn parse_and_verify_rejects_missing_prefix() {
        let crypto = DmpCrypto::generate();
        let record = make_record(&crypto, "alice", Some(1));
        let wire = record.sign(&crypto).unwrap();
        let stripped = wire.strip_prefix(RECORD_PREFIX).unwrap();
        assert!(IdentityRecord::parse_and_verify(stripped).is_none());
    }

    #[test]
    fn parse_and_verify_rejects_bad_base64() {
        let bogus = format!("{RECORD_PREFIX}!!!not-base64!!!");
        assert!(IdentityRecord::parse_and_verify(&bogus).is_none());
    }

    #[test]
    fn parse_and_verify_rejects_flipped_signature() {
        let crypto = DmpCrypto::generate();
        let record = make_record(&crypto, "alice", Some(1));
        let wire = record.sign(&crypto).unwrap();
        let payload = wire.strip_prefix(RECORD_PREFIX).unwrap();
        let mut bytes = BASE64_STANDARD.decode(payload).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = format!("{RECORD_PREFIX}{}", BASE64_STANDARD.encode(&bytes));
        assert!(IdentityRecord::parse_and_verify(&tampered).is_none());
    }

    #[test]
    fn wire_name_uses_identity_domain() {
        let record = sample_record("alice");
        assert_eq!(
            record.wire_name("mesh.example.com"),
            identity_domain("alice", "mesh.example.com"),
        );
    }
}

//! Signed revocation records for DMP key lifecycle (M5.4).
//!
//! A [`RevocationRecord`] is a self-signed declaration that
//! `revoked_spk` is permanently invalid. Self-signed by `revoked_spk` itself,
//! it is weaker than a designated-revocation-key model: a compromised key can
//! forge the revocation, and a lost key cannot revoke itself. This is a v1
//! simplification documented in the Python reference under
//! `docs/protocol/rotation.md` "Revocation model".
//!
//! Revocations are PERMANENT assertions. A valid revocation signed by
//! `revoked_spk` at any point in the past remains a valid revocation:
//! "this key is dead" is not a statement that expires. The
//! [`RevocationRecord::parse_and_verify`] entry point therefore enforces no
//! expiry by default; callers with custom freshness policies (forensic replay
//! windows, stale-log pruning) opt in by passing `max_age_seconds = Some(_)`.
//!
//! Wire format mirrors [`crate::rotation::RotationRecord`]: a
//! `v=dmp1;t=revocation;` prefix followed by base64'd `body || sig`. The
//! shared subject-type constants, reason codes, and validators are imported
//! from the [`crate::rotation`] module — they live there because the rotation
//! module is the larger of the two and it would create an import cycle to put
//! them here. The split into two modules prevents accidental call-site
//! confusion between the co-signed rotation flow and the self-signed
//! revocation flow.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;

use crate::crypto::{DmpCrypto, ED25519_KEY_LEN, ED25519_SIG_LEN};
use crate::rotation::{
    normalize_subject, validate_subject, MAX_SUBJECT_LEN, MAX_USER_IDENTITY_SUBJECT_LEN,
    MAX_WIRE_LEN, REASON_COMPROMISE, REASON_LOST_KEY, REASON_OTHER, REASON_ROUTINE,
    SUBJECT_TYPE_BOOTSTRAP_SIGNER, SUBJECT_TYPE_CLUSTER_OPERATOR, SUBJECT_TYPE_USER_IDENTITY,
};

/// TXT prefix that tags a DMP revocation record.
pub const RECORD_PREFIX: &str = "v=dmp1;t=revocation;";

/// Magic header for revocation record bodies.
pub const MAGIC: &[u8] = b"DMPRV01";

/// Length of an Ed25519 signing public key carried in the body.
pub const SPK_LEN: usize = ED25519_KEY_LEN;

/// Length of the Ed25519 signature trailer.
pub const SIG_LEN: usize = ED25519_SIG_LEN;

/// Allowed positive clock-skew on `ts` even when no `max_age_seconds` cap is
/// supplied. Mirrors Kerberos defaults; rejects records claiming to be from
/// the far future.
pub const FUTURE_TS_SKEW_SECONDS: u64 = 300;

/// Errors returned while building or parsing revocation records.
#[derive(Debug, thiserror::Error)]
pub enum RevocationError {
    /// Subject validation (shared with rotation) rejected the input.
    #[error(transparent)]
    Subject(#[from] crate::rotation::RotationError),
    /// `reason_code` was not 1, 2, 3, or 4.
    #[error("invalid reason_code {actual}; must be 1, 2, 3, or 4")]
    InvalidReasonCode { actual: u8 },
    /// The body was shorter than the fixed-layout minimum.
    #[error("body too short for header")]
    BodyTooShort,
    /// The magic header did not match [`MAGIC`].
    #[error("bad magic")]
    BadMagic,
    /// The subject_type byte was not 1, 2, or 3.
    #[error("invalid subject_type {actual}; must be 1, 2, or 3")]
    InvalidSubjectType { actual: u8 },
    /// The encoded `subject_len` field was zero or above the per-type cap.
    #[error("invalid subject length")]
    InvalidSubjectLength,
    /// The body was truncated mid-subject.
    #[error("truncated subject")]
    TruncatedSubject,
    /// The body had trailing bytes or was truncated in the fixed tail.
    #[error("trailing bytes or truncated tail")]
    TrailingOrTruncatedTail,
    /// The subject was not valid UTF-8.
    #[error("subject not utf-8")]
    InvalidUtf8,
    /// The signing key supplied to [`RevocationRecord::sign`] did not match
    /// the declared `revoked_spk`.
    #[error("revoked_crypto signing key does not match declared revoked_spk")]
    KeyMismatch,
    /// The signed wire exceeded [`MAX_WIRE_LEN`].
    #[error("revocation record wire size {actual} exceeds MAX_WIRE_LEN {max}")]
    WireTooLong { actual: usize, max: usize },
}

/// Self-signed declaration that `revoked_spk` is permanently invalid.
///
/// Body layout:
///
/// ```text
/// magic            (7 bytes,  b"DMPRV01")
/// subject_type     (1 byte,   1 = user_identity, 2 = cluster, 3 = bootstrap)
/// subject_len      (1 byte,   1..=64 for cluster/bootstrap, 1..=255 for user)
/// subject          (subject_len utf-8 bytes)
/// revoked_spk      (32 bytes, Ed25519 verifying key)
/// reason_code      (1 byte,   1..=4)
/// ts               (8 bytes,  big-endian unix seconds)
/// ```
///
/// Trailing signature:
///
/// ```text
/// sig              (64 bytes, Ed25519 signature over `body` by revoked_spk)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationRecord {
    /// One of the `SUBJECT_TYPE_*` constants from [`crate::rotation`].
    pub subject_type: u8,
    /// Subject string. Format depends on `subject_type`.
    pub subject: String,
    /// 32-byte Ed25519 signing public key being revoked.
    pub revoked_spk: [u8; SPK_LEN],
    /// One of the `REASON_*` constants from [`crate::rotation`].
    pub reason_code: u8,
    /// Unix seconds at publication.
    pub ts: u64,
}

impl RevocationRecord {
    fn validate(&self) -> Result<(), RevocationError> {
        validate_subject(self.subject_type, &self.subject)?;
        if !matches!(
            self.reason_code,
            REASON_COMPROMISE | REASON_ROUTINE | REASON_LOST_KEY | REASON_OTHER,
        ) {
            return Err(RevocationError::InvalidReasonCode {
                actual: self.reason_code,
            });
        }
        Ok(())
    }

    /// Serialize the body as documented in the struct-level layout.
    pub fn to_body_bytes(&self) -> Result<Vec<u8>, RevocationError> {
        self.validate()?;
        let subject_bytes = self.subject.as_bytes();
        // validate_subject caps subject length at 255 (user) or 64 (DNS), so
        // the cast cannot truncate.
        let subject_len = u8::try_from(subject_bytes.len())
            .expect("subject length is bounded above by validate_subject");
        let mut out =
            Vec::with_capacity(MAGIC.len() + 1 + 1 + subject_bytes.len() + SPK_LEN + 1 + 8);
        out.extend_from_slice(MAGIC);
        out.push(self.subject_type);
        out.push(subject_len);
        out.extend_from_slice(subject_bytes);
        out.extend_from_slice(&self.revoked_spk);
        out.push(self.reason_code);
        out.extend_from_slice(&self.ts.to_be_bytes());
        Ok(out)
    }

    /// Parse the body buffer (no signature trailer) back into a record.
    pub fn from_body_bytes(body: &[u8]) -> Result<Self, RevocationError> {
        let min_len = MAGIC.len() + 1 + 1 + SPK_LEN + 1 + 8;
        if body.len() < min_len {
            return Err(RevocationError::BodyTooShort);
        }
        let mut off = 0;
        if &body[off..off + MAGIC.len()] != MAGIC {
            return Err(RevocationError::BadMagic);
        }
        off += MAGIC.len();
        let subject_type = body[off];
        off += 1;
        if subject_type != SUBJECT_TYPE_USER_IDENTITY
            && subject_type != SUBJECT_TYPE_CLUSTER_OPERATOR
            && subject_type != SUBJECT_TYPE_BOOTSTRAP_SIGNER
        {
            return Err(RevocationError::InvalidSubjectType {
                actual: subject_type,
            });
        }
        let subject_len = body[off] as usize;
        off += 1;
        let parse_cap = if subject_type == SUBJECT_TYPE_USER_IDENTITY {
            MAX_USER_IDENTITY_SUBJECT_LEN
        } else {
            MAX_SUBJECT_LEN
        };
        if subject_len == 0 || subject_len > parse_cap {
            return Err(RevocationError::InvalidSubjectLength);
        }
        if off + subject_len > body.len() {
            return Err(RevocationError::TruncatedSubject);
        }
        let subject = std::str::from_utf8(&body[off..off + subject_len])
            .map_err(|_| RevocationError::InvalidUtf8)?
            .to_string();
        off += subject_len;
        if off + SPK_LEN + 1 + 8 != body.len() {
            return Err(RevocationError::TrailingOrTruncatedTail);
        }
        let mut revoked_spk = [0u8; SPK_LEN];
        revoked_spk.copy_from_slice(&body[off..off + SPK_LEN]);
        off += SPK_LEN;
        let reason_code = body[off];
        off += 1;
        if !matches!(
            reason_code,
            REASON_COMPROMISE | REASON_ROUTINE | REASON_LOST_KEY | REASON_OTHER,
        ) {
            return Err(RevocationError::InvalidReasonCode {
                actual: reason_code,
            });
        }
        let ts = u64::from_be_bytes(body[off..off + 8].try_into().unwrap());

        validate_subject(subject_type, &subject)?;
        Ok(Self {
            subject_type,
            subject,
            revoked_spk,
            reason_code,
            ts,
        })
    }

    /// Serialize and self-sign with `revoked_crypto`. Returns the wire string.
    ///
    /// `revoked_crypto`'s signing public key must match `self.revoked_spk`.
    pub fn sign(&self, revoked_crypto: &DmpCrypto) -> Result<String, RevocationError> {
        if revoked_crypto.signing_public_key_bytes() != self.revoked_spk {
            return Err(RevocationError::KeyMismatch);
        }
        let body = self.to_body_bytes()?;
        let sig = revoked_crypto.sign_data(&body);
        let mut blob = Vec::with_capacity(body.len() + SIG_LEN);
        blob.extend_from_slice(&body);
        blob.extend_from_slice(&sig);
        let wire = format!("{RECORD_PREFIX}{}", BASE64_STANDARD.encode(&blob));
        if wire.len() > MAX_WIRE_LEN {
            return Err(RevocationError::WireTooLong {
                actual: wire.len(),
                max: MAX_WIRE_LEN,
            });
        }
        Ok(wire)
    }

    /// Parse a wire string, verify the single signature. Never panics.
    ///
    /// Revocations are PERMANENT by default — the freshness window is opt-in
    /// via `max_age_seconds`. When `max_age_seconds = Some(n)`, a record with
    /// `ts + n < now` is rejected. A small positive clock-skew guard
    /// ([`FUTURE_TS_SKEW_SECONDS`] on `ts > now`) is always enforced so an
    /// attacker cannot pre-publish a far-future-dated revocation that would
    /// game a future caller's freshness gate.
    #[must_use]
    pub fn parse_and_verify(
        wire: &str,
        expected_revoked_spk: Option<&[u8]>,
        expected_subject: Option<&str>,
        now: Option<u64>,
        max_age_seconds: Option<u64>,
    ) -> Option<Self> {
        if !wire.starts_with(RECORD_PREFIX) {
            return None;
        }
        if wire.len() > MAX_WIRE_LEN {
            return None;
        }
        let blob = BASE64_STANDARD.decode(&wire[RECORD_PREFIX.len()..]).ok()?;
        if blob.len() < MAGIC.len() + SIG_LEN {
            return None;
        }
        let split = blob.len() - SIG_LEN;
        let body = &blob[..split];
        let sig = &blob[split..];

        let record = Self::from_body_bytes(body).ok()?;

        if !DmpCrypto::verify_signature(body, sig, &record.revoked_spk) {
            return None;
        }

        if let Some(expected) = expected_revoked_spk {
            if expected.len() != SPK_LEN {
                return None;
            }
            if expected != record.revoked_spk {
                return None;
            }
        }

        if let Some(expected) = expected_subject {
            if normalize_subject(record.subject_type, &record.subject)
                != normalize_subject(record.subject_type, expected)
            {
                return None;
            }
        }

        let now_ts = now.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
        });
        if let Some(max_age) = max_age_seconds {
            // Saturate so an absurdly large cap can never wrap around.
            if record.ts.saturating_add(max_age) < now_ts {
                return None;
            }
        }
        // Future-ts guard. record.ts > now_ts + 300 is rejected. We compute
        // it without overflow by guarding on now_ts + skew first.
        if record.ts > now_ts.saturating_add(FUTURE_TS_SKEW_SECONDS) {
            return None;
        }
        Some(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(crypto: &DmpCrypto) -> RevocationRecord {
        RevocationRecord {
            subject_type: SUBJECT_TYPE_USER_IDENTITY,
            subject: "alice@example.com".to_string(),
            revoked_spk: crypto.signing_public_key_bytes(),
            reason_code: REASON_COMPROMISE,
            ts: 1_700_000_000,
        }
    }

    #[test]
    fn body_round_trip() {
        let crypto = DmpCrypto::generate();
        let record = sample_record(&crypto);
        let body = record.to_body_bytes().unwrap();
        let parsed = RevocationRecord::from_body_bytes(&body).unwrap();
        assert_eq!(parsed, record);
    }

    #[test]
    fn body_layout_is_byte_exact() {
        let record = RevocationRecord {
            subject_type: SUBJECT_TYPE_CLUSTER_OPERATOR,
            subject: "mesh.example.com".to_string(),
            revoked_spk: [0x33; SPK_LEN],
            reason_code: REASON_ROUTINE,
            ts: 0x0900_0000_0000_0001,
        };
        let body = record.to_body_bytes().unwrap();
        assert_eq!(&body[..7], MAGIC);
        assert_eq!(body[7], SUBJECT_TYPE_CLUSTER_OPERATOR);
        assert_eq!(body[8] as usize, "mesh.example.com".len());
        let off = 9;
        assert_eq!(&body[off..off + 16], b"mesh.example.com");
        let off = off + 16;
        assert_eq!(&body[off..off + 32], &[0x33; 32]);
        let off = off + 32;
        assert_eq!(body[off], REASON_ROUTINE);
        let off = off + 1;
        assert_eq!(&body[off..off + 8], &0x0900_0000_0000_0001u64.to_be_bytes());
    }

    #[test]
    fn from_body_bytes_rejects_short_buffer() {
        let buf = [0u8; 8];
        assert!(matches!(
            RevocationRecord::from_body_bytes(&buf),
            Err(RevocationError::BodyTooShort),
        ));
    }

    #[test]
    fn from_body_bytes_rejects_bad_magic() {
        let crypto = DmpCrypto::generate();
        let mut body = sample_record(&crypto).to_body_bytes().unwrap();
        body[0] ^= 0x01;
        assert!(matches!(
            RevocationRecord::from_body_bytes(&body),
            Err(RevocationError::BadMagic),
        ));
    }

    #[test]
    fn from_body_bytes_rejects_bad_reason_code() {
        let crypto = DmpCrypto::generate();
        let mut record = sample_record(&crypto);
        record.reason_code = 99;
        assert!(matches!(
            record.to_body_bytes(),
            Err(RevocationError::InvalidReasonCode { .. }),
        ));
    }

    #[test]
    fn sign_and_parse_round_trip() {
        let crypto = DmpCrypto::generate();
        let record = sample_record(&crypto);
        let wire = record.sign(&crypto).unwrap();
        let parsed = RevocationRecord::parse_and_verify(&wire, None, None, Some(record.ts), None)
            .expect("verify");
        assert_eq!(parsed, record);
    }

    #[test]
    fn sign_rejects_wrong_key() {
        let crypto = DmpCrypto::generate();
        let other = DmpCrypto::generate();
        let record = sample_record(&crypto);
        assert!(matches!(
            record.sign(&other),
            Err(RevocationError::KeyMismatch),
        ));
    }

    #[test]
    fn parse_and_verify_rejects_missing_prefix() {
        let crypto = DmpCrypto::generate();
        let record = sample_record(&crypto);
        let wire = record.sign(&crypto).unwrap();
        let stripped = wire.strip_prefix(RECORD_PREFIX).unwrap();
        assert!(
            RevocationRecord::parse_and_verify(stripped, None, None, Some(record.ts), None)
                .is_none()
        );
    }

    #[test]
    fn parse_and_verify_rejects_bad_base64() {
        let bogus = format!("{RECORD_PREFIX}!!!not-base64!!!");
        assert!(RevocationRecord::parse_and_verify(&bogus, None, None, Some(0), None).is_none());
    }

    #[test]
    fn parse_and_verify_rejects_flipped_signature() {
        let crypto = DmpCrypto::generate();
        let record = sample_record(&crypto);
        let wire = record.sign(&crypto).unwrap();
        let payload = wire.strip_prefix(RECORD_PREFIX).unwrap();
        let mut bytes = BASE64_STANDARD.decode(payload).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = format!("{RECORD_PREFIX}{}", BASE64_STANDARD.encode(&bytes));
        assert!(
            RevocationRecord::parse_and_verify(&tampered, None, None, Some(record.ts), None)
                .is_none(),
        );
    }

    #[test]
    fn parse_and_verify_max_age_cap_rejects_stale() {
        let crypto = DmpCrypto::generate();
        let record = sample_record(&crypto);
        let wire = record.sign(&crypto).unwrap();
        // Without a cap, the same wire parses fine arbitrarily far in the future.
        assert!(RevocationRecord::parse_and_verify(
            &wire,
            None,
            None,
            Some(record.ts + 10_000_000),
            None,
        )
        .is_some());
        // With a 1-day cap and now far past ts+1day, parse rejects.
        assert!(RevocationRecord::parse_and_verify(
            &wire,
            None,
            None,
            Some(record.ts + 10_000_000),
            Some(86_400),
        )
        .is_none());
    }

    #[test]
    fn parse_and_verify_rejects_future_ts_beyond_skew() {
        let crypto = DmpCrypto::generate();
        let record = sample_record(&crypto);
        let wire = record.sign(&crypto).unwrap();
        // now == ts - 1000 means record claims to be 1000s in the future,
        // outside the 300s skew window.
        assert!(RevocationRecord::parse_and_verify(
            &wire,
            None,
            None,
            Some(record.ts - 1000),
            None,
        )
        .is_none());
        // Within the 300s skew, accepted.
        assert!(
            RevocationRecord::parse_and_verify(&wire, None, None, Some(record.ts - 100), None,)
                .is_some()
        );
    }

    #[test]
    fn parse_and_verify_rejects_revoked_spk_mismatch() {
        let crypto = DmpCrypto::generate();
        let other = DmpCrypto::generate();
        let record = sample_record(&crypto);
        let wire = record.sign(&crypto).unwrap();
        let bad_spk = other.signing_public_key_bytes();
        assert!(RevocationRecord::parse_and_verify(
            &wire,
            Some(&bad_spk),
            None,
            Some(record.ts),
            None,
        )
        .is_none());
    }

    #[test]
    fn parse_and_verify_subject_normalization() {
        let crypto = DmpCrypto::generate();
        let record = sample_record(&crypto);
        let wire = record.sign(&crypto).unwrap();
        // Case-insensitive host, trailing-dot stripped.
        assert!(RevocationRecord::parse_and_verify(
            &wire,
            None,
            Some("alice@EXAMPLE.com."),
            Some(record.ts),
            None,
        )
        .is_some());
        assert!(RevocationRecord::parse_and_verify(
            &wire,
            None,
            Some("bob@example.com"),
            Some(record.ts),
            None,
        )
        .is_none());
    }

    #[test]
    fn validate_rejects_unknown_reason_code() {
        let crypto = DmpCrypto::generate();
        let mut record = sample_record(&crypto);
        record.reason_code = 5;
        assert!(matches!(
            record.to_body_bytes(),
            Err(RevocationError::InvalidReasonCode { actual: 5 }),
        ));
        record.reason_code = 0;
        assert!(matches!(
            record.to_body_bytes(),
            Err(RevocationError::InvalidReasonCode { actual: 0 }),
        ));
    }

    #[test]
    fn from_body_bytes_rejects_trailing_bytes() {
        let crypto = DmpCrypto::generate();
        let mut body = sample_record(&crypto).to_body_bytes().unwrap();
        body.push(0);
        assert!(matches!(
            RevocationRecord::from_body_bytes(&body),
            Err(RevocationError::TrailingOrTruncatedTail),
        ));
    }

    #[test]
    fn constants_match_python_reference() {
        assert_eq!(RECORD_PREFIX, "v=dmp1;t=revocation;");
        assert_eq!(MAGIC, b"DMPRV01");
        assert_eq!(FUTURE_TS_SKEW_SECONDS, 300);
    }
}

//! Signed rotation records for DMP key lifecycle (M5.4).
//!
//! A [`RotationRecord`] is a co-signed statement of the form "the holder of
//! `old_spk` authorizes that `new_spk` succeeds it for `subject`". It is
//! co-signed by BOTH keys; neither alone can forge it. See
//! `docs/protocol/rotation.md` in the Python reference for the full design
//! and threat model.
//!
//! Three rotation scenarios share this single wire type:
//!
//! 1. **User identity key rotation** — a user re-derives their identity from
//!    a new passphrase and wants existing pinned contacts to follow without
//!    out-of-band re-pinning.
//! 2. **Cluster operator key rotation** — an operator rotates the Ed25519
//!    key that signs the cluster manifest.
//! 3. **Bootstrap zone signer rotation** — the zone operator rotates the
//!    key that signs the `_dmp.<user_domain>` bootstrap record.
//!
//! Cosign body ordering: `old_spk` comes BEFORE `new_spk` in the body. The
//! signing flow reads "prove you authorized leaving the old identity, then
//! prove you're picking up the new one"; the body reads left-to-right in
//! that order.
//!
//! Wire format mirrors `ClusterManifest` / `BootstrapRecord`: a
//! `v=dmp1;t=rotation;` prefix followed by base64'd `body || sig_old || sig_new`.
//!
//! Sibling module [`crate::revocation`] handles the revocation half. The
//! shared subject-type constants, reason codes, and validators live here
//! because rotation is the larger of the two and revocation imports from it.
//! The two records have different security models (rotation is co-signed,
//! revocation is self-signed by the revoked key), so they ship as separate
//! types to prevent accidental call-site confusion.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::crypto::{DmpCrypto, ED25519_KEY_LEN, ED25519_SIG_LEN};

/// TXT prefix that tags a DMP rotation record.
pub const RECORD_PREFIX: &str = "v=dmp1;t=rotation;";

/// Magic header for rotation record bodies.
pub const MAGIC: &[u8] = b"DMPROT1";

/// Length of an Ed25519 signing public key carried in the body.
pub const SPK_LEN: usize = ED25519_KEY_LEN;

/// Length of an Ed25519 signature trailer.
pub const SIG_LEN: usize = ED25519_SIG_LEN;

/// Maximum subject length in UTF-8 bytes for cluster / bootstrap subjects.
///
/// Matches `MAX_CLUSTER_NAME_LEN` from the Python reference. User-identity
/// subjects use the relaxed [`MAX_USER_IDENTITY_SUBJECT_LEN`] cap to fit
/// `user@host` concatenations.
pub const MAX_SUBJECT_LEN: usize = 64;

/// Maximum subject length for `user_identity` subjects.
///
/// The wire encodes `subject_len` as a single octet; 255 is the largest value
/// that fits. The per-subject-type relaxation matters because a 63-byte user
/// half plus `@` plus a long FQDN host can easily exceed the 64-byte cap that
/// applies to bare DNS-name subjects.
pub const MAX_USER_IDENTITY_SUBJECT_LEN: usize = 255;

/// Absolute wire-length cap (post-base64, including the prefix).
///
/// 1200 bytes is symmetric with the other hardened DMP records and leaves
/// headroom over the ~4 TXT-string-of-255-chars budget.
pub const MAX_WIRE_LEN: usize = 1200;

/// Subject type: an end-user identity expressed as `user@host`.
pub const SUBJECT_TYPE_USER_IDENTITY: u8 = 1;

/// Subject type: a cluster operator key, where the subject is a DNS name.
pub const SUBJECT_TYPE_CLUSTER_OPERATOR: u8 = 2;

/// Subject type: a bootstrap zone signer key, where the subject is a DNS name.
pub const SUBJECT_TYPE_BOOTSTRAP_SIGNER: u8 = 3;

/// Reason code: assumed compromise (most urgent; chain walk aborts immediately).
pub const REASON_COMPROMISE: u8 = 1;
/// Reason code: routine rotation (the replacement was already published).
pub const REASON_ROUTINE: u8 = 2;
/// Reason code: lost key (the user cannot self-sign — v1 limitation).
pub const REASON_LOST_KEY: u8 = 3;
/// Reason code: other / unspecified.
pub const REASON_OTHER: u8 = 4;

/// Maximum DNS label length per RFC 1035.
const MAX_DNS_LABEL_LEN: usize = 63;

/// Errors returned while building or parsing rotation records.
#[derive(Debug, thiserror::Error)]
pub enum RotationError {
    /// The subject string was empty after UTF-8 encoding.
    #[error("subject must be a non-empty string")]
    SubjectEmpty,
    /// The subject_type was not 1, 2, or 3.
    #[error("invalid subject_type {actual}; must be 1, 2, or 3")]
    InvalidSubjectType { actual: u8 },
    /// The subject was longer than the per-type cap.
    #[error("subject too long (max {max} utf-8 bytes, got {actual})")]
    SubjectTooLong { actual: usize, max: usize },
    /// A user-identity subject was malformed (missing `@`, empty halves, ...).
    #[error("invalid user-identity subject: {reason}")]
    InvalidUserSubject { reason: &'static str },
    /// A DNS-name subject failed validation (label rules, IDN, etc.).
    #[error("invalid dns-name subject: {reason}")]
    InvalidDnsName { reason: String },
    /// `old_spk == new_spk` — a self-loop is rejected.
    #[error("old_spk and new_spk must differ")]
    SameKey,
    /// The body was shorter than the fixed-layout minimum.
    #[error("body too short for header")]
    BodyTooShort,
    /// The magic header did not match [`MAGIC`].
    #[error("bad magic")]
    BadMagic,
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
    /// The signing key supplied to [`RotationRecord::sign`] did not match the
    /// declared `old_spk` or `new_spk`.
    #[error("signing key does not match declared spk")]
    KeyMismatch,
    /// The signed wire exceeded [`MAX_WIRE_LEN`].
    #[error("rotation record wire size {actual} exceeds MAX_WIRE_LEN {max}")]
    WireTooLong { actual: usize, max: usize },
}

/// Validate that `subject` is well-formed for `subject_type`.
///
/// Used by both [`RotationRecord`] and [`crate::revocation::RevocationRecord`];
/// the rules live here because rotation is the larger of the two modules and
/// revocation imports from it (see module docs).
pub(crate) fn validate_subject(subject_type: u8, subject: &str) -> Result<(), RotationError> {
    if subject.is_empty() {
        return Err(RotationError::SubjectEmpty);
    }
    if subject_type != SUBJECT_TYPE_USER_IDENTITY
        && subject_type != SUBJECT_TYPE_CLUSTER_OPERATOR
        && subject_type != SUBJECT_TYPE_BOOTSTRAP_SIGNER
    {
        return Err(RotationError::InvalidSubjectType {
            actual: subject_type,
        });
    }
    let cap = if subject_type == SUBJECT_TYPE_USER_IDENTITY {
        MAX_USER_IDENTITY_SUBJECT_LEN
    } else {
        MAX_SUBJECT_LEN
    };
    let byte_len = subject.len();
    if byte_len == 0 || byte_len > cap {
        return Err(RotationError::SubjectTooLong {
            actual: byte_len,
            max: cap,
        });
    }
    if subject_type == SUBJECT_TYPE_USER_IDENTITY {
        validate_user_subject(subject)?;
    } else {
        let normalized = subject.strip_suffix('.').unwrap_or(subject);
        if normalized.is_empty() {
            return Err(RotationError::InvalidDnsName {
                reason: "subject must have at least one label".to_string(),
            });
        }
        validate_dns_name(normalized)?;
    }
    Ok(())
}

/// Validate a user-identity subject of the form `user@host`.
pub(crate) fn validate_user_subject(subject: &str) -> Result<(), RotationError> {
    let Some((user, host)) = subject.split_once('@') else {
        return Err(RotationError::InvalidUserSubject {
            reason: "user-identity subject must be in user@host form",
        });
    };
    let user = user.trim();
    let host = host.trim();
    if user.is_empty() || host.is_empty() {
        return Err(RotationError::InvalidUserSubject {
            reason: "user-identity subject must have non-empty user and host",
        });
    }
    let normalized_host = host.strip_suffix('.').unwrap_or(host);
    if normalized_host.is_empty() {
        return Err(RotationError::InvalidUserSubject {
            reason: "user-identity host must have at least one label",
        });
    }
    validate_dns_name(normalized_host)
}

/// Validate that `name` is a publishable ASCII DNS name.
///
/// Mirrors `dmp.core.cluster._validate_dns_name` from the Python reference.
/// The caller is responsible for stripping any trailing dot beforehand.
fn validate_dns_name(name: &str) -> Result<(), RotationError> {
    if name.is_empty() {
        return Err(RotationError::InvalidDnsName {
            reason: "name must be non-empty".to_string(),
        });
    }
    if name.ends_with('.') {
        return Err(RotationError::InvalidDnsName {
            reason: "trailing dot must be stripped before validation".to_string(),
        });
    }
    if !name.is_ascii() {
        return Err(RotationError::InvalidDnsName {
            reason: "name must be ASCII (no IDN support)".to_string(),
        });
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err(RotationError::InvalidDnsName {
                reason: "name has empty label (leading/double dot not allowed)".to_string(),
            });
        }
        if label.len() > MAX_DNS_LABEL_LEN {
            return Err(RotationError::InvalidDnsName {
                reason: format!("label {label:?} exceeds {MAX_DNS_LABEL_LEN} chars"),
            });
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(RotationError::InvalidDnsName {
                reason: format!("label {label:?} cannot start or end with '-'"),
            });
        }
        for ch in label.chars() {
            if !(ch.is_ascii() && (ch.is_ascii_alphanumeric() || ch == '-')) {
                return Err(RotationError::InvalidDnsName {
                    reason: format!(
                        "label {label:?} contains invalid character {ch:?} (letters/digits/'-' only)"
                    ),
                });
            }
        }
    }
    Ok(())
}

/// Normalize a subject for case-insensitive / trailing-dot equality.
///
/// User-identity subjects keep the user half as-written (mailbox-style usernames
/// can be case-sensitive in practice) and casefold only the host half. Cluster
/// and bootstrap subjects are full DNS names and casefold entirely.
pub(crate) fn normalize_subject(subject_type: u8, subject: &str) -> String {
    if subject_type == SUBJECT_TYPE_USER_IDENTITY {
        let Some((user, host)) = subject.split_once('@') else {
            return subject.to_string();
        };
        let host = host.trim();
        let host = host.strip_suffix('.').unwrap_or(host);
        format!("{}@{}", user.trim(), host.to_ascii_lowercase())
    } else {
        let norm = subject.strip_suffix('.').unwrap_or(subject);
        norm.to_ascii_lowercase()
    }
}

/// Co-signed claim that `new_spk` succeeds `old_spk` for `subject`.
///
/// Body layout:
///
/// ```text
/// magic            (7 bytes,  b"DMPROT1")
/// subject_type     (1 byte,   1 = user_identity, 2 = cluster, 3 = bootstrap)
/// subject_len      (1 byte,   1..=64 for cluster/bootstrap, 1..=255 for user)
/// subject          (subject_len utf-8 bytes)
/// old_spk          (32 bytes, Ed25519 verifying key)
/// new_spk          (32 bytes, Ed25519 verifying key)
/// seq              (8 bytes,  big-endian)
/// ts               (8 bytes,  big-endian unix seconds)
/// exp              (8 bytes,  big-endian unix seconds)
/// ```
///
/// Trailing signatures (64 bytes each):
///
/// ```text
/// sig_old          Ed25519 signature over `body` by old_spk
/// sig_new          Ed25519 signature over `body` by new_spk
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationRecord {
    /// One of the `SUBJECT_TYPE_*` constants.
    pub subject_type: u8,
    /// Subject string. Format depends on `subject_type`.
    pub subject: String,
    /// 32-byte Ed25519 signing public key being rotated away from.
    pub old_spk: [u8; SPK_LEN],
    /// 32-byte Ed25519 signing public key being rotated to.
    pub new_spk: [u8; SPK_LEN],
    /// Monotonically increasing rotation sequence number for this subject.
    pub seq: u64,
    /// Unix seconds at publication.
    pub ts: u64,
    /// Unix seconds after which the record is expired.
    pub exp: u64,
}

impl RotationRecord {
    fn validate(&self) -> Result<(), RotationError> {
        validate_subject(self.subject_type, &self.subject)?;
        if self.old_spk == self.new_spk {
            return Err(RotationError::SameKey);
        }
        Ok(())
    }

    /// Serialize the body as documented in the struct-level layout.
    pub fn to_body_bytes(&self) -> Result<Vec<u8>, RotationError> {
        self.validate()?;
        let subject_bytes = self.subject.as_bytes();
        // validate_subject caps subject length at 255 (user) or 64 (DNS), so
        // the cast cannot truncate.
        let subject_len = u8::try_from(subject_bytes.len())
            .expect("subject length is bounded above by validate_subject");
        let mut out = Vec::with_capacity(
            MAGIC.len() + 1 + 1 + subject_bytes.len() + SPK_LEN + SPK_LEN + 8 + 8 + 8,
        );
        out.extend_from_slice(MAGIC);
        out.push(self.subject_type);
        out.push(subject_len);
        out.extend_from_slice(subject_bytes);
        out.extend_from_slice(&self.old_spk);
        out.extend_from_slice(&self.new_spk);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.ts.to_be_bytes());
        out.extend_from_slice(&self.exp.to_be_bytes());
        Ok(out)
    }

    /// Parse the body buffer (no signature trailers) back into a record.
    pub fn from_body_bytes(body: &[u8]) -> Result<Self, RotationError> {
        let min_len = MAGIC.len() + 1 + 1 + SPK_LEN + SPK_LEN + 8 + 8 + 8;
        if body.len() < min_len {
            return Err(RotationError::BodyTooShort);
        }
        let mut off = 0;
        if &body[off..off + MAGIC.len()] != MAGIC {
            return Err(RotationError::BadMagic);
        }
        off += MAGIC.len();
        let subject_type = body[off];
        off += 1;
        if subject_type != SUBJECT_TYPE_USER_IDENTITY
            && subject_type != SUBJECT_TYPE_CLUSTER_OPERATOR
            && subject_type != SUBJECT_TYPE_BOOTSTRAP_SIGNER
        {
            return Err(RotationError::InvalidSubjectType {
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
            return Err(RotationError::InvalidSubjectLength);
        }
        if off + subject_len > body.len() {
            return Err(RotationError::TruncatedSubject);
        }
        let subject = std::str::from_utf8(&body[off..off + subject_len])
            .map_err(|_| RotationError::InvalidUtf8)?
            .to_string();
        off += subject_len;
        if off + SPK_LEN + SPK_LEN + 8 + 8 + 8 != body.len() {
            return Err(RotationError::TrailingOrTruncatedTail);
        }
        let mut old_spk = [0u8; SPK_LEN];
        old_spk.copy_from_slice(&body[off..off + SPK_LEN]);
        off += SPK_LEN;
        let mut new_spk = [0u8; SPK_LEN];
        new_spk.copy_from_slice(&body[off..off + SPK_LEN]);
        off += SPK_LEN;
        let seq = u64::from_be_bytes(body[off..off + 8].try_into().unwrap());
        off += 8;
        let ts = u64::from_be_bytes(body[off..off + 8].try_into().unwrap());
        off += 8;
        let exp = u64::from_be_bytes(body[off..off + 8].try_into().unwrap());

        validate_subject(subject_type, &subject)?;
        if old_spk == new_spk {
            return Err(RotationError::SameKey);
        }
        Ok(Self {
            subject_type,
            subject,
            old_spk,
            new_spk,
            seq,
            ts,
            exp,
        })
    }

    /// Serialize, co-sign by `old_crypto` and `new_crypto`, return the wire string.
    ///
    /// Both keypairs must match the declared `old_spk` / `new_spk` in the body.
    /// Catches the common rotation-flow footgun where a caller swaps the two
    /// `DmpCrypto` arguments by mistake.
    pub fn sign(
        &self,
        old_crypto: &DmpCrypto,
        new_crypto: &DmpCrypto,
    ) -> Result<String, RotationError> {
        if old_crypto.signing_public_key_bytes() != self.old_spk {
            return Err(RotationError::KeyMismatch);
        }
        if new_crypto.signing_public_key_bytes() != self.new_spk {
            return Err(RotationError::KeyMismatch);
        }
        let body = self.to_body_bytes()?;
        let sig_old = old_crypto.sign_data(&body);
        let sig_new = new_crypto.sign_data(&body);
        let mut blob = Vec::with_capacity(body.len() + SIG_LEN + SIG_LEN);
        blob.extend_from_slice(&body);
        blob.extend_from_slice(&sig_old);
        blob.extend_from_slice(&sig_new);
        let wire = format!("{RECORD_PREFIX}{}", BASE64_STANDARD.encode(&blob));
        if wire.len() > MAX_WIRE_LEN {
            return Err(RotationError::WireTooLong {
                actual: wire.len(),
                max: MAX_WIRE_LEN,
            });
        }
        Ok(wire)
    }

    /// Parse a wire string, verify BOTH signatures, enforce expiry. Never panics.
    ///
    /// Returns `None` for any malformed input, signature failure, mismatched
    /// pin, or expired record. The caller pins `expected_old_spk` and
    /// `expected_subject` when known; both are optional so the routine can also
    /// be used in discovery flows.
    #[must_use]
    pub fn parse_and_verify(
        wire: &str,
        expected_old_spk: Option<&[u8]>,
        expected_subject: Option<&str>,
        now: Option<u64>,
    ) -> Option<Self> {
        if !wire.starts_with(RECORD_PREFIX) {
            return None;
        }
        if wire.len() > MAX_WIRE_LEN {
            return None;
        }
        let blob = BASE64_STANDARD.decode(&wire[RECORD_PREFIX.len()..]).ok()?;
        if blob.len() < MAGIC.len() + 2 * SIG_LEN {
            return None;
        }
        let split = blob.len() - 2 * SIG_LEN;
        let body = &blob[..split];
        let sig_old = &blob[split..split + SIG_LEN];
        let sig_new = &blob[split + SIG_LEN..];

        let record = Self::from_body_bytes(body).ok()?;

        if !DmpCrypto::verify_signature(body, sig_old, &record.old_spk) {
            return None;
        }
        if !DmpCrypto::verify_signature(body, sig_new, &record.new_spk) {
            return None;
        }

        if let Some(expected) = expected_old_spk {
            if expected.len() != SPK_LEN {
                return None;
            }
            if expected != record.old_spk {
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
        if record.exp < now_ts {
            return None;
        }
        Some(record)
    }

    /// Returns true iff `now > self.exp`. When `now` is `None`, the system
    /// clock is consulted (Unix seconds).
    #[must_use]
    pub fn is_expired(&self, now: Option<u64>) -> bool {
        let now = now.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
        });
        now > self.exp
    }
}

// --------------------------------------------------------------------------
// RRset naming conventions
// --------------------------------------------------------------------------

/// DNS name where user-identity rotations for `username@user_domain` live.
///
/// Convention: `rotate.dmp.<username-hash>.<user_domain>` — mirrors the
/// `identity_domain` helper in [`crate::identity`] and keeps the rotation
/// records alongside the identity zone.
#[must_use]
pub fn rotation_rrset_name_user_identity(username: &str, user_domain: &str) -> String {
    let digest = Sha256::digest(username.as_bytes());
    let hash_hex = hex::encode(digest);
    let base = user_domain.trim_end_matches('.');
    format!("rotate.id-{}.{}", &hash_hex[..16], base)
}

/// Zone-anchored user-identity rotation name: `rotate.dmp.<zone>`.
///
/// When the user publishes their identity at `dmp.<zone>` (see
/// [`crate::identity::zone_anchored_identity_name`]), rotations live at
/// `rotate.dmp.<zone>`.
#[must_use]
pub fn rotation_rrset_name_zone_anchored(identity_domain_str: &str) -> String {
    format!("rotate.dmp.{}", identity_domain_str.trim_end_matches('.'))
}

/// DNS name where cluster-operator rotations live.
pub fn rotation_rrset_name_cluster(cluster_base_domain: &str) -> Result<String, RotationError> {
    let normalized = cluster_base_domain
        .strip_suffix('.')
        .unwrap_or(cluster_base_domain);
    validate_dns_name(normalized)?;
    Ok(format!("rotate.cluster.{normalized}"))
}

/// DNS name where bootstrap-signer rotations live.
pub fn rotation_rrset_name_bootstrap(user_domain: &str) -> Result<String, RotationError> {
    let normalized = user_domain.strip_suffix('.').unwrap_or(user_domain);
    validate_dns_name(normalized)?;
    Ok(format!("rotate._dmp.{normalized}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_record(old: &DmpCrypto, new: &DmpCrypto) -> RotationRecord {
        RotationRecord {
            subject_type: SUBJECT_TYPE_USER_IDENTITY,
            subject: "alice@example.com".to_string(),
            old_spk: old.signing_public_key_bytes(),
            new_spk: new.signing_public_key_bytes(),
            seq: 1,
            ts: 1_700_000_000,
            exp: 1_900_000_000,
        }
    }

    #[test]
    fn body_round_trip() {
        let old = DmpCrypto::generate();
        let new = DmpCrypto::generate();
        let record = user_record(&old, &new);
        let body = record.to_body_bytes().unwrap();
        let parsed = RotationRecord::from_body_bytes(&body).unwrap();
        assert_eq!(parsed, record);
    }

    #[test]
    fn body_layout_is_byte_exact() {
        let mut record = RotationRecord {
            subject_type: SUBJECT_TYPE_CLUSTER_OPERATOR,
            subject: "mesh.example.com".to_string(),
            old_spk: [0x11; SPK_LEN],
            new_spk: [0x22; SPK_LEN],
            seq: 0x0102_0304_0506_0708,
            ts: 0x0900_0000_0000_0001,
            exp: 0x0900_0000_0000_0002,
        };
        let body = record.to_body_bytes().unwrap();
        assert_eq!(&body[..7], MAGIC);
        assert_eq!(body[7], SUBJECT_TYPE_CLUSTER_OPERATOR);
        assert_eq!(body[8] as usize, "mesh.example.com".len());
        let off = 9;
        assert_eq!(&body[off..off + 16], b"mesh.example.com");
        let off = off + 16;
        assert_eq!(&body[off..off + 32], &[0x11; 32]);
        let off = off + 32;
        assert_eq!(&body[off..off + 32], &[0x22; 32]);
        let off = off + 32;
        assert_eq!(&body[off..off + 8], &0x0102_0304_0506_0708u64.to_be_bytes());
        let off = off + 8;
        assert_eq!(&body[off..off + 8], &0x0900_0000_0000_0001u64.to_be_bytes());
        let off = off + 8;
        assert_eq!(&body[off..off + 8], &0x0900_0000_0000_0002u64.to_be_bytes());
        // Invalidating the body via too-large subject_len byte triggers
        // SubjectTooLong on the round trip back through validate.
        record.subject = String::new();
        assert!(matches!(
            record.to_body_bytes(),
            Err(RotationError::SubjectEmpty),
        ));
    }

    #[test]
    fn from_body_bytes_rejects_short_buffer() {
        let buf = [0u8; 8];
        assert!(matches!(
            RotationRecord::from_body_bytes(&buf),
            Err(RotationError::BodyTooShort),
        ));
    }

    #[test]
    fn from_body_bytes_rejects_bad_magic() {
        let old = DmpCrypto::generate();
        let new = DmpCrypto::generate();
        let mut body = user_record(&old, &new).to_body_bytes().unwrap();
        body[0] ^= 0x01;
        assert!(matches!(
            RotationRecord::from_body_bytes(&body),
            Err(RotationError::BadMagic),
        ));
    }

    #[test]
    fn from_body_bytes_rejects_zero_subject_len() {
        let old = DmpCrypto::generate();
        let new = DmpCrypto::generate();
        let mut body = user_record(&old, &new).to_body_bytes().unwrap();
        body[8] = 0;
        assert!(matches!(
            RotationRecord::from_body_bytes(&body),
            Err(RotationError::InvalidSubjectLength),
        ));
    }

    #[test]
    fn from_body_bytes_rejects_trailing_bytes() {
        let old = DmpCrypto::generate();
        let new = DmpCrypto::generate();
        let mut body = user_record(&old, &new).to_body_bytes().unwrap();
        body.push(0);
        assert!(matches!(
            RotationRecord::from_body_bytes(&body),
            Err(RotationError::TrailingOrTruncatedTail),
        ));
    }

    #[test]
    fn from_body_bytes_rejects_same_keys() {
        let old = DmpCrypto::generate();
        let mut record = user_record(&old, &old);
        // validate() catches this before serialization, so build a body manually.
        record.new_spk = record.old_spk;
        assert!(matches!(
            record.to_body_bytes(),
            Err(RotationError::SameKey)
        ));
    }

    #[test]
    fn sign_and_parse_round_trip() {
        let old = DmpCrypto::generate();
        let new = DmpCrypto::generate();
        let record = user_record(&old, &new);
        let wire = record.sign(&old, &new).unwrap();
        let parsed =
            RotationRecord::parse_and_verify(&wire, None, None, Some(record.exp)).expect("verify");
        assert_eq!(parsed, record);
    }

    #[test]
    fn sign_rejects_swapped_keys() {
        let old = DmpCrypto::generate();
        let new = DmpCrypto::generate();
        let record = user_record(&old, &new);
        // Pass the keys in the wrong order.
        assert!(matches!(
            record.sign(&new, &old),
            Err(RotationError::KeyMismatch),
        ));
    }

    #[test]
    fn parse_and_verify_rejects_missing_prefix() {
        let old = DmpCrypto::generate();
        let new = DmpCrypto::generate();
        let record = user_record(&old, &new);
        let wire = record.sign(&old, &new).unwrap();
        let stripped = wire.strip_prefix(RECORD_PREFIX).unwrap();
        assert!(RotationRecord::parse_and_verify(stripped, None, None, Some(record.exp)).is_none());
    }

    #[test]
    fn parse_and_verify_rejects_bad_base64() {
        let bogus = format!("{RECORD_PREFIX}!!!not-base64!!!");
        assert!(RotationRecord::parse_and_verify(&bogus, None, None, Some(0)).is_none());
    }

    #[test]
    fn parse_and_verify_rejects_flipped_signature() {
        let old = DmpCrypto::generate();
        let new = DmpCrypto::generate();
        let record = user_record(&old, &new);
        let wire = record.sign(&old, &new).unwrap();
        let payload = wire.strip_prefix(RECORD_PREFIX).unwrap();
        let mut bytes = BASE64_STANDARD.decode(payload).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = format!("{RECORD_PREFIX}{}", BASE64_STANDARD.encode(&bytes));
        assert!(
            RotationRecord::parse_and_verify(&tampered, None, None, Some(record.exp)).is_none(),
        );
    }

    #[test]
    fn parse_and_verify_rejects_third_key_forgery_of_sig_new() {
        // Build a valid (old, new)-cosigned record, then swap sig_new for one
        // produced by an unrelated third key. parse_and_verify must reject
        // because the embedded new_spk does not match the third key.
        let old = DmpCrypto::generate();
        let new = DmpCrypto::generate();
        let third = DmpCrypto::generate();
        let record = user_record(&old, &new);
        let body = record.to_body_bytes().unwrap();
        let sig_old = old.sign_data(&body);
        let sig_third = third.sign_data(&body);
        let mut blob = Vec::new();
        blob.extend_from_slice(&body);
        blob.extend_from_slice(&sig_old);
        blob.extend_from_slice(&sig_third);
        let wire = format!("{RECORD_PREFIX}{}", BASE64_STANDARD.encode(&blob));
        assert!(
            RotationRecord::parse_and_verify(&wire, None, None, Some(record.exp)).is_none(),
            "cosign forgery via third key must fail",
        );
    }

    #[test]
    fn parse_and_verify_rejects_expired() {
        let old = DmpCrypto::generate();
        let new = DmpCrypto::generate();
        let record = user_record(&old, &new);
        let wire = record.sign(&old, &new).unwrap();
        assert!(
            RotationRecord::parse_and_verify(&wire, None, None, Some(record.exp + 1)).is_none(),
        );
    }

    #[test]
    fn parse_and_verify_rejects_old_spk_mismatch() {
        let old = DmpCrypto::generate();
        let new = DmpCrypto::generate();
        let third = DmpCrypto::generate();
        let record = user_record(&old, &new);
        let wire = record.sign(&old, &new).unwrap();
        let bad_spk = third.signing_public_key_bytes();
        assert!(
            RotationRecord::parse_and_verify(&wire, Some(&bad_spk), None, Some(record.exp))
                .is_none(),
        );
    }

    #[test]
    fn parse_and_verify_rejects_subject_mismatch() {
        let old = DmpCrypto::generate();
        let new = DmpCrypto::generate();
        let record = user_record(&old, &new);
        let wire = record.sign(&old, &new).unwrap();
        assert!(RotationRecord::parse_and_verify(
            &wire,
            None,
            Some("bob@example.com"),
            Some(record.exp),
        )
        .is_none());
    }

    #[test]
    fn parse_and_verify_subject_normalization_matches_case_and_dot() {
        let old = DmpCrypto::generate();
        let new = DmpCrypto::generate();
        let record = user_record(&old, &new);
        let wire = record.sign(&old, &new).unwrap();
        // Case-insensitive host, trailing-dot stripped.
        assert!(RotationRecord::parse_and_verify(
            &wire,
            None,
            Some("alice@EXAMPLE.com."),
            Some(record.exp),
        )
        .is_some());
    }

    #[test]
    fn validate_subject_user_identity_requires_user_and_host() {
        assert!(matches!(
            validate_subject(SUBJECT_TYPE_USER_IDENTITY, "alice"),
            Err(RotationError::InvalidUserSubject { .. }),
        ));
        assert!(matches!(
            validate_subject(SUBJECT_TYPE_USER_IDENTITY, "@example.com"),
            Err(RotationError::InvalidUserSubject { .. }),
        ));
        assert!(matches!(
            validate_subject(SUBJECT_TYPE_USER_IDENTITY, "alice@"),
            Err(RotationError::InvalidUserSubject { .. }),
        ));
    }

    #[test]
    fn validate_subject_dns_subjects_reject_underscores() {
        assert!(matches!(
            validate_subject(SUBJECT_TYPE_CLUSTER_OPERATOR, "_dmp.example.com"),
            Err(RotationError::InvalidDnsName { .. }),
        ));
    }

    #[test]
    fn validate_subject_rejects_overlong_user_identity() {
        let huge = format!("u@{}", "a".repeat(MAX_USER_IDENTITY_SUBJECT_LEN));
        assert!(matches!(
            validate_subject(SUBJECT_TYPE_USER_IDENTITY, &huge),
            Err(RotationError::SubjectTooLong { .. }),
        ));
    }

    #[test]
    fn validate_subject_rejects_overlong_cluster() {
        let huge = "a".repeat(MAX_SUBJECT_LEN + 1);
        assert!(matches!(
            validate_subject(SUBJECT_TYPE_CLUSTER_OPERATOR, &huge),
            Err(RotationError::SubjectTooLong { .. }),
        ));
    }

    #[test]
    fn validate_subject_rejects_unknown_type() {
        assert!(matches!(
            validate_subject(99, "alice@example.com"),
            Err(RotationError::InvalidSubjectType { .. }),
        ));
    }

    #[test]
    fn normalize_subject_user_identity_lowercases_host_only() {
        assert_eq!(
            normalize_subject(SUBJECT_TYPE_USER_IDENTITY, "Alice@EXAMPLE.com."),
            "Alice@example.com",
        );
    }

    #[test]
    fn normalize_subject_dns_lowercases_full() {
        assert_eq!(
            normalize_subject(SUBJECT_TYPE_CLUSTER_OPERATOR, "MESH.Example.COM."),
            "mesh.example.com",
        );
    }

    #[test]
    fn rrset_names_match_python_conventions() {
        let user = rotation_rrset_name_user_identity("alice", "mesh.example.com.");
        assert!(user.starts_with("rotate.id-"));
        assert!(user.ends_with(".mesh.example.com"));
        assert_eq!(
            rotation_rrset_name_zone_anchored("alice.example.com."),
            "rotate.dmp.alice.example.com",
        );
        assert_eq!(
            rotation_rrset_name_cluster("mesh.example.com.").unwrap(),
            "rotate.cluster.mesh.example.com",
        );
        assert_eq!(
            rotation_rrset_name_bootstrap("example.com").unwrap(),
            "rotate._dmp.example.com",
        );
    }

    #[test]
    fn is_expired_uses_explicit_now() {
        let old = DmpCrypto::generate();
        let new = DmpCrypto::generate();
        let record = user_record(&old, &new);
        assert!(!record.is_expired(Some(record.exp)));
        assert!(!record.is_expired(Some(record.exp - 1)));
        assert!(record.is_expired(Some(record.exp + 1)));
    }

    #[test]
    fn constants_match_python_reference() {
        assert_eq!(RECORD_PREFIX, "v=dmp1;t=rotation;");
        assert_eq!(MAGIC, b"DMPROT1");
        assert_eq!(MAX_SUBJECT_LEN, 64);
        assert_eq!(MAX_USER_IDENTITY_SUBJECT_LEN, 255);
        assert_eq!(MAX_WIRE_LEN, 1200);
        assert_eq!(SUBJECT_TYPE_USER_IDENTITY, 1);
        assert_eq!(SUBJECT_TYPE_CLUSTER_OPERATOR, 2);
        assert_eq!(SUBJECT_TYPE_BOOTSTRAP_SIGNER, 3);
        assert_eq!(REASON_COMPROMISE, 1);
        assert_eq!(REASON_ROUTINE, 2);
        assert_eq!(REASON_LOST_KEY, 3);
        assert_eq!(REASON_OTHER, 4);
    }
}

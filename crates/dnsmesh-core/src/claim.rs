//! Signed claim records for first-message reach (M8.2).
//!
//! A claim is a tiny recipient-keyed pointer published by a sender to a claim
//! provider node, asserting "I have mail for {recipient_id} at {my mailbox
//! zone}, slot {N}, signed by {sender_spk}, valid until {exp}." The provider
//! hosts the claim — it does NOT store the ciphertext. The recipient polls
//! one or more claim providers, verifies the Ed25519 signature, then fetches
//! the actual manifest+chunks from `sender_mailbox_domain` via the normal
//! cross-zone receive path.
//!
//! Wire format (mirrors Python `dmp.core.claim`):
//!
//! ```text
//! v=dmp1;t=claim;<base64(body || sig)>
//!
//! body:
//!     magic(7)                          // b"DMPCL01" (shared with cluster
//!                                       //  manifest; the wire prefix is
//!                                       //  what disambiguates the two —
//!                                       //  do NOT change this magic)
//!     msg_id(16)
//!     sender_spk(32)
//!     sender_mailbox_domain_len(1)
//!     sender_mailbox_domain(utf-8, 1..=43 bytes)
//!     slot(1)                           // 0..=9
//!     ts(8 BE)
//!     exp(8 BE)
//! sig:
//!     Ed25519 signature over body       // 64 bytes
//! ```
//!
//! Trust model: the claim is signed by `sender_spk`. The provider hosts but
//! does not vouch — a malicious provider can drop or reorder, but cannot
//! forge. Recipients must verify the signature on receive; an unsigned or
//! forged claim is dropped at parse time. Cross-recipient replay (a malicious
//! provider rebroadcasting a captured claim under a different
//! `mb-{hash12}` label) cannot recover the underlying message: the sender's
//! manifest+chunks live under the real recipient's hash12 in the sender's
//! own zone, and the wrong recipient's hash12 doesn't match.
//!
//! Replay / freshness: `exp <= now` is rejected, and a `ts` more than
//! `ts_skew_seconds` in the FUTURE relative to `now` is rejected as a
//! forward-dated forgery (extending lifetime past TTL caps). Past-skewed
//! `ts` is accepted — `exp` is the lifetime bound, and a recipient polling
//! several minutes after a sender publishes must not lose the claim.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::crypto::{DmpCrypto, ED25519_KEY_LEN, ED25519_SIG_LEN};
use crate::ed25519_points::is_low_order;

/// TXT prefix that tags a DMP claim record.
pub const RECORD_PREFIX: &str = "v=dmp1;t=claim;";

/// Magic bytes opening every claim body. Shared with `ClusterManifest` in the
/// Python reference; the wire prefix is what distinguishes the two record
/// types. Mirrored here verbatim for byte-level interop.
pub const MAGIC: &[u8; 7] = b"DMPCL01";

/// Length of the message ID embedded in the body.
pub const MSG_ID_LEN: usize = 16;

/// Maximum sender mailbox domain length in UTF-8 bytes.
///
/// Derived in the Python reference from the 255-byte single-DNS-string TXT
/// budget: `floor((255 - len(prefix)) * 3/4) - 137 = 43`. Covers realistic
/// deployment names; operators with longer zones either shorten the
/// user-facing label or wait for multi-string TXT support.
pub const MAX_MAILBOX_DOMAIN_LEN: usize = 43;

/// Maximum permitted slot index (slots are 0..=9).
pub const MAX_SLOT: u8 = 9;

/// Maximum allowed wire size (UTF-8 bytes), matching the single 255-byte
/// DNS TXT string limit.
pub const MAX_WIRE_LEN: usize = 255;

/// Default `ts` future-skew tolerance for `parse_and_verify`, in seconds.
pub const DEFAULT_TS_SKEW_SECONDS: u64 = 300;

/// Errors returned while building or parsing claim records.
#[derive(Debug, thiserror::Error)]
pub enum ClaimError {
    /// `sender_mailbox_domain` was empty.
    #[error("sender_mailbox_domain must not be empty")]
    MailboxDomainEmpty,
    /// `sender_mailbox_domain` exceeded [`MAX_MAILBOX_DOMAIN_LEN`].
    #[error("sender_mailbox_domain length {actual} > MAX_MAILBOX_DOMAIN_LEN {max}")]
    MailboxDomainTooLong { actual: usize, max: usize },
    /// `sender_mailbox_domain` contained whitespace or control characters.
    #[error("sender_mailbox_domain contains whitespace or control characters")]
    MailboxDomainInvalidChars,
    /// `slot` was out of range (must be 0..=[`MAX_SLOT`]).
    #[error("slot {actual} out of range (max {max})")]
    SlotOutOfRange { actual: u8, max: u8 },
    /// `exp <= ts`, which means the claim is born expired.
    #[error("exp must be strictly greater than ts")]
    ExpNotAfterTs,
    /// The signing key supplied to [`ClaimRecord::sign`] does not match
    /// `self.sender_spk`.
    #[error("sender_crypto signing key does not match declared sender_spk")]
    SenderKeyMismatch,
    /// The encoded wire form would exceed [`MAX_WIRE_LEN`] bytes.
    #[error("claim wire size {actual} exceeds MAX_WIRE_LEN {max}")]
    WireTooLong { actual: usize, max: usize },
    /// The body buffer was shorter than the minimum-size record.
    #[error("claim body too short")]
    BodyTooShort,
    /// The body did not begin with [`MAGIC`].
    #[error("bad magic")]
    BadMagic,
    /// `sender_mailbox_domain_len` was zero or above the maximum.
    #[error("sender_mailbox_domain_len out of range: {0}")]
    InvalidDomainLen(u8),
    /// The body was truncated mid-field.
    #[error("claim body truncated")]
    BodyTruncated,
    /// The body had trailing bytes after parsing the documented fields.
    #[error("trailing claim body bytes")]
    TrailingBytes,
    /// `sender_mailbox_domain` was not valid UTF-8.
    #[error("sender_mailbox_domain is not valid utf-8")]
    InvalidUtf8,
    /// `recipient_id` for [`claim_rrset_name`] was not 32 bytes.
    #[error("recipient_id must be 32 bytes")]
    InvalidRecipientId,
    /// `provider_zone` for [`claim_rrset_name`] was empty.
    #[error("provider_zone must be a non-empty string")]
    ProviderZoneEmpty,
}

/// Signed first-contact pointer published to a claim provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimRecord {
    /// 16-byte message ID (sender-chosen, unique per message — typically uuid4).
    pub msg_id: [u8; MSG_ID_LEN],
    /// 32-byte Ed25519 signing public key of the sender.
    pub sender_spk: [u8; ED25519_KEY_LEN],
    /// UTF-8 zone the sender's mailbox lives under (1..=[`MAX_MAILBOX_DOMAIN_LEN`] bytes).
    pub sender_mailbox_domain: String,
    /// Mailbox slot the message is parked at (0..=[`MAX_SLOT`]).
    pub slot: u8,
    /// Unix seconds at publication.
    pub ts: u64,
    /// Unix seconds after which the claim is expired.
    pub exp: u64,
}

impl ClaimRecord {
    /// Validate string-level invariants on `sender_mailbox_domain`.
    fn validate_mailbox_domain(domain: &str) -> Result<&[u8], ClaimError> {
        if domain.is_empty() {
            return Err(ClaimError::MailboxDomainEmpty);
        }
        let bytes = domain.as_bytes();
        if bytes.len() > MAX_MAILBOX_DOMAIN_LEN {
            return Err(ClaimError::MailboxDomainTooLong {
                actual: bytes.len(),
                max: MAX_MAILBOX_DOMAIN_LEN,
            });
        }
        // Reject whitespace / control chars: a `sender_mailbox_domain` like
        // "a.b.com\nslot-0..." is trying to confuse downstream DNS query
        // construction. Match Python's char check (`< 0x21 || == 0x7F`),
        // operating on chars (post-utf8 decode) to mirror behaviour.
        for c in domain.chars() {
            let cp = u32::from(c);
            if cp < 0x21 || cp == 0x7F {
                return Err(ClaimError::MailboxDomainInvalidChars);
            }
        }
        Ok(bytes)
    }

    /// Serialize the signable body (everything except the signature).
    pub fn to_body_bytes(&self) -> Result<Vec<u8>, ClaimError> {
        let domain_bytes = Self::validate_mailbox_domain(&self.sender_mailbox_domain)?;
        if self.slot > MAX_SLOT {
            return Err(ClaimError::SlotOutOfRange {
                actual: self.slot,
                max: MAX_SLOT,
            });
        }
        if self.exp <= self.ts {
            return Err(ClaimError::ExpNotAfterTs);
        }

        let mut out = Vec::with_capacity(
            MAGIC.len() + MSG_ID_LEN + ED25519_KEY_LEN + 1 + domain_bytes.len() + 1 + 8 + 8,
        );
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.msg_id);
        out.extend_from_slice(&self.sender_spk);
        // Length-bounded above by MAX_MAILBOX_DOMAIN_LEN (43), so the cast cannot truncate.
        out.push(u8::try_from(domain_bytes.len()).expect("domain length fits in u8"));
        out.extend_from_slice(domain_bytes);
        out.push(self.slot);
        out.extend_from_slice(&self.ts.to_be_bytes());
        out.extend_from_slice(&self.exp.to_be_bytes());
        Ok(out)
    }

    /// Parse the signable body. Does NOT verify the signature; use
    /// [`ClaimRecord::parse_and_verify`] for the complete check.
    pub fn from_body_bytes(body: &[u8]) -> Result<Self, ClaimError> {
        // magic(7) + msg_id(16) + spk(32) + dom_len(1) + dom(>=1) + slot(1) + ts(8) + exp(8)
        let min_len = MAGIC.len() + MSG_ID_LEN + ED25519_KEY_LEN + 1 + 1 + 1 + 16;
        if body.len() < min_len {
            return Err(ClaimError::BodyTooShort);
        }
        if &body[..MAGIC.len()] != MAGIC.as_slice() {
            return Err(ClaimError::BadMagic);
        }
        let mut off = MAGIC.len();

        let mut msg_id = [0u8; MSG_ID_LEN];
        msg_id.copy_from_slice(&body[off..off + MSG_ID_LEN]);
        off += MSG_ID_LEN;

        let mut sender_spk = [0u8; ED25519_KEY_LEN];
        sender_spk.copy_from_slice(&body[off..off + ED25519_KEY_LEN]);
        off += ED25519_KEY_LEN;

        let domain_len_byte = body[off];
        let domain_len = domain_len_byte as usize;
        off += 1;
        if domain_len == 0 || domain_len > MAX_MAILBOX_DOMAIN_LEN {
            return Err(ClaimError::InvalidDomainLen(domain_len_byte));
        }
        if off + domain_len > body.len() {
            return Err(ClaimError::BodyTruncated);
        }
        let sender_mailbox_domain = std::str::from_utf8(&body[off..off + domain_len])
            .map_err(|_| ClaimError::InvalidUtf8)?
            .to_string();
        off += domain_len;

        if off + 1 > body.len() {
            return Err(ClaimError::BodyTruncated);
        }
        let slot = body[off];
        off += 1;
        if slot > MAX_SLOT {
            return Err(ClaimError::SlotOutOfRange {
                actual: slot,
                max: MAX_SLOT,
            });
        }

        if off + 16 > body.len() {
            return Err(ClaimError::BodyTruncated);
        }
        let ts = u64::from_be_bytes(body[off..off + 8].try_into().unwrap());
        off += 8;
        let exp = u64::from_be_bytes(body[off..off + 8].try_into().unwrap());
        off += 8;

        if off != body.len() {
            return Err(ClaimError::TrailingBytes);
        }

        if exp <= ts {
            return Err(ClaimError::ExpNotAfterTs);
        }

        let record = Self {
            msg_id,
            sender_spk,
            sender_mailbox_domain,
            slot,
            ts,
            exp,
        };
        // Re-run string-level validation so a parsed body can never produce a
        // record that fails downstream invariants (control chars, etc).
        Self::validate_mailbox_domain(&record.sender_mailbox_domain)?;
        Ok(record)
    }

    /// Sign with `sender_crypto` and return the wire-format TXT record string.
    ///
    /// `sender_crypto` must hold the private half of `self.sender_spk`; a
    /// mismatch is caught here and refused.
    pub fn sign(&self, sender_crypto: &DmpCrypto) -> Result<String, ClaimError> {
        if sender_crypto.signing_public_key_bytes() != self.sender_spk {
            return Err(ClaimError::SenderKeyMismatch);
        }
        let body = self.to_body_bytes()?;
        let signature = sender_crypto.sign_data(&body);
        let mut combined = Vec::with_capacity(body.len() + ED25519_SIG_LEN);
        combined.extend_from_slice(&body);
        combined.extend_from_slice(&signature);
        let wire = format!("{RECORD_PREFIX}{}", BASE64_STANDARD.encode(&combined));
        if wire.len() > MAX_WIRE_LEN {
            return Err(ClaimError::WireTooLong {
                actual: wire.len(),
                max: MAX_WIRE_LEN,
            });
        }
        Ok(wire)
    }

    /// Parse + verify signature + enforce freshness. Never panics; returns
    /// `None` on any failure (mirrors Python `parse_and_verify`).
    ///
    /// `now` defaults to the system clock when `None`. `ts_skew_seconds`
    /// caps how far in the FUTURE `ts` may be relative to `now`; past-skewed
    /// `ts` is accepted because `exp` governs lifetime.
    #[must_use]
    pub fn parse_and_verify(wire: &str, now: Option<u64>, ts_skew_seconds: u64) -> Option<Self> {
        if !wire.starts_with(RECORD_PREFIX) {
            return None;
        }
        if wire.len() > MAX_WIRE_LEN {
            return None;
        }
        let payload = wire.strip_prefix(RECORD_PREFIX)?;
        let blob = BASE64_STANDARD.decode(payload).ok()?;
        if blob.len() < ED25519_SIG_LEN + 1 {
            return None;
        }
        let split = blob.len() - ED25519_SIG_LEN;
        let body = &blob[..split];
        let sig = &blob[split..];

        let record = Self::from_body_bytes(body).ok()?;

        // Low-order Ed25519 pubkey guard. The identity point (01 00..00)
        // verifies every message under permissive RFC 8032; other small-order
        // points permit grinding forgeries.
        if is_low_order(&record.sender_spk) {
            return None;
        }

        if !DmpCrypto::verify_signature(body, sig, &record.sender_spk) {
            return None;
        }

        let now = now.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
        });
        // Future-skew only: a claim signed in the FUTURE is suspicious
        // (forward-dated forgery to extend lifetime past TTL caps); a claim
        // signed in the past is fine — `exp` is what bounds validity.
        if record.ts > now && record.ts - now > ts_skew_seconds {
            return None;
        }
        if record.exp <= now {
            return None;
        }

        Some(record)
    }
}

/// Return the RRset name for a claim addressed to `recipient_id`.
///
/// Format: `claim-{slot}.mb-{sha256(recipient_id)[:12 hex]}.{provider_zone}`
/// (a trailing dot on `provider_zone` is stripped). Mirrors the mailbox slot
/// RRset naming convention so a provider operator can run claim-server
/// alongside a normal mailbox node without colliding namespaces (the
/// `claim-` prefix vs `slot-` keeps the two spaces distinct).
pub fn claim_rrset_name(
    recipient_id: &[u8; 32],
    slot: u8,
    provider_zone: &str,
) -> Result<String, ClaimError> {
    if slot > MAX_SLOT {
        return Err(ClaimError::SlotOutOfRange {
            actual: slot,
            max: MAX_SLOT,
        });
    }
    if provider_zone.is_empty() {
        return Err(ClaimError::ProviderZoneEmpty);
    }
    let digest = Sha256::digest(recipient_id);
    let hash_hex = hex::encode(digest);
    let zone = provider_zone.trim_end_matches('.');
    Ok(format!("claim-{slot}.mb-{}.{zone}", &hash_hex[..12]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519_points::LOW_ORDER_ED25519_PUBKEYS;

    fn sample_record(spk: [u8; ED25519_KEY_LEN]) -> ClaimRecord {
        ClaimRecord {
            msg_id: [0xAB; MSG_ID_LEN],
            sender_spk: spk,
            sender_mailbox_domain: "alice.mesh.example.com".to_string(),
            slot: 3,
            ts: 1_700_000_000,
            exp: 1_700_000_300,
        }
    }

    #[test]
    fn body_round_trip() {
        let crypto = DmpCrypto::generate();
        let record = sample_record(crypto.signing_public_key_bytes());
        let body = record.to_body_bytes().unwrap();
        let parsed = ClaimRecord::from_body_bytes(&body).unwrap();
        assert_eq!(parsed, record);
    }

    #[test]
    fn body_layout_is_byte_exact() {
        let record = ClaimRecord {
            msg_id: [0x11; MSG_ID_LEN],
            sender_spk: [0x22; ED25519_KEY_LEN],
            sender_mailbox_domain: "ab".to_string(),
            slot: 7,
            ts: 0x0123_4567_89AB_CDEF,
            exp: 0xFEDC_BA98_7654_3210,
        };
        let body = record.to_body_bytes().unwrap();
        assert_eq!(&body[0..7], MAGIC.as_slice());
        assert_eq!(&body[7..23], &[0x11u8; 16]);
        assert_eq!(&body[23..55], &[0x22u8; 32]);
        assert_eq!(body[55], 2);
        assert_eq!(&body[56..58], b"ab");
        assert_eq!(body[58], 7);
        assert_eq!(&body[59..67], &0x0123_4567_89AB_CDEFu64.to_be_bytes());
        assert_eq!(&body[67..75], &0xFEDC_BA98_7654_3210u64.to_be_bytes());
    }

    #[test]
    fn empty_mailbox_domain_rejected() {
        let mut record = sample_record([0x22; ED25519_KEY_LEN]);
        record.sender_mailbox_domain.clear();
        assert!(matches!(
            record.to_body_bytes(),
            Err(ClaimError::MailboxDomainEmpty),
        ));
    }

    #[test]
    fn mailbox_domain_max_len_accepted() {
        let mut record = sample_record([0x22; ED25519_KEY_LEN]);
        record.sender_mailbox_domain = "a".repeat(MAX_MAILBOX_DOMAIN_LEN);
        let body = record.to_body_bytes().unwrap();
        let parsed = ClaimRecord::from_body_bytes(&body).unwrap();
        assert_eq!(parsed.sender_mailbox_domain.len(), MAX_MAILBOX_DOMAIN_LEN);
    }

    #[test]
    fn mailbox_domain_over_max_rejected() {
        let mut record = sample_record([0x22; ED25519_KEY_LEN]);
        record.sender_mailbox_domain = "a".repeat(MAX_MAILBOX_DOMAIN_LEN + 1);
        assert!(matches!(
            record.to_body_bytes(),
            Err(ClaimError::MailboxDomainTooLong { .. }),
        ));
    }

    #[test]
    fn mailbox_domain_control_char_rejected() {
        let mut record = sample_record([0x22; ED25519_KEY_LEN]);
        record.sender_mailbox_domain = "a.b.com\nslot-0".to_string();
        assert!(matches!(
            record.to_body_bytes(),
            Err(ClaimError::MailboxDomainInvalidChars),
        ));
    }

    #[test]
    fn slot_max_accepted() {
        let mut record = sample_record([0x22; ED25519_KEY_LEN]);
        record.slot = MAX_SLOT;
        let body = record.to_body_bytes().unwrap();
        let parsed = ClaimRecord::from_body_bytes(&body).unwrap();
        assert_eq!(parsed.slot, MAX_SLOT);
    }

    #[test]
    fn slot_over_max_rejected() {
        let mut record = sample_record([0x22; ED25519_KEY_LEN]);
        record.slot = MAX_SLOT + 1;
        assert!(matches!(
            record.to_body_bytes(),
            Err(ClaimError::SlotOutOfRange { .. }),
        ));
    }

    #[test]
    fn exp_le_ts_rejected() {
        let mut record = sample_record([0x22; ED25519_KEY_LEN]);
        record.exp = record.ts;
        assert!(matches!(
            record.to_body_bytes(),
            Err(ClaimError::ExpNotAfterTs),
        ));
    }

    #[test]
    fn from_body_bytes_rejects_bad_magic() {
        let crypto = DmpCrypto::generate();
        let record = sample_record(crypto.signing_public_key_bytes());
        let mut body = record.to_body_bytes().unwrap();
        body[0] = b'X';
        assert!(matches!(
            ClaimRecord::from_body_bytes(&body),
            Err(ClaimError::BadMagic),
        ));
    }

    #[test]
    fn from_body_bytes_rejects_short_buffer() {
        let buf = [0u8; 10];
        assert!(matches!(
            ClaimRecord::from_body_bytes(&buf),
            Err(ClaimError::BodyTooShort),
        ));
    }

    #[test]
    fn from_body_bytes_rejects_trailing_bytes() {
        let crypto = DmpCrypto::generate();
        let record = sample_record(crypto.signing_public_key_bytes());
        let mut body = record.to_body_bytes().unwrap();
        body.push(0);
        assert!(matches!(
            ClaimRecord::from_body_bytes(&body),
            Err(ClaimError::TrailingBytes),
        ));
    }

    #[test]
    fn sign_and_parse_round_trip() {
        let crypto = DmpCrypto::generate();
        let now = 1_700_000_100u64;
        let record = ClaimRecord {
            msg_id: [0x55; MSG_ID_LEN],
            sender_spk: crypto.signing_public_key_bytes(),
            sender_mailbox_domain: "alice.example.com".to_string(),
            slot: 0,
            ts: 1_700_000_000,
            exp: 1_700_000_300,
        };
        let wire = record.sign(&crypto).unwrap();
        let parsed = ClaimRecord::parse_and_verify(&wire, Some(now), DEFAULT_TS_SKEW_SECONDS)
            .expect("must verify");
        assert_eq!(parsed, record);
    }

    #[test]
    fn sign_rejects_key_mismatch() {
        let alice = DmpCrypto::generate();
        let bob = DmpCrypto::generate();
        let mut record = sample_record(alice.signing_public_key_bytes());
        record.exp = record.ts + 100;
        assert!(matches!(
            record.sign(&bob),
            Err(ClaimError::SenderKeyMismatch),
        ));
    }

    #[test]
    fn parse_rejects_bad_prefix() {
        let crypto = DmpCrypto::generate();
        let mut record = sample_record(crypto.signing_public_key_bytes());
        record.exp = record.ts + 100;
        let wire = record.sign(&crypto).unwrap();
        let stripped = wire.strip_prefix(RECORD_PREFIX).unwrap().to_string();
        assert!(ClaimRecord::parse_and_verify(
            &stripped,
            Some(record.ts + 1),
            DEFAULT_TS_SKEW_SECONDS
        )
        .is_none());
    }

    #[test]
    fn parse_rejects_bad_base64() {
        let bogus = format!("{RECORD_PREFIX}!!!not-base64!!!");
        assert!(ClaimRecord::parse_and_verify(&bogus, Some(0), DEFAULT_TS_SKEW_SECONDS).is_none());
    }

    #[test]
    fn parse_rejects_flipped_signature() {
        let crypto = DmpCrypto::generate();
        let mut record = sample_record(crypto.signing_public_key_bytes());
        record.exp = record.ts + 100;
        let wire = record.sign(&crypto).unwrap();
        let payload = wire.strip_prefix(RECORD_PREFIX).unwrap();
        let mut bytes = BASE64_STANDARD.decode(payload).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = format!("{RECORD_PREFIX}{}", BASE64_STANDARD.encode(&bytes));
        assert!(ClaimRecord::parse_and_verify(
            &tampered,
            Some(record.ts + 1),
            DEFAULT_TS_SKEW_SECONDS
        )
        .is_none());
    }

    #[test]
    fn parse_rejects_low_order_spk_substitution() {
        // Sign with a real key, then mutate the wire to swap sender_spk for a
        // known low-order pubkey. parse_and_verify must reject before the
        // signature check even runs; even if a permissive Ed25519 verify
        // happened to accept the swapped key, the low-order guard fires first.
        let crypto = DmpCrypto::generate();
        let mut record = sample_record(crypto.signing_public_key_bytes());
        record.exp = record.ts + 100;
        let wire = record.sign(&crypto).unwrap();
        let payload = wire.strip_prefix(RECORD_PREFIX).unwrap();
        let mut bytes = BASE64_STANDARD.decode(payload).unwrap();
        // sender_spk lives at body offset MAGIC + MSG_ID_LEN (= 23..55).
        let spk_off = MAGIC.len() + MSG_ID_LEN;
        bytes[spk_off..spk_off + ED25519_KEY_LEN].copy_from_slice(&LOW_ORDER_ED25519_PUBKEYS[0]);
        let mutated = format!("{RECORD_PREFIX}{}", BASE64_STANDARD.encode(&bytes));
        assert!(ClaimRecord::parse_and_verify(
            &mutated,
            Some(record.ts + 1),
            DEFAULT_TS_SKEW_SECONDS
        )
        .is_none());
    }

    #[test]
    fn parse_rejects_expired() {
        let crypto = DmpCrypto::generate();
        let mut record = sample_record(crypto.signing_public_key_bytes());
        record.ts = 1_000;
        record.exp = 1_100;
        let wire = record.sign(&crypto).unwrap();
        // now == exp is rejected (Python: `exp <= now`).
        assert!(
            ClaimRecord::parse_and_verify(&wire, Some(1_100), DEFAULT_TS_SKEW_SECONDS).is_none()
        );
        assert!(
            ClaimRecord::parse_and_verify(&wire, Some(1_200), DEFAULT_TS_SKEW_SECONDS).is_none()
        );
    }

    #[test]
    fn parse_rejects_forward_dated() {
        let crypto = DmpCrypto::generate();
        let mut record = sample_record(crypto.signing_public_key_bytes());
        record.ts = 2_000_000_000;
        record.exp = 2_000_000_300;
        let wire = record.sign(&crypto).unwrap();
        // ts is 1_000_000 seconds ahead of now; far above DEFAULT_TS_SKEW_SECONDS.
        assert!(
            ClaimRecord::parse_and_verify(&wire, Some(1_000_000_000), DEFAULT_TS_SKEW_SECONDS)
                .is_none()
        );
    }

    #[test]
    fn parse_accepts_past_skewed_ts() {
        // A claim signed minutes ago (ts < now) must still verify as long as
        // exp is in the future. Regression guard: an earlier version wrongly
        // capped lifetime by rejecting past-skewed ts too.
        let crypto = DmpCrypto::generate();
        let mut record = sample_record(crypto.signing_public_key_bytes());
        record.ts = 1_700_000_000;
        record.exp = 1_700_010_000;
        let wire = record.sign(&crypto).unwrap();
        let now = record.ts + 600; // 10 min after publication
        let parsed = ClaimRecord::parse_and_verify(&wire, Some(now), DEFAULT_TS_SKEW_SECONDS)
            .expect("past-skewed ts with future exp must verify");
        assert_eq!(parsed, record);
    }

    #[test]
    fn claim_rrset_name_format() {
        let recipient_id = [0xCD; 32];
        let name = claim_rrset_name(&recipient_id, 4, "provider.example.com").unwrap();
        let digest = Sha256::digest(recipient_id);
        let hash12 = &hex::encode(digest)[..12];
        assert_eq!(name, format!("claim-4.mb-{hash12}.provider.example.com"));
    }

    #[test]
    fn claim_rrset_name_strips_trailing_dot() {
        let recipient_id = [0; 32];
        let name = claim_rrset_name(&recipient_id, 0, "provider.example.com.").unwrap();
        assert!(name.ends_with(".provider.example.com"));
        assert!(!name.ends_with('.'));
    }

    #[test]
    fn claim_rrset_name_rejects_bad_slot() {
        assert!(matches!(
            claim_rrset_name(&[0; 32], MAX_SLOT + 1, "z.example"),
            Err(ClaimError::SlotOutOfRange { .. }),
        ));
    }

    #[test]
    fn claim_rrset_name_rejects_empty_zone() {
        assert!(matches!(
            claim_rrset_name(&[0; 32], 0, ""),
            Err(ClaimError::ProviderZoneEmpty),
        ));
    }
}

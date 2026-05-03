//! Signed slot manifests for DMP mailboxes.
//!
//! A slot manifest is the TXT record a sender publishes at a mailbox slot to tell
//! the recipient "a message is waiting here." It names the message, how many
//! chunks to fetch, when it expires, and is signed by the sender's Ed25519
//! identity so it cannot be forged or silently mutated.
//!
//! Without this anyone can publish to a mailbox slot and impersonate any sender.
//! With this, forged slots are detectable and the recipient-side replay cache
//! (in the client crate) can reject re-publication of old valid manifests.
//!
//! Wire format (compact binary to fit a single 255-byte DNS TXT string):
//!
//! ```text
//! v=dmp1;t=manifest;d=<b64(body || sig)>
//!
//! body = msg_id(16) || sender_spk(32) || recipient_id(32)
//!     || total_chunks(4) || data_chunks(4) || prekey_id(4)
//!     || ts(8) || exp(8)                                       =  108 bytes
//! sig  = Ed25519 signature over `body`                         =   64 bytes
//! ```
//!
//! `data_chunks` is the erasure threshold k: the recipient needs any k of the
//! `total_chunks` to reconstruct the message. When erasure is disabled (single
//! chunk legacy flow) `data_chunks == total_chunks`.
//!
//! `prekey_id` selects which one-time X25519 prekey was used for ECDH.
//! [`NO_PREKEY`] (0) means the sender fell back to the recipient's long-term
//! X25519 key — no forward secrecy for that message.
//!
//! Replay protection lives in the client crate (`dnsmesh-client`); this module
//! is purely the wire-format codec and signature gate.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;

use crate::crypto::{DmpCrypto, ED25519_KEY_LEN, ED25519_SIG_LEN};

/// TXT prefix that tags a DMP slot manifest record.
pub const RECORD_PREFIX: &str = "v=dmp1;t=manifest;d=";

/// Length of [`SlotManifest::msg_id`] in bytes.
pub const MSG_ID_LEN: usize = 16;
/// Length of the SHA-256 recipient ID embedded in the body.
pub const RECIPIENT_ID_LEN: usize = 32;

/// Total length of the signed manifest body in bytes.
pub const BODY_LEN: usize = MSG_ID_LEN + ED25519_KEY_LEN + RECIPIENT_ID_LEN + 4 + 4 + 4 + 8 + 8; // 108

/// Length of the Ed25519 signature trailer in bytes.
pub const SIG_LEN: usize = ED25519_SIG_LEN;

/// Total wire length of `body || sig` in bytes (pre-base64).
pub const WIRE_LEN: usize = BODY_LEN + SIG_LEN; // 172

/// Default manifest TTL in seconds, matching the Python reference.
pub const DEFAULT_MANIFEST_TTL: u64 = 300;

/// Sentinel `prekey_id` meaning "sender did not use a prekey; ECDH used the
/// recipient's long-term X25519 key — no forward secrecy for this message."
pub const NO_PREKEY: u32 = 0;

/// Protocol-level cap on chunk count in a signed manifest.
///
/// Without a cap, a signature-valid manifest can ask the receiver to fetch
/// ~2^32 chunks and the DNS-query loop pins the process. 1024 chunks at the
/// per-chunk plaintext budget is well past anything the rest of the stack is
/// sized for.
pub const MAX_TOTAL_CHUNKS: u32 = 1024;

/// Errors returned while building or parsing slot manifests.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// `total_chunks` was zero, less than `data_chunks`, or above [`MAX_TOTAL_CHUNKS`].
    #[error("total_chunks {actual} out of range (max {max})")]
    TotalChunksOutOfRange { actual: u32, max: u32 },
    /// `data_chunks` was zero or greater than `total_chunks`.
    #[error("data_chunks must be in 1..=total_chunks")]
    DataChunksOutOfRange,
    /// The body buffer was not exactly [`BODY_LEN`] bytes.
    #[error("manifest body must be {expected} bytes, got {actual}")]
    BodyLengthMismatch { expected: usize, actual: usize },
}

/// Claim that a message is waiting at a mailbox slot.
///
/// The Ed25519 signature covers [`SlotManifest::to_body_bytes`] so any mutation
/// of any field breaks verification. The `sender_spk` is embedded in the body
/// and is what the verifier checks against — manifests are self-signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotManifest {
    /// 16-byte message ID (sender-chosen, unique per message).
    pub msg_id: [u8; MSG_ID_LEN],
    /// 32-byte Ed25519 signing public key of the sender.
    pub sender_spk: [u8; ED25519_KEY_LEN],
    /// 32-byte SHA-256 of the recipient's X25519 public key.
    pub recipient_id: [u8; RECIPIENT_ID_LEN],
    /// Total number of chunks the sender published (n).
    pub total_chunks: u32,
    /// Erasure threshold — number of chunks needed to reconstruct (k).
    pub data_chunks: u32,
    /// One-time prekey ID used for ECDH; [`NO_PREKEY`] (0) means long-term key.
    pub prekey_id: u32,
    /// Unix seconds at publication.
    pub ts: u64,
    /// Unix seconds after which the recipient should drop the manifest.
    pub exp: u64,
}

impl SlotManifest {
    /// Validate field invariants matching the Python reference.
    fn validate(&self) -> Result<(), ManifestError> {
        if self.total_chunks == 0 || self.total_chunks > MAX_TOTAL_CHUNKS {
            return Err(ManifestError::TotalChunksOutOfRange {
                actual: self.total_chunks,
                max: MAX_TOTAL_CHUNKS,
            });
        }
        if self.data_chunks == 0 || self.data_chunks > self.total_chunks {
            return Err(ManifestError::DataChunksOutOfRange);
        }
        Ok(())
    }

    /// Serialize the body into the [`BODY_LEN`]-byte signed payload layout.
    ///
    /// All multi-byte integers are big-endian. Field order:
    /// `msg_id(16) || sender_spk(32) || recipient_id(32) || total_chunks(4)
    /// || data_chunks(4) || prekey_id(4) || ts(8) || exp(8)`.
    pub fn to_body_bytes(&self) -> Result<[u8; BODY_LEN], ManifestError> {
        self.validate()?;
        let mut out = [0u8; BODY_LEN];
        let mut offset = 0;
        out[offset..offset + MSG_ID_LEN].copy_from_slice(&self.msg_id);
        offset += MSG_ID_LEN;
        out[offset..offset + ED25519_KEY_LEN].copy_from_slice(&self.sender_spk);
        offset += ED25519_KEY_LEN;
        out[offset..offset + RECIPIENT_ID_LEN].copy_from_slice(&self.recipient_id);
        offset += RECIPIENT_ID_LEN;
        out[offset..offset + 4].copy_from_slice(&self.total_chunks.to_be_bytes());
        offset += 4;
        out[offset..offset + 4].copy_from_slice(&self.data_chunks.to_be_bytes());
        offset += 4;
        out[offset..offset + 4].copy_from_slice(&self.prekey_id.to_be_bytes());
        offset += 4;
        out[offset..offset + 8].copy_from_slice(&self.ts.to_be_bytes());
        offset += 8;
        out[offset..offset + 8].copy_from_slice(&self.exp.to_be_bytes());
        Ok(out)
    }

    /// Parse a [`BODY_LEN`]-byte body buffer (no signature trailer).
    pub fn from_body_bytes(body: &[u8]) -> Result<Self, ManifestError> {
        if body.len() != BODY_LEN {
            return Err(ManifestError::BodyLengthMismatch {
                expected: BODY_LEN,
                actual: body.len(),
            });
        }
        let mut msg_id = [0u8; MSG_ID_LEN];
        msg_id.copy_from_slice(&body[0..16]);
        let mut sender_spk = [0u8; ED25519_KEY_LEN];
        sender_spk.copy_from_slice(&body[16..48]);
        let mut recipient_id = [0u8; RECIPIENT_ID_LEN];
        recipient_id.copy_from_slice(&body[48..80]);
        let total_chunks = u32::from_be_bytes(body[80..84].try_into().unwrap());
        let data_chunks = u32::from_be_bytes(body[84..88].try_into().unwrap());
        let prekey_id = u32::from_be_bytes(body[88..92].try_into().unwrap());
        let ts = u64::from_be_bytes(body[92..100].try_into().unwrap());
        let exp = u64::from_be_bytes(body[100..108].try_into().unwrap());

        if total_chunks == 0 || total_chunks > MAX_TOTAL_CHUNKS {
            return Err(ManifestError::TotalChunksOutOfRange {
                actual: total_chunks,
                max: MAX_TOTAL_CHUNKS,
            });
        }
        if data_chunks == 0 || data_chunks > total_chunks {
            return Err(ManifestError::DataChunksOutOfRange);
        }

        Ok(Self {
            msg_id,
            sender_spk,
            recipient_id,
            total_chunks,
            data_chunks,
            prekey_id,
            ts,
            exp,
        })
    }

    /// Sign the body with `sender_crypto` and return the wire-format TXT record.
    ///
    /// The caller is responsible for ensuring `self.sender_spk` matches
    /// `sender_crypto.signing_public_key_bytes()`; otherwise verification will
    /// fail because the manifest is self-signed.
    pub fn sign(&self, sender_crypto: &DmpCrypto) -> Result<String, ManifestError> {
        let body = self.to_body_bytes()?;
        let signature = sender_crypto.sign_data(&body);
        let mut wire = [0u8; WIRE_LEN];
        wire[..BODY_LEN].copy_from_slice(&body);
        wire[BODY_LEN..].copy_from_slice(&signature);
        Ok(format!("{RECORD_PREFIX}{}", BASE64_STANDARD.encode(wire)))
    }

    /// Parse and verify a manifest TXT record.
    ///
    /// Returns `Some((manifest, signature))` on success, or `None` if the record
    /// is malformed, truncated, or the signature fails verification against the
    /// `sender_spk` embedded in the body. Callers should still check `exp` and
    /// replay state separately.
    #[must_use]
    pub fn parse_and_verify(record: &str) -> Option<(Self, [u8; SIG_LEN])> {
        let payload = record.strip_prefix(RECORD_PREFIX)?;
        let wire = BASE64_STANDARD.decode(payload).ok()?;
        if wire.len() != WIRE_LEN {
            return None;
        }
        let body = &wire[..BODY_LEN];
        let mut signature = [0u8; SIG_LEN];
        signature.copy_from_slice(&wire[BODY_LEN..]);
        let manifest = Self::from_body_bytes(body).ok()?;
        if !DmpCrypto::verify_signature(body, &signature, &manifest.sender_spk) {
            return None;
        }
        Some((manifest, signature))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest(spk: [u8; ED25519_KEY_LEN]) -> SlotManifest {
        SlotManifest {
            msg_id: [0xAB; MSG_ID_LEN],
            sender_spk: spk,
            recipient_id: [0xCD; RECIPIENT_ID_LEN],
            total_chunks: 4,
            data_chunks: 2,
            prekey_id: 7,
            ts: 1_700_000_000,
            exp: 1_700_000_300,
        }
    }

    #[test]
    fn body_round_trip() {
        let crypto = DmpCrypto::generate();
        let manifest = sample_manifest(crypto.signing_public_key_bytes());
        let body = manifest.to_body_bytes().unwrap();
        let parsed = SlotManifest::from_body_bytes(&body).unwrap();
        assert_eq!(parsed, manifest);
    }

    #[test]
    fn body_layout_is_byte_exact() {
        let manifest = SlotManifest {
            msg_id: [0x11; MSG_ID_LEN],
            sender_spk: [0x22; ED25519_KEY_LEN],
            recipient_id: [0x33; RECIPIENT_ID_LEN],
            total_chunks: 1024,
            data_chunks: 512,
            prekey_id: 0x0000_0007,
            ts: 0x0123_4567_89AB_CDEF,
            exp: 0xFEDC_BA98_7654_3210,
        };
        let body = manifest.to_body_bytes().unwrap();
        assert_eq!(body.len(), BODY_LEN);
        assert_eq!(&body[0..16], &[0x11; 16]);
        assert_eq!(&body[16..48], &[0x22; 32]);
        assert_eq!(&body[48..80], &[0x33; 32]);
        assert_eq!(&body[80..84], &1024u32.to_be_bytes());
        assert_eq!(&body[84..88], &512u32.to_be_bytes());
        assert_eq!(&body[88..92], &0x0000_0007u32.to_be_bytes());
        assert_eq!(&body[92..100], &0x0123_4567_89AB_CDEFu64.to_be_bytes());
        assert_eq!(&body[100..108], &0xFEDC_BA98_7654_3210u64.to_be_bytes());
    }

    #[test]
    fn from_body_bytes_rejects_short_buffer() {
        let buf = [0u8; BODY_LEN - 1];
        assert!(matches!(
            SlotManifest::from_body_bytes(&buf),
            Err(ManifestError::BodyLengthMismatch { .. }),
        ));
    }

    #[test]
    fn from_body_bytes_rejects_long_buffer() {
        let buf = [0u8; BODY_LEN + 1];
        assert!(matches!(
            SlotManifest::from_body_bytes(&buf),
            Err(ManifestError::BodyLengthMismatch { .. }),
        ));
    }

    #[test]
    fn to_body_bytes_rejects_zero_total_chunks() {
        let crypto = DmpCrypto::generate();
        let mut manifest = sample_manifest(crypto.signing_public_key_bytes());
        manifest.total_chunks = 0;
        manifest.data_chunks = 0;
        assert!(matches!(
            manifest.to_body_bytes(),
            Err(ManifestError::TotalChunksOutOfRange { .. }),
        ));
    }

    #[test]
    fn to_body_bytes_rejects_data_chunks_above_total() {
        let crypto = DmpCrypto::generate();
        let mut manifest = sample_manifest(crypto.signing_public_key_bytes());
        manifest.total_chunks = 4;
        manifest.data_chunks = 5;
        assert!(matches!(
            manifest.to_body_bytes(),
            Err(ManifestError::DataChunksOutOfRange),
        ));
    }

    #[test]
    fn to_body_bytes_rejects_total_above_protocol_max() {
        let crypto = DmpCrypto::generate();
        let mut manifest = sample_manifest(crypto.signing_public_key_bytes());
        manifest.total_chunks = MAX_TOTAL_CHUNKS + 1;
        manifest.data_chunks = 1;
        assert!(matches!(
            manifest.to_body_bytes(),
            Err(ManifestError::TotalChunksOutOfRange { .. }),
        ));
    }

    #[test]
    fn sign_and_parse_round_trip() {
        let crypto = DmpCrypto::generate();
        let manifest = sample_manifest(crypto.signing_public_key_bytes());
        let wire = manifest.sign(&crypto).unwrap();
        let (parsed, _sig) = SlotManifest::parse_and_verify(&wire).expect("manifest must verify");
        assert_eq!(parsed, manifest);
    }

    #[test]
    fn parse_and_verify_rejects_missing_prefix() {
        let crypto = DmpCrypto::generate();
        let manifest = sample_manifest(crypto.signing_public_key_bytes());
        let wire = manifest.sign(&crypto).unwrap();
        let stripped = wire.strip_prefix(RECORD_PREFIX).unwrap();
        assert!(SlotManifest::parse_and_verify(stripped).is_none());
    }

    #[test]
    fn parse_and_verify_rejects_bad_base64() {
        let bogus = format!("{RECORD_PREFIX}!!!not-base64!!!");
        assert!(SlotManifest::parse_and_verify(&bogus).is_none());
    }

    #[test]
    fn parse_and_verify_rejects_flipped_signature() {
        let crypto = DmpCrypto::generate();
        let manifest = sample_manifest(crypto.signing_public_key_bytes());
        let wire = manifest.sign(&crypto).unwrap();
        let payload = wire.strip_prefix(RECORD_PREFIX).unwrap();
        let mut bytes = BASE64_STANDARD.decode(payload).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = format!("{RECORD_PREFIX}{}", BASE64_STANDARD.encode(&bytes));
        assert!(SlotManifest::parse_and_verify(&tampered).is_none());
    }

    #[test]
    fn parse_and_verify_rejects_wrong_wire_length() {
        // Truncated wire (missing one byte of signature) must fail.
        let crypto = DmpCrypto::generate();
        let manifest = sample_manifest(crypto.signing_public_key_bytes());
        let wire = manifest.sign(&crypto).unwrap();
        let payload = wire.strip_prefix(RECORD_PREFIX).unwrap();
        let mut bytes = BASE64_STANDARD.decode(payload).unwrap();
        bytes.pop();
        let truncated = format!("{RECORD_PREFIX}{}", BASE64_STANDARD.encode(&bytes));
        assert!(SlotManifest::parse_and_verify(&truncated).is_none());
    }

    #[test]
    fn is_expired_uses_explicit_now() {
        let crypto = DmpCrypto::generate();
        let manifest = sample_manifest(crypto.signing_public_key_bytes());
        assert!(!manifest.is_expired(Some(manifest.exp)));
        assert!(!manifest.is_expired(Some(manifest.exp - 1)));
        assert!(manifest.is_expired(Some(manifest.exp + 1)));
    }

    #[test]
    fn constants_match_python_reference() {
        assert_eq!(RECORD_PREFIX, "v=dmp1;t=manifest;d=");
        assert_eq!(BODY_LEN, 108);
        assert_eq!(SIG_LEN, 64);
        assert_eq!(WIRE_LEN, 172);
        assert_eq!(NO_PREKEY, 0);
        assert_eq!(MAX_TOTAL_CHUNKS, 1024);
        assert_eq!(DEFAULT_MANIFEST_TTL, 300);
    }
}

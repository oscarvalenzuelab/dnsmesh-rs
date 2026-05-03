//! Core DMP message structures: header, framed message, and DNS-encoded identity.
//!
//! Wire format mirrors the Python `dmp.core.message` module byte-for-byte:
//!
//! - `DMPHeader` is a JSON object serialized with `separators=(",", ":")`, hex-encoded
//!   byte fields, and insertion-ordered keys (`v`, `type`, `msg_id`, `sender`,
//!   `recipient`, `total`, `chunk`, `ts`, `ttl`).
//! - `DMPMessage` frames as `[header_len: u16 BE][header_json][payload][signature(32)]`.
//!   The trailing 32 bytes are reserved for a Poly1305-style MAC; this module treats
//!   them as opaque.
//! - `DMPIdentity` serializes to a DNS TXT body of the form
//!   `v=dmp1;type=identity;data=<json>`.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Length in bytes of a DMP message ID (UUIDv4 raw bytes).
pub const MESSAGE_ID_LEN: usize = 16;
/// Length in bytes of a DMP user ID (SHA-256 over an X25519 public key).
pub const USER_ID_LEN: usize = 32;
/// Length in bytes of the trailing MAC slot in a framed [`DMPMessage`].
///
/// Python places a 32-byte Poly1305 MAC placeholder here. This module treats it as
/// opaque; integrity is the caller's responsibility.
pub const SIGNATURE_LEN: usize = 32;
/// Header-length prefix size in bytes (big-endian `u16`).
pub const HEADER_LEN_PREFIX: usize = 2;
/// Minimum framed message size: `HEADER_LEN_PREFIX + SIGNATURE_LEN`.
pub const MIN_MESSAGE_LEN: usize = HEADER_LEN_PREFIX + SIGNATURE_LEN;
/// Default header TTL in seconds (5 minutes), matching Python.
pub const DEFAULT_TTL_SECS: u32 = 300;
/// Current header version. Anything else is rejected by `validate_basic`.
pub const HEADER_VERSION: u8 = 1;

/// Prefix for a DMP identity DNS TXT record.
pub const IDENTITY_RECORD_PREFIX: &str = "v=dmp1;type=identity;data=";

/// Errors returned by message parsing, validation, and DNS-record decoding.
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    /// Framed message was shorter than [`MIN_MESSAGE_LEN`].
    #[error("message too short: {len} bytes (need at least {min})")]
    TooShort {
        /// Bytes actually supplied.
        len: usize,
        /// Minimum required size.
        min: usize,
    },
    /// Header length prefix exceeded the available buffer.
    #[error("incomplete message: header_len {header_len} exceeds buffer")]
    Incomplete {
        /// Declared header length.
        header_len: usize,
    },
    /// Header JSON failed to parse or had a malformed/unknown field.
    #[error("invalid header: {0}")]
    InvalidHeader(String),
    /// `MessageType` string did not match any known variant.
    #[error("unknown message type: {0}")]
    UnknownMessageType(String),
    /// A hex-encoded byte field failed to decode.
    #[error("invalid hex field {field}: {source}")]
    InvalidHex {
        /// Name of the offending field (e.g. `"msg_id"`).
        field: &'static str,
        /// Underlying hex decoding error.
        #[source]
        source: hex::FromHexError,
    },
    /// A decoded byte field had the wrong length.
    #[error("invalid length for {field}: expected {expected}, got {actual}")]
    InvalidLength {
        /// Name of the offending field.
        field: &'static str,
        /// Required length.
        expected: usize,
        /// Length actually decoded.
        actual: usize,
    },
    /// `validate_basic` rejected a header (version, expiry, chunk range, etc).
    #[error("validation failed: {0}")]
    Validation(String),
    /// Identity DNS record did not start with [`IDENTITY_RECORD_PREFIX`].
    #[error("invalid identity record format")]
    InvalidIdentityRecord,
}

/// DMP message types. Wire-encoded as the uppercase string literals from Python's
/// `MessageType.value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// Application data message.
    Data,
    /// Acknowledgement of a previously received message.
    Ack,
    /// Discovery probe / announcement.
    Discovery,
    /// Identity record exchange.
    Identity,
    /// Mailbox-routed message.
    Mailbox,
}

impl MessageType {
    /// Wire string form, identical to Python's `MessageType.value`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Data => "DATA",
            Self::Ack => "ACK",
            Self::Discovery => "DISCOVERY",
            Self::Identity => "IDENTITY",
            Self::Mailbox => "MAILBOX",
        }
    }

    /// Parse a wire string into a [`MessageType`].
    pub fn parse(s: &str) -> Result<Self, MessageError> {
        match s {
            "DATA" => Ok(Self::Data),
            "ACK" => Ok(Self::Ack),
            "DISCOVERY" => Ok(Self::Discovery),
            "IDENTITY" => Ok(Self::Identity),
            "MAILBOX" => Ok(Self::Mailbox),
            other => Err(MessageError::UnknownMessageType(other.to_string())),
        }
    }
}

impl std::str::FromStr for MessageType {
    type Err = MessageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// DMP message header containing all routing and chunking metadata.
///
/// Mirrors Python's `DMPHeader` dataclass. Byte fields are fixed-size at this layer:
/// the JSON wire form hex-encodes them, but in-memory they are arrays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DMPHeader {
    /// Header version. Always [`HEADER_VERSION`] for the current protocol.
    pub version: u8,
    /// Type discriminator; see [`MessageType`].
    pub message_type: MessageType,
    /// 16-byte message identifier (typically UUIDv4 raw bytes).
    pub message_id: [u8; MESSAGE_ID_LEN],
    /// 32-byte sender user ID (SHA-256 over the sender's X25519 public key).
    pub sender_id: [u8; USER_ID_LEN],
    /// 32-byte recipient user ID.
    pub recipient_id: [u8; USER_ID_LEN],
    /// Total number of chunks in the logical message (>= 1).
    pub total_chunks: u32,
    /// Zero-based chunk index; must be `< total_chunks`.
    pub chunk_number: u32,
    /// Unix epoch seconds at send time.
    pub timestamp: u64,
    /// Time-to-live in seconds. Message is considered expired after `timestamp + ttl`.
    pub ttl: u32,
}

impl Default for DMPHeader {
    fn default() -> Self {
        Self {
            version: HEADER_VERSION,
            message_type: MessageType::Data,
            message_id: [0u8; MESSAGE_ID_LEN],
            sender_id: [0u8; USER_ID_LEN],
            recipient_id: [0u8; USER_ID_LEN],
            total_chunks: 1,
            chunk_number: 0,
            timestamp: current_unix_secs(),
            ttl: DEFAULT_TTL_SECS,
        }
    }
}

impl DMPHeader {
    /// Serialize as compact JSON matching Python's `to_bytes`.
    ///
    /// Key order is fixed: `v`, `type`, `msg_id`, `sender`, `recipient`, `total`,
    /// `chunk`, `ts`, `ttl`. Byte fields are lowercase hex with no separators.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert("v".to_string(), Value::from(self.version));
        map.insert("type".to_string(), Value::from(self.message_type.as_str()));
        map.insert(
            "msg_id".to_string(),
            Value::from(hex::encode(self.message_id)),
        );
        map.insert(
            "sender".to_string(),
            Value::from(hex::encode(self.sender_id)),
        );
        map.insert(
            "recipient".to_string(),
            Value::from(hex::encode(self.recipient_id)),
        );
        map.insert("total".to_string(), Value::from(self.total_chunks));
        map.insert("chunk".to_string(), Value::from(self.chunk_number));
        map.insert("ts".to_string(), Value::from(self.timestamp));
        map.insert("ttl".to_string(), Value::from(self.ttl));
        // serde_json with `preserve_order` keeps insertion order, matching Python.
        // Default `to_vec` emits compact JSON (no whitespace), matching `separators=(",", ":")`.
        serde_json::to_vec(&Value::Object(map)).expect("DMPHeader is always serializable to JSON")
    }

    /// Parse a header from its compact-JSON wire form.
    pub fn from_bytes(data: &[u8]) -> Result<Self, MessageError> {
        let value: Value =
            serde_json::from_slice(data).map_err(|e| MessageError::InvalidHeader(e.to_string()))?;
        let obj = value
            .as_object()
            .ok_or_else(|| MessageError::InvalidHeader("expected JSON object".to_string()))?;

        let version = get_u64(obj, "v")?
            .try_into()
            .map_err(|_| MessageError::InvalidHeader("v out of range for u8".to_string()))?;
        let type_str = get_str(obj, "type")?;
        let message_type = MessageType::parse(type_str)?;
        let message_id = get_hex_array::<MESSAGE_ID_LEN>(obj, "msg_id")?;
        let sender_id = get_hex_array::<USER_ID_LEN>(obj, "sender")?;
        let recipient_id = get_hex_array::<USER_ID_LEN>(obj, "recipient")?;
        let total_chunks = get_u64(obj, "total")?
            .try_into()
            .map_err(|_| MessageError::InvalidHeader("total out of range for u32".to_string()))?;
        let chunk_number = get_u64(obj, "chunk")?
            .try_into()
            .map_err(|_| MessageError::InvalidHeader("chunk out of range for u32".to_string()))?;
        let timestamp = get_u64(obj, "ts")?;
        let ttl = get_u64(obj, "ttl")?
            .try_into()
            .map_err(|_| MessageError::InvalidHeader("ttl out of range for u32".to_string()))?;

        Ok(Self {
            version,
            message_type,
            message_id,
            sender_id,
            recipient_id,
            total_chunks,
            chunk_number,
            timestamp,
            ttl,
        })
    }

    /// Whether this header is expired relative to `now` (Unix epoch seconds).
    ///
    /// Matches Python's strict `now > timestamp + ttl` comparison.
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        now > self.timestamp.saturating_add(u64::from(self.ttl))
    }

    /// Stable per-chunk identifier of the form `<msg_id_hex>-<chunk_4digit>`.
    ///
    /// Matches Python's `f"{message_id.hex()}-{chunk_number:04d}"`. Chunk numbers
    /// beyond 9999 still render with their natural digit count.
    #[must_use]
    pub fn get_chunk_id(&self) -> String {
        format!("{}-{:04}", hex::encode(self.message_id), self.chunk_number)
    }
}

/// Complete DMP message: header, payload, and trailing 32-byte signature slot.
///
/// `signature` is opaque to this struct; integrity verification belongs to the
/// caller (e.g., the chunk encoder/decoder).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DMPMessage {
    /// Routing/chunking metadata.
    pub header: DMPHeader,
    /// Application payload (post-encryption / post-encoding from upper layers).
    pub payload: Vec<u8>,
    /// 32-byte trailing MAC slot. Stored as a `Vec` to mirror Python; `validate_basic`
    /// does not enforce its length, but `to_bytes`/`from_bytes` always frame 32 bytes.
    pub signature: Vec<u8>,
}

impl Default for DMPMessage {
    fn default() -> Self {
        Self {
            header: DMPHeader::default(),
            payload: Vec::new(),
            signature: vec![0u8; SIGNATURE_LEN],
        }
    }
}

impl DMPMessage {
    /// Frame as `[header_len: u16 BE][header_json][payload][signature(32)]`.
    ///
    /// The trailing signature is right-padded or truncated to exactly
    /// [`SIGNATURE_LEN`] bytes to keep the wire format fixed.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let header_bytes = self.header.to_bytes();
        let header_len = header_bytes.len();
        let mut out =
            Vec::with_capacity(HEADER_LEN_PREFIX + header_len + self.payload.len() + SIGNATURE_LEN);
        // Truncate header_len to u16 — values >65535 would overflow the wire format,
        // but a well-formed header is well under that.
        let header_len_u16 = u16::try_from(header_len)
            .expect("DMP headers must fit in u16; oversize headers are not representable");
        out.extend_from_slice(&header_len_u16.to_be_bytes());
        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&self.payload);
        // Frame exactly SIGNATURE_LEN bytes; pad with zeros or truncate.
        let mut sig = [0u8; SIGNATURE_LEN];
        let take = self.signature.len().min(SIGNATURE_LEN);
        sig[..take].copy_from_slice(&self.signature[..take]);
        out.extend_from_slice(&sig);
        out
    }

    /// Parse a framed DMP message.
    pub fn from_bytes(data: &[u8]) -> Result<Self, MessageError> {
        if data.len() < MIN_MESSAGE_LEN {
            return Err(MessageError::TooShort {
                len: data.len(),
                min: MIN_MESSAGE_LEN,
            });
        }
        let header_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < HEADER_LEN_PREFIX + header_len + SIGNATURE_LEN {
            return Err(MessageError::Incomplete { header_len });
        }
        let header_end = HEADER_LEN_PREFIX + header_len;
        let payload_end = data.len() - SIGNATURE_LEN;
        let header = DMPHeader::from_bytes(&data[HEADER_LEN_PREFIX..header_end])?;
        let payload = data[header_end..payload_end].to_vec();
        let signature = data[payload_end..].to_vec();
        Ok(Self {
            header,
            payload,
            signature,
        })
    }

    /// SHA-256 over `header.to_bytes() || payload` — the message identity hash.
    ///
    /// The trailing signature slot is intentionally excluded so a re-MAC of the same
    /// content yields the same hash.
    #[must_use]
    pub fn calculate_message_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.header.to_bytes());
        hasher.update(&self.payload);
        hasher.finalize().into()
    }

    /// Build a sibling chunk message that shares this message's routing header but
    /// carries a different `chunk_number` and `chunk_data`. Inherits the parent's
    /// signature slot verbatim — callers that need per-chunk MACs must overwrite it.
    #[must_use]
    pub fn create_chunk(&self, chunk_num: u32, chunk_data: &[u8]) -> Self {
        let mut header = self.header.clone();
        header.chunk_number = chunk_num;
        Self {
            header,
            payload: chunk_data.to_vec(),
            signature: self.signature.clone(),
        }
    }

    /// Cheap structural validation: version, expiry, chunk range, and header byte-field
    /// lengths. Returns `Ok(())` on success or [`MessageError::Validation`] on failure.
    ///
    /// Does NOT verify the trailing signature — that requires a key the caller owns.
    pub fn validate_basic(&self, now: u64) -> Result<(), MessageError> {
        if self.header.version != HEADER_VERSION {
            return Err(MessageError::Validation(format!(
                "Unsupported version: {}",
                self.header.version
            )));
        }
        if self.header.is_expired(now) {
            return Err(MessageError::Validation("Message has expired".to_string()));
        }
        if self.header.chunk_number >= self.header.total_chunks {
            return Err(MessageError::Validation(format!(
                "Invalid chunk number: {} >= {}",
                self.header.chunk_number, self.header.total_chunks
            )));
        }
        // The byte fields are arrays at this layer, so their lengths are guaranteed by
        // the type system. We still expose this method for parity with Python and to
        // catch future schema drift if these fields ever become Vec<u8>.
        if self.header.message_id.len() != MESSAGE_ID_LEN {
            return Err(MessageError::Validation(
                "Invalid message ID length".to_string(),
            ));
        }
        if self.header.sender_id.len() != USER_ID_LEN {
            return Err(MessageError::Validation(
                "Invalid sender ID length".to_string(),
            ));
        }
        if self.header.recipient_id.len() != USER_ID_LEN {
            return Err(MessageError::Validation(
                "Invalid recipient ID length".to_string(),
            ));
        }
        Ok(())
    }
}

/// User identity record for the DMP DNS overlay.
///
/// Encoded into a TXT record body of the form
/// `v=dmp1;type=identity;data=<json>`. The JSON object holds `username`, hex-encoded
/// `pubkey`, `created` (Unix seconds), hex-encoded `sig`, and free-form `meta`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DMPIdentity {
    /// Human-readable identity username (e.g. local-part of an address).
    pub username: String,
    /// Raw public key bytes (X25519 by convention; hex-encoded on the wire).
    pub public_key: Vec<u8>,
    /// Creation time as Unix epoch seconds.
    pub created_at: u64,
    /// Self-signature over the identity body (hex-encoded on the wire). May be empty
    /// for unsigned/preliminary records.
    pub signature: Vec<u8>,
    /// Free-form metadata. Preserved verbatim across the round-trip.
    pub metadata: Value,
}

impl DMPIdentity {
    /// SHA-256 over the public key — the user ID this identity claims.
    #[must_use]
    pub fn get_user_id(&self) -> [u8; 32] {
        Sha256::digest(&self.public_key).into()
    }

    /// Format as a DNS TXT record body. Matches Python's `to_dns_record`.
    #[must_use]
    pub fn to_dns_record(&self) -> String {
        let mut data = Map::new();
        data.insert("username".to_string(), Value::from(self.username.clone()));
        data.insert(
            "pubkey".to_string(),
            Value::from(hex::encode(&self.public_key)),
        );
        data.insert("created".to_string(), Value::from(self.created_at));
        data.insert("sig".to_string(), Value::from(hex::encode(&self.signature)));
        data.insert("meta".to_string(), self.metadata.clone());
        let json_str = serde_json::to_string(&Value::Object(data))
            .expect("DMPIdentity is always serializable to JSON");
        format!("{IDENTITY_RECORD_PREFIX}{json_str}")
    }

    /// Parse a DNS TXT record body produced by [`Self::to_dns_record`].
    pub fn from_dns_record(record: &str) -> Result<Self, MessageError> {
        let json_str = record
            .strip_prefix(IDENTITY_RECORD_PREFIX)
            .ok_or(MessageError::InvalidIdentityRecord)?;
        let value: Value = serde_json::from_str(json_str)
            .map_err(|e| MessageError::InvalidHeader(e.to_string()))?;
        let obj = value
            .as_object()
            .ok_or_else(|| MessageError::InvalidHeader("expected JSON object".to_string()))?;
        let username = get_str(obj, "username")?.to_string();
        let pubkey_hex = get_str(obj, "pubkey")?;
        let public_key = hex::decode(pubkey_hex).map_err(|e| MessageError::InvalidHex {
            field: "pubkey",
            source: e,
        })?;
        let created_at = get_u64(obj, "created")?;
        let sig_hex = get_str(obj, "sig")?;
        let signature = hex::decode(sig_hex).map_err(|e| MessageError::InvalidHex {
            field: "sig",
            source: e,
        })?;
        let metadata = obj
            .get("meta")
            .cloned()
            .unwrap_or_else(|| Value::Object(Map::new()));

        Ok(Self {
            username,
            public_key,
            created_at,
            signature,
            metadata,
        })
    }
}

// --- Helpers --------------------------------------------------------------

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn get_u64(obj: &Map<String, Value>, key: &'static str) -> Result<u64, MessageError> {
    obj.get(key)
        .ok_or_else(|| MessageError::InvalidHeader(format!("missing field: {key}")))?
        .as_u64()
        .ok_or_else(|| MessageError::InvalidHeader(format!("field {key} is not a u64")))
}

fn get_str<'a>(obj: &'a Map<String, Value>, key: &'static str) -> Result<&'a str, MessageError> {
    obj.get(key)
        .ok_or_else(|| MessageError::InvalidHeader(format!("missing field: {key}")))?
        .as_str()
        .ok_or_else(|| MessageError::InvalidHeader(format!("field {key} is not a string")))
}

fn get_hex_array<const N: usize>(
    obj: &Map<String, Value>,
    key: &'static str,
) -> Result<[u8; N], MessageError> {
    let s = get_str(obj, key)?;
    let bytes = hex::decode(s).map_err(|e| MessageError::InvalidHex {
        field: match key {
            "msg_id" => "msg_id",
            "sender" => "sender",
            "recipient" => "recipient",
            _ => "field",
        },
        source: e,
    })?;
    if bytes.len() != N {
        return Err(MessageError::InvalidLength {
            field: match key {
                "msg_id" => "msg_id",
                "sender" => "sender",
                "recipient" => "recipient",
                _ => "field",
            },
            expected: N,
            actual: bytes.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> DMPHeader {
        DMPHeader {
            version: 1,
            message_type: MessageType::Data,
            message_id: [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
                0xff, 0x00,
            ],
            sender_id: [0xa1; USER_ID_LEN],
            recipient_id: [0xb2; USER_ID_LEN],
            total_chunks: 4,
            chunk_number: 2,
            timestamp: 1_700_000_000,
            ttl: 600,
        }
    }

    #[test]
    fn message_type_round_trips_python_strings() {
        for mt in [
            MessageType::Data,
            MessageType::Ack,
            MessageType::Discovery,
            MessageType::Identity,
            MessageType::Mailbox,
        ] {
            assert_eq!(MessageType::parse(mt.as_str()).unwrap(), mt);
        }
        // Wire strings are uppercase, matching Python `MessageType.value`.
        assert_eq!(MessageType::Data.as_str(), "DATA");
        assert_eq!(MessageType::Mailbox.as_str(), "MAILBOX");
        assert!(matches!(
            MessageType::parse("data"),
            Err(MessageError::UnknownMessageType(_))
        ));
    }

    #[test]
    fn header_to_bytes_matches_python_layout() {
        let header = sample_header();
        let bytes = header.to_bytes();
        let json = std::str::from_utf8(&bytes).unwrap();
        // Compact JSON, no whitespace, fixed key order.
        let expected = format!(
            r#"{{"v":1,"type":"DATA","msg_id":"{}","sender":"{}","recipient":"{}","total":4,"chunk":2,"ts":1700000000,"ttl":600}}"#,
            hex::encode(header.message_id),
            hex::encode(header.sender_id),
            hex::encode(header.recipient_id),
        );
        assert_eq!(json, expected);
    }

    #[test]
    fn header_round_trip() {
        let header = sample_header();
        let bytes = header.to_bytes();
        let parsed = DMPHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, header);
    }

    #[test]
    fn header_from_bytes_rejects_bad_hex() {
        let bad = br#"{"v":1,"type":"DATA","msg_id":"zzzz","sender":"00","recipient":"00","total":1,"chunk":0,"ts":0,"ttl":0}"#;
        assert!(matches!(
            DMPHeader::from_bytes(bad),
            Err(MessageError::InvalidHex { .. })
        ));
    }

    #[test]
    fn header_from_bytes_rejects_wrong_length_id() {
        let json = format!(
            r#"{{"v":1,"type":"DATA","msg_id":"{}","sender":"{}","recipient":"{}","total":1,"chunk":0,"ts":0,"ttl":0}}"#,
            "11".repeat(15), // only 15 bytes, not 16
            "a1".repeat(USER_ID_LEN),
            "b2".repeat(USER_ID_LEN),
        );
        assert!(matches!(
            DMPHeader::from_bytes(json.as_bytes()),
            Err(MessageError::InvalidLength { .. })
        ));
    }

    #[test]
    fn get_chunk_id_format() {
        let mut h = sample_header();
        h.message_id = [0u8; MESSAGE_ID_LEN];
        h.chunk_number = 7;
        assert_eq!(h.get_chunk_id(), format!("{}-0007", "0".repeat(32)));
        h.chunk_number = 1234;
        assert_eq!(h.get_chunk_id(), format!("{}-1234", "0".repeat(32)));
    }

    #[test]
    fn is_expired_strict_greater_than() {
        let h = sample_header();
        // not expired exactly at boundary
        let boundary = h.timestamp + u64::from(h.ttl);
        assert!(!h.is_expired(boundary));
        assert!(h.is_expired(boundary + 1));
    }

    fn sample_message() -> DMPMessage {
        DMPMessage {
            header: sample_header(),
            payload: b"hello world".to_vec(),
            signature: vec![0xcc; SIGNATURE_LEN],
        }
    }

    #[test]
    fn message_round_trip() {
        let msg = sample_message();
        let bytes = msg.to_bytes();
        let parsed = DMPMessage::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn message_from_bytes_rejects_too_short() {
        assert!(matches!(
            DMPMessage::from_bytes(&[0u8; 33]),
            Err(MessageError::TooShort { .. })
        ));
    }

    #[test]
    fn message_from_bytes_rejects_incomplete() {
        // Claim a 1000-byte header but supply only 50 bytes total.
        let mut buf = vec![0u8; 50];
        buf[0..2].copy_from_slice(&1000u16.to_be_bytes());
        assert!(matches!(
            DMPMessage::from_bytes(&buf),
            Err(MessageError::Incomplete { .. })
        ));
    }

    #[test]
    fn validate_basic_accepts_valid_message() {
        let msg = sample_message();
        let now = msg.header.timestamp + 10;
        msg.validate_basic(now).unwrap();
    }

    #[test]
    fn validate_basic_rejects_unknown_version() {
        let mut msg = sample_message();
        msg.header.version = 2;
        let now = msg.header.timestamp + 10;
        assert!(matches!(
            msg.validate_basic(now),
            Err(MessageError::Validation(_))
        ));
    }

    #[test]
    fn validate_basic_rejects_expired() {
        let msg = sample_message();
        let now = msg.header.timestamp + u64::from(msg.header.ttl) + 1;
        assert!(matches!(
            msg.validate_basic(now),
            Err(MessageError::Validation(_))
        ));
    }

    #[test]
    fn validate_basic_rejects_chunk_out_of_range() {
        let mut msg = sample_message();
        msg.header.chunk_number = msg.header.total_chunks;
        let now = msg.header.timestamp + 10;
        assert!(matches!(
            msg.validate_basic(now),
            Err(MessageError::Validation(_))
        ));
    }

    #[test]
    fn calculate_message_hash_is_deterministic() {
        let msg = sample_message();
        let h1 = msg.calculate_message_hash();
        let h2 = msg.calculate_message_hash();
        assert_eq!(h1, h2);
        // Independent SHA-256 over header || payload — externally checkable.
        let mut hasher = Sha256::new();
        hasher.update(msg.header.to_bytes());
        hasher.update(&msg.payload);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(h1, expected);
        // Changing the signature does NOT change the hash.
        let mut other = msg.clone();
        other.signature = vec![0xff; SIGNATURE_LEN];
        assert_eq!(other.calculate_message_hash(), h1);
        // Changing the payload DOES change the hash.
        let mut other = msg.clone();
        other.payload.push(0x00);
        assert_ne!(other.calculate_message_hash(), h1);
    }

    #[test]
    fn create_chunk_inherits_routing() {
        let msg = sample_message();
        let chunk = msg.create_chunk(3, b"chunk-3");
        assert_eq!(chunk.header.message_id, msg.header.message_id);
        assert_eq!(chunk.header.sender_id, msg.header.sender_id);
        assert_eq!(chunk.header.recipient_id, msg.header.recipient_id);
        assert_eq!(chunk.header.total_chunks, msg.header.total_chunks);
        assert_eq!(chunk.header.timestamp, msg.header.timestamp);
        assert_eq!(chunk.header.ttl, msg.header.ttl);
        assert_eq!(chunk.header.chunk_number, 3);
        assert_eq!(chunk.payload, b"chunk-3");
        assert_eq!(chunk.signature, msg.signature);
    }

    #[test]
    fn identity_dns_record_round_trip() {
        let identity = DMPIdentity {
            username: "alice".to_string(),
            public_key: vec![0xab; 32],
            created_at: 1_700_000_000,
            signature: vec![0xcd; 64],
            metadata: serde_json::json!({"device": "phone", "n": 7}),
        };
        let record = identity.to_dns_record();
        assert!(record.starts_with(IDENTITY_RECORD_PREFIX));
        let parsed = DMPIdentity::from_dns_record(&record).unwrap();
        assert_eq!(parsed, identity);
    }

    #[test]
    fn identity_from_dns_record_rejects_bad_prefix() {
        assert!(matches!(
            DMPIdentity::from_dns_record("v=other;data={}"),
            Err(MessageError::InvalidIdentityRecord)
        ));
    }

    #[test]
    fn identity_default_metadata_is_empty_object() {
        let body = format!(
            r#"{}{{"username":"bob","pubkey":"{}","created":1,"sig":""}}"#,
            IDENTITY_RECORD_PREFIX,
            hex::encode([0u8; 32]),
        );
        let parsed = DMPIdentity::from_dns_record(&body).unwrap();
        assert_eq!(parsed.metadata, Value::Object(Map::new()));
    }

    #[test]
    fn identity_user_id_is_sha256_of_pubkey() {
        let identity = DMPIdentity {
            username: "alice".to_string(),
            public_key: vec![0u8; 32],
            created_at: 0,
            signature: vec![],
            metadata: Value::Object(Map::new()),
        };
        let id = identity.get_user_id();
        // sha256 of 32 zero bytes — same vector used in crypto.rs.
        assert_eq!(
            hex::encode(id),
            "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
        );
    }
}

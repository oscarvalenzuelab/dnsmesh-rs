//! DNS-discoverable bootstrap records: user-domain to cluster routing.
//!
//! A `BootstrapRecord` is a signed TXT record published at `_dmp.<user_domain>`
//! that maps an address like `alice@example.com` to one or more DMP clusters.
//! The signer is the *zone operator* of the user domain, a trust role distinct
//! from the cluster operator whose key signs `ClusterManifest`. In a self-
//! hosted deployment the two keys may coincide; in multi-tenant deployments
//! the zone operator points at clusters run by third parties.
//!
//! Wire format (binary, base64'd, prefixed with `v=dmp1;t=bootstrap;`):
//!
//! ```text
//! body:
//!     magic            (7) = b"DMPBS01"
//!     seq              (8 BE)
//!     exp              (8 BE)
//!     signer_spk      (32)
//!     user_domain_len  (1)
//!     user_domain     (utf-8, <= 64 bytes)
//!     entry_count      (1, 1..=16)
//!     per entry:
//!         priority         (2 BE)
//!         base_domain_len  (1)
//!         base_domain      (utf-8, <= 64 bytes)
//!         operator_spk    (32)
//! sig: Ed25519 signature over body (64 bytes)
//! ```
//!
//! Entries are sorted by ascending priority on sign and on parse so
//! `entries[0]` is always the most preferred.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;

use crate::cluster::{validate_dns_name, ClusterError};
use crate::crypto::{DmpCrypto, ED25519_KEY_LEN, ED25519_SIG_LEN};

/// TXT prefix that tags a DMP bootstrap record.
pub const RECORD_PREFIX: &str = "v=dmp1;t=bootstrap;";

/// Magic bytes at the start of a bootstrap record body.
pub const MAGIC: &[u8; 7] = b"DMPBS01";

/// Length of the trailing Ed25519 signature in bytes.
pub const SIG_LEN: usize = ED25519_SIG_LEN;

/// Length of the zone-operator Ed25519 signing public key in bytes.
pub const SIGNER_SPK_LEN: usize = ED25519_KEY_LEN;

/// Length of the per-entry cluster operator Ed25519 signing public key in bytes.
pub const OPERATOR_SPK_LEN: usize = ED25519_KEY_LEN;

/// Maximum `user_domain` length in UTF-8 bytes (excluding a permitted
/// canonical-FQDN trailing dot).
pub const MAX_USER_DOMAIN_LEN: usize = 64;

/// Maximum `cluster_base_domain` length in UTF-8 bytes (excluding a
/// permitted canonical-FQDN trailing dot).
pub const MAX_BASE_DOMAIN_LEN: usize = 64;

/// Maximum number of entries in a bootstrap record.
pub const MAX_ENTRY_COUNT: usize = 16;

/// Absolute wire-length cap, enforced at sign() and parse_and_verify time.
pub const MAX_WIRE_LEN: usize = 1200;

/// Errors returned while building or parsing bootstrap records.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    /// `user_domain` was empty after canonicalization.
    #[error("user_domain must be a non-empty string")]
    UserDomainEmpty,
    /// `user_domain` had a doubled trailing dot or empty interior label.
    #[error("user_domain has empty label (leading/double/interior dot not allowed)")]
    EmptyLabel,
    /// `user_domain` exceeded the byte cap.
    #[error("user_domain too long (max {max} utf-8 bytes, got {actual})")]
    UserDomainTooLong { actual: usize, max: usize },
    /// `cluster_base_domain` was empty or too long.
    #[error("invalid cluster_base_domain: {0}")]
    InvalidBaseDomain(String),
    /// A label-rule violation in `user_domain` or `cluster_base_domain`.
    #[error("invalid label: {0}")]
    InvalidLabel(String),
    /// A 32-byte key was expected but a different number of bytes was supplied.
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    /// Empty entry list, or count above [`MAX_ENTRY_COUNT`].
    #[error("invalid entry_count: {0}")]
    InvalidEntryCount(String),
    /// Two entries shared the same `(priority, cluster_base_domain)` pair.
    #[error("duplicate entry (priority={priority}, cluster_base_domain={base_domain:?})")]
    DuplicateEntry { priority: u16, base_domain: String },
    /// The body buffer was truncated or had trailing bytes.
    #[error("malformed body: {0}")]
    MalformedBody(&'static str),
    /// The signing key did not match the declared `signer_spk`.
    #[error("signing key does not match declared signer_spk")]
    SigningKeyMismatch,
    /// The wire string exceeded [`MAX_WIRE_LEN`].
    #[error("wire size {actual} exceeds MAX_WIRE_LEN {max}")]
    WireTooLong { actual: usize, max: usize },
}

impl From<ClusterError> for BootstrapError {
    fn from(value: ClusterError) -> Self {
        match value {
            ClusterError::ClusterNameEmpty => Self::UserDomainEmpty,
            ClusterError::EmptyLabel => Self::EmptyLabel,
            ClusterError::ClusterNameTooLong { actual, max } => {
                Self::UserDomainTooLong { actual, max }
            }
            ClusterError::InvalidLabel(s) => Self::InvalidLabel(s),
            other => Self::MalformedBody(match other {
                ClusterError::MalformedBody(s) => s,
                _ => "validation error",
            }),
        }
    }
}

/// Return the TXT RRset name where this user-domain's bootstrap lives.
///
/// Convention: `_dmp.<user_domain>`. Applies the same DNS-name validation
/// `BootstrapRecord` enforces so direct callers get the same early
/// rejection.
pub fn bootstrap_rrset_name(user_domain: &str) -> Result<String, BootstrapError> {
    validate_dns_name(user_domain).map_err(BootstrapError::from)?;
    let normalized = user_domain.strip_suffix('.').unwrap_or(user_domain);
    Ok(format!("_dmp.{normalized}"))
}

/// One cluster choice inside a bootstrap record.
///
/// Lower `priority` is preferred (like SMTP MX). The same
/// `(priority, cluster_base_domain)` pair must not repeat within a
/// record; duplicate priorities with distinct base domains are fine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapEntry {
    /// 16-bit unsigned preference; lower is preferred.
    pub priority: u16,
    /// DNS name where the cluster's manifest lives (under `cluster.<X>`).
    pub cluster_base_domain: String,
    /// 32-byte Ed25519 signing public key of the cluster operator that
    /// signs the manifest at `cluster.<cluster_base_domain>`.
    pub operator_spk: [u8; OPERATOR_SPK_LEN],
}

impl BootstrapEntry {
    /// Validate field invariants. Mutates `self` only to canonicalize a
    /// single trailing dot on `cluster_base_domain`.
    fn validate(&mut self) -> Result<(), BootstrapError> {
        if self.cluster_base_domain.is_empty() {
            return Err(BootstrapError::InvalidBaseDomain(
                "must be a non-empty string".into(),
            ));
        }
        validate_dns_name(&self.cluster_base_domain).map_err(BootstrapError::from)?;
        if self.cluster_base_domain.ends_with('.') {
            self.cluster_base_domain.pop();
        }
        if self.cluster_base_domain.is_empty() {
            return Err(BootstrapError::InvalidBaseDomain(
                "must be a non-empty string".into(),
            ));
        }
        if self.cluster_base_domain.len() > MAX_BASE_DOMAIN_LEN {
            return Err(BootstrapError::InvalidBaseDomain(format!(
                "too long (max {MAX_BASE_DOMAIN_LEN} utf-8 bytes)"
            )));
        }
        Ok(())
    }

    /// Serialize one entry to its on-the-wire body bytes. Mutates `self`
    /// to canonicalize the trailing dot on `cluster_base_domain`.
    pub fn to_body_bytes(&mut self) -> Result<Vec<u8>, BootstrapError> {
        self.validate()?;
        let base_bytes = self.cluster_base_domain.as_bytes();
        let mut out = Vec::with_capacity(2 + 1 + base_bytes.len() + OPERATOR_SPK_LEN);
        out.extend_from_slice(&self.priority.to_be_bytes());
        // Length-checked above against MAX_BASE_DOMAIN_LEN (64); cast cannot truncate.
        out.push(u8::try_from(base_bytes.len()).expect("base_domain length fits in u8"));
        out.extend_from_slice(base_bytes);
        out.extend_from_slice(&self.operator_spk);
        Ok(out)
    }

    /// Parse one entry starting at `offset`; returns the entry and the
    /// new offset on success.
    pub fn from_body_bytes(body: &[u8], offset: usize) -> Result<(Self, usize), BootstrapError> {
        // priority(2) + base_domain_len(1) = 3 bytes minimum header
        if offset + 3 > body.len() {
            return Err(BootstrapError::MalformedBody(
                "truncated entry: missing priority/base_domain_len",
            ));
        }
        let mut off = offset;
        let priority = u16::from_be_bytes([body[off], body[off + 1]]);
        off += 2;
        let base_len = body[off] as usize;
        off += 1;
        if off + base_len > body.len() {
            return Err(BootstrapError::MalformedBody(
                "truncated entry: cluster_base_domain",
            ));
        }
        let has_trailing_dot = base_len > 0 && body[off + base_len - 1] == b'.';
        let effective_len = base_len - usize::from(has_trailing_dot);
        if effective_len == 0 || effective_len > MAX_BASE_DOMAIN_LEN {
            return Err(BootstrapError::InvalidBaseDomain("invalid length".into()));
        }
        let mut base_domain = std::str::from_utf8(&body[off..off + base_len])
            .map_err(|_| BootstrapError::InvalidBaseDomain("not utf-8".into()))?
            .to_string();
        off += base_len;
        if off + OPERATOR_SPK_LEN > body.len() {
            return Err(BootstrapError::MalformedBody(
                "truncated entry: operator_spk",
            ));
        }
        let mut operator_spk = [0u8; OPERATOR_SPK_LEN];
        operator_spk.copy_from_slice(&body[off..off + OPERATOR_SPK_LEN]);
        off += OPERATOR_SPK_LEN;
        validate_dns_name(&base_domain).map_err(BootstrapError::from)?;
        if base_domain.ends_with('.') {
            base_domain.pop();
        }
        Ok((
            Self {
                priority,
                cluster_base_domain: base_domain,
                operator_spk,
            },
            off,
        ))
    }
}

/// DNS-discoverable pointer from a user domain to one or more clusters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapRecord {
    /// Owner of the address space (e.g. `example.com`).
    pub user_domain: String,
    /// 32-byte Ed25519 signing public key of the zone operator.
    pub signer_spk: [u8; SIGNER_SPK_LEN],
    /// One or more cluster entries; sorted by priority ascending.
    pub entries: Vec<BootstrapEntry>,
    /// Monotonic sequence number; higher wins on refresh.
    pub seq: u64,
    /// Unix seconds; `parse_and_verify` rejects records where `exp < now`.
    pub exp: u64,
}

impl BootstrapRecord {
    /// Validate field invariants. Mutates `self` to canonicalize trailing
    /// dots on `user_domain` and per-entry `cluster_base_domain`, and to
    /// sort entries by priority ascending.
    fn validate(&mut self) -> Result<(), BootstrapError> {
        if self.user_domain.is_empty() {
            return Err(BootstrapError::UserDomainEmpty);
        }
        if self.user_domain.ends_with("..") {
            return Err(BootstrapError::EmptyLabel);
        }
        if self.user_domain.ends_with('.') {
            self.user_domain.pop();
        }
        if self.user_domain.is_empty() {
            return Err(BootstrapError::UserDomainEmpty);
        }
        if self.user_domain.len() > MAX_USER_DOMAIN_LEN {
            return Err(BootstrapError::UserDomainTooLong {
                actual: self.user_domain.len(),
                max: MAX_USER_DOMAIN_LEN,
            });
        }
        validate_dns_name(&self.user_domain).map_err(BootstrapError::from)?;

        if self.entries.is_empty() {
            return Err(BootstrapError::InvalidEntryCount(
                "must contain at least one entry".into(),
            ));
        }
        if self.entries.len() > MAX_ENTRY_COUNT {
            return Err(BootstrapError::InvalidEntryCount(format!(
                "too many entries (max {MAX_ENTRY_COUNT})"
            )));
        }

        // Validate each entry first (canonicalizing trailing dots), then
        // detect duplicates on (priority, casefolded base_domain).
        let mut seen: std::collections::HashSet<(u16, String)> =
            std::collections::HashSet::with_capacity(self.entries.len());
        for entry in &mut self.entries {
            entry.validate()?;
            let key = (
                entry.priority,
                entry.cluster_base_domain.to_ascii_lowercase(),
            );
            if !seen.insert(key) {
                return Err(BootstrapError::DuplicateEntry {
                    priority: entry.priority,
                    base_domain: entry.cluster_base_domain.clone(),
                });
            }
        }

        // Sort entries by priority ascending. Rust's sort_by_key is stable
        // so insertion order on priority ties is preserved (matches Python).
        self.entries.sort_by_key(|e| e.priority);
        Ok(())
    }

    /// Serialize the body. Mutates `self` to canonicalize trailing dots
    /// and sort entries by priority.
    pub fn to_body_bytes(&mut self) -> Result<Vec<u8>, BootstrapError> {
        self.validate()?;
        let name_bytes = self.user_domain.as_bytes();
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.exp.to_be_bytes());
        out.extend_from_slice(&self.signer_spk);
        // Length-checked in validate() against MAX_USER_DOMAIN_LEN (64); cast cannot truncate.
        out.push(u8::try_from(name_bytes.len()).expect("user_domain length fits in u8"));
        out.extend_from_slice(name_bytes);
        // Length-checked in validate() against MAX_ENTRY_COUNT (16); cast cannot truncate.
        out.push(u8::try_from(self.entries.len()).expect("entry count fits in u8"));
        for entry in &mut self.entries {
            out.extend_from_slice(&entry.to_body_bytes()?);
        }
        Ok(out)
    }

    /// Parse a body buffer (no signature trailer) into a [`BootstrapRecord`].
    pub fn from_body_bytes(body: &[u8]) -> Result<Self, BootstrapError> {
        let min_header = MAGIC.len() + 8 + 8 + SIGNER_SPK_LEN + 1;
        if body.len() < min_header {
            return Err(BootstrapError::MalformedBody("body too short for header"));
        }
        let mut off = 0;
        if &body[off..off + MAGIC.len()] != MAGIC.as_slice() {
            return Err(BootstrapError::MalformedBody("bad magic"));
        }
        off += MAGIC.len();
        let seq = u64::from_be_bytes(body[off..off + 8].try_into().expect("8 bytes"));
        off += 8;
        let exp = u64::from_be_bytes(body[off..off + 8].try_into().expect("8 bytes"));
        off += 8;
        let mut signer_spk = [0u8; SIGNER_SPK_LEN];
        signer_spk.copy_from_slice(&body[off..off + SIGNER_SPK_LEN]);
        off += SIGNER_SPK_LEN;
        let name_len = body[off] as usize;
        off += 1;
        if off + name_len > body.len() {
            return Err(BootstrapError::MalformedBody("truncated user_domain"));
        }
        let has_trailing_dot = name_len > 0 && body[off + name_len - 1] == b'.';
        let effective_len = name_len - usize::from(has_trailing_dot);
        if effective_len == 0 || effective_len > MAX_USER_DOMAIN_LEN {
            return Err(BootstrapError::UserDomainTooLong {
                actual: effective_len,
                max: MAX_USER_DOMAIN_LEN,
            });
        }
        let mut user_domain = std::str::from_utf8(&body[off..off + name_len])
            .map_err(|_| BootstrapError::MalformedBody("user_domain not utf-8"))?
            .to_string();
        validate_dns_name(&user_domain).map_err(BootstrapError::from)?;
        if user_domain.ends_with('.') {
            user_domain.pop();
        }
        off += name_len;

        if off + 1 > body.len() {
            return Err(BootstrapError::MalformedBody(
                "truncated: missing entry_count",
            ));
        }
        let entry_count = body[off] as usize;
        off += 1;
        if entry_count == 0 {
            return Err(BootstrapError::InvalidEntryCount(
                "must contain at least one entry".into(),
            ));
        }
        if entry_count > MAX_ENTRY_COUNT {
            return Err(BootstrapError::InvalidEntryCount(
                "entry_count exceeds protocol max".into(),
            ));
        }

        let mut entries: Vec<BootstrapEntry> = Vec::with_capacity(entry_count);
        let mut seen: std::collections::HashSet<(u16, String)> =
            std::collections::HashSet::with_capacity(entry_count);
        for _ in 0..entry_count {
            let (entry, new_off) = BootstrapEntry::from_body_bytes(body, off)?;
            off = new_off;
            let key = (
                entry.priority,
                entry.cluster_base_domain.to_ascii_lowercase(),
            );
            if !seen.insert(key) {
                return Err(BootstrapError::DuplicateEntry {
                    priority: entry.priority,
                    base_domain: entry.cluster_base_domain,
                });
            }
            entries.push(entry);
        }

        if off != body.len() {
            return Err(BootstrapError::MalformedBody(
                "trailing bytes after last entry",
            ));
        }

        // Sort on parse so a correctly-signed but mis-ordered record
        // still yields a deterministic best_entry().
        entries.sort_by_key(|e| e.priority);

        Ok(Self {
            user_domain,
            signer_spk,
            entries,
            seq,
            exp,
        })
    }

    /// Sign the record and emit the wire-format TXT record string.
    ///
    /// Mutates `self` to canonicalize trailing dots and sort entries.
    pub fn sign(&mut self, crypto: &DmpCrypto) -> Result<String, BootstrapError> {
        if crypto.signing_public_key_bytes() != self.signer_spk {
            return Err(BootstrapError::SigningKeyMismatch);
        }
        let body = self.to_body_bytes()?;
        let signature = crypto.sign_data(&body);
        let mut wire = Vec::with_capacity(body.len() + SIG_LEN);
        wire.extend_from_slice(&body);
        wire.extend_from_slice(&signature);
        let encoded = format!("{RECORD_PREFIX}{}", BASE64_STANDARD.encode(&wire));
        if encoded.len() > MAX_WIRE_LEN {
            return Err(BootstrapError::WireTooLong {
                actual: encoded.len(),
                max: MAX_WIRE_LEN,
            });
        }
        Ok(encoded)
    }

    /// Parse and verify a TXT record. Returns `Some(record)` on success
    /// or `None` on any failure (missing prefix, bad base64, signature
    /// mismatch, oversized wire, expired, pinned-key mismatch, or
    /// `expected_user_domain` mismatch).
    ///
    /// `signer_spk_pinned`: when `Some`, the signature is verified
    /// against this key and the body's embedded `signer_spk` must match
    /// it byte-for-byte. When `None`, the embedded `signer_spk` is used
    /// as the verifier (TOFU); callers expecting Python parity should
    /// always pass `Some`.
    ///
    /// `expected_user_domain`: when `Some`, the parsed `user_domain` must
    /// match the supplied name (case-insensitive, single trailing dot
    /// stripped) or the record is rejected. Lets a caller bind a record
    /// to the DNS owner name they queried, defeating cross-domain replay
    /// where a record signed for domain A is republished under domain B.
    ///
    /// `now`: when `Some`, used for expiry comparison; when `None`, the
    /// current Unix time is consulted.
    #[must_use]
    pub fn parse_and_verify(
        wire: &str,
        signer_spk_pinned: Option<&[u8]>,
        expected_user_domain: Option<&str>,
        now: Option<u64>,
    ) -> Option<Self> {
        if !wire.starts_with(RECORD_PREFIX) {
            return None;
        }
        if wire.len() > MAX_WIRE_LEN {
            return None;
        }
        let payload = wire.strip_prefix(RECORD_PREFIX)?;
        let blob = BASE64_STANDARD.decode(payload).ok()?;
        if blob.len() < SIG_LEN + MAGIC.len() {
            return None;
        }
        let split = blob.len() - SIG_LEN;
        let body = &blob[..split];
        let signature = &blob[split..];

        if let Some(pinned) = signer_spk_pinned {
            if pinned.len() != SIGNER_SPK_LEN {
                return None;
            }
            if !DmpCrypto::verify_signature(body, signature, pinned) {
                return None;
            }
        }

        let record = Self::from_body_bytes(body).ok()?;

        if let Some(pinned) = signer_spk_pinned {
            if record.signer_spk.as_slice() != pinned {
                return None;
            }
        } else if !DmpCrypto::verify_signature(body, signature, &record.signer_spk) {
            return None;
        }

        let now_ts = now.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
        });
        if record.exp < now_ts {
            return None;
        }

        if let Some(expected) = expected_user_domain {
            let parsed_norm = record
                .user_domain
                .strip_suffix('.')
                .unwrap_or(&record.user_domain)
                .to_ascii_lowercase();
            let expected_norm = expected
                .strip_suffix('.')
                .unwrap_or(expected)
                .to_ascii_lowercase();
            if parsed_norm != expected_norm {
                return None;
            }
        }

        Some(record)
    }

    /// Return the lowest-priority (most preferred) entry.
    ///
    /// Entries are sorted by priority at sign/parse time so this is
    /// always `entries[0]`. On priority ties the sort is stable and
    /// returns the earliest-inserted entry.
    #[must_use]
    pub fn best_entry(&self) -> &BootstrapEntry {
        &self.entries[0]
    }

    /// Returns true iff `now > self.exp`.
    #[must_use]
    pub fn is_expired(&self, now: Option<u64>) -> bool {
        let now_ts = now.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
        });
        now_ts > self.exp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNER_SEED_HEX: &str =
        "e04dce4d5bab48891ee2b5d1ac6ef71089d5038d91d9ac9e6d9887c7e4103130";
    const SIGNER_SPK_HEX: &str = "e573c9bb2a9930e5375eb2d759b3a0732d5c5a45fe5d7182ad7353021f6b8e22";
    const OPERATOR_SPK_HEX: &str =
        "edd3bed94b75ba0d49a17f97da145ac51fdd0f208e8351f655e782e1ac3b9065";

    fn signer() -> DmpCrypto {
        let seed = hex::decode(SIGNER_SEED_HEX).unwrap();
        DmpCrypto::from_private_bytes(&seed).unwrap()
    }

    fn signer_spk() -> [u8; SIGNER_SPK_LEN] {
        let raw = hex::decode(SIGNER_SPK_HEX).unwrap();
        let mut spk = [0u8; SIGNER_SPK_LEN];
        spk.copy_from_slice(&raw);
        spk
    }

    fn operator_spk() -> [u8; OPERATOR_SPK_LEN] {
        let raw = hex::decode(OPERATOR_SPK_HEX).unwrap();
        let mut spk = [0u8; OPERATOR_SPK_LEN];
        spk.copy_from_slice(&raw);
        spk
    }

    fn sample_record() -> BootstrapRecord {
        BootstrapRecord {
            user_domain: "example.com".to_string(),
            signer_spk: signer_spk(),
            entries: vec![BootstrapEntry {
                priority: 10,
                cluster_base_domain: "mesh.example.com".to_string(),
                operator_spk: operator_spk(),
            }],
            seq: 1,
            exp: 2_051_222_400,
        }
    }

    #[test]
    fn body_round_trip() {
        let mut record = sample_record();
        let body = record.to_body_bytes().unwrap();
        let parsed = BootstrapRecord::from_body_bytes(&body).unwrap();
        assert_eq!(parsed, record);
    }

    #[test]
    fn sign_and_parse_round_trip() {
        let crypto = signer();
        let mut record = sample_record();
        let wire = record.sign(&crypto).unwrap();
        let parsed =
            BootstrapRecord::parse_and_verify(&wire, Some(&signer_spk()), None, Some(record.exp))
                .expect("verify must succeed");
        assert_eq!(parsed, record);
    }

    #[test]
    fn bootstrap_rrset_name_format() {
        assert_eq!(
            bootstrap_rrset_name("example.com").unwrap(),
            "_dmp.example.com"
        );
        assert_eq!(
            bootstrap_rrset_name("example.com.").unwrap(),
            "_dmp.example.com"
        );
    }

    #[test]
    fn bootstrap_rrset_name_rejects_bad_input() {
        assert!(bootstrap_rrset_name("").is_err());
        assert!(bootstrap_rrset_name("example.com..").is_err());
        assert!(bootstrap_rrset_name("-example.com").is_err());
    }

    #[test]
    fn empty_entry_list_rejected() {
        let mut record = sample_record();
        record.entries.clear();
        assert!(matches!(
            record.to_body_bytes(),
            Err(BootstrapError::InvalidEntryCount(_)),
        ));
    }

    #[test]
    fn over_max_entries_rejected() {
        let mut record = sample_record();
        record.entries = (0..=MAX_ENTRY_COUNT)
            .map(|i| BootstrapEntry {
                priority: u16::try_from(i).unwrap(),
                cluster_base_domain: format!("c{i}.example.com"),
                operator_spk: operator_spk(),
            })
            .collect();
        assert!(matches!(
            record.to_body_bytes(),
            Err(BootstrapError::InvalidEntryCount(_)),
        ));
    }

    #[test]
    fn duplicate_entries_rejected() {
        let mut record = sample_record();
        record.entries = vec![
            BootstrapEntry {
                priority: 10,
                cluster_base_domain: "mesh.example.com".to_string(),
                operator_spk: operator_spk(),
            },
            BootstrapEntry {
                priority: 10,
                cluster_base_domain: "MESH.example.com".to_string(),
                operator_spk: operator_spk(),
            },
        ];
        assert!(matches!(
            record.to_body_bytes(),
            Err(BootstrapError::DuplicateEntry { .. }),
        ));
    }

    #[test]
    fn entries_sorted_by_priority_on_sign() {
        let mut record = sample_record();
        record.entries = vec![
            BootstrapEntry {
                priority: 30,
                cluster_base_domain: "c30.example.com".to_string(),
                operator_spk: operator_spk(),
            },
            BootstrapEntry {
                priority: 10,
                cluster_base_domain: "c10.example.com".to_string(),
                operator_spk: operator_spk(),
            },
            BootstrapEntry {
                priority: 20,
                cluster_base_domain: "c20.example.com".to_string(),
                operator_spk: operator_spk(),
            },
        ];
        let _ = record.to_body_bytes().unwrap();
        assert_eq!(
            record
                .entries
                .iter()
                .map(|e| e.priority)
                .collect::<Vec<_>>(),
            vec![10, 20, 30],
        );
        assert_eq!(record.best_entry().priority, 10);
    }

    #[test]
    fn parse_and_verify_rejects_missing_prefix() {
        let mut record = sample_record();
        let crypto = signer();
        let wire = record.sign(&crypto).unwrap();
        let stripped = wire.strip_prefix(RECORD_PREFIX).unwrap();
        assert!(BootstrapRecord::parse_and_verify(
            stripped,
            Some(&signer_spk()),
            None,
            Some(record.exp)
        )
        .is_none());
    }

    #[test]
    fn parse_and_verify_rejects_bad_base64() {
        let bogus = format!("{RECORD_PREFIX}!!!not-base64!!!");
        assert!(
            BootstrapRecord::parse_and_verify(&bogus, Some(&signer_spk()), None, Some(0)).is_none()
        );
    }

    #[test]
    fn parse_and_verify_rejects_flipped_signature() {
        let mut record = sample_record();
        let crypto = signer();
        let wire = record.sign(&crypto).unwrap();
        let payload = wire.strip_prefix(RECORD_PREFIX).unwrap();
        let mut bytes = BASE64_STANDARD.decode(payload).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = format!("{RECORD_PREFIX}{}", BASE64_STANDARD.encode(&bytes));
        assert!(BootstrapRecord::parse_and_verify(
            &tampered,
            Some(&signer_spk()),
            None,
            Some(record.exp)
        )
        .is_none());
    }

    #[test]
    fn parse_and_verify_rejects_expired() {
        let mut record = sample_record();
        record.exp = 100;
        let crypto = signer();
        let wire = record.sign(&crypto).unwrap();
        assert!(
            BootstrapRecord::parse_and_verify(&wire, Some(&signer_spk()), None, Some(101))
                .is_none()
        );
        assert!(
            BootstrapRecord::parse_and_verify(&wire, Some(&signer_spk()), None, Some(100))
                .is_some()
        );
    }

    #[test]
    fn parse_and_verify_rejects_wrong_pinned_key() {
        let mut record = sample_record();
        let crypto = signer();
        let wire = record.sign(&crypto).unwrap();
        let wrong = [0xAAu8; SIGNER_SPK_LEN];
        assert!(
            BootstrapRecord::parse_and_verify(&wire, Some(&wrong), None, Some(record.exp))
                .is_none()
        );
    }

    #[test]
    fn parse_and_verify_rejects_wrong_expected_user_domain() {
        let mut record = sample_record();
        let crypto = signer();
        let wire = record.sign(&crypto).unwrap();
        // Same wire, but binding to a different user domain — cross-domain replay must be refused.
        assert!(BootstrapRecord::parse_and_verify(
            &wire,
            Some(&signer_spk()),
            Some("not-the-signed-domain.example.com"),
            Some(record.exp)
        )
        .is_none());
    }

    #[test]
    fn parse_and_verify_normalizes_expected_user_domain() {
        let mut record = sample_record();
        let crypto = signer();
        let wire = record.sign(&crypto).unwrap();
        let expected = format!("{}.", record.user_domain.to_ascii_uppercase());
        assert!(BootstrapRecord::parse_and_verify(
            &wire,
            Some(&signer_spk()),
            Some(&expected),
            Some(record.exp)
        )
        .is_some());
    }

    #[test]
    fn sign_rejects_mismatched_signing_key() {
        let mut record = sample_record();
        record.signer_spk = [0u8; SIGNER_SPK_LEN];
        let crypto = signer();
        assert!(matches!(
            record.sign(&crypto),
            Err(BootstrapError::SigningKeyMismatch),
        ));
    }

    #[test]
    fn from_body_bytes_rejects_bad_magic() {
        let mut record = sample_record();
        let mut body = record.to_body_bytes().unwrap();
        body[0] = b'X';
        assert!(matches!(
            BootstrapRecord::from_body_bytes(&body),
            Err(BootstrapError::MalformedBody(_)),
        ));
    }

    #[test]
    fn from_body_bytes_rejects_zero_entry_count() {
        let mut record = sample_record();
        let mut body = record.to_body_bytes().unwrap();
        // entry_count is the last byte before the first entry; we know
        // exactly where it sits because we control the inputs.
        let header = MAGIC.len() + 8 + 8 + SIGNER_SPK_LEN + 1 + record.user_domain.len() + 1;
        // entry_count is at header - 1.
        body[header - 1] = 0;
        assert!(matches!(
            BootstrapRecord::from_body_bytes(&body),
            Err(BootstrapError::InvalidEntryCount(_)),
        ));
    }

    #[test]
    fn from_body_bytes_rejects_trailing_bytes() {
        let mut record = sample_record();
        let mut body = record.to_body_bytes().unwrap();
        body.push(0);
        assert!(matches!(
            BootstrapRecord::from_body_bytes(&body),
            Err(BootstrapError::MalformedBody(_)),
        ));
    }

    #[test]
    fn user_domain_with_trailing_dot_is_normalized() {
        let mut record = sample_record();
        record.user_domain = "example.com.".to_string();
        let body = record.to_body_bytes().unwrap();
        assert_eq!(record.user_domain, "example.com");
        let parsed = BootstrapRecord::from_body_bytes(&body).unwrap();
        assert_eq!(parsed.user_domain, "example.com");
    }

    #[test]
    fn double_trailing_dot_rejected() {
        let mut record = sample_record();
        record.user_domain = "example.com..".to_string();
        assert!(matches!(
            record.to_body_bytes(),
            Err(BootstrapError::EmptyLabel),
        ));
    }
}

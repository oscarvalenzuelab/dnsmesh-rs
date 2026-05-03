//! Signed cluster manifests for DMP node federation.
//!
//! A *cluster* is a set of DMP nodes run by one or more operators that
//! collectively serve the same mailbox data. A signed `ClusterManifest`,
//! published as a TXT record at `cluster.<cluster_name>`, lists the
//! operator-trusted node set. Clients pin the cluster-operator Ed25519
//! public key and re-fetch the manifest to learn the current node set.
//!
//! Wire format (binary, base64'd, prefixed with `v=dmp1;t=cluster;`):
//!
//! ```text
//! body:
//!     magic            (7) = b"DMPCL01"
//!     seq              (8 BE)
//!     exp              (8 BE)
//!     operator_spk    (32)
//!     cluster_name_len (1)
//!     cluster_name    (utf-8, <= 64 bytes)
//!     node_count       (1)
//!     per node:
//!         node_id_len      (1)
//!         node_id          (ascii, <= 16 bytes)
//!         http_endpoint_len(2 BE)
//!         http_endpoint    (utf-8, <= 128 bytes)
//!         dns_endpoint_len (2 BE; 0 == absent)
//!         dns_endpoint     (utf-8, <= 64 bytes)
//! sig: Ed25519 signature over body (64 bytes)
//! ```
//!
//! Note: the magic bytes `DMPCL01` are shared with `claim.rs` in the Python
//! reference, but the two record types are disambiguated by their TXT
//! `RECORD_PREFIX`. Within this module the magic is only meaningful after
//! the prefix has already been stripped.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;

use crate::crypto::{DmpCrypto, ED25519_KEY_LEN, ED25519_SIG_LEN};

/// TXT prefix that tags a DMP cluster manifest record.
pub const RECORD_PREFIX: &str = "v=dmp1;t=cluster;";

/// Magic bytes at the start of a cluster manifest body.
pub const MAGIC: &[u8; 7] = b"DMPCL01";

/// Length of the trailing Ed25519 signature in bytes.
pub const SIG_LEN: usize = ED25519_SIG_LEN;

/// Length of the operator Ed25519 signing public key in bytes.
pub const OPERATOR_SPK_LEN: usize = ED25519_KEY_LEN;

/// Maximum `node_id` length in ASCII bytes.
pub const MAX_NODE_ID_LEN: usize = 16;

/// Maximum `http_endpoint` length in UTF-8 bytes.
pub const MAX_HTTP_ENDPOINT_LEN: usize = 128;

/// Maximum `dns_endpoint` length in UTF-8 bytes.
pub const MAX_DNS_ENDPOINT_LEN: usize = 64;

/// Maximum `cluster_name` length in UTF-8 bytes (not counting a single
/// canonical-FQDN trailing dot, which is permitted on the wire and
/// stripped on parse).
pub const MAX_CLUSTER_NAME_LEN: usize = 64;

/// Protocol-level ceiling on the number of nodes per manifest. The
/// 1200-byte wire cap may bind earlier in practice.
pub const MAX_NODE_COUNT: usize = 32;

/// Per-label DNS cap (RFC 1035: labels max out at 63 octets).
pub const MAX_DNS_LABEL_LEN: usize = 63;

/// Absolute wire-length cap, enforced at sign() and parse_and_verify time.
pub const MAX_WIRE_LEN: usize = 1200;

/// Errors returned while building or parsing cluster manifests.
#[derive(Debug, thiserror::Error)]
pub enum ClusterError {
    /// `cluster_name` was empty after canonicalization.
    #[error("cluster_name must be a non-empty string")]
    ClusterNameEmpty,
    /// `cluster_name` had a doubled trailing dot or empty interior label.
    #[error("cluster_name has empty label (leading/double/interior dot not allowed)")]
    EmptyLabel,
    /// `cluster_name` exceeded the byte cap.
    #[error("cluster_name too long (max {max} utf-8 bytes, got {actual})")]
    ClusterNameTooLong { actual: usize, max: usize },
    /// A label in `cluster_name` exceeded the per-label DNS cap or had
    /// an invalid character.
    #[error("cluster_name label invalid: {0}")]
    InvalidLabel(String),
    /// A 32-byte key was expected but a different number of bytes was supplied.
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    /// `node_id` was empty, non-ASCII, or too long.
    #[error("invalid node_id: {0}")]
    InvalidNodeId(String),
    /// `http_endpoint` was empty or too long.
    #[error("invalid http_endpoint: {0}")]
    InvalidHttpEndpoint(String),
    /// `dns_endpoint` was supplied but empty or too long.
    #[error("invalid dns_endpoint: {0}")]
    InvalidDnsEndpoint(String),
    /// Empty node list, or count above [`MAX_NODE_COUNT`].
    #[error("invalid node_count: {0}")]
    InvalidNodeCount(String),
    /// Two nodes carried the same `node_id`.
    #[error("duplicate node_id {0:?} in cluster manifest")]
    DuplicateNodeId(String),
    /// The body buffer was truncated or had trailing bytes.
    #[error("malformed body: {0}")]
    MalformedBody(&'static str),
    /// The signing key did not match the declared `operator_spk`.
    #[error("signing key does not match declared operator_spk")]
    SigningKeyMismatch,
    /// The wire string exceeded [`MAX_WIRE_LEN`].
    #[error("wire size {actual} exceeds MAX_WIRE_LEN {max}")]
    WireTooLong { actual: usize, max: usize },
}

/// Validate that `name` is a publishable DNS owner name.
///
/// Rules: non-empty after stripping a single trailing `.`, ASCII only,
/// each label 1..=63 chars, letters/digits/`-` only, no leading or
/// trailing `-`, no empty (interior) labels.
///
/// Re-used by `bootstrap.rs` to keep the two record types in lockstep —
/// a name that validates for one must validate for the other.
pub(crate) fn validate_dns_name(name: &str) -> Result<(), ClusterError> {
    if name.is_empty() {
        return Err(ClusterError::ClusterNameEmpty);
    }
    // Doubled trailing dot signals an empty final label; reject rather
    // than silently collapsing.
    if name.ends_with("..") {
        return Err(ClusterError::EmptyLabel);
    }
    let normalized = name.strip_suffix('.').unwrap_or(name);
    if normalized.is_empty() {
        return Err(ClusterError::ClusterNameEmpty);
    }
    if !normalized.is_ascii() {
        return Err(ClusterError::InvalidLabel(format!(
            "{name:?} must be ASCII (no IDN support)"
        )));
    }
    for label in normalized.split('.') {
        if label.is_empty() {
            return Err(ClusterError::EmptyLabel);
        }
        if label.len() > MAX_DNS_LABEL_LEN {
            return Err(ClusterError::InvalidLabel(format!(
                "{label:?} exceeds {MAX_DNS_LABEL_LEN} chars"
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ClusterError::InvalidLabel(format!(
                "{label:?} cannot start or end with '-'"
            )));
        }
        for ch in label.chars() {
            if !(ch.is_ascii_alphanumeric() || ch == '-') {
                return Err(ClusterError::InvalidLabel(format!(
                    "{label:?} contains invalid character {ch:?} (letters/digits/'-' only)"
                )));
            }
        }
    }
    Ok(())
}

/// Return the TXT RRset name where this cluster's manifest lives.
///
/// Convention: `cluster.<cluster_name>`. Applies the same DNS-name
/// validation `ClusterManifest` enforces so direct callers get the same
/// early rejection.
pub fn cluster_rrset_name(cluster_name: &str) -> Result<String, ClusterError> {
    validate_dns_name(cluster_name)?;
    let normalized = cluster_name.strip_suffix('.').unwrap_or(cluster_name);
    Ok(format!("cluster.{normalized}"))
}

/// One node entry in a cluster manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterNode {
    /// Stable human-readable node id (used for logs and dedupe).
    pub node_id: String,
    /// HTTP ingress for writes and direct API calls.
    pub http_endpoint: String,
    /// Optional DNS ingress; `None` means the client should query
    /// upstream DNS for reads instead.
    pub dns_endpoint: Option<String>,
}

impl ClusterNode {
    fn validate(&self) -> Result<(), ClusterError> {
        if self.node_id.is_empty() {
            return Err(ClusterError::InvalidNodeId(
                "must be a non-empty string".into(),
            ));
        }
        if !self.node_id.is_ascii() {
            return Err(ClusterError::InvalidNodeId("must be ASCII".into()));
        }
        if self.node_id.len() > MAX_NODE_ID_LEN {
            return Err(ClusterError::InvalidNodeId(format!(
                "too long (max {MAX_NODE_ID_LEN} ascii bytes)"
            )));
        }
        if self.http_endpoint.is_empty() {
            return Err(ClusterError::InvalidHttpEndpoint(
                "must be a non-empty string".into(),
            ));
        }
        if self.http_endpoint.len() > MAX_HTTP_ENDPOINT_LEN {
            return Err(ClusterError::InvalidHttpEndpoint(format!(
                "too long (max {MAX_HTTP_ENDPOINT_LEN} utf-8 bytes)"
            )));
        }
        if let Some(dns) = &self.dns_endpoint {
            if dns.is_empty() {
                return Err(ClusterError::InvalidDnsEndpoint(
                    "must be a non-empty string when provided".into(),
                ));
            }
            if dns.len() > MAX_DNS_ENDPOINT_LEN {
                return Err(ClusterError::InvalidDnsEndpoint(format!(
                    "too long (max {MAX_DNS_ENDPOINT_LEN} utf-8 bytes)"
                )));
            }
        }
        Ok(())
    }

    /// Serialize one node entry to its on-the-wire body bytes.
    pub fn to_body_bytes(&self) -> Result<Vec<u8>, ClusterError> {
        self.validate()?;
        let id_bytes = self.node_id.as_bytes();
        let http_bytes = self.http_endpoint.as_bytes();
        let dns_bytes: &[u8] = self.dns_endpoint.as_deref().map_or(&[], str::as_bytes);
        let mut out =
            Vec::with_capacity(1 + id_bytes.len() + 2 + http_bytes.len() + 2 + dns_bytes.len());
        // Length-checked above against MAX_NODE_ID_LEN (16); cast cannot truncate.
        out.push(u8::try_from(id_bytes.len()).expect("node_id length fits in u8"));
        out.extend_from_slice(id_bytes);
        // Length-checked above against MAX_HTTP_ENDPOINT_LEN (128); cast cannot truncate.
        let http_len = u16::try_from(http_bytes.len()).expect("http_endpoint length fits in u16");
        out.extend_from_slice(&http_len.to_be_bytes());
        out.extend_from_slice(http_bytes);
        // Length-checked above against MAX_DNS_ENDPOINT_LEN (64); cast cannot truncate.
        let dns_len = u16::try_from(dns_bytes.len()).expect("dns_endpoint length fits in u16");
        out.extend_from_slice(&dns_len.to_be_bytes());
        out.extend_from_slice(dns_bytes);
        Ok(out)
    }

    /// Parse one node entry starting at `offset`; returns the node and
    /// the new offset on success.
    pub fn from_body_bytes(body: &[u8], offset: usize) -> Result<(Self, usize), ClusterError> {
        let mut off = offset;
        if off + 1 > body.len() {
            return Err(ClusterError::MalformedBody(
                "truncated node: missing node_id length",
            ));
        }
        let id_len = body[off] as usize;
        off += 1;
        if id_len == 0 || id_len > MAX_NODE_ID_LEN {
            return Err(ClusterError::InvalidNodeId("invalid length".into()));
        }
        if off + id_len > body.len() {
            return Err(ClusterError::MalformedBody("truncated node: node_id"));
        }
        let id_slice = &body[off..off + id_len];
        if !id_slice.is_ascii() {
            return Err(ClusterError::InvalidNodeId("not ASCII".into()));
        }
        let node_id = std::str::from_utf8(id_slice)
            .map_err(|_| ClusterError::InvalidNodeId("not ASCII".into()))?
            .to_string();
        off += id_len;

        if off + 2 > body.len() {
            return Err(ClusterError::MalformedBody(
                "truncated node: missing http_endpoint length",
            ));
        }
        let http_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
        off += 2;
        if http_len == 0 || http_len > MAX_HTTP_ENDPOINT_LEN {
            return Err(ClusterError::InvalidHttpEndpoint("invalid length".into()));
        }
        if off + http_len > body.len() {
            return Err(ClusterError::MalformedBody("truncated node: http_endpoint"));
        }
        let http_endpoint = std::str::from_utf8(&body[off..off + http_len])
            .map_err(|_| ClusterError::InvalidHttpEndpoint("not utf-8".into()))?
            .to_string();
        off += http_len;

        if off + 2 > body.len() {
            return Err(ClusterError::MalformedBody(
                "truncated node: missing dns_endpoint length",
            ));
        }
        let dns_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
        off += 2;
        if dns_len > MAX_DNS_ENDPOINT_LEN {
            return Err(ClusterError::InvalidDnsEndpoint("invalid length".into()));
        }
        let dns_endpoint = if dns_len > 0 {
            if off + dns_len > body.len() {
                return Err(ClusterError::MalformedBody("truncated node: dns_endpoint"));
            }
            let s = std::str::from_utf8(&body[off..off + dns_len])
                .map_err(|_| ClusterError::InvalidDnsEndpoint("not utf-8".into()))?
                .to_string();
            off += dns_len;
            Some(s)
        } else {
            None
        };

        Ok((
            Self {
                node_id,
                http_endpoint,
                dns_endpoint,
            },
            off,
        ))
    }
}

/// Signed list of nodes that make up a DMP cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterManifest {
    /// DNS name (e.g. `mesh.example.com`) under which the manifest is
    /// published as `cluster.<cluster_name>` TXT.
    pub cluster_name: String,
    /// 32-byte Ed25519 signing public key of the cluster operator.
    pub operator_spk: [u8; OPERATOR_SPK_LEN],
    /// One or more cluster nodes; capped at [`MAX_NODE_COUNT`].
    pub nodes: Vec<ClusterNode>,
    /// Monotonic sequence number; higher wins on refresh.
    pub seq: u64,
    /// Unix seconds; `parse_and_verify` rejects manifests where `exp < now`.
    pub exp: u64,
}

impl ClusterManifest {
    /// Validate field invariants, mutating `self` only to canonicalize a
    /// single trailing dot on `cluster_name`.
    fn validate(&mut self) -> Result<(), ClusterError> {
        if self.cluster_name.is_empty() {
            return Err(ClusterError::ClusterNameEmpty);
        }
        if self.cluster_name.ends_with("..") {
            return Err(ClusterError::EmptyLabel);
        }
        if self.cluster_name.ends_with('.') {
            self.cluster_name.pop();
        }
        if self.cluster_name.is_empty() {
            return Err(ClusterError::ClusterNameEmpty);
        }
        let name_bytes = self.cluster_name.as_bytes();
        if name_bytes.len() > MAX_CLUSTER_NAME_LEN {
            return Err(ClusterError::ClusterNameTooLong {
                actual: name_bytes.len(),
                max: MAX_CLUSTER_NAME_LEN,
            });
        }
        validate_dns_name(&self.cluster_name)?;

        if self.nodes.is_empty() {
            return Err(ClusterError::InvalidNodeCount(
                "must contain at least one node".into(),
            ));
        }
        if self.nodes.len() > MAX_NODE_COUNT {
            return Err(ClusterError::InvalidNodeCount(format!(
                "too many nodes (max {MAX_NODE_COUNT})"
            )));
        }
        let mut seen: std::collections::HashSet<&str> =
            std::collections::HashSet::with_capacity(self.nodes.len());
        for node in &self.nodes {
            node.validate()?;
            if !seen.insert(node.node_id.as_str()) {
                return Err(ClusterError::DuplicateNodeId(node.node_id.clone()));
            }
        }
        Ok(())
    }

    /// Serialize the body. Mutates `self` to strip a single canonical
    /// FQDN trailing dot from `cluster_name`, matching the Python
    /// reference's normalization behavior.
    pub fn to_body_bytes(&mut self) -> Result<Vec<u8>, ClusterError> {
        self.validate()?;
        let name_bytes = self.cluster_name.as_bytes();
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.exp.to_be_bytes());
        out.extend_from_slice(&self.operator_spk);
        // Length-checked in validate() against MAX_CLUSTER_NAME_LEN (64); cast cannot truncate.
        out.push(u8::try_from(name_bytes.len()).expect("cluster_name length fits in u8"));
        out.extend_from_slice(name_bytes);
        // Length-checked in validate() against MAX_NODE_COUNT (32); cast cannot truncate.
        out.push(u8::try_from(self.nodes.len()).expect("node count fits in u8"));
        for node in &self.nodes {
            out.extend_from_slice(&node.to_body_bytes()?);
        }
        Ok(out)
    }

    /// Parse a body buffer (no signature trailer) into a [`ClusterManifest`].
    pub fn from_body_bytes(body: &[u8]) -> Result<Self, ClusterError> {
        let min_header = MAGIC.len() + 8 + 8 + OPERATOR_SPK_LEN + 1;
        if body.len() < min_header {
            return Err(ClusterError::MalformedBody("body too short for header"));
        }
        let mut off = 0;
        if &body[off..off + MAGIC.len()] != MAGIC.as_slice() {
            return Err(ClusterError::MalformedBody("bad magic"));
        }
        off += MAGIC.len();
        let seq = u64::from_be_bytes(body[off..off + 8].try_into().expect("8 bytes"));
        off += 8;
        let exp = u64::from_be_bytes(body[off..off + 8].try_into().expect("8 bytes"));
        off += 8;
        let mut operator_spk = [0u8; OPERATOR_SPK_LEN];
        operator_spk.copy_from_slice(&body[off..off + OPERATOR_SPK_LEN]);
        off += OPERATOR_SPK_LEN;
        let name_len = body[off] as usize;
        off += 1;
        if off + name_len > body.len() {
            return Err(ClusterError::MalformedBody("truncated cluster_name"));
        }
        // Allow MAX+1 on the wire when the last byte is a canonical-FQDN dot.
        let has_trailing_dot = name_len > 0 && body[off + name_len - 1] == b'.';
        let effective_len = name_len - usize::from(has_trailing_dot);
        if effective_len == 0 || effective_len > MAX_CLUSTER_NAME_LEN {
            return Err(ClusterError::ClusterNameTooLong {
                actual: effective_len,
                max: MAX_CLUSTER_NAME_LEN,
            });
        }
        let mut cluster_name = std::str::from_utf8(&body[off..off + name_len])
            .map_err(|_| ClusterError::MalformedBody("cluster_name not utf-8"))?
            .to_string();
        validate_dns_name(&cluster_name)?;
        if cluster_name.ends_with('.') {
            cluster_name.pop();
        }
        off += name_len;

        if off + 1 > body.len() {
            return Err(ClusterError::MalformedBody("truncated: missing node_count"));
        }
        let node_count = body[off] as usize;
        off += 1;
        if node_count > MAX_NODE_COUNT {
            return Err(ClusterError::InvalidNodeCount(
                "node_count exceeds protocol max".into(),
            ));
        }

        let mut nodes = Vec::with_capacity(node_count);
        let mut seen: std::collections::HashSet<String> =
            std::collections::HashSet::with_capacity(node_count);
        for _ in 0..node_count {
            let (node, new_off) = ClusterNode::from_body_bytes(body, off)?;
            off = new_off;
            if !seen.insert(node.node_id.clone()) {
                return Err(ClusterError::DuplicateNodeId(node.node_id));
            }
            nodes.push(node);
        }

        if off != body.len() {
            return Err(ClusterError::MalformedBody(
                "trailing bytes after last node",
            ));
        }

        Ok(Self {
            cluster_name,
            operator_spk,
            nodes,
            seq,
            exp,
        })
    }

    /// Sign the manifest and emit the wire-format TXT record string.
    ///
    /// Mutates `self` to canonicalize the trailing dot on `cluster_name`.
    pub fn sign(&mut self, operator_crypto: &DmpCrypto) -> Result<String, ClusterError> {
        if operator_crypto.signing_public_key_bytes() != self.operator_spk {
            return Err(ClusterError::SigningKeyMismatch);
        }
        let body = self.to_body_bytes()?;
        let signature = operator_crypto.sign_data(&body);
        let mut wire = Vec::with_capacity(body.len() + SIG_LEN);
        wire.extend_from_slice(&body);
        wire.extend_from_slice(&signature);
        let encoded = format!("{RECORD_PREFIX}{}", BASE64_STANDARD.encode(&wire));
        if encoded.len() > MAX_WIRE_LEN {
            return Err(ClusterError::WireTooLong {
                actual: encoded.len(),
                max: MAX_WIRE_LEN,
            });
        }
        Ok(encoded)
    }

    /// Parse and verify a TXT record. Returns `Some(manifest)` on success
    /// or `None` on any failure (missing prefix, bad base64, signature
    /// mismatch, oversized wire, expired, pinned-key mismatch, or
    /// `expected_cluster_name` mismatch).
    ///
    /// `operator_spk_pinned`: when `Some`, the signature is verified
    /// against this key and the body's embedded `operator_spk` must match
    /// it byte-for-byte (Python parity). When `None`, the embedded
    /// `operator_spk` is used as the verifier (TOFU mode); callers
    /// expecting Python parity should always pass `Some`.
    ///
    /// `expected_cluster_name`: when `Some`, the parsed `cluster_name` must
    /// match the supplied name (case-insensitive, single trailing dot
    /// stripped) or the record is rejected. Lets a caller bind a manifest
    /// to the DNS owner name they queried, defeating cross-cluster replay
    /// where a manifest signed for cluster A is republished under cluster B.
    ///
    /// `now`: when `Some`, used for expiry comparison; when `None`, the
    /// current Unix time is consulted.
    #[must_use]
    pub fn parse_and_verify(
        wire: &str,
        operator_spk_pinned: Option<&[u8]>,
        expected_cluster_name: Option<&str>,
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

        // If a pinned key is supplied, validate signature against it
        // before unpacking any body fields. Otherwise, fall through to
        // body unpack and verify with the embedded operator_spk.
        if let Some(pinned) = operator_spk_pinned {
            if pinned.len() != OPERATOR_SPK_LEN {
                return None;
            }
            if !DmpCrypto::verify_signature(body, signature, pinned) {
                return None;
            }
        }

        let manifest = Self::from_body_bytes(body).ok()?;

        if let Some(pinned) = operator_spk_pinned {
            if manifest.operator_spk.as_slice() != pinned {
                return None;
            }
        } else if !DmpCrypto::verify_signature(body, signature, &manifest.operator_spk) {
            return None;
        }

        let now_ts = now.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
        });
        if manifest.exp < now_ts {
            return None;
        }

        if let Some(expected) = expected_cluster_name {
            let parsed_norm = manifest
                .cluster_name
                .strip_suffix('.')
                .unwrap_or(&manifest.cluster_name)
                .to_ascii_lowercase();
            let expected_norm = expected
                .strip_suffix('.')
                .unwrap_or(expected)
                .to_ascii_lowercase();
            if parsed_norm != expected_norm {
                return None;
            }
        }

        Some(manifest)
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

    const OPERATOR_SEED_HEX: &str =
        "d373740143cc05dbf6a52d29cd418d44a21b5cada8db6a1eba2cdcaa2d10a9ac";
    const OPERATOR_SPK_HEX: &str =
        "2ec2785b7b2e0f5cf5a3bf6fc620cb9e1e67fa798577cfbfea34c46a20fc168b";

    fn operator() -> DmpCrypto {
        let seed = hex::decode(OPERATOR_SEED_HEX).unwrap();
        DmpCrypto::from_private_bytes(&seed).unwrap()
    }

    fn operator_spk() -> [u8; OPERATOR_SPK_LEN] {
        let raw = hex::decode(OPERATOR_SPK_HEX).unwrap();
        let mut spk = [0u8; OPERATOR_SPK_LEN];
        spk.copy_from_slice(&raw);
        spk
    }

    fn sample_manifest() -> ClusterManifest {
        ClusterManifest {
            cluster_name: "mesh.example.com".to_string(),
            operator_spk: operator_spk(),
            nodes: vec![
                ClusterNode {
                    node_id: "n01".to_string(),
                    http_endpoint: "https://n1.example.com:8053".to_string(),
                    dns_endpoint: None,
                },
                ClusterNode {
                    node_id: "n02".to_string(),
                    http_endpoint: "https://n2.example.com:8053".to_string(),
                    dns_endpoint: Some("203.0.113.2:53".to_string()),
                },
            ],
            seq: 1,
            exp: 2_051_222_400,
        }
    }

    #[test]
    fn body_round_trip() {
        let mut manifest = sample_manifest();
        let body = manifest.to_body_bytes().unwrap();
        let parsed = ClusterManifest::from_body_bytes(&body).unwrap();
        assert_eq!(parsed, manifest);
    }

    #[test]
    fn sign_and_parse_round_trip() {
        let crypto = operator();
        let mut manifest = sample_manifest();
        let wire = manifest.sign(&crypto).unwrap();
        let parsed = ClusterManifest::parse_and_verify(
            &wire,
            Some(&operator_spk()),
            None,
            Some(manifest.exp),
        )
        .expect("verify must succeed");
        assert_eq!(parsed, manifest);
    }

    #[test]
    fn cluster_rrset_name_format() {
        assert_eq!(
            cluster_rrset_name("mesh.example.com").unwrap(),
            "cluster.mesh.example.com",
        );
        assert_eq!(
            cluster_rrset_name("mesh.example.com.").unwrap(),
            "cluster.mesh.example.com",
        );
    }

    #[test]
    fn cluster_rrset_name_rejects_bad_input() {
        assert!(cluster_rrset_name("").is_err());
        assert!(cluster_rrset_name("mesh.example.com..").is_err());
        assert!(cluster_rrset_name("-mesh.example.com").is_err());
    }

    #[test]
    fn validate_dns_name_accepts_canonical_forms() {
        assert!(validate_dns_name("example.com").is_ok());
        assert!(validate_dns_name("example.com.").is_ok());
        assert!(validate_dns_name("a").is_ok());
        assert!(validate_dns_name("a-b.c-d").is_ok());
    }

    #[test]
    fn validate_dns_name_rejects_bad_inputs() {
        assert!(validate_dns_name("").is_err());
        assert!(validate_dns_name(".example.com").is_err());
        assert!(validate_dns_name("example..com").is_err());
        assert!(validate_dns_name("example.com..").is_err());
        assert!(validate_dns_name("-bad.com").is_err());
        assert!(validate_dns_name("bad-.com").is_err());
        assert!(validate_dns_name("bad_underscore.com").is_err());
        assert!(validate_dns_name("non-ascii-\u{e9}.com").is_err());
        let too_long = "a".repeat(MAX_DNS_LABEL_LEN + 1);
        assert!(validate_dns_name(&too_long).is_err());
    }

    #[test]
    fn validate_rejects_empty_node_list() {
        let mut manifest = sample_manifest();
        manifest.nodes.clear();
        assert!(matches!(
            manifest.to_body_bytes(),
            Err(ClusterError::InvalidNodeCount(_)),
        ));
    }

    #[test]
    fn validate_rejects_too_many_nodes() {
        let mut manifest = sample_manifest();
        manifest.nodes = (0..=MAX_NODE_COUNT)
            .map(|i| ClusterNode {
                node_id: format!("n{i:02}"),
                http_endpoint: "https://x.example.com:8053".to_string(),
                dns_endpoint: None,
            })
            .collect();
        assert!(matches!(
            manifest.to_body_bytes(),
            Err(ClusterError::InvalidNodeCount(_)),
        ));
    }

    #[test]
    fn validate_rejects_duplicate_node_ids() {
        let mut manifest = sample_manifest();
        manifest.nodes[1].node_id = manifest.nodes[0].node_id.clone();
        assert!(matches!(
            manifest.to_body_bytes(),
            Err(ClusterError::DuplicateNodeId(_)),
        ));
    }

    #[test]
    fn validate_rejects_empty_node_id() {
        let mut manifest = sample_manifest();
        manifest.nodes[0].node_id.clear();
        assert!(matches!(
            manifest.to_body_bytes(),
            Err(ClusterError::InvalidNodeId(_)),
        ));
    }

    #[test]
    fn validate_rejects_oversize_node_id() {
        let mut manifest = sample_manifest();
        manifest.nodes[0].node_id = "x".repeat(MAX_NODE_ID_LEN + 1);
        assert!(matches!(
            manifest.to_body_bytes(),
            Err(ClusterError::InvalidNodeId(_)),
        ));
    }

    #[test]
    fn validate_rejects_oversize_http_endpoint() {
        let mut manifest = sample_manifest();
        manifest.nodes[0].http_endpoint = "x".repeat(MAX_HTTP_ENDPOINT_LEN + 1);
        assert!(matches!(
            manifest.to_body_bytes(),
            Err(ClusterError::InvalidHttpEndpoint(_)),
        ));
    }

    #[test]
    fn validate_rejects_oversize_dns_endpoint() {
        let mut manifest = sample_manifest();
        manifest.nodes[0].dns_endpoint = Some("x".repeat(MAX_DNS_ENDPOINT_LEN + 1));
        assert!(matches!(
            manifest.to_body_bytes(),
            Err(ClusterError::InvalidDnsEndpoint(_)),
        ));
    }

    #[test]
    fn parse_and_verify_rejects_missing_prefix() {
        let mut manifest = sample_manifest();
        let crypto = operator();
        let wire = manifest.sign(&crypto).unwrap();
        let stripped = wire.strip_prefix(RECORD_PREFIX).unwrap();
        assert!(ClusterManifest::parse_and_verify(
            stripped,
            Some(&operator_spk()),
            None,
            Some(manifest.exp)
        )
        .is_none());
    }

    #[test]
    fn parse_and_verify_rejects_bad_base64() {
        let bogus = format!("{RECORD_PREFIX}!!!not-base64!!!");
        assert!(
            ClusterManifest::parse_and_verify(&bogus, Some(&operator_spk()), None, Some(0))
                .is_none()
        );
    }

    #[test]
    fn parse_and_verify_rejects_flipped_signature() {
        let mut manifest = sample_manifest();
        let crypto = operator();
        let wire = manifest.sign(&crypto).unwrap();
        let payload = wire.strip_prefix(RECORD_PREFIX).unwrap();
        let mut bytes = BASE64_STANDARD.decode(payload).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = format!("{RECORD_PREFIX}{}", BASE64_STANDARD.encode(&bytes));
        assert!(ClusterManifest::parse_and_verify(
            &tampered,
            Some(&operator_spk()),
            None,
            Some(manifest.exp)
        )
        .is_none());
    }

    #[test]
    fn parse_and_verify_rejects_expired() {
        let mut manifest = sample_manifest();
        manifest.exp = 100;
        let crypto = operator();
        let wire = manifest.sign(&crypto).unwrap();
        assert!(
            ClusterManifest::parse_and_verify(&wire, Some(&operator_spk()), None, Some(101))
                .is_none()
        );
        assert!(
            ClusterManifest::parse_and_verify(&wire, Some(&operator_spk()), None, Some(100))
                .is_some()
        );
    }

    #[test]
    fn parse_and_verify_rejects_wrong_pinned_key() {
        let mut manifest = sample_manifest();
        let crypto = operator();
        let wire = manifest.sign(&crypto).unwrap();
        let wrong = [0xAAu8; OPERATOR_SPK_LEN];
        assert!(
            ClusterManifest::parse_and_verify(&wire, Some(&wrong), None, Some(manifest.exp))
                .is_none()
        );
    }

    #[test]
    fn parse_and_verify_rejects_wrong_expected_cluster_name() {
        let mut manifest = sample_manifest();
        let crypto = operator();
        let wire = manifest.sign(&crypto).unwrap();
        // Same wire, but binding to a different cluster — cross-cluster replay must be refused.
        assert!(ClusterManifest::parse_and_verify(
            &wire,
            Some(&operator_spk()),
            Some("not-the-signed-cluster.example.com"),
            Some(manifest.exp)
        )
        .is_none());
    }

    #[test]
    fn parse_and_verify_normalizes_expected_cluster_name() {
        let mut manifest = sample_manifest();
        let crypto = operator();
        let wire = manifest.sign(&crypto).unwrap();
        // Trailing dot + uppercase must compare equal to the body's normalized form.
        let expected = format!("{}.", manifest.cluster_name.to_ascii_uppercase());
        assert!(ClusterManifest::parse_and_verify(
            &wire,
            Some(&operator_spk()),
            Some(&expected),
            Some(manifest.exp)
        )
        .is_some());
    }

    #[test]
    fn sign_rejects_mismatched_signing_key() {
        let mut manifest = sample_manifest();
        manifest.operator_spk = [0u8; OPERATOR_SPK_LEN];
        let crypto = operator();
        assert!(matches!(
            manifest.sign(&crypto),
            Err(ClusterError::SigningKeyMismatch),
        ));
    }

    #[test]
    fn from_body_bytes_rejects_bad_magic() {
        let mut manifest = sample_manifest();
        let mut body = manifest.to_body_bytes().unwrap();
        body[0] = b'X';
        assert!(matches!(
            ClusterManifest::from_body_bytes(&body),
            Err(ClusterError::MalformedBody(_)),
        ));
    }

    #[test]
    fn from_body_bytes_rejects_trailing_bytes() {
        let mut manifest = sample_manifest();
        let mut body = manifest.to_body_bytes().unwrap();
        body.push(0);
        assert!(matches!(
            ClusterManifest::from_body_bytes(&body),
            Err(ClusterError::MalformedBody(_)),
        ));
    }

    #[test]
    fn cluster_name_with_trailing_dot_is_normalized() {
        let mut manifest = sample_manifest();
        manifest.cluster_name = "mesh.example.com.".to_string();
        let body = manifest.to_body_bytes().unwrap();
        // After to_body_bytes, the dot is stripped from self.cluster_name.
        assert_eq!(manifest.cluster_name, "mesh.example.com");
        let parsed = ClusterManifest::from_body_bytes(&body).unwrap();
        assert_eq!(parsed.cluster_name, "mesh.example.com");
    }

    #[test]
    fn double_trailing_dot_rejected() {
        let mut manifest = sample_manifest();
        manifest.cluster_name = "mesh.example.com..".to_string();
        assert!(matches!(
            manifest.to_body_bytes(),
            Err(ClusterError::EmptyLabel),
        ));
    }
}

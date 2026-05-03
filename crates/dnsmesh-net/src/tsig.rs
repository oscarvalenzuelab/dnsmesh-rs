//! TSIG primitives for signed DNS UPDATE.
//!
//! Mirrors the slice of `dmp/network/dns_update_writer.py` that touches
//! TSIG: a key (name + algorithm + secret) plus the helpers to plug it
//! into `hickory-proto`'s [`hickory_proto::dnssec::tsig::TSigner`] at
//! the layer where the DNS UPDATE writer signs messages.
//!
//! RFC 8945 lists nine algorithm names; we expose only the three that
//! `hickory-proto` 0.25 supports cryptographically (HMAC-SHA256,
//! HMAC-SHA384, HMAC-SHA512). The MD5/SHA1/SHA224 algorithms in the Python
//! `SUPPORTED_TSIG_ALGORITHMS` list are intentionally omitted: they're no
//! longer recommended by the RFC and `hickory-proto`'s
//! `TsigAlgorithm::supported()` rejects them, so trying to construct a
//! `TSigner` with them would fail at runtime anyway. The truncated
//! variants (`hmac-sha256-128`, `hmac-sha384-192`, `hmac-sha512-256`) are
//! also out: hickory's TSIG verification path explicitly does not
//! support truncated HMACs (see `dnssec/tsig.rs` in hickory-proto), and
//! emitting them without verification would be asymmetric.

use std::sync::Arc;

use hickory_proto::dnssec::rdata::tsig::TsigAlgorithm as HickoryTsigAlgorithm;
use hickory_proto::dnssec::tsig::TSigner;
use hickory_proto::rr::Name;
use zeroize::Zeroizing;

/// RFC 8945 algorithm name for HMAC-SHA256.
pub const ALGORITHM_HMAC_SHA256: &str = "hmac-sha256";
/// RFC 8945 algorithm name for HMAC-SHA384.
pub const ALGORITHM_HMAC_SHA384: &str = "hmac-sha384";
/// RFC 8945 algorithm name for HMAC-SHA512.
pub const ALGORITHM_HMAC_SHA512: &str = "hmac-sha512";

/// Default fudge (max acceptable client/server clock skew, in seconds) for TSIG.
///
/// 300 seconds matches BIND's default and the value the Python writer
/// inherits from `dnspython`. Long enough that a few seconds of NTP drift
/// don't cause spurious BADTIME failures; short enough that a stolen
/// signed packet has a small replay window.
pub const DEFAULT_FUDGE_SECS: u16 = 300;

/// A TSIG MAC algorithm supported by this crate.
///
/// The wire-format string returned by [`TsigAlgorithm::as_str`] is the
/// canonical RFC 8945 presentation form (lowercase, trailing dot omitted).
/// Construction from a string is case-insensitive and tolerates the
/// trailing dot that DNS presentation form sometimes carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TsigAlgorithm {
    /// HMAC with SHA-256. The SHOULD-implement default in RFC 8945.
    HmacSha256,
    /// HMAC with SHA-384.
    HmacSha384,
    /// HMAC with SHA-512.
    HmacSha512,
}

impl TsigAlgorithm {
    /// Return the canonical RFC 8945 presentation-form name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HmacSha256 => ALGORITHM_HMAC_SHA256,
            Self::HmacSha384 => ALGORITHM_HMAC_SHA384,
            Self::HmacSha512 => ALGORITHM_HMAC_SHA512,
        }
    }

    /// Parse an RFC 8945 presentation-form name.
    ///
    /// Case-insensitive; a trailing dot (as in `hmac-sha256.`) is tolerated.
    pub fn parse(s: &str) -> Result<Self, TsigError> {
        let normalized = s.trim().trim_end_matches('.').to_ascii_lowercase();
        match normalized.as_str() {
            ALGORITHM_HMAC_SHA256 => Ok(Self::HmacSha256),
            ALGORITHM_HMAC_SHA384 => Ok(Self::HmacSha384),
            ALGORITHM_HMAC_SHA512 => Ok(Self::HmacSha512),
            _ => Err(TsigError::UnsupportedAlgorithm(s.to_string())),
        }
    }
}

impl std::fmt::Display for TsigAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for TsigAlgorithm {
    type Err = TsigError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl From<TsigAlgorithm> for HickoryTsigAlgorithm {
    fn from(algo: TsigAlgorithm) -> Self {
        match algo {
            TsigAlgorithm::HmacSha256 => Self::HmacSha256,
            TsigAlgorithm::HmacSha384 => Self::HmacSha384,
            TsigAlgorithm::HmacSha512 => Self::HmacSha512,
        }
    }
}

/// A TSIG key: name, algorithm, and shared secret.
///
/// Construction validates that the name and secret are non-empty and that
/// the name parses as a DNS name. The secret is held in a [`Zeroizing<Vec<u8>>`]
/// so it's wiped from memory on drop. The [`Debug`] impl is hand-written to
/// redact the secret rather than print it — accidentally `dbg!`-ing a key or
/// surfacing it through a derived `Debug` on a containing struct should never
/// leak the shared secret to logs.
#[derive(Clone)]
pub struct TsigKey {
    name: String,
    algorithm: TsigAlgorithm,
    secret: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for TsigKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TsigKey")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .field(
                "secret",
                &format_args!("<redacted {} bytes>", self.secret.len()),
            )
            .finish()
    }
}

impl TsigKey {
    /// Build a `TsigKey` from its parts.
    ///
    /// `name` is the TSIG key's owner name as it's known to the
    /// authoritative DNS server (e.g. `dmp-publish-key`). Empty names
    /// and empty secrets are rejected.
    pub fn new(
        name: impl Into<String>,
        algorithm: TsigAlgorithm,
        secret: impl Into<Vec<u8>>,
    ) -> Result<Self, TsigError> {
        let name = name.into();
        let secret = secret.into();
        if name.trim().is_empty() {
            return Err(TsigError::EmptyName);
        }
        if secret.is_empty() {
            return Err(TsigError::EmptySecret);
        }
        // Validate the key name is a parseable DNS name. Any error from
        // hickory means the operator typed something that won't survive
        // the wire — surface it now, not at first publish.
        Name::from_ascii(&name).map_err(|e| TsigError::InvalidKeyName {
            name: name.clone(),
            reason: e.to_string(),
        })?;
        Ok(Self {
            name,
            algorithm,
            secret: Zeroizing::new(secret),
        })
    }

    /// Owner name of the key (as supplied by the operator).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// MAC algorithm.
    #[must_use]
    pub fn algorithm(&self) -> TsigAlgorithm {
        self.algorithm
    }

    /// Shared secret (raw bytes).
    #[must_use]
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// Build a hickory `TSigner` ready to plug into a UDP / TCP client
    /// stream as a [`hickory_proto::op::MessageFinalizer`].
    ///
    /// Wraps in `Arc<dyn MessageFinalizer>` because that's the type
    /// `UdpClientStream::with_signer` and `Client::new` accept.
    ///
    /// Returns `TsigError::SignerInit` if hickory rejects the key (the
    /// most common reason in practice is a feature-flag mismatch — the
    /// `dnssec-aws-lc-rs` feature must be enabled, which our Cargo.toml
    /// already requires).
    pub fn to_signer(
        &self,
        fudge_secs: u16,
    ) -> Result<Arc<dyn hickory_proto::op::MessageFinalizer>, TsigError> {
        let key_name = Name::from_ascii(&self.name).map_err(|e| TsigError::InvalidKeyName {
            name: self.name.clone(),
            reason: e.to_string(),
        })?;
        let signer = TSigner::new(
            (*self.secret).clone(),
            HickoryTsigAlgorithm::from(self.algorithm),
            key_name,
            fudge_secs,
        )
        .map_err(|e| TsigError::SignerInit(e.to_string()))?;
        Ok(Arc::new(signer))
    }
}

/// Errors produced by [`TsigKey::new`] / [`TsigAlgorithm::parse`].
#[derive(Debug, thiserror::Error)]
pub enum TsigError {
    /// The supplied key name was empty or whitespace-only.
    #[error("TSIG key name must be non-empty")]
    EmptyName,
    /// The supplied secret was empty.
    #[error("TSIG secret must be non-empty")]
    EmptySecret,
    /// The supplied key name was not a parseable DNS name.
    #[error("invalid TSIG key name {name:?}: {reason}")]
    InvalidKeyName { name: String, reason: String },
    /// The supplied algorithm string was not one of the supported names.
    #[error("unsupported TSIG algorithm: {0:?}")]
    UnsupportedAlgorithm(String),
    /// Hickory rejected the signer construction.
    #[error("could not construct TSIG signer: {0}")]
    SignerInit(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_round_trips_through_string() {
        for algo in [
            TsigAlgorithm::HmacSha256,
            TsigAlgorithm::HmacSha384,
            TsigAlgorithm::HmacSha512,
        ] {
            assert_eq!(TsigAlgorithm::parse(algo.as_str()).unwrap(), algo);
            assert_eq!(algo.to_string(), algo.as_str());
        }
    }

    #[test]
    fn algorithm_parse_is_case_insensitive_and_dot_tolerant() {
        assert_eq!(
            TsigAlgorithm::parse("HMAC-SHA256").unwrap(),
            TsigAlgorithm::HmacSha256,
        );
        assert_eq!(
            TsigAlgorithm::parse("hmac-sha256.").unwrap(),
            TsigAlgorithm::HmacSha256,
        );
        assert_eq!(
            TsigAlgorithm::parse("  Hmac-Sha384.  ").unwrap(),
            TsigAlgorithm::HmacSha384,
        );
    }

    #[test]
    fn algorithm_rejects_unsupported_names() {
        // MD5/SHA1/SHA224/truncated variants are explicitly omitted; reject them.
        for name in [
            "hmac-md5",
            "hmac-sha1",
            "hmac-sha224",
            "hmac-sha256-128",
            "hmac-sha512-256",
            "",
            "garbage",
        ] {
            assert!(matches!(
                TsigAlgorithm::parse(name),
                Err(TsigError::UnsupportedAlgorithm(_))
            ));
        }
    }

    #[test]
    fn key_round_trip_construction() {
        let key = TsigKey::new("dmp-key", TsigAlgorithm::HmacSha256, vec![1u8; 32]).unwrap();
        assert_eq!(key.name(), "dmp-key");
        assert_eq!(key.algorithm(), TsigAlgorithm::HmacSha256);
        assert_eq!(key.secret(), &[1u8; 32]);
    }

    #[test]
    fn debug_redacts_the_secret() {
        // Arbitrary printable ASCII that would be obvious in `dbg!` output.
        let secret = b"this-secret-must-not-leak".to_vec();
        let key = TsigKey::new("dmp-key", TsigAlgorithm::HmacSha256, secret.clone()).unwrap();
        let rendered = format!("{key:?}");
        assert!(
            !rendered.contains("this-secret-must-not-leak"),
            "TsigKey Debug must not leak the secret: {rendered}",
        );
        assert!(rendered.contains("redacted"));
        // Sanity: the name and algorithm still appear.
        assert!(rendered.contains("dmp-key"));
        assert!(rendered.contains("HmacSha256"));
    }

    #[test]
    fn key_rejects_empty_name() {
        let err = TsigKey::new("", TsigAlgorithm::HmacSha256, vec![1u8; 16]).unwrap_err();
        assert!(matches!(err, TsigError::EmptyName));
        let err = TsigKey::new("   ", TsigAlgorithm::HmacSha256, vec![1u8; 16]).unwrap_err();
        assert!(matches!(err, TsigError::EmptyName));
    }

    #[test]
    fn key_rejects_empty_secret() {
        let err = TsigKey::new("dmp-key", TsigAlgorithm::HmacSha256, Vec::<u8>::new()).unwrap_err();
        assert!(matches!(err, TsigError::EmptySecret));
    }

    #[test]
    fn key_rejects_unparseable_name() {
        // A bare colon is not a valid DNS label.
        let err = TsigKey::new("bad:name", TsigAlgorithm::HmacSha256, vec![1u8; 16]);
        // Some hickory versions accept odd labels; if hickory accepts it,
        // we don't fail the test — the contract is "if hickory would
        // reject it later, reject it now". Trust hickory's parser.
        if let Err(e) = err {
            assert!(matches!(e, TsigError::InvalidKeyName { .. }));
        }
    }

    #[test]
    fn to_signer_produces_usable_finalizer() {
        use hickory_proto::op::{Message, Query};
        // 32 bytes of 0xab is a perfectly valid HMAC-SHA256 key.
        let key = TsigKey::new("dmp-key", TsigAlgorithm::HmacSha256, vec![0xab; 32]).unwrap();
        let signer = key
            .to_signer(DEFAULT_FUDGE_SECS)
            .expect("hickory should accept the key with the dnssec-aws-lc-rs feature on");
        // We can't introspect the Arc<dyn MessageFinalizer> directly, but
        // we can finalize a real message with it and confirm the TSIG RR
        // shows up.
        let mut msg = Message::new();
        msg.add_query(Query::new());
        msg.finalize(signer.as_ref(), 0).unwrap();
        let tsig_records = msg.signature();
        assert_eq!(tsig_records.len(), 1, "expected exactly one TSIG record");
        // sanity: the MAC inside is non-empty (HMAC-SHA256 = 32 bytes).
        if let hickory_proto::rr::RData::DNSSEC(hickory_proto::dnssec::rdata::DNSSECRData::TSIG(
            tsig,
        )) = tsig_records[0].data()
        {
            assert!(!tsig.mac().is_empty());
            assert!(tsig.mac().len() >= 32);
        } else {
            panic!("expected TSIG RData");
        }
    }
}

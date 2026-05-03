//! Reader / writer abstractions for DNS TXT records.
//!
//! Mirrors `dmp/network/base.py`: writing happens against an authoritative source
//! (Cloudflare API, BIND RFC 2136 UPDATE, etc.) and is eventually consistent;
//! reading goes through a recursive resolver. Implementing one side does not
//! imply the other.

use async_trait::async_trait;

use crate::error::NetError;

/// Publish TXT records to an authoritative DNS zone.
#[async_trait]
pub trait DnsRecordWriter: Send + Sync {
    /// Create or update a TXT record at fully-qualified `name`.
    ///
    /// Returns `Ok(true)` if the write was accepted by the authoritative source.
    /// Propagation delay is the caller's problem.
    async fn publish_txt_record(
        &self,
        name: &str,
        value: &str,
        ttl_seconds: u32,
    ) -> Result<bool, NetError>;

    /// Delete a TXT record at fully-qualified `name`.
    ///
    /// Some backends (Route53) require the record value to target an exact RRset;
    /// others (Cloudflare, BIND UPDATE) delete by name alone. Callers should pass
    /// `value` when known; backends that don't need it ignore it.
    async fn delete_txt_record(&self, name: &str, value: Option<&str>) -> Result<bool, NetError>;
}

/// Query TXT records via a resolver.
#[async_trait]
pub trait DnsRecordReader: Send + Sync {
    /// Return the list of TXT strings at `name`, or `None` if no record.
    ///
    /// `None` means the record is absent or unreachable. Backends may coalesce
    /// NXDOMAIN / NoAnswer / transport errors to `None`; callers that need to
    /// distinguish should use a richer backend interface.
    async fn query_txt_record(&self, name: &str) -> Result<Option<Vec<String>>, NetError>;
}

/// A backend that supports both reading and writing TXT records.
///
/// Real production deployments typically use separate reader and writer
/// backends (resolver vs. authoritative API). [`DnsRecordStore`] is primarily
/// for [`crate::InMemoryDnsStore`] and for backends that own both sides.
pub trait DnsRecordStore: DnsRecordReader + DnsRecordWriter {}

impl<T> DnsRecordStore for T where T: DnsRecordReader + DnsRecordWriter {}

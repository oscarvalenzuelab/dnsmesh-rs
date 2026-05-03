//! DMP DNS transport, resolver glue, and network I/O.
//!
//! Reading and writing DNS records are two different concerns:
//! - Writing requires authoritative control over a zone (Cloudflare API, BIND
//!   RFC 2136 UPDATE, etc.) and is eventually consistent across caches.
//! - Reading goes through a recursive resolver, with its own caching
//!   semantics and failure modes (NXDOMAIN vs. NoAnswer vs. transport error).
//!
//! Keeping the interfaces separate ([`DnsRecordReader`] vs.
//! [`DnsRecordWriter`]) lets a backend implement one side without implying the
//! other. [`InMemoryDnsStore`] implements both for tests.

pub mod base;
#[cfg(feature = "cloudflare")]
pub mod cloudflare;
pub mod composite_reader;
pub mod dns_update_writer;
pub mod error;
pub mod fanout_writer;
pub mod memory;
#[cfg(feature = "cloudflare")]
pub mod node_token;
pub mod resolver_pool;
pub mod tsig;
pub mod union_reader;

pub use base::{DnsRecordReader, DnsRecordStore, DnsRecordWriter};
#[cfg(feature = "cloudflare")]
pub use cloudflare::{CloudflarePublisher, CloudflarePublisherConfig};
pub use composite_reader::CompositeReader;
pub use dns_update_writer::{DnsUpdateWriter, DnsUpdateWriterConfig};
pub use error::NetError;
pub use fanout_writer::{FanoutWriter, Quorum};
pub use memory::InMemoryDnsStore;
#[cfg(feature = "cloudflare")]
pub use node_token::{NodeTokenPublisher, NodeTokenPublisherConfig};
pub use resolver_pool::{HostSpec, ResolverPool, ResolverPoolConfig};
pub use tsig::{TsigAlgorithm, TsigError, TsigKey, DEFAULT_FUDGE_SECS};
pub use union_reader::UnionReader;

#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!version().is_empty());
    }
}

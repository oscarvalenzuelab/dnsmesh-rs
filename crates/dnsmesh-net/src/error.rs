//! Shared error type for DMP network transports.

/// Errors returned by [`crate::DnsRecordReader`] / [`crate::DnsRecordWriter`] backends.
///
/// Backends are expected to coalesce DNS-level failure modes (NXDOMAIN, NoAnswer,
/// transport timeout) to `Ok(None)` from `query_txt_record` rather than surface them as
/// errors — callers only need to know "did I get records back or not?". A `NetError`
/// indicates a *configuration* or *transport* problem severe enough that the call
/// can't be answered at all (e.g. the supplied host list is empty, the resolver
/// couldn't be constructed, or an authoritative write was rejected).
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// The supplied host list was empty or otherwise invalid.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    /// A host literal could not be parsed as an IPv4 or IPv6 address.
    #[error("invalid host literal {host:?}: {reason}")]
    InvalidHost { host: String, reason: String },
    /// A port number was outside the legal 1..=65535 range or had the wrong type.
    #[error("invalid port {port}: {reason}")]
    InvalidPort { port: i64, reason: String },
    /// The DNS query name could not be parsed as a valid name.
    #[error("invalid dns name {name:?}: {reason}")]
    InvalidName { name: String, reason: String },
    /// All upstream resolvers refused or failed transport for this query, and there
    /// was no oracle for "name not found".
    #[error("no resolver returned a usable answer")]
    NoUsableAnswer,
    /// An authoritative write backend rejected the request.
    /// The authoritative server answered a DNS UPDATE with a non-zero
    /// RCODE. Carries the code so callers can tell a rejected TSIG key
    /// (NOTAUTH), an out-of-scope name (REFUSED) and clock skew (BADTIME)
    /// apart, instead of reporting an unqualified failure.
    #[error("{server} rejected the DNS UPDATE for {name}: {rcode}")]
    UpdateRejected {
        name: String,
        server: String,
        rcode: String,
    },
    #[error("authoritative write failed: {0}")]
    WriteFailed(String),
    /// A lower-level DNS protocol error escaped a backend that didn't translate it.
    #[error("dns transport: {0}")]
    Transport(String),
    /// A TSIG primitive (key construction, signer setup) rejected the input.
    #[error("tsig: {0}")]
    Tsig(#[from] crate::tsig::TsigError),
}

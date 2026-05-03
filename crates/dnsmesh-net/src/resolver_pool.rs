//! Resolver pool with per-host health tracking and automatic failover.
//!
//! Mirrors `dmp/network/resolver_pool.py`. Recursive resolvers fail in several
//! ways — NXDOMAIN, NoAnswer, transport timeout — and callers of
//! [`crate::DnsRecordReader::query_txt_record`] want a single boolean answer:
//! "did I get records back?" not a taxonomy of DNS failure modes.
//!
//! [`ResolverPool`] tries upstreams in priority order. A host with too many
//! consecutive transport failures is *deprioritized* until its cooldown
//! elapses. NXDOMAIN / NoAnswer answers are buffered: a not-found is only
//! treated as a health failure if a lower-priority resolver retroactively
//! produces a real answer for the same name (the "oracle rule" — a successful
//! lookup proves earlier resolvers were lying or stale).

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::xfer::Protocol;
use hickory_resolver::proto::ProtoErrorKind;
use hickory_resolver::{ResolveErrorKind, Resolver};
use parking_lot::Mutex;

use crate::base::DnsRecordReader;
use crate::error::NetError;

/// Public IPv4 resolvers, intentionally operator-diverse. IPv6 is excluded
/// because many networks lack v6 connectivity and a silently unreachable v6
/// literal would burn the probe budget for no gain.
pub const WELL_KNOWN_RESOLVERS: &[&str] = &[
    "8.8.8.8",         // Google
    "8.8.4.4",         // Google
    "1.1.1.1",         // Cloudflare
    "1.0.0.1",         // Cloudflare
    "9.9.9.9",         // Quad9
    "149.112.112.112", // Quad9
    "208.67.222.222",  // OpenDNS
    "208.67.220.220",  // OpenDNS
];

/// One entry in the [`ResolverPool::new`] hosts argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostSpec {
    /// Bare IP literal — inherits the pool-wide default port.
    Bare(IpAddr),
    /// Explicit `(ip, port)`.
    WithPort(IpAddr, u16),
}

impl HostSpec {
    fn resolve(&self, default_port: u16) -> (IpAddr, u16) {
        match self {
            Self::Bare(ip) => (*ip, default_port),
            Self::WithPort(ip, port) => (*ip, *port),
        }
    }
}

impl FromStr for HostSpec {
    type Err = NetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip = s.parse::<IpAddr>().map_err(|e| NetError::InvalidHost {
            host: s.to_string(),
            reason: e.to_string(),
        })?;
        Ok(Self::Bare(ip))
    }
}

impl From<(IpAddr, u16)> for HostSpec {
    fn from((ip, port): (IpAddr, u16)) -> Self {
        Self::WithPort(ip, port)
    }
}

/// Configuration knobs for [`ResolverPool`]. Defaults match the Python pool.
#[derive(Debug, Clone, Copy)]
pub struct ResolverPoolConfig {
    /// Default UDP/TCP port for bare-host entries.
    pub port: u16,
    /// Per-query socket timeout.
    pub timeout: Duration,
    /// How long a demoted host is skipped before being re-tried.
    pub cooldown: Duration,
    /// Number of consecutive transport failures before a host is put into cooldown.
    pub failure_threshold: u32,
}

impl Default for ResolverPoolConfig {
    fn default() -> Self {
        Self {
            port: 53,
            timeout: Duration::from_secs(5),
            cooldown: Duration::from_secs(60),
            failure_threshold: 1,
        }
    }
}

#[derive(Debug)]
struct HostState {
    // Kept for Debug output and the planned `snapshot()` health API; the
    // resolver itself already binds (ip, port) at construction time.
    #[allow(dead_code)]
    ip: IpAddr,
    #[allow(dead_code)]
    port: u16,
    resolver: Resolver<TokioConnectionProvider>,
    health: Mutex<HostHealth>,
}

#[derive(Debug, Default, Clone, Copy)]
struct HostHealth {
    consecutive_failures: u32,
    last_failure: Option<Instant>,
}

impl HostState {
    fn record_success(&self) {
        let mut h = self.health.lock();
        h.consecutive_failures = 0;
        h.last_failure = None;
    }

    fn record_failure(&self) {
        let mut h = self.health.lock();
        h.consecutive_failures = h.consecutive_failures.saturating_add(1);
        h.last_failure = Some(Instant::now());
    }

    fn is_cooled_down(&self, threshold: u32, cooldown: Duration) -> bool {
        let h = self.health.lock();
        if h.consecutive_failures < threshold {
            return false;
        }
        h.last_failure.is_some_and(|ts| ts.elapsed() < cooldown)
    }

    fn last_failure_age(&self) -> Duration {
        self.health
            .lock()
            .last_failure
            .map_or(Duration::MAX, |ts| ts.elapsed())
    }
}

/// A [`DnsRecordReader`] that fans a query across multiple upstream resolvers.
///
/// Tries hosts in the order given (insertion order), returning the first
/// non-empty TXT answer. Hosts with recent transport failures are skipped
/// until their cooldown elapses.
#[derive(Debug)]
pub struct ResolverPool {
    states: Vec<Arc<HostState>>,
    config: ResolverPoolConfig,
}

impl ResolverPool {
    /// Build a pool from a list of host specs and a configuration.
    ///
    /// Returns an error if `hosts` is empty, contains a non-IP literal, or has
    /// an out-of-range port. Hostnames are rejected on purpose — resolving them
    /// at startup would reintroduce the DNS-ordering problem the pool exists
    /// to solve.
    pub fn new(
        hosts: impl IntoIterator<Item = HostSpec>,
        config: ResolverPoolConfig,
    ) -> Result<Self, NetError> {
        if config.failure_threshold < 1 {
            return Err(NetError::InvalidConfig(
                "failure_threshold must be >= 1".into(),
            ));
        }
        let mut states: Vec<Arc<HostState>> = Vec::new();
        for spec in hosts {
            let (ip, port) = spec.resolve(config.port);
            let mut cfg = ResolverConfig::new();
            cfg.add_name_server(NameServerConfig::new(
                std::net::SocketAddr::new(ip, port),
                Protocol::Udp,
            ));
            cfg.add_name_server(NameServerConfig::new(
                std::net::SocketAddr::new(ip, port),
                Protocol::Tcp,
            ));
            let mut opts = ResolverOpts::default();
            opts.timeout = config.timeout;
            opts.attempts = 2;
            opts.use_hosts_file = hickory_resolver::config::ResolveHosts::Never;
            opts.cache_size = 0;
            let mut builder =
                Resolver::builder_with_config(cfg, TokioConnectionProvider::default());
            *builder.options_mut() = opts;
            let resolver = builder.build();
            states.push(Arc::new(HostState {
                ip,
                port,
                resolver,
                health: Mutex::default(),
            }));
        }
        if states.is_empty() {
            return Err(NetError::InvalidConfig(
                "ResolverPool requires at least one host".into(),
            ));
        }
        Ok(Self { states, config })
    }

    /// Convenience constructor using the [`WELL_KNOWN_RESOLVERS`] list and default
    /// configuration.
    pub fn well_known() -> Result<Self, NetError> {
        let hosts = WELL_KNOWN_RESOLVERS
            .iter()
            .map(|s| {
                s.parse::<IpAddr>()
                    .map(HostSpec::Bare)
                    .map_err(|e| NetError::InvalidHost {
                        host: (*s).to_string(),
                        reason: e.to_string(),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(hosts, ResolverPoolConfig::default())
    }

    /// Number of upstream hosts configured.
    #[must_use]
    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// True iff the pool has no hosts. Constructor rejects this; included for
    /// clippy-len-zero ergonomics.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    fn ordered_hosts(&self) -> Vec<Arc<HostState>> {
        let cooldown = self.config.cooldown;
        let threshold = self.config.failure_threshold;
        let mut preferred: Vec<Arc<HostState>> = Vec::new();
        let mut deferred: Vec<Arc<HostState>> = Vec::new();
        for state in &self.states {
            if state.is_cooled_down(threshold, cooldown) {
                deferred.push(Arc::clone(state));
            } else {
                preferred.push(Arc::clone(state));
            }
        }
        // Within deferred tier, oldest-failure-first: most likely recovered.
        deferred.sort_by_key(|s| std::cmp::Reverse(s.last_failure_age()));
        preferred.extend(deferred);
        preferred
    }
}

/// Outcome of one upstream's attempt at a query, before the oracle rule fires.
enum HostOutcome {
    /// Got a real answer; pool returns immediately.
    Found(Vec<String>),
    /// Authoritative not-found (NXDOMAIN or NoAnswer). Provisionally healthy.
    NotFound,
    /// Transport failure (timeout, refused, resolver unreachable). Health -1.
    Transport,
    /// The query name itself is malformed — caller bug, not a resolver fault.
    /// Bubbles up as [`NetError::InvalidName`] without poisoning resolver health.
    BadName(String),
}

#[async_trait]
impl DnsRecordReader for ResolverPool {
    async fn query_txt_record(&self, name: &str) -> Result<Option<Vec<String>>, NetError> {
        // Validate the name once up-front so we don't burn resolver attempts on
        // a malformed input. hickory's TXT lookup expects a syntactically-valid
        // name; an empty string or invalid label gives `ProtoError`. We treat
        // those as caller bugs, not resolver health failures.
        if name.is_empty() {
            return Err(NetError::InvalidName {
                name: name.to_string(),
                reason: "name must be non-empty".into(),
            });
        }

        let ordered = self.ordered_hosts();
        let mut not_found_buffer: Vec<Arc<HostState>> = Vec::new();
        for state in ordered {
            match query_one(&state, name).await {
                HostOutcome::Found(values) => {
                    state.record_success();
                    // Oracle rule: any earlier "not found" is now an oracle failure.
                    for buf in &not_found_buffer {
                        buf.record_failure();
                    }
                    return Ok(Some(values));
                }
                HostOutcome::NotFound => {
                    not_found_buffer.push(state);
                }
                HostOutcome::Transport => {
                    state.record_failure();
                }
                HostOutcome::BadName(reason) => {
                    // Caller bug — surface eagerly, don't try the rest of the pool.
                    return Err(NetError::InvalidName {
                        name: name.to_string(),
                        reason,
                    });
                }
            }
        }
        // Everyone said "not found". A genuinely-absent name is a HEALTHY answer
        // for each not-found host: clear their failure streaks so an old transient
        // transport failure doesn't shadow good behavior forever. No demotions
        // (the oracle rule didn't fire — nobody disproved them).
        for state in &not_found_buffer {
            state.record_success();
        }
        Ok(None)
    }
}

async fn query_one(state: &HostState, name: &str) -> HostOutcome {
    match state.resolver.txt_lookup(name).await {
        Ok(lookup) => {
            let mut out: Vec<String> = Vec::new();
            for txt in lookup.iter() {
                let mut joined = String::new();
                for chunk in txt.txt_data() {
                    // TXT data is bytes-on-wire; DMP records are always ASCII /
                    // UTF-8 with the literal `v=dmp1;...` prefix. Lossy decode
                    // is fine — non-UTF-8 records aren't ours.
                    joined.push_str(&String::from_utf8_lossy(chunk));
                }
                if !joined.is_empty() {
                    out.push(joined);
                }
            }
            if out.is_empty() {
                HostOutcome::NotFound
            } else {
                HostOutcome::Found(out)
            }
        }
        Err(err) => classify_error(&err),
    }
}

fn classify_error(err: &hickory_resolver::ResolveError) -> HostOutcome {
    // Three buckets:
    // - `NoRecordsFound` (NXDOMAIN/NoAnswer) — authoritative "no such record",
    //   provisionally healthy.
    // - `DomainNameTooLong` / label-syntax errors — caller-supplied name is
    //   malformed; surface as `BadName` so we don't poison resolver health on
    //   a typo.
    // - Everything else — transport-level fault.
    match err.kind() {
        ResolveErrorKind::Proto(proto) => match proto.kind() {
            ProtoErrorKind::NoRecordsFound { .. } => HostOutcome::NotFound,
            ProtoErrorKind::DomainNameTooLong(_)
            | ProtoErrorKind::LabelBytesTooLong(_)
            | ProtoErrorKind::CharacterDataTooLong { .. } => {
                HostOutcome::BadName(proto.kind().to_string())
            }
            _ => HostOutcome::Transport,
        },
        _ => HostOutcome::Transport,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_spec_parses_ipv4_literal() {
        let spec: HostSpec = "8.8.8.8".parse().unwrap();
        assert_eq!(spec, HostSpec::Bare("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn host_spec_rejects_hostname() {
        let err = "dns.example.com".parse::<HostSpec>().unwrap_err();
        assert!(matches!(err, NetError::InvalidHost { .. }));
    }

    #[test]
    fn host_spec_with_port() {
        let spec = HostSpec::WithPort("127.0.0.1".parse().unwrap(), 5353);
        assert_eq!(spec.resolve(53), ("127.0.0.1".parse().unwrap(), 5353));
    }

    #[test]
    fn well_known_resolvers_count_matches_python() {
        // Eight entries: Google v4 x2, Cloudflare v4 x2, Quad9 v4 x2, OpenDNS v4 x2.
        assert_eq!(WELL_KNOWN_RESOLVERS.len(), 8);
    }

    #[test]
    fn pool_rejects_empty_hosts() {
        let err = ResolverPool::new(std::iter::empty(), ResolverPoolConfig::default()).unwrap_err();
        assert!(matches!(err, NetError::InvalidConfig(_)));
    }

    #[test]
    fn pool_well_known_constructs() {
        let pool = ResolverPool::well_known().unwrap();
        assert_eq!(pool.len(), 8);
        // Sanity: every state has a unique (ip, port).
        let mut keys: Vec<(IpAddr, u16)> = pool.states.iter().map(|s| (s.ip, s.port)).collect();
        keys.sort();
        let unique = {
            let mut k = keys.clone();
            k.dedup();
            k.len()
        };
        assert_eq!(keys.len(), unique);
    }

    #[test]
    fn config_default_matches_python_defaults() {
        let c = ResolverPoolConfig::default();
        assert_eq!(c.port, 53);
        assert_eq!(c.failure_threshold, 1);
        assert_eq!(c.cooldown, Duration::from_secs(60));
    }
}

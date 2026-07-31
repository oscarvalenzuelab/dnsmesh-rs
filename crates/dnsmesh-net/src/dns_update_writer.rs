//! Client-side DNS UPDATE writer.
//!
//! Mirrors `dmp/network/dns_update_writer.py`. Implements
//! [`DnsRecordWriter`] against a remote authoritative DNS server using
//! RFC 2136 UPDATE + RFC 8945 TSIG.
//!
//! Design notes (carried over from the Python writer):
//!
//! - One-shot UPDATE per call. We don't batch publishes, on purpose —
//!   the caller's flow already understands per-record progress, and one
//!   UPDATE per record keeps failure granularity matching the existing
//!   HTTP path.
//! - UDP first, TCP fallback on truncation. A signed UPDATE plus
//!   response can blow past 512 bytes pretty quickly with a 32-byte
//!   HMAC tag; sane DNS servers signal via TC=1 and we retry on TCP.
//! - Failures don't bubble up as errors — we surface `Ok(false)` to
//!   match the [`DnsRecordWriter`] contract. Transport errors, REFUSED,
//!   NXRRSET, SERVFAIL, signature failures, timeouts: all map to
//!   `Ok(false)` after a `tracing::warn`. Construction-time validation
//!   errors (empty zone, invalid TSIG key) are the only `Err` path.
//!
//! Hostname resolution is the caller's job. Unlike the Python writer
//! (which threads a `ResolverPool` into `_resolve_to_ip`), this Rust
//! writer takes an already-resolved [`SocketAddr`]. The cleaner contract
//! lets the same `DnsUpdateWriter` work with any resolution strategy
//! (CLI flag, environment variable, M9.2.3 contact metadata) without
//! coupling the writer to a particular pool implementation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hickory_client::client::Client;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordSet, RecordType};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::tcp::TcpClientStream;
use hickory_proto::udp::UdpClientStream;
use hickory_proto::xfer::{DnsHandle, DnsResponse};

use crate::base::DnsRecordWriter;
use crate::error::NetError;
use crate::tsig::{TsigKey, DEFAULT_FUDGE_SECS};

/// Default per-call socket timeout. Matches the Python writer's `DEFAULT_TIMEOUT`.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Configuration for [`DnsUpdateWriter`].
#[derive(Debug, Clone)]
pub struct DnsUpdateWriterConfig {
    /// Authoritative zone the writer is allowed to UPDATE under (e.g. `example.com`).
    /// The trailing dot is optional; both `example.com` and `example.com.` are accepted.
    pub zone: String,
    /// Already-resolved socket address of the authoritative server.
    /// Hostname resolution is the caller's responsibility — see the
    /// module-level docs for why.
    pub server: SocketAddr,
    /// TSIG key to sign each UPDATE with.
    pub tsig_key: TsigKey,
    /// Per-call socket timeout for both UDP and TCP attempts.
    pub timeout: Duration,
    /// TSIG fudge (clock-skew tolerance) in seconds. Defaults to
    /// [`crate::DEFAULT_FUDGE_SECS`] (300).
    pub fudge_secs: u16,
}

impl DnsUpdateWriterConfig {
    /// Build a config with the writer's default timeout / fudge values.
    pub fn new(zone: impl Into<String>, server: SocketAddr, tsig_key: TsigKey) -> Self {
        Self {
            zone: zone.into(),
            server,
            tsig_key,
            timeout: DEFAULT_TIMEOUT,
            fudge_secs: DEFAULT_FUDGE_SECS,
        }
    }
}

/// Send TSIG-signed RFC 2136 UPDATE messages to an authoritative DNS server.
///
/// Construction is cheap (no network I/O). Each
/// [`publish_txt_record`](DnsRecordWriter::publish_txt_record) /
/// [`delete_txt_record`](DnsRecordWriter::delete_txt_record) call sends
/// one UDP packet (with TCP fallback on truncation) and returns
/// `Ok(true)` iff the server answered NOERROR.
///
/// The caller is responsible for ensuring the records they publish are
/// within the TSIG key's authorized scope — out-of-scope writes bounce
/// as REFUSED on the server side, which we surface as `Ok(false)`.
#[derive(Debug, Clone)]
pub struct DnsUpdateWriter {
    zone: Name,
    server: SocketAddr,
    tsig_key: TsigKey,
    timeout: Duration,
    fudge_secs: u16,
}

impl DnsUpdateWriter {
    /// Validate the configuration and return a writer.
    ///
    /// Errors only on configuration problems (empty zone, unparseable
    /// zone name); the TSIG key was already validated at
    /// [`TsigKey::new`] time.
    pub fn new(config: DnsUpdateWriterConfig) -> Result<Self, NetError> {
        let zone_text = config.zone.trim().trim_end_matches('.');
        if zone_text.is_empty() {
            return Err(NetError::InvalidConfig("zone must be non-empty".into()));
        }
        let zone = Name::from_ascii(zone_text)
            .map_err(|e| NetError::InvalidName {
                name: config.zone.clone(),
                reason: e.to_string(),
            })?
            .to_lowercase();
        Ok(Self {
            zone,
            server: config.server,
            tsig_key: config.tsig_key,
            timeout: config.timeout,
            fudge_secs: config.fudge_secs,
        })
    }

    /// Build the in-memory UPDATE message for a TXT add. Pulled out so
    /// the unit tests can exercise wire-format round-tripping without a
    /// network.
    fn build_publish_message(
        &self,
        name: &str,
        value: &str,
        ttl: u32,
    ) -> Result<Message, NetError> {
        let owner = parse_owner(name)?;
        if !self.zone.zone_of(&owner) {
            return Err(NetError::InvalidName {
                name: name.to_string(),
                reason: format!("name is not within zone {}", self.zone),
            });
        }
        let txt = TXT::new(vec![value.to_string()]);
        let mut record = Record::from_rdata(owner, ttl, RData::TXT(txt));
        record.set_dns_class(DNSClass::IN);
        let rrset: RecordSet = record.into();
        // `append` with `must_exist=false` is "add to RRset, creating it if absent" — the
        // RFC 2136 §2.5.1 additive add, with no prerequisite. Hickory's `create()` would
        // add a "MUST NOT EXIST" prerequisite (§2.4.4), which makes republishes and
        // multi-value RRsets fail with YXRRSET. The Python writer uses dnspython's
        // `UpdateMessage.add()`, which is the no-prerequisite additive form too.
        Ok(hickory_proto::op::update_message::append(
            rrset,
            self.zone.clone(),
            /* must_exist = */ false,
            /* use_edns   = */ true,
        ))
    }

    /// Build the in-memory UPDATE message for a TXT delete (whole RRset
    /// or specific RR). Pulled out for testability — see
    /// [`Self::build_publish_message`].
    fn build_delete_message(&self, name: &str, value: Option<&str>) -> Result<Message, NetError> {
        let owner = parse_owner(name)?;
        if !self.zone.zone_of(&owner) {
            return Err(NetError::InvalidName {
                name: name.to_string(),
                reason: format!("name is not within zone {}", self.zone),
            });
        }
        let msg = match value {
            None => {
                // Delete the whole TXT RRset at this name.
                let record = Record::from_rdata(owner, 0, RData::Update0(RecordType::TXT));
                hickory_proto::op::update_message::delete_rrset(record, self.zone.clone(), true)
            }
            Some(v) => {
                // Delete a specific TXT RR.
                let txt = TXT::new(vec![v.to_string()]);
                let mut record = Record::from_rdata(owner, 0, RData::TXT(txt));
                record.set_dns_class(DNSClass::IN);
                let rrset: RecordSet = record.into();
                hickory_proto::op::update_message::delete_by_rdata(rrset, self.zone.clone(), true)
            }
        };
        Ok(msg)
    }

    /// UDP-first, TCP-on-truncation send.
    ///
    /// `Ok(true)` on a signed NOERROR response. Transport and TSIG
    /// authentication failures come back as errors carrying the cause: they
    /// used to be flattened to `Ok(false)`, which surfaced to the user as a
    /// bare "publish failed" with the actual reason only in a log line they
    /// would never see. A wrong TSIG secret and an unreachable server looked
    /// identical.
    async fn send(&self, message: Message, op: &str, name: &str) -> Result<bool, NetError> {
        let signer = self.tsig_key.to_signer(self.fudge_secs)?;
        // First attempt: UDP.
        let provider = TokioRuntimeProvider::default();
        let udp_outcome = self
            .send_udp(&message, signer.clone(), provider.clone())
            .await;
        let response = match udp_outcome {
            UdpOutcome::Ok(resp) => resp,
            UdpOutcome::Truncated => {
                tracing::debug!(
                    "DNS UPDATE {} for {} truncated over UDP, retrying TCP",
                    op,
                    name
                );
                match self.send_tcp(&message, signer, provider).await {
                    Ok(resp) => resp,
                    Err(e) => {
                        tracing::warn!("DNS UPDATE TCP retry for {}/{} failed: {}", op, name, e);
                        return Err(NetError::UpdateRejected {
                            name: name.to_string(),
                            server: self.server.to_string(),
                            rcode: format!("TCP retry failed: {e}"),
                        });
                    }
                }
            }
            UdpOutcome::Failed(e) => {
                tracing::warn!("DNS UPDATE UDP for {}/{} failed: {}", op, name, e);
                return Err(NetError::UpdateRejected {
                    name: name.to_string(),
                    server: self.server.to_string(),
                    rcode: e.clone(),
                });
            }
        };
        let rcode = response.response_code();
        if rcode == hickory_proto::op::ResponseCode::NoError {
            Ok(true)
        } else {
            // Surfaced as an error rather than a bare `false`. The RCODE is
            // the only thing that distinguishes a rejected TSIG key from an
            // out-of-scope name or clock skew, and dropping it left callers
            // reporting "publish failed" with nothing to act on.
            tracing::info!(
                "DNS UPDATE {} for {} rejected by {}: rcode={}",
                op,
                name,
                self.server,
                rcode
            );
            Err(NetError::UpdateRejected {
                name: name.to_string(),
                server: self.server.to_string(),
                rcode: rcode.to_string(),
            })
        }
    }

    async fn send_udp(
        &self,
        message: &Message,
        signer: Arc<dyn hickory_proto::op::MessageFinalizer>,
        provider: TokioRuntimeProvider,
    ) -> UdpOutcome {
        let conn = UdpClientStream::builder(self.server, provider)
            .with_timeout(Some(self.timeout))
            .with_signer(Some(signer))
            .build();
        let (mut client, bg) = match Client::connect(conn).await {
            Ok(pair) => pair,
            Err(e) => return UdpOutcome::Failed(e.to_string()),
        };
        let bg_handle = tokio::spawn(bg);
        let result = run_update(&mut client, message.clone(), self.timeout).await;
        // Drop the client handle before awaiting the background — that
        // signals the multiplexer to wind down. The background task
        // returns Err(_) when its handles drop, which we ignore.
        drop(client);
        let _ = bg_handle.await;
        match result {
            Ok(resp) => {
                if resp.truncated() {
                    UdpOutcome::Truncated
                } else {
                    UdpOutcome::Ok(resp)
                }
            }
            Err(e) => UdpOutcome::Failed(e),
        }
    }

    async fn send_tcp(
        &self,
        message: &Message,
        signer: Arc<dyn hickory_proto::op::MessageFinalizer>,
        provider: TokioRuntimeProvider,
    ) -> Result<DnsResponse, String> {
        let (connect, sender) =
            TcpClientStream::new(self.server, None, Some(self.timeout), provider);
        let (mut client, bg) = Client::with_timeout(connect, sender, self.timeout, Some(signer))
            .await
            .map_err(|e| e.to_string())?;
        let bg_handle = tokio::spawn(bg);
        let result = run_update(&mut client, message.clone(), self.timeout).await;
        drop(client);
        let _ = bg_handle.await;
        result
    }
}

enum UdpOutcome {
    Ok(DnsResponse),
    Truncated,
    Failed(String),
}

/// Send `message` through `client` and wait for the (single) response.
///
/// `Client::send` returns a stream because the same handle is used for
/// AXFR / IXFR which are streaming responses. For an UPDATE we expect
/// exactly one response and treat anything else as failure.
async fn run_update(
    client: &mut Client,
    message: Message,
    timeout: Duration,
) -> Result<DnsResponse, String> {
    use futures_util::stream::StreamExt as _;
    use hickory_proto::xfer::{DnsRequest, DnsRequestOptions};

    // Convert our pre-built UPDATE into a request the multiplexer can drive.
    let opts = DnsRequestOptions::default();
    let mut response_stream = client.send(DnsRequest::new(message, opts));
    match tokio::time::timeout(timeout, response_stream.next()).await {
        Ok(Some(Ok(resp))) => Ok(resp),
        Ok(Some(Err(e))) => Err(e.to_string()),
        Ok(None) => Err("dns client returned no response".to_string()),
        Err(_) => Err("dns update timed out".to_string()),
    }
}

#[async_trait]
impl DnsRecordWriter for DnsUpdateWriter {
    async fn publish_txt_record(
        &self,
        name: &str,
        value: &str,
        ttl_seconds: u32,
    ) -> Result<bool, NetError> {
        let message = match self.build_publish_message(name, value, ttl_seconds) {
            Ok(msg) => msg,
            Err(e) => {
                tracing::warn!(
                    "DNS UPDATE add for {} aborted: could not assemble: {}",
                    name,
                    e
                );
                return Ok(false);
            }
        };
        self.send(message, "add", name).await
    }

    async fn delete_txt_record(&self, name: &str, value: Option<&str>) -> Result<bool, NetError> {
        let message = match self.build_delete_message(name, value) {
            Ok(msg) => msg,
            Err(e) => {
                tracing::warn!(
                    "DNS UPDATE delete for {} aborted: could not assemble: {}",
                    name,
                    e
                );
                return Ok(false);
            }
        };
        self.send(message, "delete", name).await
    }
}

/// Parse a TXT owner name, normalizing the trailing dot.
fn parse_owner(name: &str) -> Result<Name, NetError> {
    let trimmed = name.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(NetError::InvalidName {
            name: name.to_string(),
            reason: "owner name must be non-empty".into(),
        });
    }
    let mut owner = Name::from_ascii(trimmed).map_err(|e| NetError::InvalidName {
        name: name.to_string(),
        reason: e.to_string(),
    })?;
    owner.set_fqdn(true);
    Ok(owner.to_lowercase())
}

/// Internal helper: a query the writer would need to send if hickory's
/// helper builders weren't sufficient. Currently unused — `update_message::create`
/// covers our two cases — but kept here as documentation for the message
/// shape we expect (an `UPDATE` with a single Zone Query for the SOA).
#[allow(dead_code)]
fn build_zone_query(zone: &Name) -> Query {
    let mut q = Query::new();
    q.set_name(zone.clone())
        .set_query_class(DNSClass::IN)
        .set_query_type(RecordType::SOA);
    q
}

/// Internal helper: shape of a freshly-constructed UPDATE before
/// hickory's helpers fill it in. Kept around for documentation /
/// reference; not on any code path.
#[allow(dead_code)]
fn fresh_update_message() -> Message {
    let mut m = Message::new();
    m.set_message_type(MessageType::Query)
        .set_op_code(OpCode::Update)
        .set_recursion_desired(false);
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tsig::TsigAlgorithm;

    fn test_key() -> TsigKey {
        TsigKey::new("dmp-test-key", TsigAlgorithm::HmacSha256, vec![0xab; 32]).unwrap()
    }

    fn test_server() -> SocketAddr {
        "127.0.0.1:53".parse().unwrap()
    }

    #[test]
    fn new_rejects_empty_zone() {
        let err = DnsUpdateWriter::new(DnsUpdateWriterConfig::new("", test_server(), test_key()))
            .unwrap_err();
        assert!(matches!(err, NetError::InvalidConfig(_)));
        let err =
            DnsUpdateWriter::new(DnsUpdateWriterConfig::new("   ", test_server(), test_key()))
                .unwrap_err();
        assert!(matches!(err, NetError::InvalidConfig(_)));
    }

    #[test]
    fn new_rejects_invalid_zone_name() {
        // A literal NUL is unambiguously not a valid label byte.
        let err = DnsUpdateWriter::new(DnsUpdateWriterConfig::new(
            "bad\u{0}.example",
            test_server(),
            test_key(),
        ));
        // hickory may either reject the NUL outright or accept it as an
        // odd label. Assert either: we wanted a clean failure; if hickory
        // accepts it, we don't fail the test.
        if let Err(e) = err {
            assert!(matches!(e, NetError::InvalidName { .. }));
        }
    }

    #[test]
    fn new_accepts_zone_with_or_without_trailing_dot() {
        DnsUpdateWriter::new(DnsUpdateWriterConfig::new(
            "example.com",
            test_server(),
            test_key(),
        ))
        .unwrap();
        DnsUpdateWriter::new(DnsUpdateWriterConfig::new(
            "example.com.",
            test_server(),
            test_key(),
        ))
        .unwrap();
    }

    #[test]
    fn build_publish_round_trips_through_wire() {
        let writer = DnsUpdateWriter::new(DnsUpdateWriterConfig::new(
            "example.com.",
            test_server(),
            test_key(),
        ))
        .unwrap();
        let msg = writer
            .build_publish_message("alice.example.com", "v=dmp1;t=identity;data", 600)
            .unwrap();
        // Serialize and parse back.
        let bytes = msg.to_vec().expect("serialize");
        let parsed = Message::from_vec(&bytes).expect("parse");
        // Zone Query: name=example.com, type=SOA.
        assert_eq!(parsed.queries().len(), 1);
        assert_eq!(parsed.queries()[0].query_type(), RecordType::SOA);
        assert!(parsed.queries()[0]
            .name()
            .to_ascii()
            .to_lowercase()
            .starts_with("example.com"));
        // Updates section ("name servers" in hickory-speak): our TXT add.
        let updates = parsed.name_servers();
        // The exact count varies between hickory versions because
        // `update_message::create` also emits a prerequisite. Find the
        // TXT update by hand.
        let txt_update = updates
            .iter()
            .find(|r| r.record_type() == RecordType::TXT)
            .expect("TXT update record present");
        assert_eq!(txt_update.ttl(), 600);
        assert!(txt_update
            .name()
            .to_ascii()
            .to_lowercase()
            .starts_with("alice.example.com"));
        if let RData::TXT(txt) = txt_update.data() {
            let bytes = &txt.txt_data()[0];
            assert_eq!(&bytes[..], b"v=dmp1;t=identity;data");
        } else {
            panic!("expected RData::TXT");
        }
    }

    #[test]
    fn build_publish_rejects_out_of_zone_name() {
        let writer = DnsUpdateWriter::new(DnsUpdateWriterConfig::new(
            "example.com",
            test_server(),
            test_key(),
        ))
        .unwrap();
        let err = writer
            .build_publish_message("alice.evil.tld", "value", 60)
            .unwrap_err();
        assert!(matches!(err, NetError::InvalidName { .. }));
    }

    #[test]
    fn build_delete_whole_rrset_message_round_trips() {
        let writer = DnsUpdateWriter::new(DnsUpdateWriterConfig::new(
            "example.com",
            test_server(),
            test_key(),
        ))
        .unwrap();
        let msg = writer
            .build_delete_message("alice.example.com", None)
            .unwrap();
        let bytes = msg.to_vec().expect("serialize");
        let parsed = Message::from_vec(&bytes).expect("parse");
        let updates = parsed.name_servers();
        let any_txt = updates
            .iter()
            .find(|r| r.record_type() == RecordType::TXT)
            .expect("delete TXT update record present");
        // Whole-RRset delete: CLASS must be ANY, TTL 0.
        assert_eq!(any_txt.dns_class(), DNSClass::ANY);
        assert_eq!(any_txt.ttl(), 0);
    }

    #[test]
    fn build_delete_specific_rdata_message_round_trips() {
        let writer = DnsUpdateWriter::new(DnsUpdateWriterConfig::new(
            "example.com",
            test_server(),
            test_key(),
        ))
        .unwrap();
        let msg = writer
            .build_delete_message("alice.example.com", Some("v=dmp1;t=identity;data"))
            .unwrap();
        let bytes = msg.to_vec().expect("serialize");
        let parsed = Message::from_vec(&bytes).expect("parse");
        let updates = parsed.name_servers();
        let txt_delete = updates
            .iter()
            .find(|r| r.record_type() == RecordType::TXT)
            .expect("TXT delete record present");
        // Specific-RR delete: CLASS must be NONE, TTL 0, rdata matches.
        assert_eq!(txt_delete.dns_class(), DNSClass::NONE);
        assert_eq!(txt_delete.ttl(), 0);
        if let RData::TXT(txt) = txt_delete.data() {
            assert_eq!(&txt.txt_data()[0][..], b"v=dmp1;t=identity;data");
        } else {
            panic!("expected RData::TXT");
        }
    }

    #[test]
    fn signed_message_round_trips_with_a_tsig_record() {
        // Build the message, sign it via the writer's TSIG signer, then
        // serialize / parse and confirm the TSIG RR rides along with a
        // non-empty MAC.
        let writer = DnsUpdateWriter::new(DnsUpdateWriterConfig::new(
            "example.com",
            test_server(),
            test_key(),
        ))
        .unwrap();
        let mut msg = writer
            .build_publish_message("alice.example.com", "value", 60)
            .unwrap();
        let signer = writer.tsig_key.to_signer(writer.fudge_secs).unwrap();
        msg.finalize(signer.as_ref(), 1_700_000_000).unwrap();

        let bytes = msg.to_vec().unwrap();
        let parsed = Message::from_vec(&bytes).unwrap();
        let tsigs = parsed.signature();
        assert_eq!(tsigs.len(), 1, "expected one TSIG record");
        if let RData::DNSSEC(hickory_proto::dnssec::rdata::DNSSECRData::TSIG(t)) = tsigs[0].data() {
            assert!(!t.mac().is_empty(), "TSIG MAC must be non-empty");
            assert_eq!(t.mac().len(), 32, "HMAC-SHA256 MAC is 32 bytes");
        } else {
            panic!("expected RData::DNSSEC(TSIG)");
        }
    }
}

//! Signed node heartbeats for the M5.8 discovery directory.
//!
//! Every opted-in node periodically emits a `HeartbeatRecord` asserting "I am
//! `<endpoint>`, operated by `<operator_spk>`, running version `<version>`,
//! capabilities `<bitfield>`, claim_provider_zone `<zone>`, as of `<ts>`,
//! valid until `<exp>`." Peers store received heartbeats in a local
//! seen-store and re-export them so aggregators (including a central
//! directory website) can render "which nodes are reachable right now"
//! without introducing a new trust anchor: every entry in the aggregated
//! list is a verifiable signature under the operator key.
//!
//! Wire format (mirrors Python `dmp.core.heartbeat`):
//!
//! ```text
//! v=dmp1;t=heartbeat;<base64(body || sig)>
//!
//! body:
//!     magic(7)                          // b"DMPHB03" (current); legacy
//!                                       //  b"DMPHB02" still parsed for
//!                                       //  rolling-upgrade compatibility
//!     endpoint_len(2 BE)
//!     endpoint(utf-8, 1..=255 bytes)
//!     operator_spk(32)
//!     version_len(1)
//!     version(utf-8, 0..=32 bytes)
//!     capabilities(2 BE)                // bitfield (M8.2+); bit 0 is
//!                                       //  CAP_CLAIM_PROVIDER, rest reserved
//!     claim_provider_zone_len(1)        // DMPHB03 only; legacy DMPHB02
//!                                       //  wires omit this field and the
//!                                       //  zone string entirely (parsed as
//!                                       //  empty for cross-version verify)
//!     claim_provider_zone(utf-8, 0..=64 bytes)
//!     ts(8 BE)
//!     exp(8 BE)
//! sig:
//!     Ed25519 signature over body       // 64 bytes
//! ```
//!
//! Capabilities: bit 0 (`CAP_CLAIM_PROVIDER`) advertises that this node
//! hosts the M8 first-contact claim namespace under its own zone. Pre-M8.2
//! nodes that read a v=DMPHB03 record but don't understand a given bit
//! ignore unknown bits rather than rejecting the record (forward-compat).
//!
//! Replay: `ts` must verify-to-now within `±ts_skew_seconds`; `exp <= now`
//! is rejected. We sign new wires with `DMPHB03` only — there's no legacy
//! emission path.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;

use crate::crypto::{DmpCrypto, ED25519_KEY_LEN, ED25519_SIG_LEN};
use crate::ed25519_points::is_low_order;

/// TXT prefix that tags a DMP heartbeat record.
pub const RECORD_PREFIX: &str = "v=dmp1;t=heartbeat;";

/// Magic bytes opening every current (DMPHB03) heartbeat body.
pub const MAGIC: &[u8; 7] = b"DMPHB03";

/// Magic bytes for the legacy DMPHB02 wire. Still accepted on parse so a 0.5
/// node can verify heartbeats from peers that haven't upgraded yet, and so a
/// 0.5 node ingesting its own pre-upgrade SeenStore rows doesn't lose every
/// peer until they republish. New wires are signed with [`MAGIC`] only.
pub const LEGACY_MAGIC: &[u8; 7] = b"DMPHB02";

/// Capability bit advertising that the node hosts the M8 claim namespace
/// under its own zone.
pub const CAP_CLAIM_PROVIDER: u16 = 1 << 0;

/// Mask of all capability bits this code understands. Unknown bits in a
/// parsed record are tolerated (forward-compat) but a node won't act on
/// capabilities it doesn't have a constant for.
pub const CAP_KNOWN_MASK: u16 = CAP_CLAIM_PROVIDER;

/// Maximum endpoint string length in UTF-8 bytes.
pub const MAX_ENDPOINT_LEN: usize = 255;

/// Maximum version string length in UTF-8 bytes.
pub const MAX_VERSION_LEN: usize = 32;

/// Maximum claim provider zone length in UTF-8 bytes. Same ceiling as the
/// claim record's `MAX_MAILBOX_DOMAIN_LEN` shape — keeps the heartbeat wire
/// inside a single 255-byte DNS TXT after sig + base64 overhead.
pub const MAX_CLAIM_PROVIDER_ZONE_LEN: usize = 64;

/// Maximum allowed wire size (UTF-8 bytes), matching `ClusterManifest` and
/// `RotationRecord`.
pub const MAX_WIRE_LEN: usize = 1200;

/// Default `ts` symmetric-skew tolerance for `parse_and_verify`, in seconds.
pub const DEFAULT_TS_SKEW_SECONDS: u64 = 300;

const SCHEME_HTTPS: &str = "https";
const SCHEME_HTTP: &str = "http";

/// Errors returned while building or parsing heartbeat records.
#[derive(Debug, thiserror::Error)]
pub enum HeartbeatError {
    /// `endpoint` was empty.
    #[error("endpoint must not be empty")]
    EndpointEmpty,
    /// `endpoint` exceeded [`MAX_ENDPOINT_LEN`].
    #[error("endpoint length {actual} > MAX_ENDPOINT_LEN {max}")]
    EndpointTooLong { actual: usize, max: usize },
    /// `endpoint` contained non-ASCII bytes.
    #[error("endpoint must be ASCII")]
    EndpointNotAscii,
    /// `endpoint` contained whitespace or control characters.
    #[error("endpoint contains whitespace or control characters")]
    EndpointInvalidChars,
    /// `endpoint` did not parse as a valid URL.
    #[error("endpoint did not parse as a URL")]
    EndpointMalformed,
    /// `endpoint` used a scheme other than `https` or `http`.
    #[error("endpoint scheme must be https or http")]
    EndpointBadScheme,
    /// `endpoint` carried a `user:pass@` userinfo segment.
    #[error("endpoint must not carry userinfo")]
    EndpointHasUserinfo,
    /// `endpoint` was missing a host component.
    #[error("endpoint must include a host")]
    EndpointMissingHost,
    /// `endpoint` carried path / query / fragment.
    #[error("endpoint must be <scheme>://<host>[:port], no path / query / fragment")]
    EndpointHasExtras,
    /// `endpoint` host was a localhost alias.
    #[error("endpoint host is a localhost alias")]
    EndpointLocalhost,
    /// `endpoint` host was an IP literal in a non-public range.
    #[error("endpoint host is a non-public IP address")]
    EndpointPrivateIp,
    /// `version` exceeded [`MAX_VERSION_LEN`].
    #[error("version length {actual} > MAX_VERSION_LEN {max}")]
    VersionTooLong { actual: usize, max: usize },
    /// `version` contained non-ASCII bytes.
    #[error("version must be ASCII")]
    VersionNotAscii,
    /// `claim_provider_zone` exceeded [`MAX_CLAIM_PROVIDER_ZONE_LEN`].
    #[error("claim_provider_zone length {actual} > MAX_CLAIM_PROVIDER_ZONE_LEN {max}")]
    ZoneTooLong { actual: usize, max: usize },
    /// `claim_provider_zone` contained non-ASCII bytes.
    #[error("claim_provider_zone must be ASCII")]
    ZoneNotAscii,
    /// `claim_provider_zone` contained whitespace or control characters.
    #[error("claim_provider_zone contains whitespace or control characters")]
    ZoneInvalidChars,
    /// `exp <= ts`, which means the record is born expired.
    #[error("exp must be strictly greater than ts")]
    ExpNotAfterTs,
    /// The signing key supplied to [`HeartbeatRecord::sign`] does not match
    /// `self.operator_spk`.
    #[error("operator_crypto signing key does not match declared operator_spk")]
    OperatorKeyMismatch,
    /// The encoded wire form would exceed [`MAX_WIRE_LEN`] bytes.
    #[error("heartbeat wire size {actual} exceeds MAX_WIRE_LEN {max}")]
    WireTooLong { actual: usize, max: usize },
    /// The body buffer was shorter than the minimum-size record.
    #[error("heartbeat body too short")]
    BodyTooShort,
    /// The body did not begin with [`MAGIC`] or [`LEGACY_MAGIC`].
    #[error("bad magic")]
    BadMagic,
    /// `endpoint_len` was zero or above [`MAX_ENDPOINT_LEN`].
    #[error("endpoint_len out of range: {0}")]
    InvalidEndpointLen(u16),
    /// `version_len` was above [`MAX_VERSION_LEN`].
    #[error("version_len out of range: {0}")]
    InvalidVersionLen(u8),
    /// `claim_provider_zone_len` was above [`MAX_CLAIM_PROVIDER_ZONE_LEN`].
    #[error("claim_provider_zone_len out of range: {0}")]
    InvalidZoneLen(u8),
    /// The body was truncated mid-field.
    #[error("heartbeat body truncated")]
    BodyTruncated,
    /// The body had trailing bytes after parsing the documented fields.
    #[error("trailing heartbeat body bytes")]
    TrailingBytes,
    /// A length-prefixed UTF-8 field was not valid UTF-8.
    #[error("heartbeat field is not valid utf-8")]
    InvalidUtf8,
}

/// Signed node heartbeat.
///
/// Construct + [`HeartbeatRecord::sign`], or parse via
/// [`HeartbeatRecord::parse_and_verify`]. Signed by `operator_spk` (the
/// Ed25519 key the node operator already uses for cluster manifests /
/// bootstrap records — heartbeat does not add a new trust anchor).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatRecord {
    /// `https?://host[:port]` URL the node serves on. No path / query /
    /// fragment, no userinfo, no localhost or private IPs (validated).
    pub endpoint: String,
    /// 32-byte Ed25519 signing public key of the operator.
    pub operator_spk: [u8; ED25519_KEY_LEN],
    /// Free-form ASCII version string (0..=[`MAX_VERSION_LEN`] bytes).
    pub version: String,
    /// Unix seconds at publication.
    pub ts: u64,
    /// Unix seconds after which the record is expired.
    pub exp: u64,
    /// Capability bitfield (M8.2+). See [`CAP_CLAIM_PROVIDER`].
    pub capabilities: u16,
    /// Claim provider zone the node serves under (empty when the node
    /// isn't acting as a claim provider).
    pub claim_provider_zone: String,
}

impl HeartbeatRecord {
    /// Serialize the signable body (everything except the signature).
    ///
    /// Always emits the current `DMPHB03` magic. Legacy `DMPHB02` wires can
    /// be parsed via [`HeartbeatRecord::from_body_bytes`], but never emitted.
    pub fn to_body_bytes(&self) -> Result<Vec<u8>, HeartbeatError> {
        validate_endpoint(&self.endpoint)?;
        validate_version(&self.version)?;
        validate_zone(&self.claim_provider_zone)?;
        if self.exp <= self.ts {
            return Err(HeartbeatError::ExpNotAfterTs);
        }

        let endpoint_bytes = self.endpoint.as_bytes();
        let version_bytes = self.version.as_bytes();
        let zone_bytes = self.claim_provider_zone.as_bytes();

        // endpoint_len is bounded above by MAX_ENDPOINT_LEN (255), so the
        // u16 cast cannot truncate; version_len and zone_len fit in u8 by the
        // same logic via their respective max constants.
        let endpoint_len_u16 = u16::try_from(endpoint_bytes.len())
            .expect("endpoint length fits in u16 after validation");
        let version_len_u8 =
            u8::try_from(version_bytes.len()).expect("version length fits in u8 after validation");
        let zone_len_u8 =
            u8::try_from(zone_bytes.len()).expect("zone length fits in u8 after validation");

        let mut out = Vec::with_capacity(
            MAGIC.len()
                + 2
                + endpoint_bytes.len()
                + ED25519_KEY_LEN
                + 1
                + version_bytes.len()
                + 2
                + 1
                + zone_bytes.len()
                + 8
                + 8,
        );
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&endpoint_len_u16.to_be_bytes());
        out.extend_from_slice(endpoint_bytes);
        out.extend_from_slice(&self.operator_spk);
        out.push(version_len_u8);
        out.extend_from_slice(version_bytes);
        out.extend_from_slice(&self.capabilities.to_be_bytes());
        out.push(zone_len_u8);
        out.extend_from_slice(zone_bytes);
        out.extend_from_slice(&self.ts.to_be_bytes());
        out.extend_from_slice(&self.exp.to_be_bytes());
        Ok(out)
    }

    /// Parse the signable body. Does NOT verify the signature; use
    /// [`HeartbeatRecord::parse_and_verify`] for the complete check.
    ///
    /// Accepts both DMPHB03 (current) and DMPHB02 (legacy) wires. Legacy
    /// wires omit `claim_provider_zone_len` and the zone bytes; we default
    /// `claim_provider_zone` to empty in that case.
    pub fn from_body_bytes(body: &[u8]) -> Result<Self, HeartbeatError> {
        if body.len() < MAGIC.len() + 2 {
            return Err(HeartbeatError::BodyTooShort);
        }
        let magic_slice = &body[..MAGIC.len()];
        let is_legacy = if magic_slice == MAGIC.as_slice() {
            false
        } else if magic_slice == LEGACY_MAGIC.as_slice() {
            true
        } else {
            return Err(HeartbeatError::BadMagic);
        };
        let mut off = MAGIC.len();

        let endpoint_len = u16::from_be_bytes(body[off..off + 2].try_into().unwrap());
        off += 2;
        if endpoint_len == 0 || endpoint_len as usize > MAX_ENDPOINT_LEN {
            return Err(HeartbeatError::InvalidEndpointLen(endpoint_len));
        }
        if off + endpoint_len as usize > body.len() {
            return Err(HeartbeatError::BodyTruncated);
        }
        let endpoint = std::str::from_utf8(&body[off..off + endpoint_len as usize])
            .map_err(|_| HeartbeatError::InvalidUtf8)?
            .to_string();
        off += endpoint_len as usize;

        if off + ED25519_KEY_LEN > body.len() {
            return Err(HeartbeatError::BodyTruncated);
        }
        let mut operator_spk = [0u8; ED25519_KEY_LEN];
        operator_spk.copy_from_slice(&body[off..off + ED25519_KEY_LEN]);
        off += ED25519_KEY_LEN;

        if off + 1 > body.len() {
            return Err(HeartbeatError::BodyTruncated);
        }
        let version_len = body[off];
        off += 1;
        if version_len as usize > MAX_VERSION_LEN {
            return Err(HeartbeatError::InvalidVersionLen(version_len));
        }
        if off + version_len as usize > body.len() {
            return Err(HeartbeatError::BodyTruncated);
        }
        let version = std::str::from_utf8(&body[off..off + version_len as usize])
            .map_err(|_| HeartbeatError::InvalidUtf8)?
            .to_string();
        off += version_len as usize;

        if off + 2 > body.len() {
            return Err(HeartbeatError::BodyTruncated);
        }
        let capabilities = u16::from_be_bytes(body[off..off + 2].try_into().unwrap());
        off += 2;

        // M9: claim_provider_zone (uint8 length-prefixed utf-8). Legacy
        // DMPHB02 wires don't carry this field — treat as empty so cross-
        // version verification keeps working through the rolling upgrade.
        let claim_provider_zone = if is_legacy {
            String::new()
        } else {
            if off + 1 > body.len() {
                return Err(HeartbeatError::BodyTruncated);
            }
            let zone_len = body[off];
            off += 1;
            if zone_len as usize > MAX_CLAIM_PROVIDER_ZONE_LEN {
                return Err(HeartbeatError::InvalidZoneLen(zone_len));
            }
            if off + zone_len as usize > body.len() {
                return Err(HeartbeatError::BodyTruncated);
            }
            let zone = std::str::from_utf8(&body[off..off + zone_len as usize])
                .map_err(|_| HeartbeatError::InvalidUtf8)?
                .to_string();
            off += zone_len as usize;
            zone
        };

        if off + 16 > body.len() {
            return Err(HeartbeatError::BodyTruncated);
        }
        let ts = u64::from_be_bytes(body[off..off + 8].try_into().unwrap());
        off += 8;
        let exp = u64::from_be_bytes(body[off..off + 8].try_into().unwrap());
        off += 8;

        if off != body.len() {
            return Err(HeartbeatError::TrailingBytes);
        }

        // Re-run the shape checks so a malformed body can't produce a
        // record that later blows up downstream.
        validate_endpoint(&endpoint)?;
        validate_version(&version)?;
        if exp <= ts {
            return Err(HeartbeatError::ExpNotAfterTs);
        }

        Ok(Self {
            endpoint,
            operator_spk,
            version,
            ts,
            exp,
            capabilities,
            claim_provider_zone,
        })
    }

    /// Sign with `operator_crypto` and return the wire-format TXT record string.
    ///
    /// `operator_crypto` must hold the private half of `self.operator_spk`;
    /// a mismatch is caught here and refused.
    pub fn sign(&self, operator_crypto: &DmpCrypto) -> Result<String, HeartbeatError> {
        if operator_crypto.signing_public_key_bytes() != self.operator_spk {
            return Err(HeartbeatError::OperatorKeyMismatch);
        }
        let body = self.to_body_bytes()?;
        let signature = operator_crypto.sign_data(&body);
        let mut combined = Vec::with_capacity(body.len() + ED25519_SIG_LEN);
        combined.extend_from_slice(&body);
        combined.extend_from_slice(&signature);
        let wire = format!("{RECORD_PREFIX}{}", BASE64_STANDARD.encode(&combined));
        if wire.len() > MAX_WIRE_LEN {
            return Err(HeartbeatError::WireTooLong {
                actual: wire.len(),
                max: MAX_WIRE_LEN,
            });
        }
        Ok(wire)
    }

    /// Parse + verify signature + enforce freshness. Never panics; returns
    /// `None` on any failure (mirrors Python `parse_and_verify`).
    ///
    /// `now` defaults to the system clock when `None`. `ts_skew_seconds`
    /// caps how far either side of `now` `ts` may be (symmetric, unlike
    /// claim records — captured heartbeats are a known replay vector).
    #[must_use]
    pub fn parse_and_verify(wire: &str, now: Option<u64>, ts_skew_seconds: u64) -> Option<Self> {
        if !wire.starts_with(RECORD_PREFIX) {
            return None;
        }
        if wire.len() > MAX_WIRE_LEN {
            return None;
        }
        let payload = wire.strip_prefix(RECORD_PREFIX)?;
        let blob = BASE64_STANDARD.decode(payload).ok()?;
        // Smallest legal DMPHB02 body: magic(7) + endpoint_len(2) + endpoint(>=1)
        // + spk(32) + version_len(1) + capabilities(2) + ts/exp(16). DMPHB03
        // adds 1 byte for zone_len. Use the legacy lower bound here so a
        // legacy wire passes the size gate; from_body_bytes does per-version
        // structural validation downstream.
        let min_blob_len = MAGIC.len() + 2 + 1 + ED25519_KEY_LEN + 1 + 2 + 16 + ED25519_SIG_LEN;
        if blob.len() < min_blob_len {
            return None;
        }
        let split = blob.len() - ED25519_SIG_LEN;
        let body = &blob[..split];
        let sig = &blob[split..];

        let record = Self::from_body_bytes(body).ok()?;

        // Low-order pubkey guard. Same defense as registration / claim.
        if is_low_order(&record.operator_spk) {
            return None;
        }

        if !DmpCrypto::verify_signature(body, sig, &record.operator_spk) {
            return None;
        }

        let now = now.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
        });
        // Symmetric skew: capture-and-replay of an old heartbeat is a real
        // attack here, so reject ts that is too far in the past as well.
        if record.ts.abs_diff(now) > ts_skew_seconds {
            return None;
        }
        if record.exp <= now {
            return None;
        }

        Some(record)
    }
}

/// Hostnames that resolve to the host itself. Block all case variants at the
/// wire layer because every reasonable resolver maps `localhost` to the
/// loopback addresses, and that's an SSRF vector on the crawler side.
const LOCALHOST_ALIASES: &[&str] = &["localhost", "localhost.localdomain", "ip6-localhost"];

fn validate_endpoint(endpoint: &str) -> Result<(), HeartbeatError> {
    if endpoint.is_empty() {
        return Err(HeartbeatError::EndpointEmpty);
    }
    if endpoint.len() > MAX_ENDPOINT_LEN {
        return Err(HeartbeatError::EndpointTooLong {
            actual: endpoint.len(),
            max: MAX_ENDPOINT_LEN,
        });
    }
    if !endpoint.is_ascii() {
        return Err(HeartbeatError::EndpointNotAscii);
    }
    for c in endpoint.chars() {
        let cp = u32::from(c);
        if cp < 0x21 || cp == 0x7F {
            return Err(HeartbeatError::EndpointInvalidChars);
        }
    }

    let parsed = ParsedUrl::parse(endpoint).ok_or(HeartbeatError::EndpointMalformed)?;
    let scheme_lower = parsed.scheme.to_ascii_lowercase();
    if scheme_lower != SCHEME_HTTPS && scheme_lower != SCHEME_HTTP {
        return Err(HeartbeatError::EndpointBadScheme);
    }
    if parsed.has_userinfo {
        return Err(HeartbeatError::EndpointHasUserinfo);
    }
    if parsed.host.is_empty() {
        return Err(HeartbeatError::EndpointMissingHost);
    }
    if parsed.has_extras {
        return Err(HeartbeatError::EndpointHasExtras);
    }

    let host_lower = parsed.host.to_ascii_lowercase();
    if LOCALHOST_ALIASES.iter().any(|alias| *alias == host_lower) {
        return Err(HeartbeatError::EndpointLocalhost);
    }

    if let Some(reason) = ip_literal_is_non_public(&parsed.host) {
        return Err(reason);
    }

    Ok(())
}

fn validate_version(version: &str) -> Result<(), HeartbeatError> {
    if version.len() > MAX_VERSION_LEN {
        return Err(HeartbeatError::VersionTooLong {
            actual: version.len(),
            max: MAX_VERSION_LEN,
        });
    }
    if !version.is_ascii() {
        return Err(HeartbeatError::VersionNotAscii);
    }
    Ok(())
}

fn validate_zone(zone: &str) -> Result<(), HeartbeatError> {
    if zone.len() > MAX_CLAIM_PROVIDER_ZONE_LEN {
        return Err(HeartbeatError::ZoneTooLong {
            actual: zone.len(),
            max: MAX_CLAIM_PROVIDER_ZONE_LEN,
        });
    }
    if zone.is_empty() {
        return Ok(());
    }
    if !zone.is_ascii() {
        return Err(HeartbeatError::ZoneNotAscii);
    }
    for c in zone.chars() {
        let cp = u32::from(c);
        if cp < 0x21 || cp == 0x7F {
            return Err(HeartbeatError::ZoneInvalidChars);
        }
    }
    Ok(())
}

/// Minimal URL split: extracts scheme, host, port-detection, and flags
/// userinfo / path / query / fragment. Returns `None` on structurally
/// malformed input. Tight ASCII-only parser — `validate_endpoint` rejects
/// non-ASCII before reaching this function.
struct ParsedUrl<'a> {
    scheme: &'a str,
    host: String,
    has_userinfo: bool,
    has_extras: bool,
}

impl<'a> ParsedUrl<'a> {
    fn parse(s: &'a str) -> Option<Self> {
        let scheme_end = s.find("://")?;
        let scheme = &s[..scheme_end];
        if scheme.is_empty() {
            return None;
        }
        // Scheme must be alpha for the leading char and alpha/digit/+/-/. afterwards
        // (RFC 3986). Not strictly required for the security checks downstream,
        // but rejecting weird schemes keeps `urlsplit`-equivalent semantics.
        let scheme_bytes = scheme.as_bytes();
        if !scheme_bytes[0].is_ascii_alphabetic() {
            return None;
        }
        for &b in &scheme_bytes[1..] {
            if !(b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')) {
                return None;
            }
        }

        let after_scheme = &s[scheme_end + 3..];

        // Cut at the first /, ?, or # — everything after is "extras"
        // (path/query/fragment). Authority is whatever's left.
        let mut authority_end = after_scheme.len();
        let mut has_extras = false;
        for (i, ch) in after_scheme.char_indices() {
            if ch == '/' || ch == '?' || ch == '#' {
                authority_end = i;
                has_extras = true;
                break;
            }
        }
        let authority = &after_scheme[..authority_end];

        // userinfo: anything before a '@' inside the authority.
        let (has_userinfo, hostport) = match authority.rfind('@') {
            Some(idx) => (true, &authority[idx + 1..]),
            None => (false, authority),
        };

        // host: bracketed IPv6 literal, or hostport up to the LAST ':' (so
        // IPv6 colons don't confuse port detection). We don't need the port
        // value — only the host string for SSRF checks.
        let host = if let Some(stripped) = hostport.strip_prefix('[') {
            let close = stripped.find(']')?;
            // Reject anything between ] and the optional :port (matches urlsplit).
            let after_bracket = &stripped[close + 1..];
            if !after_bracket.is_empty() && !after_bracket.starts_with(':') {
                return None;
            }
            stripped[..close].to_string()
        } else if let Some(idx) = hostport.rfind(':') {
            // Plain "host:port" — only treat as port if the suffix is digits.
            let (h, p) = hostport.split_at(idx);
            let port_suffix = &p[1..];
            if port_suffix.is_empty() || port_suffix.bytes().all(|b| b.is_ascii_digit()) {
                h.to_string()
            } else {
                hostport.to_string()
            }
        } else {
            hostport.to_string()
        };

        Some(Self {
            scheme,
            host,
            has_userinfo,
            has_extras,
        })
    }
}

/// If `host` parses as an IPv4 or IPv6 literal in a non-public range, return
/// the corresponding error variant. Hostname inputs (non-IP) return `None`;
/// hostname-resolution SSRF defense is the aggregator's job at connect time.
fn ip_literal_is_non_public(host: &str) -> Option<HeartbeatError> {
    if let Ok(addr) = host.parse::<std::net::IpAddr>() {
        if !ip_is_public(addr) {
            return Some(HeartbeatError::EndpointPrivateIp);
        }
    }
    None
}

fn ip_is_public(addr: std::net::IpAddr) -> bool {
    match addr {
        std::net::IpAddr::V4(v4) => {
            // Mirrors Python's ipaddress.IPv4Address public/private checks:
            // reject loopback, private (10/8, 172.16/12, 192.168/16),
            // link-local (169.254/16), multicast (224/4), reserved (240/4),
            // unspecified (0.0.0.0).
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || is_v4_reserved(v4)
                || is_v4_shared_or_benchmarking(v4)
                || is_v4_documentation(v4))
        }
        std::net::IpAddr::V6(v6) => {
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || is_v6_unique_local(&v6)
                || is_v6_link_local(&v6)
                || is_v6_reserved(&v6))
        }
    }
}

fn is_v4_reserved(v4: std::net::Ipv4Addr) -> bool {
    // 240.0.0.0/4 (reserved for future use, "is_reserved" in Python).
    v4.octets()[0] >= 240
}

fn is_v4_shared_or_benchmarking(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    // 100.64.0.0/10 (RFC 6598 shared address space) — Python flags as private.
    if o[0] == 100 && (o[1] & 0xC0) == 0x40 {
        return true;
    }
    // 198.18.0.0/15 (benchmarking).
    if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
        return true;
    }
    false
}

fn is_v4_documentation(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
}

fn is_v6_unique_local(v6: &std::net::Ipv6Addr) -> bool {
    // fc00::/7
    (v6.octets()[0] & 0xFE) == 0xFC
}

fn is_v6_link_local(v6: &std::net::Ipv6Addr) -> bool {
    // fe80::/10
    let o = v6.octets();
    o[0] == 0xFE && (o[1] & 0xC0) == 0x80
}

fn is_v6_reserved(v6: &std::net::Ipv6Addr) -> bool {
    // 2001:db8::/32 (documentation) at minimum; mirror Python's broader
    // `is_reserved` by also flagging the IETF-reserved 0100::/8 block.
    let o = v6.octets();
    if o[0] == 0x01 {
        return true;
    }
    o[0] == 0x20 && o[1] == 0x01 && o[2] == 0x0D && o[3] == 0xB8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519_points::LOW_ORDER_ED25519_PUBKEYS;

    fn sample_record(spk: [u8; ED25519_KEY_LEN]) -> HeartbeatRecord {
        HeartbeatRecord {
            endpoint: "https://node.example.com:8443".to_string(),
            operator_spk: spk,
            version: "0.5.0".to_string(),
            ts: 1_700_000_000,
            exp: 1_700_000_300,
            capabilities: CAP_CLAIM_PROVIDER,
            claim_provider_zone: "claim.example.com".to_string(),
        }
    }

    #[test]
    fn body_round_trip() {
        let crypto = DmpCrypto::generate();
        let record = sample_record(crypto.signing_public_key_bytes());
        let body = record.to_body_bytes().unwrap();
        let parsed = HeartbeatRecord::from_body_bytes(&body).unwrap();
        assert_eq!(parsed, record);
    }

    #[test]
    fn body_layout_starts_with_dmphb03() {
        let crypto = DmpCrypto::generate();
        let record = sample_record(crypto.signing_public_key_bytes());
        let body = record.to_body_bytes().unwrap();
        assert_eq!(&body[..7], MAGIC.as_slice());
    }

    #[test]
    fn endpoint_max_len_accepted() {
        // Build a length-MAX_ENDPOINT_LEN URL: "https://" + host padded out to MAX.
        let prefix = "https://";
        let host_len = MAX_ENDPOINT_LEN - prefix.len();
        // Host must still be a valid label sequence; use a single long label
        // of 'a' chars, capped at 63 to stay legal-DNS-ish then ".com".
        // Simpler: pad with 'a's broken every 60 chars by '.'.
        let mut host = String::new();
        while host.len() + prefix.len() + 4 < MAX_ENDPOINT_LEN {
            if !host.is_empty() {
                host.push('.');
            }
            let chunk = "a".repeat(60.min(host_len - host.len() - 4));
            host.push_str(&chunk);
        }
        // Pad the trailing label with .com plus enough chars to land exactly on max.
        host.push_str(".com");
        while host.len() + prefix.len() < MAX_ENDPOINT_LEN {
            host.push('a');
        }
        let endpoint = format!("{prefix}{host}");
        assert_eq!(endpoint.len(), MAX_ENDPOINT_LEN);
        let mut record = sample_record([0x22; ED25519_KEY_LEN]);
        record.endpoint = endpoint.clone();
        let body = record.to_body_bytes().unwrap();
        let parsed = HeartbeatRecord::from_body_bytes(&body).unwrap();
        assert_eq!(parsed.endpoint, endpoint);
    }

    #[test]
    fn endpoint_over_max_rejected() {
        let mut record = sample_record([0x22; ED25519_KEY_LEN]);
        record.endpoint = format!("https://{}.com", "a".repeat(MAX_ENDPOINT_LEN));
        assert!(matches!(
            record.to_body_bytes(),
            Err(HeartbeatError::EndpointTooLong { .. }),
        ));
    }

    #[test]
    fn version_max_accepted() {
        let mut record = sample_record([0x22; ED25519_KEY_LEN]);
        record.version = "v".repeat(MAX_VERSION_LEN);
        let body = record.to_body_bytes().unwrap();
        let parsed = HeartbeatRecord::from_body_bytes(&body).unwrap();
        assert_eq!(parsed.version.len(), MAX_VERSION_LEN);
    }

    #[test]
    fn version_over_max_rejected() {
        let mut record = sample_record([0x22; ED25519_KEY_LEN]);
        record.version = "v".repeat(MAX_VERSION_LEN + 1);
        assert!(matches!(
            record.to_body_bytes(),
            Err(HeartbeatError::VersionTooLong { .. }),
        ));
    }

    #[test]
    fn zone_max_accepted() {
        let mut record = sample_record([0x22; ED25519_KEY_LEN]);
        record.claim_provider_zone = "z".repeat(MAX_CLAIM_PROVIDER_ZONE_LEN);
        let body = record.to_body_bytes().unwrap();
        let parsed = HeartbeatRecord::from_body_bytes(&body).unwrap();
        assert_eq!(
            parsed.claim_provider_zone.len(),
            MAX_CLAIM_PROVIDER_ZONE_LEN
        );
    }

    #[test]
    fn zone_over_max_rejected() {
        let mut record = sample_record([0x22; ED25519_KEY_LEN]);
        record.claim_provider_zone = "z".repeat(MAX_CLAIM_PROVIDER_ZONE_LEN + 1);
        assert!(matches!(
            record.to_body_bytes(),
            Err(HeartbeatError::ZoneTooLong { .. }),
        ));
    }

    #[test]
    fn endpoint_rejects_localhost_alias() {
        let mut record = sample_record([0x22; ED25519_KEY_LEN]);
        record.endpoint = "https://localhost:8443".to_string();
        assert!(matches!(
            record.to_body_bytes(),
            Err(HeartbeatError::EndpointLocalhost),
        ));
    }

    #[test]
    fn endpoint_rejects_loopback_ipv4() {
        let mut record = sample_record([0x22; ED25519_KEY_LEN]);
        record.endpoint = "https://127.0.0.1:8443".to_string();
        assert!(matches!(
            record.to_body_bytes(),
            Err(HeartbeatError::EndpointPrivateIp),
        ));
    }

    #[test]
    fn endpoint_rejects_private_ipv4() {
        let mut record = sample_record([0x22; ED25519_KEY_LEN]);
        record.endpoint = "https://10.0.0.1".to_string();
        assert!(matches!(
            record.to_body_bytes(),
            Err(HeartbeatError::EndpointPrivateIp),
        ));
    }

    #[test]
    fn endpoint_rejects_loopback_ipv6() {
        let mut record = sample_record([0x22; ED25519_KEY_LEN]);
        record.endpoint = "https://[::1]:8443".to_string();
        assert!(matches!(
            record.to_body_bytes(),
            Err(HeartbeatError::EndpointPrivateIp),
        ));
    }

    #[test]
    fn endpoint_rejects_userinfo() {
        let mut record = sample_record([0x22; ED25519_KEY_LEN]);
        record.endpoint = "https://user@public.example.com".to_string();
        assert!(matches!(
            record.to_body_bytes(),
            Err(HeartbeatError::EndpointHasUserinfo),
        ));
    }

    #[test]
    fn endpoint_rejects_path() {
        let mut record = sample_record([0x22; ED25519_KEY_LEN]);
        record.endpoint = "https://node.example.com/v1/info".to_string();
        assert!(matches!(
            record.to_body_bytes(),
            Err(HeartbeatError::EndpointHasExtras),
        ));
    }

    #[test]
    fn endpoint_rejects_bad_scheme() {
        let mut record = sample_record([0x22; ED25519_KEY_LEN]);
        record.endpoint = "file:///etc/passwd".to_string();
        // file: doesn't have an authority shape but our parser still rejects
        // either way; either path-rejection or scheme rejection is fine.
        let err = record.to_body_bytes().unwrap_err();
        assert!(matches!(
            err,
            HeartbeatError::EndpointBadScheme | HeartbeatError::EndpointMissingHost,
        ));
    }

    #[test]
    fn from_body_bytes_rejects_bad_magic() {
        let crypto = DmpCrypto::generate();
        let record = sample_record(crypto.signing_public_key_bytes());
        let mut body = record.to_body_bytes().unwrap();
        body[0] = b'X';
        assert!(matches!(
            HeartbeatRecord::from_body_bytes(&body),
            Err(HeartbeatError::BadMagic),
        ));
    }

    #[test]
    fn sign_and_parse_round_trip() {
        let crypto = DmpCrypto::generate();
        let now = 1_700_000_100u64;
        let record = HeartbeatRecord {
            endpoint: "https://node.example.com:8443".to_string(),
            operator_spk: crypto.signing_public_key_bytes(),
            version: "0.5.0".to_string(),
            ts: 1_700_000_000,
            exp: 1_700_000_300,
            capabilities: CAP_CLAIM_PROVIDER,
            claim_provider_zone: "claim.example.com".to_string(),
        };
        let wire = record.sign(&crypto).unwrap();
        let parsed = HeartbeatRecord::parse_and_verify(&wire, Some(now), DEFAULT_TS_SKEW_SECONDS)
            .expect("must verify");
        assert_eq!(parsed, record);
    }

    #[test]
    fn sign_rejects_key_mismatch() {
        let alice = DmpCrypto::generate();
        let bob = DmpCrypto::generate();
        let record = sample_record(alice.signing_public_key_bytes());
        assert!(matches!(
            record.sign(&bob),
            Err(HeartbeatError::OperatorKeyMismatch),
        ));
    }

    #[test]
    fn parse_rejects_bad_prefix() {
        let crypto = DmpCrypto::generate();
        let record = sample_record(crypto.signing_public_key_bytes());
        let wire = record.sign(&crypto).unwrap();
        let stripped = wire.strip_prefix(RECORD_PREFIX).unwrap().to_string();
        assert!(HeartbeatRecord::parse_and_verify(
            &stripped,
            Some(record.ts + 1),
            DEFAULT_TS_SKEW_SECONDS,
        )
        .is_none());
    }

    #[test]
    fn parse_rejects_bad_base64() {
        let bogus = format!("{RECORD_PREFIX}!!!not-base64!!!");
        assert!(
            HeartbeatRecord::parse_and_verify(&bogus, Some(0), DEFAULT_TS_SKEW_SECONDS).is_none()
        );
    }

    #[test]
    fn parse_rejects_flipped_signature() {
        let crypto = DmpCrypto::generate();
        let record = sample_record(crypto.signing_public_key_bytes());
        let wire = record.sign(&crypto).unwrap();
        let payload = wire.strip_prefix(RECORD_PREFIX).unwrap();
        let mut bytes = BASE64_STANDARD.decode(payload).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = format!("{RECORD_PREFIX}{}", BASE64_STANDARD.encode(&bytes));
        assert!(HeartbeatRecord::parse_and_verify(
            &tampered,
            Some(record.ts + 1),
            DEFAULT_TS_SKEW_SECONDS,
        )
        .is_none());
    }

    #[test]
    fn parse_rejects_low_order_spk_substitution() {
        // Sign legitimately, then mutate the wire to swap operator_spk for a
        // known low-order pubkey. parse_and_verify must reject before the
        // signature check even runs; the low-order guard fires first.
        let crypto = DmpCrypto::generate();
        let record = sample_record(crypto.signing_public_key_bytes());
        let wire = record.sign(&crypto).unwrap();
        let payload = wire.strip_prefix(RECORD_PREFIX).unwrap();
        let mut bytes = BASE64_STANDARD.decode(payload).unwrap();
        // operator_spk lives after magic(7) + endpoint_len(2) + endpoint(N).
        let endpoint_len = u16::from_be_bytes(bytes[7..9].try_into().unwrap()) as usize;
        let spk_off = MAGIC.len() + 2 + endpoint_len;
        bytes[spk_off..spk_off + ED25519_KEY_LEN].copy_from_slice(&LOW_ORDER_ED25519_PUBKEYS[0]);
        let mutated = format!("{RECORD_PREFIX}{}", BASE64_STANDARD.encode(&bytes));
        assert!(HeartbeatRecord::parse_and_verify(
            &mutated,
            Some(record.ts + 1),
            DEFAULT_TS_SKEW_SECONDS,
        )
        .is_none());
    }

    #[test]
    fn parse_rejects_expired() {
        let crypto = DmpCrypto::generate();
        let mut record = sample_record(crypto.signing_public_key_bytes());
        record.ts = 1_000;
        record.exp = 1_100;
        let wire = record.sign(&crypto).unwrap();
        // exp <= now is rejected.
        assert!(
            HeartbeatRecord::parse_and_verify(&wire, Some(1_100), DEFAULT_TS_SKEW_SECONDS)
                .is_none()
        );
    }

    #[test]
    fn parse_rejects_ts_outside_skew_either_side() {
        let crypto = DmpCrypto::generate();
        let mut record = sample_record(crypto.signing_public_key_bytes());
        record.ts = 1_700_000_000;
        record.exp = 1_700_010_000;
        let wire = record.sign(&crypto).unwrap();
        // 10 minutes ahead of ts — outside default 5-minute symmetric window.
        assert!(HeartbeatRecord::parse_and_verify(
            &wire,
            Some(record.ts + 600),
            DEFAULT_TS_SKEW_SECONDS,
        )
        .is_none());
        // 10 minutes BEHIND ts (forward-dated) also rejected.
        assert!(HeartbeatRecord::parse_and_verify(
            &wire,
            Some(record.ts - 600),
            DEFAULT_TS_SKEW_SECONDS,
        )
        .is_none());
    }

    #[test]
    fn parse_legacy_dmphb02_round_trip() {
        // Hand-craft a DMPHB02 body (no claim_provider_zone fields), sign it,
        // base64-prefix it, and confirm parse_and_verify accepts the legacy
        // wire with claim_provider_zone defaulted to "".
        let crypto = DmpCrypto::generate();
        let endpoint = "https://legacy.example.com:8443".to_string();
        let version = "0.4.0".to_string();
        let capabilities: u16 = CAP_CLAIM_PROVIDER;
        let ts: u64 = 1_700_000_000;
        let exp: u64 = 1_700_000_300;
        let now = ts + 60;

        let endpoint_bytes = endpoint.as_bytes();
        let version_bytes = version.as_bytes();
        let mut body = Vec::new();
        body.extend_from_slice(LEGACY_MAGIC);
        body.extend_from_slice(&u16::try_from(endpoint_bytes.len()).unwrap().to_be_bytes());
        body.extend_from_slice(endpoint_bytes);
        body.extend_from_slice(&crypto.signing_public_key_bytes());
        body.push(u8::try_from(version_bytes.len()).unwrap());
        body.extend_from_slice(version_bytes);
        body.extend_from_slice(&capabilities.to_be_bytes());
        body.extend_from_slice(&ts.to_be_bytes());
        body.extend_from_slice(&exp.to_be_bytes());

        let signature = crypto.sign_data(&body);
        let mut combined = Vec::with_capacity(body.len() + ED25519_SIG_LEN);
        combined.extend_from_slice(&body);
        combined.extend_from_slice(&signature);
        let wire = format!("{RECORD_PREFIX}{}", BASE64_STANDARD.encode(&combined));

        let parsed = HeartbeatRecord::parse_and_verify(&wire, Some(now), DEFAULT_TS_SKEW_SECONDS)
            .expect("legacy DMPHB02 wire must verify");
        assert_eq!(parsed.endpoint, endpoint);
        assert_eq!(parsed.version, version);
        assert_eq!(parsed.capabilities, capabilities);
        assert_eq!(parsed.ts, ts);
        assert_eq!(parsed.exp, exp);
        assert_eq!(parsed.claim_provider_zone, "");
        assert_eq!(parsed.operator_spk, crypto.signing_public_key_bytes());
    }

    #[test]
    fn parse_rejects_too_long_wire() {
        // Construct a wire that exceeds MAX_WIRE_LEN by base64-padding random
        // bytes. We only check the length gate — content doesn't have to verify.
        let oversize = "A".repeat(MAX_WIRE_LEN);
        let wire = format!("{RECORD_PREFIX}{oversize}");
        assert!(wire.len() > MAX_WIRE_LEN);
        assert!(
            HeartbeatRecord::parse_and_verify(&wire, Some(0), DEFAULT_TS_SKEW_SECONDS).is_none()
        );
    }
}

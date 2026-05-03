//! HTTP-API publisher for a DMP node's bearer-token endpoint.
//!
//! Mirrors `_HttpWriter` in `dmp/cli.py:369`. The Python flow is:
//!
//! ```text
//! POST   <endpoint>/v1/records/<name>  + Authorization: Bearer <token>
//!   body:    { "value": "...", "ttl": <secs> }
//!   success: 201 Created
//!
//! DELETE <endpoint>/v1/records/<name>  + Authorization: Bearer <token>
//!   body:    { "value": "..." }   (optional; some backends require it
//!                                  for an exact-match RRset delete)
//!   success: 204 No Content
//! ```
//!
//! The bearer token is the per-user `dmp_v1_...` value the operator
//! got from `dnsmesh register` and saved at
//! `<config_home>/tokens/<node-host>.json`.
//!
//! Use case: operators on multi-tenant nodes that expose the HTTP-API
//! publish path but NOT TSIG-signed RFC 2136 UPDATE. The node-side
//! TSIG path works fine when offered (RFC 2136 is older and broadly
//! supported), but new node operators tend to ship the HTTP-API
//! first because it's easier to deploy behind a typical reverse-
//! proxy + load-balancer stack.
//!
//! Feature-gated under `cloudflare` since both publishers share the
//! same reqwest + serde_json dep set; a more granular `http-publishers`
//! feature would be cleaner but isn't worth the churn pre-1.0.

use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::base::DnsRecordWriter;
use crate::error::NetError;

/// Configuration for [`NodeTokenPublisher`].
pub struct NodeTokenPublisherConfig {
    /// Base URL of the node's HTTP API. Either `https://host` or
    /// `https://host:port`. The publisher refuses non-loopback http
    /// schemes — bearer tokens over cleartext is the same threat
    /// model the Cloudflare publisher rejects.
    pub endpoint: String,
    /// Per-user bearer token. The `dmp_v1_...` string from
    /// `<config_home>/tokens/<host>.json`.
    pub token: Zeroizing<String>,
    /// Per-request timeout. Defaults to 10s (matches Python's
    /// `requests.post(..., timeout=10)` at cli.py:414).
    pub request_timeout: Duration,
}

impl std::fmt::Debug for NodeTokenPublisherConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeTokenPublisherConfig")
            .field("endpoint", &self.endpoint)
            .field("token", &"<redacted>")
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}

impl NodeTokenPublisherConfig {
    pub fn new(endpoint: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            token: Zeroizing::new(token.into()),
            request_timeout: Duration::from_secs(10),
        }
    }
}

/// HTTP-backed [`DnsRecordWriter`] talking to a DMP node's bearer-
/// auth API.
pub struct NodeTokenPublisher {
    client: reqwest::Client,
    base: String,
    headers: HeaderMap,
}

impl std::fmt::Debug for NodeTokenPublisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Same reasoning as CloudflarePublisher::Debug — the headers
        // map carries the bearer; redact via finish_non_exhaustive.
        f.debug_struct("NodeTokenPublisher")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl NodeTokenPublisher {
    pub fn new(config: &NodeTokenPublisherConfig) -> Result<Self, NetError> {
        let endpoint = config.endpoint.trim_end_matches('/').to_string();
        let scheme_loopback_http = endpoint_is_loopback_http(&endpoint);
        if !endpoint.starts_with("https://") && !scheme_loopback_http {
            return Err(NetError::InvalidConfig(format!(
                "node endpoint must be https:// (or http:// to a loopback for tests); got {endpoint}"
            )));
        }

        let mut headers = HeaderMap::new();
        let bearer = format!("Bearer {}", config.token.as_str());
        let mut auth = HeaderValue::from_str(&bearer)
            .map_err(|e| NetError::InvalidConfig(format!("token unencodable as header: {e}")))?;
        auth.set_sensitive(true);
        headers.insert(AUTHORIZATION, auth);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let mut builder = reqwest::Client::builder()
            .timeout(config.request_timeout)
            // Same redirect / TLS-only posture as the Cloudflare
            // publisher: never let a 30x leak the bearer to a host
            // outside this endpoint.
            .redirect(reqwest::redirect::Policy::none());
        if !scheme_loopback_http {
            builder = builder.https_only(true);
        }
        let client = builder
            .build()
            .map_err(|e| NetError::InvalidConfig(format!("node-token http client: {e}")))?;

        Ok(Self {
            client,
            base: endpoint,
            headers,
        })
    }
}

#[async_trait]
impl DnsRecordWriter for NodeTokenPublisher {
    async fn publish_txt_record(
        &self,
        name: &str,
        value: &str,
        ttl_seconds: u32,
    ) -> Result<bool, NetError> {
        let url = format!("{}/v1/records/{name}", self.base);
        let body = PublishBody {
            value,
            ttl: ttl_seconds,
        };
        let resp = self
            .client
            .post(&url)
            .headers(self.headers.clone())
            .json(&body)
            .send()
            .await
            .map_err(|e| NetError::Transport(format!("node-token POST {url}: {e}")))?;
        let status = resp.status();
        if status == reqwest::StatusCode::CREATED {
            return Ok(true);
        }
        // Non-201: surface the operator-actionable reason. Python
        // captures status + body for the same purpose (cli.py:399).
        let body_text = resp.text().await.unwrap_or_default();
        Err(NetError::Transport(format!(
            "node-token publish {name} failed: HTTP {status}: {body_text}",
        )))
    }

    async fn delete_txt_record(&self, name: &str, value: Option<&str>) -> Result<bool, NetError> {
        let url = format!("{}/v1/records/{name}", self.base);
        // Python: optional {"value": "..."} body. Some node backends
        // (RRset multi-value) need it for exact-match delete; others
        // ignore it. Send only when the caller passed Some.
        let mut req = self.client.delete(&url).headers(self.headers.clone());
        if let Some(v) = value {
            req = req.json(&DeleteBody { value: v });
        }
        let resp = req
            .send()
            .await
            .map_err(|e| NetError::Transport(format!("node-token DELETE {url}: {e}")))?;
        let status = resp.status();
        if status == reqwest::StatusCode::NO_CONTENT {
            return Ok(true);
        }
        // 404 is treated as "already gone" for idempotency, mirroring
        // the Cloudflare publisher.
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(true);
        }
        let body_text = resp.text().await.unwrap_or_default();
        Err(NetError::Transport(format!(
            "node-token delete {name} failed: HTTP {status}: {body_text}",
        )))
    }
}

#[derive(Debug, Serialize)]
struct PublishBody<'a> {
    value: &'a str,
    ttl: u32,
}

#[derive(Debug, Serialize)]
struct DeleteBody<'a> {
    value: &'a str,
}

/// True iff `endpoint` is `http://<loopback>[:port]` — used by the
/// scheme guard so wiremock-backed tests work without weakening the
/// production https-only posture.
fn endpoint_is_loopback_http(endpoint: &str) -> bool {
    let Some(rest) = endpoint.strip_prefix("http://") else {
        return false;
    };
    let host = rest
        .split_once('/')
        .map_or(rest, |(h, _)| h)
        .split_once(':')
        .map_or(rest, |(h, _)| h);
    matches!(host, "127.0.0.1" | "[::1]" | "::1" | "localhost")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cfg_for(server: &MockServer) -> NodeTokenPublisherConfig {
        NodeTokenPublisherConfig {
            endpoint: server.uri(),
            token: Zeroizing::new("dmp_v1_TESTTOKEN".to_string()),
            request_timeout: Duration::from_secs(5),
        }
    }

    #[tokio::test]
    async fn publish_201_returns_ok_true_with_bearer_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/records/id-deadbeef.dmp.example"))
            .and(header("authorization", "Bearer dmp_v1_TESTTOKEN"))
            .and(header("content-type", "application/json"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
            .expect(1)
            .mount(&server)
            .await;

        let pub_ = NodeTokenPublisher::new(&cfg_for(&server)).unwrap();
        assert!(pub_
            .publish_txt_record("id-deadbeef.dmp.example", "v=dmp1;...", 300)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn publish_non_201_surfaces_status_and_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/records/id-bad.dmp.example"))
            .respond_with(ResponseTemplate::new(403).set_body_string("scope denied"))
            .mount(&server)
            .await;

        let pub_ = NodeTokenPublisher::new(&cfg_for(&server)).unwrap();
        let err = pub_
            .publish_txt_record("id-bad.dmp.example", "v", 300)
            .await
            .unwrap_err();
        let s = format!("{err}");
        assert!(s.contains("403"));
        assert!(s.contains("scope denied"));
    }

    #[tokio::test]
    async fn delete_204_returns_ok_true() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/v1/records/id-x.dmp.example"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let pub_ = NodeTokenPublisher::new(&cfg_for(&server)).unwrap();
        assert!(pub_
            .delete_txt_record("id-x.dmp.example", None)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn delete_404_is_idempotent_ok() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/v1/records/id-absent.dmp.example"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let pub_ = NodeTokenPublisher::new(&cfg_for(&server)).unwrap();
        assert!(pub_
            .delete_txt_record("id-absent.dmp.example", None)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn refuses_non_loopback_http_endpoint() {
        let cfg = NodeTokenPublisherConfig {
            endpoint: "http://api.example.com".to_string(),
            token: Zeroizing::new("t".to_string()),
            request_timeout: Duration::from_secs(1),
        };
        let err = NodeTokenPublisher::new(&cfg).unwrap_err();
        assert!(format!("{err}").contains("https"));
    }
}

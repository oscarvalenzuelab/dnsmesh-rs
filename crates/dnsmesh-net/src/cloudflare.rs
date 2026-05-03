//! HTTP-API DNS publisher targeting the Cloudflare v4 endpoint.
//!
//! Mirrors `CloudflarePublisher` in `dmp/network/dns_publisher.py`.
//! Useful for operators whose authoritative zones live on Cloudflare
//! and who don't want to set up an RFC 2136 TSIG-signed UPDATE path
//! via a self-hosted BIND/PowerDNS deployment. The free tier supports
//! up to 1000 records per zone, which covers a single-user identity
//! plus prekey pool plus active mailbox slots and chunks comfortably.
//!
//! API surface used (all under `https://api.cloudflare.com/client/v4`):
//!
//! - `GET  /zones/{zone}/dns_records?name={fqdn}&type=TXT` — find by name
//! - `POST /zones/{zone}/dns_records`                       — create
//! - `PUT  /zones/{zone}/dns_records/{id}`                  — update
//! - `DELETE /zones/{zone}/dns_records/{id}`                — delete
//!
//! Auth is a single API token in `Authorization: Bearer <token>`. The
//! token must hold the `Zone:DNS:Edit` permission for the target
//! zone. Cloudflare splits long values into multi-string TXT RDATA
//! internally (~2048-character cap on `content`) — we pass the value
//! as a single string and let Cloudflare's edge handle the split,
//! same as the Python reference.
//!
//! The publisher does NOT match the Python `_find_record` semantics
//! exactly: Python looks up by `(name, type)` and operates on the
//! first hit, dropping any siblings. We do the same — Cloudflare's
//! v4 API returns records in insertion order, so a re-publish of an
//! existing name overwrites the FIRST record at that name. Callers
//! that need RRset-level multi-value semantics should publish
//! distinct values under distinct names; DMP's wire format does
//! exactly that (mailbox slot 0..9, separate chunk-numbered names).
//!
//! Feature-gated under `cloudflare` so non-cloudflare consumers
//! (mobile FFI, the standard DnsUpdateWriter path) don't carry the
//! reqwest + serde_json dep weight.

use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::base::DnsRecordWriter;
use crate::error::NetError;

/// Configuration for [`CloudflarePublisher`].
///
/// `api_token` MUST hold `Zone:DNS:Edit` for `zone_id`. Anything wider
/// (e.g. an account-level token) is unnecessary surface area on the
/// runner; if it leaks, the blast radius is the entire Cloudflare
/// account rather than just one zone.
pub struct CloudflarePublisherConfig {
    /// Cloudflare zone ID (the 32-char hex string from the zone
    /// dashboard, NOT the human-readable zone name).
    pub zone_id: String,
    /// Cloudflare API token, scoped to `Zone:DNS:Edit` on the target
    /// zone.
    pub api_token: Zeroizing<String>,
    /// Override the API base URL. Default `https://api.cloudflare.com`
    /// — tests point this at a wiremock server.
    pub api_base: Option<String>,
    /// HTTP client timeout per request. Defaults to 10 seconds —
    /// matches the Python reference's `dns.query.tcp(... timeout=10)`.
    pub request_timeout: Duration,
}

impl std::fmt::Debug for CloudflarePublisherConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflarePublisherConfig")
            .field("zone_id", &self.zone_id)
            .field("api_token", &"<redacted>")
            .field("api_base", &self.api_base)
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}

impl CloudflarePublisherConfig {
    /// Convenience constructor for the production defaults.
    pub fn new(zone_id: impl Into<String>, api_token: impl Into<String>) -> Self {
        Self {
            zone_id: zone_id.into(),
            api_token: Zeroizing::new(api_token.into()),
            api_base: None,
            request_timeout: Duration::from_secs(10),
        }
    }
}

/// HTTP-backed [`DnsRecordWriter`] for Cloudflare-hosted zones.
pub struct CloudflarePublisher {
    client: reqwest::Client,
    base_url: String,
    /// Cached header map so every request reuses the same Authorization
    /// header without rebuilding it. The token lives in this map and
    /// nowhere else after construction.
    headers: HeaderMap,
    /// Serializes the GET-then-POST/PUT critical section per
    /// publisher instance so two concurrent `publish_txt_record`
    /// calls against the same name can't both miss the existing
    /// record and create duplicates. Without the lock the API would
    /// happily store two TXT records at one name, and DMP semantics
    /// expect distinct names per record (slot-N, chunk-X) — so
    /// duplicates are bugs not features.
    publish_lock: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for CloudflarePublisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The Authorization header carries the API token — never
        // surface its content in Debug, even in dev logs. The
        // finish_non_exhaustive intentionally elides the headers
        // map and the reqwest::Client's internal state.
        f.debug_struct("CloudflarePublisher")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl CloudflarePublisher {
    /// Build a publisher from `config`. Validates the API token can
    /// be encoded as an HTTP header value (rejects newlines / control
    /// chars) and constructs the underlying [`reqwest::Client`].
    pub fn new(config: CloudflarePublisherConfig) -> Result<Self, NetError> {
        // Pre-validate zone_id format so an operator who pasted the
        // human-readable zone NAME (e.g. "example.com") instead of
        // the 32-char hex zone ID gets a clear error at config-load
        // time, not a 404 from Cloudflare on the first publish. The
        // dashboard prints zone IDs in lowercase hex, but we accept
        // mixed-case for tolerance.
        let zid = config.zone_id.trim();
        let zone_id_ok = zid.len() == 32 && zid.chars().all(|c| c.is_ascii_hexdigit());
        if !zone_id_ok {
            return Err(NetError::InvalidConfig(format!(
                "cloudflare zone_id must be 32 hex chars (the value Cloudflare's dashboard \
                 prints as `Zone ID`, NOT the human-readable zone name); got {zid:?}"
            )));
        }
        // Use the trimmed form in the URL path too — trimming only
        // for validation but interpolating the original would let a
        // `\t<id>\n` zone_id validate while still producing a
        // malformed request URL.
        let zone_id = zid.to_string();

        let api_base = config
            .api_base
            .unwrap_or_else(|| "https://api.cloudflare.com".to_string());
        // Validate scheme — production talks https only. The wiremock
        // test fixtures bind on http://127.0.0.1:<port>, so we allow
        // http when the base resolves to a loopback address. Anything
        // else with a non-https scheme is refused at construction so
        // a copy-paste config error can never ship the bearer over
        // cleartext.
        let scheme_is_loopback_http = api_base_is_loopback_http(&api_base);
        if !api_base.starts_with("https://") && !scheme_is_loopback_http {
            return Err(NetError::InvalidConfig(format!(
                "cloudflare api_base must be https:// (or http:// to a loopback for tests); got {api_base}"
            )));
        }
        let base_url = format!("{api_base}/client/v4/zones/{zone_id}/dns_records");

        let mut headers = HeaderMap::new();
        let bearer = format!("Bearer {}", config.api_token.as_str());
        let mut auth_value = HeaderValue::from_str(&bearer).map_err(|e| {
            NetError::InvalidConfig(format!("api_token unencodable as header: {e}"))
        })?;
        auth_value.set_sensitive(true);
        headers.insert(AUTHORIZATION, auth_value);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let mut builder = reqwest::Client::builder()
            .timeout(config.request_timeout)
            // We never want a transparent redirect to leak the
            // Authorization header to a non-Cloudflare host.
            .redirect(reqwest::redirect::Policy::none());
        if !scheme_is_loopback_http {
            // Reject HTTP-scheme requests at the transport layer so a
            // hostile DNS rebinding (api.cloudflare.com → 127.0.0.1)
            // followed by a cleartext-only response can't trick us
            // into sending the bearer over the wire unencrypted. Skip
            // for the loopback-http test fixture so wiremock keeps
            // working.
            builder = builder.https_only(true);
        }
        let client = builder
            .build()
            .map_err(|e| NetError::InvalidConfig(format!("cloudflare http client: {e}")))?;

        Ok(Self {
            client,
            base_url,
            headers,
            publish_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Find the first DNS record matching `(name, type=TXT)`. Returns
    /// `Ok(None)` if no record exists. Wraps Cloudflare's GET
    /// /dns_records?name=&type=.
    async fn find_record(&self, name: &str) -> Result<Option<DnsRecord>, NetError> {
        let resp = self
            .client
            .get(&self.base_url)
            .headers(self.headers.clone())
            .query(&[("name", name), ("type", "TXT")])
            .send()
            .await
            .map_err(|e| NetError::Transport(format!("cloudflare GET: {e}")))?;
        if !resp.status().is_success() {
            return Err(NetError::Transport(format!(
                "cloudflare GET {} status {}",
                name,
                resp.status(),
            )));
        }
        let body: ListResponse = resp
            .json()
            .await
            .map_err(|e| NetError::Transport(format!("cloudflare GET decode: {e}")))?;
        if !body.success {
            return Err(NetError::Transport(format!(
                "cloudflare GET {name} unsuccessful: {:?}",
                body.errors
            )));
        }
        Ok(body.result.into_iter().next())
    }
}

#[async_trait]
impl DnsRecordWriter for CloudflarePublisher {
    async fn publish_txt_record(
        &self,
        name: &str,
        value: &str,
        ttl_seconds: u32,
    ) -> Result<bool, NetError> {
        // Cloudflare enforces a 60s minimum TTL. Anything lower is
        // accepted-but-clamped silently on their side; clamp here so
        // the value we report writing matches the value that actually
        // hits the edge.
        let ttl = ttl_seconds.max(60);
        let payload = WriteRecord {
            r#type: "TXT",
            name,
            content: value,
            ttl,
            proxied: false,
        };

        // Hold the publish lock across the GET-then-POST/PUT
        // critical section so two concurrent publishers can't both
        // miss the existing record and end up with a duplicate at
        // the same name. The lock is per-publisher-instance; running
        // multiple `dnsmesh send` processes in parallel against the
        // same Cloudflare zone still races at the API level (each
        // process has its own publisher), but that's a deliberate
        // boundary — DMP record names are designed to be unique per
        // (slot/chunk/etc.) so the per-process serialization is
        // sufficient for any single client's traffic.
        let _guard = self.publish_lock.lock().await;
        let existing = self.find_record(name).await?;
        let resp = match existing {
            Some(rec) => {
                let url = format!("{}/{}", self.base_url, rec.id);
                self.client
                    .put(url)
                    .headers(self.headers.clone())
                    .json(&payload)
                    .send()
                    .await
            }
            None => {
                self.client
                    .post(&self.base_url)
                    .headers(self.headers.clone())
                    .json(&payload)
                    .send()
                    .await
            }
        }
        .map_err(|e| NetError::Transport(format!("cloudflare write: {e}")))?;
        let status = resp.status();
        let body: WriteResponse = resp
            .json()
            .await
            .map_err(|e| NetError::Transport(format!("cloudflare write decode: {e}")))?;
        if !body.success {
            return Err(NetError::Transport(format!(
                "cloudflare write {name} status={status} unsuccessful: {:?}",
                body.errors
            )));
        }
        Ok(true)
    }

    async fn delete_txt_record(&self, name: &str, _value: Option<&str>) -> Result<bool, NetError> {
        // Cloudflare deletes by record ID, not by value. The Python
        // reference also ignores `value` for this backend.
        let Some(record) = self.find_record(name).await? else {
            // Already absent — Python returns True here for
            // idempotent-delete semantics.
            return Ok(true);
        };
        let url = format!("{}/{}", self.base_url, record.id);
        let resp = self
            .client
            .delete(url)
            .headers(self.headers.clone())
            .send()
            .await
            .map_err(|e| NetError::Transport(format!("cloudflare DELETE: {e}")))?;
        let status = resp.status();
        let body: DeleteResponse = resp
            .json()
            .await
            .map_err(|e| NetError::Transport(format!("cloudflare DELETE decode: {e}")))?;
        if !body.success {
            return Err(NetError::Transport(format!(
                "cloudflare DELETE {name} status={status} unsuccessful: {:?}",
                body.errors
            )));
        }
        Ok(true)
    }
}

/// Return true iff `base` is `http://<loopback>[:port]` — the shape
/// the in-tree wiremock fixtures bind to. Used to gate the strict
/// https-only check so production configs can't be pointed at an
/// http endpoint while tests still work.
fn api_base_is_loopback_http(base: &str) -> bool {
    let Some(rest) = base.strip_prefix("http://") else {
        return false;
    };
    let host = rest
        .split_once('/')
        .map_or(rest, |(h, _)| h)
        .split_once(':')
        .map_or(rest, |(h, _)| h);
    // Accept both literal IPs (127.0.0.1, ::1) and the "localhost"
    // hostname. We don't resolve — a hostname literally spelled
    // "localhost" satisfies the test fixture; anything else doesn't.
    matches!(host, "127.0.0.1" | "[::1]" | "::1" | "localhost")
}

#[derive(Debug, Serialize)]
struct WriteRecord<'a> {
    r#type: &'a str,
    name: &'a str,
    content: &'a str,
    ttl: u32,
    proxied: bool,
}

#[derive(Debug, Deserialize)]
struct DnsRecord {
    id: String,
    #[serde(default)]
    #[allow(dead_code)]
    name: String,
}

#[derive(Debug, Deserialize)]
struct ListResponse {
    success: bool,
    #[serde(default)]
    errors: Vec<ApiError>,
    #[serde(default)]
    result: Vec<DnsRecord>,
}

#[derive(Debug, Deserialize)]
struct WriteResponse {
    success: bool,
    #[serde(default)]
    errors: Vec<ApiError>,
}

#[derive(Debug, Deserialize)]
struct DeleteResponse {
    success: bool,
    #[serde(default)]
    errors: Vec<ApiError>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ApiError {
    code: i64,
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config_for(server: &MockServer, zone_id: &str) -> CloudflarePublisherConfig {
        CloudflarePublisherConfig {
            zone_id: zone_id.to_string(),
            api_token: Zeroizing::new("test-token".to_string()),
            api_base: Some(server.uri()),
            request_timeout: Duration::from_secs(5),
        }
    }

    #[tokio::test]
    async fn publish_creates_when_record_does_not_exist() {
        let server = MockServer::start().await;
        let zone_id = "0123456789abcdef0123456789abcdef";
        let base = format!("/client/v4/zones/{zone_id}/dns_records");

        // GET returns success with empty result → no existing record.
        Mock::given(method("GET"))
            .and(path(&base))
            .and(query_param("name", "alice.example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "errors": [],
                "result": [],
            })))
            .expect(1)
            .mount(&server)
            .await;

        // POST creates the record. Cloudflare's response carries the
        // newly-allocated id; success: true is the load-bearing flag.
        Mock::given(method("POST"))
            .and(path(&base))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "errors": [],
                "result": { "id": "newrec1", "name": "alice.example.com" },
            })))
            .expect(1)
            .mount(&server)
            .await;

        let pub_ = CloudflarePublisher::new(config_for(&server, zone_id)).unwrap();
        assert!(pub_
            .publish_txt_record("alice.example.com", "v=dmp1;…", 300)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn publish_updates_when_record_already_exists() {
        let server = MockServer::start().await;
        let zone_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let base = format!("/client/v4/zones/{zone_id}/dns_records");
        let put_path = format!("{base}/existing-id");

        Mock::given(method("GET"))
            .and(path(&base))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "errors": [],
                "result": [{ "id": "existing-id", "name": "alice.example.com" }],
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(put_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "errors": [],
            })))
            .expect(1)
            .mount(&server)
            .await;

        let pub_ = CloudflarePublisher::new(config_for(&server, zone_id)).unwrap();
        assert!(pub_
            .publish_txt_record("alice.example.com", "updated", 300)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn delete_when_absent_is_idempotent_ok() {
        let server = MockServer::start().await;
        let zone_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let base = format!("/client/v4/zones/{zone_id}/dns_records");

        Mock::given(method("GET"))
            .and(path(&base))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "errors": [],
                "result": [],
            })))
            .expect(1)
            .mount(&server)
            .await;

        // No DELETE mock — if delete_txt_record tried to call the
        // endpoint when the record is absent, wiremock's "no match"
        // surface would surface as a 404 and the assertion below
        // would fail.

        let pub_ = CloudflarePublisher::new(config_for(&server, zone_id)).unwrap();
        assert!(
            pub_.delete_txt_record("alice.example.com", None)
                .await
                .unwrap(),
            "delete of absent record returns Ok(true) (idempotent)",
        );
    }

    #[tokio::test]
    async fn delete_when_present_calls_delete_endpoint() {
        let server = MockServer::start().await;
        let zone_id = "cccccccccccccccccccccccccccccccc";
        let base = format!("/client/v4/zones/{zone_id}/dns_records");
        let delete_path = format!("{base}/rec-to-drop");

        Mock::given(method("GET"))
            .and(path(&base))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "errors": [],
                "result": [{ "id": "rec-to-drop", "name": "alice.example.com" }],
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(delete_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "errors": [],
            })))
            .expect(1)
            .mount(&server)
            .await;

        let pub_ = CloudflarePublisher::new(config_for(&server, zone_id)).unwrap();
        assert!(pub_
            .delete_txt_record("alice.example.com", Some("v=dmp1;…"))
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn write_unsuccessful_response_surfaces_as_error() {
        let server = MockServer::start().await;
        let zone_id = "dddddddddddddddddddddddddddddddd";
        let base = format!("/client/v4/zones/{zone_id}/dns_records");

        Mock::given(method("GET"))
            .and(path(&base))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "errors": [],
                "result": [],
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(&base))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": false,
                "errors": [{ "code": 1004, "message": "DNS Validation Error" }],
            })))
            .mount(&server)
            .await;

        let pub_ = CloudflarePublisher::new(config_for(&server, zone_id)).unwrap();
        let err = pub_
            .publish_txt_record("alice.example.com", "bad", 300)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("unsuccessful"));
    }

    #[tokio::test]
    async fn refuses_short_or_non_hex_zone_id() {
        // A zone_id that's the human-readable zone name (or any
        // non-32-hex string) must fail at construction so an operator
        // gets a clear error before the first publish 404s.
        for bad in [
            "example.com",
            "deadbeef",
            "ZID",
            "0123456789abcdef0123456789abcdez",
        ] {
            let cfg = CloudflarePublisherConfig {
                zone_id: bad.to_string(),
                api_token: Zeroizing::new("t".to_string()),
                api_base: None,
                request_timeout: Duration::from_secs(1),
            };
            let err = CloudflarePublisher::new(cfg).unwrap_err();
            assert!(
                format!("{err}").contains("32 hex"),
                "expected zone_id format refusal for {bad:?}; got: {err}",
            );
        }
    }

    #[tokio::test]
    async fn refuses_non_loopback_http_api_base() {
        // Plain-http override pointing at a non-loopback host must fail
        // at construction so a copy-paste mistake can't ship the bearer
        // over cleartext. wiremock tests above use 127.0.0.1 and pass.
        let cfg = CloudflarePublisherConfig {
            zone_id: "0123456789abcdef0123456789abcdef".to_string(),
            api_token: Zeroizing::new("test-token".to_string()),
            api_base: Some("http://api.cloudflare.com".to_string()),
            request_timeout: Duration::from_secs(1),
        };
        let err = CloudflarePublisher::new(cfg).unwrap_err();
        assert!(
            format!("{err}").contains("https"),
            "expected https-only refusal, got: {err}",
        );
    }

    #[tokio::test]
    async fn ttl_below_60_clamps_silently_to_60() {
        let server = MockServer::start().await;
        let zone_id = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let base = format!("/client/v4/zones/{zone_id}/dns_records");

        Mock::given(method("GET"))
            .and(path(&base))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "errors": [],
                "result": [],
            })))
            .mount(&server)
            .await;
        // Match a body containing `"ttl":60` — that's the clamp
        // applied before the request leaves us. wiremock's body_string
        // matcher is the simplest way to assert without parsing the
        // whole JSON.
        Mock::given(method("POST"))
            .and(path(&base))
            .and(wiremock::matchers::body_string_contains("\"ttl\":60"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "errors": [],
                "result": { "id": "x" },
            })))
            .expect(1)
            .mount(&server)
            .await;

        let pub_ = CloudflarePublisher::new(config_for(&server, zone_id)).unwrap();
        assert!(pub_
            .publish_txt_record("alice.example.com", "v", 30)
            .await
            .unwrap());
    }
}

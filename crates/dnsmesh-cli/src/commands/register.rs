//! `dnsmesh register` and `dnsmesh tsig register`.
//!
//! Mirrors `cmd_register` and `cmd_tsig_register` in `dmp/cli.py`.
//! Both walk the same Ed25519 challenge/confirm dance against a
//! multi-tenant node:
//!
//!   1. `GET  /v1/registration/challenge` → challenge bytes + node hostname
//!   2. Sign `challenge || subject || node || 0x01` with the local
//!      Ed25519 signing key (the one that signs IdentityRecords).
//!   3. `POST /v1/registration/confirm` (plain register) or
//!      `POST /v1/registration/tsig-confirm` (TSIG register).
//!   4. Persist the response — token JSON for plain register, full
//!      TSIG block written into `config.yaml` for tsig register.
//!
//! After `tsig register` succeeds, subsequent `dnsmesh identity
//! publish` / `dnsmesh send` go over RFC 2136 UPDATE through the
//! node's DNS port. The HTTP-token form saved by plain `register` is
//! kept under `<config_home>/tokens/<host>.json` for forward
//! compatibility with a future HTTP-token publisher; the Rust CLI
//! today uses the TSIG path.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use dnsmesh_core::crypto::DmpCrypto;
use serde::{Deserialize, Serialize};

use crate::cli::{RegisterArgs, TsigCmd};
use crate::client_factory::PassphraseSource;
use crate::config::{ConfigFile, PublishConfig};

/// Strip any `<scheme>://` prefix and trailing `/` from `node`. Mirrors
/// the Python CLI's normalization at cli.py:3383 — operators paste the
/// URL from their browser bar, we want a bare hostname.
fn normalize_node(node: &str) -> String {
    let mut s = node.trim().to_string();
    if let Some(idx) = s.find("://") {
        s = s[idx + 3..].to_string();
    }
    while s.ends_with('/') {
        s.pop();
    }
    s
}

/// Build the request payload signed by the registrant's Ed25519 key.
/// Must match the server's `_build_signing_payload` byte-for-byte:
/// `challenge_bytes || subject-utf8 || node-utf8 || 0x01`.
fn signing_payload(challenge: &[u8], subject: &str, node: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(challenge.len() + subject.len() + node.len() + 1);
    out.extend_from_slice(challenge);
    out.extend_from_slice(subject.as_bytes());
    out.extend_from_slice(node.as_bytes());
    out.push(0x01);
    out
}

#[derive(Debug, Deserialize)]
struct ChallengeResponse {
    challenge: String,
    node: String,
}

#[derive(Debug, Serialize)]
struct ConfirmRequest<'a> {
    subject: &'a str,
    ed25519_spk: &'a str,
    challenge: &'a str,
    signature: &'a str,
    /// Only sent for `tsig-confirm`. The server uses it to extend the
    /// minted scope to mailbox / claim records keyed on the X25519
    /// hash. Plain `confirm` ignores it.
    #[serde(skip_serializing_if = "Option::is_none")]
    x25519_pub: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
struct PlainConfirmResponse {
    token: String,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    expires_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct TsigConfirmResponse {
    tsig_key_name: String,
    tsig_secret_hex: String,
    #[serde(default = "default_algo")]
    tsig_algorithm: String,
    zone: String,
    #[serde(default)]
    allowed_suffixes: Vec<String>,
    #[serde(default)]
    expires_at: Option<i64>,
}

fn default_algo() -> String {
    "hmac-sha256".to_string()
}

/// On-disk shape mirroring `<config_home>/tokens/<host>.json` from
/// the Python `dmp.client.node_tokens.save_token`. Preserves field
/// names so a Python install can reuse a token saved by Rust and
/// vice versa.
#[derive(Debug, Serialize, Deserialize)]
struct SavedToken<'a> {
    version: u32,
    node: &'a str,
    subject: &'a str,
    token: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<i64>,
    registered_spk: &'a str,
    saved_at: i64,
}

fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::limited(2))
        // We talk to the node's HTTPS endpoint by default. Plain http
        // is allowed only when the operator passes --scheme http (dev
        // nodes); the URL builder pulls the scheme from RegisterArgs.
        .build()
        .context("building HTTP client")
}

async fn fetch_challenge(http: &reqwest::Client, base: &str) -> Result<ChallengeResponse> {
    let url = format!("{base}/v1/registration/challenge");
    let resp = http
        .get(&url)
        .send()
        .await
        .with_context(|| format!("cannot reach {url}"))?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        bail!(
            "{url} returned 404 — the node either doesn't expose registration \
             (DMP_REGISTRATION_ENABLED=1) or isn't in multi-tenant mode."
        );
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        bail!("registration rate-limited (429). Try again later.");
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("challenge request failed: HTTP {status}: {body}");
    }
    resp.json::<ChallengeResponse>()
        .await
        .context("decoding challenge response")
}

/// Map an HTTP status code from the confirm endpoints to a
/// human-readable error. 401 / 403 / 409 / 404 each have a
/// specific operator-actionable cause; anything else surfaces with
/// the body.
fn confirm_error_for(status: reqwest::StatusCode, body: &str, subject: &str) -> anyhow::Error {
    match status.as_u16() {
        401 => anyhow!(
            "node rejected the signature (401). Usually means the signing key \
             stored locally doesn't match the one the user thinks it does — \
             re-check the passphrase + kdf_salt."
        ),
        403 => anyhow!(
            "subject {subject:?} is not in the node's allowlist (403). Ask \
             the operator to add your domain or pick a permitted subject."
        ),
        409 => anyhow!(
            "subject {subject:?} is already held by a different key (409). \
             Use the same passphrase you registered with, or have the \
             operator revoke the prior token."
        ),
        404 => anyhow!(
            "node returned 404 from confirm — the registration endpoint may \
             not be exposed (DMP_REGISTRATION_ENABLED=1 / DMP_DNS_UPDATE_ENABLED=1)."
        ),
        _ => anyhow!("confirm failed: HTTP {status}: {body}"),
    }
}

async fn run_challenge_confirm(
    http: &reqwest::Client,
    base: &str,
    subject: &str,
    crypto: &DmpCrypto,
) -> Result<(ChallengeResponse, ConfirmRequestOwned)> {
    let challenge = fetch_challenge(http, base).await?;
    let challenge_bytes = hex::decode(&challenge.challenge).context("server challenge not hex")?;
    let payload = signing_payload(&challenge_bytes, subject, &challenge.node);
    let sig = crypto.sign_data(&payload);
    let owned = ConfirmRequestOwned {
        subject: subject.to_string(),
        ed25519_spk: hex::encode(crypto.signing_public_key_bytes()),
        challenge: challenge.challenge.clone(),
        signature: hex::encode(sig),
        x25519_pub: hex::encode(crypto.public_key_bytes()),
    };
    Ok((challenge, owned))
}

struct ConfirmRequestOwned {
    subject: String,
    ed25519_spk: String,
    challenge: String,
    signature: String,
    x25519_pub: String,
}

impl ConfirmRequestOwned {
    fn as_ref(&self, include_x25519: bool) -> ConfirmRequest<'_> {
        ConfirmRequest {
            subject: &self.subject,
            ed25519_spk: &self.ed25519_spk,
            challenge: &self.challenge,
            signature: &self.signature,
            x25519_pub: include_x25519.then_some(self.x25519_pub.as_str()),
        }
    }
}

/// Open the local config (raw, pre-resolution) so we can mutate it
/// and write back. The resolved-config path goes through path
/// expansion + validation; for register we want to read what the
/// user actually wrote and persist what we add to it.
fn load_raw_config(path: &Path) -> Result<ConfigFile> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("could not read config at {}", path.display()))?;
    let cfg: ConfigFile = serde_yaml::from_str(&raw)
        .with_context(|| format!("invalid YAML in {}", path.display()))?;
    if cfg.username.trim().is_empty() {
        bail!("config: username must not be empty");
    }
    if cfg.domain.trim().is_empty() {
        bail!("config: domain must not be empty");
    }
    Ok(cfg)
}

/// Resolve which subject the registration is for. Caller can override
/// via `--subject`; the default is `<username>@<domain>`.
fn resolve_subject(cfg: &ConfigFile, args: &RegisterArgs) -> String {
    args.subject
        .clone()
        .unwrap_or_else(|| format!("{}@{}", cfg.username, cfg.domain))
}

fn config_home_for(path: &Path) -> PathBuf {
    path.parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn build_crypto(cfg: &ConfigFile, source: &PassphraseSource) -> Result<DmpCrypto> {
    let passphrase = source.read()?;
    let salt = match cfg.kdf_salt.as_deref() {
        Some(hex_str) => {
            Some(hex::decode(hex_str.trim()).context("config.kdf_salt is not valid hex")?)
        }
        None => None,
    };
    DmpCrypto::from_passphrase(&passphrase, salt.as_deref())
        .map_err(|e| anyhow!("deriving identity from passphrase: {e}"))
}

pub async fn run_register(
    args: RegisterArgs,
    config_override: Option<&Path>,
    passphrase_env: Option<&str>,
) -> Result<()> {
    let config_path = match config_override {
        Some(p) => p.to_path_buf(),
        None => ConfigFile::default_path()?,
    };
    let cfg = load_raw_config(&config_path)?;
    let subject = resolve_subject(&cfg, &args);
    let crypto = build_crypto(&cfg, &PassphraseSource::from_cli(passphrase_env))?;

    let node_host = normalize_node(&args.node);
    if node_host.is_empty() {
        bail!("--node must not be empty after stripping scheme/path");
    }
    let base = format!("{}://{node_host}", args.scheme);
    let http = build_http_client()?;
    let (_challenge, owned) = run_challenge_confirm(&http, &base, &subject, &crypto).await?;
    let resp = http
        .post(format!("{base}/v1/registration/confirm"))
        .json(&owned.as_ref(false))
        .send()
        .await
        .context("confirm request failed to reach node")?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(confirm_error_for(status, &body, &subject));
    }
    let body: PlainConfirmResponse = resp.json().await.context("decoding confirm response")?;

    // Persist the token under <config_home>/tokens/<host>.json mode 0600.
    let tokens_dir = config_home_for(&config_path).join("tokens");
    std::fs::create_dir_all(&tokens_dir)
        .with_context(|| format!("creating tokens dir {}", tokens_dir.display()))?;
    let out_path = tokens_dir.join(format!("{node_host}.json"));
    let saved = SavedToken {
        version: 1,
        node: &node_host,
        subject: body.subject.as_deref().unwrap_or(&subject),
        token: &body.token,
        expires_at: body.expires_at,
        registered_spk: &owned.ed25519_spk,
        saved_at: unix_now(),
    };
    let payload = serde_json::to_vec_pretty(&saved).context("serializing saved token JSON")?;
    write_secret_file(&out_path, &payload)?;

    println!("registered {subject} on {node_host}");
    println!("  token saved to {} (mode 0600)", out_path.display());
    if let Some(ts) = body.expires_at {
        println!("  expires at unix {ts}");
    }
    println!(
        "  note: the Rust CLI does not yet ship an HTTP-token publisher; \
         use `dnsmesh tsig register --node {node_host}` for the TSIG-based \
         publish path."
    );
    Ok(())
}

pub async fn run_tsig_register(
    common: RegisterArgs,
    dns_server: Option<String>,
    dns_port: u16,
    config_override: Option<&Path>,
    passphrase_env: Option<&str>,
) -> Result<()> {
    let config_path = match config_override {
        Some(p) => p.to_path_buf(),
        None => ConfigFile::default_path()?,
    };
    let mut cfg = load_raw_config(&config_path)?;
    // Don't write a publish: block while a cloudflare: block is
    // already present. ConfigFile::resolve hard-fails on dual-config,
    // so persisting both would brick the config until the operator
    // manually deleted one. Refuse here with a clear remediation.
    if cfg.cloudflare.is_some() {
        bail!(
            "config already has a `cloudflare:` block; refusing to add a `publish:` (TSIG) \
             block that would conflict on next load. Delete the cloudflare: block first \
             if you want to switch to TSIG, or pick the cloudflare path."
        );
    }
    let subject = resolve_subject(&cfg, &common);
    let crypto = build_crypto(&cfg, &PassphraseSource::from_cli(passphrase_env))?;

    let node_host = normalize_node(&common.node);
    if node_host.is_empty() {
        bail!("--node must not be empty after stripping scheme/path");
    }
    let base = format!("{}://{node_host}", common.scheme);
    let http = build_http_client()?;
    let (_challenge, owned) = run_challenge_confirm(&http, &base, &subject, &crypto).await?;
    let resp = http
        .post(format!("{base}/v1/registration/tsig-confirm"))
        .json(&owned.as_ref(true))
        .send()
        .await
        .context("tsig-confirm request failed to reach node")?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(confirm_error_for(status, &body, &subject));
    }
    let body: TsigConfirmResponse = resp
        .json()
        .await
        .context("decoding tsig-confirm response")?;

    // Persist:
    //   1. the TSIG secret as a separate file under config_home (mode 0600)
    //   2. a publish: block in config.yaml pointing at the new key
    let config_home = config_home_for(&config_path);
    let secret_path = config_home.join(format!("tsig-{node_host}.key"));
    let secret_blob = format!("hex:{}\n", body.tsig_secret_hex);
    write_secret_file(&secret_path, secret_blob.as_bytes())?;

    let server = match dns_server {
        Some(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => node_host.clone(),
    };
    cfg.publish = Some(PublishConfig {
        zone: body.zone.clone(),
        server: format!("{server}:{dns_port}"),
        tsig_key_name: body.tsig_key_name.clone(),
        tsig_algorithm: body.tsig_algorithm.clone(),
        tsig_secret_path: secret_path.clone(),
    });
    cfg.save(&config_path)?;
    // Restore restrictive permissions after save (serde_yaml writes
    // through std::fs::write which honors umask but not our explicit
    // 0600 want). The config carries an Ed25519 public key in the
    // username hash, but the TSIG-key path it now points at is the
    // real secret — the public-key portion is fine to leak; pin the
    // config to 0600 anyway so a future field that DOES carry secret
    // material is safe by default.
    chmod_0600(&config_path)?;

    println!("registered {subject} on {node_host}");
    println!("  TSIG key:  {}", body.tsig_key_name);
    println!("  algorithm: {}", body.tsig_algorithm);
    println!("  zone:      {}", body.zone);
    println!("  DNS:       {server}:{dns_port}/udp");
    if !body.allowed_suffixes.is_empty() {
        println!("  scope:");
        for s in &body.allowed_suffixes {
            println!("    - {s}");
        }
    }
    if let Some(ts) = body.expires_at {
        println!("  expires:   unix {ts}");
    }
    println!(
        "  saved TSIG secret to {} (mode 0600)",
        secret_path.display()
    );
    println!(
        "  config: {} updated with the publish: block — `identity publish` \
         and `send` will now go over RFC 2136 UPDATE.",
        config_path.display()
    );
    Ok(())
}

/// Top-level dispatcher for `tsig <subcommand>`. Currently only
/// `register` exists; future subcommands (rotate, revoke) will land
/// here.
pub async fn run_tsig(
    cmd: TsigCmd,
    config_override: Option<&Path>,
    passphrase_env: Option<&str>,
) -> Result<()> {
    match cmd {
        TsigCmd::Register {
            common,
            dns_server,
            dns_port,
        } => {
            run_tsig_register(
                common,
                dns_server,
                dns_port,
                config_override,
                passphrase_env,
            )
            .await
        }
    }
}

fn write_secret_file(path: &Path, body: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating dir {}", parent.display()))?;
    let tmp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating tempfile in {}", parent.display()))?;
    tmp.as_file()
        .write_all(body)
        .with_context(|| format!("writing tempfile body for {}", path.display()))?;
    tmp.as_file().sync_all().ok();
    tmp.persist(path)
        .map_err(|e| anyhow!("renaming tempfile onto {}: {e}", path.display()))?;
    chmod_0600(path)?;
    Ok(())
}

#[cfg(unix)]
fn chmod_0600(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut perms = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)
        .with_context(|| format!("chmod 600 {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn chmod_0600(_path: &Path) -> Result<()> {
    // Windows POSIX-mode bits don't map cleanly onto NTFS ACLs. The
    // file lands with default ACL inheritance; an operator running on
    // Windows should review their ACLs separately.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_scheme_and_trailing_slash() {
        assert_eq!(normalize_node("https://dnsmesh.io"), "dnsmesh.io");
        assert_eq!(normalize_node("https://dnsmesh.io/"), "dnsmesh.io");
        assert_eq!(normalize_node("dnsmesh.io"), "dnsmesh.io");
        assert_eq!(normalize_node("http://dev.local:8443"), "dev.local:8443");
        assert_eq!(normalize_node("  dnsmesh.io  "), "dnsmesh.io");
    }

    #[test]
    fn signing_payload_layout_matches_spec() {
        let challenge = [0xAB, 0xCD];
        let p = signing_payload(&challenge, "alice@example.com", "node.example");
        // challenge(2) || subject(17) || node(12) || version(1) = 32
        assert_eq!(p.len(), 2 + 17 + 12 + 1);
        assert_eq!(&p[..2], &challenge);
        assert_eq!(&p[2..19], b"alice@example.com");
        assert_eq!(&p[19..31], b"node.example");
        assert_eq!(p[31], 0x01);
    }
}

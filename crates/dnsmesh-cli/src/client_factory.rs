//! Build a [`DmpClient`] from a [`ResolvedConfig`] plus a passphrase
//! source. Centralised so init / send / recv / doctor all converge on
//! one construction sequence.

use std::collections::BTreeMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use dnsmesh_client::{DmpClient, DmpClientConfig};
use dnsmesh_net::{
    CloudflarePublisher, CloudflarePublisherConfig, DnsRecordReader, DnsRecordWriter,
    DnsUpdateWriter, DnsUpdateWriterConfig, HostSpec, InMemoryDnsStore, NodeTokenPublisher,
    NodeTokenPublisherConfig, ResolverPool, ResolverPoolConfig, TsigAlgorithm, TsigKey,
};

use crate::config::{CloudflareConfig, PublishConfig, ResolvedConfig};

/// Env var that swaps the real TSIG writer + recursive reader for an
/// `InMemoryDnsStore` persisted to a JSON file. Two CLI invocations
/// pointed at the same path share a single virtual mesh — that's how
/// the mutt round-trip integration test wires send and recv against
/// each other without needing a live BIND zone.
///
/// Test-only. The whole backdoor is `cfg(debug_assertions)`-gated so
/// release builds hard-disable it: an operator who accidentally
/// exports this var in a prod shell gets a `tracing::warn!` that the
/// var is ignored, and `dnsmesh` continues to publish over the real
/// configured TSIG writer. Compile-time gating means the JSON-store
/// code path simply doesn't exist in release artifacts.
///
/// **Known limitations of the backdoor (test-only, by design):**
///   * No interprocess locking — concurrent CLI invocations against
///     one JSON file race on read-modify-write. The mutt round-trip
///     test runs commands sequentially, which is the only supported
///     shape.
///   * The store is loaded once at `build_client` time; a long-lived
///     `recv --watch` won't see writes from later `dnsmesh send`
///     processes. Use `--once` for round-trip testing.
const TEST_STORE_ENV: &str = "DMP_TEST_INMEMORY_STORE_FILE";

/// TTL we re-apply when reloading the store from disk. JSON snapshots
/// drop the original TTLs (matches the python_interop helper); 24h is
/// well above any test runtime so re-loaded records read live.
const TEST_STORE_TTL: u32 = 86_400;

/// Where the passphrase comes from.
#[derive(Debug, Clone)]
pub enum PassphraseSource {
    /// Prompt interactively via `rpassword`.
    Prompt,
    /// Read the named env var. Empty / unset is rejected with a clear error.
    Env(String),
    /// Use the value verbatim. Used by tests.
    #[allow(dead_code)]
    Literal(String),
}

impl PassphraseSource {
    pub fn from_cli(insecure_env: Option<&str>) -> Self {
        match insecure_env {
            Some(name) if !name.is_empty() => Self::Env(name.to_string()),
            _ => Self::Prompt,
        }
    }

    pub fn read(&self) -> Result<String> {
        match self {
            Self::Prompt => rpassword::prompt_password("DMP passphrase: ")
                .context("reading passphrase from terminal"),
            Self::Env(name) => match std::env::var(name) {
                Ok(v) if !v.is_empty() => Ok(v),
                _ => Err(anyhow!(
                    "passphrase env var `{name}` is empty or unset; export it before running"
                )),
            },
            Self::Literal(s) => Ok(s.clone()),
        }
    }
}

/// Bundled outputs of [`build_client`]. The `writer` is also returned
/// so doctor / publish-only paths can inspect whether a real publish
/// destination is configured.
pub struct BuiltClient {
    pub client: DmpClient,
    pub publish_configured: bool,
    /// When the test backdoor (`DMP_TEST_INMEMORY_STORE_FILE`) is in
    /// effect, this is the shared in-memory store. The dispatcher
    /// calls [`flush_test_store`] before exit so subsequent CLI
    /// invocations see the changes this one made.
    pub test_store: Option<(PathBuf, Arc<InMemoryDnsStore>)>,
}

/// Build the [`DmpClient`] described by `cfg`. Always opens a real
/// resolver pool (or the well-known list) and wires either a TSIG
/// writer (if `cfg.publish` is set) or a stub no-op writer. The stub
/// returns success without performing I/O — calls into it on a publish
/// flow are caught at command dispatch with [`require_publish`].
///
/// When `DMP_TEST_INMEMORY_STORE_FILE` is set, both reader and writer
/// resolve to a single `InMemoryDnsStore` JSON-persisted to that path;
/// it overrides everything else in `cfg.publish` / `cfg.resolvers`.
/// Test-only — see [`TEST_STORE_ENV`].
pub async fn build_client(cfg: &ResolvedConfig, source: PassphraseSource) -> Result<BuiltClient> {
    let passphrase = source.read()?;

    let test_store = match test_store_path() {
        Some(p) => {
            let store = Arc::new(InMemoryDnsStore::new());
            if let Err(e) = load_test_store(&p, &store).await {
                tracing::warn!(path = %p.display(), error = %e, "failed to preload test store");
            }
            Some((p, store))
        }
        None => None,
    };

    let (reader, writer, publish_configured) = if let Some((_, ref store)) = test_store {
        let r: Arc<dyn DnsRecordReader> = store.clone();
        let w: Arc<dyn DnsRecordWriter> = store.clone();
        // The backdoor implies "publish is configured" — the writer
        // accepts records — so require_publish() lets send / publish
        // through.
        (r, w, true)
    } else {
        let reader = build_reader(cfg.resolvers.as_deref())?;
        // Discover any saved bearer tokens from `dnsmesh register` so
        // build_writer can fall back to HTTP-token publishing when
        // neither cloudflare: nor publish: is wired up. Filter to the
        // current subject so a stray token saved under a different
        // identity (e.g. a previous `init` in the same config home)
        // can't silently become this session's writer.
        let current_subject = format!("{}@{}", cfg.username, cfg.domain);
        let saved_tokens = discover_saved_tokens(&cfg.config_home, &current_subject);
        let (writer, configured) = build_writer(
            cfg.publish.as_ref(),
            cfg.cloudflare.as_ref(),
            saved_tokens.as_deref(),
        )?;
        (reader, writer, configured)
    };

    let client_cfg = DmpClientConfig {
        username: cfg.username.clone(),
        passphrase,
        domain: cfg.domain.clone(),
        kdf_salt: cfg.kdf_salt.clone(),
        db_path: Some(cfg.db_path.clone()),
        writer,
        reader,
        // Off by default — callers wanting opt-in can flip this through
        // a future `cfg.rotation_chain_enabled` config-file field. The
        // wire format is still flagged audit-pending in the Python
        // source-of-truth.
        rotation_chain_enabled: false,
    };
    let client = DmpClient::new(client_cfg)
        .await
        .context("constructing DmpClient")?;
    Ok(BuiltClient {
        client,
        publish_configured,
        test_store,
    })
}

fn test_store_path() -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    {
        std::env::var_os(TEST_STORE_ENV).map(PathBuf::from)
    }
    #[cfg(not(debug_assertions))]
    {
        // Release builds refuse to honor the backdoor — the JSON-store
        // code path is excluded from binaries shipped to operators.
        // If the var is set anyway, log loudly so the operator notices
        // their environment is misconfigured (some sibling tool that
        // expected to use the backdoor in a debug binary likely got
        // copied into a prod context).
        if std::env::var_os(TEST_STORE_ENV).is_some() {
            tracing::warn!(
                "{TEST_STORE_ENV} is set but ignored in release builds — \
                 the in-memory test backdoor only exists in debug-mode \
                 (`cargo test`) artifacts. Unset the var to avoid confusion."
            );
        }
        None
    }
}

/// Read every TXT name + value pair from the on-disk JSON snapshot
/// and replay them into `store` at [`TEST_STORE_TTL`]. A missing file
/// is fine — the test starts with an empty mesh. Async because the
/// store's `publish_txt_record` is — `build_client` is itself async
/// so we await directly without spawning a nested runtime.
async fn load_test_store(path: &std::path::Path, store: &InMemoryDnsStore) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("reading test store snapshot at {}", path.display()))?;
    let snapshot: BTreeMap<String, Vec<String>> = serde_json::from_str(&body)
        .with_context(|| format!("parsing test store JSON at {}", path.display()))?;
    for (name, values) in snapshot {
        for v in values {
            store
                .publish_txt_record(&name, &v, TEST_STORE_TTL)
                .await
                .map_err(|e| anyhow!("preloading {name}: {e}"))?;
        }
    }
    Ok(())
}

/// Persist the current state of `store` back to `path`. Called by the
/// dispatcher after every CLI invocation when the test backdoor is in
/// effect, so subsequent invocations see the changes.
///
/// Writes via tempfile + rename so a SIGINT mid-write can't leave a
/// corrupt JSON file on disk that the next `build_client` would parse
/// as "empty store" and silently drop every previously-published
/// record. The tempfile lives in the same directory as the target so
/// the rename is atomic on the same filesystem.
pub async fn flush_test_store(path: &std::path::Path, store: &InMemoryDnsStore) -> Result<()> {
    let mut snapshot: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for name in store.list_names() {
        if let Some(values) = store
            .query_txt_record(&name)
            .await
            .with_context(|| format!("reading test store name {name}"))?
        {
            snapshot.insert(name, values);
        }
    }
    let body = serde_json::to_string_pretty(&snapshot)
        .context("serializing test store snapshot to JSON")?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let tmp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating tempfile in {}", parent.display()))?;
    {
        use std::io::Write as _;
        let mut handle = tmp.as_file();
        handle
            .write_all(body.as_bytes())
            .with_context(|| format!("writing tempfile body for {}", path.display()))?;
        handle
            .sync_all()
            .with_context(|| format!("fsync'ing tempfile for {}", path.display()))?;
    }
    tmp.persist(path)
        .map_err(|e| anyhow!("renaming tempfile onto {}: {e}", path.display()))?;
    Ok(())
}

/// Persist the test-store snapshot, if active. Every command that
/// owns a [`BuiltClient`] should `maybe_flush(&built).await?` on its
/// success path so a subsequent CLI invocation sees the records this
/// one published. No-op when the test backdoor isn't in effect.
pub async fn maybe_flush(built: &BuiltClient) -> Result<()> {
    if let Some((path, store)) = &built.test_store {
        flush_test_store(path, store).await?;
    }
    Ok(())
}

/// Common error message for commands that need a writer to be wired up.
pub fn require_publish(built: &BuiltClient) -> Result<()> {
    if built.publish_configured {
        Ok(())
    } else {
        Err(anyhow!(
            "this command publishes to DNS but no publish destination is configured — \
             add either a `publish:` block (TSIG / RFC 2136) or a `cloudflare:` block \
             (Cloudflare hosted zones) to your config. See examples/ for templates."
        ))
    }
}

fn build_reader(resolvers: Option<&[String]>) -> Result<Arc<dyn DnsRecordReader>> {
    // Resolution order:
    //   1. config.yaml `resolvers:` (explicit operator override)
    //   2. /etc/resolv.conf (Linux + macOS — picks up corporate / VPN
    //      DNS that wouldn't be in the well-known list)
    //   3. ResolverPool::well_known (Quad9 / Google / Cloudflare)
    //
    // Empty `resolvers:` AND unparseable resolv.conf both fall through
    // to the well-known list — never leave the user with no resolver.
    let explicit = resolvers.filter(|l| !l.is_empty());
    let pool = if let Some(list) = explicit {
        let hosts: Vec<HostSpec> = list
            .iter()
            .map(|s| {
                s.parse::<HostSpec>()
                    .map_err(|e| anyhow!("invalid resolver `{s}`: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        ResolverPool::new(hosts, ResolverPoolConfig::default()).context("building resolver pool")?
    } else {
        build_reader_from_os().unwrap_or_else(|| {
            ResolverPool::well_known().expect("well-known resolver pool must construct")
        })
    };
    Ok(Arc::new(pool))
}

/// Read `/etc/resolv.conf` and turn its `nameserver` lines into a
/// resolver pool. Returns `None` when:
///   - the file is missing (Windows, sandboxed containers)
///   - it contains no `nameserver` lines we can parse
///   - any read / parse error — falling back to the well-known list
///     is always safer than blocking the CLI.
///
/// On macOS the file is symlinked to `/var/run/resolv.conf` and
/// updated by `mDNSResponder` whenever the network changes; on Linux
/// it's typically managed by `systemd-resolved` or NetworkManager.
/// Either way, the parsed addresses are the resolvers the rest of
/// the OS is using right now — better default than the public Quad9
/// / Google / Cloudflare list when the user is on a corporate VPN
/// with split-horizon DNS.
fn build_reader_from_os() -> Option<ResolverPool> {
    let body = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    let mut hosts: Vec<HostSpec> = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        let Some(rest) = trimmed.strip_prefix("nameserver") else {
            continue;
        };
        let addr = rest.trim();
        if addr.is_empty() {
            continue;
        }
        // resolv.conf carries IP literals (no port). HostSpec parses
        // `<ip>` or `<ip>:<port>` — pass as-is and let it fail on
        // anything weird. macOS occasionally seeds `nameserver
        // 169.254.83.61%en0` with a scope id; HostSpec rejects that
        // and we skip without poisoning the pool.
        match addr.parse::<HostSpec>() {
            Ok(host) => hosts.push(host),
            Err(e) => {
                tracing::debug!(
                    addr,
                    error = %e,
                    "skipping unparseable /etc/resolv.conf nameserver line",
                );
            }
        }
    }
    if hosts.is_empty() {
        return None;
    }
    tracing::info!(
        count = hosts.len(),
        "resolver pool seeded from /etc/resolv.conf (set `resolvers:` in config to override)"
    );
    ResolverPool::new(hosts, ResolverPoolConfig::default()).ok()
}

fn build_writer(
    publish: Option<&PublishConfig>,
    cloudflare: Option<&CloudflareConfig>,
    saved_tokens: Option<&[SavedToken]>,
) -> Result<(Arc<dyn DnsRecordWriter>, bool)> {
    // Priority order:
    //   1. Cloudflare (explicit, operator-chosen)
    //   2. TSIG / publish: block (explicit, operator-chosen)
    //   3. HTTP-token (auto-detected from <config_home>/tokens/*.json
    //      saved by `dnsmesh register`)
    //   4. In-memory stub + publish_configured=false
    if let Some(cf) = cloudflare {
        let token = read_cloudflare_token(&cf.api_token_path)?;
        let cfg = CloudflarePublisherConfig::new(cf.zone_id.clone(), token);
        let writer = CloudflarePublisher::new(cfg).context("building CloudflarePublisher")?;
        return Ok((Arc::new(writer), true));
    }
    if let Some(p) = publish {
        let server = resolve_server_addr(&p.server)?;
        let algorithm = TsigAlgorithm::parse(&p.tsig_algorithm)
            .with_context(|| format!("unsupported TSIG algorithm `{}`", p.tsig_algorithm))?;
        let secret = read_tsig_secret(&p.tsig_secret_path)?;
        let key = TsigKey::new(&p.tsig_key_name, algorithm, secret)
            .context("building TSIG key from config")?;
        let cfg = DnsUpdateWriterConfig::new(p.zone.clone(), server, key);
        let writer = DnsUpdateWriter::new(cfg).context("building DnsUpdateWriter")?;
        return Ok((Arc::new(writer), true));
    }
    // No explicit config; fall back to a saved HTTP token if there is
    // one. Multiple tokens can co-exist (one per node host the user
    // ever registered against); we pick the freshest by `saved_at`.
    if let Some(tokens) = saved_tokens {
        if let Some(tok) = tokens.iter().max_by_key(|t| t.saved_at) {
            let endpoint = format!("https://{}", tok.node);
            let cfg = NodeTokenPublisherConfig::new(endpoint, tok.token.clone());
            let writer = NodeTokenPublisher::new(&cfg).context("building NodeTokenPublisher")?;
            tracing::info!(
                node = tok.node.as_str(),
                "using HTTP-token publisher (auto-detected from saved register token)"
            );
            return Ok((Arc::new(writer), true));
        }
    }
    Ok((Arc::new(InMemoryDnsStore::new()), false))
}

/// Saved bearer-token shape — same as the JSON written by
/// `commands/register.rs::run_register`.
#[derive(Debug, serde::Deserialize)]
struct SavedToken {
    node: String,
    token: String,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    saved_at: i64,
}

/// Cap on the saved-token JSON file we'll read — covers any
/// realistic token blob with a wide margin (real tokens are ~70
/// chars). Without a size limit a bloated `tokens/<host>.json` on
/// the local fs would be a trivial local-DoS vector at startup.
const MAX_TOKEN_FILE_BYTES: u64 = 16 * 1024;

/// Walk `<config_home>/tokens/` and load every `*.json` file as a
/// SavedToken, filtered to entries whose `subject` matches the
/// current `username@domain`. Returns `None` when no candidates
/// remain. A malformed JSON file is logged and skipped — a single
/// bad token shouldn't block startup.
fn discover_saved_tokens(
    config_home: &std::path::Path,
    current_subject: &str,
) -> Option<Vec<SavedToken>> {
    let dir = config_home.join("tokens");
    if !dir.is_dir() {
        return None;
    }
    let mut out: Vec<SavedToken> = Vec::new();
    let entries = std::fs::read_dir(&dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        if let Ok(meta) = std::fs::metadata(&path) {
            if meta.len() > MAX_TOKEN_FILE_BYTES {
                tracing::warn!(
                    path = %path.display(),
                    size = meta.len(),
                    "skipping oversized saved token file (>16 KiB)",
                );
                continue;
            }
        }
        let body = match std::fs::read_to_string(&path) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "skipping unreadable saved token");
                continue;
            }
        };
        match serde_json::from_str::<SavedToken>(&body) {
            Ok(t) if !t.token.is_empty() && is_safe_node_authority(&t.node) => {
                // Subject match: prefer tokens whose `subject` matches
                // the current identity. Tokens missing the subject
                // field are accepted (forward/back compat with token
                // JSON written before this filter shipped); operators
                // can re-run `dnsmesh register` to refresh.
                let subject_ok = t
                    .subject
                    .as_deref()
                    .is_none_or(|s| s.eq_ignore_ascii_case(current_subject));
                if subject_ok {
                    out.push(t);
                } else {
                    tracing::debug!(
                        path = %path.display(),
                        subject = ?t.subject,
                        current_subject,
                        "skipping saved token registered for a different subject",
                    );
                }
            }
            Ok(_) => {
                tracing::warn!(path = %path.display(), "saved token missing/malformed node/token fields; skipping");
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "saved token JSON malformed; skipping");
            }
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// True iff `s` looks like a bare host or `host:port` — no scheme,
/// no path, no userinfo. The bearer URL is built as
/// `https://{node}/v1/records/...`, so a tampered or mistyped
/// `node` field could carry path/userinfo surprises if not filtered.
fn is_safe_node_authority(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    if s.contains("://") || s.contains('/') || s.contains('@') || s.contains('?') || s.contains('#')
    {
        return false;
    }
    // Reject control chars / whitespace.
    s.chars().all(|c| !c.is_control() && !c.is_whitespace())
}

/// Read a Cloudflare API token from disk. The file holds the token
/// verbatim (no `base64:` / `hex:` envelope, unlike TSIG secrets) —
/// Cloudflare tokens are the URL-safe base64 form of an opaque blob,
/// not random bytes. Trailing whitespace / newlines are stripped so a
/// token saved with `pbpaste > token.txt` still works without a final
/// `tr -d '\n'` step.
///
/// The file-bytes buffer is held in `Zeroizing<Vec<u8>>` so the
/// on-disk token isn't left lingering in heap memory after the
/// trim/copy into the returned String. The String itself is further
/// wrapped in `Zeroizing<String>` by `CloudflarePublisherConfig`.
fn read_cloudflare_token(path: &std::path::Path) -> Result<String> {
    use zeroize::Zeroizing;
    warn_if_tsig_file_world_readable(path);
    let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
        std::fs::read(path)
            .with_context(|| format!("reading Cloudflare API token at {}", path.display()))?,
    );
    let token_str = std::str::from_utf8(&bytes)
        .with_context(|| format!("Cloudflare API token at {} must be UTF-8", path.display()))?
        .trim();
    if token_str.is_empty() {
        return Err(anyhow!(
            "Cloudflare API token file {} is empty",
            path.display()
        ));
    }
    Ok(token_str.to_string())
}

fn resolve_server_addr(server: &str) -> Result<SocketAddr> {
    server
        .to_socket_addrs()
        .with_context(|| format!("resolving DNS UPDATE server `{server}`"))?
        .next()
        .ok_or_else(|| anyhow!("server `{server}` resolved to zero addresses"))
}

/// Read a TSIG secret from disk.
///
/// Three accepted forms, in order of operator preference:
/// - `base64:<...>` — standard form, what `dnssec-keygen` and BIND ship.
/// - `hex:<...>` — handy when the operator generated via `openssl rand -hex 32`.
/// - Anything else — raw bytes, the file IS the key byte-for-byte.
///
/// We pick by prefix on the trimmed UTF-8 reading of the file; binary keys
/// without a textual prefix fall through to the raw-bytes branch.
fn read_tsig_secret(path: &std::path::Path) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine as _;

    warn_if_tsig_file_world_readable(path);

    let bytes = std::fs::read(path)
        .with_context(|| format!("reading TSIG secret at {}", path.display()))?;
    let text = std::str::from_utf8(&bytes).map_or("", str::trim);
    if let Some(b64_body) = text.strip_prefix("base64:") {
        return BASE64_STANDARD
            .decode(b64_body.trim())
            .with_context(|| format!("base64-decoding TSIG secret at {}", path.display()));
    }
    if let Some(hex_body) = text.strip_prefix("hex:") {
        return hex::decode(hex_body.trim())
            .with_context(|| format!("hex-decoding TSIG secret at {}", path.display()));
    }
    Ok(bytes)
}

/// On Unix, log a warning if the TSIG-secret file is readable by group or
/// other. We don't refuse to run — the operator may know what they're doing
/// (e.g. a baked-in container path) — but a tracing::warn is loud enough
/// that operators see the misconfiguration the first time they run anything
/// that touches the secret.
fn warn_if_tsig_file_world_readable(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // No metadata yet → the read() in the caller will surface a clearer error.
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            // Anything readable beyond owner is a hardening miss.
            if mode & 0o077 != 0 {
                tracing::warn!(
                    "TSIG secret file {} is mode 0{mode:o}; recommend `chmod 600` to scope it to the owner",
                    path.display(),
                );
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

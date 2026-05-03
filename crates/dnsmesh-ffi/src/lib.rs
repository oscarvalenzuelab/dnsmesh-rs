//! DMP UniFFI surface for Kotlin / Swift / Python bindings.
//!
//! M5 of the Rust port: a synchronous-at-the-boundary wrapper around
//! [`dnsmesh_client::DmpClient`] driven by a private `tokio` runtime.
//! Consumers in Swift / Kotlin see a blocking API and run it on their
//! own background thread when they need non-blocking semantics.
//!
//! # Why proc-macro (not .udl)?
//!
//! UniFFI 0.28 supports two scaffolding modes: the legacy `.udl` IDL
//! file and a pure-Rust proc-macro mode where every exported type /
//! function / impl is annotated and the bindgen reads the metadata back
//! out of the compiled crate. The proc-macro mode is the modern
//! recommendation, keeps the API definition next to the code that
//! implements it, and skips the `build.rs` plus `.udl` generation step
//! entirely. We use it here.
//!
//! # Why sync at the boundary?
//!
//! UniFFI's async support requires per-language runtime glue (Swift's
//! `Task`, Kotlin's coroutines) that is awkward to share between iOS
//! and Android. Driving the async client API through `runtime.block_on`
//! lets us ship one set of bindings that work identically on every
//! platform; mobile callers wrap each call in their own background
//! task / thread when responsiveness matters.
//!
//! # `test-helpers` Cargo feature
//!
//! The `test-helpers` feature gates the `InMemoryStore` object and
//! `DmpClient::new_with_shared_store` constructor. Foreign callers
//! building the default cdylib never see those types — they're an
//! in-process store that doesn't survive a crash, which is fine for
//! acceptance tests but a misuse-magnet for production. CI enables the
//! feature for `cargo test`.

use std::path::PathBuf;
use std::sync::Arc;

use dnsmesh_client::{
    Contact as ClientContact, DmpClient as InnerClient, DmpClientConfig as InnerConfig,
    InboxMessage as InnerInbox,
};
use dnsmesh_net::{
    DnsRecordReader, DnsRecordWriter, DnsUpdateWriter, DnsUpdateWriterConfig, InMemoryDnsStore,
    ResolverPool, TsigAlgorithm, TsigKey,
};
use tokio::runtime::Runtime;

uniffi::setup_scaffolding!();

/// Crate version, exposed as a free function on the FFI namespace.
#[uniffi::export]
#[must_use]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ---------------------------------------------------------------------------
// Records (UniFFI plain-old-data inputs / outputs).
// ---------------------------------------------------------------------------

/// Authoritative-DNS publish destination.
///
/// Mirrors the publish block of `dnsmesh_cli::config::PublishConfig`
/// but flattens the TSIG fields so foreign-language callers can build
/// it without poking at file paths. The TSIG secret is delivered as a
/// raw byte vector — the CLI's "base64:" / "hex:" file decoding is a
/// CLI concern, not an FFI one.
#[derive(uniffi::Record, Debug, Clone)]
pub struct PublishConfig {
    /// Authoritative zone the writer is allowed to UPDATE under
    /// (e.g. `mesh.example.com`).
    pub zone: String,
    /// Already-resolved authoritative server, in `ip:port` form
    /// (e.g. `198.51.100.7:53`). Hostname resolution is the caller's
    /// responsibility — see the docs on [`DnsUpdateWriterConfig`].
    pub server_addr: String,
    /// TSIG key name as configured on the authoritative server.
    pub tsig_key_name: String,
    /// Algorithm name, one of `hmac-sha256` / `hmac-sha384` /
    /// `hmac-sha512`. Case-insensitive; trailing dot tolerated.
    pub tsig_algorithm: String,
    /// Raw TSIG secret bytes. Treat the whole vector as the key — no
    /// base64 / hex prefix is stripped at this layer.
    ///
    /// # Secret residency
    ///
    /// This `Vec<u8>` is caller-owned heap memory. The Rust side does
    /// **not** zeroize it on drop, and UniFFI does not zeroize the
    /// foreign-language heap copy either. The original Swift `Data` /
    /// Kotlin `ByteArray` lives until the host language's GC collects
    /// it; the Rust copy lives for the lifetime of the
    /// [`DmpClient`] (it's stored inside the writer's TSIG key). Treat
    /// these bytes as long-lived secret material — minimize logging
    /// and avoid handing the same `PublishConfig` to multiple
    /// constructors if you can derive fresh values instead.
    pub tsig_secret: Vec<u8>,
}

/// Configuration handed to [`DmpClient::new`].
///
/// Construction is fully declarative: the FFI builds a tokio runtime,
/// a DNS reader and writer (per `use_well_known_resolvers` /
/// `use_in_memory_store` / `publish`), and the inner
/// [`dnsmesh_client::DmpClient`] from these fields.
#[derive(uniffi::Record, Debug, Clone)]
pub struct DmpClientConfig {
    /// DMP username (e.g. `"alice"`).
    pub username: String,
    /// Argon2id-derived passphrase used to seed the long-term identity.
    ///
    /// # Secret residency
    ///
    /// The Rust side does **not** zeroize this `String` on drop, and
    /// UniFFI does not zeroize the foreign-language heap copy either.
    /// The Swift `String` / Kotlin `String` lives until the host
    /// language's GC collects it, and the Rust copy lives until the
    /// inner [`dnsmesh_client::DmpClientConfig`] is consumed by
    /// [`DmpClient::new`] (after which the derived identity material,
    /// not the passphrase, is what's retained). Consumers who care
    /// about minimizing the secret-residency window should:
    ///
    /// - pass freshly-derived passphrases rather than long-lived
    ///   in-memory copies,
    /// - avoid logging or persisting the [`DmpClientConfig`] anywhere,
    /// - drop their handle to the config promptly after the
    ///   constructor returns.
    pub passphrase: String,
    /// Mesh zone this client publishes under (e.g. `"mesh.local"`).
    pub domain: String,
    /// Filesystem path to the local sqlite database. `None` opens an
    /// ephemeral in-memory database — fine for tests, never for
    /// production (a process restart wipes pinned contacts and
    /// prekey scalars).
    pub db_path: Option<String>,
    /// Optional Argon2id salt. Production callers should pass a
    /// per-identity random salt; `None` falls back to the crate
    /// default (matching Python).
    pub kdf_salt: Option<Vec<u8>>,
    /// `true` (the default for production) builds a [`ResolverPool`]
    /// over the eight well-known public resolvers (Google / Cloudflare /
    /// Quad9 / OpenDNS). `false` is only meaningful when paired with
    /// `use_in_memory_store=true` (tests).
    pub use_well_known_resolvers: bool,
    /// Optional authoritative-DNS publish destination. `None` means
    /// the client is read-only: any call to `publish_identity`,
    /// `refresh_prekeys`, or `send_message` returns
    /// [`FfiError::PublishNotConfigured`]. Use this for receive-only
    /// or identity-fetch deployments.
    pub publish: Option<PublishConfig>,
    /// **TEST-ONLY**: short-circuit the reader / writer and use a
    /// single shared [`InMemoryDnsStore`] for both. When `true`,
    /// `use_well_known_resolvers` and `publish` are both ignored. The
    /// store is owned by this client; two clients that need to share
    /// state must both opt in via the `shared_store` helper (see the
    /// integration tests).
    pub use_in_memory_store: bool,
}

/// A pinned identity. Mirrors [`dnsmesh_client::Contact`].
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    /// DMP username.
    pub username: String,
    /// 32-byte X25519 encryption pubkey.
    pub x25519_pk: Vec<u8>,
    /// 32-byte Ed25519 verifying key.
    pub ed25519_spk: Vec<u8>,
    /// Mesh zone the contact is published under.
    pub domain: String,
}

/// A delivered, decrypted inbox entry. Mirrors
/// [`dnsmesh_client::InboxMessage`].
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct InboxMessage {
    /// 32-byte Ed25519 verifying key of the sender, lifted verbatim
    /// from the verified slot manifest.
    pub sender_signing_pk: Vec<u8>,
    /// Decrypted plaintext.
    pub plaintext: Vec<u8>,
    /// Sender-supplied timestamp from the inner DMP header (Unix seconds).
    pub timestamp: u64,
    /// 16-byte message ID.
    pub msg_id: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

/// Errors surfaced by the FFI surface.
///
/// Each variant carries structured fields rather than a flat string so
/// Swift / Kotlin callers can pattern-match on the actionable cases
/// (`ContactNotFound`, `PublishFailed`, `NoRecordFound`, etc.) and surface
/// type-aware UI without substring-matching the message.
#[derive(uniffi::Error, Debug, thiserror::Error)]
pub enum FfiError {
    /// Configuration value rejected before any network / disk I/O.
    #[error("invalid configuration: {message}")]
    InvalidConfig {
        /// Human-readable detail about which field was rejected and why.
        message: String,
    },
    /// `publish` was `None` on the [`DmpClientConfig`] but the caller
    /// invoked a method that requires a real authoritative writer
    /// (`publish_identity`, `refresh_prekeys`, `send_message`). Set
    /// [`DmpClientConfig::publish`] to enable publish / send flows.
    #[error(
        "publish backend not configured \
         — set DmpClientConfig.publish to enable publish/send flows"
    )]
    PublishNotConfigured,
    /// The FFI method was invoked from a thread that already has a
    /// tokio runtime in scope (e.g. inside a Swift `Task` that runs on
    /// `tokio-uniffi`). Calling [`tokio::runtime::Runtime::block_on`]
    /// in that situation panics; we refuse instead. Wrap the FFI call
    /// in a fresh OS thread (or `tokio::task::spawn_blocking`) before
    /// retrying.
    #[error(
        "called from inside a tokio runtime \
         — wrap the FFI call in a background thread first"
    )]
    AlreadyInTokioContext,
    /// `add_contact` / `send_message` referenced a username that is
    /// not in the local pinned-contact store.
    #[error("contact `{username}` not found")]
    ContactNotFound {
        /// The username the caller asked for.
        username: String,
    },
    /// `send_message` could not publish a chunk or manifest because
    /// the writer rejected the request (TSIG, NXDOMAIN, etc.).
    #[error("could not publish DNS record: {message}")]
    PublishFailed {
        /// Human-readable detail mirroring the underlying writer error.
        message: String,
    },
    /// A DNS lookup returned no usable records for the queried name.
    #[error("dns record not found at `{name}`")]
    NoRecordFound {
        /// The fully-qualified DNS name we queried.
        name: String,
    },
    /// A TXT record was returned but failed signature verification or
    /// wire-format parsing.
    #[error("signature verification failed: {message}")]
    VerifyFailed {
        /// Human-readable detail about which name / record failed.
        message: String,
    },
    /// Underlying transport / sqlite / filesystem I/O failure.
    #[error("io error: {message}")]
    Io {
        /// Human-readable detail from the OS / network layer.
        message: String,
    },
    /// Catch-all for crypto / chunking / manifest internals that
    /// foreign callers cannot meaningfully react to beyond logging.
    #[error("internal error: {message}")]
    Internal {
        /// Human-readable detail preserved from the inner error.
        message: String,
    },
}

impl From<dnsmesh_client::ClientError> for FfiError {
    fn from(err: dnsmesh_client::ClientError) -> Self {
        use dnsmesh_client::ClientError as CE;
        match err {
            CE::InvalidConfig(msg) => Self::InvalidConfig { message: msg },
            CE::InvalidAddress { address } => Self::InvalidConfig {
                message: format!("invalid address {address:?}: must be in the form user@host"),
            },
            CE::ContactNotFound { username } => Self::ContactNotFound { username },
            CE::PublishFailed { kind, name } => Self::PublishFailed {
                message: format!("publish failed for {kind} at {name}"),
            },
            CE::NoRecordFound { name } => Self::NoRecordFound { name },
            CE::VerifyFailed { name } => Self::VerifyFailed {
                message: format!("record at {name} failed verification"),
            },
            CE::Net(e) => Self::Io {
                message: e.to_string(),
            },
            CE::Storage(e) => Self::Io {
                message: e.to_string(),
            },
            other @ (CE::Crypto(_)
            | CE::Identity(_)
            | CE::Prekey(_)
            | CE::Manifest(_)
            | CE::Erasure(_)
            | CE::Chunking(_)) => Self::Internal {
                message: other.to_string(),
            },
        }
    }
}

impl From<dnsmesh_net::NetError> for FfiError {
    fn from(err: dnsmesh_net::NetError) -> Self {
        Self::Io {
            message: err.to_string(),
        }
    }
}

impl From<dnsmesh_net::TsigError> for FfiError {
    fn from(err: dnsmesh_net::TsigError) -> Self {
        Self::InvalidConfig {
            message: err.to_string(),
        }
    }
}

impl From<std::io::Error> for FfiError {
    fn from(err: std::io::Error) -> Self {
        Self::Io {
            message: err.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers.
// ---------------------------------------------------------------------------

fn build_runtime() -> Result<Runtime, FfiError> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| FfiError::InvalidConfig {
            message: format!("could not build tokio runtime: {e}"),
        })
}

fn build_writer(publish: &PublishConfig) -> Result<Arc<dyn DnsRecordWriter>, FfiError> {
    let server = publish
        .server_addr
        .parse()
        .map_err(|e: std::net::AddrParseError| FfiError::InvalidConfig {
            message: format!(
                "publish.server_addr {:?} is not a valid ip:port: {e}",
                publish.server_addr,
            ),
        })?;
    let algorithm = TsigAlgorithm::parse(&publish.tsig_algorithm)?;
    let key = TsigKey::new(
        &publish.tsig_key_name,
        algorithm,
        publish.tsig_secret.clone(),
    )?;
    let cfg = DnsUpdateWriterConfig::new(publish.zone.clone(), server, key);
    let writer = DnsUpdateWriter::new(cfg)?;
    Ok(Arc::new(writer))
}

fn build_reader(use_well_known: bool) -> Result<Arc<dyn DnsRecordReader>, FfiError> {
    if use_well_known {
        let pool = ResolverPool::well_known()?;
        Ok(Arc::new(pool))
    } else {
        // Fallback for callers who set neither use_in_memory_store nor
        // use_well_known_resolvers: an empty in-memory store. They get
        // back NXDOMAIN-equivalent (None) for every query, which is
        // honest behavior for "no resolver configured."
        Ok(Arc::new(InMemoryDnsStore::new()))
    }
}

// ---------------------------------------------------------------------------
// DmpClient — the UniFFI Object exposed to Swift / Kotlin.
// ---------------------------------------------------------------------------

struct ClientInner {
    runtime: Runtime,
    client: InnerClient,
    /// `true` when this client has a real (or test-shared) writer
    /// wired up. `false` when [`DmpClientConfig::publish`] was `None`
    /// and the FFI installed a private no-op store; in that case the
    /// publish / send flows return [`FfiError::PublishNotConfigured`]
    /// instead of silently writing into a per-process bit-bucket.
    publish_configured: bool,
}

impl ClientInner {
    /// Drive `fut` to completion on the private runtime, refusing to
    /// nest if the calling thread already has a tokio runtime in
    /// scope.
    ///
    /// `Runtime::block_on` panics with "Cannot start a runtime from
    /// within a runtime" when called from inside another runtime's
    /// worker. Across an FFI boundary that panic becomes a process
    /// abort. We preflight with [`tokio::runtime::Handle::try_current`]
    /// and surface a typed error instead, which the foreign caller
    /// can recover from by wrapping the FFI call in a fresh OS thread
    /// or `tokio::task::spawn_blocking`.
    fn block_on<F, T>(&self, fut: F) -> Result<T, FfiError>
    where
        F: std::future::Future<Output = T> + Send,
        T: Send,
    {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(FfiError::AlreadyInTokioContext);
        }
        Ok(self.runtime.block_on(fut))
    }
}

/// High-level DMP client.
///
/// Exposed to Swift / Kotlin as an opaque handle. Every method is
/// synchronous: the call returns when the underlying async work
/// resolves. Callers run methods on a background thread / coroutine
/// when they need non-blocking semantics — see the module docs for
/// the rationale.
#[derive(uniffi::Object)]
pub struct DmpClient {
    inner: ClientInner,
}

#[uniffi::export]
impl DmpClient {
    /// Build a client from `config`.
    ///
    /// Returns an `Arc<Self>` because UniFFI requires owning-pointer
    /// constructors for objects.
    #[uniffi::constructor]
    pub fn new(config: DmpClientConfig) -> Result<Arc<Self>, FfiError> {
        // 1. Spin up a private multi-thread runtime up-front. The
        //    reader/writer constructors do not themselves touch the
        //    network, but DmpClient::new is async, so we need the
        //    runtime to drive it.
        let runtime = build_runtime()?;

        // 2. Decide on reader + writer. `use_in_memory_store=true` is
        //    the test-only path and short-circuits the rest. The
        //    `publish_configured` flag tracks whether publish flows
        //    will hit a real (or test-shared) writer; if it stays
        //    false, publish_identity / refresh_prekeys / send_message
        //    refuse rather than silently writing into a per-process
        //    no-op store.
        let (reader, writer, publish_configured): (
            Arc<dyn DnsRecordReader>,
            Arc<dyn DnsRecordWriter>,
            bool,
        ) = if config.use_in_memory_store {
            let store = Arc::new(InMemoryDnsStore::new());
            (store.clone(), store, true)
        } else {
            let r = build_reader(config.use_well_known_resolvers)?;
            if let Some(p) = config.publish.as_ref() {
                let w = build_writer(p)?;
                (r, w, true)
            } else {
                // No publish destination wired. Install an isolated
                // no-op store as the writer so the inner client
                // construction succeeds (it requires a writer
                // handle), but flag publish_configured=false so the
                // publish methods fail loudly instead of writing
                // into a black hole.
                let stub: Arc<dyn DnsRecordWriter> = Arc::new(InMemoryDnsStore::new());
                (r, stub, false)
            }
        };

        let inner_cfg = InnerConfig {
            username: config.username,
            passphrase: config.passphrase,
            domain: config.domain,
            kdf_salt: config.kdf_salt,
            db_path: config.db_path.map(PathBuf::from),
            writer,
            reader,
            // Rotation-chain walking is opt-in at the inner client.
            // FFI consumers don't expose the toggle yet — wire format
            // is still flagged audit-pending. Flip to true once the
            // FFI surface adds an explicit config field for it.
            rotation_chain_enabled: false,
        };

        // 3. Drive the async constructor on our private runtime. We're
        //    on the constructor's calling thread (no tokio runtime in
        //    scope yet) so block_on is safe; using Runtime::block_on
        //    directly here mirrors the helper but skips the
        //    Handle::try_current check because it would be the same
        //    answer.
        let client = runtime.block_on(InnerClient::new(inner_cfg))?;

        Ok(Arc::new(Self {
            inner: ClientInner {
                runtime,
                client,
                publish_configured,
            },
        }))
    }

    /// DMP username this client publishes under.
    pub fn username(&self) -> String {
        self.inner.client.username().to_string()
    }

    /// Hex-encoded long-term X25519 public key.
    pub fn x25519_public_key_hex(&self) -> String {
        self.inner.client.x25519_public_key_hex()
    }

    /// Hex-encoded long-term Ed25519 verifying key.
    pub fn ed25519_signing_public_key_hex(&self) -> String {
        self.inner.client.ed25519_signing_public_key_hex()
    }

    /// Publish the long-term identity TXT record.
    pub fn publish_identity(&self) -> Result<(), FfiError> {
        if !self.inner.publish_configured {
            return Err(FfiError::PublishNotConfigured);
        }
        self.inner
            .block_on(self.inner.client.publish_identity())??;
        Ok(())
    }

    /// Generate `count` new prekeys and publish them with `ttl_seconds`.
    /// Returns the number of records the writer accepted.
    pub fn refresh_prekeys(&self, count: u32, ttl_seconds: u64) -> Result<u32, FfiError> {
        if !self.inner.publish_configured {
            return Err(FfiError::PublishNotConfigured);
        }
        Ok(self
            .inner
            .block_on(self.inner.client.refresh_prekeys(count, ttl_seconds))??)
    }

    /// Fetch and verify another user's identity record.
    pub fn fetch_identity(&self, user_at_host: String) -> Result<Contact, FfiError> {
        let c = self
            .inner
            .block_on(self.inner.client.fetch_identity(&user_at_host))??;
        Ok(contact_from_client(&c))
    }

    /// Pin `contact` to the local contact store. Returns `true` on
    /// first add, `false` on overwrite.
    pub fn add_contact(&self, contact: Contact) -> Result<bool, FfiError> {
        let inner = contact_to_client(&contact)?;
        Ok(self
            .inner
            .block_on(self.inner.client.add_contact(inner))??)
    }

    /// List every pinned contact, alphabetical by username.
    pub fn list_contacts(&self) -> Result<Vec<Contact>, FfiError> {
        let listed = self.inner.block_on(self.inner.client.list_contacts())??;
        Ok(listed.iter().map(contact_from_client).collect())
    }

    /// Send an end-to-end-encrypted message to a pinned contact.
    /// Returns the 16-byte message ID.
    pub fn send_message(
        &self,
        recipient_username: String,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, FfiError> {
        if !self.inner.publish_configured {
            return Err(FfiError::PublishNotConfigured);
        }
        let id = self.inner.block_on(
            self.inner
                .client
                .send_message(&recipient_username, &plaintext),
        )??;
        Ok(id.to_vec())
    }

    /// Pull every reassembled, signature-verified message addressed
    /// to this client out of its 10 mailbox slots.
    pub fn receive_messages(&self) -> Result<Vec<InboxMessage>, FfiError> {
        let inbox = self
            .inner
            .block_on(self.inner.client.receive_messages())??;
        Ok(inbox.into_iter().map(inbox_to_ffi).collect())
    }
}

// ---------------------------------------------------------------------------
// Test-only: a Rust-constructed in-memory store handle.
//
// Gated on the `test-helpers` Cargo feature so the default cdylib (the
// artifact that ships to Swift / Kotlin) does NOT expose
// `InMemoryStore` or `DmpClient::new_with_shared_store` in its UniFFI
// metadata. CI enables the feature for `cargo test`.
// ---------------------------------------------------------------------------

/// Test-only opaque handle around an [`InMemoryDnsStore`].
///
/// Two FFI clients can share one of these via
/// [`DmpClient::new_with_shared_store`] to exercise the full
/// publish / send / receive flow without configuring real DNS. The
/// helper is gated behind the `test-helpers` Cargo feature so the
/// default cdylib (the artifact foreign callers consume) doesn't
/// expose it — an in-process store that doesn't survive a crash is
/// fine for acceptance tests but a misuse-magnet for production.
#[cfg(feature = "test-helpers")]
#[derive(uniffi::Object)]
pub struct InMemoryStore {
    handle: Arc<InMemoryDnsStore>,
}

#[cfg(feature = "test-helpers")]
#[uniffi::export]
impl InMemoryStore {
    /// Build a fresh, empty in-memory store.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            handle: Arc::new(InMemoryDnsStore::new()),
        })
    }
}

#[cfg(feature = "test-helpers")]
#[uniffi::export]
impl DmpClient {
    /// Build a client whose reader + writer point at the supplied
    /// shared [`InMemoryStore`] handle.
    ///
    /// **TEST-ONLY** (gated on the `test-helpers` Cargo feature). The
    /// integration-test flow uses it to wire two clients against one
    /// store and exercise the full happy path without DNS.
    #[uniffi::constructor]
    pub fn new_with_shared_store(
        config: DmpClientConfig,
        store: Arc<InMemoryStore>,
    ) -> Result<Arc<Self>, FfiError> {
        let runtime = build_runtime()?;
        let inner_cfg = InnerConfig {
            username: config.username,
            passphrase: config.passphrase,
            domain: config.domain,
            kdf_salt: config.kdf_salt,
            db_path: config.db_path.map(PathBuf::from),
            writer: store.handle.clone(),
            reader: store.handle.clone(),
            rotation_chain_enabled: false,
        };
        let client = runtime.block_on(InnerClient::new(inner_cfg))?;
        Ok(Arc::new(Self {
            inner: ClientInner {
                runtime,
                client,
                publish_configured: true,
            },
        }))
    }
}

// ---------------------------------------------------------------------------
// Conversions between FFI records and inner client types.
// ---------------------------------------------------------------------------

fn contact_from_client(c: &ClientContact) -> Contact {
    Contact {
        username: c.username.clone(),
        x25519_pk: c.x25519_pk.to_vec(),
        ed25519_spk: c.ed25519_spk.to_vec(),
        domain: c.domain.clone(),
    }
}

fn contact_to_client(c: &Contact) -> Result<ClientContact, FfiError> {
    let x25519_pk: [u8; 32] =
        c.x25519_pk
            .as_slice()
            .try_into()
            .map_err(|_| FfiError::InvalidConfig {
                message: format!(
                    "contact.x25519_pk must be 32 bytes; got {}",
                    c.x25519_pk.len(),
                ),
            })?;
    let ed25519_spk: [u8; 32] =
        c.ed25519_spk
            .as_slice()
            .try_into()
            .map_err(|_| FfiError::InvalidConfig {
                message: format!(
                    "contact.ed25519_spk must be 32 bytes; got {}",
                    c.ed25519_spk.len(),
                ),
            })?;
    Ok(ClientContact {
        username: c.username.clone(),
        x25519_pk,
        ed25519_spk,
        domain: c.domain.clone(),
    })
}

fn inbox_to_ffi(m: InnerInbox) -> InboxMessage {
    InboxMessage {
        sender_signing_pk: m.sender_signing_pk.to_vec(),
        plaintext: m.plaintext,
        timestamp: m.timestamp,
        msg_id: m.msg_id.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Rust-side acceptance tests.
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "test-helpers"))]
mod tests {
    use super::*;

    fn salt(prefix: &str) -> Vec<u8> {
        // Argon2id salt: at least 8 bytes. Pad to 16 to match the
        // dnsmesh-client tests so failures here don't get blamed on
        // a too-short salt when the real cause is something else.
        let mut s = prefix.as_bytes().to_vec();
        while s.len() < 16 {
            s.push(b'.');
        }
        s
    }

    fn make_config(name: &str) -> DmpClientConfig {
        DmpClientConfig {
            username: name.to_string(),
            passphrase: format!("passphrase-for-{name}"),
            domain: "mesh.local".to_string(),
            db_path: None,
            kdf_salt: Some(salt(name)),
            use_well_known_resolvers: false,
            publish: None,
            use_in_memory_store: false,
        }
    }

    #[test]
    fn version_is_set() {
        assert!(!version().is_empty());
    }

    #[test]
    fn standalone_client_with_in_memory_store_publishes_and_lists() {
        // Self-contained: one client, its own ephemeral store. Smokes
        // the construction + publish / refresh_prekeys / list_contacts
        // path end-to-end.
        let cfg = DmpClientConfig {
            use_in_memory_store: true,
            ..make_config("solo")
        };
        let client = DmpClient::new(cfg).expect("construct standalone client");

        // Identity / signing pubkeys are 32 bytes each, hex-encoded
        // (64 hex chars).
        assert_eq!(client.x25519_public_key_hex().len(), 64);
        assert_eq!(client.ed25519_signing_public_key_hex().len(), 64);
        assert_eq!(client.username(), "solo");

        client.publish_identity().expect("publish_identity");
        let n = client.refresh_prekeys(3, 3600).expect("refresh_prekeys");
        assert_eq!(n, 3, "in-memory store always accepts publishes");

        // No contacts pinned yet.
        let listed = client.list_contacts().expect("list_contacts");
        assert!(listed.is_empty());
    }

    #[test]
    fn fetch_identity_rejects_malformed_address() {
        // The address parser surfaces invalid-config — confirm the
        // typed variant comes out so foreign callers can match on it
        // structurally.
        let cfg = DmpClientConfig {
            use_in_memory_store: true,
            ..make_config("fetch-bad")
        };
        let client = DmpClient::new(cfg).expect("construct");
        let err = client.fetch_identity("not-an-address".into()).unwrap_err();
        assert!(
            matches!(err, FfiError::InvalidConfig { .. }),
            "expected InvalidConfig, got {err:?}",
        );
    }

    #[test]
    fn alice_to_bob_round_trip_through_shared_store() {
        // Closes the M5 acceptance loop: two FFI clients share one
        // in-memory store, both publish, alice pins bob, alice sends,
        // bob receives, and the plaintext round-trips through the
        // FFI wire types byte-for-byte. Replay-cache dedup is
        // covered by the second receive_messages call.
        let store = InMemoryStore::new();

        let alice_cfg = make_config("alice");
        let bob_cfg = make_config("bob");
        let alice =
            DmpClient::new_with_shared_store(alice_cfg, store.clone()).expect("alice construction");
        let bob = DmpClient::new_with_shared_store(bob_cfg, store).expect("bob construction");

        alice.publish_identity().expect("alice publish_identity");
        bob.publish_identity().expect("bob publish_identity");
        alice.refresh_prekeys(5, 3600).expect("alice prekeys");
        bob.refresh_prekeys(5, 3600).expect("bob prekeys");

        // Alice fetches + pins bob (sender-side requirement).
        let bob_contact = alice
            .fetch_identity("bob@mesh.local".into())
            .expect("fetch bob");
        assert_eq!(bob_contact.username, "bob");
        assert_eq!(bob_contact.x25519_pk.len(), 32);
        assert_eq!(bob_contact.ed25519_spk.len(), 32);
        assert_eq!(bob_contact.domain, "mesh.local");
        let added = alice.add_contact(bob_contact.clone()).expect("add bob");
        assert!(added, "first pin must report newly-added");

        // Bob pins alice so we exercise pinned-contact mode (not TOFU)
        // on the receive side.
        let alice_contact = bob
            .fetch_identity("alice@mesh.local".into())
            .expect("fetch alice");
        bob.add_contact(alice_contact).expect("pin alice");

        // Alice sends a non-trivial plaintext (non-empty, non-ASCII)
        // so any silent encoding bug at the FFI boundary surfaces.
        let plaintext = b"hello bob from alice via the FFI \xC3\xA9".to_vec();
        let msg_id = alice
            .send_message("bob".into(), plaintext.clone())
            .expect("send_message");
        assert_eq!(msg_id.len(), 16, "msg_id must be 16 bytes");

        // Bob receives — exactly one inbox entry, decrypted plaintext
        // matches, sender_signing_pk == alice's verifying key.
        let inbox = bob.receive_messages().expect("receive_messages");
        assert_eq!(inbox.len(), 1, "bob must see exactly one new message");
        assert_eq!(inbox[0].plaintext, plaintext);
        assert_eq!(inbox[0].msg_id, msg_id);
        let alice_spk_hex = alice.ed25519_signing_public_key_hex();
        assert_eq!(hex::encode(&inbox[0].sender_signing_pk), alice_spk_hex);

        // Replay-cache dedup: a second receive returns nothing.
        let again = bob.receive_messages().expect("second receive");
        assert!(again.is_empty(), "replay cache must dedup; got {again:?}");
    }

    #[test]
    fn add_contact_round_trips_through_ffi_wire_shape() {
        // The Contact record uses Vec<u8> on the wire (UniFFI doesn't
        // have a fixed-size [u8; 32] type). Confirm the byte-length
        // validation rejects malformed inputs cleanly so foreign
        // callers don't crash the bindgen with a panic.
        let cfg = DmpClientConfig {
            use_in_memory_store: true,
            ..make_config("contact-shape")
        };
        let client = DmpClient::new(cfg).expect("construct");
        let bad = Contact {
            username: "shorty".into(),
            x25519_pk: vec![0xAA; 16], // wrong length
            ed25519_spk: vec![0xBB; 32],
            domain: "mesh.local".into(),
        };
        let err = client.add_contact(bad).unwrap_err();
        assert!(
            matches!(err, FfiError::InvalidConfig { .. }),
            "wrong-length pk must surface InvalidConfig, got {err:?}",
        );
    }

    #[test]
    fn send_message_to_unknown_contact_surfaces_typed_contact_not_found() {
        // The structured-variant FFI errors (replacing the older
        // flat_error string match) must surface `ContactNotFound`
        // verbatim — that's the variant Swift / Kotlin will switch on.
        let cfg = DmpClientConfig {
            use_in_memory_store: true,
            ..make_config("nobody-loves-me")
        };
        let client = DmpClient::new(cfg).expect("construct");
        let err = client
            .send_message("ghost".into(), b"x".to_vec())
            .unwrap_err();
        match err {
            FfiError::ContactNotFound { username } => {
                assert_eq!(username, "ghost");
            }
            other => panic!("expected ContactNotFound, got {other:?}"),
        }
    }

    #[test]
    fn publish_methods_refuse_when_publish_unconfigured() {
        // When `publish == None` and `use_in_memory_store == false`,
        // the writer is a private no-op store and any publish flow
        // MUST refuse rather than silently write into a bit-bucket.
        // Use a real reader (empty in-memory store via
        // use_well_known_resolvers=false) so construction succeeds
        // without network I/O.
        let cfg = DmpClientConfig {
            use_in_memory_store: false,
            use_well_known_resolvers: false,
            publish: None,
            ..make_config("no-publish")
        };
        let client = DmpClient::new(cfg).expect("construct read-only client");

        assert!(
            matches!(
                client.publish_identity().unwrap_err(),
                FfiError::PublishNotConfigured
            ),
            "publish_identity must refuse when publish is unconfigured",
        );
        assert!(
            matches!(
                client.refresh_prekeys(3, 3600).unwrap_err(),
                FfiError::PublishNotConfigured
            ),
            "refresh_prekeys must refuse when publish is unconfigured",
        );
        assert!(
            matches!(
                client
                    .send_message("anyone".into(), b"hi".to_vec())
                    .unwrap_err(),
                FfiError::PublishNotConfigured
            ),
            "send_message must refuse when publish is unconfigured",
        );
    }

    #[test]
    fn block_on_refuses_to_nest_inside_a_running_runtime() {
        // ClientInner::block_on preflights with Handle::try_current
        // and surfaces AlreadyInTokioContext instead of panicking.
        // Drive the test from inside a freshly-built runtime's
        // block_on (so Handle::try_current returns Ok on the test
        // thread) and confirm a method call returns the typed error
        // instead of aborting.
        let cfg = DmpClientConfig {
            use_in_memory_store: true,
            ..make_config("nested")
        };
        let client = DmpClient::new(cfg).expect("construct");

        let outer = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build outer runtime");

        let result = outer.block_on(async {
            // We're now inside outer's worker. Calling any FFI method
            // should refuse rather than panic.
            client.list_contacts()
        });

        match result {
            Err(FfiError::AlreadyInTokioContext) => {}
            other => panic!("expected AlreadyInTokioContext, got {other:?}"),
        }
    }
}

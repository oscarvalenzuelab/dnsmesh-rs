//! [`DmpClient`] — high-level send/receive entry point.
//!
//! Phase-2A scope ships construction, identity accessors, contact management,
//! identity / prekey publishing, and the send path. Receive lands in 2B.

use std::path::PathBuf;
use std::sync::Arc;

use dnsmesh_core::crypto::{derive_user_id, DmpCrypto, STORAGE_KEY_LEN};
use dnsmesh_net::{DnsRecordReader, DnsRecordWriter};
use dnsmesh_storage::{ContactStore, IntroQueue, OpenedDb, PrekeyStore, ReplayCache};
use zeroize::Zeroizing;

use crate::error::ClientError;

/// Configuration handed to [`DmpClient::new`].
///
/// `writer` and `reader` are passed as `Arc<dyn …>` so the client clones the
/// handles into its async tasks without hard-coding a backend.  In the tests
/// both halves point at one `Arc<InMemoryDnsStore>`; in production they point
/// at distinct backends (recursive resolver vs authoritative writer).
pub struct DmpClientConfig {
    /// DMP username (e.g. `"alice"`). Used to derive the identity DNS label
    /// and embedded into every published [`dnsmesh_core::identity::IdentityRecord`].
    pub username: String,
    /// Argon2id-derived passphrase that produces the identity's X25519 seed.
    /// Forwarded verbatim to [`DmpCrypto::from_passphrase`].
    pub passphrase: String,
    /// Mesh zone, e.g. `"mesh.local"`. Identity / prekey / slot / chunk names
    /// are anchored under this zone.
    pub domain: String,
    /// Optional Argon2id salt. Defaults to
    /// [`dnsmesh_core::DEFAULT_ARGON2_SALT`] when `None`.  Production callers
    /// should always supply a per-identity random salt.
    pub kdf_salt: Option<Vec<u8>>,
    /// Where to keep the local sqlite database.  `None` opens an in-memory db
    /// (tests / ephemeral runs).
    pub db_path: Option<PathBuf>,
    /// DNS writer used for publish operations (identity, prekeys, manifest,
    /// chunks).
    pub writer: Arc<dyn DnsRecordWriter>,
    /// DNS reader used for lookups (other users' identities and prekey pools).
    pub reader: Arc<dyn DnsRecordReader>,
    /// EXPERIMENTAL (M5.4): walk the published rotation chain on a
    /// receive verify-failure to discover whether a pinned contact has
    /// rotated to a new key, and cross-check pinned-key manifests
    /// against published revocations. Disabled by default — wire format
    /// for rotation/revocation records is still flagged for audit-driven
    /// revision in v0.3.0 of the Python source-of-truth.
    pub rotation_chain_enabled: bool,
}

impl std::fmt::Debug for DmpClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DmpClientConfig")
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("kdf_salt_present", &self.kdf_salt.is_some())
            .field("db_path", &self.db_path)
            .finish_non_exhaustive()
    }
}

/// High-level DMP client.
///
/// Holds the long-term identity, the local prekey + contact stores, and
/// references to the DNS reader / writer backends. Cloning is intentionally
/// not supported — the local sqlite handles are owned, and clients are
/// expected to live for the lifetime of the application.
pub struct DmpClient {
    pub(crate) username: String,
    pub(crate) domain: String,
    pub(crate) crypto: DmpCrypto,
    pub(crate) user_id: [u8; 32],
    pub(crate) writer: Arc<dyn DnsRecordWriter>,
    pub(crate) reader: Arc<dyn DnsRecordReader>,
    pub(crate) prekeys: PrekeyStore,
    pub(crate) contacts: ContactStore,
    /// Phase-2B receive-path dedup. Holds (sender_spk, msg_id) pairs
    /// keyed on the manifest's `exp` field so entries auto-expire in
    /// step with the manifest TTL. Lives behind the same sqlite file as
    /// the prekey + contact stores when `db_path` is `Some`.
    pub(crate) replay_cache: ReplayCache,
    /// First-contact quarantine for un-pinned senders. The receive path
    /// writes an entry here in pinned-contacts mode whenever a
    /// signature-valid manifest arrives from a `sender_spk` not in the
    /// pinned set; the user reviews it via `dnsmesh intro list/accept/
    /// trust/block`. Same sqlite file as the other stores when
    /// `db_path` is `Some`.
    pub(crate) intro_queue: IntroQueue,
    /// Per-config opt-in for the rotation-chain walking on receive
    /// verify failures (and the symmetric revocation cross-check on
    /// pinned-key successes). Off by default — the wire format for
    /// rotation/revocation records is still pre-audit in the Python
    /// source-of-truth.
    pub(crate) rotation_chain_enabled: bool,
}

impl std::fmt::Debug for DmpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DmpClient")
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("user_id", &hex::encode(self.user_id))
            .finish_non_exhaustive()
    }
}

impl DmpClient {
    /// Build a client from `config`.
    ///
    /// Opens the sqlite database (file or in-memory), runs migrations, and
    /// derives the identity from the passphrase. Does NOT touch the network —
    /// in particular, [`Self::publish_identity`] and
    /// [`Self::refresh_prekeys`] are separate calls so that callers can decide
    /// when to publish.
    ///
    /// The `async` here is API-stable scaffolding: the body is currently
    /// synchronous (Argon2id KDF + sqlite open) but a future revision is
    /// expected to run those on a blocking pool, and we don't want to break
    /// callers when that lands.
    #[allow(clippy::unused_async)]
    pub async fn new(config: DmpClientConfig) -> Result<Self, ClientError> {
        if config.username.trim().is_empty() {
            return Err(ClientError::InvalidConfig(
                "username must not be empty".to_string(),
            ));
        }
        if config.domain.trim().is_empty() {
            return Err(ClientError::InvalidConfig(
                "domain must not be empty".to_string(),
            ));
        }

        let crypto = DmpCrypto::from_passphrase(&config.passphrase, config.kdf_salt.as_deref())?;
        let user_id = derive_user_id(&crypto.public_key_bytes());

        // PrekeyStore + ContactStore each take their own Connection, so we
        // open the database twice. Sqlite under WAL handles cross-connection
        // locking for us; the cost is one fd per store, which is fine for the
        // lifetime of a client.
        let prekeys = match &config.db_path {
            Some(path) => PrekeyStore::new(OpenedDb::open(path)?),
            None => PrekeyStore::new(OpenedDb::open_in_memory()?),
        };
        let contacts = match &config.db_path {
            Some(path) => ContactStore::new(OpenedDb::open(path)?),
            None => ContactStore::new(OpenedDb::open_in_memory()?),
        };
        let replay_cache = match &config.db_path {
            Some(path) => ReplayCache::new(OpenedDb::open(path)?),
            None => ReplayCache::new(OpenedDb::open_in_memory()?),
        };
        let intro_queue = match &config.db_path {
            Some(path) => IntroQueue::new(OpenedDb::open(path)?),
            None => IntroQueue::new(OpenedDb::open_in_memory()?),
        };

        Ok(Self {
            username: config.username,
            domain: config.domain,
            crypto,
            user_id,
            writer: config.writer,
            reader: config.reader,
            prekeys,
            contacts,
            replay_cache,
            intro_queue,
            rotation_chain_enabled: config.rotation_chain_enabled,
        })
    }

    /// DMP username this client publishes under.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Mesh zone this client is anchored to.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Derive this identity's local at-rest storage key.
    ///
    /// Exposed so host applications can encrypt their own per-identity
    /// files under the same key the SDK uses for local storage, instead of
    /// inventing a second scheme. The desktop client needs this for its
    /// persisted message history.
    ///
    /// See [`DmpCrypto::derive_storage_key`] for the derivation. The result
    /// is zeroized on drop; don't persist it and don't put it on the wire.
    #[must_use]
    pub fn storage_key(&self) -> Zeroizing<[u8; STORAGE_KEY_LEN]> {
        self.crypto.derive_storage_key()
    }

    /// Hex-encoded long-term X25519 public key.
    #[must_use]
    pub fn x25519_public_key_hex(&self) -> String {
        hex::encode(self.crypto.public_key_bytes())
    }

    /// Hex-encoded long-term Ed25519 verifying key.
    #[must_use]
    pub fn ed25519_signing_public_key_hex(&self) -> String {
        hex::encode(self.crypto.signing_public_key_bytes())
    }

    /// SHA-256 over this identity's X25519 public key — the user ID embedded
    /// into routing labels and signed manifests.
    #[must_use]
    pub fn user_id(&self) -> [u8; 32] {
        self.user_id
    }
}

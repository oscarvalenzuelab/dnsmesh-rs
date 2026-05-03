//! Errors surfaced by the high-level [`crate::DmpClient`] API.
//!
//! Wraps the lower-layer errors verbatim via `#[from]` so callers can match on
//! the concrete cause when they need to (e.g. distinguish a verify failure from
//! a transport failure) but still have one umbrella type to pass around.

use dnsmesh_core::chunking::ChunkingError;
use dnsmesh_core::crypto::CryptoError;
use dnsmesh_core::erasure::ErasureError;
use dnsmesh_core::identity::IdentityError;
use dnsmesh_core::manifest::ManifestError;
use dnsmesh_core::prekeys::PrekeyError;
use dnsmesh_net::NetError;
use dnsmesh_storage::StorageError;

/// Errors returned by [`crate::DmpClient`].
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The supplied configuration was invalid (e.g. empty username, empty
    /// domain, salt too short for Argon2id).
    #[error("invalid client configuration: {0}")]
    InvalidConfig(String),

    /// `fetch_identity` was given a string that did not parse as `user@host`.
    #[error("invalid address {address:?}: must be in the form user@host")]
    InvalidAddress {
        /// The address string the caller supplied.
        address: String,
    },

    /// A DNS lookup returned no usable records for the queried name.
    #[error("no records found at {name}")]
    NoRecordFound {
        /// The fully-qualified DNS name we queried.
        name: String,
    },

    /// A TXT record was returned but failed signature verification or wire
    /// parsing.
    #[error("record at {name} failed verification")]
    VerifyFailed {
        /// The fully-qualified DNS name we queried.
        name: String,
    },

    /// `add_contact` / `send_message` referenced a username that is not in
    /// the local contact store.
    #[error("contact {username:?} is not pinned")]
    ContactNotFound {
        /// The username the caller asked for.
        username: String,
    },

    /// `send_message` could not publish a chunk or the manifest TXT record
    /// because the writer rejected the request.
    #[error("publish failed for {kind} at {name}")]
    PublishFailed {
        /// What we were trying to publish — `"chunk"`, `"manifest"`, etc.
        kind: &'static str,
        /// Fully-qualified DNS name we tried to write.
        name: String,
    },

    /// Crypto layer failed (Argon2id KDF, ECDH, AEAD).
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// Identity-record builder rejected a username (length, encoding) or
    /// failed verification on parse.
    #[error(transparent)]
    Identity(#[from] IdentityError),

    /// Prekey-record builder rejected a body shape.
    #[error(transparent)]
    Prekey(#[from] PrekeyError),

    /// Manifest builder rejected a chunk count or could not be signed.
    #[error(transparent)]
    Manifest(#[from] ManifestError),

    /// Erasure encoder rejected the plaintext (too large) or a redundancy
    /// argument.
    #[error(transparent)]
    Erasure(#[from] ErasureError),

    /// Per-chunk RS+checksum wrapper rejected a block.
    #[error(transparent)]
    Chunking(#[from] ChunkingError),

    /// Underlying DNS reader/writer surfaced a transport or config error.
    #[error(transparent)]
    Net(#[from] NetError),

    /// Sqlite-backed local stores surfaced an error.
    #[error(transparent)]
    Storage(#[from] StorageError),
}

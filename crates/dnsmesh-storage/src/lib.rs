//! DMP local persistence for keys, sessions, and message state.
//!
//! Each DMP identity owns one sqlite file (`~/.dmp/dmp-rs.sqlite` by
//! default) holding four tables:
//!
//!   - [`prekeys::PrekeyStore`]   — one-time X25519 prekey *private*
//!     halves. The forward-secrecy fix (delete on `consume`) lives
//!     here; see the module docs for the rationale.
//!   - [`intro_queue::IntroQueue`] — quarantined first-contact messages
//!     awaiting user accept/reject in the CLI.
//!   - [`replay_cache::ReplayCache`] — `(sender_spk, msg_id)` dedup with
//!     a TTL. Replaces the Python client's JSON-file persistence.
//!   - [`contacts::ContactStore`]  — persisted address book with the
//!     `--require-signing-key` trust flag. New in the Rust port.
//!
//! Schema is versioned via [`refinery`]; [`connection::OpenedDb::open`]
//! applies pending migrations on every open. Stores hold a single
//! [`rusqlite::Connection`] behind a `parking_lot::Mutex`; rusqlite is
//! sync, so callers in async contexts wrap calls in
//! `tokio::task::spawn_blocking` at the high-level client layer.
//!
//! The on-disk file is intentionally separate from the Python client's
//! `~/.dmp/dmp.sqlite` so a user running both clients on one identity
//! won't have their writes serialize through the same sqlite lock.

pub mod connection;
pub mod contacts;
pub mod error;
pub mod intro_queue;
pub mod prekeys;
pub mod replay_cache;

mod migrations;

pub use connection::{default_db_path, OpenedDb};
pub use contacts::{Contact, ContactStore, NewContact};
pub use error::StorageError;
pub use intro_queue::{IntroQueue, NewIntro, PendingIntro};
pub use prekeys::{GeneratedPrekey, PrekeyStore};
pub use replay_cache::{ReplayCache, DEFAULT_TTL_SECS};

/// Crate version, used by health-check / `dnsmesh --version` style code.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!version().is_empty());
    }
}

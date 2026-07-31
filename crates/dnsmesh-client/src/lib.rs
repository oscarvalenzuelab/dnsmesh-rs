//! DMP high-level client API.
//!
//! Closes M3 of the Rust port: identity construction, identity / prekey
//! publishing, contact management, and the full end-to-end-encrypted
//! send + receive flow.
//!
//! See [`DmpClient`] for the entry point.

pub mod addressing;
pub mod claim;
pub mod client;
pub mod contacts;
pub mod error;
pub mod intro;
pub mod publish;
pub mod receive;
pub mod rotate;
pub(crate) mod rotation_chain;
pub mod send;
pub mod unpublish;

pub use claim::{ClaimFailure, ClaimSend};
pub use client::{DmpClient, DmpClientConfig};
pub use contacts::Contact;
pub use error::ClientError;
pub use intro::DeliveredIntro;
pub use receive::InboxMessage;
pub use rotate::{
    RotateOutcome, RotateReason, DEFAULT_ROTATION_EXP_SECONDS, DEFAULT_ROTATION_TTL_SECONDS,
};
pub use unpublish::UnpublishReport;
// Re-export PendingIntro so CLI / FFI consumers don't have to take a
// direct dnsmesh-storage dep just to render `dnsmesh intro list`.
pub use dnsmesh_storage::PendingIntro;

/// Crate version.
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

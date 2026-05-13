//! DMP protocol primitives, crypto, and wire format.

pub mod bootstrap;
pub mod chunking;
pub mod claim;
pub mod cluster;
pub mod crypto;
pub mod ed25519_points;
pub mod envelope;
pub mod erasure;
pub mod heartbeat;
pub mod identity;
pub mod manifest;
pub mod message;
pub mod prekeys;
pub mod revocation;
pub mod rotation;

pub use crypto::{
    derive_user_id, deterministic_nonce, CryptoError, DmpCrypto, EncryptedMessage,
    DEFAULT_ARGON2_SALT, ED25519_DOMAIN, ED25519_KEY_LEN, ED25519_SIG_LEN, HKDF_INFO, HKDF_SALT,
    NONCE_LEN, X25519_KEY_LEN,
};

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

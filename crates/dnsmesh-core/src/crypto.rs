//! Cryptographic operations for DMP protocol.
//!
//! Each DMP identity has TWO keypairs:
//! - X25519 for ECDH key exchange + ChaCha20-Poly1305 message encryption
//! - Ed25519 for sender authentication via signatures
//!
//! The Ed25519 signing key is deterministically derived from the X25519 private key
//! bytes (domain-separated SHA-256), so a passphrase yields the same full identity.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Argon2id time cost (iterations) used by [`DmpCrypto::from_passphrase`].
pub const ARGON2_TIME_COST: u32 = 2;
/// Argon2id memory cost in KiB (32 MiB).
pub const ARGON2_MEMORY_COST_KIB: u32 = 32 * 1024;
/// Argon2id parallelism factor.
pub const ARGON2_PARALLELISM: u32 = 2;
/// Argon2id output length in bytes (X25519 seed size).
pub const ARGON2_HASH_LEN: usize = 32;

/// Domain separator for deriving the Ed25519 seed from the X25519 private key.
///
/// `ed25519_seed = SHA-256(x25519_private_bytes || ED25519_DOMAIN)`.
pub const ED25519_DOMAIN: &[u8] = b"DMP-v1-Ed25519-signing-key";

/// Default Argon2id salt used when callers don't supply one.
///
/// This is a fixed sentinel for tests/demos and is intentionally weak. Production callers
/// should pass a per-identity random salt.
pub const DEFAULT_ARGON2_SALT: &[u8] = b"DMP-default-v2-argon2id";

/// HKDF salt used to derive ChaCha20 keys from ECDH shared secrets.
pub const HKDF_SALT: &[u8] = b"DMP-v1";
/// HKDF info string for the message-encryption key derivation.
pub const HKDF_INFO: &[u8] = b"DMP-Message-Encryption";

/// X25519 public/private key length.
pub const X25519_KEY_LEN: usize = 32;
/// Ed25519 public/signing-public key length.
pub const ED25519_KEY_LEN: usize = 32;
/// Ed25519 signature length.
pub const ED25519_SIG_LEN: usize = 64;
/// ChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 12;

const MIN_ENCRYPTED_LEN: usize = X25519_KEY_LEN + NONCE_LEN;

/// Errors returned by crypto primitives.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// A 32-byte key was expected but a different number of bytes was supplied.
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    /// `EncryptedMessage::from_bytes` was given fewer than 44 bytes.
    #[error("encrypted message too short: {len} bytes (need at least {min})")]
    EncryptedMessageTooShort { len: usize, min: usize },
    /// AEAD authentication failed during decryption.
    #[error("aead authentication failed")]
    AeadFailure,
    /// X25519 ECDH produced a non-contributory (all-zero) shared secret. Indicates a low-order
    /// or malformed peer public key; refuse to derive an AEAD key from it.
    #[error("x25519 shared secret is non-contributory")]
    NonContributoryEcdh,
    /// Argon2 parameters or password derivation failed.
    #[error("argon2: {0}")]
    Argon2(String),
    /// `from_passphrase` was given a salt shorter than 8 bytes.
    #[error("salt must be at least 8 bytes")]
    SaltTooShort,
}

/// Container for an ECDH + ChaCha20-Poly1305 ciphertext.
///
/// Wire layout (matches Python `EncryptedMessage.to_bytes`):
///
/// ```text
/// ephemeral_public_key (32) || nonce (12) || ciphertext (variable, includes 16-byte Poly1305 tag)
/// ```
///
/// The ciphertext is opaque to this struct — the caller frames the outer message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedMessage {
    /// X25519 ephemeral public key the sender used for ECDH.
    pub ephemeral_public_key: [u8; X25519_KEY_LEN],
    /// 12-byte ChaCha20-Poly1305 nonce.
    pub nonce: [u8; NONCE_LEN],
    /// ChaCha20-Poly1305 ciphertext, including the 16-byte authentication tag.
    pub ciphertext: Vec<u8>,
}

impl EncryptedMessage {
    /// Serialize as `ephemeral_public_key || nonce || ciphertext` with no length framing.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MIN_ENCRYPTED_LEN + self.ciphertext.len());
        out.extend_from_slice(&self.ephemeral_public_key);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parse from `ephemeral_public_key || nonce || ciphertext`.
    ///
    /// Matches the Python parser: requires at least 44 bytes, allows zero-length ciphertext
    /// (which can never authenticate but is permitted at parse time).
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < MIN_ENCRYPTED_LEN {
            return Err(CryptoError::EncryptedMessageTooShort {
                len: data.len(),
                min: MIN_ENCRYPTED_LEN,
            });
        }
        let mut ephemeral_public_key = [0u8; X25519_KEY_LEN];
        ephemeral_public_key.copy_from_slice(&data[..X25519_KEY_LEN]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&data[X25519_KEY_LEN..MIN_ENCRYPTED_LEN]);
        Ok(Self {
            ephemeral_public_key,
            nonce,
            ciphertext: data[MIN_ENCRYPTED_LEN..].to_vec(),
        })
    }
}

/// A 32-byte X25519 private seed wrapped to zero on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct PrivateSeed([u8; X25519_KEY_LEN]);

/// Core DMP crypto identity: long-term X25519 keypair plus a deterministically-derived
/// Ed25519 signing keypair.
pub struct DmpCrypto {
    /// Original input bytes used to seed this identity. Kept verbatim because Python's
    /// `X25519PrivateKey.private_bytes(Raw, Raw)` returns the unclamped input, and the
    /// Ed25519 domain-separated derivation hashes those exact bytes. Clamping happens
    /// inside the X25519 scalar arithmetic transparently.
    private_seed: PrivateSeed,
    x25519_secret: StaticSecret,
    x25519_public: X25519PublicKey,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl std::fmt::Debug for DmpCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DmpCrypto")
            .field("x25519_public", &hex::encode(self.x25519_public.to_bytes()))
            .field("verifying_key", &hex::encode(self.verifying_key.to_bytes()))
            .finish_non_exhaustive()
    }
}

impl DmpCrypto {
    /// Generate a fresh random identity using the OS RNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut seed = [0u8; X25519_KEY_LEN];
        OsRng.fill_bytes(&mut seed);
        let crypto =
            Self::from_private_bytes(&seed).expect("32 bytes is always a valid X25519 seed");
        seed.zeroize();
        crypto
    }

    /// Construct an identity from a 32-byte X25519 private seed.
    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != X25519_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: X25519_KEY_LEN,
                actual: bytes.len(),
            });
        }
        let mut seed = [0u8; X25519_KEY_LEN];
        seed.copy_from_slice(bytes);

        let x25519_secret = StaticSecret::from(seed);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        // Ed25519 seed = SHA-256(x25519_private_seed || ED25519_DOMAIN). Use the original
        // input bytes (unclamped) because that is what Python feeds into the SHA-256.
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(ED25519_DOMAIN);
        let ed_seed: [u8; 32] = hasher.finalize().into();

        let signing_key = SigningKey::from_bytes(&ed_seed);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            private_seed: PrivateSeed(seed),
            x25519_secret,
            x25519_public,
            signing_key,
            verifying_key,
        })
    }

    /// Derive an identity from a passphrase using Argon2id.
    ///
    /// `salt` defaults to [`DEFAULT_ARGON2_SALT`] (a fixed sentinel; intentionally weak).
    /// Production callers should pass a per-identity random salt of at least 8 bytes.
    pub fn from_passphrase(passphrase: &str, salt: Option<&[u8]>) -> Result<Self, CryptoError> {
        let salt = salt.unwrap_or(DEFAULT_ARGON2_SALT);
        if salt.len() < 8 {
            return Err(CryptoError::SaltTooShort);
        }
        let params = Params::new(
            ARGON2_MEMORY_COST_KIB,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            Some(ARGON2_HASH_LEN),
        )
        .map_err(|e| CryptoError::Argon2(e.to_string()))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut output = [0u8; ARGON2_HASH_LEN];
        argon2
            .hash_password_into(passphrase.as_bytes(), salt, &mut output)
            .map_err(|e| CryptoError::Argon2(e.to_string()))?;
        let crypto = Self::from_private_bytes(&output)?;
        output.zeroize();
        Ok(crypto)
    }

    /// Raw 32-byte X25519 public key.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; X25519_KEY_LEN] {
        self.x25519_public.to_bytes()
    }

    /// Raw 32-byte X25519 private seed (matches Python's `get_private_key_bytes`).
    #[must_use]
    pub fn private_key_bytes(&self) -> [u8; X25519_KEY_LEN] {
        self.private_seed.0
    }

    /// Raw 32-byte Ed25519 signing public key.
    #[must_use]
    pub fn signing_public_key_bytes(&self) -> [u8; ED25519_KEY_LEN] {
        self.verifying_key.to_bytes()
    }

    /// Sign `data` with the Ed25519 signing key. Returns a 64-byte signature.
    #[must_use]
    pub fn sign_data(&self, data: &[u8]) -> [u8; ED25519_SIG_LEN] {
        self.signing_key.sign(data).to_bytes()
    }

    /// Encrypt `plaintext` for `recipient_public_key` using ECDH + ChaCha20-Poly1305.
    ///
    /// A fresh ephemeral X25519 keypair and 12-byte random nonce are generated per call.
    pub fn encrypt_for_recipient(
        &self,
        plaintext: &[u8],
        recipient_public_key: &[u8; X25519_KEY_LEN],
        aad: Option<&[u8]>,
    ) -> Result<EncryptedMessage, CryptoError> {
        let mut ephemeral_seed = [0u8; X25519_KEY_LEN];
        OsRng.fill_bytes(&mut ephemeral_seed);
        let ephemeral_secret = StaticSecret::from(ephemeral_seed);
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
        ephemeral_seed.zeroize();

        let recipient = X25519PublicKey::from(*recipient_public_key);
        let shared = ephemeral_secret.diffie_hellman(&recipient);
        if !shared.was_contributory() {
            return Err(CryptoError::NonContributoryEcdh);
        }

        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(HKDF_SALT), shared.as_bytes())
            .expand(HKDF_INFO, &mut key)
            .expect("32 bytes is within HKDF-SHA256's output length budget");

        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);

        let cipher = ChaCha20Poly1305::new(&key.into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: aad.unwrap_or(&[]),
                },
            )
            .map_err(|_| CryptoError::AeadFailure)?;

        key.zeroize();

        Ok(EncryptedMessage {
            ephemeral_public_key: ephemeral_public.to_bytes(),
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    /// Decrypt `msg` with the long-term X25519 private key.
    pub fn decrypt_message(
        &self,
        msg: &EncryptedMessage,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        Self::decrypt_with_secret(&self.x25519_secret, msg, aad)
    }

    /// Decrypt `msg` with an alternate X25519 private key (e.g. a one-time prekey).
    pub fn decrypt_message_with_secret(
        msg: &EncryptedMessage,
        aad: Option<&[u8]>,
        secret: &StaticSecret,
    ) -> Result<Vec<u8>, CryptoError> {
        Self::decrypt_with_secret(secret, msg, aad)
    }

    fn decrypt_with_secret(
        secret: &StaticSecret,
        msg: &EncryptedMessage,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        let ephemeral_public = X25519PublicKey::from(msg.ephemeral_public_key);
        let shared = secret.diffie_hellman(&ephemeral_public);
        if !shared.was_contributory() {
            return Err(CryptoError::NonContributoryEcdh);
        }

        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(HKDF_SALT), shared.as_bytes())
            .expand(HKDF_INFO, &mut key)
            .expect("32 bytes is within HKDF-SHA256's output length budget");

        let cipher = ChaCha20Poly1305::new(&key.into());
        let nonce = Nonce::from_slice(&msg.nonce);
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &msg.ciphertext,
                    aad: aad.unwrap_or(&[]),
                },
            )
            .map_err(|_| CryptoError::AeadFailure);

        key.zeroize();
        plaintext
    }

    /// Verify an Ed25519 signature against a raw 32-byte public key.
    ///
    /// Returns `false` on any error. Uses [`VerifyingKey::verify_strict`] so non-canonical R
    /// values, malleable signatures, and low-order public keys are rejected up front. This is
    /// stricter than `verify` (the permissive RFC-8032 form) and stricter than what the Python
    /// reference does, but every signature legitimately produced by [`DmpCrypto::sign_data`] is
    /// strict-valid, so the change is safe for happy-path interop and removes a class of weak-key
    /// forgeries that affect rotation cosignatures, manifest replay, etc.
    #[must_use]
    pub fn verify_signature(data: &[u8], signature: &[u8], signing_public_key: &[u8]) -> bool {
        if signature.len() != ED25519_SIG_LEN || signing_public_key.len() != ED25519_KEY_LEN {
            return false;
        }
        if crate::ed25519_points::is_low_order(signing_public_key) {
            return false;
        }
        let pk_bytes: [u8; ED25519_KEY_LEN] = match signing_public_key.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig_bytes: [u8; ED25519_SIG_LEN] = match signature.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(&pk_bytes) else {
            return false;
        };
        let signature = Signature::from_bytes(&sig_bytes);
        verifying_key.verify_strict(data, &signature).is_ok()
    }

    /// Borrow the underlying X25519 [`StaticSecret`]. Useful when callers need to perform
    /// ECDH directly (e.g., the prekey-decrypt path that must override the long-term key).
    #[must_use]
    pub fn x25519_secret(&self) -> &StaticSecret {
        &self.x25519_secret
    }
}

/// Deterministic 12-byte nonce derived from message metadata.
///
/// `nonce = SHA-256(message_id || chunk_number_be4 || timestamp_be8)[:12]`.
#[must_use]
pub fn deterministic_nonce(
    message_id: &[u8],
    chunk_number: u32,
    timestamp: u64,
) -> [u8; NONCE_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(message_id);
    hasher.update(chunk_number.to_be_bytes());
    hasher.update(timestamp.to_be_bytes());
    let digest = hasher.finalize();
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&digest[..NONCE_LEN]);
    nonce
}

/// SHA-256 over an X25519 public key, used as the user ID throughout the protocol.
#[must_use]
pub fn derive_user_id(public_key: &[u8; X25519_KEY_LEN]) -> [u8; 32] {
    Sha256::digest(public_key).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vector lifted from `docs/protocol/vectors/identity_record.json` case 0:
    /// the signer seed plus its expected Ed25519 verifying key.
    const ALICE_SEED_HEX: &str = "08c240c67466120fcd17e86c2f5badab38d926f8b01b0afcec6369229dc621da";
    const ALICE_ED25519_SPK_HEX: &str =
        "293c1c181315c368e21344d717faef768dc1bbc5d1d2dcde62a2d77888441575";
    const ALICE_X25519_PK_HEX: &str =
        "9cfcecee647bf53742ff71cead91fb894a409c6e1d5f6127f3d01f1729e70e11";

    fn alice() -> DmpCrypto {
        let seed = hex::decode(ALICE_SEED_HEX).unwrap();
        DmpCrypto::from_private_bytes(&seed).unwrap()
    }

    #[test]
    fn ed25519_derivation_matches_python_vector() {
        let crypto = alice();
        assert_eq!(
            hex::encode(crypto.signing_public_key_bytes()),
            ALICE_ED25519_SPK_HEX,
            "Ed25519 signing key derivation must match Python's SHA-256(seed || domain) flow",
        );
    }

    #[test]
    fn x25519_public_key_matches_python_vector() {
        let crypto = alice();
        assert_eq!(
            hex::encode(crypto.public_key_bytes()),
            ALICE_X25519_PK_HEX,
            "X25519 public key derivation must match Python's clamped scalar mult",
        );
    }

    #[test]
    fn private_key_bytes_round_trip() {
        let seed = hex::decode(ALICE_SEED_HEX).unwrap();
        let crypto = DmpCrypto::from_private_bytes(&seed).unwrap();
        assert_eq!(
            hex::encode(crypto.private_key_bytes()),
            ALICE_SEED_HEX,
            "private_key_bytes must round-trip the input seed verbatim (matches Python unclamped)",
        );
    }

    #[test]
    fn from_private_bytes_rejects_wrong_length() {
        assert!(matches!(
            DmpCrypto::from_private_bytes(&[0u8; 31]),
            Err(CryptoError::InvalidKeyLength { .. }),
        ));
        assert!(matches!(
            DmpCrypto::from_private_bytes(&[0u8; 33]),
            Err(CryptoError::InvalidKeyLength { .. }),
        ));
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let crypto = alice();
        let data = b"message under test";
        let sig = crypto.sign_data(data);
        assert!(DmpCrypto::verify_signature(
            data,
            &sig,
            &crypto.signing_public_key_bytes(),
        ));
    }

    #[test]
    fn verify_signature_rejects_tampered_data() {
        let crypto = alice();
        let sig = crypto.sign_data(b"original");
        assert!(!DmpCrypto::verify_signature(
            b"tampered",
            &sig,
            &crypto.signing_public_key_bytes(),
        ));
    }

    #[test]
    fn verify_signature_rejects_short_keys() {
        let crypto = alice();
        let sig = crypto.sign_data(b"data");
        assert!(!DmpCrypto::verify_signature(b"data", &sig, &[0u8; 31]));
        assert!(!DmpCrypto::verify_signature(
            b"data",
            &sig[..63],
            &crypto.signing_public_key_bytes()
        ));
    }

    #[test]
    fn encrypt_decrypt_round_trip_no_aad() {
        let alice = DmpCrypto::generate();
        let bob = DmpCrypto::generate();
        let plaintext = b"hello bob";
        let encrypted = alice
            .encrypt_for_recipient(plaintext, &bob.public_key_bytes(), None)
            .unwrap();
        let decrypted = bob.decrypt_message(&encrypted, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_round_trip_with_aad() {
        let alice = DmpCrypto::generate();
        let bob = DmpCrypto::generate();
        let plaintext = b"hello bob";
        let aad = b"some-message-id\x00\x00\x00\x05";
        let encrypted = alice
            .encrypt_for_recipient(plaintext, &bob.public_key_bytes(), Some(aad))
            .unwrap();
        let decrypted = bob.decrypt_message(&encrypted, Some(aad)).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_aad_mismatch_fails() {
        let alice = DmpCrypto::generate();
        let bob = DmpCrypto::generate();
        let encrypted = alice
            .encrypt_for_recipient(b"x", &bob.public_key_bytes(), Some(b"aad-1"))
            .unwrap();
        assert!(matches!(
            bob.decrypt_message(&encrypted, Some(b"aad-2")),
            Err(CryptoError::AeadFailure),
        ));
    }

    #[test]
    fn encrypted_message_round_trip_bytes() {
        let alice = DmpCrypto::generate();
        let bob = DmpCrypto::generate();
        let encrypted = alice
            .encrypt_for_recipient(b"payload", &bob.public_key_bytes(), None)
            .unwrap();
        let bytes = encrypted.to_bytes();
        let parsed = EncryptedMessage::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, encrypted);
    }

    #[test]
    fn encrypted_message_from_bytes_rejects_short_input() {
        assert!(matches!(
            EncryptedMessage::from_bytes(&[0u8; 43]),
            Err(CryptoError::EncryptedMessageTooShort { .. }),
        ));
    }

    #[test]
    fn from_passphrase_rejects_short_salt() {
        assert!(matches!(
            DmpCrypto::from_passphrase("hunter2", Some(b"short")),
            Err(CryptoError::SaltTooShort),
        ));
    }

    #[test]
    fn from_passphrase_is_deterministic() {
        let salt = b"deterministic-test-salt";
        let a = DmpCrypto::from_passphrase("correct horse battery staple", Some(salt)).unwrap();
        let b = DmpCrypto::from_passphrase("correct horse battery staple", Some(salt)).unwrap();
        assert_eq!(a.public_key_bytes(), b.public_key_bytes());
        assert_eq!(a.signing_public_key_bytes(), b.signing_public_key_bytes());
    }

    #[test]
    fn deterministic_nonce_is_stable() {
        let n1 = deterministic_nonce(b"msg-id-16-bytes!", 7, 1_700_000_000);
        let n2 = deterministic_nonce(b"msg-id-16-bytes!", 7, 1_700_000_000);
        assert_eq!(n1, n2);
        let n3 = deterministic_nonce(b"msg-id-16-bytes!", 8, 1_700_000_000);
        assert_ne!(n1, n3);
    }

    #[test]
    fn derive_user_id_matches_sha256() {
        let pk = [0u8; X25519_KEY_LEN];
        let id = derive_user_id(&pk);
        // sha256 of 32 zero bytes — externally verifiable
        assert_eq!(
            hex::encode(id),
            "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
        );
    }

    #[test]
    fn verify_signature_rejects_low_order_pubkey() {
        // The Ed25519 identity point is in the low-order block list. Any signature
        // claimed to be from it must be rejected before the underlying RFC-8032 verify.
        let mut identity_pk = [0u8; 32];
        identity_pk[0] = 0x01;
        let dummy_sig = [0u8; ED25519_SIG_LEN];
        assert!(!DmpCrypto::verify_signature(
            b"any data",
            &dummy_sig,
            &identity_pk
        ));
    }

    #[test]
    fn decrypt_rejects_non_contributory_ephemeral() {
        // An ephemeral X25519 public key of all zeros produces an all-zero shared secret
        // (non-contributory). Refuse to derive an AEAD key from it instead of letting
        // the attacker pick the key.
        let alice = DmpCrypto::generate();
        let attacker_msg = EncryptedMessage {
            ephemeral_public_key: [0u8; X25519_KEY_LEN],
            nonce: [0u8; NONCE_LEN],
            ciphertext: vec![0u8; 16], // any ciphertext shape
        };
        assert!(matches!(
            alice.decrypt_message(&attacker_msg, None),
            Err(CryptoError::NonContributoryEcdh),
        ));
    }

    #[test]
    fn encrypt_rejects_low_order_recipient() {
        // A recipient public key of all zeros is non-contributory in X25519 ECDH.
        // Refuse to encrypt to it; otherwise the resulting ciphertext would be
        // decryptable by anyone (the AEAD key is fully attacker-derivable).
        let alice = DmpCrypto::generate();
        let zero_recipient = [0u8; X25519_KEY_LEN];
        assert!(matches!(
            alice.encrypt_for_recipient(b"x", &zero_recipient, None),
            Err(CryptoError::NonContributoryEcdh),
        ));
    }

    #[test]
    fn prekey_decrypt_path_uses_alternate_secret() {
        // Recipient publishes an ephemeral prekey. Sender encrypts to the prekey public key.
        // Recipient decrypts with the prekey *secret*, not the long-term identity secret.
        let alice = DmpCrypto::generate();
        let prekey_secret = StaticSecret::random_from_rng(OsRng);
        let prekey_public = X25519PublicKey::from(&prekey_secret);
        let encrypted = alice
            .encrypt_for_recipient(b"x3dh-style", &prekey_public.to_bytes(), Some(b"hdr"))
            .unwrap();
        let plaintext =
            DmpCrypto::decrypt_message_with_secret(&encrypted, Some(b"hdr"), &prekey_secret)
                .unwrap();
        assert_eq!(plaintext, b"x3dh-style");
    }
}

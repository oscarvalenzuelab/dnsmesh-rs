//! Identity rotation and revocation publishing.
//!
//! Mirrors `cmd_identity_rotate` from `dmp/cli.py:1816`. The wire types
//! (`RotationRecord`, `RevocationRecord`) and the receive-side chain
//! walker (`crates/dnsmesh-client/src/rotation_chain.rs`) were already
//! ported. This module is the publish side: build → sign → push.
//!
//! Two reasons-modes:
//!
//! - `Reason::Routine` — periodic rotation. Publishes a `RotationRecord`
//!   from old_spk → new_spk and a fresh `IdentityRecord` for the new key.
//!   No revocation. Recipients with rotation_chain_enabled walk forward
//!   to the new key transparently; recipients without it have to re-pin.
//! - `Reason::Compromise` / `Reason::LostKey` — same as Routine PLUS a
//!   self-signed `RevocationRecord` for the old key, so receivers with
//!   rotation_chain_enabled also drop in-flight messages signed by the
//!   compromised key. Mirrors Python's `--reason {compromise,lost_key}`.
//!
//! Failure semantics match Python (cli.py:2080–2125):
//!
//! - RotationRecord publish failure is fatal — die immediately.
//! - RevocationRecord and the new-key IdentityRecord publish failures
//!   surface as `RotateOutcome` warnings; the rotation is already
//!   committed to DNS at that point, no rollback is possible.
//!
//! `seq` is wall-clock milliseconds, matching Python (cli.py:1999). The
//! receive-side walker enforces strictly-increasing seq across hops.

use std::time::{SystemTime, UNIX_EPOCH};

use dnsmesh_core::crypto::DmpCrypto;
use dnsmesh_core::identity::{identity_domain, make_record};
use dnsmesh_core::revocation::RevocationRecord;
use dnsmesh_core::rotation::{
    rotation_rrset_name_user_identity, RotationRecord, REASON_COMPROMISE, REASON_LOST_KEY,
    SUBJECT_TYPE_USER_IDENTITY,
};

use crate::client::DmpClient;
use crate::error::ClientError;
use crate::publish::DEFAULT_IDENTITY_TTL_SECONDS;

/// Why the user is rotating. The reason determines whether a
/// `RevocationRecord` is published alongside the `RotationRecord`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotateReason {
    /// Periodic key refresh; old key remains valid for receivers
    /// without rotation_chain_enabled. No revocation.
    Routine,
    /// Old key was disclosed; publish a `RevocationRecord` so
    /// rotation-aware receivers drop messages signed by it.
    Compromise,
    /// Old key was destroyed (lost passphrase, hardware failure).
    /// Same publish shape as `Compromise`; the revocation reason
    /// code on the wire differs.
    LostKey,
}

impl RotateReason {
    /// Map to the revocation-record `reason_code` byte
    /// (constants live in `dnsmesh_core::rotation::REASON_*`).
    /// `Routine` returns `None` (no revocation published).
    fn revocation_code(self) -> Option<u8> {
        match self {
            Self::Routine => None,
            Self::Compromise => Some(REASON_COMPROMISE),
            Self::LostKey => Some(REASON_LOST_KEY),
        }
    }
}

/// Per-step outcome surfaced to the caller. Mirrors the Python flow's
/// "warn-but-continue" behavior — the rotation as a whole succeeds as
/// long as `rotation_record_published` is true; the other two writes
/// are best-effort with documented recovery paths.
#[derive(Debug, Clone)]
pub struct RotateOutcome {
    /// `RotationRecord` published successfully. If false, the entire
    /// rotation is treated as failed and the client error is in
    /// `rotation_publish_error`.
    pub rotation_record_published: bool,
    /// Set when `rotation_record_published` is false.
    pub rotation_publish_error: Option<String>,
    /// `Some(true)` = revocation published.
    /// `Some(false)` = revocation publish failed (operator should
    /// re-publish manually).
    /// `None` = no revocation requested (`Routine`).
    pub revocation_published: Option<bool>,
    /// New-key `IdentityRecord` publish outcome. `false` means the
    /// rotation chain is on DNS but the new key isn't yet resolvable
    /// via `identity fetch`; the operator should re-run
    /// `dnsmesh identity publish` after pointing at the new key.
    pub new_identity_published: bool,
    /// 1-second resolution wall-clock seq embedded in the
    /// RotationRecord. Returned for debug + telemetry; the chain
    /// walker's strict-increase rule means the operator wants to
    /// know what landed if a follow-up re-rotate is needed.
    pub seq: u64,
}

impl DmpClient {
    /// Rotate this identity's signing key and publish the chain
    /// records that pinned receivers will walk forward through.
    ///
    /// Caller MUST construct `new_crypto` from the same `kdf_salt`
    /// the current client uses, with a NEW passphrase. Reusing the
    /// salt is deliberate (cli.py:1960) — operators rarely want to
    /// re-randomize the salt mid-flow, and keeping it stable means
    /// the username-hash-based DNS labels don't change.
    ///
    /// Returns once the writes complete (or fail). The local client
    /// state is NOT mutated — the caller is responsible for
    /// reconstructing a `DmpClient` against the new passphrase for
    /// subsequent commands. (The reason: `crypto` is owned by the
    /// running async tasks; mutating it mid-flight would race the
    /// receive loop.)
    ///
    /// Failure shape:
    /// - `Err(ClientError::PublishFailed)` if the `RotationRecord`
    ///   itself fails. That is the rotation's load-bearing publish.
    /// - `Ok(outcome)` for any other partial-success case.
    ///   `outcome.revocation_published` and `outcome.new_identity_published`
    ///   carry the per-step result; the operator's next action is
    ///   driven by which booleans came back false.
    pub async fn rotate_identity(
        &self,
        new_crypto: &DmpCrypto,
        reason: RotateReason,
        ttl_seconds: u32,
        exp_seconds: u64,
    ) -> Result<RotateOutcome, ClientError> {
        let old_spk = self.crypto.signing_public_key_bytes();
        let new_spk = new_crypto.signing_public_key_bytes();
        if old_spk == new_spk {
            return Err(ClientError::InvalidConfig(
                "rotate_identity: new keypair derives the same signing key as the current one"
                    .to_string(),
            ));
        }

        let now = unix_now_secs();
        let now_ms = unix_now_millis();
        let exp = now.saturating_add(exp_seconds);
        let subject = format!("{}@{}", self.username, self.domain);

        // 1. RotationRecord — the load-bearing publish. Die on fail.
        let rotation = RotationRecord {
            subject_type: SUBJECT_TYPE_USER_IDENTITY,
            subject: subject.clone(),
            old_spk,
            new_spk,
            seq: now_ms,
            ts: now,
            exp,
        };
        let rotation_wire = rotation
            .sign(&self.crypto, new_crypto)
            .map_err(|e| ClientError::InvalidConfig(format!("RotationRecord sign: {e}")))?;
        let rotate_name = rotation_rrset_name_user_identity(&self.username, &self.domain);
        let ok = self
            .writer
            .publish_txt_record(&rotate_name, &rotation_wire, ttl_seconds)
            .await?;
        if !ok {
            return Err(ClientError::PublishFailed {
                kind: "rotation",
                name: rotate_name,
            });
        }
        let mut outcome = RotateOutcome {
            rotation_record_published: true,
            rotation_publish_error: None,
            revocation_published: None,
            new_identity_published: false,
            seq: now_ms,
        };

        // 2. RevocationRecord — only for compromise/lost_key. Warn on fail.
        if let Some(reason_code) = reason.revocation_code() {
            let revocation = RevocationRecord {
                subject_type: SUBJECT_TYPE_USER_IDENTITY,
                subject: subject.clone(),
                revoked_spk: old_spk,
                reason_code,
                ts: now,
            };
            // Self-signed by the OLD key — same RRset as the rotation.
            let rev_wire = revocation
                .sign(&self.crypto)
                .map_err(|e| ClientError::InvalidConfig(format!("RevocationRecord sign: {e}")))?;
            let rev_ok = self
                .writer
                .publish_txt_record(&rotate_name, &rev_wire, ttl_seconds)
                .await
                .unwrap_or(false);
            outcome.revocation_published = Some(rev_ok);
            if !rev_ok {
                tracing::warn!(
                    rrset = rotate_name.as_str(),
                    "rotate: RevocationRecord publish failed; rotation is already on DNS, \
                     re-run `dnsmesh identity revoke` to retry"
                );
            }
        }

        // 3. New-key IdentityRecord — fresh signed binding for the
        //    new key at the same id-<hash>.<domain> RRset. Warn on
        //    fail; the rotation chain is enough for chain-aware
        //    receivers, but a `dnsmesh identity fetch` won't find the
        //    new keys until the IdentityRecord re-publishes.
        let new_identity = make_record(new_crypto, &self.username, Some(now));
        let new_id_wire = new_identity.sign(new_crypto)?;
        let identity_name = identity_domain(&self.username, &self.domain);
        let id_ok = self
            .writer
            .publish_txt_record(&identity_name, &new_id_wire, ttl_seconds)
            .await
            .unwrap_or(false);
        outcome.new_identity_published = id_ok;
        if !id_ok {
            tracing::warn!(
                name = identity_name.as_str(),
                "rotate: new-key IdentityRecord publish failed; chain is on DNS but \
                 `identity fetch` will return the OLD key until you re-run `identity publish` \
                 with the new passphrase",
            );
        }

        Ok(outcome)
    }

    /// Publish a standalone `RevocationRecord` for THIS client's
    /// current signing key, self-signed.
    ///
    /// Use when shutting an identity down without rotating to a new
    /// one (e.g. you're abandoning this username entirely). For the
    /// usual "I lost my key, here's the new one" flow use
    /// [`Self::rotate_identity`] with `RotateReason::Compromise` or
    /// `RotateReason::LostKey` — that publishes BOTH the rotation
    /// pointer AND the revocation in one call.
    ///
    /// `ttl_seconds` is the published TXT TTL. The revocation itself
    /// is permanent at the wire level (the receive-side parser
    /// doesn't enforce age), so the TTL only governs how long the
    /// recursive resolvers cache it.
    pub async fn revoke_identity(
        &self,
        reason: RotateReason,
        ttl_seconds: u32,
    ) -> Result<(), ClientError> {
        let Some(reason_code) = reason.revocation_code() else {
            return Err(ClientError::InvalidConfig(
                "revoke_identity: RotateReason::Routine is invalid for a standalone revoke; \
                 use Compromise or LostKey"
                    .to_string(),
            ));
        };
        let now = unix_now_secs();
        let revocation = RevocationRecord {
            subject_type: SUBJECT_TYPE_USER_IDENTITY,
            subject: format!("{}@{}", self.username, self.domain),
            revoked_spk: self.crypto.signing_public_key_bytes(),
            reason_code,
            ts: now,
        };
        let wire = revocation
            .sign(&self.crypto)
            .map_err(|e| ClientError::InvalidConfig(format!("RevocationRecord sign: {e}")))?;
        let name = rotation_rrset_name_user_identity(&self.username, &self.domain);
        let ok = self
            .writer
            .publish_txt_record(&name, &wire, ttl_seconds)
            .await?;
        if !ok {
            return Err(ClientError::PublishFailed {
                kind: "revocation",
                name,
            });
        }
        Ok(())
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn unix_now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Default TTL for the rotation/revocation publishes. Mirrors
/// [`crate::publish::DEFAULT_IDENTITY_TTL_SECONDS`] so an operator who
/// never customizes ttl gets the same 24h cache horizon for all the
/// identity-related publishes.
pub const DEFAULT_ROTATION_TTL_SECONDS: u32 = DEFAULT_IDENTITY_TTL_SECONDS;

/// Default `exp_seconds` for the RotationRecord — 1 year after now.
/// Matches Python's default at cli.py:4854 (`86400 * 365`).
/// RotationRecord.exp bounds the chain walker's freshness gate; a
/// year is comfortably long for routine rotations and short enough
/// that an attacker who somehow gets a stale rotation re-cached
/// can't extend it indefinitely.
pub const DEFAULT_ROTATION_EXP_SECONDS: u64 = 86_400 * 365;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::DmpClientConfig;
    use dnsmesh_core::rotation::RECORD_PREFIX as ROTATION_PREFIX;
    use dnsmesh_net::{DnsRecordReader, DnsRecordWriter, InMemoryDnsStore};

    fn salt(prefix: &str) -> Vec<u8> {
        let mut s = prefix.as_bytes().to_vec();
        while s.len() < 16 {
            s.push(b'.');
        }
        s
    }

    async fn make_client(name: &str, store: Arc<InMemoryDnsStore>) -> DmpClient {
        let cfg = DmpClientConfig {
            username: name.to_string(),
            passphrase: format!("old-{name}"),
            domain: "mesh.local".to_string(),
            kdf_salt: Some(salt(name)),
            db_path: None,
            writer: store.clone() as Arc<dyn DnsRecordWriter>,
            reader: store as Arc<dyn DnsRecordReader>,
            rotation_chain_enabled: false,
        };
        DmpClient::new(cfg).await.unwrap()
    }

    #[tokio::test]
    async fn rotate_publishes_chain_and_new_identity() {
        let store = Arc::new(InMemoryDnsStore::new());
        let alice = make_client("alice-rot-pub", store.clone()).await;

        // New crypto from a different passphrase + same salt.
        let new_crypto =
            DmpCrypto::from_passphrase("new-alice-rot-pub", Some(&salt("alice-rot-pub"))).unwrap();
        assert_ne!(
            new_crypto.signing_public_key_bytes(),
            alice.crypto.signing_public_key_bytes(),
        );

        let outcome = alice
            .rotate_identity(&new_crypto, RotateReason::Routine, 3600, 86_400)
            .await
            .unwrap();
        assert!(outcome.rotation_record_published);
        assert!(outcome.new_identity_published);
        assert!(
            outcome.revocation_published.is_none(),
            "Routine reason emits no revocation"
        );

        // Inspect the rotation RRset; should hold one TXT that
        // parse_and_verify accepts.
        let rotate_name = rotation_rrset_name_user_identity(alice.username(), alice.domain());
        let recs = store
            .query_txt_record(&rotate_name)
            .await
            .unwrap()
            .expect("rotate rrset present");
        assert_eq!(recs.len(), 1);
        assert!(recs[0].starts_with(ROTATION_PREFIX));
        let parsed = RotationRecord::parse_and_verify(&recs[0], None, None, None).expect("verify");
        assert_eq!(parsed.old_spk, alice.crypto.signing_public_key_bytes());
        assert_eq!(parsed.new_spk, new_crypto.signing_public_key_bytes());

        // The new IdentityRecord lives at id-<hash>.<domain>, alongside
        // any pre-existing identity record for the OLD key. The
        // InMemoryDnsStore semantics keep both in the same RRset (DNS
        // multi-value behavior); receivers parse each and pick the
        // signature-valid one.
        let id_name = identity_domain(alice.username(), alice.domain());
        let id_recs = store
            .query_txt_record(&id_name)
            .await
            .unwrap()
            .unwrap_or_default();
        assert!(
            !id_recs.is_empty(),
            "fresh IdentityRecord must publish at id-<hash>.<domain>",
        );
    }

    #[tokio::test]
    async fn rotate_with_compromise_also_emits_revocation() {
        let store = Arc::new(InMemoryDnsStore::new());
        let alice = make_client("alice-rot-comp", store.clone()).await;
        let new_crypto =
            DmpCrypto::from_passphrase("new-alice-rot-comp", Some(&salt("alice-rot-comp")))
                .unwrap();
        let outcome = alice
            .rotate_identity(&new_crypto, RotateReason::Compromise, 3600, 86_400)
            .await
            .unwrap();
        assert_eq!(outcome.revocation_published, Some(true));

        // Both rotation + revocation TXT live at the rotate RRset.
        let rotate_name = rotation_rrset_name_user_identity(alice.username(), alice.domain());
        let recs = store
            .query_txt_record(&rotate_name)
            .await
            .unwrap()
            .expect("rotate rrset");
        assert_eq!(
            recs.len(),
            2,
            "rotation + revocation co-located on the rotate rrset"
        );
    }

    #[tokio::test]
    async fn revoke_standalone_publishes_self_signed_revocation() {
        let store = Arc::new(InMemoryDnsStore::new());
        let alice = make_client("alice-revoke", store.clone()).await;
        alice
            .revoke_identity(RotateReason::Compromise, 3600)
            .await
            .unwrap();
        let rotate_name = rotation_rrset_name_user_identity(alice.username(), alice.domain());
        let recs = store
            .query_txt_record(&rotate_name)
            .await
            .unwrap()
            .expect("revocation rrset");
        assert_eq!(recs.len(), 1);
        let parsed = RevocationRecord::parse_and_verify(&recs[0], None, None, None, None)
            .expect("revocation must verify under old SPK");
        assert_eq!(parsed.revoked_spk, alice.crypto.signing_public_key_bytes());
    }

    #[tokio::test]
    async fn rotate_rejects_same_keypair() {
        let store = Arc::new(InMemoryDnsStore::new());
        let alice = make_client("alice-same", store).await;
        let same = DmpCrypto::from_passphrase("old-alice-same", Some(&salt("alice-same"))).unwrap();
        let err = alice
            .rotate_identity(&same, RotateReason::Routine, 3600, 86_400)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("same signing key"));
    }

    #[tokio::test]
    async fn revoke_routine_is_invalid() {
        let store = Arc::new(InMemoryDnsStore::new());
        let alice = make_client("alice-routine-revoke", store).await;
        let err = alice
            .revoke_identity(RotateReason::Routine, 3600)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("Routine"));
    }
}

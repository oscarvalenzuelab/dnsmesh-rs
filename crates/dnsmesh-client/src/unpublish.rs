//! Unpublish — DNS UPDATE deletes for every name this client owns.
//!
//! When a user wants to "delete this identity", `rm ~/.dmp` only kills
//! local state — published records keep resolving until they TTL out
//! (24h). This module sweeps the writer with DNS UPDATE deletes against
//! every name we know we published under: the identity record, the
//! prekey RRset, all 10 mailbox slots, and the rotation/revocation
//! RRset. Chunk records aren't tracked locally (we don't keep a list
//! of msg-keys we've published for); they expire on their own.
//!
//! The `purge` flow that wipes local state on top of this lives in
//! the CLI layer (commands/purge.rs) — keeping that out of the SDK
//! since "delete my sqlite db" isn't a network operation.

use dnsmesh_core::identity::identity_domain;
use dnsmesh_core::prekeys::prekey_rrset_name;
use dnsmesh_core::rotation::rotation_rrset_name_user_identity;

use crate::addressing::{slot_domain, SLOT_COUNT};
use crate::client::DmpClient;
use crate::error::ClientError;

/// Per-name outcome of [`DmpClient::unpublish_identity`]. Operators
/// reading this can see at a glance which names are gone vs which
/// the writer rejected; the latter usually means the TSIG scope
/// doesn't include that name (and the operator should ask the node
/// admin, or wait for the records to TTL out naturally).
#[derive(Debug, Clone)]
pub struct UnpublishReport {
    /// Each entry is `(name, deleted)`. `deleted == true` means the
    /// writer accepted the DELETE; `false` means the call surfaced
    /// no-op or the writer rejected. The operator can grep this
    /// list for `false` to see what's still live.
    pub deletes: Vec<(String, bool)>,
}

impl DmpClient {
    /// Issue DNS UPDATE deletes against every name this client
    /// published. Returns a per-name success/failure report so the
    /// operator can see what's actually gone.
    ///
    /// Names swept (relative to `(self.username, self.domain)`):
    /// - `id-<hash16>.<domain>` — identity record
    /// - `prekeys.id-<hash12>.<domain>` — prekey RRset
    /// - `slot-{0..9}.mb-<hash12>.<domain>` — every mailbox slot
    /// - `rotate.id-<hash16>.<domain>` — rotation/revocation RRset
    ///
    /// Chunk records (`chunk-<num>-<key>.<domain>`) are NOT swept —
    /// we don't track the (msg_id, key) pairs locally after the
    /// initial publish, and a wildcard delete isn't a thing in DNS
    /// UPDATE. They TTL out at their original publish TTL (24h
    /// default for routine traffic, often shorter for the chunked
    /// payloads themselves).
    ///
    /// The writer is called once per name. Failures don't short-
    /// circuit; we sweep the whole list and report. Mirrors the
    /// "best-effort cleanup" pattern used elsewhere (consume_prekey
    /// in receive.rs, rotation revocation publish).
    pub async fn unpublish_identity(&self) -> Result<UnpublishReport, ClientError> {
        let mut deletes: Vec<(String, bool)> = Vec::new();

        // 1. Identity record.
        let identity_name = identity_domain(&self.username, &self.domain);
        let ok = self
            .writer
            .delete_txt_record(&identity_name, None)
            .await
            .unwrap_or(false);
        deletes.push((identity_name, ok));

        // 2. Prekey RRset (all members).
        let prekey_name = prekey_rrset_name(&self.username, &self.domain);
        let ok = self
            .writer
            .delete_txt_record(&prekey_name, None)
            .await
            .unwrap_or(false);
        deletes.push((prekey_name, ok));

        // 3. Every mailbox slot. SLOT_COUNT=10; cheap enough to
        //    issue all 10 deletes unconditionally instead of
        //    pre-querying which ones have records.
        for slot in 0..SLOT_COUNT {
            let slot_name = slot_domain(&self.user_id, slot, &self.domain);
            let ok = self
                .writer
                .delete_txt_record(&slot_name, None)
                .await
                .unwrap_or(false);
            deletes.push((slot_name, ok));
        }

        // 4. Rotation / revocation RRset.
        let rotate_name = rotation_rrset_name_user_identity(&self.username, &self.domain);
        let ok = self
            .writer
            .delete_txt_record(&rotate_name, None)
            .await
            .unwrap_or(false);
        deletes.push((rotate_name, ok));

        Ok(UnpublishReport { deletes })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use dnsmesh_core::identity::identity_domain;
    use dnsmesh_core::prekeys::prekey_rrset_name;
    use dnsmesh_core::rotation::rotation_rrset_name_user_identity;
    use dnsmesh_net::{DnsRecordReader, DnsRecordWriter, InMemoryDnsStore};

    use crate::addressing::{slot_domain, SLOT_COUNT};
    use crate::{DmpClient, DmpClientConfig};

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
            passphrase: format!("pass-for-{name}"),
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
    async fn unpublish_drops_identity_prekey_slots_and_rotate_rrsets() {
        let store = Arc::new(InMemoryDnsStore::new());
        let alice = make_client("alice-unpub", store.clone()).await;

        // Publish a baseline so there's something to sweep.
        alice.publish_identity(false).await.unwrap();
        alice.refresh_prekeys(3, 3600).await.unwrap();

        // Pre-condition: identity + prekey records exist in the store.
        let id_name = identity_domain(alice.username(), alice.domain());
        let pk_name = prekey_rrset_name(alice.username(), alice.domain());
        assert!(store.query_txt_record(&id_name).await.unwrap().is_some());
        assert!(store.query_txt_record(&pk_name).await.unwrap().is_some());

        let report = alice.unpublish_identity().await.unwrap();

        // Expected length: 1 identity + 1 prekey + 10 slots + 1 rotate = 13.
        assert_eq!(report.deletes.len(), 1 + 1 + SLOT_COUNT as usize + 1);

        // Identity + prekey deletes succeeded (the records existed).
        let by_name: std::collections::HashMap<&str, bool> = report
            .deletes
            .iter()
            .map(|(n, ok)| (n.as_str(), *ok))
            .collect();
        assert_eq!(by_name.get(id_name.as_str()), Some(&true));
        assert_eq!(by_name.get(pk_name.as_str()), Some(&true));

        // Post-condition: the records are gone from the store.
        assert!(store.query_txt_record(&id_name).await.unwrap().is_none());
        assert!(store.query_txt_record(&pk_name).await.unwrap().is_none());

        // Rotation RRset entry is in the report (no records there
        // means delete returns false; that's expected post-init).
        let rotate_name = rotation_rrset_name_user_identity(alice.username(), alice.domain());
        assert!(by_name.contains_key(rotate_name.as_str()));

        // Each slot is in the report.
        for slot in 0..SLOT_COUNT {
            let n = slot_domain(&alice.user_id(), slot, alice.domain());
            assert!(
                by_name.contains_key(n.as_str()),
                "slot {slot} missing from report"
            );
        }
    }

    #[tokio::test]
    async fn unpublish_is_idempotent() {
        let store = Arc::new(InMemoryDnsStore::new());
        let alice = make_client("alice-unpub-idem", store.clone()).await;
        alice.publish_identity(false).await.unwrap();
        // First sweep removes; second sweep is a no-op (nothing to
        // delete) but still completes without error.
        alice.unpublish_identity().await.unwrap();
        let report = alice.unpublish_identity().await.unwrap();
        // All entries report `false` since nothing was there anymore.
        for (name, ok) in &report.deletes {
            assert!(!*ok, "expected no-op delete for {name} on second sweep");
        }
    }
}

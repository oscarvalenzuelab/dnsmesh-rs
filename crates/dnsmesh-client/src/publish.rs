//! Identity / prekey publishing.
//!
//! Both methods write TXT records via `self.writer` and persist any
//! sender-private state via `self.prekeys`. Writes are best-effort at the
//! transport layer: if the writer rejects a record we surface the failure
//! immediately, but we don't retry — the caller (CLI / SDK) decides the
//! retry policy.

use dnsmesh_core::identity::{identity_domain, make_record};
use dnsmesh_core::prekeys::prekey_rrset_name;

use crate::addressing::DEFAULT_PREKEY_TTL_SECONDS;
use crate::client::DmpClient;
use crate::error::ClientError;

/// TTL applied to the [`dnsmesh_core::identity::IdentityRecord`] TXT publish.
///
/// 24 hours matches the Python reference (`DMPClient.publish_identity` uses
/// the same default). Identity records are cheap to refresh, so a longer TTL
/// would just delay rotations without saving meaningful work.
pub const DEFAULT_IDENTITY_TTL_SECONDS: u32 = 86_400;

impl DmpClient {
    /// Publish this client's signed [`dnsmesh_core::identity::IdentityRecord`]
    /// TXT to its identity DNS name (`id-<sha256(username)[:16]>.<domain>`).
    pub async fn publish_identity(&self) -> Result<(), ClientError> {
        let record = make_record(&self.crypto, &self.username, None);
        let wire = record.sign(&self.crypto)?;
        let name = identity_domain(&self.username, &self.domain);
        let ok = self
            .writer
            .publish_txt_record(&name, &wire, DEFAULT_IDENTITY_TTL_SECONDS)
            .await?;
        if !ok {
            return Err(ClientError::PublishFailed {
                kind: "identity",
                name,
            });
        }
        Ok(())
    }

    /// Generate `count` new prekeys, sign each, publish to the prekey RRset,
    /// and persist private halves to the local prekey store.
    ///
    /// `ttl_seconds` is applied to BOTH the published TXT record and the
    /// stored exp field, matching Python `refresh_prekeys`.  Returns the
    /// number of records the writer actually accepted.
    pub async fn refresh_prekeys(&self, count: u32, ttl_seconds: u64) -> Result<u32, ClientError> {
        let ttl = if ttl_seconds == 0 {
            DEFAULT_PREKEY_TTL_SECONDS
        } else {
            ttl_seconds
        };
        // u32 wide enough for u32::MAX prekeys on the wire; cap at usize for the
        // local pool generator.
        let pool = self.prekeys.generate_pool(count as usize, ttl)?;
        let name = prekey_rrset_name(&self.username, &self.domain);
        // ttl_seconds in seconds; convert to u32 with saturation. 24h fits in u32
        // trivially; senders publishing a >136-year TTL get clamped, which is the
        // safest behaviour we can offer here.
        let ttl_u32 = u32::try_from(ttl).unwrap_or(u32::MAX);

        let mut published: u32 = 0;
        for entry in pool {
            let wire = entry.prekey.sign(&self.crypto)?;
            let ok = self
                .writer
                .publish_txt_record(&name, &wire, ttl_u32)
                .await?;
            if !ok {
                continue;
            }
            // Remember the wire bytes so a future `consume` (phase 2B) can
            // DELETE the matching record from the writer.
            self.prekeys.record_wire(entry.prekey.prekey_id, &wire)?;
            published = published.saturating_add(1);
        }
        Ok(published)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use dnsmesh_core::identity::IdentityRecord;
    use dnsmesh_core::prekeys::Prekey;
    use dnsmesh_net::{DnsRecordReader, InMemoryDnsStore};

    use crate::client::DmpClientConfig;

    fn salt_bytes(prefix: &str) -> Vec<u8> {
        // Salt must be at least 8 bytes for the Argon2id wrapper to accept it.
        let mut s = prefix.as_bytes().to_vec();
        while s.len() < 16 {
            s.push(b'.');
        }
        s
    }

    async fn make_client(name: &str, store: Arc<InMemoryDnsStore>) -> DmpClient {
        let cfg = DmpClientConfig {
            username: name.to_string(),
            passphrase: format!("passphrase-for-{name}"),
            domain: "mesh.local".to_string(),
            kdf_salt: Some(salt_bytes(name)),
            db_path: None,
            writer: store.clone(),
            reader: store,
            rotation_chain_enabled: false,
        };
        DmpClient::new(cfg).await.unwrap()
    }

    #[tokio::test]
    async fn publish_identity_writes_a_verifiable_record() {
        let store = Arc::new(InMemoryDnsStore::new());
        let client = make_client("alice", store.clone()).await;
        client.publish_identity().await.unwrap();
        let name = identity_domain(&client.username, &client.domain);
        let records = store.query_txt_record(&name).await.unwrap().unwrap();
        assert_eq!(records.len(), 1);
        let (parsed, _sig) =
            IdentityRecord::parse_and_verify(&records[0]).expect("identity record must verify");
        assert_eq!(parsed.username, "alice");
        assert_eq!(
            parsed.x25519_pk,
            client.crypto.public_key_bytes(),
            "published x25519_pk must match the local identity",
        );
    }

    #[tokio::test]
    async fn refresh_prekeys_publishes_and_records_wire_bytes() {
        let store = Arc::new(InMemoryDnsStore::new());
        let client = make_client("bob", store.clone()).await;
        let n = client.refresh_prekeys(5, 3600).await.unwrap();
        assert_eq!(n, 5);
        let name = prekey_rrset_name(&client.username, &client.domain);
        let records = store.query_txt_record(&name).await.unwrap().unwrap();
        assert_eq!(records.len(), 5);
        let spk = client.crypto.signing_public_key_bytes();
        for r in &records {
            assert!(
                Prekey::parse_and_verify(r, &spk).is_some(),
                "every published prekey must verify under the publisher's spk",
            );
        }
        // wire-record persistence: every live prekey id should round-trip through
        // get_wire so consume() can DELETE the right TXT.
        for id in client.prekeys.list_live_ids().unwrap() {
            assert!(client.prekeys.get_wire(id).unwrap().is_some());
        }
    }
}

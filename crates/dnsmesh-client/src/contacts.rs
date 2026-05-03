//! Contact management — fetch a user's identity record from DNS, persist a
//! contact to the local store, and list pinned contacts.

use dnsmesh_core::identity::{identity_domain, parse_address, IdentityRecord};
use dnsmesh_storage::{Contact as StoredContact, NewContact};

use crate::client::DmpClient;
use crate::error::ClientError;

/// A pinned identity. Mirrors [`dnsmesh_storage::Contact`] but exposed at the
/// client API surface so callers don't have to depend on the storage crate
/// directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    /// DMP username.
    pub username: String,
    /// 32-byte X25519 encryption pubkey.
    pub x25519_pk: [u8; 32],
    /// 32-byte Ed25519 verifying key.
    pub ed25519_spk: [u8; 32],
    /// Mesh zone the contact is published under.
    pub domain: String,
}

impl Contact {
    /// Convert into the storage-layer shape. The storage `domain` column
    /// (V3) carries the per-contact zone so cross-zone receive can walk
    /// it on the next poll.
    pub(crate) fn to_new_contact(&self) -> NewContact<'_> {
        NewContact {
            username: &self.username,
            x25519_pk: &self.x25519_pk,
            ed25519_spk: &self.ed25519_spk,
            // 2A: every contact is treated as TOFU. The
            // `--require-signing-key` trust mode is exposed in 2B alongside
            // the receive path that enforces it.
            require_signing_key: false,
            domain: &self.domain,
        }
    }

    /// Promote a stored contact into the public type. The domain is read
    /// from the storage row; an empty string (V1/V2 legacy rows) is
    /// surfaced verbatim so the receive path can apply its own
    /// "treat empty as own zone" fallback at one place.
    fn from_stored(stored: StoredContact) -> Self {
        Self {
            username: stored.username,
            x25519_pk: stored.x25519_pk,
            ed25519_spk: stored.ed25519_spk,
            domain: stored.domain,
        }
    }
}

impl DmpClient {
    /// Fetch and verify another user's [`IdentityRecord`].
    ///
    /// `address` must be in the form `user@host`; the DNS query is sent to
    /// `id-<sha256(user)[:16]>.<host>`. Verifying the signature is enough to
    /// trust the binding `(username, x25519_pk, ed25519_spk)` for the
    /// purpose of populating a contact entry — TOFU still applies once the
    /// caller pins the result via [`Self::add_contact`].
    pub async fn fetch_identity(&self, address: &str) -> Result<Contact, ClientError> {
        let (user, host) = parse_address(address).ok_or_else(|| ClientError::InvalidAddress {
            address: address.to_string(),
        })?;
        let name = identity_domain(&user, &host);
        let records = self
            .reader
            .query_txt_record(&name)
            .await?
            .ok_or_else(|| ClientError::NoRecordFound { name: name.clone() })?;
        for record in &records {
            if let Some((parsed, _sig)) = IdentityRecord::parse_and_verify(record) {
                if parsed.username != user {
                    // Verified record for a different username at this
                    // address: refuse, otherwise an attacker controlling
                    // the zone could drop someone else's signed identity
                    // here and we'd happily pin it.
                    continue;
                }
                return Ok(Contact {
                    username: parsed.username,
                    x25519_pk: parsed.x25519_pk,
                    ed25519_spk: parsed.ed25519_spk,
                    domain: host,
                });
            }
        }
        Err(ClientError::VerifyFailed { name })
    }

    /// Pin `contact` to the local contact store.
    ///
    /// Returns `true` if this is the first time we've pinned this username,
    /// `false` if the existing entry was overwritten with the supplied keys.
    ///
    /// The `async` here is API-stable scaffolding for the eventual move to
    /// `spawn_blocking` for the sqlite write.
    #[allow(clippy::unused_async)]
    pub async fn add_contact(&self, contact: Contact) -> Result<bool, ClientError> {
        let existing = self.contacts.get_contact(&contact.username)?;
        let newly_added = existing.is_none();
        self.contacts.add_contact(contact.to_new_contact())?;
        Ok(newly_added)
    }

    /// List every pinned contact, sorted alphabetically.
    ///
    /// The contact's `domain` comes straight from the V3 storage column.
    /// Rows added before V3 (or rows added without an explicit zone)
    /// surface an empty `domain`; the receive path treats that as
    /// "use the local mesh zone" so legacy same-mesh deployments
    /// keep working without a re-add.
    ///
    /// The `async` here is API-stable scaffolding for the eventual move to
    /// `spawn_blocking` for the sqlite read.
    #[allow(clippy::unused_async)]
    pub async fn list_contacts(&self) -> Result<Vec<Contact>, ClientError> {
        let stored = self.contacts.list_contacts()?;
        Ok(stored.into_iter().map(Contact::from_stored).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contact_round_trips_through_new_contact() {
        let c = Contact {
            username: "alice".to_string(),
            x25519_pk: [0xAA; 32],
            ed25519_spk: [0xBB; 32],
            domain: "mesh.local".to_string(),
        };
        let nc = c.to_new_contact();
        assert_eq!(nc.username, "alice");
        assert_eq!(*nc.x25519_pk, [0xAA; 32]);
        assert_eq!(*nc.ed25519_spk, [0xBB; 32]);
        assert!(!nc.require_signing_key);
        assert_eq!(nc.domain, "mesh.local");
    }
}

//! Sqlite-backed contact store. NEW in the Rust port.
//!
//! The Python client keeps contacts in an in-memory dict and reloads
//! them on every CLI invocation via DNS — slow, and no way to mark a
//! sender as "trusted to skip the intro queue" persistently. The Rust
//! port persists contacts so:
//!
//!   - the high-level client checks a sender against this table before
//!     queuing an intro (skip the queue for already-trusted senders),
//!   - the CLI's address-book commands work without DNS round-trips,
//!   - the per-contact `require_signing_key` flag can express the
//!     `--require-signing-key` trust mode out of the M3 plan.
//!
//! No equivalent Python module exists; the schema is entirely a Rust-
//! port addition.

use std::time::{SystemTime, UNIX_EPOCH};

use dnsmesh_core::{ED25519_KEY_LEN, X25519_KEY_LEN};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};

use crate::connection::OpenedDb;
use crate::error::StorageError;

/// A persisted contact entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    /// Display name / DMP username (PRIMARY KEY).
    pub username: String,
    /// 32-byte X25519 public key — used for ECDH when sending.
    pub x25519_pk: [u8; X25519_KEY_LEN],
    /// 32-byte Ed25519 signing public key — used to verify manifests.
    pub ed25519_spk: [u8; ED25519_KEY_LEN],
    /// Unix seconds when this contact was first added.
    pub first_seen_ts: u64,
    /// If true, the receive path requires the sender's manifest
    /// signature to verify against `ed25519_spk` exactly — even one
    /// malformed signature drops the message rather than falling back
    /// to the intro queue. Maps to the M3 plan's
    /// `--require-signing-key` trust mode.
    pub require_signing_key: bool,
    /// Mesh zone the contact is published under (e.g. `"mesh.local"`).
    ///
    /// Cross-zone receive walks each pinned contact's zone in addition
    /// to the caller's own zone — without this column we can't tell a
    /// Rust client which foreign zones to poll, so a Python sender at
    /// `alice.zone` sending to a Rust recipient at `bob.zone` becomes
    /// invisible. Empty string means "use the local mesh zone" — the
    /// V1/V2 legacy default for rows that predate the V3 migration.
    pub domain: String,
}

/// Inputs for [`ContactStore::add_contact`]. Borrowing variant so
/// callers don't allocate twice for the INSERT bind.
#[derive(Debug, Clone, Copy)]
pub struct NewContact<'a> {
    pub username: &'a str,
    pub x25519_pk: &'a [u8; X25519_KEY_LEN],
    pub ed25519_spk: &'a [u8; ED25519_KEY_LEN],
    pub require_signing_key: bool,
    /// Mesh zone the contact is published under. See
    /// [`Contact::domain`] for the back-compat semantics around `""`.
    pub domain: &'a str,
}

/// Sqlite-backed contact store.
pub struct ContactStore {
    conn: Mutex<Connection>,
}

impl std::fmt::Debug for ContactStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContactStore").finish()
    }
}

impl ContactStore {
    /// Build a store from a fully-opened, migrated database.
    #[must_use]
    pub fn new(db: OpenedDb) -> Self {
        Self::from_connection(db.into_connection())
    }

    /// Build a store from a raw [`Connection`]. Connection must already
    /// have the latest migrations applied.
    #[must_use]
    pub fn from_connection(conn: Connection) -> Self {
        Self {
            conn: Mutex::new(conn),
        }
    }

    /// Insert or replace a contact.
    ///
    /// Username collisions overwrite the existing entry. This matches
    /// the `dnsmesh contact add --replace`-style flow we want from the
    /// CLI: re-running an add with a rotated key updates the cached
    /// public material rather than erroring out. `first_seen_ts` is
    /// preserved across an upsert so the audit-trail timestamp doesn't
    /// reset on every key rotation.
    pub fn add_contact(&self, new: NewContact<'_>) -> Result<(), StorageError> {
        let now = unix_now();
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO contacts \
             (username, x25519_pk, ed25519_spk, first_seen_ts, require_signing_key, domain) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT(username) DO UPDATE SET \
                 x25519_pk           = excluded.x25519_pk, \
                 ed25519_spk         = excluded.ed25519_spk, \
                 require_signing_key = excluded.require_signing_key, \
                 domain              = excluded.domain",
            params![
                new.username,
                &new.x25519_pk[..],
                &new.ed25519_spk[..],
                i64_secs(now),
                i32::from(new.require_signing_key),
                new.domain,
            ],
        )?;
        Ok(())
    }

    /// Look up a contact by username.
    pub fn get_contact(&self, username: &str) -> Result<Option<Contact>, StorageError> {
        let conn = self.conn.lock();
        let row = conn
            .query_row(
                "SELECT username, x25519_pk, ed25519_spk, first_seen_ts, require_signing_key, domain \
                 FROM contacts WHERE username = ?1",
                params![username],
                row_to_contact,
            )
            .optional()?;
        match row {
            Some(Ok(c)) => Ok(Some(c)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// Delete a contact by username. Returns `true` if a row was removed.
    pub fn remove_contact(&self, username: &str) -> Result<bool, StorageError> {
        let conn = self.conn.lock();
        let removed = conn.execute(
            "DELETE FROM contacts WHERE username = ?1",
            params![username],
        )?;
        Ok(removed > 0)
    }

    /// Every contact, sorted alphabetically by username.
    pub fn list_contacts(&self) -> Result<Vec<Contact>, StorageError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT username, x25519_pk, ed25519_spk, first_seen_ts, require_signing_key, domain \
             FROM contacts ORDER BY username ASC",
        )?;
        let rows = stmt.query_map([], row_to_contact)?;
        let mut out = Vec::new();
        for r in rows {
            // Each `r` is a rusqlite::Result<Result<Contact, StorageError>>.
            out.push(r??);
        }
        Ok(out)
    }

    /// Number of stored contacts.
    pub fn len(&self) -> Result<u64, StorageError> {
        let conn = self.conn.lock();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM contacts", [], |row| row.get(0))?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// True if the store has zero contacts.
    pub fn is_empty(&self) -> Result<bool, StorageError> {
        Ok(self.len()? == 0)
    }
}

/// Decode one row into a [`Contact`]. Returns `Err(StorageError)` if a
/// blob column is the wrong length — that should only happen if the db
/// file was hand-edited or imported from a different schema.
fn row_to_contact(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Contact, StorageError>> {
    let username: String = row.get(0)?;
    let x25519_blob: Vec<u8> = row.get(1)?;
    let ed25519_blob: Vec<u8> = row.get(2)?;
    let first_seen_ts: i64 = row.get(3)?;
    let require_signing_key: i64 = row.get(4)?;
    let domain: String = row.get(5)?;

    if x25519_blob.len() != X25519_KEY_LEN {
        return Ok(Err(StorageError::CorruptBlobLength {
            field: "contacts.x25519_pk",
            expected: X25519_KEY_LEN,
            actual: x25519_blob.len(),
        }));
    }
    if ed25519_blob.len() != ED25519_KEY_LEN {
        return Ok(Err(StorageError::CorruptBlobLength {
            field: "contacts.ed25519_spk",
            expected: ED25519_KEY_LEN,
            actual: ed25519_blob.len(),
        }));
    }
    let mut x25519_pk = [0u8; X25519_KEY_LEN];
    x25519_pk.copy_from_slice(&x25519_blob);
    let mut ed25519_spk = [0u8; ED25519_KEY_LEN];
    ed25519_spk.copy_from_slice(&ed25519_blob);

    Ok(Ok(Contact {
        username,
        x25519_pk,
        ed25519_spk,
        first_seen_ts: u64::try_from(first_seen_ts).unwrap_or(0),
        require_signing_key: require_signing_key != 0,
        domain,
    }))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn i64_secs(secs: u64) -> i64 {
    i64::try_from(secs).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> ContactStore {
        ContactStore::new(OpenedDb::open_in_memory().unwrap())
    }

    fn pk(b: u8) -> [u8; X25519_KEY_LEN] {
        [b; X25519_KEY_LEN]
    }
    fn spk(b: u8) -> [u8; ED25519_KEY_LEN] {
        [b; ED25519_KEY_LEN]
    }

    #[test]
    fn add_and_get_round_trip() {
        let s = store();
        s.add_contact(NewContact {
            username: "alice",
            x25519_pk: &pk(1),
            ed25519_spk: &spk(2),
            require_signing_key: true,
            domain: "mesh.local",
        })
        .unwrap();
        let got = s.get_contact("alice").unwrap().expect("contact present");
        assert_eq!(got.username, "alice");
        assert_eq!(got.x25519_pk, pk(1));
        assert_eq!(got.ed25519_spk, spk(2));
        assert!(got.require_signing_key);
        assert!(got.first_seen_ts > 0);
        assert_eq!(got.domain, "mesh.local");
    }

    #[test]
    fn add_contact_upserts_on_username_collision() {
        let s = store();
        s.add_contact(NewContact {
            username: "bob",
            x25519_pk: &pk(1),
            ed25519_spk: &spk(2),
            require_signing_key: false,
            domain: "old.zone",
        })
        .unwrap();
        // Re-add with a rotated key + new zone.
        s.add_contact(NewContact {
            username: "bob",
            x25519_pk: &pk(99),
            ed25519_spk: &spk(99),
            require_signing_key: true,
            domain: "new.zone",
        })
        .unwrap();
        let got = s.get_contact("bob").unwrap().unwrap();
        assert_eq!(got.x25519_pk, pk(99));
        assert!(got.require_signing_key);
        assert_eq!(got.domain, "new.zone");
        assert_eq!(s.len().unwrap(), 1);
    }

    #[test]
    fn remove_returns_true_only_for_existing() {
        let s = store();
        s.add_contact(NewContact {
            username: "carol",
            x25519_pk: &pk(3),
            ed25519_spk: &spk(3),
            require_signing_key: false,
            domain: "mesh.local",
        })
        .unwrap();
        assert!(s.remove_contact("carol").unwrap());
        assert!(!s.remove_contact("carol").unwrap());
        assert!(s.is_empty().unwrap());
    }

    #[test]
    fn list_is_alphabetical() {
        let s = store();
        for name in &["charlie", "alice", "bob"] {
            s.add_contact(NewContact {
                username: name,
                x25519_pk: &pk(1),
                ed25519_spk: &spk(1),
                require_signing_key: false,
                domain: "mesh.local",
            })
            .unwrap();
        }
        let names: Vec<String> = s
            .list_contacts()
            .unwrap()
            .into_iter()
            .map(|c| c.username)
            .collect();
        assert_eq!(names, vec!["alice", "bob", "charlie"]);
    }

    #[test]
    fn get_unknown_username_is_none() {
        let s = store();
        assert!(s.get_contact("nobody").unwrap().is_none());
    }

    #[test]
    fn domain_round_trips_through_list_and_get() {
        // Cross-zone fix: the per-contact domain must persist through
        // both list_contacts and get_contact, otherwise the receive
        // path can't tell which foreign zones to poll.
        let s = store();
        s.add_contact(NewContact {
            username: "remote",
            x25519_pk: &pk(7),
            ed25519_spk: &spk(8),
            require_signing_key: false,
            domain: "alice.zone",
        })
        .unwrap();
        s.add_contact(NewContact {
            username: "local",
            x25519_pk: &pk(1),
            ed25519_spk: &spk(2),
            require_signing_key: false,
            domain: "",
        })
        .unwrap();

        let got_remote = s.get_contact("remote").unwrap().unwrap();
        assert_eq!(got_remote.domain, "alice.zone");
        let got_local = s.get_contact("local").unwrap().unwrap();
        assert_eq!(
            got_local.domain, "",
            "empty domain (V1/V2 back-compat) must survive round-trip",
        );

        let listed = s.list_contacts().unwrap();
        let by_name: std::collections::HashMap<_, _> = listed
            .into_iter()
            .map(|c| (c.username.clone(), c))
            .collect();
        assert_eq!(by_name["remote"].domain, "alice.zone");
        assert_eq!(by_name["local"].domain, "");
    }
}

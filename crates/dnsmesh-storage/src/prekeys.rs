//! Sqlite-backed store of one-time prekey *private* keys.
//!
//! Mirrors `dmp/core/prekeys.py::PrekeyStore` with one critical
//! deviation: [`PrekeyStore::consume`] DELETES the row. Python's
//! implementation kept the row (only meaning to delete it but the bug
//! was never followed through) and that broke forward secrecy — anyone
//! who later compromised the sqlite file could decrypt past traffic.
//! Here, deletion is the actual security guarantee. The `consumed_at`
//! column added in V2 is an audit/debug aid only; in normal operation
//! the row is gone before anything observes the timestamp.
//!
//! The wire-format [`Prekey`] struct (the public side that gets signed
//! and published in DNS) lives in `dnsmesh-core`. This module owns the
//! private halves: 32-byte X25519 secret keys held in
//! [`Zeroizing<Vec<u8>>`] so they're wiped from memory on drop.

use std::time::{SystemTime, UNIX_EPOCH};

use dnsmesh_core::prekeys::Prekey;
use dnsmesh_core::X25519_KEY_LEN;
use parking_lot::Mutex;
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::connection::OpenedDb;
use crate::error::StorageError;

/// How many random `prekey_id` candidates we'll try before giving up on
/// a collision. Mirrors the Python `_retry in range(10)` loop, but
/// surfaces the exhaustion as a real error rather than `RuntimeError`.
const MAX_PREKEY_ID_RETRIES: u32 = 16;

/// A freshly-generated prekey + its private half, returned by
/// [`PrekeyStore::generate_pool`].
///
/// The private key is wrapped in `Zeroizing` so the heap buffer is
/// wiped when this struct is dropped. Callers that need to keep the
/// private key past the immediate publish step should re-fetch it from
/// the store via [`PrekeyStore::get_private_key`] rather than holding
/// this struct alive.
pub struct GeneratedPrekey {
    /// Public side — sign this with the identity key and publish.
    pub prekey: Prekey,
    /// 32-byte X25519 private scalar. Zeroized on drop.
    pub private_key: Zeroizing<[u8; X25519_KEY_LEN]>,
}

impl std::fmt::Debug for GeneratedPrekey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedPrekey")
            .field("prekey", &self.prekey)
            .field(
                "private_key",
                &format_args!("<redacted {} bytes>", self.private_key.len()),
            )
            .finish()
    }
}

/// Sqlite-backed store of prekey private keys.
///
/// Thread-safe via a single `parking_lot::Mutex<Connection>`. Rusqlite
/// is not reentrant, so we take care never to call back into the store
/// while the lock is held.
pub struct PrekeyStore {
    conn: Mutex<Connection>,
}

impl std::fmt::Debug for PrekeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrekeyStore").finish()
    }
}

impl PrekeyStore {
    /// Build a store from a fully-opened, migrated database.
    #[must_use]
    pub fn new(db: OpenedDb) -> Self {
        Self::from_connection(db.into_connection())
    }

    /// Build a store from a raw sqlite [`Connection`]. The connection
    /// must already have the latest migrations applied (call
    /// [`OpenedDb::open`] first); no schema work happens here.
    #[must_use]
    pub fn from_connection(conn: Connection) -> Self {
        Self {
            conn: Mutex::new(conn),
        }
    }

    /// Generate `count` fresh prekeys, persist their private halves,
    /// and return the public + private pairs.
    ///
    /// Each prekey gets a random 32-bit id; collisions retry up to
    /// `MAX_PREKEY_ID_RETRIES` times before erroring out. The returned
    /// [`GeneratedPrekey`] entries hold zeroizing private keys — the
    /// caller is expected to immediately sign and publish the public
    /// side, then drop the private bytes.
    ///
    /// Callers should follow up with [`Self::record_wire`] for each
    /// returned prekey so [`Self::consume`] can also delete the
    /// published TXT record from DNS.
    pub fn generate_pool(
        &self,
        count: usize,
        ttl_seconds: u64,
    ) -> Result<Vec<GeneratedPrekey>, StorageError> {
        let now = unix_now();
        let exp = now.saturating_add(ttl_seconds);
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let prekey_id = allocate_prekey_id(&tx)?;

            // Generate a fresh X25519 keypair. StaticSecret::random_from_rng
            // pulls from OsRng, matching the Python `X25519PrivateKey.generate()`
            // which goes through cryptography's OS-RNG.
            let secret = StaticSecret::random_from_rng(OsRng);
            let public = X25519PublicKey::from(&secret);
            let mut sk_bytes = secret.to_bytes();
            let pk_bytes = public.to_bytes();

            tx.execute(
                "INSERT INTO prekeys \
                 (prekey_id, private_key, public_key, exp, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    prekey_id,
                    &sk_bytes[..],
                    &pk_bytes[..],
                    i64_secs(exp),
                    i64_secs(now)
                ],
            )?;

            let prekey = Prekey {
                prekey_id,
                public_key: pk_bytes,
                exp,
            };
            // Move the secret bytes into a zeroizing wrapper for return,
            // then wipe the local copy.
            let private_key = Zeroizing::new(sk_bytes);
            sk_bytes = [0u8; X25519_KEY_LEN];
            let _ = sk_bytes; // silence unused-assignment lints
            out.push(GeneratedPrekey {
                prekey,
                private_key,
            });
        }
        tx.commit()?;
        Ok(out)
    }

    /// Remember the signed TXT record bytes published for `prekey_id`.
    ///
    /// [`Self::consume`] uses this so it can also delete the record from
    /// DNS, preventing senders from picking already-consumed entries.
    /// No-op if `prekey_id` is unknown.
    pub fn record_wire(&self, prekey_id: u32, wire_record: &str) -> Result<(), StorageError> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE prekeys SET wire_record = ?1 WHERE prekey_id = ?2",
            params![wire_record, prekey_id],
        )?;
        Ok(())
    }

    /// Return the stored wire-record string for `prekey_id`, or `None`
    /// if absent or empty.
    pub fn get_wire(&self, prekey_id: u32) -> Result<Option<String>, StorageError> {
        let conn = self.conn.lock();
        let row: Option<String> = conn
            .query_row(
                "SELECT wire_record FROM prekeys WHERE prekey_id = ?1",
                params![prekey_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(row.filter(|s| !s.is_empty()))
    }

    /// Return the private key for `prekey_id`, or `None` if absent or
    /// expired.
    ///
    /// The returned bytes are wrapped in `Zeroizing` so the heap buffer
    /// is wiped on drop. Match the Python contract: a prekey that has
    /// passed its `exp` is treated as not-found rather than returned.
    pub fn get_private_key(
        &self,
        prekey_id: u32,
    ) -> Result<Option<Zeroizing<[u8; X25519_KEY_LEN]>>, StorageError> {
        let now = unix_now();
        let conn = self.conn.lock();
        let row: Option<Vec<u8>> = conn
            .query_row(
                "SELECT private_key FROM prekeys WHERE prekey_id = ?1 AND exp > ?2",
                params![prekey_id, i64_secs(now)],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some(bytes) => {
                if bytes.len() != X25519_KEY_LEN {
                    return Err(StorageError::CorruptBlobLength {
                        field: "prekeys.private_key",
                        expected: X25519_KEY_LEN,
                        actual: bytes.len(),
                    });
                }
                let mut arr = [0u8; X25519_KEY_LEN];
                arr.copy_from_slice(&bytes);
                Ok(Some(Zeroizing::new(arr)))
            }
        }
    }

    /// Consume (delete) the prekey for `prekey_id`. Returns `true` if
    /// something was deleted.
    ///
    /// **This is the forward-secrecy fix.** Python only intended to
    /// delete on consume but the bug left the row in place; a later
    /// compromise of the sqlite file could then re-derive the session
    /// key and decrypt past traffic. Here the DELETE is the guarantee:
    /// once the row is gone, neither this process nor a future attacker
    /// with the long-term key can recover the prekey scalar.
    ///
    /// We update `consumed_at` in the same transaction before the
    /// delete; the column is purely an audit/debug aid (it's gone with
    /// the row in the same commit) but provides a single hook in the
    /// codebase that ties consume() to a timestamp for tracing.
    pub fn consume(&self, prekey_id: u32) -> Result<bool, StorageError> {
        let now = unix_now();
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        // Update consumed_at first as a no-op-on-disk audit hook (the
        // DELETE below removes the row anyway, but having the UPDATE in
        // the codepath makes the intent explicit and lets future
        // tracing/audit hooks tap in at one place).
        tx.execute(
            "UPDATE prekeys SET consumed_at = ?1 WHERE prekey_id = ?2",
            params![i64_secs(now), prekey_id],
        )?;
        let removed = tx.execute(
            "DELETE FROM prekeys WHERE prekey_id = ?1",
            params![prekey_id],
        )?;
        tx.commit()?;
        Ok(removed > 0)
    }

    /// Number of unexpired prekeys.
    pub fn count_live(&self) -> Result<u64, StorageError> {
        let now = unix_now();
        let conn = self.conn.lock();
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM prekeys WHERE exp > ?1",
            params![i64_secs(now)],
            |row| row.get(0),
        )?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// Delete every expired prekey. Returns the number of rows removed.
    pub fn cleanup_expired(&self) -> Result<u64, StorageError> {
        let now = unix_now();
        let conn = self.conn.lock();
        let removed = conn.execute(
            "DELETE FROM prekeys WHERE exp <= ?1",
            params![i64_secs(now)],
        )?;
        Ok(removed as u64)
    }

    /// IDs of every unexpired prekey, sorted ascending.
    pub fn list_live_ids(&self) -> Result<Vec<u32>, StorageError> {
        let now = unix_now();
        let conn = self.conn.lock();
        let mut stmt =
            conn.prepare("SELECT prekey_id FROM prekeys WHERE exp > ?1 ORDER BY prekey_id")?;
        let rows = stmt.query_map(params![i64_secs(now)], |row| row.get::<_, i64>(0))?;
        let mut out = Vec::new();
        for r in rows {
            let id = r?;
            // sqlite stores INTEGER as i64; our prekey_id is u32. The
            // INSERT path always uses a u32, so a wider value here means
            // the file was hand-edited. Truncate via try_from and surface
            // the corruption.
            let id = u32::try_from(id).map_err(|_| StorageError::CorruptBlobLength {
                field: "prekeys.prekey_id",
                expected: 4,
                actual: 8,
            })?;
            out.push(id);
        }
        Ok(out)
    }
}

fn allocate_prekey_id(tx: &rusqlite::Transaction<'_>) -> Result<u32, StorageError> {
    for _ in 0..MAX_PREKEY_ID_RETRIES {
        let mut buf = [0u8; 4];
        OsRng.fill_bytes(&mut buf);
        let candidate = u32::from_be_bytes(buf);
        let exists: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM prekeys WHERE prekey_id = ?1",
                params![candidate],
                |row| row.get(0),
            )
            .optional()?;
        if exists.is_none() {
            return Ok(candidate);
        }
    }
    Err(StorageError::PrekeyIdExhausted {
        tries: MAX_PREKEY_ID_RETRIES,
    })
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Convert a unix-seconds u64 into the i64 sqlite stores. Saturating
/// is the right behavior here: a u64 large enough to overflow i64 is
/// far past the heat-death of any plausible deployment, and we'd
/// rather pin to i64::MAX than panic.
fn i64_secs(secs: u64) -> i64 {
    i64::try_from(secs).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> PrekeyStore {
        PrekeyStore::new(OpenedDb::open_in_memory(&crate::connection::TEST_STORAGE_KEY).unwrap())
    }

    #[test]
    fn generate_pool_persists_and_returns_keys() {
        let s = store();
        let pool = s.generate_pool(3, 3600).unwrap();
        assert_eq!(pool.len(), 3);
        // Each row should be retrievable by id, and the bytes round-trip.
        for entry in &pool {
            let sk = s
                .get_private_key(entry.prekey.prekey_id)
                .unwrap()
                .expect("private key must be retrievable");
            assert_eq!(&*sk, &*entry.private_key);
            // Public key derived from the stored private must match the
            // public bytes we returned.
            let derived = X25519PublicKey::from(&StaticSecret::from(*sk)).to_bytes();
            assert_eq!(derived, entry.prekey.public_key);
        }
        assert_eq!(s.count_live().unwrap(), 3);
    }

    #[test]
    fn list_live_ids_is_sorted_and_complete() {
        let s = store();
        let pool = s.generate_pool(5, 3600).unwrap();
        let mut expected: Vec<u32> = pool.iter().map(|p| p.prekey.prekey_id).collect();
        expected.sort_unstable();
        assert_eq!(s.list_live_ids().unwrap(), expected);
    }

    #[test]
    fn consume_deletes_the_row_for_forward_secrecy() {
        let s = store();
        let pool = s.generate_pool(1, 3600).unwrap();
        let id = pool[0].prekey.prekey_id;
        assert!(s.get_private_key(id).unwrap().is_some());
        assert!(s.consume(id).unwrap());
        // The row is GONE — this is the forward-secrecy guarantee.
        assert!(s.get_private_key(id).unwrap().is_none());
        // count_live reflects the deletion.
        assert_eq!(s.count_live().unwrap(), 0);
        // Second consume returns false (nothing to delete).
        assert!(!s.consume(id).unwrap());
    }

    #[test]
    fn record_and_get_wire_round_trip() {
        let s = store();
        let pool = s.generate_pool(1, 3600).unwrap();
        let id = pool[0].prekey.prekey_id;
        assert!(s.get_wire(id).unwrap().is_none());
        s.record_wire(id, "v=dmp1;t=prekey;d=abcd").unwrap();
        assert_eq!(
            s.get_wire(id).unwrap().as_deref(),
            Some("v=dmp1;t=prekey;d=abcd"),
        );
    }

    #[test]
    fn expired_prekeys_are_invisible_until_cleanup() {
        let s = store();
        // ttl_seconds = 0 means exp == now; the > now filter excludes it.
        let pool = s.generate_pool(2, 0).unwrap();
        assert_eq!(s.count_live().unwrap(), 0);
        assert!(s.list_live_ids().unwrap().is_empty());
        for entry in &pool {
            assert!(s.get_private_key(entry.prekey.prekey_id).unwrap().is_none());
        }
        assert_eq!(s.cleanup_expired().unwrap(), 2);
        assert_eq!(s.cleanup_expired().unwrap(), 0);
    }

    #[test]
    fn get_private_key_returns_none_for_unknown_id() {
        let s = store();
        assert!(s.get_private_key(0xdead_beef).unwrap().is_none());
    }

    #[test]
    fn debug_redacts_the_private_key() {
        let s = store();
        let pool = s.generate_pool(1, 3600).unwrap();
        let rendered = format!("{:?}", pool[0]);
        assert!(rendered.contains("redacted"));
        // The hex bytes themselves must not appear.
        let hex_sk = hex::encode(&pool[0].private_key[..]);
        assert!(
            !rendered.contains(&hex_sk),
            "GeneratedPrekey Debug must not leak the private key",
        );
    }
}

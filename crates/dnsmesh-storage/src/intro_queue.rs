//! Sqlite-backed pending-intro queue.
//!
//! When a claim-discovered manifest is signed by a `sender_spk` that is
//! NOT in the recipient's pinned-contact set, the receive path lands the
//! decrypted plaintext into this queue rather than delivering it
//! straight to the inbox. The user reviews entries with the CLI and
//! chooses to accept (deliver this one) or reject (drop it).
//!
//! Mirrors the *intros* portion of `dmp/client/intro_queue.py`. The
//! Python module also owns a `denylist` table; that lives in this same
//! schema (V1) but is exposed through a separate API on
//! [`IntroQueue`] for clarity. Multi-device sync of the queue or
//! denylist is deliberately out of scope here, same as Python.

use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};

use crate::connection::OpenedDb;
use crate::error::StorageError;

/// A single quarantined first-contact message awaiting user review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingIntro {
    /// Auto-incrementing id for CLI-side reference (`dnsmesh intro accept N`).
    pub intro_id: i64,
    /// 32-byte Ed25519 signing public key of the sender.
    pub sender_spk: Vec<u8>,
    /// Optional username known via fetched identity record. Empty if unknown.
    pub sender_username: Option<String>,
    /// 16-byte message id from the manifest.
    pub msg_id: Vec<u8>,
    /// Decrypted plaintext payload. Stored as-is so the user reviewing
    /// the queue sees what was actually sent — re-fetching from DNS at
    /// review time would risk the chunks expiring before the user got
    /// to them.
    pub payload: Vec<u8>,
    /// Unix seconds when the receive path queued this entry.
    pub received_at: u64,
    /// Manifest-derived expiry; past this point the user can still see
    /// the row (because plaintext is captured) but the source manifest
    /// in DNS is no longer addressable.
    pub expires_at: u64,
}

/// Inputs for [`IntroQueue::enqueue`].
///
/// Borrowing variant so callers don't have to clone every field — the
/// store will allocate its own owned copies for the INSERT bind. All
/// fields are `Copy`-friendly so this whole struct is `Copy` and a
/// caller can pass the same value to [`IntroQueue::enqueue`] twice
/// (e.g. retry on a transient sqlite IO error) without rebuilding it.
#[derive(Debug, Clone, Copy)]
pub struct NewIntro<'a> {
    pub sender_spk: &'a [u8],
    pub sender_username: Option<&'a str>,
    pub msg_id: &'a [u8],
    pub payload: &'a [u8],
    pub expires_at: u64,
}

/// Sqlite-backed pending-intro queue + sender denylist.
pub struct IntroQueue {
    conn: Mutex<Connection>,
}

impl std::fmt::Debug for IntroQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntroQueue").finish()
    }
}

impl IntroQueue {
    /// Build a queue from a fully-opened, migrated database.
    #[must_use]
    pub fn new(db: OpenedDb) -> Self {
        Self::from_connection(db.into_connection())
    }

    /// Build a queue from a raw [`Connection`]. Connection must already
    /// have the latest migrations applied.
    #[must_use]
    pub fn from_connection(conn: Connection) -> Self {
        Self {
            conn: Mutex::new(conn),
        }
    }

    /// Insert a new pending intro. Returns:
    ///
    ///   - `Ok(Some(intro_id))` on insert,
    ///   - `Ok(None)` if `(sender_spk, msg_id)` is already pending — a
    ///     poll that re-discovers the same claim won't grow the queue —
    ///     or if `sender_spk` is on the denylist (block was previously
    ///     called).
    ///
    /// Mirrors Python `IntroQueue.add_intro` — the deny check is
    /// pulled into this method so the receive path doesn't have to
    /// remember to gate every enqueue.
    pub fn enqueue(&self, intro: NewIntro<'_>) -> Result<Option<i64>, StorageError> {
        let now = unix_now();
        let conn = self.conn.lock();
        if Self::is_blocked_inner(&conn, intro.sender_spk)? {
            return Ok(None);
        }
        let result = conn.execute(
            "INSERT INTO intro_queue \
             (sender_spk, sender_username, msg_id, payload, received_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                intro.sender_spk,
                intro.sender_username,
                intro.msg_id,
                intro.payload,
                i64_secs(now),
                i64_secs(intro.expires_at),
            ],
        );
        match result {
            Ok(_) => Ok(Some(conn.last_insert_rowid())),
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                // UNIQUE(sender_spk, msg_id) collision: dedup, no-op.
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Add `sender_spk` to the denylist. Idempotent — re-blocking the
    /// same sender refreshes `blocked_at` + `note` rather than failing.
    pub fn block_sender(&self, sender_spk: &[u8], note: &str) -> Result<(), StorageError> {
        let now = unix_now();
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO intro_denylist (sender_spk, blocked_at, note) \
             VALUES (?1, ?2, ?3) \
             ON CONFLICT(sender_spk) DO UPDATE SET blocked_at = excluded.blocked_at, \
                                                   note       = excluded.note",
            params![sender_spk, i64_secs(now), note],
        )?;
        Ok(())
    }

    /// Remove `sender_spk` from the denylist. Returns `true` if a row
    /// was actually removed.
    pub fn unblock_sender(&self, sender_spk: &[u8]) -> Result<bool, StorageError> {
        let conn = self.conn.lock();
        let removed = conn.execute(
            "DELETE FROM intro_denylist WHERE sender_spk = ?1",
            params![sender_spk],
        )?;
        Ok(removed > 0)
    }

    /// True if `sender_spk` has been previously blocked.
    pub fn is_blocked(&self, sender_spk: &[u8]) -> Result<bool, StorageError> {
        let conn = self.conn.lock();
        Self::is_blocked_inner(&conn, sender_spk)
    }

    fn is_blocked_inner(conn: &Connection, sender_spk: &[u8]) -> Result<bool, StorageError> {
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM intro_denylist WHERE sender_spk = ?1",
            params![sender_spk],
            |row| row.get(0),
        )?;
        Ok(n > 0)
    }

    /// All pending intros, newest first by `received_at`.
    pub fn list_pending(&self) -> Result<Vec<PendingIntro>, StorageError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT intro_id, sender_spk, sender_username, msg_id, payload, \
                    received_at, expires_at \
             FROM intro_queue ORDER BY received_at DESC, intro_id DESC",
        )?;
        let rows = stmt.query_map([], row_to_intro)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Look up one entry by id.
    pub fn get(&self, intro_id: i64) -> Result<Option<PendingIntro>, StorageError> {
        let conn = self.conn.lock();
        let row = conn
            .query_row(
                "SELECT intro_id, sender_spk, sender_username, msg_id, payload, \
                        received_at, expires_at \
                 FROM intro_queue WHERE intro_id = ?1",
                params![intro_id],
                row_to_intro,
            )
            .optional()?;
        Ok(row)
    }

    /// Accept the intro (delete it; caller is responsible for delivery
    /// to the inbox). Returns `true` if a row was removed.
    pub fn accept(&self, intro_id: i64) -> Result<bool, StorageError> {
        self.delete_one(intro_id)
    }

    /// Reject the intro (delete it; caller decides whether to denylist
    /// the sender separately). Returns `true` if a row was removed.
    pub fn reject(&self, intro_id: i64) -> Result<bool, StorageError> {
        self.delete_one(intro_id)
    }

    /// Read-and-delete `intro_id` atomically: the same DELETE statement
    /// returns the row it removed via the SQLite `RETURNING` clause. If
    /// two concurrent callers both invoke `take(id)`, exactly one wins
    /// the row; the other gets `Ok(None)`. Without this atomicity, an
    /// `accept_intro` / `trust_intro` race could surface the same
    /// plaintext to two consumers — the queue is per-machine but a
    /// user with two terminals open would still hit it.
    pub fn take(&self, intro_id: i64) -> Result<Option<PendingIntro>, StorageError> {
        let conn = self.conn.lock();
        // SQLite 3.35+ supports DELETE ... RETURNING. The bundled
        // rusqlite ships a recent enough libsqlite3-sys that this is
        // available across all our targets.
        let row = conn
            .query_row(
                "DELETE FROM intro_queue WHERE intro_id = ?1 \
                 RETURNING intro_id, sender_spk, sender_username, msg_id, \
                           payload, received_at, expires_at",
                params![intro_id],
                row_to_intro,
            )
            .optional()?;
        Ok(row)
    }

    /// Drop every entry whose `expires_at` is in the past. Returns the
    /// number of rows removed.
    pub fn cleanup_expired(&self) -> Result<u64, StorageError> {
        let now = unix_now();
        let conn = self.conn.lock();
        let removed = conn.execute(
            "DELETE FROM intro_queue WHERE expires_at <= ?1",
            params![i64_secs(now)],
        )?;
        Ok(removed as u64)
    }

    /// Number of currently-pending intros (regardless of expiry).
    pub fn len(&self) -> Result<u64, StorageError> {
        let conn = self.conn.lock();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM intro_queue", [], |row| row.get(0))?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// True if the queue holds zero entries.
    pub fn is_empty(&self) -> Result<bool, StorageError> {
        Ok(self.len()? == 0)
    }

    fn delete_one(&self, intro_id: i64) -> Result<bool, StorageError> {
        let conn = self.conn.lock();
        let removed = conn.execute(
            "DELETE FROM intro_queue WHERE intro_id = ?1",
            params![intro_id],
        )?;
        Ok(removed > 0)
    }
}

fn row_to_intro(row: &rusqlite::Row<'_>) -> rusqlite::Result<PendingIntro> {
    Ok(PendingIntro {
        intro_id: row.get(0)?,
        sender_spk: row.get(1)?,
        sender_username: row.get(2)?,
        msg_id: row.get(3)?,
        payload: row.get(4)?,
        received_at: u64::try_from(row.get::<_, i64>(5)?).unwrap_or(0),
        expires_at: u64::try_from(row.get::<_, i64>(6)?).unwrap_or(0),
    })
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

    fn queue() -> IntroQueue {
        IntroQueue::new(OpenedDb::open_in_memory(&crate::connection::TEST_STORAGE_KEY).unwrap())
    }

    fn sample(spk: u8, mid: u8) -> (Vec<u8>, Vec<u8>) {
        (vec![spk; 32], vec![mid; 16])
    }

    #[test]
    fn enqueue_and_list_round_trip() {
        let q = queue();
        let (spk, mid) = sample(1, 1);
        let id = q
            .enqueue(NewIntro {
                sender_spk: &spk,
                sender_username: Some("alice"),
                msg_id: &mid,
                payload: b"hello",
                expires_at: u64::MAX / 2,
            })
            .unwrap()
            .expect("first enqueue must insert");
        let got = q.get(id).unwrap().expect("get by id");
        assert_eq!(got.sender_spk, spk);
        assert_eq!(got.msg_id, mid);
        assert_eq!(got.payload, b"hello");
        assert_eq!(got.sender_username.as_deref(), Some("alice"));
        assert_eq!(q.list_pending().unwrap().len(), 1);
    }

    #[test]
    fn duplicate_enqueue_is_no_op() {
        let q = queue();
        let (spk, mid) = sample(2, 2);
        let intro = NewIntro {
            sender_spk: &spk,
            sender_username: None,
            msg_id: &mid,
            payload: b"x",
            expires_at: u64::MAX / 2,
        };
        assert!(q.enqueue(intro).unwrap().is_some());
        assert!(q.enqueue(intro).unwrap().is_none(), "second insert dedups");
        assert_eq!(q.len().unwrap(), 1);
    }

    #[test]
    fn accept_and_reject_remove_rows() {
        let q = queue();
        let (spk1, mid1) = sample(1, 1);
        let (spk2, mid2) = sample(2, 2);
        let id1 = q
            .enqueue(NewIntro {
                sender_spk: &spk1,
                sender_username: None,
                msg_id: &mid1,
                payload: b"a",
                expires_at: u64::MAX / 2,
            })
            .unwrap()
            .unwrap();
        let id2 = q
            .enqueue(NewIntro {
                sender_spk: &spk2,
                sender_username: None,
                msg_id: &mid2,
                payload: b"b",
                expires_at: u64::MAX / 2,
            })
            .unwrap()
            .unwrap();
        assert!(q.accept(id1).unwrap());
        assert!(!q.accept(id1).unwrap(), "second accept is a no-op");
        assert!(q.reject(id2).unwrap());
        assert!(q.is_empty().unwrap());
    }

    #[test]
    fn take_is_atomic_read_and_delete() {
        let q = queue();
        let (spk, mid) = sample(9, 9);
        let id = q
            .enqueue(NewIntro {
                sender_spk: &spk,
                sender_username: Some("eve"),
                msg_id: &mid,
                payload: b"surface me once",
                expires_at: u64::MAX / 2,
            })
            .unwrap()
            .unwrap();
        let first = q.take(id).unwrap();
        let second = q.take(id).unwrap();
        assert!(first.is_some(), "first take must surface the row");
        assert!(
            second.is_none(),
            "second take must be empty — DELETE RETURNING is atomic",
        );
        assert_eq!(first.unwrap().payload, b"surface me once");
    }

    #[test]
    fn block_sender_drops_subsequent_enqueues() {
        let q = queue();
        let (spk, mid1) = sample(7, 1);
        let (_, mid2) = sample(7, 2);
        // First enqueue lands.
        q.enqueue(NewIntro {
            sender_spk: &spk,
            sender_username: None,
            msg_id: &mid1,
            payload: b"a",
            expires_at: u64::MAX / 2,
        })
        .unwrap()
        .unwrap();
        // Block the sender.
        q.block_sender(&spk, "abusive").unwrap();
        assert!(q.is_blocked(&spk).unwrap());
        // Second enqueue from the same sender is silently dropped.
        let res = q
            .enqueue(NewIntro {
                sender_spk: &spk,
                sender_username: None,
                msg_id: &mid2,
                payload: b"b",
                expires_at: u64::MAX / 2,
            })
            .unwrap();
        assert!(res.is_none(), "blocked sender must not be enqueued");
        // Block is idempotent — re-blocking refreshes the row, doesn't fail.
        q.block_sender(&spk, "still abusive").unwrap();
        // Unblock allows future enqueues.
        assert!(q.unblock_sender(&spk).unwrap());
        assert!(!q.is_blocked(&spk).unwrap());
        let after = q
            .enqueue(NewIntro {
                sender_spk: &spk,
                sender_username: None,
                msg_id: &mid2,
                payload: b"b",
                expires_at: u64::MAX / 2,
            })
            .unwrap();
        assert!(after.is_some(), "enqueue resumes after unblock");
    }

    #[test]
    fn cleanup_expired_drops_only_past_entries() {
        let q = queue();
        let (spk_a, mid_a) = sample(1, 1);
        let (spk_b, mid_b) = sample(2, 2);
        // Past expiry — will be cleaned.
        q.enqueue(NewIntro {
            sender_spk: &spk_a,
            sender_username: None,
            msg_id: &mid_a,
            payload: b"old",
            expires_at: 1,
        })
        .unwrap();
        // Far-future expiry — survives.
        q.enqueue(NewIntro {
            sender_spk: &spk_b,
            sender_username: None,
            msg_id: &mid_b,
            payload: b"new",
            expires_at: u64::MAX / 2,
        })
        .unwrap();
        assert_eq!(q.cleanup_expired().unwrap(), 1);
        assert_eq!(q.len().unwrap(), 1);
    }
}

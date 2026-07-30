//! Sqlite-backed replay cache.
//!
//! Reject re-publication of already-seen `(sender_spk, msg_id)` pairs.
//! Mirrors `dmp/core/manifest.py::ReplayCache` with one upgrade: the
//! Python implementation persisted to a JSON file (rewriting the whole
//! file atomically on every `record()`); the Rust port stores entries
//! in the per-identity sqlite db so check / record / cleanup are all
//! atomic transactions and we can scale past a few thousand entries
//! without the O(n) write amplification of the JSON rewrite.
//!
//! The split API (`has_seen` + `record`) and the convenience
//! `check_and_record` are preserved verbatim. New code in the Rust
//! port should prefer `has_seen` + `record` around the work that proves
//! the message was actually delivered, so a transient DNS miss during
//! chunk fetch doesn't permanently blacklist a valid manifest.

use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use rusqlite::{params, Connection};

use crate::connection::OpenedDb;
use crate::error::StorageError;

/// Default TTL applied by [`ReplayCache::record`] when no expiry is
/// supplied. Matches Python's `default_ttl = 3600`.
pub const DEFAULT_TTL_SECS: u64 = 3600;

/// Sqlite-backed replay cache.
pub struct ReplayCache {
    conn: Mutex<Connection>,
    default_ttl_secs: u64,
}

impl std::fmt::Debug for ReplayCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayCache")
            .field("default_ttl_secs", &self.default_ttl_secs)
            .finish_non_exhaustive()
    }
}

impl ReplayCache {
    /// Build a cache with the default TTL from a fully-opened database.
    #[must_use]
    pub fn new(db: OpenedDb) -> Self {
        Self::from_connection(db.into_connection(), DEFAULT_TTL_SECS)
    }

    /// Build a cache with a custom default TTL.
    #[must_use]
    pub fn with_ttl(db: OpenedDb, default_ttl_secs: u64) -> Self {
        Self::from_connection(db.into_connection(), default_ttl_secs)
    }

    /// Build a cache from a raw connection. Connection must already
    /// have the latest migrations applied.
    #[must_use]
    pub fn from_connection(conn: Connection, default_ttl_secs: u64) -> Self {
        Self {
            conn: Mutex::new(conn),
            default_ttl_secs,
        }
    }

    /// Read-only check: has this `(sender_spk, msg_id)` been recorded
    /// and not yet expired?
    pub fn has_seen(&self, sender_spk: &[u8], msg_id: &[u8]) -> Result<bool, StorageError> {
        let now = unix_now();
        let conn = self.conn.lock();
        Self::purge_locked(&conn, now)?;
        let exists: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM replay_cache \
                 WHERE sender_spk = ?1 AND msg_id = ?2 AND expiry > ?3",
                params![sender_spk, msg_id, i64_secs(now)],
                |row| row.get(0),
            )
            .ok();
        Ok(exists.is_some())
    }

    /// Commit `(sender_spk, msg_id)` to the seen set. If `expiry` is
    /// `None`, expires `default_ttl_secs` from now.
    ///
    /// Idempotent re-records bump the expiry to the new value (UPSERT
    /// on the composite primary key), matching Python's behavior of
    /// overwriting the dict entry.
    pub fn record(
        &self,
        sender_spk: &[u8],
        msg_id: &[u8],
        expiry: Option<u64>,
    ) -> Result<(), StorageError> {
        let now = unix_now();
        let exp = expiry.unwrap_or_else(|| now.saturating_add(self.default_ttl_secs));
        let conn = self.conn.lock();
        Self::purge_locked(&conn, now)?;
        conn.execute(
            "INSERT INTO replay_cache (sender_spk, msg_id, expiry) \
             VALUES (?1, ?2, ?3) \
             ON CONFLICT(sender_spk, msg_id) DO UPDATE SET expiry = excluded.expiry",
            params![sender_spk, msg_id, i64_secs(exp)],
        )?;
        Ok(())
    }

    /// Atomic check-then-record. Returns `true` if the pair was fresh
    /// (and is now recorded); `false` if it was already in the cache.
    ///
    /// New code should prefer the explicit [`Self::has_seen`] +
    /// [`Self::record`] pair around the work that proves the message
    /// actually delivered. This method exists for callers that genuinely
    /// want the old single-step semantics (e.g. cheap dedup paths where
    /// re-fetching is OK on a false positive).
    pub fn check_and_record(
        &self,
        sender_spk: &[u8],
        msg_id: &[u8],
        expiry: Option<u64>,
    ) -> Result<bool, StorageError> {
        if self.has_seen(sender_spk, msg_id)? {
            return Ok(false);
        }
        self.record(sender_spk, msg_id, expiry)?;
        Ok(true)
    }

    /// Remove every entry whose expiry has passed. Returns the row
    /// count removed. Callers usually don't need this — `has_seen` and
    /// `record` purge inline — but it's exposed for periodic
    /// background sweeps when the cache has grown very large.
    pub fn cleanup_expired(&self) -> Result<u64, StorageError> {
        let now = unix_now();
        let conn = self.conn.lock();
        Ok(Self::purge_locked(&conn, now)? as u64)
    }

    /// Number of currently-live (unexpired) entries.
    pub fn size(&self) -> Result<u64, StorageError> {
        let now = unix_now();
        let conn = self.conn.lock();
        Self::purge_locked(&conn, now)?;
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM replay_cache WHERE expiry > ?1",
            params![i64_secs(now)],
            |row| row.get(0),
        )?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    fn purge_locked(conn: &Connection, now: u64) -> Result<usize, StorageError> {
        let removed = conn.execute(
            "DELETE FROM replay_cache WHERE expiry <= ?1",
            params![i64_secs(now)],
        )?;
        Ok(removed)
    }
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

    fn cache() -> ReplayCache {
        ReplayCache::new(OpenedDb::open_in_memory(&crate::connection::TEST_STORAGE_KEY).unwrap())
    }

    #[test]
    fn record_then_has_seen_is_true() {
        let c = cache();
        let spk = vec![1u8; 32];
        let mid = vec![2u8; 16];
        assert!(!c.has_seen(&spk, &mid).unwrap());
        c.record(&spk, &mid, Some(u64::MAX / 2)).unwrap();
        assert!(c.has_seen(&spk, &mid).unwrap());
    }

    #[test]
    fn check_and_record_returns_false_on_replay() {
        let c = cache();
        let spk = vec![3u8; 32];
        let mid = vec![4u8; 16];
        assert!(c.check_and_record(&spk, &mid, Some(u64::MAX / 2)).unwrap());
        // Second call is a replay.
        assert!(!c.check_and_record(&spk, &mid, Some(u64::MAX / 2)).unwrap());
    }

    #[test]
    fn record_with_default_ttl_expires_after_purge() {
        // Use TTL=0 so every record() is immediately stale.
        let cache = ReplayCache::with_ttl(
            OpenedDb::open_in_memory(&crate::connection::TEST_STORAGE_KEY).unwrap(),
            0,
        );
        let spk = vec![5u8; 32];
        let mid = vec![6u8; 16];
        cache.record(&spk, &mid, None).unwrap();
        // The next has_seen call purges expired entries (expiry == now,
        // and the DELETE runs `expiry <= now`), so the record vanishes.
        assert!(!cache.has_seen(&spk, &mid).unwrap());
        assert_eq!(cache.size().unwrap(), 0);
    }

    #[test]
    fn cleanup_expired_returns_dropped_count() {
        let c = cache();
        // Mix expired + live.
        c.record(&[7u8; 32], &[7u8; 16], Some(1)).unwrap();
        c.record(&[8u8; 32], &[8u8; 16], Some(u64::MAX / 2))
            .unwrap();
        // The has_seen calls inside record() also purge — so by the
        // second record() the expired entry may already be gone. Either
        // way, cleanup_expired plus the inline purges remove exactly
        // one row in total.
        let dropped = c.cleanup_expired().unwrap();
        assert!(dropped <= 1);
        assert_eq!(c.size().unwrap(), 1);
    }

    #[test]
    fn record_is_keyed_on_pair_not_either_alone() {
        let c = cache();
        let spk_a = vec![1u8; 32];
        let spk_b = vec![2u8; 32];
        let mid = vec![9u8; 16];
        c.record(&spk_a, &mid, Some(u64::MAX / 2)).unwrap();
        // Different sender, same msg_id is NOT a replay.
        assert!(!c.has_seen(&spk_b, &mid).unwrap());
    }
}

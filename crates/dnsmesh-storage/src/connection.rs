//! Sqlite file open + migration + PRAGMA setup.
//!
//! Every store in this crate ultimately runs against a connection
//! produced here. The default file lives at `~/.dmp/dmp-rs.sqlite` —
//! intentionally distinct from the Python client's `~/.dmp/dmp.sqlite`
//! so that running both clients on the same identity won't trip
//! sqlite's single-writer lock.
//!
//! [`OpenedDb::open`] applies all pending refinery migrations on every
//! open, so an in-place upgrade of this binary just works on the next
//! launch.

use std::path::{Path, PathBuf};

use rusqlite::Connection;

use crate::error::StorageError;
use crate::migrations;

/// Default sqlite file path: `$HOME/.dmp/dmp-rs.sqlite`.
///
/// Returns `None` if the home directory cannot be determined (no `HOME`
/// env var on Unix, etc.). Callers that want a specific path should
/// pass it directly to [`OpenedDb::open`].
#[must_use]
pub fn default_db_path() -> Option<PathBuf> {
    // std::env::home_dir is back-stable in 1.86; this crate's MSRV is
    // 1.85 so use the env var directly. Mirrors what `dirs::home_dir`
    // would return on Unix without pulling in another dep.
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".dmp").join("dmp-rs.sqlite"))
}

/// A migrated, PRAGMA-tuned sqlite connection.
///
/// Owned by exactly one store at a time — the crate's stores each take a
/// connection by value. To run multiple stores against the same db file
/// the high-level client opens multiple `OpenedDb`s; sqlite handles the
/// cross-connection locking under WAL.
pub struct OpenedDb {
    conn: Connection,
    path: Option<PathBuf>,
}

impl std::fmt::Debug for OpenedDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedDb")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl OpenedDb {
    /// Open `path`, create parent dirs as needed, apply migrations, set
    /// PRAGMAs.
    ///
    /// The file is created with default umask permissions; callers that
    /// need stricter perms (the recommendation is 0o600 on the file and
    /// 0o700 on its parent dir, matching the Python client) should
    /// chmod after this returns. We don't do it here because the typical
    /// in-process layout opens the file once at startup and re-uses the
    /// connection — the chmod cost belongs in the bootstrap layer.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut conn = Connection::open(&path)?;
        Self::tune_pragmas(&conn)?;
        migrations::runner().run(&mut conn)?;
        Ok(Self {
            conn,
            path: Some(path),
        })
    }

    /// Open an in-memory database. Tests and ephemeral worker tasks.
    pub fn open_in_memory() -> Result<Self, StorageError> {
        let mut conn = Connection::open_in_memory()?;
        Self::tune_pragmas(&conn)?;
        migrations::runner().run(&mut conn)?;
        Ok(Self { conn, path: None })
    }

    /// On-disk path of this database, or `None` for in-memory.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Consume the wrapper and yield the inner [`Connection`].
    ///
    /// Each store takes its connection this way, then wraps it in
    /// `parking_lot::Mutex<Connection>` for thread-safe access from
    /// the high-level client.
    #[must_use]
    pub fn into_connection(self) -> Connection {
        self.conn
    }

    /// Borrow the underlying connection (rare; for ad-hoc queries in
    /// tests). Stores should call [`Self::into_connection`].
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    fn tune_pragmas(conn: &Connection) -> Result<(), StorageError> {
        // WAL: non-blocking reads against writers. Matches the Python
        // setup. Skipped silently for in-memory dbs (sqlite ignores it
        // there, but the pragma_query call still works).
        // synchronous=NORMAL: durability tradeoff matching the Python
        // client. FULL would survive an OS crash mid-COMMIT but at a
        // throughput cost we don't need for the local key store.
        // foreign_keys=ON for future migrations that use FKs.
        // busy_timeout=5000: WAL removes reader-vs-writer contention but
        // not writer-vs-writer. With one connection per store in the
        // client (prekeys + intros + replay + contacts all writing
        // independently) plus refresh_prekeys batches, default 0ms
        // returns SQLITE_BUSY on the first conflict. 5s is generous;
        // realistic contention windows are sub-millisecond.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_open_runs_all_migrations() {
        let db = OpenedDb::open_in_memory().expect("open in-memory db");
        // V2 added consumed_at to prekeys; if the migration ran the
        // column exists. If it didn't, the query errors out.
        let exists: i64 = db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('prekeys') WHERE name = 'consumed_at'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1, "V2 must add consumed_at column");
    }

    #[test]
    fn file_open_creates_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b").join("dmp-rs.sqlite");
        let _db = OpenedDb::open(&nested).expect("open creates parents");
        assert!(nested.exists(), "db file should exist after open");
    }

    #[test]
    fn reopening_the_same_file_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dmp-rs.sqlite");
        {
            let _db = OpenedDb::open(&path).unwrap();
        }
        // Second open re-runs migrations (refinery is no-op on already
        // applied versions) and must succeed.
        let _db = OpenedDb::open(&path).unwrap();
    }
}

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

use dnsmesh_core::crypto::STORAGE_KEY_LEN;
use rusqlite::Connection;
use zeroize::Zeroizing;

use crate::error::StorageError;
use crate::migrations;

/// Apply the SQLCipher key to a freshly-opened connection.
///
/// Uses the raw-key form (`x'<64 hex chars>'`), which hands SQLCipher the
/// 32 bytes directly instead of running its own PBKDF2 over them. The key
/// we get is already an HKDF output over an Argon2id-derived seed, so a
/// second password-stretching pass would cost latency on every open —
/// there are four connections per client — and buy nothing.
///
/// Must run before any other statement on the connection, including the
/// PRAGMA tuning and the migration runner.
fn apply_key(conn: &Connection, key: &[u8]) -> Result<(), StorageError> {
    if key.len() != STORAGE_KEY_LEN {
        return Err(StorageError::InvalidStorageKeyLength {
            expected: STORAGE_KEY_LEN,
            actual: key.len(),
        });
    }
    // The pragma string embeds the key, so keep it in a wrapper that wipes
    // on drop rather than leaving it in a stray String allocation.
    let pragma = Zeroizing::new(format!("x'{}'", hex::encode(key)));
    conn.pragma_update(None, "key", pragma.as_str())?;
    Ok(())
}

/// Force SQLCipher to actually verify the key.
///
/// `PRAGMA key` itself never fails — SQLCipher defers validation until the
/// first page read. Touching `sqlite_master` is the standard way to make a
/// bad key surface immediately instead of at some arbitrary later query.
fn probe_readable(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    })
    .map(|_| ())
}

/// Decide which error a failed keyed open deserves.
///
/// SQLCipher answers "file is not a database" for both a wrong key and an
/// unencrypted file, but those want opposite handling. Re-opening without a
/// key separates them: if the file reads fine unkeyed, it is a plaintext
/// database from an older build.
fn classify_open_failure(path: &Path, keyed_err: rusqlite::Error) -> StorageError {
    if let Ok(plain) = Connection::open(path) {
        if probe_readable(&plain).is_ok() {
            return StorageError::LegacyPlaintextDatabase {
                path: path.display().to_string(),
            };
        }
    }
    StorageError::Sqlite(keyed_err)
}

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
    /// Open `path` under SQLCipher with `key`, create parent dirs as
    /// needed, apply migrations, set PRAGMAs.
    ///
    /// `key` must be [`STORAGE_KEY_LEN`] bytes — in practice
    /// `DmpCrypto::derive_storage_key()`. A fresh file is encrypted from
    /// its first write, so the schema the migrations create is already
    /// keyed.
    ///
    /// Returns [`StorageError::LegacyPlaintextDatabase`] when `path` holds
    /// an unencrypted database from a build that predates at-rest
    /// encryption. There is no in-place upgrade: the caller should surface
    /// that as "re-create this identity", not as a passphrase problem.
    ///
    /// The file is created with default umask permissions; callers that
    /// need stricter perms (the recommendation is 0o600 on the file and
    /// 0o700 on its parent dir, matching the Python client) should
    /// chmod after this returns. We don't do it here because the typical
    /// in-process layout opens the file once at startup and re-uses the
    /// connection — the chmod cost belongs in the bootstrap layer.
    pub fn open<P: AsRef<Path>>(path: P, key: &[u8]) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut conn = Connection::open(&path)?;
        apply_key(&conn, key)?;
        // Validate the key before the migration runner touches anything —
        // refinery's own failure on an unreadable file is far less legible
        // than the classification below.
        if let Err(e) = probe_readable(&conn) {
            return Err(classify_open_failure(&path, e));
        }
        Self::tune_pragmas(&conn)?;
        migrations::runner().run(&mut conn)?;
        Ok(Self {
            conn,
            path: Some(path),
        })
    }

    /// Open an in-memory database. Tests and ephemeral worker tasks.
    ///
    /// Keyed for API symmetry with [`Self::open`] — an in-memory database
    /// never reaches disk, so encryption is moot, but taking the same
    /// argument keeps callers from having two shapes to thread through.
    pub fn open_in_memory(key: &[u8]) -> Result<Self, StorageError> {
        let mut conn = Connection::open_in_memory()?;
        apply_key(&conn, key)?;
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

/// Fixed storage key for tests. Real callers derive theirs from the
/// identity passphrase; tests only need something 32 bytes and stable.
#[cfg(test)]
pub(crate) const TEST_STORAGE_KEY: [u8; STORAGE_KEY_LEN] = [0x2a; STORAGE_KEY_LEN];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_open_runs_all_migrations() {
        let db = OpenedDb::open_in_memory(&TEST_STORAGE_KEY).expect("open in-memory db");
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
        let _db = OpenedDb::open(&nested, &TEST_STORAGE_KEY).expect("open creates parents");
        assert!(nested.exists(), "db file should exist after open");
    }

    /// The whole point: a caller with filesystem access but not the key
    /// must not be able to read row data out of the file.
    #[test]
    fn on_disk_file_does_not_leak_row_contents() {
        const CANARY: &[u8] = b"canary-payload-do-not-leak";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dmp-rs.sqlite");
        {
            let db = OpenedDb::open(&path, &TEST_STORAGE_KEY).unwrap();
            db.connection()
                .execute_batch(
                    "CREATE TABLE leak_probe (x BLOB); \
                     INSERT INTO leak_probe VALUES (x'63616e6172792d7061796c6f61642d646f2d6e6f742d6c65616b');",
                )
                .unwrap();
        }
        let raw = std::fs::read(&path).unwrap();
        assert!(
            !raw.windows(CANARY.len()).any(|w| w == CANARY),
            "row contents found in plaintext on disk",
        );
    }

    /// A wrong key must not silently open the database.
    #[test]
    fn wrong_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dmp-rs.sqlite");
        {
            let _db = OpenedDb::open(&path, &TEST_STORAGE_KEY).unwrap();
        }
        let wrong = [0x99u8; STORAGE_KEY_LEN];
        assert!(OpenedDb::open(&path, &wrong).is_err());
    }

    /// An unencrypted database from a pre-encryption build must be
    /// identified as such, not reported as a wrong key — the two need
    /// opposite responses and SQLCipher gives the same message for both.
    #[test]
    fn legacy_plaintext_database_is_classified_distinctly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dmp-rs.sqlite");
        // Build a plaintext db the way an older build would have: open with
        // no key at all, so SQLCipher leaves it unencrypted.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("CREATE TABLE t (x TEXT); INSERT INTO t VALUES ('legacy');")
                .unwrap();
        }
        match OpenedDb::open(&path, &TEST_STORAGE_KEY) {
            Err(StorageError::LegacyPlaintextDatabase { path: reported }) => {
                assert!(reported.contains("dmp-rs.sqlite"), "got {reported}");
            }
            other => panic!("expected LegacyPlaintextDatabase, got {other:?}"),
        }
    }

    /// Guards the length check — a truncated key must be refused up front
    /// rather than silently stretched or padded by SQLCipher.
    #[test]
    fn short_key_is_refused() {
        assert!(matches!(
            OpenedDb::open_in_memory(&[0x2a; 16]),
            Err(StorageError::InvalidStorageKeyLength {
                expected: STORAGE_KEY_LEN,
                actual: 16
            }),
        ));
    }

    #[test]
    fn reopening_the_same_file_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dmp-rs.sqlite");
        {
            let _db = OpenedDb::open(&path, &TEST_STORAGE_KEY).unwrap();
        }
        // Second open re-runs migrations (refinery is no-op on already
        // applied versions) and must succeed.
        let _db = OpenedDb::open(&path, &TEST_STORAGE_KEY).unwrap();
    }
}

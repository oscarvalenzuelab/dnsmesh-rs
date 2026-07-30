//! Shared error type for the DMP storage crate.

/// Errors returned by every store in this crate.
///
/// Wraps [`rusqlite::Error`] for direct sqlite failures and refinery's
/// migration error for schema-version mismatches caught at open time.
/// Callers in the high-level client should generally treat anything but
/// the explicit "not found" / domain enums as fatal — sqlite errors at
/// runtime usually mean the file was corrupted or the disk filled up.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// A sqlite operation failed (constraint violation, I/O, syntax).
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Refinery rejected a migration on open. Usually means the on-disk
    /// schema is from a newer build than this binary knows about.
    #[error("schema migration: {0}")]
    Migration(#[from] refinery::Error),
    /// Filesystem prep around the db file (parent dir creation, perms).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Allocating a fresh prekey_id collided with an existing row 16 times
    /// in a row. Statistically impossible against a 32-bit space unless
    /// the table is already nearly full; surface it instead of looping
    /// forever.
    #[error("could not allocate unique prekey_id after {tries} attempts")]
    PrekeyIdExhausted { tries: u32 },
    /// A blob column had the wrong length to round-trip into a fixed-size
    /// Rust array (e.g. an X25519 private key column not 32 bytes long).
    /// Indicates the file was hand-edited or written by a different
    /// schema; never raised on a db this crate created itself.
    #[error("corrupt {field}: expected {expected} bytes, got {actual}")]
    CorruptBlobLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    /// The storage key was not the expected length.
    #[error("storage key must be {expected} bytes, got {actual}")]
    InvalidStorageKeyLength { expected: usize, actual: usize },
    /// The file on disk is an *unencrypted* database from a build that
    /// predates at-rest encryption.
    ///
    /// Distinguished from a wrong key deliberately: SQLCipher reports both
    /// as "file is not a database", but they need opposite responses. This
    /// one is not recoverable by supplying different input — there is no
    /// in-place upgrade path, so the caller should tell the user to
    /// re-create the identity rather than re-prompt for a passphrase.
    #[error(
        "database at {path} is unencrypted (created before at-rest encryption); \
         it cannot be upgraded in place"
    )]
    LegacyPlaintextDatabase { path: String },
}

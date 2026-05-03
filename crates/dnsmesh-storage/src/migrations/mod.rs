//! Embedded sqlite migrations driven by `refinery`.
//!
//! Versioning lives in the filenames inside `migrations/` (`V1__*.sql`,
//! `V2__*.sql`, ...) and is interpreted by `refinery::embed_migrations!`.
//! Each migration is applied exactly once per database file; refinery
//! tracks state in its own `refinery_schema_history` table.
//!
//! Schema changes happen here. The store modules call
//! [`runner`] from [`crate::connection::OpenedDb::open`] to bring a
//! freshly-opened db file up to the current schema version.

refinery::embed_migrations!("src/migrations");

pub use migrations::runner;

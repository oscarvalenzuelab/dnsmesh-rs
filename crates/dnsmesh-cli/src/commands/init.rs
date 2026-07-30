//! `dnsmesh init <username> --domain <DOMAIN>`.
//!
//! Creates the config-home (default `$HOME/.dmp/`), prompts for the
//! passphrase, writes a fresh `config.yaml`, and opens the sqlite db
//! once so the migration runs and the user discovers any I/O errors
//! immediately rather than on the first send.

use std::path::Path;

use anyhow::{anyhow, Context, Result};

use crate::cli::InitArgs;
use crate::client_factory::{build_client, PassphraseSource};
use crate::config::ConfigFile;

pub async fn run(
    args: InitArgs,
    config_override: Option<&Path>,
    passphrase_env: Option<&str>,
) -> Result<()> {
    if args.username.trim().is_empty() {
        return Err(anyhow!("username must not be empty"));
    }
    if args.domain.trim().is_empty() {
        return Err(anyhow!("--domain must not be empty"));
    }

    let path = match config_override {
        Some(p) => p.to_path_buf(),
        None => ConfigFile::default_path()?,
    };

    if path.exists() {
        return Err(anyhow!(
            "config already exists at {} — refusing to overwrite. \
             Move it aside or pass --config to point elsewhere.",
            path.display()
        ));
    }

    // Generate a per-identity Argon2id salt at init time. Without
    // this, the default sentinel salt (`DEFAULT_ARGON2_SALT` in
    // dnsmesh-core) is used and any two users with the same
    // passphrase derive the same identity — matches Python's
    // `cli init` behavior. Persisted as hex into config.yaml so the
    // identity is stable across `dnsmesh tsig register` and any
    // subsequent re-derivation.
    let mut salt = [0u8; 32];
    getrandom::getrandom(&mut salt).context("generating identity kdf_salt")?;
    let kdf_salt_hex = hex::encode(salt);

    let config = ConfigFile {
        username: args.username,
        domain: args.domain,
        db_path: None,
        resolvers: None,
        publish: None,
        cloudflare: None,
        kdf_salt: Some(kdf_salt_hex),
    };

    // Build the client first against an in-memory resolved view so a
    // failure (passphrase mismatch on retype, sqlite write error, etc.)
    // doesn't leave a half-baked config.yaml on disk that the next
    // `init` would refuse to overwrite. We materialize the file only
    // after the client opens cleanly.
    let resolved_preview = config.clone().with_resolved_paths(&path)?;

    // The database is encrypted under a key derived from the salt above,
    // which only becomes durable when config.yaml is written. Building the
    // client creates that file, so any failure between here and the save
    // leaves an encrypted database whose key is gone: the next `init`
    // would mint a different salt, fail to open the leftover, and report
    // an opaque "file is not a database" until someone deleted it by hand.
    //
    // Track whether the db pre-existed so cleanup only ever removes a file
    // this run created — an unrelated database next to a missing config is
    // an odd state, but not ours to delete.
    let db_existed_before = resolved_preview.db_path.exists();
    let discard_partial_db = || discard_partial_db(&resolved_preview.db_path, db_existed_before);

    let source = PassphraseSource::from_cli(passphrase_env);
    let built = match build_client(&resolved_preview, source).await {
        Ok(built) => built,
        Err(e) => {
            discard_partial_db();
            return Err(e);
        }
    };

    // Release the sqlite handles before any cleanup below can touch the
    // file, and before re-reading the config.
    drop(built);

    if let Err(e) = config.save(&path) {
        discard_partial_db();
        return Err(e);
    }
    let resolved = ConfigFile::load(Some(&path)).context("re-reading freshly-written config")?;

    println!(
        "initialized identity for {}@{}",
        resolved.username, resolved.domain
    );
    println!("  config: {}", resolved.config_path.display());
    println!("  db:     {}", resolved.db_path.display());
    println!(
        "  next:   `dnsmesh identity show` to view your pubkeys, then \
         `dnsmesh identity publish` once a `publish:` block is configured"
    );
    Ok(())
}

/// Remove an encrypted database this `init` run created, along with its WAL
/// sidecars.
///
/// No-op when `existed_before` is set. The database is keyed by the salt in
/// `config.yaml`; if that never becomes durable the file is unopenable
/// forever, so leaving it behind means the next `init` mints a different
/// salt and dies on an opaque "file is not a database". But a database that
/// predates this run is not ours to delete, however odd it looks sitting
/// next to a missing config.
fn discard_partial_db(db_path: &Path, existed_before: bool) {
    if existed_before {
        return;
    }
    for suffix in ["", "-wal", "-shm"] {
        let mut p = db_path.to_path_buf().into_os_string();
        p.push(suffix);
        let _ = std::fs::remove_file(std::path::PathBuf::from(p));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(p: &Path) {
        std::fs::write(p, b"x").unwrap();
    }

    /// A database created by this run is removed along with its sidecars,
    /// so the next `init` starts clean rather than tripping over a file
    /// whose key no longer exists anywhere.
    #[test]
    fn discards_db_and_sidecars_when_run_created_them() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("dmp-rs.sqlite");
        let wal = dir.path().join("dmp-rs.sqlite-wal");
        let shm = dir.path().join("dmp-rs.sqlite-shm");
        touch(&db);
        touch(&wal);
        touch(&shm);

        discard_partial_db(&db, false);

        assert!(!db.exists(), "db should be removed");
        assert!(!wal.exists(), "wal sidecar should be removed");
        assert!(!shm.exists(), "shm sidecar should be removed");
    }

    /// The guard that matters: never delete a database that was already
    /// there when this run started.
    #[test]
    fn leaves_a_preexisting_db_alone() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("dmp-rs.sqlite");
        touch(&db);

        discard_partial_db(&db, true);

        assert!(db.exists(), "a pre-existing db must never be deleted");
    }

    /// Cleanup runs on failure paths, so it has to tolerate the db never
    /// having been created at all.
    #[test]
    fn missing_db_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        discard_partial_db(&dir.path().join("absent.sqlite"), false);
    }
}

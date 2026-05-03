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
    let source = PassphraseSource::from_cli(passphrase_env);
    let _built = build_client(&resolved_preview, source).await?;

    config.save(&path)?;
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

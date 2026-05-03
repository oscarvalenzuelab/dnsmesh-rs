//! `dnsmesh purge` — wipe an identity's local state, optionally
//! sweeping DNS UPDATE deletes against every record it published.
//!
//! When the user wants to fully decommission an identity, the prior
//! "rm ~/.dmp" + 24h TTL wait was the only path. This subcommand:
//!
//!   1. With `--remote` — runs the SDK-level `unpublish_identity`
//!      sweep first so all the published records start expiring
//!      immediately at TTL=0 (or, more precisely, get DELETE'd at
//!      the authoritative server and propagate out via cache poison
//!      / TTL).
//!   2. Wipes the on-disk state under `<config_home>`:
//!      - `config.yaml` — the YAML config
//!      - `dmp-rs.sqlite` — keyring + contacts + prekeys + intros + replay
//!      - `tsig-*.key` — saved TSIG secrets
//!      - `tokens/<host>.json` — saved bearer tokens from `register`
//!
//! Local-only purge (no `--remote`) is a quick reset; the published
//! records keep resolving until DNS TTLs expire (24h default). Add
//! `--remote` to actually clean up DNS too.

use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};

use crate::cli::PurgeArgs;
use crate::client_factory::{build_client, PassphraseSource};
use crate::config::ConfigFile;

pub async fn run(
    args: PurgeArgs,
    config_override: Option<&Path>,
    passphrase_env: Option<&str>,
) -> Result<()> {
    // Resolve the config-home from the override or the default
    // location. We do this BEFORE building the client so that even
    // local-only purge (no --remote) can run without prompting for a
    // passphrase — the local wipe doesn't need crypto.
    let config_path = match config_override {
        Some(p) => p.to_path_buf(),
        None => ConfigFile::default_path()?,
    };
    let config_home = config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| anyhow!("config path {} has no parent", config_path.display()))?
        .to_path_buf();

    // Refuse to purge a path that doesn't look like a dnsmesh home
    // (no config.yaml). Operators sometimes mis-target this kind of
    // command; a missing config.yaml is the canary that says "you're
    // pointing at the wrong directory."
    if !config_path.exists() {
        bail!(
            "no config at {} — refusing to purge a directory that doesn't look \
             like a dnsmesh home. Pass --config <path/to/config.yaml> if your \
             config lives outside ~/.dmp.",
            config_path.display()
        );
    }

    // Confirm before doing anything irreversible.
    confirm(&config_path, args.remote, args.yes)?;

    if args.remote {
        // 1. DNS UPDATE deletes. Build the client (needs passphrase
        //    to derive identity) and call the SDK-level unpublish.
        //
        // If the remote sweep can't delete records (TSIG scope
        // rejected, network unreachable, partial deletes), proceeding
        // to wipe the local credentials leaves DNS records live with
        // no way to retry — the operator just lost the keys + tokens
        // needed to authenticate UPDATE deletes. So when any
        // record-delete reports failure we abort the local wipe by
        // default and give the operator a recovery path.
        // `--force-local-after-remote-failure` is the explicit
        // override for the rare case where the operator wants the
        // local wipe regardless.
        let cfg = ConfigFile::load(Some(&config_path))?;
        if cfg.publish.is_none() && cfg.cloudflare.is_none() {
            eprintln!(
                "purge --remote: no publish destination in config; skipping the DNS \
                 sweep (would have nothing to authenticate UPDATE deletes against). \
                 Local wipe still runs."
            );
        } else {
            let source = PassphraseSource::from_cli(passphrase_env);
            let built = build_client(&cfg, source).await?;
            // Heuristic: writer is "functional" if at least ONE
            // delete succeeded. The unpublish sweep walks 13 names
            // (identity + prekey + 10 slots + rotate), most of
            // which are normally empty for an active user — the
            // delete returns false for empty names, which would
            // make a strict "any failure → abort" rule trigger on
            // every purge. So we abort only when the entire sweep
            // returned zero successes (network down, TSIG fully
            // rejected, etc.) — that's when the operator genuinely
            // hasn't deleted anything and shouldn't lose their
            // credentials.
            let remote_clean = match built.client.unpublish_identity().await {
                Ok(report) => {
                    let succeeded = report.deletes.iter().filter(|(_, ok)| *ok).count();
                    let total = report.deletes.len();
                    println!("purge --remote: DNS sweep deleted {succeeded}/{total} records");
                    if succeeded == 0 {
                        eprintln!(
                            "purge --remote: zero deletes succeeded — the writer probably \
                             rejected the requests (TSIG scope mismatch, transport down, \
                             etc.). None of your published records were swept."
                        );
                        false
                    } else {
                        true
                    }
                }
                Err(e) => {
                    eprintln!("purge --remote: DNS sweep returned an error: {e}");
                    false
                }
            };
            if !remote_clean && !args.force_local_after_remote_failure {
                bail!(
                    "purge --remote: aborting local wipe because the DNS sweep didn't \
                     succeed. Without local credentials you can't retry the deletes; the \
                     records would TTL out (24h default) on their own. Re-run with \
                     `--force-local-after-remote-failure` to wipe local state anyway, \
                     accepting that the records stay live until TTL expiry."
                );
            }
        }
    }

    // 2. Local wipe. Walk every file we know we wrote into
    //    <config_home> and remove it. Anything we didn't write
    //    (random user files in ~/.dmp/) is left alone — we
    //    deliberately don't `rm -rf <config_home>/` because the
    //    user may have other state there.
    let removed = wipe_local(&config_home)?;
    println!(
        "purge: removed {} local file(s) from {}",
        removed.len(),
        config_home.display()
    );
    for p in &removed {
        println!("  - {}", p.display());
    }
    if !args.remote {
        eprintln!(
            "Note: published records (identity, prekeys, mailbox slots) keep resolving \
             until DNS TTLs expire (24h default). Re-run with --remote to issue DELETE's \
             against them, or wait it out."
        );
    }
    Ok(())
}

fn confirm(config_path: &Path, remote: bool, yes: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        bail!(
            "non-interactive purge requires --yes. This nukes the local config and \
             keystore at {}; with --remote it also DELETE's every record this identity \
             published. Re-run with --yes to confirm intent.",
            config_path.display()
        );
    }
    let scope = if remote {
        "wipe local state AND DNS UPDATE delete every published record"
    } else {
        "wipe local state (DNS records will TTL out on their own)"
    };
    eprint!(
        "Purge {}: {scope}? This is permanent. [y/N] ",
        config_path.display()
    );
    let _ = std::io::stderr().flush();
    let mut buf = String::new();
    std::io::stdin()
        .read_line(&mut buf)
        .context("reading purge confirmation from stdin")?;
    if !matches!(buf.trim(), "y" | "Y" | "yes" | "YES" | "Yes") {
        bail!("purge aborted by user");
    }
    Ok(())
}

/// Remove dnsmesh-owned files under `home`. Returns the list of paths
/// actually removed (used for the operator-facing report).
fn wipe_local(home: &Path) -> Result<Vec<PathBuf>> {
    let mut removed: Vec<PathBuf> = Vec::new();

    // Files we always own:
    let canonical = ["config.yaml", "dmp-rs.sqlite"];
    for name in canonical {
        let path = home.join(name);
        if path.exists() {
            std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
            removed.push(path);
        }
    }

    // tsig-<host>.key files — emitted by `dnsmesh tsig register`.
    if let Ok(entries) = std::fs::read_dir(home) {
        for entry in entries.flatten() {
            let p = entry.path();
            let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if name.starts_with("tsig-")
                && Path::new(name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("key"))
            {
                if let Err(e) = std::fs::remove_file(&p) {
                    tracing::warn!("could not remove {}: {e}", p.display());
                    continue;
                }
                removed.push(p);
            }
        }
    }

    // tokens/<host>.json — emitted by `dnsmesh register`. Remove the
    // whole directory if it exists; we own it.
    let tokens_dir = home.join("tokens");
    if tokens_dir.is_dir() {
        // Track each removed token file individually so the report is
        // useful, then remove the empty parent.
        if let Ok(entries) = std::fs::read_dir(&tokens_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if let Err(e) = std::fs::remove_file(&p) {
                    tracing::warn!("could not remove {}: {e}", p.display());
                    continue;
                }
                removed.push(p);
            }
        }
        // Best-effort: the tokens dir might have stuff we don't
        // recognize. If it's empty, drop it; otherwise leave it.
        let _ = std::fs::remove_dir(&tokens_dir);
    }

    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn wipe_local_removes_canonical_files_only() {
        let dir = TempDir::new().unwrap();
        let home = dir.path();
        // Stage every file we expect to clean up.
        fs::write(home.join("config.yaml"), "username: alice\n").unwrap();
        fs::write(home.join("dmp-rs.sqlite"), b"\x00").unwrap();
        fs::write(home.join("tsig-dnsmesh.io.key"), "hex:abcd\n").unwrap();
        fs::write(home.join("tsig-other.example.key"), "hex:1234\n").unwrap();
        fs::create_dir_all(home.join("tokens")).unwrap();
        fs::write(home.join("tokens/dnsmesh.io.json"), "{}").unwrap();
        // Plus a file we must NOT touch — operator's notes, say.
        fs::write(home.join("operator-notes.txt"), "this stays").unwrap();

        let removed = wipe_local(home).unwrap();

        assert_eq!(removed.len(), 5, "expected 5 removals; got {removed:?}");
        // Canonical files gone:
        assert!(!home.join("config.yaml").exists());
        assert!(!home.join("dmp-rs.sqlite").exists());
        assert!(!home.join("tsig-dnsmesh.io.key").exists());
        assert!(!home.join("tsig-other.example.key").exists());
        assert!(!home.join("tokens/dnsmesh.io.json").exists());
        assert!(
            !home.join("tokens").exists(),
            "empty tokens dir should be cleaned up"
        );
        // Operator file untouched:
        assert!(home.join("operator-notes.txt").exists());
    }

    #[test]
    fn wipe_local_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let home = dir.path();
        // No files staged. wipe_local should report zero removals.
        let removed = wipe_local(home).unwrap();
        assert!(removed.is_empty());
    }
}

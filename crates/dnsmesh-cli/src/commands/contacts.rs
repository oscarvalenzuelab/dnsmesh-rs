//! `dnsmesh contacts {add,list}`.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use dnsmesh_client::Contact;
use dnsmesh_core::identity::parse_address;

use crate::cli::ContactsCmd;
use crate::client_factory::{build_client, maybe_flush, PassphraseSource};
use crate::config::ConfigFile;

pub async fn run(
    cmd: ContactsCmd,
    config_override: Option<&Path>,
    passphrase_env: Option<&str>,
) -> Result<()> {
    let cfg = ConfigFile::load(config_override)?;
    let source = PassphraseSource::from_cli(passphrase_env);
    let built = build_client(&cfg, source).await?;
    let client = &built.client;

    match cmd {
        ContactsCmd::Add {
            address,
            x25519,
            ed25519,
        } => {
            let (username, host) = parse_address(&address)
                .ok_or_else(|| anyhow!("invalid address `{address}`: expected `user@host`"))?;
            // Clap's `requires` cross-link guarantees both flags arrive
            // together or neither does; the `match` here documents the
            // two real call modes (manual keys vs DNS resolve).
            let contact = match (x25519, ed25519) {
                (Some(x), Some(e)) => Contact {
                    username: username.clone(),
                    x25519_pk: parse_hex32(&x, "x25519")?,
                    ed25519_spk: parse_hex32(&e, "ed25519")?,
                    domain: host.clone(),
                },
                (None, None) => client
                    .fetch_identity(&address)
                    .await
                    .with_context(|| format!("resolving {address} via DNS"))?,
                _ => unreachable!("clap `requires` couples x25519 + ed25519"),
            };
            let newly = client.add_contact(contact).await?;
            if newly {
                println!("pinned {username}@{host}");
            } else {
                println!("updated {username}@{host}");
            }
        }
        ContactsCmd::List => {
            let contacts = client.list_contacts().await?;
            if contacts.is_empty() {
                println!("(no pinned contacts)");
                maybe_flush(&built).await?;
                return Ok(());
            }
            // Header. We lean on plain spaces rather than a borrowed
            // table-rendering crate — this is short, scannable, and
            // sidesteps the dep budget constraint from the plan.
            //
            // first_seen_ts lives on the storage row but the high-level
            // client Contact doesn't surface it; M4 prints just the
            // identity columns and leaves enrichment to M5+.
            println!("{:<20} {:<28} ED25519 (first 16)", "USERNAME", "DOMAIN");
            for c in contacts {
                let spk = hex::encode(c.ed25519_spk);
                let short = &spk[..spk.len().min(16)];
                let domain = if c.domain.is_empty() {
                    "(local)".to_string()
                } else {
                    c.domain.clone()
                };
                println!(
                    "{:<20} {:<28} {}",
                    truncate(&c.username, 20),
                    truncate(&domain, 28),
                    short,
                );
            }
        }
    }
    maybe_flush(&built).await?;
    Ok(())
}

fn parse_hex32(s: &str, label: &str) -> Result<[u8; 32]> {
    let bytes =
        hex::decode(s).with_context(|| format!("invalid {label} hex: must be 64 hex chars"))?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "{label} pubkey must be 32 bytes (64 hex chars); got {} bytes",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut out = s[..max.saturating_sub(1)].to_string();
        out.push('…');
        out
    }
}

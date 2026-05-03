//! `dnsmesh intro {list,accept,trust,block}`.
//!
//! Mirrors the `cmd_intro_*` family in `dmp/cli.py`. The actual queue
//! lives behind [`dnsmesh_client::DmpClient`] — this module just
//! formats output, parses CLI args, and routes to the client.

use std::path::Path;

use anyhow::Result;

use crate::cli::IntroCmd;
use crate::client_factory::{build_client, maybe_flush, PassphraseSource};
use crate::config::ConfigFile;

pub async fn run(
    cmd: IntroCmd,
    config_override: Option<&Path>,
    passphrase_env: Option<&str>,
) -> Result<()> {
    let cfg = ConfigFile::load(config_override)?;
    let source = PassphraseSource::from_cli(passphrase_env);
    let built = build_client(&cfg, source).await?;
    let client = &built.client;

    match cmd {
        IntroCmd::List => {
            let pending = client.list_intros().await?;
            if pending.is_empty() {
                println!("(no pending intros)");
                return Ok(());
            }
            // Plain-text columns. Same shape as `contacts list` so the
            // two outputs scan together.
            println!(
                "{:<6} {:<20} {:<22} {:<10} BYTES",
                "ID", "SENDER (ed25519/8)", "RECEIVED", "EXPIRES",
            );
            for intro in pending {
                let spk = hex::encode(&intro.sender_spk);
                let short = &spk[..spk.len().min(16)];
                let received = format_unix(intro.received_at);
                let expires = format_unix(intro.expires_at);
                println!(
                    "{:<6} {:<20} {:<22} {:<10} {}",
                    intro.intro_id,
                    short,
                    received,
                    expires,
                    intro.payload.len(),
                );
            }
        }
        IntroCmd::Accept { intro_id } => {
            let Some(delivered) = client.accept_intro(intro_id).await? else {
                anyhow::bail!("no intro with id {intro_id}");
            };
            // For interactive review the user wants the actual content,
            // not just a confirmation. Print as UTF-8 if it parses and
            // hex otherwise — keeps the non-text payload case sane.
            print_payload(&delivered.message.plaintext);
            eprintln!(
                "accepted intro {intro_id} (sender {})",
                hex::encode(delivered.message.sender_signing_pk),
            );
        }
        IntroCmd::Trust { intro_id, address } => {
            let Some(delivered) = client.trust_intro(intro_id, &address).await? else {
                anyhow::bail!("no intro with id {intro_id}");
            };
            print_payload(&delivered.message.plaintext);
            eprintln!("trusted intro {intro_id}: pinned {address}");
        }
        IntroCmd::Block { intro_id, note } => {
            let removed = client.block_intro(intro_id, &note).await?;
            if removed {
                println!("blocked intro {intro_id}");
            } else {
                println!("no intro with id {intro_id}");
            }
        }
    }
    maybe_flush(&built).await?;
    Ok(())
}

fn print_payload(bytes: &[u8]) {
    match std::str::from_utf8(bytes) {
        Ok(text) => println!("{text}"),
        Err(_) => println!("<binary, {} bytes>: {}", bytes.len(), hex::encode(bytes)),
    }
}

fn format_unix(ts: u64) -> String {
    if ts == 0 {
        return "—".to_string();
    }
    // Avoid pulling chrono into the CLI just for one line: print the
    // raw unix seconds. Operators can `date -r <ts>` if they want a
    // human form. Keeps the dep budget in line with the rest of M4.
    format!("{ts}")
}

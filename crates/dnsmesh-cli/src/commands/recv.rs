//! `dnsmesh recv` — poll mailbox slots, optionally deliver to a Maildir.
//!
//! Without `--maildir` the decrypted messages are emitted to stdout in
//! a human-readable format. With `--maildir` they're written into a
//! standard cur/new/tmp tree mutt can poll. `--watch` re-polls on
//! `--interval` seconds; `--once` (the default) does one pass and
//! exits, which is the right shape for cron and for `set
//! mail_check_recent` setups.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use dnsmesh_client::{DmpClient, InboxMessage};
use tokio::time::sleep;

use crate::cli::RecvArgs;
use crate::client_factory::{build_client, maybe_flush, PassphraseSource};
use crate::config::ConfigFile;
use crate::mua::maildir as maildir_writer;

pub async fn run(
    args: RecvArgs,
    config_override: Option<&Path>,
    passphrase_env: Option<&str>,
) -> Result<()> {
    let cfg = ConfigFile::load(config_override)?;
    let source = PassphraseSource::from_cli(passphrase_env);
    let built = build_client(&cfg, source).await?;
    let client = &built.client;

    if args.watch {
        let interval = Duration::from_secs(args.interval.max(1));
        loop {
            poll_once(client, args.maildir.as_deref(), &args.claim_via).await?;
            // Flush each pass so an external observer (a watching test,
            // mutt's poll loop) sees the prekey-consume deletes that
            // receive performs. The watch loop never returns from this
            // function, so the after-loop flush below would never fire.
            maybe_flush(&built).await?;
            sleep(interval).await;
        }
    } else {
        poll_once(client, args.maildir.as_deref(), &args.claim_via).await?;
    }
    maybe_flush(&built).await?;
    Ok(())
}

async fn poll_once(
    client: &DmpClient,
    maildir_root: Option<&Path>,
    claim_via: &[String],
) -> Result<()> {
    let mut inbox = client
        .receive_messages()
        .await
        .context("polling mailbox slots")?;
    // Each `--claim-via` provider zone gets its own sweep through the
    // claim path. Replay-cache + intro-queue routing are shared, so
    // double-discovery (one zone publishes for the same message twice,
    // or own-zone walk also picks it up) deduplicates cleanly.
    for zone in claim_via {
        let from_claims = client
            .receive_via_claim(zone)
            .await
            .with_context(|| format!("polling claim provider zone {zone}"))?;
        inbox.extend(from_claims);
    }
    if inbox.is_empty() {
        if maildir_root.is_none() {
            println!("(no new messages)");
        }
        return Ok(());
    }

    if let Some(root) = maildir_root {
        // Build an spk → "user@domain" map ONCE per poll so the
        // Maildir writer can stamp the real address into From: for
        // pinned senders. Without this every delivered message had a
        // synthetic `dmp-<spk>@dmp.local` From: header — replies in
        // mutt would land at that nonexistent address. Looking up
        // per-message would issue N sqlite queries; one bulk fetch
        // is fine.
        let address_by_spk = build_spk_address_map(client).await?;
        for msg in &inbox {
            let resolved = address_by_spk
                .get(&msg.sender_signing_pk)
                .map(String::as_str);
            let id = maildir_writer::deliver(root, msg, resolved)
                .with_context(|| format!("delivering to {}", root.display()))?;
            println!(
                "delivered {} to {}/new/{}",
                short_id(msg),
                root.display(),
                id
            );
        }
    } else {
        for msg in &inbox {
            print_human(msg);
        }
    }
    Ok(())
}

/// Pull the contact store and produce an `spk → "user@domain"` map.
/// Runs once per poll iteration so every Maildir delivery in that
/// pass shares the same snapshot.
async fn build_spk_address_map(client: &DmpClient) -> Result<HashMap<[u8; 32], String>> {
    let contacts = client
        .list_contacts()
        .await
        .context("loading pinned contacts for sender-address resolution")?;
    let mut out = HashMap::with_capacity(contacts.len());
    for c in contacts {
        // Domain is empty for V1/V2 legacy rows; that case can't be
        // turned into a routable address, so skip — falls through to
        // the synthetic placeholder for that sender.
        if c.domain.is_empty() {
            continue;
        }
        out.insert(c.ed25519_spk, format!("{}@{}", c.username, c.domain));
    }
    Ok(out)
}

fn short_id(msg: &InboxMessage) -> String {
    let s = hex::encode(msg.msg_id);
    s[..s.len().min(12)].to_string()
}

fn print_human(msg: &InboxMessage) {
    let sender = hex::encode(msg.sender_signing_pk);
    let short_sender = &sender[..sender.len().min(16)];
    let msg_id = hex::encode(msg.msg_id);
    println!(
        "from {short_sender}…  msg_id={msg_id}  ts={}",
        msg.timestamp
    );
    match std::str::from_utf8(&msg.plaintext) {
        Ok(text) => println!("  {text}"),
        Err(_) => println!("  (binary, {} bytes)", msg.plaintext.len()),
    }
    println!();
}

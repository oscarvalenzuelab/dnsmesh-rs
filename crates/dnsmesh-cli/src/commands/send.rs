//! `dnsmesh send` — three input modes converging on `client.send_message`.
//!
//! 1. Default: `dnsmesh send <recipient>` reads body bytes from stdin.
//! 2. sendmail-compat: `dnsmesh send -t` reads RFC 5322 from stdin and
//!    pulls the To: header for the recipient.
//! 3. Scripting: `--recipient … --message …` flags for shell scripts.

use std::io::Read;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use dnsmesh_client::ClientError;
use dnsmesh_core::identity::parse_address;

use crate::cli::SendArgs;
use crate::client_factory::{build_client, maybe_flush, PassphraseSource};
use crate::config::{ConfigFile, ResolvedConfig};
use crate::mua::rfc5322;

pub async fn run(
    args: SendArgs,
    config_override: Option<&Path>,
    passphrase_env: Option<&str>,
) -> Result<()> {
    // Surface a hint when sendmail-compat flags carried information we don't
    // act on. We accept-and-ignore, but a quiet log helps a confused operator
    // understand what we did with `dnsmesh send -t -f alice@example.com`.
    if let Some(ref envelope) = args.envelope_from {
        tracing::debug!("sendmail-compat: ignoring -f/--from envelope sender {envelope:?}");
    }
    if !args.trailing.is_empty() {
        tracing::debug!(
            "sendmail-compat: ignoring trailing recipient args {:?} (in -t mode the To: header chooses)",
            args.trailing
        );
    }

    let cfg = ConfigFile::load(config_override)?;
    require_publish_in_config(&cfg)?;
    let source = PassphraseSource::from_cli(passphrase_env);
    let built = build_client(&cfg, source).await?;
    let client = &built.client;

    let (recipient_addr, body) = pick_inputs(&args)?;
    let recipient_username = resolve_recipient_username(&recipient_addr);

    // Cross-zone hint: when the recipient lives in a zone different
    // from ours AND the operator hasn't explicitly opted into the
    // claim-routing path with --claim-via, surface a stderr nudge. A
    // recipient who doesn't have us pinned will only walk their own
    // zone (+ pinned-contact zones) on receive — they'll never see
    // a manifest published in our zone. Suggesting --claim-via
    // <recipient_zone> moves the manifest into the receiver's zone
    // walk, which is the only way first-contact across zones works
    // without out-of-band pinning.
    //
    // We don't auto-add the claim — publishing to the recipient's
    // zone usually requires a TSIG key for THAT zone (which the
    // sender doesn't have unless the same node operator runs both
    // zones). The hint lets the operator decide.
    if args.claim_via.is_empty() {
        warn_cross_zone_first_contact(&recipient_addr, client.domain());
    }

    let send_result = if args.claim_via.is_empty() {
        client.send_message(&recipient_username, &body).await
    } else {
        // The client API takes &[&str]; flatten the owned Vec<String>
        // into refs without an extra allocation per element.
        let provider_refs: Vec<&str> = args.claim_via.iter().map(String::as_str).collect();
        client
            .send_message_with_claim(&recipient_username, &body, &provider_refs)
            .await
    };
    // Replying to a sender you accepted (but didn't trust) lands here.
    // The actionable fix is one command — surface it on stderr so the
    // operator doesn't have to dig through `identity fetch` + `contacts
    // add --x25519 ... --ed25519 ...`. The error itself still bails so
    // exit-code-driven scripts keep working.
    if let Err(ClientError::ContactNotFound { ref username }) = send_result {
        eprintln!(
            "note: contact `{username}` is not pinned. Run\n  \
             dnsmesh contacts add {recipient_addr}\n\
             to resolve and pin them via DNS, then retry."
        );
    }
    let msg_id = if args.claim_via.is_empty() {
        send_result.with_context(|| format!("sending to {recipient_addr}"))?
    } else {
        send_result.with_context(|| format!("sending to {recipient_addr} via claim"))?
    };
    println!("{}", hex::encode(msg_id));
    maybe_flush(&built).await?;
    Ok(())
}

/// Emit a one-line stderr hint when the recipient address parses to a
/// host different from `sender_domain`. A no-op when the recipient is
/// in the same zone (the common case — all manifests land where the
/// receiver already polls).
///
/// Suppressed when the address can't be parsed (the existing send
/// path falls back to "treat it as a bare username", and the
/// cross-zone question doesn't apply).
fn warn_cross_zone_first_contact(recipient_addr: &str, sender_domain: &str) {
    let Some((_, recipient_host)) = parse_address(recipient_addr) else {
        return;
    };
    let recipient_norm = recipient_host.trim_end_matches('.').to_ascii_lowercase();
    let sender_norm = sender_domain.trim_end_matches('.').to_ascii_lowercase();
    if recipient_norm == sender_norm {
        return;
    }
    eprintln!(
        "note: {recipient_addr} is in a different zone than this client \
         ({sender_norm}). For the recipient to find your message without \
         pinning you first, also publish a claim in their zone:\n  \
         dnsmesh send --claim-via {recipient_norm} {recipient_addr}\n\
         (skip this if you've already coordinated out-of-band — the \
         recipient running `dnsmesh identity fetch ...@{sender_norm} --add` \
         will let them walk your zone on the next recv.)"
    );
}

/// Pre-flight: bail out on missing `publish:` block BEFORE we prompt for the
/// passphrase or open the keystore. Saves an unnecessary prompt and matches
/// the principle of failing as early as the failure is decidable.
fn require_publish_in_config(cfg: &ResolvedConfig) -> Result<()> {
    // Test backdoor: when DMP_TEST_INMEMORY_STORE_FILE is set, the
    // CLI swaps in an in-memory store that accepts publishes — the
    // pre-flight check is therefore satisfied. See
    // client_factory.rs::TEST_STORE_ENV.
    if std::env::var_os("DMP_TEST_INMEMORY_STORE_FILE").is_some() {
        return Ok(());
    }
    if cfg.publish.is_none() && cfg.cloudflare.is_none() {
        anyhow::bail!(
            "no publish destination in config — `send` needs an authoritative DNS writer. \
             Add either a `publish:` block (TSIG / RFC 2136 against your own BIND/PowerDNS) \
             or a `cloudflare:` block (Cloudflare-hosted zone). See examples/ for templates."
        );
    }
    Ok(())
}

/// Decide which input mode the caller asked for and produce
/// (recipient_address, body_bytes).
fn pick_inputs(args: &SendArgs) -> Result<(String, Vec<u8>)> {
    if args.read_recipients {
        // sendmail's `-t` semantics (RFC + GNU/Postfix shape): scan
        // headers for recipients; positional addresses passed
        // alongside are ADDRESSES TO SUPPRESS, not deliveries to
        // perform. mutt / neomutt always pass the To: target as a
        // positional after `-t`, so we accept-and-ignore positional
        // addresses (the To: header drives recipient choice). Only
        // structured-flag overrides (`--recipient` / `--message`) are
        // a hard conflict with `-t`.
        if args.recipient_flag.is_some() || args.message.is_some() {
            return Err(anyhow!(
                "-t / --read-recipients reads the recipient and body from stdin; \
                 do not also pass --recipient or --message"
            ));
        }
        if args.recipient.is_some() || !args.trailing.is_empty() {
            tracing::debug!(
                "sendmail -t mode: ignoring positional address(es) {:?} {:?} \
                 (suppression-list semantics; To: header drives recipient choice)",
                args.recipient,
                args.trailing,
            );
        }
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("reading RFC 5322 from stdin")?;
        let parsed = rfc5322::parse(&buf)?;
        return Ok((parsed.recipient, parsed.body));
    }

    let recipient = match (args.recipient.as_ref(), args.recipient_flag.as_ref()) {
        (Some(_), Some(_)) => {
            return Err(anyhow!(
                "give the recipient either as positional or via --recipient, not both"
            ))
        }
        (Some(r), None) | (None, Some(r)) => r.clone(),
        (None, None) => {
            return Err(anyhow!(
                "recipient required (positional, --recipient, or use -t to read it from stdin)"
            ))
        }
    };

    let body = if let Some(text) = args.message.as_ref() {
        text.as_bytes().to_vec()
    } else {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("reading message body from stdin")?;
        buf
    };

    Ok((recipient, body))
}

/// `client.send_message` keys contacts by username. If the address
/// includes `@host` we strip it; bare usernames pass through unchanged.
fn resolve_recipient_username(address: &str) -> String {
    parse_address(address).map_or_else(|| address.to_string(), |(user, _)| user)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_recipient_strips_host_part() {
        assert_eq!(resolve_recipient_username("alice@mesh.local"), "alice");
        assert_eq!(resolve_recipient_username("alice"), "alice");
    }

    /// `warn_cross_zone_first_contact` is a stderr-side-effect; we
    /// can't capture it here without restructuring. The contract
    /// being tested in this module is just that the address-parsing
    /// path matches what send.rs actually invokes (so a future
    /// refactor that breaks parse_address would surface here).
    #[test]
    fn cross_zone_predicate_matches_address_parsing() {
        // Same zone — should be a no-op (no hint emitted).
        assert!(parse_address("alice@mesh.local").is_some());
        // Cross zone — would emit the hint.
        let cross = parse_address("alice@other.example.com").unwrap();
        assert_ne!(cross.1, "mesh.local");
        // Bare username — no hint, no parse.
        assert!(parse_address("alice").is_none());
    }
}

//! `dnsmesh identity {show,publish,refresh-prekeys,fetch,rotate,revoke}`.

use std::io::{IsTerminal as _, Write as _};
use std::path::Path;

use anyhow::{bail, Context, Result};
use dnsmesh_client::RotateReason;
use dnsmesh_core::crypto::DmpCrypto;
use dnsmesh_core::identity::identity_domain;

use crate::cli::{IdentityCmd, RevokeReasonArg, RotateReasonArg};
use crate::client_factory::{build_client, maybe_flush, require_publish, PassphraseSource};
use crate::config::ConfigFile;

pub async fn run(
    cmd: IdentityCmd,
    config_override: Option<&Path>,
    passphrase_env: Option<&str>,
) -> Result<()> {
    let cfg = ConfigFile::load(config_override)?;

    // Pre-flight: refuse publish-side commands BEFORE prompting for the
    // passphrase. Saves an unnecessary prompt when the operator forgot
    // to wire up `publish:` in config.yaml.
    if matches!(
        cmd,
        IdentityCmd::Publish
            | IdentityCmd::RefreshPrekeys { .. }
            | IdentityCmd::Rotate { .. }
            | IdentityCmd::Revoke { .. }
    ) && cfg.publish.is_none()
        && cfg.cloudflare.is_none()
        && std::env::var_os("DMP_TEST_INMEMORY_STORE_FILE").is_none()
    {
        bail!(
            "no publish destination in config — this command needs an authoritative DNS writer. \
             Add either a `publish:` block (TSIG / RFC 2136) or a `cloudflare:` block \
             (Cloudflare hosted zones). See examples/ for templates."
        );
    }

    let source = PassphraseSource::from_cli(passphrase_env);
    let built = build_client(&cfg, source).await?;
    let client = &built.client;

    match cmd {
        IdentityCmd::Show => {
            let dns_name = identity_domain(client.username(), client.domain());
            println!("username:   {}", client.username());
            println!("domain:     {}", client.domain());
            println!("x25519_pk:  {}", client.x25519_public_key_hex());
            println!("ed25519_spk: {}", client.ed25519_signing_public_key_hex());
            println!("dns_name:   {dns_name}");
        }
        IdentityCmd::Publish => {
            require_publish(&built)?;
            client.publish_identity().await?;
            let dns_name = identity_domain(client.username(), client.domain());
            println!("published identity at {dns_name}");
        }
        IdentityCmd::RefreshPrekeys { count, ttl } => {
            require_publish(&built)?;
            let n = client.refresh_prekeys(count, ttl).await?;
            println!("published {n} prekey(s) with ttl={ttl}s");
        }
        IdentityCmd::Fetch { address, add } => {
            let contact = client.fetch_identity(&address).await?;
            println!("username:    {}", contact.username);
            println!("domain:      {}", contact.domain);
            println!("x25519_pk:   {}", hex::encode(contact.x25519_pk));
            println!("ed25519_spk: {}", hex::encode(contact.ed25519_spk));
            if add {
                let newly = client.add_contact(contact.clone()).await?;
                if newly {
                    println!("contact pinned: {}", contact.username);
                } else {
                    println!("contact updated: {}", contact.username);
                }
            }
        }
        IdentityCmd::Rotate {
            reason,
            new_passphrase_env,
            ttl,
            exp_seconds,
        } => {
            require_publish(&built)?;
            run_rotate(
                client,
                &cfg,
                reason,
                new_passphrase_env.as_deref(),
                ttl,
                exp_seconds,
            )
            .await?;
        }
        IdentityCmd::Revoke { reason, ttl, yes } => {
            require_publish(&built)?;
            run_revoke(client, reason, ttl, yes).await?;
        }
        IdentityCmd::Unpublish { yes } => {
            require_publish(&built)?;
            run_unpublish(client, yes).await?;
        }
    }
    maybe_flush(&built).await?;
    Ok(())
}

async fn run_unpublish(client: &dnsmesh_client::DmpClient, yes: bool) -> Result<()> {
    if !yes {
        if !std::io::stdin().is_terminal() {
            bail!(
                "non-interactive unpublish requires --yes — every record this identity \
                 published will be DELETE'd from DNS. There is no `republish` button; you \
                 will have to re-run `dnsmesh identity publish` + `refresh-prekeys` to \
                 come back online."
            );
        }
        eprint!(
            "DNS UPDATE delete every record published by {}@{}? \
             (identity, prekeys, all 10 mailbox slots, rotation RRset) [y/N] ",
            client.username(),
            client.domain(),
        );
        let _ = std::io::stderr().flush();
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .context("reading unpublish confirmation from stdin")?;
        if !matches!(buf.trim(), "y" | "Y" | "yes" | "YES" | "Yes") {
            bail!("unpublish aborted by user");
        }
    }
    let report = client.unpublish_identity().await?;
    let succeeded = report.deletes.iter().filter(|(_, ok)| *ok).count();
    let total = report.deletes.len();
    println!("unpublished {succeeded}/{total} records:");
    for (name, ok) in &report.deletes {
        let mark = if *ok { "✓" } else { "·" };
        println!("  {mark} {name}");
    }
    if succeeded < total {
        eprintln!(
            "Note: lines marked `·` were already absent or the writer rejected the \
             DELETE. Records you didn't publish (e.g. unused mailbox slots) and entries \
             outside your TSIG scope will TTL out on their own."
        );
    }
    Ok(())
}

/// Execute `dnsmesh identity rotate`. Splits into a separate fn so the
/// big `run()` match arm stays readable.
async fn run_rotate(
    client: &dnsmesh_client::DmpClient,
    cfg: &crate::config::ResolvedConfig,
    reason: RotateReasonArg,
    new_pass_env: Option<&str>,
    ttl: u32,
    exp_seconds: u64,
) -> Result<()> {
    // 1. Get the new passphrase. Same priority as the existing
    //    `--insecure-passphrase-env DMP_PASS` plumbing: env var first,
    //    interactive prompt fallback. Differs from the OLD passphrase
    //    so the new key isn't accidentally identical.
    let new_passphrase = read_new_passphrase(new_pass_env)?;
    let new_crypto = DmpCrypto::from_passphrase(&new_passphrase, cfg.kdf_salt.as_deref())
        .context("deriving new identity from --new-passphrase")?;

    // 2. Sanity-check upstream: rotate_identity also rejects the
    //    same-key case but we'd rather error here than after a useless
    //    prompt for confirmation.
    if new_crypto.signing_public_key_bytes()
        == hex_decode_spk(&client.ed25519_signing_public_key_hex())?
    {
        bail!(
            "new passphrase derives the same signing key as the current one — \
             pick a different passphrase. Did you re-type the same one?"
        );
    }

    // 3. Confirm interactively unless redirected (env passphrase implies
    //    non-interactive intent). Rotation is not reversible — the
    //    rotation pointer goes onto DNS the moment we publish.
    if std::io::stdin().is_terminal() && new_pass_env.is_none() {
        eprintln!(
            "About to rotate {}@{}. This publishes a RotationRecord pointing the OLD key \
             at the NEW one and is NOT reversible. Continue? [y/N] ",
            client.username(),
            client.domain(),
        );
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .context("reading rotation confirmation from stdin")?;
        let trimmed = buf.trim();
        if !matches!(trimmed, "y" | "Y" | "yes" | "YES" | "Yes") {
            bail!("rotate aborted by user");
        }
    }

    let rotate_reason = match reason {
        RotateReasonArg::Routine => RotateReason::Routine,
        RotateReasonArg::Compromise => RotateReason::Compromise,
        RotateReasonArg::LostKey => RotateReason::LostKey,
    };

    let outcome = client
        .rotate_identity(&new_crypto, rotate_reason, ttl, exp_seconds)
        .await?;

    println!("rotation:    published (seq={})", outcome.seq);
    let mut partial_failure = false;
    if let Some(rev_ok) = outcome.revocation_published {
        if rev_ok {
            println!("revocation:  published (reason={reason:?})");
        } else {
            partial_failure = true;
            eprintln!(
                "revocation:  PUBLISH FAILED — re-run `dnsmesh identity revoke --reason {}` \
                 with the OLD passphrase to retry. Rotation pointer is already on DNS.",
                match reason {
                    RotateReasonArg::Compromise => "compromise",
                    RotateReasonArg::LostKey => "lost-key",
                    RotateReasonArg::Routine => unreachable!(),
                }
            );
        }
    }
    if outcome.new_identity_published {
        println!(
            "new identity: published at {}",
            identity_domain(client.username(), client.domain())
        );
    } else {
        partial_failure = true;
        eprintln!(
            "new identity: PUBLISH FAILED — `dnsmesh identity fetch` will return the OLD key \
             until you re-run `dnsmesh identity publish` with the new passphrase exported."
        );
    }
    println!();
    println!(
        "IMPORTANT: future commands need the NEW passphrase. Update your DMP_PASS / passphrase \
         env (or your prompt input) before next invocation. The Rust CLI does not store the \
         passphrase between commands — there's nothing to clear locally."
    );

    // Compromise/lost-key UX hint: the published RevocationRecord
    // aborts the receive-side chain walker for pinned old-key
    // receivers, which means contacts have to re-pin out of band.
    // This is protocol design — not a Rust port bug — but the
    // operator should know the operational consequence.
    if matches!(
        reason,
        RotateReasonArg::Compromise | RotateReasonArg::LostKey
    ) {
        eprintln!(
            "\nNote: --reason {} publishes a RevocationRecord. Receivers running with \
             rotation_chain_enabled will reject the old key entirely (the chain walker \
             aborts on a pinned-key revocation, by design — old-key spam is dropped). \
             Pinned contacts will have to RE-PIN you under the new key out-of-band; \
             the chain doesn't transparently move them forward when the old key is \
             revoked. For a seamless transparent rotation use `--reason routine` \
             instead.",
            match reason {
                RotateReasonArg::Compromise => "compromise",
                RotateReasonArg::LostKey => "lost-key",
                RotateReasonArg::Routine => unreachable!(),
            }
        );
    }

    // A partial-failure rotation is NOT exit-zero. The rotation
    // pointer is already on DNS, but the operator needs to know via
    // process exit (cron jobs, CI, scripts) that further action is
    // required. Mirrors Python's exit-code-3 at cli.py:2232.
    if partial_failure {
        bail!(
            "rotation completed with partial publish failures — see warnings above. \
             Exit code 1: the rotation pointer is on DNS but follow-up publishes are needed."
        );
    }
    Ok(())
}

async fn run_revoke(
    client: &dnsmesh_client::DmpClient,
    reason: RevokeReasonArg,
    ttl: u32,
    yes: bool,
) -> Result<()> {
    if !yes {
        if !std::io::stdin().is_terminal() {
            bail!(
                "non-interactive revoke requires --yes — revocation is permanent and there is \
                 no way to un-revoke a key once published. Re-run with --yes to confirm intent."
            );
        }
        eprint!(
            "PERMANENTLY revoke {}@{}? You will need to re-register a fresh identity (new SPK) \
             on the node to send under this username again. [y/N] ",
            client.username(),
            client.domain(),
        );
        let _ = std::io::stderr().flush();
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .context("reading revoke confirmation from stdin")?;
        if !matches!(buf.trim(), "y" | "Y" | "yes" | "YES" | "Yes") {
            bail!("revoke aborted by user");
        }
    }

    let rotate_reason = match reason {
        RevokeReasonArg::Compromise => RotateReason::Compromise,
        RevokeReasonArg::LostKey => RotateReason::LostKey,
    };
    client.revoke_identity(rotate_reason, ttl).await?;
    println!(
        "revoked {}@{} (reason={:?}). Future receivers running with rotation_chain_enabled \
         will drop messages signed by this key.",
        client.username(),
        client.domain(),
        reason,
    );
    println!(
        "Note: the rotation chain has no `unrevoke` operation. To send under this username \
         again you'd have to re-register a fresh identity (new SPK) at this address on the \
         node — the operator may need to revoke the old TSIG token for that to work."
    );
    Ok(())
}

/// Read the new passphrase from the named env var if provided, else
/// prompt interactively (silent input, just like the existing
/// `rpassword` prompt for the current passphrase).
fn read_new_passphrase(env_name: Option<&str>) -> Result<String> {
    if let Some(name) = env_name {
        match std::env::var(name) {
            Ok(v) if !v.is_empty() => return Ok(v),
            _ => bail!(
                "new-passphrase env var `{name}` is empty or unset — export it before \
                 invoking, or omit --new-passphrase-env to be prompted"
            ),
        }
    }
    rpassword::prompt_password("new DMP passphrase: ")
        .context("reading new passphrase from terminal")
}

fn hex_decode_spk(s: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(s).context("decoding current signing-key hex")?;
    if raw.len() != 32 {
        bail!("expected 32-byte signing key, got {}", raw.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

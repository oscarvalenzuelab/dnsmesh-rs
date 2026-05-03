//! `dnsmesh doctor` — light diagnostics over config / db / DNS.
//!
//! Mirrors the spirit of Python `cmd_doctor`: walk a curated checklist
//! and print PASS / WARN / FAIL with an actionable hint per failure.
//! Exits 0 if everything is PASS or WARN, 1 if any FAIL surfaced.

use std::path::Path;

use anyhow::Result;
use dnsmesh_net::{DnsRecordReader, ResolverPool, ResolverPoolConfig};

use crate::client_factory::{build_client, PassphraseSource};
use crate::config::ConfigFile;

pub async fn run(config_override: Option<&Path>, passphrase_env: Option<&str>) -> Result<()> {
    let mut any_fail = false;

    // 1. Config exists & parses.
    let cfg = match ConfigFile::try_load(config_override) {
        Ok(Some(c)) => {
            println!("[PASS] config: {}", c.config_path.display());
            c
        }
        Ok(None) => {
            println!("[FAIL] config: not found — run `dnsmesh init <username> --domain <DOMAIN>`");
            return Err(anyhow::anyhow!("doctor: config missing"));
        }
        Err(e) => {
            println!("[FAIL] config: {e}");
            return Err(e);
        }
    };

    // 2. Resolver pool reaches at least one upstream. Use a known-
    //    public name (google.com TXT) so a transient miss for our own
    //    zone doesn't poison the result.
    let pool = match cfg.resolvers.as_deref() {
        Some(list) if !list.is_empty() => {
            // Surface invalid resolver entries before we drop them. The
            // production client construction rejects them — doctor must
            // not silently let a typo through.
            let mut parsed = Vec::new();
            let mut invalid = Vec::new();
            for entry in list {
                match entry.parse() {
                    Ok(spec) => parsed.push(spec),
                    Err(_) => invalid.push(entry.clone()),
                }
            }
            if !invalid.is_empty() {
                println!(
                    "[FAIL] resolvers: invalid entries {invalid:?} (must be IPv4/IPv6 literals; \
                     hostnames are not accepted)"
                );
                any_fail = true;
            }
            if parsed.is_empty() {
                println!("[FAIL] resolvers: every entry was invalid; cannot build a pool");
                return summary(true);
            }
            match ResolverPool::new(parsed, ResolverPoolConfig::default()) {
                Ok(p) => p,
                Err(e) => {
                    println!("[FAIL] resolvers: invalid config: {e}");
                    return summary(true);
                }
            }
        }
        _ => match ResolverPool::well_known() {
            Ok(p) => p,
            Err(e) => {
                println!("[FAIL] resolvers: cannot build well-known pool: {e}");
                any_fail = true;
                return summary(any_fail);
            }
        },
    };
    match pool.query_txt_record("google.com").await {
        Ok(_) => println!("[PASS] resolvers: reachable ({} upstream(s))", pool.len()),
        Err(e) => {
            println!("[WARN] resolvers: TXT lookup failed: {e}");
        }
    }

    // 3. Try to open the client (sqlite migration + KDF). This also
    //    confirms the passphrase is acceptable and the db file is
    //    writable.
    let source = PassphraseSource::from_cli(passphrase_env);
    let built = match build_client(&cfg, source).await {
        Ok(b) => {
            println!("[PASS] client: opened db at {}", cfg.db_path.display());
            b
        }
        Err(e) => {
            println!("[FAIL] client: {e}");
            any_fail = true;
            return summary(any_fail);
        }
    };

    // 4. Are we set up to publish? Reading-only flows still work
    //    without a writer, so this is a WARN not a FAIL.
    if built.publish_configured {
        println!("[PASS] publish: TSIG-signed UPDATE writer wired");
    } else {
        println!(
            "[WARN] publish: no `publish:` block in config — `identity publish`, \
             `refresh-prekeys`, and `send` will refuse to run"
        );
    }

    // 5. Is our identity actually published? Try fetching ourselves.
    let self_addr = format!("{}@{}", cfg.username, cfg.domain);
    match built.client.fetch_identity(&self_addr).await {
        Ok(_) => println!("[PASS] identity: published at {self_addr}"),
        Err(e) => println!(
            "[WARN] identity: not yet published at {self_addr} ({e}). \
             Run `dnsmesh identity publish` once your `publish:` block is configured."
        ),
    }

    summary(any_fail)
}

fn summary(any_fail: bool) -> Result<()> {
    if any_fail {
        Err(anyhow::anyhow!("doctor: one or more FAIL checks"))
    } else {
        Ok(())
    }
}

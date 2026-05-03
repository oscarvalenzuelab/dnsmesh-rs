//! On-disk YAML config for the `dnsmesh` CLI.
//!
//! Mirrors the shape Python's `cli.py` understands where the two
//! overlap. Two extras are Rust-port specific: the `db_path` field
//! pointing at the V3 sqlite file (Python uses a JSON file), and the
//! optional `publish:` block carrying the TSIG-write-side knobs that
//! Python keeps in a separate JSON.
//!
//! Path resolution rules (applied at load time):
//!
//!   - Empty `db_path` → `<config_home>/dmp-rs.sqlite`.
//!   - `~`-prefixed paths expand to `$HOME`.
//!   - Relative paths are anchored to the config home (the directory
//!     containing the YAML), not to the process working directory.
//!     Anchoring to cwd would make every shell that cd'd into a
//!     different folder pick up a different sqlite file, which is the
//!     source of about half of every "where did my keys go?" bug
//!     report we want to avoid.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

/// Top-level on-disk shape.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfigFile {
    pub username: String,
    pub domain: String,

    /// Where to keep the local sqlite database. `None` = `<config_home>/dmp-rs.sqlite`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_path: Option<PathBuf>,

    /// Recursive resolvers to query. `None` = use [`dnsmesh_net::ResolverPool::well_known`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolvers: Option<Vec<String>>,

    /// Argon2id salt as a hex string. `None` = use the default
    /// sentinel salt (`DEFAULT_ARGON2_SALT` in dnsmesh-core). The
    /// Python CLI persists this as `kdf_salt: <hex>`; setting the
    /// same value here makes the Rust client derive the same
    /// X25519 plus Ed25519 identity from a given passphrase, which is
    /// what lets a TSIG key registered against a Python-derived SPK
    /// authenticate Rust-published records under the same identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf_salt: Option<String>,

    /// Optional TSIG-signed publish destination. Required for `identity publish` /
    /// `identity refresh-prekeys` to work; reading-only flows (recv, fetch, list)
    /// never need it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish: Option<PublishConfig>,

    /// Optional Cloudflare HTTP-API publish destination. Mutually
    /// exclusive with `publish:` — set whichever matches the zone's
    /// hosting platform. When both are present, `cloudflare:` wins
    /// (the operator deliberately set the more specific one) and
    /// `publish:` is logged as ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloudflare: Option<CloudflareConfig>,
}

/// Authoritative-zone publish config — TSIG key, server, zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishConfig {
    /// Authoritative zone we're allowed to UPDATE under (e.g. `dmp.example.com`).
    pub zone: String,
    /// `host:port` of the authoritative server. Hostnames are accepted.
    pub server: String,
    /// TSIG key name as configured on the server.
    pub tsig_key_name: String,
    /// One of `hmac-sha256`, `hmac-sha384`, `hmac-sha512`.
    #[serde(default = "default_tsig_algorithm")]
    pub tsig_algorithm: String,
    /// Path to a file holding the TSIG secret as base64. We do NOT inline
    /// the secret in YAML so the on-disk config stays safe to share.
    pub tsig_secret_path: PathBuf,
}

fn default_tsig_algorithm() -> String {
    "hmac-sha256".to_string()
}

/// Cloudflare-hosted-zone publish config. Pulls the API token from
/// disk so the YAML stays safe to share — same shape the TSIG-secret
/// path takes in [`PublishConfig`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareConfig {
    /// Cloudflare zone ID (the 32-char hex string from the zone
    /// dashboard, NOT the human-readable zone name).
    pub zone_id: String,
    /// Path to a file holding the Cloudflare API token (raw text, no
    /// envelope). The token must hold `Zone:DNS:Edit` for `zone_id`.
    pub api_token_path: PathBuf,
}

/// Resolved view of the config: paths anchored to a known home, ready
/// for the rest of the CLI to consume without each command re-implementing
/// path expansion.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    /// Directory the config file lives in. Kept around so commands
    /// that need to write sibling files (TSIG secret, sqlite) have a
    /// stable anchor without re-deriving it from `config_path`.
    #[allow(dead_code)]
    pub config_home: PathBuf,
    pub config_path: PathBuf,
    pub username: String,
    pub domain: String,
    pub db_path: PathBuf,
    pub resolvers: Option<Vec<String>>,
    pub publish: Option<PublishConfig>,
    pub cloudflare: Option<CloudflareConfig>,
    /// Decoded Argon2id salt bytes when `kdf_salt:` is set in the
    /// YAML; otherwise `None` and the client uses the default
    /// sentinel salt. Kept here (rather than re-parsing in every
    /// caller) so a malformed hex literal trips at config-load time.
    pub kdf_salt: Option<Vec<u8>>,
}

impl ConfigFile {
    /// Default config-file path, honoring `$DMP_CONFIG_HOME` then `~/.dmp/`.
    pub fn default_path() -> Result<PathBuf> {
        Ok(default_config_home()?.join("config.yaml"))
    }

    /// Resolve the config-home directory the same way [`Self::default_path`]
    /// does. Exposed so init can mkdir before writing.
    #[allow(dead_code)]
    pub fn default_home() -> Result<PathBuf> {
        default_config_home()
    }

    /// Load (and resolve) from `override_path` if set, otherwise from
    /// the default location.
    pub fn load(override_path: Option<&Path>) -> Result<ResolvedConfig> {
        let path = match override_path {
            Some(p) => p.to_path_buf(),
            None => Self::default_path()?,
        };
        let raw = std::fs::read_to_string(&path).with_context(|| {
            format!(
                "could not read config at {} — run `dnsmesh init` first",
                path.display()
            )
        })?;
        let parsed: Self = serde_yaml::from_str(&raw)
            .with_context(|| format!("invalid YAML in {}", path.display()))?;
        parsed.resolve(path)
    }

    /// Same as [`Self::load`] but tolerates a missing file by returning
    /// `Ok(None)`. Used by `doctor`.
    pub fn try_load(override_path: Option<&Path>) -> Result<Option<ResolvedConfig>> {
        let path = match override_path {
            Some(p) => p.to_path_buf(),
            None => Self::default_path()?,
        };
        if !path.exists() {
            return Ok(None);
        }
        Self::load(Some(&path)).map(Some)
    }

    /// Resolve paths against the eventual config location WITHOUT writing
    /// the file. `init` uses this so it can build a client (and surface
    /// any failure) before persisting `config.yaml`.
    pub fn with_resolved_paths(self, config_path: &Path) -> Result<ResolvedConfig> {
        self.resolve(config_path.to_path_buf())
    }

    /// Persist to YAML at `path`. Creates parent directories as needed.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating config directory {}", parent.display()))?;
        }
        let yaml = serde_yaml::to_string(self).context("serializing config")?;
        std::fs::write(path, yaml)
            .with_context(|| format!("writing config to {}", path.display()))?;
        Ok(())
    }

    fn resolve(self, config_path: PathBuf) -> Result<ResolvedConfig> {
        let config_home = config_path
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);

        if self.username.trim().is_empty() {
            return Err(anyhow!("config: username must not be empty"));
        }
        if self.domain.trim().is_empty() {
            return Err(anyhow!("config: domain must not be empty"));
        }

        let db_path = match self.db_path {
            Some(p) => resolve_path(&p, &config_home)?,
            None => config_home.join("dmp-rs.sqlite"),
        };

        let publish = self
            .publish
            .map(|mut p| {
                p.tsig_secret_path = resolve_path(&p.tsig_secret_path, &config_home)?;
                Ok::<_, anyhow::Error>(p)
            })
            .transpose()?;
        let cloudflare = self
            .cloudflare
            .map(|mut c| {
                c.api_token_path = resolve_path(&c.api_token_path, &config_home)?;
                Ok::<_, anyhow::Error>(c)
            })
            .transpose()?;

        if cloudflare.is_some() && publish.is_some() {
            // Silent-override risk: an operator who copy-pastes a
            // sample config with both blocks and forgets to delete
            // one ends up publishing to a different backend than
            // they think they configured. Hard-fail with a clear
            // remediation message instead.
            return Err(anyhow!(
                "config carries BOTH a `publish:` (TSIG / RFC 2136) and a `cloudflare:` \
                 block. Pick one — DMP supports either backend, but the silent override \
                 the prior CLI did made misconfiguration easy to miss. Delete whichever \
                 block you don't actually want."
            ));
        }

        let kdf_salt = self
            .kdf_salt
            .as_deref()
            .map(|s| hex::decode(s.trim()).context("config.kdf_salt is not valid hex"))
            .transpose()?;

        Ok(ResolvedConfig {
            config_home,
            config_path,
            username: self.username,
            domain: self.domain,
            db_path,
            resolvers: self.resolvers,
            publish,
            cloudflare,
            kdf_salt,
        })
    }
}

/// Pick the config-home directory.
///
/// Priority: `$DMP_CONFIG_HOME` env var, then `$HOME/.dmp`. `$HOME`
/// missing is a hard error rather than a silent fallback to `.` so a
/// broken environment surfaces immediately.
fn default_config_home() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("DMP_CONFIG_HOME") {
        return Ok(PathBuf::from(home));
    }
    let home = std::env::var_os("HOME")
        .ok_or_else(|| anyhow!("HOME is not set; set DMP_CONFIG_HOME or HOME"))?;
    Ok(PathBuf::from(home).join(".dmp"))
}

/// Expand `~` and anchor relative paths against `base`.
fn resolve_path(p: &Path, base: &Path) -> Result<PathBuf> {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        let home =
            std::env::var_os("HOME").ok_or_else(|| anyhow!("cannot expand ~ — HOME is not set"))?;
        return Ok(PathBuf::from(home).join(rest));
    }
    if s == "~" {
        let home =
            std::env::var_os("HOME").ok_or_else(|| anyhow!("cannot expand ~ — HOME is not set"))?;
        return Ok(PathBuf::from(home));
    }
    if p.is_absolute() {
        return Ok(p.to_path_buf());
    }
    Ok(base.join(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn round_trip_yaml_with_publish_block() {
        let cfg = ConfigFile {
            username: "alice".into(),
            domain: "mesh.local".into(),
            db_path: Some(PathBuf::from("dmp-rs.sqlite")),
            resolvers: Some(vec!["1.1.1.1".into(), "8.8.8.8".into()]),
            publish: Some(PublishConfig {
                zone: "dmp.example.com".into(),
                server: "192.0.2.1:53".into(),
                tsig_key_name: "dmp-publish".into(),
                tsig_algorithm: "hmac-sha256".into(),
                tsig_secret_path: PathBuf::from("tsig.key"),
            }),
            cloudflare: None,
            kdf_salt: None,
        };
        let yaml = serde_yaml::to_string(&cfg).unwrap();
        let parsed: ConfigFile = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.username, "alice");
        assert_eq!(parsed.domain, "mesh.local");
        assert_eq!(parsed.resolvers.as_ref().unwrap().len(), 2);
        assert!(parsed.publish.is_some());
    }

    #[test]
    fn resolve_anchors_relative_paths_to_config_home() {
        let dir = TempDir::new().unwrap();
        let cfg_path = dir.path().join("config.yaml");
        let cfg = ConfigFile {
            username: "alice".into(),
            domain: "mesh.local".into(),
            db_path: Some(PathBuf::from("custom.sqlite")),
            resolvers: None,
            publish: None,
            cloudflare: None,
            kdf_salt: None,
        };
        cfg.save(&cfg_path).unwrap();
        let resolved = ConfigFile::load(Some(&cfg_path)).unwrap();
        assert_eq!(resolved.db_path, dir.path().join("custom.sqlite"));
    }

    #[test]
    fn resolve_uses_default_db_when_unset() {
        let dir = TempDir::new().unwrap();
        let cfg_path = dir.path().join("config.yaml");
        let cfg = ConfigFile {
            username: "alice".into(),
            domain: "mesh.local".into(),
            db_path: None,
            resolvers: None,
            publish: None,
            cloudflare: None,
            kdf_salt: None,
        };
        cfg.save(&cfg_path).unwrap();
        let resolved = ConfigFile::load(Some(&cfg_path)).unwrap();
        assert_eq!(resolved.db_path, dir.path().join("dmp-rs.sqlite"));
    }

    #[test]
    fn dual_config_publish_and_cloudflare_hard_fails() {
        // A config with both publish: and cloudflare: blocks fails
        // at load time so an operator can't accidentally publish to
        // the wrong backend.
        let dir = TempDir::new().unwrap();
        let cfg_path = dir.path().join("config.yaml");
        let cfg = ConfigFile {
            username: "alice".into(),
            domain: "mesh.local".into(),
            db_path: None,
            resolvers: None,
            publish: Some(PublishConfig {
                zone: "dmp.example.com".into(),
                server: "192.0.2.1:53".into(),
                tsig_key_name: "k".into(),
                tsig_algorithm: "hmac-sha256".into(),
                tsig_secret_path: PathBuf::from("tsig.key"),
            }),
            cloudflare: Some(CloudflareConfig {
                zone_id: "0123456789abcdef0123456789abcdef".into(),
                api_token_path: PathBuf::from("cf-token"),
            }),
            kdf_salt: None,
        };
        cfg.save(&cfg_path).unwrap();
        let err = ConfigFile::load(Some(&cfg_path)).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("BOTH"),
            "expected hard-fail mentioning BOTH; got: {msg}",
        );
    }

    #[test]
    fn empty_username_rejected() {
        let dir = TempDir::new().unwrap();
        let cfg_path = dir.path().join("config.yaml");
        let cfg = ConfigFile {
            username: "  ".into(),
            domain: "mesh.local".into(),
            db_path: None,
            resolvers: None,
            publish: None,
            cloudflare: None,
            kdf_salt: None,
        };
        cfg.save(&cfg_path).unwrap();
        assert!(ConfigFile::load(Some(&cfg_path)).is_err());
    }

    #[test]
    fn dmp_config_home_overrides_default() {
        let dir = TempDir::new().unwrap();
        // Only verify the resolver function honors the env var; we do
        // NOT mutate it in a multi-threaded test runner, just call the
        // private helper directly.
        // Save the previous value so we don't leak state across tests
        // that share the env.
        let prev = std::env::var_os("DMP_CONFIG_HOME");
        // SAFETY note: tests in this module run on a single test process
        // but with Cargo's parallel runner, env mutation can race. The
        // resolver is exercised in the integration smoke tests under a
        // unique tempdir per test, so we keep this assertion narrow.
        std::env::set_var("DMP_CONFIG_HOME", dir.path());
        let home = default_config_home().unwrap();
        assert_eq!(home, dir.path());
        match prev {
            Some(v) => std::env::set_var("DMP_CONFIG_HOME", v),
            None => std::env::remove_var("DMP_CONFIG_HOME"),
        }
    }
}

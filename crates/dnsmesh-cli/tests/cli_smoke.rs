//! M4 gate proxy: drive the `dnsmesh` binary at the process boundary.
//!
//! Each test runs in a fresh `DMP_CONFIG_HOME` tempdir and supplies the
//! passphrase via the `--insecure-passphrase-env` opt-in so we never
//! prompt. Everything that matters for the M4 gate — init, identity
//! show, contacts add+list — is exercised here.

use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;
use tempfile::TempDir;

const PASSPHRASE: &str = "smoke-test-passphrase";

/// Build a clean `Command` whose env points the CLI at `home` for both
/// config and HOME (so default_db_path resolves there too).
fn dnsmesh(home: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("dnsmesh").expect("binary built");
    cmd.env_remove("DMP_CONFIG")
        .env("DMP_CONFIG_HOME", home.path())
        .env("HOME", home.path())
        .env("DMP_PASSPHRASE", PASSPHRASE)
        .env("DMP_INSECURE_PASSPHRASE_ENV", "DMP_PASSPHRASE");
    cmd
}

#[test]
fn help_exits_zero_and_mentions_dmp() {
    let mut cmd = Command::cargo_bin("dnsmesh").expect("binary built");
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("DMP"));
}

#[test]
fn version_exits_zero() {
    let mut cmd = Command::cargo_bin("dnsmesh").expect("binary built");
    cmd.arg("--version").assert().success();
}

#[test]
fn init_then_identity_show_then_contacts_round_trip() {
    let home = TempDir::new().unwrap();

    // init
    dnsmesh(&home)
        .args(["init", "alice", "--domain", "mesh.local"])
        .assert()
        .success()
        .stdout(predicate::str::contains("alice@mesh.local"));

    // identity show — should print a 64-char hex pubkey.
    dnsmesh(&home)
        .args(["identity", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("username:   alice"))
        .stdout(predicate::str::is_match(r"x25519_pk:\s+[0-9a-f]{64}").unwrap())
        .stdout(predicate::str::is_match(r"ed25519_spk:\s+[0-9a-f]{64}").unwrap());

    // contacts add — uses 32-byte placeholder keys.
    let x25519 = "11".repeat(32);
    let ed25519 = "22".repeat(32);
    dnsmesh(&home)
        .args([
            "contacts",
            "add",
            "bob@mesh.local",
            "--x25519",
            &x25519,
            "--ed25519",
            &ed25519,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("pinned bob@mesh.local"));

    // contacts list — should show the row.
    dnsmesh(&home)
        .args(["contacts", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bob"))
        .stdout(predicate::str::contains("mesh.local"));
}

#[test]
fn init_refuses_to_overwrite_existing_config() {
    let home = TempDir::new().unwrap();
    dnsmesh(&home)
        .args(["init", "alice", "--domain", "mesh.local"])
        .assert()
        .success();
    dnsmesh(&home)
        .args(["init", "alice", "--domain", "mesh.local"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn identity_publish_without_publish_block_fails_with_helpful_message() {
    let home = TempDir::new().unwrap();
    dnsmesh(&home)
        .args(["init", "alice", "--domain", "mesh.local"])
        .assert()
        .success();
    dnsmesh(&home)
        .args(["identity", "publish"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("publish:"));
}

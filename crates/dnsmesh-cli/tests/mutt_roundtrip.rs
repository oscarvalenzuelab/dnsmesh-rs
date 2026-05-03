//! End-to-end mutt round-trip QA against the `dnsmesh` binary.
//!
//! Closes the M4 plan gate that the smoke tests don't actually
//! exercise: "mutt round-trip works (compose → `dnsmesh send -t` →
//! recipient `dnsmesh recv --maildir` → mutt sees message)". We
//! drive the same command line mutt's `set sendmail` would invoke,
//! pipe a representative RFC 5322 message in via stdin, then run
//! the recipient's `dnsmesh recv --maildir <tmp>` and assert the
//! resulting Maildir tree carries the original plaintext.
//!
//! How we share state without a live BIND zone:
//!   - The CLI's `client_factory.rs` honors `DMP_TEST_INMEMORY_STORE_FILE`
//!     and swaps both reader and writer for an in-memory store
//!     persisted to that JSON file.
//!   - Two CLI invocations pointed at the same path share one
//!     virtual mesh — alice's send writes records, bob's recv
//!     reads them.
//!   - No real DNS, no TSIG, no mutt binary required. The format
//!     we drive on stdin matches exactly what mutt's sendmail-compat
//!     hands to `dnsmesh send -t`.
//!
//! Why this is "mutt round-trip" and not just an SDK round trip:
//!   - It exercises `dnsmesh send -t` as a child process — the
//!     same shape mutt's `set sendmail = "/usr/local/bin/dnsmesh send -t"`
//!     would invoke.
//!   - The stdin payload is real RFC 5322: To, From, Subject, blank
//!     line, body — `mua/rfc5322.rs` parses it and pulls `To:` for
//!     the recipient.
//!   - The output is a real Maildir tree (cur / new / tmp + atomic
//!     rename) that any MUA — mutt, neomutt, alot, aerc — can poll.
#![allow(clippy::too_many_lines)]

use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use assert_cmd::cargo::CommandCargoExt;

const ALICE_PASSPHRASE: &str = "alice-mutt-pp";
const BOB_PASSPHRASE: &str = "bob-mutt-pp";
const DOMAIN: &str = "mesh.local";

/// Build a `dnsmesh` invocation pre-wired with the test backdoor +
/// quiet tracing. Each caller layers on `--config`, the passphrase
/// env, and the subcommand.
fn dnsmesh_cmd(workdir: &Path, store: &Path) -> Command {
    let mut cmd = Command::cargo_bin("dnsmesh").expect("dnsmesh binary built");
    cmd.env("DMP_TEST_INMEMORY_STORE_FILE", store);
    cmd.env("DMP_CONFIG_HOME", workdir);
    // Quiet the tracing output so test stderr stays scannable when
    // assertions fail. Override with RUST_LOG=debug if you need to
    // see the publish chain.
    cmd.env("RUST_LOG", "warn");
    cmd
}

fn write_yaml_config(path: &Path, username: &str, db_path: &Path) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let body = format!(
        "username: {username}\n\
         domain: {DOMAIN}\n\
         storage:\n  db_path: {}\n",
        db_path.display()
    );
    fs::write(path, body).unwrap();
}

/// Per-identity command builder: layers passphrase env + --config on
/// top of [`dnsmesh_cmd`]. Each invocation gets a fresh `Command`
/// because std::process::Command isn't cheap to clone.
fn identity_cmd(
    workspace: &Path,
    store: &Path,
    config: &Path,
    passphrase_env_name: &str,
    passphrase_env_value: &str,
) -> Command {
    let mut cmd = dnsmesh_cmd(workspace, store);
    cmd.env(passphrase_env_name, passphrase_env_value);
    cmd.arg("--config").arg(config);
    cmd.arg("--insecure-passphrase-env")
        .arg(passphrase_env_name);
    cmd
}

fn assert_ok(label: &str, out: &std::process::Output) {
    assert!(
        out.status.success(),
        "{label} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn alice_sends_via_stdin_bob_receives_into_maildir() {
    // Independent workdir per identity, both sharing the same
    // DMP_TEST_INMEMORY_STORE_FILE so the publishes alice makes
    // become visible to bob's poll. Tempdir is auto-cleaned on
    // test exit.
    let workspace = tempfile::tempdir().expect("tmpdir");
    let workspace_path = workspace.path();
    let store_path = workspace_path.join("mesh-store.json");

    let alice_home = workspace_path.join("alice-home");
    let bob_home = workspace_path.join("bob-home");
    let alice_config = alice_home.join("config.yaml");
    let bob_config = bob_home.join("config.yaml");
    let alice_db = alice_home.join("dmp-rs.sqlite");
    let bob_db = bob_home.join("dmp-rs.sqlite");
    write_yaml_config(&alice_config, "alice-mutt", &alice_db);
    write_yaml_config(&bob_config, "bob-mutt", &bob_db);

    let alice = |args: &[&str]| {
        let mut cmd = identity_cmd(
            workspace_path,
            &store_path,
            &alice_config,
            "DMP_INSECURE_PASSPHRASE_VALUE_ALICE",
            ALICE_PASSPHRASE,
        );
        cmd.args(args);
        cmd
    };
    let bob = |args: &[&str]| {
        let mut cmd = identity_cmd(
            workspace_path,
            &store_path,
            &bob_config,
            "DMP_INSECURE_PASSPHRASE_VALUE_BOB",
            BOB_PASSPHRASE,
        );
        cmd.args(args);
        cmd
    };

    // Step 1 — alice publishes her identity + a prekey pool.
    let out = alice(&["identity", "publish"])
        .output()
        .expect("alice identity publish");
    assert_ok("alice identity publish", &out);
    let out = alice(&["identity", "refresh-prekeys", "--count", "5"])
        .output()
        .expect("alice refresh-prekeys");
    assert_ok("alice refresh-prekeys", &out);

    // Step 2 — bob publishes his identity + prekeys.
    let out = bob(&["identity", "publish"])
        .output()
        .expect("bob identity publish");
    assert_ok("bob identity publish", &out);
    let out = bob(&["identity", "refresh-prekeys", "--count", "5"])
        .output()
        .expect("bob refresh-prekeys");
    assert_ok("bob refresh-prekeys", &out);

    // Step 3 — alice fetches bob's identity and pins him so the
    // contact lookup at send time succeeds. Mirrors what an
    // operator would do before wiring up `set sendmail` in muttrc.
    let bob_address = format!("bob-mutt@{DOMAIN}");
    let out = alice(&["identity", "fetch", &bob_address, "--add"])
        .output()
        .expect("alice fetch bob");
    assert_ok("alice fetch bob", &out);

    // Step 4 — alice runs `dnsmesh send -t` with an RFC 5322 body
    // on stdin. Same shape mutt drops onto stdin via
    // `set sendmail = "/usr/local/bin/dnsmesh send -t"`.
    let rfc5322 = format!(
        "From: alice <alice-mutt@{DOMAIN}>\r\n\
         To: bob <bob-mutt@{DOMAIN}>\r\n\
         Subject: mutt round-trip QA\r\n\
         Date: Sun, 02 May 2026 17:30:00 -0700\r\n\
         Message-ID: <mutt-rt-1@example>\r\n\
         \r\n\
         hello bob -- sent via dnsmesh send -t, recv'd into a Maildir.\r\n",
    );
    // mutt / neomutt invoke sendmail as `<binary> -t <recipient>` —
    // the positional address is sendmail-`-t`'s "suppression list",
    // not a delivery target. Pass the recipient positionally here
    // so the integration test asserts that we tolerate it.
    // Regression guard: a previous build hard-errored on this shape,
    // breaking real mutt configs.
    let mut child = alice(&["send", "-t", &bob_address])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn alice send");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(rfc5322.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("alice send");
    assert_ok("alice send -t", &out);
    let msg_id = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_eq!(msg_id.len(), 32, "msg_id is 16 bytes hex (32 chars)");

    // Step 4.5 — bob also pins alice. Without this the recv writer
    // can't resolve the manifest's sender_spk to a real address and
    // falls back to a synthetic `dmp-<spk>@dmp.local` From: header.
    // For the From-header-resolves-to-real-address assertion below
    // bob has to know who alice is.
    let alice_address = format!("alice-mutt@{DOMAIN}");
    let out = bob(&["identity", "fetch", &alice_address, "--add"])
        .output()
        .expect("bob fetch alice");
    assert_ok("bob fetch alice", &out);

    // Step 5 — bob runs `dnsmesh recv --maildir <tmp>` and the
    // delivered message lands in cur/new/tmp.
    let maildir_root = workspace_path.join("bob-maildir");
    let out = bob(&["recv", "--maildir"])
        .arg(&maildir_root)
        .output()
        .expect("bob recv");
    assert_ok("bob recv --maildir", &out);

    // Step 6 — confirm the Maildir layout + payload.
    let new_dir = maildir_root.join("new");
    assert!(
        new_dir.is_dir(),
        "recv must materialize the Maildir new/ tree at {}",
        new_dir.display()
    );
    let entries: Vec<_> = fs::read_dir(&new_dir)
        .expect("read maildir new/")
        .filter_map(Result::ok)
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "exactly one delivered message expected; got {entries:?}",
    );
    let body = fs::read_to_string(entries[0].path()).expect("read maildir entry");
    assert!(
        body.contains("hello bob -- sent via dnsmesh send -t"),
        "delivered Maildir message must contain alice's plaintext; got:\n{body}",
    );
    // From: + Reply-To: must carry the resolved real address so a
    // mutt reply lands at alice's actual mailbox, not at a synthetic
    // `@dmp.local` nowhere-address. Regression guard.
    assert!(
        body.contains(&format!("From: {alice_address}")),
        "From: must carry alice's pinned address ({alice_address}); got:\n{body}",
    );
    assert!(
        body.contains(&format!("Reply-To: {alice_address}")),
        "Reply-To: must mirror From: so claws/older-mutt configs land right",
    );
    assert!(
        body.contains(&format!("X-DMP-Sender-Address: {alice_address}")),
        "X-DMP-Sender-Address breadcrumb must match the resolved From:",
    );
    assert!(
        !body.contains("@dmp.local"),
        "synthetic dmp.local placeholder must not appear when sender is pinned",
    );

    // Step 7 — second recv should be empty: the replay cache learned
    // (sender_spk, msg_id) on the first poll. Mirrors mutt's poll
    // loop where the second call after a successful one is a no-op.
    let out = bob(&["recv", "--maildir"])
        .arg(&maildir_root)
        .output()
        .expect("bob second recv");
    assert_ok("bob second recv", &out);
    let entries: Vec<_> = fs::read_dir(&new_dir)
        .expect("re-read maildir new/")
        .filter_map(Result::ok)
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "replay cache must keep recv idempotent; got {entries:?}",
    );
}

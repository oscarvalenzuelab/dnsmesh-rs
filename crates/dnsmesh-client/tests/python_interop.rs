//! Live Rust→Python interop round-trip test.
//!
//! "Interop test sends from Rust, reads with Python CLI" — the
//! milestone-3 gate. M1 already proved byte-equal wire format against
//! the Python source-of-truth via the `tests/interop` vectors; this
//! test exercises the full chunked-send + manifest-publish + decrypt
//! cycle across the language boundary.
//!
//! Flow:
//!   1. `python_interop_helper.py prepare` creates Bob (deterministic
//!      passphrase + salt) inside a Python InMemoryDNSStore, has Bob
//!      publish his identity card and a prekey RRset, dumps the store
//!      to JSON.
//!   2. The Rust test loads that JSON into a Rust `InMemoryDnsStore`,
//!      creates Alice, fetches Bob's identity, pins, calls
//!      `send_message`, and dumps the resulting store back to JSON.
//!   3. `python_interop_helper.py verify` recreates Bob with the same
//!      passphrase + salt (so the long-term X25519 secret matches and
//!      the prekey privates are still in Bob's local prekey store —
//!      generated deterministically from the Argon2 seed), loads the
//!      JSON, and asserts the Rust-published manifest decrypts to the
//!      expected plaintext.
//!
//! Gating: skipped unless `DNSMESH_PYTHON_INTEROP=1`. To run locally:
//!
//!   python3 -m venv ../.dmp-venv
//!   ../.dmp-venv/bin/pip install -e ../DNSMeshProtocol
//!   DNSMESH_PYTHON_INTEROP=1 \
//!     DNSMESH_PYTHON_BIN=$(pwd)/../.dmp-venv/bin/python3 \
//!     cargo test -p dnsmesh-client --test python_interop -- --nocapture
//!
//! `DNSMESH_PYTHON_BIN` defaults to `python3` if unset.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use dnsmesh_client::{DmpClient, DmpClientConfig};
use dnsmesh_net::{DnsRecordReader, DnsRecordWriter, InMemoryDnsStore};

/// On-disk JSON shape — matches the Python helper's output.
#[derive(Debug, Serialize, Deserialize)]
struct StoreSnapshot {
    /// `{name: [value, ...]}`. TTLs are not serialized; reload republishes
    /// at the test TTL below.
    records: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    bob: serde_json::Value,
}

const PUBLISH_TTL: u32 = 86_400; // matches the Python helper

/// Salt long enough for Argon2id and identical on both sides.
const ALICE_SALT: &[u8; 16] = b"interop-alice-sl";
const ALICE_PASSPHRASE: &str = "interop-test-alice-passphrase";
const ALICE_USERNAME: &str = "alice-interop";
const DOMAIN: &str = "mesh.local";

const PLAINTEXT: &[u8] = b"hello bob -- sent from rust, decrypted by python";

fn skip_if_disabled() -> bool {
    if std::env::var_os("DNSMESH_PYTHON_INTEROP").is_none() {
        eprintln!(
            "skipping python_interop test: set DNSMESH_PYTHON_INTEROP=1 \
             (and DNSMESH_PYTHON_BIN to a python with the dmp package installed) to run"
        );
        return true;
    }
    false
}

fn python_bin() -> String {
    std::env::var("DNSMESH_PYTHON_BIN").unwrap_or_else(|_| "python3".to_string())
}

fn helper_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/python_interop_helper.py")
}

fn run_python(workdir: &std::path::Path, args: &[&str]) -> (i32, String, String) {
    let helper = helper_path();
    let output = Command::new(python_bin())
        .arg(helper)
        .arg("--workdir")
        .arg(workdir)
        .args(args)
        .output()
        .expect("python helper must spawn");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (code, stdout, stderr)
}

async fn dump_store(store: &InMemoryDnsStore) -> StoreSnapshot {
    let mut records = BTreeMap::new();
    for name in store.list_names() {
        if let Some(values) = store.query_txt_record(&name).await.unwrap() {
            records.insert(name, values);
        }
    }
    StoreSnapshot {
        records,
        bob: serde_json::Value::Null,
    }
}

async fn load_store(store: &InMemoryDnsStore, snap: &StoreSnapshot) {
    for (name, values) in &snap.records {
        for v in values {
            store
                .publish_txt_record(name, v, PUBLISH_TTL)
                .await
                .unwrap();
        }
    }
}

#[tokio::test]
async fn rust_send_python_receive_round_trip() {
    if skip_if_disabled() {
        return;
    }

    let workdir = tempfile::tempdir().expect("tmpdir");

    // ---- Step 1: Python prepares Bob's published store -------------------
    let (code, stdout, stderr) = run_python(workdir.path(), &["prepare"]);
    assert_eq!(
        code, 0,
        "python prepare failed (exit {code}): stdout={stdout} stderr={stderr}"
    );
    let prepared_path = workdir.path().join("store-after-bob-publish.json");
    let prepared_json = std::fs::read_to_string(&prepared_path)
        .expect("python prepare must produce store-after-bob-publish.json");
    let prepared: StoreSnapshot =
        serde_json::from_str(&prepared_json).expect("python prepare output must be valid JSON");
    assert!(
        !prepared.records.is_empty(),
        "python prepare produced an empty store"
    );

    // ---- Step 2: Rust Alice sends to Bob ---------------------------------
    let store = Arc::new(InMemoryDnsStore::new());
    load_store(&store, &prepared).await;

    let cfg = DmpClientConfig {
        username: ALICE_USERNAME.to_string(),
        passphrase: ALICE_PASSPHRASE.to_string(),
        domain: DOMAIN.to_string(),
        kdf_salt: Some(ALICE_SALT.to_vec()),
        db_path: None,
        writer: store.clone() as Arc<dyn DnsRecordWriter>,
        reader: store.clone() as Arc<dyn DnsRecordReader>,
        rotation_chain_enabled: false,
    };
    let alice = DmpClient::new(cfg).await.expect("alice construction");

    // Alice publishes her own identity so Bob's receive flow can verify
    // her manifest signature against an in-zone identity record. (TOFU
    // also accepts any signature-valid manifest, but publishing is
    // closer to real usage and validates the publish path round-trip.)
    alice
        .publish_identity(false)
        .await
        .expect("publish_identity");
    alice
        .refresh_prekeys(5, u64::from(PUBLISH_TTL))
        .await
        .expect("refresh_prekeys");

    // Address must be `<bob-username>@<bob-domain>` to match what the
    // Python helper published. Both sides use `mesh.local`.
    let address = "bob-interop@mesh.local";
    let bob_contact = alice.fetch_identity(address).await.unwrap_or_else(|e| {
        panic!("alice.fetch_identity({address}) failed: {e}");
    });
    assert_eq!(bob_contact.username, "bob-interop");

    let added = alice
        .add_contact(bob_contact.clone())
        .await
        .expect("add_contact");
    assert!(added, "first add must report newly-added");

    let _msg_id = alice
        .send_message("bob-interop", PLAINTEXT)
        .await
        .expect("send_message");

    // ---- Step 3: Hand the post-send store to Python verify --------------
    let after = dump_store(&store).await;
    let after_path = workdir.path().join("store-after-alice-send.json");
    std::fs::write(&after_path, serde_json::to_string_pretty(&after).unwrap())
        .expect("write store-after-alice-send.json");

    let expect = std::str::from_utf8(PLAINTEXT).unwrap();
    let (code, stdout, stderr) =
        run_python(workdir.path(), &["verify", "--expect-plaintext", expect]);
    assert!(
        code == 0,
        "python verify failed (exit {code}): stdout={stdout} stderr={stderr}",
    );
    // Helper prints a JSON summary on stdout; sanity-check the count.
    let summary: serde_json::Value =
        serde_json::from_str(&stdout).expect("python verify must emit JSON summary");
    assert_eq!(
        summary["count"].as_u64(),
        Some(1),
        "expected exactly one delivered message; got: {stdout}"
    );
    assert_eq!(
        summary["messages"][0]["plaintext"].as_str(),
        Some(expect),
        "delivered plaintext does not match what alice sent",
    );
}

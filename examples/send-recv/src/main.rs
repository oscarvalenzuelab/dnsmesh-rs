//! Minimal end-to-end send + receive against an in-memory DNS store.
//!
//! Two `DmpClient`s — alice and bob — share an `InMemoryDnsStore`,
//! so reads and writes go through the same process-local backing
//! map instead of the live DNS path. This is the same harness used
//! in the workspace integration tests; the only thing that changes
//! when you point at real DNS is the reader / writer wiring.
//!
//! Run: `cargo run --release` (from this directory).

use std::sync::Arc;

use anyhow::Result;
use dnsmesh_client::{DmpClient, DmpClientConfig};
use dnsmesh_net::InMemoryDnsStore;

#[tokio::main]
async fn main() -> Result<()> {
    let store = Arc::new(InMemoryDnsStore::new());

    let alice = build_client("alice", "alice.example.com", store.clone()).await?;
    let bob = build_client("bob", "bob.example.com", store.clone()).await?;

    // Both publish their identity + a prekey pool.
    alice.publish_identity(false).await?;
    bob.publish_identity(false).await?;
    alice.refresh_prekeys(10, 3600).await?;
    bob.refresh_prekeys(10, 3600).await?;

    // Alice fetches Bob's identity and pins it as a contact.
    let bob_contact = alice.fetch_identity("bob@bob.example.com").await?;
    alice.add_contact(bob_contact).await?;

    // Bob does the symmetric thing so he can attribute Alice's send.
    let alice_contact = bob.fetch_identity("alice@alice.example.com").await?;
    bob.add_contact(alice_contact).await?;

    // Send.
    let msg_id = alice
        .send_message("bob", b"hello from the dnsmesh-rs send-recv example")
        .await?;
    println!("sent message {}", to_hex(&msg_id));

    // Receive on bob's side. The first call decrypts and returns
    // the message. A second call would hit the replay cache and
    // return an empty Vec — the protocol guarantees once-only
    // delivery on a per-(sender_spk, msg_id) basis.
    let inbox = bob.receive_messages().await?;
    assert_eq!(inbox.len(), 1, "exactly one message expected");
    let msg = &inbox[0];
    println!(
        "received from spk={} ({} bytes): {}",
        to_hex(&msg.sender_signing_pk),
        msg.plaintext.len(),
        String::from_utf8_lossy(&msg.plaintext),
    );

    let inbox_again = bob.receive_messages().await?;
    assert!(
        inbox_again.is_empty(),
        "second receive must hit the replay cache",
    );
    println!("replay cache held — second receive returned 0 messages");

    Ok(())
}

async fn build_client(name: &str, domain: &str, store: Arc<InMemoryDnsStore>) -> Result<DmpClient> {
    // Pad the username to a 16+ byte salt so Argon2id is happy.
    let mut salt = name.as_bytes().to_vec();
    while salt.len() < 16 {
        salt.push(b'.');
    }
    let cfg = DmpClientConfig {
        username: name.to_string(),
        passphrase: format!("example-passphrase-for-{name}"),
        domain: domain.to_string(),
        kdf_salt: Some(salt),
        db_path: None,
        writer: store.clone(),
        reader: store,
        rotation_chain_enabled: false,
    };
    Ok(DmpClient::new(cfg).await?)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

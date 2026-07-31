//! End-to-end integration tests for the M3 send + receive flow.
//!
//! Phase 2A pins down the publish + send path (manifest lands at the
//! recipient's slot, chunks at the derived chunk names). Phase 2B
//! extends this with the round-trip: bob calls `receive_messages()`,
//! decrypts the plaintext, and the second call sees the replay cache
//! drop the same message.

use std::sync::Arc;

use dnsmesh_client::addressing::{slot_domain, slot_for_msg_id, SLOT_COUNT};
use dnsmesh_client::{DmpClient, DmpClientConfig};
use dnsmesh_core::crypto::derive_user_id;
use dnsmesh_core::manifest::SlotManifest;
use dnsmesh_core::prekeys::prekey_rrset_name;
use dnsmesh_net::{DnsRecordReader, DnsRecordWriter, InMemoryDnsStore};

fn salt(prefix: &str) -> Vec<u8> {
    let mut s = prefix.as_bytes().to_vec();
    while s.len() < 16 {
        s.push(b'.');
    }
    s
}

async fn make_client(name: &str, store: Arc<InMemoryDnsStore>) -> DmpClient {
    make_client_in_zone(name, "mesh.local", store).await
}

async fn make_client_in_zone(name: &str, domain: &str, store: Arc<InMemoryDnsStore>) -> DmpClient {
    make_client_in_zone_with(name, domain, store, false).await
}

async fn make_client_in_zone_with(
    name: &str,
    domain: &str,
    store: Arc<InMemoryDnsStore>,
    rotation_chain_enabled: bool,
) -> DmpClient {
    let cfg = DmpClientConfig {
        username: name.to_string(),
        passphrase: format!("passphrase-for-{name}"),
        domain: domain.to_string(),
        kdf_salt: Some(salt(name)),
        db_path: None,
        writer: store.clone(),
        reader: store,
        rotation_chain_enabled,
    };
    DmpClient::new(cfg).await.expect("client construction")
}

#[tokio::test]
async fn alice_send_to_bob_publishes_chunks_and_manifest() {
    let store = Arc::new(InMemoryDnsStore::new());

    let alice = make_client("alice", store.clone()).await;
    let bob = make_client("bob", store.clone()).await;

    // Both publish identities + prekey pools.
    alice.publish_identity(false).await.unwrap();
    bob.publish_identity(false).await.unwrap();
    let n_alice = alice.refresh_prekeys(10, 3600).await.unwrap();
    let n_bob = bob.refresh_prekeys(10, 3600).await.unwrap();
    assert_eq!(n_alice, 10);
    assert_eq!(n_bob, 10);

    // Alice fetches bob's identity, pins him, then sends.
    let bob_contact = alice.fetch_identity("bob@mesh.local").await.unwrap();
    assert_eq!(bob_contact.username, "bob");
    assert_eq!(bob_contact.x25519_pk, bob.x25519_public_key_hex_bytes());
    assert_eq!(
        bob_contact.ed25519_spk,
        bob.ed25519_signing_public_key_hex_bytes()
    );

    let added = alice.add_contact(bob_contact.clone()).await.unwrap();
    assert!(added, "first add must report newly-added");

    let plaintext = b"hello bob from alice";
    let msg_id = alice.send_message("bob", plaintext).await.unwrap();

    // Manifest TXT must exist at the deterministic slot.
    let recipient_id = derive_user_id(&bob_contact.x25519_pk);
    let slot = slot_for_msg_id(&msg_id);
    assert!(slot < SLOT_COUNT);
    let slot_name = slot_domain(&recipient_id, slot, alice.domain());

    let records = store
        .query_txt_record(&slot_name)
        .await
        .unwrap()
        .expect("manifest TXT must exist after send");
    assert_eq!(records.len(), 1, "exactly one manifest at the slot");

    let (manifest, _sig) =
        SlotManifest::parse_and_verify(&records[0]).expect("manifest must verify under sender_spk");
    assert_eq!(manifest.msg_id, msg_id);
    assert_eq!(manifest.recipient_id, recipient_id);
    assert_eq!(
        manifest.sender_spk,
        alice.ed25519_signing_public_key_hex_bytes()
    );
    assert!(manifest.total_chunks >= manifest.data_chunks);
    assert!(manifest.data_chunks >= 1);
}

#[tokio::test]
async fn list_contacts_returns_pinned_entries() {
    let store = Arc::new(InMemoryDnsStore::new());
    let alice = make_client("alice2", store.clone()).await;
    let bob = make_client("bob2", store.clone()).await;
    bob.publish_identity(false).await.unwrap();
    let bob_contact = alice.fetch_identity("bob2@mesh.local").await.unwrap();
    alice.add_contact(bob_contact).await.unwrap();
    let listed = alice.list_contacts().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].username, "bob2");
}

#[tokio::test]
async fn add_contact_returns_false_on_overwrite() {
    let store = Arc::new(InMemoryDnsStore::new());
    let alice = make_client("alice3", store.clone()).await;
    let bob = make_client("bob3", store.clone()).await;
    bob.publish_identity(false).await.unwrap();
    let c = alice.fetch_identity("bob3@mesh.local").await.unwrap();
    assert!(alice.add_contact(c.clone()).await.unwrap());
    assert!(!alice.add_contact(c).await.unwrap());
}

#[tokio::test]
async fn fetch_identity_rejects_malformed_address() {
    let store = Arc::new(InMemoryDnsStore::new());
    let alice = make_client("alice4", store).await;
    let err = alice.fetch_identity("not-an-address").await.unwrap_err();
    let s = format!("{err}");
    assert!(s.contains("invalid address"), "got {s}");
}

#[tokio::test]
async fn fetch_identity_returns_no_record_when_absent() {
    let store = Arc::new(InMemoryDnsStore::new());
    let alice = make_client("alice5", store).await;
    let err = alice.fetch_identity("ghost@mesh.local").await.unwrap_err();
    let s = format!("{err}");
    assert!(s.contains("no records"), "got {s}");
}

#[tokio::test]
async fn send_message_rejects_unknown_contact() {
    let store = Arc::new(InMemoryDnsStore::new());
    let alice = make_client("alice6", store).await;
    let err = alice.send_message("nobody", b"x").await.unwrap_err();
    let s = format!("{err}");
    assert!(s.contains("not pinned"), "got {s}");
}

#[tokio::test]
async fn alice_to_bob_round_trip_with_replay_dedup() {
    // Full M3 round-trip: both publish, both pin each other, alice
    // sends, bob receives, second receive returns nothing because the
    // replay cache deduplicates.
    let store = Arc::new(InMemoryDnsStore::new());

    let alice = make_client("alice-rt", store.clone()).await;
    let bob = make_client("bob-rt", store.clone()).await;

    alice.publish_identity(false).await.unwrap();
    bob.publish_identity(false).await.unwrap();
    alice.refresh_prekeys(10, 3600).await.unwrap();
    bob.refresh_prekeys(10, 3600).await.unwrap();

    // Bidirectional pin so neither side falls back to TOFU.
    let bob_contact = alice.fetch_identity("bob-rt@mesh.local").await.unwrap();
    let alice_contact = bob.fetch_identity("alice-rt@mesh.local").await.unwrap();
    alice.add_contact(bob_contact.clone()).await.unwrap();
    bob.add_contact(alice_contact.clone()).await.unwrap();

    let plaintext = b"hello bob from alice";
    let _msg_id = alice.send_message("bob-rt", plaintext).await.unwrap();

    let inbox = bob.receive_messages().await.unwrap();
    assert_eq!(inbox.len(), 1, "bob must see exactly one new message");
    assert_eq!(inbox[0].plaintext, plaintext);
    assert_eq!(
        inbox[0].sender_signing_pk,
        alice.ed25519_signing_public_key_hex_bytes(),
        "delivered sender_signing_pk must match alice's verifying key",
    );

    // Second poll: replay cache must drop the same (sender_spk, msg_id).
    let inbox_again = bob.receive_messages().await.unwrap();
    assert!(
        inbox_again.is_empty(),
        "replay cache must dedupe; got {inbox_again:?}",
    );
}

#[tokio::test]
async fn tofu_mode_accepts_signature_valid_manifest_without_pinning() {
    // Bob has zero pinned contacts. Alice still sends successfully
    // (bob isn't on alice's contact list either, but alice DOES need
    // to pin bob to send — that's a sender-side requirement, not a
    // receiver-side one). The receive path must accept any
    // signature-valid manifest in TOFU mode.
    let store = Arc::new(InMemoryDnsStore::new());

    let alice = make_client("alice-tofu", store.clone()).await;
    let bob = make_client("bob-tofu", store.clone()).await;

    alice.publish_identity(false).await.unwrap();
    bob.publish_identity(false).await.unwrap();
    alice.refresh_prekeys(10, 3600).await.unwrap();
    bob.refresh_prekeys(10, 3600).await.unwrap();

    // Alice pins bob (sender-side requirement).
    let bob_contact = alice.fetch_identity("bob-tofu@mesh.local").await.unwrap();
    alice.add_contact(bob_contact).await.unwrap();
    // Bob deliberately does NOT pin alice — TOFU mode.
    assert!(bob.list_contacts().await.unwrap().is_empty());

    let plaintext = b"first contact in tofu mode";
    alice.send_message("bob-tofu", plaintext).await.unwrap();

    let inbox = bob.receive_messages().await.unwrap();
    assert_eq!(
        inbox.len(),
        1,
        "TOFU mode must accept any signature-valid manifest",
    );
    assert_eq!(inbox[0].plaintext, plaintext);
    assert_eq!(
        inbox[0].sender_signing_pk,
        alice.ed25519_signing_public_key_hex_bytes(),
    );
}

#[tokio::test]
async fn pinned_mode_drops_manifest_from_unknown_sender() {
    // Bob pins charlie (some unrelated contact) but not alice. When
    // alice sends, the receive path must NOT deliver to bob's inbox —
    // the message gets quarantined into the intro queue instead.
    let store = Arc::new(InMemoryDnsStore::new());

    let alice = make_client("alice-strict", store.clone()).await;
    let bob = make_client("bob-strict", store.clone()).await;
    let charlie = make_client("charlie-strict", store.clone()).await;

    alice.publish_identity(false).await.unwrap();
    bob.publish_identity(false).await.unwrap();
    charlie.publish_identity(false).await.unwrap();
    alice.refresh_prekeys(10, 3600).await.unwrap();
    bob.refresh_prekeys(10, 3600).await.unwrap();

    // Alice pins bob so she can send to him.
    let bob_contact = alice.fetch_identity("bob-strict@mesh.local").await.unwrap();
    alice.add_contact(bob_contact).await.unwrap();

    // Bob pins charlie — anyone, just so he's NOT in TOFU mode.
    let charlie_contact = bob
        .fetch_identity("charlie-strict@mesh.local")
        .await
        .unwrap();
    bob.add_contact(charlie_contact).await.unwrap();

    alice
        .send_message("bob-strict", b"should be quarantined")
        .await
        .unwrap();

    let inbox = bob.receive_messages().await.unwrap();
    assert!(
        inbox.is_empty(),
        "pinned-mode must NOT deliver un-pinned manifests to the inbox; got {inbox:?}",
    );

    // The message is in the intro queue instead of dropped.
    let pending = bob.list_intros().await.unwrap();
    assert_eq!(
        pending.len(),
        1,
        "un-pinned manifest must land in intro queue"
    );
    assert_eq!(pending[0].payload, b"should be quarantined");
    assert_eq!(
        pending[0].sender_spk,
        alice.ed25519_signing_public_key_hex_bytes().to_vec(),
    );
}

#[tokio::test]
async fn accept_intro_promotes_payload_without_pinning_sender() {
    let store = Arc::new(InMemoryDnsStore::new());

    let alice = make_client("alice-aci", store.clone()).await;
    let bob = make_client("bob-aci", store.clone()).await;
    let charlie = make_client("charlie-aci", store.clone()).await;

    alice.publish_identity(false).await.unwrap();
    bob.publish_identity(false).await.unwrap();
    charlie.publish_identity(false).await.unwrap();
    alice.refresh_prekeys(10, 3600).await.unwrap();
    bob.refresh_prekeys(10, 3600).await.unwrap();

    let bob_contact = alice.fetch_identity("bob-aci@mesh.local").await.unwrap();
    alice.add_contact(bob_contact).await.unwrap();

    let charlie_contact = bob.fetch_identity("charlie-aci@mesh.local").await.unwrap();
    bob.add_contact(charlie_contact).await.unwrap();

    alice
        .send_message("bob-aci", b"hi from alice")
        .await
        .unwrap();
    bob.receive_messages().await.unwrap(); // quarantines

    let intro_id = bob.list_intros().await.unwrap()[0].intro_id;
    let delivered = bob
        .accept_intro(intro_id)
        .await
        .unwrap()
        .expect("intro must be present");
    assert_eq!(delivered.intro_id, intro_id);
    assert_eq!(delivered.message.plaintext, b"hi from alice");
    assert_eq!(
        delivered.message.sender_signing_pk,
        alice.ed25519_signing_public_key_hex_bytes(),
    );

    // Queue is empty + sender is NOT pinned (accept ≠ trust).
    assert!(bob.list_intros().await.unwrap().is_empty());
    let names: Vec<_> = bob
        .list_contacts()
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.username)
        .collect();
    assert!(
        !names.contains(&"alice-aci".to_string()),
        "accept must NOT add the sender as a contact",
    );
}

#[tokio::test]
async fn trust_intro_pins_sender_and_promotes_payload() {
    let store = Arc::new(InMemoryDnsStore::new());

    let alice = make_client("alice-trust", store.clone()).await;
    let bob = make_client("bob-trust", store.clone()).await;
    let charlie = make_client("charlie-trust", store.clone()).await;

    alice.publish_identity(false).await.unwrap();
    bob.publish_identity(false).await.unwrap();
    charlie.publish_identity(false).await.unwrap();
    alice.refresh_prekeys(10, 3600).await.unwrap();
    bob.refresh_prekeys(10, 3600).await.unwrap();

    let bob_contact = alice.fetch_identity("bob-trust@mesh.local").await.unwrap();
    alice.add_contact(bob_contact).await.unwrap();
    let charlie_contact = bob
        .fetch_identity("charlie-trust@mesh.local")
        .await
        .unwrap();
    bob.add_contact(charlie_contact).await.unwrap();

    alice
        .send_message("bob-trust", b"first contact")
        .await
        .unwrap();
    bob.receive_messages().await.unwrap();

    let intro_id = bob.list_intros().await.unwrap()[0].intro_id;
    let delivered = bob
        .trust_intro(intro_id, "alice-trust@mesh.local")
        .await
        .unwrap()
        .expect("intro must promote");
    assert_eq!(delivered.message.plaintext, b"first contact");

    // Alice is now pinned; queue is empty.
    let names: Vec<_> = bob
        .list_contacts()
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.username)
        .collect();
    assert!(
        names.contains(&"alice-trust".to_string()),
        "trust must pin the sender (got {names:?})",
    );
    assert!(bob.list_intros().await.unwrap().is_empty());

    // Subsequent messages from alice now go straight to inbox without
    // quarantine.
    alice
        .send_message("bob-trust", b"second message")
        .await
        .unwrap();
    let inbox = bob.receive_messages().await.unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].plaintext, b"second message");
    assert!(bob.list_intros().await.unwrap().is_empty());
}

#[tokio::test]
async fn block_intro_denylists_future_messages_from_same_sender() {
    let store = Arc::new(InMemoryDnsStore::new());

    let alice = make_client("alice-blk", store.clone()).await;
    let bob = make_client("bob-blk", store.clone()).await;
    let charlie = make_client("charlie-blk", store.clone()).await;

    alice.publish_identity(false).await.unwrap();
    bob.publish_identity(false).await.unwrap();
    charlie.publish_identity(false).await.unwrap();
    alice.refresh_prekeys(10, 3600).await.unwrap();
    bob.refresh_prekeys(10, 3600).await.unwrap();

    let bob_contact = alice.fetch_identity("bob-blk@mesh.local").await.unwrap();
    alice.add_contact(bob_contact).await.unwrap();
    let charlie_contact = bob.fetch_identity("charlie-blk@mesh.local").await.unwrap();
    bob.add_contact(charlie_contact).await.unwrap();

    alice
        .send_message("bob-blk", b"abusive ping")
        .await
        .unwrap();
    bob.receive_messages().await.unwrap();

    let intro_id = bob.list_intros().await.unwrap()[0].intro_id;
    assert!(bob.block_intro(intro_id, "abusive sender").await.unwrap());
    assert!(bob.list_intros().await.unwrap().is_empty());

    // A second message from alice now never even reaches the queue.
    alice
        .send_message("bob-blk", b"second abusive ping")
        .await
        .unwrap();
    let inbox = bob.receive_messages().await.unwrap();
    assert!(inbox.is_empty(), "blocked sender must not reach inbox");
    let pending = bob.list_intros().await.unwrap();
    assert!(
        pending.is_empty(),
        "blocked sender must not re-queue; got {pending:?}",
    );
}

#[tokio::test]
async fn second_receive_does_not_double_quarantine() {
    // After receive quarantines a message, polling a second time
    // should NOT add the same row again. Replay cache dedupes the
    // intro queue too, not just the inbox.
    let store = Arc::new(InMemoryDnsStore::new());
    let alice = make_client("alice-dq", store.clone()).await;
    let bob = make_client("bob-dq", store.clone()).await;
    let charlie = make_client("charlie-dq", store.clone()).await;

    alice.publish_identity(false).await.unwrap();
    bob.publish_identity(false).await.unwrap();
    charlie.publish_identity(false).await.unwrap();
    alice.refresh_prekeys(10, 3600).await.unwrap();
    bob.refresh_prekeys(10, 3600).await.unwrap();

    let bob_contact = alice.fetch_identity("bob-dq@mesh.local").await.unwrap();
    alice.add_contact(bob_contact).await.unwrap();
    let charlie_contact = bob.fetch_identity("charlie-dq@mesh.local").await.unwrap();
    bob.add_contact(charlie_contact).await.unwrap();

    alice.send_message("bob-dq", b"hello").await.unwrap();

    bob.receive_messages().await.unwrap();
    bob.receive_messages().await.unwrap();
    bob.receive_messages().await.unwrap();

    let pending = bob.list_intros().await.unwrap();
    assert_eq!(
        pending.len(),
        1,
        "replay cache must dedup re-discovered manifests; got {pending:?}",
    );
}

#[tokio::test]
async fn receive_consumes_published_prekey_record() {
    // When receive successfully decrypts a message that used a
    // recipient prekey, both the local sqlite row AND the published
    // TXT record must drop. Without the DNS delete, future senders
    // would still pick that prekey from the live RRset and encrypt
    // to a public key whose secret has been wiped — making every
    // subsequent message undecryptable.
    let store = Arc::new(InMemoryDnsStore::new());

    let alice = make_client("alice-pkc", store.clone()).await;
    let bob = make_client("bob-pkc", store.clone()).await;

    alice.publish_identity(false).await.unwrap();
    bob.publish_identity(false).await.unwrap();
    alice.refresh_prekeys(3, 3600).await.unwrap();
    let n = bob.refresh_prekeys(3, 3600).await.unwrap();
    assert_eq!(n, 3);

    // Bob's prekey RRset starts at 3.
    let bob_prekey_name = prekey_rrset_name("bob-pkc", bob.domain());
    let before = store
        .query_txt_record(&bob_prekey_name)
        .await
        .unwrap()
        .expect("bob's prekey RRset must exist after refresh");
    assert_eq!(before.len(), 3, "expected 3 published prekeys before send");

    // Alice pins bob, sends, bob receives.
    let bob_contact = alice.fetch_identity("bob-pkc@mesh.local").await.unwrap();
    let alice_contact = bob.fetch_identity("alice-pkc@mesh.local").await.unwrap();
    alice.add_contact(bob_contact).await.unwrap();
    bob.add_contact(alice_contact).await.unwrap();

    alice
        .send_message("bob-pkc", b"prekey consume me")
        .await
        .unwrap();
    let inbox = bob.receive_messages().await.unwrap();
    assert_eq!(inbox.len(), 1);

    // Bob's prekey RRset must now have exactly one fewer entry — the
    // one used by alice's manifest.
    let after = store
        .query_txt_record(&bob_prekey_name)
        .await
        .unwrap()
        .expect("RRset must still exist with two remaining entries");
    assert_eq!(
        after.len(),
        2,
        "consume_prekey must DELETE the published TXT in addition to the local row",
    );
}

#[tokio::test]
async fn cross_zone_send_and_receive_round_trip() {
    // Alice and bob live in different zones. The SENDER publishes
    // the manifest under the SENDER's zone (Python `_slot_domain`
    // defaults to `self.domain`; the Rust send.rs publishes at
    // `slot_domain(&recipient_id, slot, &self.domain)`). Without
    // cross-zone receive, bob would only walk `bob.zone` and never
    // see alice's manifest at `alice.zone`. With the fix, bob's
    // receive walks `[bob.zone, alice.zone]` (own zone + pinned-
    // contact zone) and the round-trip succeeds.
    let store = Arc::new(InMemoryDnsStore::new());

    let alice = make_client_in_zone("alice-xz", "alice.zone", store.clone()).await;
    let bob = make_client_in_zone("bob-xz", "bob.zone", store.clone()).await;

    alice.publish_identity(false).await.unwrap();
    bob.publish_identity(false).await.unwrap();
    alice.refresh_prekeys(5, 3600).await.unwrap();
    bob.refresh_prekeys(5, 3600).await.unwrap();

    // Each fetches the other (parse_address gives us the zone) and
    // pins. Contact.domain is populated from the host part of the
    // user@host address — see contacts.rs::fetch_identity.
    let bob_contact = alice.fetch_identity("bob-xz@bob.zone").await.unwrap();
    assert_eq!(bob_contact.domain, "bob.zone");
    alice.add_contact(bob_contact.clone()).await.unwrap();

    let alice_contact = bob.fetch_identity("alice-xz@alice.zone").await.unwrap();
    assert_eq!(
        alice_contact.domain, "alice.zone",
        "fetch_identity must populate the contact's home zone for cross-zone receive",
    );
    bob.add_contact(alice_contact).await.unwrap();

    // Alice sends. Manifest publishes under alice.zone (sender's zone),
    // not bob.zone — confirm by querying bob's slot under alice.zone.
    let plaintext = b"cross-zone payload";
    let msg_id = alice.send_message("bob-xz", plaintext).await.unwrap();
    let bob_id = derive_user_id(&bob.x25519_public_key_hex_bytes());
    let slot = slot_for_msg_id(&msg_id);
    let manifest_at_alice_zone = store
        .query_txt_record(&slot_domain(&bob_id, slot, "alice.zone"))
        .await
        .unwrap();
    assert!(
        manifest_at_alice_zone.is_some(),
        "manifest must land in the SENDER's zone (alice.zone), not the recipient's",
    );
    let manifest_at_bob_zone = store
        .query_txt_record(&slot_domain(&bob_id, slot, "bob.zone"))
        .await
        .unwrap();
    assert!(
        manifest_at_bob_zone.is_none(),
        "manifest must not land in bob.zone — Python parity check",
    );

    // Bob receives. Without the cross-zone walk this returns empty;
    // with it, the message decrypts cleanly.
    let inbox = bob.receive_messages().await.unwrap();
    assert_eq!(
        inbox.len(),
        1,
        "cross-zone walk must surface alice.zone manifest from bob's poll",
    );
    assert_eq!(inbox[0].plaintext, plaintext);
    assert_eq!(
        inbox[0].sender_signing_pk,
        alice.ed25519_signing_public_key_hex_bytes(),
    );

    // Second poll: replay cache must dedupe regardless of source zone.
    let inbox_again = bob.receive_messages().await.unwrap();
    assert!(inbox_again.is_empty());
}

#[tokio::test]
async fn send_message_with_claim_publishes_both_manifest_and_claim() {
    use dnsmesh_core::claim::{claim_rrset_name, ClaimRecord};

    let store = Arc::new(InMemoryDnsStore::new());

    let alice = make_client("alice-claim-pub", store.clone()).await;
    let bob = make_client("bob-claim-pub", store.clone()).await;

    alice.publish_identity(false).await.unwrap();
    bob.publish_identity(false).await.unwrap();
    alice.refresh_prekeys(5, 3600).await.unwrap();
    bob.refresh_prekeys(5, 3600).await.unwrap();

    let bob_contact = alice
        .fetch_identity("bob-claim-pub@mesh.local")
        .await
        .unwrap();
    alice.add_contact(bob_contact.clone()).await.unwrap();

    let provider_zone = "provider.example.com";
    let sent = alice
        .send_message_with_claim(
            "bob-claim-pub",
            b"hello via claim provider",
            &[provider_zone],
        )
        .await
        .unwrap();
    assert!(
        sent.all_claims_published(),
        "in-memory writer accepts every zone, so no claim should fail: {:?}",
        sent.claim_failures,
    );
    let msg_id = sent.msg_id;

    // Manifest still lands at the sender's mailbox slot (alice is the
    // sender; recipient_id is derived from bob's X25519 PK; alice
    // publishes under her own zone).
    let recipient_id = derive_user_id(&bob_contact.x25519_pk);
    let slot = slot_for_msg_id(&msg_id);
    assert!(slot < SLOT_COUNT);
    let manifest_records = store
        .query_txt_record(&slot_domain(&recipient_id, slot, "mesh.local"))
        .await
        .unwrap();
    assert!(
        manifest_records.is_some(),
        "manifest must still publish to the sender's slot",
    );

    // Claim landed at the provider zone with the same recipient_id +
    // slot. We narrow the u32 slot to u8 because the claim label uses
    // the byte form.
    let claim_slot = u8::try_from(slot).unwrap();
    let claim_name = claim_rrset_name(&recipient_id, claim_slot, provider_zone).unwrap();
    let claim_records = store
        .query_txt_record(&claim_name)
        .await
        .unwrap()
        .expect("claim TXT must exist at provider zone");
    assert_eq!(claim_records.len(), 1, "exactly one claim per provider");
    let parsed =
        ClaimRecord::parse_and_verify(&claim_records[0], None, 60).expect("claim must verify");
    assert_eq!(parsed.msg_id, msg_id);
    assert_eq!(
        parsed.sender_spk,
        alice.ed25519_signing_public_key_hex_bytes(),
    );
    assert_eq!(parsed.sender_mailbox_domain, "mesh.local");
    assert_eq!(parsed.slot, claim_slot);
}

#[tokio::test]
async fn receive_via_claim_decrypts_and_routes_to_inbox() {
    let store = Arc::new(InMemoryDnsStore::new());

    let alice = make_client("alice-rvc", store.clone()).await;
    let bob = make_client("bob-rvc", store.clone()).await;

    alice.publish_identity(false).await.unwrap();
    bob.publish_identity(false).await.unwrap();
    alice.refresh_prekeys(5, 3600).await.unwrap();
    bob.refresh_prekeys(5, 3600).await.unwrap();

    // Bidirectional pin so bob's receive_via_claim routes to inbox,
    // not the intro queue.
    let bob_contact = alice.fetch_identity("bob-rvc@mesh.local").await.unwrap();
    let alice_contact = bob.fetch_identity("alice-rvc@mesh.local").await.unwrap();
    alice.add_contact(bob_contact.clone()).await.unwrap();
    bob.add_contact(alice_contact.clone()).await.unwrap();

    let provider_zone = "provider.example.com";
    alice
        .send_message_with_claim("bob-rvc", b"hello via claim", &[provider_zone])
        .await
        .unwrap();

    let inbox = bob.receive_via_claim(provider_zone).await.unwrap();
    assert_eq!(inbox.len(), 1, "claim path must deliver pinned message");
    assert_eq!(inbox[0].plaintext, b"hello via claim");
    assert_eq!(
        inbox[0].sender_signing_pk,
        alice.ed25519_signing_public_key_hex_bytes(),
    );

    // Replay cache: a second poll on the same provider zone returns
    // nothing because the (sender_spk, msg_id) is already recorded.
    let again = bob.receive_via_claim(provider_zone).await.unwrap();
    assert!(again.is_empty(), "claim path must dedup via replay cache");
}

#[tokio::test]
async fn receive_via_claim_quarantines_unpinned_sender() {
    let store = Arc::new(InMemoryDnsStore::new());

    let alice = make_client("alice-rvcq", store.clone()).await;
    let bob = make_client("bob-rvcq", store.clone()).await;
    let charlie = make_client("charlie-rvcq", store.clone()).await;

    alice.publish_identity(false).await.unwrap();
    bob.publish_identity(false).await.unwrap();
    charlie.publish_identity(false).await.unwrap();
    alice.refresh_prekeys(5, 3600).await.unwrap();
    bob.refresh_prekeys(5, 3600).await.unwrap();

    // Alice pins bob (sender-side requirement).
    let bob_contact = alice.fetch_identity("bob-rvcq@mesh.local").await.unwrap();
    alice.add_contact(bob_contact).await.unwrap();
    // Bob pins charlie — anyone, just so he's NOT in TOFU mode.
    let charlie_contact = bob.fetch_identity("charlie-rvcq@mesh.local").await.unwrap();
    bob.add_contact(charlie_contact).await.unwrap();

    let provider_zone = "provider.example.com";
    alice
        .send_message_with_claim("bob-rvcq", b"first contact via claim", &[provider_zone])
        .await
        .unwrap();

    let inbox = bob.receive_via_claim(provider_zone).await.unwrap();
    assert!(
        inbox.is_empty(),
        "claim path must NOT deliver un-pinned manifests to the inbox; got {inbox:?}",
    );
    let pending = bob.list_intros().await.unwrap();
    assert_eq!(
        pending.len(),
        1,
        "claim path must quarantine un-pinned senders; got {pending:?}",
    );
    assert_eq!(pending[0].payload, b"first contact via claim");
}

#[tokio::test]
async fn rotation_chain_walks_to_new_key_when_enabled() {
    // Bob pins alice-old. Alice rotates to alice-new and publishes a
    // co-signed RotationRecord at her rotation RRset. Alice-new sends.
    // With rotation_chain_enabled=true bob's receive walks the chain
    // and delivers the manifest signed by alice-new directly to the
    // inbox; with the flag off the same setup quarantines (un-pinned
    // sender) instead.
    use dnsmesh_core::crypto::DmpCrypto;
    use dnsmesh_core::rotation::{
        rotation_rrset_name_zone_anchored, RotationRecord, SUBJECT_TYPE_USER_IDENTITY,
    };

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    let store = Arc::new(InMemoryDnsStore::new());

    // Two alice identities, same username + zone (rotation IS a key
    // change, not a user change). Different passphrases give different
    // (X25519, Ed25519) keypairs from the Argon2 KDF.
    let alice_old = make_client_in_zone("alice-rot", "mesh.local", store.clone()).await;
    // alice_new uses a different passphrase via the lower-level helper
    // so the resulting client has the same username but a different
    // signing key.
    let alice_new_cfg = DmpClientConfig {
        username: "alice-rot".to_string(),
        passphrase: "rotated-passphrase-v2".to_string(),
        domain: "mesh.local".to_string(),
        kdf_salt: Some(b"alice-rot-new!!!".to_vec()),
        db_path: None,
        writer: store.clone(),
        reader: store.clone(),
        rotation_chain_enabled: false,
    };
    let alice_new = DmpClient::new(alice_new_cfg).await.unwrap();

    // alice-new publishes her current identity record so bob can fetch
    // it if needed (the rotation chain walk doesn't require it, but
    // we want a complete world). alice-old publishes too so bob's
    // initial fetch picks up alice-old's keys.
    alice_old.publish_identity(false).await.unwrap();
    // Different identity record at the SAME identity name as alice-old.
    // The InMemoryDnsStore RRset semantics let both records co-exist;
    // the receive flow (and rotation walker) verify each independently.
    alice_new.publish_identity(false).await.unwrap();
    alice_new.refresh_prekeys(5, 3600).await.unwrap();

    // Rebuild the two crypto handles directly so we can sign the
    // RotationRecord. Argon2 is deterministic from (passphrase, salt),
    // so DmpCrypto::from_passphrase reproduces alice_old and alice_new
    // bit-for-bit. This avoids exposing DmpClient.crypto publicly.
    let mut s_old = b"alice-rot".to_vec();
    while s_old.len() < 16 {
        s_old.push(b'.');
    }
    let crypto_old = DmpCrypto::from_passphrase("passphrase-for-alice-rot", Some(&s_old)).unwrap();
    let crypto_new =
        DmpCrypto::from_passphrase("rotated-passphrase-v2", Some(b"alice-rot-new!!!")).unwrap();
    let old_spk = crypto_old.signing_public_key_bytes();
    let new_spk = crypto_new.signing_public_key_bytes();
    assert_ne!(old_spk, new_spk, "old and new keys must differ");

    // Build + sign a RotationRecord pointing alice-old → alice-new.
    let now = unix_now();
    let record = RotationRecord {
        subject_type: SUBJECT_TYPE_USER_IDENTITY,
        subject: "alice-rot@mesh.local".to_string(),
        old_spk,
        new_spk,
        seq: 1,
        ts: now,
        exp: now + 3600,
    };
    let wire = record.sign(&crypto_old, &crypto_new).unwrap();
    let rotation_name = rotation_rrset_name_zone_anchored("mesh.local");
    store
        .publish_txt_record(&rotation_name, &wire, 3600)
        .await
        .unwrap();

    // Bob — note that we open him with rotation_chain_enabled = true.
    let bob = make_client_in_zone_with("bob-rot", "mesh.local", store.clone(), true).await;
    bob.publish_identity(false).await.unwrap();
    bob.refresh_prekeys(5, 3600).await.unwrap();

    // Bob pins ALICE-OLD (the key he originally onboarded against).
    // Note: alice-old has a different username under the hood —
    // actually, both alice clients share the same username "alice-rot"
    // because rotation is a key change at the same identity. We pin
    // by fetching identity records; the in-memory RRset has both
    // records for alice-rot (old + new). Bob's pin captures whichever
    // verifies first; because of RRset ordering we explicitly use the
    // old crypto to construct the contact.
    let bob_pins_alice_old = dnsmesh_client::Contact {
        username: "alice-rot".to_string(),
        x25519_pk: hex::decode(alice_old.x25519_public_key_hex())
            .unwrap()
            .try_into()
            .unwrap(),
        ed25519_spk: old_spk,
        domain: "mesh.local".to_string(),
    };
    bob.add_contact(bob_pins_alice_old).await.unwrap();

    // alice-old fetches bob and pins him so alice can send.
    let bob_contact = alice_new
        .fetch_identity("bob-rot@mesh.local")
        .await
        .unwrap();
    alice_new.add_contact(bob_contact).await.unwrap();

    // alice-new (the rotated key) sends to bob.
    alice_new
        .send_message("bob-rot", b"hello after rotation")
        .await
        .unwrap();

    let inbox = bob.receive_messages().await.unwrap();
    assert_eq!(
        inbox.len(),
        1,
        "rotation chain walk must surface alice-new's manifest as if pinned",
    );
    assert_eq!(inbox[0].plaintext, b"hello after rotation");
    assert_eq!(
        inbox[0].sender_signing_pk, new_spk,
        "delivered sender_signing_pk is the new key, not the pinned old one",
    );
    assert!(
        bob.list_intros().await.unwrap().is_empty(),
        "rotation acceptance routes to inbox, not the intro queue",
    );
}

#[tokio::test]
async fn rotation_chain_disabled_quarantines_rotated_key() {
    // Same setup as the previous test but rotation_chain_enabled =
    // false on bob. The same rotated-key manifest now lands in the
    // intro queue because the chain walker never runs.
    use dnsmesh_core::crypto::DmpCrypto;
    use dnsmesh_core::rotation::{
        rotation_rrset_name_zone_anchored, RotationRecord, SUBJECT_TYPE_USER_IDENTITY,
    };

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    let store = Arc::new(InMemoryDnsStore::new());
    let alice_old = make_client_in_zone("alice-nrot", "mesh.local", store.clone()).await;
    let alice_new_cfg = DmpClientConfig {
        username: "alice-nrot".to_string(),
        passphrase: "rotated-passphrase-no-chain".to_string(),
        domain: "mesh.local".to_string(),
        kdf_salt: Some(b"alice-nrot-new..".to_vec()),
        db_path: None,
        writer: store.clone(),
        reader: store.clone(),
        rotation_chain_enabled: false,
    };
    let alice_new = DmpClient::new(alice_new_cfg).await.unwrap();
    alice_old.publish_identity(false).await.unwrap();
    alice_new.publish_identity(false).await.unwrap();
    alice_new.refresh_prekeys(5, 3600).await.unwrap();

    let mut s_old = b"alice-nrot".to_vec();
    while s_old.len() < 16 {
        s_old.push(b'.');
    }
    let crypto_old = DmpCrypto::from_passphrase("passphrase-for-alice-nrot", Some(&s_old)).unwrap();
    let crypto_new =
        DmpCrypto::from_passphrase("rotated-passphrase-no-chain", Some(b"alice-nrot-new.."))
            .unwrap();
    let old_spk = crypto_old.signing_public_key_bytes();
    let new_spk = crypto_new.signing_public_key_bytes();

    let now = unix_now();
    let record = RotationRecord {
        subject_type: SUBJECT_TYPE_USER_IDENTITY,
        subject: "alice-nrot@mesh.local".to_string(),
        old_spk,
        new_spk,
        seq: 1,
        ts: now,
        exp: now + 3600,
    };
    let wire = record.sign(&crypto_old, &crypto_new).unwrap();
    let rotation_name = rotation_rrset_name_zone_anchored("mesh.local");
    store
        .publish_txt_record(&rotation_name, &wire, 3600)
        .await
        .unwrap();

    // bob with rotation_chain_enabled = false (default).
    let bob = make_client_in_zone("bob-nrot", "mesh.local", store.clone()).await;
    bob.publish_identity(false).await.unwrap();
    bob.refresh_prekeys(5, 3600).await.unwrap();
    let bob_pins_alice_old = dnsmesh_client::Contact {
        username: "alice-nrot".to_string(),
        x25519_pk: hex::decode(alice_old.x25519_public_key_hex())
            .unwrap()
            .try_into()
            .unwrap(),
        ed25519_spk: old_spk,
        domain: "mesh.local".to_string(),
    };
    bob.add_contact(bob_pins_alice_old).await.unwrap();

    let bob_contact = alice_new
        .fetch_identity("bob-nrot@mesh.local")
        .await
        .unwrap();
    alice_new.add_contact(bob_contact).await.unwrap();

    alice_new
        .send_message("bob-nrot", b"rotated message but flag off")
        .await
        .unwrap();

    let inbox = bob.receive_messages().await.unwrap();
    assert!(
        inbox.is_empty(),
        "without rotation_chain_enabled, rotated-key manifest must NOT land in inbox; got {inbox:?}",
    );
    let pending = bob.list_intros().await.unwrap();
    assert_eq!(
        pending.len(),
        1,
        "without the flag, the rotated-key manifest is treated as un-pinned and quarantined",
    );
}

#[tokio::test]
async fn rotation_chain_revocation_check_fails_closed_on_dns_error() {
    // When rotation_chain_enabled is true and a pinned-key manifest
    // arrives, the receive flow MUST drop on a failing revocation
    // RRset query rather than silently fall through to "no revocation
    // found, deliver". Without this, a DNS provider that can
    // selectively fail the rotate.* RRset can keep a revoked pinned
    // key delivering past its revocation.
    //
    // We build a wrapper reader that proxies the legitimate store but
    // fails reads of the rotation-RRset names. With that reader bob's
    // receive must NOT deliver alice's manifest.
    use async_trait::async_trait;
    use dnsmesh_core::rotation::{
        rotation_rrset_name_user_identity, rotation_rrset_name_zone_anchored,
    };
    use dnsmesh_net::error::NetError;

    struct RotationFailingReader {
        inner: Arc<InMemoryDnsStore>,
        fail_names: Vec<String>,
    }

    #[async_trait]
    impl DnsRecordReader for RotationFailingReader {
        async fn query_txt_record(&self, name: &str) -> Result<Option<Vec<String>>, NetError> {
            if self.fail_names.iter().any(|n| n == name) {
                return Err(NetError::Transport(format!(
                    "synthetic dns failure for {name}"
                )));
            }
            self.inner.query_txt_record(name).await
        }
    }

    let store = Arc::new(InMemoryDnsStore::new());

    // Two clients pinned bidirectionally so the receive path goes
    // through the in_pinned_set branch rather than TOFU.
    let alice = make_client_in_zone_with("alice-revfc", "mesh.local", store.clone(), true).await;
    let bob = make_client_in_zone_with("bob-revfc", "mesh.local", store.clone(), true).await;
    alice.publish_identity(false).await.unwrap();
    bob.publish_identity(false).await.unwrap();
    alice.refresh_prekeys(5, 3600).await.unwrap();
    bob.refresh_prekeys(5, 3600).await.unwrap();
    let bob_contact = alice.fetch_identity("bob-revfc@mesh.local").await.unwrap();
    let alice_contact = bob.fetch_identity("alice-revfc@mesh.local").await.unwrap();
    alice.add_contact(bob_contact).await.unwrap();
    bob.add_contact(alice_contact).await.unwrap();

    alice
        .send_message("bob-revfc", b"should be dropped on dns failure")
        .await
        .unwrap();

    // Rebuild bob with a reader that fails on the rotation RRset names
    // for alice. The shared store still holds alice's published
    // manifest + chunks; only the revocation lookup is being sabotaged.
    let fail_names = vec![
        rotation_rrset_name_zone_anchored("mesh.local"),
        rotation_rrset_name_user_identity("alice-revfc", "mesh.local"),
    ];
    let failing_reader = Arc::new(RotationFailingReader {
        inner: store.clone(),
        fail_names,
    });
    let cfg = DmpClientConfig {
        username: "bob-revfc-strict".to_string(),
        passphrase: "passphrase-for-bob-revfc".to_string(),
        domain: "mesh.local".to_string(),
        kdf_salt: Some(salt("bob-revfc")), // same salt as bob → same identity
        db_path: None,
        writer: store.clone(),
        reader: failing_reader,
        rotation_chain_enabled: true,
    };
    let bob_strict = DmpClient::new(cfg).await.unwrap();
    let alice_contact_again = alice
        .fetch_identity("alice-revfc@mesh.local")
        .await
        .unwrap();
    bob_strict.add_contact(alice_contact_again).await.unwrap();

    let result = bob_strict.receive_messages().await;
    assert!(
        result.is_err(),
        "fail-closed semantics: a DNS error on the revocation RRset MUST propagate, not silently deliver. Got: {result:?}",
    );

    // Sanity check the OPPOSITE: with a working reader (the original
    // store), bob WOULD deliver the same manifest.
    let inbox = bob.receive_messages().await.unwrap();
    assert_eq!(
        inbox.len(),
        1,
        "control: with a working reader, the manifest delivers normally",
    );
}

#[tokio::test]
async fn dmpv2_envelope_round_trip_populates_sender_label() {
    // Both sides advertise v2: alice publishes with --advertise-v2,
    // bob publishes with --advertise-v2, alice pins bob, alice sends,
    // bob receives. The receiver MUST surface a `sender_label` of
    // "alice@mesh.local" because the envelope's `from` claim resolves
    // back to alice's IdentityRecord with the same SPK as the
    // manifest. This is the happy path the desktop UI depends on for
    // first-contact rendering.
    let store = Arc::new(InMemoryDnsStore::new());
    let alice = make_client("alice-v2", store.clone()).await;
    let bob = make_client("bob-v2", store.clone()).await;

    alice.publish_identity(true).await.unwrap();
    bob.publish_identity(true).await.unwrap();
    alice.refresh_prekeys(5, 3600).await.unwrap();
    bob.refresh_prekeys(5, 3600).await.unwrap();

    let bob_contact = alice.fetch_identity("bob-v2@mesh.local").await.unwrap();
    alice.add_contact(bob_contact).await.unwrap();
    let alice_contact = bob.fetch_identity("alice-v2@mesh.local").await.unwrap();
    bob.add_contact(alice_contact).await.unwrap();

    alice.send_message("bob-v2", b"hello v2").await.unwrap();
    let inbox = bob.receive_messages().await.unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].plaintext, b"hello v2");
    assert_eq!(
        inbox[0].sender_label.as_deref(),
        Some("alice-v2@mesh.local"),
        "v2 receiver must surface the SPK-verified sender label",
    );
}

#[tokio::test]
async fn dmpv2_sender_with_v1_only_recipient_uses_no_envelope() {
    // Alice advertises v2 but bob only advertises v1. The send path
    // checks bob's published `versions` (currently [1]) and falls
    // back to plain wire format. Bob's receive path decrypts without
    // an envelope and surfaces `sender_label = None` — existing v1
    // receivers continue to work unchanged.
    let store = Arc::new(InMemoryDnsStore::new());
    let alice = make_client("alice-mix", store.clone()).await;
    let bob = make_client("bob-mix", store.clone()).await;

    alice.publish_identity(true).await.unwrap();
    bob.publish_identity(false).await.unwrap();
    alice.refresh_prekeys(5, 3600).await.unwrap();
    bob.refresh_prekeys(5, 3600).await.unwrap();

    let bob_contact = alice.fetch_identity("bob-mix@mesh.local").await.unwrap();
    alice.add_contact(bob_contact).await.unwrap();
    let alice_contact = bob.fetch_identity("alice-mix@mesh.local").await.unwrap();
    bob.add_contact(alice_contact).await.unwrap();

    alice
        .send_message("bob-mix", b"hello legacy")
        .await
        .unwrap();
    let inbox = bob.receive_messages().await.unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].plaintext, b"hello legacy");
    assert_eq!(
        inbox[0].sender_label, None,
        "v1-only recipient must not see a sender_label — no envelope was emitted",
    );
}

#[tokio::test]
async fn dmpv2_first_contact_intro_queue_keeps_sender_label() {
    // Alice and bob both advertise v2 but bob has NOT pinned alice.
    // Alice's message lands in bob's intro queue (quarantine). The
    // intro row must preserve the SPK-verified sender label from the
    // envelope so the desktop UI can render "alice-fc@mesh.local"
    // next to the pending-intro card instead of forcing the user to
    // recognize a raw 32-byte SPK.
    let store = Arc::new(InMemoryDnsStore::new());
    let alice = make_client("alice-fc", store.clone()).await;
    let bob = make_client("bob-fc", store.clone()).await;

    alice.publish_identity(true).await.unwrap();
    bob.publish_identity(true).await.unwrap();
    alice.refresh_prekeys(5, 3600).await.unwrap();
    bob.refresh_prekeys(5, 3600).await.unwrap();

    // Alice pins bob (so she can send). Bob has another pinned
    // contact to keep pinned-contacts mode active — without any
    // pinned contact, TOFU mode would deliver alice straight to the
    // inbox instead of quarantining her.
    let bob_contact = alice.fetch_identity("bob-fc@mesh.local").await.unwrap();
    alice.add_contact(bob_contact).await.unwrap();
    let other = make_client("other-fc", store.clone()).await;
    other.publish_identity(false).await.unwrap();
    let other_contact = bob.fetch_identity("other-fc@mesh.local").await.unwrap();
    bob.add_contact(other_contact).await.unwrap();

    alice
        .send_message("bob-fc", b"intro request")
        .await
        .unwrap();
    let inbox = bob.receive_messages().await.unwrap();
    assert!(
        inbox.is_empty(),
        "alice is not pinned by bob; her message must quarantine, not deliver",
    );
    let pending = bob.list_intros().await.unwrap();
    assert_eq!(
        pending.len(),
        1,
        "alice's message must surface in the intro queue"
    );
    assert_eq!(
        pending[0].sender_username.as_deref(),
        Some("alice-fc@mesh.local"),
        "intro row must preserve the SPK-verified sender label for UI rendering",
    );
}

// Helper trait to expose the raw byte arrays in this test file. The public
// API only exposes hex strings; tests use the bytes directly to compare
// against on-wire values.
trait ClientBytes {
    fn x25519_public_key_hex_bytes(&self) -> [u8; 32];
    fn ed25519_signing_public_key_hex_bytes(&self) -> [u8; 32];
}

impl ClientBytes for DmpClient {
    fn x25519_public_key_hex_bytes(&self) -> [u8; 32] {
        let hex_str = self.x25519_public_key_hex();
        let v = hex::decode(hex_str).unwrap();
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }
    fn ed25519_signing_public_key_hex_bytes(&self) -> [u8; 32] {
        let hex_str = self.ed25519_signing_public_key_hex();
        let v = hex::decode(hex_str).unwrap();
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }
}

/// A claim the writer refuses must be reported, not swallowed.
///
/// This is the shape of the real failure: a TSIG key scoped to one zone
/// cannot write a claim into another node's zone. The writer declines
/// without erroring, and the send used to return a message id as though
/// everything had worked, so an un-pinned recipient silently never saw the
/// message.
#[tokio::test]
async fn claim_failures_are_reported_not_swallowed() {
    /// Accepts the manifest and chunks, refuses anything that looks like a
    /// claim record, mirroring an out-of-zone DNS UPDATE being declined.
    #[derive(Debug)]
    struct RefusesClaims {
        inner: Arc<InMemoryDnsStore>,
    }

    #[async_trait::async_trait]
    impl DnsRecordWriter for RefusesClaims {
        async fn publish_txt_record(
            &self,
            name: &str,
            value: &str,
            ttl: u32,
        ) -> Result<bool, dnsmesh_net::NetError> {
            if name.starts_with("claim-") || name.starts_with("_dnsmesh-claim") {
                // Declined, not an error: exactly what the real writer does
                // when the name falls outside the TSIG key's zone.
                return Ok(false);
            }
            self.inner.publish_txt_record(name, value, ttl).await
        }

        async fn delete_txt_record(
            &self,
            name: &str,
            value: Option<&str>,
        ) -> Result<bool, dnsmesh_net::NetError> {
            self.inner.delete_txt_record(name, value).await
        }
    }

    let store = Arc::new(InMemoryDnsStore::new());
    let bob = make_client("bob-claim-refused", store.clone()).await;
    bob.publish_identity(false).await.unwrap();
    bob.refresh_prekeys(5, 3600).await.unwrap();

    let writer = Arc::new(RefusesClaims {
        inner: store.clone(),
    });
    let alice = DmpClient::new(DmpClientConfig {
        username: "alice-claim-refused".to_string(),
        passphrase: "passphrase-for-alice-claim-refused".to_string(),
        domain: "mesh.local".to_string(),
        kdf_salt: Some(salt("alice-claim-refused")),
        db_path: None,
        writer,
        reader: store.clone(),
        rotation_chain_enabled: false,
    })
    .await
    .unwrap();
    alice.publish_identity(false).await.unwrap();

    let bob_contact = alice
        .fetch_identity("bob-claim-refused@mesh.local")
        .await
        .unwrap();
    alice.add_contact(bob_contact).await.unwrap();

    let sent = alice
        .send_message_with_claim("bob-claim-refused", b"body", &["provider.example.com"])
        .await
        .expect("the message itself still goes out");

    assert!(
        !sent.all_claims_published(),
        "a refused claim must not report success",
    );
    assert_eq!(sent.claim_failures.len(), 1);
    assert_eq!(sent.claim_failures[0].provider_zone, "provider.example.com",);
    assert!(
        !sent.claim_failures[0].reason.is_empty(),
        "a failure needs a reason the caller can show the user",
    );
}

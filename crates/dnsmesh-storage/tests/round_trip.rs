//! End-to-end round-trip across every store in the crate.
//!
//! Opens a tempfile-backed sqlite db, populates each store, drops all
//! handles, reopens the same file, and verifies state survived. Catches
//! regressions in:
//!
//!   - migrations not running cleanly on a fresh file,
//!   - WAL files being left in a state that an out-of-process reopen
//!     can't read (the WAL checkpoint should happen on `Connection`
//!     drop),
//!   - any of the stores accidentally caching state in memory rather
//!     than going to disk.

use dnsmesh_storage::{
    Contact, ContactStore, IntroQueue, NewContact, NewIntro, OpenedDb, PrekeyStore, ReplayCache,
};

/// Fixed SQLCipher key. Real callers derive theirs from the identity
/// passphrase; this test only needs one that is 32 bytes and stable across
/// the close/reopen it exercises.
const TEST_KEY: [u8; 32] = [0x2a; 32];

#[test]
fn persists_across_reopen() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();
    // Drop the temp handle so we own the path; the file itself stays
    // until tmp is dropped at end of scope.
    drop(tmp.reopen().unwrap());

    // ---- populate ----------------------------------------------------------
    let prekey_ids: Vec<u32>;
    let intro_id: i64;
    let replay_spk = vec![0xaau8; 32];
    let replay_mid = vec![0xbbu8; 16];
    let alice_x25519 = [0x11u8; 32];
    let alice_ed25519 = [0x22u8; 32];

    {
        // Each store opens its own Connection. WAL mode handles the
        // cross-connection serialization for us.
        let prekeys = PrekeyStore::new(OpenedDb::open(&path, &TEST_KEY).unwrap());
        let intros = IntroQueue::new(OpenedDb::open(&path, &TEST_KEY).unwrap());
        let replay = ReplayCache::new(OpenedDb::open(&path, &TEST_KEY).unwrap());
        let contacts = ContactStore::new(OpenedDb::open(&path, &TEST_KEY).unwrap());

        // Prekeys: generate 3, remember their ids.
        let pool = prekeys.generate_pool(3, 3600).unwrap();
        prekey_ids = pool.iter().map(|p| p.prekey.prekey_id).collect();
        // Wire-record one of them so we can verify get_wire across reopen.
        prekeys
            .record_wire(prekey_ids[0], "v=dmp1;t=prekey;d=AAAA")
            .unwrap();

        // Intro queue: enqueue one entry that should survive.
        intro_id = intros
            .enqueue(NewIntro {
                sender_spk: &[0x33u8; 32],
                sender_username: Some("stranger"),
                msg_id: &[0x44u8; 16],
                payload: b"hello after reopen",
                expires_at: u64::MAX / 2,
            })
            .unwrap()
            .expect("first enqueue must insert");

        // Replay cache: record one pair, verify has_seen, then close.
        replay
            .record(&replay_spk, &replay_mid, Some(u64::MAX / 2))
            .unwrap();
        assert!(replay.has_seen(&replay_spk, &replay_mid).unwrap());

        // Contacts: insert two so we can also verify list ordering.
        contacts
            .add_contact(NewContact {
                username: "alice",
                x25519_pk: &alice_x25519,
                ed25519_spk: &alice_ed25519,
                require_signing_key: true,
                domain: "alice.zone",
            })
            .unwrap();
        contacts
            .add_contact(NewContact {
                username: "bob",
                x25519_pk: &[0x55u8; 32],
                ed25519_spk: &[0x66u8; 32],
                require_signing_key: false,
                domain: "",
            })
            .unwrap();

        // Stores drop here, closing every connection. WAL gets
        // checkpointed implicitly by sqlite when the last connection
        // closes (default journal_size_limit kicks in).
    }

    // ---- reopen and verify -------------------------------------------------
    let prekeys = PrekeyStore::new(OpenedDb::open(&path, &TEST_KEY).unwrap());
    let intros = IntroQueue::new(OpenedDb::open(&path, &TEST_KEY).unwrap());
    let replay = ReplayCache::new(OpenedDb::open(&path, &TEST_KEY).unwrap());
    let contacts = ContactStore::new(OpenedDb::open(&path, &TEST_KEY).unwrap());

    // Prekeys survived: every id is still live, and the wire record came back.
    let mut live_after = prekeys.list_live_ids().unwrap();
    let mut expected = prekey_ids.clone();
    live_after.sort_unstable();
    expected.sort_unstable();
    assert_eq!(live_after, expected, "prekeys must survive reopen");
    assert_eq!(
        prekeys.get_wire(prekey_ids[0]).unwrap().as_deref(),
        Some("v=dmp1;t=prekey;d=AAAA"),
    );
    // Forward-secrecy fix: consume() removes the row.
    assert!(prekeys.consume(prekey_ids[1]).unwrap());
    assert!(prekeys.get_private_key(prekey_ids[1]).unwrap().is_none());

    // Intro queue: the entry is still pending under the same id.
    let pending = intros.list_pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].intro_id, intro_id);
    assert_eq!(pending[0].payload, b"hello after reopen");
    assert_eq!(pending[0].sender_username.as_deref(), Some("stranger"));

    // Replay cache: still rejects the seen pair.
    assert!(replay.has_seen(&replay_spk, &replay_mid).unwrap());
    assert!(
        !replay
            .check_and_record(&replay_spk, &replay_mid, Some(u64::MAX / 2))
            .unwrap(),
        "check_and_record must report a replay after reopen",
    );

    // Contacts: alphabetical, with the require_signing_key flag preserved.
    let listed: Vec<Contact> = contacts.list_contacts().unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].username, "alice");
    assert_eq!(listed[0].x25519_pk, alice_x25519);
    assert_eq!(listed[0].ed25519_spk, alice_ed25519);
    assert!(listed[0].require_signing_key);
    assert_eq!(listed[0].domain, "alice.zone");
    assert_eq!(listed[1].username, "bob");
    assert!(!listed[1].require_signing_key);
    assert_eq!(
        listed[1].domain, "",
        "empty-string domain (back-compat for V1/V2 inserts) must persist",
    );
}

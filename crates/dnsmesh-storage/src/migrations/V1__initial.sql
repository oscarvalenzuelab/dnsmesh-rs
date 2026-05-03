-- DMP Rust client initial schema (V1).
--
-- Single sqlite file per identity holds:
--
--   prekeys       — one-time X25519 prekey *private* halves (forward
--                   secrecy state). The wire-format Prekey struct lives
--                   in dnsmesh-core; this table stores the secrets that
--                   never leave the local box.
--   intro_queue   — quarantined messages from unknown senders awaiting
--                   user accept/reject in the CLI.
--   replay_cache  — (sender_spk, msg_id) pairs already delivered, with a
--                   TTL. The Python client kept this in a JSON file; the
--                   Rust port upgrades it to sqlite for atomicity.
--   contacts      — persisted address book. NEW in the Rust port; the
--                   Python client keeps contacts in memory only and loses
--                   them across CLI invocations.
--
-- An operator should be able to `sqlite3 ~/.dmp/dmp-rs.sqlite` and
-- recognize the structure from the Python equivalents.

CREATE TABLE prekeys (
    prekey_id   INTEGER PRIMARY KEY,
    private_key BLOB    NOT NULL,
    public_key  BLOB    NOT NULL,
    exp         INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    wire_record TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX idx_prekeys_exp ON prekeys(exp);

CREATE TABLE intro_queue (
    intro_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_spk      BLOB    NOT NULL,
    sender_username TEXT,
    msg_id          BLOB    NOT NULL,
    payload         BLOB    NOT NULL,
    received_at     INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    UNIQUE(sender_spk, msg_id)
);
CREATE INDEX idx_intro_queue_expires ON intro_queue(expires_at);

CREATE TABLE replay_cache (
    sender_spk BLOB    NOT NULL,
    msg_id     BLOB    NOT NULL,
    expiry     INTEGER NOT NULL,
    PRIMARY KEY (sender_spk, msg_id)
);
CREATE INDEX idx_replay_cache_expiry ON replay_cache(expiry);

CREATE TABLE contacts (
    username            TEXT    PRIMARY KEY,
    x25519_pk           BLOB    NOT NULL,
    ed25519_spk         BLOB    NOT NULL,
    first_seen_ts       INTEGER NOT NULL,
    require_signing_key INTEGER NOT NULL DEFAULT 0
);

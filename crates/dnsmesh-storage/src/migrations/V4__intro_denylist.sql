-- Sender denylist for the intro-queue flow.
--
-- When a user blocks an intro (`dnsmesh intro block <id>`), the sender's
-- 32-byte Ed25519 signing public key lands here, and any future receive
-- pass that finds a manifest signed by the same key drops it silently
-- without quarantining a fresh intro. Mirrors the `denylist` table in
-- `dmp/client/intro_queue.py`.
--
-- We keep this in its own table rather than a flag on `intro_queue`
-- because the denylist must outlive any specific quarantined message
-- (the queue row gets deleted when block fires; the denial sticks).

CREATE TABLE intro_denylist (
    sender_spk BLOB    PRIMARY KEY,
    blocked_at INTEGER NOT NULL,
    note       TEXT    NOT NULL DEFAULT ''
);

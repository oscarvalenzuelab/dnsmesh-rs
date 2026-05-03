"""Driver for the Rust↔Python interop round-trip test.

Two subcommands:

  prepare  Build a Python InMemoryDNSStore, create Bob (deterministic),
           have Bob publish his identity record + a prekey RRset, then
           dump the store as JSON. Bob's keys come from a fixed
           passphrase + salt so the second invocation can recreate the
           same identity.

  verify   Load the JSON store written by the Rust sender, recreate Bob
           with the same passphrase + salt, call receive_messages, and
           assert the plaintext matches.

Wire format compatibility against the Python source-of-truth was already
proved at M1 (byte-equal interop vectors). This script proves the next
layer: the full chunked-send + manifest-publish + decrypt round trip
crosses the Rust↔Python boundary cleanly.

The script is invoked by `tests/python_interop.rs` via std::process::Command.
Output JSON goes to stdout on success; errors are written to stderr and
the process exits non-zero.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dmp.client.client import DMPClient
from dmp.core.identity import identity_domain, make_record
from dmp.core.prekeys import prekey_rrset_name
from dmp.network.memory import InMemoryDNSStore


# Fixed identity material so prepare + verify recreate the same Bob.
BOB_PASSPHRASE = "interop-test-bob-passphrase"
BOB_SALT = b"interop-bob-salt"  # 16 bytes — Argon2id requires >= 8
BOB_USERNAME = "bob-interop"
DOMAIN = "mesh.local"
PUBLISH_TTL = 86_400  # 24h, well above test runtime


def store_to_dict(store: InMemoryDNSStore) -> dict[str, list[str]]:
    """Snapshot the store as `{name: [value, ...]}`. Drops TTL because
    the receiving side will republish at PUBLISH_TTL."""
    out: dict[str, list[str]] = {}
    for name in store.list_names():
        values = store.query_txt_record(name) or []
        if values:
            out[name] = values
    return out


def store_from_dict(store: InMemoryDNSStore, blob: dict[str, list[str]]) -> None:
    for name, values in blob.items():
        for v in values:
            store.publish_txt_record(name, v, ttl=PUBLISH_TTL)


def make_bob(store: InMemoryDNSStore, prekey_db: Path) -> DMPClient:
    return DMPClient(
        BOB_USERNAME,
        BOB_PASSPHRASE,
        domain=DOMAIN,
        store=store,
        kdf_salt=BOB_SALT,
        # The prekey *privates* live in this sqlite file — without
        # persistence they would vanish between the prepare and verify
        # subprocesses, and Bob would silently drop the inbound message
        # because the prekey_id lookup misses. The replay cache and
        # intro queue stay in :memory: since neither persists across the
        # prepare/verify boundary.
        prekey_store_path=str(prekey_db),
        # M8.4 in upstream made intro_queue_path mandatory: a missing
        # arg now raises rather than silently defaulting to :memory:.
        # We're fine with ephemeral here — the queue isn't load-bearing
        # for the round-trip test (Bob is in TOFU mode and accepts every
        # signature-valid manifest into the inbox directly).
        intro_queue_path=":memory:",
        # TOFU is required because Bob never pinned Alice — we want any
        # signature-valid manifest at Bob's slot to be delivered. Mirrors
        # the `tofu_mode_accepts_signature_valid_manifest_without_pinning`
        # case in the Rust end-to-end suite.
        allow_tofu=True,
    )


def bob_prekey_db(workdir: Path) -> Path:
    return workdir / "bob-prekeys.sqlite"


def cmd_prepare(args: argparse.Namespace) -> int:
    store = InMemoryDNSStore()
    bob = make_bob(store, bob_prekey_db(Path(args.workdir)))

    # No client.publish_identity() in Python — this is what the CLI does
    # in cmd_identity_publish (cli.py:1748). Replicate it inline.
    record = make_record(bob.crypto, bob.username)
    wire = record.sign(bob.crypto)
    name = identity_domain(bob.username, bob.domain)
    if not bob.writer.publish_txt_record(name, wire, ttl=PUBLISH_TTL):
        print(f"failed to publish identity record at {name}", file=sys.stderr)
        return 2

    published = bob.refresh_prekeys(count=10, ttl_seconds=PUBLISH_TTL)
    if published == 0:
        print("refresh_prekeys produced 0 records", file=sys.stderr)
        return 2

    payload = {
        "records": store_to_dict(store),
        "bob": {
            "username": bob.username,
            "domain": bob.domain,
            "x25519_pk_hex": bob.crypto.get_public_key_bytes().hex(),
            "ed25519_spk_hex": bob.crypto.get_signing_public_key_bytes().hex(),
            "user_id_hex": bob.user_id.hex(),
            "identity_record_name": name,
            "prekey_rrset_name": prekey_rrset_name(bob.username, bob.domain),
            "published_prekeys": published,
        },
    }
    out_path = Path(args.workdir) / "store-after-bob-publish.json"
    out_path.write_text(json.dumps(payload, indent=2))
    print(json.dumps({"out_path": str(out_path), "published_prekeys": published}))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    in_path = Path(args.workdir) / "store-after-alice-send.json"
    if not in_path.exists():
        print(f"missing input store: {in_path}", file=sys.stderr)
        return 2
    blob = json.loads(in_path.read_text())

    store = InMemoryDNSStore()
    store_from_dict(store, blob["records"])

    bob = make_bob(store, bob_prekey_db(Path(args.workdir)))
    inbox = bob.receive_messages()
    out: dict = {
        "messages": [
            {
                "plaintext": (
                    m.plaintext.decode("utf-8", errors="replace")
                    if isinstance(m.plaintext, (bytes, bytearray))
                    else str(m.plaintext)
                ),
                "plaintext_hex": (
                    m.plaintext.hex()
                    if isinstance(m.plaintext, (bytes, bytearray))
                    else None
                ),
                "sender_signing_pk_hex": (
                    m.sender_signing_pk.hex()
                    if isinstance(getattr(m, "sender_signing_pk", None), (bytes, bytearray))
                    else None
                ),
            }
            for m in inbox
        ],
        "count": len(inbox),
    }
    if args.expect_plaintext is not None:
        wanted = args.expect_plaintext
        got = [m["plaintext"] for m in out["messages"]]
        if wanted not in got:
            print(
                f"plaintext mismatch — expected {wanted!r} in inbox, got {got!r}",
                file=sys.stderr,
            )
            print(json.dumps(out))
            return 3
    print(json.dumps(out))
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--workdir", required=True, help="scratch dir for the JSON store snapshots")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("prepare")
    v = sub.add_parser("verify")
    v.add_argument("--expect-plaintext", default=None)
    args = p.parse_args()
    if args.cmd == "prepare":
        return cmd_prepare(args)
    if args.cmd == "verify":
        return cmd_verify(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())

---
title: Differences from the Python reference
layout: default
parent: Reference
nav_order: 2
---

# Differences from the Python reference
{: .no_toc }

`dnsmesh-rs` is a **client port** of the
[Python reference at `oscarvalenzuelab/DNSMeshProtocol`](https://github.com/oscarvalenzuelab/DNSMeshProtocol).
The wire format is byte-identical and is exercised against the
reference in CI. Below are the deliberate differences in scope,
implementation, and surface area.

1. TOC
{:toc}

## Same

- **Wire format.** Records, manifests, claim records, rotation
  records, prekeys, chunked payloads — all byte-compatible. The
  test vectors under
  [`crates/dnsmesh-core/tests/interop/vectors/`](https://github.com/oscarvalenzuelab/dnsmesh-rs/tree/main/crates/dnsmesh-core/tests/interop/vectors)
  are lifted verbatim from the Python repo and validated round-
  trip in `cargo test`.
- **Crypto primitives.** X25519, Ed25519, ChaCha20-Poly1305,
  HKDF-SHA256, SHA-256, Argon2id (memory-hard, 32 MiB, t=2, p=2,
  32-byte output) — same algorithms, same parameters.
- **KDF.** Passphrase + salt → X25519 seed via Argon2id. The
  Ed25519 signing seed is derived as
  `SHA-256(x25519_priv || b"DMP-v1-Ed25519-signing-key")`. A
  passphrase + `kdf_salt` in either client derives the same
  identity.
- **Replay defense.** Per-recipient `(sender_spk, msg_id)` cache.
  Persisted to disk so a process restart doesn't re-deliver
  in-flight messages.
- **Identity rotation chain.** Co-signed `RotationRecord` (new ←
  old), self-signed `RevocationRecord`, opt-in chain walking on
  receive. Fails-closed on DNS errors against the rotation /
  revocation RRset to avoid pinned-key bypass.
- **Claim routing.** Cross-zone delivery hint via signed
  `ClaimRecord` records.

## Different

### Client-only

The Rust port does **not** ship:

- An authoritative DNS node implementation.
- The publish API or registration challenge endpoints.
- Federation, anti-entropy, or cluster code.
- Operator deploy tooling, Docker images, install scripts.
- The directory aggregator + heartbeat publisher.

All of those continue to live in the Python reference. The Rust
port talks to them as a client.

### On-disk layout

| Concern | Python reference | Rust port |
|---|---|---|
| Replay cache | `replay_cache.json` (JSON file, atomic rename) | SQLite row in `dmp-rs.sqlite` |
| Contacts | YAML in `contacts.yaml` | SQLite rows |
| Prekey private bytes | JSON file under `prekeys/` | SQLite rows |
| Intro queue | JSON | SQLite rows |
| TSIG secret | base64 in `tsig.key` | base64 in `tsig-<host>.key` |
| Passphrase | env / file / prompt | env / file / prompt — same priority order |
| Config | YAML | YAML — schema mostly the same, see [Config reference]({{ site.baseurl }}/reference/config) |

The unified SQLite store lets the Rust port hold the replay
cache, contacts, prekeys, and intros under a single
transactional surface — useful for the FFI and mobile cases
where a flat-file layout would be awkward.

### Sendmail-compat CLI

`dnsmesh send -t` accepts the sendmail-compatible invocation
style mutt and friends use: read RFC 5322 from stdin, pull
recipients from `To:` / `Cc:` / `Bcc:`. Positional addresses
are accepted as a suppression list (ignored, the way classic
sendmail behaved).

The Python CLI's `send` is positional-only. If you use mutt,
the Rust CLI is the right transport. See the
[mutt integration guide]({{ site.baseurl }}/guide/mua-mutt).

### Maildir delivery

`dnsmesh recv --maildir <path>` writes RFC 5322 messages into a
standard `new/` / `cur/` / `tmp/` Maildir. Decrypted messages
carry `X-DMP-*` headers (sender SPK, sender address, message
ID, timestamp) so MUAs can attribute them inline.

The Python CLI returns decrypted bodies on stdout / via library
callers; it does not deliver into Maildir.

### Mobile-first FFI

`dnsmesh-ffi` is a first-class workspace crate with `cdylib`,
`staticlib`, and `rlib` outputs, intended to be consumed by
Swift via xcframework or by Kotlin via aar. The Python
implementation is consumable by Python applications, full stop.

### Unified `purge`

`dnsmesh purge --remote` walks DNS UPDATE deletes against every
record an identity published (identity, prekeys, all 10 mailbox
slots, rotation/revocation RRset), then wipes local state. With
a `--force-local-after-remote-failure` opt-out, it is a single
command for "fully decommission this identity" instead of `rm
~/.dmp` + a 24h TTL wait.

The Python CLI's equivalent is multiple manual steps.

### Three publishing back-ends, mutually exclusive

The Rust port supports TSIG, Cloudflare HTTP API, and node-token
HTTP — but a config carrying more than one back-end **fails at
load time** rather than picking a winner silently. See
[Publishers]({{ site.baseurl }}/guide/publishers).

The Python reference allows the implicit-precedence case; we
deliberately tightened that to avoid the
"why is it publishing to the wrong place" footgun.

## Missing — on the roadmap before 1.0

- **OS keychain integration.** Saved bearer tokens / TSIG keys
  live as plaintext 0600 files at rest. iOS Keychain, macOS
  Keychain, and Linux Secret Service integrations are scoped for
  pre-1.0.
- **Stable FFI ABI.** The exported C surface will move during
  pre-0.1.0; mobile consumers should pin to a specific commit.
- **Code-signing wired through CI.** `release.yml` ships
  unsigned binaries today (no certs yet); the signing steps are
  staged behind secret-presence gates so adding the secrets
  turns signing on without a workflow edit.
- **External cryptographic audit.** Scoped against the Python
  reference; the Rust port's wire-format compatibility means a
  successful audit there transfers most of the property to here.
- **Sample mobile applications.** SwiftUI and Compose shells
  consuming the FFI bindings are scoped for pre-1.0 so embedders
  have a working consumer to copy from.
- **`alot` / `aerc` / `mu` / `notmuch` integration recipes.**
  Mutt is documented today; other MUAs that accept a sendmail
  binary should work with minor adaptation, but each will get
  its own recipe before 1.0.

## Missing — out of scope for the Rust port

- **The DMP node.** Authoritative DNS, publish API, federation,
  anti-entropy, registration challenge endpoints — those stay in
  the Python reference. The Rust port is a client.
- **Operator tooling.** Install scripts, Docker, multi-tenant
  configuration, heartbeat directory aggregation — Python.
- **Protocol design changes.** Wire-format proposals are filed
  against
  [oscarvalenzuelab/DNSMeshProtocol](https://github.com/oscarvalenzuelab/DNSMeshProtocol),
  not here. The Rust port follows the spec.

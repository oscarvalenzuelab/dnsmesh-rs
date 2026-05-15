# Changelog

All notable changes to this project will be documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This Rust port is wire-compatible with the Python reference at
[oscarvalenzuelab/DNSMeshProtocol](https://github.com/oscarvalenzuelab/DNSMeshProtocol);
breaking wire-format changes there will be reflected here.

## [Unreleased]

## [0.1.2] — 2026-05-15 — DMPv2 plaintext envelope

Pulls the Rust port up to wire parity with the Python 0.7.5 release.
DMPv2 envelope landed end-to-end: encoder, decoder, ASCII-only
canonicalizer, identity `versions` capability field, send-side
capability gate, receive-side SPK-binding verifier, FFI surface for
`InboxMessage.sender_label`, opt-in `--advertise-v2` flag on the CLI.

### Added

- `dnsmesh_core::envelope` module — strict ASCII-only `user@host`
  canonicalization, `encode()` / `decode()` for the DMPv2 plaintext
  wrapper, 256-byte header cap.
- `IdentityRecord.versions: Vec<u8>` with `normalize_versions()`
  guard that rejects overlong inputs as `VersionsArgTooLong` instead
  of panicking at serialization. Default omits the suffix and stays
  byte-identical to pre-this-release records.
- `publish_identity(advertise_v2: bool)` and
  `rotate_identity(..., advertise_v2)` on the client API; matching
  `--advertise-v2` flag on `dnsmesh identity publish` / `rotate`.
- `DmpClient::recipient_versions()` and `resolve_envelope_label()`
  helpers powering the send-side gate and the receive-side SPK
  binding.
- `InboxMessage.sender_label: Option<String>` plumbed all the way
  through the FFI so Tauri / Swift / Kotlin consumers see the
  SPK-verified label.
- Interop vector files `dmpv2_envelope.json` and an extended
  `identity_record.json`, both synced from the Python reference and
  exercised in `interop_dmpv2_envelope.rs` / `interop_identity.rs`.

### Changed

- Send path conditionally wraps the plaintext with a DMPv2 envelope
  when the recipient advertises `versions` containing `2`; falls
  back to v1 wire format otherwise.

## [0.1.0] — 2026-05-03

Initial release of the Rust port of the DNS Mesh Protocol. Wire
format is byte-identical to the Python reference and exercised in CI
via the `python_interop` round-trip test. The compiled CLI binary,
SDK static / dynamic libraries, and mobile artifacts are MIT-licensed
end-to-end (no GPL transitive dependencies).

### Added — client SDK

- `dnsmesh-core` — wire format encoders / decoders for identity
  records, rotation records, revocation records, claim records, slot
  manifests, prekey RRsets, and chunked payloads.
- Crypto stack: X25519 ECDH, Ed25519 signatures, ChaCha20-Poly1305
  AEAD, HKDF-SHA256, SHA-256, Argon2id (32 MiB / t=2 / p=2) for
  passphrase → key derivation. Identity is deterministic from
  `(passphrase, salt)`; salt persists in `config.yaml` after
  `dnsmesh init`.
- In-tree Reed-Solomon erasure coding (k-of-m over GF(2^8))
  byte-output-compatible with tahoe-lafs `zfec`. No external
  GPL-licensed dependency in the build graph.
- `dnsmesh-net` — DNS resolver pool with OS auto-detect, three
  publishing back-ends:
  - **TSIG** — RFC 2136 UPDATE signed with RFC 8945 TSIG.
  - **Cloudflare** — Cloudflare DNS HTTP API; serializes
    GET-then-POST/PUT to avoid duplicate-record race.
  - **Node-token HTTP** — bearer-authenticated POST/DELETE against
    `/v1/records/<name>` on a multi-tenant DMP node.
  Publish back-ends are mutually exclusive; config rejects ambiguity
  at load time.
- `dnsmesh-storage` — SQLite-backed local store: identity, pinned
  contacts, prekey private bytes, replay cache, intro queue. Schema
  managed by `refinery` migrations.
- `dnsmesh-client` — high-level `DmpClient`:
  - Identity publish, prekey pool refresh, identity fetch with
    pinning.
  - Send: chunk + AEAD-seal + sign + publish slot manifest.
  - Receive: walk own zone + pinned-contact zones, dedupe via replay
    cache, decrypt and verify, optional rotation-chain walking
    (opt-in, fail-closed on DNS error to avoid pinned-key bypass).
  - Identity rotate (routine / compromise / lost-key) with co-signed
    `RotationRecord` and self-signed `RevocationRecord`.
  - Full identity unpublish: DNS UPDATE deletes against every
    published record name.
  - Cross-zone receive: pinned contacts in other zones contribute
    their zones to the slot-walk set.

### Added — CLI

- `dnsmesh init <user> --domain <zone> [--node <host>]` and
  `--cloudflare-zone-id <id>` variants.
- `dnsmesh register --node <host>` (per-user bearer token via HTTPS
  challenge) and `dnsmesh tsig register --node <host>` (per-user TSIG
  key).
- `dnsmesh identity {publish, refresh-prekeys, fetch, rotate, revoke,
  unpublish, show, list, trust}`.
- `dnsmesh contacts {list, show, pin, trust, remove}`.
- `dnsmesh intro {list, show, accept, deny}` for first-contact
  quarantine of un-pinned senders.
- `dnsmesh send <recipient> "..."` and sendmail-compatible
  `dnsmesh send -t` mode that reads recipients from RFC 5322
  `To:` / `Cc:` / `Bcc:` headers (positional addresses are accepted
  as a sendmail suppression list and ignored).
- `dnsmesh recv [--maildir <path>] [--watch] [--interval <s>]` —
  Maildir delivery with `X-DMP-Sender-SPK`, `X-DMP-Sender-Address`,
  `X-DMP-Msg-Id`, `X-DMP-Timestamp` attribution headers.
- `dnsmesh purge [--remote] [--yes] [--force-local-after-remote-failure]`
  for full identity decommissioning. Aborts the local wipe on partial
  remote-delete failure unless explicitly forced, so the operator
  retains the credentials needed to retry.
- `dnsmesh doctor` for config + DNS reachability + prekey-pool
  diagnostics.

### Added — mobile FFI

- `dnsmesh-ffi` crate with `cdylib` / `staticlib` / `rlib` outputs
  consumable from Swift (xcframework) and Kotlin (aar).
- Skeleton Swift package at
  [`examples/ios-bridge/`](https://github.com/oscarvalenzuelab/dnsmesh-rs/tree/main/examples/ios-bridge)
  ready to wire in a built xcframework.

### Added — documentation

- Documentation site at <https://oscarvalenzuelab.github.io/dnsmesh-rs/>:
  getting-started walkthrough, full CLI reference, SDK guide, mutt /
  neomutt integration guide, mobile bindings guide, publisher
  comparison, config-file field reference, differences-from-Python
  page.
- Runnable Rust SDK example at
  [`examples/send-recv/`](https://github.com/oscarvalenzuelab/dnsmesh-rs/tree/main/examples/send-recv).

### Added — CI / release pipeline

- Push CI: `cargo fmt --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`, Python
  reference interop round-trip, `cargo audit`, `cargo deny check`,
  proptest parser-robustness fuzz harness.
- Tag-driven release workflows:
  - `cli-v<semver>` ships the `dnsmesh` CLI binary across 7 desktop
    targets. Six are produced by the GHA matrix; `x86_64-apple-darwin`
    is uploaded per-tag via `scripts/release-darwin-x86.sh` (the GHA
    `macos-13` free-tier runner pool is exhausted, so the Intel Mac
    build is a manual cross-compile from an Apple Silicon host).
  - `sdk-v<semver>` ships the FFI library across the same 7 targets.
  - `mobile-v<semver>` ships an iOS xcframework + Android aar with
    generated Swift / Kotlin bindings.
- `aarch64-unknown-linux-gnu` is built via `cargo zigbuild` for clean
  glibc versioning. Code-signing is wired but gated on
  `secrets.APPLE_DEVELOPER_ID_CERT_NAME` /
  `secrets.WINDOWS_AUTHENTICODE_CERT` etc. — sets up automatically
  when secrets are present.
- GitHub Pages deploy on any change under `docs/**`.

### Security

- Threat model and known limits documented in
  [SECURITY.md](https://github.com/oscarvalenzuelab/dnsmesh-rs/blob/main/SECURITY.md).
  Vulnerability reports to `oscar.valenzuela.b_AT_gmail.com`.

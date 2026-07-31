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

## [0.3.0] - 2026-07-31 - claim failures are reported

### Breaking

- `DmpClient::send_message_with_claim` returns `ClaimSend` instead of
  `[u8; 16]`. The message id moves to `.msg_id`; `.claim_failures` lists
  the provider zones that refused, with a reason for each.

### Fixed

- Claim publish failures are no longer swallowed. The method logged a
  warning and returned `Ok(msg_id)` whether the claim published or not, so
  no caller could tell the difference and the message id printed either
  way. A claim that does not publish means an un-pinned recipient never
  discovers the message, and cross-zone sends hit this every time: a TSIG
  key scoped to one zone cannot write a claim into another node's zone, the
  writer declines without erroring, and the send looked entirely
  successful.

  The message itself is still delivered, so this is a partial success
  rather than an error at the SDK layer, and callers decide how loud to be.

- `dnsmesh send --claim-via` prints which zones refused and why, says
  plainly that an un-pinned recipient will not find the message, suggests
  registering with the node serving that zone, and exits non-zero so
  scripts notice. Same-zone sends are unchanged.

## [0.2.1] - 2026-07-30 - Android build fix

Build fix only. No API or behaviour change from 0.2.0.

### Fixed

- The x86_64 Android build works again. OpenSSL 3.6 emits SM4 AVX
  instructions in `crypto/sm4/sm4-x86_64.S` and the NDK r26 clang
  assembler does not know them, so building vendored OpenSSL for
  `x86_64-linux-android` failed with "invalid instruction mnemonic
  'vsm4key4'". Nothing here uses SM4, so `openssl-src` is held at the 3.5
  series, where the file does not exist to fail on. The pin is declared
  in `Cargo.toml` rather than left to the lockfile so a routine
  `cargo update` cannot quietly undo it. Worth lifting once the NDK ships
  a newer assembler; check the x86_64 Android build before doing so,
  since CI does not cover Android.

## [0.2.0] - 2026-07-30 - encryption at rest

The local database is now encrypted. This is a breaking release in two
ways: the storage API changed, and databases written by earlier versions
cannot be opened.

### Breaking

- `OpenedDb::open` and `OpenedDb::open_in_memory` now take the storage
  key. Callers that open the database directly need to pass it; going
  through `DmpClient` requires no change, since it derives the key
  itself.
- Databases created before this release cannot be opened. There is no
  in-place upgrade path. `OpenedDb::open` recognises a plaintext file and
  returns `StorageError::LegacyPlaintextDatabase` so callers can say
  "recreate the identity" rather than reporting corruption.
- `dnsmesh-storage` links SQLCipher with vendored OpenSSL instead of
  plain bundled sqlite. Cross-compiling for Android needs
  `RANLIB_<target>=llvm-ranlib`: NDK r23 and later dropped the
  per-triple ranlib shims that OpenSSL's build system looks for.

### Added

- `DmpCrypto::derive_storage_key`, HKDF-SHA256 over the passphrase-derived
  seed under a new `DMP-Storage-At-Rest` domain separator. Domain
  separated from both the messaging key and the signing key.
- `DmpClient::storage_key`, so host applications can encrypt their own
  per-identity files under the same key rather than inventing a second
  scheme.
- `StorageError::LegacyPlaintextDatabase` and
  `StorageError::InvalidStorageKeyLength`.

### Changed

- The database is opened with the raw-key pragma, so SQLCipher uses the
  32 bytes directly instead of running its own PBKDF2 over them. The key
  is already an HKDF output over an Argon2id seed, and there are four
  connections per client, so a second stretching pass would cost latency
  for nothing.
- Opening now probes `sqlite_master` immediately. `PRAGMA key` never
  fails on its own, so without the probe a bad key surfaced at some
  arbitrary later query instead of at open time.
- The CLI explains a failed open. A wrong passphrase used to print
  "file is not a database", which reads like corruption when it is
  almost always a typo.
- `dnsmesh init` removes the database it created if the run fails before
  the salt reaches `config.yaml`. The database is keyed by that salt, so
  an interrupted init used to leave a file that nothing could ever open,
  and the next init would fail on it with no hint to delete it.

### Notes

Wire format is unchanged. This release only affects local storage, so it
does not break interoperability with the Python reference or with peers
running earlier versions.

## [0.1.3] — 2026-05-15 — CLI quality-of-life

CLI-only release. SDK code is unchanged from 0.1.2; the desktop
and mobile builds against `sdk-v0.1.2` keep working without
re-pinning.

### Added

- `dnsmesh contacts add <addr>` now accepts the bare address form.
  When `--x25519` and `--ed25519` are both omitted, the command
  resolves the address via DNS (signed-IdentityRecord lookup,
  same path as `identity fetch`) and pins whatever the zone
  returns. Clap's `requires` cross-link keeps the all-or-nothing
  contract — passing only one hex flag is a parse-time error.
  Pinning by explicit hex keys still works for the offline /
  scripted case.

### Changed

- `dnsmesh send` prints an actionable stderr hint on
  `contact_not_found` before bailing — a one-line nudge pointing
  at `dnsmesh contacts add <full address>`. Exit code unchanged.
  Bare-username sends skip the hint since `contacts add` rejects
  bare usernames.

### Fixed

- `dnsmesh recv` human output now displays the SPK-verified envelope
  label (e.g. `from alice@example.com (78c40174…)`) when the inbound
  DMPv2 envelope's `from` claim resolves back to an IdentityRecord
  pinning the same Ed25519 key as the manifest. v1 messages and
  envelope-failed-verify cases keep falling back to the SPK-hex
  line. Closes parity with the Maildir writer, which already
  stamped the verified address into From: headers.

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

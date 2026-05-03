# Security

This is **non-certified, pre-external-audit software** in a
**pre-alpha** state. The crate boundaries, wire-format compatibility,
and on-disk schema are still moving. **Don't route confidentiality-
critical traffic through `dnsmesh-rs` until both the wire-format
external cryptographic audit lands (against the Python reference at
[oscarvalenzuelab/DNSMeshProtocol](https://github.com/oscarvalenzuelab/DNSMeshProtocol))
*and* this Rust port has cut a tagged 0.1.0 release.**

`dnsmesh-rs` is a Rust **client SDK + CLI** port of the DNS Mesh
Protocol. The protocol specification, the authoritative DNS node
implementation, and the federation / cluster code live in the
Python reference repo above. This crate consumes the same wire
format the spec defines; the protocol's threat model, known limits,
and audit posture are documented there. This file covers what is
specific to the Rust port.

## Reporting a vulnerability

Email `oscar.valenzuela.b_AT_gmail.com` (replace `_AT_` with `@`).
Once this repository is flipped public,
[GitHub's private vulnerability reporting](https://github.com/oscarvalenzuelab/dnsmesh-rs/security/advisories/new)
will become the preferred channel.

Include in the report:

- Affected version (commit SHA, release tag, or `cargo` revision).
- Minimum reproduction.
- Your assessment of impact.

For non-security questions, open a regular GitHub issue. Please
don't open a public issue for an unpatched security bug.

## Scope of this repository

`dnsmesh-rs` ships:

- A **client SDK** (`dnsmesh-core`, `dnsmesh-net`,
  `dnsmesh-storage`, `dnsmesh-client`) that speaks the DMP wire
  format end-to-end against any conformant DMP node.
- A **CLI** (`dnsmesh-cli`) that wraps the SDK for interactive use
  and MUA integration (sendmail-compat for `mutt`/`neomutt`,
  Maildir delivery).
- A **mobile FFI** (`dnsmesh-ffi`) staticlib/cdylib surface for
  iOS and Android consumers.

It does **not** ship:

- The authoritative DNS node, the publish API, federation code, or
  the operator deploy scripts. Those live in the Python reference.
- TLS termination, reverse-proxy config, or network-level controls.
  Operators front the Python node with their own proxy.

Threat-model questions about the *protocol* — chunking,
manifests, slot semantics, replay defenses, traffic analysis,
zone-anchored identity — are answered in the
[Python repo's SECURITY.md](https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/SECURITY.md).

## Cryptographic primitives (mirrors the spec)

- **X25519** (RFC 7748) via the `x25519-dalek` crate.
- **Ed25519** (RFC 8032) via the `ed25519-dalek` crate.
- **ChaCha20-Poly1305 AEAD** (RFC 8439) via the `chacha20poly1305`
  crate.
- **HKDF-SHA256** (RFC 5869) via the `hkdf` crate.
- **SHA-256** via the `sha2` crate.
- **Argon2id** (memory-hard passphrase KDF, 32 MiB / t=2 / p=2 /
  32-byte output) via the `argon2` crate.

The Ed25519 signing seed is derived from the X25519 private bytes
via `SHA-256(x25519_priv || b"DMP-v1-Ed25519-signing-key")` — bit-for-
bit identical to the Python reference, because the wire format
requires it.

## Identity passphrase

The CLI reads `$DMP_PASSPHRASE` first, then a 0400-permission file
referenced by `passphrase_file` in the config, then an interactive
TTY prompt. **Loss of the passphrase is loss of the identity** —
there is no recovery, by design. Persist it in a password manager
or a 0400 file; the CLI refuses to read passphrase files with
permissive mode bits.

When the SDK's `DmpClient` is constructed without a salt (library
demos), it falls back to a fixed sentinel `DMP-default-v2-argon2id`
that matches the Python reference. **That path is weaker against
targeted offline attack and is a footgun** — production deployments
must go through the CLI (which generates a 32-byte random salt at
`dnsmesh init`) or pass their own salt.

## Known limits (port-specific)

These are limits introduced or surfaced by the Rust port itself.
For protocol-level limits, see the Python `SECURITY.md`.

1. **Pre-tag, pre-audit.** No semver guarantee until 0.1.0. Wire
   format compatibility with a specific Python version is exercised
   by the `dmp-interop` integration test, but the harness only runs
   against the pinned reference revision in CI.
2. **Test backdoor under `cfg(debug_assertions)`.** The
   `DMP_TEST_INMEMORY_STORE_FILE` env var swaps in a file-backed
   `InMemoryDnsStore` for cross-process test orchestration. It is
   compile-gated to debug builds and absent from release artifacts;
   release verification asserts the symbol is not present in the
   `target/release/` binary.
3. **Replay cache lives in SQLite.** `dmp-rs.sqlite` under the
   config home holds the replay cache, contact pinning, prekey
   private bytes, and intro queue. The file uses default OS
   permissions; on shared systems set `chmod 0700 ~/.dmp` after
   `dnsmesh init`.
4. **Saved bearer tokens / TSIG keys are stored at rest in
   plaintext.** `dnsmesh register` writes
   `tokens/<host>.json`; `dnsmesh tsig register` writes
   `tsig-<host>.key`. Both are 0600 on creation. There is no OS
   keychain integration yet — that's a roadmap item before 0.1.0.
5. **Cloudflare publisher caches the Zone API token in config.**
   `cloudflare.api_token` lives in `config.yaml` (0600). If you'd
   rather not persist it, set `cloudflare.api_token: "${CF_TOKEN}"`
   and export `CF_TOKEN` at runtime — `dnsmesh-rs` resolves
   `${VAR}` substitutions in config strings.
6. **OS resolver auto-detect parses `/etc/resolv.conf` directly.**
   On systems with split-horizon DNS or `systemd-resolved` stub
   resolvers, the parsed list may not match what the system actually
   queries. Override with `resolvers: [...]` in config when in doubt.
7. **No FFI ABI stability promise yet.** `dnsmesh-ffi`'s exported
   surface will move during pre-0.1.0; mobile consumers should pin
   to a specific commit until the FFI surface freezes.
8. **Pre-audit review only.** This port has had iterative internal
   review and is exercised against the Python reference in CI, but
   it has not been through external cryptanalysis. See the Python
   repo's SECURITY.md for the full discussion of why automated and
   peer review do not substitute for a professional audit.

## Out-of-scope for this repository

- Server-side hardening of DMP nodes — see the Python reference.
- Operator deploy / TLS / reverse proxy — see the Python reference's
  `deploy/` directory.
- Wire format and protocol-level threat model — see the Python
  reference's `docs/protocol/` and `SECURITY.md`.

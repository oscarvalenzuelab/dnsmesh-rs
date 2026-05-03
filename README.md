# dnsmesh-rs

**End-to-end encrypted messaging delivered over DNS — Rust SDK and CLI for the
[DNS Mesh Protocol](https://github.com/oscarvalenzuelab/DNSMeshProtocol).**

## What this is

DMP is an open protocol for moving end-to-end encrypted messages between
two people using DNS as the transport. The recipient's identity, prekeys,
and mailbox slots all resolve like any other DNS record; there is no
central server, no app store, and no gatekeeper between sender and
recipient. If DNS works on your network, DMP works on your network.

`dnsmesh-rs` is the Rust port of the client side of that protocol. It
ships:

- A composable **client SDK** so applications can embed DMP without
  binding to a single language runtime.
- A **command-line interface** that doubles as a sendmail-compatible
  MTA stub for `mutt` / `neomutt` and other Maildir-aware clients.
- A **mobile FFI** layer for iOS and Android consumers (UniFFI bindings
  are tracked behind the FFI surface).

The authoritative DNS node, the publish API, and the federation /
cluster code live in the Python reference at
[oscarvalenzuelab/DNSMeshProtocol](https://github.com/oscarvalenzuelab/DNSMeshProtocol).
This crate consumes the same wire format and is exercised against the
reference in CI.

## Why a Rust port

- **Embeddability.** A single static library that drops into iOS,
  Android, server backends, and other Rust crates without forcing a
  Python runtime onto the embedder.
- **Footprint.** No interpreter, no GIL, predictable memory.
- **Deterministic builds.** `cargo` artifacts are signable and
  reproducible; mobile teams can pin a specific commit and ship the
  binary unchanged across stores.

The Rust port is intentionally **client-only**. The node implementation
stays in Python, where its threading model, ops tooling, and federation
story already exist.

## Install

Pick whichever path fits how you usually install command-line tools.

### Pre-built binary (recommended)

Pre-built CLI binaries are published on every `cli-v<semver>` tag at
[github.com/oscarvalenzuelab/dnsmesh-rs/releases](https://github.com/oscarvalenzuelab/dnsmesh-rs/releases).
Six targets ship per release; pick the one matching your machine:

| Platform | Asset |
|---|---|
| macOS (Apple Silicon, and Intel via Rosetta) | `dnsmesh-cli-<version>-aarch64-apple-darwin.tar.gz` |
| Linux — x86_64, glibc | `dnsmesh-cli-<version>-x86_64-unknown-linux-gnu.tar.gz` |
| Linux — x86_64, static (musl) | `dnsmesh-cli-<version>-x86_64-unknown-linux-musl.tar.gz` |
| Linux — aarch64 | `dnsmesh-cli-<version>-aarch64-unknown-linux-gnu.tar.gz` |
| Windows — x86_64 | `dnsmesh-cli-<version>-x86_64-pc-windows-msvc.zip` |
| Windows — aarch64 | `dnsmesh-cli-<version>-aarch64-pc-windows-msvc.zip` |

```sh
# macOS Apple Silicon, latest release:
curl -fsSL -o dnsmesh.tar.gz \
  https://github.com/oscarvalenzuelab/dnsmesh-rs/releases/latest/download/dnsmesh-cli-aarch64-apple-darwin.tar.gz
tar -xzf dnsmesh.tar.gz
sudo install -m 0755 dnsmesh /usr/local/bin/
dnsmesh --version
```

macOS and Windows binaries are code-signed once the signing certs are
configured (see [CONTRIBUTING.md](https://github.com/oscarvalenzuelab/dnsmesh-rs/blob/main/CONTRIBUTING.md#signing-posture));
until then the workflow ships unsigned binaries with a clear log line.

### Build from source

If you have a Rust toolchain (`rustup`), the one-liner is:

```sh
cargo install --git https://github.com/oscarvalenzuelab/dnsmesh-rs \
              --tag cli-v0.1.0 \
              --bin dnsmesh \
              dnsmesh-cli
```

Drop `--tag cli-v0.1.0` to track `main` instead of a tagged release.
Or, if you'd rather check the tree out and have it around for hacking:

```sh
git clone https://github.com/oscarvalenzuelab/dnsmesh-rs
cd dnsmesh-rs
cargo build --workspace --release
sudo install -m 0755 target/release/dnsmesh /usr/local/bin/
```

The release pipeline that produces the prebuilts above runs the same
profile (`--release`, `lto = "thin"`, `codegen-units = 1`, `strip =
true`), so building locally gives you the same binary modulo
code-signing.

## Quickstart

This walks you through publishing an identity to a public DMP node,
adding a contact, and exchanging a message — about five minutes
end-to-end. It assumes `dnsmesh` is on your `$PATH` from one of the
install paths above.

Set a passphrase. **This is the only thing protecting your identity
keys** — back it up like an SSH key. The CLI reads `$DMP_PASSPHRASE`
first, then a 0400-permission file, then an interactive prompt.

```sh
read -rs DMP_PASSPHRASE     # silent — not in shell history
export DMP_PASSPHRASE
```

Initialize, mint credentials against a node, and publish:

```sh
# Create local config + keystore.
dnsmesh init alice --domain dmp.example.com --node example.com

# Mint a per-user TSIG key by HTTPS challenge — one round trip.
dnsmesh tsig register --node example.com

# Publish the identity record + a pool of one-time prekeys.
dnsmesh identity publish
dnsmesh identity refresh-prekeys
```

Add a contact and exchange a message:

```sh
dnsmesh identity fetch bob@dmp.example.com --add
dnsmesh send bob@dmp.example.com "hi bob"
dnsmesh recv
```

Sanity check that DNS sees what you just published:

```sh
dig _dnsmesh-heartbeat.dmp.example.com TXT +short
```

## Read mail with `mutt`

The `dnsmesh` binary speaks just enough of the sendmail interface to
plug into `mutt` / `neomutt` as both a sender and a Maildir source.
Minimal `~/.muttrc`:

```muttrc
set folder      = "$HOME/.dmp/maildir"
set spoolfile   = "+inbox"
set sendmail    = "/path/to/target/release/dnsmesh send -t"
set use_envelope_from = yes
```

Then run a polling loop in another shell:

```sh
dnsmesh recv --maildir ~/.dmp/maildir --watch
```

A complete walkthrough with neomutt, attachments, supervisor wiring
(launchd / systemd / cron), and troubleshooting lives in the
[mutt integration guide](https://oscarvalenzuelab.github.io/dnsmesh-rs/guide/mua-mutt)
on the docs site.

## Crates

This is a Cargo workspace. Embedders pull in only what they need.

| Crate | Kind | Purpose |
| --- | --- | --- |
| `dnsmesh-core` | lib | Protocol primitives, crypto, wire format. |
| `dnsmesh-net` | lib | DNS transport, resolver glue, publishers (TSIG / Cloudflare / node-token). |
| `dnsmesh-storage` | lib | SQLite-backed persistence: identity, contacts, prekeys, replay cache, intro queue. |
| `dnsmesh-client` | lib | High-level `DmpClient` API composing the lower crates. |
| `dnsmesh-ffi` | cdylib / staticlib / rlib | C ABI surface for Kotlin / Swift / Python bindings. |
| `dnsmesh-cli` | bin | The `dnsmesh` command-line interface + MUA integration. |

## Building and testing

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release
```

The release binary lands at `target/release/dnsmesh`. Cross-compilation
profiles for mobile targets are wired through `dnsmesh-ffi`'s build
matrix (see the FFI crate for `aarch64-apple-ios`, `aarch64-linux-android`,
`armv7-linux-androideabi`).

## Differences from the Python reference

- **Same wire format.** Records, manifests, claim records, rotation
  records, prekeys, and chunked payloads are byte-compatible. Python
  ↔ Rust round-trip is exercised in CI.
- **Client-only.** No node, federation, anti-entropy, or operator
  deploy code lives here.
- **SQLite for state** instead of the Python reference's filesystem
  layout. `dmp-rs.sqlite` holds replay cache, contacts, intros, and
  prekey private bytes.
- **Mobile-first FFI.** `dnsmesh-ffi` is a first-class crate, not a
  bolt-on.
- **MUA-compat CLI.** `dnsmesh send -t` accepts the sendmail
  invocation style `mutt` and friends use; `dnsmesh recv --maildir`
  delivers into a Maildir tree.

## License

This Rust port is licensed under the
[MIT License](https://github.com/oscarvalenzuelab/dnsmesh-rs/blob/main/LICENSE).
This is
intentionally asymmetric with the Python reference, which is licensed
AGPL-3.0: the SDK is meant to be embeddable by third-party applications
(mobile apps, server integrations, other Rust crates) without imposing
AGPL obligations on the embedder.

## Contributing

See [CONTRIBUTING.md](https://github.com/oscarvalenzuelab/dnsmesh-rs/blob/main/CONTRIBUTING.md)
and [CODE_OF_CONDUCT.md](https://github.com/oscarvalenzuelab/dnsmesh-rs/blob/main/CODE_OF_CONDUCT.md).
In short: format, clippy-clean,
tests pass, security-relevant changes get called out in the PR template,
and any change touching wire format ships with interop test vectors
against the Python reference.

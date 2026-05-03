---
title: Getting started
layout: default
nav_order: 2
---

# Getting started
{: .no_toc }

Send your first DMP message in five minutes: build the CLI, mint
credentials against a node, publish your identity, add a contact,
and exchange a message.

1. TOC
{:toc}

## What you need

- A Rust toolchain (`rustup`, stable channel) — `cargo --version` should print `1.80` or newer.
- Git.
- A passphrase you'll remember. **It is the only thing protecting your identity keys.** Lose it, you lose the identity. There is no recovery.
- A DMP node you can register against. The reference public node is `dnsmesh.io`; you can also run your own — see the
  [deployment guides at DNSMeshProtocol](https://oscarvalenzuelab.github.io/DNSMeshProtocol/deployment/).

You **don't** need to run a node to use the CLI. The remainder of this
guide assumes you'll register against `dnsmesh.io`.

## 1. Build

```sh
git clone https://github.com/oscarvalenzuelab/dnsmesh-rs
cd dnsmesh-rs
cargo build --workspace --release
export PATH="$PWD/target/release:$PATH"
dnsmesh --version
```

Once a tagged release is cut, prebuilt binaries will be available
under [Releases](https://github.com/oscarvalenzuelab/dnsmesh-rs/releases).
Until then, build from source.

## 2. Set a passphrase

The CLI looks for the passphrase in three places, in priority order:

1. The `DMP_PASSPHRASE` environment variable.
2. A 0400-permission file referenced by `passphrase_file:` in
   `config.yaml`.
3. An interactive TTY prompt.

The simplest path for a quickstart is the env-var route — read it
silently so it does not land in shell history:

```sh
read -rs DMP_PASSPHRASE
export DMP_PASSPHRASE
```

For something more durable, write it to a 0400 file and reference
it from your config:

```sh
install -m 0400 /dev/stdin ~/.dmp/passphrase <<<'your-passphrase-here'
```

```yaml
# in ~/.dmp/config.yaml
passphrase_file: ~/.dmp/passphrase
```

The CLI refuses to read passphrase files with permissive mode bits.

## 3. Initialize an identity

```sh
dnsmesh init alice --domain dmp.example.com --node example.com
```

This creates `~/.dmp/config.yaml`, derives Alice's Ed25519 / X25519
keypair from the passphrase + a freshly-generated 32-byte random
salt, and stores keystore state in `~/.dmp/dmp-rs.sqlite`.

`--domain` is the DNS zone your identity will publish under
(`alice@dmp.example.com`). `--node` is the DMP node you will
register with for publishing credentials.

## 4. Mint credentials at the node

You have three publishing-back-end choices: TSIG, Cloudflare HTTP
API, and node-token HTTP. The most-common path for the public
reference node is TSIG via one HTTPS challenge:

```sh
dnsmesh tsig register --node example.com
```

That writes `~/.dmp/tsig-example.com.key` (mode 0600) and adds a
`publish:` block to `config.yaml`. Every DNS UPDATE after this is
signed with the per-user TSIG key — no further HTTPS round trips.

For Cloudflare-hosted zones use the API token instead:

```sh
dnsmesh init alice --domain dmp.example.com --cloudflare-zone-id <32-hex>
# write the API token to ~/.dmp/cloudflare-token (mode 0600), then:
dnsmesh identity publish
```

For nodes that expose a bearer-token HTTP publish API, see
[`dnsmesh register`]({{ site.baseurl }}/guide/cli#register).

See [Publishers]({{ site.baseurl }}/guide/publishers) for the full
trade-offs between back-ends.

## 5. Publish your identity and a prekey pool

```sh
dnsmesh identity publish
dnsmesh identity refresh-prekeys
```

`publish` writes the long-term identity record. `refresh-prekeys`
writes a pool of one-time X25519 prekeys: senders consume one per
message and the recipient deletes the matching private key on
successful decrypt, giving forward secrecy for prekey-consumed
messages.

Sanity-check that DNS sees what you just wrote:

```sh
dig _dnsmesh-heartbeat.dmp.example.com TXT +short
dig id-$(echo -n alice | sha256sum | cut -c1-16).dmp.example.com TXT +short
```

## 6. Add a contact

To send to bob, you need bob's identity record pinned in your
contacts list. This is the protocol's anchor of trust.

```sh
dnsmesh identity fetch bob@dmp.example.com --add
```

The `--add` flag pins the fetched signing key. After pinning,
subsequent fetches verify the same key returns; a key change is
treated as a trust break and refused unless the chain walker can
prove a legitimate rotation (see [rotation chain]({{ site.baseurl }}/reference/differences#rotation-chain)).

## 7. Send and receive

```sh
dnsmesh send bob@dmp.example.com "hi bob"
dnsmesh recv
```

`recv` walks every mailbox slot under your zone (and, for pinned
contacts in other zones, theirs too), pulls down any new manifests,
verifies signatures, and decrypts the chunked payload back into the
plaintext. Decrypted messages live in the local SQLite store; pass
`--maildir <path>` to also deliver them as RFC 5322 messages into a
Maildir tree your mail client already knows about.

## What now

- [Wire it into mutt]({{ site.baseurl }}/guide/mua-mutt) so
  `dnsmesh` is a sendmail-compatible transport behind your existing
  MUA.
- [Use the SDK from your own application]({{ site.baseurl }}/guide/sdk) instead of the CLI.
- [Embed it on mobile]({{ site.baseurl }}/guide/mobile) via the FFI
  surface.
- Read the [config reference]({{ site.baseurl }}/reference/config)
  for every option in `config.yaml`.

## Troubleshooting

`dnsmesh doctor` is the first thing to run when something is off —
it reports identity state, publisher reachability, prekey-pool
size, and contact pinning consistency. Most "send returned OK but
recv finds nothing" issues are visible from `doctor` output.

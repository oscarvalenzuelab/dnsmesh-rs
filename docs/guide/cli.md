---
title: CLI reference
layout: default
parent: Guide
nav_order: 1
---

# CLI reference
{: .no_toc }

Every `dnsmesh` subcommand and its flags. For getting started end-to-
end, see the [Getting started]({{ site.baseurl }}/getting-started)
walkthrough first.

1. TOC
{:toc}

## Global options

These apply to every subcommand:

| Flag | Purpose |
|---|---|
| `--config <path>` | Path to a YAML config file. Defaults to `$DMP_CONFIG_HOME/config.yaml` or `~/.dmp/config.yaml`. |
| `--passphrase-env <NAME>` | Read the passphrase from the named env var instead of prompting. Use only for non-interactive scripts and CI. |
| `-h`, `--help` | Per-subcommand help. |
| `-V`, `--version` | Print the version and exit. |

## `init`

Create a new identity. Writes `config.yaml` and the SQLite keystore.

```sh
dnsmesh init <username> --domain <zone> [--node <host>]
```

| Flag | Purpose |
|---|---|
| `--domain <zone>` | DNS zone you publish under. Identity address becomes `<username>@<zone>`. |
| `--node <host>` | Hostname of the DMP node you intend to register against. Pre-populates the registration target for later `register` / `tsig register` runs. |
| `--cloudflare-zone-id <id>` | If set, write a `cloudflare:` block instead of a `publish:` block. Mutually exclusive with `--node`. |

`init` is idempotent against an existing config home only if the
new args match the existing identity. To re-init under a different
identity, run [`purge`](#purge) first.

## `register`

Register for a per-user bearer token on a multi-tenant node. The
token authenticates HTTP publishes to the node's
`/v1/records/<name>` endpoint. For RFC 2136 TSIG-based publishes
use [`tsig register`](#tsig-register) instead.

```sh
dnsmesh register --node <host>
```

| Flag | Purpose |
|---|---|
| `--node <host>` | Node hostname (bare host or full URL — scheme + path are stripped). |
| `--subject <subject>` | Subject to register; defaults to `<username>@<domain>` from local config. |
| `--scheme <https\|http>` | URL scheme for the registration call. Always `https` outside of dev runs. |

Saves the bearer token to `<config_home>/tokens/<host>.json`
(mode 0600). The publishing back-end is auto-selected when no
`publish:` / `cloudflare:` block is in config.

## `tsig register`

Register a TSIG key on a multi-tenant node and persist it into the
local config so subsequent `identity publish` / `send` flows go
over RFC 2136 UPDATE signed with that key.

```sh
dnsmesh tsig register --node <host>
```

Writes the secret to `<config_home>/tsig-<host>.key` (mode 0600)
and adds a `publish:` block to `config.yaml`.

## `identity show`

Print this client's identity (username, full address, signing /
DH public-key fingerprints, the DNS name where the identity record
publishes).

```sh
dnsmesh identity show
```

## `identity publish`

Publish the signed identity record to DNS. Required before contacts
can fetch and pin you.

```sh
dnsmesh identity publish [--ttl <seconds>]
```

## `identity refresh-prekeys`

Generate and publish a fresh pool of one-time X25519 prekeys.
Senders consume one prekey per first message and the matching
private key is deleted on successful decrypt — that's where the
forward-secrecy property comes from for prekey-consumed messages.

```sh
dnsmesh identity refresh-prekeys [--count <N>] [--ttl <seconds>]
```

| Flag | Purpose |
|---|---|
| `--count <N>` | Pool size to publish. Default: 50. |
| `--ttl <seconds>` | DNS TTL on the prekey RRset. Default: matches identity record. |

Run this on a cron / systemd timer so the pool never drains.
Senders quietly fall back to the long-term DH key when no prekey
is available, which works but loses forward secrecy.

## `identity fetch`

Fetch and verify another user's identity record.

```sh
dnsmesh identity fetch <subject> [--add]
```

`<subject>` is `<username>@<zone>`. With `--add`, the fetched
signing key is pinned in the local contact list — every
subsequent fetch of this contact verifies the key matches what
was pinned, with rotation-chain walking opt-in via
`rotation_chain_enabled` in config.

## `identity rotate`

Rotate the signing key. Publishes a co-signed `RotationRecord`
(new key ← old key) plus a fresh `IdentityRecord` for the new key.

```sh
dnsmesh identity rotate --reason <routine|compromise|lost-key> [--yes]
```

With `--reason compromise` or `lost-key`, also publishes a self-
signed `RevocationRecord` for the OLD key so rotation-aware
receivers drop in-flight messages signed by the compromised key.

After a `compromise`/`lost-key` rotation, pinned contacts running
older clients (without rotation-chain support) need to re-pin you
out-of-band. With `routine`, contacts walk the chain transparently.

## `identity revoke`

Publish a self-signed `RevocationRecord` for the current key
without rotating to a new one. Use this when shutting down an
identity. For "I lost my key, here's the new one," use `rotate
--reason lost-key` instead.

```sh
dnsmesh identity revoke --reason <retired|lost-key|compromise> [--ttl <seconds>] [--yes]
```

## `identity unpublish`

Walk DNS UPDATE deletes against every record this identity
published — identity record, prekey RRset, all 10 mailbox slots,
rotation/revocation RRset. Local state stays intact. For the
"wipe everything" flow use [`purge`](#purge) instead.

```sh
dnsmesh identity unpublish [--yes]
```

## `contacts`

Local address-book operations.

```sh
dnsmesh contacts list
dnsmesh contacts show <subject>
dnsmesh contacts pin <subject>
dnsmesh contacts trust <subject>
dnsmesh contacts remove <subject>
```

Pinning binds the contact's signing-key fingerprint into the local
keystore. Subsequent fetches verify the pin still holds; a mismatch
without a verifiable rotation chain is a hard refusal.

## `intro`

Inbox for first-contact messages from un-pinned senders. `recv`
quarantines unknown senders here so a typo or a stranger doesn't
get to silently inject into your trusted store.

```sh
dnsmesh intro list
dnsmesh intro show <id>
dnsmesh intro accept <id>      # promote to a pinned contact
dnsmesh intro deny <id>        # add to denylist
```

## `send`

Send an end-to-end-encrypted message.

```sh
dnsmesh send <recipient> "message body"
echo "body" | dnsmesh send <recipient>
dnsmesh send -t < message.eml
```

| Flag | Purpose |
|---|---|
| `-t` | Read the recipient list from RFC 5322 `To:` / `Cc:` / `Bcc:` headers in stdin. This is the sendmail-compatible mode used by `mutt` / `neomutt`. Positional addresses are accepted-and-ignored as a sendmail suppression list. |
| `--subject <s>` | RFC 5322 subject line passthrough (no-op for plain bodies). |
| `--from <addr>` | Override the From: header. Default: this identity's pinned address. |

See the [mutt integration guide]({{ site.baseurl }}/guide/mua-mutt)
for the full MUA wiring.

## `recv`

Poll mailbox slots and emit decrypted messages.

```sh
dnsmesh recv
dnsmesh recv --maildir ~/Mail/dmp
dnsmesh recv --maildir ~/Mail/dmp --watch --interval 30
```

| Flag | Purpose |
|---|---|
| `--maildir <path>` | Deliver decrypted messages as RFC 5322 files into a Maildir tree (`new/`, `cur/`, `tmp/`). |
| `--watch` | Poll on an interval instead of running once. Default interval: 60 seconds. |
| `--interval <seconds>` | Poll cadence in `--watch` mode. |

## `doctor`

Light diagnostics. Reports identity state, publisher reachability,
prekey-pool size, and contact pinning consistency. The first thing
to run when something is off.

```sh
dnsmesh doctor
```

## `purge`

Wipe local state and (with `--remote`) walk DNS UPDATE deletes
against every record this identity published. Use this when
decommissioning an identity instead of `rm ~/.dmp` and waiting on
DNS TTLs.

```sh
dnsmesh purge [--remote] [--yes] [--force-local-after-remote-failure]
```

| Flag | Purpose |
|---|---|
| `--remote` | Also walk DNS UPDATE deletes. Without this, only local state is wiped and published records keep resolving until TTLs expire (24h default). |
| `--yes` | Skip the interactive confirmation. Required for non-interactive scripts. Combined with `--remote`, will happily nuke a production identity. |
| `--force-local-after-remote-failure` | Wipe local state even if `--remote` failed to delete some records. By default a partial remote sweep aborts the local wipe so credentials needed to retry the DNS deletes survive. |

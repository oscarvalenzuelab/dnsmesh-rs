---
title: Config reference
layout: default
parent: Reference
nav_order: 1
---

# Config reference
{: .no_toc }

Every field in `~/.dmp/config.yaml`, what it does, and what
defaults are applied when it's omitted.

1. TOC
{:toc}

## Top-level fields

```yaml
username: alice                      # required
domain: dmp.example.com              # required
db_path: ~/.dmp/dmp-rs.sqlite        # optional, default: <config_home>/dmp-rs.sqlite
resolvers:                           # optional, default: parsed /etc/resolv.conf
  - 1.1.1.1:53
  - 9.9.9.9:53
kdf_salt: <64-hex chars>             # optional, default: random per `init`
publish:                             # optional, mutually exclusive with `cloudflare:`
  zone: dmp.example.com
  server: 192.0.2.1:53
  tsig_key_name: dmp-publish-alice
  tsig_algorithm: hmac-sha256
  tsig_secret_path: ~/.dmp/tsig-example.com.key
cloudflare:                          # optional, mutually exclusive with `publish:`
  zone_id: 0123456789abcdef0123456789abcdef
  api_token_path: ~/.dmp/cloudflare-token
```

### `username` (required)

Local-part of your DMP address. Used to derive the identity record
DNS name (`id-<sha256(username)[:16]>.<domain>` for hash-based
identities, or `dmp.<domain>` for zone-anchored identities).

### `domain` (required)

DNS zone you publish under. The full address is
`<username>@<domain>`. For zone-anchored deployments where you
control the entire zone, this is your zone (`alice.example.com`)
and identity records publish at `dmp.<domain>`. For shared mesh
deployments, this is the mesh zone (`dmp.dnsmesh.io`) and
identity records publish at the hashed name.

### `db_path` (optional)

SQLite database holding the replay cache, contact pinning, prekey
private bytes, and intro queue. Default location is
`<config_home>/dmp-rs.sqlite` (typically `~/.dmp/dmp-rs.sqlite`).

The file uses default OS permissions on creation. On shared
systems, set `chmod 0700 ~/.dmp` after `dnsmesh init` to keep
other users from reading it.

### `resolvers` (optional)

List of recursive resolvers to query. Each entry is `host:port`
or `host` (defaults to `:53`). When omitted, the client parses
`/etc/resolv.conf` and uses what the OS uses.

```yaml
resolvers:
  - 1.1.1.1:53
  - 9.9.9.9:53
  - 8.8.8.8:53
```

On systems with split-horizon DNS or a `systemd-resolved` stub
listener at `127.0.0.53`, the auto-detect may not reflect what
the system actually queries. Set this explicitly when in doubt.

### `kdf_salt` (optional)

Argon2id salt used to derive the X25519 + Ed25519 identity from
the passphrase. 32 bytes, encoded as 64 hex chars.

`dnsmesh init` writes a fresh random salt here. **Don't change
it after init** — every byte of the keypair depends on this salt,
so changing it is equivalent to throwing away the identity.

When the field is absent, the SDK falls back to a fixed sentinel
salt for compatibility with library demos. **The sentinel path
is weaker against targeted offline attack and is a footgun** —
production deployments must persist a real random salt (which
the CLI does automatically).

### `publish` (optional, mutually exclusive with `cloudflare:`)

TSIG-signed RFC 2136 publish target.

```yaml
publish:
  zone: dmp.example.com
  server: 192.0.2.1:53
  tsig_key_name: dmp-publish-alice
  tsig_algorithm: hmac-sha256          # default: hmac-sha256
  tsig_secret_path: ~/.dmp/tsig-example.com.key
```

| Field | Required | Notes |
|---|---|---|
| `zone` | yes | Authoritative zone you're allowed to UPDATE under. |
| `server` | yes | `host:port` of the authoritative server. Hostnames are accepted; the resolver from `resolvers:` is used to resolve it. |
| `tsig_key_name` | yes | TSIG key name as configured on the server. |
| `tsig_algorithm` | no | One of `hmac-sha256`, `hmac-sha384`, `hmac-sha512`. Default: `hmac-sha256`. |
| `tsig_secret_path` | yes | Path to a file holding the TSIG secret as base64. Inline secrets in YAML are not supported on purpose — the on-disk config stays safe to share. |

### `cloudflare` (optional, mutually exclusive with `publish:`)

Cloudflare HTTP API publish target.

```yaml
cloudflare:
  zone_id: 0123456789abcdef0123456789abcdef
  api_token_path: ~/.dmp/cloudflare-token
```

| Field | Required | Notes |
|---|---|---|
| `zone_id` | yes | Cloudflare zone ID — the 32-char hex string from the zone dashboard, **not** the human-readable zone name. The publisher hard-fails on a non-32-hex value at startup. |
| `api_token_path` | yes | Path to a file holding the Cloudflare API token (raw text, no `base64:` / `hex:` envelope). The token must hold `Zone:DNS:Edit` for `zone_id`. |

A config carrying both `publish:` and `cloudflare:` blocks fails
at load time with a clear remediation message — there is no
implicit precedence. Pick one and delete the other.

## Auto-discovered HTTP-token publishing

When neither `publish:` nor `cloudflare:` is configured, the
client looks for saved bearer tokens at
`<config_home>/tokens/<host>.json` (mode 0600) — written by
`dnsmesh register`. Tokens are filtered to entries whose `subject`
matches the current `<username>@<domain>` so a stray token from a
prior `init` cannot silently become this session's writer.

## File modes the CLI enforces

| Path | Mode | Why |
|---|---|---|
| `~/.dmp/passphrase` | 0400 | Refuses to read with broader bits set. |
| `~/.dmp/tsig-*.key` | 0600 | TSIG secret. |
| `~/.dmp/cloudflare-token` | 0600 | API token. |
| `~/.dmp/tokens/*.json` | 0600 | Saved bearer tokens. |

## Environment variables

| Variable | Purpose |
|---|---|
| `DMP_CONFIG_HOME` | Override the default `~/.dmp` directory. |
| `DMP_PASSPHRASE` | Passphrase for non-interactive runs. Highest precedence. |
| `DMP_PASSPHRASE_FILE` | Absolute path to a 0400 file holding the passphrase. |
| `RUST_LOG` | Tracing filter. `dnsmesh=debug` is a useful default. |

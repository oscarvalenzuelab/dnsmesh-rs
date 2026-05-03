---
title: Publishers
layout: default
parent: Guide
nav_order: 5
---

# Publishers
{: .no_toc }

How `dnsmesh` writes records into DNS, and which back-end to choose
for which deployment.

1. TOC
{:toc}

## Three back-ends

| Back-end | Wire | Use when |
|---|---|---|
| **TSIG** | RFC 2136 UPDATE + RFC 8945 TSIG | Authoritative server speaks RFC 2136. Most self-hosted DMP nodes. The lowest-friction path. |
| **Cloudflare** | Cloudflare HTTP API | Your zone is hosted on Cloudflare. Skips the DNS UPDATE round trip; uses the Cloudflare REST API instead. |
| **Node-token HTTP** | Bearer-token POST/DELETE to `/v1/records/<name>` on a DMP node | Multi-tenant nodes that gate publishing behind per-user tokens (a registration-API contract, not a DNS contract). |

Exactly one back-end is active at a time. A config that carries
both a `publish:` and a `cloudflare:` block fails at load time
with a clear remediation message — there is no implicit
precedence to remember.

## Choosing one

- If you control the authoritative DNS server (BIND, Knot,
  PowerDNS, dnsmesh-node), use **TSIG**. It's the most efficient:
  one signed UDP packet per write, no HTTP layer.
- If your zone lives on **Cloudflare**, use the Cloudflare API.
  TSIG against Cloudflare doesn't work — they don't expose RFC
  2136 — so this is the right path.
- If you're publishing under someone else's mesh zone (e.g.
  `dmp.dnsmesh.io`), the operator decides which back-end you can
  use. The reference public node accepts both **TSIG** (after
  `dnsmesh tsig register`) and **node-token HTTP** (after
  `dnsmesh register`).

## TSIG

`dnsmesh tsig register --node <host>` mints a per-user TSIG key
via one HTTPS challenge and writes a `publish:` block plus a
`tsig-<host>.key` file. After that, every publish is a signed
RFC 2136 UPDATE — no further HTTPS round-trips.

The `publish:` block in `config.yaml`:

```yaml
publish:
  zone: dmp.example.com
  server: 192.0.2.1:53
  tsig_key_name: dmp-publish-alice
  tsig_algorithm: hmac-sha256
  tsig_secret_path: ~/.dmp/tsig-example.com.key
```

The TSIG secret stays on disk in a 0600 file rather than inline
in YAML so the config remains safe to share.

## Cloudflare

`init` with `--cloudflare-zone-id <32-hex>` writes a `cloudflare:`
block. Persist the API token to a 0600 file and reference it from
the block:

```yaml
cloudflare:
  zone_id: 0123456789abcdef0123456789abcdef
  api_token_path: ~/.dmp/cloudflare-token
```

The API token must hold `Zone:DNS:Edit` for the configured
`zone_id` (not the human-readable zone name — the publisher
hard-fails on a non-32-hex zone_id at startup with a clear error).

The publisher serializes concurrent writes to the same record-
name to avoid the GET-then-POST/PUT race that would otherwise
let two `publish_txt_record` calls both miss an existing record
and create duplicates.

## Node-token HTTP

`dnsmesh register --node <host>` issues a registration challenge
(HTTPS GET) and confirms it (HTTPS POST), receiving a per-user
bearer token in return. The token is saved to
`<config_home>/tokens/<host>.json` (mode 0600).

When neither `publish:` nor `cloudflare:` is configured, the
client auto-discovers saved tokens for the current subject and
publishes via bearer-authenticated POST/DELETE to
`/v1/records/<name>` on the node.

Tokens are filtered by subject — a stray token from a previous
`init` under a different identity in the same config home cannot
silently become this session's writer.

## Readers

The DNS reader is independent of the publisher. By default
`dnsmesh-rs` queries the OS resolvers parsed from
`/etc/resolv.conf`. Override with an explicit list in
`config.yaml`:

```yaml
resolvers:
  - 1.1.1.1:53
  - 9.9.9.9:53
```

On systems with split-horizon DNS or `systemd-resolved` stub
resolvers, the auto-detect may not match what the system actually
queries — set `resolvers:` explicitly when in doubt.

## Test back-end

`InMemoryDnsStore` is a process-local mock store implementing
both reader and writer. Use it in unit / integration tests so
the harness doesn't depend on a live DNS path. **It is not safe
for production** — it is process-local and provides no
authentication. The CLI guards entry into in-memory mode behind
a `cfg(debug_assertions)` env-var backdoor, absent from release
artifacts.

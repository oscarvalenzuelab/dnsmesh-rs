---
title: Home
layout: default
nav_order: 1
---

# dnsmesh-rs
{: .fs-9 }

Rust SDK and CLI for the DNS Mesh Protocol — end-to-end encrypted
messaging delivered over DNS, with a sendmail-compatible bridge for
`mutt`/`neomutt` and an FFI surface for iOS and Android consumers.
{: .fs-6 .fw-300 }

[Get started]({{ site.baseurl }}/getting-started){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[Mutt integration]({{ site.baseurl }}/guide/mua-mutt){: .btn .fs-5 .mb-4 .mb-md-0 .mr-2 }
[Protocol spec](https://github.com/oscarvalenzuelab/DNSMeshProtocol){: .btn .fs-5 .mb-4 .mb-md-0 .mr-2 }
[GitHub](https://github.com/oscarvalenzuelab/dnsmesh-rs){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## What this is

DMP is an open protocol for moving end-to-end encrypted messages
between two people using DNS as the transport. The recipient's
identity, prekeys, and mailbox slots resolve like any other DNS
record. There is no central server, no app store, no gatekeeper
between sender and recipient.

`dnsmesh-rs` is the Rust port of the **client** side of that
protocol. The protocol specification, the authoritative DNS node,
and the federation / cluster code live in the Python reference at
[oscarvalenzuelab/DNSMeshProtocol](https://github.com/oscarvalenzuelab/DNSMeshProtocol).
This port consumes the same wire format, byte-for-byte, and is
exercised against the reference in CI.

This site documents the Rust port. For protocol questions —
threat model, wire format, claim routing, rotation chain semantics
— follow the link out to the spec repository.

## Why a Rust port

- **Embeddability.** A single static library for iOS, Android,
  server backends, and other Rust crates without forcing a Python
  runtime onto the embedder.
- **Deterministic builds.** `cargo` artifacts are signable and
  reproducible; mobile teams pin a specific commit and ship the
  binary unchanged across stores.
- **Footprint.** No interpreter, no GIL, predictable memory.

The Rust port is intentionally **client-only**. The node
implementation stays in Python, where its threading model,
operational tooling, and federation story already exist.

## Where to go next

| If you want to… | Read |
|---|---|
| Send your first message | [Getting started]({{ site.baseurl }}/getting-started) |
| Wire `dnsmesh` into mutt / neomutt | [Mutt integration guide]({{ site.baseurl }}/guide/mua-mutt) |
| Use the SDK from your own Rust application | [SDK guide]({{ site.baseurl }}/guide/sdk) |
| Embed on iOS / Android | [Mobile bindings]({{ site.baseurl }}/guide/mobile) |
| Understand publishing back-ends (TSIG / Cloudflare / HTTP token) | [Publishers]({{ site.baseurl }}/guide/publishers) |
| See `dnsmesh` subcommand reference | [CLI reference]({{ site.baseurl }}/guide/cli) |
| Understand on-disk config | [Config reference]({{ site.baseurl }}/reference/config) |
| Compare to the Python reference | [Differences from the Python reference]({{ site.baseurl }}/reference/differences) |
| Understand the threat model | [Python repo's SECURITY.md](https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/SECURITY.md) |

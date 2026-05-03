---
title: SDK guide
layout: default
parent: Guide
nav_order: 2
---

# SDK guide
{: .no_toc }

Use `dnsmesh-client` from your own Rust application. The CLI is a
thin wrapper around this same SDK; everything the CLI does, an
embedder can do directly.

1. TOC
{:toc}

## Crate map

`dnsmesh-rs` is a Cargo workspace. Pull in only what your
application needs.

| Crate | When to depend on it |
|---|---|
| `dnsmesh-core` | You need wire-format encode/decode, crypto primitives, signature verification, or claim-record parsing without the network or storage layers. |
| `dnsmesh-net` | You need the DNS resolver, a publishing back-end, or to compose your own client at a lower level than `DmpClient`. |
| `dnsmesh-storage` | You need the SQLite-backed keystore / contacts / replay-cache abstractions. |
| `dnsmesh-client` | High-level `DmpClient`. Composes the lower crates and is the right starting point for most embedders. |
| `dnsmesh-ffi` | You're writing a non-Rust consumer (mobile app, Swift / Kotlin host). See the [Mobile bindings guide]({{ site.baseurl }}/guide/mobile). |

## Minimal example

A complete in-memory round-trip — alice publishes, bob fetches and
pins, alice sends, bob receives — without touching the network. The
runnable form lives at
[`examples/send-recv/`](https://github.com/oscarvalenzuelab/dnsmesh-rs/tree/main/examples/send-recv).

```rust
use std::sync::Arc;
use dnsmesh_client::{DmpClient, DmpClientConfig};
use dnsmesh_net::store::InMemoryDnsStore;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let store = Arc::new(InMemoryDnsStore::new());

    let alice = DmpClient::with_in_memory_store(
        DmpClientConfig::test_config("alice", "alice.zone"),
        store.clone(),
    )
    .await?;
    let bob = DmpClient::with_in_memory_store(
        DmpClientConfig::test_config("bob", "bob.zone"),
        store.clone(),
    )
    .await?;

    alice.publish_identity().await?;
    alice.refresh_prekeys(10).await?;

    bob.fetch_identity("alice@alice.zone").await?.pin().await?;
    alice.fetch_identity("bob@bob.zone").await?.pin().await?;

    alice.send("bob@bob.zone", b"hi bob").await?;

    let received = bob.recv().await?;
    assert_eq!(received[0].body(), b"hi bob");
    Ok(())
}
```

## Constructing a real client

For non-test code, build a `DmpClient` from a `DmpClientConfig`
that wires up:

1. A [DNS reader]({{ site.baseurl }}/guide/publishers#readers) — the resolver pool used for fetches.
2. A [publisher]({{ site.baseurl }}/guide/publishers) — TSIG, Cloudflare, or HTTP-token.
3. A [storage handle]({{ site.baseurl }}/reference/config#dmp-rs-sqlite) — almost always `dmp-rs.sqlite` under the config home.
4. The identity passphrase (and optionally a custom KDF salt).

The CLI's `client_factory.rs` is the canonical reference for how
to assemble these from a `config.yaml` on disk.

## Receiving asynchronously

`recv` returns a `Vec<ReceivedMessage>`; for long-lived
applications use the streaming variant:

```rust
use futures::StreamExt;

let mut stream = client.recv_stream(std::time::Duration::from_secs(60));
while let Some(msg) = stream.next().await {
    handle(msg?);
}
```

The stream walks every mailbox slot, follows pinned contacts'
zones for cross-zone messages, deduplicates against the local
replay cache, and emits each successfully-decrypted message
exactly once.

## Error handling

`DmpClient` returns `dnsmesh_client::ClientError`, a structured
error enum with variants for crypto failures, network errors,
storage errors, and protocol-level rejections (signature
verification failed, replay, expired). Match on variants rather
than string-comparing.

## Wire-format compatibility

The Rust port and the Python reference exchange messages bit-for-
bit. The interop test under
`crates/dnsmesh-client/tests/python_interop.rs` runs as part of CI
and is the gate for any change touching wire format.

If you're reading or writing DMP records outside `dnsmesh-client`
— for instance, building a directory aggregator or a server-side
manifest validator — depend on `dnsmesh-core` directly and use the
parsers there. Nothing in `-core` touches the network or
filesystem.

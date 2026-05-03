# `examples/send-recv`

Minimal end-to-end send + receive using `dnsmesh-client` directly.
Two clients (alice and bob) share an `InMemoryDnsStore`, so the
example runs entirely in-process — no DNS lookups, no network I/O,
no operator-side state to set up.

## Run

```sh
cd examples/send-recv
cargo run --release
```

Expected output (hex digests will differ per build because the
identity passphrase + salt is the only deterministic input):

```
sent message <32 hex>
received from spk=<64 hex> (43 bytes): hello from the dnsmesh-rs send-recv example
replay cache held — second receive returned 0 messages
```

## What it shows

1. **Identity publish.** `alice.publish_identity()` writes the
   signed identity record to the (in-memory) DNS store. Same call
   shape against a real publisher.
2. **Prekey publish.** `refresh_prekeys(10, 3600)` writes ten
   one-time X25519 prekeys with a 1-hour TTL. The recipient
   deletes the matching private key on successful decrypt — this
   is where forward secrecy comes from for prekey-consumed
   messages.
3. **Identity fetch + pin.** `fetch_identity` resolves a contact's
   identity record; `add_contact` pins the signing-key fingerprint
   in the local keystore so subsequent fetches are verified
   against the pin.
4. **Send.** `send_message` ECDH's a fresh ephemeral key against
   the recipient's prekey, AEAD-seals the body, chunks it across
   one or more chunk RRsets, and publishes a signed slot manifest.
5. **Receive.** `receive_messages` walks every mailbox slot,
   pulls down the manifest, fetches the chunks, verifies the
   manifest signature, decrypts the body, and deduplicates against
   the replay cache.
6. **Replay defense.** A second `receive_messages` call returns
   an empty Vec — the per-(sender_spk, msg_id) cache prevents
   re-delivery.

## Going from this to a real client

To swap in a real DNS reader / writer, replace the
`InMemoryDnsStore` with the resolver pool and publisher you want.
Concretely, the CLI's `client_factory.rs` builds a `reader: Arc<dyn
DnsRecordReader>` from a resolver list and a `writer: Arc<dyn
DnsRecordWriter>` from one of:

- `Arc::new(TsigPublisher::new(publish_config)?)` — RFC 2136 + TSIG.
- `Arc::new(CloudflarePublisher::new(cloudflare_config)?)` — Cloudflare HTTP API.
- `Arc::new(NodeTokenPublisher::new(saved_token)?)` — bearer-token HTTP.

Everything else above stays the same.

## Note on `kdf_salt`

The example pads the username out to a 16-byte salt for
simplicity. **Production code must pass a 32-byte cryptographically
random salt** — typically `dnsmesh init` generates one and persists
it in `config.yaml` under `kdf_salt`. Re-using the same passphrase
across two random salts produces two independent identities.

# Examples

Runnable (and skeleton) examples for `dnsmesh-rs`.

| Directory | What it shows | Status |
|---|---|---|
| [`send-recv/`](https://github.com/oscarvalenzuelab/dnsmesh-rs/tree/main/examples/send-recv) | End-to-end `DmpClient` round-trip against an in-memory DNS store. Two clients in one process, no network, no operator state. | Runnable: `cd send-recv && cargo run --release`. |
| [`ios-bridge/`](https://github.com/oscarvalenzuelab/dnsmesh-rs/tree/main/examples/ios-bridge) | Skeleton Swift package consuming the `dnsmesh-ffi` xcframework. | Scaffold only — needs the xcframework built locally and `Package.swift` flipped to the real `binaryTarget`. |

For wiring `dnsmesh` into mutt or neomutt as a sendmail-compatible
transport, see the [mutt integration guide](https://oscarvalenzuelab.github.io/dnsmesh-rs/guide/mua-mutt)
on the docs site and the
[`crates/dnsmesh-cli/examples/`](https://github.com/oscarvalenzuelab/dnsmesh-rs/tree/main/crates/dnsmesh-cli/examples)
muttrc reference.

# `examples/ios-bridge`

Skeleton Swift package showing how an iOS or macOS application
would consume the `dnsmesh-ffi` xcframework once mobile binding
generation lands. **This is a scaffold, not a runnable demo.**

## What you need

- A Rust toolchain with `aarch64-apple-ios` and (for simulator
  builds on Apple Silicon) `aarch64-apple-ios-sim` targets
  installed:

  ```sh
  rustup target add aarch64-apple-ios aarch64-apple-ios-sim
  ```

- Xcode command-line tools (`xcrun`, `xcodebuild`).
- Swift 5.9+.

## Build the xcframework locally

Until the first `mobile-v<semver>` tag is cut and the release
pipeline starts publishing pre-built artifacts, build the
xcframework yourself:

```sh
# From the dnsmesh-rs repository root.
cargo build --release --target aarch64-apple-ios -p dnsmesh-ffi
cargo build --release --target aarch64-apple-ios-sim -p dnsmesh-ffi

# Combine into an xcframework.
xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libdnsmesh_ffi.a \
    -library target/aarch64-apple-ios-sim/release/libdnsmesh_ffi.a \
    -output examples/ios-bridge/DnsMesh.xcframework
```

(For x86_64 simulator hosts, also build `--target
x86_64-apple-ios` and add a third `-library` argument. For
universal simulator builds, lipo the two simulator slices first.)

## Wire it into the Swift package

After running the build above, `examples/ios-bridge/`
contains a real `DnsMesh.xcframework`. Open `Package.swift`
and:

1. Uncomment the `binaryTarget` and the dependent `target`
   blocks.
2. Delete the placeholder target right below them.
3. Move `Sources/DnsMesh/Placeholder.swift` aside (or delete it)
   and drop the generated Swift bindings in there once
   `dnsmesh-ffi`'s UniFFI bindgen is wired up.

```sh
swift build
swift test     # once you add tests
```

## Consuming the API

The intended usage shape (subject to change before 1.0):

```swift
import DnsMesh

let config = try DmpClientConfig(
    username: "alice",
    domain: "alice.example.com",
    publishMode: .nodeToken(host: "example.com")
)
let client = try DmpClient(config: config, passphrase: passphrase)

try await client.publishIdentity()
try await client.refreshPrekeys(count: 50)

let bobId = try await client.fetchIdentity("bob@example.com")
try await client.pinContact(bobId)

try await client.send(
    to: "bob@example.com",
    body: "hi from iOS".data(using: .utf8)!
)

for message in try await client.receive() {
    print("\(message.senderAddress ?? "<unpinned>"): \(String(data: message.plaintext, encoding: .utf8) ?? "<binary>")")
}
```

## Roadmap before this becomes runnable

- UniFFI integration in `crates/dnsmesh-ffi` so the high-level
  Swift / Kotlin bindings are generated rather than hand-rolled.
- Pre-built xcframework artifacts attached to `mobile-v<semver>`
  GitHub releases.
- A SwiftUI sample app target alongside this skeleton.

See [Mobile bindings](https://oscarvalenzuelab.github.io/dnsmesh-rs/guide/mobile)
on the docs site for the broader context (or read the source at
[`docs/guide/mobile.md`](https://github.com/oscarvalenzuelab/dnsmesh-rs/blob/main/docs/guide/mobile.md)
until the site is published).

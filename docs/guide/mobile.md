---
title: Mobile bindings
layout: default
parent: Guide
nav_order: 4
---

# Mobile bindings
{: .no_toc }

Embed `dnsmesh-rs` into iOS and Android applications via the FFI
crate. The Rust port is mobile-ready by design — `dnsmesh-ffi`
exposes a stable C ABI surface that can be consumed directly or
through generated Swift / Kotlin bindings.

1. TOC
{:toc}

{: .warning }
> **FFI surface is pre-1.0.** The exported C symbols, struct
> layouts, and Swift / Kotlin binding shapes will change before
> the first tagged release. Mobile consumers should pin to a
> specific commit until the FFI surface freezes.

## Build artifacts

The release pipeline (`mobile.yml`, tag prefix `mobile-v<semver>`)
produces:

| Platform | Artifact |
|---|---|
| iOS (device + universal simulator) | `DnsMesh.xcframework` |
| Android (four ABIs: `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`) | `dnsmesh-ffi-<version>.aar` |
| Generated language bindings | Swift sources + Kotlin sources alongside the binary artifacts |

Until the first `mobile-v` tag is cut, build locally:

```sh
# iOS device
cargo build --release --target aarch64-apple-ios -p dnsmesh-ffi

# iOS simulator (Apple Silicon hosts)
cargo build --release --target aarch64-apple-ios-sim -p dnsmesh-ffi

# Android arm64
cargo ndk -t arm64-v8a build --release -p dnsmesh-ffi
```

The `xcframework` and `aar` packagings are produced by
[`build-mobile.sh`](https://github.com/oscarvalenzuelab/dnsmesh-rs/blob/main/scripts/build-mobile.sh)
in the repository.

## Swift integration (iOS)

A skeleton Swift package consuming the xcframework lives at
[`examples/ios-bridge/`](https://github.com/oscarvalenzuelab/dnsmesh-rs/tree/main/examples/ios-bridge).
Drop the xcframework into `Frameworks/`, point `Package.swift` at
it, and the generated Swift bindings under
`Sources/DnsMesh/` expose the high-level client API:

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

try await client.send(to: "bob@example.com", body: "hi from iOS".data(using: .utf8)!)
```

## Kotlin integration (Android)

The `aar` ships native libraries plus generated Kotlin bindings.
Add it as a module dependency:

```kotlin
// settings.gradle.kts
include(":dnsmesh-ffi")
project(":dnsmesh-ffi").projectDir = file("path/to/dnsmesh-ffi-<version>.aar")

// app/build.gradle.kts
dependencies {
    implementation(project(":dnsmesh-ffi"))
}
```

```kotlin
import com.dnsmesh.DmpClient
import com.dnsmesh.DmpClientConfig

val config = DmpClientConfig(
    username = "alice",
    domain = "alice.example.com",
    publishMode = PublishMode.NodeToken("example.com"),
)
val client = DmpClient.create(config, passphrase)

client.publishIdentity()
client.refreshPrekeys(count = 50)
```

## Threading and runtimes

The FFI surface is **synchronous from the host language's
perspective**. Internally, `dnsmesh-ffi` builds a single Tokio
runtime per `DmpClient` and `block_on`s into it. Calling an FFI
method from inside a Tokio runtime on the Rust side is detected
and rejected with a typed `AlreadyInTokioContext` error rather
than a panic — but this is mostly relevant for non-mobile
embedders. Mobile callers calling from the main thread or a
background queue will not hit it.

## Storage

The mobile FFI accepts an optional `storagePath` parameter; if
omitted, it uses an OS-conventional default (iOS: app Documents
directory; Android: app files directory). The on-disk layout is
the same `dmp-rs.sqlite` + `tsig-*.key` + `tokens/` tree the CLI
uses, so a config home is portable between the CLI and a mobile
embedding for the same identity.

## Roadmap before 1.0

- ABI stability commitment.
- Code-signing wired through the release pipeline (Apple Developer
  ID + Authenticode — see [CONTRIBUTING.md](https://github.com/oscarvalenzuelab/dnsmesh-rs/blob/main/CONTRIBUTING.md#signing-posture)).
- Sample app shells for iOS (SwiftUI) and Android (Compose).
- OS-keychain integration so the passphrase is held in the device
  secure enclave rather than passed through the FFI.

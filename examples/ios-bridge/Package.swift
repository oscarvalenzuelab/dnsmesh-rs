// swift-tools-version: 5.9
//
// Skeleton Swift package consuming the dnsmesh-ffi xcframework.
//
// The xcframework is not yet pre-built — until the first
// `mobile-v<semver>` release tag is cut, build it locally per the
// instructions in the accompanying README.md, drop the resulting
// `DnsMesh.xcframework` next to this Package.swift, and uncomment
// the binaryTarget block below.

import PackageDescription

let package = Package(
    name: "DnsMesh",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
    ],
    products: [
        .library(
            name: "DnsMesh",
            targets: ["DnsMesh"]
        ),
    ],
    targets: [
        // Once you have a built xcframework on disk, uncomment this
        // block and remove the placeholder target below it.
        //
        // .binaryTarget(
        //     name: "DnsMeshFFI",
        //     path: "DnsMesh.xcframework"
        // ),
        // .target(
        //     name: "DnsMesh",
        //     dependencies: ["DnsMeshFFI"],
        //     path: "Sources/DnsMesh"
        // ),

        // Placeholder target so `swift build` doesn't fail when the
        // xcframework isn't on disk yet. Delete this when wiring the
        // real binaryTarget above.
        .target(
            name: "DnsMesh",
            path: "Sources/DnsMesh",
            sources: ["Placeholder.swift"]
        ),
    ]
)

#!/usr/bin/env bash
#
# Build the x86_64-apple-darwin (Intel Mac) artifacts locally on
# Apple Silicon and upload them to the existing GitHub release pages
# for `cli-v<version>` and `sdk-v<version>`.
#
# Background: the GHA `macos-13` free-tier runner pool is exhausted
# in practice — release jobs targeting `x86_64-apple-darwin` sit in
# queue indefinitely. macOS 13 itself reached end-of-life in November
# 2025. The release matrix in `.github/workflows/release.yml`
# therefore omits `x86_64-apple-darwin`. This script is the per-tag
# manual step that fills the gap, producing artifacts byte-equivalent
# to what the GHA matrix would have produced (same `--release` profile,
# same packaging, same naming).
#
# Usage:
#   scripts/release-darwin-x86.sh <version>
# Example:
#   scripts/release-darwin-x86.sh 0.1.0
#
# Requires:
#   - Apple Silicon Mac with rustup + cargo
#   - rustup target add x86_64-apple-darwin
#   - gh CLI authenticated against the repo (`gh auth status`)
#   - cli-v<version> and sdk-v<version> releases must already exist
#     on github (i.e. push the tags first, let the GHA workflow run,
#     then run this script to add the missing target).

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <version>" >&2
    echo "example: $0 0.1.0" >&2
    exit 64
fi

VERSION="$1"
TARGET="x86_64-apple-darwin"
REPO="oscarvalenzuelab/dnsmesh-rs"

# Sanity: refuse to run on anything but Apple Silicon (cross-compile
# from arm64 to x86_64 is the supported path; from x86_64 we'd just
# be doing a native build).
if [[ "$(uname -m)" != "arm64" || "$(uname -s)" != "Darwin" ]]; then
    echo "error: this script expects an Apple Silicon Mac (uname -m == arm64); got $(uname -m) on $(uname -s)" >&2
    exit 1
fi

# Sanity: workspace version must match the version arg.
WORKSPACE_VERSION="$(awk -F'"' '/^version = /{print $2; exit}' Cargo.toml)"
if [[ "$WORKSPACE_VERSION" != "$VERSION" ]]; then
    echo "error: arg version=$VERSION but Cargo.toml workspace.package.version=$WORKSPACE_VERSION" >&2
    echo "       sync the two before running this script — typically by checking out the release tag" >&2
    exit 1
fi

# Sanity: target installed?
if ! rustup target list --installed 2>/dev/null | grep -qx "$TARGET"; then
    echo "error: rust target '$TARGET' not installed. run: rustup target add $TARGET" >&2
    exit 1
fi

# Sanity: gh logged in?
if ! gh auth status >/dev/null 2>&1; then
    echo "error: gh CLI not authenticated. run: gh auth login" >&2
    exit 1
fi

# Sanity: do the cli-v + sdk-v releases exist on github?
for tag in "cli-v$VERSION" "sdk-v$VERSION"; do
    if ! gh release view "$tag" -R "$REPO" >/dev/null 2>&1; then
        echo "error: release '$tag' does not exist on $REPO" >&2
        echo "       push the tag first and let the GHA workflow create the release," >&2
        echo "       then run this script to fill in the $TARGET artifact" >&2
        exit 1
    fi
done

echo "==> building $TARGET artifacts for v$VERSION"
cargo build -p dnsmesh-cli --release --target "$TARGET"
cargo build -p dnsmesh-ffi --release --target "$TARGET"

# Smoke-test the CLI binary. Will run via Rosetta on Apple Silicon
# but exits with the right version string.
echo "==> smoke test"
"target/$TARGET/release/dnsmesh" --version

# Verify Mach-O archs are correct (Rosetta would still execute the
# wrong arch silently, so explicit check).
file "target/$TARGET/release/dnsmesh" | grep -q 'x86_64' \
    || { echo "error: dnsmesh binary is not Mach-O x86_64" >&2; exit 1; }
file "target/$TARGET/release/libdnsmesh_ffi.dylib" | grep -q 'x86_64' \
    || { echo "error: libdnsmesh_ffi.dylib is not Mach-O x86_64" >&2; exit 1; }

# Stage + tarball, matching the layout `release.yml`'s "Package CLI
# tarball (unix)" / "Package SDK tarball (unix)" steps produce.
STAGE_DIR="$(mktemp -d -t dnsmesh-release.XXXXXX)"
trap 'rm -rf "$STAGE_DIR"' EXIT

cli_stage="dnsmesh-cli-$VERSION-$TARGET"
mkdir -p "$STAGE_DIR/$cli_stage"
cp "target/$TARGET/release/dnsmesh" "$STAGE_DIR/$cli_stage/"
cp LICENSE README.md "$STAGE_DIR/$cli_stage/"
tar -C "$STAGE_DIR" -czf "$STAGE_DIR/$cli_stage.tar.gz" "$cli_stage"

sdk_stage="dnsmesh-sdk-$VERSION-$TARGET"
mkdir -p "$STAGE_DIR/$sdk_stage"
cp "target/$TARGET/release/libdnsmesh_ffi.dylib" "$STAGE_DIR/$sdk_stage/"
cp "target/$TARGET/release/libdnsmesh_ffi.a" "$STAGE_DIR/$sdk_stage/"
cp LICENSE README.md "$STAGE_DIR/$sdk_stage/"
tar -C "$STAGE_DIR" -czf "$STAGE_DIR/$sdk_stage.tar.gz" "$sdk_stage"

echo "==> uploading to github releases"
gh release upload "cli-v$VERSION" "$STAGE_DIR/$cli_stage.tar.gz" -R "$REPO" --clobber
gh release upload "sdk-v$VERSION" "$STAGE_DIR/$sdk_stage.tar.gz" -R "$REPO" --clobber

echo "==> done"
echo "  https://github.com/$REPO/releases/tag/cli-v$VERSION"
echo "  https://github.com/$REPO/releases/tag/sdk-v$VERSION"

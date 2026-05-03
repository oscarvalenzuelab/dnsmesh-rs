#!/usr/bin/env bash
# build-aar.sh — assemble a minimal Android Archive (.aar) from cargo-ndk output.
#
# An .aar is a zip with a documented layout:
#   AndroidManifest.xml   (required)
#   classes.jar           (required; empty placeholder is fine for an FFI-only
#                          library — Kotlin bindings are shipped alongside as
#                          source under bindings/kotlin/ for the consumer to
#                          compile in their own module)
#   jni/<abi>/lib*.so     (the cargo-ndk output)
#   R.txt                 (required, empty)
#
# Usage: build-aar.sh <version>
#
# Inputs:
#   ./jniLibs/<abi>/libdnsmesh_ffi.so  (cargo-ndk -o jniLibs output)
#
# Output:
#   ./dist/dnsmesh-ffi-<version>.aar
#
# This is deliberately the minimum viable AAR. M7+ work: switch to a real gradle
# build via cargo-ndk-android-gradle when we want consumer-rules.pro / R8 /
# proper Maven publication.
set -euo pipefail

VERSION="${1:?usage: build-aar.sh <version>}"
# Reject anything that would let VERSION smuggle path components or shell
# metachars into the filename. Caller is the workflow and pulls VERSION from
# a regex-validated tag, so this is belt-and-braces, not the primary defense.
if [[ ! "$VERSION" =~ ^[A-Za-z0-9._+-]+$ ]]; then
  echo "::error::VERSION contains unsupported characters: $VERSION" >&2
  exit 1
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

JNI_SRC="${JNI_SRC:-jniLibs}"
OUT_DIR="${OUT_DIR:-dist}"
mkdir -p "$OUT_DIR"

# Resolve OUT_DIR to an absolute path *before* we cd into the WORKDIR
# subshell. Previously the script used `$OLDPWD`, which is the parent
# shell's PWD at the moment of subshell entry — fragile for any caller
# that runs the script from outside the repo root or with an absolute
# OUT_DIR.
ABS_OUT_DIR="$(cd "$OUT_DIR" && pwd)"

if [[ ! -d "$JNI_SRC" ]]; then
  echo "::error::expected $JNI_SRC/ from cargo-ndk; run cargo ndk -o $JNI_SRC ... first" >&2
  exit 1
fi

cat > "$WORKDIR/AndroidManifest.xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.dnsmesh.ffi">
    <uses-sdk android:minSdkVersion="24" />
</manifest>
EOF

# Empty classes.jar — required by the AAR format. We ship Kotlin bindings as
# source under bindings/kotlin/ so the consumer's own Kotlin compiler picks
# them up; that keeps us out of the "ship a JVM jar from CI" rabbit hole.
#
# Build a *valid* empty jar by zipping a stub directory into a freshly
# materialized empty staging dir, then verify it. A 0-byte classes.jar is
# rejected by AGP and would only be caught when an Android consumer tries
# to import the AAR — fail here instead.
EMPTY_JAR_STAGE="$(mktemp -d)"
mkdir -p "$EMPTY_JAR_STAGE/META-INF"
cat > "$EMPTY_JAR_STAGE/META-INF/MANIFEST.MF" <<'EOF'
Manifest-Version: 1.0
Created-By: dnsmesh build-aar.sh

EOF
# Try `jar` first, then fall back to `zip`. On macOS the `jar` binary is a
# wrapper that fails at runtime if no JRE is installed, so checking
# `command -v jar` alone isn't enough; we run it and fall through if it
# can't actually produce output.
JAR_OK=0
if command -v jar >/dev/null 2>&1; then
  if ( cd "$EMPTY_JAR_STAGE" && jar cfM "$WORKDIR/classes.jar" META-INF/MANIFEST.MF ) 2>/dev/null; then
    JAR_OK=1
  fi
fi
if [[ $JAR_OK -eq 0 ]]; then
  if command -v zip >/dev/null 2>&1; then
    ( cd "$EMPTY_JAR_STAGE" && zip -q "$WORKDIR/classes.jar" META-INF/MANIFEST.MF )
  else
    echo "::error::neither working 'jar' (with JRE) nor 'zip' available — cannot build classes.jar" >&2
    exit 1
  fi
fi
rm -rf "$EMPTY_JAR_STAGE"

if [[ ! -s "$WORKDIR/classes.jar" ]]; then
  echo "::error::classes.jar build produced an empty file (would fail AGP validation)" >&2
  exit 1
fi
# Cheap structural sanity check — any zip util can list it.
if command -v unzip >/dev/null 2>&1; then
  unzip -l "$WORKDIR/classes.jar" >/dev/null || {
    echo "::error::classes.jar is not a valid zip/jar archive" >&2
    exit 1
  }
fi

: > "$WORKDIR/R.txt"

mkdir -p "$WORKDIR/jni"
# cargo-ndk -o jniLibs lays out per-ABI dirs already (arm64-v8a, armeabi-v7a,
# x86, x86_64). Copy the whole tree (-L is a no-op when none of the entries
# are symlinks; we don't expect any in CI but it's the safer default than
# silently following them anywhere unexpected).
cp -RL "$JNI_SRC"/. "$WORKDIR/jni/"

ls -la "$WORKDIR" "$WORKDIR/jni"

OUT="$ABS_OUT_DIR/dnsmesh-ffi-${VERSION}.aar"
( cd "$WORKDIR" && zip -r "$OUT" \
    AndroidManifest.xml classes.jar R.txt jni )

echo "wrote $OUT"
ls -la "$OUT"

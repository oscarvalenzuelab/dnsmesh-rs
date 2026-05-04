# Contributing

Contributions welcome. Run `cargo fmt`, `cargo clippy --workspace -- -D warnings`, and
`cargo test --workspace` before opening a PR. The Rust port must remain wire-compatible
with the Python reference implementation; any change touching wire format requires
interop test vectors.

## Releases & signing

Releases are tag-driven. There are three tag prefixes, each wired to its own
workflow under `.github/workflows/`:

| Tag prefix | Workflow | Artifacts |
|---|---|---|
| `cli-v<semver>` | `release.yml` | `dnsmesh` CLI binary, 7 desktop targets, packaged as `dnsmesh-cli-<version>-<triple>.{tar.gz,zip}` |
| `sdk-v<semver>` | `release.yml` | `libdnsmesh_ffi.{so,dylib,dll}` + `libdnsmesh_ffi.a`, 7 desktop targets, packaged as `dnsmesh-sdk-<version>-<triple>.{tar.gz,zip}` |
| `mobile-v<semver>` | `mobile.yml` | `DnsMesh.xcframework` (iOS device + universal simulator) and `dnsmesh-ffi-<version>.aar` (four Android ABIs) plus the generated Swift / Kotlin bindings |

The decoupled tags let CLI, SDK, and mobile cadences move independently — for
example, you can ship a CLI bugfix as `cli-v0.1.1` without re-cutting the SDK.

### Tag → release flow

1. Bump `workspace.package.version` in the root `Cargo.toml` (the FFI and CLI
   crates inherit it via `version.workspace = true`).
2. Commit the bump on `main`.
3. Push the matching tag, e.g. `git tag cli-v0.1.1 && git push origin cli-v0.1.1`.
4. The workflow's `validate` job extracts the version from the tag and asserts
   it matches `cargo metadata`'s workspace version. A mismatch fails the
   release loudly before any build runs — fix the tag, don't fix the workflow.

The 7-target desktop matrix is:
`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`x86_64-unknown-linux-musl`, `aarch64-apple-darwin`,
`x86_64-apple-darwin`, `x86_64-pc-windows-msvc`,
`aarch64-pc-windows-msvc`. The two cross-compiled targets (aarch64
linux, aarch64 windows) skip the post-build smoke test because the
runner can't execute the binary; everything else runs `dnsmesh
--version` as a sanity check.

`x86_64-apple-darwin` is **not** built by `release.yml` — the GHA
`macos-13` free-tier runner pool is exhausted in practice and macOS
13 itself reached end-of-life in November 2025. The release flow for
that target is a per-tag manual step run from any Apple Silicon Mac:

```sh
# After the cli-v<version> + sdk-v<version> tags exist on github
# (i.e. the GHA workflow has run and produced the other 6 targets):
scripts/release-darwin-x86.sh <version>
```

The script cross-compiles to `x86_64-apple-darwin`, packages the
tarballs with the same naming convention `release.yml` uses, and
uploads them to the existing release pages via `gh release upload
--clobber`. The result is byte-equivalent to what a `macos-13` GHA
runner would have produced (same `--release` profile, same packaging,
unsigned).

`aarch64-unknown-linux-gnu` is built via `cargo zigbuild` rather than `cross`.
Zig's linker handles glibc versioning cleanly without us needing a custom
Docker image, and the install footprint is one cargo install plus one
setup-zig action.

### Signing posture

The default posture is **unsigned binaries**. We don't have certs yet; this
is the explicit policy for the private-repo iteration phase. The release
workflows ship binaries with no Authenticode or Developer ID signature and
log a clear `... unset — shipping unsigned ...` line so it's visible in the
job output.

When certs are acquired, set the secrets below and signing turns on
automatically — no workflow edit needed. Each signing step is gated on the
secret being non-empty, so partial setup (macOS only, Windows only, etc.) is
fine.

#### macOS code signing

| Secret | Purpose |
|---|---|
| `APPLE_DEVELOPER_ID_CERT_NAME` | Common name from the Developer ID Application certificate; passed as `codesign --sign "<name>"`. Setting this enables signing for the CLI binary, the FFI dylib, and the iOS xcframework. |
| `APPLE_DEVELOPER_ID_CERT` | Base64 of the .p12 keychain export (used in a follow-up to import the cert into the runner keychain — currently the workflow assumes the cert is preinstalled, so this is reserved for later wiring). |

Notarization is **stubbed**, not wired. The relevant block in `release.yml`
logs the `xcrun notarytool` invocation as a TODO. To enable, add:

| Secret | Purpose |
|---|---|
| `APPLE_NOTARIZATION_USER` | Apple ID for notarization submission. |
| `APPLE_NOTARIZATION_PASS` | App-specific password for the same Apple ID. |
| `APPLE_TEAM_ID` | Developer team identifier. |

Then promote the TODO block in `release.yml` to a real step.

#### Windows code signing

| Secret | Purpose |
|---|---|
| `WINDOWS_AUTHENTICODE_CERT` | Base64 of the Authenticode .pfx cert. The workflow decodes it to a temp file at signing time. |
| `WINDOWS_AUTHENTICODE_PASS` | Password for the .pfx. |

Setting both enables `signtool` invocation against the CLI .exe and the FFI
.dll, with timestamping via `http://timestamp.digicert.com`.

#### Setting the secrets

Repository → Settings → Secrets and variables → Actions → New repository
secret. The names above are case-sensitive; they're referenced verbatim in
the workflows.

### Audit & fuzz cadence

`.github/workflows/audit.yml` runs `cargo audit`, `cargo deny check`, and the
proptest parser-robustness suite. The fuzz job sizes its case budget from
`DMP_FUZZ_MAX_EXAMPLES`: 1000 cases on PR/push, 10000 on the weekly cron
(Mondays 06:17 UTC). This mirrors the 500 / 5000 split the Python repo uses
for the Hypothesis parser fuzz harness.

<!--
PR title format: short imperative, ~72 chars max.
e.g. `cli: store contacts under full user@host key`
     `client: walk rotation chain on receive`
-->

## What changed

<!--
30-second summary. Why did this change happen, and what does the
reader need to know to review it?
-->

## Tests

<!--
List new or modified tests. For each, say what behavior it pins.
Delete tests only with explicit justification.
-->

- [ ] New tests cover the new behavior
- [ ] `cargo test --workspace` passes locally
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` is clean
- [ ] Python interop tests (`dmp-interop`) still pass — required when wire format / record encoding changes

## Security implications

<!--
Mandatory section. Pick one and expand:

- [ ] None — this PR does not touch security-sensitive code
- [ ] Wire format — specify the before/after and backward compatibility
- [ ] AEAD AAD surface — specify exactly what bytes changed and why
- [ ] Key management — specify key lifecycle impact (storage, rotation, derivation)
- [ ] Network surface — specify new endpoints / listening ports / outbound destinations
- [ ] Other: ___________
-->

## Breaking changes

<!--
Anything that would make a client built against the previous tag stop
working? If yes, enumerate and add to CHANGELOG.md under BREAKING.
-->

- [ ] No breaking changes
- [ ] Wire format changed (must match spec at oscarvalenzuelab/DNSMeshProtocol)
- [ ] CLI surface changed (docs updated)
- [ ] SDK API changed (docs updated, semver impact noted)
- [ ] On-disk schema changed (migration path documented)

## Definition of done

- [ ] `CHANGELOG.md` updated under the right section
- [ ] `docs/` updated for any user-facing change
- [ ] CI green

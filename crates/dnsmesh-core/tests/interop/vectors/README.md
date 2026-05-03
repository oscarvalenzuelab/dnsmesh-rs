# Interop test vectors

These JSON files are lifted verbatim from the reference Python implementation at
`oscarvalenzuelab/DNSMeshProtocol`, path `docs/protocol/vectors/`. They define byte-level
wire format interop and are how the Rust port proves it talks the same wire as the Python
reference.

## Updating

If the upstream vectors regenerate (new fields, fixed bug, etc.), copy them across again
and re-run `cargo test --test interop`. Any wire-format change should be intentional and
land alongside a Python upstream change first.

## Schema

Each file is a JSON array of test cases. Common fields per case:

- `description`: human-readable label
- `inputs`: the protocol-element fields used to build the record
- `expected_wire_hex`: the literal TXT string (UTF-8) hex-encoded
- `*_seed_hex`: 32-byte X25519 private seed used to derive the signing identity
  via `DmpCrypto::from_private_bytes`
- `verify_with_*`: optional pinned verifier inputs
- `expected_parse_result`: present (`"none"`) when the case must fail to parse/verify
- `wire_from_case`: when present, the `expected_wire_hex` is a tampered copy of an
  earlier case's wire (used for signature-failure cases)

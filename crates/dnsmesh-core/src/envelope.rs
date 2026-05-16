//! DMPv2 plaintext envelope.
//!
//! Wraps the AEAD plaintext with a versioned header that carries optional
//! sender metadata (today: `from = user@host`). Lives INSIDE the AEAD
//! ciphertext, so the wrapper itself is not visible on the wire — DNS chunks
//! still expose only the existing [`crate::message::DMPHeader`] JSON and the
//! encrypted blob.
//!
//! Wire format:
//!
//! ```text
//! DMPV2_PREFIX + canonical_json(header) + b"\n" + body
//! ```
//!
//! - [`DMPV2_PREFIX`] (6 bytes) discriminates a v1 plaintext (no envelope,
//!   body bytes only) from a v2 plaintext (envelope present). Plain ASCII
//!   so a misrouted v2 plaintext arriving at a v1 receiver renders as
//!   readable garbage rather than binary noise. Misrouting should not
//!   happen once [`crate::identity::IdentityRecord::versions`] gates
//!   emission, but the readable-fallback property is cheap insurance.
//! - Header JSON is serialized with sorted keys and the most compact
//!   separators so encoding is deterministic; receivers MUST parse
//!   generously (ignore unknown keys) so future fields can be added
//!   without breaking older receivers.
//! - `\n` terminates the header. Empty body is legal.
//!
//! Trust: the `from` claim by itself is unauthenticated metadata — the
//! sender chose to write whatever they wanted. The receiver MUST verify
//! `fetch_identity(from).ed25519_spk == manifest.sender_spk` before
//! trusting the claim. Canonicalization rejects non-ASCII addresses at
//! v1 so homograph attacks are out of scope.

use std::collections::BTreeMap;

/// 6-byte magic that marks the start of a DMPv2 envelope inside the
/// AEAD plaintext.
pub const DMPV2_PREFIX: &[u8; 6] = b"DMPV2:";

/// Reject any envelope whose header JSON exceeds this many bytes.
///
/// Defensive cap — a malicious sender can already bloat the AEAD
/// payload by stuffing the body, so the cost of bloated metadata is
/// linear, not catastrophic. The cap nonetheless keeps the header at
/// a sane size for deterministic parsing.
pub const MAX_HEADER_BYTES: usize = 256;

const LOCALPART_MAX: usize = 64;
const HOST_LABEL_MAX: usize = 63;
const HOST_MAX: usize = 253;

/// Return the canonical `user@host` form, or `None` on reject.
///
/// Rules (intentionally strict for v1):
/// - ASCII only. Non-ASCII codepoints reject.
/// - Lowercased.
/// - Trailing dots on host stripped.
/// - Local-part: starts alphanumeric, then `a-z0-9_-.`, up to 64 chars.
/// - Host: dot-separated labels, each `a-z0-9-` not starting/ending
///   with `-`, label <= 63 chars, total <= 253 chars.
/// - Exactly one `@`.
/// - Empty local-part or host reject.
///
/// Used on both encode and decode. Receivers MUST canonicalize before
/// any comparison or UI render — never display the raw bytes the
/// sender wrote.
#[must_use]
pub fn canonicalize_address(addr: &str) -> Option<String> {
    if !addr.is_ascii() {
        return None;
    }
    let trimmed = addr.trim().to_ascii_lowercase();
    let (local, host_raw) = trimmed.split_once('@')?;
    // Reject if any further '@' exists in the supposedly-host part.
    if host_raw.contains('@') {
        return None;
    }
    let host = host_raw.trim_end_matches('.');
    if local.is_empty() || host.is_empty() {
        return None;
    }
    if host.len() > HOST_MAX {
        return None;
    }
    if !local_part_ok(local) {
        return None;
    }
    if !host_ok(host) {
        return None;
    }
    Some(format!("{local}@{host}"))
}

fn local_part_ok(local: &str) -> bool {
    if local.len() > LOCALPART_MAX || local.is_empty() {
        return false;
    }
    let bytes = local.as_bytes();
    let first = bytes[0];
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    if local.ends_with('.') {
        return false;
    }
    if local.contains("..") {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-' || *b == b'.')
}

fn host_ok(host: &str) -> bool {
    for label in host.split('.') {
        if !label_ok(label) {
            return false;
        }
    }
    true
}

fn label_ok(label: &str) -> bool {
    if label.is_empty() || label.len() > HOST_LABEL_MAX {
        return false;
    }
    let bytes = label.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        return false;
    }
    if !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

/// Wrap `body` with a DMPv2 envelope, or return `body` unchanged.
///
/// Returns the raw `body` (no wrapper) when `sender_addr` is `None` or
/// fails canonicalization — that's the v1 wire form, which existing
/// v1 receivers decrypt and display unchanged. Callers gate v2 emission
/// on the recipient's published version capability (see
/// [`crate::identity::IdentityRecord::versions`]) so a wrapped plaintext
/// never reaches a v1 receiver.
#[must_use]
pub fn encode(body: &[u8], sender_addr: Option<&str>) -> Vec<u8> {
    let Some(addr) = sender_addr else {
        return body.to_vec();
    };
    let Some(canonical) = canonicalize_address(addr) else {
        return body.to_vec();
    };
    let header_bytes = canonical_json_from_one_field("from", &canonical);
    if header_bytes.len() > MAX_HEADER_BYTES {
        return body.to_vec();
    }
    let mut out = Vec::with_capacity(DMPV2_PREFIX.len() + header_bytes.len() + 1 + body.len());
    out.extend_from_slice(DMPV2_PREFIX);
    out.extend_from_slice(&header_bytes);
    out.push(b'\n');
    out.extend_from_slice(body);
    out
}

/// Split a decrypted plaintext into `(body, claimed_from_or_None)`.
///
/// Decision matrix:
/// - Prefix does not match -> `(plaintext, None)`. Treat as v1 wire form.
/// - Prefix matches but no newline appears within
///   [`MAX_HEADER_BYTES`] -> `(plaintext, None)`. Safety valve for the
///   implausible case where a v1 body happens to start with `DMPV2:`
///   followed by `>MAX_HEADER_BYTES` bytes without a newline.
/// - Prefix matches, newline found, but the header bytes are not
///   well-formed JSON OR the JSON is not an object -> `(plaintext, None)`.
///   A real v2 wrapper from this codebase always emits well-formed
///   canonical JSON, so a header that fails to parse is far more
///   likely a v1 message that happens to start with `DMPV2:` than
///   a genuine envelope. Falling back to the full plaintext means a
///   legacy v1 message keeps its body intact instead of losing
///   everything up to the first newline.
/// - Prefix matches, newline found, header parses as an object ->
///   committed v2 envelope. Body is everything after the first
///   newline. Inside the envelope the `from` claim is parsed and
///   canonicalized; missing / non-string / non-canonicalizable
///   `from` returns `(body, None)` because the wrapper itself is
///   real but the metadata isn't trustworthy.
///
/// The returned `claimed_from` is canonicalized. It is NOT yet
/// trust-verified — the caller MUST resolve `from` via DNS and
/// compare `ed25519_spk` against the manifest's `sender_spk` before
/// populating any user-visible sender label.
#[must_use]
pub fn decode(plaintext: &[u8]) -> (Vec<u8>, Option<String>) {
    if !plaintext.starts_with(DMPV2_PREFIX) {
        return (plaintext.to_vec(), None);
    }
    let rest = &plaintext[DMPV2_PREFIX.len()..];
    let scan_limit = (MAX_HEADER_BYTES + 1).min(rest.len());
    let Some(nl_offset) = rest[..scan_limit].iter().position(|b| *b == b'\n') else {
        return (plaintext.to_vec(), None);
    };
    let header_bytes = &rest[..nl_offset];
    let Ok(header_str) = std::str::from_utf8(header_bytes) else {
        return (plaintext.to_vec(), None);
    };
    let parsed: serde_json::Value = match serde_json::from_str(header_str) {
        Ok(v) => v,
        Err(_) => return (plaintext.to_vec(), None),
    };
    let serde_json::Value::Object(map) = parsed else {
        return (plaintext.to_vec(), None);
    };
    let body = rest[nl_offset + 1..].to_vec();
    let Some(raw_from) = map.get("from") else {
        return (body, None);
    };
    let Some(raw_from_str) = raw_from.as_str() else {
        return (body, None);
    };
    let Some(canonical) = canonicalize_address(raw_from_str) else {
        return (body, None);
    };
    (body, Some(canonical))
}

/// Serialize a single-string-field object to bytes with sorted keys
/// and the most compact separator (`","` between fields, `":"` between
/// key/value). Mirrors Python's
/// `json.dumps({"from": addr}, sort_keys=True, separators=(",", ":"),
/// ensure_ascii=True)` so the bytes are byte-identical to the Python
/// reference.
fn canonical_json_from_one_field(key: &str, value: &str) -> Vec<u8> {
    let mut map: BTreeMap<&str, &str> = BTreeMap::new();
    map.insert(key, value);
    // serde_json::to_string on a BTreeMap emits sorted keys with the
    // same compact separators Python's `separators=(",", ":")` does.
    serde_json::to_vec(&map).expect("BTreeMap<&str,&str> always serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(addr: &str) -> Option<String> {
        canonicalize_address(addr)
    }

    #[test]
    fn canonicalize_simple_passes_through() {
        assert_eq!(
            canon("alice@example.com").as_deref(),
            Some("alice@example.com")
        );
    }

    #[test]
    fn canonicalize_lowercases() {
        assert_eq!(
            canon("Alice@Example.COM").as_deref(),
            Some("alice@example.com")
        );
    }

    #[test]
    fn canonicalize_strips_surrounding_whitespace() {
        assert_eq!(
            canon("  alice@example.com  ").as_deref(),
            Some("alice@example.com")
        );
    }

    #[test]
    fn canonicalize_strips_trailing_dot_on_host() {
        assert_eq!(
            canon("alice@example.com.").as_deref(),
            Some("alice@example.com")
        );
    }

    #[test]
    fn canonicalize_rejects_non_ascii() {
        // U+00E1 LATIN SMALL LETTER A WITH ACUTE
        assert!(canon("\u{00e1}lice@example.com").is_none());
        // U+0430 CYRILLIC SMALL LETTER A
        assert!(canon("\u{0430}lice@example.com").is_none());
    }

    #[test]
    fn canonicalize_rejects_missing_at() {
        assert!(canon("aliceexample.com").is_none());
    }

    #[test]
    fn canonicalize_rejects_multiple_at() {
        assert!(canon("alice@bob@example.com").is_none());
    }

    #[test]
    fn canonicalize_rejects_empty_local() {
        assert!(canon("@example.com").is_none());
    }

    #[test]
    fn canonicalize_rejects_empty_host() {
        assert!(canon("alice@").is_none());
        assert!(canon("alice@.").is_none());
    }

    #[test]
    fn canonicalize_rejects_local_starting_with_punctuation() {
        assert!(canon(".alice@example.com").is_none());
        assert!(canon("-alice@example.com").is_none());
    }

    #[test]
    fn canonicalize_rejects_local_ending_with_dot() {
        assert!(canon("alice.@example.com").is_none());
    }

    #[test]
    fn canonicalize_rejects_double_dot_in_local() {
        assert!(canon("a..b@example.com").is_none());
    }

    #[test]
    fn canonicalize_rejects_label_with_leading_hyphen() {
        assert!(canon("alice@-bad.example.com").is_none());
    }

    #[test]
    fn canonicalize_rejects_label_with_trailing_hyphen() {
        assert!(canon("alice@bad-.example.com").is_none());
    }

    #[test]
    fn canonicalize_rejects_oversize_localpart() {
        let long = "a".repeat(LOCALPART_MAX + 1);
        assert!(canon(&format!("{long}@example.com")).is_none());
    }

    #[test]
    fn canonicalize_accepts_localpart_at_cap() {
        let long = "a".repeat(LOCALPART_MAX);
        let want = format!("{long}@example.com");
        assert_eq!(canon(&want).as_deref(), Some(want.as_str()));
    }

    #[test]
    fn encode_none_addr_returns_body_unchanged() {
        let body = b"hello world";
        assert_eq!(encode(body, None).as_slice(), body);
    }

    #[test]
    fn encode_invalid_addr_returns_body_unchanged() {
        let body = b"hello world";
        assert_eq!(encode(body, Some("not-an-address")).as_slice(), body);
    }

    #[test]
    fn encode_valid_addr_produces_wrapper() {
        let wrapped = encode(b"hi", Some("alice@example.com"));
        assert!(wrapped.starts_with(DMPV2_PREFIX));
        assert!(wrapped.ends_with(b"hi"));
        // The header JSON is canonical.
        let header_part = &wrapped[DMPV2_PREFIX.len()..wrapped.len() - b"\nhi".len()];
        assert_eq!(header_part, br#"{"from":"alice@example.com"}"#);
    }

    #[test]
    fn encode_canonicalizes_before_wrapping() {
        let wrapped = encode(b"hi", Some("ALICE@Example.COM."));
        assert!(wrapped
            .windows(b"\"from\":\"alice@example.com\"".len())
            .any(|w| w == b"\"from\":\"alice@example.com\""));
    }

    #[test]
    fn encode_empty_body_works() {
        let wrapped = encode(b"", Some("alice@example.com"));
        let want = [
            DMPV2_PREFIX.as_slice(),
            br#"{"from":"alice@example.com"}"#,
            b"\n",
        ]
        .concat();
        assert_eq!(wrapped, want);
    }

    #[test]
    fn decode_v1_returns_unchanged() {
        let (body, sender) = decode(b"plain message no wrapper");
        assert_eq!(body, b"plain message no wrapper");
        assert_eq!(sender, None);
    }

    #[test]
    fn decode_empty_returns_unchanged() {
        let (body, sender) = decode(b"");
        assert!(body.is_empty());
        assert_eq!(sender, None);
    }

    #[test]
    fn decode_v2_roundtrip() {
        let wrapped = encode(b"hello", Some("alice@example.com"));
        let (body, sender) = decode(&wrapped);
        assert_eq!(body, b"hello");
        assert_eq!(sender.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn decode_v2_with_empty_body() {
        let wrapped = encode(b"", Some("alice@example.com"));
        let (body, sender) = decode(&wrapped);
        assert!(body.is_empty());
        assert_eq!(sender.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn decode_v2_with_binary_body() {
        let binary: Vec<u8> = (0u8..=255).collect();
        let wrapped = encode(&binary, Some("alice@example.com"));
        let (body, sender) = decode(&wrapped);
        assert_eq!(body, binary);
        assert_eq!(sender.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn decode_canonicalizes_sender_on_decode() {
        let raw_header = br#"{"from":"Alice@Example.COM."}"#;
        let mut wrapped = Vec::new();
        wrapped.extend_from_slice(DMPV2_PREFIX);
        wrapped.extend_from_slice(raw_header);
        wrapped.push(b'\n');
        wrapped.extend_from_slice(b"body");
        let (body, sender) = decode(&wrapped);
        assert_eq!(body, b"body");
        assert_eq!(sender.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn decode_prefix_no_newline_returns_full_plaintext() {
        let mut input = Vec::new();
        input.extend_from_slice(DMPV2_PREFIX);
        input.extend_from_slice(b"junk no newline");
        let (body, sender) = decode(&input);
        assert_eq!(body, input);
        assert_eq!(sender, None);
    }

    #[test]
    fn decode_prefix_newline_past_cap_returns_full_plaintext() {
        let mut input = Vec::new();
        input.extend_from_slice(DMPV2_PREFIX);
        input.extend(std::iter::repeat_n(b'x', MAX_HEADER_BYTES + 5));
        input.push(b'\n');
        input.extend_from_slice(b"rest");
        let copy = input.clone();
        let (body, sender) = decode(&input);
        assert_eq!(body, copy);
        assert_eq!(sender, None);
    }

    #[test]
    fn decode_bad_json_falls_back_to_v1_plaintext() {
        let mut input = Vec::new();
        input.extend_from_slice(DMPV2_PREFIX);
        input.extend_from_slice(b"{not json}");
        input.push(b'\n');
        input.extend_from_slice(b"body");
        let copy = input.clone();
        let (body, sender) = decode(&input);
        assert_eq!(body, copy);
        assert_eq!(sender, None);
    }

    #[test]
    fn decode_json_not_a_dict_falls_back_to_v1_plaintext() {
        let mut input = Vec::new();
        input.extend_from_slice(DMPV2_PREFIX);
        input.extend_from_slice(br#"["alice@example.com"]"#);
        input.push(b'\n');
        input.extend_from_slice(b"body");
        let copy = input.clone();
        let (body, sender) = decode(&input);
        assert_eq!(body, copy);
        assert_eq!(sender, None);
    }

    #[test]
    fn decode_missing_from_returns_body_with_none() {
        let mut input = Vec::new();
        input.extend_from_slice(DMPV2_PREFIX);
        input.extend_from_slice(br#"{"other":"x"}"#);
        input.push(b'\n');
        input.extend_from_slice(b"body");
        let (body, sender) = decode(&input);
        assert_eq!(body, b"body");
        assert_eq!(sender, None);
    }

    #[test]
    fn decode_from_not_a_string_returns_body_with_none() {
        let mut input = Vec::new();
        input.extend_from_slice(DMPV2_PREFIX);
        input.extend_from_slice(br#"{"from":42}"#);
        input.push(b'\n');
        input.extend_from_slice(b"body");
        let (body, sender) = decode(&input);
        assert_eq!(body, b"body");
        assert_eq!(sender, None);
    }

    #[test]
    fn decode_from_uncanonicalizable_returns_body_with_none() {
        let mut input = Vec::new();
        input.extend_from_slice(DMPV2_PREFIX);
        input.extend_from_slice(br#"{"from":"not-an-address"}"#);
        input.push(b'\n');
        input.extend_from_slice(b"body");
        let (body, sender) = decode(&input);
        assert_eq!(body, b"body");
        assert_eq!(sender, None);
    }

    #[test]
    fn decode_ignores_unknown_keys() {
        let header = br#"{"from":"alice@example.com","reply_to":"bob@example.com"}"#;
        let mut input = Vec::new();
        input.extend_from_slice(DMPV2_PREFIX);
        input.extend_from_slice(header);
        input.push(b'\n');
        input.extend_from_slice(b"body");
        let (body, sender) = decode(&input);
        assert_eq!(body, b"body");
        assert_eq!(sender.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn legacy_message_starting_with_prefix_and_newline_preserved() {
        // A v1 plaintext that happens to start with DMPV2: followed by
        // non-JSON content and a newline within MAX_HEADER_BYTES MUST be
        // delivered intact, not truncated.
        let mut legacy = Vec::new();
        legacy.extend_from_slice(DMPV2_PREFIX);
        legacy.extend_from_slice(b"actual first line\nrest of message");
        let copy = legacy.clone();
        let (body, sender) = decode(&legacy);
        assert_eq!(body, copy);
        assert_eq!(sender, None);
    }
}

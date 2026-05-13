//! Maildir delivery for `dnsmesh recv --maildir`.
//!
//! The `maildir` crate handles the cur/new/tmp atomic-rename dance
//! (write `tmp/<unique>`, fsync, rename to `new/<unique>`) — we just
//! synthesize an RFC 5322 envelope around the decrypted payload and
//! hand it the bytes.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, Result};
use dnsmesh_client::InboxMessage;
use maildir::Maildir;

/// Write `msg` into the Maildir rooted at `root`. Creates the
/// `cur/new/tmp` subdirs if missing.
///
/// `sender_address` is the resolved `user@host` form of the sender
/// when the receiver has them pinned (looked up by ed25519_spk in the
/// contact store). When `None`, we fall back to a synthetic
/// `dmp-<spk-prefix>@dmp.local` so the envelope still parses; mutt's
/// "reply" path will land on that synthetic address and fail to
/// send (no `id-...dmp.local` exists), which is the correct behavior
/// for an un-pinned sender — better than letting the reply silently
/// route to a stranger.
pub fn deliver(root: &Path, msg: &InboxMessage, sender_address: Option<&str>) -> Result<String> {
    let md = Maildir::from(root.to_path_buf());
    md.create_dirs()
        .with_context(|| format!("creating maildir at {}", root.display()))?;
    let envelope = build_envelope(msg, sender_address);
    let id = md
        .store_new(envelope.as_slice())
        .with_context(|| format!("writing to maildir at {}", root.display()))?;
    Ok(id)
}

/// Build the RFC 5322 envelope around `msg.plaintext`.
///
/// Headers carry a few X-DMP-* breadcrumbs so the receiver can
/// reconstruct sender / msg-id / timestamp from inside the MUA.
/// Non-UTF-8 bodies are base64-encoded with `Content-Type:
/// application/octet-stream` so the file lands intact rather than as
/// a garbled string.
///
/// When `sender_address` is `Some("alice@mesh.example.com")` (the
/// caller resolved the manifest's `sender_spk` against the local
/// contact store and found a pinned match), that string lands in
/// `From:` so an MUA's reply lands at the real address. Otherwise
/// the synthetic `dmp-<spk-prefix>@dmp.local` placeholder is used.
/// Either way, `X-DMP-Sender-Address` carries the resolved value (or
/// the synthetic one) and `X-DMP-Sender-SPK` carries the raw 32-byte
/// signing key for downstream tooling.
pub fn build_envelope(msg: &InboxMessage, sender_address: Option<&str>) -> Vec<u8> {
    let sender_hex = hex::encode(msg.sender_signing_pk);
    let msg_id_hex = hex::encode(msg.msg_id);
    let short_id = &msg_id_hex[..msg_id_hex.len().min(12)];
    let short_sender = &sender_hex[..sender_hex.len().min(12)];

    // Resolved real address from the contact store, if available.
    // Otherwise the synthetic placeholder. Either form is RFC 5322-
    // legal and parses through mail-parser cleanly on the loop-back
    // path (`dnsmesh send -t` reading mutt's reply stdin).
    let synthetic = format!("dmp-{short_sender}@dmp.local");
    let from_addr = sender_address.unwrap_or(&synthetic);
    let subject_label = sender_address
        .and_then(|a| a.split('@').next())
        .unwrap_or(short_sender);
    let subject = format!("[DMP] {subject_label} {short_id}");

    let mut out = String::new();
    let _ = writeln!(out, "From: {from_addr}");
    let _ = writeln!(out, "Subject: {subject}");
    // Reply-To matches From — explicitly redundant, but some MUAs
    // (older mutt configs, claws-mail) honor Reply-To over From for
    // composing replies, so setting both is safer.
    let _ = writeln!(out, "Reply-To: {from_addr}");
    let _ = writeln!(out, "X-DMP-Sender-SPK: {sender_hex}");
    let _ = writeln!(out, "X-DMP-Sender-Address: {from_addr}");
    let _ = writeln!(out, "X-DMP-Msg-Id: {msg_id_hex}");
    let _ = writeln!(out, "X-DMP-Timestamp: {}", msg.timestamp);
    let _ = writeln!(out, "MIME-Version: 1.0");

    let is_utf8 = std::str::from_utf8(&msg.plaintext).is_ok();
    if is_utf8 {
        let _ = writeln!(out, "Content-Type: text/plain; charset=utf-8");
        let _ = writeln!(out, "Content-Transfer-Encoding: 8bit");
        out.push('\n');
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&msg.plaintext);
        bytes
    } else {
        // Non-UTF-8 plaintext is uncommon for chat-shaped DMP traffic
        // (the source-of-truth Python client only sends text), but for
        // binary payloads we use the standard base64 transfer encoding
        // so any MUA can decode them out of the box.
        use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
        use base64::Engine as _;

        let _ = writeln!(out, "Content-Type: application/octet-stream");
        let _ = writeln!(out, "Content-Transfer-Encoding: base64");
        out.push('\n');
        let encoded = BASE64_STANDARD.encode(&msg.plaintext);
        let mut bytes = out.into_bytes();
        // RFC 2045 caps base64 lines at 76 characters.
        for chunk in encoded.as_bytes().chunks(76) {
            bytes.extend_from_slice(chunk);
            bytes.push(b'\n');
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_message(text: &[u8]) -> InboxMessage {
        InboxMessage {
            sender_signing_pk: [0xAB; 32],
            plaintext: text.to_vec(),
            timestamp: 1_700_000_000,
            msg_id: [0xCD; 16],
            sender_label: None,
        }
    }

    #[test]
    fn deliver_writes_file_into_new_subdir() {
        let dir = TempDir::new().unwrap();
        let id = deliver(dir.path(), &sample_message(b"hello"), None).unwrap();
        let new_dir = dir.path().join("new");
        let mut entries: Vec<_> = std::fs::read_dir(&new_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(entries.len(), 1);
        let name = entries.pop().unwrap();
        assert_eq!(name, id, "filename in new/ must match the returned id");
    }

    #[test]
    fn deliver_round_trips_through_filesystem() {
        let dir = TempDir::new().unwrap();
        let body = b"hello over dmp\n";
        deliver(dir.path(), &sample_message(body), None).unwrap();
        let new_dir = dir.path().join("new");
        let entry = std::fs::read_dir(&new_dir)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let raw = std::fs::read(entry.path()).unwrap();
        let text = std::str::from_utf8(&raw).unwrap();
        assert!(text.contains("X-DMP-Sender-SPK:"));
        assert!(text.contains("X-DMP-Msg-Id:"));
        assert!(text.ends_with("hello over dmp\n"));
    }

    #[test]
    fn binary_body_is_base64_encoded() {
        // 0xFF is invalid as the start of a UTF-8 sequence.
        let body = vec![0xFFu8, 0x00, 0xFF];
        let env = build_envelope(&sample_message(&body), None);
        let text = std::str::from_utf8(&env).unwrap();
        assert!(text.contains("Content-Type: application/octet-stream"));
        assert!(text.contains("Content-Transfer-Encoding: base64"));
        // base64(0xFF 0x00 0xFF) == "/wD/"
        assert!(text.contains("/wD/"));
    }

    #[test]
    fn from_header_uses_resolved_address_when_available() {
        // When the caller resolved the SPK against the contact store,
        // From: AND Reply-To: must carry the real `user@host` so the
        // MUA's reply path lands at the actual sender, not a synthetic
        // `@dmp.local` placeholder.
        let env = build_envelope(
            &sample_message(b"reply test"),
            Some("alkamod-pro@dmp.dnsmesh.pro"),
        );
        let text = std::str::from_utf8(&env).unwrap();
        assert!(
            text.contains("From: alkamod-pro@dmp.dnsmesh.pro"),
            "From: must carry the resolved address; got:\n{text}",
        );
        assert!(
            text.contains("Reply-To: alkamod-pro@dmp.dnsmesh.pro"),
            "Reply-To: must mirror From: so MUAs that prefer Reply-To still land right",
        );
        assert!(
            text.contains("X-DMP-Sender-Address: alkamod-pro@dmp.dnsmesh.pro"),
            "X-DMP-Sender-Address breadcrumb must be set",
        );
        assert!(
            text.contains("[DMP] alkamod-pro"),
            "Subject label uses the resolved username, not the spk hex",
        );
        assert!(
            !text.contains("@dmp.local"),
            "synthetic dmp.local placeholder must NOT appear when address resolved",
        );
    }

    #[test]
    fn from_header_falls_back_to_synthetic_when_unresolved() {
        // Un-pinned senders (TOFU first contact, intro-queue promote
        // without trust) have no contact-store entry. We still want a
        // legal RFC 5322 envelope, so the synthetic `dmp-<spk>@dmp.local`
        // placeholder lands. Replies to it will fail to send (no
        // `id-...dmp.local` exists), which is the correct safe-by-
        // default outcome — a reply to a stranger is intent we don't
        // have.
        let env = build_envelope(&sample_message(b"unresolved"), None);
        let text = std::str::from_utf8(&env).unwrap();
        assert!(text.contains("From: dmp-"));
        assert!(text.contains("@dmp.local"));
        assert!(text.contains("Reply-To: dmp-"));
    }
}

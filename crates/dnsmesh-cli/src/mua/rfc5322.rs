//! RFC 5322 stdin parser for `dnsmesh send -t`.
//!
//! Mutt and friends drive their `set sendmail` transport by spooling
//! the outgoing message to a child process's stdin. This module pulls
//! the To: address and body text off that stream so the CLI can route
//! the payload through DMP's send path.

use anyhow::{anyhow, Result};
use mail_parser::{Address, MessageParser};

/// Result of parsing an RFC 5322 stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMessage {
    /// Recipient as the literal `address` string from the To: header
    /// (e.g. `alice@mesh.local`).
    pub recipient: String,
    /// Subject line, if present. Carried only for X-DMP-* echoing on
    /// the receive side; DMP itself never sends a subject across the
    /// wire.
    pub subject: Option<String>,
    /// Plaintext body. We try the first text/plain part; failing that,
    /// we hand back the raw bytes as best-effort UTF-8.
    pub body: Vec<u8>,
}

/// Parse a complete RFC 5322 message from `raw_bytes`.
///
/// Returns an error when:
///   - the message has no parseable To: header,
///   - the To: header has no `address` field (display-name only),
///   - the To: address has no `@` (mutt sometimes misconfigures and
///     hands us a bare username; we surface this clearly so the user
///     can fix their `set sendmail` line),
///   - the message addresses MORE THAN ONE recipient across To: / Cc: /
///     Bcc: combined. DMP's `send` is one-recipient-per-message and we
///     refuse to silently drop the others — mutt would otherwise show
///     a successful send the recipient never got.
pub fn parse(raw_bytes: &[u8]) -> Result<ParsedMessage> {
    let parsed = MessageParser::default()
        .parse(raw_bytes)
        .ok_or_else(|| anyhow!("could not parse RFC 5322 message from stdin"))?;

    let mut recipients: Vec<String> = Vec::new();
    collect_addresses(parsed.to(), &mut recipients);
    collect_addresses(parsed.cc(), &mut recipients);
    collect_addresses(parsed.bcc(), &mut recipients);

    if recipients.is_empty() {
        return Err(anyhow!(
            "no recipient found — provide a To:, Cc:, or Bcc: header with a `user@host` address"
        ));
    }
    if recipients.len() > 1 {
        return Err(anyhow!(
            "DMP send is one-recipient-per-message but stdin RFC 5322 has {} recipients ({}). \
             Send one message per recipient instead — silently delivering to only the first \
             would let mutt report a successful send the others never received.",
            recipients.len(),
            recipients.join(", "),
        ));
    }
    let recipient = recipients.into_iter().next().expect("checked non-empty");
    if !recipient.contains('@') {
        return Err(anyhow!(
            "recipient `{recipient}` has no `@` — DMP needs `user@host` form. \
             Check your mutt config (`set use_envelope_from = yes` and a fully-qualified address)."
        ));
    }

    let subject = parsed.subject().map(std::string::ToString::to_string);

    let body = if let Some(text) = parsed.body_text(0) {
        text.as_bytes().to_vec()
    } else {
        // Multipart with no text/plain part; surface the raw bytes so
        // the receive side at least sees what was sent.
        raw_bytes.to_vec()
    };

    Ok(ParsedMessage {
        recipient,
        subject,
        body,
    })
}

/// Append every parseable address from `field` (which may be a single Addr
/// or a List/Group of them) into `out`. Empty / display-name-only entries
/// are skipped silently — they don't address a real recipient.
fn collect_addresses(field: Option<&Address<'_>>, out: &mut Vec<String>) {
    let Some(addr) = field else { return };
    for a in addr.iter() {
        if let Some(s) = a.address() {
            out.push(s.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_mutt_shaped_message() {
        let raw = b"From: oscar@mesh.local\r\n\
                    To: alice@mesh.local\r\n\
                    Subject: hello\r\n\
                    \r\n\
                    hi alice\r\n";
        let p = parse(raw).unwrap();
        assert_eq!(p.recipient, "alice@mesh.local");
        assert_eq!(p.subject.as_deref(), Some("hello"));
        // mail-parser strips trailing CRLF; assert the prefix instead so
        // the test is robust across mail-parser minor versions.
        assert!(
            std::str::from_utf8(&p.body)
                .unwrap()
                .starts_with("hi alice"),
            "body should retain the plaintext payload"
        );
    }

    #[test]
    fn rejects_to_without_at_sign() {
        // mail-parser treats a bare `alice` token as a display-name with
        // no address. Either we trip the "no recipient found" branch
        // (no address pulled out of the To/Cc/Bcc walk) or the "no @"
        // branch — both are acceptable, the operator shouldn't
        // accidentally succeed here.
        let raw = b"From: x@y\r\nTo: alice\r\n\r\nbody\r\n";
        let err = parse(raw).unwrap_err().to_string();
        assert!(
            err.contains("`@`") || err.contains("no recipient found") || err.contains("missing"),
            "unexpected error message: {err}",
        );
    }

    #[test]
    fn rejects_at_less_address_when_parsed_as_addr() {
        // A To: with explicit angle brackets but no `@` is unambiguous:
        // mail-parser yields an Addr with `address: Some("alice")` and
        // we MUST surface the "no @" hint so the user fixes their
        // mutt config.
        let raw = b"From: x@y\r\nTo: <alice>\r\n\r\nbody\r\n";
        let err = parse(raw).unwrap_err().to_string();
        assert!(
            err.contains("`@`"),
            "expected an @-related error; got {err}",
        );
    }

    #[test]
    fn rejects_multiple_to_recipients() {
        let raw = b"From: x@y\r\n\
                    To: alice@mesh.local, bob@mesh.local\r\n\
                    Subject: hi\r\n\
                    \r\n\
                    body\r\n";
        let err = parse(raw).unwrap_err().to_string();
        assert!(
            err.contains("one-recipient-per-message") || err.contains("recipients"),
            "expected multi-recipient rejection; got {err}",
        );
    }

    #[test]
    fn rejects_to_plus_cc_total() {
        let raw = b"From: x@y\r\n\
                    To: alice@mesh.local\r\n\
                    Cc: carol@mesh.local\r\n\
                    \r\n\
                    body\r\n";
        let err = parse(raw).unwrap_err().to_string();
        assert!(
            err.contains("one-recipient-per-message") || err.contains("recipients"),
            "expected multi-recipient rejection across To/Cc; got {err}",
        );
    }

    #[test]
    fn parses_display_name_form() {
        let raw = b"From: oscar@mesh.local\r\n\
                    To: \"Alice Example\" <alice@mesh.local>\r\n\
                    Subject: hi\r\n\
                    \r\n\
                    body\r\n";
        let p = parse(raw).unwrap();
        assert_eq!(p.recipient, "alice@mesh.local");
    }

    #[test]
    fn body_falls_back_to_raw_when_no_text_plain() {
        // Multipart/alternative with only text/html should still yield
        // *something* rather than panicking.
        let raw = b"From: x@y\r\n\
                    To: alice@mesh.local\r\n\
                    Subject: hi\r\n\
                    Content-Type: multipart/alternative; boundary=BB\r\n\
                    \r\n\
                    --BB\r\n\
                    Content-Type: text/html\r\n\r\n\
                    <p>hello</p>\r\n\
                    --BB--\r\n";
        let p = parse(raw).unwrap();
        assert!(!p.body.is_empty());
    }
}

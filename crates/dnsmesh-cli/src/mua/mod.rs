//! Mail-user-agent compatibility surface.
//!
//! Two pieces wire the CLI into a desktop mailer like mutt/neomutt:
//!
//!   - [`rfc5322`] parses an outgoing RFC 5322 message off stdin and
//!     pulls out (recipient, body) so `dnsmesh send -t` can act as a
//!     drop-in `set sendmail` transport.
//!   - [`maildir`] writes a decrypted incoming message into a Maildir
//!     tree using the cur/new/tmp atomic-rename pattern, which mutt
//!     polls in the background.

pub mod maildir;
pub mod rfc5322;

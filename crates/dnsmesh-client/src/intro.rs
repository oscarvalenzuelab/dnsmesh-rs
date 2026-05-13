//! High-level intro-queue API exposed on [`DmpClient`].
//!
//! Mirrors the `cmd_intro_*` family in `dmp/cli.py` — the user-facing
//! flow when an un-pinned sender's message lands in quarantine:
//!
//! - [`DmpClient::list_intros`]   — show what's pending
//! - [`DmpClient::accept_intro`]  — deliver one to the inbox without pinning
//! - [`DmpClient::trust_intro`]   — deliver + pin sender as a contact
//! - [`DmpClient::block_intro`]   — drop + denylist sender
//!
//! The queue itself is defined in `dnsmesh-storage`; this module just
//! wraps it with the higher-level "promote to inbox" / "fetch + verify
//! contact identity" steps that span the network + the contact store.

use dnsmesh_storage::PendingIntro;

use crate::client::DmpClient;
use crate::error::ClientError;
use crate::receive::InboxMessage;

/// A delivered, decrypted intro pulled out of the quarantine queue.
///
/// Same shape as [`InboxMessage`] but flagged so the CLI can clearly
/// distinguish promoted-from-intro deliveries from regular inbox
/// traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveredIntro {
    pub intro_id: i64,
    pub message: InboxMessage,
}

impl DmpClient {
    /// All pending intros, newest first.
    ///
    /// `async` is API-stable scaffolding; the body is currently sync.
    #[allow(clippy::unused_async)]
    pub async fn list_intros(&self) -> Result<Vec<PendingIntro>, ClientError> {
        Ok(self.intro_queue.list_pending()?)
    }

    /// Promote one quarantined intro into a regular inbox delivery
    /// without pinning the sender. The returned [`InboxMessage`] is
    /// the same shape `receive_messages` would have produced if the
    /// sender had been pinned at receive time. The intro row is
    /// removed from the queue atomically (`DELETE … RETURNING`), so
    /// concurrent CLI invocations against the same `intro_id` cannot
    /// both surface the plaintext.
    ///
    /// Returns `Ok(None)` if `intro_id` doesn't exist (or another
    /// caller already took it).
    #[allow(clippy::unused_async)]
    pub async fn accept_intro(&self, intro_id: i64) -> Result<Option<DeliveredIntro>, ClientError> {
        let Some(intro) = self.intro_queue.take(intro_id)? else {
            return Ok(None);
        };
        let message = intro_to_message(&intro)?;
        Ok(Some(DeliveredIntro { intro_id, message }))
    }

    /// Accept the intro AND pin the sender as a trusted contact.
    ///
    /// `address` is the sender's `user@host`. We fetch their identity
    /// record, verify the Ed25519 verifying key matches the one the
    /// quarantined manifest was signed with, then commit the contact.
    /// A mismatch returns [`ClientError::VerifyFailed`] WITHOUT
    /// touching the queue or the contact store — the un-pinned intro
    /// stays available for review. We `get()` first (read-only),
    /// verify the address resolves to the same SPK, and only then
    /// `take()` to consume the row, so a verification failure leaves
    /// the queue intact.
    pub async fn trust_intro(
        &self,
        intro_id: i64,
        address: &str,
    ) -> Result<Option<DeliveredIntro>, ClientError> {
        let Some(intro) = self.intro_queue.get(intro_id)? else {
            return Ok(None);
        };
        let mut spk = [0u8; 32];
        if intro.sender_spk.len() != 32 {
            return Err(ClientError::VerifyFailed {
                name: "intro.sender_spk".to_string(),
            });
        }
        spk.copy_from_slice(&intro.sender_spk);

        let contact = self.fetch_identity(address).await?;
        if contact.ed25519_spk != spk {
            return Err(ClientError::VerifyFailed {
                name: format!(
                    "trust_intro: identity at {address} signs with a different ed25519 key than \
                     the quarantined intro"
                ),
            });
        }
        // Pin (or update) the contact. Queue consume is atomic via
        // take(): if a concurrent caller already drained the row, we
        // return Ok(None) and the contact pin still stands (idempotent
        // overwrite of the same key material).
        self.add_contact(contact).await?;
        let Some(taken) = self.intro_queue.take(intro_id)? else {
            return Ok(None);
        };
        let message = intro_to_message(&taken)?;
        Ok(Some(DeliveredIntro { intro_id, message }))
    }

    /// Drop the intro and add the sender to the denylist so future
    /// manifests from the same `sender_spk` skip the decrypt and the
    /// queue entirely. `note` is a free-form local annotation — never
    /// leaves the local sqlite db.
    ///
    /// Returns `true` if the row was actually removed (i.e. the
    /// `intro_id` was valid and the queue entry existed).
    #[allow(clippy::unused_async)]
    pub async fn block_intro(&self, intro_id: i64, note: &str) -> Result<bool, ClientError> {
        let Some(intro) = self.intro_queue.get(intro_id)? else {
            return Ok(false);
        };
        self.intro_queue.block_sender(&intro.sender_spk, note)?;
        Ok(self.intro_queue.reject(intro_id)?)
    }
}

fn intro_to_message(intro: &PendingIntro) -> Result<InboxMessage, ClientError> {
    let mut sender_signing_pk = [0u8; 32];
    if intro.sender_spk.len() != 32 {
        return Err(ClientError::VerifyFailed {
            name: "intro.sender_spk".to_string(),
        });
    }
    sender_signing_pk.copy_from_slice(&intro.sender_spk);

    let mut msg_id = [0u8; 16];
    if intro.msg_id.len() != 16 {
        return Err(ClientError::VerifyFailed {
            name: "intro.msg_id".to_string(),
        });
    }
    msg_id.copy_from_slice(&intro.msg_id);

    Ok(InboxMessage {
        sender_signing_pk,
        plaintext: intro.payload.clone(),
        // The original DMPHeader timestamp isn't part of what we
        // persisted (the intro row stores the decrypted payload, not
        // the outer DMPMessage), so we surface received_at instead —
        // the closest meaningful ts the user can see in the CLI.
        timestamp: intro.received_at,
        msg_id,
        // The intro queue stores the sender_username from the
        // original envelope verification (see receive::receive_messages
        // quarantine path) so promoted intros keep the same label.
        sender_label: intro.sender_username.clone(),
    })
}

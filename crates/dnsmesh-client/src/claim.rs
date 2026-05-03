//! Claim routing — sender-published pointers that let recipients
//! discover messages via a third-party "provider" zone.
//!
//! Mirrors the M9/M10 claim surface in `dmp/client/client.py` (the
//! `publish_claim` block at line 794 + the `receive_claims` block at
//! line 1253). A claim record is the wire-level "I delivered a
//! message for you, here's where to find it" pointer that the sender
//! drops at a well-known DNS name under a provider zone the recipient
//! is listening on. The receiver walks claim slots at the providers
//! they trust, parses + verifies signatures, fetches the corresponding
//! manifests from the sender's home zone, and decrypts as usual.
//!
//! Scope here is the M9/M10 client-side flow:
//!
//!   * [`DmpClient::publish_claim`]  — sign + publish one claim record
//!     at a single provider zone.
//!   * [`DmpClient::send_message_with_claim`] — wrap [`DmpClient::send_message`]
//!     to also publish a claim at every provider zone the caller
//!     supplies. Manifest-publish failures bubble up as before; claim-
//!     publish failures are best-effort and logged via `tracing`.
//!   * [`DmpClient::receive_via_claim`] — poll claim records at one
//!     provider zone, fetch the referenced manifest from the sender's
//!     mailbox zone, decrypt, and route the result through the same
//!     pinned-vs-TOFU-vs-intro-queue gate as [`DmpClient::receive_messages`].
//!
//! Provider selection (`select_providers` from
//! `dmp/client/claim_routing.py`) lives at the heartbeat layer and
//! belongs to a future milestone — callers pass pre-ranked zones in.

use std::collections::HashSet;

use dnsmesh_core::claim::{claim_rrset_name, ClaimRecord, MAX_SLOT};
use dnsmesh_core::crypto::derive_user_id;
use dnsmesh_core::manifest::SlotManifest;
use dnsmesh_storage::NewIntro;

use crate::addressing::{slot_domain, slot_for_msg_id, DEFAULT_TTL_SECONDS};
use crate::client::DmpClient;
use crate::contacts::Contact;
use crate::error::ClientError;
use crate::receive::InboxMessage;

/// Acceptable clock skew when verifying inbound claim freshness. Matches
/// the Python default in `dmp/core/claim.py` (60 seconds).
const CLAIM_TS_SKEW_SECONDS: u64 = 60;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl DmpClient {
    /// Sign and publish a single [`ClaimRecord`] addressed to
    /// `recipient_id` at `provider_zone`.
    ///
    /// `slot` MUST equal the manifest's slot (i.e.
    /// `slot_for_msg_id(&msg_id)`); a mismatch leaves the receiver
    /// looking at the wrong mailbox label and the message never lands.
    /// `sender_mailbox_domain` is normally `self.domain`, but the
    /// argument is exposed so a sender publishing on behalf of a
    /// foreign-zone identity can override it.
    ///
    /// Returns `true` if the writer accepted the publish.
    pub async fn publish_claim(
        &self,
        recipient_id: &[u8; 32],
        slot: u8,
        msg_id: &[u8; 16],
        exp: u64,
        provider_zone: &str,
    ) -> Result<bool, ClientError> {
        if slot > MAX_SLOT {
            return Err(ClientError::InvalidConfig(format!(
                "publish_claim: slot {slot} exceeds MAX_SLOT ({MAX_SLOT})",
            )));
        }
        let now = unix_now();
        if exp <= now {
            return Err(ClientError::InvalidConfig(format!(
                "publish_claim: exp {exp} is not in the future (now={now})",
            )));
        }
        let claim = ClaimRecord {
            msg_id: *msg_id,
            sender_spk: self.crypto.signing_public_key_bytes(),
            sender_mailbox_domain: self.domain.clone(),
            slot,
            ts: now,
            exp,
        };
        let wire = claim
            .sign(&self.crypto)
            .map_err(|e| ClientError::InvalidConfig(format!("claim sign: {e}")))?;
        let name = claim_rrset_name(recipient_id, slot, provider_zone)
            .map_err(|e| ClientError::InvalidConfig(format!("claim_rrset_name: {e}")))?;
        let ttl_u32 = u32::try_from(exp.saturating_sub(now)).unwrap_or(u32::MAX);
        let ok = self
            .writer
            .publish_txt_record(&name, &wire, ttl_u32)
            .await?;
        Ok(ok)
    }

    /// Wrap [`Self::send_message`] with claim routing: send the message
    /// as usual, then publish a claim record for it at every zone in
    /// `provider_zones`.
    ///
    /// Manifest-publish failures bubble up. Claim-publish failures are
    /// best-effort and logged via `tracing::warn!` — a recipient that
    /// reaches us through any other channel (own-zone walk, a different
    /// provider) still gets the message, so a single provider being
    /// down shouldn't block delivery. Mirrors Python's
    /// `claim_outcomes` accumulator semantics: per-provider success or
    /// failure, message itself proceeds.
    ///
    /// Returns the same 16-byte `msg_id` as [`Self::send_message`].
    pub async fn send_message_with_claim(
        &self,
        recipient_username: &str,
        plaintext: &[u8],
        provider_zones: &[&str],
    ) -> Result<[u8; 16], ClientError> {
        let msg_id = self.send_message(recipient_username, plaintext).await?;
        // Re-derive the recipient_id from the contact store so we can
        // emit the claim under the right routing label.
        let stored = self
            .contacts
            .get_contact(recipient_username)?
            .ok_or_else(|| ClientError::ContactNotFound {
                username: recipient_username.to_string(),
            })?;
        let contact = Contact {
            username: stored.username,
            x25519_pk: stored.x25519_pk,
            ed25519_spk: stored.ed25519_spk,
            domain: stored.domain,
        };
        let recipient_id = derive_user_id(&contact.x25519_pk);
        // `slot_for_msg_id` returns a u32 because the manifest helpers
        // build DNS labels from it; ClaimRecord.slot is u8 because
        // claim labels share the same 0..=MAX_SLOT (9) space. The
        // narrowing is bounded — slot_for_msg_id is `% SLOT_COUNT` so
        // the result always fits.
        let slot_u32 = slot_for_msg_id(&msg_id);
        let slot = u8::try_from(slot_u32).map_err(|_| {
            ClientError::InvalidConfig(format!(
                "send_message_with_claim: slot {slot_u32} from slot_for_msg_id does not fit in u8",
            ))
        })?;
        let exp = unix_now().saturating_add(DEFAULT_TTL_SECONDS);
        for zone in provider_zones {
            match self
                .publish_claim(&recipient_id, slot, &msg_id, exp, zone)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    tracing::warn!(provider = zone, "claim publish reported writer-no-op");
                }
                Err(e) => {
                    tracing::warn!(provider = zone, error = %e, "claim publish failed");
                }
            }
        }
        Ok(msg_id)
    }

    /// Walk every claim slot at `provider_zone` for messages addressed
    /// to this client, fetch + decrypt each referenced manifest, and
    /// return the deliverable inbox messages.
    ///
    /// Routing semantics match [`Self::receive_messages`]:
    ///
    /// * Replay-cache dedup keyed on `(sender_spk, msg_id)`.
    /// * Pinned-contacts mode + pinned sender → inbox.
    /// * Pinned-contacts mode + un-pinned + denylisted → drop.
    /// * Pinned-contacts mode + un-pinned + un-denylisted → quarantine
    ///   in the intro queue.
    /// * TOFU mode (zero pinned contacts) → inbox.
    ///
    /// Manifests are looked up at `claim.sender_mailbox_domain` (NOT
    /// `provider_zone`) — same chunk-zone integrity rule as
    /// `receive_messages`. A claim that lies about its
    /// `sender_mailbox_domain` would just send the receiver looking
    /// for chunks under the wrong zone and the fetch would miss; the
    /// signature still has to verify against the sender_spk.
    pub async fn receive_via_claim(
        &self,
        provider_zone: &str,
    ) -> Result<Vec<InboxMessage>, ClientError> {
        if provider_zone.is_empty() {
            return Err(ClientError::InvalidConfig(
                "receive_via_claim: provider_zone must not be empty".to_string(),
            ));
        }

        let listed = self.list_contacts().await?;
        let pinned: HashSet<[u8; 32]> = listed.iter().map(|c| c.ed25519_spk).collect();
        let tofu_mode = pinned.is_empty();

        let now = unix_now();
        let mut delivered: Vec<InboxMessage> = Vec::new();

        for slot in 0..=MAX_SLOT {
            let claim_name = claim_rrset_name(&self.user_id, slot, provider_zone)
                .map_err(|e| ClientError::InvalidConfig(format!("claim_rrset_name: {e}")))?;
            let Some(records) = self.reader.query_txt_record(&claim_name).await? else {
                continue;
            };
            for record in &records {
                let Some(claim) =
                    ClaimRecord::parse_and_verify(record, Some(now), CLAIM_TS_SKEW_SECONDS)
                else {
                    continue;
                };
                // Embedded slot in the claim must match the slot label
                // it was published at — otherwise we'd be willing to
                // honor a record that happened to land under a wrong
                // label.
                if claim.slot != slot {
                    continue;
                }
                let in_pinned_set = pinned.contains(&claim.sender_spk);
                let rotation_accepted =
                    if !in_pinned_set && !tofu_mode && self.rotation_chain_enabled {
                        crate::rotation_chain::rotation_manifest_accepted(
                            &self.reader,
                            &listed,
                            &claim.sender_spk,
                        )
                        .await?
                    } else {
                        false
                    };
                let quarantine = !tofu_mode && !in_pinned_set && !rotation_accepted;
                if quarantine && self.intro_queue.is_blocked(&claim.sender_spk)? {
                    continue;
                }
                if in_pinned_set
                    && self.rotation_chain_enabled
                    && crate::rotation_chain::rotation_manifest_revoked(
                        &self.reader,
                        &listed,
                        &claim.sender_spk,
                    )
                    .await?
                {
                    continue;
                }
                if self
                    .replay_cache
                    .has_seen(&claim.sender_spk, &claim.msg_id)?
                {
                    continue;
                }
                let Some(manifest) = self
                    .lookup_manifest_for_claim(&claim, &claim.sender_mailbox_domain)
                    .await?
                else {
                    continue;
                };
                if manifest.is_expired(Some(now)) {
                    continue;
                }
                let Some(decoded) = self
                    .fetch_and_decrypt(&manifest, &claim.sender_mailbox_domain)
                    .await
                else {
                    continue;
                };
                self.replay_cache.record(
                    &manifest.sender_spk,
                    &manifest.msg_id,
                    Some(manifest.exp),
                )?;
                if manifest.prekey_id != dnsmesh_core::manifest::NO_PREKEY {
                    self.consume_prekey_with_dns(manifest.prekey_id).await;
                }
                if quarantine {
                    let _ = self.intro_queue.enqueue(NewIntro {
                        sender_spk: &manifest.sender_spk,
                        sender_username: None,
                        msg_id: &manifest.msg_id,
                        payload: &decoded.plaintext,
                        expires_at: manifest.exp,
                    })?;
                    continue;
                }
                delivered.push(decoded);
            }
        }
        Ok(delivered)
    }

    /// Look up the manifest referenced by `claim` at the sender's
    /// mailbox zone and validate the cross-references against the
    /// claim. Returns `Ok(None)` if no record at the slot resolves to
    /// a verified manifest matching this claim.
    async fn lookup_manifest_for_claim(
        &self,
        claim: &ClaimRecord,
        sender_zone: &str,
    ) -> Result<Option<SlotManifest>, ClientError> {
        let slot_name = slot_domain(&self.user_id, u32::from(claim.slot), sender_zone);
        let Some(records) = self.reader.query_txt_record(&slot_name).await? else {
            return Ok(None);
        };
        for record in &records {
            let Some((manifest, _sig)) = SlotManifest::parse_and_verify(record) else {
                continue;
            };
            // The claim's (msg_id, sender_spk) MUST match the manifest
            // the receiver is about to act on. Without these checks an
            // attacker who controls the sender's published slot RRset
            // could swap in a different message and our claim path
            // would obediently fetch + decrypt it.
            if manifest.msg_id != claim.msg_id {
                continue;
            }
            if manifest.sender_spk != claim.sender_spk {
                continue;
            }
            if manifest.recipient_id != self.user_id {
                continue;
            }
            return Ok(Some(manifest));
        }
        Ok(None)
    }
}

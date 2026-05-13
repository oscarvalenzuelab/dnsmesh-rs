//! End-to-end-encrypted receive path.
//!
//! Mirrors Python `DMPClient.receive_messages` (lines 879-1023 of
//! `dmp/client/client.py`) plus `_fetch_and_decrypt` (lines 1503-1628),
//! trimmed to the M3 phase-2B surface: walk the union of (our own zone,
//! every pinned contact's zone), poll the 10 mailbox slots under each
//! one, verify each manifest, fetch + reassemble + decrypt under the
//! SAME zone the manifest came from, and dedupe via the replay cache.
//! The Python receive_messages additionally supports M10 claim routing
//! and the intro-queue quarantine flow; those land in follow-ups.
//!
//! Deviations vs. Python:
//!
//! - **TOFU fallback**: when the local contact store has zero pinned
//!   contacts we accept any signature-valid manifest. This matches
//!   Python's "no pinned signing keys" branch and keeps fresh-onboarding
//!   usable. Once the user pins any contact, only that contact's
//!   `sender_spk` is honored.
//! - **Chunk-zone integrity**: chunk RRsets for an accepted manifest
//!   are looked up under the SAME zone the manifest came from
//!   (`fetch_and_decrypt(zone)` takes the source zone verbatim). A
//!   manifest signed by Alice but published under a zone Alice doesn't
//!   control would otherwise be allowed to redirect chunk fetches
//!   anywhere — manifest-zone integrity is the load-bearing security
//!   property.

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use dnsmesh_core::chunking::MessageChunker;
use dnsmesh_core::crypto::{DmpCrypto, EncryptedMessage};
use dnsmesh_core::envelope;
use dnsmesh_core::erasure;
use dnsmesh_core::manifest::{SlotManifest, NO_PREKEY};
use dnsmesh_core::message::DMPMessage;
use dnsmesh_core::prekeys::prekey_rrset_name;
use dnsmesh_storage::NewIntro;

use crate::addressing::{chunk_domain, msg_key, slot_domain, SLOT_COUNT};
use crate::client::DmpClient;
use crate::error::ClientError;

/// Wire prefix for a chunk TXT record. Matches `send::chunk_txt_record`
/// (and Python `DMPDNSRecord(record_type="chunk").to_txt_record()` minus
/// the metadata dict) byte-for-byte.
const CHUNK_TXT_PREFIX: &str = "v=dmp1;t=chunk;d=";

/// A delivered, decrypted inbox entry returned by [`DmpClient::receive_messages`].
///
/// Mirrors Python's `InboxMessage` dataclass (lines 188-196 of
/// `dmp/client/client.py`). The `sender_signing_pk` is the verified
/// Ed25519 public key from the slot manifest — callers can match it
/// against their pinned contact list to attribute the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxMessage {
    /// 32-byte Ed25519 verifying key of the sender, lifted verbatim
    /// from the verified [`SlotManifest`].
    pub sender_signing_pk: [u8; 32],
    /// Decrypted plaintext (after stripping any DMPv2 envelope).
    pub plaintext: Vec<u8>,
    /// Sender-supplied `ts` from the inner `DMPHeader` (Unix seconds).
    pub timestamp: u64,
    /// 16-byte message ID.
    pub msg_id: [u8; 16],
    /// Trusted sender label in canonical `user@host` form, populated
    /// only when the inbound DMPv2 envelope carried a `from` claim AND
    /// that claim's resolved [`dnsmesh_core::identity::IdentityRecord`]
    /// pinned the same `ed25519_spk` as the verified manifest. `None`
    /// when no envelope was present, the claim failed canonicalization,
    /// DNS lookup failed, or the resolved record's SPK did not match.
    pub sender_label: Option<String>,
}

/// Strip the `v=dmp1;t=chunk;d=<b64>` envelope and decode the wrapped
/// chunk bytes. Returns `None` if the prefix is missing or the trailing
/// payload is not valid base64.
fn parse_chunk_txt(record: &str) -> Option<Vec<u8>> {
    let payload = record.strip_prefix(CHUNK_TXT_PREFIX)?;
    B64.decode(payload).ok()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl DmpClient {
    /// Pull every reassembled, signature-verified message addressed to
    /// this client out of its 10 mailbox slots.
    ///
    /// Returns the list of newly-delivered messages. Replay-cache hits,
    /// signature failures, expired manifests, and (in pinned-contacts
    /// mode) manifests from un-pinned senders are silently skipped. If
    /// no contacts are pinned, every signature-valid manifest is
    /// accepted (TOFU mode).
    ///
    /// On a successful decrypt the replay cache learns the
    /// `(sender_spk, msg_id)` pair and the consumed prekey (if any)
    /// is deleted from the local prekey store — that's the
    /// forward-secrecy property: once consumed, a later compromise of
    /// the long-term key cannot recover this message's session.
    pub async fn receive_messages(&self) -> Result<Vec<InboxMessage>, ClientError> {
        // Pinned-contact set drives the TOFU vs. strict-pin decision.
        // Re-built every call so a contact pinned between two
        // receive_messages() invocations takes effect immediately.
        let listed = self.list_contacts().await?;
        let pinned: HashSet<[u8; 32]> = listed.iter().map(|c| c.ed25519_spk).collect();
        let tofu_mode = pinned.is_empty();

        // Build the zone walk: own zone first (preserves the legacy
        // behavior for same-mesh deployments) then each pinned
        // contact's zone, deduped. Empty contact.domain (V1/V2 legacy
        // rows) collapses to own zone; same-domain pins also collapse,
        // so the common case stays a single walk.
        //
        // Mirrors Python `_zones_to_poll`. The SENDER publishes
        // manifests under the SENDER's zone (Python `_slot_domain`
        // defaults `zone=` to `self.domain`), so a recipient walking
        // only their own zone would never see traffic from foreign-
        // zone senders.
        let mut zones: Vec<String> = Vec::new();
        let mut seen_zone: HashSet<String> = HashSet::new();
        zones.push(self.domain.clone());
        seen_zone.insert(self.domain.clone());
        for contact in &listed {
            let zone = if contact.domain.is_empty() {
                continue;
            } else {
                &contact.domain
            };
            if seen_zone.insert(zone.clone()) {
                zones.push(zone.clone());
            }
        }

        let mut results: Vec<InboxMessage> = Vec::new();
        let now = unix_now();

        for zone in &zones {
            for slot in 0..SLOT_COUNT {
                let slot_name = slot_domain(&self.user_id, slot, zone);
                let Some(records) = self.reader.query_txt_record(&slot_name).await? else {
                    continue;
                };
                for record in &records {
                    let Some((manifest, _sig)) = SlotManifest::parse_and_verify(record) else {
                        continue;
                    };
                    // Cross-check the manifest is actually for us. A signed
                    // manifest under our slot label that names a different
                    // recipient is malformed (or hostile); drop it.
                    if manifest.recipient_id != self.user_id {
                        continue;
                    }
                    if manifest.is_expired(Some(now)) {
                        continue;
                    }
                    let in_pinned_set = pinned.contains(&manifest.sender_spk);
                    // Rotation-chain check: when a manifest is signed
                    // by a key not directly pinned, ask the published
                    // rotation chain whether some pinned contact has
                    // rotated TO this key. If so, treat the manifest
                    // as if it were pinned (deliver to inbox, not
                    // quarantine). Off by default; opt-in via
                    // DmpClientConfig::rotation_chain_enabled.
                    let rotation_accepted =
                        if !in_pinned_set && !tofu_mode && self.rotation_chain_enabled {
                            crate::rotation_chain::rotation_manifest_accepted(
                                &self.reader,
                                &listed,
                                &manifest.sender_spk,
                            )
                            .await?
                        } else {
                            false
                        };
                    let quarantine = !tofu_mode && !in_pinned_set && !rotation_accepted;
                    // Drop hard if the sender is on the denylist. Skip
                    // the decrypt entirely so we don't burn the prekey
                    // for a sender we've already chosen to ignore.
                    if quarantine && self.intro_queue.is_blocked(&manifest.sender_spk)? {
                        continue;
                    }
                    // Rotation-revocation cross-check: a manifest
                    // signed by a pinned key that the same subject has
                    // since revoked must drop. Without this a
                    // compromised-key holder keeps delivering to every
                    // pinned recipient until they re-pin out of band.
                    if in_pinned_set
                        && self.rotation_chain_enabled
                        && crate::rotation_chain::rotation_manifest_revoked(
                            &self.reader,
                            &listed,
                            &manifest.sender_spk,
                        )
                        .await?
                    {
                        continue;
                    }
                    // has_seen + record around the decrypt work means a
                    // transient DNS miss during chunk fetch doesn't
                    // permanently blacklist a valid manifest — the next
                    // receive_messages() retries it. (Python's M10 path uses
                    // a richer claim_for_decode/release/finalize sweep to
                    // dedupe across concurrent workers; M3 single-process
                    // semantics don't need that.) Replay-cache key is
                    // (sender_spk, msg_id) — independent of source zone,
                    // so a manifest seen via the own-zone walk is still
                    // dedup'd if a pinned-contact walk re-finds it. We
                    // dedup intro-queue traffic too: a quarantined
                    // message that the user later accepts shouldn't
                    // re-quarantine on the next poll.
                    if self
                        .replay_cache
                        .has_seen(&manifest.sender_spk, &manifest.msg_id)?
                    {
                        continue;
                    }
                    let Some(decoded) = self.fetch_and_decrypt(&manifest, zone).await else {
                        continue;
                    };
                    self.replay_cache.record(
                        &manifest.sender_spk,
                        &manifest.msg_id,
                        Some(manifest.exp),
                    )?;
                    if manifest.prekey_id != NO_PREKEY {
                        // Forward secrecy is enforced by the LOCAL
                        // delete (the prekey scalar is gone after
                        // consume()), so we always run consume() even
                        // if the DNS delete fails. Best-effort on the
                        // local side too: a failure here means the
                        // next receive pass will see the row and won't
                        // be able to decrypt anything new, but the
                        // already-delivered message still rolls into
                        // `results`.
                        self.consume_prekey_with_dns(manifest.prekey_id).await;
                    }
                    if quarantine {
                        // Pinned-contacts mode + un-pinned + un-blocked
                        // sender: the message decrypted fine (which
                        // means the manifest signature verified and
                        // the AEAD authenticated), but the user hasn't
                        // told us they want to talk to this sender
                        // yet. Persist the plaintext so they can
                        // review with `dnsmesh intro list/accept/
                        // trust/block` without us needing the original
                        // manifest still to be in DNS — chunks expire.
                        //
                        // `sender_label` comes from the verified DMPv2
                        // envelope (or `None` if absent/untrusted) —
                        // intro UI can render the canonical address
                        // instead of forcing the user to recognize a
                        // raw 32-byte SPK.
                        let _ = self.intro_queue.enqueue(NewIntro {
                            sender_spk: &manifest.sender_spk,
                            sender_username: decoded.sender_label.as_deref(),
                            msg_id: &manifest.msg_id,
                            payload: &decoded.plaintext,
                            expires_at: manifest.exp,
                        })?;
                        continue;
                    }
                    results.push(decoded);
                }
            }
        }

        Ok(results)
    }

    /// Delete a consumed prekey both locally (sqlite row, the actual
    /// forward-secrecy guarantee) and from the published TXT RRset
    /// (best-effort cleanup so a future sender doesn't pick a prekey
    /// whose scalar we've already wiped).
    ///
    /// Mirrors Python `_consume_prekey`. Failures of the DNS delete
    /// are logged via `tracing::warn!` but do not block delivery —
    /// the message has already decrypted and the user shouldn't see
    /// a delivery failure for a DNS-cleanup hiccup. The published
    /// record will rot out at its TTL boundary regardless.
    pub(crate) async fn consume_prekey_with_dns(&self, prekey_id: u32) {
        // 1. Look up the wire bytes published for this prekey before
        //    we drop the local row. record_wire is set at publish time
        //    by `refresh_prekeys`; if it's missing the row predates
        //    that wiring or never made it onto the writer.
        let wire = match self.prekeys.get_wire(prekey_id) {
            Ok(w) => w,
            Err(e) => {
                tracing::warn!(
                    prekey_id,
                    error = %e,
                    "consume_prekey: wire lookup failed; skipping DNS delete",
                );
                None
            }
        };

        // 2. Best-effort DNS delete of the exact TXT we published.
        //    Passing `Some(&wire)` matches Python's `value=wire` so we
        //    only remove the one record we own, not the entire RRset.
        if let Some(wire_record) = wire {
            let name = prekey_rrset_name(&self.username, &self.domain);
            match self
                .writer
                .delete_txt_record(&name, Some(&wire_record))
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    tracing::warn!(
                        prekey_id,
                        name,
                        "consume_prekey: writer reported no TXT removed",
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        prekey_id,
                        name,
                        error = %e,
                        "consume_prekey: DNS delete failed; record will rot at TTL",
                    );
                }
            }
        }

        // 3. Local delete is the security guarantee. Even if step 2
        //    failed, after this point neither this process nor a
        //    later attacker with the long-term key can recover the
        //    prekey scalar.
        if let Err(e) = self.prekeys.consume(prekey_id) {
            tracing::warn!(
                prekey_id,
                error = %e,
                "consume_prekey: local sqlite consume failed; row may be retained",
            );
        }
    }

    /// Fetch every chunk RRset for `manifest`, reassemble via erasure
    /// decode, parse the outer [`DMPMessage`], cross-check the inner
    /// header against the manifest, rebuild the AAD, and decrypt.
    ///
    /// `zone` is the zone the manifest was fetched from — chunk RRsets
    /// MUST be looked up under the same zone (`source_zone` in
    /// Python's `_fetch_and_decrypt`). Re-deriving it from
    /// `self.domain` would let a manifest signed for our user but
    /// published in a foreign zone redirect chunk fetches back into
    /// our own zone, which the sender doesn't control.
    ///
    /// Returns `None` on any failure: missing chunks, decode failure,
    /// header mismatch, expired inner header, prekey lookup miss, or
    /// AEAD authentication failure. Mirrors Python `_fetch_and_decrypt`.
    pub(crate) async fn fetch_and_decrypt(
        &self,
        manifest: &SlotManifest,
        zone: &str,
    ) -> Option<InboxMessage> {
        let key = msg_key(
            &manifest.msg_id,
            &manifest.recipient_id,
            &manifest.sender_spk,
        );
        let chunker = MessageChunker::new(true);

        // Walk every chunk position up to total_chunks, collecting
        // valid shares keyed by share_id. Stop early once we have k
        // shares — erasure::decode only needs k of n.
        let data_chunks = manifest.data_chunks as usize;
        let mut shares: HashMap<usize, Vec<u8>> = HashMap::with_capacity(data_chunks);
        for chunk_num in 0..manifest.total_chunks {
            if shares.len() >= data_chunks {
                break;
            }
            let name = chunk_domain(&key, chunk_num, zone);
            let Ok(Some(records)) = self.reader.query_txt_record(&name).await else {
                continue;
            };
            for txt in &records {
                let Some(wire_chunk) = parse_chunk_txt(txt) else {
                    continue;
                };
                let Some(block) = chunker.unwrap_block(&wire_chunk) else {
                    continue;
                };
                shares.insert(chunk_num as usize, block);
                break;
            }
        }
        if shares.len() < data_chunks {
            return None;
        }

        let share_refs: Vec<(usize, &[u8])> =
            shares.iter().map(|(k, v)| (*k, v.as_slice())).collect();
        let assembled = erasure::decode(&share_refs, data_chunks, manifest.total_chunks as usize)?;
        let outer = DMPMessage::from_bytes(&assembled).ok()?;
        let encrypted = EncryptedMessage::from_bytes(&outer.payload).ok()?;

        // Inner-header cross-checks against the signed manifest. The
        // AEAD proves the ciphertext and AAD are bound to a sender who
        // had ECDH access to the recipient key, and the manifest
        // signature proves a specific sender published the slot — but
        // without these checks a legitimate sender could put a
        // different msg_id / recipient_id inside the ciphertext than in
        // the manifest and we'd surface the lie.
        if outer.header.message_id != manifest.msg_id {
            return None;
        }
        if outer.header.recipient_id != manifest.recipient_id {
            return None;
        }
        if outer.header.is_expired(unix_now()) {
            return None;
        }

        // Rebuild the same AAD the sender bound at encrypt time. Must
        // mirror `send::build_aad` byte-for-byte: the outer header with
        // total_chunks AND chunk_number both forced to 0, then
        // prekey_id as 4 big-endian bytes. Forcing both to 0 keeps the
        // AAD stable across the post-encryption erasure step (which
        // overwrites total_chunks on the wire) without coupling the
        // crypto to the chunking decision.
        let mut aad_header = outer.header.clone();
        aad_header.total_chunks = 0;
        aad_header.chunk_number = 0;
        let mut aad = aad_header.to_bytes();
        aad.extend_from_slice(&manifest.prekey_id.to_be_bytes());

        // Prekey-based ECDH path for forward secrecy. When prekey_id
        // is NO_PREKEY (0) we fall back to the long-term identity
        // secret; otherwise we look up the matching one-time X25519
        // private key and decrypt with it.
        let raw_plaintext = if manifest.prekey_id == NO_PREKEY {
            self.crypto.decrypt_message(&encrypted, Some(&aad)).ok()?
        } else {
            let prekey_sk = self.prekeys.get_private_key(manifest.prekey_id).ok()??;
            // We don't depend on x25519_dalek directly (no new top-
            // level dep), so we can't build a `StaticSecret` from the
            // prekey bytes here. Instead we rebuild a transient
            // DmpCrypto around the scalar — the Ed25519 derivation it
            // also performs is unused but it's the cheapest way to
            // reach decrypt_message without widening the crate graph.
            // The transient identity drops at end of scope; its
            // private seed zeroizes through `Zeroize`.
            let prekey_crypto = DmpCrypto::from_private_bytes(&prekey_sk[..]).ok()?;
            prekey_crypto.decrypt_message(&encrypted, Some(&aad)).ok()?
        };

        // Peel any DMPv2 envelope. A v1 plaintext (no prefix) is
        // returned unchanged with `claimed_from = None`; v2 envelopes
        // strip the wrapper and surface the canonical `from` claim for
        // SPK-binding verification.
        let (plaintext, claimed_from) = envelope::decode(&raw_plaintext);
        let sender_label = match claimed_from {
            Some(addr) => {
                self.resolve_envelope_label(&addr, &manifest.sender_spk)
                    .await
            }
            None => None,
        };

        Some(InboxMessage {
            sender_signing_pk: manifest.sender_spk,
            plaintext,
            timestamp: outer.header.timestamp,
            msg_id: outer.header.message_id,
            sender_label,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Local copy of the send-side encoder. The send path keeps its own
    /// private `chunk_txt_record` helper; this test pins the receive
    /// parser against the exact same `v=dmp1;t=chunk;d=<b64>` shape so a
    /// future drift in either side's wire format trips at least one
    /// test before round-trip fails in integration.
    fn encode_like_send(wire_chunk: &[u8]) -> String {
        format!("{CHUNK_TXT_PREFIX}{}", B64.encode(wire_chunk))
    }

    #[test]
    fn parse_chunk_txt_round_trips_with_send_format() {
        for wire in [
            Vec::<u8>::new(),
            vec![0x00],
            vec![0xAB, 0xCD],
            (0u8..=255).collect::<Vec<u8>>(),
        ] {
            let txt = encode_like_send(&wire);
            let parsed = parse_chunk_txt(&txt).expect("send format must parse");
            assert_eq!(parsed, wire, "round-trip must preserve every byte");
        }
    }

    #[test]
    fn parse_chunk_txt_rejects_missing_prefix() {
        assert!(parse_chunk_txt("d=YQ==").is_none());
        assert!(parse_chunk_txt("v=dmp1;t=manifest;d=YQ==").is_none());
    }

    #[test]
    fn parse_chunk_txt_rejects_bad_base64() {
        let bogus = format!("{CHUNK_TXT_PREFIX}!!!not-base64!!!");
        assert!(parse_chunk_txt(&bogus).is_none());
    }
}

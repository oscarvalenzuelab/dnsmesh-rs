//! End-to-end-encrypted send path.
//!
//! Mirrors Python `DMPClient.send_message` (lines 587-840 of
//! `dmp/client/client.py`) trimmed to the M3 phase-2A surface: pick a
//! recipient prekey if one is published, ECDH-encrypt with header-bound AAD,
//! erasure-encode, RS-wrap each share, publish chunks, then publish the
//! signed [`SlotManifest`] at the recipient's mailbox slot.

use std::time::{SystemTime, UNIX_EPOCH};

use dnsmesh_core::chunking::MessageChunker;
use dnsmesh_core::crypto::derive_user_id;
use dnsmesh_core::envelope;
use dnsmesh_core::erasure;
use dnsmesh_core::manifest::{SlotManifest, NO_PREKEY};
use dnsmesh_core::message::{DMPHeader, DMPMessage, MessageType};
use dnsmesh_core::prekeys::{prekey_rrset_name, Prekey};
use rand_core::{OsRng, RngCore};

use crate::addressing::{chunk_domain, msg_key, slot_domain, slot_for_msg_id, DEFAULT_TTL_SECONDS};
use crate::client::DmpClient;
use crate::contacts::Contact;
use crate::error::ClientError;

/// Build a TXT chunk record matching Python's `DMPDNSRecord(version=1,
/// record_type="chunk", data=…, metadata={}).to_txt_record()`.
///
/// Format: `v=dmp1;t=chunk;d=<base64(wire_chunk)>`. Dropping the metadata dict
/// keeps the record under the 255-byte TXT cap (chunk_num and msg_key live in
/// the domain name, not in the record body).
fn chunk_txt_record(wire_chunk: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    let b64 = B64.encode(wire_chunk);
    format!("v=dmp1;t=chunk;d={b64}")
}

/// Build the AAD bound into the per-message AEAD encryption.
///
/// Mirrors Python's `aad_header` block: a `DMPHeader` with `total_chunks` set
/// to 0 (sentinel — the real value isn't known until after erasure
/// encoding) followed by `prekey_id` as 4 big-endian bytes.
///
/// Including `prekey_id` in the AAD is defense-in-depth — an attacker who
/// rewrites the manifest's `prekey_id` field would already break the ECDH
/// derivation, but binding it here surfaces the failure as a clean AEAD tag
/// mismatch rather than an opaque "shared secret disagreed".
fn build_aad(
    msg_id: &[u8; 16],
    sender_id: &[u8; 32],
    recipient_id: &[u8; 32],
    timestamp: u64,
    ttl: u32,
    prekey_id: u32,
) -> Vec<u8> {
    let header = DMPHeader {
        version: 1,
        message_type: MessageType::Data,
        message_id: *msg_id,
        sender_id: *sender_id,
        recipient_id: *recipient_id,
        total_chunks: 0,
        chunk_number: 0,
        timestamp,
        ttl,
    };
    let mut out = header.to_bytes();
    out.extend_from_slice(&prekey_id.to_be_bytes());
    out
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl DmpClient {
    /// Cross-version gate for the send path.
    ///
    /// Check the recipient's published `versions` BEFORE encrypting;
    /// wrap with a DMPv2 envelope only if they declared v2 support in
    /// their IdentityRecord. A v1-only recipient receives the
    /// plaintext as-is so existing receivers keep working without
    /// re-pinning. The envelope's `from` claim is the sender's
    /// canonical address — the receiver will resolve it back through
    /// DNS and compare against the manifest SPK before trusting the
    /// label.
    async fn maybe_wrap_envelope(&self, contact: &Contact, plaintext: &[u8]) -> Vec<u8> {
        let recipient_versions = self.recipient_versions(contact).await;
        if recipient_versions.contains(&2) {
            let sender_addr = format!("{}@{}", self.username, self.domain);
            envelope::encode(plaintext, Some(&sender_addr))
        } else {
            plaintext.to_vec()
        }
    }

    /// Wrap each erasure share with the per-chunk RS+checksum codec and
    /// publish under its `chunk-NNNN-<msg_key>.<domain>` DNS name. Returns
    /// the first publish failure encountered, or `Ok(())` when every chunk
    /// was accepted.
    async fn publish_chunks(
        &self,
        shares: &[Vec<u8>],
        key: &str,
        ttl_u32: u32,
    ) -> Result<(), ClientError> {
        let chunker = MessageChunker::new(true);
        for (chunk_num, share) in shares.iter().enumerate() {
            let wire_chunk = chunker.wrap_block(share)?;
            let txt = chunk_txt_record(&wire_chunk);
            let cn =
                u32::try_from(chunk_num).expect("chunk_num was bounded by n which fits in u32");
            let name = chunk_domain(key, cn, &self.domain);
            let ok = self.writer.publish_txt_record(&name, &txt, ttl_u32).await?;
            if !ok {
                return Err(ClientError::PublishFailed {
                    kind: "chunk",
                    name,
                });
            }
        }
        Ok(())
    }

    /// Pick a fresh prekey from the recipient's published pool.
    ///
    /// Returns `(prekey_id, prekey_pub)` on success, or `None` if the contact
    /// has no pinned signing key, no live prekey records are published, or
    /// the pool DNS fetch fails.  The caller falls back to the recipient's
    /// long-term X25519 key in the `None` case (no forward secrecy for that
    /// message).  Mirrors Python `_pick_recipient_prekey`.
    async fn pick_recipient_prekey(&self, contact: &Contact) -> Option<(u32, [u8; 32])> {
        let name = prekey_rrset_name(&contact.username, &contact.domain);
        let Ok(Some(records)) = self.reader.query_txt_record(&name).await else {
            return None;
        };
        let mut verified: Vec<Prekey> = Vec::with_capacity(records.len());
        for txt in &records {
            let Some(pk) = Prekey::parse_and_verify(txt, &contact.ed25519_spk) else {
                continue;
            };
            if pk.is_expired(None) {
                continue;
            }
            verified.push(pk);
        }
        if verified.is_empty() {
            return None;
        }
        // Random pick out of the verified pool. OsRng is overkill for a load-
        // spreading choice but it sidesteps any predictability concern.
        let idx = (OsRng.next_u32() as usize) % verified.len();
        let chosen = verified.swap_remove(idx);
        Some((chosen.prekey_id, chosen.public_key))
    }

    /// Send an end-to-end-encrypted message to a pinned contact.
    ///
    /// Returns the 16-byte message ID on success.  Replicates the Python
    /// reference's full flow: prekey pick → AAD-bound encryption → erasure
    /// encode → per-chunk RS+checksum wrap → publish chunks → publish signed
    /// manifest at the recipient's mailbox slot.
    pub async fn send_message(
        &self,
        recipient_username: &str,
        plaintext: &[u8],
    ) -> Result<[u8; 16], ClientError> {
        let stored = self
            .contacts
            .get_contact(recipient_username)?
            .ok_or_else(|| ClientError::ContactNotFound {
                username: recipient_username.to_string(),
            })?;
        // Promote the stored row into the public Contact shape. The V3
        // `domain` column gives us the recipient's home zone; an empty
        // string (V1/V2 legacy row) falls back to the local mesh zone
        // so same-mesh deployments keep working without a re-add. The
        // recipient's prekey RRset lives at THEIR zone, not ours, so
        // sending to a foreign-zone contact would silently fail
        // without this fix.
        let recipient_domain = if stored.domain.is_empty() {
            self.domain.clone()
        } else {
            stored.domain.clone()
        };
        let contact = Contact {
            username: stored.username,
            x25519_pk: stored.x25519_pk,
            ed25519_spk: stored.ed25519_spk,
            domain: recipient_domain,
        };

        let recipient_id = derive_user_id(&contact.x25519_pk);
        let mut msg_id = [0u8; 16];
        OsRng.fill_bytes(&mut msg_id);
        let now = unix_now();
        let ttl_u32 = u32::try_from(DEFAULT_TTL_SECONDS).unwrap_or(u32::MAX);

        // Pick a prekey if the recipient has a live pool published.
        let (prekey_id, recipient_pubkey) = match self.pick_recipient_prekey(&contact).await {
            Some((pid, pk)) => (pid, pk),
            None => (NO_PREKEY, contact.x25519_pk),
        };

        let plaintext_owned = self.maybe_wrap_envelope(&contact, plaintext).await;

        // Encrypt with header-bound AAD. The AAD is a `DMPHeader` block with
        // `total_chunks=0` so it stays stable regardless of the post-
        // erasure chunk count, plus `prekey_id` as 4 big-endian bytes.
        let aad = build_aad(
            &msg_id,
            &self.user_id,
            &recipient_id,
            now,
            ttl_u32,
            prekey_id,
        );
        let encrypted =
            self.crypto
                .encrypt_for_recipient(&plaintext_owned, &recipient_pubkey, Some(&aad))?;

        // Build the outer DMPMessage frame.  The header here uses the real
        // chunk count (set after erasure encode), unlike the AAD block.
        let outer_header = DMPHeader {
            version: 1,
            message_type: MessageType::Data,
            message_id: msg_id,
            sender_id: self.user_id,
            recipient_id,
            total_chunks: 1, // overwritten below
            chunk_number: 0,
            timestamp: now,
            ttl: ttl_u32,
        };
        let mut outer = DMPMessage {
            header: outer_header,
            payload: encrypted.to_bytes(),
            signature: vec![0u8; 32],
        };

        // Erasure-encode the framed outer message into n equal-sized blocks.
        let outer_bytes = outer.to_bytes();
        let (shares, k, n) = erasure::encode(&outer_bytes, erasure::DEFAULT_REDUNDANCY)?;
        // Capture the real chunk count back into the header so the wire
        // matches Python (it gates on `total_chunks` post-encode but does
        // not regenerate the AAD).
        let total_chunks = u32::try_from(n).map_err(|_| {
            ClientError::InvalidConfig(format!(
                "erasure encode produced n={n} which does not fit in u32",
            ))
        })?;
        let data_chunks = u32::try_from(k).map_err(|_| {
            ClientError::InvalidConfig(format!(
                "erasure encode produced k={k} which does not fit in u32",
            ))
        })?;
        outer.header.total_chunks = total_chunks;

        let sender_spk = self.crypto.signing_public_key_bytes();
        let key = msg_key(&msg_id, &recipient_id, &sender_spk);

        self.publish_chunks(&shares, &key, ttl_u32).await?;

        let manifest = SlotManifest {
            msg_id,
            sender_spk,
            recipient_id,
            total_chunks,
            data_chunks,
            prekey_id,
            ts: now,
            exp: now.saturating_add(u64::from(ttl_u32)),
        };
        let slot_record = manifest.sign(&self.crypto)?;
        let slot = slot_for_msg_id(&msg_id);
        let slot_name = slot_domain(&recipient_id, slot, &self.domain);
        let ok = self
            .writer
            .publish_txt_record(&slot_name, &slot_record, ttl_u32)
            .await?;
        if !ok {
            return Err(ClientError::PublishFailed {
                kind: "manifest",
                name: slot_name,
            });
        }

        Ok(msg_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_txt_record_format() {
        let wire = vec![0xAB, 0xCD];
        let txt = chunk_txt_record(&wire);
        // base64("AB CD") = "q80="
        assert_eq!(txt, "v=dmp1;t=chunk;d=q80=");
    }

    #[test]
    fn build_aad_includes_prekey_id_at_tail() {
        let aad = build_aad(
            &[1u8; 16],
            &[2u8; 32],
            &[3u8; 32],
            1_700_000_000,
            300,
            0x1234_5678,
        );
        let tail = &aad[aad.len() - 4..];
        assert_eq!(tail, &0x1234_5678u32.to_be_bytes());
    }

    #[test]
    fn build_aad_uses_total_chunks_zero_sentinel() {
        let aad = build_aad(&[0u8; 16], &[0u8; 32], &[0u8; 32], 0, 0, 0);
        // The AAD should embed `"total":0` literally as part of the header JSON.
        let header_part = &aad[..aad.len() - 4];
        let s = std::str::from_utf8(header_part).unwrap();
        assert!(
            s.contains("\"total\":0"),
            "AAD header should pin total=0; got {s}"
        );
    }
}

//! Client-side rotation chain walking (M5.4 — opt-in).
//!
//! Mirrors `dmp/client/rotation_chain.py`. When a manifest's
//! `sender_spk` doesn't match any pinned contact's signing key, the
//! receive flow optionally walks the published rotation chain
//! (`rotate.…` RRsets) to discover whether a pinned contact has
//! rotated to a new key. Symmetrically, after a pinned contact's
//! manifest verifies, the receive flow can cross-check the rotation
//! RRset for a revocation of the SAME spk and drop the message
//! defensively.
//!
//! Both behaviors are gated behind `DmpClientConfig::rotation_chain_enabled`
//! (default `false`) per the Python opt-in flag — wire format is
//! still flagged "subject to audit-driven revision in v0.3.0" in the
//! Python source.
//!
//! Walk semantics (mirroring Python step-for-step):
//!
//! 1. Fetch every TXT at the candidate rotation RRset(s) for the
//!    contact's `subject = <user>@<host>`. We try BOTH the zone-
//!    anchored form (`rotate.dmp.<host>`) and the per-username hash
//!    form (`rotate.id-<hash16>.<host>`); a contact pinned at
//!    one form may have rotations published at the other. The hash
//!    form mirrors `rotation_rrset_name_user_identity` exactly —
//!    Python's docstring claims `rotate.dmp.id-<hash12>` but its
//!    actual helper output is `rotate.id-<hash16>` and we follow
//!    the helper, not the (stale) docstring.
//! 2. Partition into rotations + revocations, verifying each.
//!    Subject-type / subject-string mismatches drop silently — the
//!    Python parse_and_verify already enforces the same.
//! 3. Pinned key revoked → abort trust (return `None`).
//! 4. Walk forward from `pinned_spk`, hop-bounded
//!    ([`MAX_ROTATION_HOPS`]). Each hop:
//!    - Find the rotation whose `old_spk` == current head.
//!    - Two distinct `new_spk` from the same head → ambiguous fork,
//!      abort.
//!    - Sequence numbers must strictly increase.
//!    - The next-hop key must not be revoked.
//!    - Cycle detection: revisiting a key → abort.
//! 5. Stop when no rotation extends the head; return that head as
//!    the "current" key.
//!
//! Returning `None` is the conservative signal: "couldn't produce a
//! trustworthy current key; don't trust any message under this
//! subject until the user re-pins out-of-band."

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use dnsmesh_core::revocation::{RevocationRecord, RECORD_PREFIX as REVOCATION_PREFIX};
use dnsmesh_core::rotation::{
    rotation_rrset_name_user_identity, rotation_rrset_name_zone_anchored, RotationRecord,
    RECORD_PREFIX as ROTATION_PREFIX, SUBJECT_TYPE_USER_IDENTITY,
};
use dnsmesh_net::DnsRecordReader;

use crate::contacts::Contact;
use crate::error::ClientError;

/// Walk-bound mirroring the Python `max_hops=4` default. Large enough
/// for several years of routine rotation; small enough that a
/// pathologically long or attacker-constructed chain fails fast.
pub(crate) const MAX_ROTATION_HOPS: usize = 4;

/// Walk every pinned contact's rotation chain. Returns `Ok(true)` when
/// at least one chain ends at `sender_spk` — i.e. some contact rotated
/// from their pinned key to the key that signed this manifest. Used
/// on the receive verify-failure branch to decide whether an inbound
/// manifest should be accepted as if its key were pinned directly.
pub(crate) async fn rotation_manifest_accepted(
    reader: &Arc<dyn DnsRecordReader>,
    contacts: &[Contact],
    sender_spk: &[u8; 32],
) -> Result<bool, ClientError> {
    for contact in contacts {
        if contact.username.is_empty() || contact.domain.is_empty() {
            // Hash-form RRset names need both halves; same constraint
            // Python places.
            continue;
        }
        let subject = format!("{}@{}", contact.username, contact.domain);
        if let Some(head) = resolve_current_spk(
            reader,
            &contact.ed25519_spk,
            &subject,
            SUBJECT_TYPE_USER_IDENTITY,
        )
        .await?
        {
            if &head == sender_spk {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Cross-check whether `sender_spk` has a published revocation under
/// any pinned contact's rotation RRset. The receive path calls this
/// AFTER a pinned-key manifest verifies, to drop messages signed by
/// a pinned key the sender has since revoked. Without this, a
/// compromised-key holder could keep delivering to every recipient
/// who pinned the old key until the recipient re-pinned out-of-band.
pub(crate) async fn rotation_manifest_revoked(
    reader: &Arc<dyn DnsRecordReader>,
    contacts: &[Contact],
    sender_spk: &[u8; 32],
) -> Result<bool, ClientError> {
    for contact in contacts {
        if contact.username.is_empty() || contact.domain.is_empty() {
            continue;
        }
        let subject = format!("{}@{}", contact.username, contact.domain);
        if is_spk_revoked(reader, sender_spk, &subject, SUBJECT_TYPE_USER_IDENTITY).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Walk the chain from `pinned_spk` and return the head key, or
/// `None` if the chain can't be trusted (revoked anywhere on path,
/// ambiguous fork, seq regression, hop limit exceeded). Returning
/// `None` is a load-bearing trust signal — see module docs.
async fn resolve_current_spk(
    reader: &Arc<dyn DnsRecordReader>,
    pinned_spk: &[u8; 32],
    subject: &str,
    subject_type: u8,
) -> Result<Option<[u8; 32]>, ClientError> {
    let names = derive_rrset_names(subject, subject_type);
    if names.is_empty() {
        return Ok(None);
    }
    let records = fetch_records(reader, &names).await?;
    if records.is_empty() {
        return Ok(None);
    }
    let (rotations, revocations) = partition(&records, subject, subject_type);
    if revocations.iter().any(|r| &r.revoked_spk == pinned_spk) {
        return Ok(None);
    }
    let revoked_spks: HashSet<[u8; 32]> = revocations.iter().map(|r| r.revoked_spk).collect();
    let mut by_old: HashMap<[u8; 32], Vec<RotationRecord>> = HashMap::new();
    for rot in rotations {
        by_old.entry(rot.old_spk).or_default().push(rot);
    }

    let mut head = *pinned_spk;
    let mut visited: HashSet<[u8; 32]> = HashSet::new();
    visited.insert(head);
    let mut last_seq: Option<u64> = None;
    for hop in 0..MAX_ROTATION_HOPS {
        let candidates = match by_old.get(&head) {
            Some(c) if !c.is_empty() => c.clone(),
            _ => {
                // Hop 0 with no successor means the pinned key is
                // already the head and there's no chain to follow —
                // return None so the caller falls back to a direct
                // comparison against pinned_spk.
                return Ok(if hop == 0 { None } else { Some(head) });
            }
        };

        // Ambiguous-fork detection. Two rotations from the same head
        // with distinct new_spks is a hard fail regardless of seq —
        // higher-seq-wins would let an attacker race the legitimate
        // publisher with a later-numbered fork.
        let distinct_new: HashSet<[u8; 32]> = candidates.iter().map(|r| r.new_spk).collect();
        if distinct_new.len() > 1 {
            return Ok(None);
        }

        // Pick the lowest-seq candidate; same-seq duplicates with the
        // same new_spk are harmless (publisher reissue).
        let mut sorted = candidates;
        sorted.sort_by_key(|r| r.seq);
        let rot = &sorted[0];

        // Seq must strictly increase along the walk.
        if let Some(prev) = last_seq {
            if rot.seq <= prev {
                return Ok(None);
            }
        }
        last_seq = Some(rot.seq);

        let next_spk = rot.new_spk;
        if revoked_spks.contains(&next_spk) {
            return Ok(None);
        }
        if !visited.insert(next_spk) {
            // Cycle — should be impossible given monotonic seq, but
            // belt-and-braces against a publisher / attacker forcing
            // seq to bend.
            return Ok(None);
        }
        head = next_spk;
    }

    // Reached the hop bound. If head has no further successor we're
    // exactly at the tail and that's fine; otherwise a longer chain
    // exists and we refuse to follow it blindly.
    let candidates_after = by_old.get(&head).cloned().unwrap_or_default();
    Ok(if candidates_after.is_empty() {
        Some(head)
    } else {
        None
    })
}

/// Standalone variant of the revocation check (no rotation walk —
/// just "is there a verifying revocation targeting this spk?").
///
/// Uses [`fetch_records_strict`] rather than the fail-open
/// [`fetch_records`] so a malicious DNS provider that can selectively
/// fail one of the candidate RRset names cannot hide a revocation
/// that lives at the other name. Failing open here turned into a
/// pinned-key revocation bypass — an attacker holding a compromised
/// pinned key keeps delivering until the recipient re-pins out of
/// band, even though a legitimate revocation IS published. Failing
/// closed (any DNS error → propagate Err → receive.rs drops the
/// manifest) trades transient false-drops on flaky resolvers for the
/// security property the user opted into.
async fn is_spk_revoked(
    reader: &Arc<dyn DnsRecordReader>,
    candidate_spk: &[u8; 32],
    subject: &str,
    subject_type: u8,
) -> Result<bool, ClientError> {
    let names = derive_rrset_names(subject, subject_type);
    if names.is_empty() {
        return Ok(false);
    }
    let records = fetch_records_strict(reader, &names).await?;
    if records.is_empty() {
        return Ok(false);
    }
    let (_rotations, revocations) = partition(&records, subject, subject_type);
    Ok(revocations.iter().any(|r| &r.revoked_spk == candidate_spk))
}

fn derive_rrset_names(subject: &str, subject_type: u8) -> Vec<String> {
    if subject_type != SUBJECT_TYPE_USER_IDENTITY {
        // Cluster + bootstrap subjects aren't relevant for client
        // receive — they belong to the operator-key flow. Mirrors the
        // Python-side return-empty for those subject types.
        return Vec::new();
    }
    let Some(at) = subject.find('@') else {
        return Vec::new();
    };
    let user = subject[..at].trim();
    let host = subject[at + 1..].trim();
    if user.is_empty() || host.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    out.push(rotation_rrset_name_zone_anchored(host));
    let hash_form = rotation_rrset_name_user_identity(user, host);
    if !out.contains(&hash_form) {
        out.push(hash_form);
    }
    out
}

/// Fail-OPEN fetch: per-name DNS errors are swallowed and we return
/// whatever we got. Used by [`resolve_current_spk`] where the worst
/// case of a missed rotation record is "treat sender as un-pinned"
/// (i.e. fall back to the existing TOFU/intro-queue path) — same
/// failure mode as if rotation_chain_enabled was off.
async fn fetch_records(
    reader: &Arc<dyn DnsRecordReader>,
    names: &[String],
) -> Result<Vec<String>, ClientError> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for name in names {
        // A read error on one candidate name shouldn't poison the
        // entire walk — the second candidate may resolve fine.
        // Mirrors Python's swallow-and-continue at line 119. We
        // explicitly drop the `Ok(None) | Err(_)` arms — both mean
        // "no records here, try the next name."
        if let Ok(Some(records)) = reader.query_txt_record(name).await {
            for txt in records {
                if seen.insert(txt.clone()) {
                    out.push(txt);
                }
            }
        }
    }
    Ok(out)
}

/// Fail-CLOSED fetch: any per-name DNS error propagates as `Err`. Used
/// by [`is_spk_revoked`] so a malicious / partial DNS path that can
/// selectively fail the RRset carrying a valid revocation cannot hide
/// it. The receive.rs caller propagates the Err with `?` and the
/// in-flight manifest is dropped — a transient resolver failure
/// during a revocation check is a worse outcome than acting on a
/// stale "no revocation" answer.
async fn fetch_records_strict(
    reader: &Arc<dyn DnsRecordReader>,
    names: &[String],
) -> Result<Vec<String>, ClientError> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for name in names {
        // Errors propagate (the whole point of the strict variant).
        // `Ok(None)` is the normal "this name has no record" case and
        // we just skip to the next candidate.
        let result = reader.query_txt_record(name).await?;
        if let Some(records) = result {
            for txt in records {
                if seen.insert(txt.clone()) {
                    out.push(txt);
                }
            }
        }
    }
    Ok(out)
}

fn partition(
    records: &[String],
    subject: &str,
    subject_type: u8,
) -> (Vec<RotationRecord>, Vec<RevocationRecord>) {
    let mut rotations = Vec::new();
    let mut revocations = Vec::new();
    for txt in records {
        if txt.starts_with(ROTATION_PREFIX) {
            if let Some(rot) = RotationRecord::parse_and_verify(txt, None, Some(subject), None) {
                if rot.subject_type == subject_type {
                    rotations.push(rot);
                }
            }
        } else if txt.starts_with(REVOCATION_PREFIX) {
            if let Some(rev) =
                RevocationRecord::parse_and_verify(txt, None, Some(subject), None, None)
            {
                if rev.subject_type == subject_type {
                    revocations.push(rev);
                }
            }
        }
        // Anything else (slot manifests stomping on the rotate RRset
        // by accident, etc.) is silently ignored.
    }
    (rotations, revocations)
}

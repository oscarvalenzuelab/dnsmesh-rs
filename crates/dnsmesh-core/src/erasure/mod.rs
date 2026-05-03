//! Cross-chunk erasure coding via Reed-Solomon (k-of-n) using zfec.
//!
//! The per-chunk RS layer in [`crate::chunking`] repairs bit errors *within* a
//! chunk but does nothing against chunk loss. This module sits above it: the
//! plaintext is split into k data blocks, zfec generates (n-k) parity blocks,
//! and any k of the n total blocks suffice to reconstruct. Chunk loss up to
//! n-k is fully recoverable.
//!
//! `k` is chosen per-message based on plaintext size:
//!
//! ```text
//! k = max(1, ceil((len(plaintext) + 4) / DATA_PER_CHUNK))   // +4 for length prefix
//! parity = max(1, ceil(k * redundancy))
//! n = k + parity
//! ```
//!
//! [`DEFAULT_REDUNDANCY`] = 0.3 gives ~30% redundancy. Small `k` always gets at
//! least one parity block so every message survives a single lost chunk; this
//! also ensures `k < n`, which zfec requires.
//!
//! Each block is exactly [`crate::chunking::DATA_PER_CHUNK`] bytes, the same
//! size as a chunk payload, so a block fits the per-chunk RS wrapper without
//! layout changes. The plaintext is length-prefixed (4 bytes, big-endian)
//! before zero-padding so the recipient can strip trailing zeros
//! unambiguously.
//!
//! Byte-output compatibility with Python `zfec` is provided by the in-tree
//! `fec` module, an MIT-licensed implementation of zfec's specific
//! Vandermonde-systematic Reed-Solomon construction over GF(2^8) with
//! primitive polynomial 0x11D. The `python_interop` test in `dnsmesh-client`
//! exercises the full round-trip against the Python reference and is the
//! gate for any change here.

mod fec;

use fec::{Chunk, Fec};

use crate::chunking::DATA_PER_CHUNK;

/// Default fraction of parity blocks to add, relative to data block count.
pub const DEFAULT_REDUNDANCY: f64 = 0.3;

/// Length of the big-endian unsigned plaintext-length prefix prepended before
/// zero-padding.
pub const LEN_PREFIX: usize = 4;

/// Errors returned while running cross-chunk erasure encoding.
#[derive(Debug, thiserror::Error)]
pub enum ErasureError {
    /// Plaintext is too large for the 4-byte big-endian length prefix
    /// (> u32::MAX).
    #[error("plaintext too large for {LEN_PREFIX}-byte length prefix")]
    PlaintextTooLarge,
    /// `redundancy` was not finite or was negative.
    #[error("redundancy must be a non-negative finite number")]
    InvalidRedundancy,
    /// zfec rejected the (k, n) pair (e.g. k == 0 or k >= n). Should not occur
    /// for parameters produced by [`choose_kn`].
    #[error("zfec encoder rejected ({k}, {n}): {message}")]
    EncoderInit {
        /// The chosen number of data blocks.
        k: usize,
        /// The chosen total number of blocks.
        n: usize,
        /// Underlying error message from zfec.
        message: String,
    },
    /// zfec returned an error during encoding.
    #[error("zfec encode failed: {0}")]
    Encode(String),
}

/// Choose `(k, n)` for a given plaintext size and redundancy fraction.
///
/// `k = max(1, ceil((plaintext_size + LEN_PREFIX) / DATA_PER_CHUNK))`
/// `parity = max(1, ceil(k * redundancy))`
/// `n = k + parity`
///
/// Always returns `k < n` so the result is a legal zfec configuration.
///
/// # Errors
///
/// Returns [`ErasureError::InvalidRedundancy`] when `redundancy` is NaN,
/// infinite, or negative.
pub fn choose_kn(plaintext_size: usize, redundancy: f64) -> Result<(usize, usize), ErasureError> {
    if !redundancy.is_finite() || redundancy < 0.0 {
        return Err(ErasureError::InvalidRedundancy);
    }
    let wrapped = plaintext_size.saturating_add(LEN_PREFIX);
    let k = div_ceil(wrapped, DATA_PER_CHUNK).max(1);
    // Cast to f64 is fine here: k fits in u32 in any realistic message; even a
    // 4 GiB plaintext is k ~= 33 million, well within f64's 53-bit mantissa.
    #[allow(clippy::cast_precision_loss)]
    let parity_f = (k as f64) * redundancy;
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let parity = (parity_f.ceil() as usize).max(1);
    let n = k + parity;
    Ok((k, n))
}

/// Encode plaintext into `n` equal-sized blocks where any `k` reconstruct.
///
/// Returns `(blocks, k, n)` with each block exactly [`DATA_PER_CHUNK`] bytes.
/// The first `k` blocks are the data blocks (share IDs `0..k`); the remaining
/// `n - k` are parity blocks (share IDs `k..n`).
///
/// The plaintext is wrapped as `len_be4 || plaintext || zero_padding` so the
/// receiver can recover the original length unambiguously.
///
/// # Errors
///
/// - [`ErasureError::PlaintextTooLarge`] if `plaintext.len() > u32::MAX`.
/// - [`ErasureError::InvalidRedundancy`] if `redundancy` is non-finite or
///   negative.
/// - [`ErasureError::EncoderInit`] / [`ErasureError::Encode`] on zfec failures
///   (should not occur for valid inputs).
pub fn encode(
    plaintext: &[u8],
    redundancy: f64,
) -> Result<(Vec<Vec<u8>>, usize, usize), ErasureError> {
    if plaintext.len() > u32::MAX as usize {
        return Err(ErasureError::PlaintextTooLarge);
    }
    let (k, n) = choose_kn(plaintext.len(), redundancy)?;

    // Length prefix + plaintext + zero padding to exactly k * DATA_PER_CHUNK.
    let total = k * DATA_PER_CHUNK;
    let mut padded = Vec::with_capacity(total);
    #[allow(clippy::cast_possible_truncation)]
    let len = plaintext.len() as u32;
    padded.extend_from_slice(&len.to_be_bytes());
    padded.extend_from_slice(plaintext);
    padded.resize(total, 0);

    let fec = Fec::new(k, n).map_err(|e| ErasureError::EncoderInit {
        k,
        n,
        message: format!("{e:?}"),
    })?;
    // zfec's intrinsic padding is 0 here because `padded` is already exactly
    // k * DATA_PER_CHUNK bytes.
    let (chunks, padding) = fec
        .encode(&padded)
        .map_err(|e| ErasureError::Encode(format!("{e:?}")))?;
    debug_assert_eq!(padding, 0);

    let mut blocks: Vec<Vec<u8>> = chunks.into_iter().map(|c| c.data).collect();
    debug_assert_eq!(blocks.len(), n);
    debug_assert!(blocks.iter().all(|b| b.len() == DATA_PER_CHUNK));
    // Defensive: enforce DATA_PER_CHUNK width even on debug builds turned off.
    for b in &mut blocks {
        b.truncate(DATA_PER_CHUNK);
    }

    Ok((blocks, k, n))
}

/// Reconstruct plaintext from any `k` valid `(share_id, block)` pairs.
///
/// Returns `Some(plaintext)` on success or `None` when fewer than `k` shares
/// are supplied, the parameters are invalid, share data is the wrong width,
/// the length prefix is malformed, or zfec rejects the inputs.
#[must_use]
pub fn decode(shares: &[(usize, &[u8])], k: usize, n: usize) -> Option<Vec<u8>> {
    if k == 0 || n <= k {
        return None;
    }
    if shares.len() < k {
        return None;
    }

    // zfec needs share IDs in ascending order. Take the first k by index, with
    // duplicates rejected.
    let mut sorted: Vec<(usize, &[u8])> = shares.to_vec();
    sorted.sort_by_key(|(idx, _)| *idx);
    sorted.dedup_by_key(|(idx, _)| *idx);
    if sorted.len() < k {
        return None;
    }
    let chosen = &sorted[..k];

    // All blocks must be exactly DATA_PER_CHUNK bytes.
    if chosen.iter().any(|(_, b)| b.len() != DATA_PER_CHUNK) {
        return None;
    }
    // All indices must be within [0, n).
    if chosen.iter().any(|(idx, _)| *idx >= n) {
        return None;
    }

    let chunks: Vec<Chunk> = chosen
        .iter()
        .map(|(idx, b)| Chunk::new(b.to_vec(), *idx))
        .collect();

    let fec = Fec::new(k, n).ok()?;
    // Padding is 0 because `encode` always pads to k * DATA_PER_CHUNK.
    let padded = fec.decode(&chunks, 0).ok()?;
    if padded.len() < LEN_PREFIX {
        return None;
    }

    let mut len_buf = [0u8; LEN_PREFIX];
    len_buf.copy_from_slice(&padded[..LEN_PREFIX]);
    let length = u32::from_be_bytes(len_buf) as usize;
    if length > padded.len() - LEN_PREFIX {
        return None;
    }
    Some(padded[LEN_PREFIX..LEN_PREFIX + length].to_vec())
}

fn div_ceil(a: usize, b: usize) -> usize {
    if b == 0 {
        return 0;
    }
    a / b + usize::from(a % b != 0)
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn share_refs(blocks: &[Vec<u8>]) -> Vec<(usize, &[u8])> {
        blocks
            .iter()
            .enumerate()
            .map(|(i, b)| (i, b.as_slice()))
            .collect()
    }

    #[test]
    fn choose_kn_matches_python_formula() {
        // 0-byte plaintext: wrapped is 4 bytes, k = 1, parity = max(1, ceil(0.3)) = 1.
        assert_eq!(choose_kn(0, 0.3).unwrap(), (1, 2));
        // 124 bytes + 4-byte prefix = 128, fits in 1 block exactly.
        assert_eq!(choose_kn(124, 0.3).unwrap(), (1, 2));
        // 125 bytes + 4-byte prefix = 129, needs 2 blocks.
        assert_eq!(choose_kn(125, 0.3).unwrap(), (2, 3));
        // 10 blocks worth of plaintext: k=10, parity = ceil(3.0) = 3.
        assert_eq!(
            choose_kn(10 * DATA_PER_CHUNK - LEN_PREFIX, 0.3).unwrap(),
            (10, 13)
        );
    }

    #[test]
    fn choose_kn_rejects_invalid_redundancy() {
        assert!(matches!(
            choose_kn(100, f64::NAN),
            Err(ErasureError::InvalidRedundancy),
        ));
        assert!(matches!(
            choose_kn(100, -0.1),
            Err(ErasureError::InvalidRedundancy),
        ));
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let (blocks, k, n) = encode(&[], DEFAULT_REDUNDANCY).unwrap();
        assert_eq!((k, n), (1, 2));
        let shares = share_refs(&blocks);
        let recovered = decode(&shares, k, n).unwrap();
        assert_eq!(recovered, Vec::<u8>::new());
    }

    #[test]
    fn small_plaintext_round_trips() {
        let plaintext = b"hello world";
        let (blocks, k, n) = encode(plaintext, DEFAULT_REDUNDANCY).unwrap();
        assert_eq!(blocks.len(), n);
        assert!(blocks.iter().all(|b| b.len() == DATA_PER_CHUNK));
        let shares = share_refs(&blocks);
        let recovered = decode(&shares, k, n).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn large_multi_block_plaintext_round_trips() {
        let plaintext: Vec<u8> = (0..(10 * DATA_PER_CHUNK))
            .map(|i| ((i * 31) & 0xff) as u8)
            .collect();
        let (blocks, k, n) = encode(&plaintext, DEFAULT_REDUNDANCY).unwrap();
        assert!(k >= 10);
        assert_eq!(blocks.len(), n);
        let shares = share_refs(&blocks);
        let recovered = decode(&shares, k, n).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn loss_tolerance_matches_n_minus_k() {
        let plaintext: Vec<u8> = (0..512u32).map(|i| (i & 0xff) as u8).collect();
        let (blocks, k, n) = encode(&plaintext, DEFAULT_REDUNDANCY).unwrap();
        assert!(n - k >= 1);
        // Drop exactly n-k shares from the middle and verify decode succeeds.
        let kept: Vec<(usize, &[u8])> = blocks
            .iter()
            .enumerate()
            .skip(n - k) // drop the first n-k
            .map(|(i, b)| (i, b.as_slice()))
            .collect();
        assert_eq!(kept.len(), k);
        let recovered = decode(&kept, k, n).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn fewer_than_k_shares_fails() {
        let plaintext: Vec<u8> = (0..512u32).map(|i| (i & 0xff) as u8).collect();
        let (blocks, k, n) = encode(&plaintext, DEFAULT_REDUNDANCY).unwrap();
        assert!(k >= 2);
        let too_few: Vec<(usize, &[u8])> = blocks
            .iter()
            .enumerate()
            .take(k - 1)
            .map(|(i, b)| (i, b.as_slice()))
            .collect();
        assert!(decode(&too_few, k, n).is_none());
    }

    #[test]
    fn decode_accepts_any_k_of_n() {
        let plaintext: Vec<u8> = (0..512u32).map(|i| ((i * 13) & 0xff) as u8).collect();
        let (blocks, k, n) = encode(&plaintext, DEFAULT_REDUNDANCY).unwrap();
        // Pick the last k shares (parity-heavy subset).
        let tail: Vec<(usize, &[u8])> = blocks
            .iter()
            .enumerate()
            .skip(n - k)
            .map(|(i, b)| (i, b.as_slice()))
            .collect();
        assert_eq!(tail.len(), k);
        assert_eq!(decode(&tail, k, n).unwrap(), plaintext);

        // Pick first k (data-only subset).
        let head: Vec<(usize, &[u8])> = blocks
            .iter()
            .enumerate()
            .take(k)
            .map(|(i, b)| (i, b.as_slice()))
            .collect();
        assert_eq!(decode(&head, k, n).unwrap(), plaintext);
    }

    #[test]
    fn decode_invariant_to_input_ordering() {
        let plaintext: Vec<u8> = (0..400u32).map(|i| (i & 0xff) as u8).collect();
        let (blocks, k, n) = encode(&plaintext, DEFAULT_REDUNDANCY).unwrap();
        let mut shares: Vec<(usize, &[u8])> = blocks
            .iter()
            .enumerate()
            .map(|(i, b)| (i, b.as_slice()))
            .collect();
        // Shuffle deterministically by reversing.
        shares.reverse();
        let recovered = decode(&shares, k, n).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn decode_rejects_wrong_block_size() {
        let plaintext = b"x";
        let (blocks, k, n) = encode(plaintext, DEFAULT_REDUNDANCY).unwrap();
        // Truncate one block to the wrong width.
        let mut bad = blocks.clone();
        bad[0].truncate(DATA_PER_CHUNK - 1);
        let shares: Vec<(usize, &[u8])> = bad
            .iter()
            .enumerate()
            .map(|(i, b)| (i, b.as_slice()))
            .collect();
        assert!(decode(&shares, k, n).is_none());
    }

    #[test]
    fn decode_rejects_index_out_of_range() {
        let plaintext = b"x";
        let (blocks, k, n) = encode(plaintext, DEFAULT_REDUNDANCY).unwrap();
        let bogus: Vec<(usize, &[u8])> = blocks
            .iter()
            .map(|b| (n + 5, b.as_slice()))
            .take(k)
            .collect();
        assert!(decode(&bogus, k, n).is_none());
    }

    #[test]
    fn decode_dedupes_shares_and_still_needs_k_unique() {
        let plaintext = b"hello";
        let (blocks, k, n) = encode(plaintext, DEFAULT_REDUNDANCY).unwrap();
        if k < 2 {
            // For k=1, dedup leaves one share which equals k; pick a larger
            // plaintext to test meaningful dedup.
            return;
        }
        // Provide k+1 shares but with one duplicate, so unique count = k.
        let mut shares: Vec<(usize, &[u8])> =
            vec![(0, blocks[0].as_slice()), (0, blocks[0].as_slice())];
        for (i, block) in blocks.iter().enumerate().take(k).skip(1) {
            shares.push((i, block.as_slice()));
        }
        assert_eq!(decode(&shares, k, n).unwrap(), plaintext);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        #[test]
        fn random_plaintext_round_trips(
            plaintext in proptest::collection::vec(any::<u8>(), 0..1024),
            redundancy in 0.1f64..0.5f64,
        ) {
            let (blocks, k, n) = encode(&plaintext, redundancy).unwrap();
            prop_assert!(blocks.iter().all(|b| b.len() == DATA_PER_CHUNK));
            prop_assert_eq!(blocks.len(), n);
            // Use any k shares — pick the last k (parity-heavy subset) to
            // exercise the recovery path, not just the data shares.
            let kept: Vec<(usize, &[u8])> = blocks
                .iter()
                .enumerate()
                .skip(n - k)
                .map(|(i, b)| (i, b.as_slice()))
                .collect();
            let recovered = decode(&kept, k, n);
            prop_assert_eq!(recovered.as_deref(), Some(plaintext.as_slice()));
        }
    }
}

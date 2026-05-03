//! Per-chunk Reed-Solomon error correction for DMP message chunks.
//!
//! Each chunk is independently protected by Reed-Solomon parity bytes (RS BCH,
//! GF(256) with the conventional `x^8 + x^4 + x^3 + x^2 + 1` polynomial). This
//! provides bit-error correction *within* a chunk but does not protect against
//! whole-chunk loss; cross-chunk erasure coding lives in [`crate::erasure`].
//!
//! Wire layout per chunk:
//!
//! ```text
//! sha256(decoded_block)[:8] || RSCodec::encode(decoded_block)
//! ```
//!
//! With `MessageChunker::DATA_PER_CHUNK` = 128 and `MessageChunker::RS_SYMBOLS`
//! = 32, a fully-wrapped chunk is 8 + 128 + 32 = 168 bytes.
//!
//! The checksum covers the *decoded* block so the receiver can run RS decode
//! first (repairing any bit flips inside the encoded payload) and then validate
//! against the clean reference. Checksumming the RS-encoded body would reject
//! every corrupt chunk before RS had a chance to repair it.
//!
//! The Rust [`reed_solomon`] crate (mersinvald) is byte-compatible with Python's
//! `reedsolo`: both implement RS BCH over GF(256) with the same default
//! polynomial and the same parity-byte ordering. A 32-parity-byte encoding of
//! `bytes(0..128)` produces parity
//! `c1b13256c52283a89aaa18220186766121c15b5a1148ec9c8062880a13ab7f2d` in both
//! libraries, which is the wire-compat anchor for this module.

use reed_solomon::{Decoder, Encoder};
use sha2::{Digest, Sha256};

/// Raw payload bytes per chunk before RS + checksum overhead.
///
/// Sized so a wrapped chunk plus the `v=dmp1;t=chunk;d=<base64>` envelope fits
/// inside a single 255-byte DNS TXT string.
pub const DATA_PER_CHUNK: usize = 128;

/// Number of Reed-Solomon parity bytes appended per chunk. 32 parity bytes
/// corrects up to 16 byte errors per chunk.
pub const RS_SYMBOLS: usize = 32;

/// Truncation length of the per-chunk SHA-256 checksum.
pub const CHECKSUM_LEN: usize = 8;

/// Size of a wrapped chunk on the wire when ECC is enabled.
pub const WRAPPED_LEN: usize = CHECKSUM_LEN + DATA_PER_CHUNK + RS_SYMBOLS;

/// Errors returned while wrapping or unwrapping chunks.
#[derive(Debug, thiserror::Error)]
pub enum ChunkingError {
    /// `wrap_block` was given a slice whose length differed from
    /// [`DATA_PER_CHUNK`].
    #[error("block must be exactly {expected} bytes; got {actual}")]
    InvalidBlockLength {
        /// Expected block length in bytes.
        expected: usize,
        /// Length of the supplied block in bytes.
        actual: usize,
    },
}

/// Splits message blocks into DNS-compatible chunks with per-chunk Reed-Solomon
/// error correction.
///
/// Wire format produced by [`MessageChunker::wrap_block`]:
/// `sha256(block)[:8] || rs_encoded_payload`, where `rs_encoded_payload` is
/// `RSCodec::encode(block)` when ECC is enabled and just `block` otherwise.
#[derive(Debug, Clone, Copy)]
pub struct MessageChunker {
    /// When `true`, blocks are RS-encoded on wrap and RS-decoded on unwrap so
    /// bit errors can be repaired. When `false`, blocks pass through verbatim
    /// and only the SHA-256 checksum protects integrity.
    pub enable_error_correction: bool,
}

impl Default for MessageChunker {
    fn default() -> Self {
        Self {
            enable_error_correction: true,
        }
    }
}

impl MessageChunker {
    /// Construct a chunker with the given ECC setting.
    #[must_use]
    pub fn new(enable_error_correction: bool) -> Self {
        Self {
            enable_error_correction,
        }
    }

    /// Wrap exactly [`DATA_PER_CHUNK`] bytes into wire form.
    ///
    /// Output layout:
    ///
    /// ```text
    /// sha256(block)[:CHECKSUM_LEN] || RS_encode(block)
    /// ```
    ///
    /// When `enable_error_correction` is `false`, the RS step is skipped and
    /// the encoded payload equals `block` verbatim.
    ///
    /// # Errors
    ///
    /// Returns [`ChunkingError::InvalidBlockLength`] if `block` is not exactly
    /// [`DATA_PER_CHUNK`] bytes.
    pub fn wrap_block(&self, block: &[u8]) -> Result<Vec<u8>, ChunkingError> {
        if block.len() != DATA_PER_CHUNK {
            return Err(ChunkingError::InvalidBlockLength {
                expected: DATA_PER_CHUNK,
                actual: block.len(),
            });
        }

        let checksum = sha256_prefix(block);

        let payload_len = if self.enable_error_correction {
            DATA_PER_CHUNK + RS_SYMBOLS
        } else {
            DATA_PER_CHUNK
        };
        let mut out = Vec::with_capacity(CHECKSUM_LEN + payload_len);
        out.extend_from_slice(&checksum);

        if self.enable_error_correction {
            let rs = Encoder::new(RS_SYMBOLS);
            let codeword = rs.encode(block);
            // `codeword` derefs to `[u8]` of length DATA_PER_CHUNK + RS_SYMBOLS.
            out.extend_from_slice(&codeword[..]);
        } else {
            out.extend_from_slice(block);
        }

        Ok(out)
    }

    /// Inverse of [`wrap_block`]. Returns the decoded block on success or
    /// `None` on RS-uncorrectable corruption or checksum mismatch.
    ///
    /// Order of operations matches the Python implementation: RS decode runs
    /// **first** (so bit flips in the encoded payload get repaired), then the
    /// checksum is verified against the repaired bytes. Verifying the checksum
    /// against the RS-encoded body would reject every recoverable corruption.
    ///
    /// [`wrap_block`]: MessageChunker::wrap_block
    #[must_use]
    pub fn unwrap_block(&self, wire: &[u8]) -> Option<Vec<u8>> {
        if wire.len() <= CHECKSUM_LEN {
            return None;
        }
        let checksum = &wire[..CHECKSUM_LEN];
        let encoded = &wire[CHECKSUM_LEN..];

        let block: Vec<u8> = if self.enable_error_correction {
            let decoder = Decoder::new(RS_SYMBOLS);
            let recovered = decoder.correct(encoded, None).ok()?;
            recovered.data().to_vec()
        } else {
            encoded.to_vec()
        };

        if sha256_prefix(&block) != checksum {
            return None;
        }
        Some(block)
    }
}

fn sha256_prefix(data: &[u8]) -> [u8; CHECKSUM_LEN] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&digest[..CHECKSUM_LEN]);
    out
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    fn pattern_block() -> Vec<u8> {
        (0..DATA_PER_CHUNK).map(|i| i as u8).collect()
    }

    #[test]
    fn wrap_then_unwrap_round_trips() {
        let chunker = MessageChunker::new(true);
        let block = pattern_block();
        let wire = chunker.wrap_block(&block).unwrap();
        assert_eq!(wire.len(), WRAPPED_LEN);
        let recovered = chunker.unwrap_block(&wire).unwrap();
        assert_eq!(recovered, block);
    }

    #[test]
    fn wrap_then_unwrap_round_trips_without_ecc() {
        let chunker = MessageChunker::new(false);
        let block = pattern_block();
        let wire = chunker.wrap_block(&block).unwrap();
        assert_eq!(wire.len(), CHECKSUM_LEN + DATA_PER_CHUNK);
        let recovered = chunker.unwrap_block(&wire).unwrap();
        assert_eq!(recovered, block);
    }

    #[test]
    fn wire_layout_matches_python_reedsolo_vector() {
        // Anchor for byte-level wire compatibility with Python reedsolo.
        // Encoding bytes(0..128) with RSCodec(32) yields parity bytes
        // c1b13256c52283a8 9aaa182201867661 21c15b5a1148ec9c 8062880a13ab7f2d
        // and a SHA-256 prefix of e3b48bee... over the data block.
        let chunker = MessageChunker::new(true);
        let block = pattern_block();
        let wire = chunker.wrap_block(&block).unwrap();
        assert_eq!(
            hex::encode(&wire[CHECKSUM_LEN + DATA_PER_CHUNK..]),
            "c1b13256c52283a89aaa18220186766121c15b5a1148ec9c8062880a13ab7f2d",
            "RS parity must match Python reedsolo for the same input",
        );
        // Data section is unchanged before the parity bytes (systematic encoding).
        assert_eq!(
            &wire[CHECKSUM_LEN..CHECKSUM_LEN + DATA_PER_CHUNK],
            &block[..],
        );
    }

    #[test]
    fn corrupted_bytes_inside_correction_budget_repair() {
        let chunker = MessageChunker::new(true);
        let block = pattern_block();
        let mut wire = chunker.wrap_block(&block).unwrap();

        // RS_SYMBOLS = 32 parity bytes corrects up to RS_SYMBOLS / 2 = 16
        // byte errors. Flip a handful spread across the data section.
        for &i in &[10usize, 25, 40, 75, 100, 130, 150] {
            // Skip the checksum prefix; flip in the RS-protected region.
            let target = CHECKSUM_LEN + (i % (DATA_PER_CHUNK + RS_SYMBOLS));
            wire[target] ^= 0xa5;
        }

        let recovered = chunker.unwrap_block(&wire).unwrap();
        assert_eq!(recovered, block, "RS must repair flips within budget");
    }

    #[test]
    fn corruption_beyond_budget_returns_none() {
        let chunker = MessageChunker::new(true);
        let block = pattern_block();
        let mut wire = chunker.wrap_block(&block).unwrap();
        // Corrupt 17 bytes — one over the 16-byte correction budget.
        for i in 0..17 {
            wire[CHECKSUM_LEN + i] ^= 0xff;
        }
        assert!(chunker.unwrap_block(&wire).is_none());
    }

    #[test]
    fn checksum_mismatch_returns_none() {
        let chunker = MessageChunker::new(true);
        let block = pattern_block();
        let mut wire = chunker.wrap_block(&block).unwrap();
        // Flip a checksum byte; RS payload is intact but checksum verification
        // must reject it.
        wire[0] ^= 0x01;
        assert!(chunker.unwrap_block(&wire).is_none());
    }

    #[test]
    fn wrap_rejects_short_block() {
        let chunker = MessageChunker::new(true);
        let short = vec![0u8; DATA_PER_CHUNK - 1];
        let err = chunker.wrap_block(&short).unwrap_err();
        match err {
            ChunkingError::InvalidBlockLength { expected, actual } => {
                assert_eq!(expected, DATA_PER_CHUNK);
                assert_eq!(actual, DATA_PER_CHUNK - 1);
            }
        }
    }

    #[test]
    fn wrap_rejects_long_block() {
        let chunker = MessageChunker::new(true);
        let long = vec![0u8; DATA_PER_CHUNK + 1];
        assert!(matches!(
            chunker.wrap_block(&long),
            Err(ChunkingError::InvalidBlockLength { .. }),
        ));
    }

    #[test]
    fn unwrap_rejects_too_short_wire() {
        let chunker = MessageChunker::new(true);
        assert!(chunker.unwrap_block(&[]).is_none());
        assert!(chunker.unwrap_block(&[0u8; CHECKSUM_LEN]).is_none());
    }
}

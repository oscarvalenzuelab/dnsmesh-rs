//! Reed-Solomon erasure coding (k-of-m) over GF(2^8), byte-output
//! compatible with tahoe-lafs `zfec`. GF(2^8) with primitive polynomial
//! 0x11D, generator α = 2, Vandermonde encoder evaluated at distinct
//! points (0, 1, α, α², …) with the top k×k inverted to make it
//! systematic.
//!
//! References:
//! - L. Rizzo, "Effective Erasure Codes for Reliable Computer Communication
//!   Protocols" (1997).
//! - tahoe-lafs/zfec: <https://github.com/tahoe-lafs/zfec>.
//! - J. Plank, "A tutorial on Reed-Solomon coding for fault-tolerance in
//!   RAID-like systems" (1997).

// Allowed lints — math-style code follows Rizzo's variable names + matrix
// indexing idioms. Casts in field arithmetic are bounded by 256.
#![allow(
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::needless_range_loop,
    clippy::range_minus_one,
    clippy::unnecessary_wraps,
    clippy::assigning_clones,
    clippy::useless_conversion,
    clippy::explicit_into_iter_loop
)]

use std::sync::OnceLock;

/// Errors returned by the FEC encoder/decoder.
#[derive(Debug, thiserror::Error)]
pub enum FecError {
    /// `k` was zero.
    #[error("k must be > 0")]
    ZeroK,
    /// `m` was zero.
    #[error("m must be > 0")]
    ZeroM,
    /// `m` exceeded the GF(2^8) ceiling.
    #[error("m must be <= 256")]
    BigM,
    /// `k` >= `m`.
    #[error("k must be < m")]
    KGtM,
    /// Decoder received fewer than k unique shares.
    #[error("not enough chunks for decode: need {need}, got {got}")]
    NotEnoughChunks {
        /// The required number of shares (`k`).
        need: usize,
        /// The number of unique shares supplied.
        got: usize,
    },
    /// A share's index was out of `[0, m)`.
    #[error("share index {index} out of range [0, {m})")]
    IndexOutOfRange {
        /// The offending index.
        index: usize,
        /// The configured `m`.
        m: usize,
    },
    /// Shares had inconsistent block sizes.
    #[error("inconsistent share sizes: expected {expected}, got {got}")]
    InconsistentShareSize {
        /// The expected block size (taken from the first share).
        expected: usize,
        /// The size of the offending share.
        got: usize,
    },
}

/// One block of the encoded message — `data` is `chunk_size` bytes, `index`
/// is the share number in `[0, m)`. Indices `[0, k)` are the original data
/// chunks (zfec is systematic); indices `[k, m)` are parity.
#[derive(Debug, Clone)]
pub struct Chunk {
    /// The chunk payload.
    pub data: Vec<u8>,
    /// The chunk's share index in `[0, m)`.
    pub index: usize,
}

impl Chunk {
    /// Construct a chunk from raw bytes + share index.
    #[must_use]
    pub fn new(data: Vec<u8>, index: usize) -> Self {
        Self { data, index }
    }
}

/// Forward Error Correcting encoder/decoder.
///
/// `k` is the number of original data chunks. `m` is the total number of
/// chunks produced (k data + (m-k) parity). Any k of the m chunks suffice
/// to reconstruct the original.
pub struct Fec {
    k: usize,
    m: usize,
    /// Row-major (m × k) systematic encoder matrix. The first k rows are
    /// the identity; the bottom (m-k) rows are the parity generator.
    enc_matrix: Vec<u8>,
}

impl Fec {
    /// Build a FEC encoder/decoder for the given (k, m).
    ///
    /// # Errors
    ///
    /// Returns [`FecError::ZeroK`] / [`FecError::ZeroM`] / [`FecError::BigM`]
    /// / [`FecError::KGtM`] for invalid parameters. zfec's hard limit is
    /// `m <= 256` because GF(2^8) has 256 distinct field elements; you can't
    /// pick more than 256 distinct evaluation points.
    pub fn new(k: usize, m: usize) -> Result<Self, FecError> {
        if k == 0 {
            return Err(FecError::ZeroK);
        }
        if m == 0 {
            return Err(FecError::ZeroM);
        }
        if m > 256 {
            return Err(FecError::BigM);
        }
        if k >= m {
            return Err(FecError::KGtM);
        }

        // Build the m×k Vandermonde-derived matrix used as a working buffer.
        // The first row is the basis vector [1, 0, ..., 0] — equivalent to
        // evaluating at the field point 0 (since 0^0 = 1, 0^j = 0 for j > 0).
        // Subsequent rows r in 1..m are evaluated at α^(r-1):
        //   tmp[r][c] = α^((r-1) * c)
        // Distinct evaluation points (0, α^0, α^1, …, α^(m-2)) → invertible
        // top-k×k Vandermonde sub-matrix.
        let mut tmp = vec![0u8; m * k];
        let g = gf_tables();
        tmp[0] = 1;
        for col in 1..k {
            tmp[col] = 0;
        }
        for row in 0..(m - 1) {
            let p = &mut tmp[(row + 1) * k..(row + 2) * k];
            for col in 0..k {
                p[col] = g.exp[modnn((row * col) as i32) as usize];
            }
        }

        // Invert the top k×k of tmp (Vandermonde with distinct evaluation
        // points; always invertible) and multiply the bottom m-k rows by
        // the inverse. Result: the bottom m-k rows of the systematic encoder.
        invert_vandermonde(&mut tmp, k, g);

        let mut enc_matrix = vec![0u8; m * k];
        // Copy bottom m-k rows of tmp into bottom of enc_matrix multiplied
        // by the (now-inverted) top k×k.
        matmul(
            &tmp[k * k..], // (m-k) × k bottom of original (Vandermonde) matrix
            &tmp[..k * k], // k × k inverse
            &mut enc_matrix[k * k..],
            m - k,
            k,
            k,
            g,
        );
        // Top k rows of enc_matrix = identity (saves a matmul; zfec does
        // the same).
        for i in 0..k {
            enc_matrix[i * k + i] = 1;
        }

        Ok(Self { k, m, enc_matrix })
    }

    /// Encode `data` into `m` chunks, each `ceil(data.len() / k)` bytes.
    ///
    /// Returns the chunks plus the number of zero bytes appended at the end
    /// of the original data to make it divide evenly into k chunks. The
    /// caller passes the same `padding` count to [`Self::decode`] to recover
    /// the original length.
    ///
    /// # Errors
    ///
    /// Currently does not return an error; the `Result` type is preserved
    /// for forward compatibility with future preconditions.
    pub fn encode(&self, data: &[u8]) -> Result<(Vec<Chunk>, usize), FecError> {
        let chunk_size = chunk_size_for(data.len(), self.k);

        // Slice data into k chunks of exactly chunk_size bytes, zero-padding
        // the tail. `padding` is the number of zero bytes added.
        let mut chunks: Vec<Vec<u8>> = Vec::with_capacity(self.m);
        let mut padding = 0usize;
        for i in 0..self.k {
            let start = i * chunk_size;
            let end = start + chunk_size;
            if start >= data.len() {
                chunks.push(vec![0u8; chunk_size]);
                padding += chunk_size;
            } else if end > data.len() {
                let mut block = Vec::with_capacity(chunk_size);
                block.extend_from_slice(&data[start..]);
                let added = end - data.len();
                block.resize(chunk_size, 0);
                padding += added;
                chunks.push(block);
            } else {
                chunks.push(data[start..end].to_vec());
            }
        }

        // Compute the m-k parity chunks. parity[i][b] = sum_j enc_matrix[(k+i)*k + j] * data[j][b]
        let g = gf_tables();
        let mut parity: Vec<Vec<u8>> = vec![vec![0u8; chunk_size]; self.m - self.k];
        for (i, parity_chunk) in parity.iter_mut().enumerate() {
            let row_start = (self.k + i) * self.k;
            for j in 0..self.k {
                let coeff = self.enc_matrix[row_start + j];
                if coeff == 0 {
                    continue;
                }
                addmul(parity_chunk, &chunks[j], coeff, chunk_size, g);
            }
        }

        // Combine data + parity into the result.
        let mut out = Vec::with_capacity(self.m);
        for (i, data_chunk) in chunks.into_iter().enumerate() {
            out.push(Chunk {
                data: data_chunk,
                index: i,
            });
        }
        for (offset, parity_chunk) in parity.into_iter().enumerate() {
            out.push(Chunk {
                data: parity_chunk,
                index: self.k + offset,
            });
        }

        Ok((out, padding))
    }

    /// Reconstruct the original `data` from any `k` (or more) chunks.
    ///
    /// `padding` is the value returned by [`Self::encode`] for the original
    /// encode. It's stripped from the tail of the recovered output.
    ///
    /// # Errors
    ///
    /// - [`FecError::NotEnoughChunks`] when fewer than `k` unique chunks are supplied.
    /// - [`FecError::IndexOutOfRange`] / [`FecError::InconsistentShareSize`] for malformed inputs.
    pub fn decode(&self, encoded: &[Chunk], padding: usize) -> Result<Vec<u8>, FecError> {
        if encoded.len() < self.k {
            return Err(FecError::NotEnoughChunks {
                need: self.k,
                got: encoded.len(),
            });
        }

        // Validate share indices and uniform chunk size up-front.
        let chunk_size = encoded[0].data.len();
        for c in encoded {
            if c.index >= self.m {
                return Err(FecError::IndexOutOfRange {
                    index: c.index,
                    m: self.m,
                });
            }
            if c.data.len() != chunk_size {
                return Err(FecError::InconsistentShareSize {
                    expected: chunk_size,
                    got: c.data.len(),
                });
            }
        }

        // Build a working set of m chunk slots (only k will end up populated)
        // mirroring zfec's reorganize-share-numbers approach. share_nums[i]
        // says which actual share occupies slot i (after parity chunks are
        // shifted into missing data slots).
        let mut share_nums: Vec<Option<usize>> = vec![None; self.m];
        let mut chunks: Vec<Vec<u8>> = vec![Vec::new(); self.m];
        for c in encoded {
            // Skip duplicates: first occurrence wins.
            if share_nums[c.index].is_some() {
                continue;
            }
            share_nums[c.index] = Some(c.index);
            chunks[c.index] = c.data.clone();
        }

        // Identify missing data slots and fill them with available parity
        // shares in order. After this loop, every slot in 0..k is populated
        // (either by its own data chunk or by a parity chunk standing in).
        let mut missing: Vec<usize> = Vec::new();
        for (i, slot) in share_nums.iter().enumerate().take(self.k) {
            if slot.is_none() {
                missing.push(i);
            }
        }
        let mut missing_iter = missing.iter().copied();
        let mut replaced: Vec<usize> = Vec::new();
        for parity_idx in self.k..self.m {
            if !chunks[parity_idx].is_empty() {
                if let Some(missing_data_slot) = missing_iter.next() {
                    replaced.push(missing_data_slot);
                    share_nums[missing_data_slot] = Some(parity_idx);
                    chunks[missing_data_slot] = chunks[parity_idx].clone();
                } else {
                    break;
                }
            }
        }

        // If after reorganization any data slot is still empty, we didn't
        // have enough unique shares.
        let unique_share_count = share_nums
            .iter()
            .take(self.k)
            .filter(|s| s.is_some())
            .count();
        if unique_share_count < self.k {
            return Err(FecError::NotEnoughChunks {
                need: self.k,
                got: unique_share_count,
            });
        }

        // Fast path: all original data chunks were present, no recovery
        // needed.
        if replaced.is_empty() {
            let mut flat = Vec::with_capacity(self.k * chunk_size);
            for chunk in chunks.iter().take(self.k) {
                flat.extend_from_slice(chunk);
            }
            return Ok(strip_padding(flat, padding));
        }

        // Build the k×k decode matrix. For row i:
        //   - If share_nums[i] < k, the row is the i-th identity row
        //     (the data chunk at slot i is the actual data, no recovery).
        //   - Else (parity standing in for a missing data slot), the row is
        //     the parity's encoder coefficients.
        // Inverting this matrix gives the linear map from "what's in each
        // slot now" back to "the original data chunks."
        let g = gf_tables();
        let mut m_dec = vec![0u8; self.k * self.k];
        for i in 0..self.k {
            let p = &mut m_dec[i * self.k..(i + 1) * self.k];
            let actual = share_nums[i].expect("slot i must be populated");
            if actual < self.k {
                p[i] = 1;
            } else {
                let row_start = actual * self.k;
                p.copy_from_slice(&self.enc_matrix[row_start..row_start + self.k]);
            }
        }
        invert_matrix(&mut m_dec, self.k, g)?;

        // For each replaced (missing) data slot, recompute the original data
        // chunk by multiplying the inverse-decode-matrix row against the
        // current chunk values.
        let mut recovered: Vec<Vec<u8>> = vec![vec![0u8; chunk_size]; replaced.len()];
        for (out_idx, &missing_slot) in replaced.iter().enumerate() {
            let row_start = missing_slot * self.k;
            for col in 0..self.k {
                let coeff = m_dec[row_start + col];
                if coeff == 0 {
                    continue;
                }
                addmul(&mut recovered[out_idx], &chunks[col], coeff, chunk_size, g);
            }
        }
        for (idx, slot) in replaced.iter().zip(recovered.into_iter()) {
            chunks[*idx] = slot;
        }

        let mut flat = Vec::with_capacity(self.k * chunk_size);
        for chunk in chunks.iter().take(self.k) {
            flat.extend_from_slice(chunk);
        }
        Ok(strip_padding(flat, padding))
    }
}

/// `ceil(data_len / k)`, with `k > 0` enforced by [`Fec::new`].
fn chunk_size_for(data_len: usize, k: usize) -> usize {
    if data_len == 0 {
        // zfec-rs returns 0 here too; the empty-input case is degenerate but
        // round-trips through `encode` + `decode` cleanly because every
        // chunk is then 0 bytes long.
        return 0;
    }
    data_len.div_ceil(k)
}

fn strip_padding(mut v: Vec<u8>, padding: usize) -> Vec<u8> {
    if padding >= v.len() {
        v.clear();
    } else {
        v.truncate(v.len() - padding);
    }
    v
}

// ---------------------------------------------------------------------------
// GF(2^8) tables and arithmetic.
// ---------------------------------------------------------------------------

/// Primitive polynomial 0x11D in big-endian bit order, expressed as the
/// 9-character string `"101110001"` (same encoding zfec uses). Bit i (from
/// the left) is set if α^i is part of the polynomial. This particular
/// polynomial is x^8 + x^4 + x^3 + x^2 + 1 — the AES/Rijndael field
/// polynomial.
const PP: &[u8; 9] = b"101110001";

/// Process-wide GF(2^8) lookup tables. Computed once on first use.
struct GfTables {
    /// `exp[i]` = α^i in polynomial representation, for i in 0..255. The
    /// table is doubled to 510 entries so `exp[a + b]` for a, b < 255 never
    /// overflows the lookup (the same trick the Rizzo reference uses).
    exp: [u8; 510],
    /// `inverse[x]` = x^-1 in GF(2^8), with `inverse[0] = 0` (sentinel).
    inverse: [u8; 256],
    /// `mul[x][y]` = x * y in GF(2^8). 64 KiB on the heap, populated once
    /// for the process lifetime; faster than log+antilog per byte.
    mul: Box<[[u8; 256]; 256]>,
}

fn gf_tables() -> &'static GfTables {
    static TABLES: OnceLock<GfTables> = OnceLock::new();
    TABLES.get_or_init(build_gf_tables)
}

fn build_gf_tables() -> GfTables {
    let mut exp = [0u8; 510];
    let mut log = [0i32; 256];
    let mut inverse = [0u8; 256];

    // Seed exp[0..8] with bits 1, 2, 4, 8, 16, 32, 64, 128 — successive
    // powers of α evaluated as polynomials. Build exp[8] from PP.
    let mut mask: u8 = 1;
    exp[8] = 0;
    for i in 0..8 {
        exp[i] = mask;
        log[exp[i] as usize] = i as i32;
        if PP[i] == b'1' {
            exp[8] ^= mask;
        }
        mask <<= 1;
    }
    log[exp[8] as usize] = 8;

    // Recursively compute exp[9..255]. If the next power would set bit 8
    // (i.e. exp[i-1] has its top bit set), reduce by exp[8] (= α^8).
    let mask = 1u8 << 7;
    for i in 9..255 {
        exp[i] = if exp[i - 1] >= mask {
            exp[8] ^ ((exp[i - 1] ^ mask) << 1)
        } else {
            exp[i - 1] << 1
        };
        log[exp[i] as usize] = i as i32;
    }
    log[0] = 255; // sentinel; gf_log[0] is never legitimately read.

    // Double the exp table so multiplication's modular sum stays in range
    // without an explicit `% 255`.
    for i in 0..255 {
        exp[i + 255] = exp[i];
    }

    // Inverse table: x^-1 = α^(255 - log(x)) for x != 0.
    inverse[0] = 0;
    inverse[1] = 1;
    for i in 2..=255 {
        inverse[i] = exp[255 - log[i] as usize];
    }

    // Multiplication table. Zero is special-cased so the result doesn't
    // depend on the log[0] sentinel: any product with 0 is 0. Heap-boxed
    // because the 64 KiB table is larger than clippy's stack threshold.
    let mut mul: Box<[[u8; 256]; 256]> = vec![[0u8; 256]; 256]
        .into_boxed_slice()
        .try_into()
        .expect("256 rows of 256 u8s");
    for i in 0..256 {
        for j in 0..256 {
            mul[i][j] = if i == 0 || j == 0 {
                0
            } else {
                exp[modnn(log[i] + log[j]) as usize]
            };
        }
    }

    GfTables { exp, inverse, mul }
}

/// `x mod 255` via fold rather than division. Works because 256 ≡ 1
/// (mod 255), so high bits can be added to low bits.
fn modnn(mut x: i32) -> u8 {
    while x >= 255 {
        x -= 255;
        x = (x >> 8) + (x & 255);
    }
    x as u8
}

/// `dst[i] ^= mul[c][src[i]]` for i in 0..len. The hot inner loop of both
/// encode and decode. No-op when c == 0.
fn addmul(dst: &mut [u8], src: &[u8], c: u8, len: usize, g: &GfTables) {
    if c == 0 || src.is_empty() {
        return;
    }
    let mulc = &g.mul[c as usize];
    for i in 0..len {
        dst[i] ^= mulc[src[i] as usize];
    }
}

/// `c = a * b` where `a` is n×k, `b` is k×m, `c` is n×m, all stored
/// row-major. Standard triple-loop with GF multiply.
fn matmul(a: &[u8], b: &[u8], c: &mut [u8], n: usize, k: usize, m: usize, g: &GfTables) {
    for row in 0..n {
        for col in 0..m {
            let mut acc: u8 = 0;
            for i in 0..k {
                let pa = a[row * k + i];
                let pb = b[col + i * m];
                acc ^= g.mul[pa as usize][pb as usize];
            }
            c[row * m + col] = acc;
        }
    }
}

/// In-place inverse of the top k×k of a Vandermonde matrix. `src` is k rows
/// long, each row k bytes; the second column of each row provides the
/// evaluation points p_0, p_1, ..., p_{k-1} (in our usage, p_0 = 0 and
/// p_i = α^(i-1) for i >= 1).
///
/// Implementation lifted from the Numerical Recipes / Rizzo construction:
/// build the polynomial P(x) = ∏_i (x - p_i), then for each row use
/// synthetic division to derive that row of the inverse.
fn invert_vandermonde(src: &mut [u8], k: usize, g: &GfTables) {
    if k == 1 {
        // Degenerate case: 1×1 Vandermonde with sole entry α^0 = 1.
        return;
    }
    let mut b = vec![0u8; k];
    let mut c = vec![0u8; k];
    let mut p = vec![0u8; k];

    // Pull the evaluation points (the second column of each row).
    let mut j = 1;
    for i in 0..k {
        c[i] = 0;
        p[i] = src[j];
        j += k;
    }

    // Build P(x) = ∏_i (x - p_i) recursively. After step i, c holds the
    // coefficients of P_i = (x - p_0)(x - p_1)...(x - p_i). In GF(2^m),
    // subtraction is XOR, so (x - p_i) == (x + p_i) and the recurrence
    // reduces to XORing p_i into c[k-1].
    c[k - 1] = p[0];
    for i in 1..k {
        let p_i = p[i];
        for jj in (k - 1 - (i - 1))..(k - 1) {
            c[jj] ^= g.mul[p_i as usize][c[jj + 1] as usize];
        }
        c[k - 1] ^= p_i;
    }

    // For each row of the inverse, use synthetic division by (x - p_row)
    // to derive its coefficients.
    for row in 0..k {
        let xx = p[row];
        let mut t: u8 = 1;
        b[k - 1] = 1;
        for i in (1..=(k - 1)).rev() {
            b[i - 1] = c[i] ^ g.mul[xx as usize][b[i] as usize];
            t = g.mul[xx as usize][t as usize] ^ b[i - 1];
        }
        let t_inv = g.inverse[t as usize];
        for col in 0..k {
            src[col * k + row] = g.mul[t_inv as usize][b[col] as usize];
        }
    }
}

/// In-place Gauss-Jordan inversion of a k×k matrix over GF(2^8). Returns
/// `Err(FecError::NotEnoughChunks)` when the matrix is singular (which can
/// happen if the caller supplied k chunks that don't span the data space —
/// e.g. duplicates pretending to be distinct).
fn invert_matrix(src: &mut [u8], k: usize, g: &GfTables) -> Result<(), FecError> {
    let mut indxc = vec![0usize; k];
    let mut indxr = vec![0usize; k];
    let mut ipiv = vec![0u8; k];

    for col in 0..k {
        let mut irow = 0usize;
        let mut icol = 0usize;
        let mut piv_found = false;

        // Try the diagonal first; if it's already non-zero and untaken, use
        // it. Otherwise scan for any usable pivot.
        if ipiv[col] != 1 && src[col * k + col] != 0 {
            irow = col;
            icol = col;
            piv_found = true;
        }
        if !piv_found {
            'outer: for row in 0..k {
                if ipiv[row] == 1 {
                    continue;
                }
                for ix in 0..k {
                    if ipiv[ix] == 0 && src[row * k + ix] != 0 {
                        irow = row;
                        icol = ix;
                        piv_found = true;
                        break 'outer;
                    }
                }
            }
        }
        if !piv_found {
            // Singular matrix → caller's k shares are linearly dependent.
            return Err(FecError::NotEnoughChunks { need: k, got: 0 });
        }
        ipiv[icol] += 1;

        // Swap rows so the pivot lands on the diagonal of column `icol`.
        if irow != icol {
            for ix in 0..k {
                src.swap(irow * k + ix, icol * k + ix);
            }
        }
        indxr[col] = irow;
        indxc[col] = icol;

        // Normalize the pivot row by 1/pivot, then eliminate the column
        // from every other row.
        let pivot_val = src[icol * k + icol];
        debug_assert!(pivot_val != 0);
        if pivot_val != 1 {
            let inv = g.inverse[pivot_val as usize];
            src[icol * k + icol] = 1;
            for ix in 0..k {
                let v = src[icol * k + ix];
                src[icol * k + ix] = g.mul[inv as usize][v as usize];
            }
        }

        // Eliminate column icol from all other rows. The trick that makes
        // this in-place inversion work (vs. the textbook augmented-matrix
        // approach) is that we DON'T skip jj == icol in the XOR. We zero
        // p[icol] first, then XOR in c * pivot_row, which puts c *
        // pivot_row[icol] == c / pivot_val at p[icol]. Across all pivots
        // that ends up storing the inverse coefficients in src, in place,
        // instead of an identity matrix.
        let mut pivot_row = vec![0u8; k];
        pivot_row.copy_from_slice(&src[icol * k..icol * k + k]);

        for ix in 0..k {
            if ix == icol {
                continue;
            }
            let c = src[ix * k + icol];
            if c == 0 {
                continue;
            }
            src[ix * k + icol] = 0;
            let row_start = ix * k;
            for jj in 0..k {
                src[row_start + jj] ^= g.mul[c as usize][pivot_row[jj] as usize];
            }
        }
    }

    // Final column-swap pass to undo the row permutations applied during
    // pivot selection (Numerical Recipes step).
    for col in (0..k).rev() {
        if indxr[col] != indxc[col] {
            for row in 0..k {
                src.swap(row * k + indxr[col], row * k + indxc[col]);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hardcoded test vector lifted from zfec-rs's own test suite. If our
    /// encode produces these exact bytes, byte-output compatibility with
    /// zfec is proven for this (k, m, input).
    #[test]
    fn matches_zfec_known_vector_5_8() {
        let fec = Fec::new(5, 8).unwrap();
        let (chunks, _padding) = fec.encode(b"some_ssidthe_password").unwrap();
        let mut concat = Vec::new();
        for c in chunks {
            concat.extend(c.data);
        }
        // The exact byte string the original tahoe-lafs C zfec produces for
        // this input at k=5, m=8 (and which zfec-rs reproduces).
        let expected: &[u8] =
            b"some_ssidthe_password\x00\x00\x00\x00]\xd8\x94\xea\x91\x1bGU\xff+\x882[\xa6\xd3";
        assert_eq!(concat, expected);
    }

    #[test]
    fn round_trip_complete() {
        // No chunks dropped; decode hits the all-data fast path.
        let fec = Fec::new(5, 8).unwrap();
        let data = b"hello world from the dnsmesh fec module".to_vec();
        let (chunks, padding) = fec.encode(&data).unwrap();
        let recovered = fec.decode(&chunks, padding).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn round_trip_with_each_block_missing() {
        // Drop one block at a time across every (k, m) up to a small bound;
        // matches zfec-rs's `decoder_extensive` test in spirit.
        let data = b"some_ssidthe_password";
        for m in 2..12 {
            for k in 1..m {
                let fec = Fec::new(k, m).unwrap();
                let (chunks, padding) = fec.encode(data).unwrap();
                for drop_idx in 0..m {
                    let mut subset = chunks.clone();
                    subset.remove(drop_idx);
                    let decoded = fec
                        .decode(&subset, padding)
                        .unwrap_or_else(|e| panic!("k={k} m={m} drop={drop_idx}: {e}"));
                    assert_eq!(decoded, data, "k={k} m={m} drop={drop_idx}");
                }
            }
        }
    }

    #[test]
    fn round_trip_max_loss() {
        // Drop exactly m-k blocks (maximum tolerable loss) and confirm
        // decode still works.
        let data = (0..200u16).map(|i| (i & 0xff) as u8).collect::<Vec<_>>();
        for (k, m) in [(3, 5), (5, 8), (7, 12), (10, 15)] {
            let fec = Fec::new(k, m).unwrap();
            let (chunks, padding) = fec.encode(&data).unwrap();
            // Drop the FIRST m-k chunks (always data chunks since chunks[0..k] are data).
            let kept = chunks[(m - k)..].to_vec();
            assert_eq!(kept.len(), k);
            let decoded = fec.decode(&kept, padding).unwrap();
            assert_eq!(decoded, data);
        }
    }

    #[test]
    fn fewer_than_k_shares_errors() {
        let fec = Fec::new(5, 8).unwrap();
        let (chunks, padding) = fec.encode(b"x").unwrap();
        let too_few = chunks[..4].to_vec();
        assert!(matches!(
            fec.decode(&too_few, padding),
            Err(FecError::NotEnoughChunks { .. })
        ));
    }

    #[test]
    fn rejects_out_of_range_index() {
        let fec = Fec::new(2, 4).unwrap();
        let (mut chunks, padding) = fec.encode(b"yo").unwrap();
        chunks[0].index = 99;
        assert!(matches!(
            fec.decode(&chunks, padding),
            Err(FecError::IndexOutOfRange { .. })
        ));
    }

    #[test]
    fn rejects_inconsistent_share_size() {
        let fec = Fec::new(2, 4).unwrap();
        let (mut chunks, padding) = fec.encode(b"abcd").unwrap();
        chunks[0].data.push(0); // off by one
        assert!(matches!(
            fec.decode(&chunks, padding),
            Err(FecError::InconsistentShareSize { .. })
        ));
    }

    #[test]
    fn rejects_invalid_params() {
        assert!(matches!(Fec::new(0, 5), Err(FecError::ZeroK)));
        assert!(matches!(Fec::new(5, 0), Err(FecError::ZeroM)));
        assert!(matches!(Fec::new(5, 5), Err(FecError::KGtM)));
        assert!(matches!(Fec::new(5, 4), Err(FecError::KGtM)));
        assert!(matches!(Fec::new(5, 257), Err(FecError::BigM)));
    }

    #[test]
    fn duplicates_in_decode_input_are_ignored() {
        let fec = Fec::new(3, 5).unwrap();
        let (chunks, padding) = fec.encode(b"hello").unwrap();
        // Pass the first chunk twice plus the next two — unique count = 3 = k.
        let with_dup = vec![
            chunks[0].clone(),
            chunks[0].clone(),
            chunks[1].clone(),
            chunks[2].clone(),
        ];
        let decoded = fec.decode(&with_dup, padding).unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn k_equals_one_degenerate_case() {
        // k=1, m=2: one data chunk + one parity chunk that's a copy of it.
        let fec = Fec::new(1, 2).unwrap();
        let (chunks, padding) = fec.encode(b"single").unwrap();
        assert_eq!(chunks.len(), 2);
        // With k=1, both chunks should equal the data (parity row is just
        // [1] in this case).
        assert_eq!(chunks[0].data, chunks[1].data);
        // Decode from just the parity chunk.
        let just_parity = vec![chunks[1].clone()];
        let decoded = fec.decode(&just_parity, padding).unwrap();
        assert_eq!(decoded, b"single");
    }

    #[test]
    fn modnn_matches_naive_modulo() {
        for x in 0..1024 {
            let naive = (x % 255) as u8;
            assert_eq!(modnn(x), naive, "x={x}");
        }
    }

    #[test]
    fn gf_tables_are_self_consistent() {
        let g = gf_tables();
        // exp/log inverse property: exp[log[x]] == x for x != 0.
        for x in 1u32..=255 {
            // log table is private; use the identity exp[i+255] == exp[i].
            // We verify by checking that for every x there exists some i
            // with exp[i] == x.
            let mut found = false;
            for i in 0..255 {
                if g.exp[i] as u32 == x {
                    found = true;
                    break;
                }
            }
            assert!(found, "no log entry for x={x}");
        }
        // inverse property: x * inverse[x] == 1 for x != 0.
        for x in 1u32..=255 {
            let inv = g.inverse[x as usize];
            assert_eq!(g.mul[x as usize][inv as usize], 1, "x={x} inv={inv}");
        }
        // Multiplication zero property.
        for x in 0..256 {
            assert_eq!(g.mul[0][x], 0);
            assert_eq!(g.mul[x][0], 0);
        }
        // Multiplication identity.
        for x in 0..256 {
            assert_eq!(g.mul[1][x] as usize, x);
            assert_eq!(g.mul[x][1] as usize, x);
        }
    }
}

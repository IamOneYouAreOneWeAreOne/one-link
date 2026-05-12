//! Cross-platform determinism vectors for `ol_fec`.
//!
//! The Reed-Solomon parity bytes for a fixed `(plaintext, k, m)` MUST
//! be byte-identical across x86_64 / aarch64 / RISC-V — peers
//! interoperate by comparing bytes, not by re-deriving parity from
//! local state. Both the scalar path AND the SSSE3 SIMD path MUST
//! produce identical bytes (the SIMD-matches-scalar property test in
//! `gf256.rs` covers this exhaustively).
//!
//! This file pins the parity output for a specific RS(10, 4) encode of
//! 10×64-byte data shards. A platform that diverges fails this test
//! loudly.

use ol_fec::Codec;

fn hex_encode_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

/// Deterministic 64-byte data shard for index `i`. The byte pattern is
/// `(i + j) as u8` for `j in 0..64`, with a final 0xCD marker so any
/// off-by-one in indexing is immediately visible.
fn data_shard(i: u8) -> Vec<u8> {
    let mut out = vec![0u8; 64];
    for j in 0..63 {
        out[j] = i.wrapping_add(j as u8);
    }
    out[63] = 0xCD;
    out
}

#[test]
fn cross_platform_rs_10_4_parity_pinned() {
    let codec = Codec::new(10, 4).unwrap();
    let data: Vec<Vec<u8>> = (0u8..10).map(data_shard).collect();
    let data_refs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
    let parity = codec.encode(&data_refs).unwrap();

    assert_eq!(parity.len(), 4);
    for p in &parity {
        assert_eq!(p.len(), 64);
    }

    // Pin each of the 4 parity shards by hex. Any divergence in the
    // GF(2^8) operations, Cauchy matrix construction, or SIMD path
    // failure mode immediately surfaces here.
    let p_hex: [String; 4] = [
        hex_encode_lower(&parity[0]),
        hex_encode_lower(&parity[1]),
        hex_encode_lower(&parity[2]),
        hex_encode_lower(&parity[3]),
    ];

    let expected = pinned_parity_hex();
    let mut diverged = Vec::new();
    for i in 0..4 {
        if p_hex[i] != expected[i] {
            diverged.push((i, p_hex[i].clone(), expected[i]));
        }
    }
    if !diverged.is_empty() {
        // Print all four so the new vector is easy to copy in.
        eprintln!("=== ol_fec determinism: divergence detected ===");
        for (i, actual, expected) in &diverged {
            eprintln!("shard {i}: ACTUAL   = {actual}");
            eprintln!("           EXPECTED = {expected}");
        }
        eprintln!("=== current platform's parity (paste into PINNED_P{{0..3}}): ===");
        for (i, hex) in p_hex.iter().enumerate() {
            eprintln!("PINNED_P{i} = \"{hex}\"");
        }
        panic!(
            "ol_fec parity diverged from the pinned vector ({} shards). \
             If you changed the GF(2^8) primitives or Cauchy matrix \
             construction, update the test vector AND bump the \
             wire-format version per ADR-0016.",
            diverged.len()
        );
    }
}

/// Pinned parity bytes for the RS(10, 4) encode of the 10 data shards
/// produced by [`data_shard`].
///
/// Recompute via:
/// ```ignore
/// for p in &parity { println!("{}", hex_encode_lower(p)); }
/// ```
fn pinned_parity_hex() -> [&'static str; 4] {
    PINNED_PARITY_HEX
}

const PINNED_PARITY_HEX: [&str; 4] = [PINNED_P0, PINNED_P1, PINNED_P2, PINNED_P3];

// Pinned on Windows x86_64 with SSSE3 path (also verified equal to the
// scalar path by `simd_matches_scalar_across_all_coefficients_and_sizes`).
// Linux/macOS arm64 builds must produce the same bytes or this test fails.
const PINNED_P0: &str =
    "8ab54d3e3c040a497dd0dd6aba1e121c86b94132300806ac881ae6c2ad2a225f92ad5526241c125165c8c572a2060a049ea1592a28101e7d7995908983424213";
const PINNED_P1: &str =
    "cc340b097a744c783b369b4bfcf054cec038070576784064ce32a0cfebe364a9d42c1311626c5460232e8353e4e84cd6d8201f1d6e60585c3f3ad6dcc5c50413";
const PINNED_P2: &str =
    "f1feaa7011264864f54ebcfa996ad63f5f5004debf88e664fd3590f592f2f127b6b9ed3756610f23b209fbbdde2d917818174399f8cfa164edc3c8eb84d9bfdc";
const PINNED_P3: &str =
    "55010e6fb5dbec7d51a3187b3d817212fbafa0c11b7542db59fc3453363555c412464928f29cab3a16e45f3c7ac63555bce8e7865c32058c49426c0320461bdc";

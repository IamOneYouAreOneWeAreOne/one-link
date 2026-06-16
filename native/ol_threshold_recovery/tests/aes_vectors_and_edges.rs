//! Cross-validation against canonical AES test vectors + exhaustive
//! edge cases. Catches any drift in gf_mul / gf_inv / share format.

use ol_threshold_recovery::gf256::{gf_inv, gf_mul, gf_pow};
use ol_threshold_recovery::prng::PrngState;
use ol_threshold_recovery::shamir::{
    max_participants, reconstruct_byte, reconstruct_bytes, share_byte, share_bytes, Share,
};

// ── AES test vectors (FIPS 197 GF(2^8) multiplication) ────────────

#[test]
fn aes_mul_classic_vectors() {
    // FIPS 197 §4.2.1 — classic AES MixColumns test vector chain.
    // 0x53 * 0xCA = 0x01 (canonical inverse pair in AES GF(2^8)).
    assert_eq!(gf_mul(0x53, 0xCA), 0x01);
    // 0x57 * 0x83 = 0xC1 (AES standard test pair).
    assert_eq!(gf_mul(0x57, 0x83), 0xC1);
    // 0xD4 * 0x02 = 0xB3 (xtime equivalent).
    assert_eq!(gf_mul(0xD4, 0x02), 0xB3);
    // 0xBF * 0x03 = 0xDA (xtime + add).
    assert_eq!(gf_mul(0xBF, 0x03), 0xDA);
}

#[test]
fn aes_inverse_classic_pair() {
    // 0x53 and 0xCA are multiplicative inverses in AES GF(2^8).
    assert_eq!(gf_inv(0x53), 0xCA);
    assert_eq!(gf_inv(0xCA), 0x53);
}

#[test]
fn aes_xtime_consistency() {
    // xtime(x) in AES is x * 0x02. Walk a small chain:
    // xtime(0x57) = 0xAE; xtime(0xAE) = 0x47 (since high bit set, XOR 0x1B).
    assert_eq!(gf_mul(0x57, 0x02), 0xAE);
    assert_eq!(gf_mul(0xAE, 0x02), 0x47);
    // xtime(0x47) = 0x8E (no reduction needed).
    assert_eq!(gf_mul(0x47, 0x02), 0x8E);
    // xtime(0x8E) = 0x07 (high bit set; 0x11C ^ 0x11B = 0x07).
    assert_eq!(gf_mul(0x8E, 0x02), 0x07);
}

#[test]
fn inverse_canonical_pairs() {
    // Spot-check well-known canonical AES inverse pairs.
    // 0x53 ↔ 0xCA is the textbook AES S-box example pair.
    // 0x01 is the self-inverse (1 * 1 = 1 in any field).
    let canonical = [(0x01u32, 0x01u32), (0x53, 0xCA), (0xCA, 0x53)];
    for (a, expected) in canonical {
        assert_eq!(gf_inv(a), expected, "gf_inv(0x{a:02X})");
    }
}

#[test]
fn inverse_property_all_nonzero() {
    // Exhaustive: a * a^-1 == 1 for every nonzero a. This is the
    // canonical correctness check — passing it means the inverse
    // table is fully consistent regardless of which specific
    // textbook table values we trust.
    for a in 1u32..256 {
        let inv = gf_inv(a);
        assert_eq!(gf_mul(a, inv), 1, "a=0x{a:02X} inv=0x{inv:02X}");
        // Inverse is its own inverse.
        assert_eq!(gf_inv(inv), a, "double-inv mismatch for a=0x{a:02X}");
    }
}

#[test]
fn pow_matches_repeated_mul() {
    // gf_pow(a, e) == a * a * ... e times. Spot-check.
    for a in [0x02u32, 0x57, 0xA5] {
        let mut expected = 1u32;
        for e in 0..32u32 {
            assert_eq!(gf_pow(a, e), expected, "a=0x{a:02X} e={e}");
            expected = gf_mul(expected, a);
        }
    }
}

// ── Shamir edge cases ─────────────────────────────────────────────

#[test]
fn all_zero_secret_roundtrips() {
    // Critical: a secret of all zeros must split + reconstruct
    // correctly. (Catches off-by-one cases that might accidentally
    // emit non-zero shares for a zero secret.)
    let zero = vec![0u8; 64];
    let mut st = PrngState::new(0xDEAD_BEEF);
    let streams = share_bytes(&zero, 3, 5, &mut st).unwrap();
    let xs = vec![1u8, 2, 3];
    let refs: Vec<&[u8]> = streams[..3].iter().map(Vec::as_slice).collect();
    let recovered = reconstruct_bytes(&xs, &refs, 3).unwrap();
    assert_eq!(recovered, zero);
}

#[test]
fn all_ff_secret_roundtrips() {
    let ff = vec![0xFFu8; 64];
    let mut st = PrngState::new(0xCAFE_BABE);
    let streams = share_bytes(&ff, 3, 5, &mut st).unwrap();
    let xs = vec![1u8, 2, 3];
    let refs: Vec<&[u8]> = streams[..3].iter().map(Vec::as_slice).collect();
    let recovered = reconstruct_bytes(&xs, &refs, 3).unwrap();
    assert_eq!(recovered, ff);
}

#[test]
fn alternating_secret_roundtrips() {
    let secret: Vec<u8> = (0..64u8)
        .map(|i| if i % 2 == 0 { 0xAA } else { 0x55 })
        .collect();
    let mut st = PrngState::new(0x1234_5678);
    let streams = share_bytes(&secret, 4, 7, &mut st).unwrap();
    let xs = vec![1u8, 3, 5, 7];
    let refs: Vec<&[u8]> = [&streams[0], &streams[2], &streams[4], &streams[6]]
        .iter()
        .map(|v| v.as_slice())
        .collect();
    let recovered = reconstruct_bytes(&xs, &refs, 4).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn single_byte_secret() {
    for &b in &[0x00u8, 0x01, 0x42, 0x7F, 0x80, 0xFF] {
        let mut st = PrngState::new(u64::from(b) * 31);
        let streams = share_bytes(&[b], 2, 3, &mut st).unwrap();
        let xs = vec![1u8, 2];
        let refs: Vec<&[u8]> = [&streams[0], &streams[1]]
            .iter()
            .map(|v| v.as_slice())
            .collect();
        let recovered = reconstruct_bytes(&xs, &refs, 2).unwrap();
        assert_eq!(recovered, &[b]);
    }
}

#[test]
fn n_equals_max_participants_255() {
    // The GF(2^8) ceiling. Maximum the scheme supports.
    let n: u32 = max_participants();
    let k: u32 = 100;
    let mut st = PrngState::new(0xABCD_EF01_2345_6789);
    let secret = b"max-participants stress test";
    let streams = share_bytes(secret, k, n, &mut st).unwrap();
    assert_eq!(streams.len(), n as usize);
    // Pick K random-ish shares and reconstruct.
    let xs: Vec<u8> = (1..=k as u8).collect();
    let refs: Vec<&[u8]> = streams[..k as usize].iter().map(Vec::as_slice).collect();
    let recovered = reconstruct_bytes(&xs, &refs, k).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn k_equals_n_requires_all_shares() {
    // K = N: any single missing share makes recovery impossible
    // (mathematically: not enough points to interpolate degree-(K-1)
    // polynomial). Reconstruction with fewer than K returns the
    // not-enough-shares error.
    let mut st = PrngState::new(0xDEAD_BEEF);
    let shares = share_byte(0x42, 3, 3, &mut st).unwrap();
    assert_eq!(reconstruct_byte(&shares, 3).unwrap(), 0x42);
    // Only 2 shares: error.
    let sub = vec![shares[0], shares[1]];
    let err = reconstruct_byte(&sub, 3).unwrap_err();
    assert!(matches!(
        err,
        ol_threshold_recovery::shamir::ShareError::NotEnoughShares { .. }
    ));
}

#[test]
fn empty_secret_handled() {
    let mut st = PrngState::new(0);
    let streams = share_bytes(&[], 2, 3, &mut st).unwrap();
    assert_eq!(streams.len(), 3);
    for s in &streams {
        assert!(s.is_empty());
    }
    let xs = vec![1u8, 2];
    let refs: Vec<&[u8]> = [&streams[0], &streams[1]]
        .iter()
        .map(|v| v.as_slice())
        .collect();
    let recovered = reconstruct_bytes(&xs, &refs, 2).unwrap();
    assert!(recovered.is_empty());
}

#[test]
fn share_x_values_sequential_1_to_n() {
    // The scheme assigns x = 1, 2, ..., n to shares. Pin this so any
    // refactor that breaks the contract is caught.
    let mut st = PrngState::new(0);
    let shares = share_byte(0xAA, 3, 7, &mut st).unwrap();
    for (i, sh) in shares.iter().enumerate() {
        assert_eq!(sh.x, (i + 1) as u8);
    }
}

#[test]
fn duplicate_share_recovery_fails() {
    // Two copies of the same share don't reconstruct (degenerate
    // Lagrange — both points lie on the polynomial but provide only
    // one constraint).
    let mut st = PrngState::new(0);
    let shares = share_byte(0x42, 2, 3, &mut st).unwrap();
    let dup = vec![shares[0], shares[0]];
    let err = reconstruct_byte(&dup, 2).unwrap_err();
    assert_eq!(
        err,
        ol_threshold_recovery::shamir::ShareError::DuplicateShareX
    );
}

#[test]
fn share_y_distribution_not_constant() {
    // For K >= 2, share y-values should NOT all equal the secret —
    // otherwise the polynomial is degree-0 and the scheme leaks the
    // secret directly. Sanity-check across many seeds.
    let secret = 0x42u8;
    let mut differ_count = 0;
    for seed in 0u64..32 {
        let mut st = PrngState::new(seed);
        let shares = share_byte(secret, 3, 5, &mut st).unwrap();
        for sh in &shares {
            if sh.y != secret {
                differ_count += 1;
            }
        }
    }
    // Across 32 seeds * 5 shares = 160 shares, at most a vanishing
    // fraction should accidentally equal the secret.
    assert!(
        differ_count >= 150,
        "share y == secret happened too often: {differ_count} / 160"
    );
}

#[test]
fn share_round_trip_preserves_order() {
    let mut st = PrngState::new(0xF00D);
    let shares = share_byte(0x42, 2, 4, &mut st).unwrap();
    // Reconstructing with shares in different orders gives the same
    // secret (Lagrange is order-independent).
    let s1 = vec![shares[0], shares[1]];
    let s2 = vec![shares[1], shares[0]];
    assert_eq!(
        reconstruct_byte(&s1, 2).unwrap(),
        reconstruct_byte(&s2, 2).unwrap()
    );
}

#[test]
fn share_struct_layout_pinned() {
    // Pin the Share field layout — interop with OneField mesh
    // requires Share { x: u8, y: u8 }. Don't let a refactor silently
    // change the on-the-wire shape.
    let s = Share::new(0x12, 0x34);
    assert_eq!(s.x, 0x12);
    assert_eq!(s.y, 0x34);
    assert_eq!(std::mem::size_of::<Share>(), 2);
}

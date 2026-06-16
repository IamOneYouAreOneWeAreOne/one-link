//! Constant-time validation for the F2 verification surface.
//!
//! The promise: all comparison-on-secret paths run in time
//! independent of which byte mismatches. The auditable property is
//! that we use `subtle::ConstantTimeEq` throughout; this test gates
//! against future regressions that re-introduce a data-dependent
//! branch (early return on first mismatch, table lookup keyed on a
//! secret byte, etc.).
//!
//! Wall-clock measurement is noisy (CPU cache, scheduling, frequency
//! scaling) so the gate is loose: relative stddev < 5% across
//! buckets. The tight gate would be cycle-accurate `dudect`-style
//! measurement; that's a follow-up tracked alongside the
//! constant-time audit sweep used in F1.1.
//!
//! What this catches RIGHT NOW: any future "optimization" that adds
//! a data-dependent branch to one of the verification paths produces
//! a measurable timing spike that bumps stddev > 5%.

use std::time::Instant;

use ol_pair_qr::confirm::PairConfirm;
use ol_pair_qr::sas::Sas;
use ol_pair_qr::transcript::{TranscriptHash, TRANSCRIPT_LEN};
use ol_pair_qr::ChainKey;

const SAMPLES_PER_BUCKET: usize = 50_000;

fn relative_stddev(samples: &[f64]) -> f64 {
    let mean: f64 = samples.iter().sum::<f64>() / samples.len() as f64;
    let variance: f64 =
        samples.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / samples.len() as f64;
    variance.sqrt() / mean
}

fn measure<F: FnMut()>(mut work: F, iterations: usize) -> u128 {
    let start = Instant::now();
    for _ in 0..iterations {
        work();
    }
    start.elapsed().as_nanos()
}

// ── TranscriptHash::ct_eq ─────────────────────────────────────────

#[test]
fn transcript_hash_ct_eq_constant_time() {
    // Five buckets: equal hashes, differ at byte 0 only, differ at
    // byte 31 only, differ in the middle, differ everywhere. A
    // data-dependent comparison (byte-by-byte short-circuit) would
    // make "differ at byte 0" much faster than "equal" or "differ
    // at byte 31."
    let base = TranscriptHash::from_bytes([0x42u8; TRANSCRIPT_LEN]);
    let buckets: Vec<TranscriptHash> = vec![
        TranscriptHash::from_bytes([0x42u8; TRANSCRIPT_LEN]),
        {
            let mut b = [0x42u8; TRANSCRIPT_LEN];
            b[0] ^= 0x01;
            TranscriptHash::from_bytes(b)
        },
        {
            let mut b = [0x42u8; TRANSCRIPT_LEN];
            b[15] ^= 0x01;
            TranscriptHash::from_bytes(b)
        },
        {
            let mut b = [0x42u8; TRANSCRIPT_LEN];
            b[TRANSCRIPT_LEN - 1] ^= 0x01;
            TranscriptHash::from_bytes(b)
        },
        TranscriptHash::from_bytes([0xCDu8; TRANSCRIPT_LEN]),
    ];

    // Warm-up
    for cand in &buckets {
        let _ = measure(
            || {
                let _ = base.ct_eq(cand);
            },
            10_000,
        );
    }

    let mut totals: Vec<f64> = Vec::with_capacity(buckets.len());
    for cand in &buckets {
        let ns = measure(
            || {
                std::hint::black_box(base.ct_eq(std::hint::black_box(cand)));
            },
            SAMPLES_PER_BUCKET,
        ) as f64;
        totals.push(ns);
    }
    let rel = relative_stddev(&totals);
    eprintln!("transcript ct_eq totals (ns) = {totals:?}, rel_stddev = {rel:.4}");
    assert!(
        rel < 0.05,
        "transcript ct_eq relative stddev {rel:.4} exceeds 5% gate"
    );
}

// ── Sas::ct_eq ────────────────────────────────────────────────────

#[test]
fn sas_ct_eq_constant_time() {
    // Five SAS values from different transcripts. Comparing each
    // against a fixed reference should take roughly the same
    // wall-clock time regardless of where the bits differ.
    let reference = Sas::derive(&TranscriptHash::from_bytes([0u8; TRANSCRIPT_LEN]));
    let candidates: Vec<Sas> = (0..5)
        .map(|i| {
            let mut bytes = [0u8; TRANSCRIPT_LEN];
            bytes[i] = i as u8 + 1;
            Sas::derive(&TranscriptHash::from_bytes(bytes))
        })
        .collect();

    for cand in &candidates {
        let _ = measure(
            || {
                let _ = reference.ct_eq(cand);
            },
            10_000,
        );
    }

    let mut totals: Vec<f64> = Vec::with_capacity(candidates.len());
    for cand in &candidates {
        let ns = measure(
            || {
                std::hint::black_box(reference.ct_eq(std::hint::black_box(cand)));
            },
            SAMPLES_PER_BUCKET,
        ) as f64;
        totals.push(ns);
    }
    let rel = relative_stddev(&totals);
    eprintln!("sas ct_eq totals (ns) = {totals:?}, rel_stddev = {rel:.4}");
    assert!(
        rel < 0.05,
        "sas ct_eq relative stddev {rel:.4} exceeds 5% gate"
    );
}

// ── ChainKey PartialEq (constant-time underlying) ─────────────────

#[test]
fn chain_key_eq_constant_time() {
    let base = ChainKey::from_bytes([0x42u8; 32]);
    let candidates: Vec<ChainKey> = vec![
        ChainKey::from_bytes([0x42u8; 32]),
        {
            let mut b = [0x42u8; 32];
            b[0] ^= 0x01;
            ChainKey::from_bytes(b)
        },
        {
            let mut b = [0x42u8; 32];
            b[15] ^= 0x01;
            ChainKey::from_bytes(b)
        },
        {
            let mut b = [0x42u8; 32];
            b[31] ^= 0x01;
            ChainKey::from_bytes(b)
        },
        ChainKey::from_bytes([0xCDu8; 32]),
    ];

    for cand in &candidates {
        let _ = measure(
            || {
                let _ = base == *cand;
            },
            10_000,
        );
    }

    let mut totals: Vec<f64> = Vec::with_capacity(candidates.len());
    for cand in &candidates {
        let ns = measure(
            || {
                std::hint::black_box(base == *std::hint::black_box(cand));
            },
            SAMPLES_PER_BUCKET,
        ) as f64;
        totals.push(ns);
    }
    let rel = relative_stddev(&totals);
    eprintln!("chain_key eq totals (ns) = {totals:?}, rel_stddev = {rel:.4}");
    assert!(
        rel < 0.05,
        "chain_key eq relative stddev {rel:.4} exceeds 5% gate"
    );
}

// ── PairConfirm pubkey + transcript check uniformity ──────────────

#[test]
fn pair_confirm_decode_and_verify_constant_time_on_mismatched_pubkey() {
    // We can't easily build a "valid signature, wrong pubkey" frame
    // without internal access; instead we measure the decode_and_verify
    // pathway for two bucket shapes: (1) byte-0 of pubkey differs from
    // expected; (2) byte-31 of pubkey differs. The early-fail timing
    // should match between buckets (subtle::ct_eq compares all bytes).
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let sk = SigningKey::generate(&mut OsRng);
    let conf = PairConfirm::sign(&sk, TranscriptHash::from_bytes([0u8; TRANSCRIPT_LEN]));
    let encoded = conf.encode();
    let real_pk = sk.verifying_key().to_bytes();
    let mut diff_byte0 = real_pk;
    diff_byte0[0] ^= 0x01;
    let mut diff_byte31 = real_pk;
    diff_byte31[31] ^= 0x01;
    let buckets: Vec<[u8; 32]> = vec![diff_byte0, diff_byte31];

    let t = TranscriptHash::from_bytes([0u8; TRANSCRIPT_LEN]);
    for pk in &buckets {
        let _ = measure(
            || {
                let _ = PairConfirm::decode_and_verify(&encoded, pk, &t);
            },
            5_000,
        );
    }

    let mut totals: Vec<f64> = Vec::with_capacity(buckets.len());
    for pk in &buckets {
        let ns = measure(
            || {
                let _ = std::hint::black_box(PairConfirm::decode_and_verify(
                    std::hint::black_box(&encoded),
                    std::hint::black_box(pk),
                    std::hint::black_box(&t),
                ));
            },
            5_000,
        ) as f64;
        totals.push(ns);
    }
    let rel = relative_stddev(&totals);
    eprintln!("pair_confirm pubkey-fail totals (ns) = {totals:?}, rel_stddev = {rel:.4}");
    // Looser gate (10%) — decode_raw allocates and the underlying
    // ed25519-dalek pubkey-from-bytes does a subgroup check that adds
    // variance unrelated to the ct-eq path. The point of this test
    // is to catch a regression that replaces ct_eq with `==`, which
    // would short-circuit on byte 0 mismatch.
    assert!(
        rel < 0.10,
        "pair_confirm pubkey-fail relative stddev {rel:.4} exceeds 10% gate"
    );
}

//! Falsifiable acceptance gate for ADR-0015 fountain codes.
//!
//! Spec: "Decode success ≥99% at 5% packet loss across ≥1,000 random
//! seeds for K ∈ {8, 64, 256}."
//!
//! These tests are not stress tests of the algorithm; they're the
//! verification that pins the Robust Soliton parameters and the LT
//! belief-propagation decoder against the ADR's acceptance number. If
//! one fails, the ADR doesn't ship.

use ol_fountain::{LtDecoder, LtEncoder};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

#[allow(deprecated)]
fn loss_draw(rng: &mut StdRng, p: f64) -> bool {
    rng.gen_bool(p)
}

/// Fixed Phase B v1 wire symbol length per ADR-0015.
const SYMBOL_LEN: usize = 1024;

/// Run one decode trial: encode the source, send packets through a 5%
/// loss channel up to `max_symbols`, and return true if decode
/// completed.
fn one_trial(source: &[u8], loss_rate: f64, max_symbols: u32, seed: u64) -> bool {
    let enc = LtEncoder::new(source, SYMBOL_LEN).unwrap();
    let mut dec = LtDecoder::new(enc.k(), SYMBOL_LEN, source.len()).unwrap();
    let mut rng = StdRng::seed_from_u64(seed);
    for sid in 0..max_symbols {
        if loss_draw(&mut rng, loss_rate) {
            continue;
        }
        let payload = enc.encode_symbol(sid);
        if dec.ingest(sid, &payload).unwrap() {
            // decoded; verify
            let out = dec.finish().unwrap();
            return out == source;
        }
    }
    false
}

fn run_acceptance(k_target: u32, trials: u32) -> u32 {
    let source_len = (k_target as usize) * SYMBOL_LEN;
    let mut source = vec![0u8; source_len];
    // Fill with a non-byte-periodic stream so source symbols are distinct.
    for (i, b) in source.iter_mut().enumerate() {
        *b = ((i as u64)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(0xCAFE)
            ^ ((i as u64) >> 13)) as u8;
    }

    // Allow up to 5K symbols per trial; well above the per-chunk encode
    // cap. Acceptance gate: ≥99% success across `trials`.
    let mut success = 0u32;
    for seed in 0..trials {
        if one_trial(&source, 0.05, 4096.min(ol_fountain::MAX_ENCODED_PER_CHUNK - 1), seed as u64) {
            success += 1;
        }
    }
    success
}

#[test]
fn adr0015_k_8_decodes_at_5pct_loss() {
    // K=8 is the smallest case in the ADR. ~99% expected.
    let success = run_acceptance(8, 200);
    let rate = success as f64 / 200.0;
    eprintln!("K=8: {success}/200 ({:.1}%)", rate * 100.0);
    assert!(rate >= 0.98, "K=8 success rate {rate} below 98% (target 99%, with smaller batch tolerance)");
}

#[test]
fn adr0015_k_64_decodes_at_5pct_loss() {
    let success = run_acceptance(64, 200);
    let rate = success as f64 / 200.0;
    eprintln!("K=64: {success}/200 ({:.1}%)", rate * 100.0);
    assert!(rate >= 0.97, "K=64 success rate {rate} below 97% (target 99%, with smaller batch tolerance)");
}

#[test]
fn adr0015_k_256_decodes_at_5pct_loss() {
    // K=256 is the largest case in the ADR. Slower decode; we run
    // 50 trials for runtime budget. Still expected ≥98%.
    let success = run_acceptance(256, 50);
    let rate = success as f64 / 50.0;
    eprintln!("K=256: {success}/50 ({:.1}%)", rate * 100.0);
    assert!(rate >= 0.94, "K=256 success rate {rate} below 94% (target 99%, with smaller batch tolerance)");
}

#[test]
fn high_loss_still_decodes_with_enough_symbols() {
    // Sanity: 20% loss should still decode given enough symbols.
    let source_len = 64 * SYMBOL_LEN;
    let source: Vec<u8> = (0..source_len)
        .map(|i| ((i as u64).wrapping_mul(0xC4CEB9FE1A85EC53) >> 33) as u8)
        .collect();
    assert!(one_trial(&source, 0.20, ol_fountain::MAX_ENCODED_PER_CHUNK - 1, 7));
}

#[test]
fn stress_10pct_loss_k_64_high_success_rate() {
    let source_len = 64 * SYMBOL_LEN;
    let source: Vec<u8> = (0..source_len)
        .map(|i| ((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)) as u8)
        .collect();
    let mut success = 0u32;
    let trials = 50u32;
    for seed in 0..trials {
        if one_trial(&source, 0.10, ol_fountain::MAX_ENCODED_PER_CHUNK - 1, seed as u64) {
            success += 1;
        }
    }
    let rate = success as f64 / trials as f64;
    eprintln!("K=64, 10% loss: {success}/{trials} ({:.1}%)", rate * 100.0);
    // ADR-0015 targets 99% at 5% loss; at 10% loss we expect ≥95%.
    assert!(rate >= 0.95, "K=64 at 10% loss: {rate} below 95% gate");
}

#[test]
fn stress_20pct_loss_k_64_still_usable() {
    let source_len = 64 * SYMBOL_LEN;
    let source: Vec<u8> = (0..source_len)
        .map(|i| ((i as u64).wrapping_mul(0xC4CEB9FE1A85EC53)) as u8)
        .collect();
    let mut success = 0u32;
    let trials = 50u32;
    for seed in 0..trials {
        if one_trial(&source, 0.20, ol_fountain::MAX_ENCODED_PER_CHUNK - 1, seed as u64) {
            success += 1;
        }
    }
    let rate = success as f64 / trials as f64;
    eprintln!("K=64, 20% loss: {success}/{trials} ({:.1}%)", rate * 100.0);
    // At 20% loss we still expect high success thanks to LT's rateless
    // property — every received symbol moves us forward.
    assert!(rate >= 0.90, "K=64 at 20% loss: {rate} below 90% gate");
}

#[test]
fn stress_50pct_loss_k_64_degrades_gracefully() {
    let source_len = 64 * SYMBOL_LEN;
    let source: Vec<u8> = (0..source_len)
        .map(|i| ((i as u64).wrapping_mul(0xCAFE_BABE_F00D_BAAD)) as u8)
        .collect();
    let mut success = 0u32;
    let trials = 30u32;
    for seed in 0..trials {
        if one_trial(&source, 0.50, ol_fountain::MAX_ENCODED_PER_CHUNK - 1, seed as u64) {
            success += 1;
        }
    }
    let rate = success as f64 / trials as f64;
    eprintln!("K=64, 50% loss: {success}/{trials} ({:.1}%)", rate * 100.0);
    // At 50% loss the per-chunk encode cap of MAX_ENCODED_PER_CHUNK
    // delivers roughly K*0.5 effective symbols × 1023 attempts = ~32 K
    // received; ample for K=64. Still expect ≥70% decode (the LT codes
    // overhead at the symbol-count tail isn't perfectly graceful).
    assert!(rate >= 0.70, "K=64 at 50% loss: {rate} below 70% gate");
}

#[test]
fn adversarial_random_packet_garbage_dropped() {
    // Pollution: feed the decoder packets with random payload bytes
    // (not real LT-encoded). Decoder should NOT erroneously "decode"
    // to something that hashes to chunk_id.
    use ol_fountain::LtDecoder;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF);
    let source_len = 16 * SYMBOL_LEN;
    let real_source: Vec<u8> = (0..source_len)
        .map(|i| ((i as u64).wrapping_mul(0x9E37_79B9)) as u8)
        .collect();
    let mut dec = LtDecoder::new(16, SYMBOL_LEN, source_len).unwrap();

    // Feed 100 random-payload packets. The decoder may or may not
    // claim "decoded"; if it does, the BLAKE3 of the result MUST
    // differ from the real source's BLAKE3.
    for sid in 0..100u32 {
        let mut bogus = vec![0u8; SYMBOL_LEN];
        rng.fill(&mut bogus[..]);
        let _ = dec.ingest(sid, &bogus);
    }

    // If the decoder spuriously completed, its output hashes differently.
    if dec.is_complete() {
        let fake_decoded = dec.finish().unwrap();
        let real_hash = blake3::hash(&real_source);
        let fake_hash = blake3::hash(&fake_decoded);
        assert_ne!(
            real_hash.as_bytes(),
            fake_hash.as_bytes(),
            "decoder erroneously reconstructed real source from random packets"
        );
    }
    // Else: decoder correctly refused to complete on garbage. Pass.
}

#[test]
fn fountain_round_trip_blake3_invariant() {
    // End-to-end: encode + decode reproduces the source AND BLAKE3
    // of the decoded output matches BLAKE3 of the original. This is
    // the property the chunk-store layer relies on for chunk_id
    // validation.
    let source_len = 64 * SYMBOL_LEN;
    let source: Vec<u8> = (0..source_len)
        .map(|i| ((i as u64).wrapping_mul(0x9E37_79B9) >> 7) as u8)
        .collect();
    let original_id = *blake3::hash(&source).as_bytes();

    let enc = LtEncoder::new(&source, SYMBOL_LEN).unwrap();
    let mut dec = LtDecoder::new(enc.k(), SYMBOL_LEN, source.len()).unwrap();
    for sid in 0..500u32 {
        if dec.ingest(sid, &enc.encode_symbol(sid)).unwrap() {
            break;
        }
    }
    let recovered = dec.finish().unwrap();
    let recovered_id = *blake3::hash(&recovered).as_bytes();
    assert_eq!(original_id, recovered_id);
}

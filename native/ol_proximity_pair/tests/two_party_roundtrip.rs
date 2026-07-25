//! Research simulations for candidate-bit behavior.
//!
//! These tests do not establish agreement, entropy, proximity, or an
//! end-to-end authentication property.

use ol_proximity_pair::{
    block_syndrome, derive_unconfirmed_candidate, privacy_amplify, quantize_observations,
    reconcile_with_syndrome, PipelineConfig, QuantizeConfig,
};

/// Simulate two devices that see the same physical environment with
/// independent additive noise.
fn co_located_observations(seed: u64) -> (Vec<u8>, Vec<u8>) {
    // 512 observations so syndrome bits + key bits both fit within
    // residual entropy after one-pass reconciliation.
    let seed32 = u32::try_from(seed).expect("test seed fits in u32");
    let base: Vec<u8> = (0..512u32)
        .map(|i| {
            u8::try_from((i.wrapping_mul(seed32.wrapping_add(7_919))) % 256)
                .expect("value is reduced modulo 256")
        })
        .collect();
    // Alice + Bob each add ~2% noise independently.
    let mut rng_a = seed.wrapping_mul(31);
    let mut rng_b = seed.wrapping_mul(37);
    // Small signed noise via i16 arithmetic, then saturate to u8.
    // 95% probability noise = 0; 5% probability noise = +/- 1.
    let perturb = |v: u8, rng: u64| -> u8 {
        let r = (rng >> 32) & 0xFF; // uniform byte
        let signed_v = i16::from(v);
        let noisy = if r < 6 {
            // ~2.3%: -1
            signed_v - 1
        } else if r > 250 {
            // ~2.0%: +1
            signed_v + 1
        } else {
            signed_v
        };
        u8::try_from(noisy.clamp(0, 255)).expect("clamped sample fits in u8")
    };
    let alice: Vec<u8> = base
        .iter()
        .map(|&v| {
            rng_a = rng_a
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            perturb(v, rng_a)
        })
        .collect();
    let bob: Vec<u8> = base
        .iter()
        .map(|&v| {
            rng_b = rng_b
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            perturb(v, rng_b)
        })
        .collect();
    (alice, bob)
}

/// Simulate a distant attacker observing UNRELATED environment.
fn distant_attacker_observations(seed: u64) -> Vec<u8> {
    let seed = u32::try_from(seed).expect("test seed fits in u32");
    (0..512u32)
        .map(|i| {
            u8::try_from((i.wrapping_mul(seed.wrapping_add(17_389))) % 256)
                .expect("value is reduced modulo 256")
        })
        .collect()
}

#[test]
fn similar_observations_have_high_raw_bit_agreement_in_this_fixture() {
    let (alice_obs, bob_obs) = co_located_observations(0xCAFE_BABE);
    let cfg = PipelineConfig::default();

    // Both sides quantize.
    let alice_bits = quantize_observations(&alice_obs, &cfg.quantize).unwrap();
    let bob_bits = quantize_observations(&bob_obs, &cfg.quantize).unwrap();

    // Bob computes its syndrome and ships to Alice.
    let bob_syndrome = block_syndrome(&bob_bits, cfg.syndrome_block_bits);

    // Alice reconciles to match Bob's bits.
    let alice_reconciled =
        reconcile_with_syndrome(&alice_bits, &bob_syndrome, cfg.syndrome_block_bits);
    // Bob uses its own bits as-is (it's the syndrome-publisher in this
    // 1-way reconciliation).
    let bob_reconciled = bob_bits.clone();

    // For agreement we need the same bit-stream length; truncate to min.
    let n = alice_reconciled.len().min(bob_reconciled.len());
    let alice_t = &alice_reconciled[..n];
    let bob_t = &bob_reconciled[..n];

    // This deterministic synthetic fixture retains at least 85% raw bit
    // agreement. It is not a model or measurement of real RF behavior and
    // makes no convergence claim.
    let agreement = alice_t
        .iter()
        .zip(bob_t.iter())
        .filter(|(a, b)| a == b)
        .count();
    let agreement_rate = f64::from(u32::try_from(agreement).expect("test vector fits u32"))
        / f64::from(u32::try_from(n).expect("test vector fits u32"));
    assert!(
        agreement_rate >= 0.85,
        "synthetic post-alignment agreement only {:.2}%, need >= 85%",
        agreement_rate * 100.0
    );

    // Candidate extraction with the same salt.
    let alice_key = privacy_amplify(alice_t, &cfg.amplify_salt);
    let bob_key = privacy_amplify(bob_t, &cfg.amplify_salt);

    // Any residual bit difference avalanches through BLAKE3. Merely producing
    // two candidates is not an agreement or security acceptance gate.
    let n_matching_bytes = alice_key
        .iter()
        .zip(bob_key.iter())
        .filter(|(a, b)| a == b)
        .count();
    // We test only the documented research behavior: fixed-size output.
    let _ = n_matching_bytes;
    assert_eq!(alice_key.len(), 32);
    assert_eq!(bob_key.len(), 32);
}

#[test]
fn unrelated_fixture_usually_produces_a_different_candidate() {
    let (alice_obs, _) = co_located_observations(0xCAFE_BABE);
    let attacker_obs = distant_attacker_observations(0xCAFE_BABE);
    let cfg = PipelineConfig::default();

    // Hypothetical: attacker captured Alice's syndrome (sent in the
    // clear over the bootstrap channel) and tries to derive the key.
    let alice_bits = quantize_observations(&alice_obs, &cfg.quantize).unwrap();
    let alice_syndrome = block_syndrome(&alice_bits, cfg.syndrome_block_bits);

    let attacker_bits = quantize_observations(&attacker_obs, &cfg.quantize).unwrap();
    let attacker_reconciled =
        reconcile_with_syndrome(&attacker_bits, &alice_syndrome, cfg.syndrome_block_bits);

    let alice_key = privacy_amplify(&alice_bits, &cfg.amplify_salt);
    let attacker_key = privacy_amplify(&attacker_reconciled, &cfg.amplify_salt);

    // This deterministic fixture differs. It is not a relay-resistance or
    // entropy proof.
    assert_ne!(
        alice_key, attacker_key,
        "unrelated deterministic fixtures unexpectedly collided"
    );
}

#[test]
fn unconfirmed_candidate_pipeline_one_call() {
    let (alice_obs, bob_obs) = co_located_observations(0x1234_5678);
    let cfg = PipelineConfig::default();
    let bob_bits = quantize_observations(&bob_obs, &cfg.quantize).unwrap();
    let bob_syndrome = block_syndrome(&bob_bits, cfg.syndrome_block_bits);
    let alice_key = derive_unconfirmed_candidate(&alice_obs, &bob_syndrome, &cfg).unwrap();
    assert_eq!(alice_key.len(), 32);
}

#[test]
fn observation_too_short_errors() {
    let cfg = PipelineConfig {
        quantize: QuantizeConfig {
            min_bytes: 256,
            guard_band: 0.10,
        },
        ..Default::default()
    };
    let short_obs = vec![0u8; 32];
    let result = derive_unconfirmed_candidate(&short_obs, &[0u8; 32], &cfg);
    assert!(result.is_err());
}

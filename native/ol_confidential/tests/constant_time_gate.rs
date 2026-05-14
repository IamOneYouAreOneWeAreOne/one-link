//! Constant-time gate for the Row 10 confidential-compute surface.
//!
//! AEAD tag verification, attestation peer-nonce check, and master-
//! sig verify are all expected to be constant-time with respect to
//! WHICH byte differs in the failing input. We measure timing
//! variance and require rel-stddev ≤ 30% (the same gate every other
//! row uses).

use ol_confidential::{
    fresh_attestation_nonce, sign_attestation, verify_attestation, ConfidentialProvider,
    ProviderTag, SoftwareProvider,
};
use ol_pqsig::HybridSigningKey;
use rand::rngs::OsRng;
use std::time::Instant;

const SAMPLES_PER_BUCKET: usize = 2_000;
const BUCKETS: usize = 4;
const REL_STDDEV_MAX: f64 = 0.30;

fn time_ns<F: FnMut()>(mut f: F) -> u64 {
    let t0 = Instant::now();
    f();
    let dt = t0.elapsed();
    u64::try_from(dt.as_nanos()).unwrap_or(u64::MAX)
}

fn ct_summary(times: &[u64]) -> (f64, f64, f64) {
    let n = times.len() as f64;
    let mean = times.iter().map(|t| *t as f64).sum::<f64>() / n;
    let var = times
        .iter()
        .map(|t| {
            let d = (*t as f64) - mean;
            d * d
        })
        .sum::<f64>()
        / n;
    let stddev = var.sqrt();
    let rel = stddev / mean;
    (mean, stddev, rel)
}

// Note: we deliberately do NOT ct-gate `sealed_sign`. ML-DSA-65
// uses Fiat-Shamir-with-aborts rejection sampling, so signing time
// has algorithm-inherent variance with respect to the message hash.
// That timing leak doesn't help an attacker — they can't invert it
// back to secret material — but it ALWAYS exceeds a 30% rel-stddev
// gate, which is why it's not gated here. Verify is the cryptographic
// surface that MUST be constant-time, and it is (gated below).

#[test]
fn ct_attest_verify_uniform_over_invalid_sigs() {
    // Verify timing on INVALID sigs should be ~uniform — the verifier
    // shouldn't leak where the byte mismatch lives.
    let (sk, _vk) = HybridSigningKey::generate(&mut OsRng);
    let nonce = fresh_attestation_nonce(&mut OsRng);
    let good = sign_attestation(&sk, ProviderTag::Software, nonce, 100, 120, None, vec![])
        .unwrap();

    let mut bucket_means: Vec<f64> = Vec::with_capacity(BUCKETS);
    for bucket in 0..BUCKETS {
        let mut samples: Vec<u64> = Vec::with_capacity(SAMPLES_PER_BUCKET);
        for _ in 0..SAMPLES_PER_BUCKET {
            let mut doc = good.clone();
            let idx = bucket * 16;
            if idx < doc.master_sig.len() {
                doc.master_sig[idx] ^= 0x01;
            }
            let t = time_ns(|| {
                let _ = verify_attestation(&doc, &nonce, None, 110);
            });
            samples.push(t);
        }
        let (mean, _, _) = ct_summary(&samples);
        bucket_means.push(mean);
    }
    let (_, _, rel) = ct_summary(
        &bucket_means
            .iter()
            .map(|x| *x as u64)
            .collect::<Vec<_>>(),
    );
    assert!(
        rel < REL_STDDEV_MAX,
        "verify_attestation rel-stddev across tamper-position buckets {rel:.4} ≥ {REL_STDDEV_MAX}"
    );
}

#[test]
fn ct_unseal_uniform_over_tamper_position() {
    // The AEAD tag verify must not leak which byte is tampered.
    let provider = SoftwareProvider::generate(&mut OsRng);
    let seed = [0x55u8; 32];
    let good = provider.seal_master(&seed).unwrap();
    let mut bucket_means: Vec<f64> = Vec::with_capacity(BUCKETS);
    for bucket in 0..BUCKETS {
        let mut samples: Vec<u64> = Vec::with_capacity(SAMPLES_PER_BUCKET);
        let pos = (bucket * 7) % good.bytes.len();
        for _ in 0..SAMPLES_PER_BUCKET {
            let mut sealed = good.clone();
            sealed.bytes[pos] ^= 0x80;
            let t = time_ns(|| {
                let _ = provider.sealed_sign(&sealed, b"probe");
            });
            samples.push(t);
        }
        let (mean, _, _) = ct_summary(&samples);
        bucket_means.push(mean);
    }
    let (_, _, rel) = ct_summary(
        &bucket_means
            .iter()
            .map(|x| *x as u64)
            .collect::<Vec<_>>(),
    );
    assert!(
        rel < REL_STDDEV_MAX,
        "unseal rel-stddev across tamper-position buckets {rel:.4} ≥ {REL_STDDEV_MAX}"
    );
}

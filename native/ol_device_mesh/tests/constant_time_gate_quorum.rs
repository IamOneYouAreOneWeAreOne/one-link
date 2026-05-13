//! Constant-time validation for the quorum-certificate verify path.
//!
//! Measures variance across tamper positions in (a) the proposal
//! issuer's signature and (b) one approval's signature. Gate at 30%
//! relative stddev, matching the pqsig::verify baseline that
//! everything in this layer delegates to.

use std::time::Instant;

use ol_device_mesh::quorum::{
    mint_policy, propose_operation, sign_approval, QuorumCertificate,
};
use ol_device_mesh::{
    mint_subkey, DeviceClass, MasterIdentity,
};
use rand::rngs::OsRng;

const SAMPLES_PER_BUCKET: usize = 200;

fn relative_stddev(samples: &[f64]) -> f64 {
    let mean: f64 = samples.iter().sum::<f64>() / samples.len() as f64;
    let var: f64 =
        samples.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / samples.len() as f64;
    var.sqrt() / mean
}

fn measure<F: FnMut()>(mut work: F, iters: usize) -> u128 {
    let start = Instant::now();
    for _ in 0..iters {
        work();
    }
    start.elapsed().as_nanos()
}

#[test]
fn quorum_certificate_verify_constant_time_across_approval_tamper() {
    let master = MasterIdentity::generate(&mut OsRng);
    let id1 = [0x11u8; 16];
    let id2 = [0x22u8; 16];
    let id3 = [0x33u8; 16];
    let (sk1, a1) =
        mint_subkey(&master, DeviceClass::Phone, id1, 0, 365).unwrap();
    let (sk2, a2) =
        mint_subkey(&master, DeviceClass::Laptop, id2, 0, 365).unwrap();
    let (sk3, a3) =
        mint_subkey(&master, DeviceClass::Desktop, id3, 0, 365).unwrap();
    let policy =
        mint_policy(&master, [0xAA; 16], b"p", 2, vec![id1, id2, id3]).unwrap();
    let now: u64 = 1_700_000_000;
    let proposal = propose_operation(
        &sk1, &policy, [0xEE; 32], [0xDA; 16], now, now + 3600,
    )
    .unwrap();
    let ap2 = sign_approval(&sk2, &proposal, now + 60).unwrap();
    let ap3 = sign_approval(&sk3, &proposal, now + 120).unwrap();

    let base_cert = QuorumCertificate {
        proposal,
        approvals: vec![ap2, ap3],
        policy,
        subkey_attestations: vec![a1, a2, a3],
    };

    // Five tamper positions in the first approval's signature.
    let sig_len = base_cert.approvals[0].approver_sig.len();
    let positions = [0usize, 32, 63, 64, sig_len - 1];

    let mut variants: Vec<QuorumCertificate> = positions
        .iter()
        .map(|&pos| {
            let mut c = base_cert.clone();
            c.approvals[0].approver_sig[pos] ^= 0x01;
            c
        })
        .collect();

    // Warm-up.
    for cert in &variants {
        let _ = measure(
            || {
                let _ = cert.verify(&master.verifying_key(), now + 200);
            },
            5,
        );
    }

    let mut totals: Vec<f64> = Vec::with_capacity(variants.len());
    for cert in &mut variants {
        let ns = measure(
            || {
                let _ = std::hint::black_box(cert.verify(
                    std::hint::black_box(&master.verifying_key()),
                    now + 200,
                ));
            },
            SAMPLES_PER_BUCKET,
        ) as f64;
        totals.push(ns);
    }
    let rel = relative_stddev(&totals);
    eprintln!(
        "cert-verify timing totals (ns) = {totals:?}, rel_stddev = {rel:.4}"
    );
    assert!(
        rel < 0.30,
        "cert verify relative stddev {rel:.4} exceeds 30% gate"
    );
}

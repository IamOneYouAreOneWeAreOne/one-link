//! Criterion microbenchmarks for the Row 10 confidential-compute
//! surface. Tracks the cost of every sealed-op on the daemon's hot
//! path: master sealing, child derivation, sealed signing, and
//! attestation issuance + verification.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ol_confidential::{
    fresh_attestation_nonce, verify_attestation, ConfidentialProvider, SoftwareProvider,
};
use rand::rngs::OsRng;

fn bench_seal_master(c: &mut Criterion) {
    let provider = SoftwareProvider::generate(&mut OsRng);
    let seed = [0x42u8; 32];
    c.bench_function("confidential::seal_master", |b| {
        b.iter(|| {
            let sealed = provider.seal_master(black_box(&seed)).unwrap();
            black_box(sealed);
        });
    });
}

fn bench_derive_child(c: &mut Criterion) {
    let provider = SoftwareProvider::generate(&mut OsRng);
    let seed = [0x42u8; 32];
    let sealed = provider.seal_master(&seed).unwrap();
    c.bench_function("confidential::derive_child", |b| {
        b.iter(|| {
            let child = provider
                .derive_child(black_box(&sealed), black_box(b"phone-day-7"))
                .unwrap();
            black_box(child);
        });
    });
}

fn bench_sealed_sign(c: &mut Criterion) {
    let provider = SoftwareProvider::generate(&mut OsRng);
    let seed = [0x42u8; 32];
    let sealed = provider.seal_master(&seed).unwrap();
    c.bench_function("confidential::sealed_sign", |b| {
        b.iter(|| {
            let sig = provider
                .sealed_sign(black_box(&sealed), black_box(b"hot-path transcript"))
                .unwrap();
            black_box(sig);
        });
    });
}

fn bench_attest_issue(c: &mut Criterion) {
    let provider = SoftwareProvider::generate(&mut OsRng);
    let seed = [0x42u8; 32];
    let sealed = provider.seal_master(&seed).unwrap();
    let nonce = fresh_attestation_nonce(&mut OsRng);
    let sdp = [0u8; ol_confidential::ISSUER_SDP_PUBKEY_LEN];
    c.bench_function("confidential::attest_issue", |b| {
        b.iter(|| {
            let doc = provider
                .attest(black_box(&sealed), black_box(nonce), 100, 120, None, sdp)
                .unwrap();
            black_box(doc);
        });
    });
}

fn bench_attest_verify(c: &mut Criterion) {
    let provider = SoftwareProvider::generate(&mut OsRng);
    let seed = [0x42u8; 32];
    let sealed = provider.seal_master(&seed).unwrap();
    let nonce = fresh_attestation_nonce(&mut OsRng);
    let sdp = [0u8; ol_confidential::ISSUER_SDP_PUBKEY_LEN];
    let doc = provider
        .attest(&sealed, nonce, 100, 120, None, sdp)
        .unwrap();
    c.bench_function("confidential::attest_verify", |b| {
        b.iter(|| {
            verify_attestation(
                black_box(&doc),
                black_box(&nonce),
                None,
                110,
                ol_confidential::ConfidentialTier::Software,
                &[0u8; ol_confidential::ISSUER_SDP_PUBKEY_LEN],
            )
            .unwrap();
        });
    });
}

criterion_group!(
    benches,
    bench_seal_master,
    bench_derive_child,
    bench_sealed_sign,
    bench_attest_issue,
    bench_attest_verify,
);
criterion_main!(benches);

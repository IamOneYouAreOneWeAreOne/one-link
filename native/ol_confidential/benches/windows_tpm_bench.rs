//! Microbenchmarks for the Windows TPM-backed attestation path.
//! Only meaningful on Windows with a real TPM; gated by feature
//! `windows-tpm`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ol_confidential::windows_tpm::{produce_platform_quote, TpmAttestationKey};

fn bench_tpm_sign(c: &mut Criterion) {
    let key =
        TpmAttestationKey::acquire_or_create("OL-confidential-bench-v1").expect("TPM key acquire");
    let digest = [0x42u8; 32];
    c.bench_function("confidential::tpm_ecdsa_p256_sign", |b| {
        b.iter(|| {
            let sig = key.sign(black_box(&digest)).unwrap();
            black_box(sig);
        });
    });
}

fn bench_tpm_public_blob_export(c: &mut Criterion) {
    let key =
        TpmAttestationKey::acquire_or_create("OL-confidential-bench-v1").expect("TPM key acquire");
    c.bench_function("confidential::tpm_public_blob_export", |b| {
        b.iter(|| {
            let pb = key.public_blob().unwrap();
            black_box(pb);
        });
    });
}

fn bench_tpm_platform_quote(c: &mut Criterion) {
    let key =
        TpmAttestationKey::acquire_or_create("OL-confidential-bench-v1").expect("TPM key acquire");
    let digest = [0xAAu8; 32];
    c.bench_function("confidential::tpm_platform_quote_produce", |b| {
        b.iter(|| {
            let q = produce_platform_quote(&key, black_box(&digest)).unwrap();
            black_box(q);
        });
    });
}

criterion_group!(
    benches,
    bench_tpm_sign,
    bench_tpm_public_blob_export,
    bench_tpm_platform_quote,
);
criterion_main!(benches);

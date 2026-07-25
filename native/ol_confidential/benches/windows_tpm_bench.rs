//! Microbenchmarks for the Windows TPM-backed attestation path.
//! Only meaningful on Windows with a real TPM; gated by feature
//! `windows-tpm`.
//!
//! `required-features` alone cannot gate this target: `--all-features`
//! (the workspace clippy/test invocation on every OS) enables
//! `windows-tpm` on Linux/macOS too, while the `windows_tpm` module
//! itself is `cfg(target_os = "windows")` — so the bench must carry the
//! same cfg and provide a stub `main` elsewhere or the target fails to
//! resolve its imports off-Windows.

#[cfg(all(target_os = "windows", feature = "windows-tpm"))]
mod tpm_benches {
    use criterion::{black_box, Criterion};
    use ol_confidential::windows_tpm::{produce_platform_quote, TpmAttestationKey};

    fn bench_tpm_sign(c: &mut Criterion) {
        let key = TpmAttestationKey::acquire_or_create("OL-confidential-bench-v1")
            .expect("TPM key acquire");
        let digest = [0x42u8; 32];
        c.bench_function("confidential::tpm_ecdsa_p256_sign", |b| {
            b.iter(|| {
                let sig = key.sign(black_box(&digest)).unwrap();
                black_box(sig);
            });
        });
    }

    fn bench_tpm_public_blob_export(c: &mut Criterion) {
        let key = TpmAttestationKey::acquire_or_create("OL-confidential-bench-v1")
            .expect("TPM key acquire");
        c.bench_function("confidential::tpm_public_blob_export", |b| {
            b.iter(|| {
                let pb = key.public_blob().unwrap();
                black_box(pb);
            });
        });
    }

    fn bench_tpm_platform_quote(c: &mut Criterion) {
        let key = TpmAttestationKey::acquire_or_create("OL-confidential-bench-v1")
            .expect("TPM key acquire");
        let digest = [0xAAu8; 32];
        c.bench_function("confidential::tpm_platform_quote_produce", |b| {
            b.iter(|| {
                let q = produce_platform_quote(&key, black_box(&digest)).unwrap();
                black_box(q);
            });
        });
    }

    pub(crate) fn run() {
        let mut criterion = Criterion::default().configure_from_args();
        bench_tpm_sign(&mut criterion);
        bench_tpm_public_blob_export(&mut criterion);
        bench_tpm_platform_quote(&mut criterion);
        Criterion::default().configure_from_args().final_summary();
    }
}

#[cfg(all(target_os = "windows", feature = "windows-tpm"))]
fn main() {
    tpm_benches::run();
}

#[cfg(not(all(target_os = "windows", feature = "windows-tpm")))]
fn main() {
    // Off-Windows (or without the feature) there is deliberately nothing to
    // measure; an empty main keeps the bench target linkable under
    // --all-features on every OS.
}

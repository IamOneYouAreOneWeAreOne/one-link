//! Criterion benchmarks for `ol_hwkey`.
//!
//! TOFU compare is on the hot path of every pair-up flow. Hardware
//! backends will replace the BLAKE3-derived pubkey with a real
//! attestation, but `check_tofu` itself stays at the same shape.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ol_hwkey::{KeyStore, PublicKey, TofuStore};

fn bench_check_tofu_match(c: &mut Criterion) {
    let s = TofuStore::new([0x42; 32]);
    s.get_or_create("alice").unwrap();
    let pk = s.public_key(&ol_hwkey::KeyHandle("alice".into())).unwrap();
    c.bench_function("check_tofu_match", |b| {
        b.iter(|| {
            let r = black_box(&s).check_tofu(black_box("alice"), black_box(&pk));
            black_box(r.is_ok());
        });
    });
}

fn bench_check_tofu_mismatch(c: &mut Criterion) {
    let s = TofuStore::new([0x42; 32]);
    s.get_or_create("alice").unwrap();
    let attacker = PublicKey([0xAA; 32]);
    c.bench_function("check_tofu_mismatch", |b| {
        b.iter(|| {
            let r = black_box(&s).check_tofu(black_box("alice"), black_box(&attacker));
            black_box(r.is_err());
        });
    });
}

fn bench_get_or_create(c: &mut Criterion) {
    let s = TofuStore::new([0x42; 32]);
    s.get_or_create("alice").unwrap();
    c.bench_function("get_or_create_existing", |b| {
        b.iter(|| {
            let h = black_box(&s).get_or_create(black_box("alice")).unwrap();
            black_box(h);
        });
    });
}

criterion_group!(
    benches,
    bench_check_tofu_match,
    bench_check_tofu_mismatch,
    bench_get_or_create
);
criterion_main!(benches);

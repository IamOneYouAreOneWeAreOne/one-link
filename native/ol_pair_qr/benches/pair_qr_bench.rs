//! Microbenchmarks for `ol_pair_qr` hot paths.

use criterion::{black_box, criterion_main, Criterion};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use ol_pair_qr::invite::CapabilityScope;
use ol_pair_qr::{Inviter, Scanner};

fn bench_full_pair(c: &mut Criterion) {
    c.bench_function("pair_full_roundtrip", |b| {
        b.iter(|| {
            let mut inviter = Inviter::new(
                SigningKey::generate(&mut OsRng),
                &mut OsRng,
                1_900_000_000,
                CapabilityScope::empty(),
            );
            let invite_bytes = inviter.invite_bytes();
            let (mut scanner, resp_bytes) = Scanner::scan(
                SigningKey::generate(&mut OsRng),
                black_box(&invite_bytes),
                100,
                &mut OsRng,
            )
            .unwrap();
            let _ = inviter.receive_response(&resp_bytes).unwrap();
            let (confirm_bytes, k_inviter) = inviter.confirm().unwrap();
            let k_scanner = scanner.receive_confirm(&confirm_bytes).unwrap();
            black_box((k_inviter, k_scanner));
        });
    });
}

fn bench_invite_decode_verify(c: &mut Criterion) {
    let inviter = Inviter::new(
        SigningKey::generate(&mut OsRng),
        &mut OsRng,
        1_900_000_000,
        CapabilityScope::empty(),
    );
    let bytes = inviter.invite_bytes();
    c.bench_function("invite_decode_and_verify", |b| {
        b.iter(|| {
            let inv = ol_pair_qr::Invite::decode_and_verify(black_box(&bytes)).unwrap();
            black_box(inv);
        });
    });
}

fn bench_sas_derive(c: &mut Criterion) {
    let t = ol_pair_qr::TranscriptHash::from_bytes([0x42; 32]);
    c.bench_function("sas_derive", |b| {
        b.iter(|| {
            let s = ol_pair_qr::Sas::derive(black_box(&t));
            black_box(s);
        });
    });
}

fn benchmarks() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_full_pair(&mut criterion);
    bench_invite_decode_verify(&mut criterion);
    bench_sas_derive(&mut criterion);
}

criterion_main!(benchmarks);

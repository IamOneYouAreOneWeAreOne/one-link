//! Microbenchmarks for the Row 6 cover-traffic primitives.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;
use rand::Rng;

use ol_onion::sphinx::core::{generate_static_keypair, SphinxHop};
use ol_onion::sphinx::cover::{
    build_cover_packet, is_cover_payload, CoverScheduler, RateEqualizer, COVER_SENTINEL,
    COVER_PAYLOAD_MIN,
};
use ol_onion::HopId;

fn make_relay() -> (curve25519_dalek::scalar::Scalar, SphinxHop) {
    let (sk, pk) = generate_static_keypair(&mut OsRng);
    let mut id = [0u8; 32];
    OsRng.fill(&mut id);
    (
        sk,
        SphinxHop {
            id: HopId::from_bytes(id),
            static_pk: pk,
        },
    )
}

fn bench_scheduler_next_wait(c: &mut Criterion) {
    let mut sched = CoverScheduler::new(1.0, [0x42; 32]);
    c.bench_function("cover::scheduler_next_wait_ms", |b| {
        b.iter(|| black_box(sched.next_wait_ms()));
    });
}

fn bench_is_cover_payload(c: &mut Criterion) {
    let cover = {
        let mut v = COVER_SENTINEL.to_vec();
        v.extend_from_slice(&[0u8; 256]);
        v
    };
    let real = vec![0xABu8; 256];
    c.bench_function("cover::is_cover_payload_true", |b| {
        b.iter(|| black_box(is_cover_payload(black_box(&cover))));
    });
    c.bench_function("cover::is_cover_payload_false", |b| {
        b.iter(|| black_box(is_cover_payload(black_box(&real))));
    });
}

fn bench_rate_equalizer_observe(c: &mut Criterion) {
    let mut eq = RateEqualizer::new(5.0);
    let mut counter: u64 = 1;
    c.bench_function("cover::rate_equalizer_observe_emit", |b| {
        b.iter(|| {
            eq.observe_real_emission(black_box(counter * 100));
            counter += 1;
        });
    });
}

fn bench_rate_equalizer_current_rate(c: &mut Criterion) {
    let mut eq = RateEqualizer::new(5.0);
    for i in 0..50 {
        eq.observe_real_emission(i * 200);
    }
    c.bench_function("cover::rate_equalizer_current_cover_rate", |b| {
        b.iter(|| black_box(eq.current_cover_rate()));
    });
}

fn bench_build_cover_packet_1_hop(c: &mut Criterion) {
    let (_, dest) = make_relay();
    let circuit = vec![dest];
    c.bench_function("cover::build_cover_packet_1_hop", |b| {
        b.iter(|| {
            let (eph_sk, _) = generate_static_keypair(&mut OsRng);
            let p = build_cover_packet(
                black_box(&eph_sk),
                black_box(&circuit),
                COVER_PAYLOAD_MIN,
                &mut OsRng,
            )
            .unwrap();
            black_box(p);
        });
    });
}

fn bench_build_cover_packet_3_hop(c: &mut Criterion) {
    let (_, r1) = make_relay();
    let (_, r2) = make_relay();
    let (_, dest) = make_relay();
    let circuit = vec![r1, r2, dest];
    c.bench_function("cover::build_cover_packet_3_hop", |b| {
        b.iter(|| {
            let (eph_sk, _) = generate_static_keypair(&mut OsRng);
            let p = build_cover_packet(
                black_box(&eph_sk),
                black_box(&circuit),
                256,
                &mut OsRng,
            )
            .unwrap();
            black_box(p);
        });
    });
}

criterion_group!(
    benches,
    bench_scheduler_next_wait,
    bench_is_cover_payload,
    bench_rate_equalizer_observe,
    bench_rate_equalizer_current_rate,
    bench_build_cover_packet_1_hop,
    bench_build_cover_packet_3_hop,
);
criterion_main!(benches);

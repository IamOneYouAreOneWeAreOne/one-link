//! Microbenchmarks for the Row 6 cover-traffic primitives.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;
use rand::Rng;

use ol_onion::sphinx::core::{generate_static_keypair, SphinxHop};
use ol_onion::sphinx::cover::{
    build_cover_packet, is_cover_payload_authenticated, CoverScheduler, RateEqualizer,
    COVER_PAYLOAD_MIN, COVER_SENTINEL, COVER_TRAILER_LEN,
};
use ol_onion::HopId;

const COVER_BENCH_KEY: [u8; 32] = [0xA5; 32];
const COVER_TRAILER_DOMAIN: &str = "ol-sphinx-cover-trailer-v1";

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
    let mut sched = CoverScheduler::new(1.0, [0x42; 32]).unwrap();
    c.bench_function("cover::scheduler_next_wait_ms", |b| {
        b.iter(|| black_box(sched.next_wait_ms()));
    });
}

fn authenticated_cover_payload(shared_key: &[u8; 32], body_len: usize) -> Vec<u8> {
    let mut payload = COVER_SENTINEL.to_vec();
    payload.extend((0..body_len).map(|i| u8::try_from(i % 251).unwrap()));

    let mac_key = blake3::derive_key(COVER_TRAILER_DOMAIN, shared_key);
    let mut hasher = blake3::Hasher::new_keyed(&mac_key);
    hasher.update(&payload);
    payload.extend_from_slice(&hasher.finalize().as_bytes()[..COVER_TRAILER_LEN]);
    payload
}

fn bench_is_cover_payload_authenticated(c: &mut Criterion) {
    let cover = authenticated_cover_payload(&COVER_BENCH_KEY, 256);
    let real = vec![0xABu8; cover.len()];
    let mut forged = cover.clone();
    *forged.last_mut().expect("authenticated trailer is present") ^= 0x01;

    assert!(is_cover_payload_authenticated(&COVER_BENCH_KEY, &cover));
    assert!(!is_cover_payload_authenticated(&COVER_BENCH_KEY, &real));
    assert!(!is_cover_payload_authenticated(&COVER_BENCH_KEY, &forged));

    c.bench_function("cover::is_cover_payload_authenticated_true", |b| {
        b.iter(|| {
            black_box(is_cover_payload_authenticated(
                black_box(&COVER_BENCH_KEY),
                black_box(&cover),
            ))
        });
    });
    c.bench_function("cover::is_cover_payload_authenticated_false_prefix", |b| {
        b.iter(|| {
            black_box(is_cover_payload_authenticated(
                black_box(&COVER_BENCH_KEY),
                black_box(&real),
            ))
        });
    });
    c.bench_function("cover::is_cover_payload_authenticated_bad_tag", |b| {
        b.iter(|| {
            black_box(is_cover_payload_authenticated(
                black_box(&COVER_BENCH_KEY),
                black_box(&forged),
            ))
        });
    });
}

fn bench_rate_equalizer_observe(c: &mut Criterion) {
    let mut eq = RateEqualizer::new(5.0).unwrap();
    let mut counter: u64 = 1;
    c.bench_function("cover::rate_equalizer_observe_emit", |b| {
        b.iter(|| {
            eq.observe_real_emission(black_box(counter * 100));
            counter += 1;
        });
    });
}

fn bench_rate_equalizer_current_rate(c: &mut Criterion) {
    let mut eq = RateEqualizer::new(5.0).unwrap();
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
            let p = build_cover_packet(black_box(&eph_sk), black_box(&circuit), 256, &mut OsRng)
                .unwrap();
            black_box(p);
        });
    });
}

// Criterion's macro generates the public group function, so the lint exception
// is confined to that generated item instead of the benchmark crate.
#[allow(missing_docs)]
mod criterion_benchmark_harness {
    use super::{
        bench_build_cover_packet_1_hop, bench_build_cover_packet_3_hop,
        bench_is_cover_payload_authenticated, bench_rate_equalizer_current_rate,
        bench_rate_equalizer_observe, bench_scheduler_next_wait, criterion_group,
    };

    criterion_group!(
        benches,
        bench_scheduler_next_wait,
        bench_is_cover_payload_authenticated,
        bench_rate_equalizer_observe,
        bench_rate_equalizer_current_rate,
        bench_build_cover_packet_1_hop,
        bench_build_cover_packet_3_hop,
    );
}
criterion_main!(criterion_benchmark_harness::benches);

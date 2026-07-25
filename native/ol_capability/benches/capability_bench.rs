//! Criterion benchmarks for `ol_capability`.
//!
//! ADR-0021 claims: "HMAC chain is fast (~200 ns per caveat at BLAKE3
//! speed)". These benches measure root mint, attenuate, verify (chain
//! length 0/1/4/16), and wire encode/decode round trip.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ol_capability::{Capability, Caveat, Context, CAP_ID_LEN, ROOT_KEY_LEN};
use zeroize::Zeroizing;

fn fixed_root() -> Zeroizing<[u8; ROOT_KEY_LEN]> {
    Zeroizing::new([0x42u8; ROOT_KEY_LEN])
}
fn fixed_id() -> [u8; CAP_ID_LEN] {
    [0xCDu8; CAP_ID_LEN]
}

fn bench_root_mint(c: &mut Criterion) {
    let root = fixed_root();
    let id = fixed_id();
    c.bench_function("root_mint", |b| {
        b.iter(|| {
            let cap = Capability::root(black_box(id), black_box(&root));
            black_box(cap);
        });
    });
}

fn bench_attenuate(c: &mut Criterion) {
    let root = fixed_root();
    let cap = Capability::root(fixed_id(), &root);
    c.bench_function("attenuate_one_caveat", |b| {
        b.iter(|| {
            let attenuated = black_box(&cap)
                .attenuate(Caveat::ExpiresAt(black_box(1_000_000)))
                .unwrap();
            black_box(attenuated);
        });
    });
}

fn bench_verify_chain(c: &mut Criterion) {
    let root = fixed_root();
    let ctx = Context::new()
        .with_now(500_000)
        .with_path("/folder/file")
        .with_operation("read")
        .with_peer([0x77u8; 32]);

    let mut group = c.benchmark_group("verify_chain_length");
    for len in &[0usize, 1, 4, 16] {
        let mut cap = Capability::root(fixed_id(), &root);
        for i in 0..*len {
            let cav = match i % 5 {
                0 => Caveat::ExpiresAt(1_000_000),
                1 => Caveat::PathPrefix("/folder".to_string()),
                2 => Caveat::OperationIn(vec!["read".into(), "list".into()]),
                3 => Caveat::PeerFingerprint([0x77u8; 32]),
                _ => Caveat::AuditTag("audit".to_string()),
            };
            cap = cap.attenuate(cav).unwrap();
        }
        group.bench_with_input(BenchmarkId::from_parameter(len), len, |b, _| {
            b.iter(|| {
                let r = black_box(&cap).verify(black_box(&root), black_box(&ctx));
                black_box(r.is_ok());
            });
        });
    }
    group.finish();
}

fn bench_wire_round_trip(c: &mut Criterion) {
    let root = fixed_root();
    let cap = Capability::root(fixed_id(), &root)
        .attenuate(Caveat::ExpiresAt(1_000_000))
        .unwrap()
        .attenuate(Caveat::PathPrefix("/folder".to_string()))
        .unwrap()
        .attenuate(Caveat::OperationIn(vec!["read".into()]))
        .unwrap()
        .attenuate(Caveat::AuditTag("alice".into()))
        .unwrap();
    c.bench_function("encode_4_caveats", |b| {
        b.iter(|| {
            let bytes = black_box(&cap).encode();
            black_box(bytes);
        });
    });
    let bytes = cap.encode();
    c.bench_function("decode_4_caveats", |b| {
        b.iter(|| {
            let decoded = Capability::decode(black_box(&bytes)).unwrap();
            black_box(decoded);
        });
    });
}

// Criterion's macro generates the public group function, so the lint exception
// is confined to that generated item instead of the benchmark crate.
#[allow(missing_docs)]
mod criterion_benchmark_harness {
    use super::{
        bench_attenuate, bench_root_mint, bench_verify_chain, bench_wire_round_trip,
        criterion_group,
    };

    criterion_group!(
        benches,
        bench_root_mint,
        bench_attenuate,
        bench_verify_chain,
        bench_wire_round_trip
    );
}
criterion_main!(criterion_benchmark_harness::benches);

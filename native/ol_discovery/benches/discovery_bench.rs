//! Criterion benchmark for ol_discovery primitives.
//!
//! Establishes baseline throughput for hot ops:
//!   - NodeId XOR distance
//!   - Routing-table insert (bucket bookkeeping)
//!   - Routing-table closest_to (sort over a populated table)
//!   - Record sign + verify (Ed25519 cost)

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use ed25519_dalek::SigningKey;

use ol_discovery::node_id::NodeId;
use ol_discovery::record::{PeerRecord, SignedRecord};
use ol_discovery::routing::RoutingTable;

fn bench_xor_distance(c: &mut Criterion) {
    let a = NodeId([0xAA; 32]);
    let b = NodeId([0x55; 32]);
    c.bench_function("node_id/distance", |bch| {
        bch.iter(|| black_box(a).distance(black_box(&b)));
    });
    c.bench_function("node_id/xor_leading_zeros", |bch| {
        bch.iter(|| black_box(a).xor_leading_zeros(black_box(&b)));
    });
    c.bench_function("node_id/bucket_index", |bch| {
        bch.iter(|| black_box(a).bucket_index(black_box(&b)));
    });
}

fn bench_routing_insert(c: &mut Criterion) {
    c.bench_function("routing/insert_into_empty", |bch| {
        bch.iter_with_setup(
            || RoutingTable::new(NodeId([0x00; 32])),
            |mut t| {
                let _ = t.insert(NodeId([0xAA; 32]), 0);
                t
            },
        );
    });
    // Populate a table to a realistic size, then bench insert.
    c.bench_function("routing/insert_into_populated_100", |bch| {
        bch.iter_with_setup(
            || {
                let mut t = RoutingTable::new(NodeId([0x00; 32]));
                for i in 1u8..=100 {
                    let _ = t.insert(NodeId([i; 32]), i as u64);
                }
                t
            },
            |mut t| {
                let _ = t.insert(NodeId([0x42; 32]), 200);
                t
            },
        );
    });
}

fn bench_routing_closest_to(c: &mut Criterion) {
    let target = NodeId([0xFF; 32]);
    for &n in &[16usize, 64, 256, 1024] {
        let mut t = RoutingTable::new(NodeId([0x00; 32]));
        for i in 0..n {
            let mut id = [0u8; 32];
            id[0] = (i & 0xFF) as u8;
            id[1] = ((i >> 8) & 0xFF) as u8;
            // Skip self.
            if id != [0u8; 32] {
                let _ = t.insert(NodeId(id), i as u64);
            }
        }
        let label = format!("routing/closest_to_n_{n}");
        c.bench_function(&label, |bch| {
            bch.iter(|| t.closest_to(black_box(&target)));
        });
    }
}

fn bench_record_sign(c: &mut Criterion) {
    use rand_core::OsRng;
    let sk = SigningKey::generate(&mut OsRng);
    let rec = PeerRecord {
        publisher_pubkey: sk.verifying_key().to_bytes(),
        endpoints: vec!["udp://1.2.3.4:5678".into()],
        publish_time_unix: 1_700_000_000,
        ttl_secs: 86_400,
    };
    c.bench_function("record/sign", |bch| {
        bch.iter(|| {
            let r = rec.clone();
            black_box(SignedRecord::sign(r, &sk).unwrap())
        });
    });
}

fn bench_record_verify(c: &mut Criterion) {
    use rand_core::OsRng;
    let sk = SigningKey::generate(&mut OsRng);
    let rec = PeerRecord {
        publisher_pubkey: sk.verifying_key().to_bytes(),
        endpoints: vec!["udp://1.2.3.4:5678".into()],
        publish_time_unix: 1_700_000_000,
        ttl_secs: 86_400,
    };
    let signed = SignedRecord::sign(rec, &sk).unwrap();
    c.bench_function("record/verify", |bch| {
        bch.iter(|| black_box(&signed).verify().unwrap());
    });
}

fn bench_canonical_bytes(c: &mut Criterion) {
    use rand_core::OsRng;
    let sk = SigningKey::generate(&mut OsRng);
    let rec = PeerRecord {
        publisher_pubkey: sk.verifying_key().to_bytes(),
        endpoints: vec!["udp://1.2.3.4:5678".into(), "quic://5.6.7.8:9012".into()],
        publish_time_unix: 1_700_000_000,
        ttl_secs: 86_400,
    };
    c.bench_function("record/canonical_bytes", |bch| {
        bch.iter(|| black_box(&rec).canonical_bytes());
    });
}

fn bench_synthetic_id(c: &mut Criterion) {
    let t = RoutingTable::new(NodeId([0x00; 32]));
    c.bench_function("routing/synthetic_id_for_bucket_mid", |bch| {
        bch.iter(|| t.synthetic_id_for_bucket(black_box(128)));
    });
}

fn bench_stale_buckets_query(c: &mut Criterion) {
    // Populate a routing table to a realistic size, then bench the
    // maintenance hot-path: `stale_buckets(now, max_age)`.
    let mut t = RoutingTable::new(NodeId([0x00; 32]));
    for i in 1u16..=512 {
        let mut id = [0u8; 32];
        id[0] = (i & 0xFF) as u8;
        id[1] = ((i >> 8) & 0xFF) as u8;
        let _ = t.insert(NodeId(id), 1_000 + i as u64);
    }
    c.bench_function("routing/stale_buckets_n_512", |bch| {
        bch.iter(|| t.stale_buckets(black_box(10_000), black_box(3600)));
    });
}

criterion_group!(
    benches,
    bench_xor_distance,
    bench_routing_insert,
    bench_routing_closest_to,
    bench_record_sign,
    bench_record_verify,
    bench_canonical_bytes,
    bench_synthetic_id,
    bench_stale_buckets_query,
);
criterion_main!(benches);

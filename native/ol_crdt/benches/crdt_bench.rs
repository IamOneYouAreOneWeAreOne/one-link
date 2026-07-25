//! Criterion benchmarks for `ol_crdt`.
//!
//! The folder merge is the engine's foundation for the "every state
//! change is CRDT-mergeable" doctrine — daemon gossip will invoke it on
//! every sync round, so it must stay cheap at realistic state sizes.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ol_crdt::{Folder, Lattice, ReplicaId};

fn rid(b: u8) -> ReplicaId {
    ReplicaId([b; 32])
}
fn fid(i: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..4].copy_from_slice(&i.to_le_bytes());
    out
}

fn build_folder(n: usize, replica: u8) -> Folder {
    let r = rid(replica);
    let mut f = Folder::new();
    for i in 0..n {
        let file_id = u32::try_from(i).expect("benchmark folder sizes fit in u32");
        let scalar = u64::try_from(i).expect("supported Rust pointer widths fit in u64");
        f.add_file(
            &r,
            fid(file_id),
            format!("f{i}.bin"),
            scalar * 1024,
            scalar * 7,
        );
    }
    f
}

fn bench_add_file(c: &mut Criterion) {
    c.bench_function("add_file_to_empty", |b| {
        b.iter(|| {
            let mut f = Folder::new();
            f.add_file(&rid(1), fid(black_box(0)), "f.bin".into(), 1024, 100);
            black_box(f);
        });
    });
}

fn bench_merge_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("merge_size");
    for n in &[10usize, 100, 1000] {
        let a = build_folder(*n, 0x01);
        let b = build_folder(*n, 0x02);
        group.bench_with_input(BenchmarkId::from_parameter(n), n, |bench, _| {
            bench.iter(|| {
                let mut left = a.clone();
                left.merge(black_box(&b));
                black_box(left);
            });
        });
    }
    group.finish();
}

fn bench_contains(c: &mut Criterion) {
    let f = build_folder(1000, 0x01);
    c.bench_function("contains_hit_among_1000", |b| {
        b.iter(|| {
            let hit = black_box(&f).contains(black_box(&fid(500)));
            black_box(hit);
        });
    });
}

// Criterion's macro generates the public group function, so the lint exception
// is confined to that generated item instead of the benchmark crate.
#[allow(missing_docs)]
mod criterion_benchmark_harness {
    use super::{bench_add_file, bench_contains, bench_merge_scaling, criterion_group};

    criterion_group!(benches, bench_add_file, bench_merge_scaling, bench_contains);
}
criterion_main!(criterion_benchmark_harness::benches);

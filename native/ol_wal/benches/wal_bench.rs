//! Throughput benchmarks for `ol_wal`.
//!
//! Measures group-commit throughput at varying batch sizes. The chunk
//! store layers above sit on top of these numbers; group commit is what
//! makes 10K+ logical writes/s/thread possible per ADR-0005.
//!
//! Run:
//!   cargo bench -p `ol_wal` --bench `wal_bench`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ol_wal::{LogKind, Record, Wal};
use tempfile::tempdir;

fn rec(payload_len: usize) -> Record {
    Record {
        kind: 0x01,
        flags: 0x00,
        payload: vec![0xABu8; payload_len],
    }
}

fn bench_group_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("wal_group_commit");

    for &(batch_size, payload_kib) in &[(1usize, 1usize), (16, 1), (128, 1), (16, 64), (128, 64)] {
        let payload_bytes = payload_kib * 1024;
        let total_bytes = batch_size as u64 * payload_bytes as u64;
        group.throughput(Throughput::Bytes(total_bytes));
        group.bench_with_input(
            BenchmarkId::new(
                format!("batch={batch_size},payload={payload_kib}KiB"),
                batch_size,
            ),
            &(batch_size, payload_bytes),
            |b, &(batch_size, payload_bytes)| {
                b.iter_with_setup(
                    || {
                        let dir = tempdir().expect("tempdir");
                        let wal = Wal::create(dir.path(), LogKind::ChunkLog).expect("create wal");
                        (dir, wal)
                    },
                    |(_dir, mut wal)| {
                        for _ in 0..batch_size {
                            wal.append(black_box(&rec(payload_bytes))).expect("append");
                        }
                        wal.flush().expect("flush");
                    },
                );
            },
        );
    }
    group.finish();
}

// Criterion's macro generates the public group function, so the lint exception
// is confined to that generated item instead of the benchmark crate.
#[allow(missing_docs)]
mod criterion_benchmark_harness {
    use super::{bench_group_commit, criterion_group};

    criterion_group!(benches, bench_group_commit);
}
criterion_main!(criterion_benchmark_harness::benches);

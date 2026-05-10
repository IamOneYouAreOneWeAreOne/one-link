//! Throughput benchmarks for `ol_chunk_store`.
//!
//! Measures the integrating layer at the same dimensions Phase A1's
//! acceptance gate cares about: chunk-write rate (with manifest WAL
//! coupling) and chunk-read latency.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ol_chunk_store::{
    ChunkAddressKind, ChunkAeadKind, ChunkRecord, ChunkRecordKind, ChunkStore, ManifestRecord,
    ManifestRecordKind, StripeDescriptor,
};
use tempfile::tempdir;

fn make_chunk(id_byte: u8, plaintext_len: u32) -> ChunkRecord {
    let mut chunk_id = [0u8; 32];
    chunk_id[0] = id_byte;
    chunk_id[1] = 0xAA;
    let ct_len = plaintext_len as usize + ((plaintext_len as usize + 16383) / 16384) * 16;
    ChunkRecord {
        kind: ChunkRecordKind::ChunkBlob,
        address_kind: ChunkAddressKind::Raw,
        aead_kind: ChunkAeadKind::AesGcm256,
        compressed: false,
        format_aware: false,
        length_plaintext: plaintext_len,
        chunk_id,
        ratchet_key_id: [0x55u8; 16],
        stripe_descriptor: StripeDescriptor::NONE,
        ciphertext: vec![0xCDu8; ct_len],
    }
}

fn bench_write_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunk_store_write");
    for &(batch_size, plaintext_kib) in &[(1usize, 64usize), (16, 64), (128, 64), (16, 4)] {
        let plaintext_bytes = (plaintext_kib * 1024) as u32;
        let total_bytes = batch_size as u64 * u64::from(plaintext_bytes);
        group.throughput(Throughput::Bytes(total_bytes));
        group.bench_with_input(
            BenchmarkId::new(
                format!("batch={batch_size},plaintext={plaintext_kib}KiB"),
                batch_size,
            ),
            &(batch_size, plaintext_bytes),
            |b, &(batch_size, plaintext_bytes)| {
                b.iter_with_setup(
                    || tempdir().expect("tempdir"),
                    |dir| {
                        let mut store = ChunkStore::open(dir.path()).expect("open");
                        for i in 0..batch_size {
                            let r = make_chunk((i & 0xFF) as u8, plaintext_bytes);
                            store.append_chunk(black_box(&r)).expect("append");
                        }
                        store
                            .append_manifest(&ManifestRecord {
                                kind: ManifestRecordKind::ManifestVersion,
                                flags: 0,
                                hlc_timestamp: 1,
                                actor_id: [0u8; 32],
                                chunk_log_anchor: 0,
                                body: b"batch".to_vec(),
                            })
                            .expect("append manifest");
                        store.flush().expect("flush");
                    },
                );
            },
        );
    }
    group.finish();
}

fn bench_read_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunk_store_read");
    let dir = tempdir().unwrap();
    let mut store = ChunkStore::open(dir.path()).unwrap();
    // Pre-populate 1024 chunks at 64 KiB each.
    let mut ids = Vec::new();
    for i in 0u32..1024 {
        let mut r = make_chunk(0, 64 * 1024);
        r.chunk_id[0..4].copy_from_slice(&i.to_le_bytes());
        store.append_chunk(&r).unwrap();
        ids.push(r.chunk_id);
    }
    store.flush().unwrap();

    group.bench_function("read_random", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let id = ids[idx % ids.len()];
            idx = idx.wrapping_add(101); // pseudo-random stride coprime with len
            let r = store.read_chunk(black_box(&id)).expect("read");
            black_box(r);
        });
    });
    group.bench_function("locate_random", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let id = ids[idx % ids.len()];
            idx = idx.wrapping_add(101);
            let loc = store.locate_chunk(black_box(&id));
            black_box(loc);
        });
    });
    group.bench_function("has_random", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let id = ids[idx % ids.len()];
            idx = idx.wrapping_add(101);
            let h = store.has_chunk(black_box(&id));
            black_box(h);
        });
    });
    group.finish();
}

fn bench_replay(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunk_store_replay");
    for &count in &[100usize, 1000, 5000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &count,
            |b, &count| {
                b.iter_with_setup(
                    || {
                        let dir = tempdir().unwrap();
                        {
                            let mut store = ChunkStore::open(dir.path()).unwrap();
                            for i in 0..count {
                                let mut r = make_chunk(0, 4 * 1024);
                                r.chunk_id[0..4].copy_from_slice(&(i as u32).to_le_bytes());
                                store.append_chunk(&r).unwrap();
                            }
                            store.flush().unwrap();
                        }
                        dir
                    },
                    |dir| {
                        let store = ChunkStore::open(dir.path()).unwrap();
                        black_box(store.stats());
                    },
                );
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_write_throughput, bench_read_latency, bench_replay);
criterion_main!(benches);

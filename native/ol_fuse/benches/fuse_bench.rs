//! Criterion benchmarks for the in-memory `FilesystemBackend` reference
//! implementation. The numbers establish a baseline for the daemon's
//! future chunk-store-backed implementation: any wired backend should
//! match these or do better on the same workload shape.

// The criterion_group! macro expands to an undocumented public function;
// the workspace lints flag it. Silence locally — generated code.
#![allow(missing_docs)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ol_fuse::{FilesystemBackend, MemoryBackend};

fn populate(fs: &MemoryBackend, n: usize) {
    let payload = vec![0xABu8; 4096];
    for i in 0..n {
        let path = format!("dir/file_{i:04}.bin");
        fs.write(&path, 0, &payload).unwrap();
    }
}

fn bench_getattr(c: &mut Criterion) {
    let fs = MemoryBackend::new();
    populate(&fs, 1000);
    c.bench_function("getattr/file_present", |b| {
        b.iter(|| {
            let s = fs.getattr(black_box("dir/file_0500.bin")).unwrap();
            black_box(s);
        });
    });
    c.bench_function("getattr/file_missing", |b| {
        b.iter(|| {
            let s = fs.getattr(black_box("dir/file_9999.bin"));
            black_box(s).err();
        });
    });
}

fn bench_read(c: &mut Criterion) {
    let fs = MemoryBackend::new();
    let payload = vec![0xCCu8; 64 * 1024]; // 64 KiB
    fs.write("big.bin", 0, &payload).unwrap();
    c.bench_function("read/4KiB_at_offset_0", |b| {
        b.iter(|| {
            let bytes = fs.read(black_box("big.bin"), 0, 4096).unwrap();
            black_box(bytes);
        });
    });
    c.bench_function("read/16KiB_at_offset_8192", |b| {
        b.iter(|| {
            let bytes = fs.read(black_box("big.bin"), 8192, 16384).unwrap();
            black_box(bytes);
        });
    });
}

fn bench_readdir(c: &mut Criterion) {
    let fs = MemoryBackend::new();
    populate(&fs, 200);
    c.bench_function("readdir/200_files", |b| {
        b.iter(|| {
            let entries = fs.readdir(black_box("dir")).unwrap();
            black_box(entries);
        });
    });
}

fn bench_write(c: &mut Criterion) {
    let fs = MemoryBackend::new();
    let payload = vec![0xFFu8; 4096];
    c.bench_function("write/4KiB_overwrite", |b| {
        b.iter(|| {
            let n = fs
                .write(black_box("scratch.bin"), 0, black_box(&payload))
                .unwrap();
            black_box(n);
        });
    });
}

criterion_group!(
    benches,
    bench_getattr,
    bench_read,
    bench_readdir,
    bench_write
);
criterion_main!(benches);

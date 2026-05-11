use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ol_grammar::{compress, decompress};

fn bench_compress(c: &mut Criterion) {
    let mut group = c.benchmark_group("compress");
    for n in &[128usize, 512, 2048] {
        let input: Vec<u8> = (b"abcdef").iter().cycle().take(*n).copied().collect();
        group.bench_with_input(BenchmarkId::from_parameter(n), n, |b, _| {
            b.iter(|| {
                let g = compress(black_box(&input));
                black_box(g);
            });
        });
    }
    group.finish();
}

fn bench_decompress(c: &mut Criterion) {
    let input: Vec<u8> = b"abcdef".iter().cycle().take(2048).copied().collect();
    let grammar = compress(&input);
    c.bench_function("decompress_2KB", |b| {
        b.iter(|| {
            let out = decompress(black_box(&grammar)).unwrap();
            black_box(out);
        });
    });
}

criterion_group!(benches, bench_compress, bench_decompress);
criterion_main!(benches);

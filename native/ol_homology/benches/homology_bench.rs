use std::collections::HashMap;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ol_homology::{components_of, fragility_score};

fn build_chain(n: usize) -> (Vec<String>, Vec<(String, String)>) {
    let nodes: Vec<String> = (0..n).map(|i| format!("c{}", i)).collect();
    let edges: Vec<(String, String)> = (0..n.saturating_sub(1))
        .map(|i| (nodes[i].clone(), nodes[i + 1].clone()))
        .collect();
    (nodes, edges)
}

fn bench_components(c: &mut Criterion) {
    let mut group = c.benchmark_group("components_of");
    for n in &[16usize, 64, 256] {
        let (nodes, edges) = build_chain(*n);
        group.bench_with_input(BenchmarkId::from_parameter(n), n, |b, _| {
            b.iter(|| {
                let r = components_of(black_box(&nodes), black_box(&edges));
                black_box(r);
            });
        });
    }
    group.finish();
}

fn bench_fragility(c: &mut Criterion) {
    let mut group = c.benchmark_group("fragility_score");
    for n in &[16usize, 64, 128] {
        let (nodes, edges) = build_chain(*n);
        let holders: HashMap<String, usize> = nodes.iter().map(|n| (n.clone(), 2)).collect();
        group.bench_with_input(BenchmarkId::from_parameter(n), n, |b, _| {
            b.iter(|| {
                let r = fragility_score(black_box(&nodes), black_box(&edges), black_box(&holders));
                black_box(r);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_components, bench_fragility);
criterion_main!(benches);

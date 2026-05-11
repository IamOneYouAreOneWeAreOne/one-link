//! Criterion benchmarks for `ol_routing`.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ol_routing::{edge_cost, edge_weight, loss_penalty, shortest_path, AdjacencyGraph};

fn bench_edge_math(c: &mut Criterion) {
    c.bench_function("edge_weight", |b| {
        b.iter(|| {
            let w = edge_weight(black_box(0.001), black_box(100.0));
            black_box(w);
        });
    });
    c.bench_function("loss_penalty", |b| {
        b.iter(|| {
            let p = loss_penalty(black_box(0.5));
            black_box(p);
        });
    });
    c.bench_function("edge_cost", |b| {
        b.iter(|| {
            let c2 = edge_cost(black_box(0.001), black_box(100.0), black_box(0.5));
            black_box(c2);
        });
    });
}

fn build_grid(n: usize) -> AdjacencyGraph {
    let mut g = AdjacencyGraph::new();
    for i in 0..n {
        for j in 0..n {
            let me = format!("n_{}_{}", i, j);
            if i + 1 < n {
                let down = format!("n_{}_{}", i + 1, j);
                g.add_edge(me.clone(), down.clone(), edge_cost(0.001, 100.0, 0.0));
                g.add_edge(down, me.clone(), edge_cost(0.001, 100.0, 0.0));
            }
            if j + 1 < n {
                let right = format!("n_{}_{}", i, j + 1);
                g.add_edge(me.clone(), right.clone(), edge_cost(0.001, 100.0, 0.0));
                g.add_edge(right, me, edge_cost(0.001, 100.0, 0.0));
            }
        }
    }
    g
}

fn bench_shortest_path_grid(c: &mut Criterion) {
    let mut group = c.benchmark_group("shortest_path_grid");
    for n in &[8usize, 16, 32] {
        let g = build_grid(*n);
        let start = "n_0_0".to_string();
        let goal = format!("n_{}_{}", n - 1, n - 1);
        group.bench_with_input(BenchmarkId::from_parameter(n), n, |b, _| {
            b.iter(|| {
                let r = shortest_path(&g, &start, &goal).unwrap();
                black_box(r);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_edge_math, bench_shortest_path_grid);
criterion_main!(benches);

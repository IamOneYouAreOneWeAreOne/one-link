//! Criterion benchmarks for `ol_codegen`.
//!
//! Tracks parser + emitter throughput for both struct and enum
//! declarations. Numbers are not a release gate; the criterion
//! report is used to catch regressions PR-over-PR.

// The criterion_group! macro expands to an undocumented public function;
// the workspace lints flag it. Silence locally — generated code.
#![allow(missing_docs)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ol_codegen::{
    emit_rust_enum, emit_rust_struct, parse_enum, parse_struct, EmitOptions,
};

const STRUCT_SMALL: &str = "struct Cap { id: [u8; 32], not_after: u64 }";
const STRUCT_WIDE: &str = "struct Wide { a: u8, b: u16, c: u32, d: u64, e: [u8; 32], f: String, g: u32, h: u64 }";
const ENUM_MIXED: &str = "enum Caveat { NotAfter(u64), Scope(String), Audit([u8; 32]), Sentinel }";

fn bench_parser(c: &mut Criterion) {
    c.bench_function("parse_struct/small", |b| {
        b.iter(|| {
            let p = parse_struct(black_box(STRUCT_SMALL)).unwrap();
            black_box(p);
        });
    });
    c.bench_function("parse_struct/wide", |b| {
        b.iter(|| {
            let p = parse_struct(black_box(STRUCT_WIDE)).unwrap();
            black_box(p);
        });
    });
    c.bench_function("parse_enum/mixed", |b| {
        b.iter(|| {
            let p = parse_enum(black_box(ENUM_MIXED)).unwrap();
            black_box(p);
        });
    });
}

fn bench_emitter(c: &mut Criterion) {
    let small = parse_struct(STRUCT_SMALL).unwrap();
    let wide = parse_struct(STRUCT_WIDE).unwrap();
    let enum_mixed = parse_enum(ENUM_MIXED).unwrap();
    let opts = EmitOptions::default();
    c.bench_function("emit_rust_struct/small", |b| {
        b.iter(|| {
            let out = emit_rust_struct(black_box(&small), black_box(&opts)).unwrap();
            black_box(out);
        });
    });
    c.bench_function("emit_rust_struct/wide", |b| {
        b.iter(|| {
            let out = emit_rust_struct(black_box(&wide), black_box(&opts)).unwrap();
            black_box(out);
        });
    });
    c.bench_function("emit_rust_enum/mixed", |b| {
        b.iter(|| {
            let out = emit_rust_enum(black_box(&enum_mixed), black_box(&opts)).unwrap();
            black_box(out);
        });
    });
}

criterion_group!(benches, bench_parser, bench_emitter);
criterion_main!(benches);

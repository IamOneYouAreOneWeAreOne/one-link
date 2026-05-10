//! Throughput benchmarks for `ol_aead`.
//!
//! Phase A1 acceptance gate per [ADR-0002](../../../docs/decisions/0002-aead-frame.md):
//! ≥ 4 GiB/s/core (AES-NI) or ≥ 3 GiB/s/core (ChaCha20-Poly1305) on
//! 64 KiB chunk encrypt + decrypt.
//!
//! Run:
//!   cargo bench -p ol_aead --bench aead_bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ol_aead::{
    cipher::{AeadCipher, AeadKind},
    decrypt_chunk, encrypt_chunk,
    key::ChunkAeadKey,
};

fn fill_pseudo_random(buf: &mut [u8], mut state: u64) {
    for byte in buf.iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = (state & 0xFF) as u8;
    }
}

fn bench_chunk_encrypt(c: &mut Criterion) {
    let key = ChunkAeadKey::from_bytes([0x42u8; 32]);
    let chunk_id = [0x01u8; 32];
    let mut group = c.benchmark_group("chunk_encrypt");

    for size_kib in [16usize, 64, 256] {
        let n = size_kib * 1024;
        let mut buf = vec![0u8; n];
        fill_pseudo_random(&mut buf, 0xCAFE_BABE_u64.wrapping_add(size_kib as u64));
        group.throughput(Throughput::Bytes(n as u64));
        for kind in [AeadKind::AesGcm256, AeadKind::ChaCha20Poly1305] {
            let cipher = AeadCipher::with_kind(kind, &key);
            let label = match kind {
                AeadKind::AesGcm256 => "aes",
                AeadKind::ChaCha20Poly1305 => "chacha",
            };
            group.bench_with_input(
                BenchmarkId::new(label, size_kib),
                &(cipher.clone(), buf.clone()),
                |b, (cipher, buf)| {
                    b.iter(|| {
                        let ct = encrypt_chunk(black_box(cipher), black_box(&chunk_id), black_box(buf))
                            .expect("encrypt");
                        black_box(ct);
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_chunk_decrypt(c: &mut Criterion) {
    let key = ChunkAeadKey::from_bytes([0x42u8; 32]);
    let chunk_id = [0x02u8; 32];
    let mut group = c.benchmark_group("chunk_decrypt");

    for size_kib in [16usize, 64, 256] {
        let n = size_kib * 1024;
        let mut buf = vec![0u8; n];
        fill_pseudo_random(&mut buf, 0xF00D_BABE_u64.wrapping_add(size_kib as u64));
        group.throughput(Throughput::Bytes(n as u64));
        for kind in [AeadKind::AesGcm256, AeadKind::ChaCha20Poly1305] {
            let cipher = AeadCipher::with_kind(kind, &key);
            let ct = encrypt_chunk(&cipher, &chunk_id, &buf).expect("encrypt for decrypt bench");
            let label = match kind {
                AeadKind::AesGcm256 => "aes",
                AeadKind::ChaCha20Poly1305 => "chacha",
            };
            group.bench_with_input(
                BenchmarkId::new(label, size_kib),
                &(cipher.clone(), ct.clone(), buf.len()),
                |b, (cipher, ct, plaintext_len)| {
                    b.iter(|| {
                        let pt = decrypt_chunk(
                            black_box(cipher),
                            black_box(&chunk_id),
                            black_box(*plaintext_len),
                            black_box(ct),
                        )
                        .expect("decrypt");
                        black_box(pt);
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_chunk_encrypt, bench_chunk_decrypt);
criterion_main!(benches);

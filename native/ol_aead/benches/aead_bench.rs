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
    decrypt_chunk, encrypt_chunk, encrypt_chunks_par,
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

/// Parallel multi-chunk encryption throughput. Compare sequential vs
/// `encrypt_chunks_par` over batches of 32 / 128 chunks at 64 KiB each.
fn bench_par_encrypt(c: &mut Criterion) {
    let key = ChunkAeadKey::from_bytes([0xCDu8; 32]);
    let cipher = AeadCipher::with_kind(AeadKind::AesGcm256, &key);
    let chunk_size = 64 * 1024usize;

    let mut group = c.benchmark_group("aead_par_encrypt");
    for &n_chunks in &[32usize, 128] {
        let mut ids: Vec<[u8; 32]> = Vec::with_capacity(n_chunks);
        let mut bufs: Vec<Vec<u8>> = Vec::with_capacity(n_chunks);
        for i in 0..n_chunks {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&(i as u32).to_le_bytes());
            ids.push(id);
            let mut b = vec![0u8; chunk_size];
            fill_pseudo_random(&mut b, 0x9E37_79B9_u64.wrapping_add(i as u64));
            bufs.push(b);
        }
        group.throughput(Throughput::Bytes((n_chunks * chunk_size) as u64));

        // Sequential reference.
        let ids_ref = ids.clone();
        let bufs_ref = bufs.clone();
        let cipher_seq = cipher.clone();
        group.bench_with_input(
            BenchmarkId::new("seq", n_chunks),
            &(cipher_seq, ids_ref, bufs_ref),
            |b, (cipher, ids, bufs)| {
                b.iter(|| {
                    for (id, buf) in ids.iter().zip(bufs.iter()) {
                        let ct = encrypt_chunk(black_box(cipher), black_box(id), black_box(buf)).unwrap();
                        black_box(ct);
                    }
                });
            },
        );

        // Parallel via rayon.
        let cipher_par = cipher.clone();
        let ids_par = ids.clone();
        let bufs_par = bufs.clone();
        group.bench_with_input(
            BenchmarkId::new("par", n_chunks),
            &(cipher_par, ids_par, bufs_par),
            |b, (cipher, ids, bufs)| {
                b.iter(|| {
                    let inputs: Vec<(&[u8; 32], &[u8])> = ids
                        .iter()
                        .zip(bufs.iter())
                        .map(|(id, buf)| (id, buf.as_slice()))
                        .collect();
                    let cts = encrypt_chunks_par(black_box(cipher), &inputs).unwrap();
                    black_box(cts);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_chunk_encrypt, bench_chunk_decrypt, bench_par_encrypt);
criterion_main!(benches);

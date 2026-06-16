//! Loopback latency benchmarks for `ol_transfer::TransferEngine`.
//!
//! Pins the Phase B baseline for the integrated chunk-fetch path:
//!
//! - `fetch_chunk_local` — the chunk is already in the receiver's store
//!   (no transport round trip). Measures the read-local fast path.
//! - `fetch_chunk_warm` — fresh fetch from a paired peer over a warm
//!   cached connection. Measures the QUIC round-trip + chunk_store
//!   append + flush cost.
//! - `fetch_many_warm_serial` — 16 chunks fetched serially over a warm
//!   connection. Measures throughput on a small batch.
//! - `bloom_handshake_warm` — bloom round trip with a 1000-chunk
//!   manifest scope.

use std::sync::{Arc, RwLock};

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use ol_chunk_store::{
    ChunkAddressKind, ChunkAeadKind, ChunkRecord, ChunkRecordKind, ChunkStore, StripeDescriptor,
};
use ol_quic::{Endpoint, EndpointConfig, Identity, PeerFingerprint, PeerRegistry};
use ol_transfer::{TransferConfig, TransferEngine};
use tempfile::TempDir;
use tokio::runtime::Runtime;

#[derive(Debug)]
struct AlwaysPair;

impl PeerRegistry for AlwaysPair {
    fn is_paired_peer(&self, _: &PeerFingerprint) -> bool {
        true
    }
}

fn fast_config() -> EndpointConfig {
    EndpointConfig {
        bind: "127.0.0.1:0".parse().expect("valid bind"),
        idle_timeout_ms: 30_000,
        keepalive_interval_ms: 5_000,
        ..Default::default()
    }
}

fn mk_record(seed: u32, plaintext_len: u32) -> ChunkRecord {
    let mut chunk_id = [0u8; 32];
    chunk_id[..4].copy_from_slice(&seed.to_le_bytes());
    chunk_id[31] = 0xCD;
    ChunkRecord {
        kind: ChunkRecordKind::ChunkBlob,
        address_kind: ChunkAddressKind::Raw,
        aead_kind: ChunkAeadKind::AesGcm256,
        compressed: false,
        format_aware: false,
        length_plaintext: plaintext_len,
        chunk_id,
        ratchet_key_id: [0x77u8; 16],
        stripe_descriptor: StripeDescriptor::NONE,
        ciphertext: vec![0xCDu8; plaintext_len as usize + 16],
    }
}

struct Fixture {
    _alice_root: TempDir,
    _bob_root: TempDir,
    alice_engine: Arc<TransferEngine>,
    bob_engine: Arc<TransferEngine>,
    alice_fp: PeerFingerprint,
    chunk_ids: Vec<[u8; 32]>,
}

async fn setup_pair(
    rt_handle: &tokio::runtime::Handle,
    num_chunks: u32,
    chunk_size: u32,
) -> Fixture {
    let alice_id = Arc::new(Identity::generate().unwrap());
    let bob_id = Arc::new(Identity::generate().unwrap());
    let alice_fp = alice_id.fingerprint();

    let alice_root = TempDir::new().unwrap();
    let bob_root = TempDir::new().unwrap();
    let alice_store = Arc::new(RwLock::new(ChunkStore::open(alice_root.path()).unwrap()));
    let bob_store = Arc::new(RwLock::new(ChunkStore::open(bob_root.path()).unwrap()));

    let alice_endpoint = Arc::new(
        Endpoint::server_for_identity(alice_id.clone(), Arc::new(AlwaysPair), fast_config())
            .unwrap(),
    );
    let bob_endpoint = Arc::new(
        Endpoint::server_for_identity(bob_id.clone(), Arc::new(AlwaysPair), fast_config()).unwrap(),
    );
    let alice_addr = alice_endpoint.local_addr().unwrap();

    // Pre-populate alice's store with num_chunks chunks.
    let mut chunk_ids = Vec::with_capacity(num_chunks as usize);
    {
        let mut s = alice_store.write().unwrap();
        for i in 0..num_chunks {
            let rec = mk_record(i, chunk_size);
            chunk_ids.push(rec.chunk_id);
            s.append_chunk(&rec).unwrap();
        }
        s.flush().unwrap();
    }

    let alice_engine = TransferEngine::new(alice_store, alice_endpoint, TransferConfig::default());
    let bob_engine = TransferEngine::new(bob_store, bob_endpoint, TransferConfig::default());

    let alice_server = Arc::clone(&alice_engine);
    rt_handle.spawn(async move {
        let _ = alice_server.run_server().await;
    });

    bob_engine
        .register_peer(alice_fp, alice_addr)
        .await
        .unwrap();
    // Warm the connection cache.
    let _ = bob_engine.ping(&alice_fp, vec![0u8; 8]).await.unwrap();

    Fixture {
        _alice_root: alice_root,
        _bob_root: bob_root,
        alice_engine,
        bob_engine,
        alice_fp,
        chunk_ids,
    }
}

fn bench_fetch_chunk_local(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let fx = rt.block_on(setup_pair(rt.handle(), 16, 1024));

    // Pre-fetch one chunk so bob's store has it; subsequent fetches are
    // pure local-store reads.
    rt.block_on(async {
        fx.bob_engine
            .fetch_chunk(&fx.alice_fp, &fx.chunk_ids[0])
            .await
            .unwrap();
    });

    c.bench_function("fetch_chunk_local", |b| {
        b.iter(|| {
            rt.block_on(async {
                fx.bob_engine
                    .fetch_chunk(&fx.alice_fp, &fx.chunk_ids[0])
                    .await
                    .unwrap();
            });
        });
    });
}

fn bench_fetch_chunk_warm(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("transfer_fetch");
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("fetch_chunk_warm_1KiB", |b| {
        // Setup once outside the iter so we measure steady-state per-fetch latency.
        let fx = rt.block_on(setup_pair(rt.handle(), 10_000, 1024));
        let mut i = 0u32;
        b.iter(|| {
            let idx = (i as usize) % fx.chunk_ids.len();
            rt.block_on(async {
                let _ = fx
                    .bob_engine
                    .fetch_chunk(&fx.alice_fp, &fx.chunk_ids[idx])
                    .await
                    .unwrap();
            });
            i = i.wrapping_add(1);
        });
    });
    group.finish();
}

fn bench_bloom_handshake_warm(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let fx = rt.block_on(setup_pair(rt.handle(), 1000, 1024));

    // Bob has a subset of the same chunks (the first 500).
    let bob_subset: Vec<[u8; 32]> = fx.chunk_ids.iter().take(500).copied().collect();

    c.bench_function("bloom_handshake_warm_1k", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _missing = fx
                    .bob_engine
                    .bloom_handshake(&fx.alice_fp, &bob_subset)
                    .await
                    .unwrap();
            });
        });
    });
}

/// Compare `fetch_chunk_fountain` vs `fetch_chunk` (single ChunkResponse)
/// on loopback. On a no-loss link, fountain has wire overhead from the
/// FountainPacket header (~4.4% per symbol) + extra symbols beyond K
/// for decode safety. This bench tells us how much that costs.
fn bench_fountain_vs_warm(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("fountain_vs_warm");
    // 16 KiB chunk = K=16 source symbols at 1 KiB. Big enough for the
    // fountain overhead to be visible; small enough to keep the bench
    // fast.
    let chunk_bytes = 16 * 1024u32;
    group.throughput(Throughput::Bytes(chunk_bytes as u64));

    group.bench_function("warm_chunk_response_16KiB", |b| {
        let fx = rt.block_on(setup_pair(rt.handle(), 10_000, chunk_bytes));
        let mut i = 0u32;
        b.iter(|| {
            let idx = (i as usize) % fx.chunk_ids.len();
            rt.block_on(async {
                let _ = fx
                    .bob_engine
                    .fetch_chunk(&fx.alice_fp, &fx.chunk_ids[idx])
                    .await
                    .unwrap();
            });
            i = i.wrapping_add(1);
        });
    });

    group.bench_function("fountain_16KiB", |b| {
        let fx = rt.block_on(setup_pair(rt.handle(), 10_000, chunk_bytes));
        let mut i = 0u32;
        b.iter(|| {
            let idx = (i as usize) % fx.chunk_ids.len();
            rt.block_on(async {
                let _ = fx
                    .bob_engine
                    .fetch_chunk_fountain(&fx.alice_fp, &fx.chunk_ids[idx])
                    .await
                    .unwrap();
            });
            i = i.wrapping_add(1);
        });
    });

    group.finish();
}

/// Compare `bloom_handshake_scoped` vs `bloom_handshake` on a server
/// with a large memtable (10K chunks) where the want_list is small
/// (100 chunks). Scoped path should crush the full-scan path because
/// it doesn't walk the server's 10K chunks.
fn bench_scoped_vs_full_bloom(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let fx = rt.block_on(setup_pair(rt.handle(), 10_000, 1024));

    // Bob has a subset of 100 chunks; want_list is 200 chunks (50% missing).
    let bob_have: Vec<[u8; 32]> = fx.chunk_ids.iter().take(100).copied().collect();
    let want_list: Vec<[u8; 32]> = fx.chunk_ids.iter().take(200).copied().collect();

    let mut group = c.benchmark_group("scoped_vs_full_bloom");

    group.bench_function("full_scan_10k_server", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _missing = fx
                    .bob_engine
                    .bloom_handshake(&fx.alice_fp, &bob_have)
                    .await
                    .unwrap();
            });
        });
    });

    group.bench_function("scoped_200_want_10k_server", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _missing = fx
                    .bob_engine
                    .bloom_handshake_scoped(&fx.alice_fp, &bob_have, &want_list)
                    .await
                    .unwrap();
            });
        });
    });

    group.finish();
}

/// Group-commit win: 32 chunks via `fetch_many` (1 fsync) vs 32
/// sequential `fetch_chunk` calls (32 fsyncs).
fn bench_group_commit_win(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    const BATCH: u32 = 32;

    let mut group = c.benchmark_group("group_commit");
    group.throughput(Throughput::Elements(BATCH as u64));

    group.bench_function("fetch_many_batched_x32", |b| {
        // Fresh fixture per measurement so each iter has un-fetched chunks.
        b.iter_with_setup(
            || rt.block_on(setup_pair(rt.handle(), BATCH, 1024)),
            |fx| {
                rt.block_on(async {
                    let outcomes = fx
                        .bob_engine
                        .fetch_many(&fx.alice_fp, fx.chunk_ids.clone())
                        .await
                        .unwrap();
                    assert_eq!(outcomes.len(), BATCH as usize);
                });
            },
        );
    });

    group.bench_function("sequential_fetch_chunk_x32", |b| {
        b.iter_with_setup(
            || rt.block_on(setup_pair(rt.handle(), BATCH, 1024)),
            |fx| {
                rt.block_on(async {
                    for cid in &fx.chunk_ids {
                        let _ = fx.bob_engine.fetch_chunk(&fx.alice_fp, cid).await.unwrap();
                    }
                });
            },
        );
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_fetch_chunk_local,
    bench_fetch_chunk_warm,
    bench_bloom_handshake_warm,
    bench_group_commit_win,
    bench_fountain_vs_warm,
    bench_scoped_vs_full_bloom,
);
criterion_main!(benches);

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
    let mut c = EndpointConfig::default();
    c.bind = "127.0.0.1:0".parse().expect("valid bind");
    c.idle_timeout_ms = 30_000;
    c.keepalive_interval_ms = 5_000;
    c
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

async fn setup_pair(rt_handle: &tokio::runtime::Handle, num_chunks: u32, chunk_size: u32) -> Fixture {
    let alice_id = Arc::new(Identity::generate().unwrap());
    let bob_id = Arc::new(Identity::generate().unwrap());
    let alice_fp = alice_id.fingerprint();

    let alice_root = TempDir::new().unwrap();
    let bob_root = TempDir::new().unwrap();
    let alice_store = Arc::new(RwLock::new(ChunkStore::open(alice_root.path()).unwrap()));
    let bob_store = Arc::new(RwLock::new(ChunkStore::open(bob_root.path()).unwrap()));

    let alice_endpoint = Arc::new(
        Endpoint::server_for_identity(alice_id.clone(), Arc::new(AlwaysPair), fast_config()).unwrap(),
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

    bob_engine.register_peer(alice_fp, alice_addr).await.unwrap();
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

criterion_group!(
    benches,
    bench_fetch_chunk_local,
    bench_fetch_chunk_warm,
    bench_bloom_handshake_warm,
);
criterion_main!(benches);

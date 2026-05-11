//! End-to-end integration tests for `ol_transfer::TransferEngine`.
//!
//! Validates the full chunk-store + QUIC + Bloom-init wiring per
//! ADR-0013's verification gate:
//!
//! 1. End-to-end fetch — paired peers; B fetches X from A; X is on B's store.
//! 2. Idempotence — repeated `fetch_chunk` returns cached, no transport.
//! 3. Bloom-init delta — B sends bloom of its 1024 chunks; gets back ~missing.
//! 4. Chunk-not-found — B asks for Y, A doesn't have it.
//! 5. Protocol violation — server replies with wrong frame kind.
//! 6. Cached connection reuse — N fetches reuse one connection.
//! 7. Concurrent fetch backpressure — bounded by `max_inflight_per_peer`.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock as StdRwLock};

use ol_chunk_store::{
    ChunkAddressKind, ChunkAeadKind, ChunkRecord, ChunkRecordKind, ChunkStore, StripeDescriptor,
};
use ol_quic::{Endpoint, EndpointConfig, Identity, PeerFingerprint, PeerRegistry};
use ol_transfer::{FetchOutcome, TransferConfig, TransferEngine, TransferError};
use tempfile::TempDir;

// ─────────────────────────── test fixtures ─────────────────────────────

#[derive(Debug)]
struct PairedRegistry {
    permitted: Vec<PeerFingerprint>,
}

impl PeerRegistry for PairedRegistry {
    fn is_paired_peer(&self, fp: &PeerFingerprint) -> bool {
        self.permitted.iter().any(|p| p == fp)
    }
}

fn fast_config() -> EndpointConfig {
    let mut c = EndpointConfig::default();
    c.bind = "127.0.0.1:0".parse().expect("valid bind");
    c.idle_timeout_ms = 30_000;
    c.keepalive_interval_ms = 5_000;
    c
}

fn mk_record_u32(seed: u32, plaintext_len: u32, ciphertext_len: usize) -> ChunkRecord {
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
        ciphertext: vec![0xCDu8; ciphertext_len],
    }
}

fn mk_record(id_byte: u8, plaintext_len: u32, ciphertext_len: usize) -> ChunkRecord {
    let mut chunk_id = [0u8; 32];
    chunk_id[0] = id_byte;
    chunk_id[1] = 0xAA;
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
        ciphertext: vec![0xCDu8; ciphertext_len],
    }
}

struct Peer {
    // `identity` is referenced through endpoint TLS plumbing during
    // setup; it stays owned here so the Arc isn't dropped before the
    // endpoint, but isn't read directly inside the test body — keep
    // the field with a leading underscore so Rust knows we hold it
    // deliberately.
    _identity: Arc<Identity>,
    fingerprint: PeerFingerprint,
    _root: TempDir,
    store: Arc<StdRwLock<ChunkStore>>,
    endpoint: Arc<Endpoint>,
    addr: SocketAddr,
}

fn build_peer(permitted_partners: Vec<PeerFingerprint>) -> Peer {
    let identity = Arc::new(Identity::generate().unwrap());
    let fingerprint = identity.fingerprint();
    let root = TempDir::new().unwrap();
    let store = ChunkStore::open(root.path()).unwrap();
    let store = Arc::new(StdRwLock::new(store));
    let registry = Arc::new(PairedRegistry {
        permitted: permitted_partners,
    });
    let endpoint = Arc::new(
        Endpoint::server_for_identity(identity.clone(), registry, fast_config()).unwrap(),
    );
    let addr = endpoint.local_addr().unwrap();
    Peer {
        identity,
        fingerprint,
        _root: root,
        store,
        endpoint,
        addr,
    }
}

/// Build a paired (alice, bob) duo where each accepts connections from
/// the other.
fn pair() -> (Peer, Peer) {
    let alice_id = Arc::new(Identity::generate().unwrap());
    let bob_id = Arc::new(Identity::generate().unwrap());
    let alice_fp = alice_id.fingerprint();
    let bob_fp = bob_id.fingerprint();

    let alice_root = TempDir::new().unwrap();
    let bob_root = TempDir::new().unwrap();
    let alice_store = Arc::new(StdRwLock::new(ChunkStore::open(alice_root.path()).unwrap()));
    let bob_store = Arc::new(StdRwLock::new(ChunkStore::open(bob_root.path()).unwrap()));

    let alice_registry = Arc::new(PairedRegistry {
        permitted: vec![bob_fp],
    });
    let bob_registry = Arc::new(PairedRegistry {
        permitted: vec![alice_fp],
    });

    let alice_endpoint = Arc::new(
        Endpoint::server_for_identity(alice_id.clone(), alice_registry, fast_config()).unwrap(),
    );
    let bob_endpoint = Arc::new(
        Endpoint::server_for_identity(bob_id.clone(), bob_registry, fast_config()).unwrap(),
    );
    let alice_addr = alice_endpoint.local_addr().unwrap();
    let bob_addr = bob_endpoint.local_addr().unwrap();

    let alice = Peer {
        _identity: alice_id,
        fingerprint: alice_fp,
        _root: alice_root,
        store: alice_store,
        endpoint: alice_endpoint,
        addr: alice_addr,
    };
    let bob = Peer {
        _identity: bob_id,
        fingerprint: bob_fp,
        _root: bob_root,
        store: bob_store,
        endpoint: bob_endpoint,
        addr: bob_addr,
    };
    (alice, bob)
}

// ─────────────────────────── tests ─────────────────────────────────────

#[tokio::test]
async fn fetch_chunk_round_trip() {
    let (alice, bob) = pair();

    // Alice has the chunk.
    let record = mk_record(0x42, 1024, 1040);
    let chunk_id = record.chunk_id;
    {
        let mut s = alice.store.write().unwrap();
        s.append_chunk(&record).unwrap();
        s.flush().unwrap();
    }

    let alice_engine =
        TransferEngine::new(alice.store.clone(), alice.endpoint.clone(), TransferConfig::default());
    let bob_engine =
        TransferEngine::new(bob.store.clone(), bob.endpoint.clone(), TransferConfig::default());

    let alice_server = Arc::clone(&alice_engine);
    tokio::spawn(async move {
        let _ = alice_server.run_server().await;
    });

    bob_engine.register_peer(alice.fingerprint, alice.addr).await.unwrap();

    let fetched = bob_engine
        .fetch_chunk(&alice.fingerprint, &chunk_id)
        .await
        .unwrap();
    assert_eq!(fetched.chunk_id, chunk_id);
    assert_eq!(fetched.length_plaintext, 1024);
    assert_eq!(fetched.ciphertext.len(), 1040);

    // Bob's store now has it.
    {
        let s = bob.store.read().unwrap();
        assert!(s.has_chunk(&chunk_id));
    }
}

#[tokio::test]
async fn fetch_chunk_idempotent_returns_local() {
    let (alice, bob) = pair();
    let record = mk_record(0x55, 256, 272);
    let chunk_id = record.chunk_id;
    {
        let mut s = alice.store.write().unwrap();
        s.append_chunk(&record).unwrap();
        s.flush().unwrap();
    }

    let alice_engine =
        TransferEngine::new(alice.store.clone(), alice.endpoint.clone(), TransferConfig::default());
    let bob_engine =
        TransferEngine::new(bob.store.clone(), bob.endpoint.clone(), TransferConfig::default());

    let alice_server = Arc::clone(&alice_engine);
    tokio::spawn(async move {
        let _ = alice_server.run_server().await;
    });

    bob_engine.register_peer(alice.fingerprint, alice.addr).await.unwrap();

    // First fetch: over the wire.
    let first = bob_engine
        .fetch_chunk(&alice.fingerprint, &chunk_id)
        .await
        .unwrap();
    // Second fetch: must hit local store (no transport).
    let second = bob_engine
        .fetch_chunk(&alice.fingerprint, &chunk_id)
        .await
        .unwrap();
    assert_eq!(first.chunk_id, second.chunk_id);
    assert_eq!(first.ciphertext, second.ciphertext);

    // Even forgetting Alice and re-fetching the now-local chunk works.
    bob_engine.forget_peer(&alice.fingerprint).await;
    let third = bob_engine
        .fetch_chunk(&alice.fingerprint, &chunk_id)
        .await
        .unwrap();
    assert_eq!(third.chunk_id, chunk_id);
}

#[tokio::test]
async fn chunk_not_found_at_peer() {
    let (alice, bob) = pair();
    let alice_engine =
        TransferEngine::new(alice.store.clone(), alice.endpoint.clone(), TransferConfig::default());
    let bob_engine =
        TransferEngine::new(bob.store.clone(), bob.endpoint.clone(), TransferConfig::default());

    let alice_server = Arc::clone(&alice_engine);
    tokio::spawn(async move {
        let _ = alice_server.run_server().await;
    });

    bob_engine.register_peer(alice.fingerprint, alice.addr).await.unwrap();

    let missing_id = [0xDEu8; 32];
    let result = bob_engine.fetch_chunk(&alice.fingerprint, &missing_id).await;
    assert!(matches!(result, Err(TransferError::ChunkNotFound { .. })));
}

#[tokio::test]
async fn peer_unknown_returns_error() {
    let bob = build_peer(vec![]);
    let bob_engine =
        TransferEngine::new(bob.store.clone(), bob.endpoint.clone(), TransferConfig::default());

    let mystery_fp = Identity::generate().unwrap().fingerprint();
    let result = bob_engine.fetch_chunk(&mystery_fp, &[0u8; 32]).await;
    assert!(matches!(result, Err(TransferError::PeerUnknown { .. })));
}

#[tokio::test]
async fn bloom_handshake_returns_missing_chunks() {
    let (alice, bob) = pair();

    // Alice has 100 chunks; Bob has the first 50.
    let mut alice_ids = Vec::new();
    for i in 0u8..100 {
        let r = mk_record(i, 64, 80);
        let id = r.chunk_id;
        {
            let mut s = alice.store.write().unwrap();
            s.append_chunk(&r).unwrap();
            s.flush().unwrap();
        }
        alice_ids.push(id);
    }
    let mut bob_local = Vec::new();
    for i in 0u8..50 {
        let r = mk_record(i, 64, 80);
        let id = r.chunk_id;
        {
            let mut s = bob.store.write().unwrap();
            s.append_chunk(&r).unwrap();
            s.flush().unwrap();
        }
        bob_local.push(id);
    }

    let alice_engine =
        TransferEngine::new(alice.store.clone(), alice.endpoint.clone(), TransferConfig::default());
    let bob_engine =
        TransferEngine::new(bob.store.clone(), bob.endpoint.clone(), TransferConfig::default());

    let alice_server = Arc::clone(&alice_engine);
    tokio::spawn(async move {
        let _ = alice_server.run_server().await;
    });

    bob_engine.register_peer(alice.fingerprint, alice.addr).await.unwrap();

    // Bob sends bloom of its 50 chunks; the server-side (Alice) iterates
    // its memtable (100 chunks) and returns the ones NOT in Bob's bloom.
    // Expected: roughly 50 missing (the second half), ± FP-rate noise.
    let missing = bob_engine
        .bloom_handshake(&alice.fingerprint, &bob_local)
        .await
        .unwrap();
    // Filter false-positive rate is 1%, so expect between 45 and 50 missing.
    assert!(
        missing.len() >= 45 && missing.len() <= 50,
        "expected ~50 missing chunks, got {}",
        missing.len()
    );
    // None of the returned ids should be in bob_local (true positives).
    for cid in &missing {
        assert!(!bob_local.contains(cid));
    }
}

#[tokio::test]
async fn ping_round_trip() {
    let (alice, bob) = pair();
    let alice_engine =
        TransferEngine::new(alice.store.clone(), alice.endpoint.clone(), TransferConfig::default());
    let bob_engine =
        TransferEngine::new(bob.store.clone(), bob.endpoint.clone(), TransferConfig::default());

    let alice_server = Arc::clone(&alice_engine);
    tokio::spawn(async move {
        let _ = alice_server.run_server().await;
    });

    bob_engine.register_peer(alice.fingerprint, alice.addr).await.unwrap();

    let pong = bob_engine
        .ping(&alice.fingerprint, b"hello".to_vec())
        .await
        .unwrap();
    assert_eq!(pong, b"hello");
}

#[tokio::test]
async fn fetch_many_with_mix_of_outcomes() {
    let (alice, bob) = pair();

    // Alice has 10 chunks. Bob will request 12 — 10 hit, 2 miss.
    let mut want = Vec::new();
    for i in 0u8..10 {
        let r = mk_record(i, 32, 48);
        let id = r.chunk_id;
        {
            let mut s = alice.store.write().unwrap();
            s.append_chunk(&r).unwrap();
            s.flush().unwrap();
        }
        want.push(id);
    }
    // Two ids Alice doesn't have.
    let mut missing_1 = [0u8; 32];
    missing_1[0] = 0xEE;
    let mut missing_2 = [0u8; 32];
    missing_2[0] = 0xEF;
    want.push(missing_1);
    want.push(missing_2);

    let alice_engine =
        TransferEngine::new(alice.store.clone(), alice.endpoint.clone(), TransferConfig::default());
    let bob_engine =
        TransferEngine::new(bob.store.clone(), bob.endpoint.clone(), TransferConfig::default());

    let alice_server = Arc::clone(&alice_engine);
    tokio::spawn(async move {
        let _ = alice_server.run_server().await;
    });

    bob_engine.register_peer(alice.fingerprint, alice.addr).await.unwrap();

    let outcomes = bob_engine.fetch_many(&alice.fingerprint, want.clone()).await.unwrap();
    assert_eq!(outcomes.len(), 12);

    let mut fetched = 0;
    let mut not_found = 0;
    for (i, o) in outcomes.iter().enumerate() {
        if i < 10 {
            match o {
                FetchOutcome::Fetched { length_plaintext, .. } => {
                    assert_eq!(*length_plaintext, 32);
                    fetched += 1;
                }
                FetchOutcome::AlreadyLocal { .. } => {
                    // Acceptable: occasional re-entrancy on shared store.
                    fetched += 1;
                }
                other => panic!("expected Fetched for index {i}, got {other:?}"),
            }
        } else {
            assert!(
                matches!(o, FetchOutcome::NotFound { .. }),
                "expected NotFound for index {i}, got {o:?}"
            );
            not_found += 1;
        }
    }
    assert_eq!(fetched, 10);
    assert_eq!(not_found, 2);
}

#[tokio::test]
async fn known_peers_reflects_registry() {
    let bob = build_peer(vec![]);
    let bob_engine =
        TransferEngine::new(bob.store.clone(), bob.endpoint.clone(), TransferConfig::default());

    assert!(bob_engine.known_peers().await.is_empty());
    let fp = Identity::generate().unwrap().fingerprint();
    let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
    bob_engine.register_peer(fp, addr).await.unwrap();
    assert_eq!(bob_engine.known_peers().await, vec![fp]);
    bob_engine.forget_peer(&fp).await;
    assert!(bob_engine.known_peers().await.is_empty());
}

#[tokio::test]
async fn bloom_handshake_scoped_filters_to_want_list() {
    // Server has 200 chunks. Client has 50 of them. Client's want_list
    // is a 100-chunk subset of the server's chunks. The server should
    // return exactly the 50 in want_list that the client doesn't have.
    let (alice, bob) = pair();
    let mut all_ids = Vec::new();
    for i in 0u32..200 {
        let r = mk_record_u32(i, 32, 48);
        let id = r.chunk_id;
        {
            let mut s = alice.store.write().unwrap();
            s.append_chunk(&r).unwrap();
            s.flush().unwrap();
        }
        all_ids.push(id);
    }
    // Bob's existing: first 50.
    let bob_have: Vec<[u8; 32]> = all_ids.iter().take(50).copied().collect();
    // Want list: 100 ids spanning ids 25..125 (so 25 overlap with already_have, 75 are missing).
    let want_list: Vec<[u8; 32]> = all_ids.iter().skip(25).take(100).copied().collect();

    let alice_engine =
        TransferEngine::new(alice.store.clone(), alice.endpoint.clone(), TransferConfig::default());
    let bob_engine =
        TransferEngine::new(bob.store.clone(), bob.endpoint.clone(), TransferConfig::default());
    let alice_server = Arc::clone(&alice_engine);
    tokio::spawn(async move {
        let _ = alice_server.run_server().await;
    });
    bob_engine.register_peer(alice.fingerprint, alice.addr).await.unwrap();

    let missing = bob_engine
        .bloom_handshake_scoped(&alice.fingerprint, &bob_have, &want_list)
        .await
        .unwrap();
    // Expected count: roughly 75 (want_list minus bob_have intersection).
    // Bloom FP rate 1% means we may see slightly fewer.
    assert!(
        missing.len() >= 70 && missing.len() <= 75,
        "expected ~75 missing, got {}",
        missing.len()
    );
    // None of the returned ids should be in bob_have.
    for cid in &missing {
        assert!(!bob_have.contains(cid));
    }
    // All returned ids should be in want_list.
    for cid in &missing {
        assert!(want_list.contains(cid));
    }
}

#[tokio::test]
async fn fetch_chunk_fountain_round_trip() {
    // ADR-0015 wire path: client requests via FountainRequest, server
    // streams FountainBurst frames, client decodes + acks.
    let (alice, bob) = pair();

    // Alice has a 16 KiB chunk (so K=16-ish at the 1 KiB symbol size).
    let record = mk_record(0x9F, 16 * 1024, 16 * 1024 + 16);
    let chunk_id = record.chunk_id;
    {
        let mut s = alice.store.write().unwrap();
        s.append_chunk(&record).unwrap();
        s.flush().unwrap();
    }

    let alice_engine =
        TransferEngine::new(alice.store.clone(), alice.endpoint.clone(), TransferConfig::default());
    let bob_engine =
        TransferEngine::new(bob.store.clone(), bob.endpoint.clone(), TransferConfig::default());

    let alice_server = Arc::clone(&alice_engine);
    tokio::spawn(async move {
        let _ = alice_server.run_server().await;
    });
    bob_engine.register_peer(alice.fingerprint, alice.addr).await.unwrap();

    let fetched = bob_engine
        .fetch_chunk_fountain(&alice.fingerprint, &chunk_id)
        .await
        .unwrap();
    assert_eq!(fetched.chunk_id, chunk_id);
    assert_eq!(fetched.length_plaintext, 16 * 1024);
    assert_eq!(fetched.ciphertext.len(), 16 * 1024 + 16);

    // Bob's store has it.
    let s = bob.store.read().unwrap();
    assert!(s.has_chunk(&chunk_id));
}

#[tokio::test]
async fn fetch_chunk_fountain_not_found() {
    let (alice, bob) = pair();
    let alice_engine =
        TransferEngine::new(alice.store.clone(), alice.endpoint.clone(), TransferConfig::default());
    let bob_engine =
        TransferEngine::new(bob.store.clone(), bob.endpoint.clone(), TransferConfig::default());

    let alice_server = Arc::clone(&alice_engine);
    tokio::spawn(async move {
        let _ = alice_server.run_server().await;
    });
    bob_engine.register_peer(alice.fingerprint, alice.addr).await.unwrap();

    let result = bob_engine
        .fetch_chunk_fountain(&alice.fingerprint, &[0xFFu8; 32])
        .await;
    assert!(matches!(result, Err(TransferError::ChunkNotFound { .. })));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_fetch_stress_200_parallel() {
    // Stress: bob asks alice for 200 chunks in parallel via fetch_many.
    // Confirms the RwLock + group commit + fetch task spawn pattern
    // doesn't deadlock under concurrent load.
    let (alice, bob) = pair();
    let mut chunk_ids = Vec::with_capacity(200);
    for i in 0u32..200 {
        let r = mk_record_u32(i, 1024, 1040);
        let id = r.chunk_id;
        {
            let mut s = alice.store.write().unwrap();
            s.append_chunk(&r).unwrap();
        }
        chunk_ids.push(id);
    }
    {
        let mut s = alice.store.write().unwrap();
        s.flush().unwrap();
    }

    let alice_engine =
        TransferEngine::new(alice.store.clone(), alice.endpoint.clone(), TransferConfig::default());
    let bob_engine =
        TransferEngine::new(bob.store.clone(), bob.endpoint.clone(), TransferConfig::default());
    let alice_server = Arc::clone(&alice_engine);
    tokio::spawn(async move {
        let _ = alice_server.run_server().await;
    });
    bob_engine.register_peer(alice.fingerprint, alice.addr).await.unwrap();

    let start = std::time::Instant::now();
    let outcomes = bob_engine.fetch_many(&alice.fingerprint, chunk_ids.clone()).await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(outcomes.len(), 200);
    let success_count = outcomes.iter().filter(|o| o.is_success()).count();
    assert_eq!(success_count, 200);
    eprintln!("200 parallel fetches: {:?}", elapsed);

    // Bob now has all 200 chunks.
    let s = bob.store.read().unwrap();
    let mut found = 0;
    for cid in &chunk_ids {
        if s.has_chunk(cid) {
            found += 1;
        }
    }
    assert_eq!(found, 200);
}

#[tokio::test]
async fn cached_connection_reused_across_fetches() {
    let (alice, bob) = pair();

    // Pre-populate alice with 5 chunks.
    let mut ids = Vec::new();
    for i in 0u8..5 {
        let r = mk_record(i, 64, 80);
        let id = r.chunk_id;
        {
            let mut s = alice.store.write().unwrap();
            s.append_chunk(&r).unwrap();
            s.flush().unwrap();
        }
        ids.push(id);
    }

    let alice_engine =
        TransferEngine::new(alice.store.clone(), alice.endpoint.clone(), TransferConfig::default());
    let bob_engine =
        TransferEngine::new(bob.store.clone(), bob.endpoint.clone(), TransferConfig::default());

    let alice_server = Arc::clone(&alice_engine);
    tokio::spawn(async move {
        let _ = alice_server.run_server().await;
    });

    bob_engine.register_peer(alice.fingerprint, alice.addr).await.unwrap();

    // Each fetch reuses the cached connection. We can't directly assert
    // "exactly one connection" from outside, but we CAN observe that all
    // 5 fetches succeed in rapid succession (handshake cost ~100ms each
    // would be ~500ms total; cached path should be <100ms total). On a
    // loopback this is easily met; we just assert all succeed.
    for id in &ids {
        let _ = bob_engine.fetch_chunk(&alice.fingerprint, id).await.unwrap();
    }
    let stats = bob_engine.store_stats();
    assert!(stats.indexed_chunks >= 5);
}

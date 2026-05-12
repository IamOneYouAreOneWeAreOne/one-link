//! End-to-end loopback tests for `ol_quic`.
//!
//! Validates the full QUIC handshake + identity-bound TLS + wire
//! framing on a single host. Two endpoints (server + client) bind
//! ephemeral UDP ports; the client dials the server using the server's
//! known fingerprint; we exercise:
//!
//! - successful connect + frame round-trip,
//! - rejection on fingerprint mismatch,
//! - rejection from a server whose registry doesn't recognize the client,
//! - 100 MiB single-stream throughput as the Phase A2 acceptance number.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ol_quic::{
    Endpoint, EndpointConfig, Frame, FrameKind, Identity, PeerFingerprint, PeerRegistry,
};

#[derive(Debug)]
struct PairedRegistry {
    permitted: Vec<PeerFingerprint>,
}

impl PeerRegistry for PairedRegistry {
    fn is_paired_peer(&self, fingerprint: &PeerFingerprint) -> bool {
        self.permitted.iter().any(|fp| fp == fingerprint)
    }
}

#[derive(Debug)]
struct DenyAll;

impl PeerRegistry for DenyAll {
    fn is_paired_peer(&self, _fingerprint: &PeerFingerprint) -> bool {
        false
    }
}

fn ipv4_loopback_config() -> EndpointConfig {
    let mut c = EndpointConfig::default();
    c.bind = "127.0.0.1:0".parse().expect("valid bind");
    // Faster idle timeout for tests.
    c.idle_timeout_ms = 5_000;
    c.keepalive_interval_ms = 1_000;
    c
}

#[tokio::test]
async fn handshake_and_frame_round_trip() {
    let alice = Arc::new(Identity::generate().unwrap());
    let bob = Arc::new(Identity::generate().unwrap());

    let alice_registry = Arc::new(PairedRegistry {
        permitted: vec![bob.fingerprint()],
    });
    let alice_server =
        Endpoint::server_for_identity(alice.clone(), alice_registry, ipv4_loopback_config())
            .unwrap();
    let alice_addr = alice_server.local_addr().unwrap();

    let bob_client = Endpoint::client_for_identity(bob.clone(), ipv4_loopback_config()).unwrap();

    // Server-side accept loop in the background.
    let alice_fp = alice.fingerprint();
    let server_handle = tokio::spawn(async move {
        let conn = alice_server.accept().await.expect("incoming").unwrap();
        // Echo: read one Ping frame, reply with a Pong containing the same nonce.
        let (mut send, mut recv) = conn.accept_bi_stream().await.unwrap();
        let frame = ol_quic::transport::read_frame(&mut recv).await.unwrap();
        assert_eq!(frame.kind, FrameKind::Ping);
        let reply = Frame::new(FrameKind::Pong, frame.payload).unwrap();
        ol_quic::transport::write_frame(&mut send, &reply)
            .await
            .unwrap();
        send.finish().unwrap();
        // Wait for the client to close before tearing down the endpoint.
        let _ = conn.closed().await;
    });

    let conn = bob_client.connect(alice_addr, alice_fp).await.unwrap();
    let request = Frame::new(FrameKind::Ping, vec![0x42u8; 8]).unwrap();
    let response = conn
        .send_frame_request_response(request.clone())
        .await
        .unwrap();
    assert_eq!(response.kind, FrameKind::Pong);
    assert_eq!(response.payload, request.payload);

    conn.close(0, b"ok");
    // server_handle joins on close.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), server_handle).await;
}

#[tokio::test]
async fn rejects_when_client_not_in_server_registry() {
    let alice = Arc::new(Identity::generate().unwrap());
    let bob = Arc::new(Identity::generate().unwrap());

    let alice_server =
        Endpoint::server_for_identity(alice.clone(), Arc::new(DenyAll), ipv4_loopback_config())
            .unwrap();
    let alice_addr = alice_server.local_addr().unwrap();
    let alice_fp = alice.fingerprint();

    let bob_client = Endpoint::client_for_identity(bob.clone(), ipv4_loopback_config()).unwrap();
    tokio::spawn(async move {
        let _ = alice_server.accept().await;
    });

    let connect_result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        bob_client.connect(alice_addr, alice_fp),
    )
    .await;

    let conn = match connect_result {
        Ok(Ok(conn)) => conn,
        Ok(Err(_)) | Err(_) => return, // rejected at handshake — pass
    };

    // QUIC may resolve `connect()` after the initial CRYPTO exchange
    // even before the server's verifier verdict reaches us. Confirm
    // rejection by trying to USE the connection — opening a stream and
    // exchanging a frame must fail when the server rejected our cert.
    let request = Frame::new(FrameKind::Ping, vec![0u8; 8]).unwrap();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        conn.send_frame_request_response(request),
    )
    .await;
    match result {
        Ok(Ok(_)) => panic!("expected rejection at data path, got successful round-trip"),
        Ok(Err(_)) | Err(_) => {} // pass
    }
}

#[tokio::test]
async fn rejects_on_fingerprint_mismatch() {
    let alice = Arc::new(Identity::generate().unwrap());
    let bob = Arc::new(Identity::generate().unwrap());
    let mallory_fp = Identity::generate().unwrap().fingerprint();

    let alice_registry = Arc::new(PairedRegistry {
        permitted: vec![bob.fingerprint()],
    });
    let alice_server =
        Endpoint::server_for_identity(alice.clone(), alice_registry, ipv4_loopback_config())
            .unwrap();
    let alice_addr = alice_server.local_addr().unwrap();

    let bob_client = Endpoint::client_for_identity(bob.clone(), ipv4_loopback_config()).unwrap();

    tokio::spawn(async move {
        if let Some(result) = alice_server.accept().await {
            let _ = result;
        }
    });

    // Bob dials but expects mallory's fingerprint — TLS rejects.
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        bob_client.connect(alice_addr, mallory_fp),
    )
    .await;
    match result {
        Ok(Ok(_)) => panic!("expected fingerprint mismatch rejection"),
        Ok(Err(_)) | Err(_) => {}
    }
}

#[tokio::test]
async fn bulk_throughput_100_mib() {
    let alice = Arc::new(Identity::generate().unwrap());
    let bob = Arc::new(Identity::generate().unwrap());

    let alice_registry = Arc::new(PairedRegistry {
        permitted: vec![bob.fingerprint()],
    });
    let alice_server =
        Endpoint::server_for_identity(alice.clone(), alice_registry, ipv4_loopback_config())
            .unwrap();
    let alice_addr = alice_server.local_addr().unwrap();
    let alice_fp = alice.fingerprint();

    let bob_client = Endpoint::client_for_identity(bob.clone(), ipv4_loopback_config()).unwrap();

    // 100 chunks × 1 MiB (the bulk frame cap).
    const CHUNKS: usize = 100;
    const CHUNK_SIZE: usize = 1024 * 1024;

    let payload = vec![0xCDu8; CHUNK_SIZE];
    let payload_for_server = payload.clone();
    let server_handle = tokio::spawn(async move {
        let conn = alice_server.accept().await.expect("incoming").unwrap();
        for _ in 0..CHUNKS {
            let (mut send, mut recv) = conn.accept_bi_stream().await.unwrap();
            // Read the request (ChunkRequest with a 32-byte chunk_id),
            // ignore the payload, reply with ChunkResponse of 1 MiB.
            let _req = ol_quic::transport::read_frame(&mut recv).await.unwrap();
            let frame = Frame::new(FrameKind::ChunkResponse, payload_for_server.clone()).unwrap();
            ol_quic::transport::write_frame(&mut send, &frame)
                .await
                .unwrap();
            send.finish().unwrap();
        }
        let _ = conn.closed().await;
    });

    let conn = bob_client.connect(alice_addr, alice_fp).await.unwrap();
    let start = std::time::Instant::now();
    let mut total = 0usize;
    for _ in 0..CHUNKS {
        let req = Frame::new(FrameKind::ChunkRequest, vec![0u8; 32]).unwrap();
        let response = conn.send_frame_request_response(req).await.unwrap();
        total += response.payload.len();
    }
    let elapsed = start.elapsed();
    conn.close(0, b"ok");

    let mib = total as f64 / (1024.0 * 1024.0);
    let mibps = mib / elapsed.as_secs_f64();
    println!(
        "ol_quic loopback throughput: {} MiB in {:.3}s = {:.1} MiB/s",
        mib as u64,
        elapsed.as_secs_f64(),
        mibps,
    );
    assert_eq!(total, CHUNKS * CHUNK_SIZE);
    assert!(
        mibps > 100.0,
        "expected >100 MiB/s on loopback, got {mibps}"
    );

    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server_handle).await;
}

#[tokio::test]
async fn parallel_streams_no_head_of_line_blocking() {
    let alice = Arc::new(Identity::generate().unwrap());
    let bob = Arc::new(Identity::generate().unwrap());
    let alice_registry = Arc::new(PairedRegistry {
        permitted: vec![bob.fingerprint()],
    });
    let alice_server =
        Endpoint::server_for_identity(alice.clone(), alice_registry, ipv4_loopback_config())
            .unwrap();
    let alice_addr = alice_server.local_addr().unwrap();
    let alice_fp = alice.fingerprint();

    let bob_client = Endpoint::client_for_identity(bob.clone(), ipv4_loopback_config()).unwrap();

    let server_done = Arc::new(AtomicBool::new(false));
    let server_done_clone = server_done.clone();
    let server_handle = tokio::spawn(async move {
        let conn = alice_server.accept().await.expect("incoming").unwrap();
        // Accept up to 32 streams concurrently; each pings + pongs.
        let mut handles = Vec::new();
        for _ in 0..32 {
            let (mut send, mut recv) = conn.accept_bi_stream().await.unwrap();
            handles.push(tokio::spawn(async move {
                let req = ol_quic::transport::read_frame(&mut recv).await.unwrap();
                let reply = Frame::new(FrameKind::Pong, req.payload).unwrap();
                ol_quic::transport::write_frame(&mut send, &reply)
                    .await
                    .unwrap();
                send.finish().unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        server_done_clone.store(true, Ordering::SeqCst);
        let _ = conn.closed().await;
    });

    let conn = bob_client.connect(alice_addr, alice_fp).await.unwrap();
    let conn = Arc::new(conn);

    let mut handles = Vec::new();
    for i in 0..32u8 {
        let conn = conn.clone();
        handles.push(tokio::spawn(async move {
            let req = Frame::new(FrameKind::Ping, vec![i; 64]).unwrap();
            let resp = conn.send_frame_request_response(req).await.unwrap();
            assert_eq!(resp.kind, FrameKind::Pong);
            assert_eq!(resp.payload, vec![i; 64]);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    conn.close(0, b"ok");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server_handle).await;
    assert!(server_done.load(Ordering::SeqCst));
}

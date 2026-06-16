//! Throughput benchmarks for `ol_quic` loopback.
//!
//! Run:
//!   cargo bench -p ol_quic --bench quic_bench

use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ol_quic::{
    Endpoint, EndpointConfig, Frame, FrameKind, Identity, PeerFingerprint, PeerRegistry,
};
use tokio::runtime::Runtime;

#[derive(Debug)]
struct PairedRegistry {
    permitted: Vec<PeerFingerprint>,
}

impl PeerRegistry for PairedRegistry {
    fn is_paired_peer(&self, fp: &PeerFingerprint) -> bool {
        self.permitted.iter().any(|x| x == fp)
    }
}

fn cfg() -> EndpointConfig {
    EndpointConfig {
        bind: "127.0.0.1:0".parse().expect("valid bind"),
        idle_timeout_ms: 30_000,
        keepalive_interval_ms: 5_000,
        ..Default::default()
    }
}

fn bench_loopback_round_trip(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");
    let mut group = c.benchmark_group("ol_quic_loopback");

    for &payload_kib in &[1usize, 64, 256, 1024] {
        let payload_bytes = payload_kib * 1024;
        group.throughput(Throughput::Bytes(payload_bytes as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(payload_kib),
            &payload_bytes,
            |b, &payload_bytes| {
                b.iter_custom(|iters| {
                    rt.block_on(async {
                        let alice = Arc::new(Identity::generate().unwrap());
                        let bob = Arc::new(Identity::generate().unwrap());
                        let alice_registry = Arc::new(PairedRegistry {
                            permitted: vec![bob.fingerprint()],
                        });
                        let server =
                            Endpoint::server_for_identity(alice.clone(), alice_registry, cfg())
                                .unwrap();
                        let addr = server.local_addr().unwrap();
                        let alice_fp = alice.fingerprint();
                        let client = Endpoint::client_for_identity(bob.clone(), cfg()).unwrap();

                        let payload_for_server = vec![0xCDu8; payload_bytes];
                        let server_handle = tokio::spawn(async move {
                            let conn = server.accept().await.expect("incoming").unwrap();
                            for _ in 0..iters {
                                let (mut send, mut recv) = conn.accept_bi_stream().await.unwrap();
                                let _req = ol_quic::transport::read_frame(&mut recv).await.unwrap();
                                let resp = Frame::new(
                                    FrameKind::ChunkResponse,
                                    payload_for_server.clone(),
                                )
                                .unwrap();
                                ol_quic::transport::write_frame(&mut send, &resp)
                                    .await
                                    .unwrap();
                                send.finish().unwrap();
                            }
                            let _ = conn.closed().await;
                        });

                        let conn = client.connect(addr, alice_fp).await.unwrap();
                        let start = std::time::Instant::now();
                        for _ in 0..iters {
                            let req = Frame::new(FrameKind::ChunkRequest, vec![0u8; 32]).unwrap();
                            let resp = conn.send_frame_request_response(req).await.unwrap();
                            black_box(resp);
                        }
                        let elapsed = start.elapsed();
                        conn.close(0, b"ok");
                        let _ =
                            tokio::time::timeout(std::time::Duration::from_secs(3), server_handle)
                                .await;
                        elapsed
                    })
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_loopback_round_trip);
criterion_main!(benches);

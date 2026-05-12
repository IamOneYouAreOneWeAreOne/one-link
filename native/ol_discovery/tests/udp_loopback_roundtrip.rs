//! Two UdpTransport instances on loopback talk to each other.
//! The acceptance gate for production-deployable F1.3.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use ol_discovery::lookup::Transport;
use ol_discovery::node_id::NodeId;
use ol_discovery::rpc::{
    FindValueOutcome, Header, Request, Response, RpcEnvelope,
};
use ol_discovery::udp_transport::{
    EndpointResolver, RequestHandler, UdpTransport,
};

fn id(b: u8) -> NodeId {
    NodeId([b; 32])
}

/// Test handler: PING → Pong; FIND_NODE → return fixed closest set;
/// FIND_VALUE → return fixed closer set. Everything else → Pong.
struct StubHandler {
    closest_to_return: Mutex<Vec<NodeId>>,
}

impl RequestHandler for StubHandler {
    fn handle<'a>(
        &'a self,
        env: RpcEnvelope<Request>,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + 'a>> {
        Box::pin(async move {
            match env.body {
                Request::Ping => Response::Pong,
                Request::FindNode { .. } => {
                    let c = self.closest_to_return.lock().await.clone();
                    Response::FindNodeResult { closest: c }
                }
                Request::FindValue { .. } => {
                    let c = self.closest_to_return.lock().await.clone();
                    Response::FindValueResult(FindValueOutcome::Closer(c))
                }
                Request::Store(_) => {
                    Response::StoreResult(ol_discovery::rpc::StoreOutcome::Accepted)
                }
            }
        })
    }
}

/// Build two UdpTransports on ephemeral localhost ports, return
/// (transport_a, addr_a, transport_b, addr_b).
async fn spawn_two_peers(
    a_id: NodeId,
    b_id: NodeId,
    handler_b: Arc<dyn RequestHandler>,
) -> (UdpTransport, SocketAddr, UdpTransport, SocketAddr) {
    let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr_a = sock_a.local_addr().unwrap();
    let addr_b = sock_b.local_addr().unwrap();
    // Each peer's resolver only knows the OTHER peer.
    let r_a: Arc<dyn EndpointResolver> = {
        let b = b_id;
        Arc::new(move |peer: NodeId| if peer == b { Some(addr_b) } else { None })
    };
    let r_b: Arc<dyn EndpointResolver> = {
        let a = a_id;
        Arc::new(move |peer: NodeId| if peer == a { Some(addr_a) } else { None })
    };
    let t_a = UdpTransport::new(sock_a.clone(), a_id, r_a)
        .with_timeout_ms(1000);
    let t_b = UdpTransport::new(sock_b.clone(), b_id, r_b)
        .with_timeout_ms(1000);
    // B runs a receiver with the handler.
    let _h_b = t_b.spawn_receiver(handler_b);
    // A also runs a receiver so it can receive responses. Empty handler.
    struct PongOnly;
    impl RequestHandler for PongOnly {
        fn handle<'a>(
            &'a self,
            _env: RpcEnvelope<Request>,
        ) -> Pin<Box<dyn Future<Output = Response> + Send + 'a>> {
            Box::pin(async move { Response::Pong })
        }
    }
    let _h_a = t_a.spawn_receiver(Arc::new(PongOnly));
    (t_a, addr_a, t_b, addr_b)
}

#[tokio::test]
async fn find_node_query_over_udp_loopback() {
    let a_id = id(0x01);
    let b_id = id(0x02);
    let canned_closest = vec![id(0xA), id(0xB), id(0xC)];
    let handler = Arc::new(StubHandler {
        closest_to_return: Mutex::new(canned_closest.clone()),
    });
    let (t_a, _, _t_b, _) =
        spawn_two_peers(a_id, b_id, handler).await;
    // Give the receivers a beat to start.
    tokio::time::sleep(Duration::from_millis(20)).await;
    // Alice queries Bob for closest to a target.
    let target = id(0xFF);
    let result = t_a.query(b_id, target, false).await;
    match result {
        ol_discovery::lookup::LookupQueryResult::CloserPeers(c) => {
            assert_eq!(c, canned_closest);
        }
        other => panic!("expected CloserPeers, got {other:?}"),
    }
}

#[tokio::test]
async fn find_value_returns_closer_when_no_record() {
    let a_id = id(0x01);
    let b_id = id(0x02);
    let canned = vec![id(0x10), id(0x20)];
    let handler = Arc::new(StubHandler {
        closest_to_return: Mutex::new(canned.clone()),
    });
    let (t_a, _, _t_b, _) = spawn_two_peers(a_id, b_id, handler).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let target = id(0xCC);
    let result = t_a.query(b_id, target, true).await;
    match result {
        ol_discovery::lookup::LookupQueryResult::CloserPeers(c) => {
            assert_eq!(c, canned);
        }
        other => panic!("expected CloserPeers, got {other:?}"),
    }
}

#[tokio::test]
async fn query_unknown_peer_returns_failed() {
    // Alice's resolver doesn't know peer 0xFF.
    let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let a_id = id(0x01);
    let resolver: Arc<dyn EndpointResolver> =
        Arc::new(|_peer: NodeId| None);
    let t_a = UdpTransport::new(sock_a, a_id, resolver)
        .with_timeout_ms(500);
    let result = t_a.query(id(0xFF), id(0xAA), false).await;
    assert!(matches!(
        result,
        ol_discovery::lookup::LookupQueryResult::Failed
    ));
}

#[tokio::test]
async fn query_to_silent_peer_times_out_to_failed() {
    let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    // Bind a second socket but DON'T spawn a receiver.
    let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr_b = sock_b.local_addr().unwrap();
    let a_id = id(0x01);
    let b_id = id(0x02);
    let resolver: Arc<dyn EndpointResolver> =
        Arc::new(move |peer: NodeId| if peer == b_id { Some(addr_b) } else { None });
    let t_a = UdpTransport::new(sock_a, a_id, resolver)
        .with_timeout_ms(200);
    let result = t_a.query(b_id, id(0xCC), false).await;
    assert!(matches!(
        result,
        ol_discovery::lookup::LookupQueryResult::Failed
    ));
}

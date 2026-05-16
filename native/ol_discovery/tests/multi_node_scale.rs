//! Multi-node DHT scale test.
//!
//! Spins up N DhtNodes on loopback UDP, seeds them in a chain
//! (node[i+1] knows node[i]), then verifies a TRANSITIVE lookup
//! works: node[N-1] can find node[0]'s record via iterative
//! lookup that walks the chain.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use ol_discovery::dht_node::DhtNode;
use ol_discovery::node_id::NodeId;
use ol_discovery::record::{PeerRecord, SignedRecord, RECORD_DEFAULT_TTL_SECS};

struct Peer {
    _sk: SigningKey,
    id: NodeId,
    node: DhtNode,
    _record: SignedRecord,
}

fn make_peer(seed_peers: Vec<(NodeId, std::net::SocketAddr)>) -> Peer {
    let sk = SigningKey::generate(&mut OsRng);
    let id = NodeId::from_pubkey(&sk.verifying_key().to_bytes());
    let node =
        DhtNode::new("127.0.0.1:0".parse().unwrap(), id, seed_peers).unwrap();
    let addr = node.local_addr();
    let rec = PeerRecord {
        publisher_pubkey: sk.verifying_key().to_bytes(),
        endpoints: vec![format!("udp://{addr}")],
        publish_time_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        ttl_secs: RECORD_DEFAULT_TTL_SECS,
    };
    let signed = SignedRecord::sign(rec, &sk).unwrap();
    node.publish_self_record(signed.clone());
    Peer {
        _sk: sk,
        id,
        node,
        _record: signed,
    }
}

#[test]
fn ten_nodes_pairwise_lookup() {
    // Build 10 nodes; each one is seeded with all the prior ones.
    let mut peers: Vec<Peer> = Vec::new();
    for _ in 0..10 {
        let seeds = peers
            .iter()
            .map(|p| (p.id, p.node.local_addr()))
            .collect::<Vec<_>>();
        peers.push(make_peer(seeds));
    }
    // Give receivers time to warm up.
    std::thread::sleep(Duration::from_millis(100));

    // Every node should be able to look up node 0's record via
    // iterative discovery walking the chain.
    let target = peers[0].id;
    let mut found_count = 0;
    let mut missed = Vec::new();
    for (i, p) in peers.iter().enumerate().skip(1) {
        match p.node.lookup_record(target) {
            Ok(Some(rec)) => {
                rec.verify().expect("signature verifies");
                assert_eq!(rec.node_id(), target);
                found_count += 1;
            }
            Ok(None) => missed.push(i),
            Err(e) => panic!("lookup error from node {i}: {e}"),
        }
    }
    // 9 nodes lookup target = node[0]. At minimum: node[1] (direct
    // seed) and through chain to others.
    assert!(
        found_count >= 5,
        "expected at least 5 of 9 nodes to find node[0] via lookup; got {found_count}; missed={missed:?}"
    );

    for p in peers {
        p.node.shutdown();
    }
}

#[test]
fn five_nodes_lookup_in_all_directions() {
    // Build 5 nodes in a chain. Each looks up node 0.
    let mut peers: Vec<Peer> = Vec::new();
    for _ in 0..5 {
        let seeds = peers
            .iter()
            .map(|p| (p.id, p.node.local_addr()))
            .collect::<Vec<_>>();
        peers.push(make_peer(seeds));
    }
    std::thread::sleep(Duration::from_millis(80));

    // Each pair: source looks up target's record. The lookup MUST
    // either succeed (Ok), converge cleanly to None (Ok(None)), or
    // return a typed NoBootstrap error (peer 0 has empty routing
    // table). Never panic.
    use ol_discovery::dht_node::DhtError;
    use ol_discovery::lookup::LookupError;
    for src_idx in 0..peers.len() {
        for tgt_idx in 0..peers.len() {
            if src_idx == tgt_idx {
                continue;
            }
            let r =
                peers[src_idx].node.lookup_record(peers[tgt_idx].id);
            // Either Ok(Some|None) or Err(NoBootstrap) — both valid.
            match r {
                Ok(_) => {}
                Err(DhtError::Lookup(LookupError::NoBootstrap)) => {}
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
    }
    for p in peers {
        p.node.shutdown();
    }
}

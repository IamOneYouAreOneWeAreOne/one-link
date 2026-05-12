//! THE production acceptance gate: two DhtNodes on real UDP
//! sockets find each other.

use std::net::SocketAddr;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use ol_discovery::dht_node::DhtNode;
use ol_discovery::node_id::NodeId;
use ol_discovery::record::{PeerRecord, SignedRecord, RECORD_DEFAULT_TTL_SECS};

fn make_keypair() -> (SigningKey, NodeId) {
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key().to_bytes();
    let id = NodeId::from_pubkey(&pk);
    (sk, id)
}

fn make_self_record(sk: &SigningKey, addr: SocketAddr) -> SignedRecord {
    let rec = PeerRecord {
        publisher_pubkey: sk.verifying_key().to_bytes(),
        endpoints: vec![format!("udp://{addr}")],
        publish_time_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        ttl_secs: RECORD_DEFAULT_TTL_SECS,
    };
    SignedRecord::sign(rec, sk).unwrap()
}

#[test]
fn two_nodes_lookup_each_other() {
    let (sk_a, id_a) = make_keypair();
    let (sk_b, id_b) = make_keypair();
    // Bind A first (so we know its addr to seed B with).
    let node_a = DhtNode::new(
        "127.0.0.1:0".parse().unwrap(),
        id_a,
        vec![],
    )
    .unwrap();
    let addr_a = node_a.local_addr();
    let rec_a = make_self_record(&sk_a, addr_a);
    node_a.publish_self_record(rec_a.clone());

    // Bind B, seed it with A's (id, addr).
    let node_b = DhtNode::new(
        "127.0.0.1:0".parse().unwrap(),
        id_b,
        vec![(id_a, addr_a)],
    )
    .unwrap();
    let addr_b = node_b.local_addr();
    let rec_b = make_self_record(&sk_b, addr_b);
    node_b.publish_self_record(rec_b.clone());
    // A also gets a seed for B so it can route to B.
    node_a.add_seed_peer(id_b, addr_b);

    // Give receivers a beat to wire up.
    std::thread::sleep(Duration::from_millis(50));

    // B looks up A's NodeId — should find at least A in the closest set.
    let closest_to_a = node_b.lookup(id_a).expect("lookup ok");
    assert!(
        !closest_to_a.is_empty(),
        "B should find at least A in lookup result"
    );
    assert!(
        closest_to_a.contains(&id_a),
        "lookup result should include the target itself"
    );

    // A looks up B.
    let closest_to_b = node_a.lookup(id_b).expect("lookup ok");
    assert!(closest_to_b.contains(&id_b));

    node_a.shutdown();
    node_b.shutdown();
}

#[test]
fn dht_node_local_addr_reports_bound_port() {
    let (_, id) = make_keypair();
    let node =
        DhtNode::new("127.0.0.1:0".parse().unwrap(), id, vec![]).unwrap();
    let addr = node.local_addr();
    assert_eq!(addr.ip().to_string(), "127.0.0.1");
    assert!(addr.port() > 0);
    node.shutdown();
}

#[test]
fn dht_node_routing_table_grows_after_seed_add() {
    let (_, id_a) = make_keypair();
    let (_, id_b) = make_keypair();
    let node =
        DhtNode::new("127.0.0.1:0".parse().unwrap(), id_a, vec![]).unwrap();
    assert_eq!(node.routing_table_len(), 0);
    node.add_seed_peer(id_b, "127.0.0.1:12345".parse().unwrap());
    assert_eq!(node.routing_table_len(), 1);
    node.shutdown();
}

#[test]
fn dht_node_publish_self_record_increases_records_count() {
    let (sk, id) = make_keypair();
    let node =
        DhtNode::new("127.0.0.1:0".parse().unwrap(), id, vec![]).unwrap();
    assert_eq!(node.records_len(), 0);
    let rec = make_self_record(&sk, node.local_addr());
    node.publish_self_record(rec);
    assert_eq!(node.records_len(), 1);
    node.shutdown();
}

#[test]
fn dht_node_find_value_returns_stored_record() {
    let (sk_a, id_a) = make_keypair();
    let (sk_b, id_b) = make_keypair();
    let node_a = DhtNode::new(
        "127.0.0.1:0".parse().unwrap(),
        id_a,
        vec![],
    )
    .unwrap();
    let addr_a = node_a.local_addr();
    let rec_a = make_self_record(&sk_a, addr_a);
    node_a.publish_self_record(rec_a.clone());

    let node_b = DhtNode::new(
        "127.0.0.1:0".parse().unwrap(),
        id_b,
        vec![(id_a, addr_a)],
    )
    .unwrap();
    let _ = make_self_record(&sk_b, node_b.local_addr());
    std::thread::sleep(Duration::from_millis(50));

    // B looks up A's RECORD (FIND_VALUE) — should retrieve it.
    let found = node_b.lookup_record(id_a).expect("lookup_record ok");
    assert!(found.is_some());
    let found = found.unwrap();
    found.verify().unwrap();
    assert_eq!(found.record.publisher_pubkey, rec_a.record.publisher_pubkey);

    node_a.shutdown();
    node_b.shutdown();
}

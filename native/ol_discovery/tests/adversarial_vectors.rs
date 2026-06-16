//! Adversarial test vectors for the sovereign discovery layer.
//!
//! Covers known attack patterns against Kademlia DHTs:
//!   - Sybil/eclipse via bucket flooding
//!   - Forged record injection
//!   - RPC replay
//!   - Oversized payloads / amplification attempts
//!   - Lookup loop-back attacks (peer returning self)
//!   - Stale-timestamp replay

use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use ol_discovery::node_id::{NodeId, NODE_ID_BITS};
use ol_discovery::record::{PeerRecord, RecordError, SignedRecord};
use ol_discovery::routing::{InsertOutcome, RoutingTable};
use ol_discovery::rpc::{
    validate_response_size, FindValueOutcome, Header, Response, RpcError, MAX_CLOCK_SKEW_SECS,
    MAX_FIND_RESULTS,
};

fn make_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

// ── Sybil / Eclipse: routing-table flooding resistance ────────────

#[test]
fn adversarial_bucket_flood_does_not_evict_responding_head() {
    // An attacker creates many peers in the same bucket trying to
    // displace a legit peer. With least-recently-seen replacement,
    // the legit (early-arrival) peer stays UNTIL it times out.
    let own = NodeId([0x00; 32]);
    let mut t = RoutingTable::with_k(own, 2);
    // Two legit peers in bucket 0 (top bit set).
    let legit_a = NodeId({
        let mut x = [0u8; 32];
        x[0] = 0x80;
        x[1] = 0x01;
        x
    });
    let legit_b = NodeId({
        let mut x = [0u8; 32];
        x[0] = 0x80;
        x[1] = 0x02;
        x
    });
    t.insert(legit_a, 1);
    t.insert(legit_b, 2);
    // Flood 100 attacker peers in the same bucket. With bucket
    // full, every insert returns BucketFull (caller would PING the
    // head). Legit peers stay until they fail PINGs.
    for i in 0..100 {
        let attacker = NodeId({
            let mut x = [0u8; 32];
            x[0] = 0x80;
            x[1] = 0x10 + i;
            x
        });
        let outcome = t.insert(attacker, 1000 + i as u64);
        assert!(matches!(outcome, InsertOutcome::BucketFull { .. }));
    }
    // Both legit peers still in the table.
    assert!(t.contains(&legit_a));
    assert!(t.contains(&legit_b));
    assert_eq!(t.len(), 2);
}

#[test]
fn adversarial_sybil_close_to_target_node_costs_keygen() {
    // Demonstrating: NodeId comes from BLAKE3(ed25519_pubkey).
    // Generating an attractive NodeId near a specific target
    // requires keygen until the BLAKE3 hash hits the prefix.
    // No GPU shortcut on Ed25519 keygen -> meaningful cost per bit.
    //
    // This test just confirms that distinct keys produce distinct
    // NodeIds with high probability (sanity for the keygen-cost story).
    let mut ids = std::collections::HashSet::new();
    for _ in 0..200 {
        let sk = make_key();
        let id = NodeId::from_pubkey(&sk.verifying_key().to_bytes());
        assert!(ids.insert(id), "BLAKE3 collision in 200 keygens?!");
    }
}

// ── Forged record injection ───────────────────────────────────────

#[test]
fn adversarial_forged_signature_rejected() {
    let sk = make_key();
    let rec = PeerRecord {
        publisher_pubkey: sk.verifying_key().to_bytes(),
        endpoints: vec!["udp://1.2.3.4:5".into()],
        publish_time_unix: 1_700_000_000,
        ttl_secs: 86_400,
    };
    let signed = SignedRecord::sign(rec, &sk).unwrap();
    // Tamper the signature: flip every bit.
    let mut forged = signed.clone();
    for b in forged.signature.iter_mut() {
        *b ^= 0xFF;
    }
    assert_eq!(forged.verify().unwrap_err(), RecordError::BadSignature);
}

#[test]
fn adversarial_publisher_swap_rejected() {
    // Attacker captures a legit record + tries to swap in their own
    // publisher_pubkey while keeping the original signature. Verification
    // must reject (signature doesn't match the tampered canonical bytes).
    let sk_legit = make_key();
    let sk_attacker = make_key();
    let rec = PeerRecord {
        publisher_pubkey: sk_legit.verifying_key().to_bytes(),
        endpoints: vec!["udp://1.2.3.4:5".into()],
        publish_time_unix: 1_700_000_000,
        ttl_secs: 86_400,
    };
    let signed_legit = SignedRecord::sign(rec, &sk_legit).unwrap();
    let mut forged = signed_legit.clone();
    forged.record.publisher_pubkey = sk_attacker.verifying_key().to_bytes();
    let err = forged.verify().unwrap_err();
    assert!(matches!(
        err,
        RecordError::BadSignature | RecordError::MalformedPubkey
    ));
}

#[test]
fn adversarial_record_for_someone_else_at_sign_time() {
    // Attacker tries to mint a record claiming to be a different
    // publisher than they actually are.
    let sk_attacker = make_key();
    let other_pubkey = make_key().verifying_key().to_bytes();
    let rec = PeerRecord {
        publisher_pubkey: other_pubkey,
        endpoints: vec!["udp://attacker:5".into()],
        publish_time_unix: 1_700_000_000,
        ttl_secs: 86_400,
    };
    // sign() rejects: signing key's public component != claimed pubkey.
    assert_eq!(
        SignedRecord::sign(rec, &sk_attacker).unwrap_err(),
        RecordError::PubkeyMismatch
    );
}

// ── RPC replay + clock-skew defenses ──────────────────────────────

#[test]
fn adversarial_envelope_in_future_rejected() {
    let h = Header::new(
        NodeId([0xAA; 32]),
        [0x00; 16],
        1_000_000 + MAX_CLOCK_SKEW_SECS + 1,
    );
    assert!(!h.is_within_skew(1_000_000));
}

#[test]
fn adversarial_envelope_in_past_rejected() {
    let h = Header::new(NodeId([0xAA; 32]), [0x00; 16], 1_000);
    assert!(!h.is_within_skew(1_000 + MAX_CLOCK_SKEW_SECS + 1));
}

#[test]
fn adversarial_envelope_at_exact_boundary_accepted() {
    let h = Header::new(
        NodeId([0xAA; 32]),
        [0x00; 16],
        1_000_000 + MAX_CLOCK_SKEW_SECS,
    );
    assert!(h.is_within_skew(1_000_000));
}

// ── Amplification: oversized FIND_NODE/FIND_VALUE responses ────────

#[test]
fn adversarial_oversized_find_node_result_rejected() {
    // Receiver tries to return more than K closest. Caller validates
    // and rejects to defeat amplification (small request -> huge response).
    let resp = Response::FindNodeResult {
        closest: (0..(MAX_FIND_RESULTS + 50))
            .map(|i| NodeId([i as u8; 32]))
            .collect(),
    };
    let err = validate_response_size(&resp).unwrap_err();
    assert!(matches!(err, RpcError::TooManyResults { .. }));
}

#[test]
fn adversarial_oversized_find_value_closer_rejected() {
    let resp = Response::FindValueResult(FindValueOutcome::Closer(
        (0..(MAX_FIND_RESULTS + 1))
            .map(|i| NodeId([i as u8; 32]))
            .collect(),
    ));
    let err = validate_response_size(&resp).unwrap_err();
    assert!(matches!(err, RpcError::TooManyResults { .. }));
}

#[test]
fn adversarial_endpoint_count_amplification_rejected() {
    // Try to mint a record with too many endpoints (would otherwise
    // bloat each STORE message + multiply DHT storage cost).
    let sk = make_key();
    let mut rec = PeerRecord {
        publisher_pubkey: sk.verifying_key().to_bytes(),
        endpoints: vec![],
        publish_time_unix: 1_700_000_000,
        ttl_secs: 86_400,
    };
    for i in 0..50 {
        rec.endpoints.push(format!("udp://{i}.0.0.0:1"));
    }
    let err = SignedRecord::sign(rec, &sk).unwrap_err();
    assert!(matches!(err, RecordError::TooManyEndpoints { .. }));
}

#[test]
fn adversarial_endpoint_length_amplification_rejected() {
    let sk = make_key();
    let mut rec = PeerRecord {
        publisher_pubkey: sk.verifying_key().to_bytes(),
        endpoints: vec![],
        publish_time_unix: 1_700_000_000,
        ttl_secs: 86_400,
    };
    rec.endpoints.push("x".repeat(10_000));
    let err = SignedRecord::sign(rec, &sk).unwrap_err();
    assert!(matches!(err, RecordError::EndpointTooLong { .. }));
}

// ── Routing-table edge attacks ────────────────────────────────────

#[test]
fn adversarial_max_bucket_index_holds() {
    // Two NodeIds differing only in the very last bit.
    // bucket_index should be exactly NODE_ID_BITS - 1.
    let a = NodeId([0u8; 32]);
    let mut bx = [0u8; 32];
    bx[31] = 0x01;
    let b = NodeId(bx);
    assert_eq!(a.bucket_index(&b), Some(NODE_ID_BITS - 1));
}

#[test]
fn adversarial_routing_table_handles_all_bits_flipped() {
    // Edge case: peer ID is exact complement of own. Bucket 0
    // (everything-differs). Routing must accept.
    let own = NodeId([0x00; 32]);
    let attacker = NodeId([0xFF; 32]);
    assert_eq!(own.bucket_index(&attacker), Some(0));
    let mut t = RoutingTable::new(own);
    assert_eq!(t.insert(attacker, 0), InsertOutcome::Inserted);
    assert!(t.contains(&attacker));
}

// ── Expired-record replay ──────────────────────────────────────────

#[test]
fn adversarial_expired_record_signature_still_validates() {
    // Important property: an expired record's SIGNATURE is still
    // valid (signature commits to the timestamp). Receivers reject
    // expired records via the freshness check, NOT by signature
    // failure. This means a captured-but-expired record is provably
    // OLD — useful for forensic / debug — but not usable.
    let sk = make_key();
    let rec = PeerRecord {
        publisher_pubkey: sk.verifying_key().to_bytes(),
        endpoints: vec!["udp://1.2.3.4:5".into()],
        publish_time_unix: 1_000,
        ttl_secs: 100,
    };
    let signed = SignedRecord::sign(rec, &sk).unwrap();
    // Signature still validates.
    signed.verify().unwrap();
    // But the freshness check at "now = 2000" returns false (expired).
    assert!(!signed.verify_and_check_freshness(2_000).unwrap());
    // While at "now = 1050" it's still fresh.
    assert!(signed.verify_and_check_freshness(1_050).unwrap());
}

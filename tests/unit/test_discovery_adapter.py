"""Acceptance tests for the Python adapter wrapping ol_discovery
(Phase F1.3 daemon wiring — sovereign DHT peer discovery)."""

from __future__ import annotations

import pytest


def _native_available() -> bool:
    try:
        from one_link_native import discovery  # noqa: F401

        return True
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native.discovery not installed",
)


def test_module_imports_cleanly():
    from one_link import discovery_native as disc

    assert disc.HAS_NATIVE is True
    assert disc.NODE_ID_BYTES == 32
    assert disc.NODE_ID_BITS == 256
    assert disc.K_BUCKET_DEFAULT == 20
    assert disc.MAX_BUCKETS == 256
    assert disc.RECORD_DEFAULT_TTL_SECS == 24 * 60 * 60


# ── NodeId surface ────────────────────────────────────────────────


def test_node_id_from_raw_bytes():
    from one_link import discovery_native as disc

    raw = bytes(range(32))
    nid = disc.node_id(raw)
    assert nid.as_bytes() == raw


def test_node_id_rejects_wrong_size():
    from one_link import discovery_native as disc

    with pytest.raises(ValueError):
        disc.node_id(b"too short")
    with pytest.raises(ValueError):
        disc.node_id(b"x" * 33)


def test_node_id_from_pubkey_deterministic():
    from one_link import discovery_native as disc

    pk = b"\x42" * 32
    nid1 = disc.node_id_from_pubkey(pk)
    nid2 = disc.node_id_from_pubkey(pk)
    assert nid1.as_bytes() == nid2.as_bytes()
    # Different pubkey -> different NodeId.
    nid3 = disc.node_id_from_pubkey(b"\x43" * 32)
    assert nid1.as_bytes() != nid3.as_bytes()


def test_node_id_distance_self_is_zero():
    from one_link import discovery_native as disc

    nid = disc.node_id(b"\x42" * 32)
    assert nid.distance(nid) == b"\x00" * 32


def test_node_id_bucket_index_self_is_none():
    from one_link import discovery_native as disc

    nid = disc.node_id(b"\x42" * 32)
    assert nid.bucket_index(nid) is None


def test_node_id_bucket_index_full_complement():
    """NodeIds that differ in the top bit are in bucket 0."""
    from one_link import discovery_native as disc

    a = disc.node_id(b"\x00" * 32)
    b = disc.node_id(b"\x80" + b"\x00" * 31)
    assert a.bucket_index(b) == 0


# ── PeerRecord + SignedRecord ─────────────────────────────────────


def _make_keypair():
    """Build an Ed25519 keypair as (seed, pubkey)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import secrets

    seed = secrets.token_bytes(32)
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return seed, pk


def test_sign_and_verify_roundtrip():
    from one_link import discovery_native as disc

    seed, pk = _make_keypair()
    rec = disc.peer_record(
        publisher_pubkey=pk,
        endpoints=["udp://1.2.3.4:5678"],
        publish_time_unix=1_700_000_000,
    )
    signed = disc.sign_record(rec, signing_key_seed=seed)
    # Verify must succeed (no exception).
    signed.verify()
    # Fresh at +100 seconds.
    assert signed.verify_and_check_freshness(1_700_000_100) is True


def test_signed_record_carries_metadata():
    from one_link import discovery_native as disc

    seed, pk = _make_keypair()
    rec = disc.peer_record(
        publisher_pubkey=pk,
        endpoints=["udp://1.2.3.4:5678", "quic://5.6.7.8:9012"],
        publish_time_unix=1_700_000_000,
        ttl_secs=3600,
    )
    signed = disc.sign_record(rec, signing_key_seed=seed)
    r = signed.record()
    assert r.publisher_pubkey() == pk
    assert r.endpoints() == ["udp://1.2.3.4:5678", "quic://5.6.7.8:9012"]
    assert r.publish_time_unix() == 1_700_000_000
    assert r.ttl_secs() == 3600
    assert len(signed.signature()) == 64


def test_record_node_id_matches_pubkey_hash():
    """Record's node_id() must equal NodeId.from_pubkey(publisher_pubkey)."""
    from one_link import discovery_native as disc

    seed, pk = _make_keypair()
    rec = disc.peer_record(
        publisher_pubkey=pk,
        endpoints=["udp://x:1"],
        publish_time_unix=1,
    )
    assert rec.node_id().as_bytes() == disc.node_id_from_pubkey(pk).as_bytes()


def test_verify_rejects_tampered_record():
    from one_link import discovery_native as disc

    seed, pk = _make_keypair()
    rec = disc.peer_record(
        publisher_pubkey=pk,
        endpoints=["udp://1.2.3.4:5678"],
        publish_time_unix=1_700_000_000,
    )
    signed = disc.sign_record(rec, signing_key_seed=seed)
    # Build a tampered record + reattach the original signature.
    rec_tampered = disc.peer_record(
        publisher_pubkey=pk,
        endpoints=["udp://9.9.9.9:6666"],  # changed endpoint
        publish_time_unix=1_700_000_000,
    )
    sig = signed.signature()
    tampered = disc.signed_record_from_parts(record=rec_tampered, signature=sig)
    with pytest.raises(ValueError):
        tampered.verify()


def test_freshness_check_catches_expired():
    from one_link import discovery_native as disc

    seed, pk = _make_keypair()
    rec = disc.peer_record(
        publisher_pubkey=pk,
        endpoints=["udp://1.2.3.4:5678"],
        publish_time_unix=1000,
        ttl_secs=100,
    )
    signed = disc.sign_record(rec, signing_key_seed=seed)
    # Within TTL.
    assert signed.verify_and_check_freshness(1050) is True
    # Expired.
    assert signed.verify_and_check_freshness(1101) is False


# ── RoutingTable surface ──────────────────────────────────────────


def test_routing_table_basic_lifecycle():
    from one_link import discovery_native as disc

    own = disc.node_id(b"\x00" * 32)
    table = disc.routing_table(own, k=4)
    assert table.is_empty()
    assert table.len() == 0
    assert table.k() == 4
    assert table.own_id().as_bytes() == own.as_bytes()


def test_routing_insert_inserted_then_bumped():
    from one_link import discovery_native as disc

    own = disc.node_id(b"\x00" * 32)
    table = disc.routing_table(own, k=4)
    peer = disc.node_id(b"\xAA" * 32)
    outcome, head = table.insert(peer, last_seen_unix=100)
    assert outcome == disc.InsertOutcome.Inserted
    assert head is None
    assert table.contains(peer)
    # Reinsert -> bump to tail.
    outcome2, _ = table.insert(peer, last_seen_unix=200)
    assert outcome2 == disc.InsertOutcome.BumpedToTail
    assert table.len() == 1


def test_routing_self_insert_ignored():
    from one_link import discovery_native as disc

    own = disc.node_id(b"\x42" * 32)
    table = disc.routing_table(own, k=4)
    outcome, head = table.insert(own, last_seen_unix=100)
    assert outcome == disc.InsertOutcome.SelfInsertIgnored
    assert head is None
    assert table.is_empty()


def test_routing_bucket_full_returns_head():
    from one_link import discovery_native as disc

    own = disc.node_id(b"\x00" * 32)
    table = disc.routing_table(own, k=2)
    # Two peers in same bucket (top bit set).
    p1 = disc.node_id(b"\x80\x01" + b"\x00" * 30)
    p2 = disc.node_id(b"\x80\x02" + b"\x00" * 30)
    p3 = disc.node_id(b"\x80\x03" + b"\x00" * 30)
    table.insert(p1, 1)
    table.insert(p2, 2)
    outcome, head = table.insert(p3, 3)
    assert outcome == disc.InsertOutcome.BucketFull
    assert head is not None
    # Head is the LEAST-recently-seen = p1.
    assert head.as_bytes() == p1.as_bytes()
    assert not table.contains(p3)  # not inserted; caller decides via PING


def test_routing_closest_to_returns_sorted():
    from one_link import discovery_native as disc

    own = disc.node_id(b"\x00" * 32)
    table = disc.routing_table(own, k=20)
    # Insert several peers.
    for i in range(1, 16):
        peer = disc.node_id(bytes([i]) + b"\x00" * 31)
        table.insert(peer, last_seen_unix=i)
    # Look up closest to a target far from own.
    target = disc.node_id(b"\xFF" * 32)
    closest = table.closest_to(target)
    assert len(closest) <= 20
    # Distances monotonically non-decreasing.
    distances = [c.distance(target) for c in closest]
    for a, b in zip(distances, distances[1:]):
        assert a <= b


def test_routing_remove():
    from one_link import discovery_native as disc

    own = disc.node_id(b"\x00" * 32)
    table = disc.routing_table(own, k=4)
    peer = disc.node_id(b"\xAA" * 32)
    table.insert(peer, 100)
    assert table.contains(peer)
    assert table.remove(peer) is True
    assert not table.contains(peer)
    assert table.remove(peer) is False  # already gone


def test_routing_bucket_sizes_sums_to_len():
    from one_link import discovery_native as disc

    own = disc.node_id(b"\x00" * 32)
    table = disc.routing_table(own, k=8)
    for i in range(1, 24):
        peer = disc.node_id(bytes([i]) + b"\x00" * 31)
        table.insert(peer, last_seen_unix=i)
    sizes = table.bucket_sizes()
    assert len(sizes) == 256
    assert sum(sizes) == table.len()


# ── Cross-component scenario: discovery flow ──────────────────────


def test_end_to_end_publish_and_lookup():
    """A peer publishes a signed record; another verifies + indexes."""
    from one_link import discovery_native as disc

    seed_a, pk_a = _make_keypair()
    seed_b, pk_b = _make_keypair()

    # Peer A: publish self-record.
    rec_a = disc.peer_record(
        publisher_pubkey=pk_a,
        endpoints=["udp://10.0.0.1:5000"],
        publish_time_unix=1_700_000_000,
    )
    signed_a = disc.sign_record(rec_a, signing_key_seed=seed_a)

    # Peer B: receives signed_a, verifies, indexes peer A in routing table.
    signed_a.verify()  # raises on bad sig
    a_node_id = signed_a.node_id()
    own_b = disc.node_id_from_pubkey(pk_b)
    table_b = disc.routing_table(own_b)
    outcome, _ = table_b.insert(a_node_id, last_seen_unix=1_700_000_001)
    assert outcome == disc.InsertOutcome.Inserted

    # Later: B looks up A's NodeId, finds the entry.
    found = table_b.closest_to(a_node_id)
    assert len(found) >= 1
    assert found[0].as_bytes() == a_node_id.as_bytes()


# ── F1.3++ DhtNode end-to-end (the production acceptance gate) ────


def test_two_dht_nodes_find_each_other_over_udp():
    """THE production acceptance gate: two Python-constructed
    DhtNodes on real UDP loopback sockets discover each other,
    look each other up by NodeId, and retrieve cryptographically-
    signed records end-to-end."""
    import time

    from one_link import discovery_native as disc

    seed_a, pk_a = _make_keypair()
    seed_b, pk_b = _make_keypair()
    id_a = disc.node_id_from_pubkey(pk_a)
    id_b = disc.node_id_from_pubkey(pk_b)

    # Spin up A first.
    node_a = disc.dht_node(
        bind_addr="127.0.0.1:0", own_id=id_a, seed_peers=[]
    )
    try:
        addr_a = node_a.local_addr()
        rec_a = disc.peer_record(
            publisher_pubkey=pk_a,
            endpoints=[f"udp://{addr_a}"],
            publish_time_unix=int(time.time()),
        )
        signed_a = disc.sign_record(rec_a, signing_key_seed=seed_a)
        node_a.publish_self_record(signed_a)

        # Spin up B, seed it with A.
        node_b = disc.dht_node(
            bind_addr="127.0.0.1:0",
            own_id=id_b,
            seed_peers=[(id_a, addr_a)],
        )
        try:
            addr_b = node_b.local_addr()
            rec_b = disc.peer_record(
                publisher_pubkey=pk_b,
                endpoints=[f"udp://{addr_b}"],
                publish_time_unix=int(time.time()),
            )
            signed_b = disc.sign_record(rec_b, signing_key_seed=seed_b)
            node_b.publish_self_record(signed_b)
            node_a.add_seed_peer(id_b, addr_b)

            # Let receivers warm up.
            time.sleep(0.05)

            # B looks up A's RECORD via FIND_VALUE over the wire.
            found_a = node_b.lookup_record(id_a)
            assert found_a is not None
            found_a.verify()  # cryptographic verification
            assert found_a.record().publisher_pubkey() == pk_a

            # A looks up B via FIND_NODE.
            closest_to_b = node_a.lookup(id_b)
            assert any(p.as_bytes() == id_b.as_bytes() for p in closest_to_b)

            # Both routing tables have learned each other.
            assert node_a.routing_table_len() >= 1
            assert node_b.routing_table_len() >= 1
        finally:
            node_b.shutdown()
    finally:
        node_a.shutdown()


def test_dht_node_local_addr_returns_bound_port():
    from one_link import discovery_native as disc

    _, pk = _make_keypair()
    id_ = disc.node_id_from_pubkey(pk)
    node = disc.dht_node(bind_addr="127.0.0.1:0", own_id=id_)
    try:
        addr = node.local_addr()
        assert addr.startswith("127.0.0.1:")
        port = int(addr.split(":")[1])
        assert port > 0
    finally:
        node.shutdown()


def test_dht_node_shutdown_then_methods_raise():
    from one_link import discovery_native as disc

    _, pk = _make_keypair()
    id_ = disc.node_id_from_pubkey(pk)
    node = disc.dht_node(bind_addr="127.0.0.1:0", own_id=id_)
    node.shutdown()
    with pytest.raises(RuntimeError):
        node.local_addr()


def test_dht_node_rejects_bad_bind_addr():
    from one_link import discovery_native as disc

    _, pk = _make_keypair()
    id_ = disc.node_id_from_pubkey(pk)
    with pytest.raises(ValueError):
        disc.dht_node(bind_addr="not-an-addr", own_id=id_)

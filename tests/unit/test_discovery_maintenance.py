"""Row 3 acceptance tests for the DhtNode maintenance API
(refresh_stale_buckets / republish_records / tick_maintenance) +
the asyncio run_maintenance_loop helper."""

from __future__ import annotations

import asyncio
import time

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


def _make_node(seed_peers=None):
    from one_link import discovery_native as disc
    import secrets

    pub = secrets.token_bytes(32)
    nid = disc.node_id_from_pubkey(pub)
    return disc.dht_node(
        bind_addr="127.0.0.1:0",
        own_id=nid,
        seed_peers=seed_peers or [],
    ), nid


def test_tick_maintenance_returns_tuple_on_empty_node():
    """Empty node: bucket refresh + record republish both no-op."""
    node, _ = _make_node()
    try:
        now = int(time.time())
        result = node.tick_maintenance(now, 3600, 3600)
        assert isinstance(result, tuple)
        assert len(result) == 2
        refreshed, republished = result
        assert refreshed == 0
        assert republished == 0
    finally:
        node.shutdown()


def test_refresh_stale_buckets_marks_fresh_when_seeded():
    """A node seeded with another peer has non-empty buckets; first
    refresh call returns >0, second immediately after returns 0."""
    from one_link import discovery_native as disc
    import secrets

    # Create a seed peer first.
    seed_node, seed_id = _make_node()
    try:
        seed_addr = seed_node.local_addr()

        # Create a fresh node seeded with the first.
        pub = secrets.token_bytes(32)
        nid = disc.node_id_from_pubkey(pub)
        client = disc.dht_node(
            bind_addr="127.0.0.1:0",
            own_id=nid,
            seed_peers=[(seed_id, seed_addr)],
        )
        try:
            # First call with future timestamp marks all initialized
            # buckets as stale, then refreshes them.
            future = int(time.time()) + 10
            count = client.refresh_stale_buckets(future, 0)
            assert count > 0, "expected at least one bucket to refresh"

            # Second call with max_age=1: just-marked buckets count
            # as fresh.
            count_again = client.refresh_stale_buckets(future, 1)
            assert count_again == 0
        finally:
            client.shutdown()
    finally:
        seed_node.shutdown()


def test_republish_without_peers_reports_no_acknowledgement():
    """An eligible record remains cached, but no peer can acknowledge it."""
    from one_link import discovery_native as disc

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    priv_seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    real_pub = priv.public_key().public_bytes_raw()
    # A self-record is valid only when its publisher-derived node ID matches
    # the DHT node's configured identity. The old fixture accidentally tested
    # an impossible cross-identity publication that now correctly fails shut.
    nid = disc.node_id_from_pubkey(real_pub)
    node = disc.dht_node(bind_addr="127.0.0.1:0", own_id=nid, seed_peers=[])
    try:
        addr = node.local_addr()
        real_rec = disc.peer_record(
            publisher_pubkey=real_pub,
            endpoints=[f"udp://{addr}"],
            publish_time_unix=int(time.time()),
        )
        signed = disc.sign_record(real_rec, signing_key_seed=priv_seed)
        node.publish_self_record(signed)
        assert node.records_len() == 1

        future = int(time.time()) + 10
        republished = node.republish_records(future, 0)
        assert republished == 0
        assert node.records_len() == 1

        # Very large max_age → record looks fresh → 0.
        republished_fresh = node.republish_records(future, 10_000)
        assert republished_fresh == 0
    finally:
        node.shutdown()


def test_republish_counts_record_acknowledged_by_reachable_peer():
    """The result counts distinct records with a real remote STORE ACK."""
    from one_link import discovery_native as disc

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    def make_identity():
        private_key = Ed25519PrivateKey.generate()
        seed = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_key = private_key.public_key().public_bytes_raw()
        return seed, public_key, disc.node_id_from_pubkey(public_key)

    seed_a, pub_a, id_a = make_identity()
    node_a = disc.dht_node(bind_addr="127.0.0.1:0", own_id=id_a, seed_peers=[])
    node_b = None
    try:
        record_a = disc.peer_record(
            publisher_pubkey=pub_a,
            endpoints=[f"udp://{node_a.local_addr()}"],
            publish_time_unix=int(time.time()),
        )
        node_a.publish_self_record(
            disc.sign_record(record_a, signing_key_seed=seed_a)
        )

        seed_b, pub_b, id_b = make_identity()
        node_b = disc.dht_node(
            bind_addr="127.0.0.1:0",
            own_id=id_b,
            seed_peers=[(id_a, node_a.local_addr())],
        )
        record_b = disc.peer_record(
            publisher_pubkey=pub_b,
            endpoints=[f"udp://{node_b.local_addr()}"],
            publish_time_unix=int(time.time()),
        )
        node_b.publish_self_record(
            disc.sign_record(record_b, signing_key_seed=seed_b)
        )
        node_a.add_seed_peer(id_b, node_b.local_addr())
        time.sleep(0.05)

        future = int(time.time()) + 10
        assert node_b.republish_records(future, 0) == 1
        assert node_a.lookup_record(id_b) is not None
    finally:
        if node_b is not None:
            node_b.shutdown()
        node_a.shutdown()


def test_tick_maintenance_returns_combined_counts():
    """tick_maintenance calls both passes; returned tuple matches
    the (refreshed, republished) shape."""
    node, _ = _make_node()
    try:
        now = int(time.time())
        refreshed, republished = node.tick_maintenance(now, 3600, 3600)
        # Empty node: both zero.
        assert refreshed == 0
        assert republished == 0
    finally:
        node.shutdown()


def test_run_maintenance_loop_respects_stop_event():
    """The asyncio loop helper exits cleanly when the stop event fires."""
    from one_link import discovery_native as disc

    async def runit():
        node, _ = _make_node()
        try:
            stop = asyncio.Event()
            task = asyncio.create_task(
                disc.run_maintenance_loop(
                    node, period_secs=0.05, stop_event=stop
                )
            )
            # Let it tick a few times.
            await asyncio.sleep(0.2)
            stop.set()
            await asyncio.wait_for(task, timeout=2.0)
        finally:
            node.shutdown()

    asyncio.run(runit())


def test_run_maintenance_loop_swallows_errors():
    """The loop must not abort if a tick raises — it logs + continues."""
    from one_link import discovery_native as disc

    class FakeNode:
        def __init__(self):
            self.ticks = 0

        def tick_maintenance(self, now, b, r):
            self.ticks += 1
            if self.ticks == 1:
                raise RuntimeError("simulated tick failure")
            return (0, 0)

    async def runit():
        node = FakeNode()
        stop = asyncio.Event()
        task = asyncio.create_task(
            disc.run_maintenance_loop(node, period_secs=0.02, stop_event=stop)
        )
        await asyncio.sleep(0.1)
        stop.set()
        await asyncio.wait_for(task, timeout=2.0)
        assert node.ticks >= 2  # survived the error + ticked again

    asyncio.run(runit())

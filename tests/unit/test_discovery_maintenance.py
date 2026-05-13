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


def test_republish_records_counts_aged_records():
    """A node with one self-record: with max_age=0 it counts as
    aged → 1 republished; with large max_age → 0."""
    from one_link import discovery_native as disc
    import secrets

    # ed25519 keypair for signing the record.
    sk_seed = secrets.token_bytes(32)
    pub = secrets.token_bytes(32)  # not actually paired; the record's
    # publisher_pubkey just identifies it.
    nid = disc.node_id_from_pubkey(pub)
    node = disc.dht_node(
        bind_addr="127.0.0.1:0", own_id=nid, seed_peers=[]
    )
    try:
        # Construct + sign a record. publisher_pubkey must match the
        # signing key's pubkey for verify, but for republish we only
        # need it to be present in the records map.
        addr = node.local_addr()
        rec = disc.peer_record(
            publisher_pubkey=pub,
            endpoints=[f"udp://{addr}"],
            publish_time_unix=int(time.time()),
        )
        # The sign uses sk_seed and signs the canonical bytes; the
        # record's publisher_pubkey is for verifying. We use SAME
        # pub <-> sk pair via ed25519 deriving from seed; for this
        # test we don't actually verify the signature, just store +
        # republish.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives import serialization

        priv = Ed25519PrivateKey.generate()
        priv_seed = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        real_pub = priv.public_key().public_bytes_raw()
        real_rec = disc.peer_record(
            publisher_pubkey=real_pub,
            endpoints=[f"udp://{addr}"],
            publish_time_unix=int(time.time()),
        )
        signed = disc.sign_record(real_rec, signing_key_seed=priv_seed)
        node.publish_self_record(signed)

        future = int(time.time()) + 10
        republished = node.republish_records(future, 0)
        assert republished == 1

        # Very large max_age → record looks fresh → 0.
        republished_fresh = node.republish_records(future, 10_000)
        assert republished_fresh == 0
    finally:
        node.shutdown()


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

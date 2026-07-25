"""Adapter for the Coherence Mesh F1.3 sovereign-discovery primitive
(``ol_discovery`` via ``one_link_native``).

Per COHERENCE_MESH_PLAN.md Phase F1.3. Kademlia DHT for sovereign
peer discovery — two daemons find each other WITHOUT any rendezvous
server, DNS, or central registry.

Exposes the sync pieces (NodeId, RoutingTable, SignedRecord); the
daemon orchestrates lookup at the Python level using its own asyncio
UDP socket.

Typical daemon usage:

.. code-block:: python

    from one_link import discovery_native as disc

    # Derive my NodeId from my Ed25519 master pubkey.
    my_id = disc.node_id_from_pubkey(my_master_pubkey)

    # Stand up the routing table.
    table = disc.routing_table(my_id, k=20)

    # On every received RPC from a peer, refresh their table entry.
    outcome, head = table.insert(peer_id, last_seen_unix=now)
    if outcome == disc.InsertOutcome.BucketFull:
        # PING head; if timeout, table.replace_head_on_timeout(...)
        ...

    # Publish own reachability as a signed record.
    rec = disc.peer_record(
        publisher_pubkey=my_master_pubkey,
        endpoints=['udp://1.2.3.4:5678', 'quic://my.host:9012'],
        publish_time_unix=now,
    )
    signed = disc.sign_record(rec, signing_key_seed=my_master_seed)
    # ...gossip `signed` to nearby peers' routing tables...

    # When receiving a record from a peer, verify before trusting.
    signed.verify()  # raises ValueError if signature bad
    if signed.verify_and_check_freshness(now_unix=now):
        # Trusted + not expired; use it.
        ...
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from one_link_native.discovery import InsertOutcome as NativeInsertOutcome

log = logging.getLogger(__name__)

InsertOutcome: type[NativeInsertOutcome] | None

try:
    from one_link_native import discovery as _native_disc  # type: ignore[import-not-found,attr-defined]

    HAS_NATIVE: bool = True
    InsertOutcome = _native_disc.InsertOutcome
    NODE_ID_BYTES: int = _native_disc.NODE_ID_BYTES
    NODE_ID_BITS: int = _native_disc.NODE_ID_BITS
    K_BUCKET_DEFAULT: int = _native_disc.K_BUCKET_DEFAULT
    MAX_BUCKETS: int = _native_disc.MAX_BUCKETS
    RECORD_DEFAULT_TTL_SECS: int = _native_disc.RECORD_DEFAULT_TTL_SECS
except ImportError as exc:
    HAS_NATIVE = False
    _native_disc = None  # type: ignore[assignment]
    InsertOutcome = None  # type: ignore[assignment]
    NODE_ID_BYTES = 32
    NODE_ID_BITS = 256
    K_BUCKET_DEFAULT = 20
    MAX_BUCKETS = 256
    RECORD_DEFAULT_TTL_SECS = 24 * 60 * 60
    log.info(
        "one_link_native.discovery not installed (%s); sovereign "
        "peer discovery unavailable. Build via "
        "`cd native && maturin develop --release`.",
        exc,
    )


def node_id(raw: bytes) -> Any:
    """Construct a NodeId from 32 raw bytes."""
    _require_native()
    return _native_disc.NodeId(bytes(raw))


def node_id_from_pubkey(pubkey: bytes) -> Any:
    """Derive a NodeId = BLAKE3(ed25519_pubkey).

    ``pubkey`` must be 32 bytes (the raw Ed25519 public key).
    """
    _require_native()
    return _native_disc.NodeId.from_pubkey(bytes(pubkey))


def peer_record(
    *,
    publisher_pubkey: bytes,
    endpoints: list[str],
    publish_time_unix: int,
    ttl_secs: int | None = None,
) -> Any:
    """Build an unsigned peer-announcement record.

    ``ttl_secs`` defaults to 24 hours.
    """
    _require_native()
    ttl = (
        int(ttl_secs)
        if ttl_secs is not None
        else RECORD_DEFAULT_TTL_SECS
    )
    return _native_disc.PeerRecord(
        bytes(publisher_pubkey),
        list(endpoints),
        int(publish_time_unix),
        ttl,
    )


def sign_record(record: Any, *, signing_key_seed: bytes) -> Any:
    """Sign a PeerRecord with a 32-byte Ed25519 signing-key seed.

    The signing key's public component must match
    ``record.publisher_pubkey`` (otherwise raises ValueError).
    """
    _require_native()
    return _native_disc.SignedRecord.sign(record, bytes(signing_key_seed))


def signed_record_from_parts(*, record: Any, signature: bytes) -> Any:
    """Reconstruct a SignedRecord from its (record, 64-byte signature)
    components — e.g., when received off the wire."""
    _require_native()
    return _native_disc.SignedRecord(record, bytes(signature))


def routing_table(own_id: Any, *, k: int = K_BUCKET_DEFAULT) -> Any:
    """Build a Kademlia K-bucket routing table."""
    _require_native()
    return _native_disc.RoutingTable(own_id, int(k))


def dht_node(
    *,
    bind_addr: str,
    own_id: Any,
    seed_peers: list[tuple[Any, str]] | None = None,
) -> Any:
    """Build a production-deployable DhtNode.

    ``bind_addr``: "host:port" the UDP socket binds to (use
    "0.0.0.0:7117" in production; "127.0.0.1:0" for ephemeral test).
    ``own_id``: this node's NodeId.
    ``seed_peers``: optional list of (NodeId, "host:port") bootstrap
    peers. Empty for the first node in a fresh swarm.

    The returned object owns a tokio runtime + UDP socket + receiver
    task. Call ``shutdown()`` to release cleanly.
    """
    _require_native()
    return _native_disc.DhtNode(
        bind_addr,
        own_id,
        list(seed_peers or []),
    )


# Row 3 maintenance defaults. Kademlia paper recommends 1 hour for
# both; daemons can tune via DhtNode.tick_maintenance(...).
BUCKET_REFRESH_INTERVAL_SECS = 3600
RECORD_REPUBLISH_INTERVAL_SECS = 3600


async def run_maintenance_loop(
    node: Any,
    *,
    period_secs: float = 60.0,
    bucket_max_age_secs: int = BUCKET_REFRESH_INTERVAL_SECS,
    record_max_age_secs: int = RECORD_REPUBLISH_INTERVAL_SECS,
    stop_event: Any = None,
) -> None:
    """Row 3 — long-running asyncio maintenance loop for a DhtNode.

    Calls ``node.tick_maintenance(...)`` every ``period_secs`` seconds
    with the configured staleness thresholds. Returns when
    ``stop_event`` (an asyncio.Event) is set.

    Daemons typically schedule this once at startup:

    .. code-block:: python

        node = disc.dht_node(bind_addr="0.0.0.0:7117", own_id=my_id)
        stop = asyncio.Event()
        task = asyncio.create_task(disc.run_maintenance_loop(node, stop_event=stop))
        # ... at shutdown:
        stop.set()
        await task
    """
    import asyncio
    import time

    if stop_event is None:
        stop_event = asyncio.Event()
    while not stop_event.is_set():
        try:
            now = int(time.time())
            node.tick_maintenance(
                now, bucket_max_age_secs, record_max_age_secs
            )
        except Exception as exc:
            # Maintenance is availability work rather than a request-path
            # security boundary, so a single failed tick remains non-fatal.
            # It must not be invisible: a permanently broken DHT otherwise
            # looks like an empty network forever.
            log.warning("sovereign discovery maintenance tick failed: %s", exc)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=period_secs)
        except asyncio.TimeoutError:
            continue


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.discovery required for sovereign DHT "
            "discovery but not installed; build via "
            "`cd native && maturin develop --release`."
        )

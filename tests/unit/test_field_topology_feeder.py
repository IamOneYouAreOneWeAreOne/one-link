"""Tests for the daemon's FieldSnapshotManager topology feeder.

Without the feeder, the manager spins idle (no peers, no edges, no
solve). The feeder samples the daemon's discovery registry +
relay_metrics every 5s and pushes the result into the manager.
"""

from __future__ import annotations

import pytest


def _phase_e_available() -> bool:
    try:
        from one_link_native import coherence_field  # noqa: F401

        return True
    except ImportError:
        return False


def test_push_topology_skipped_when_no_discovery():
    """The feeder must no-op when discovery isn't initialised yet
    (early-startup window before mDNS is up)."""
    from one_link.daemon import Daemon

    class _Stub:
        discovery = None
        _relay_metrics: dict = {}

    class _MgrStub:
        update_topology_calls = 0
        update_peer_source_calls = 0

        def update_topology(self, edges):
            type(self).update_topology_calls += 1

        def update_peer_source(self, peer, **kwargs):
            type(self).update_peer_source_calls += 1

    Daemon._push_topology_to_field_snapshot(_Stub(), _MgrStub())  # type: ignore[arg-type]
    assert _MgrStub.update_topology_calls == 0


def test_push_topology_skipped_with_one_peer():
    """Below 2 peers the feeder is a no-op — graph needs ≥ 2 nodes
    for an edge to make sense."""
    from one_link.daemon import Daemon

    class _Peer:
        short_id = "abc12345"

    class _Registry:
        def list(self):
            return [_Peer()]

    class _Discovery:
        registry = _Registry()

    class _Stub:
        discovery = _Discovery()
        _relay_metrics: dict = {}

    class _MgrStub:
        calls = 0

        def update_topology(self, edges):
            type(self).calls += 1

        def update_peer_source(self, peer, **kwargs):
            pass

    Daemon._push_topology_to_field_snapshot(_Stub(), _MgrStub())  # type: ignore[arg-type]
    assert _MgrStub.calls == 0


def test_push_topology_builds_pairwise_edges_for_two_peers():
    """With 2 peers + no relay metrics, the feeder builds 1 edge
    (full mesh on 2 nodes = 1 edge). Per-peer source contributions
    use the no-metrics defaults (density=1.0, flux=0.5)."""
    from one_link.daemon import Daemon

    class _Peer:
        def __init__(self, sid):
            self.short_id = sid

    class _Registry:
        def __init__(self, peers):
            self._peers = peers

        def list(self):
            return self._peers

    class _Discovery:
        def __init__(self, peers):
            self.registry = _Registry(peers)

    peers = [_Peer("aaa"), _Peer("bbb")]

    class _Stub:
        discovery = _Discovery(peers)
        _relay_metrics: dict = {}

    captured_edges = []
    captured_sources = []

    class _MgrStub:
        def update_topology(self, edges):
            captured_edges.extend(edges)

        def update_peer_source(self, peer, **kwargs):
            captured_sources.append((peer, kwargs))

    Daemon._push_topology_to_field_snapshot(_Stub(), _MgrStub())  # type: ignore[arg-type]
    # 2 peers → 1 undirected edge.
    assert len(captured_edges) == 1
    edge = captured_edges[0]
    # Each peer gets a source contribution.
    assert len(captured_sources) == 2
    # Default density + flux for peers without relay metrics.
    for _peer, kwargs in captured_sources:
        assert kwargs["density"] == 1.0
        assert kwargs["flux"] == 0.5


def test_push_topology_uses_relay_metrics_for_source():
    """When relay metrics exist for a peer, density + flux derive
    from (1 - loss) and 1000/rtt respectively."""
    from one_link.daemon import Daemon

    class _Peer:
        def __init__(self, sid, url):
            self.short_id = sid
            self.rendezvous_url = url

    class _Registry:
        def __init__(self, peers):
            self._peers = peers

        def list(self):
            return self._peers

    class _Discovery:
        def __init__(self, peers):
            self.registry = _Registry(peers)

    peers = [
        _Peer("aaa", "https://a.relay"),
        _Peer("bbb", "https://b.relay"),
    ]

    class _Stub:
        discovery = _Discovery(peers)
        _relay_metrics: dict = {
            "https://a.relay": {"rtt_ms": 50.0, "loss_rate": 0.1},
            # bbb has no metrics → falls back to defaults
        }

    captured = []

    class _MgrStub:
        def update_topology(self, edges):
            pass

        def update_peer_source(self, peer, **kwargs):
            captured.append((peer, kwargs))

    Daemon._push_topology_to_field_snapshot(_Stub(), _MgrStub())  # type: ignore[arg-type]
    sources = dict((sid, kwargs) for sid, kwargs in captured)
    # 'aaa' has metrics: density = 1 - 0.1 = 0.9; flux = 1000/50 = 20.
    assert sources["aaa"]["density"] == pytest.approx(0.9)
    assert sources["aaa"]["flux"] == pytest.approx(20.0)
    # 'bbb' has no metrics → default density 1.0, flux 0.5.
    assert sources["bbb"]["density"] == 1.0
    assert sources["bbb"]["flux"] == 0.5


@pytest.mark.skipif(
    not _phase_e_available(),
    reason="one_link_native.coherence_field not installed",
)
def test_feeder_drives_real_field_snapshot_manager():
    """End-to-end: pushing topology into a real FieldSnapshotManager
    causes its next _tick to produce a snapshot. Without the feeder
    the manager's min_peers gate keeps it idle."""
    from one_link.daemon import Daemon
    from one_link.field_snapshot import FieldSnapshotManager

    class _Peer:
        def __init__(self, sid):
            self.short_id = sid
            self.rendezvous_url = f"https://{sid}.relay"

    class _Registry:
        def __init__(self, peers):
            self._peers = peers

        def list(self):
            return self._peers

    class _Discovery:
        def __init__(self, peers):
            self.registry = _Registry(peers)

    peers = [_Peer(f"peer{i:02d}") for i in range(5)]

    class _Stub:
        discovery = _Discovery(peers)
        _relay_metrics: dict = {}

    mgr = FieldSnapshotManager()
    # Pre-tick: no topology, no snapshot.
    assert mgr.snapshot() is None
    Daemon._push_topology_to_field_snapshot(_Stub(), mgr)  # type: ignore[arg-type]
    # Verify the manager now sees topology (peers + edges).
    metrics = mgr.metrics()
    assert metrics["field_topology_edge_count"] > 0
    assert metrics["field_source_peer_count"] == 5
    # Force a tick.
    mgr._tick()  # type: ignore[attr-defined]
    snap = mgr.snapshot()
    assert snap is not None
    assert len(snap.peers) == 5
    assert len(snap.field) == 5
    assert snap.solve_iterations >= 1

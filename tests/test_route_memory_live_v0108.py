from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import json
from types import SimpleNamespace

import pytest

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import UIServer
from one_link.state import State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key()
    pub_bytes = pub.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk,
        public=pub,
        public_bytes=pub_bytes,
        fingerprint=fp,
        short_id=fp[:8],
        hostname="route-test",
    )


def test_live_route_observations_surface_best_route_and_scores():
    daemon = Daemon(_identity())
    fp = "aa" * 32

    daemon._record_route_observation(
        fp,
        route="relay",
        ok=True,
        latency_ms=120,
        bandwidth_bps=20_000_000,
    )
    daemon._record_route_observation(
        fp,
        route="lan",
        ok=True,
        latency_ms=5,
        bandwidth_bps=250_000_000,
    )
    daemon._record_route_observation(
        fp,
        route="relay",
        ok=False,
        error_code="timeout",
    )

    health = daemon.get_pair_health(fp)

    assert health is not None
    assert health["best_route"] == "lan"
    assert health["bandwidth_bps"] > 0
    assert 0.0 <= health["reliability"] <= 1.0
    assert health["route_scores"][0]["route"] == "lan"


def test_live_route_memory_feeds_swarm_health_fields():
    daemon = Daemon(_identity())
    fp = "bb" * 32

    daemon._record_route_observation(
        fp,
        route="prior",
        ok=True,
        latency_ms=1,
        bandwidth_bps=1_000_000_000,
    )

    health = daemon.get_pair_health(fp)

    assert health["best_route"] == "prior"
    assert health["latency_ewma_ms"] == 1
    assert health["bandwidth_bps"] == 1_000_000_000
    assert health["reliability"] == 1.0


def test_failed_route_observation_degrades_reliability_without_crashing():
    daemon = Daemon(_identity())
    fp = "cc" * 32

    daemon._record_route_observation(fp, route="lan", ok=False, error_code="chunk_retry")
    daemon._record_route_observation(fp, route="lan", ok=True, latency_ms=10, bandwidth_bps=10_000_000)

    health = daemon.get_pair_health(fp)

    assert health["best_route"] == "lan"
    assert health["reliability"] == 0.5
    assert health["route_scores"][0]["attempts"] == 2


def test_route_memory_persists_runtime_observations(tmp_path):
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(_identity())
    daemon.state = state
    fp = "dd" * 32

    daemon._record_route_observation(
        fp,
        route="lan",
        ok=True,
        latency_ms=4,
        bandwidth_bps=800_000_000,
    )
    daemon._record_route_observation(
        fp,
        route="relay",
        ok=False,
        error_code="timeout",
    )

    rows = state.list_route_memory(fp)
    by_route = {r["route"]: r for r in rows}

    assert by_route["lan"]["successes"] == 1
    assert by_route["lan"]["bandwidth_bps"] == 800_000_000
    assert by_route["relay"]["failures"] == 1
    state.close()


def test_route_memory_loads_after_restart_and_feeds_health(tmp_path):
    state = State(db_path=tmp_path / "state.db")
    fp = "ee" * 32
    state.upsert_route_memory(
        peer_fp=fp,
        route="lan",
        attempts=4,
        successes=4,
        failures=0,
        score=145.0,
        latency_ms=3.0,
        bandwidth_bps=900_000_000.0,
    )
    state.upsert_route_memory(
        peer_fp=fp,
        route="relay",
        attempts=4,
        successes=2,
        failures=2,
        score=40.0,
        latency_ms=120.0,
        bandwidth_bps=20_000_000.0,
    )
    daemon = Daemon(_identity())
    daemon.state = state

    daemon._load_persisted_route_memory()
    health = daemon.get_pair_health(fp)
    observations = daemon._transfer_route_observations(fp)

    assert health["best_route"] == "lan"
    assert health["bandwidth_bps"] == 900_000_000.0
    assert len(observations) == 8
    assert sum(1 for obs in observations if obs.ok) == 6
    state.close()


@pytest.mark.asyncio
async def test_collect_dial_candidates_includes_verified_durable_routes(tmp_path):
    state = State(db_path=tmp_path / "state.db")
    peer_pub = "11" * 32
    peer_fp = fingerprint_of(bytes.fromhex(peer_pub))
    state.upsert_route_candidate(
        peer_fp=peer_fp,
        route="lan",
        transport="tcp",
        host="10.0.0.44",
        port=17117,
        source="endpoint_verify",
        verified=True,
    )
    daemon = Daemon(_identity())
    daemon.state = state
    daemon.rendezvous = None
    peer = SimpleNamespace(
        short_id="peer1111",
        hostname="peer",
        address="10.0.0.2",
        port=17117,
        ed_pub_hex=peer_pub,
    )

    candidates = await daemon._collect_dial_candidates(peer)

    assert candidates[:2] == [("10.0.0.2", 17117), ("10.0.0.44", 17117)]
    state.close()


@pytest.mark.asyncio
async def test_verify_endpoint_failure_records_durable_candidate(tmp_path, monkeypatch):
    state = State(db_path=tmp_path / "state.db")
    peer = _identity()
    state.upsert_peer(
        fingerprint=peer.fingerprint,
        short_id=peer.short_id,
        pubkey=peer.public_bytes,
        trust_default="pinned",
    )
    daemon = Daemon(_identity())
    daemon.state = state

    async def fail_open(*_args, **_kwargs):
        raise OSError("dial refused")

    monkeypatch.setattr("asyncio.open_connection", fail_open)

    await daemon._verify_and_promote_endpoint(
        peer.fingerprint,
        peer.short_id,
        "10.0.0.55",
        17117,
        source="signed_bootstrap",
        route="lan",
    )

    rows = state.list_route_candidates(peer.fingerprint, include_expired=True)
    assert rows[0]["host"] == "10.0.0.55"
    assert rows[0]["failures"] == 1
    assert rows[0]["verified"] is False
    state.close()


def test_trusted_chunk_sources_use_verified_durable_routes(tmp_path):
    state = State(db_path=tmp_path / "state.db")
    source = _identity()
    sender = _identity()
    state.upsert_peer(
        fingerprint=source.fingerprint,
        short_id=source.short_id,
        pubkey=source.public_bytes,
        hostname="source",
    )
    state.set_peer_trust(source.fingerprint, "pinned")
    state.upsert_peer(
        fingerprint=sender.fingerprint,
        short_id=sender.short_id,
        pubkey=sender.public_bytes,
        hostname="sender",
    )
    state.set_peer_trust(sender.fingerprint, "pinned")
    state.upsert_route_candidate(
        peer_fp=source.fingerprint,
        route="lan",
        transport="tcp",
        host="10.0.0.77",
        port=17117,
        source="session_open",
        verified=True,
    )
    daemon = Daemon(_identity())
    daemon.state = state

    peers = daemon._trusted_chunk_source_peers(exclude_fp=sender.fingerprint)

    assert len(peers) == 1
    assert peers[0].address == "10.0.0.77"
    assert peers[0].port == 17117
    assert peers[0].ed_pub_hex == source.public_bytes.hex()
    state.close()


@pytest.mark.asyncio
async def test_api_peers_surfaces_live_route_memory(tmp_path):
    state = State(db_path=tmp_path / "state.db")
    pub_hex = "bb" * 32
    peer_fp = fingerprint_of(bytes.fromhex(pub_hex))
    state.upsert_peer(
        fingerprint=peer_fp,
        short_id="bbbbbbbb",
        pubkey=bytes.fromhex(pub_hex),
        trust_default="pinned",
    )
    health_store = {
        peer_fp: {
            "last_alive_ms": 123,
            "latency_ewma_ms": 5.0,
            "bandwidth_bps": 250_000_000.0,
            "reliability": 0.99,
            "best_route": "lan",
            "route_scores": [{"route": "lan", "score": 120.0}],
        }
    }
    daemon = SimpleNamespace(
        state=state,
        discovery=None,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
        _outbound_sessions={},
        _inbound_regime={},
        _peer_presence={},
        get_pair_health=lambda fp: health_store.get(fp),
    )
    server = UIServer(daemon)

    class _Req:
        query: dict = {}
        match_info: dict = {}

    resp = await server.api_peers(_Req())
    body = json.loads(resp.text)
    peer = next(p for p in body["peers"] if p["fingerprint"] == peer_fp)

    assert peer["health"]["best_route"] == "lan"
    assert peer["health"]["bandwidth_bps"] == 250_000_000.0
    assert peer["health"]["reliability"] == 0.99
    assert peer["health"]["route_scores"][0]["route"] == "lan"
    state.close()

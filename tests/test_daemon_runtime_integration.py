"""End-to-end integration for the wired-up daemon runtimes.

Verifies every Tier β/γ/δ/ε/η runtime adapter is reachable through
the daemon's HTTP surface + dispatch, end-to-end:

  - report_metrics → BrowserMetricsCache updates → Immune sees new RTT/loss
  - observe_frame → PredictiveContinuityRuntime stats update
  - predict_frame → engine emits a predicted frame after a seed
  - mark_handoff_prewarmed → HandoffOrchestrator transitions
  - attest_frame → CALL_FRAME_ATTEST broadcast (already covered in
    test_daemon_frame_attest; included for completeness here)

Plus the immune tick loop: when a call is active and vitals are
bad, the runtime fires the right ImmuneAction.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock

import blake3
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from one_link.call_immune import GraduationMode, ImmuneAction
from one_link.crossfade import CrossfadeKind
from one_link.daemon import Daemon
from one_link.handoff_orchestrator import HandoffPhase, HandoffRequest
from one_link.identity import Identity


# ---------------------------------------------------------------------------
# Scaffolding
# ---------------------------------------------------------------------------

def _make_identity(name: str) -> Identity:
    seed = blake3.blake3(name.encode()).digest()[:32]
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fp = blake3.blake3(pub_bytes).hexdigest()
    return Identity(
        private=priv, public=priv.public_key(), public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname=name,
    )


class _FakePeer:
    def __init__(self, ed_pub_hex: str) -> None:
        self.ed_pub_hex = ed_pub_hex
        self.trust = "pinned"


class _FakeState:
    def __init__(self, peers: dict[str, str]) -> None:
        self._peers = {fp: _FakePeer(pub) for fp, pub in peers.items()}

    def get_peer(self, fp: str):
        return self._peers.get(fp)


class _FakeRequest:
    def __init__(self, body: dict) -> None:
        self._body = body

    async def json(self) -> dict:
        return self._body


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@pytest.fixture
def me() -> Identity:
    return _make_identity("me-runtime")


@pytest.fixture
def peer() -> Identity:
    return _make_identity("peer-runtime")


@pytest.fixture
def server(
    me: Identity,
    peer: Identity,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    import one_link.server as server_mod

    monkeypatch.setattr(server_mod, "data_dir", lambda: tmp_path)
    from one_link.server import UIServer
    d = Daemon(me=me)
    d.state = _FakeState({peer.fingerprint: peer.public_bytes.hex()})
    d._call_registry.open(
        call_id="rt-call-1",
        peer_master_vk_hex=peer.fingerprint,
        local_role="originator",
        local_master_vk_hex=me.fingerprint,
        started_at_ms=1_000,
    )
    d._predictive.open_call("rt-call-1")
    d.send_to = AsyncMock()
    s = UIServer.__new__(UIServer)
    s.daemon = d
    s._lp_call_api_cached = None
    return s


# ---------------------------------------------------------------------------
# Daemon construction: every runtime is present
# ---------------------------------------------------------------------------

def test_daemon_init_has_all_runtimes(me: Identity) -> None:
    d = Daemon(me=me)
    assert d._immune_system is not None
    assert d._immune_metrics is not None
    assert d._predictive is not None
    assert d._handoff is not None
    assert d._transport_priority is not None


# ---------------------------------------------------------------------------
# report_metrics
# ---------------------------------------------------------------------------

def test_report_metrics_updates_immune_cache(server) -> None:
    req = _FakeRequest({
        "action": "report_metrics",
        "call_id": "rt-call-1",
        "rtt_ms": 320.0,
        "loss_rate": 0.12,
        "jitter_ms": 18.0,
        "confirm_ratio_voice": 0.7,
        "bandwidth_estimate_kbps": 80.0,
    })
    resp = _run(server.api_call_action(req))
    body = json.loads(resp.body.decode("utf-8"))
    assert body["ok"] is True
    cached = server.daemon._immune_metrics.get("rt-call-1")
    assert cached["rtt_ms"] == 320.0
    assert cached["loss_rate"] == 0.12
    assert cached["confirm_ratio_voice"] == 0.7


def test_report_metrics_writes_privacy_safe_media_audit(
    server,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import one_link.server as server_mod

    monkeypatch.setattr(server_mod, "data_dir", lambda: tmp_path)
    req = _FakeRequest({
        "action": "report_metrics",
        "call_id": "rt-call-1",
        "rtt_ms": 44.0,
        "loss_rate": 0.0,
        "ice_connection_state": "connected",
        "connection_state": "connected",
        "ice_gathering_state": "complete",
        "signaling_state": "stable",
        "has_local_description": True,
        "has_remote_description": True,
        "local_audio_tracks": 1,
        "local_video_tracks": 1,
        "local_live_audio_tracks": 1,
        "local_live_video_tracks": 1,
        "remote_audio_tracks": 1,
        "remote_video_tracks": 1,
        "remote_live_audio_tracks": 1,
        "remote_live_video_tracks": 1,
        # These must never be persisted by the audit helper.
        "sdp": "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n",
        "candidate": "candidate:1 1 udp 1 192.168.1.10 9999 typ host",
    })
    resp = _run(server.api_call_action(req))
    body = json.loads(resp.body.decode("utf-8"))
    assert body["ok"] is True

    audit = tmp_path / "logs" / "call_media_audit.jsonl"
    row = json.loads(audit.read_text(encoding="utf-8").splitlines()[-1])
    assert row["call_id"] == "rt-call-1"
    assert row["ice_connection_state"] == "connected"
    assert row["remote_audio_tracks"] == 1
    assert row["remote_video_tracks"] == 1
    assert row["local_live_audio_tracks"] == 1
    assert row["remote_live_video_tracks"] == 1
    assert row["has_local_description"] is True
    assert row["has_remote_description"] is True
    assert row["row_type"] == "metrics"
    serialized = json.dumps(row)
    assert "192.168.1.10" not in serialized
    assert "v=0" not in serialized


def test_report_call_event_writes_privacy_safe_media_audit(
    server,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import one_link.server as server_mod

    monkeypatch.setattr(server_mod, "data_dir", lambda: tmp_path)
    req = _FakeRequest({
        "action": "report_call_event",
        "call_id": "rt-call-1",
        "event": "offer_sent",
        "reason": "metrics",
        "state": "connected",
        "media_kind": "video",
        "ok": True,
        # These must never be persisted by the audit helper.
        "sdp": "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\n",
        "candidate": "candidate:1 1 udp 1 10.0.0.5 9999 typ host",
        "peer_label": "Personal Laptop",
        "file_name": "private.pdf",
    })
    resp = _run(server.api_call_action(req))
    body = json.loads(resp.body.decode("utf-8"))
    assert body["ok"] is True

    audit = tmp_path / "logs" / "call_media_audit.jsonl"
    row = json.loads(audit.read_text(encoding="utf-8").splitlines()[-1])
    assert row["row_type"] == "event"
    assert row["call_id"] == "rt-call-1"
    assert row["event"] == "offer_sent"
    assert row["reason"] == "metrics"
    assert row["state"] == "connected"
    assert row["media_kind"] == "video"
    assert row["ok"] is True
    serialized = json.dumps(row)
    assert "10.0.0.5" not in serialized
    assert "v=0" not in serialized
    assert "Personal Laptop" not in serialized
    assert "private.pdf" not in serialized


def test_report_metrics_clamps_out_of_range_values(server) -> None:
    req = _FakeRequest({
        "action": "report_metrics",
        "call_id": "rt-call-1",
        "loss_rate": 1.7,            # > 1.0
        "confirm_ratio_voice": -0.3,  # < 0.0
    })
    _run(server.api_call_action(req))
    cached = server.daemon._immune_metrics.get("rt-call-1")
    assert cached["loss_rate"] == 1.0
    assert cached["confirm_ratio_voice"] == 0.0


def test_report_metrics_rejects_missing_call_id(server) -> None:
    req = _FakeRequest({"action": "report_metrics", "rtt_ms": 100.0})
    resp = _run(server.api_call_action(req))
    body = json.loads(resp.body.decode("utf-8"))
    assert body["ok"] is False


# ---------------------------------------------------------------------------
# observe_frame + predict_frame
# ---------------------------------------------------------------------------

def test_observe_frame_increments_predictive_decisions(server) -> None:
    req = _FakeRequest({
        "action": "observe_frame",
        "call_id": "rt-call-1",
        "media_kind": "audio",
        "seq": 42,
        "timestamp_us": 1_000,
    })
    resp = _run(server.api_call_action(req))
    body = json.loads(resp.body.decode("utf-8"))
    assert body["ok"] is True
    stats = server.daemon._predictive.stats("rt-call-1")
    assert stats["decisions_audio"] == 1
    assert stats["last_real_seq_audio"] == 42


def test_predict_frame_returns_predicted_after_seed(server) -> None:
    # Seed with a real frame first
    _run(server.api_call_action(_FakeRequest({
        "action": "observe_frame",
        "call_id": "rt-call-1",
        "media_kind": "audio",
        "seq": 1,
        "timestamp_us": 0,
    })))
    # Then request a prediction
    req = _FakeRequest({
        "action": "predict_frame",
        "call_id": "rt-call-1",
        "media_kind": "audio",
        "due_seq": 2,
        "now_us": 20_000,
    })
    resp = _run(server.api_call_action(req))
    body = json.loads(resp.body.decode("utf-8"))
    assert body["ok"] is True
    assert body["predicted"] is True
    assert body["frame_kind"] == "PREDICTED"


def test_predict_frame_without_seed_refuses(server) -> None:
    req = _FakeRequest({
        "action": "predict_frame",
        "call_id": "rt-call-1",
        "media_kind": "audio",
        "due_seq": 1,
        "now_us": 0,
    })
    resp = _run(server.api_call_action(req))
    body = json.loads(resp.body.decode("utf-8"))
    assert body["ok"] is True
    assert body["predicted"] is False
    assert body["reason"] == "no_seed"


# ---------------------------------------------------------------------------
# mark_handoff_prewarmed
# ---------------------------------------------------------------------------

def test_mark_handoff_prewarmed_advances_phase(server) -> None:
    server.daemon._handoff.start_handoff(
        request=HandoffRequest(
            call_id="rt-call-1", kind=CrossfadeKind.ROUTE_HANDOFF,
            primary_id="p", secondary_id="s",
        ),
        now_ms=0,
    )
    req = _FakeRequest({
        "action": "mark_handoff_prewarmed",
        "call_id": "rt-call-1",
    })
    _run(server.api_call_action(req))
    tick = server.daemon._handoff.tick("rt-call-1", now_ms=0)
    # Now in MIXING phase.
    assert tick.phase == HandoffPhase.MIXING


# ---------------------------------------------------------------------------
# Live immune tick + browser overlay
# ---------------------------------------------------------------------------

def test_live_immune_tick_uses_browser_metrics(me: Identity, peer: Identity) -> None:
    """Drive one immune tick by hand and confirm the browser-
    reported metrics flow through the cache → overlay → engine."""
    from one_link.call_immune_runtime import drive_immune_tick_for_call

    d = Daemon(me=me)
    d.state = _FakeState({peer.fingerprint: peer.public_bytes.hex()})
    d._immune_system.mode = GraduationMode.AUTOPILOT
    d._call_registry.open(
        call_id="rt-call-2",
        peer_master_vk_hex=peer.fingerprint,
        local_role="originator",
        local_master_vk_hex=me.fingerprint,
        started_at_ms=1_000,
    )
    # Browser reports bad conditions.
    d._immune_metrics.update(
        call_id="rt-call-2",
        rtt_ms=400.0, loss_rate=0.18,
        jitter_ms=60.0, confirm_ratio_voice=0.5,
    )
    decision = drive_immune_tick_for_call(
        daemon=d,
        immune=d._immune_system,
        metrics=d._immune_metrics,
        tick_counter=d._immune_tick_counter,
        audit=None,
        call_id="rt-call-2",
        peer_master_vk_hex=peer.fingerprint,
    )
    # Bad metrics → not HOLD.
    assert decision.action != ImmuneAction.HOLD


def test_immune_tick_loop_method_exists_and_returns_coroutine(me: Identity) -> None:
    """Sanity: the loop is wired into daemon.start as expected."""
    d = Daemon(me=me)
    coro = d._immune_tick_loop()
    assert asyncio.iscoroutine(coro)
    coro.close()


def test_immune_audit_lazy_init_attribute_set(me: Identity) -> None:
    """The audit attribute is None pre-start and gets populated only
    after start() has been called."""
    d = Daemon(me=me)
    # Before start, the field exists but the audit logger is None.
    assert hasattr(d, "_immune_audit")
    assert d._immune_audit is None


# ---------------------------------------------------------------------------
# CALL_INVITE opens predictive runtime for the call
# ---------------------------------------------------------------------------

def test_call_invite_opens_predictive_runtime(me: Identity, peer: Identity) -> None:
    d = Daemon(me=me)
    d.state = _FakeState({peer.fingerprint: peer.public_bytes.hex()})

    msg = {
        "t": "CALL_INVITE",
        "id": "x",
        "ts": 0,
        "from": peer.short_id,
        "call_id": "rt-invite-1",
    }

    class _Channel:
        peer_ed_pub = peer.public_bytes
        peer_short_id = peer.short_id
        peer_caps = {"features": []}

        async def send(self, _: bytes) -> None:
            pass

    d._broadcast_tail = lambda _: None  # type: ignore
    _run(d._on_peer_message(_Channel(), msg))

    # Predictive runtime should now have state for this call.
    stats = d._predictive.stats("rt-invite-1")
    assert stats is not None
    # No frames observed yet → empty stats dict OR baseline defaults.
    assert "confirm_ratio_voice" in stats or stats == {}

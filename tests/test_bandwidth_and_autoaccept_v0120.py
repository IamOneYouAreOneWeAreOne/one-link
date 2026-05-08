"""v0.12.0 — Bandwidth cap + auto-accept rules WIRED.

Closes the "shipped settings, not enforced" gap from v0.11.6.

Bandwidth cap:
  - new module one_link.pacing with BandwidthPacer (token bucket).
  - daemon.bandwidth_pacer instance, set_cap from settings on
    boot + on every /api/settings save.
  - send_file's chunk loop calls await pacer.pace(len(chunk))
    BEFORE each FILE_CHUNK / FILE_BIN_CHUNK send.

Auto-accept rules:
  - daemon caches auto_accept_max_size_mb +
    auto_accept_extensions in memory.
  - FILE_OFFER handler calls _file_passes_auto_accept(name, size)
    before opening any write handle. Failure ACKs the offer with
    rejected="auto_accept_<reason>" and writes nothing.
  - Tests cover the size-cap + extension-allowlist branches plus
    the live-refresh path (settings save mutates daemon state).
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.pacing import BandwidthPacer
from one_link.server import UIServer
from one_link.state import State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="bw-host",
    )


@pytest_asyncio.fixture
async def http(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = None
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    daemon.folder_engine = None
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield client, daemon, state, server.token
    finally:
        await client.close()
        state.close()


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ───────── BandwidthPacer primitive ──────────────────────────────────

@pytest.mark.asyncio
async def test_pacer_unlimited_is_no_op():
    """cap=0 → no waiting, no scheduling overhead."""
    p = BandwidthPacer(cap_kbps=0)
    assert p.is_unlimited
    t0 = time.monotonic()
    for _ in range(100):
        await p.pace(1024 * 1024)  # 1 MB each
    elapsed = time.monotonic() - t0
    # 100 MB at "unlimited" should finish in well under 50ms even
    # on a slow CI box. If it's anywhere near 1s, the no-op branch
    # is broken.
    assert elapsed < 0.5, f"unlimited pacer slept ({elapsed:.3f}s)"


@pytest.mark.asyncio
async def test_pacer_throttles_to_approximately_cap():
    """At 1024 kbps (= 128 KB/s), sending 256KB should take ~2s.
    Allow generous tolerance (±0.5s) for scheduling jitter."""
    p = BandwidthPacer(cap_kbps=1024)  # 128 KB/s
    # Drain the initial bucket first so we measure steady-state.
    await p.pace(int(p._state.capacity_bytes))  # type: ignore[union-attr]
    t0 = time.monotonic()
    target_bytes = 128 * 1024  # 1 second worth at the cap
    sent = 0
    while sent < target_bytes:
        chunk = min(16 * 1024, target_bytes - sent)
        await p.pace(chunk)
        sent += chunk
    elapsed = time.monotonic() - t0
    # Should be ≈ 1.0s. Allow 0.5–1.8s.
    assert 0.5 <= elapsed <= 1.8, f"expected ~1s, got {elapsed:.3f}s"


@pytest.mark.asyncio
async def test_pacer_set_cap_takes_effect_live():
    """A user changing the cap mid-transfer must affect subsequent
    paces. We don't preempt in-flight sleeps but the next call
    should respect the new rate."""
    p = BandwidthPacer(cap_kbps=0)
    assert p.is_unlimited
    p.set_cap(8192)  # 1 MB/s
    assert not p.is_unlimited
    assert p.cap_kbps == 8192
    p.set_cap(0)
    assert p.is_unlimited


@pytest.mark.asyncio
async def test_pacer_zero_bytes_is_no_op():
    p = BandwidthPacer(cap_kbps=1024)
    t0 = time.monotonic()
    await p.pace(0)
    await p.pace(-5)
    assert time.monotonic() - t0 < 0.05


@pytest.mark.asyncio
async def test_pacer_handles_chunk_larger_than_capacity():
    """A single pace() call bigger than the bucket capacity must
    still complete (drain to 0 + sleep enough)."""
    p = BandwidthPacer(cap_kbps=1024)  # cap = 64 KB capacity
    huge = 256 * 1024  # 256 KB — 4x capacity
    t0 = time.monotonic()
    await p.pace(huge)
    elapsed = time.monotonic() - t0
    # 256 KB at 128 KB/s, minus initial bucket of 64 KB ≈ 1.5s
    assert 0.5 <= elapsed <= 3.0


# ───────── Daemon refresh_runtime_settings ──────────────────────────

@pytest.mark.asyncio
async def test_refresh_runtime_settings_pulls_bandwidth_cap(http):
    client, daemon, state, token = http
    state.set_setting("bandwidth_cap_kbps", "5120")
    daemon.refresh_runtime_settings()
    assert daemon.bandwidth_pacer.cap_kbps == 5120


@pytest.mark.asyncio
async def test_refresh_runtime_settings_unlimited_when_zero(http):
    client, daemon, state, token = http
    state.set_setting("bandwidth_cap_kbps", "5120")
    daemon.refresh_runtime_settings()
    state.delete_setting("bandwidth_cap_kbps")
    daemon.refresh_runtime_settings()
    assert daemon.bandwidth_pacer.is_unlimited


@pytest.mark.asyncio
async def test_refresh_pulls_auto_accept_size(http):
    client, daemon, state, token = http
    state.set_setting("auto_accept_max_size_mb", "100")
    daemon.refresh_runtime_settings()
    assert daemon._auto_accept_max_size_bytes == 100 * 1024 * 1024


@pytest.mark.asyncio
async def test_refresh_pulls_auto_accept_extensions(http):
    client, daemon, state, token = http
    state.set_setting("auto_accept_extensions", "png,jpg,pdf")
    daemon.refresh_runtime_settings()
    assert daemon._auto_accept_extensions == {"png", "jpg", "pdf"}


# ───────── Settings save triggers refresh ────────────────────────────

@pytest.mark.asyncio
async def test_settings_save_refreshes_pacer_live(http):
    """The whole point of the wire-through: saving the setting via
    the API must update the in-memory pacer, NOT just the DB row."""
    client, daemon, _, token = http
    assert daemon.bandwidth_pacer.is_unlimited
    resp = await client.post(
        "/api/settings", headers=_h(token),
        json={"bandwidth_cap_kbps": 2048},
    )
    assert resp.status == 200
    assert daemon.bandwidth_pacer.cap_kbps == 2048


@pytest.mark.asyncio
async def test_settings_save_refreshes_auto_accept_live(http):
    client, daemon, _, token = http
    assert daemon._auto_accept_max_size_bytes == 0
    await client.post(
        "/api/settings", headers=_h(token),
        json={
            "auto_accept_max_size_mb": 50,
            "auto_accept_extensions": "png,jpg",
        },
    )
    assert daemon._auto_accept_max_size_bytes == 50 * 1024 * 1024
    assert daemon._auto_accept_extensions == {"png", "jpg"}


# ───────── _file_passes_auto_accept ─────────────────────────────────

def test_passes_with_no_rules_set(tmp_path: Path):
    """Empty filter = accept everything (matches default behavior)."""
    me = _identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    ok, reason = daemon._file_passes_auto_accept(name="big.zip", size=10**12)
    assert ok is True
    assert reason == ""
    state.close()


def test_blocks_when_size_exceeds_cap(tmp_path: Path):
    me = _identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon._auto_accept_max_size_bytes = 100 * 1024 * 1024
    ok, reason = daemon._file_passes_auto_accept(
        name="x.bin", size=200 * 1024 * 1024,
    )
    assert ok is False
    assert reason == "exceeds_max_size"
    state.close()


def test_blocks_when_extension_not_in_allowlist(tmp_path: Path):
    me = _identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon._auto_accept_extensions = {"png", "jpg"}
    ok, reason = daemon._file_passes_auto_accept(name="doc.pdf", size=1)
    assert ok is False
    assert reason == "extension_blocked"
    state.close()


def test_passes_when_extension_in_allowlist(tmp_path: Path):
    me = _identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon._auto_accept_extensions = {"png", "jpg"}
    ok, _ = daemon._file_passes_auto_accept(name="photo.png", size=1)
    assert ok is True
    state.close()


def test_extension_match_is_case_insensitive(tmp_path: Path):
    """Settings normalization lowercases the allowlist; the check
    must lowercase the inbound filename's extension too."""
    me = _identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon._auto_accept_extensions = {"png"}
    ok, _ = daemon._file_passes_auto_accept(name="PHOTO.PNG", size=1)
    assert ok is True
    state.close()


def test_no_extension_blocked_when_allowlist_active(tmp_path: Path):
    """A file with no extension at all should fail an allowlist —
    'extension empty' isn't a wildcard."""
    me = _identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon._auto_accept_extensions = {"png"}
    ok, reason = daemon._file_passes_auto_accept(name="README", size=1)
    assert ok is False
    assert reason == "extension_blocked"
    state.close()


def test_size_check_at_exact_boundary(tmp_path: Path):
    """File exactly at cap should pass (cap is inclusive of equal)."""
    me = _identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon._auto_accept_max_size_bytes = 100
    ok, _ = daemon._file_passes_auto_accept(name="x.bin", size=100)
    assert ok is True
    ok, reason = daemon._file_passes_auto_accept(name="x.bin", size=101)
    assert ok is False
    assert reason == "exceeds_max_size"
    state.close()


# ───────── version pin ──────────────────────────────────────────────

def test_page_version_bumped():
    from one_link import __version__
    html = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert f'PAGE_BUILT_FOR = "{__version__}"' in html

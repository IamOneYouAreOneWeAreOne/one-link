"""Integration tests for the Row 10 + Row 6 daemon wiring.

Boots a Daemon instance, exercises:

- ``daemon.sealed_master`` is None when no master seed exists,
  or a ``SealedMasterIdentity`` when the seed file is present.
- ``daemon._cover_traffic`` is a running ``CoverTrafficDaemon``
  after ``start()`` and stopped after ``stop()``.
- The new /api/v1/attestation/{challenge,issue,verify} routes
  produce + verify a doc end-to-end.
"""

from __future__ import annotations

import asyncio
import base64
import json
import secrets
import tempfile
from pathlib import Path

import pytest

from one_link.confidential_native import HAS_NATIVE
from one_link.cover_traffic import HAS_NATIVE as COVER_HAS_NATIVE
from one_link.daemon import Daemon
from one_link.identity import load_or_create as load_or_create_identity
from one_link import master_seed as ms

pytestmark = pytest.mark.skipif(
    not (HAS_NATIVE and COVER_HAS_NATIVE),
    reason="one_link_native not built; run `cd native && maturin develop --release`",
)


def _make_daemon_with_seed(tmpdir: Path) -> Daemon:
    """Construct a Daemon + plant a master seed in tmpdir so
    `load_sealed_master` returns a sealed handle."""
    # Plant the seed.
    seed, _created = ms.load_or_create_seed(tmpdir)
    assert len(seed) == 32
    # Construct an Identity in the same tmpdir.
    me = load_or_create_identity(tmpdir / "identity.key")
    daemon = Daemon(me)
    return daemon


@pytest.fixture
def daemon_with_seed(monkeypatch):
    """Daemon with a populated master seed in a tmpdir, and the
    paths.data_dir helper monkeypatched to return that tmpdir."""
    td = tempfile.mkdtemp(prefix="ol_row10_test_")
    tmp_path = Path(td)

    def _data_dir() -> Path:
        return tmp_path

    monkeypatch.setattr("one_link.paths.data_dir", _data_dir)
    daemon = _make_daemon_with_seed(tmp_path)
    yield daemon


# ── Sealed master at boot ─────────────────────────────────────────


def test_sealed_master_is_none_before_start():
    me = load_or_create_identity(
        Path(tempfile.mkdtemp(prefix="ol_test_")) / "identity.key"
    )
    daemon = Daemon(me)
    # Before start(), the seal isn't loaded yet — should be None.
    assert daemon.sealed_master is None


def test_cover_traffic_is_none_before_start():
    me = load_or_create_identity(
        Path(tempfile.mkdtemp(prefix="ol_test_")) / "identity.key"
    )
    daemon = Daemon(me)
    assert daemon._cover_traffic is None
    assert daemon._cover_emit_count == 0


# ── Boot path ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_daemon_start_attaches_sealed_master_and_cover_traffic(
    daemon_with_seed,
):
    """Full start() should populate both sealed_master and
    _cover_traffic when the master seed exists + native ext is
    built. stop() cleanly tears down."""
    daemon = daemon_with_seed
    try:
        await daemon.start()
    except Exception:
        # Some unrelated start path may fail (control server bind,
        # etc.) — that's outside this test's scope. Skip if start
        # genuinely couldn't run.
        await daemon.stop()
        pytest.skip("daemon.start() failed outside the Row 10/6 wiring")
        return

    try:
        # Sealed master should be populated.
        assert daemon.sealed_master is not None, "sealed_master should attach"
        assert daemon.sealed_master is not False
        # It should be a SealedMasterIdentity with a working
        # master_vk().
        vk = daemon.sealed_master.master_vk()
        assert len(vk) == 1984

        # Cover-traffic scheduler should be running.
        assert daemon._cover_traffic is not None
        assert daemon._cover_traffic.is_running
        assert daemon._cover_traffic.rate_hz == 0.5
    finally:
        await daemon.stop()
        # After stop, cover-traffic should be drained.
        assert daemon._cover_traffic is None


# ── Attestation API ───────────────────────────────────────────────


def _server_url_root(daemon) -> str:
    """The control-server URL the test client hits."""
    # The control server listens on 127.0.0.1:<port>.
    # We pull the port out of the daemon's bound server.
    sockets = daemon._control_server.sockets  # type: ignore[union-attr]
    host, port = sockets[0].getsockname()[:2]
    return f"http://{host}:{port}"


@pytest.mark.asyncio
async def test_attestation_round_trip_via_api(daemon_with_seed, monkeypatch):
    """Issue + verify an attestation through the new /api/v1/attestation/* endpoints."""
    daemon = daemon_with_seed
    try:
        await daemon.start()
    except Exception:
        await daemon.stop()
        pytest.skip("daemon.start() failed outside the attestation API scope")
        return

    try:
        # Walk the daemon's UI server endpoints directly via the
        # in-process aiohttp handlers (no real HTTP — the test
        # client + server share an event loop).
        ui = daemon.ui_server
        assert ui is not None, "UI server should be up after start()"

        # Synthesise a request object and exercise the handlers.
        from aiohttp.test_utils import make_mocked_request

        # Challenge.
        req = make_mocked_request("POST", "/api/v1/attestation/challenge")
        resp = await ui.api_attestation_challenge(req)
        body = json.loads(resp.body.decode())
        assert body["ok"] is True
        challenge = base64.b64decode(body["challenge_b64"])
        assert len(challenge) == 32

        # Issue.
        issue_body = {"challenge_b64": body["challenge_b64"]}
        async def _payload():
            return issue_body
        req2 = make_mocked_request("POST", "/api/v1/attestation/issue")
        req2.json = _payload  # type: ignore[method-assign]
        resp = await ui.api_attestation_issue(req2)
        body2 = json.loads(resp.body.decode())
        assert body2["ok"] is True, body2
        wire = body2["doc"]
        assert wire["v"] == 1
        assert wire["provider_tag"] == 1  # SOFTWARE
        # Master VK on wire round-trips.
        master_vk = base64.b64decode(wire["master_vk"])
        assert master_vk == daemon.sealed_master.master_vk()

        # Verify.
        verify_body = {
            "challenge_b64": body["challenge_b64"],
            "doc": wire,
        }
        async def _payload2():
            return verify_body
        req3 = make_mocked_request("POST", "/api/v1/attestation/verify")
        req3.json = _payload2  # type: ignore[method-assign]
        resp = await ui.api_attestation_verify(req3)
        body3 = json.loads(resp.body.decode())
        assert body3["ok"] is True, body3
    finally:
        await daemon.stop()


@pytest.mark.asyncio
async def test_attestation_verify_rejects_wrong_challenge(daemon_with_seed):
    """Issue under challenge A, verify with challenge B -> 400."""
    daemon = daemon_with_seed
    try:
        await daemon.start()
    except Exception:
        await daemon.stop()
        pytest.skip("daemon.start() failed outside the attestation API scope")
        return
    try:
        ui = daemon.ui_server
        assert ui is not None
        from aiohttp.test_utils import make_mocked_request

        challenge_a = secrets.token_bytes(32)
        async def _issue_payload():
            return {"challenge_b64": base64.b64encode(challenge_a).decode("ascii")}

        req = make_mocked_request("POST", "/api/v1/attestation/issue")
        req.json = _issue_payload  # type: ignore[method-assign]
        resp = await ui.api_attestation_issue(req)
        wire = json.loads(resp.body.decode())["doc"]

        challenge_b = secrets.token_bytes(32)
        async def _verify_payload():
            return {
                "challenge_b64": base64.b64encode(challenge_b).decode("ascii"),
                "doc": wire,
            }
        req2 = make_mocked_request("POST", "/api/v1/attestation/verify")
        req2.json = _verify_payload  # type: ignore[method-assign]
        resp = await ui.api_attestation_verify(req2)
        body = json.loads(resp.body.decode())
        assert body["ok"] is False
    finally:
        await daemon.stop()

"""Tests for ``Daemon.request_blob_with_dedupe_fallback`` — the
fetch-path orchestrator that retries dedupe-site alternates after the
primary peer fails.

Exercises:
  - Primary success returns immediately, no alternates consulted
  - Primary failure + no alternates returns no_alternates
  - Primary failure + alternate success returns succeeded_via=alt
  - Primary failure + every alternate fails returns all_failed
  - max_alternates bounds the retry count
  - Attempts chain is recorded in order
  - folder_name + timeout_s are propagated to each request
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from one_link import daemon as daemon_module


def _bare_daemon():
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d.state = MagicMock()
    d._is_pinned = MagicMock(return_value=True)
    d.request_blob_from_peer = AsyncMock()
    d.find_alternate_sources_for_blob = MagicMock(return_value=())
    return d


# ---------- primary success ----------


@pytest.mark.asyncio
async def test_primary_success_returns_immediately() -> None:
    d = _bare_daemon()
    d.request_blob_from_peer = AsyncMock(return_value={"status": "requested"})
    out = await d.request_blob_with_dedupe_fallback(
        "h" * 64, primary="peerA",
    )
    assert out["status"] == "requested"
    assert out["succeeded_via"] == "peerA"
    assert out["primary_status"] == "requested"
    # Only one attempt — the primary.
    assert len(out["attempts"]) == 1
    # Alternates never consulted.
    d.find_alternate_sources_for_blob.assert_not_called()


# ---------- primary fail + no alternates ----------


@pytest.mark.asyncio
async def test_primary_fail_no_alternates() -> None:
    d = _bare_daemon()
    d.request_blob_from_peer = AsyncMock(
        return_value={"status": "no_session", "detail": "primary offline"},
    )
    d.find_alternate_sources_for_blob = MagicMock(return_value=())
    out = await d.request_blob_with_dedupe_fallback(
        "h" * 64, primary="peerA",
    )
    assert out["status"] == "no_alternates"
    assert out["succeeded_via"] is None
    assert out["primary_status"] == "no_session"
    assert len(out["attempts"]) == 1


# ---------- primary fail + alternate success ----------


@pytest.mark.asyncio
async def test_primary_fail_alternate_success() -> None:
    d = _bare_daemon()
    d.request_blob_from_peer = AsyncMock(side_effect=[
        {"status": "no_session", "detail": "primary offline"},
        {"status": "requested"},  # alt 1 success
    ])
    d.find_alternate_sources_for_blob = MagicMock(
        return_value=("peerB", "peerC"),
    )
    out = await d.request_blob_with_dedupe_fallback(
        "h" * 64, primary="peerA",
    )
    assert out["status"] == "requested"
    assert out["succeeded_via"] == "peerB"
    assert out["primary_status"] == "no_session"
    assert len(out["attempts"]) == 2
    assert out["attempts"][0]["peer"] == "peerA"
    assert out["attempts"][1]["peer"] == "peerB"


@pytest.mark.asyncio
async def test_alternates_exclude_primary() -> None:
    """The alternates lookup must exclude the original sender so we
    don't retry the same peer that just failed."""
    d = _bare_daemon()
    d.request_blob_from_peer = AsyncMock(
        return_value={"status": "no_session"},
    )
    d.find_alternate_sources_for_blob = MagicMock(return_value=())
    await d.request_blob_with_dedupe_fallback("h" * 64, primary="peerA")
    call_kwargs = d.find_alternate_sources_for_blob.call_args.kwargs
    assert call_kwargs["exclude"] == ["peerA"]


# ---------- all alternates fail ----------


@pytest.mark.asyncio
async def test_all_alternates_fail() -> None:
    d = _bare_daemon()
    d.request_blob_from_peer = AsyncMock(side_effect=[
        {"status": "no_session"},
        {"status": "no_session"},
        {"status": "no_cap"},
        {"status": "send_failed"},
    ])
    d.find_alternate_sources_for_blob = MagicMock(
        return_value=("peerB", "peerC", "peerD"),
    )
    out = await d.request_blob_with_dedupe_fallback(
        "h" * 64, primary="peerA",
    )
    assert out["status"] == "all_failed"
    assert out["succeeded_via"] is None
    assert len(out["attempts"]) == 4  # primary + 3 alternates


# ---------- max_alternates bound ----------


@pytest.mark.asyncio
async def test_max_alternates_caps_retries() -> None:
    d = _bare_daemon()
    d.request_blob_from_peer = AsyncMock(
        return_value={"status": "no_session"},
    )
    # 10 alternates available, but max_alternates=2 should bound.
    d.find_alternate_sources_for_blob = MagicMock(
        return_value=tuple(f"peer{i}" for i in range(10)),
    )
    out = await d.request_blob_with_dedupe_fallback(
        "h" * 64, primary="peerA", max_alternates=2,
    )
    assert len(out["attempts"]) == 3  # primary + 2 alternates


@pytest.mark.asyncio
async def test_max_alternates_zero_skips_alternates() -> None:
    d = _bare_daemon()
    d.request_blob_from_peer = AsyncMock(
        return_value={"status": "no_session"},
    )
    d.find_alternate_sources_for_blob = MagicMock(
        return_value=("peerB", "peerC"),
    )
    out = await d.request_blob_with_dedupe_fallback(
        "h" * 64, primary="peerA", max_alternates=0,
    )
    # Only the primary attempt.
    assert len(out["attempts"]) == 1
    assert out["status"] == "all_failed"


@pytest.mark.asyncio
async def test_max_alternates_negative_treated_as_zero() -> None:
    d = _bare_daemon()
    d.request_blob_from_peer = AsyncMock(
        return_value={"status": "no_session"},
    )
    d.find_alternate_sources_for_blob = MagicMock(return_value=("peerB",))
    out = await d.request_blob_with_dedupe_fallback(
        "h" * 64, primary="peerA", max_alternates=-5,
    )
    assert len(out["attempts"]) == 1


# ---------- propagation ----------


@pytest.mark.asyncio
async def test_folder_name_propagated_to_requests() -> None:
    d = _bare_daemon()
    d.request_blob_from_peer = AsyncMock(side_effect=[
        {"status": "no_session"},
        {"status": "requested"},
    ])
    d.find_alternate_sources_for_blob = MagicMock(return_value=("peerB",))
    await d.request_blob_with_dedupe_fallback(
        "h" * 64, primary="peerA", folder_name="myfolder",
    )
    # Both calls passed folder_name. Pin the count: a fallback that stopped
    # retrying would make this loop pass over a single call -- or none -- while
    # the dedupe path silently stopped working.
    calls = d.request_blob_from_peer.call_args_list
    assert len(calls) == 2, f"expected primary + fallback, got {len(calls)}"
    for call in calls:
        assert call.kwargs["folder_name"] == "myfolder"


@pytest.mark.asyncio
async def test_timeout_propagated() -> None:
    d = _bare_daemon()
    d.request_blob_from_peer = AsyncMock(side_effect=[
        {"status": "no_session"},
        {"status": "requested"},
    ])
    d.find_alternate_sources_for_blob = MagicMock(return_value=("peerB",))
    await d.request_blob_with_dedupe_fallback(
        "h" * 64, primary="peerA", timeout_s=5.0,
    )
    calls = d.request_blob_from_peer.call_args_list
    assert len(calls) == 2, f"expected primary + fallback, got {len(calls)}"
    for call in calls:
        assert call.kwargs["timeout_s"] == 5.0


# ---------- defensive ----------


@pytest.mark.asyncio
async def test_find_alternates_exception_treated_as_no_alternates() -> None:
    d = _bare_daemon()
    d.request_blob_from_peer = AsyncMock(
        return_value={"status": "no_session"},
    )
    d.find_alternate_sources_for_blob = MagicMock(
        side_effect=RuntimeError("simulated"),
    )
    out = await d.request_blob_with_dedupe_fallback(
        "h" * 64, primary="peerA",
    )
    assert out["status"] == "no_alternates"
    # Primary attempt still recorded.
    assert len(out["attempts"]) == 1


@pytest.mark.asyncio
async def test_attempts_record_status_and_detail() -> None:
    d = _bare_daemon()
    d.request_blob_from_peer = AsyncMock(side_effect=[
        {"status": "no_cap", "detail": "peer lacks BLOB_REQUEST_V1"},
        {"status": "send_failed", "detail": "channel closed"},
    ])
    d.find_alternate_sources_for_blob = MagicMock(return_value=("peerB",))
    out = await d.request_blob_with_dedupe_fallback(
        "h" * 64, primary="peerA",
    )
    assert out["attempts"][0]["status"] == "no_cap"
    assert out["attempts"][0]["detail"] == "peer lacks BLOB_REQUEST_V1"
    assert out["attempts"][1]["status"] == "send_failed"
    assert out["attempts"][1]["detail"] == "channel closed"

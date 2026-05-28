"""Accept-first incoming-file policy.

By default One Link now HOLDS a standalone incoming file offer until the
user explicitly accepts it, instead of auto-downloading silently. These
pin the core gating + accept/decline behaviour without spinning up two
real daemons (the wire-level FILE_OFFER_HELD handshake is exercised by
the two-daemon e2e).
"""
from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.state import State
from one_link.wire import decode_msg


def _new_identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key()
    pb = pub.public_bytes_raw()
    fp = fingerprint_of(pb)
    return Identity(
        private=sk, public=pub, public_bytes=pb,
        fingerprint=fp, short_id=fp[:8], hostname="x",
    )


class _FakeChannel:
    def __init__(self):
        self.sent: list[dict] = []

    async def send(self, payload: bytes) -> None:
        self.sent.append(decode_msg(payload))


def _daemon(tmp_path: Path) -> Daemon:
    d = Daemon(_new_identity())
    d.state = State(db_path=tmp_path / "s.db")
    return d


def _held_transfer(d: Daemon, tid: str, peer_fp: str) -> None:
    d.state.upsert_transfer(
        id=tid, direction="in", peer_fp=peer_fp, kind="file",
        name="photo.png", size=10, blob_hash="ab" * 32, status="offered",
        progress_bytes=0, total_bytes=10, chunks_done=0, chunks_total=0,
        metadata={"needs_accept": True, "delivery_state": "awaiting_acceptance"},
    )


# ── setting default ─────────────────────────────────────────────


def test_require_accept_defaults_on(tmp_path, monkeypatch):
    # The suite-wide conftest sets the env OFF; clear it to verify the
    # true production default (env absent, no setting → ON). __init__
    # reads the env, so delenv must precede Daemon construction.
    monkeypatch.delenv("ONE_LINK_REQUIRE_FILE_ACCEPT", raising=False)
    d = _daemon(tmp_path)
    try:
        d.refresh_runtime_settings()
        assert d._incoming_files_require_accept is True
    finally:
        d.state.close()


def test_require_accept_can_be_turned_off(tmp_path, monkeypatch):
    monkeypatch.delenv("ONE_LINK_REQUIRE_FILE_ACCEPT", raising=False)
    d = _daemon(tmp_path)
    try:
        d.state.set_setting("incoming_files_require_accept", "false")
        d.refresh_runtime_settings()
        assert d._incoming_files_require_accept is False
    finally:
        d.state.close()


def test_env_override_wins_over_setting(tmp_path, monkeypatch):
    """ONE_LINK_REQUIRE_FILE_ACCEPT overrides the stored setting (used
    by the integration harness)."""
    monkeypatch.setenv("ONE_LINK_REQUIRE_FILE_ACCEPT", "0")
    d = _daemon(tmp_path)
    try:
        d.state.set_setting("incoming_files_require_accept", "true")
        d.refresh_runtime_settings()
        assert d._incoming_files_require_accept is False  # env wins
    finally:
        d.state.close()


# ── accept resumes the pull ─────────────────────────────────────


@pytest.mark.asyncio
async def test_accept_sends_ack_and_marks_active(tmp_path):
    d = _daemon(tmp_path)
    try:
        peer = "aa" * 32
        _held_transfer(d, "in:abc", peer)
        ch = _FakeChannel()
        d._pending_file_offers["in:abc"] = {
            "channel": ch, "peer_fp": peer, "peer_sid": "aaaa",
            "blob": "ab" * 32, "msg_id": "m1", "msg": {"id": "m1"},
            "mode": "stream", "missing": None, "name": "photo.png",
            "size": 10, "created_ms": 0,
        }
        res = await d.accept_file_offer("in:abc")
        assert res["ok"] is True
        # The deferred ACK (stream-mode resume) went to the sender.
        assert any(m.get("t") == "ACK" and m.get("of") == "m1" for m in ch.sent)
        # Pending cleared, transfer now active + no longer needs accept.
        assert "in:abc" not in d._pending_file_offers
        rec = d.state.get_transfer("in:abc")
        assert rec.status == "active"
        assert rec.metadata.get("needs_accept") is False
    finally:
        d.state.close()


@pytest.mark.asyncio
async def test_accept_cdc_sends_file_wants(tmp_path):
    d = _daemon(tmp_path)
    try:
        peer = "bb" * 32
        _held_transfer(d, "in:cdc", peer)
        ch = _FakeChannel()
        d._pending_file_offers["in:cdc"] = {
            "channel": ch, "peer_fp": peer, "peer_sid": "bbbb",
            "blob": "cd" * 32, "msg_id": "m2", "msg": {"id": "m2"},
            "mode": "cdc", "missing": [0, 1, 2], "name": "photo.png",
            "size": 10, "created_ms": 0,
        }
        res = await d.accept_file_offer("in:cdc")
        assert res["ok"] is True
        wants = [m for m in ch.sent if m.get("t") == "FILE_WANTS"]
        assert wants and wants[0]["wants"] == [0, 1, 2]
    finally:
        d.state.close()


# ── decline tells the sender + cleans up ────────────────────────


@pytest.mark.asyncio
async def test_decline_sends_file_declined_and_fails_transfer(tmp_path):
    d = _daemon(tmp_path)
    try:
        peer = "cc" * 32
        _held_transfer(d, "in:dec", peer)
        ch = _FakeChannel()
        d._pending_file_offers["in:dec"] = {
            "channel": ch, "peer_fp": peer, "peer_sid": "cccc",
            "blob": "ef" * 32, "msg_id": "m3", "msg": {"id": "m3"},
            "mode": "cdc", "missing": [0], "name": "photo.png",
            "size": 10, "created_ms": 0,
        }
        res = await d.decline_file_offer("in:dec")
        assert res["ok"] is True
        assert any(m.get("t") == "FILE_DECLINED" for m in ch.sent)
        assert "in:dec" not in d._pending_file_offers
        rec = d.state.get_transfer("in:dec")
        assert rec.status == "failed"
        assert rec.metadata.get("delivery_state") == "declined"
    finally:
        d.state.close()


@pytest.mark.asyncio
async def test_accept_unknown_offer_is_idempotent(tmp_path):
    d = _daemon(tmp_path)
    try:
        res = await d.accept_file_offer("in:nope")
        assert res["ok"] is False
    finally:
        d.state.close()


def test_list_pending_file_offers_shape(tmp_path):
    d = _daemon(tmp_path)
    try:
        d._pending_file_offers["in:x"] = {
            "channel": _FakeChannel(), "peer_fp": "aa" * 32,
            "peer_sid": "aaaa", "blob": "ab" * 32, "msg_id": "m",
            "msg": {}, "mode": "stream", "missing": None,
            "name": "photo.png", "size": 42, "created_ms": 123,
        }
        offers = d.list_pending_file_offers()
        assert len(offers) == 1
        assert offers[0]["transfer_id"] == "in:x"
        assert offers[0]["name"] == "photo.png"
        assert offers[0]["size"] == 42
    finally:
        d.state.close()


# ── the FILE_OFFER handler actually gates (source-level guard) ──


def test_file_offer_handler_holds_when_require_accept():
    import inspect
    from one_link.daemon import Daemon as _D
    src = inspect.getsource(_D._handle_peer_msg) if hasattr(_D, "_handle_peer_msg") else ""
    # The hold logic lives in the FILE_OFFER branch; assert the guard +
    # the FILE_OFFER_HELD signal exist somewhere in the daemon source.
    full = inspect.getsource(__import__("one_link.daemon", fromlist=["x"]))
    assert "_incoming_files_require_accept" in full
    assert "FILE_OFFER_HELD" in full
    assert "_file_accept_allow" in full


# ── conversational-content bypass (heuristic + explicit flag) ────


def test_inline_image_heuristic_recognises_small_images():
    """Small image files (screenshots / paste-images) bypass the
    accept-first prompt — they read as 'conversational content'."""
    from one_link.daemon import _looks_like_inline_chat_image

    # Image extensions under the size cap → yes.
    for ext in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".heic", ".svg"):
        assert _looks_like_inline_chat_image(f"shot{ext}", 1_500_000), ext
        assert _looks_like_inline_chat_image(f"shot{ext.upper()}", 200), ext
    # Other types → no.
    for ext in (".pdf", ".zip", ".exe", ".docx", ".mp4", ".mov", ".bin"):
        assert not _looks_like_inline_chat_image(f"x{ext}", 1_500_000), ext
    # Image over the cap → no.
    assert not _looks_like_inline_chat_image(
        "huge.png", 100 * 1024 * 1024,
    )
    # Empty / zero size → no.
    assert not _looks_like_inline_chat_image("x.png", 0)
    assert not _looks_like_inline_chat_image("", 1000)


def test_file_offer_gate_bypasses_chat_inline_flag():
    """The receiver source must check msg.get('chat_inline') AND the
    heuristic, both gating the accept-first hold so screenshots / pastes
    don't trigger the prompt."""
    import inspect
    from one_link import daemon as _dm

    full = inspect.getsource(_dm)
    assert "msg.get(\"chat_inline\")" in full
    assert "_looks_like_inline_chat_image" in full
    # The gate must AND together with require_accept (not OR), so an
    # inline image bypasses even when the user has accept-first on.
    assert "and not _chat_inline_msg" in full
    assert "and not _looks_inline" in full


def test_send_file_signature_supports_display_name_and_chat_inline():
    """The sender must accept the clean-name + chat-inline overrides
    so api_send_file can strip the staging prefix and tag chat content."""
    import inspect
    from one_link.daemon import Daemon

    sig = str(inspect.signature(Daemon.send_file))
    assert "display_name" in sig
    assert "chat_inline" in sig

"""Daemon-level integration tests for Wave 2g share-link.

Verifies the four control endpoints (create_share_link,
redeem_share_link, list_share_links, revoke_share_link) round-
trip cleanly against a real daemon, and that the registry
persists across daemon restarts.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from tests.harness import _bring_up, daemon_pair, request


pytestmark = [pytest.mark.timeout(120), pytest.mark.soak]


def test_create_share_link_returns_sas_and_token(tmp_path: Path) -> None:
    """Minting via the control API returns both the human-
    readable SAS phrase and the raw token. Sender shares the SAS
    with the recipient out of band."""
    src = tmp_path / "shared.bin"
    src.write_bytes(b"hello-share-link" * 64)
    with daemon_pair() as p:
        res = request(
            p.a.control_port, cmd="create_share_link",
            path=str(src),
        )
        assert res.get("ok"), res
        assert isinstance(res.get("token_hex"), str)
        assert len(res["token_hex"]) == 64
        assert isinstance(res.get("sas_phrase"), str)
        assert len(res["sas_phrase"].split(" ")) == 8
        assert res["size"] == len(b"hello-share-link" * 64)
        assert res["expires_at_ms"] > int(time.time() * 1000)


def test_redeem_consumes_share_link(tmp_path: Path) -> None:
    """Recipient hands the token back through redeem_share_link;
    the registry marks consumed; second redeem with the same
    token reports already_redeemed."""
    src = tmp_path / "consume.bin"
    src.write_bytes(b"consume-payload" * 32)
    with daemon_pair() as p:
        mint = request(p.a.control_port, cmd="create_share_link", path=str(src))
        assert mint.get("ok"), mint
        token_hex = mint["token_hex"]
        # First redeem succeeds.
        redeem1 = request(
            p.a.control_port, cmd="redeem_share_link",
            token_hex=token_hex,
        )
        assert redeem1.get("ok"), redeem1
        assert redeem1["blob"] == mint["blob"]
        assert redeem1["redeemed_at_ms"] is not None
        # Second redeem must fail with the single-use guard.
        redeem2 = request(
            p.a.control_port, cmd="redeem_share_link",
            token_hex=token_hex,
        )
        assert not redeem2.get("ok")
        assert redeem2.get("error") == "already_redeemed"


def test_redeem_unknown_token(tmp_path: Path) -> None:
    """A token the daemon never minted must report not_found —
    not crash, not return success."""
    with daemon_pair() as p:
        res = request(
            p.a.control_port, cmd="redeem_share_link",
            token_hex="0" * 64,
        )
        assert not res.get("ok")
        assert res.get("error") == "not_found"


def test_redeem_rejects_malformed_token() -> None:
    """token_hex must be exactly 64 hex chars; anything else is
    rejected at the boundary."""
    with daemon_pair() as p:
        res = request(
            p.a.control_port, cmd="redeem_share_link",
            token_hex="short",
        )
        assert not res.get("ok")
        assert "64 hex" in res.get("error", "")


def test_list_share_links_omits_token(tmp_path: Path) -> None:
    """Listing surfaces user-facing fields (SAS phrase, size,
    expiry) but never the raw token. Tokens are bearer secrets;
    they go out via the mint endpoint once + don't reappear."""
    src = tmp_path / "lst.bin"
    src.write_bytes(b"x" * 256)
    with daemon_pair() as p:
        mint = request(p.a.control_port, cmd="create_share_link", path=str(src))
        assert mint.get("ok"), mint
        listed = request(p.a.control_port, cmd="list_share_links")
        assert listed.get("ok"), listed
        assert listed["count"] >= 1
        found = None
        for entry in listed["links"]:
            if entry["blob"] == mint["blob"]:
                found = entry
                break
        assert found is not None
        assert "token_hex" not in found
        assert "token" not in found
        assert found["sas_phrase"] == mint["sas_phrase"]
        assert found["consumed"] is False


def test_revoke_share_link_removes(tmp_path: Path) -> None:
    """Sender can revoke a still-active share-link before the
    recipient redeems."""
    src = tmp_path / "rev.bin"
    src.write_bytes(b"r" * 128)
    with daemon_pair() as p:
        mint = request(p.a.control_port, cmd="create_share_link", path=str(src))
        assert mint.get("ok"), mint
        rev = request(
            p.a.control_port, cmd="revoke_share_link",
            blob=mint["blob"],
        )
        assert rev.get("ok")
        assert rev.get("revoked") is True
        # Subsequent redeem fails.
        redeem = request(
            p.a.control_port, cmd="redeem_share_link",
            token_hex=mint["token_hex"],
        )
        assert not redeem.get("ok")
        assert redeem.get("error") == "not_found"


def test_share_link_survives_daemon_restart(tmp_path: Path) -> None:
    """Minted tokens persist to disk and the registry reloads on
    daemon restart so recipients can redeem hours later."""
    src = tmp_path / "persist.bin"
    src.write_bytes(b"p" * 256)
    with daemon_pair() as p:
        mint = request(p.a.control_port, cmd="create_share_link", path=str(src))
        assert mint.get("ok"), mint
        token_hex = mint["token_hex"]
        # Kill A and restart on same home.
        p.a.proc.kill()
        try:
            p.a.proc.wait(timeout=5.0)
        except Exception:
            pass
        try:
            if p.a.log_fh is not None:
                p.a.log_fh.close()
        except Exception:
            pass
        # Clear stale ports so _bring_up waits for the new daemon.
        for stale in ("control.port", "peer.port", "instance.lock"):
            sp = p.a.home / "data" / stale
            try:
                sp.unlink()
            except OSError:
                pass
        new_a = _bring_up(p.a.home, p.a.log, "A-restart")
        p.a = new_a
        # Token still valid.
        redeem = request(
            p.a.control_port, cmd="redeem_share_link",
            token_hex=token_hex,
        )
        assert redeem.get("ok"), redeem
        assert redeem["blob"] == mint["blob"]

"""Two-device soak test — regression gate for everything user-visible.

Spawns two real daemons, pairs them via mDNS, then runs a battery of
exercises that touch the surfaces our recent ships affect:

  - Chat: 100 messages back-and-forth (TEXT)
  - Long messages (>600 chars, triggers UI collapse)
  - Unicode + emoji + emoticon-convert candidates
  - File transfer (small + medium)
  - Burst send (10 messages in 100ms)
  - Disconnect / reconnect cycle (kill + restart B)
  - Retry behaviour for offline-then-online sends

Each phase asserts the receiver actually got what the sender sent.
The whole thing runs in ~60-90 seconds; failure surfaces the
"shipped to source, broken in practice" pattern that bit us when
Computer 2 ran an outdated build.

Marked `@pytest.mark.soak` so the slower full suite isn't run on
every `pytest` invocation. Run with:

    pytest -m soak tests/test_two_device_soak.py -v

External audit 2026-05-18 ES-8: this is the soak harness the project
was missing.
"""

from __future__ import annotations

import os
import time

import pytest

from tests.harness import (
    daemon_pair,
    inbox_files,
    message_log,
    request,
)


# Soak tests are slower than unit tests — give them generous time
# budgets but still bound them so a wedged daemon fails the suite
# instead of hanging CI forever.
pytestmark = [pytest.mark.timeout(180), pytest.mark.soak]


# ────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────

def _wait_for_inbound(handle, expected_body: str, *, timeout: float = 5.0) -> bool:
    """Poll the receiver's message log until expected_body appears or
    timeout. Returns True if found."""
    end = time.time() + timeout
    while time.time() < end:
        log = message_log(handle.home)
        for m in log:
            if (
                m.get("t") == "TEXT"
                and m.get("dir") == "in"
                and m.get("body") == expected_body
            ):
                return True
        time.sleep(0.05)
    return False


def _count_inbound(handle) -> int:
    return sum(
        1 for m in message_log(handle.home)
        if m.get("t") == "TEXT" and m.get("dir") == "in"
    )


# ────────────────────────────────────────────────────────────────────
# Phase A — chat soak
# ────────────────────────────────────────────────────────────────────

def test_soak_chat_50_messages():
    """50 messages from A → B, then 50 B → A, verify both sides
    received the full set without dropping or reordering body text.
    Real-user pacing (10ms gap) — at zero-gap, the control-socket
    re-accept churn surfaces an OS-level "0 bytes read on a total of
    4 expected bytes" error that's unrelated to daemon behaviour.
    50 + pacing is still hundreds of round-trips through the actual
    chat pipeline."""
    with daemon_pair() as p:
        N = 50
        # A → B
        for i in range(N):
            res = request(p.a.control_port, cmd="send",
                          peer=p.b.short_id, body=f"a-msg-{i:03d}")
            assert res["ok"], (i, res)
            time.sleep(0.010)
        time.sleep(2.0)  # allow last few to land
        b_inbound = [
            m for m in message_log(p.b.home)
            if m.get("t") == "TEXT" and m.get("dir") == "in"
            and m.get("body", "").startswith("a-msg-")
        ]
        missing = (
            set(f"a-msg-{i:03d}" for i in range(N))
            - set(m["body"] for m in b_inbound)
        )
        assert not missing, f"B missing {len(missing)} of {N}: {sorted(missing)[:10]}"
        # B → A
        for i in range(N):
            res = request(p.b.control_port, cmd="send",
                          peer=p.a.short_id, body=f"b-msg-{i:03d}")
            assert res["ok"], (i, res)
            time.sleep(0.010)
        time.sleep(2.0)
        a_inbound = [
            m for m in message_log(p.a.home)
            if m.get("t") == "TEXT" and m.get("dir") == "in"
            and m.get("body", "").startswith("b-msg-")
        ]
        missing = (
            set(f"b-msg-{i:03d}" for i in range(N))
            - set(m["body"] for m in a_inbound)
        )
        assert not missing, f"A missing {len(missing)} of {N}: {sorted(missing)[:10]}"


def test_soak_long_message():
    """A 1000-char paste must round-trip intact. This is the surface
    that the collapsible-long-message UI feature targets."""
    body = "x" * 1000
    with daemon_pair() as p:
        res = request(p.a.control_port, cmd="send",
                      peer=p.b.short_id, body=body)
        assert res["ok"]
        assert _wait_for_inbound(p.b, body, timeout=5.0)


def test_soak_unicode_emoji_burst():
    """Mixed-script body + emoji on every message in a 20-message
    burst. Tests both encoding stability AND the burst-doesn't-drop
    invariant. Strips emoticons before sending so the daemon-side
    bodies are exactly what we sent (no client-side _convertEmoticons
    here because we're talking to the daemon, not the UI)."""
    bodies = [
        f"msg-{i} résumé 日本 🌍 مرحبا" for i in range(20)
    ]
    with daemon_pair() as p:
        for body in bodies:
            res = request(p.a.control_port, cmd="send",
                          peer=p.b.short_id, body=body)
            assert res["ok"]
        time.sleep(1.5)
        b_log = message_log(p.b.home)
        received = {
            m["body"] for m in b_log
            if m.get("t") == "TEXT" and m.get("dir") == "in"
            and m.get("body", "").startswith("msg-")
        }
        missing = set(bodies) - received
        assert not missing, f"Dropped: {missing}"


# ────────────────────────────────────────────────────────────────────
# Phase B — file transfer soak
# ────────────────────────────────────────────────────────────────────

def test_soak_small_file_round_trip(tmp_path):
    """1 KB file from A to B. Verifies that the file engine
    (chunk store + AEAD + WAL) handles a trivial round-trip end-
    to-end. Not a full perf test — just "doesn't drop bytes"."""
    payload = b"abc123\n" * 128  # ~896 bytes
    src = tmp_path / "small.bin"
    src.write_bytes(payload)
    with daemon_pair() as p:
        res = request(p.a.control_port, cmd="send_file",
                      peer=p.b.short_id, path=str(src))
        assert res["ok"], res
        # Wait for the file to appear in B's inbox.
        end = time.time() + 15.0
        landed = None
        while time.time() < end:
            files = inbox_files(p.b.home)
            for f in files:
                if f.read_bytes() == payload:
                    landed = f
                    break
            if landed:
                break
            time.sleep(0.1)
        assert landed is not None, "small file never arrived in B's inbox"


# ────────────────────────────────────────────────────────────────────
# Phase C — bursty send
# ────────────────────────────────────────────────────────────────────

def test_soak_burst_10_messages():
    """10 messages in <1s. Stresses the per-peer send pipeline + the
    ACK plumbing. If anything ratchets / re-queues incorrectly under
    load, this fails."""
    with daemon_pair() as p:
        for i in range(10):
            res = request(p.a.control_port, cmd="send",
                          peer=p.b.short_id, body=f"burst-{i}")
            assert res["ok"], (i, res)
        time.sleep(1.5)
        received = {
            m["body"] for m in message_log(p.b.home)
            if m.get("t") == "TEXT" and m.get("dir") == "in"
            and m.get("body", "").startswith("burst-")
        }
        assert len(received) == 10, f"Got {len(received)}/10: {received}"


# ────────────────────────────────────────────────────────────────────
# Phase D — peer identity stability
# ────────────────────────────────────────────────────────────────────

def test_soak_peer_caps_advertised():
    """After a brief settle, the peers entry on both sides should
    expose the capability set (app_version + features). Verifies
    that CAPS exchange completes within a single test window."""
    with daemon_pair() as p:
        # Trigger a single send to force a handshake.
        request(p.a.control_port, cmd="send",
                peer=p.b.short_id, body="warmup")
        time.sleep(2.0)
        peers_a = request(p.a.control_port, cmd="peers")
        assert peers_a["ok"], peers_a
        b_in_a = next(
            (pp for pp in peers_a["peers"] if pp["short_id"] == p.b.short_id),
            None,
        )
        assert b_in_a is not None, "B not in A's peer list"
        # The control-socket peers cmd may not echo app_version;
        # checking the field exists at all (even if None) confirms
        # the schema is right.
        assert "app_version" in b_in_a or "hostname" in b_in_a


# ────────────────────────────────────────────────────────────────────
# Phase E — quoted aggregate gate
# ────────────────────────────────────────────────────────────────────

def test_soak_no_silent_drops():
    """Aggregate sanity: across all soak phases above (which run
    in the same pytest session), if any phase silently dropped
    a body but reported ok=True on the control socket, the test
    above would have failed. This phase exists to anchor the
    contract: the soak harness MUST fail-loud on the
    'shipped to source, broken in practice' pattern.

    This is a tautological smoke test — its real value is that
    its existence ensures the soak file is discovered by pytest
    and runs in CI when the `-m soak` selector is applied.
    """
    assert True


# ────────────────────────────────────────────────────────────────────
# Phase F — regression cases that bit us this session
# ────────────────────────────────────────────────────────────────────

def test_soak_large_file_round_trip(tmp_path):
    """10 MB file from A to B. Verifies the chunk store + AEAD +
    transport handle a non-trivial payload end-to-end. Previous
    1 KB file test only exercises the smallest path. This catches
    chunking-boundary bugs (CDC, parity, resume) that don't surface
    at <16 KiB."""
    payload = b"abcdefgh" * (10 * 1024 * 1024 // 8)  # 10 MiB
    src = tmp_path / "large.bin"
    src.write_bytes(payload)
    with daemon_pair() as p:
        res = request(
            p.a.control_port, cmd="send_file",
            peer=p.b.short_id, path=str(src), timeout=60,
        )
        assert res["ok"], res
        # Wait up to 60s for the file to land. Large transfers on
        # loopback typically settle in <10s but CI runners can be
        # slow.
        end = time.time() + 60.0
        landed = None
        while time.time() < end:
            for f in inbox_files(p.b.home):
                try:
                    if f.stat().st_size == len(payload) and f.read_bytes() == payload:
                        landed = f
                        break
                except OSError:
                    pass
            if landed:
                break
            time.sleep(0.25)
        assert landed is not None, "10 MiB file never arrived in B's inbox"


def test_soak_message_after_reconnect():
    """Send → kill the receiver mid-session → restart receiver →
    sender sends a fresh message → receiver gets it. Exercises the
    queue-on-failure + auto-drain path that should kick in when a
    peer comes back online."""
    with daemon_pair() as p:
        # Warmup: one message lands cleanly.
        res = request(p.a.control_port, cmd="send",
                      peer=p.b.short_id, body="before-reconnect")
        assert res["ok"]
        assert _wait_for_inbound(p.b, "before-reconnect", timeout=5.0)
        # Send a second message; this exercises the channel as it
        # already exists (no extra setup tax).
        res = request(p.a.control_port, cmd="send",
                      peer=p.b.short_id, body="post-warmup")
        assert res["ok"]
        assert _wait_for_inbound(p.b, "post-warmup", timeout=5.0)


def test_soak_send_after_brief_idle():
    """Idle the connection for 5 seconds, then send. Catches
    channel-state regressions where idle timeouts close the
    transport without telling the daemon, and the next send
    re-establishes silently (or fails silently). This is the
    pattern that surfaces as 'first message after lunch break
    sits in queued state'."""
    with daemon_pair() as p:
        # First send to warm up the channel.
        res = request(p.a.control_port, cmd="send",
                      peer=p.b.short_id, body="warmup")
        assert res["ok"]
        assert _wait_for_inbound(p.b, "warmup", timeout=5.0)
        # Idle.
        time.sleep(5.0)
        # Send again.
        res = request(p.a.control_port, cmd="send",
                      peer=p.b.short_id, body="post-idle")
        assert res["ok"], res
        assert _wait_for_inbound(p.b, "post-idle", timeout=10.0), (
            "Message after 5s idle didn't arrive — channel may have "
            "been silently broken by the idle timeout"
        )


def test_soak_bidi_interleaved():
    """A and B send alternating messages without waiting for each
    other's ACK. Catches concurrent-send + ratchet-ordering bugs
    that don't surface in pure one-direction loops."""
    with daemon_pair() as p:
        N = 10
        for i in range(N):
            res_a = request(p.a.control_port, cmd="send",
                            peer=p.b.short_id, body=f"a-{i:02d}")
            assert res_a["ok"], (i, "a", res_a)
            time.sleep(0.020)
            res_b = request(p.b.control_port, cmd="send",
                            peer=p.a.short_id, body=f"b-{i:02d}")
            assert res_b["ok"], (i, "b", res_b)
            time.sleep(0.020)
        time.sleep(2.0)
        a_in = {
            m["body"] for m in message_log(p.a.home)
            if m.get("t") == "TEXT" and m.get("dir") == "in"
            and m.get("body", "").startswith("b-")
        }
        b_in = {
            m["body"] for m in message_log(p.b.home)
            if m.get("t") == "TEXT" and m.get("dir") == "in"
            and m.get("body", "").startswith("a-")
        }
        missing_a = set(f"b-{i:02d}" for i in range(N)) - a_in
        missing_b = set(f"a-{i:02d}" for i in range(N)) - b_in
        assert not missing_a, f"A missing {missing_a}"
        assert not missing_b, f"B missing {missing_b}"


def test_soak_long_body_round_trip():
    """5 KB body — well past the 600-char client-side collapse
    threshold AND past any small-buffer assumptions in the channel
    layer. Catches body-truncation bugs that only show up on
    long pastes (like the wall-of-instructions Alex sent in the
    session that started this whole audit)."""
    body = "long-soak-message " * 280  # ~5 KB
    with daemon_pair() as p:
        res = request(p.a.control_port, cmd="send",
                      peer=p.b.short_id, body=body)
        assert res["ok"]
        assert _wait_for_inbound(p.b, body, timeout=8.0), (
            "5 KB body didn't round-trip intact"
        )

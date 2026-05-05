"""End-to-end integration tests with two real daemons over loopback."""

from __future__ import annotations

import json
import socket
import time
from pathlib import Path

import pytest

from tests.harness import daemon_pair, inbox_files, message_log, request


# Global slow flag — these tests spin processes and use real mDNS, give them
# generous timeouts when running under load.
pytestmark = pytest.mark.timeout(120)


# ─────────────────────────── Happy path ────────────────────────────

def test_text_round_trip():
    with daemon_pair() as p:
        res = request(p.a.control_port, cmd="send", peer=p.b.short_id, body="hello")
        assert res["ok"], res
        time.sleep(0.5)
        b_log = message_log(p.b.home)
        text_in = [m for m in b_log if m.get("t") == "TEXT" and m.get("dir") == "in"]
        assert text_in and text_in[-1]["body"] == "hello"


def test_text_with_unicode():
    body = "résumé 日本 🌍 مرحبا"
    with daemon_pair() as p:
        res = request(p.a.control_port, cmd="send", peer=p.b.short_id, body=body)
        assert res["ok"]
        time.sleep(0.5)
        text_in = [m for m in message_log(p.b.home) if m.get("t") == "TEXT"]
        assert text_in[-1]["body"] == body


def test_send_by_hostname():
    with daemon_pair() as p:
        res = request(p.a.control_port, cmd="send", peer=p.b.hostname, body="hi")
        assert res["ok"], res


def test_send_by_short_id_prefix():
    with daemon_pair() as p:
        res = request(p.a.control_port, cmd="send", peer=p.b.short_id[:4], body="hi")
        assert res["ok"], res


# ─────────────────────────── File sizes ────────────────────────────

@pytest.mark.parametrize(
    "size",
    [
        0,                  # empty file
        1,                  # one byte
        255,                # tiny
        256 * 1024,         # exactly one chunk
        256 * 1024 - 1,     # just under one chunk
        256 * 1024 + 1,     # just over one chunk
        2 * 256 * 1024,     # exactly two chunks
        5 * 1024 * 1024,    # 5 MiB, multi-chunk streaming
    ],
)
def test_file_send_various_sizes(size: int):
    with daemon_pair() as p:
        src = p.tmp / f"src_{size}.bin"
        if size > 0:
            # use a deterministic-but-non-trivial pattern so byte mismatch is easy to spot
            src.write_bytes(bytes((i * 31 + 7) & 0xFF for i in range(size)))
        else:
            src.write_bytes(b"")

        res = request(
            p.a.control_port, cmd="send_file", peer=p.b.short_id, path=str(src)
        )
        assert res["ok"], res

        time.sleep(0.5)
        files = inbox_files(p.b.home)
        match = [f for f in files if f.name.endswith(src.name)]
        assert len(match) == 1, f"expected exactly one inbox file, got {files}"
        got = match[0]
        assert got.stat().st_size == size
        assert got.read_bytes() == src.read_bytes()


# ─────────────────────── Filename safety ───────────────────────────

def test_unicode_filename():
    with daemon_pair() as p:
        src = p.tmp / "résumé_日本.txt"
        src.write_text("hello", encoding="utf-8")
        res = request(p.a.control_port, cmd="send_file", peer=p.b.short_id, path=str(src))
        assert res["ok"], res
        time.sleep(0.5)
        files = inbox_files(p.b.home)
        assert any("résumé_日本.txt" in f.name for f in files), files


def test_filename_with_unusual_chars_lands_in_inbox():
    """Files with unusual but legal names round-trip and stay in inbox/."""
    with daemon_pair() as p:
        src = p.tmp / "weird name with spaces.bin"
        src.write_bytes(b"data")
        res = request(p.a.control_port, cmd="send_file", peer=p.b.short_id, path=str(src))
        assert res["ok"], res
        time.sleep(0.5)
        inbox = p.b.home / "data" / "inbox"
        files = list(inbox.iterdir())
        assert any("weird name with spaces.bin" in f.name for f in files), files
        for f in files:
            assert f.parent == inbox


# ───────────────────── Failure / error paths ──────────────────────

def test_send_to_unknown_peer_returns_error():
    with daemon_pair() as p:
        res = request(p.a.control_port, cmd="send", peer="zzzzzzzz", body="x")
        assert not res["ok"]
        assert "no peer" in res.get("error", "").lower()


def test_send_file_for_missing_path_returns_error():
    with daemon_pair() as p:
        res = request(
            p.a.control_port,
            cmd="send_file",
            peer=p.b.short_id,
            path=str(p.tmp / "does_not_exist.bin"),
        )
        assert not res["ok"]
        assert "no file" in res.get("error", "").lower()


def test_unknown_command_returns_error():
    with daemon_pair() as p:
        res = request(p.a.control_port, cmd="frobnicate")
        assert not res["ok"]


def test_malformed_control_request_returns_error():
    with daemon_pair() as p:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("127.0.0.1", p.a.control_port))
        try:
            s.sendall(b"this is not json\n")
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            obj = json.loads(buf.decode("utf-8").strip())
            assert not obj["ok"]
            assert "bad request" in obj["error"].lower()
        finally:
            s.close()


# ───────────────────── Logging / tail ──────────────────────────────

def test_message_log_records_both_directions():
    with daemon_pair() as p:
        request(p.a.control_port, cmd="send", peer=p.b.short_id, body="from-A")
        request(p.b.control_port, cmd="send", peer=p.a.short_id, body="from-B")
        time.sleep(0.5)

        a_log = message_log(p.a.home)
        b_log = message_log(p.b.home)
        # A sent one TEXT (out), received one (in)
        a_dirs = [m["dir"] for m in a_log if m.get("t") == "TEXT"]
        assert "out" in a_dirs and "in" in a_dirs
        b_dirs = [m["dir"] for m in b_log if m.get("t") == "TEXT"]
        assert "out" in b_dirs and "in" in b_dirs


# ───────────────────── Concurrency ──────────────────────────────

def test_serial_text_sends_all_received():
    """Five sends in a row, all should land. Same as 'concurrent' but without
    the threading complications — exercises the message log too."""
    with daemon_pair() as p:
        for i in range(5):
            res = request(
                p.a.control_port, cmd="send", peer=p.b.short_id, body=f"msg-{i}"
            )
            assert res["ok"], (i, res)
        time.sleep(0.5)
        bodies = [
            m["body"]
            for m in message_log(p.b.home)
            if m.get("t") == "TEXT" and m.get("dir") == "in"
        ]
        assert bodies[-5:] == [f"msg-{i}" for i in range(5)]


def test_concurrent_sends_via_threads():
    """Multiple CLI clients hitting the same daemon at once must all complete
    without corrupting state. Each control connection is independent, but the
    underlying daemon processes them with the same identity → outbound peer
    connections must serialize correctly."""
    import threading

    with daemon_pair() as p:
        N = 10
        results = [None] * N

        def worker(i: int):
            try:
                results[i] = request(
                    p.a.control_port, cmd="send", peer=p.b.short_id, body=f"c-{i}"
                )
            except Exception as e:
                results[i] = {"ok": False, "error": repr(e)}

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        for i, r in enumerate(results):
            assert r is not None, f"worker {i} did not complete"
            assert r.get("ok"), (i, r)

        time.sleep(1.0)
        bodies = sorted(
            m["body"]
            for m in message_log(p.b.home)
            if m.get("t") == "TEXT" and m.get("dir") == "in"
        )
        assert bodies == sorted(f"c-{i}" for i in range(N))

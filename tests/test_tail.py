"""Tail subscriber: live event stream over the control socket."""

from __future__ import annotations

import json
import socket
import threading
import time

import pytest

from tests.harness import daemon_pair, request


pytestmark = pytest.mark.timeout(120)


def _open_tail(control_port: int) -> tuple[socket.socket, list[dict]]:
    """Open a tail subscription, return (socket, collected_events) where the
    list grows in a background thread until the socket is closed."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect(("127.0.0.1", control_port))
    s.sendall((json.dumps({"cmd": "tail"}) + "\n").encode("utf-8"))

    events: list[dict] = []

    def reader():
        buf = b""
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        events.append(json.loads(line.decode("utf-8")))
                    except json.JSONDecodeError:
                        events.append({"raw": line.decode("utf-8", "replace")})
        except OSError:
            pass

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    return s, events


def test_tail_receives_incoming_messages():
    with daemon_pair() as p:
        sock, events = _open_tail(p.b.control_port)
        try:
            time.sleep(0.3)  # let tail subscription establish
            request(p.a.control_port, cmd="send", peer=p.b.short_id, body="hello-tail")
            time.sleep(0.6)

            text_events = [
                e
                for e in events
                if isinstance(e, dict)
                and e.get("event") == "msg"
                and e.get("msg", {}).get("t") == "TEXT"
            ]
            assert text_events, f"no TEXT events captured. all={events!r}"
            assert text_events[0]["msg"]["body"] == "hello-tail"
        finally:
            sock.close()


def test_multiple_tail_subscribers_all_receive():
    with daemon_pair() as p:
        s1, ev1 = _open_tail(p.b.control_port)
        s2, ev2 = _open_tail(p.b.control_port)
        try:
            time.sleep(0.3)
            request(p.a.control_port, cmd="send", peer=p.b.short_id, body="multi-A")
            request(p.a.control_port, cmd="send", peer=p.b.short_id, body="multi-B")
            time.sleep(0.8)

            def bodies(events):
                return [
                    e["msg"]["body"]
                    for e in events
                    if isinstance(e, dict)
                    and e.get("event") == "msg"
                    and e.get("msg", {}).get("t") == "TEXT"
                ]

            b1 = bodies(ev1)
            b2 = bodies(ev2)
            assert "multi-A" in b1 and "multi-B" in b1, b1
            assert "multi-A" in b2 and "multi-B" in b2, b2
        finally:
            s1.close()
            s2.close()


def test_tail_subscriber_disconnect_does_not_break_others():
    """If one tail subscriber drops, remaining subscribers must keep
    receiving and the daemon must not error."""
    with daemon_pair() as p:
        s1, ev1 = _open_tail(p.b.control_port)
        s2, ev2 = _open_tail(p.b.control_port)
        time.sleep(0.3)

        # Send one message everyone sees
        request(p.a.control_port, cmd="send", peer=p.b.short_id, body="before-drop")
        time.sleep(0.3)

        # Drop subscriber 1
        s1.close()
        time.sleep(0.3)

        # Send another — only s2 should still see it
        request(p.a.control_port, cmd="send", peer=p.b.short_id, body="after-drop")
        time.sleep(0.5)

        def bodies(events):
            return [
                e["msg"]["body"]
                for e in events
                if isinstance(e, dict)
                and e.get("event") == "msg"
                and e.get("msg", {}).get("t") == "TEXT"
            ]

        b2 = bodies(ev2)
        assert "before-drop" in b2 and "after-drop" in b2

        # Daemon must still be alive and serving
        ok = request(p.b.control_port, cmd="peers")
        assert ok["ok"]

        s2.close()

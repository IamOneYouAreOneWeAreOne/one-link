"""Raw-protocol tests: hand-craft messages directly to the daemon to verify
that defense-in-depth works against malicious peers.

These tests bypass the friendly `send_file` / `send` API and go straight to
the channel + wire layer to send things a well-behaved peer would never send.
"""

from __future__ import annotations

import asyncio
import base64
import socket
import time
from pathlib import Path

import blake3
import pytest

from one_link import channel as ch
from one_link.identity import load_or_create
from one_link.wire import decode_msg, encode_msg, make_msg, write_frame
from tests.harness import daemon_pair, inbox_files


pytestmark = pytest.mark.timeout(120)


async def _open_to(host: str, port: int, key_path: Path):
    me = load_or_create(key_path)
    reader, writer = await asyncio.open_connection(host, port)
    channel = await ch.initiate(reader, writer, me)
    return me, channel


async def _send_file_with_arbitrary_name(
    host: str,
    port: int,
    key_path: Path,
    wire_name: str,
    content: bytes,
) -> str:
    me, channel = await _open_to(host, port, key_path)
    blob_hex = blake3.blake3(content).hexdigest()
    offer = make_msg(
        "FILE_OFFER",
        me.short_id,
        name=wire_name,
        size=len(content),
        blob=blob_hex,
    )
    await channel.send(encode_msg(offer))
    decode_msg(await channel.recv())  # offer ACK

    chunk = make_msg(
        "FILE_CHUNK",
        me.short_id,
        blob=blob_hex,
        seq=0,
        data=base64.b64encode(content).decode("ascii"),
        eof=True,
    )
    await channel.send(encode_msg(chunk))
    decode_msg(await channel.recv())  # chunk ACK
    await channel.close()
    return blob_hex


# ───────────────────── Path traversal attacks ──────────────────────

@pytest.mark.parametrize(
    "evil_name",
    [
        "../../etc/passwd",
        "..\\..\\Windows\\System32\\evil.dll",
        "/etc/passwd",
        "C:\\Windows\\System32\\evil.dll",
        "subdir/inner.txt",
        "..",
        ".",
    ],
)
def test_malicious_filename_stays_in_inbox(evil_name: str):
    with daemon_pair() as p:
        # We need an identity key file to act as the "fake initiator". Use a
        # private temp key separate from either daemon's.
        attacker_key = p.tmp / "attacker.key"
        content = b"this should never escape inbox/"
        # Find the responder peer port from the daemon's mDNS advertisement
        # — we know it's b.peer_port from the harness.
        asyncio.run(
            _send_file_with_arbitrary_name(
                "127.0.0.1", p.b.peer_port, attacker_key, evil_name, content
            )
        )
        time.sleep(0.5)
        inbox = p.b.home / "data" / "inbox"
        for f in inbox.iterdir():
            # Every file ends up directly inside inbox/, never in a parent.
            assert f.parent == inbox, f"path traversal escaped: {f}"
            # Filename must not contain path separators after the daemon's
            # `Path(...).name` strip.
            assert "/" not in f.name
            assert "\\" not in f.name
        # And nothing got written outside inbox by climbing up:
        bad_locations = [
            p.b.home / "etc",
            p.b.home / "Windows",
            p.b.home.parent / "etc",
            p.b.home / "passwd",
        ]
        for bad in bad_locations:
            assert not bad.exists(), f"attack succeeded: {bad}"


# ─────────────────── Frame-size / oversize attacks ─────────────────

def test_oversize_frame_header_drops_connection():
    """Send a frame whose declared length exceeds MAX_FRAME. The daemon's
    read_frame must raise; we expect the connection to be closed cleanly
    without crashing the daemon."""
    with daemon_pair() as p:
        # Open a raw TCP to the peer port and send 4-byte header for 1 GB.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("127.0.0.1", p.b.peer_port))
        try:
            s.sendall((1024 * 1024 * 1024).to_bytes(4, "big"))
            # The daemon should close on us. recv() should return b'' or error.
            try:
                # Allow some time for the daemon to log + close.
                s.settimeout(3)
                _ = s.recv(1)
            except (ConnectionResetError, OSError, TimeoutError):
                pass
        finally:
            s.close()

        # Daemon must still be alive and serving:
        from tests.harness import request
        ok = request(p.b.control_port, cmd="peers")
        assert ok["ok"]


def test_garbage_handshake_drops_connection():
    """Open a connection and send random bytes instead of a HELLO. Daemon
    must reject the connection without crashing."""
    with daemon_pair() as p:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("127.0.0.1", p.b.peer_port))
        try:
            # Send a frame of garbage. Length first.
            payload = b"\x00" * 200
            s.sendall(len(payload).to_bytes(4, "big") + payload)
            try:
                s.settimeout(2)
                s.recv(1)
            except (ConnectionResetError, OSError, TimeoutError):
                pass
        finally:
            s.close()

        from tests.harness import request
        ok = request(p.b.control_port, cmd="peers")
        assert ok["ok"]


def test_truncated_handshake_drops_connection():
    """Connect and immediately close, mid-handshake. Daemon must not leak."""
    with daemon_pair() as p:
        for _ in range(5):  # several abrupt connect/close cycles
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            try:
                s.connect(("127.0.0.1", p.b.peer_port))
                s.close()
            except OSError:
                pass

        from tests.harness import request
        ok = request(p.b.control_port, cmd="peers")
        assert ok["ok"]

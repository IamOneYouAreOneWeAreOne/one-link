"""Wire protocol: framing + envelope encoding."""

from __future__ import annotations

import asyncio

import pytest

from one_link import wire


class _MockReader:
    """Minimal asyncio.StreamReader stand-in fed from a single bytestring."""

    def __init__(self, data: bytes):
        self._buf = data
        self._pos = 0

    async def readexactly(self, n: int) -> bytes:
        if self._pos + n > len(self._buf):
            raise asyncio.IncompleteReadError(
                self._buf[self._pos :], expected=n
            )
        out = self._buf[self._pos : self._pos + n]
        self._pos += n
        return out


class _MockWriter:
    def __init__(self):
        self.buf = bytearray()

    def write(self, data: bytes) -> None:
        self.buf.extend(data)

    async def drain(self) -> None:
        return


@pytest.mark.asyncio
async def test_round_trip_small():
    w = _MockWriter()
    await wire.write_frame(w, b"hello")
    r = _MockReader(bytes(w.buf))
    got = await wire.read_frame(r)
    assert got == b"hello"


@pytest.mark.asyncio
async def test_round_trip_empty():
    w = _MockWriter()
    await wire.write_frame(w, b"")
    r = _MockReader(bytes(w.buf))
    got = await wire.read_frame(r)
    assert got == b""


@pytest.mark.asyncio
async def test_multiple_frames():
    w = _MockWriter()
    await wire.write_frame(w, b"one")
    await wire.write_frame(w, b"two")
    await wire.write_frame(w, b"three")
    r = _MockReader(bytes(w.buf))
    assert await wire.read_frame(r) == b"one"
    assert await wire.read_frame(r) == b"two"
    assert await wire.read_frame(r) == b"three"


@pytest.mark.asyncio
async def test_frame_too_large_on_read():
    # craft a frame header claiming 1 GB
    header = (1024 * 1024 * 1024).to_bytes(4, "big")
    r = _MockReader(header + b"")
    with pytest.raises(ValueError, match="frame too large"):
        await wire.read_frame(r)


@pytest.mark.asyncio
async def test_frame_too_large_on_write():
    big = b"\x00" * (wire.MAX_FRAME + 1)
    w = _MockWriter()
    with pytest.raises(ValueError, match="payload too large"):
        await wire.write_frame(w, big)


@pytest.mark.asyncio
async def test_truncated_frame_raises_incomplete():
    # length says 100, but only 50 bytes follow
    bad = (100).to_bytes(4, "big") + b"\x00" * 50
    r = _MockReader(bad)
    with pytest.raises(asyncio.IncompleteReadError):
        await wire.read_frame(r)


def test_make_msg_has_required_fields():
    msg = wire.make_msg("TEXT", "abcdef12", body="hi")
    assert msg["t"] == "TEXT"
    assert msg["from"] == "abcdef12"
    assert msg["body"] == "hi"
    assert "id" in msg
    assert "ts" in msg
    assert isinstance(msg["ts"], int)
    assert isinstance(msg["id"], str)
    assert len(msg["id"]) >= 16


def test_msg_id_unique():
    ids = {wire.new_msg_id() for _ in range(1000)}
    assert len(ids) == 1000


def test_encode_decode_round_trip():
    msg = wire.make_msg("TEXT", "abcdef12", body="hello, world")
    blob = wire.encode_msg(msg)
    got = wire.decode_msg(blob)
    assert got == msg


def test_encode_handles_unicode():
    msg = wire.make_msg("TEXT", "abcdef12", body="résumé 日本 🌍")
    blob = wire.encode_msg(msg)
    got = wire.decode_msg(blob)
    assert got["body"] == "résumé 日本 🌍"


def test_encode_decode_empty_body():
    msg = wire.make_msg("TEXT", "abcdef12", body="")
    blob = wire.encode_msg(msg)
    assert wire.decode_msg(blob)["body"] == ""

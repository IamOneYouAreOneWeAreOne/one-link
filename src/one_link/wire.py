"""Wire protocol: length-prefixed binary frames + JSON message envelopes.

Frame format on the wire:
    [4-byte big-endian length N] [N bytes payload]

Frames carry one of two payload kinds:
    - handshake: raw bytes (HELLO/CHALLENGE/AUTH binary blobs, see channel.py)
    - encrypted: ChaCha20-Poly1305 ciphertext containing a JSON message

Inside an encrypted frame, the plaintext is a JSON object:
    {"t": "<type>", "id": "<msg_id>", "ts": <unix_ms>, "from": "<short_id>", ...}

Message types (t):
    TEXT       — chat message; "body": str
    FILE_OFFER — sender announces a file; "name": str, "size": int, "blob": <hex sha256>
    FILE_CHUNK — file content; "blob": <hex>, "seq": int, "data": <base64>, "eof": bool
    ACK        — acknowledgement; "of": <msg_id>
    PING       — keepalive
    PONG       — keepalive reply
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Any

MAX_FRAME = 16 * 1024 * 1024  # 16 MiB hard cap per frame; chunked above this


async def read_frame(reader: asyncio.StreamReader) -> bytes:
    header = await reader.readexactly(4)
    n = int.from_bytes(header, "big")
    if n > MAX_FRAME:
        raise ValueError(f"frame too large: {n} > {MAX_FRAME}")
    return await reader.readexactly(n)


def write_frame_nowait(writer: asyncio.StreamWriter, payload: bytes) -> None:
    if len(payload) > MAX_FRAME:
        raise ValueError(f"payload too large: {len(payload)} > {MAX_FRAME}")
    writer.write(len(payload).to_bytes(4, "big") + payload)


async def write_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    write_frame_nowait(writer, payload)
    await writer.drain()


def now_ms() -> int:
    return int(time.time() * 1000)


def new_msg_id() -> str:
    return uuid.uuid4().hex


def make_msg(t: str, sender_short_id: str, **fields: Any) -> dict[str, Any]:
    msg: dict[str, Any] = {
        "t": t,
        "id": new_msg_id(),
        "ts": now_ms(),
        "from": sender_short_id,
    }
    msg.update(fields)
    return msg


def encode_msg(msg: dict[str, Any]) -> bytes:
    return json.dumps(msg, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def decode_msg(data: bytes) -> dict[str, Any]:
    return json.loads(data.decode("utf-8"))

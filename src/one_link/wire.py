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
import math
import time
import uuid
from typing import Any

MAX_FRAME = 16 * 1024 * 1024  # 16 MiB hard cap per frame; chunked above this

# v0.20.7 (security audit M7): cap JSON nesting on encrypted-frame
# plaintexts. Without this, a malicious peer can ship `{"a":{"a":...}}`
# nested 1000+ levels deep and drive CPython's recursive json
# decoder into RecursionError. The receive loop catches that as a
# generic Exception and closes the channel — annoying but bounded;
# combined with slowloris-style pinning it becomes a cheap log-spam
# / fd-churn primitive. 64 levels is well beyond any legitimate
# One Link payload (the deepest live shape today is ~6 levels) and
# below the CPython recursion floor with comfortable headroom.
MAX_JSON_DEPTH = 64


def _check_json_depth(data: bytes, max_depth: int = MAX_JSON_DEPTH) -> None:
    """Pre-scan the JSON byte string for max nesting depth. Raise
    ValueError if the max-nesting peak exceeds ``max_depth``. Honors
    string boundaries so `{` inside a string literal does not count.

    Doing this BEFORE json.loads avoids the cost of full parsing for
    obviously-malicious inputs and avoids tripping CPython's
    recursion limit on the critical decode path."""
    depth = 0
    in_string = False
    escape = False
    for c in data:
        if escape:
            escape = False
            continue
        if in_string:
            if c == 0x5c:  # backslash
                escape = True
                continue
            if c == 0x22:  # closing quote
                in_string = False
            continue
        if c == 0x22:  # opening quote
            in_string = True
            continue
        if c == 0x7b or c == 0x5b:  # { or [
            depth += 1
            if depth > max_depth:
                raise ValueError(
                    f"JSON nesting too deep (>{max_depth}) — frame rejected"
                )
        elif c == 0x7d or c == 0x5d:  # } or ]
            if depth > 0:
                depth -= 1


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
    if not isinstance(msg, dict):
        raise ValueError("message must be a JSON object")
    try:
        encoded = json.dumps(
            msg,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("message is not finite JSON") from exc
    if len(encoded) > MAX_FRAME:
        raise ValueError(f"encoded message too large: {len(encoded)} > {MAX_FRAME}")
    return encoded


def _reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON field: {key}")
        out[key] = value
    return out


def _parse_finite_float(raw: str) -> float:
    value = float(raw)
    if not math.isfinite(value):
        raise ValueError("non-finite JSON number")
    return value


def _reject_json_constant(raw: str) -> None:
    raise ValueError(f"non-standard JSON constant: {raw}")


def decode_msg(data: bytes) -> dict[str, Any]:
    # v0.20.7 (security audit M7 + L3): bound JSON nesting before
    # json.loads runs, then enforce that the top-level value is an
    # object. Old behavior accepted JSON null / array / string and
    # downstream `msg.get("t")` raised AttributeError or TypeError,
    # which the recv loop swallowed and closed the channel —
    # functional but log-noisy and cheap to drive.
    if not isinstance(data, bytes):
        raise ValueError("frame payload must be bytes")
    if len(data) > MAX_FRAME:
        raise ValueError(f"frame too large: {len(data)} > {MAX_FRAME}")
    _check_json_depth(data)
    try:
        out = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_object,
            parse_float=_parse_finite_float,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise ValueError("frame is not valid JSON") from exc
    if not isinstance(out, dict):
        raise ValueError("frame must be a JSON object")
    return out

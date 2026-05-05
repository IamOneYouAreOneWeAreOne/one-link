"""One_link daemon.

Runs two asyncio servers:
  1. Peer server  — accepts connections from other One_link nodes on the LAN
                    on a TCP port advertised via mDNS.
  2. Control server — local-only (127.0.0.1) socket for the CLI to issue
                      commands (send / send-file / list-peers / tail).

For v0 the peer protocol is connection-per-action: initiator opens a TCP
connection, runs the encrypted handshake, sends one or more messages, gets
ACK, closes. Persistent peering comes later.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
import socket
from dataclasses import dataclass
from pathlib import Path

import blake3

from one_link import channel as ch
from one_link.discovery import Discovery, Peer
from one_link.identity import Identity, load_or_create
from one_link.paths import (
    data_dir,
    inbox_dir,
    message_log_path,
)
from one_link.wire import decode_msg, encode_msg, make_msg

# Forward import to avoid hard dep when server.py loads daemon.py
try:
    from one_link.server import UIServer  # noqa: F401
except Exception:
    UIServer = None  # type: ignore[assignment]

log = logging.getLogger("one_link.daemon")

CONTROL_PORT_FILE = "control.port"
PEER_PORT_FILE = "peer.port"
CHUNK_SIZE = 256 * 1024  # 256 KiB plaintext per FILE_CHUNK


def _control_port_path() -> Path:
    return data_dir() / CONTROL_PORT_FILE


def _peer_port_path() -> Path:
    return data_dir() / PEER_PORT_FILE


@dataclass
class IncomingFile:
    name: str
    size: int
    blob_hex: str
    out_path: Path
    handle: object
    received: int = 0
    hasher: object = None


class Daemon:
    def __init__(self, me: Identity):
        self.me = me
        self.discovery: Discovery | None = None
        self._peer_server: asyncio.base_events.Server | None = None
        self._control_server: asyncio.base_events.Server | None = None
        self._tail_subs: set[asyncio.StreamWriter] = set()
        self._incoming_files: dict[str, IncomingFile] = {}
        self.ui_server = None  # one_link.server.UIServer | None

    # ─── peer (encrypted) side ──────────────────────────────────────────
    async def _handle_peer(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        addr = writer.get_extra_info("peername")
        try:
            channel = await ch.respond(reader, writer, self.me)
        except Exception as e:
            log.warning("handshake failed from %s: %s", addr, e)
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()
            return
        log.info("peer connected: %s @ %s", channel.peer_short_id, addr)
        try:
            while True:
                try:
                    plaintext = await channel.recv()
                except asyncio.IncompleteReadError:
                    break
                msg = decode_msg(plaintext)
                await self._on_peer_message(channel, msg)
        except Exception as e:
            log.warning("peer loop error (%s): %s", channel.peer_short_id, e)
        finally:
            await channel.close()
            log.info("peer disconnected: %s", channel.peer_short_id)

    async def _on_peer_message(self, channel: ch.Channel, msg: dict) -> None:
        t = msg.get("t")
        if t == "TEXT":
            self._append_log({**msg, "dir": "in", "peer": channel.peer_short_id})
            self._broadcast_tail({**msg, "dir": "in", "peer": channel.peer_short_id})
            await channel.send(
                encode_msg(make_msg("ACK", self.me.short_id, of=msg["id"]))
            )
        elif t == "FILE_OFFER":
            blob = msg["blob"]
            name = Path(msg["name"]).name
            out_path = inbox_dir() / f"{blob[:8]}_{name}"
            handle = open(out_path, "wb")
            self._incoming_files[blob] = IncomingFile(
                name=name,
                size=int(msg["size"]),
                blob_hex=blob,
                out_path=out_path,
                handle=handle,
                hasher=blake3.blake3(),
            )
            log.info(
                "file offer: %s (%d bytes) blob=%s from %s",
                name,
                msg["size"],
                blob[:8],
                channel.peer_short_id,
            )
            await channel.send(
                encode_msg(make_msg("ACK", self.me.short_id, of=msg["id"]))
            )
        elif t == "FILE_CHUNK":
            blob = msg["blob"]
            f = self._incoming_files.get(blob)
            if not f:
                log.warning("FILE_CHUNK with no offer: %s", blob[:8])
                return
            data = base64.b64decode(msg["data"])
            f.handle.write(data)
            f.hasher.update(data)
            f.received += len(data)
            if msg.get("eof"):
                f.handle.close()
                got = f.hasher.hexdigest()
                ok = got == f.blob_hex
                done = {
                    "t": "FILE_DONE",
                    "id": msg["id"],
                    "ts": msg["ts"],
                    "from": msg["from"],
                    "name": f.name,
                    "size": f.size,
                    "path": str(f.out_path),
                    "blob": f.blob_hex,
                    "ok": ok,
                    "dir": "in",
                    "peer": channel.peer_short_id,
                }
                self._append_log(done)
                self._broadcast_tail(done)
                self._incoming_files.pop(blob, None)
                log.info(
                    "file done: %s ok=%s -> %s",
                    f.name,
                    ok,
                    f.out_path,
                )
            await channel.send(
                encode_msg(make_msg("ACK", self.me.short_id, of=msg["id"]))
            )
        elif t == "PING":
            await channel.send(encode_msg(make_msg("PONG", self.me.short_id)))

    # ─── outbound to a peer ─────────────────────────────────────────────
    async def send_to(self, peer: Peer, msgs: list[dict]) -> list[dict]:
        reader, writer = await asyncio.open_connection(peer.address, peer.port)
        try:
            channel = await ch.initiate(reader, writer, self.me)
            if channel.peer_short_id != peer.short_id:
                raise RuntimeError(
                    f"peer fingerprint mismatch: expected {peer.short_id}, "
                    f"got {channel.peer_short_id}"
                )
            results: list[dict] = []
            for m in msgs:
                await channel.send(encode_msg(m))
                ack = decode_msg(await channel.recv())
                results.append(ack)
                self._append_log({**m, "dir": "out", "peer": peer.short_id})
            await channel.close()
            return results
        except Exception:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()
            raise

    async def send_text(self, peer: Peer, body: str) -> dict:
        m = make_msg("TEXT", self.me.short_id, body=body)
        acks = await self.send_to(peer, [m])
        return {"sent": m, "ack": acks[0] if acks else None}

    async def send_file(self, peer: Peer, path: Path) -> dict:
        size = path.stat().st_size
        h = blake3.blake3()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        blob_hex = h.hexdigest()

        offer = make_msg(
            "FILE_OFFER",
            self.me.short_id,
            name=path.name,
            size=size,
            blob=blob_hex,
        )

        reader, writer = await asyncio.open_connection(peer.address, peer.port)
        try:
            channel = await ch.initiate(reader, writer, self.me)
            if channel.peer_short_id != peer.short_id:
                raise RuntimeError(
                    f"peer fingerprint mismatch: expected {peer.short_id}, "
                    f"got {channel.peer_short_id}"
                )

            await channel.send(encode_msg(offer))
            decode_msg(await channel.recv())  # offer ACK
            self._append_log({**offer, "dir": "out", "peer": peer.short_id})

            chunks_sent = 0
            with open(path, "rb") as f:
                seq = 0
                prev = f.read(CHUNK_SIZE)
                while prev:
                    cur = f.read(CHUNK_SIZE)
                    eof = not cur
                    chunk_msg = make_msg(
                        "FILE_CHUNK",
                        self.me.short_id,
                        blob=blob_hex,
                        seq=seq,
                        data=base64.b64encode(prev).decode("ascii"),
                        eof=eof,
                    )
                    await channel.send(encode_msg(chunk_msg))
                    decode_msg(await channel.recv())
                    chunks_sent += 1
                    prev = cur
                    seq += 1

            if chunks_sent == 0:
                empty = make_msg(
                    "FILE_CHUNK",
                    self.me.short_id,
                    blob=blob_hex,
                    seq=0,
                    data="",
                    eof=True,
                )
                await channel.send(encode_msg(empty))
                decode_msg(await channel.recv())
                chunks_sent = 1

            await channel.close()
            return {
                "offer": offer,
                "chunks": chunks_sent,
                "blob": blob_hex,
                "size": size,
            }
        except Exception:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()
            raise

    # ─── control plane (local CLI) ──────────────────────────────────────
    async def _handle_control(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            line = await reader.readline()
            if not line:
                return
            try:
                req = json.loads(line.decode("utf-8"))
            except Exception as e:
                await self._reply(writer, {"ok": False, "error": f"bad request: {e}"})
                return
            cmd = req.get("cmd")
            if cmd == "peers":
                peers = [
                    {
                        "short_id": p.short_id,
                        "hostname": p.hostname,
                        "address": p.address,
                        "port": p.port,
                    }
                    for p in (self.discovery.registry.list() if self.discovery else [])
                ]
                me = {
                    "short_id": self.me.short_id,
                    "hostname": self.me.hostname,
                }
                await self._reply(writer, {"ok": True, "me": me, "peers": peers})
            elif cmd == "send":
                peer = self._resolve_peer(req["peer"])
                if not peer:
                    await self._reply(
                        writer, {"ok": False, "error": f"no peer {req['peer']!r}"}
                    )
                    return
                result = await self.send_text(peer, req["body"])
                await self._reply(writer, {"ok": True, "result": result})
            elif cmd == "send_file":
                peer = self._resolve_peer(req["peer"])
                if not peer:
                    await self._reply(
                        writer, {"ok": False, "error": f"no peer {req['peer']!r}"}
                    )
                    return
                p = Path(req["path"])
                if not p.is_file():
                    await self._reply(writer, {"ok": False, "error": f"no file: {p}"})
                    return
                result = await self.send_file(peer, p)
                await self._reply(writer, {"ok": True, "result": result})
            elif cmd == "tail":
                self._tail_subs.add(writer)
                await self._reply(writer, {"ok": True, "tailing": True})
                try:
                    while not writer.is_closing():
                        await asyncio.sleep(60)
                finally:
                    self._tail_subs.discard(writer)
                return  # stay open
            else:
                await self._reply(writer, {"ok": False, "error": f"unknown cmd: {cmd}"})
        except Exception as e:
            log.exception("control handler error: %s", e)
            with contextlib.suppress(Exception):
                await self._reply(writer, {"ok": False, "error": str(e)})
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def _reply(self, writer: asyncio.StreamWriter, obj: dict) -> None:
        writer.write((json.dumps(obj) + "\n").encode("utf-8"))
        await writer.drain()

    def _resolve_peer(self, needle: str) -> Peer | None:
        return self.discovery.registry.find(needle) if self.discovery else None

    def _broadcast_tail(self, msg: dict) -> None:
        line = (json.dumps({"event": "msg", "msg": msg}) + "\n").encode("utf-8")
        dead: list[asyncio.StreamWriter] = []
        for w in list(self._tail_subs):
            try:
                w.write(line)
            except Exception:
                dead.append(w)
        for w in dead:
            self._tail_subs.discard(w)
        # Push to UI subscribers too
        if self.ui_server is not None:
            try:
                self.ui_server.broadcast({"type": "msg", "msg": msg})
            except Exception:
                pass

    def _append_log(self, entry: dict) -> None:
        path = message_log_path()
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    # ─── lifecycle ──────────────────────────────────────────────────────
    async def start(self) -> None:
        self._peer_server = await asyncio.start_server(
            self._handle_peer, host="0.0.0.0", port=0
        )
        peer_port = self._peer_server.sockets[0].getsockname()[1]
        _peer_port_path().write_text(str(peer_port))

        self._control_server = await asyncio.start_server(
            self._handle_control, host="127.0.0.1", port=0
        )
        ctrl_port = self._control_server.sockets[0].getsockname()[1]
        _control_port_path().write_text(str(ctrl_port))

        self.discovery = Discovery(
            short_id=self.me.short_id,
            hostname=self.me.hostname,
            port=peer_port,
            ed_pub_hex=self.me.public_bytes.hex(),
        )
        await self.discovery.start()

        # Hook the registry to broadcast peer changes to UI clients
        def _on_peer_change():
            if self.ui_server is not None:
                try:
                    peers = [
                        {
                            "short_id": p.short_id,
                            "hostname": p.hostname,
                            "address": p.address,
                            "port": p.port,
                            "ed_pub_hex": p.ed_pub_hex,
                            "online": True,
                        }
                        for p in self.discovery.registry.list()
                    ]
                    self.ui_server.broadcast({"type": "peers", "peers": peers})
                except Exception:
                    pass

        self.discovery.registry.on_change = _on_peer_change

        # Start UI server if available
        if UIServer is not None:
            try:
                self.ui_server = UIServer(self)
                ui_port = await self.ui_server.start()
            except Exception as e:
                log.warning("UI server failed to start: %s", e)
                self.ui_server = None
                ui_port = 0
        else:
            ui_port = 0

        log.info(
            "One_link daemon up — id=%s host=%s peer=:%d ctrl=:%d ui=:%d",
            self.me.short_id,
            self.me.hostname,
            peer_port,
            ctrl_port,
            ui_port,
        )

    async def serve_forever(self) -> None:
        assert self._peer_server and self._control_server
        await asyncio.gather(
            self._peer_server.serve_forever(),
            self._control_server.serve_forever(),
        )

    async def stop(self) -> None:
        if self.ui_server is not None:
            try:
                await self.ui_server.stop()
            except Exception:
                pass
        if self.discovery:
            await self.discovery.stop()
        if self._peer_server:
            self._peer_server.close()
            await self._peer_server.wait_closed()
        if self._control_server:
            self._control_server.close()
            await self._control_server.wait_closed()


async def run() -> None:
    me = load_or_create()
    daemon = Daemon(me)
    await daemon.start()
    try:
        await daemon.serve_forever()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await daemon.stop()


def read_control_port() -> int:
    p = _control_port_path()
    if not p.exists():
        raise RuntimeError("daemon not running (no control.port file)")
    return int(p.read_text().strip())


def is_daemon_alive(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()

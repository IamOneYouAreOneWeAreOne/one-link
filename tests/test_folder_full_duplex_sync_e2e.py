"""Full-duplex bidirectional folder sync over a SINGLE connection.

2026-05-27. The marquee proof that push_folder_to_peer(bidirectional=
True) exchanges blobs in BOTH directions within one dial/handshake/
ratchet cycle:

  - forward-only : A has a file, B doesn't  → B receives it
  - reverse-only : B has a file, A doesn't  → A receives it
  - both-at-once : A and B each have a DIFFERENT file in the same
                   shared folder → after ONE sync, each holds both
                   files byte-identical

The both-at-once case is the whole point: it cannot pass unless the
initiator's loop is truly full-duplex (serves its blobs AND receives
the peer's reverse manifest + blobs on the same channel).

Pairs via API (not mDNS), so it's deterministic on Windows.
"""
from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

import aiohttp
import pytest

from tests.harness import daemon_pair

pytestmark = pytest.mark.timeout(180)


def _read(home: Path, name: str) -> str:
    return (home / "data" / name).read_text(encoding="utf-8").strip()


async def _pair(s, base_a, tok_a, base_b, tok_b, p):
    async with s.get(f"{base_a}/api/peers?include_unpaired=1",
                     headers={"Authorization": f"Bearer {tok_a}"}) as r:
        ja = await r.json()
    fp_b = next((pp["fingerprint"] for pp in ja["peers"]
                 if pp["short_id"] == p.b.short_id), None)
    async with s.get(f"{base_b}/api/peers?include_unpaired=1",
                     headers={"Authorization": f"Bearer {tok_b}"}) as r:
        jb = await r.json()
    fp_a = next((pp["fingerprint"] for pp in jb["peers"]
                 if pp["short_id"] == p.a.short_id), None)
    assert fp_a and fp_b
    async with s.post(f"{base_a}/api/peers/{fp_b}/pair",
                      headers={"Authorization": f"Bearer {tok_a}"}, json={}) as r:
        assert (await r.json())["ok"]
    await asyncio.sleep(0.4)
    async with s.post(f"{base_a}/api/peers/{fp_b}/pair-confirm",
                      headers={"Authorization": f"Bearer {tok_a}"}, json={}) as r:
        assert (await r.json())["ok"]
    async with s.post(f"{base_b}/api/peers/{fp_a}/pair-confirm",
                      headers={"Authorization": f"Bearer {tok_b}"}, json={}) as r:
        assert (await r.json())["ok"]
    deadline = time.time() + 8
    while time.time() < deadline:
        async with s.get(f"{base_a}/api/peers",
                         headers={"Authorization": f"Bearer {tok_a}"}) as r:
            ja2 = await r.json()
        async with s.get(f"{base_b}/api/peers",
                         headers={"Authorization": f"Bearer {tok_b}"}) as r:
            jb2 = await r.json()
        av = next((pp for pp in ja2["peers"] if pp["fingerprint"] == fp_b), None)
        bv = next((pp for pp in jb2["peers"] if pp["fingerprint"] == fp_a), None)
        if av and bv and av["trust"] == "pinned" and bv["trust"] == "pinned":
            return fp_a, fp_b
        await asyncio.sleep(0.2)
    raise RuntimeError("pairing did not pin")


async def _mk_folder(s, base, tok, name, path, shared_with):
    path.mkdir(parents=True, exist_ok=True)
    async with s.post(f"{base}/api/folders",
                      headers={"Authorization": f"Bearer {tok}"},
                      json={"name": name, "local_path": str(path),
                            "shared_with": shared_with}) as r:
        assert r.status == 200, await r.text()


async def _sync(s, base, tok, name):
    async with s.post(f"{base}/api/folders/{name}/sync",
                      headers={"Authorization": f"Bearer {tok}"}, json={}) as r:
        return await r.json()


async def _wait_file(path: Path, payload: bytes, timeout=30) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.is_file() and path.read_bytes() == payload:
            return True
        await asyncio.sleep(0.4)
    return path.is_file() and path.read_bytes() == payload


@pytest.mark.asyncio
async def test_full_duplex_both_directions_one_connection():
    """A and B each drop a DIFFERENT file into the same shared folder.
    A single bidirectional sync from A must leave BOTH sides holding
    BOTH files — proving the initiator served its blob AND pulled the
    peer's blob on one channel."""
    with daemon_pair() as p:
        tok_a = _read(p.a.home, "ui.token")
        tok_b = _read(p.b.home, "ui.token")
        base_a = f"http://127.0.0.1:{int(_read(p.a.home, 'server.port'))}"
        base_b = f"http://127.0.0.1:{int(_read(p.b.home, 'server.port'))}"
        async with aiohttp.ClientSession() as s:
            fp_a, fp_b = await _pair(s, base_a, tok_a, base_b, tok_b, p)
            local_a = p.tmp / "fd_a"
            local_b = p.tmp / "fd_b"
            await _mk_folder(s, base_a, tok_a, "fd", local_a, [fp_b])
            await _mk_folder(s, base_b, tok_b, "fd", local_b, [fp_a])

            # Each side has a distinct file.
            pay_a = os.urandom(40_000)
            pay_b = os.urandom(55_000)
            (local_a / "from_a.bin").write_bytes(pay_a)
            (local_b / "from_b.bin").write_bytes(pay_b)
            await asyncio.sleep(1.5)  # let both watchers ingest

            # ONE bidirectional sync initiated by A.
            res = await _sync(s, base_a, tok_a, "fd")
            assert res["ok"], res

            # B must receive A's file AND A must receive B's file.
            got_b = await _wait_file(local_b / "from_a.bin", pay_a, timeout=30)
            got_a = await _wait_file(local_a / "from_b.bin", pay_b, timeout=30)
            if not (got_a and got_b):
                _d = Path(__file__).resolve().parents[1]
                (_d / "_fd_a.log").write_text(
                    p.a.log.read_text(encoding="utf-8", errors="replace"),
                    encoding="utf-8")
                (_d / "_fd_b.log").write_text(
                    p.b.log.read_text(encoding="utf-8", errors="replace"),
                    encoding="utf-8")
            assert got_b, "B did not receive A's file (forward direction)"
            assert got_a, (
                "A did not receive B's file (REVERSE direction) — "
                "full-duplex single-connection sync is broken"
            )


@pytest.mark.asyncio
async def test_full_duplex_forward_only():
    """Only A has a file. One bidirectional sync delivers it to B
    (degrades gracefully to the forward direction)."""
    with daemon_pair() as p:
        tok_a = _read(p.a.home, "ui.token")
        tok_b = _read(p.b.home, "ui.token")
        base_a = f"http://127.0.0.1:{int(_read(p.a.home, 'server.port'))}"
        base_b = f"http://127.0.0.1:{int(_read(p.b.home, 'server.port'))}"
        async with aiohttp.ClientSession() as s:
            fp_a, fp_b = await _pair(s, base_a, tok_a, base_b, tok_b, p)
            local_a = p.tmp / "fo_a"
            local_b = p.tmp / "fo_b"
            await _mk_folder(s, base_a, tok_a, "fo", local_a, [fp_b])
            await _mk_folder(s, base_b, tok_b, "fo", local_b, [fp_a])
            pay = os.urandom(30_000)
            (local_a / "only.bin").write_bytes(pay)
            await asyncio.sleep(1.5)
            res = await _sync(s, base_a, tok_a, "fo")
            assert res["ok"], res
            assert await _wait_file(local_b / "only.bin", pay, timeout=30)


@pytest.mark.asyncio
async def test_full_duplex_reverse_only():
    """Only B has a file. A initiates a bidirectional sync; the file
    flows in the REVERSE direction (B → A) on the same connection."""
    with daemon_pair() as p:
        tok_a = _read(p.a.home, "ui.token")
        tok_b = _read(p.b.home, "ui.token")
        base_a = f"http://127.0.0.1:{int(_read(p.a.home, 'server.port'))}"
        base_b = f"http://127.0.0.1:{int(_read(p.b.home, 'server.port'))}"
        async with aiohttp.ClientSession() as s:
            fp_a, fp_b = await _pair(s, base_a, tok_a, base_b, tok_b, p)
            local_a = p.tmp / "ro_a"
            local_b = p.tmp / "ro_b"
            await _mk_folder(s, base_a, tok_a, "ro", local_a, [fp_b])
            await _mk_folder(s, base_b, tok_b, "ro", local_b, [fp_a])
            pay = os.urandom(35_000)
            (local_b / "rev.bin").write_bytes(pay)
            await asyncio.sleep(1.5)
            # A initiates (A has nothing) — file must still arrive at A.
            res = await _sync(s, base_a, tok_a, "ro")
            assert res["ok"], res
            assert await _wait_file(local_a / "rev.bin", pay, timeout=30), (
                "A did not receive B's file via the reverse direction "
                "of a bidirectional sync A initiated"
            )

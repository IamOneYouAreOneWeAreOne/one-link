"""End-to-end folder sync between two real daemons.

Spins up a daemon pair, pairs them via SAS so trust is 'pinned', creates
a folder on A, shares it with B, drops a file in A's folder, and verifies
B's copy receives the file byte-identical.

This is the marquee test for live folder sync: it proves
the folder-sync wire protocol actually moves bytes between peers.
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


async def _pair_two_daemons(s, base_a, tok_a, base_b, tok_b, p):
    """Drive the SAS pairing dance via API so both peers end up trust=pinned."""
    # B fingerprint from A's view
    async with s.get(f"{base_a}/api/peers", headers={"Authorization": f"Bearer {tok_a}"}) as r:
        ja = await r.json()
    fp_b = next(pp["fingerprint"] for pp in ja["peers"] if pp["short_id"] == p.b.short_id)

    async with s.get(f"{base_b}/api/peers", headers={"Authorization": f"Bearer {tok_b}"}) as r:
        jb = await r.json()
    fp_a = next(pp["fingerprint"] for pp in jb["peers"] if pp["short_id"] == p.a.short_id)

    # A initiates pair
    async with s.post(
        f"{base_a}/api/peers/{fp_b}/pair",
        headers={"Authorization": f"Bearer {tok_a}"}, json={},
    ) as r:
        assert (await r.json())["ok"]
    await asyncio.sleep(0.5)

    # Both confirm
    async with s.post(
        f"{base_a}/api/peers/{fp_b}/pair-confirm",
        headers={"Authorization": f"Bearer {tok_a}"}, json={},
    ) as r:
        assert (await r.json())["ok"]
    async with s.post(
        f"{base_b}/api/peers/{fp_a}/pair-confirm",
        headers={"Authorization": f"Bearer {tok_b}"}, json={},
    ) as r:
        assert (await r.json())["ok"]

    # Wait for both sides to be pinned
    deadline = time.time() + 8
    while time.time() < deadline:
        async with s.get(f"{base_a}/api/peers", headers={"Authorization": f"Bearer {tok_a}"}) as r:
            ja2 = await r.json()
        async with s.get(f"{base_b}/api/peers", headers={"Authorization": f"Bearer {tok_b}"}) as r:
            jb2 = await r.json()
        a_view = next(pp for pp in ja2["peers"] if pp["fingerprint"] == fp_b)
        b_view = next(pp for pp in jb2["peers"] if pp["fingerprint"] == fp_a)
        if a_view["trust"] == "pinned" and b_view["trust"] == "pinned":
            return fp_a, fp_b
        await asyncio.sleep(0.2)
    raise RuntimeError(f"pairing did not pin: A={a_view['trust']} B={b_view['trust']}")


@pytest.mark.asyncio
async def test_folder_sync_round_trip():
    """A pairs with B, A creates a folder shared with B, A drops a file.
    B's copy of the folder receives the file byte-identical."""
    with daemon_pair() as p:
        port_a = int(_read(p.a.home, "server.port"))
        port_b = int(_read(p.b.home, "server.port"))
        tok_a = _read(p.a.home, "ui.token")
        tok_b = _read(p.b.home, "ui.token")
        base_a = f"http://127.0.0.1:{port_a}"
        base_b = f"http://127.0.0.1:{port_b}"

        async with aiohttp.ClientSession() as s:
            fp_a, fp_b = await _pair_two_daemons(s, base_a, tok_a, base_b, tok_b, p)

            # Create the folder on A's side
            local_a = p.tmp / "shared_a"
            local_a.mkdir()
            local_b = p.tmp / "shared_b"
            local_b.mkdir()

            async with s.post(
                f"{base_a}/api/folders",
                headers={"Authorization": f"Bearer {tok_a}"},
                json={
                    "name": "shared", "local_path": str(local_a),
                    "shared_with": [fp_b],
                },
            ) as r:
                resp = await r.json()
            assert r.status == 200, resp

            # B opens the matching folder so it has a place to materialize
            async with s.post(
                f"{base_b}/api/folders",
                headers={"Authorization": f"Bearer {tok_b}"},
                json={
                    "name": "shared", "local_path": str(local_b),
                    "shared_with": [fp_a],
                },
            ) as r:
                resp = await r.json()
            assert r.status == 200, resp

            # Drop a file into A's folder
            payload = os.urandom(50_000)
            sample = local_a / "hello.bin"
            sample.write_bytes(payload)

            # Give the watcher a moment to ingest
            await asyncio.sleep(1.5)

            # Ask A to sync now (instead of waiting 30s)
            async with s.post(
                f"{base_a}/api/folders/shared/sync",
                headers={"Authorization": f"Bearer {tok_a}"}, json={},
            ) as r:
                sync_res = await r.json()
            assert sync_res["ok"], sync_res
            assert sync_res["results"][0]["merkle_root"]

            # Wait for B to materialize the file
            target = local_b / "hello.bin"
            deadline = time.time() + 30
            while time.time() < deadline:
                if target.is_file() and target.read_bytes() == payload:
                    break
                await asyncio.sleep(0.4)
            else:
                a_log = p.a.log.read_text(encoding="utf-8", errors="replace")[-3000:]
                b_log = p.b.log.read_text(encoding="utf-8", errors="replace")[-3000:]
                pytest.fail(
                    f"file did not arrive at {target}\n"
                    f"--- A log ---\n{a_log}\n"
                    f"--- B log ---\n{b_log}\n"
                )
            assert target.read_bytes() == payload

            async with s.post(
                f"{base_a}/api/folders/shared/sync",
                headers={"Authorization": f"Bearer {tok_a}"}, json={},
            ) as r:
                sync_res_2 = await r.json()
            assert sync_res_2["ok"], sync_res_2
            assert sync_res_2["results"][0]["wants"] == 0


@pytest.mark.asyncio
async def test_folder_sync_blocked_for_unpaired_peer():
    """Without pairing, MANIFEST_PUSH should be ignored on the receive side
    and no file ever materializes — the trust gate works."""
    with daemon_pair() as p:
        port_a = int(_read(p.a.home, "server.port"))
        port_b = int(_read(p.b.home, "server.port"))
        tok_a = _read(p.a.home, "ui.token")
        tok_b = _read(p.b.home, "ui.token")
        base_a = f"http://127.0.0.1:{port_a}"
        base_b = f"http://127.0.0.1:{port_b}"

        async with aiohttp.ClientSession() as s:
            # Get fingerprints
            async with s.get(f"{base_a}/api/peers", headers={"Authorization": f"Bearer {tok_a}"}) as r:
                ja = await r.json()
            fp_b = next(pp["fingerprint"] for pp in ja["peers"] if pp["short_id"] == p.b.short_id)
            async with s.get(f"{base_b}/api/peers", headers={"Authorization": f"Bearer {tok_b}"}) as r:
                jb = await r.json()
            fp_a = next(pp["fingerprint"] for pp in jb["peers"] if pp["short_id"] == p.a.short_id)

            # NO pairing — peers are 'pending'
            local_a = p.tmp / "shared_a"
            local_a.mkdir()
            local_b = p.tmp / "shared_b"
            local_b.mkdir()

            async with s.post(
                f"{base_a}/api/folders",
                headers={"Authorization": f"Bearer {tok_a}"},
                json={"name": "shared", "local_path": str(local_a), "shared_with": [fp_b]},
            ) as r:
                assert r.status == 200, await r.text()
            async with s.post(
                f"{base_b}/api/folders",
                headers={"Authorization": f"Bearer {tok_b}"},
                json={"name": "shared", "local_path": str(local_b), "shared_with": [fp_a]},
            ) as r:
                assert r.status == 200, await r.text()

            (local_a / "secret.bin").write_bytes(b"do not sync me")
            await asyncio.sleep(1.5)
            async with s.post(
                f"{base_a}/api/folders/shared/sync",
                headers={"Authorization": f"Bearer {tok_a}"}, json={},
            ) as r:
                res = await r.json()
            # Push should report not_pinned
            statuses = [r["status"] for r in res.get("results", [])]
            assert "not_pinned" in statuses

            # And the file does NOT show up on B
            await asyncio.sleep(1.5)
            assert not (local_b / "secret.bin").exists()

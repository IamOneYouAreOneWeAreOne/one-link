"""SAS pairing primitives."""

from __future__ import annotations

import os

import pytest

from one_link.pairing import (
    PairState,
    PairingTracker,
    compute_sas,
    format_sas,
)


def test_sas_is_six_digits():
    sas = compute_sas(os.urandom(32), os.urandom(32))
    assert len(sas) == 6
    assert sas.isdigit()


def test_sas_is_symmetric():
    """The same code must be computed regardless of argument order."""
    a, b = os.urandom(32), os.urandom(32)
    assert compute_sas(a, b) == compute_sas(b, a)


def test_sas_is_deterministic():
    a, b = os.urandom(32), os.urandom(32)
    assert compute_sas(a, b) == compute_sas(a, b)


def test_sas_different_for_different_pairs():
    a, b, c = os.urandom(32), os.urandom(32), os.urandom(32)
    assert compute_sas(a, b) != compute_sas(a, c)


def test_sas_rejects_wrong_length():
    with pytest.raises(ValueError):
        compute_sas(b"short", os.urandom(32))
    with pytest.raises(ValueError):
        compute_sas(os.urandom(32), b"shortpubkeyXXXXXXX")


def test_format_sas_groups_digits():
    assert format_sas("123456") == "123 456"
    assert format_sas("000000") == "000 000"
    assert format_sas("999999") == "999 999"


def test_format_sas_zero_pads():
    assert format_sas("42") == "000 042"


# ───────── PairingTracker ──────────────────────────────────────────────

def test_tracker_lifecycle_outgoing():
    t = PairingTracker()
    assert t.get("aa" * 32) is None
    ctx = t.begin(peer_fp="aa" * 32, sas="123456", incoming=False)
    assert ctx.state == PairState.REQUESTED
    assert ctx.sas == "123456"

    # We say match
    t.we_confirm("aa" * 32)
    assert t.get("aa" * 32).state == PairState.CONFIRMED
    assert t.get("aa" * 32).we_confirmed
    assert not t.get("aa" * 32).they_confirmed

    # They say match
    t.they_confirm("aa" * 32)
    assert t.get("aa" * 32).state == PairState.PAIRED


def test_tracker_lifecycle_incoming():
    t = PairingTracker()
    ctx = t.begin(peer_fp="aa" * 32, sas="999999", incoming=True)
    assert ctx.state == PairState.INCOMING

    # Their confirmation arrives first
    t.they_confirm("aa" * 32)
    assert t.get("aa" * 32).state == PairState.INCOMING  # still waiting on us

    # Our user clicks match
    t.we_confirm("aa" * 32)
    assert t.get("aa" * 32).state == PairState.PAIRED


def test_tracker_reject():
    t = PairingTracker()
    t.begin(peer_fp="aa" * 32, sas="123456", incoming=False)
    t.reject("aa" * 32)
    assert t.get("aa" * 32).state == PairState.REJECTED


def test_tracker_clear():
    t = PairingTracker()
    t.begin(peer_fp="aa" * 32, sas="123456", incoming=False)
    t.clear("aa" * 32)
    assert t.get("aa" * 32) is None


def test_tracker_concurrent_peers():
    t = PairingTracker()
    t.begin(peer_fp="aa" * 32, sas="111111", incoming=False)
    t.begin(peer_fp="bb" * 32, sas="222222", incoming=True)
    assert t.get("aa" * 32).state == PairState.REQUESTED
    assert t.get("bb" * 32).state == PairState.INCOMING
    assert len(t.all()) == 2


# ───────── End-to-end pairing across two daemons ──────────────────────

import asyncio
import time

import aiohttp
from tests.harness import daemon_pair


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_pairing_round_trip_pins_both_sides():
    """A initiates pair → both daemons compute the same SAS → A confirms,
    B confirms → both ends store trust='pinned'."""
    with daemon_pair() as p:
        # Read tokens
        ta = (p.a.home / "data" / "ui.token").read_text().strip()
        tb = (p.b.home / "data" / "ui.token").read_text().strip()
        port_a = int((p.a.home / "data" / "server.port").read_text().strip())
        port_b = int((p.b.home / "data" / "server.port").read_text().strip())
        base_a = f"http://127.0.0.1:{port_a}"
        base_b = f"http://127.0.0.1:{port_b}"

        async with aiohttp.ClientSession() as s:
            # Find B's fingerprint from A's view
            async with s.get(
                f"{base_a}/api/peers",
                headers={"Authorization": f"Bearer {ta}"},
            ) as r:
                jb = await r.json()
            fp_b = next(pp["fingerprint"] for pp in jb["peers"]
                        if pp["short_id"] == p.b.short_id)
            # And A's fingerprint from B's view
            async with s.get(
                f"{base_b}/api/peers",
                headers={"Authorization": f"Bearer {tb}"},
            ) as r:
                ja = await r.json()
            fp_a = next(pp["fingerprint"] for pp in ja["peers"]
                        if pp["short_id"] == p.a.short_id)

            # Both sides compute SAS — must be equal
            async with s.get(
                f"{base_a}/api/peers/{fp_b}/sas",
                headers={"Authorization": f"Bearer {ta}"},
            ) as r:
                sas_a = (await r.json())["sas"]
            async with s.get(
                f"{base_b}/api/peers/{fp_a}/sas",
                headers={"Authorization": f"Bearer {tb}"},
            ) as r:
                sas_b = (await r.json())["sas"]
            assert sas_a == sas_b, f"SAS mismatch: A={sas_a!r} B={sas_b!r}"

            # A initiates pairing with B
            async with s.post(
                f"{base_a}/api/peers/{fp_b}/pair",
                headers={"Authorization": f"Bearer {ta}"},
                json={},
            ) as r:
                init = await r.json()
            assert init["ok"] and init["sas"] == sas_a

            # Give the PAIR_REQUEST a moment to land at B
            await asyncio.sleep(0.5)

            # Both sides confirm
            async with s.post(
                f"{base_a}/api/peers/{fp_b}/pair-confirm",
                headers={"Authorization": f"Bearer {ta}"},
                json={},
            ) as r:
                ca = await r.json()
            async with s.post(
                f"{base_b}/api/peers/{fp_a}/pair-confirm",
                headers={"Authorization": f"Bearer {tb}"},
                json={},
            ) as r:
                cb = await r.json()
            assert ca["ok"] and cb["ok"]

            # Wait for the second-leg PAIR_CONFIRM to propagate
            deadline = time.time() + 5
            both_pinned = False
            while time.time() < deadline:
                async with s.get(
                    f"{base_a}/api/peers",
                    headers={"Authorization": f"Bearer {ta}"},
                ) as r:
                    ja2 = await r.json()
                async with s.get(
                    f"{base_b}/api/peers",
                    headers={"Authorization": f"Bearer {tb}"},
                ) as r:
                    jb2 = await r.json()
                a_view = next(pp for pp in ja2["peers"] if pp["fingerprint"] == fp_b)
                b_view = next(pp for pp in jb2["peers"] if pp["fingerprint"] == fp_a)
                if a_view["trust"] == "pinned" and b_view["trust"] == "pinned":
                    both_pinned = True
                    break
                await asyncio.sleep(0.2)
            if not both_pinned:
                a_log = (p.a.log).read_text(encoding="utf-8", errors="replace")[-3000:]
                b_log = (p.b.log).read_text(encoding="utf-8", errors="replace")[-3000:]
                pytest.fail(
                    f"trust = ({a_view['trust']}, {b_view['trust']})\n"
                    f"--- A log ---\n{a_log}\n"
                    f"--- B log ---\n{b_log}\n"
                )


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_pair_reject_blocks_outbound():
    """If user rejects the SAS (suspected MITM), the peer is marked
    rejected and outbound to them refuses."""
    with daemon_pair() as p:
        ta = (p.a.home / "data" / "ui.token").read_text().strip()
        port_a = int((p.a.home / "data" / "server.port").read_text().strip())
        base_a = f"http://127.0.0.1:{port_a}"

        async with aiohttp.ClientSession() as s:
            async with s.get(
                f"{base_a}/api/peers",
                headers={"Authorization": f"Bearer {ta}"},
            ) as r:
                jb = await r.json()
            fp_b = next(pp["fingerprint"] for pp in jb["peers"]
                        if pp["short_id"] == p.b.short_id)

            async with s.post(
                f"{base_a}/api/peers/{fp_b}/pair-reject",
                headers={"Authorization": f"Bearer {ta}"},
                json={},
            ) as r:
                rj = await r.json()
            assert rj["ok"]

            # Now sending should fail with 'rejected'
            async with s.post(
                f"{base_a}/api/send",
                headers={"Authorization": f"Bearer {ta}"},
                json={"peer": p.b.short_id, "body": "hi"},
            ) as r:
                assert r.status >= 400
                err = await r.json()
                assert "rejected" in err["error"].lower()

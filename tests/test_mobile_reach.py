from __future__ import annotations

import pytest

from one_link.mobile_reach import (
    MIN_PHONE_CHUNK_BRIDGE_BYTES,
    MIN_PHONE_COURIER_BYTES,
    mobile_storage_budget_from_env,
    plan_mobile_reach,
)
from one_link.peer_rtc import BrowserPeer


class DummyChannel:
    pass


def test_mobile_reach_promotes_paired_phone_to_bridge_courier_and_chunk_helper():
    peer = BrowserPeer(
        fingerprint="phone-1",
        pubkey_bytes=b"1" * 32,
        control_dc=DummyChannel(),
        bulk_dc=DummyChannel(),
        paired_ms=1000,
    )

    summary = plan_mobile_reach(
        [peer],
        storage_budget_bytes=MIN_PHONE_CHUNK_BRIDGE_BYTES,
        now_ms=2000,
    )

    assert summary["connected"] == 1
    assert summary["paired"] == 1
    assert summary["control_bridges"] == 1
    assert summary["chunk_bridges"] == 1
    assert summary["couriers"] == 1
    plan = summary["plans"][0]
    assert "route_token_exchange" in plan["route_hints"]
    assert "browser_peer_bulk_datachannel" in plan["route_hints"]
    assert "phone_courier" in plan["route_hints"]


def test_mobile_reach_storage_budget_blocks_bulk_modes_without_blocking_pairing():
    peer = BrowserPeer(
        fingerprint="phone-2",
        pubkey_bytes=b"2" * 32,
        control_dc=DummyChannel(),
        bulk_dc=DummyChannel(),
        paired_ms=1000,
    )

    summary = plan_mobile_reach(
        [peer],
        storage_budget_bytes=MIN_PHONE_COURIER_BYTES - 1,
        now_ms=2000,
    )

    assert summary["control_bridges"] == 1
    assert summary["chunk_bridges"] == 0
    assert summary["couriers"] == 0
    assert summary["plans"][0]["reason"] == "mobile storage budget is too small for courier mode"


def test_mobile_reach_unpaired_phone_only_gets_pairing_action():
    peer = BrowserPeer(
        fingerprint="phone-3",
        pubkey_bytes=b"3" * 32,
        control_dc=DummyChannel(),
        bulk_dc=DummyChannel(),
        paired_ms=None,
    )

    summary = plan_mobile_reach([peer], storage_budget_bytes=MIN_PHONE_CHUNK_BRIDGE_BYTES)

    assert summary["paired"] == 0
    assert summary["control_bridges"] == 0
    assert summary["plans"][0]["actions"] == ["finish_phone_pairing"]


def test_mobile_storage_budget_env_is_bounded_and_validated():
    assert mobile_storage_budget_from_env({"ONE_LINK_PHONE_STORAGE_BUDGET_BYTES": "4096"}) == 4096
    assert mobile_storage_budget_from_env({"ONE_LINK_PHONE_STORAGE_BUDGET_BYTES": str(99 * 1024**3)}) == 8 * 1024**3
    with pytest.raises(ValueError, match="integer"):
        mobile_storage_budget_from_env({"ONE_LINK_PHONE_STORAGE_BUDGET_BYTES": "nope"})
    with pytest.raises(ValueError, match="non-negative"):
        mobile_storage_budget_from_env({"ONE_LINK_PHONE_STORAGE_BUDGET_BYTES": "-1"})

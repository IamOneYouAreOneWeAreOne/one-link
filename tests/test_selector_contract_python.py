"""Python-side tests for F4 contract verification.

These exercise selector_native.verify_contract (the Python helper that
matches the Rust core's ol_selector::Decision::verify_contract).
"""

from __future__ import annotations

import pytest

from one_link import selector_native


def _ok_decision() -> dict:
    """A reasonable, contract-passing baseline decision."""
    return {
        "transport": "quic_stream",
        "path": "classical",
        "onion_hops": 3,
        "cover_traffic": True,
        "batch_decision": "emit_now",
        "anchor_lay": False,
        "predictor_warm": False,
    }


def test_normal_mode_no_violations() -> None:
    d = _ok_decision()
    assert selector_native.verify_contract(d, "normal") == []
    # Even a 1-hop / no-cover / batched / relay decision is fine for normal.
    d2 = {
        **d,
        "onion_hops": 1,
        "cover_traffic": False,
        "batch_decision": "batch",
        "transport": "relay",
    }
    assert selector_native.verify_contract(d2, "normal") == []


def test_paranoid_requires_hops_and_cover() -> None:
    bad = {**_ok_decision(), "onion_hops": 1, "cover_traffic": False}
    v = selector_native.verify_contract(bad, "paranoid")
    assert "paranoid_under_hops" in v
    assert "paranoid_no_cover" in v


def test_paranoid_passes_with_good_decision() -> None:
    good = {**_ok_decision(), "onion_hops": 5, "cover_traffic": True}
    assert selector_native.verify_contract(good, "paranoid") == []


def test_battery_save_blocks_cover() -> None:
    bad = {**_ok_decision(), "cover_traffic": True}
    v = selector_native.verify_contract(bad, "battery_save")
    assert v == ["battery_save_cover"]


def test_battery_save_passes_with_cover_off() -> None:
    good = {**_ok_decision(), "cover_traffic": False}
    assert selector_native.verify_contract(good, "battery_save") == []


def test_latency_strict_blocks_batch() -> None:
    bad = {**_ok_decision(), "batch_decision": "batch"}
    v = selector_native.verify_contract(bad, "latency_strict")
    assert "latency_strict_batched" in v


def test_latency_strict_blocks_relay() -> None:
    bad = {**_ok_decision(), "transport": "relay"}
    v = selector_native.verify_contract(bad, "latency_strict")
    assert "latency_strict_relay" in v


def test_latency_strict_passes_when_clean() -> None:
    good = {
        **_ok_decision(),
        "batch_decision": "emit_now",
        "transport": "quic_stream",
    }
    assert selector_native.verify_contract(good, "latency_strict") == []


def test_unknown_mode_defaults_to_normal() -> None:
    # Garbage mode label should not raise; defaults to "normal" (no checks).
    d = {**_ok_decision(), "onion_hops": 1, "cover_traffic": False}
    assert selector_native.verify_contract(d, "supercritical") == []


# ---------- Cross-check against the actual SmartRules output ----------


pytestmark_native = pytest.mark.skipif(
    not selector_native.HAS_NATIVE,
    reason="one_link_native.selector not installed",
)


@pytestmark_native
def test_smartrules_paranoid_always_passes_contract() -> None:
    s = selector_native.smart_rules()
    for kind in ("TEXT", "FILE_OFFER", "FILE_CHUNK", "PING", "ACK"):
        for peer in ("pinned", "pending", "rejected"):
            for size in (100, 5_000, 100_000, 5_000_000):
                d = s.decide(
                    kind=kind, size=size, peer=peer, user_mode="paranoid",
                )
                v = selector_native.verify_contract(d, "paranoid")
                assert v == [], (
                    f"paranoid contract violation: kind={kind} peer={peer} "
                    f"size={size} -> {d} (violations={v})"
                )


@pytestmark_native
def test_smartrules_battery_save_always_passes_contract() -> None:
    s = selector_native.smart_rules()
    for kind in ("TEXT", "FILE_OFFER", "PING"):
        for peer in ("pinned", "pending", "rejected"):
            for size in (100, 5_000, 100_000):
                d = s.decide(
                    kind=kind, size=size, peer=peer, user_mode="battery_save",
                )
                v = selector_native.verify_contract(d, "battery_save")
                assert v == [], (
                    f"battery_save contract violation: kind={kind} peer={peer} "
                    f"size={size} -> {d} (violations={v})"
                )


@pytestmark_native
def test_smartrules_latency_strict_always_passes_contract() -> None:
    s = selector_native.smart_rules()
    for kind in ("TEXT", "FILE_OFFER", "FILE_CHUNK", "PING"):
        for peer in ("pinned", "pending", "rejected"):
            for size in (100, 1_000, 5_000, 100_000):
                for urgency in ("foreground", "background"):
                    for radio in ("active", "short_drx", "long_drx"):
                        d = s.decide(
                            kind=kind, size=size, peer=peer,
                            user_mode="latency_strict",
                            urgency=urgency,
                            radio_state=radio,
                        )
                        v = selector_native.verify_contract(d, "latency_strict")
                        assert v == [], (
                            f"latency_strict violation: kind={kind} peer={peer} "
                            f"size={size} urgency={urgency} radio={radio} "
                            f"-> {d} (violations={v})"
                        )

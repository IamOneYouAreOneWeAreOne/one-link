"""Tests for Phase H — UnifiedMin selector (Python surface).

Exercises:
  - Construction (default + custom weights)
  - decide() returns a contract-respecting Decision dict
  - F4 invariant across modes (cross-check with verify_contract)
  - Determinism + same-decision-from-same-context
  - Weight tuning affects output
  - Parity-of-surface with SmartRules
"""

from __future__ import annotations

import pytest

from one_link import selector_native


pytestmark = pytest.mark.skipif(
    not selector_native.HAS_NATIVE,
    reason="one_link_native.selector not installed",
)


# ---------- Construction ----------


def test_default_construction() -> None:
    s = selector_native.unified_min()
    assert s.name() == "UnifiedMin"
    assert "UnifiedMin" in repr(s)


def test_default_weights_present() -> None:
    s = selector_native.unified_min()
    w = s.weights()
    # All 11 fields are present + finite + non-negative.
    keys = [
        "alpha_coherence", "privacy_weight", "cover_penalty", "anchor_cost",
        "batch_latency_cost", "onion_hop_cost", "relay_rtt_multiplier",
        "lambda_dynamic", "dark_base", "dark_coherence", "dark_cover",
    ]
    for k in keys:
        assert k in w, f"missing weight: {k}"
        v = w[k]
        assert isinstance(v, float)
        assert v >= 0.0


def test_custom_weights_applied() -> None:
    s = selector_native.unified_min(privacy_weight=999.0, alpha_coherence=42.0)
    w = s.weights()
    assert w["privacy_weight"] == 999.0
    assert w["alpha_coherence"] == 42.0
    # Untouched defaults preserved.
    assert w["onion_hop_cost"] > 0


# ---------- decide() basic ----------


def test_decide_returns_decision_dict() -> None:
    s = selector_native.unified_min()
    d = s.decide(kind="TEXT", size=200, peer="pinned")
    assert "transport" in d
    assert "path" in d
    assert "onion_hops" in d
    assert "cover_traffic" in d
    assert "batch_decision" in d
    assert "anchor_lay" in d
    assert "predictor_warm" in d


def test_decide_deterministic() -> None:
    s = selector_native.unified_min()
    a = s.decide(kind="FILE_CHUNK", size=100_000, peer="pinned")
    b = s.decide(kind="FILE_CHUNK", size=100_000, peer="pinned")
    assert a == b


def test_safe_default_is_full_conservative() -> None:
    s = selector_native.unified_min()
    d = s.safe_default()
    assert d["onion_hops"] == 5
    assert d["cover_traffic"] is True
    assert d["anchor_lay"] is True


# ---------- F4 contract enforcement (Phase H gate) ----------


def test_paranoid_always_passes_contract() -> None:
    s = selector_native.unified_min()
    for kind in ("TEXT", "FILE_OFFER", "PING", "ACK"):
        for peer in ("pinned", "pending", "rejected"):
            for size in (100, 5_000, 100_000):
                d = s.decide(kind=kind, size=size, peer=peer, user_mode="paranoid")
                v = selector_native.verify_contract(d, "paranoid")
                assert v == [], (
                    f"unified_min paranoid violation: kind={kind} peer={peer} "
                    f"size={size} -> {d} (violations={v})"
                )


def test_battery_save_always_passes_contract() -> None:
    s = selector_native.unified_min()
    for kind in ("TEXT", "FILE_OFFER", "PING"):
        for peer in ("pinned", "pending", "rejected"):
            for size in (100, 5_000, 100_000):
                d = s.decide(kind=kind, size=size, peer=peer, user_mode="battery_save")
                v = selector_native.verify_contract(d, "battery_save")
                assert v == [], (
                    f"unified_min battery_save violation: kind={kind} peer={peer} "
                    f"size={size} -> {d} (violations={v})"
                )


def test_latency_strict_always_passes_contract() -> None:
    s = selector_native.unified_min()
    for kind in ("TEXT", "FILE_OFFER", "PING"):
        for peer in ("pinned", "pending", "rejected"):
            for size in (100, 5_000, 100_000):
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
                            f"unified_min latency_strict violation: kind={kind} "
                            f"peer={peer} size={size} urgency={urgency} "
                            f"radio={radio} -> {d} (violations={v})"
                        )


# ---------- Weight tuning matters ----------


def test_high_privacy_weight_forces_cover() -> None:
    # With astronomical privacy_weight, the optimum picks cover=True
    # for any mode that allows it. battery_save forbids cover by
    # contract regardless of weight; everything else allows it.
    s = selector_native.unified_min(privacy_weight=1e6, cover_penalty=1e6)
    for mode in ("normal", "paranoid", "latency_strict"):
        d = s.decide(kind="TEXT", size=200, peer="pinned", user_mode=mode)
        assert d["cover_traffic"] is True, f"mode={mode} got {d}"


def test_high_anchor_cost_suppresses_anchoring() -> None:
    # With anchor_cost = HUGE, the energy comparison should always
    # prefer no-anchor when nothing else forces it. observed_loss is
    # high enough that without the heavy penalty the default would
    # anchor, so this is a clean direction test.
    s = selector_native.unified_min(anchor_cost=1e6)
    d = s.decide(
        kind="TEXT", size=200, peer="pinned",
        observed_loss=0.04,  # below 0.05 (no forced anchor) but >0
        user_mode="normal",
    )
    # With astronomical anchor cost, no-anchor wins energy comparison.
    assert d["anchor_lay"] is False


def test_high_onion_hop_cost_picks_lower_hops_when_allowed() -> None:
    # When the contract allows it (normal mode + non-stranger peer),
    # cranking onion_hop_cost should bias toward fewer hops.
    s = selector_native.unified_min(onion_hop_cost=1000.0)
    d = s.decide(
        kind="TEXT", size=200, peer="pinned", user_mode="normal",
    )
    # For paired + normal mode, the selector should now pick 1-hop
    # (the cheapest option) — Normal mode has no minimum hop floor.
    assert d["onion_hops"] == 1


# ---------- Parity with SmartRules ----------


def test_unified_min_and_smart_rules_same_surface() -> None:
    sr = selector_native.smart_rules()
    um = selector_native.unified_min()
    # Same keyword surface.
    kwargs = dict(
        kind="TEXT", size=1000, peer="pinned",
        urgency="foreground", radio_state="active",
        network="wifi", user_mode="normal",
        observed_loss=0.0, pattern_strength=0.5,
    )
    d_sr = sr.decide(**kwargs)
    d_um = um.decide(**kwargs)
    # Both return decision dicts with the same keys.
    assert set(d_sr.keys()) == set(d_um.keys())


# ---------- Error paths ----------


def test_rejects_unknown_kind() -> None:
    s = selector_native.unified_min()
    with pytest.raises(ValueError):
        s.decide(kind="BOGUS", size=100, peer="pinned")


def test_rejects_invalid_loss() -> None:
    s = selector_native.unified_min()
    with pytest.raises(ValueError):
        s.decide(kind="TEXT", size=100, peer="pinned", observed_loss=1.5)

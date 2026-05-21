"""Tests for ``one_link.selector_native`` — D01 Smart-Rules selector.

Exercises every rule in the 14-rule tree from Gap 17 + the invariants
that must hold across user_mode contracts (paranoid always-private,
battery_save never-cover, etc.).
"""

from __future__ import annotations

import pytest

from one_link import selector_native

pytestmark = pytest.mark.skipif(
    not selector_native.HAS_NATIVE,
    reason="one_link_native.selector not installed; run "
    "`cd native && maturin develop --release`",
)


# ---------- Module metadata ----------


def test_module_metadata() -> None:
    assert selector_native.NATIVE_VERSION is not None


def test_smart_rules_instance() -> None:
    s = selector_native.smart_rules()
    assert s.name() == "SmartRules"
    assert "SmartRules" in repr(s)


# ---------- Transport rules ----------


def test_transport_big_file_paired_uses_quic_stream() -> None:
    s = selector_native.smart_rules()
    d = s.decide(
        kind="FILE_CHUNK",
        size=5_000_000,
        peer="pinned",
        network="wifi",
    )
    assert d["transport"] == "quic_stream"


def test_transport_stranger_uses_relay() -> None:
    s = selector_native.smart_rules()
    d = s.decide(
        kind="FILE_OFFER",
        size=100,
        peer="rejected",
        network="wifi",
    )
    assert d["transport"] == "relay"


def test_transport_cellular_uses_relay() -> None:
    s = selector_native.smart_rules()
    d = s.decide(
        kind="TEXT",
        size=100,
        peer="pinned",
        network="cellular",
    )
    assert d["transport"] == "relay"


def test_transport_small_foreground_msg_uses_datagram() -> None:
    s = selector_native.smart_rules()
    d = s.decide(
        kind="TEXT",
        size=500,
        peer="pinned",
        network="wifi",
    )
    assert d["transport"] == "quic_datagram"


# ---------- Path rules ----------


def test_path_small_msg_uses_classical() -> None:
    s = selector_native.smart_rules()
    d = s.decide(kind="TEXT", size=100, peer="pinned")
    assert d["path"] == "classical"


def test_path_big_file_uses_coherence() -> None:
    s = selector_native.smart_rules()
    d = s.decide(kind="FILE_CHUNK", size=200_000, peer="pinned")
    assert d["path"] == "coherence"


def test_path_latency_strict_uses_classical() -> None:
    s = selector_native.smart_rules()
    d = s.decide(
        kind="FILE_CHUNK",
        size=10_000,
        peer="pinned",
        user_mode="latency_strict",
    )
    assert d["path"] == "classical"


# ---------- Onion hop rules ----------


def test_onion_paranoid_uses_5_hops() -> None:
    s = selector_native.smart_rules()
    d = s.decide(kind="TEXT", size=100, peer="pinned", user_mode="paranoid")
    assert d["onion_hops"] == 5


def test_onion_stranger_uses_3_hops() -> None:
    s = selector_native.smart_rules()
    d = s.decide(kind="TEXT", size=100, peer="rejected")
    assert d["onion_hops"] == 3


def test_onion_paired_battery_save_uses_1_hop() -> None:
    s = selector_native.smart_rules()
    d = s.decide(
        kind="TEXT", size=100, peer="pinned", user_mode="battery_save"
    )
    assert d["onion_hops"] == 1


def test_onion_default_3_hop_floor_non_paired() -> None:
    s = selector_native.smart_rules()
    d = s.decide(kind="TEXT", size=100, peer="pending")
    assert d["onion_hops"] >= 3


# ---------- Cover traffic rules ----------


def test_cover_battery_save_off() -> None:
    s = selector_native.smart_rules()
    d = s.decide(kind="TEXT", size=100, peer="pinned", user_mode="battery_save")
    assert d["cover_traffic"] is False


def test_cover_paranoid_on() -> None:
    s = selector_native.smart_rules()
    d = s.decide(kind="TEXT", size=100, peer="pinned", user_mode="paranoid")
    assert d["cover_traffic"] is True


def test_cover_3hop_default_on() -> None:
    s = selector_native.smart_rules()
    d = s.decide(kind="TEXT", size=100, peer="rejected")  # stranger → 3-hop
    assert d["cover_traffic"] is True


# ---------- Batch decision rules ----------


def test_batch_foreground_chat_bypasses() -> None:
    s = selector_native.smart_rules()
    d = s.decide(
        kind="TEXT",
        size=500,
        peer="pinned",
        urgency="foreground",
        radio_state="long_drx",  # would normally batch, but msg overrides
    )
    assert d["batch_decision"] == "urgent_bypass"


def test_batch_background_long_drx_batches() -> None:
    s = selector_native.smart_rules()
    d = s.decide(
        kind="PING",
        size=64,
        peer="pinned",
        urgency="background",
        radio_state="long_drx",
    )
    assert d["batch_decision"] == "batch"


def test_batch_latency_strict_never_batches() -> None:
    s = selector_native.smart_rules()
    d = s.decide(
        kind="ACK",
        size=200,
        peer="pinned",
        urgency="background",
        radio_state="long_drx",
        user_mode="latency_strict",
    )
    assert d["batch_decision"] == "emit_now"


# ---------- Anchor rules ----------


def test_anchor_high_loss_yes() -> None:
    s = selector_native.smart_rules()
    d = s.decide(kind="TEXT", size=100, peer="pinned", observed_loss=0.1)
    assert d["anchor_lay"] is True


def test_anchor_low_loss_no() -> None:
    s = selector_native.smart_rules()
    d = s.decide(kind="TEXT", size=100, peer="pinned", observed_loss=0.01)
    assert d["anchor_lay"] is False


def test_anchor_cellular_file_yes() -> None:
    s = selector_native.smart_rules()
    d = s.decide(
        kind="FILE_CHUNK",
        size=100_000,
        peer="pinned",
        network="cellular",
    )
    assert d["anchor_lay"] is True


# ---------- Predictor warm ----------


def test_predictor_warm_at_high_pattern() -> None:
    s = selector_native.smart_rules()
    d = s.decide(kind="TEXT", size=100, peer="pinned", pattern_strength=0.8)
    assert d["predictor_warm"] is True


def test_predictor_cold_at_low_pattern() -> None:
    s = selector_native.smart_rules()
    d = s.decide(kind="TEXT", size=100, peer="pinned", pattern_strength=0.2)
    assert d["predictor_warm"] is False


# ---------- safe_default ----------


def test_safe_default_is_full_conservative() -> None:
    d = selector_native.safe_default()
    assert d["onion_hops"] == 5
    assert d["cover_traffic"] is True
    assert d["anchor_lay"] is True
    assert d["batch_decision"] == "emit_now"
    assert d["path"] == "classical"


# ---------- Error paths ----------


def test_rejects_unknown_kind() -> None:
    s = selector_native.smart_rules()
    with pytest.raises(ValueError):
        s.decide(kind="BOGUS", size=100, peer="pinned")


def test_rejects_unknown_peer_tier() -> None:
    s = selector_native.smart_rules()
    with pytest.raises(ValueError):
        s.decide(kind="TEXT", size=100, peer="bogus_tier")


def test_rejects_invalid_loss() -> None:
    s = selector_native.smart_rules()
    with pytest.raises(ValueError):
        s.decide(kind="TEXT", size=100, peer="pinned", observed_loss=1.5)


def test_rejects_invalid_pattern_strength() -> None:
    s = selector_native.smart_rules()
    with pytest.raises(ValueError):
        s.decide(kind="TEXT", size=100, peer="pinned", pattern_strength=-0.1)


# ---------- Mode contract invariants ----------


def test_invariant_paranoid_always_max_privacy() -> None:
    """Paranoid mode: 5-hop + cover on, regardless of other inputs."""
    s = selector_native.smart_rules()
    for kind, size, peer in [
        ("TEXT", 100, "pinned"),
        ("FILE_CHUNK", 5_000_000, "rejected"),
        ("ACK", 200, "pending"),
        ("PING", 64, "pinned"),
    ]:
        d = s.decide(kind=kind, size=size, peer=peer, user_mode="paranoid")
        assert d["onion_hops"] == 5, f"paranoid {kind} got {d['onion_hops']} hops"
        assert d["cover_traffic"] is True, f"paranoid {kind} cover off"


def test_invariant_battery_save_never_cover() -> None:
    """Battery save: never burn bandwidth on cover traffic."""
    s = selector_native.smart_rules()
    for kind, size, peer in [
        ("TEXT", 100, "pinned"),
        ("FILE_CHUNK", 5_000_000, "rejected"),
        ("ACK", 200, "pending"),
    ]:
        d = s.decide(kind=kind, size=size, peer=peer, user_mode="battery_save")
        assert d["cover_traffic"] is False, f"battery_save {kind} cover on"


# ---------- F3 mode-aware refinement ----------


def test_paranoid_transport_always_relay() -> None:
    s = selector_native.smart_rules()
    # Even big files through paranoid → relay path.
    d = s.decide(
        kind="FILE_CHUNK", size=10_000_000, peer="pinned", user_mode="paranoid"
    )
    assert d["transport"] == "relay"


def test_paranoid_always_anchors() -> None:
    s = selector_native.smart_rules()
    d = s.decide(
        kind="TEXT", size=100, peer="pinned", user_mode="paranoid",
        observed_loss=0.0,
    )
    assert d["anchor_lay"] is True


def test_battery_save_anchor_only_on_high_loss() -> None:
    s = selector_native.smart_rules()
    # 7% loss: battery_save would skip anchor (normal would lay it).
    d_low = s.decide(
        kind="TEXT", size=100, peer="pinned", user_mode="battery_save",
        observed_loss=0.07,
    )
    assert d_low["anchor_lay"] is False
    # 12% loss: battery_save lays anchor.
    d_high = s.decide(
        kind="TEXT", size=100, peer="pinned", user_mode="battery_save",
        observed_loss=0.12,
    )
    assert d_high["anchor_lay"] is True


def test_battery_save_never_warms_predictor() -> None:
    s = selector_native.smart_rules()
    d = s.decide(
        kind="TEXT", size=100, peer="pinned",
        user_mode="battery_save", pattern_strength=0.9,
    )
    assert d["predictor_warm"] is False


def test_latency_strict_anchors_files() -> None:
    s = selector_native.smart_rules()
    d = s.decide(
        kind="FILE_CHUNK", size=500_000, peer="pinned",
        user_mode="latency_strict", observed_loss=0.0,
    )
    assert d["anchor_lay"] is True


def test_latency_strict_warms_at_lower_threshold() -> None:
    s = selector_native.smart_rules()
    # 0.35 wouldn't warm under normal (needs > 0.5)
    # but does under latency_strict (needs > 0.3).
    d_strict = s.decide(
        kind="TEXT", size=100, peer="pinned",
        user_mode="latency_strict", pattern_strength=0.35,
    )
    assert d_strict["predictor_warm"] is True
    d_normal = s.decide(
        kind="TEXT", size=100, peer="pinned",
        user_mode="normal", pattern_strength=0.35,
    )
    assert d_normal["predictor_warm"] is False


def test_latency_strict_small_uses_datagram_regardless_of_urgency() -> None:
    s = selector_native.smart_rules()
    d = s.decide(
        kind="TEXT", size=500, peer="pinned",
        urgency="background",  # even background
        user_mode="latency_strict",
    )
    assert d["transport"] == "quic_datagram"

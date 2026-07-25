"""Tests for Presence Compiler.

Covers:
    - viable_rungs masking by peer caps, model match, bandwidth, confirm ratio
    - Descent on REQUEST_LOWER_FIDELITY drops exactly one rung
    - Descent on REQUEST_VOICE_ONLY jumps to AUDIO_ONLY
    - Descent on CONVERT_TO_ASYNC jumps to ASYNC_CAPSULE
    - Descent is instant; ascent requires stability window
    - Ascent only when conditions support a higher viable rung
    - ASYNC_CAPSULE is terminal (no ascent without explicit resume)
    - Capability mask: semantic rungs unreachable without model match
    - Rung transition events name from/to + reason
    - PREWARM / SUGGEST_HANDOFF do not change rung
"""

from __future__ import annotations


from one_link.call_immune import ImmuneAction, ImmuneDecision
from one_link.call_session import Rung
from one_link.presence_compiler import (
    LADDER,
    PresenceCompiler,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decision(action: ImmuneAction, tick: int = 0) -> ImmuneDecision:
    return ImmuneDecision(
        action=action,
        reason_code="test",
        triggered_by=(),
        confidence=1.0,
        tick=tick,
        vitals_hash="hash",
    )


# ---------------------------------------------------------------------------
# Initial state
# ---------------------------------------------------------------------------

def test_initial_rung_is_raw_av() -> None:
    c = PresenceCompiler(peer_capabilities=frozenset({"webrtc_av_v1"}))
    assert c.current_rung == Rung.RAW_AV


def test_initial_rung_can_be_overridden() -> None:
    c = PresenceCompiler(
        peer_capabilities=frozenset({"webrtc_av_v1"}),
        initial_rung=Rung.AUDIO_ONLY,
    )
    assert c.current_rung == Rung.AUDIO_ONLY


# ---------------------------------------------------------------------------
# viable_rungs masking
# ---------------------------------------------------------------------------

def test_viable_rungs_basic() -> None:
    c = PresenceCompiler(peer_capabilities=frozenset({"webrtc_av_v1"}))
    viable = c.viable_rungs(bandwidth_kbps=2000.0, confirm_ratio_voice=1.0)
    rungs = {spec.rung for spec in viable}
    assert Rung.RAW_AV in rungs
    assert Rung.OPUS_VIDEO in rungs
    assert Rung.AUDIO_ONLY in rungs
    # Semantic rungs require SEMANTIC_MEDIA_V1 + model match.
    assert Rung.SEMANTIC_DELTA_AV not in rungs
    assert Rung.CONCEPT_TEXT not in rungs


def test_viable_rungs_includes_semantic_when_cap_and_model_match() -> None:
    c = PresenceCompiler(
        peer_capabilities=frozenset({"webrtc_av_v1", "semantic_media_v1"}),
        model_pack_match=True,
    )
    viable = c.viable_rungs(bandwidth_kbps=2000.0, confirm_ratio_voice=1.0)
    rungs = {spec.rung for spec in viable}
    assert Rung.SEMANTIC_DELTA_AV in rungs
    assert Rung.CONCEPT_TEXT in rungs


def test_viable_rungs_masks_semantic_when_model_mismatch() -> None:
    """The peer advertises the cap but our model packs don't match.
    Semantic rungs must be silently masked out — the user never
    knows the option existed."""
    c = PresenceCompiler(
        peer_capabilities=frozenset({"webrtc_av_v1", "semantic_media_v1"}),
        model_pack_match=False,
    )
    viable = c.viable_rungs(bandwidth_kbps=2000.0, confirm_ratio_voice=1.0)
    rungs = {spec.rung for spec in viable}
    assert Rung.SEMANTIC_DELTA_AV not in rungs
    # Non-semantic still available.
    assert Rung.RAW_AV in rungs


def test_viable_rungs_filters_by_bandwidth() -> None:
    c = PresenceCompiler(peer_capabilities=frozenset({"webrtc_av_v1"}))
    # 100 kbps: too low for RAW_AV (1000) and OPUS_VIDEO (300), AUDIO_ONLY (16) ok.
    viable = c.viable_rungs(bandwidth_kbps=100.0, confirm_ratio_voice=1.0)
    rungs = {spec.rung for spec in viable}
    assert Rung.RAW_AV not in rungs
    assert Rung.OPUS_VIDEO not in rungs
    assert Rung.AUDIO_ONLY in rungs


def test_viable_rungs_filters_by_confirm_ratio() -> None:
    """SEMANTIC_DELTA_AV needs confirm_ratio_voice >= 0.95. Below
    that floor it's masked out."""
    c = PresenceCompiler(
        peer_capabilities=frozenset({"webrtc_av_v1", "semantic_media_v1"}),
        model_pack_match=True,
    )
    viable = c.viable_rungs(bandwidth_kbps=2000.0, confirm_ratio_voice=0.50)
    rungs = {spec.rung for spec in viable}
    assert Rung.SEMANTIC_DELTA_AV not in rungs


# ---------------------------------------------------------------------------
# Descent semantics
# ---------------------------------------------------------------------------

def test_lower_fidelity_descends_one_rung() -> None:
    c = PresenceCompiler(peer_capabilities=frozenset({"webrtc_av_v1"}))
    t = c.request(_decision(ImmuneAction.REQUEST_LOWER_FIDELITY, tick=10),
                  bandwidth_kbps=2000.0, confirm_ratio_voice=1.0)
    assert t is not None
    assert t.from_rung == Rung.RAW_AV
    assert t.to_rung == Rung.OPUS_VIDEO


def test_voice_only_jumps_to_audio_only() -> None:
    c = PresenceCompiler(peer_capabilities=frozenset({"webrtc_av_v1"}))
    t = c.request(_decision(ImmuneAction.REQUEST_VOICE_ONLY, tick=10),
                  bandwidth_kbps=2000.0, confirm_ratio_voice=1.0)
    assert t is not None
    assert t.from_rung == Rung.RAW_AV
    assert t.to_rung == Rung.AUDIO_ONLY


def test_convert_to_async_jumps_to_capsule() -> None:
    c = PresenceCompiler(peer_capabilities=frozenset({"webrtc_av_v1"}))
    t = c.request(_decision(ImmuneAction.CONVERT_TO_ASYNC, tick=10),
                  bandwidth_kbps=0.0, confirm_ratio_voice=0.0)
    assert t is not None
    assert t.to_rung == Rung.ASYNC_CAPSULE


def test_descent_is_instant_no_hysteresis() -> None:
    """Descent doesn't need to wait — drops happen as soon as the
    request arrives. (Ascents are the slow ones.)"""
    c = PresenceCompiler(peer_capabilities=frozenset({"webrtc_av_v1"}))
    t = c.request(_decision(ImmuneAction.REQUEST_VOICE_ONLY, tick=0),
                  bandwidth_kbps=2000.0, confirm_ratio_voice=1.0)
    assert t is not None
    assert c.current_rung == Rung.AUDIO_ONLY


def test_lower_fidelity_at_bottom_stays_at_push_to_talk() -> None:
    c = PresenceCompiler(
        peer_capabilities=frozenset({"webrtc_av_v1"}),
        initial_rung=Rung.PUSH_TO_TALK,
    )
    t = c.request(_decision(ImmuneAction.REQUEST_LOWER_FIDELITY, tick=10),
                  bandwidth_kbps=10.0, confirm_ratio_voice=1.0)
    # At PUSH_TO_TALK, lower fidelity doesn't go further; no transition.
    assert t is None
    assert c.current_rung == Rung.PUSH_TO_TALK


# ---------------------------------------------------------------------------
# Ascent semantics — slow rise after stability window
# ---------------------------------------------------------------------------

def test_no_immediate_ascent_after_descent() -> None:
    """Just because conditions improved doesn't mean we rise the next
    tick. Wait for the stability window."""
    c = PresenceCompiler(
        peer_capabilities=frozenset({"webrtc_av_v1"}),
        ascent_hysteresis_ticks=10,
    )
    # Descend to AUDIO_ONLY
    c.request(_decision(ImmuneAction.REQUEST_VOICE_ONLY, tick=0),
              bandwidth_kbps=2000.0, confirm_ratio_voice=1.0)
    # Send a HOLD on tick 1 with great conditions — no rise yet.
    t = c.request(_decision(ImmuneAction.HOLD, tick=1),
                  bandwidth_kbps=2000.0, confirm_ratio_voice=1.0)
    assert t is None
    assert c.current_rung == Rung.AUDIO_ONLY


def test_ascent_after_stability_window() -> None:
    c = PresenceCompiler(
        peer_capabilities=frozenset({"webrtc_av_v1"}),
        ascent_hysteresis_ticks=5,
    )
    # Descend to AUDIO_ONLY
    c.request(_decision(ImmuneAction.REQUEST_VOICE_ONLY, tick=0),
              bandwidth_kbps=2000.0, confirm_ratio_voice=1.0)
    # First tick AFTER descent that has good conditions sets the
    # stability anchor at tick=1.
    c.request(_decision(ImmuneAction.HOLD, tick=1),
              bandwidth_kbps=2000.0, confirm_ratio_voice=1.0)
    # Tick 2..5: still inside the window.
    for tk in range(2, 6):
        t = c.request(_decision(ImmuneAction.HOLD, tick=tk),
                      bandwidth_kbps=2000.0, confirm_ratio_voice=1.0)
        if tk < 6:
            assert t is None
    # Tick 6: anchored at 1, window is 5 → 6-1=5 >= 5, rise.
    t = c.request(_decision(ImmuneAction.HOLD, tick=6),
                  bandwidth_kbps=2000.0, confirm_ratio_voice=1.0)
    assert t is not None
    assert t.from_rung == Rung.AUDIO_ONLY
    assert t.to_rung == Rung.RAW_AV


def test_ascent_resets_when_conditions_degrade() -> None:
    """Stability window resets if conditions briefly drop. Don't
    rise yet."""
    c = PresenceCompiler(
        peer_capabilities=frozenset({"webrtc_av_v1"}),
        ascent_hysteresis_ticks=5,
    )
    c.request(_decision(ImmuneAction.REQUEST_VOICE_ONLY, tick=0),
              bandwidth_kbps=2000.0, confirm_ratio_voice=1.0)
    # Anchor stability at tick=1
    c.request(_decision(ImmuneAction.HOLD, tick=1),
              bandwidth_kbps=2000.0, confirm_ratio_voice=1.0)
    # Tick=2 — degrade bandwidth, anchor should reset
    c.request(_decision(ImmuneAction.HOLD, tick=2),
              bandwidth_kbps=10.0, confirm_ratio_voice=1.0)
    # Tick=3 — conditions back up, anchor re-set
    c.request(_decision(ImmuneAction.HOLD, tick=3),
              bandwidth_kbps=2000.0, confirm_ratio_voice=1.0)
    # Tick=6 — only 3 ticks since latest anchor; should not rise
    t = c.request(_decision(ImmuneAction.HOLD, tick=6),
                  bandwidth_kbps=2000.0, confirm_ratio_voice=1.0)
    assert t is None
    assert c.current_rung == Rung.AUDIO_ONLY


def test_no_ascent_when_no_higher_rung_viable() -> None:
    c = PresenceCompiler(
        peer_capabilities=frozenset({"webrtc_av_v1"}),
        ascent_hysteresis_ticks=5,
    )
    c.request(_decision(ImmuneAction.REQUEST_VOICE_ONLY, tick=0),
              bandwidth_kbps=2000.0, confirm_ratio_voice=1.0)
    # Stability window, but bandwidth too low for any higher rung
    for tk in range(1, 20):
        c.request(_decision(ImmuneAction.HOLD, tick=tk),
                  bandwidth_kbps=18.0, confirm_ratio_voice=1.0)
    assert c.current_rung == Rung.AUDIO_ONLY


# ---------------------------------------------------------------------------
# Async capsule is terminal
# ---------------------------------------------------------------------------

def test_async_capsule_does_not_ascend() -> None:
    """Once async-converted, the Compiler stays there forever
    (until an explicit resume creates a new CallSession)."""
    c = PresenceCompiler(
        peer_capabilities=frozenset({"webrtc_av_v1"}),
        ascent_hysteresis_ticks=1,
    )
    c.request(_decision(ImmuneAction.CONVERT_TO_ASYNC, tick=0),
              bandwidth_kbps=0.0, confirm_ratio_voice=0.0)
    assert c.current_rung == Rung.ASYNC_CAPSULE
    # Even with great conditions, never rise.
    for tk in range(1, 100):
        t = c.request(_decision(ImmuneAction.HOLD, tick=tk),
                      bandwidth_kbps=5000.0, confirm_ratio_voice=1.0)
        assert t is None
    assert c.current_rung == Rung.ASYNC_CAPSULE


# ---------------------------------------------------------------------------
# Actions that don't change rung
# ---------------------------------------------------------------------------

def test_prewarm_does_not_change_rung() -> None:
    c = PresenceCompiler(peer_capabilities=frozenset({"webrtc_av_v1"}))
    t = c.request(_decision(ImmuneAction.PREWARM_BACKUP_ROUTE, tick=0),
                  bandwidth_kbps=2000.0, confirm_ratio_voice=1.0)
    # No descent; on first request with HOLD-equivalent and stable
    # conditions we anchor stability — no actual transition.
    assert t is None
    assert c.current_rung == Rung.RAW_AV


def test_handoff_does_not_change_rung() -> None:
    c = PresenceCompiler(peer_capabilities=frozenset({"webrtc_av_v1"}))
    t = c.request(_decision(ImmuneAction.SUGGEST_DEVICE_HANDOFF, tick=0),
                  bandwidth_kbps=2000.0, confirm_ratio_voice=1.0)
    assert t is None
    assert c.current_rung == Rung.RAW_AV


def test_switch_route_does_not_change_rung() -> None:
    c = PresenceCompiler(peer_capabilities=frozenset({"webrtc_av_v1"}))
    t = c.request(_decision(ImmuneAction.SWITCH_ROUTE, tick=0),
                  bandwidth_kbps=2000.0, confirm_ratio_voice=1.0)
    assert t is None
    assert c.current_rung == Rung.RAW_AV


# ---------------------------------------------------------------------------
# Ladder integrity
# ---------------------------------------------------------------------------

def test_ladder_has_one_spec_per_rung() -> None:
    seen = {spec.rung for spec in LADDER}
    assert len(seen) == len(LADDER)


def test_ladder_specs_have_plain_language_names() -> None:
    """Doctrine §3.6.c — no jargon in user-facing names."""
    forbidden = ("wi-fi", "wifi", "ratchet", "blake3", "hex", "ed25519")
    for spec in LADDER:
        for tok in forbidden:
            assert tok not in spec.name.lower(), (
                f"rung name {spec.name!r} leaks {tok!r}"
            )

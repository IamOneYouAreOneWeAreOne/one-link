"""Tests for the Human Signal Priority Engine."""

from __future__ import annotations

import pytest

from one_link.call_session import Rung
from one_link.priority_engine import (
    MediaStream,
    QoSClass,
    StreamAllocation,
    allocate,
    total_allocated,
)


# ---------------------------------------------------------------------------
# Stream presets
# ---------------------------------------------------------------------------

VOICE = MediaStream("voice", QoSClass.P0_VOICE, min_kbps=10.0, ideal_kbps=32.0)
TIMING = MediaStream("timing", QoSClass.P1_TIMING, min_kbps=1.0, ideal_kbps=2.0)
FACE = MediaStream("face", QoSClass.P2_FACE_PRIMARY, min_kbps=50.0, ideal_kbps=200.0)
GESTURE = MediaStream("gesture", QoSClass.P3_GESTURE, min_kbps=20.0, ideal_kbps=80.0)
FILE = MediaStream("file", QoSClass.P4_FILE_INFLIGHT, min_kbps=5.0, ideal_kbps=500.0)
BG = MediaStream("bg", QoSClass.P5_VIDEO_BACKGROUND, min_kbps=50.0, ideal_kbps=500.0)
AMBIENT = MediaStream("ambient", QoSClass.P6_AMBIENT, min_kbps=0.5, ideal_kbps=2.0)

ALL_STREAMS = [VOICE, TIMING, FACE, GESTURE, FILE, BG, AMBIENT]


def _by_id(allocs: list[StreamAllocation]) -> dict[str, StreamAllocation]:
    return {a.stream_id: a for a in allocs}


# ---------------------------------------------------------------------------
# Generous bandwidth — everyone gets ideal
# ---------------------------------------------------------------------------

def test_plenty_of_bandwidth_every_stream_funded() -> None:
    allocs = allocate(
        streams=ALL_STREAMS,
        total_bandwidth_kbps=10_000.0,
        current_rung=Rung.RAW_AV,
    )
    by_id = _by_id(allocs)
    for s in ALL_STREAMS:
        assert not by_id[s.stream_id].paused
        assert by_id[s.stream_id].allocated_kbps == pytest.approx(s.ideal_kbps)


# ---------------------------------------------------------------------------
# Under pressure — lowest-class streams pause first
# ---------------------------------------------------------------------------

def test_low_bandwidth_pauses_background_first() -> None:
    """Under bandwidth pressure, lower-priority streams pause first.
    At 80 kbps the budget covers voice + timing + face minimums but
    can't fit gesture's 20 kbps or background's 50 kbps."""
    allocs = allocate(
        streams=ALL_STREAMS,
        total_bandwidth_kbps=80.0,
        current_rung=Rung.RAW_AV,
    )
    by_id = _by_id(allocs)
    assert not by_id["voice"].paused
    assert not by_id["timing"].paused
    assert not by_id["face"].paused
    # Background pauses; gesture pauses (its 20kbps min didn't fit).
    assert by_id["bg"].paused
    assert by_id["gesture"].paused


def test_voice_never_paused_under_any_pressure() -> None:
    """Voice is the human signal — under any non-zero bandwidth
    that meets its 10 kbps minimum, it must never pause."""
    for bw in [10.0, 20.0, 50.0, 100.0]:
        allocs = allocate(
            streams=ALL_STREAMS,
            total_bandwidth_kbps=bw,
            current_rung=Rung.RAW_AV,
        )
        by_id = _by_id(allocs)
        assert not by_id["voice"].paused, f"voice paused at {bw} kbps!"


def test_zero_bandwidth_pauses_everything() -> None:
    allocs = allocate(
        streams=ALL_STREAMS,
        total_bandwidth_kbps=0.0,
        current_rung=Rung.RAW_AV,
    )
    # An allocate() that returned nothing would satisfy "everything is
    # paused" without pausing anything. The claim is about every stream, so
    # every stream has to be present to make it.
    assert len(allocs) == len(ALL_STREAMS), (
        f"allocate() dropped streams: {len(allocs)} of {len(ALL_STREAMS)}"
    )
    for a in allocs:
        assert a.paused
        assert a.allocated_kbps == 0.0


def test_negative_bandwidth_handled_as_zero() -> None:
    allocs = allocate(
        streams=ALL_STREAMS,
        total_bandwidth_kbps=-100.0,
        current_rung=Rung.RAW_AV,
    )
    assert len(allocs) == len(ALL_STREAMS), (
        f"allocate() dropped streams: {len(allocs)} of {len(ALL_STREAMS)}"
    )
    for a in allocs:
        assert a.paused


# ---------------------------------------------------------------------------
# Voice survives video death (the headline guarantee)
# ---------------------------------------------------------------------------

def test_voice_intelligible_when_total_caps_at_30_kbps() -> None:
    """30 kbps total — voice (10 kbps min, 32 ideal) gets the budget
    and stays intelligible. Video / file / background pause."""
    allocs = allocate(
        streams=ALL_STREAMS,
        total_bandwidth_kbps=30.0,
        current_rung=Rung.RAW_AV,
    )
    by_id = _by_id(allocs)
    assert not by_id["voice"].paused
    assert by_id["voice"].allocated_kbps >= 10.0
    # Most video streams pause at this budget
    assert by_id["face"].paused
    assert by_id["bg"].paused
    assert by_id["gesture"].paused


# ---------------------------------------------------------------------------
# Strict priority ordering invariant
# ---------------------------------------------------------------------------

def test_priority_invariant_no_higher_priority_skipped_for_lower() -> None:
    """The 'no skipping' invariant: if a lower-priority stream is
    funded with allocation X kbps, every higher-priority stream
    with ``min_kbps <= X.min_kbps`` must also be funded. (A
    high-priority stream that's paused must have a larger min
    than every funded lower-priority stream — that's what made it
    impossible to fund first.)

    This is the right correctness property: the algorithm doesn't
    greedily skip a fundable high-priority stream to fund a low-
    priority one. It DOES allow a small low-priority stream to
    fund even when a large high-priority stream paused, because
    that's efficient use of fragmented budget."""
    for bw in [0.0, 5.0, 12.0, 30.0, 70.0, 150.0, 1000.0]:
        allocs = allocate(
            streams=ALL_STREAMS,
            total_bandwidth_kbps=bw,
            current_rung=Rung.RAW_AV,
        )
        by_id = _by_id(allocs)
        in_priority = sorted(ALL_STREAMS, key=lambda s: int(s.qos_class))
        for i, lower in enumerate(in_priority):
            if by_id[lower.stream_id].paused:
                continue
            # Lower is funded; check every strictly-higher-priority
            # stream with min_kbps <= lower.min_kbps is also funded.
            for higher in in_priority[:i]:
                if higher.min_kbps <= lower.min_kbps:
                    assert not by_id[higher.stream_id].paused, (
                        f"bw={bw}: {higher.stream_id} (higher priority, "
                        f"smaller-or-equal min) paused while "
                        f"{lower.stream_id} funded — skipping violation"
                    )


# ---------------------------------------------------------------------------
# Rung masks — Compiler-dropped rungs cede video/etc
# ---------------------------------------------------------------------------

def test_audio_only_rung_pauses_all_video_classes() -> None:
    allocs = allocate(
        streams=ALL_STREAMS,
        total_bandwidth_kbps=10_000.0,
        current_rung=Rung.AUDIO_ONLY,
    )
    by_id = _by_id(allocs)
    assert not by_id["voice"].paused
    # All video-bearing classes paused even with plenty of bandwidth.
    assert by_id["face"].paused
    assert by_id["gesture"].paused
    assert by_id["bg"].paused


def test_async_capsule_pauses_everything_except_timing() -> None:
    allocs = allocate(
        streams=ALL_STREAMS,
        total_bandwidth_kbps=10_000.0,
        current_rung=Rung.ASYNC_CAPSULE,
    )
    by_id = _by_id(allocs)
    assert not by_id["timing"].paused
    assert by_id["voice"].paused      # voice is over; this is async
    assert by_id["face"].paused
    assert by_id["bg"].paused


def test_face_still_motion_keeps_face_drops_gesture_and_bg() -> None:
    allocs = allocate(
        streams=ALL_STREAMS,
        total_bandwidth_kbps=1_000.0,
        current_rung=Rung.FACE_STILL_MOTION,
    )
    by_id = _by_id(allocs)
    assert not by_id["voice"].paused
    assert not by_id["face"].paused
    assert by_id["gesture"].paused
    assert by_id["bg"].paused


def test_push_to_talk_only_voice_and_timing() -> None:
    allocs = allocate(
        streams=ALL_STREAMS,
        total_bandwidth_kbps=1_000.0,
        current_rung=Rung.PUSH_TO_TALK,
    )
    by_id = _by_id(allocs)
    assert not by_id["voice"].paused
    assert not by_id["timing"].paused
    for sid in ("face", "gesture", "file", "bg", "ambient"):
        assert by_id[sid].paused


# ---------------------------------------------------------------------------
# Disabled streams
# ---------------------------------------------------------------------------

def test_disabled_stream_is_paused_regardless_of_bandwidth() -> None:
    streams = [VOICE, MediaStream(
        "voice-muted", QoSClass.P0_VOICE,
        min_kbps=10.0, ideal_kbps=32.0, enabled=False,
    )]
    allocs = allocate(
        streams=streams,
        total_bandwidth_kbps=10_000.0,
        current_rung=Rung.RAW_AV,
    )
    by_id = _by_id(allocs)
    assert not by_id["voice"].paused
    assert by_id["voice-muted"].paused


# ---------------------------------------------------------------------------
# Determinism + invariants
# ---------------------------------------------------------------------------

def test_total_allocated_never_exceeds_budget() -> None:
    for bw in [0.0, 17.5, 100.0, 7321.7]:
        allocs = allocate(
            streams=ALL_STREAMS,
            total_bandwidth_kbps=bw,
            current_rung=Rung.RAW_AV,
        )
        total = total_allocated(allocs)
        assert total <= bw + 1e-6, f"over-allocated at bw={bw}: total={total}"


def test_same_inputs_yield_same_allocation() -> None:
    a = allocate(
        streams=ALL_STREAMS,
        total_bandwidth_kbps=400.0,
        current_rung=Rung.RAW_AV,
    )
    b = allocate(
        streams=ALL_STREAMS,
        total_bandwidth_kbps=400.0,
        current_rung=Rung.RAW_AV,
    )
    assert a == b


def test_output_preserves_input_stream_order() -> None:
    """Allocations come back in the SAME order as the input
    streams. Callers iterating both lists in parallel mustn't
    silently get reordered."""
    streams = [BG, VOICE, FACE]  # deliberately not in priority order
    allocs = allocate(
        streams=streams,
        total_bandwidth_kbps=400.0,
        current_rung=Rung.RAW_AV,
    )
    assert [a.stream_id for a in allocs] == ["bg", "voice", "face"]


def test_tiebreak_within_class_is_lex_min() -> None:
    """Two voice streams; one gets the budget when only one fits.
    Tiebreak is deterministic by lex-min stream_id."""
    voice_a = MediaStream("voice-A", QoSClass.P0_VOICE, 10.0, 16.0)
    voice_b = MediaStream("voice-B", QoSClass.P0_VOICE, 10.0, 16.0)
    streams = [voice_a, voice_b]
    # Total budget for exactly one voice min — second must pause.
    allocs = allocate(
        streams=streams, total_bandwidth_kbps=10.0, current_rung=Rung.RAW_AV,
    )
    by_id = _by_id(allocs)
    assert not by_id["voice-A"].paused
    assert by_id["voice-B"].paused


def test_topup_distributed_in_priority_order() -> None:
    """When bandwidth covers everyone's min, leftover budget tops
    up higher-priority first."""
    streams = [VOICE, FACE]
    # min sum = 60; ideal sum = 32 + 200 = 232. Budget 100.
    allocs = allocate(
        streams=streams,
        total_bandwidth_kbps=100.0,
        current_rung=Rung.RAW_AV,
    )
    by_id = _by_id(allocs)
    # Voice gets full ideal (32) first; face gets the rest (68 -> min 50 + 18).
    # 100 budget - 60 mins = 40 leftover. Voice wants 22 (32-10); fully funded.
    # Face wants 150 (200-50); gets the remaining 18.
    assert by_id["voice"].allocated_kbps == pytest.approx(32.0)
    assert by_id["face"].allocated_kbps == pytest.approx(50.0 + 18.0)

"""Tests for CallSession CRDT.

Covers:
    - LWWRegister: with_value semantics, tiebreak by writer_id
    - LWWRegister: merge is commutative + associative + idempotent
    - ORSet: add wins, remove tombstones only observed adds,
      add-after-remove succeeds (add-wins property)
    - ORSet: merge is commutative + associative + idempotent
    - MaxCounter: merge takes max
    - ParticipantState: merge converges across reorderings
    - CallSession: merge laws (commutativity, associativity, idempotence)
    - CallSession: refuses to merge sessions with different identity fields
    - CallSession: end_reason + ended_at_ms preserved (terminal state)
    - Resume continuity: with_intensity / with_rung helpers
    - Random-property soak: 1000 random delta sequences converge
"""

from __future__ import annotations

import random

import pytest

from one_link.call_session import (
    CallSession,
    EndReason,
    Intensity,
    LWWRegister,
    MaxCounter,
    ORSet,
    ParticipantState,
    Rung,
    VerificationState,
)


# ---------------------------------------------------------------------------
# LWWRegister
# ---------------------------------------------------------------------------

def test_lww_empty_register() -> None:
    r: LWWRegister[str] = LWWRegister()
    assert r.value is None
    assert r.timestamp_ms == 0
    assert r.writer_id == ""


def test_lww_with_value_progresses() -> None:
    r: LWWRegister[str] = LWWRegister()
    r2 = r.with_value("hello", timestamp_ms=100, writer_id="alice")
    assert r2.value == "hello"
    assert r2.timestamp_ms == 100


def test_lww_older_write_loses() -> None:
    r = LWWRegister[str](value="new", timestamp_ms=200, writer_id="alice")
    r2 = r.with_value("old", timestamp_ms=100, writer_id="bob")
    assert r2.value == "new"  # older write didn't win


def test_lww_tiebreak_by_writer_id() -> None:
    r = LWWRegister[str](value="alice-wrote", timestamp_ms=100, writer_id="alice")
    r2 = r.with_value("bob-wrote", timestamp_ms=100, writer_id="bob")
    # bob > alice lexicographically, so bob's write wins on tie
    assert r2.value == "bob-wrote"


def test_lww_merge_commutative() -> None:
    a = LWWRegister[str](value="a", timestamp_ms=10, writer_id="x")
    b = LWWRegister[str](value="b", timestamp_ms=20, writer_id="y")
    assert a.merge(b) == b.merge(a)


def test_lww_merge_associative() -> None:
    a = LWWRegister[str](value="a", timestamp_ms=10, writer_id="x")
    b = LWWRegister[str](value="b", timestamp_ms=20, writer_id="y")
    c = LWWRegister[str](value="c", timestamp_ms=15, writer_id="z")
    assert a.merge(b).merge(c) == a.merge(b.merge(c))


def test_lww_merge_idempotent() -> None:
    a = LWWRegister[str](value="a", timestamp_ms=10, writer_id="x")
    assert a.merge(a) == a


# ---------------------------------------------------------------------------
# ORSet
# ---------------------------------------------------------------------------

def test_orset_add_contains() -> None:
    s: ORSet[str] = ORSet.empty()
    s2 = s.add("alpha", add_token="t1")
    assert s2.contains("alpha")
    assert "alpha" in s2.values()


def test_orset_remove_tombstones_observed_adds() -> None:
    s: ORSet[str] = ORSet.empty()
    s = s.add("alpha", add_token="t1")
    s = s.remove("alpha")
    assert not s.contains("alpha")


def test_orset_add_after_remove_succeeds() -> None:
    """The add-wins property: a concurrent add (with a new token)
    after a remove RE-establishes the element. This is critical for
    the 'rejoin a call' scenario where a device leaves and rejoins."""
    s: ORSet[str] = ORSet.empty()
    s = s.add("alpha", add_token="t1")
    s = s.remove("alpha")
    s = s.add("alpha", add_token="t2")   # fresh token
    assert s.contains("alpha")


def test_orset_merge_commutative() -> None:
    a = ORSet[str].empty().add("x", add_token="ta")
    b = ORSet[str].empty().add("y", add_token="tb")
    assert a.merge(b) == b.merge(a)


def test_orset_merge_associative() -> None:
    a = ORSet[str].empty().add("x", add_token="ta")
    b = ORSet[str].empty().add("y", add_token="tb")
    c = ORSet[str].empty().add("z", add_token="tc")
    assert a.merge(b).merge(c) == a.merge(b.merge(c))


def test_orset_merge_idempotent() -> None:
    a = ORSet[str].empty().add("x", add_token="ta")
    assert a.merge(a) == a


def test_orset_concurrent_add_remove_add_wins() -> None:
    """Device A removes 'x'; concurrently device B re-adds 'x' with
    a new token. After merge, 'x' is present (add wins)."""
    base = ORSet[str].empty().add("x", add_token="t1")
    a = base.remove("x")
    b = base.add("x", add_token="t2")
    merged_ab = a.merge(b)
    merged_ba = b.merge(a)
    assert merged_ab == merged_ba
    assert merged_ab.contains("x")


# ---------------------------------------------------------------------------
# MaxCounter
# ---------------------------------------------------------------------------

def test_max_counter_merge_takes_max() -> None:
    a = MaxCounter(value=5).merge(MaxCounter(value=10))
    assert a.value == 10


def test_max_counter_bump_only_forward() -> None:
    c = MaxCounter(value=5).bump(3)
    assert c.value == 5
    c = MaxCounter(value=5).bump(10)
    assert c.value == 10


# ---------------------------------------------------------------------------
# ParticipantState
# ---------------------------------------------------------------------------

def test_participant_merge_converges() -> None:
    base = ParticipantState(master_vk=b"alice-vk")
    a = ParticipantState(
        master_vk=b"alice-vk",
        active_devices=base.active_devices.add("phone", add_token="t1"),
        primary_mic=base.primary_mic.with_value("phone", timestamp_ms=100, writer_id="phone"),
        last_seen_alive_ms=MaxCounter(value=1000),
    )
    b = ParticipantState(
        master_vk=b"alice-vk",
        active_devices=base.active_devices.add("laptop", add_token="t2"),
        primary_mic=base.primary_mic.with_value("laptop", timestamp_ms=200, writer_id="laptop"),
        last_seen_alive_ms=MaxCounter(value=2000),
    )
    merged_ab = a.merge(b)
    merged_ba = b.merge(a)
    assert merged_ab == merged_ba
    assert merged_ab.active_devices.contains("phone")
    assert merged_ab.active_devices.contains("laptop")
    # Later mic wins
    assert merged_ab.primary_mic.value == "laptop"
    # Max counter
    assert merged_ab.last_seen_alive_ms.value == 2000


def test_participant_merge_refuses_different_master_vk() -> None:
    a = ParticipantState(master_vk=b"alice")
    b = ParticipantState(master_vk=b"bob")
    with pytest.raises(ValueError, match="master_vk"):
        a.merge(b)


# ---------------------------------------------------------------------------
# CallSession — lattice laws
# ---------------------------------------------------------------------------

def _empty_session() -> CallSession:
    return CallSession(
        call_id="call-test",
        started_at_ms=1_700_000_000_000,
        negotiated_capabilities=frozenset(["chat", "frame_provenance_v1"]),
    )


def test_session_merge_commutative() -> None:
    a = _empty_session().with_intensity(
        Intensity.HIGH, timestamp_ms=100, writer_id="alice-phone",
    )
    b = _empty_session().with_intensity(
        Intensity.MEDIUM, timestamp_ms=50, writer_id="alice-laptop",
    )
    assert a.merge(b) == b.merge(a)


def test_session_merge_associative() -> None:
    a = _empty_session().with_intensity(
        Intensity.HIGH, timestamp_ms=100, writer_id="x",
    )
    b = _empty_session().with_rung(
        Rung.AUDIO_ONLY, timestamp_ms=200, writer_id="y",
    )
    c = _empty_session().with_resumable_until(
        until_ms=999, timestamp_ms=300, writer_id="z",
    )
    assert a.merge(b).merge(c) == a.merge(b.merge(c))


def test_session_merge_idempotent() -> None:
    a = _empty_session().with_intensity(
        Intensity.HIGH, timestamp_ms=100, writer_id="x",
    )
    assert a.merge(a) == a


def test_session_refuses_different_call_id() -> None:
    a = _empty_session()
    b = CallSession(
        call_id="other-call",
        started_at_ms=a.started_at_ms,
        negotiated_capabilities=a.negotiated_capabilities,
    )
    with pytest.raises(ValueError, match="call_id"):
        a.merge(b)


def test_session_refuses_different_started_at() -> None:
    a = _empty_session()
    b = CallSession(
        call_id=a.call_id,
        started_at_ms=99,
        negotiated_capabilities=a.negotiated_capabilities,
    )
    with pytest.raises(ValueError, match="started_at_ms"):
        a.merge(b)


def test_session_refuses_different_capabilities() -> None:
    a = _empty_session()
    b = CallSession(
        call_id=a.call_id,
        started_at_ms=a.started_at_ms,
        negotiated_capabilities=frozenset(["chat"]),  # different
    )
    with pytest.raises(ValueError, match="negotiated_capabilities"):
        a.merge(b)


# ---------------------------------------------------------------------------
# End-of-call invariants
# ---------------------------------------------------------------------------

def test_ended_session_preserved_through_merge() -> None:
    """Once a call has been ended, the end_reason + ended_at_ms
    are preserved through merges with fresh views."""
    base = _empty_session()
    ended = base.with_ended(
        reason=EndReason.USER_HANGUP_LOCAL,
        ended_at_ms=5000,
        writer_id="alice",
    )
    fresh = base.with_intensity(
        Intensity.LOW, timestamp_ms=4999, writer_id="bob"
    )
    merged = ended.merge(fresh)
    assert merged.ended_at_ms.value == 5000
    assert merged.end_reason.value == int(EndReason.USER_HANGUP_LOCAL)


def test_async_conversion_preserves_state() -> None:
    """When the Immune System triggers NETWORK_ASYNC and the
    Compiler sets the resume window, both fields converge through
    later merges."""
    base = _empty_session()
    async_view = base.with_ended(
        reason=EndReason.NETWORK_ASYNC,
        ended_at_ms=10_000,
        writer_id="alice-phone",
    ).with_resumable_until(
        until_ms=10_000 + 600_000,   # 10 min window
        timestamp_ms=10_000,
        writer_id="alice-phone",
    )
    other_view = base.with_intensity(
        Intensity.MEDIUM, timestamp_ms=9_999, writer_id="bob"
    )
    merged = async_view.merge(other_view)
    assert merged.end_reason.value == int(EndReason.NETWORK_ASYNC)
    assert merged.live_resumable_until_ms.value == 10_000 + 600_000


# ---------------------------------------------------------------------------
# Read helpers
# ---------------------------------------------------------------------------

def test_default_session_is_active() -> None:
    assert _empty_session().is_active


def test_ended_session_is_not_active() -> None:
    s = _empty_session().with_ended(
        reason=EndReason.USER_HANGUP_LOCAL, ended_at_ms=1, writer_id="x"
    )
    assert not s.is_active


def test_current_intensity_default_is_ambient() -> None:
    assert _empty_session().current_intensity == Intensity.AMBIENT


def test_current_rung_default_is_raw() -> None:
    assert _empty_session().current_rung_value == Rung.RAW_AV


# ---------------------------------------------------------------------------
# Property-style soak: random delta sequences converge
# ---------------------------------------------------------------------------

def test_random_delta_sequence_converges() -> None:
    """Two devices each apply 100 random deltas to a shared session.
    They sync at the end. The merged state must be identical
    regardless of merge order."""
    rng = random.Random(0xC0FFEE)
    base = _empty_session()
    view_a = base
    view_b = base
    intensities = list(Intensity)
    rungs = list(Rung)

    for i in range(100):
        # Each "device" picks a random delta to apply locally.
        if rng.random() < 0.5:
            view_a = view_a.with_intensity(
                rng.choice(intensities),
                timestamp_ms=i * 10,
                writer_id="device-A",
            )
        else:
            view_a = view_a.with_rung(
                rng.choice(rungs),
                timestamp_ms=i * 10,
                writer_id="device-A",
            )
        if rng.random() < 0.5:
            view_b = view_b.with_intensity(
                rng.choice(intensities),
                timestamp_ms=i * 10 + 5,
                writer_id="device-B",
            )
        else:
            view_b = view_b.with_rung(
                rng.choice(rungs),
                timestamp_ms=i * 10 + 5,
                writer_id="device-B",
            )

    merged_ab = view_a.merge(view_b)
    merged_ba = view_b.merge(view_a)
    assert merged_ab == merged_ba
    # And idempotent re-merge:
    assert merged_ab.merge(merged_ab) == merged_ab


def test_thousand_random_merges_consistent() -> None:
    """1000 random three-way merges across all permutations should
    converge to the same final state."""
    rng = random.Random(42)
    base = _empty_session()

    for trial in range(1000):
        a = base.with_intensity(
            Intensity(rng.randint(0, 3)),
            timestamp_ms=rng.randint(1, 1000),
            writer_id=f"writer-a-{trial}",
        )
        b = base.with_rung(
            Rung(rng.randint(0, 8)),
            timestamp_ms=rng.randint(1, 1000),
            writer_id=f"writer-b-{trial}",
        )
        c = base.with_resumable_until(
            rng.randint(0, 9999),
            timestamp_ms=rng.randint(1, 1000),
            writer_id=f"writer-c-{trial}",
        )
        # All permutations converge.
        m_abc = a.merge(b).merge(c)
        m_acb = a.merge(c).merge(b)
        m_bac = b.merge(a).merge(c)
        m_bca = b.merge(c).merge(a)
        m_cab = c.merge(a).merge(b)
        m_cba = c.merge(b).merge(a)
        assert m_abc == m_acb == m_bac == m_bca == m_cab == m_cba, (
            f"trial {trial} failed convergence"
        )

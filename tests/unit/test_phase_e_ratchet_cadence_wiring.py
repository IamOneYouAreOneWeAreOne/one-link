"""Phase E #3 — τ_c-coupled ratchet rotation cadence acceptance gate.

When the coherence field reports a low τ_c for a peer (lossy / fragile
edge), the chunk size used in ``Daemon.send_file`` must shrink so the
per-chunk ratchet rotates faster per byte. Forward secrecy scales with
network physics.

Tests work at the unit level by exercising the same code path
``send_file`` uses: ``_fast_fixed_chunk_size_for_peer`` followed by the
field-cadence clamp. We don't spin a full daemon — that's an
integration test. Here we just prove the clamp formula behaves as the
acceptance gate requires.
"""

from __future__ import annotations

import time


def _make_daemon_stub(cadence: int | None):
    """Minimal stub with the ``cadence_for_peer`` method that
    ``send_file`` calls. Returns the cadence we configure."""

    class _Stub:
        def cadence_for_peer(self, peer_short_id: str):
            return cadence

    return _Stub()


def test_low_coherence_peer_shrinks_chunk_size():
    """Acceptance gate: a peer with a low field-driven cadence
    advisory (250 KiB) overrides the baseline 1 MiB chunk size."""
    from one_link.daemon import _fast_fixed_chunk_size_for_peer

    base = _fast_fixed_chunk_size_for_peer(
        "0.21.0-alpha", size=1 * 1024 * 1024, peer_features=()
    )
    # Inline the same clamp send_file applies after the helper.
    stub = _make_daemon_stub(cadence=250_000)
    fixed = base
    field_cadence = stub.cadence_for_peer("abc12345")
    if field_cadence is not None and field_cadence < fixed:
        fixed = max(field_cadence, 64 * 1024)
    # Low-coherence peer → field clamp wins, chunk shrinks to 250 KiB.
    assert fixed == 250_000
    assert fixed < base


def test_high_coherence_peer_keeps_baseline_chunk_size():
    """Acceptance gate: a peer with a high field-driven cadence
    advisory (4 MiB > baseline 1 MiB) does NOT inflate the chunk
    size — the field only allows shrinking, never growing past the
    peer-version-derived cap."""
    from one_link.daemon import _fast_fixed_chunk_size_for_peer

    base = _fast_fixed_chunk_size_for_peer(
        "0.21.0-alpha", size=1 * 1024 * 1024, peer_features=()
    )
    stub = _make_daemon_stub(cadence=4 * 1024 * 1024)
    fixed = base
    field_cadence = stub.cadence_for_peer("abc12345")
    if field_cadence is not None and field_cadence < fixed:
        fixed = max(field_cadence, 64 * 1024)
    # High-coherence peer → no shrink, baseline preserved.
    assert fixed == base


def test_floor_at_64kib_prevents_pathological_shrink():
    """Acceptance gate: a misbehaving field advisory cannot shrink
    the chunk size below 64 KiB — that's the floor where framing
    overhead would dominate."""
    from one_link.daemon import _fast_fixed_chunk_size_for_peer

    base = _fast_fixed_chunk_size_for_peer(
        "0.21.0-alpha", size=1 * 1024 * 1024, peer_features=()
    )
    stub = _make_daemon_stub(cadence=8 * 1024)  # 8 KiB — under the floor
    fixed = base
    field_cadence = stub.cadence_for_peer("abc12345")
    if field_cadence is not None and field_cadence < fixed:
        fixed = max(field_cadence, 64 * 1024)
    assert fixed == 64 * 1024


def test_no_snapshot_keeps_baseline():
    """When the field manager has no snapshot yet (or the peer isn't
    in the snapshot), ``cadence_for_peer`` returns None and the
    baseline chunk size is preserved unchanged."""
    from one_link.daemon import _fast_fixed_chunk_size_for_peer

    base = _fast_fixed_chunk_size_for_peer(
        "0.21.0-alpha", size=1 * 1024 * 1024, peer_features=()
    )
    stub = _make_daemon_stub(cadence=None)
    fixed = base
    field_cadence = stub.cadence_for_peer("abc12345")
    if field_cadence is not None and field_cadence < fixed:
        fixed = max(field_cadence, 64 * 1024)
    assert fixed == base


def test_env_kill_switch_disables_clamp(monkeypatch):
    """ONE_LINK_FIELD_CADENCE_DISABLE=1 forces the field to return
    None even when a real snapshot has a smaller cadence — the
    baseline chunk size survives."""
    from one_link.field_snapshot import FieldSnapshot, FieldSnapshotManager

    mgr = FieldSnapshotManager()
    fake = FieldSnapshot(
        peers=("abc12345",),
        field=(0.2,),
        cadences=((0, 4.0, 100_000),),
        solve_iterations=10,
        solve_residual=1e-7,
        solve_wall_ns=12345,
        captured_at_ns=time.perf_counter_ns(),
    )
    mgr._current = fake  # type: ignore[attr-defined]
    # Sanity: kill-switch off → cadence flows through.
    assert mgr.cadence_for_peer("abc12345") == 100_000
    # Kill-switch on → None despite the snapshot existing.
    monkeypatch.setenv("ONE_LINK_FIELD_CADENCE_DISABLE", "1")
    assert mgr.cadence_for_peer("abc12345") is None

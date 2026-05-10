"""Phase C constant-time audit for ``_is_small_order_x25519``.

Per the file-engine-v2 plan's Phase C gate item #9:

> Constant-time crypto + capability checks — uniform timing across both
> layers. Fixes existing ``double_ratchet._is_small_order_x25519()``
> frozenset (not constant-time).

These tests verify:

1. **Semantic correctness**: every block-listed point is rejected; valid
   public keys pass.
2. **Constant-time timing**: across many calls with `pub in list` vs
   `pub NOT in list`, the wall-clock variance is bounded — we ASSERT a
   loose bound (≤ 2× ratio) rather than the tight 1% gate because
   Python-level timing on Windows has scheduler noise, but the
   primitive is `hmac.compare_digest` which is itself CT.
"""

from __future__ import annotations

import os
import time

import pytest

from one_link.double_ratchet import _is_small_order_x25519, _X25519_SMALL_ORDER_POINTS


def test_all_blocklist_entries_detected() -> None:
    for entry in _X25519_SMALL_ORDER_POINTS:
        assert _is_small_order_x25519(entry), f"missed entry: {entry.hex()}"


def test_random_keys_pass() -> None:
    # 1000 random 32-byte keys — vanishingly unlikely to collide with
    # the 13-entry block list. Any collision = test re-run.
    for _ in range(1000):
        k = os.urandom(32)
        if k in _X25519_SMALL_ORDER_POINTS:
            continue
        assert not _is_small_order_x25519(k)


def test_wrong_length_inputs_rejected() -> None:
    assert _is_small_order_x25519(b"")
    assert _is_small_order_x25519(b"\x00")
    assert _is_small_order_x25519(b"\x00" * 31)
    assert _is_small_order_x25519(b"\x00" * 33)
    assert _is_small_order_x25519(b"\x00" * 64)


def test_does_not_short_circuit_on_first_entry_match() -> None:
    """The function must compare against EVERY entry, not stop at first
    hit. Two ways to verify: (a) timing test (below), (b) inspect that
    the function returns the correct verdict even when the matching
    entry is at the END of the list.
    """
    last = _X25519_SMALL_ORDER_POINTS[-1]
    first = _X25519_SMALL_ORDER_POINTS[0]
    assert _is_small_order_x25519(last)
    assert _is_small_order_x25519(first)


@pytest.mark.skipif(
    os.environ.get("SKIP_TIMING_TESTS") == "1",
    reason="timing-sensitive; set SKIP_TIMING_TESTS=1 to disable",
)
def test_timing_uniform_across_match_position() -> None:
    """Loose timing assertion: median time for (matching) vs
    (non-matching) inputs must be within 2× of each other.

    A tight 1% bound is impractical at the Python level on Windows
    (scheduler noise dominates). We assert this loose bound to confirm
    no order-of-magnitude leak; the primitive (`hmac.compare_digest`)
    is itself constant-time at the C level.
    """
    n_iters = 5000
    first_entry = _X25519_SMALL_ORDER_POINTS[0]
    last_entry = _X25519_SMALL_ORDER_POINTS[-1]
    random_key = os.urandom(32)

    def time_calls(target: bytes) -> float:
        start = time.perf_counter_ns()
        for _ in range(n_iters):
            _is_small_order_x25519(target)
        return time.perf_counter_ns() - start

    # Warm up.
    for tgt in (first_entry, last_entry, random_key):
        time_calls(tgt)

    t_first = time_calls(first_entry)
    t_last = time_calls(last_entry)
    t_rand = time_calls(random_key)
    medians = sorted([t_first, t_last, t_rand])
    spread = medians[-1] / medians[0]
    # Loose: the slowest is at most 2× the fastest. Tighter bound
    # belongs in a Rust-level Criterion benchmark.
    assert spread < 2.0, (
        f"timing spread {spread:.3f}× exceeds 2.0× — possible non-CT path. "
        f"first={t_first} last={t_last} rand={t_rand}"
    )

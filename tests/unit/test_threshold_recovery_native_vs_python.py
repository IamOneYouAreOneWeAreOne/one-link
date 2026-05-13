"""Row 9 polish: property + bench comparison of native vs pure-Python
threshold recovery.

Two claims this file enforces:
  1. The native split/combine path round-trips against arbitrary
     (secret_len, threshold, num_shares) — exhaustively, at high
     iteration count.
  2. The native path is meaningfully faster than the pure-Python
     fallback (otherwise the wiring isn't earning its complexity).

The native test path is skipped when one_link_native isn't installed,
matching `test_social_recovery_native_wired.py` conventions.
"""

from __future__ import annotations

import os
import secrets
import time

import pytest


def _native_available() -> bool:
    try:
        from one_link_native import threshold_recovery  # noqa: F401

        return True
    except ImportError:
        return False


nativeonly = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native.threshold_recovery not installed",
)


# ── 1. Round-trip property tests ──────────────────────────────────


# Test parameter sweep: (secret_len, threshold, num_shares).
# Covers small/medium/large secrets, 2-of-3 / 3-of-5 / 5-of-7 thresholds,
# and the boundary (threshold == num_shares).
_PARAM_SWEEP = [
    (1, 2, 3),       # single byte, smallest threshold
    (8, 2, 3),       # 8-byte secret
    (16, 3, 5),      # 16-byte secret, 3-of-5
    (32, 3, 5),      # 32-byte master seed, 3-of-5
    (32, 5, 7),      # 32-byte master seed, 5-of-7
    (32, 7, 7),      # threshold == num_shares
    (32, 2, 7),      # large N
    (64, 3, 5),      # 64-byte secret
    (128, 3, 5),     # 128-byte secret
    (256, 4, 9),     # 256-byte secret
    (1024, 5, 11),   # 1 KB secret — performance-relevant size
]


@nativeonly
@pytest.mark.parametrize("secret_len,threshold,num_shares", _PARAM_SWEEP)
def test_native_split_combine_round_trip_param_sweep(
    secret_len: int, threshold: int, num_shares: int
):
    """`split_compat` then `combine_compat` recovers every random
    secret across our parameter sweep."""
    from one_link import threshold_recovery_native as tr

    for _ in range(20):  # 20 random secrets per param triple
        secret = secrets.token_bytes(secret_len)
        shares = tr.split_compat(
            secret, threshold=threshold, num_shares=num_shares
        )
        assert len(shares) == num_shares
        # Try every K-subset for thoroughness on small cases.
        if num_shares <= 5:
            # Enumerate all C(num_shares, threshold) subsets.
            import itertools

            for combo in itertools.combinations(range(num_shares), threshold):
                subset = [shares[i] for i in combo]
                recovered = tr.combine_compat(subset, threshold=threshold)
                assert recovered == secret, (
                    f"subset {combo} of (k={threshold}, n={num_shares}) "
                    f"failed"
                )
        else:
            # Random subsets only.
            for _ in range(5):
                import random as _r

                indices = _r.sample(range(num_shares), threshold)
                subset = [shares[i] for i in indices]
                recovered = tr.combine_compat(subset, threshold=threshold)
                assert recovered == secret


@nativeonly
def test_native_extra_shares_dropped_to_threshold():
    """Passing more than `threshold` shares to combine_compat must
    still recover (it drops to the first `threshold`)."""
    from one_link import threshold_recovery_native as tr

    secret = os.urandom(32)
    shares = tr.split_compat(secret, threshold=3, num_shares=5)
    # All 5 shares > threshold=3 → should still recover.
    recovered = tr.combine_compat(shares, threshold=3)
    assert recovered == secret


@nativeonly
def test_native_below_threshold_rejected():
    """combine_compat with fewer than `threshold` shares raises."""
    from one_link import threshold_recovery_native as tr

    secret = os.urandom(32)
    shares = tr.split_compat(secret, threshold=3, num_shares=5)
    with pytest.raises(ValueError, match="need at least"):
        tr.combine_compat(shares[:2], threshold=3)


@nativeonly
@pytest.mark.parametrize("secret_len", [1, 16, 32, 128, 256])
def test_native_combine_subset_invariance(secret_len: int):
    """Recovery is invariant to WHICH subset of K shares is chosen.
    Recovers the SAME secret from any K of the N."""
    from one_link import threshold_recovery_native as tr

    secret = secrets.token_bytes(secret_len)
    shares = tr.split_compat(secret, threshold=3, num_shares=5)
    rec_a = tr.combine_compat([shares[0], shares[1], shares[2]], threshold=3)
    rec_b = tr.combine_compat([shares[0], shares[2], shares[4]], threshold=3)
    rec_c = tr.combine_compat([shares[1], shares[3], shares[4]], threshold=3)
    assert rec_a == secret
    assert rec_b == secret
    assert rec_c == secret


# ── 2. Native compatible with Python combine ──────────────────────


@nativeonly
def test_native_split_python_combine_interop():
    """Shares produced by native split_compat round-trip through the
    PURE-PYTHON combine. Proves wire-format compatibility across the
    two implementations."""
    from one_link import threshold as py_threshold
    from one_link import threshold_recovery_native as tr

    secret = os.urandom(32)
    native_shares = tr.split_compat(secret, threshold=3, num_shares=5)
    # Convert to py Share objects.
    py_shares = [py_threshold.Share(x=x, y=y) for x, y in native_shares[:3]]
    recovered = py_threshold.combine(py_shares)
    assert recovered == secret


def test_python_split_native_combine_interop():
    """Pure-Python split round-trips through native combine_compat."""
    if not _native_available():
        pytest.skip("native unavailable")
    from one_link import threshold as py_threshold
    from one_link import threshold_recovery_native as tr

    secret = os.urandom(32)
    py_shares = py_threshold.split(
        secret=secret, threshold=3, num_shares=5
    )
    # Convert to tuples.
    tuples = [(s.x, s.y) for s in py_shares]
    recovered = tr.combine_compat(tuples[:3], threshold=3)
    assert recovered == secret


# ── 3. Native vs Python performance comparison ───────────────────


@nativeonly
def test_native_split_meaningfully_faster_than_python_split():
    """Native split path is faster than the pure-Python equivalent.

    Strict requirement: ≥2× speedup on a 32-byte secret with k=3, n=5
    over 100 iterations. If this regresses, the native wiring isn't
    earning the build-system complexity. ≥2× is a deliberately gentle
    floor — actual ratios run much higher (the native path is BLAKE3-
    based; Python is per-byte secrets.token_bytes + Python GF mul).
    """
    from one_link import threshold as py_threshold
    from one_link import threshold_recovery_native as tr

    secret = os.urandom(32)
    iters = 100

    # Warm up both paths so allocator + jit caches are populated.
    _ = tr.split_compat(secret, threshold=3, num_shares=5)
    _ = py_threshold.split(secret=secret, threshold=3, num_shares=5)

    t_native_start = time.perf_counter()
    for _ in range(iters):
        tr.split_compat(secret, threshold=3, num_shares=5)
    t_native = time.perf_counter() - t_native_start

    t_py_start = time.perf_counter()
    for _ in range(iters):
        py_threshold.split(secret=secret, threshold=3, num_shares=5)
    t_py = time.perf_counter() - t_py_start

    ratio = t_py / t_native if t_native > 0 else float("inf")
    print(
        f"split_compat: native={t_native * 1000:.2f}ms, "
        f"python={t_py * 1000:.2f}ms over {iters} iters; "
        f"speedup={ratio:.1f}×"
    )
    assert ratio >= 2.0, (
        f"native split should be ≥2× faster than python; "
        f"got {ratio:.2f}× (native={t_native * 1000:.2f}ms, "
        f"python={t_py * 1000:.2f}ms)"
    )


@nativeonly
def test_native_combine_meaningfully_faster_than_python_combine():
    """Native combine path is faster than pure-Python on 32-byte
    secrets at k=3."""
    from one_link import threshold as py_threshold
    from one_link import threshold_recovery_native as tr

    secret = os.urandom(32)
    native_shares = tr.split_compat(secret, threshold=3, num_shares=5)
    py_shares = [py_threshold.Share(x=x, y=y) for x, y in native_shares[:3]]
    iters = 100

    # Warm up.
    _ = tr.combine_compat(native_shares[:3], threshold=3)
    _ = py_threshold.combine(py_shares)

    t_native_start = time.perf_counter()
    for _ in range(iters):
        tr.combine_compat(native_shares[:3], threshold=3)
    t_native = time.perf_counter() - t_native_start

    t_py_start = time.perf_counter()
    for _ in range(iters):
        py_threshold.combine(py_shares)
    t_py = time.perf_counter() - t_py_start

    ratio = t_py / t_native if t_native > 0 else float("inf")
    print(
        f"combine_compat: native={t_native * 1000:.2f}ms, "
        f"python={t_py * 1000:.2f}ms over {iters} iters; "
        f"speedup={ratio:.1f}×"
    )
    assert ratio >= 2.0, (
        f"native combine should be ≥2× faster than python; "
        f"got {ratio:.2f}× (native={t_native * 1000:.2f}ms, "
        f"python={t_py * 1000:.2f}ms)"
    )


# ── 4. Wired social-recovery path: native is on the critical path ─


@nativeonly
def test_social_recovery_module_imports_native():
    """The high-level social_recovery module sets _NATIVE_AVAILABLE
    when the native lib is importable. Pins the critical-path wiring."""
    from one_link import social_recovery as sr

    assert sr._NATIVE_AVAILABLE is True

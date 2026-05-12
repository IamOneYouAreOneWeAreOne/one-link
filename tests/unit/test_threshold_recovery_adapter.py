"""Acceptance tests for the Python adapter wrapping ol_threshold_recovery
(Phase F1.2 — daemon-callable surface for sovereign identity recovery)."""

from __future__ import annotations

import pytest


def _native_available() -> bool:
    try:
        from one_link_native import threshold_recovery  # noqa: F401

        return True
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native.threshold_recovery not installed",
)


def test_module_imports_cleanly():
    from one_link import threshold_recovery_native as tr

    assert tr.HAS_NATIVE is True


def test_plain_shamir_round_trip():
    """Acceptance: a 32-byte master seed (= Ed25519 master key) splits
    to 5 contacts; any 3 reconstruct it byte-identical."""
    from one_link import threshold_recovery_native as tr

    secret = b"Coherence Mesh identity seed!!\x01\x02"
    assert len(secret) == 32
    streams = tr.shamir_split(secret, k=3, n=5, seed=0xCAFE_F00D)
    assert len(streams) == 5
    assert all(len(s) == 32 for s in streams)
    # Recover from shares 0, 2, 4 (x = 1, 3, 5).
    xs = [1, 3, 5]
    recovered = tr.shamir_reconstruct(
        xs, [streams[0], streams[2], streams[4]], k=3
    )
    assert recovered == secret


def test_plain_shamir_any_three_of_five_works():
    from one_link import threshold_recovery_native as tr

    secret = b"thirty-two bytes for round-trip!"
    streams = tr.shamir_split(secret, k=3, n=5, seed=0x1234)
    # Every choice of 3-of-5 must reconstruct.
    for picks in [(0, 1, 2), (0, 2, 4), (1, 3, 4), (2, 3, 4)]:
        xs = [p + 1 for p in picks]
        ys = [streams[p] for p in picks]
        assert tr.shamir_reconstruct(xs, ys, k=3) == secret


def test_max_participants_and_param_validation():
    from one_link import threshold_recovery_native as tr

    assert tr.max_participants() == 255
    assert tr.params_valid(3, 5)
    assert not tr.params_valid(6, 5)
    assert not tr.params_valid(0, 5)


def test_invalid_params_raise_value_error():
    from one_link import threshold_recovery_native as tr

    with pytest.raises(ValueError):
        tr.shamir_split(b"x", k=0, n=5, seed=0)
    with pytest.raises(ValueError):
        tr.shamir_split(b"x", k=6, n=5, seed=0)


# ── Field-bound (alien-tech) layer ────────────────────────────────


def test_field_witness_placeholder_is_identity():
    from one_link import threshold_recovery_native as tr

    secret = b"sensitive identity material!!!\x00\x00"
    pl = tr.placeholder_witness(5)
    assert pl.is_placeholder()
    masked = tr.field_bound_split(
        secret, k=3, n=5, seed=0xBEEF, witness=pl
    )
    xs = [1, 2, 3]
    recovered = tr.field_bound_reconstruct(
        xs,
        [masked[0], masked[1], masked[2]],
        [0, 1, 2],
        k=3,
        witness=pl,
    )
    assert recovered == secret


def test_field_witness_real_roundtrip():
    """Mint with a real (non-placeholder) witness; recovery requires
    the same witness."""
    from one_link import threshold_recovery_native as tr

    secret = b"master Ed25519 seed -- 32 bytes!"
    w = tr.field_witness(
        field_seed=b"\x99" * 32,
        holder_scores=[0.12, 0.34, 0.56, 0.78, 0.90],
        epoch_ns=1_700_000_000_000_000_000,
    )
    masked = tr.field_bound_split(
        secret, k=3, n=5, seed=0xCAFE_F00D, witness=w
    )
    # Recover from shares 0, 2, 4.
    xs = [1, 3, 5]
    recovered = tr.field_bound_reconstruct(
        xs,
        [masked[0], masked[2], masked[4]],
        [0, 2, 4],
        k=3,
        witness=w,
    )
    assert recovered == secret


def test_wrong_witness_blocks_recovery():
    """ALIEN-TECH SECURITY GATE: an attacker holding all K masked
    shares but a wrong witness cannot recover the secret."""
    from one_link import threshold_recovery_native as tr

    secret = b"defense-in-depth identity bytes!"[:32]
    real = tr.field_witness(
        b"\x42" * 32, [0.1, 0.2, 0.3, 0.4, 0.5], epoch_ns=1
    )
    fake = tr.field_witness(
        b"\x99" * 32, [0.1, 0.2, 0.3, 0.4, 0.5], epoch_ns=1
    )
    masked = tr.field_bound_split(
        secret, k=3, n=5, seed=0xABCD, witness=real
    )
    xs = [1, 2, 3]
    recovered = tr.field_bound_reconstruct(
        xs,
        [masked[0], masked[1], masked[2]],
        [0, 1, 2],
        k=3,
        witness=fake,
    )
    # With overwhelming probability, recovered != secret.
    assert recovered != secret


def test_wrong_holder_scores_block_recovery():
    """Even with the right field seed + epoch, wrong holder scores
    re-key the OTPs and break recovery."""
    from one_link import threshold_recovery_native as tr

    secret = b"32-byte master seed for recovery"
    real = tr.field_witness(
        b"\x42" * 32, [0.10, 0.20, 0.30, 0.40, 0.50], epoch_ns=42
    )
    fake = tr.field_witness(
        b"\x42" * 32,
        [0.10, 0.21, 0.30, 0.40, 0.50],  # one tiny perturbation
        epoch_ns=42,
    )
    masked = tr.field_bound_split(
        secret, k=3, n=5, seed=0, witness=real
    )
    recovered = tr.field_bound_reconstruct(
        [1, 2, 3],
        [masked[0], masked[1], masked[2]],
        [0, 1, 2],
        k=3,
        witness=fake,
    )
    assert recovered != secret


def test_field_seed_size_validated():
    """field_seed must be exactly 32 bytes."""
    from one_link import threshold_recovery_native as tr

    with pytest.raises(ValueError):
        tr.field_witness(b"too short", [0.5], epoch_ns=0)
    with pytest.raises(ValueError):
        tr.field_witness(b"x" * 64, [0.5], epoch_ns=0)


def test_field_score_out_of_range_caught():
    from one_link import threshold_recovery_native as tr

    w = tr.field_witness(
        b"\x00" * 32,
        [0.1, 0.5, 1.5, 0.4, 0.8],  # 1.5 is out of [0, 1]
        epoch_ns=0,
    )
    with pytest.raises(ValueError):
        tr.field_bound_split(b"x", k=3, n=5, seed=0, witness=w)

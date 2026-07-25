from __future__ import annotations

from types import SimpleNamespace

import pytest


def test_importable_partial_extension_fails_atomic_abi_validation() -> None:
    from one_link import threshold_recovery_native as adapter

    partial = SimpleNamespace(
        shamir_split=lambda *_args: [],
        shamir_reconstruct=lambda *_args: b"",
        shamir_max_participants=lambda: 255,
        shamir_params_valid=lambda _k, _n: True,
    )
    missing = adapter._missing_native_abi(partial)
    assert "shamir_split_secure" in missing
    assert "field_bound_split_secure" in missing
    assert "FieldWitness" in missing
    assert missing  # Import success alone can never authorize HAS_NATIVE.


def test_reviewed_python_fallback_round_trips_when_policy_permits(
    monkeypatch,
) -> None:
    from one_link import threshold_recovery_native as adapter

    monkeypatch.setattr(adapter, "HAS_NATIVE", False)
    monkeypatch.setattr(adapter, "_NATIVE_MISSING_ABI", ("shamir_split_secure",))
    monkeypatch.setenv(adapter._FALLBACK_POLICY_ENV, "1")
    secret = bytes(range(32))
    shares = adapter.split_compat(secret, threshold=2, num_shares=3)
    assert adapter.combine_compat(shares[:2], threshold=2) == secret


def test_incomplete_native_raises_explicit_capability_error_when_fallback_denied(
    monkeypatch,
) -> None:
    from one_link import threshold_recovery_native as adapter

    monkeypatch.setattr(adapter, "HAS_NATIVE", False)
    monkeypatch.setattr(adapter, "_NATIVE_MISSING_ABI", ("shamir_split_secure",))
    monkeypatch.setenv(adapter._FALLBACK_POLICY_ENV, "0")
    with pytest.raises(
        adapter.ThresholdRecoveryCapabilityError,
        match="incomplete.*shamir_split_secure",
    ):
        adapter.split_compat(b"secret", threshold=2, num_shares=3)


@pytest.mark.parametrize("value", ["garbage", "sometimes", "2"])
def test_unknown_fallback_policy_values_fail_closed(monkeypatch, value: str) -> None:
    from one_link import threshold_recovery_native as adapter

    monkeypatch.setenv(adapter._FALLBACK_POLICY_ENV, value)
    assert adapter.python_fallback_permitted() is False

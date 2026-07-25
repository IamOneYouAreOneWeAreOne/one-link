"""Fail-closed truth gates for the unfinished proximity factor."""

from __future__ import annotations

import pytest

from one_link import proximity_pair_native as proximity


def test_production_factor2_capability_is_explicitly_unavailable() -> None:
    assert proximity.PRODUCTION_FACTOR2_AVAILABLE is False


def test_legacy_secret_api_never_delegates_to_a_stale_native_extension(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class UnsafeLegacyNative:
        def derive_factor2_secret(self, *args: object) -> bytes:
            raise AssertionError("legacy native API must never be called")

    monkeypatch.setattr(proximity, "_native_pp", UnsafeLegacyNative())

    with pytest.raises(proximity.Factor2UnavailableError, match="not available"):
        proximity.derive_factor2_secret(
            my_observations=b"x" * 512,
            peer_syndrome=b"\x00" * 64,
            salt=b"s" * 32,
        )


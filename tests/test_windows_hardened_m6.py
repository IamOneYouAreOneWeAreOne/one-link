"""Audit M6 May 2026 — WindowsHardenedProvider pyo3 surface.

Verifies the Python adapter for the TPM-rooted hardened provider.

Most assertions are STRUCTURAL: they check that the adapter
correctly reports the feature-gate status, raises the right error
shape when the gate is off, and exposes the right interface. The
LIVE-TPM round-trip (seal/sign/attest with real TPM) only runs when
the wheel was built with ``--features windows-tpm`` AND the host has
a functional TPM 2.0 — outside CI on a stock Windows dev box this is
typically off, so the test skips cleanly.
"""
from __future__ import annotations

import pytest

from one_link import confidential_native as cn

# 2026-06-04: the fresh() tests below exercise WindowsHardenedProvider's
# key-name validation + feature-gating, which all sit BEHIND the native
# crate. When one_link_native.confidential isn't built (e.g. the CI full
# suite, which doesn't run maturin), fresh() raises ConfidentialNotInstalled
# before any of that logic runs, so the assertions can't hold. Skip those
# three when the crate is absent; the import-contract + bool-probe tests
# above still run everywhere.
_needs_confidential_native = pytest.mark.skipif(
    not cn.HAS_NATIVE,
    reason="one_link_native.confidential not installed (native crate absent)",
)


def test_module_exports_windows_hardened_class():
    """The adapter class must always be importable so callers can
    `isinstance(p, WindowsHardenedProvider)` regardless of whether
    the feature is enabled — only construction is gated."""
    assert hasattr(cn, "WindowsHardenedProvider")


def test_has_windows_tpm_provider_returns_bool():
    """The capability probe is always callable + bool-typed."""
    flag = cn.has_windows_tpm_provider()
    assert isinstance(flag, bool)


@_needs_confidential_native
def test_fresh_without_feature_raises_friendly_error():
    """When the wheel was NOT built with --features windows-tpm,
    `fresh()` must raise ConfidentialNotInstalled with a message
    that names the audit + the missing feature flag."""
    if cn.has_windows_tpm_provider():
        pytest.skip("wheel built with windows-tpm — friendly-error path not exercised here")
    with pytest.raises(cn.ConfidentialNotInstalled) as excinfo:
        cn.WindowsHardenedProvider.fresh("OL-test-m6-no-tpm")
    msg = str(excinfo.value)
    assert "windows-tpm" in msg.lower()
    assert "audit m6" in msg.lower()


@_needs_confidential_native
def test_fresh_rejects_empty_tpm_key_name():
    """Even before reaching the native side, an empty key name
    fails fast."""
    with pytest.raises(ValueError):
        cn.WindowsHardenedProvider.fresh("")


@_needs_confidential_native
def test_fresh_rejects_non_string_tpm_key_name():
    """Type guard on the Python side."""
    with pytest.raises(ValueError):
        cn.WindowsHardenedProvider.fresh(b"not-a-str")  # type: ignore[arg-type]


@pytest.mark.skipif(
    not cn.has_windows_tpm_provider(),
    reason="wheel built without --features windows-tpm (audit M6)",
)
def test_live_tpm_round_trip():
    """When the feature is enabled AND a TPM is present, the full
    round-trip seal/sign/verify/attest must succeed under the
    HardwareBound tier. This is the OPT-IN path that exercises the
    real TPM call."""
    p = cn.WindowsHardenedProvider.fresh("OL-test-m6-live-round-trip-v1")
    assert p.tier == cn.TIER_HARDWARE_BOUND
    assert p.tag == cn.PROVIDER_TAG_WINDOWS_TPM
    seed = b"\xCC" * 32
    sealed = p.seal_master(seed)
    assert sealed.is_hardware_bound
    vk = p.verifying_key(sealed)
    sig = p.sealed_sign(sealed, b"hello-m6")
    # Master VK + transcript verify via the ol_pqsig path — exercised
    # indirectly through the attestation flow rather than directly
    # here (no Python-side HybridVerifyingKey export). Smoke check
    # that the sig is non-trivial in shape.
    assert isinstance(sig, bytes)
    assert len(sig) > 64  # hybrid Ed25519 + ML-DSA-65 is way longer
    assert isinstance(vk, bytes)
    assert len(vk) == 1984  # hybrid VK length

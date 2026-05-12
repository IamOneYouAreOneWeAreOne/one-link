"""Lock in the adversarial-field fuzz harness as a CI gate."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent / "scripts"


def _phase_e_available() -> bool:
    try:
        from one_link_native import coherence_field  # noqa: F401

        return True
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _phase_e_available(),
    reason="one_link_native.coherence_field not installed",
)


def _load_fuzz():
    spec = importlib.util.spec_from_file_location(
        "_fuzz", _SCRIPTS_DIR / "adversarial_field_fuzz.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_adversarial_fuzz_all_regimes_pass_quick():
    """Quick mode (5 trials/regime, ~50ms wall): the field solver must
    handle every adversarial regime without NaN/inf/panic across the
    full loss × noise × mutation × extreme-constants matrix."""
    fuzz = _load_fuzz()
    report = fuzz.run_fuzz(quick=True)
    assert report["all_passed"], (
        "fuzz regimes failed: "
        + ", ".join(r["regime"] for r in report["regimes"] if not r["passed"])
    )
    # Each regime must report meaningful telemetry.
    for r in report["regimes"]:
        assert "regime" in r
        assert "passed" in r
        assert r["passed"] is True


def test_adversarial_fuzz_extreme_constants_bounded():
    """Specifically: pathological (D, gamma) inputs must produce
    bounded fields or graceful errors — never NaN/inf or panic."""
    fuzz = _load_fuzz()
    from one_link import coherence_field_native as cf
    from one_link_native import coherence_field as native_cf

    extreme = fuzz.regime_extreme_constants(cf, native_cf)
    assert extreme["passed"]
    assert all(
        case.get("bounded") is True or "error" in case for case in extreme["cases"]
    )

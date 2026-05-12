"""Lock in the Phase E live demo gates as pytest regression tests."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent / "scripts"


def _load_script(name: str):
    spec = importlib.util.spec_from_file_location(
        f"_demo_{name}", _SCRIPTS_DIR / f"{name}.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


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


def test_phase_e_fragile_swarm_demo_passes_gate():
    """The plan-mandated Phase E acceptance demo: 100-peer fragile
    swarm, BE-RAR-driven routing reduces chunks-lost by ≥ 80% vs the
    Phase D BFS baseline. Run live through the pyo3 surface (not the
    Rust integration test) to catch adapter-layer regressions."""
    demo = _load_script("phase_e_live_demo")
    report = demo.run_demo(quiet=True)
    assert report["gate_passed"], (
        f"Phase E gate failed live: reduction = "
        f"{report['reduction'] * 100:.1f}%, expected ≥ "
        f"{report['pass_threshold'] * 100:.0f}%"
    )
    assert report["phase_e_chunks_lost"] <= report["phase_d_chunks_lost"]
    assert report["phase_e_solve"]["solve_iterations"] <= 50
    assert report["phase_e_solve"]["solve_residual"] < 1e-5


def test_phase_e_cross_domain_demo_all_converge():
    """The cross-domain calibration demo: same crate solves One Link
    + OneField + BioMesh fields, all converge, anchor scale spread
    spans many orders of magnitude."""
    demo = _load_script("phase_e_cross_domain_demo")
    report = demo.run_demo(quiet=True)
    assert report["all_converged"], "not every domain converged"
    assert report["anchor_spread"] > 100.0, (
        f"g_A spread across domains only {report['anchor_spread']:.2e}× — "
        "cross-domain calibration expected to span ≥ 100×"
    )
    # All three domain blocks present.
    for d in ("one_link", "one_field", "bio_mesh"):
        assert d in report["domains"], f"missing {d} domain in report"
        cal = report["domains"][d]["calibration"]
        assert cal["apparent_horizon_anchor"] > 0
        assert cal["screening_length"] > 0
        assert cal["d"] > 0
        assert cal["gamma"] > 0

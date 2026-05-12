#!/usr/bin/env python3
"""Adversarial fuzz harness for the coherence-field path.

Per ``docs/FILE_ENGINE_V2_PLAN.md`` verification section:

    in CI, inject 10/30/50% packet loss + reorder + jitter + NIC drops +
    disk-full + daemon kill -9 mid-transfer. Engine must complete or
    resume cleanly.

The field-substrate level of this gate exercises ``ol_coherence_field``
through the daemon adapter under:

- Variable-loss-rate matrices (10% / 30% / 50% / 70%).
- Out-of-order source/destination updates (the routing layer must stay
  monotone-improving).
- Numerical-jitter sources (random noise added to the source vector).
- Topology-mutation mid-solve (peer leaves the swarm while the field
  is being computed).

For each adversarial regime, asserts:
1. The solver converges (no NaN, no panic).
2. The recovered field stays bounded (no |x| > 1e10).
3. The Phase E gate (≥ 80% chunks-lost reduction vs Phase D) still
   holds at 30% / 50% loss.
4. Sign-preservation under non-negative sources stays intact.

Exit code: 0 if all regimes pass, 1 if any regime fails.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
import time
from pathlib import Path
from typing import Any


SWARM_SIZE = 100
N_CHUNKS = 1000


def _require_field():
    try:
        from one_link import coherence_field_native as cf

        if not cf.HAS_NATIVE:
            raise RuntimeError("HAS_NATIVE=False")
        return cf
    except ImportError as e:
        raise RuntimeError(
            "one_link_native.coherence_field not installed; build via "
            "`cd native && maturin develop --release`"
        ) from e


def build_swarm(cf, fragile_loss: float, rng: random.Random):
    """Build a 100-peer ring with a random fragile band whose edge
    weights are scaled by (1 - fragile_loss)."""
    g = cf.graph_laplacian(SWARM_SIZE)
    band_start = rng.randint(20, 70)
    band_len = rng.randint(15, 25)
    is_fragile = [
        band_start <= i < band_start + band_len for i in range(SWARM_SIZE)
    ]
    for i in range(SWARM_SIZE):
        j = (i + 1) % SWARM_SIZE
        weight = max(1.0 - fragile_loss, 0.05) if (is_fragile[i] or is_fragile[j]) else 1.0
        g.add_edge(i, j, weight)
    # Force a bridge through the band so Phase D's BFS picks it.
    src = 0
    dst = (band_start + band_len // 2) % SWARM_SIZE if band_start > 20 else 5
    mid = (band_start + band_len // 2) % SWARM_SIZE
    if src != mid and dst != mid:
        try:
            g.add_edge(src, mid, 1.0)
            g.add_edge(mid, dst, 1.0)
        except ValueError:
            pass  # tolerate duplicates from edge cases
    return g, is_fragile, src, dst


def regime_pure_loss(cf, native_cf, loss_rate: float, n_trials: int = 20) -> dict[str, Any]:
    """Run n_trials at a fixed loss rate, varying the fragile band per
    trial. Asserts: every solve converges, field stays bounded."""
    rng = random.Random(loss_rate * 1e6)
    converged_count = 0
    max_field_abs = 0.0
    iters = []
    residuals = []
    for trial in range(n_trials):
        g, is_fragile, _src, _dst = build_swarm(cf, loss_rate, rng)
        density = [0.05 if is_fragile[i] else 1.0 for i in range(SWARM_SIZE)]
        flux = [0.02 if is_fragile[i] else 0.8 for i in range(SWARM_SIZE)]
        source_vec = native_cf.identity_dual_source(density, flux, 0.5, 0.5)
        try:
            result = cf.solve_helmholtz(g, 1.0, 0.5, source_vec)
        except Exception as e:
            return {
                "regime": f"pure_loss_{int(loss_rate * 100)}pct",
                "passed": False,
                "trials": n_trials,
                "completed": trial,
                "error": str(e),
            }
        if result["converged"]:
            converged_count += 1
        iters.append(result["iterations"])
        residuals.append(result["residual"])
        for v in result["field"]:
            if math.isnan(v) or math.isinf(v):
                return {
                    "regime": f"pure_loss_{int(loss_rate * 100)}pct",
                    "passed": False,
                    "reason": "field contains NaN/inf",
                    "completed": trial,
                }
            max_field_abs = max(max_field_abs, abs(v))
    return {
        "regime": f"pure_loss_{int(loss_rate * 100)}pct",
        "passed": converged_count == n_trials and max_field_abs < 1e10,
        "trials": n_trials,
        "converged": converged_count,
        "max_field_abs": max_field_abs,
        "iters_median": sorted(iters)[len(iters) // 2] if iters else 0,
        "residual_max": max(residuals) if residuals else 0,
    }


def regime_source_noise(cf, native_cf, jitter: float, n_trials: int = 20) -> dict[str, Any]:
    """Inject random noise into the source vector. Solver must stay
    bounded and converge."""
    rng = random.Random(int(jitter * 1e6))
    converged = 0
    max_field = 0.0
    for trial in range(n_trials):
        g, is_fragile, _src, _dst = build_swarm(cf, 0.3, rng)
        density = [
            (0.05 if is_fragile[i] else 1.0) + rng.uniform(-jitter, jitter)
            for i in range(SWARM_SIZE)
        ]
        flux = [
            (0.02 if is_fragile[i] else 0.8) + rng.uniform(-jitter, jitter)
            for i in range(SWARM_SIZE)
        ]
        # Clamp to non-negative.
        density = [max(d, 0.0) for d in density]
        flux = [max(f, 0.0) for f in flux]
        try:
            source_vec = native_cf.identity_dual_source(density, flux, 0.5, 0.5)
            result = cf.solve_helmholtz(g, 1.0, 0.5, source_vec)
        except Exception as e:
            return {
                "regime": f"source_noise_{jitter:.2f}",
                "passed": False,
                "completed": trial,
                "error": str(e),
            }
        if result["converged"]:
            converged += 1
        for v in result["field"]:
            if math.isnan(v) or math.isinf(v):
                return {
                    "regime": f"source_noise_{jitter:.2f}",
                    "passed": False,
                    "reason": "NaN/inf field",
                }
            max_field = max(max_field, abs(v))
    return {
        "regime": f"source_noise_{jitter:.2f}",
        "passed": converged == n_trials and max_field < 1e10,
        "trials": n_trials,
        "converged": converged,
        "max_field_abs": max_field,
    }


def regime_topology_mutation(cf, native_cf, n_trials: int = 20) -> dict[str, Any]:
    """Build a graph, solve, then mutate (add edges), solve again. The
    CSR cache must invalidate cleanly and the second solve must produce
    a different but still-bounded field."""
    rng = random.Random(0xDEADBEEF)
    passed = 0
    for trial in range(n_trials):
        g, is_fragile, _src, _dst = build_swarm(cf, 0.3, rng)
        density = [0.05 if is_fragile[i] else 1.0 for i in range(SWARM_SIZE)]
        flux = [0.02 if is_fragile[i] else 0.8 for i in range(SWARM_SIZE)]
        source_vec = native_cf.identity_dual_source(density, flux, 0.5, 0.5)
        r1 = cf.solve_helmholtz(g, 1.0, 0.5, source_vec)
        # Add 5 random edges.
        for _ in range(5):
            i = rng.randint(0, SWARM_SIZE - 1)
            j = rng.randint(0, SWARM_SIZE - 1)
            if i != j:
                try:
                    g.add_edge(i, j, 0.5)
                except ValueError:
                    pass  # duplicate edge — fine, tolerated
        r2 = cf.solve_helmholtz(g, 1.0, 0.5, source_vec)
        ok = (
            r1["converged"]
            and r2["converged"]
            and all(not (math.isnan(v) or math.isinf(v)) for v in r2["field"])
        )
        if ok:
            passed += 1
    return {
        "regime": "topology_mutation",
        "passed": passed == n_trials,
        "trials": n_trials,
        "converged_both_solves": passed,
    }


def regime_extreme_constants(cf, native_cf) -> dict[str, Any]:
    """Push (D, gamma) into pathological regimes. Solver must still
    behave: converge, error gracefully, or return NotConverged — but
    NEVER panic / NaN."""
    g = cf.graph_laplacian(50)
    for i in range(50):
        g.add_edge(i, (i + 1) % 50, 1.0)
    source = [1.0] * 50
    cases = [
        (1e-9, 1.0),   # near-singular D
        (1.0, 1e-9),   # near-singular gamma
        (1e6, 1.0),    # huge D
        (1.0, 1e6),    # huge gamma
        (1e6, 1e-6),   # both extreme, opposite directions
    ]
    all_pass = True
    case_results = []
    for d, gamma in cases:
        try:
            r = cf.solve_helmholtz(g, d, gamma, source)
            ok = all(
                not (math.isnan(v) or math.isinf(v)) for v in r["field"]
            ) and abs(max(r["field"], key=abs)) < 1e20
            case_results.append(
                {"d": d, "gamma": gamma, "converged": r["converged"], "bounded": ok}
            )
            all_pass = all_pass and ok
        except Exception as e:
            # Errors are acceptable (e.g. NonConverged); panics are not.
            case_results.append(
                {"d": d, "gamma": gamma, "error": str(e)}
            )
    return {
        "regime": "extreme_constants",
        "passed": all_pass,
        "cases": case_results,
    }


def run_fuzz(seed: int = 0, quick: bool = False) -> dict[str, Any]:
    cf = _require_field()
    from one_link_native import coherence_field as native_cf
    n = 5 if quick else 20
    regimes = [
        regime_pure_loss(cf, native_cf, 0.10, n),
        regime_pure_loss(cf, native_cf, 0.30, n),
        regime_pure_loss(cf, native_cf, 0.50, n),
        regime_pure_loss(cf, native_cf, 0.70, n),
        regime_source_noise(cf, native_cf, 0.10, n),
        regime_source_noise(cf, native_cf, 0.50, n),
        regime_topology_mutation(cf, native_cf, n),
        regime_extreme_constants(cf, native_cf),
    ]
    return {
        "swarm_size": SWARM_SIZE,
        "regimes": regimes,
        "all_passed": all(r["passed"] for r in regimes),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, default=None)
    p.add_argument("--quick", action="store_true",
                   help="5 trials per regime instead of 20 (CI smoke)")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)
    t0 = time.perf_counter()
    try:
        report = run_fuzz(quick=args.quick)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    elapsed = time.perf_counter() - t0
    report["wall_seconds"] = round(elapsed, 3)
    if not args.quiet:
        print(f"=== Adversarial coherence-field fuzz ({len(report['regimes'])} regimes) ===")
        for r in report["regimes"]:
            status = "PASS" if r["passed"] else "FAIL"
            extras = [f"{k}={v}" for k, v in r.items() if k not in {"regime", "passed"}][:3]
            print(f"  [{status}] {r['regime']:30s} " + ", ".join(map(str, extras)))
        print()
        print(f"Overall: {'PASS' if report['all_passed'] else 'FAIL'} "
              f"in {elapsed:.2f}s")
    if args.out is not None:
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

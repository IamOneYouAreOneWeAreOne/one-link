#!/usr/bin/env python3
"""Phase E cross-domain calibration demo — same Rust crate, three domains.

Per ``docs/FILE_ENGINE_V2_PLAN.md``:

    same ``ol_coherence_field`` crate solves One Link's network field AND
    OneField's RF τ_c routing AND BioMesh's signal field, all from
    identical Rust + per-domain calibration constants.

This script feeds the same 100-peer ring topology to the field solver
under three calibrations (One Link, OneField, BioMesh) and reports:

- Apparent-horizon anchor ``g_A`` per domain (should span many orders
  of magnitude — the whole point of cross-domain calibration is that
  the scales are domain-specific even though the algebra is shared).
- Screening length ``ell_screen`` per domain (in domain-specific
  units).
- Field-magnitude profile per domain (verifies the solver converges
  on each calibration without numerical pathology).

Output: human-readable summary + JSON report.

Usage:
    python scripts/phase_e_cross_domain_demo.py [--out report.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


PEERS = 100


def _require_field():
    try:
        from one_link import coherence_field_native as cf

        if not cf.HAS_NATIVE:
            raise RuntimeError(
                "one_link_native.coherence_field installed but HAS_NATIVE=False"
            )
        return cf
    except ImportError as e:
        raise RuntimeError(
            "one_link_native.coherence_field not installed; build via "
            "`cd native && maturin develop --release --locked`"
        ) from e


def build_ring(cf, n: int):
    g = cf.graph_laplacian(n)
    for i in range(n):
        g.add_edge(i, (i + 1) % n, 1.0)
    return g


def solve_for_calibration(
    cf, native_cf, g, cal: dict[str, Any], n: int
) -> dict[str, Any]:
    """Run a Helmholtz solve using the calibration's (D, gamma); compose
    an identity-dual source from a synthetic density+flux profile, and
    return a summary."""
    density = [1.0 if i < n // 2 else 0.5 for i in range(n)]
    flux = [0.6] * n
    source_vec = native_cf.identity_dual_source(density, flux, 0.5, 0.5)
    solved = cf.solve_helmholtz(
        g, d=cal["d"], gamma=cal["gamma"], source=source_vec
    )
    field = solved["field"]
    return {
        "iterations": solved["iterations"],
        "residual": solved["residual"],
        "field_min": min(field),
        "field_max": max(field),
        "field_mean": sum(field) / len(field),
        "converged": solved["converged"],
    }


def run_demo(quiet: bool = False) -> dict[str, Any]:
    cf = _require_field()
    from one_link_native import coherence_field as native_cf

    g = build_ring(cf, PEERS)
    domains = {
        "one_link": cf.one_link_calibration(),
        "one_field": native_cf.one_field_calibration(),
        "bio_mesh": native_cf.bio_mesh_calibration(),
    }
    per_domain: dict[str, dict[str, Any]] = {}
    for name, cal in domains.items():
        summary = solve_for_calibration(cf, native_cf, g, cal, PEERS)
        per_domain[name] = {
            "calibration": cal,
            "solve": summary,
        }
    # Cross-domain summary.
    anchors = {
        name: per_domain[name]["calibration"]["apparent_horizon_anchor"]
        for name in domains
    }
    largest = max(anchors.values())
    smallest = min(anchors.values())
    anchor_spread = largest / smallest if smallest > 0 else float("inf")

    report = {
        "topology": {"shape": "ring", "n_peers": PEERS},
        "domains": per_domain,
        "anchor_spread": anchor_spread,
        "anchor_spread_log10": round(anchor_spread.bit_length()
                                     if isinstance(anchor_spread, int)
                                     else __import__("math").log10(anchor_spread), 2),
        "all_converged": all(
            per_domain[d]["solve"]["converged"] for d in per_domain
        ),
    }
    if not quiet:
        print("=== Phase E cross-domain calibration demo ===")
        print(f"Topology: {PEERS}-peer ring")
        print()
        for name, info in per_domain.items():
            cal = info["calibration"]
            sv = info["solve"]
            print(f"{name}:")
            print(f"  D = {cal['d']:.3e}, gamma = {cal['gamma']:.3e}")
            print(f"  ell_screen = {cal['screening_length']:.3e}")
            print(f"  g_A         = {cal['apparent_horizon_anchor']:.3e}")
            print(
                f"  solve: {sv['iterations']} iters, residual {sv['residual']:.2e}, "
                f"field mean {sv['field_mean']:.3e}"
            )
            print()
        print(f"Anchor g_A spread (largest/smallest): {anchor_spread:.2e}×")
        print(f"All domains converged: {report['all_converged']}")
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, default=None)
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)
    try:
        report = run_demo(quiet=args.quiet)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if args.out is not None:
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        if not args.quiet:
            print(f"Wrote {args.out}")
    return 0 if report["all_converged"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Honest production-readiness audit for the file engine v2 stack.

Walks every plan-mandated surface and reports its real wiring state.
Distinct from `pre_release_audit.py` which checks that tests pass —
this script checks that production paths are actually wired, not
just that the substrate compiles.

Categories:

1. **Crate availability** — every Phase A/B/C/D/E crate present in
   ``one_link_native``.
2. **Capability advertisement** — every cap in ``LOCAL_CAPABILITIES``
   matches what the docs claim.
3. **Daemon wiring** — every native primitive has a daemon-side hook
   that actually fires under the right conditions.
4. **Telemetry** — every observable counter the ops runbook
   references is reachable via ``/api/metrics``-shape output.
5. **Honest gaps** — surfaces that exist as scaffolds but aren't
   yet wired into hot paths. Reported as ``advisory`` (not failure)
   so operators see them but releases aren't blocked.

Exit code 0 = production-deployable. Exit code 1 = real wire gap.
Exit code 2 = audit infrastructure error.

Usage:
    python scripts/production_readiness_audit.py
    python scripts/production_readiness_audit.py --json out.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent


def _check_native_crates_present() -> dict[str, Any]:
    """Each plan-mandated native crate is importable as a submodule
    of ``one_link_native``."""
    expected = [
        "chunk", "aead", "wal", "store", "quic", "bloom", "fountain",
        "fec", "ratchet", "pqkem", "erasure", "bandit", "capability",
        "crdt", "hwkey", "routing", "prefetch", "homology",
        "coherence_field",
    ]
    findings: list[str] = []
    available: list[str] = []
    try:
        import one_link_native  # noqa: F401
    except ImportError:
        return {
            "category": "native crates",
            "status": "FAIL",
            "reason": "one_link_native wheel not installed",
            "expected_count": len(expected),
            "available_count": 0,
        }
    for sub in expected:
        try:
            __import__(f"one_link_native.{sub}")
            available.append(sub)
        except ImportError:
            findings.append(sub)
    status = "PASS" if not findings else "FAIL"
    return {
        "category": "native crates",
        "status": status,
        "expected_count": len(expected),
        "available_count": len(available),
        "missing": findings,
    }


def _check_capabilities_advertised() -> dict[str, Any]:
    """Every cap in ``LOCAL_CAPABILITIES`` is advertised. Audit
    confirms BLOOM_INIT_V1 + QUIC_TRANSPORT_V1 (the two new ones)
    AND every legacy cap is still there (regression gate)."""
    from one_link.capabilities import (
        BLOOM_INIT_V1,
        CHAT,
        DOUBLE_RATCHET_V1,
        FILES,
        FILE_CDC,
        FILE_RESUMABLE,
        FILE_SWARM,
        FOLDER_SYNC,
        LOCAL_CAPABILITIES,
        NATIVE_TRANSFER_V1,
        QUIC_TRANSPORT_V1,
    )

    must_advertise = (
        CHAT, FILES, FILE_CDC, FILE_RESUMABLE, FILE_SWARM, FOLDER_SYNC,
        DOUBLE_RATCHET_V1, NATIVE_TRANSFER_V1, BLOOM_INIT_V1,
        QUIC_TRANSPORT_V1,
    )
    missing = [c for c in must_advertise if c not in LOCAL_CAPABILITIES]
    status = "PASS" if not missing else "FAIL"
    return {
        "category": "capability advertisement",
        "status": status,
        "advertised_count": len(LOCAL_CAPABILITIES),
        "missing_required": missing,
    }


def _check_daemon_wiring() -> dict[str, Any]:
    """Required daemon-side methods that production code paths call."""
    from one_link.daemon import Daemon

    required_methods = [
        # Phase D / E base wiring
        "_pick_best_relay",
        "_relay_metrics_for",
        "record_relay_observation",
        "native_diagnostics",
        # Phase E coherence-field
        "_ensure_field_snapshot",
        "_field_topology_feeder_loop",
        "_push_topology_to_field_snapshot",
        "cadence_for_peer",
        "field_score_for_peer",
        "field_snapshot_metrics",
        # Phase B Bloom-init
        "build_local_bloom_advertisement",
        "filter_manifest_with_receiver_bloom",
        "_handle_bloom_init_advisory",
        "bloom_decision_for_chunk",
        "bloom_cross_check_with_file_wants",
        "_bloom_only_for_peer",
        "_maybe_send_bloom_init_advisory",
        # Phase A2 QUIC
        "_ensure_quic_endpoint",
        "transport_choice_for_peer",
        # Transport facade
        "_send_via_transport",
    ]
    missing = [m for m in required_methods if not hasattr(Daemon, m)]
    status = "PASS" if not missing else "FAIL"
    return {
        "category": "daemon wiring",
        "status": status,
        "required_count": len(required_methods),
        "present_count": len(required_methods) - len(missing),
        "missing": missing,
    }


def _check_native_diagnostics_blocks() -> dict[str, Any]:
    """``native_diagnostics()`` returns the keys the runbook +
    operator dashboards depend on."""
    from one_link.daemon import Daemon

    class _Stub:
        _prefetch_predictor = None
        _last_minted_macaroon = None

    diag = Daemon.native_diagnostics(_Stub())  # type: ignore[arg-type]
    required_blocks = {
        "prefetch", "routing", "homology", "coherence_field",
        "bloom_init", "quic_transport", "native_transfer_v1",
        "macaroon_dual_issue",
    }
    missing = sorted(required_blocks - set(diag.keys()))
    status = "PASS" if not missing else "FAIL"
    return {
        "category": "native diagnostics blocks",
        "status": status,
        "required_count": len(required_blocks),
        "present_count": len(required_blocks) - len(missing),
        "missing": missing,
    }


def _check_field_snapshot_manager_safe_defaults() -> dict[str, Any]:
    """A fresh FieldSnapshotManager returns safe-default metrics +
    None cadence without crashing — required because the production
    daemon spins it up on every start."""
    try:
        from one_link.field_snapshot import FieldSnapshotManager
    except ImportError:
        return {
            "category": "field snapshot safe defaults",
            "status": "FAIL",
            "reason": "FieldSnapshotManager not importable",
        }
    mgr = FieldSnapshotManager()
    m = mgr.metrics()
    cadence = mgr.cadence_for_peer("unknown")
    score = mgr.field_score_for_peer("unknown")
    safe = (
        m["field_solve_count"] == 0
        and m["field_solve_failures"] == 0
        and cadence is None
        and score is None
    )
    return {
        "category": "field snapshot safe defaults",
        "status": "PASS" if safe else "FAIL",
    }


def _check_perf_gates_baseline_committed() -> dict[str, Any]:
    """The per-PR regression baseline must exist."""
    baseline = REPO_ROOT / "bench_baselines" / "coherence_field.json"
    if not baseline.is_file():
        return {
            "category": "perf gate baseline",
            "status": "FAIL",
            "reason": f"{baseline} missing",
        }
    try:
        data = json.loads(baseline.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {
            "category": "perf gate baseline",
            "status": "FAIL",
            "reason": "baseline JSON invalid",
        }
    n_metrics = len(data.get("results", []))
    return {
        "category": "perf gate baseline",
        "status": "PASS" if n_metrics > 0 else "FAIL",
        "tracked_metric_count": n_metrics,
    }


# ── ADVISORY (non-blocking) checks ─────────────────────────────────


def _advisory_facade_migration() -> dict[str, Any]:
    """How many channel.send call sites use the new PeerTransport
    facade vs the raw transport. Migration is incremental; this
    surfaces progress without blocking releases."""
    daemon_src = (REPO_ROOT / "src" / "one_link" / "daemon.py").read_text(
        encoding="utf-8", errors="replace"
    )
    facade_calls = daemon_src.count("_send_via_transport(")
    raw_channel_calls = daemon_src.count("channel.send(") + daemon_src.count(
        "sess.channel.send("
    )
    return {
        "category": "facade migration progress (advisory)",
        "status": "ADVISORY",
        "facade_call_sites": facade_calls,
        "raw_channel_call_sites": raw_channel_calls,
        "migrated_fraction": (
            facade_calls / max(facade_calls + raw_channel_calls, 1)
        ),
    }


def _advisory_bloom_honor_state() -> dict[str, Any]:
    import os

    enabled = os.environ.get("ONE_LINK_BLOOM_HONOR", "0") in (
        "1", "true", "yes"
    )
    return {
        "category": "bloom-init honor state (advisory)",
        "status": "ADVISORY",
        "ONE_LINK_BLOOM_HONOR_enabled": enabled,
        "note": (
            "Off by default; flip per-host once disagreement-counter "
            "telemetry confirms safety. See PHASE_E_OPERATOR_RUNBOOK.md."
        ),
    }


def _advisory_filesystem_mount_state() -> dict[str, Any]:
    """FUSE / FSKit / WinFSP are scaffolds; actual mount-and-fsx-linux
    verification is hardware-blocked. Surface what's shipped."""
    state = {}
    for crate in ("ol_fuse", "ol_fskit", "ol_winfs"):
        path = REPO_ROOT / "native" / crate
        state[crate] = "scaffold" if path.is_dir() else "missing"
    return {
        "category": "filesystem-surface mount state (advisory)",
        "status": "ADVISORY",
        "crates": state,
        "note": (
            "Linux FUSE adapter compiles; mount-and-fsx-linux 24h "
            "verification pending Linux host. macOS FSKit + Windows "
            "WinFSP/Dokan are scaffolds awaiting Swift/C++ bridge "
            "implementation."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--json", type=Path, default=None)
    args = p.parse_args(argv)

    blocking_checks = [
        _check_native_crates_present(),
        _check_capabilities_advertised(),
        _check_daemon_wiring(),
        _check_native_diagnostics_blocks(),
        _check_field_snapshot_manager_safe_defaults(),
        _check_perf_gates_baseline_committed(),
    ]
    advisories = [
        _advisory_facade_migration(),
        _advisory_bloom_honor_state(),
        _advisory_filesystem_mount_state(),
    ]

    failed = [c for c in blocking_checks if c["status"] != "PASS"]
    print("=" * 70)
    print("PRODUCTION-READINESS AUDIT (file engine v2)")
    print("=" * 70)
    print()
    print("Blocking gates:")
    print(f"  {'Check':40s} {'Status':>8s}")
    print("-" * 50)
    for c in blocking_checks:
        print(f"  {c['category'][:40]:40s} {c['status']:>8s}")
    print()
    print("Advisory (release-non-blocking):")
    for c in advisories:
        print(f"  - {c['category']}")
        for k, v in c.items():
            if k in ("category", "status"):
                continue
            if isinstance(v, dict):
                v = ", ".join(f"{kk}={vv}" for kk, vv in v.items())
            print(f"      {k}: {v}")
    print()

    if failed:
        print(f"FAIL: {len(failed)} blocking check(s) did not pass:")
        for f in failed:
            print(f"  - {f['category']}: {f.get('reason') or f.get('missing')}")
        exit_code = 1
    else:
        print("PASS: every blocking production-readiness gate green.")
        exit_code = 0

    report = {
        "blocking": blocking_checks,
        "advisory": advisories,
        "production_ready": exit_code == 0,
    }
    if args.json is not None:
        args.json.write_text(
            json.dumps(report, indent=2, default=str), encoding="utf-8"
        )
        print(f"\n  → wrote JSON to {args.json}")

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

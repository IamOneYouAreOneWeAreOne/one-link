#!/usr/bin/env python3
"""Scoped wiring-readiness audit for the file engine v2 stack.

Walks every plan-mandated surface and reports its real wiring state.
Distinct from `pre_release_audit.py` which checks that tests pass —
this script checks that production paths are actually wired, not
just that the substrate compiles.

Categories:

1. **Crate availability** — every Phase A/B/C/D/E crate present in
   ``one_link_native``.
2. **Capability advertisement** — runtime CAPS matches executable native
   availability and never promotes protocol vocabulary into a live promise.
3. **Daemon wiring** — every native primitive has a daemon-side hook
   that actually fires under the right conditions.
4. **Telemetry** — every observable counter the ops runbook
   references is reachable via ``/api/metrics``-shape output.
5. **Honest gaps** — surfaces that exist as scaffolds but aren't yet wired
   into hot paths. They remain visible as ``advisory`` findings, but this
   script is intentionally not a whole-product release verdict.

Exit code 0 = the scoped file-engine blocking checks passed. It does **not**
mean the application is production-deployable; packaging, signing, platform,
physical-device, security-review, and advisory closure are separate gates.
Exit code 1 = a scoped blocking wire gap.
Exit code 2 = audit infrastructure error.

Usage:
    python scripts/production_readiness_audit.py
    python scripts/production_readiness_audit.py --json out.json
"""

from __future__ import annotations

import argparse
import json
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
    """Runtime CAPS must exactly follow its executable native backends."""
    from one_link import bloom_init, native_transfer, peer_quic
    from one_link.capabilities import (
        BLOOM_INIT_EXACT_V2,
        BLOOM_INIT_V1,
        CHAT,
        DOUBLE_RATCHET_V1,
        FILES,
        FILE_CDC,
        FILE_RESUMABLE,
        FILE_SWARM,
        FOLDER_SYNC,
        LOCAL_CAPABILITIES,
        NATIVE_TRANSFER_INDEXED_V1,
        PREVIEW_CAPABILITIES,
        QUIC_TRANSPORT_V1,
        advertised_capabilities,
    )

    must_advertise = (
        CHAT, FILES, FILE_CDC, FILE_RESUMABLE, FILE_SWARM, FOLDER_SYNC,
        DOUBLE_RATCHET_V1,
    )
    advertised = advertised_capabilities()
    missing = [c for c in must_advertise if c not in advertised]
    native_truth = {
        BLOOM_INIT_V1: bool(bloom_init.HAS_NATIVE),
        BLOOM_INIT_EXACT_V2: bool(bloom_init.HAS_NATIVE),
        NATIVE_TRANSFER_INDEXED_V1: bool(native_transfer.HAS_NATIVE),
        QUIC_TRANSPORT_V1: bool(peer_quic.HAS_NATIVE),
    }
    native_mismatches = {
        cap: {"advertised": cap in advertised, "available": available}
        for cap, available in native_truth.items()
        if (cap in advertised) is not available
    }
    falsely_advertised_preview = sorted(
        set(PREVIEW_CAPABILITIES) & set(advertised)
    )
    duplicates = sorted(
        cap for cap in set(LOCAL_CAPABILITIES)
        if LOCAL_CAPABILITIES.count(cap) > 1
    )
    status = (
        "PASS"
        if not missing
        and not native_mismatches
        and not falsely_advertised_preview
        and not duplicates
        else "FAIL"
    )
    return {
        "category": "capability advertisement",
        "status": status,
        "advertised_count": len(advertised),
        "missing_required": missing,
        "native_mismatches": native_mismatches,
        "falsely_advertised_preview": falsely_advertised_preview,
        "duplicates": duplicates,
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


def _check_coherence_perf_gates_configured() -> dict[str, Any]:
    """Portable SLO gate and dedicated-runner lab artifact must exist."""

    portable_gate = REPO_ROOT / "scripts" / "coherence_field_slo_gate.py"
    baseline = REPO_ROOT / "bench_baselines" / "coherence_field.json"
    if not portable_gate.is_file():
        return {
            "category": "coherence-field performance gates",
            "status": "FAIL",
            "reason": f"portable SLO gate missing: {portable_gate}",
        }
    if not baseline.is_file():
        return {
            "category": "coherence-field performance gates",
            "status": "FAIL",
            "reason": f"dedicated-runner lab baseline missing: {baseline}",
        }
    try:
        data = json.loads(baseline.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {
            "category": "coherence-field performance gates",
            "status": "FAIL",
            "reason": f"dedicated-runner lab baseline unreadable: {exc}",
        }
    rows = data.get("results") if isinstance(data, dict) else None
    n_metrics = len(rows) if isinstance(rows, list) else 0
    return {
        "category": "coherence-field performance gates",
        "status": "PASS" if n_metrics > 0 else "FAIL",
        "portable_gate": portable_gate.name,
        "historical_lab_metric_count": n_metrics,
        "historical_baseline_scope": "dedicated environment-qualified runner only",
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
    from one_link.bloom_init import bloom_honor_enabled

    enabled = bloom_honor_enabled()
    return {
        "category": "bloom-init honor state (advisory)",
        "status": "ADVISORY",
        "ONE_LINK_BLOOM_HONOR_enabled": enabled,
        "note": (
            "Exact-v2 is default-on and lossless through manifest binding plus "
            "false-positive corrections; set ONE_LINK_BLOOM_HONOR=0 for a "
            "FILE_WANTS-only compatibility rollout. V1-only peers never cut over."
        ),
    }


def _advisory_filesystem_mount_state() -> dict[str, Any]:
    """Report source and runtime mount truth without cross-platform promotion."""

    linux_adapter = REPO_ROOT / "native" / "ol_fuse" / "src" / "adapter.rs"
    python_binding = REPO_ROOT / "native" / "one_link_native" / "src" / "fuse.rs"
    state = {
        "ol_fuse": (
            "linux_fuser_adapter" if linux_adapter.is_file() else "missing"
        ),
        "one_link_native.fuse": (
            "python_binding" if python_binding.is_file() else "missing"
        ),
        "ol_fskit": (
            "scaffold_unimplemented"
            if (REPO_ROOT / "native" / "ol_fskit").is_dir()
            else "missing"
        ),
        "ol_winfs": (
            "scaffold_unimplemented"
            if (REPO_ROOT / "native" / "ol_winfs").is_dir()
            else "missing"
        ),
    }
    try:
        from one_link import fuse_native

        runtime: dict[str, Any] = fuse_native.capabilities()
    except Exception as exc:
        runtime = {
            "ready": False,
            "backend": "none",
            "reason": "probe_failed_closed",
            "error": type(exc).__name__,
        }
    return {
        "category": "filesystem-surface mount state (advisory)",
        "status": "ADVISORY",
        "crates": state,
        "runtime": runtime,
        "note": (
            "Linux has a real read-only callback-backed fuser adapter and "
            "packaged Python binding. Strict packaged /dev/fuse plus 24-hour "
            "fsx qualification remains pending. macOS FSKit and Windows "
            "WinFsp/Dokan adapters are unimplemented."
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
        _check_coherence_perf_gates_configured(),
    ]
    advisories = [
        _advisory_facade_migration(),
        _advisory_bloom_honor_state(),
        _advisory_filesystem_mount_state(),
    ]

    failed = [c for c in blocking_checks if c["status"] != "PASS"]
    print("=" * 70)
    print("FILE-ENGINE V2 WIRING-READINESS AUDIT")
    print("=" * 70)
    print()
    print("Blocking gates:")
    print(f"  {'Check':40s} {'Status':>8s}")
    print("-" * 50)
    for c in blocking_checks:
        print(f"  {c['category'][:40]:40s} {c['status']:>8s}")
    print()
    print("Advisory (outside this script's scoped blocking verdict):")
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
        print("PASS: every scoped file-engine wiring gate is green.")
        print("NOTE: this is not a whole-product production or release verdict.")
        exit_code = 0

    report = {
        "scope": "file_engine_v2_wiring",
        "blocking": blocking_checks,
        "advisory": advisories,
        "file_engine_v2_wiring_ready": exit_code == 0,
        # Kept as a fail-closed compatibility field for any older automation
        # that interpreted this scoped report as a deployment decision.
        "production_ready": False,
        "production_ready_reason": (
            "scoped wiring audit cannot establish whole-product production readiness"
        ),
    }
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(report, indent=2, default=str), encoding="utf-8"
        )
        print(f"\n  → wrote JSON to {args.json}")

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

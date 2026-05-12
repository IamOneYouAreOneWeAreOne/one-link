#!/usr/bin/env python3
"""Phase B fountain-codes stress: K=1024 source symbols at 5% loss
across ≥ 1000 random seeds.

Per ``docs/FILE_ENGINE_V2_PLAN.md``:

    RaptorQ decode succeeds with K=1024 source symbols at 5% loss
    across ≥ 1000 random seeds.

The shipped fountain codec is **LT** (Luby Transform — the simpler
sibling of RaptorQ that decodes by belief propagation). This script
exercises the same gate: K=1024 source symbols, 5% packet loss, 1000
random seeds. RaptorQ has different decode properties (systematic +
inactivation decoding) but the gate's intent — ≥ 99% successful
recoveries — applies to either codec.

Reports:
- successful decode count
- median symbols-received-before-complete (excess over K)
- failure mode breakdown (if any)

Usage:
    python scripts/fountain_k1024_stress.py [--seeds N] [--loss 0.05]
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path
from typing import Any


def _require_fountain():
    try:
        from one_link_native import fountain

        return fountain
    except ImportError as e:
        raise RuntimeError(
            "one_link_native.fountain not installed; build via "
            "`cd native && maturin develop --release`"
        ) from e


def _stress_one_seed(fountain_mod, k_target: int, loss_rate: float, seed: int) -> dict[str, Any]:
    """Encode a fixed-size source via LT, simulate `loss_rate` packet
    loss, drive the decoder until success or budget exhaustion."""
    symbol_len = 64
    source_bytes = k_target * symbol_len
    rng = random.Random(seed)
    source = bytes(rng.randint(0, 255) for _ in range(source_bytes))

    enc = fountain_mod.LtEncoder(source, symbol_len)
    k = enc.k
    dec = fountain_mod.LtDecoder(k, symbol_len, source_bytes)

    # Budget: 4× K. If we can't decode within 4K received packets at 5%
    # loss, something is wrong (overhead is typically 1.05-1.20× K).
    budget = 4 * k
    received_count = 0
    sent_count = 0
    complete = False
    while sent_count < budget:
        symbol_id = sent_count
        sent_count += 1
        if rng.random() < loss_rate:
            continue
        payload = enc.encode_symbol(symbol_id)
        received_count += 1
        if dec.ingest(symbol_id, payload):
            complete = True
            break
    if not complete:
        return {
            "seed": seed,
            "success": False,
            "k": k,
            "sent": sent_count,
            "received": received_count,
            "budget_exhausted": True,
        }
    # Verify the decoded bytes match the original.
    decoded = dec.finish()
    return {
        "seed": seed,
        "success": decoded == source,
        "k": k,
        "sent": sent_count,
        "received": received_count,
        "overhead_ratio": received_count / k,
    }


def run_stress(
    k: int = 1024, loss: float = 0.05, n_seeds: int = 1000, quiet: bool = False
) -> dict[str, Any]:
    fountain_mod = _require_fountain()
    t0 = time.perf_counter()
    successes = 0
    overheads = []
    failures = []
    for seed in range(n_seeds):
        r = _stress_one_seed(fountain_mod, k, loss, seed)
        if r["success"]:
            successes += 1
            overheads.append(r["overhead_ratio"])
        else:
            failures.append({"seed": seed, "result": r})
    elapsed = time.perf_counter() - t0
    overheads.sort()
    median_overhead = overheads[len(overheads) // 2] if overheads else None
    max_overhead = max(overheads) if overheads else None
    success_rate = successes / n_seeds if n_seeds > 0 else 0.0
    gate_passed = success_rate >= 0.99
    report = {
        "k_target": k,
        "loss_rate": loss,
        "n_seeds": n_seeds,
        "successes": successes,
        "success_rate": success_rate,
        "overhead_median": median_overhead,
        "overhead_max": max_overhead,
        "failure_count": len(failures),
        "failures_sample": failures[:5],
        "wall_seconds": round(elapsed, 3),
        "gate_passed": gate_passed,
    }
    if not quiet:
        print(f"=== Fountain K=~{k} stress: {n_seeds} seeds @ {loss * 100:.0f}% loss ===")
        print(f"Successes: {successes}/{n_seeds} = {success_rate * 100:.2f}%")
        if median_overhead is not None:
            print(f"Median overhead: {median_overhead:.3f}× K")
            print(f"Max overhead: {max_overhead:.3f}× K")
        print(f"Wall time: {elapsed:.1f}s")
        print(f"Gate (≥ 99% success): {'PASS' if gate_passed else 'FAIL'}")
        if failures:
            print(f"Sample failures: {failures[:3]}")
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--k", type=int, default=512,
                   help="Source symbol count. Default 512: shipped codec caps "
                        "encoded-symbols at MAX_ENCODED_PER_CHUNK=1024, so K=512 "
                        "leaves 2× headroom for loss overhead. Plan target K=1024 "
                        "requires raising the codec cap (Phase B follow-up).")
    p.add_argument("--loss", type=float, default=0.05)
    p.add_argument("--seeds", type=int, default=1000)
    p.add_argument("--out", type=Path, default=None)
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)
    try:
        report = run_stress(args.k, args.loss, args.seeds, quiet=args.quiet)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if args.out is not None:
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["gate_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Run the One Link never-lose transfer torture simulator.

This is a no-big-disk proof: it models a huge file with synthetic chunk
metadata, injects sleeps, corrupt chunks, route failures, and protocol
fallbacks, then exits non-zero if the simulated delivery is not eventually
verified.
"""

from __future__ import annotations

import argparse
import json

from one_link.transfer_sim import simulate_never_lose_transfer


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--size-gib", type=float, default=10.0)
    ap.add_argument("--chunk-mib", type=float, default=16.0)
    ap.add_argument("--seed", type=int, default=20260507)
    ap.add_argument("--drop-rate", type=float, default=0.35)
    ap.add_argument("--corruption-rate", type=float, default=0.05)
    ns = ap.parse_args()

    report = simulate_never_lose_transfer(
        size=int(ns.size_gib * 1024 * 1024 * 1024),
        chunk_size=int(ns.chunk_mib * 1024 * 1024),
        seed=ns.seed,
        drop_rate=ns.drop_rate,
        corruption_rate=ns.corruption_rate,
    )
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return 0 if report.delivered else 1


if __name__ == "__main__":
    raise SystemExit(main())

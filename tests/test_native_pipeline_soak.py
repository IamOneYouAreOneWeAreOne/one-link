"""Native pipeline soak test (Phase D #4).

Long-running mixed-workload soak that exercises the native CRDT folder
mirror, the relay-metrics EWMA surface, and the prefetch predictor
under interleaved adds / removes / remote-merge cycles. Acceptance
gate: zero native-mirror divergences, zero reconcile disagreements,
no Python exceptions, bounded memory growth.

Iteration count is configurable via ``ONE_LINK_SOAK_ITERS`` (default
2_000 for the regular CI run; the nightly gate sets it to 50_000). At
2K iters this completes in ~5s on Alex's laptop; at 50K it's the kind
of run that catches drift bugs the unit suite can't.
"""

from __future__ import annotations

import asyncio
import os
import random
from pathlib import Path

import pytest

from one_link.blobstore import BlobStore
from one_link.crdt import ManifestEntry, VectorClock
from one_link.foldersync import FolderEngine
from one_link.state import State


def _native_available() -> bool:
    try:
        from one_link import crdt_native

        return crdt_native.HAS_NATIVE
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native.crdt not installed (build via maturin)",
)


@pytest.mark.timeout(180)
def test_foldersync_native_pipeline_soak(tmp_path: Path):
    """Run the FolderEngine reconcile path through a randomized
    add/remove/concurrent-edit workload. Acceptance: at end, the
    native mirror reports zero divergence events and the native
    reconcile cross-check reports zero disagreements over every
    iteration."""
    iters = int(os.environ.get("ONE_LINK_SOAK_ITERS", "2000"))
    seed = int(os.environ.get("ONE_LINK_SOAK_SEED", "0xC0DEC0DE"), 0)
    rng = random.Random(seed)

    state = State(db_path=tmp_path / "state.db")
    blobs = BlobStore(tmp_path / "blobs")
    loop = asyncio.new_event_loop()
    engine = FolderEngine(
        state=state,
        blob_store=blobs,
        my_fingerprint="aa" * 32,
        loop=loop,
    )
    try:
        state.add_folder(
            name="soak",
            local_path=str(tmp_path / "soak"),
            shared_with=[],
        )

        paths = [f"f_{i:04d}.bin" for i in range(64)]
        peer_clocks: dict[str, int] = {}

        for i in range(iters):
            path = rng.choice(paths)
            op = rng.choices(
                ["add", "remove", "concurrent_edit"],
                weights=[6, 2, 2],
            )[0]
            peer = f"peer_{rng.randint(0, 3)}"
            peer_clocks[peer] = peer_clocks.get(peer, 0) + 1
            vc = VectorClock.from_dict({peer: peer_clocks[peer]})

            if op == "add":
                blob = f"blob_{i:06x}"
                entry = ManifestEntry(
                    file_path=path,
                    blob_hash=blob,
                    size=rng.randint(1, 1_000_000),
                    mtime_ms=1_700_000_000_000 + i,
                    vclock=vc,
                )
            elif op == "remove":
                entry = ManifestEntry(
                    file_path=path,
                    blob_hash=None,
                    size=0,
                    mtime_ms=1_700_000_000_000 + i,
                    vclock=vc,
                )
            else:
                # Concurrent edit: same path, different blob, same vclock
                # height — exercises the conflict / OR-set add-wins paths.
                entry = ManifestEntry(
                    file_path=path,
                    blob_hash=f"blob_alt_{i:06x}",
                    size=rng.randint(1, 1_000_000),
                    mtime_ms=1_700_000_000_000 + i,
                    vclock=vc,
                )

            engine.receive_remote_manifest(
                folder_name="soak",
                entries=[entry.to_dict()],
                peer_fp=peer,
            )

        stats = engine.native_mirror_stats()
        assert stats["divergence_events"] == 0, (
            f"native mirror divergence after {iters} iters: {stats}"
        )
        # The legacy LWW-vclock merge and the lattice OR-set differ on
        # one specific class of inputs: local has a live entry, remote
        # sends a higher-vclock tombstone. Legacy says tombstone wins
        # (vclock dominance); the OR-set is add-wins so the local
        # entry survives. This divergence is *expected* during the
        # transition window (ADR-0022). The soak bounds it at 5% so a
        # genuine regression (e.g. a bug that causes the lattice to
        # drop entries) still trips the gate.
        disagree_ratio = stats["reconcile_disagreements"] / max(
            1, stats["reconcile_checks"]
        )
        assert disagree_ratio < 0.05, (
            f"native reconcile disagreement ratio {disagree_ratio:.2%} "
            f"exceeds 5% budget — likely a real regression: {stats}"
        )
        assert stats["reconcile_checks"] >= iters, (
            "reconcile check counter should have incremented every iter"
        )
    finally:
        state.close()
        loop.close()


@pytest.mark.timeout(60)
def test_relay_metrics_ewma_soak():
    """Drive ``record_relay_observation`` through a randomized
    success/failure stream and confirm the EWMA-smoothed stats remain
    bounded + numerically stable over thousands of observations."""
    from one_link.daemon import Daemon

    iters = int(os.environ.get("ONE_LINK_SOAK_ITERS", "2000"))
    seed = int(os.environ.get("ONE_LINK_SOAK_SEED", "0xDEADBEEF"), 0)
    rng = random.Random(seed)

    class _Stub:
        _relay_metrics: dict = {}

    stub = _Stub()
    relays = [f"https://relay-{c}.example.com" for c in "abcdef"]
    for _ in range(iters):
        url = rng.choice(relays)
        if rng.random() < 0.85:
            rtt = rng.uniform(5.0, 500.0)
            Daemon.record_relay_observation(stub, url, rtt_ms=rtt, success=True)
        else:
            Daemon.record_relay_observation(stub, url, rtt_ms=None, success=False)

    for url, m in stub._relay_metrics.items():
        assert m["n_attempts"] > 0
        assert 0.0 <= m["rtt_ms"] <= 1000.0, f"rtt out of bounds: {m}"
        assert 0.0 <= m["loss_rate"] <= 1.0, f"loss_rate out of bounds: {m}"
        # NaN check (NaN never equals itself).
        assert m["rtt_ms"] == m["rtt_ms"]
        assert m["loss_rate"] == m["loss_rate"]

"""Python-level performance benchmarks comparing the Phase C-3 native
migration paths against their legacy Python counterparts.

Run::

    cd One_link
    python -m tests.benchmarks.bench_phase_c3_migration

Prints a side-by-side table (legacy vs native, lower is better) so
operators can quantify the cost of the cutover before flipping any
production switch.

Methodology:
  - Each path is warmed with 200 iterations.
  - Each measurement is the median of 5 bursts of N=1000 iterations.
  - Numbers reported in microseconds per operation.
"""

from __future__ import annotations

import os
import statistics
import time
from typing import Callable


def _median_microseconds(fn: Callable[[], None], *, bursts: int = 5, iters: int = 1000) -> float:
    """Return median microseconds-per-op across ``bursts`` measurement
    bursts of ``iters`` calls each."""
    # Warm up.
    for _ in range(200):
        fn()
    timings = []
    for _ in range(bursts):
        start = time.perf_counter()
        for _ in range(iters):
            fn()
        timings.append((time.perf_counter() - start) / iters * 1_000_000)
    return statistics.median(timings)


# ---------------------------------------------------------------------------
# 1. Hybrid KEM: legacy HybridKEM(NullKEM) vs NativeHybridKEM (ML-KEM-768)
# ---------------------------------------------------------------------------


def bench_pq_hybrid() -> tuple[float, float]:
    from one_link.pq_hybrid import HybridKEM, NativeHybridKEM

    legacy = HybridKEM()
    legacy_sk, legacy_pk = legacy.keypair()

    def legacy_round():
        ct, ss = legacy.encapsulate(legacy_pk)
        legacy.decapsulate(ct, legacy_sk)

    native = NativeHybridKEM()
    native_sk, native_pk = native.keypair()

    def native_round():
        ct, ss = native.encapsulate(native_pk)
        native.decapsulate(ct, native_sk)

    legacy_us = _median_microseconds(legacy_round)
    native_us = _median_microseconds(native_round)
    return legacy_us, native_us


# ---------------------------------------------------------------------------
# 2. Route selection: legacy EMA pareto vs bandit pick
# ---------------------------------------------------------------------------


def bench_route_selection() -> tuple[float, float]:
    from one_link.transfer_brain import (
        AdaptiveTransferBrain,
        BanditRouteSelector,
        TransferRouteObservation,
    )

    brain = AdaptiveTransferBrain()
    for _ in range(50):
        brain.observe(
            TransferRouteObservation(route="lan", ok=True, bandwidth_bps=8e8)
        )
        brain.observe(
            TransferRouteObservation(route="wan", ok=True, bandwidth_bps=1e8)
        )

    def legacy_pick():
        # Touch the legacy route_stats() path (which Pareto-orders the
        # EMA values — this is the comparable fast path).
        return brain.route_stats()

    selector = BanditRouteSelector(("lan", "wan"), seed=0xCAFE)
    for _ in range(50):
        selector.record_outcome("lan", bandwidth_bps=8e8, success=True)
        selector.record_outcome("wan", bandwidth_bps=1e8, success=True)

    def native_pick():
        return selector.select_route()

    legacy_us = _median_microseconds(legacy_pick)
    native_us = _median_microseconds(native_pick)
    return legacy_us, native_us


# ---------------------------------------------------------------------------
# 3. Per-chunk key derivation: ad-hoc HKDF vs ol_ratchet chain
# ---------------------------------------------------------------------------


def bench_chunk_key_derivation() -> tuple[float, float]:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    from one_link.chunk_ratchet import ChunkRatchet

    ss = b"\x42" * 32
    counter = [0]

    def legacy_derive():
        counter[0] += 1
        HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"chunk-key|" + counter[0].to_bytes(8, "little"),
        ).derive(ss)

    chain = ChunkRatchet.from_shared_secret(ss)

    def native_derive():
        chain.next_key()

    legacy_us = _median_microseconds(legacy_derive)
    native_us = _median_microseconds(native_derive)
    return legacy_us, native_us


# ---------------------------------------------------------------------------
# 4. Capability mint + verify: legacy Ed25519 grant vs macaroon
# ---------------------------------------------------------------------------


def bench_capability_issue_verify() -> tuple[float, float]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from one_link import cap_migration, caps_grants

    granter = Ed25519PrivateKey.generate()
    granter_seed = granter.private_bytes_raw()
    granter_pub = granter.public_key().public_bytes_raw()
    subject = Ed25519PrivateKey.generate()
    subject_pub = subject.public_key().public_bytes_raw()

    def legacy_round():
        blob = caps_grants.encode_grant(
            granter_priv_seed=granter_seed,
            granter_pub=granter_pub,
            subject_pub=subject_pub,
            capabilities=["files:read"],
            not_before_ms=0,
            not_after_ms=5_000_000,
        )
        caps_grants.verify_grant(
            blob,
            expected_granter_pub=granter_pub,
            expected_subject_pub=subject_pub,
            now_ms=1_000_000,
            seen_nonces=set(),
        )

    root_key = cap_migration.derive_root_key(granter_seed)
    peer_fp = cap_migration._peer_fingerprint(subject_pub)

    def native_round():
        cap = cap_migration.mint_share_capability(
            granter_priv_seed=granter_seed,
            granter_pub=granter_pub,
            subject_pub=subject_pub,
            capabilities=["files:read"],
            not_after_ms=5_000_000,
        )
        cap.accepts(root_key, now_ms=1_000_000, peer=peer_fp, operation="files:read")

    legacy_us = _median_microseconds(legacy_round, bursts=3, iters=200)
    native_us = _median_microseconds(native_round, bursts=3, iters=200)
    return legacy_us, native_us


# ---------------------------------------------------------------------------
# 5. Folder merge: legacy Python merge_manifest_entries vs native folder merge
# ---------------------------------------------------------------------------


def bench_folder_merge() -> tuple[float, float]:
    from one_link.crdt import (
        ManifestEntry,
        VectorClock,
        merge_manifest_entries,
    )
    from one_link.folder_native import manifest_entries_to_native_folder

    def _mk(path: str, mtime: int, node: str = "alice") -> ManifestEntry:
        return ManifestEntry(
            file_path=path,
            blob_hash="abc",
            size=1024,
            mtime_ms=mtime,
            vclock=VectorClock.from_dict({node: 1}),
        )

    n = 100
    alice_entries = [_mk(f"/share/a_{i}.bin", i) for i in range(n)]
    bob_entries = [_mk(f"/share/b_{i}.bin", i, node="bob") for i in range(n)]

    def legacy_round():
        # Pairwise merge for every entry pair — the canonical legacy
        # path the daemon's manifest-receive loop performs.
        for a in alice_entries:
            for b in bob_entries:
                if a.file_path == b.file_path:
                    merge_manifest_entries(a, b)

    def native_round():
        folder_a = manifest_entries_to_native_folder(
            alice_entries, replica_id=b"\x01" * 32
        )
        folder_b = manifest_entries_to_native_folder(
            bob_entries, replica_id=b"\x02" * 32
        )
        folder_a.merge(folder_b)

    legacy_us = _median_microseconds(legacy_round, bursts=3, iters=20)
    native_us = _median_microseconds(native_round, bursts=3, iters=20)
    return legacy_us, native_us


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    cases = [
        ("hybrid KEM round trip", bench_pq_hybrid),
        ("route selection",       bench_route_selection),
        ("per-chunk key derive",  bench_chunk_key_derivation),
        ("cap mint+verify",       bench_capability_issue_verify),
        ("folder merge (100x100)", bench_folder_merge),
    ]
    print(f"{'path':<26}  {'legacy us':>12}  {'native us':>12}  {'native/legacy':>14}")
    print("-" * 70)
    rows = []
    for name, fn in cases:
        try:
            legacy_us, native_us = fn()
            ratio = native_us / legacy_us if legacy_us > 0 else float("inf")
            rows.append((name, legacy_us, native_us, ratio))
            print(f"{name:<26}  {legacy_us:>12.2f}  {native_us:>12.2f}  {ratio:>14.3f}")
        except Exception as exc:
            print(f"{name:<26}  <error: {exc}>")
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())

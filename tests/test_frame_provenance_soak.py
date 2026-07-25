"""Soak harness for FrameProvenance + ProvenanceWiring.

Mirrors the One Link convention from
``tests/test_native_pipeline_soak.py``: a randomised property-style
harness, parametrised by ``ONE_LINK_SOAK_ITERS`` (default 2000,
nightly 50000), that exercises the round-trip flow under varying
inputs.

Acceptance per the architecture doc (Tier α-pre):
    - 100% verify-success rate on honest signers across N iterations.
    -   0% verify-success rate on forged signers.
    - Median verify latency ≤ 5 ms (cheap; this is a property of
      the cryptography library + the canonical encoding).
    - No raised exceptions, no leaked threads, no store overflow
      beyond the configured cap.

These properties are the same shape as the existing soak harness
expectations: a budget on failures, a bound on latency, and an
invariant under random inputs.
"""

from __future__ import annotations

import os
import random
import statistics
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import blake3

from one_link.frame_provenance import (
    FrameKind,
    PathClass,
    RecordingState,
)
from one_link.identity import Identity
from one_link.provenance_wiring import (
    ProvenanceStore,
    build_provenance_for_file,
    handle_inbound_provenance,
    make_send_provenance_msg,
)


def _make_identity(seed: int) -> Identity:
    rng = random.Random(seed)
    # Deterministic-ish: build a private key from 32 random bytes
    # drawn from the seeded rng. We do this rather than
    # Ed25519PrivateKey.generate() so a single soak iteration is
    # reproducible from its seed.
    raw = bytes(rng.randint(0, 255) for _ in range(32))
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fp = blake3.blake3(pub_bytes).hexdigest()
    return Identity(
        private=priv,
        public=priv.public_key(),
        public_bytes=pub_bytes,
        fingerprint=fp,
        short_id=fp[:8],
        hostname=f"soak-{seed}",
    )


def _random_blob(rng: random.Random, max_size: int = 2048) -> bytes:
    size = rng.randint(64, max_size)
    return bytes(rng.randint(0, 255) for _ in range(size))


_FRAME_KINDS = list(FrameKind)
_PATH_CLASSES = list(PathClass)
_RECORDING_STATES = list(RecordingState)


@pytest.mark.parametrize(
    "iters",
    [int(os.getenv("ONE_LINK_SOAK_ITERS", "2000"))],
)
def test_provenance_round_trip_soak(iters: int) -> None:
    """For N random scenarios:

      1) Honest sender → honest receiver always verifies.
      2) Attacker masquerading as sender NEVER verifies.
      3) Median verify+sign latency stays under the budget.
      4) Store never overflows its cap.
      5) No raised exceptions across all iterations.

    Budget: 100% honest success rate (we require zero misses); 0%
    forgery success rate (we require zero false-accepts); median
    full round-trip latency ≤ 5 ms; no exceptions.
    """
    store = ProvenanceStore(max_entries=256)
    honest_failures: list[int] = []
    forgery_accepts: list[int] = []
    latencies_us: list[int] = []
    exceptions: list[BaseException] = []

    for i in range(iters):
        try:
            rng = random.Random(i)
            sender = _make_identity(i)
            # Attacker uses an independent seed so the keys are
            # cryptographically distinct.
            attacker = _make_identity(i + 10**9)

            blob = _random_blob(rng)
            # FILE_OFFER and provenance share the canonical whole-file
            # BLAKE3-256 identifier; SHA-256 here would exercise only the
            # intentional cross-blob rejection path.
            blob_hex = blake3.blake3(blob).hexdigest()

            # Pick a random combination of frame kind / path / recording
            # so we sweep the state space, not just one combination.
            frame_kind = rng.choice(_FRAME_KINDS)
            path_class = rng.choice(_PATH_CLASSES)
            recording_state = rng.choice(_RECORDING_STATES)
            confidence = rng.random()

            # ─── Honest path ───────────────────────────────────────
            t0 = time.perf_counter_ns()
            p = build_provenance_for_file(
                identity=sender,
                file_bytes=blob,
                path_class=path_class,
                recording_state=recording_state,
                frame_kind=frame_kind,
                produce_confidence=confidence,
            )
            msg = make_send_provenance_msg(
                sender_short_id=sender.short_id,
                blob_hex=blob_hex,
                provenance=p,
            )
            parsed, verified = handle_inbound_provenance(
                msg=msg,
                peer_fp=sender.fingerprint,
                sender_public_bytes=sender.public_bytes,
                store=store,
            )
            t1 = time.perf_counter_ns()
            latencies_us.append((t1 - t0) // 1000)

            if not verified or parsed is None:
                honest_failures.append(i)
                continue

            # ─── Forgery path ──────────────────────────────────────
            fake_p = build_provenance_for_file(
                identity=attacker,
                file_bytes=blob,
                path_class=path_class,
                recording_state=recording_state,
                frame_kind=frame_kind,
                produce_confidence=confidence,
            )
            fake_msg = make_send_provenance_msg(
                # Attacker spoofs sender's short_id in the envelope:
                sender_short_id=sender.short_id,
                blob_hex=blob_hex,
                provenance=fake_p,
            )
            # Receiver verifies against the SENDER's pinned key (the
            # daemon resolves this from peer_fp → master_vk store).
            fake_parsed, fake_verified = handle_inbound_provenance(
                msg=fake_msg,
                peer_fp=sender.fingerprint,
                sender_public_bytes=sender.public_bytes,
                store=store,
            )
            if fake_verified:
                forgery_accepts.append(i)
        except BaseException as e:
            exceptions.append(e)

    # ────────────────────────────────────────────────────────────────
    # Acceptance gates
    # ────────────────────────────────────────────────────────────────

    assert not exceptions, (
        f"unexpected exceptions during soak: "
        f"{len(exceptions)}/{iters}: first={exceptions[0]!r}"
    )

    # 1) Honest path: 100% verify success.
    assert not honest_failures, (
        f"honest verify failed in {len(honest_failures)}/{iters} iters: "
        f"first={honest_failures[:10]}"
    )

    # 2) Forgery path: 0% accept rate.
    assert not forgery_accepts, (
        f"FORGERY ACCEPTED in {len(forgery_accepts)}/{iters} iters: "
        f"first={forgery_accepts[:10]}"
    )

    # 3) Latency budget. Median is the right summary statistic —
    # tails on CI can be wild. Allow 5 ms median (10x headroom over
    # local-laptop measurements; CPython Ed25519 sign+verify is
    # well under 1 ms each).
    median_us = statistics.median(latencies_us)
    assert median_us < 5_000, (
        f"median round-trip latency too high: {median_us} us "
        f"(budget 5000 us). Distribution: "
        f"p50={median_us}, p90={statistics.quantiles(latencies_us, n=10)[-1]}"
    )

    # 4) Store didn't blow its cap.
    assert len(store) <= 256, f"store overflowed cap: {len(store)}"

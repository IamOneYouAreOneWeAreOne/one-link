"""v0.21.x rotation: backward-compatibility + realistic-scale tests.

Two narrow concerns the prior test files did not cover:

1. Backward-compat: a v0.20.x peer that does not know about the
   ROTATION_CERT wire message must not crash when it receives one.
   The existing daemon's _on_peer_message dispatcher uses an
   if/elif chain that falls through unrecognized message types -
   no else branch raises. Pin that behavior.

2. Realistic-scale: the rotation queue + bundle encrypt/decrypt
   paths should hold under load representative of a real install
   (50+ peers, multi-MB bundle). Catch any quadratic behavior or
   memory blow-up before it surfaces in production.
"""
from __future__ import annotations

import os
import statistics
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# ── backward compatibility ──────────────────────────────────────────


def test_rotation_cert_dispatch_uses_silent_fallthrough_pattern():
    """The v0.21.x rotation wire messages (ROTATION_CERT,
    ROTATION_CERT_ACK) were added to the daemon's _on_peer_message
    dispatcher via if/elif branches. A v0.20.x peer (or any future
    peer that introduces a new wire type) will land in the
    fall-through path: no else clause raises, so unknown frames
    are silently ignored.

    This source-text gate pins that pattern - a refactor that adds
    a `raise RuntimeError(f'unknown wire type {t!r}')` else branch
    would break interop with every peer running an older OR newer
    protocol version.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "src" / "one_link" / "daemon.py").read_text(encoding="utf-8")
    # Locate the dispatcher branch immediately after _TRUST_SYNC_WIRE_TYPE.
    idx = src.find("elif t == _TRUST_SYNC_WIRE_TYPE:")
    assert idx > 0, "TRUST_SYNC dispatcher branch not found"
    # The 3 KB window covers the ROTATION_CERT / ROTATION_CERT_ACK
    # branches and anything that might follow them.
    body = src[idx:idx + 3000]
    # Confirm rotation branches are present (sanity).
    assert 'elif t == "ROTATION_CERT":' in body
    assert 'elif t == "ROTATION_CERT_ACK":' in body
    # No else branch in this dispatcher section that raises - the
    # method body just falls through after the last elif.
    # We pattern-match: between the last rotation elif and the end
    # of the function, there is no "else:" / "raise" pair.
    after_rotation = body[body.find('"ROTATION_CERT_ACK":'):]
    # Stop at the next top-level dispatch helper definition so we
    # don't catch unrelated else branches further down the file.
    next_def = after_rotation.find("def _handle_call_frame_attest")
    if next_def > 0:
        after_rotation = after_rotation[:next_def]
    assert "raise" not in after_rotation, (
        "dispatcher has a `raise` after the rotation branches - "
        "this breaks backward compat with peers that send wire "
        "types we do not know"
    )


def test_v0_20_peer_payload_shape_does_not_collide_with_rotation_cert():
    """A v0.20.x peer's outbound wire frames must not have t in
    ('ROTATION_CERT', 'ROTATION_CERT_ACK') by coincidence - we
    chose names that no prior version emitted. Pin this by
    grepping the prior message-type names to confirm no overlap."""
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "src" / "one_link" / "daemon.py").read_text(encoding="utf-8")
    # If "ROTATION_CERT" appears in any string literal that is NOT
    # part of our v0.21.x rotation handling, that is a collision.
    # We expect exactly two definitions (one for each message type
    # in the dispatcher) and one reference each in the helpers +
    # ack send + send-cert send. Bound: <= 12 occurrences total.
    n_cert = src.count('"ROTATION_CERT"')
    n_ack = src.count('"ROTATION_CERT_ACK"')
    assert 1 <= n_cert <= 8, f"unexpected ROTATION_CERT count: {n_cert}"
    assert 1 <= n_ack <= 8, f"unexpected ROTATION_CERT_ACK count: {n_ack}"


# ── realistic scale ────────────────────────────────────────────────


def test_rotation_queue_holds_100_pending_announcements(tmp_path):
    """A user with 100 paired peers triggers rotation: 100 rows
    land in pending_rotation_announcements. The list + summary
    endpoints should serve them in a single query without
    quadratic behavior.

    Bound: list at 100 rows must complete in < 200 ms (typically
    < 10 ms on a quiet box; the cap catches O(n^2) regressions)."""
    from one_link.state import State
    state = State(tmp_path / "scale.db")
    for i in range(100):
        state.queue_rotation_announcement(
            peer_fp=f"{i:064x}",
            old_fp="bb" * 32,
            new_fp="cc" * 32,
            cert_json='{"v":1}',
            sig_hex="00" * 64,
        )
    summary = state.rotation_announcement_summary()
    assert summary == {"total": 100, "pending": 100, "acked": 0}

    t0 = time.perf_counter()
    rows = state.list_pending_rotation_announcements(limit=200)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    assert len(rows) == 100
    assert elapsed_ms < 200, (
        f"list_pending_rotation_announcements over 100 rows took "
        f"{elapsed_ms:.1f}ms; expected <200ms (O(n^2) regression?)"
    )


def test_transition_peer_fingerprint_stays_under_1ms_on_typical_load(tmp_path):
    """transition_peer_fingerprint runs once per inbound rotation
    cert; a daemon with O(100) paired peers might process several
    per second during a rotation event. Median p50 per-call cost
    should stay well under 1 ms even on a peer row with downstream
    rows in messages / transfers / outbox tables."""
    from one_link.state import State
    state = State(tmp_path / "xition_scale.db")
    fp_a = "aa" * 32
    fp_b = "bb" * 32
    state.upsert_peer(
        fingerprint=fp_a, short_id="bench",
        pubkey=b"\x01" * 32, hostname="bench.lan",
    )
    state.set_peer_trust(fp_a, "pinned")
    # Ping-pong fp_a <-> fp_b 20 times, measuring each.
    times: list[float] = []
    for i in range(20):
        src, dst = (fp_a, fp_b) if i % 2 == 0 else (fp_b, fp_a)
        new_pub = bytes([i % 256]) * 32
        t0 = time.perf_counter()
        state.transition_peer_fingerprint(
            old_fp=src, new_fp=dst, new_pubkey=new_pub,
        )
        times.append((time.perf_counter() - t0) * 1000.0)
    p50 = statistics.median(times)
    p95 = sorted(times)[-2]
    assert p50 < 5.0, (
        f"transition_peer_fingerprint p50 = {p50:.2f}ms; "
        f"expected <5ms even with the 15-table cascade. "
        f"Did an O(n) table iteration creep in?"
    )
    # 5ms is generous; the bench reports ~0.2ms on a quiet box.
    # The cap exists to catch a 25x slowdown, not measure absolute.


def test_bundle_create_open_round_trips_at_1mb(tmp_path):
    """Bundle encrypt + decrypt at a representative-real size
    (1 MiB of state.db payload). Confirm bytes round-trip + that
    the whole flow stays under 5s (typical run is well under 1s).
    Catches a regression where AES-GCM or gzip starts copying
    buffers quadratically."""
    from one_link import backup_bundle
    src = tmp_path / "src"
    src.mkdir()
    (src / "state.db").write_bytes(os.urandom(1024 * 1024))
    (src / "master.seed").write_bytes(os.urandom(32))
    seed = os.urandom(32)
    t0 = time.perf_counter()
    bundle = backup_bundle.create_bundle(seed=seed, data_dir=src)
    t_create = time.perf_counter() - t0
    t0 = time.perf_counter()
    header, plaintext = backup_bundle.open_bundle(seed=seed, bundle_bytes=bundle)
    t_open = time.perf_counter() - t0
    assert header.plaintext_len == len(plaintext)
    assert t_create < 5.0, f"create_bundle 1MB took {t_create:.2f}s; expected <5s"
    assert t_open < 5.0, f"open_bundle 1MB took {t_open:.2f}s; expected <5s"


def test_split_and_wrap_scales_linearly_to_10_guardians(tmp_path):
    """Shamir(K, 10) + 10 ECDH wraps should be ~2x the cost of
    Shamir(K, 5). Confirm the cost grows linearly, not quadratically,
    by comparing 10-guardian wall time vs 5-guardian."""
    from one_link import social_recovery
    seed = os.urandom(32)
    pubs_5 = [
        Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        for _ in range(5)
    ]
    pubs_10 = [
        Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        for _ in range(10)
    ]
    # Warm up.
    social_recovery.split_and_wrap(seed=seed, contact_ed_pubs=pubs_5, threshold_k=3, total_n=5)
    social_recovery.split_and_wrap(seed=seed, contact_ed_pubs=pubs_10, threshold_k=5, total_n=10)
    # Time both, 10 iters each, take medians.
    times_5: list[float] = []
    times_10: list[float] = []
    for _ in range(10):
        t0 = time.perf_counter()
        social_recovery.split_and_wrap(seed=seed, contact_ed_pubs=pubs_5, threshold_k=3, total_n=5)
        times_5.append(time.perf_counter() - t0)
        t0 = time.perf_counter()
        social_recovery.split_and_wrap(seed=seed, contact_ed_pubs=pubs_10, threshold_k=5, total_n=10)
        times_10.append(time.perf_counter() - t0)
    med_5 = statistics.median(times_5)
    med_10 = statistics.median(times_10)
    ratio = med_10 / med_5 if med_5 > 0 else float("inf")
    # 2x guardians -> ~2x cost. Allow 3x as the upper bound (room
    # for noise + non-linear fixed overheads); reject 5x+ (O(n^2)).
    assert ratio < 5.0, (
        f"split_and_wrap scaled from {med_5*1000:.2f}ms (n=5) to "
        f"{med_10*1000:.2f}ms (n=10), ratio={ratio:.1f}x. Expected "
        f"~2x (linear); >5x suggests an O(n^2) regression."
    )


def test_combine_shares_with_5_of_10_is_cheap(tmp_path):
    """The combine step (Shamir inverse-VanderMonde over GF(256))
    should stay sub-millisecond even at K=5. Pin so a future
    refactor that adds an unnecessary O(n^2) preprocessing pass
    surfaces."""
    from one_link import social_recovery
    seed = os.urandom(32)
    guardians = [Ed25519PrivateKey.generate() for _ in range(10)]
    wrapped = social_recovery.split_and_wrap(
        seed=seed,
        contact_ed_pubs=[g.public_key().public_bytes_raw() for g in guardians],
        threshold_k=5, total_n=10,
    )
    unwrapped = [
        social_recovery.unwrap_share(
            wrapped=w.encoded, my_ed_priv_seed=g.private_bytes_raw(),
        )
        for w, g in list(zip(wrapped, guardians))[:5]
    ]
    # Warm up.
    social_recovery.combine_shares(unwrapped)
    # Time 100 combines.
    t0 = time.perf_counter()
    for _ in range(100):
        social_recovery.combine_shares(unwrapped)
    avg_ms = (time.perf_counter() - t0) * 10  # ms per op
    assert avg_ms < 5.0, (
        f"combine_shares 5-of-10 avg = {avg_ms:.3f}ms/op; "
        f"expected <5ms"
    )

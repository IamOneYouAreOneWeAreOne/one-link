"""Acceptance tests for sphinx_native (Phase F3.5 Sphinx Coherence)."""

from __future__ import annotations

import os

import pytest


def _native_available() -> bool:
    try:
        from one_link_native import sphinx  # noqa: F401

        return True
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native.sphinx not installed",
)


# ── Module / constants ────────────────────────────────────────────


def test_module_imports():
    from one_link import sphinx_native as sph

    assert sph.HAS_NATIVE is True
    assert sph.HOP_ID_LEN == 32
    assert sph.MAX_HOPS == 5
    assert sph.SPHINX_MAX_USER_PAYLOAD > 0
    assert sph.SPHINX_PACKET_LEN > 0
    assert sph.PQ_SPHINX_PACKET_LEN > sph.SPHINX_PACKET_LEN  # PQ has + ML-KEM ct


# ── Keypair generation ────────────────────────────────────────────


def test_generate_keypair_lengths():
    from one_link import sphinx_native as sph

    sk, pk = sph.generate_keypair()
    assert len(sk) == 32
    assert len(pk) == 32


def test_keypair_pk_matches_derive():
    from one_link import sphinx_native as sph

    sk, pk = sph.generate_keypair()
    pk2 = sph.derive_pubkey_from_scalar(sk)
    assert pk == pk2


def test_derive_pubkey_validates_length():
    from one_link import sphinx_native as sph

    with pytest.raises(ValueError, match="32 bytes"):
        sph.derive_pubkey_from_scalar(b"too short")


def test_generate_pq_keypair_lengths():
    from one_link import sphinx_native as sph

    dk, ek = sph.generate_pq_keypair()
    assert len(dk) == 2400  # ML-KEM-768 decap key
    assert len(ek) == sph.ML_KEM_EK_LEN
    assert len(ek) == 1184


# ── Standard Sphinx build + peel ──────────────────────────────────


def test_one_hop_round_trip():
    from one_link import sphinx_native as sph

    dest_sk, dest_pk = sph.generate_keypair()
    dest_id = bytes([0x11] * sph.HOP_ID_LEN)
    eph_sk, _ = sph.generate_keypair()
    packet = sph.build_sphinx(eph_sk, [(dest_id, dest_pk)], b"hello")
    assert len(packet) == sph.SPHINX_PACKET_LEN
    outcome, next_hop, payload = sph.peel_sphinx(dest_sk, packet)
    assert outcome == "deliver"
    assert next_hop == b""
    assert payload == b"hello"


def test_three_hop_round_trip():
    from one_link import sphinx_native as sph

    r1_sk, r1_pk = sph.generate_keypair()
    r2_sk, r2_pk = sph.generate_keypair()
    dest_sk, dest_pk = sph.generate_keypair()
    r1_id = bytes([0x21] * sph.HOP_ID_LEN)
    r2_id = bytes([0x22] * sph.HOP_ID_LEN)
    dest_id = bytes([0x23] * sph.HOP_ID_LEN)
    eph_sk, _ = sph.generate_keypair()
    circuit = [(r1_id, r1_pk), (r2_id, r2_pk), (dest_id, dest_pk)]
    packet = sph.build_sphinx(eph_sk, circuit, b"three-hop sphinx")

    # r1 → r2
    outcome, nh, inner = sph.peel_sphinx(r1_sk, packet)
    assert outcome == "forward"
    assert nh == r2_id
    assert len(inner) == sph.SPHINX_PACKET_LEN  # fixed size at every hop

    # r2 → dest
    outcome, nh, inner = sph.peel_sphinx(r2_sk, inner)
    assert outcome == "forward"
    assert nh == dest_id
    assert len(inner) == sph.SPHINX_PACKET_LEN

    # dest delivers
    outcome, nh, payload = sph.peel_sphinx(dest_sk, inner)
    assert outcome == "deliver"
    assert nh == b""
    assert payload == b"three-hop sphinx"


def test_alpha_changes_at_each_hop():
    """Empirical hop-blindness: alpha (bytes 1..33) changes at every hop."""
    from one_link import sphinx_native as sph

    r1_sk, r1_pk = sph.generate_keypair()
    r2_sk, r2_pk = sph.generate_keypair()
    _dest_sk, dest_pk = sph.generate_keypair()
    r1_id = bytes([0x31] * sph.HOP_ID_LEN)
    r2_id = bytes([0x32] * sph.HOP_ID_LEN)
    dest_id = bytes([0x33] * sph.HOP_ID_LEN)
    eph_sk, _ = sph.generate_keypair()
    p0 = sph.build_sphinx(
        eph_sk,
        [(r1_id, r1_pk), (r2_id, r2_pk), (dest_id, dest_pk)],
        b"x",
    )
    alpha_0 = p0[1:33]
    _, _, p1 = sph.peel_sphinx(r1_sk, p0)
    alpha_1 = p1[1:33]
    _, _, p2 = sph.peel_sphinx(r2_sk, p1)
    alpha_2 = p2[1:33]
    assert alpha_0 != alpha_1
    assert alpha_1 != alpha_2
    assert alpha_0 != alpha_2


def test_wrong_relay_key_fails():
    from one_link import sphinx_native as sph

    _dest_sk, dest_pk = sph.generate_keypair()
    eph_sk, _ = sph.generate_keypair()
    dest_id = bytes([0x41] * sph.HOP_ID_LEN)
    packet = sph.build_sphinx(eph_sk, [(dest_id, dest_pk)], b"x")
    wrong_sk = bytes([0x99] * 32)
    with pytest.raises(ValueError):
        sph.peel_sphinx(wrong_sk, packet)


def test_tampered_packet_rejected():
    from one_link import sphinx_native as sph

    dest_sk, dest_pk = sph.generate_keypair()
    eph_sk, _ = sph.generate_keypair()
    dest_id = bytes([0x51] * sph.HOP_ID_LEN)
    packet = bytearray(sph.build_sphinx(eph_sk, [(dest_id, dest_pk)], b"x"))
    packet[100] ^= 0x01  # flip a byte in the header region
    with pytest.raises(ValueError):
        sph.peel_sphinx(dest_sk, bytes(packet))


def test_empty_payload_works():
    from one_link import sphinx_native as sph

    dest_sk, dest_pk = sph.generate_keypair()
    eph_sk, _ = sph.generate_keypair()
    dest_id = bytes([0x61] * sph.HOP_ID_LEN)
    packet = sph.build_sphinx(eph_sk, [(dest_id, dest_pk)], b"")
    outcome, _, payload = sph.peel_sphinx(dest_sk, packet)
    assert outcome == "deliver"
    assert payload == b""


def test_payload_oversize_rejected():
    from one_link import sphinx_native as sph

    _, dest_pk = sph.generate_keypair()
    eph_sk, _ = sph.generate_keypair()
    dest_id = bytes([0x71] * sph.HOP_ID_LEN)
    huge = b"\x00" * (sph.SPHINX_MAX_USER_PAYLOAD + 1)
    with pytest.raises(ValueError, match="max"):
        sph.build_sphinx(eph_sk, [(dest_id, dest_pk)], huge)


def test_too_many_hops_rejected():
    from one_link import sphinx_native as sph

    eph_sk, _ = sph.generate_keypair()
    circuit = []
    for i in range(sph.MAX_HOPS + 1):
        sk, pk = sph.generate_keypair()
        circuit.append((bytes([i + 1] * sph.HOP_ID_LEN), pk))
    with pytest.raises(ValueError, match="max"):
        sph.build_sphinx(eph_sk, circuit, b"x")


# ── PQ-hybrid Sphinx ──────────────────────────────────────────────


def test_pq_one_hop_round_trip():
    from one_link import sphinx_native as sph

    entry_x_sk, entry_x_pk = sph.generate_keypair()
    entry_pq_dk, entry_pq_ek = sph.generate_pq_keypair()
    entry_id = bytes([0x81] * sph.HOP_ID_LEN)
    eph_sk, _ = sph.generate_keypair()
    packet = sph.build_pq_sphinx(
        eph_sk,
        [(entry_id, entry_x_pk, entry_pq_ek)],
        b"pq-hybrid",
    )
    assert len(packet) == sph.PQ_SPHINX_PACKET_LEN
    outcome, nh, payload = sph.peel_pq_sphinx_entry(
        entry_x_sk, entry_pq_dk, packet
    )
    assert outcome == "deliver"
    assert nh == b""
    assert payload == b"pq-hybrid"


def test_pq_three_hop_round_trip():
    from one_link import sphinx_native as sph

    entry_x_sk, entry_x_pk = sph.generate_keypair()
    entry_pq_dk, entry_pq_ek = sph.generate_pq_keypair()
    mid_x_sk, mid_x_pk = sph.generate_keypair()
    dest_x_sk, dest_x_pk = sph.generate_keypair()
    entry_id = bytes([0x91] * sph.HOP_ID_LEN)
    mid_id = bytes([0x92] * sph.HOP_ID_LEN)
    dest_id = bytes([0x93] * sph.HOP_ID_LEN)
    eph_sk, _ = sph.generate_keypair()
    circuit = [
        (entry_id, entry_x_pk, entry_pq_ek),  # entry has PQ pubkey
        (mid_id, mid_x_pk, None),              # intermediate
        (dest_id, dest_x_pk, None),            # destination
    ]
    packet = sph.build_pq_sphinx(eph_sk, circuit, b"pq three-hop")

    # Entry peels with hybrid.
    outcome, nh, inner = sph.peel_pq_sphinx_entry(entry_x_sk, entry_pq_dk, packet)
    assert outcome == "forward"
    assert nh == mid_id

    # Mid peels classical.
    outcome, nh, inner = sph.peel_pq_sphinx_intermediate(mid_x_sk, inner)
    assert outcome == "forward"
    assert nh == dest_id

    # Dest peels classical.
    outcome, nh, payload = sph.peel_pq_sphinx_intermediate(dest_x_sk, inner)
    assert outcome == "deliver"
    assert payload == b"pq three-hop"


def test_pq_wrong_decap_key_fails():
    from one_link import sphinx_native as sph

    entry_x_sk, entry_x_pk = sph.generate_keypair()
    _, entry_pq_ek = sph.generate_pq_keypair()
    wrong_pq_dk, _ = sph.generate_pq_keypair()
    entry_id = bytes([0xA1] * sph.HOP_ID_LEN)
    eph_sk, _ = sph.generate_keypair()
    packet = sph.build_pq_sphinx(
        eph_sk, [(entry_id, entry_x_pk, entry_pq_ek)], b"x"
    )
    with pytest.raises(ValueError):
        sph.peel_pq_sphinx_entry(entry_x_sk, wrong_pq_dk, packet)


def test_pq_intermediate_cannot_be_entry():
    """Catches a daemon bug: intermediate hop tries entry-mode peel."""
    from one_link import sphinx_native as sph

    entry_x_sk, entry_x_pk = sph.generate_keypair()
    entry_pq_dk, entry_pq_ek = sph.generate_pq_keypair()
    mid_x_sk, mid_x_pk = sph.generate_keypair()
    entry_id = bytes([0xB1] * sph.HOP_ID_LEN)
    mid_id = bytes([0xB2] * sph.HOP_ID_LEN)
    eph_sk, _ = sph.generate_keypair()
    packet = sph.build_pq_sphinx(
        eph_sk,
        [(entry_id, entry_x_pk, entry_pq_ek), (mid_id, mid_x_pk, None)],
        b"x",
    )
    outcome, _, inner = sph.peel_pq_sphinx_entry(entry_x_sk, entry_pq_dk, packet)
    assert outcome == "forward"
    # Now mid tries entry-mode peel with SOME PQ decap key.
    fake_dk, _ = sph.generate_pq_keypair()
    with pytest.raises(ValueError):
        sph.peel_pq_sphinx_entry(mid_x_sk, fake_dk, inner)


def test_pq_first_hop_without_pq_pk_rejected():
    from one_link import sphinx_native as sph

    _, entry_x_pk = sph.generate_keypair()
    entry_id = bytes([0xC1] * sph.HOP_ID_LEN)
    eph_sk, _ = sph.generate_keypair()
    with pytest.raises(ValueError, match="first hop must have a PQ pubkey"):
        sph.build_pq_sphinx(eph_sk, [(entry_id, entry_x_pk, None)], b"x")


# ── Hop-blindness empirical ───────────────────────────────────────


def test_alpha_pairwise_distinct_across_circuits():
    """50 random 3-hop circuits, alpha at each hop is unique."""
    from one_link import sphinx_native as sph

    alphas = set()
    for _ in range(50):
        r1_sk, r1_pk = sph.generate_keypair()
        r2_sk, r2_pk = sph.generate_keypair()
        _, dest_pk = sph.generate_keypair()
        eph_sk, _ = sph.generate_keypair()
        circuit = [
            (os.urandom(sph.HOP_ID_LEN), r1_pk),
            (os.urandom(sph.HOP_ID_LEN), r2_pk),
            (os.urandom(sph.HOP_ID_LEN), dest_pk),
        ]
        p0 = sph.build_sphinx(eph_sk, circuit, b"x")
        alphas.add(p0[1:33])
        _, _, p1 = sph.peel_sphinx(r1_sk, p0)
        alphas.add(p1[1:33])
        _, _, p2 = sph.peel_sphinx(r2_sk, p1)
        alphas.add(p2[1:33])
    # 50 circuits * 3 alphas each = 150 distinct values.
    assert len(alphas) == 150


# ── Packet size invariance ────────────────────────────────────────


def test_packet_size_constant_for_all_payload_sizes():
    """Sphinx packet is fixed-size regardless of user payload size."""
    from one_link import sphinx_native as sph

    _, dest_pk = sph.generate_keypair()
    eph_sk, _ = sph.generate_keypair()
    dest_id = bytes([0xD1] * sph.HOP_ID_LEN)
    for payload_len in [0, 1, 8, 64, 256, 512, sph.SPHINX_MAX_USER_PAYLOAD]:
        packet = sph.build_sphinx(
            eph_sk, [(dest_id, dest_pk)], b"\x00" * payload_len
        )
        assert len(packet) == sph.SPHINX_PACKET_LEN


# ── Cover traffic (row 6) ─────────────────────────────────────────


def test_cover_module_constants():
    from one_link import sphinx_native as sph

    assert sph.COVER_SENTINEL == b"OL-COVER"
    assert sph.COVER_PAYLOAD_MIN == 64
    assert sph.COVER_DEFAULT_RATE_HZ == 1.0


def test_build_cover_packet_round_trip():
    """Audit M4 May 2026 — `peel_sphinx` now returns kind=="cover"
    directly when the destination's MAC over the cover-trailer
    verifies. The legacy "deliver"+plaintext-sentinel path is gone
    (forgeable; replaced by the authenticated trailer)."""
    from one_link import sphinx_native as sph

    dest_sk, dest_pk = sph.generate_keypair()
    dest_id = bytes([0xE1] * sph.HOP_ID_LEN)
    eph_sk, _ = sph.generate_keypair()
    packet = sph.build_cover_packet(eph_sk, [(dest_id, dest_pk)], 128)
    assert len(packet) == sph.SPHINX_PACKET_LEN  # same size as real
    outcome, _, payload = sph.peel_sphinx(dest_sk, packet)
    assert outcome == "cover", (
        f"expected M4-authenticated cover peel outcome, got {outcome!r}"
    )
    # Cover variant returns an empty payload — the destination
    # silently drops without exposing trailer bytes to callers.
    assert payload == b""


def test_cover_packet_encoded_length_matches_real_packet():
    from one_link import sphinx_native as sph

    _, dest_pk = sph.generate_keypair()
    eph_sk, _ = sph.generate_keypair()
    dest_id = bytes([0xE2] * sph.HOP_ID_LEN)
    cover = sph.build_cover_packet(eph_sk, [(dest_id, dest_pk)], 256)
    real = sph.build_sphinx(eph_sk, [(dest_id, dest_pk)], b"real payload here")
    assert len(cover) == len(real) == sph.SPHINX_PACKET_LEN


def test_is_cover_payload_detection():
    from one_link import sphinx_native as sph

    assert sph.is_cover_payload(b"OL-COVER" + b"anything else")
    assert sph.is_cover_payload(b"OL-COVER")
    assert not sph.is_cover_payload(b"OL-REAL")
    assert not sph.is_cover_payload(b"hello world")
    assert not sph.is_cover_payload(b"")


def test_cover_packet_below_min_rejected():
    from one_link import sphinx_native as sph

    _, dest_pk = sph.generate_keypair()
    eph_sk, _ = sph.generate_keypair()
    dest_id = bytes([0xE3] * sph.HOP_ID_LEN)
    with pytest.raises(ValueError, match=r"cover_size must be >="):
        sph.build_cover_packet(eph_sk, [(dest_id, dest_pk)], sph.COVER_PAYLOAD_MIN - 1)


def test_cover_scheduler_basic():
    from one_link import sphinx_native as sph

    sched = sph.CoverScheduler(rate_hz=1.0, seed=bytes(32))
    waits = [sched.next_wait_ms() for _ in range(10)]
    assert all(w >= 0 for w in waits)
    assert sched.rate_hz() == 1.0


def test_cover_scheduler_deterministic_per_seed():
    from one_link import sphinx_native as sph

    s1 = sph.CoverScheduler(1.0, bytes([0x42] * 32))
    s2 = sph.CoverScheduler(1.0, bytes([0x42] * 32))
    for _ in range(20):
        assert s1.next_wait_ms() == s2.next_wait_ms()


def test_cover_scheduler_rate_validation():
    from one_link import sphinx_native as sph

    with pytest.raises(ValueError, match="positive"):
        sph.CoverScheduler(rate_hz=0.0, seed=bytes(32))
    with pytest.raises(ValueError, match="positive"):
        sph.CoverScheduler(rate_hz=-1.0, seed=bytes(32))
    with pytest.raises(ValueError, match="32 bytes"):
        sph.CoverScheduler(rate_hz=1.0, seed=b"short")


def test_cover_scheduler_mean_matches_poisson():
    """Empirical: mean inter-arrival ≈ 1/λ for Poisson process."""
    from one_link import sphinx_native as sph

    sched = sph.CoverScheduler(rate_hz=10.0, seed=bytes([0x77] * 32))
    samples = [sched.next_wait_ms() for _ in range(5000)]
    mean_ms = sum(samples) / len(samples)
    # 10 Hz → 100 ms mean.
    assert 85 < mean_ms < 115, f"mean = {mean_ms} ms (expected ~100)"


def test_cover_scheduler_rate_update():
    from one_link import sphinx_native as sph

    sched = sph.CoverScheduler(1.0, bytes(32))
    assert sched.rate_hz() == 1.0
    sched.set_rate_hz(5.0)
    assert sched.rate_hz() == 5.0
    with pytest.raises(ValueError):
        sched.set_rate_hz(0.0)


# ── RateEqualizer ─────────────────────────────────────────────────


def test_rate_equalizer_fresh_starts_at_full_cover():
    from one_link import sphinx_native as sph

    eq = sph.RateEqualizer(target_total_hz=5.0)
    assert eq.target_total_hz() == 5.0
    assert eq.current_cover_rate() == 5.0
    assert eq.observed_real_rate() == 0.0


def test_rate_equalizer_real_emissions_reduce_cover():
    from one_link import sphinx_native as sph

    eq = sph.RateEqualizer(target_total_hz=5.0)
    # 1 Hz real (1000 ms gaps).
    for i in range(20):
        eq.observe_real_emission(i * 1000)
    real = eq.observed_real_rate()
    cover = eq.current_cover_rate()
    assert real > 0.5  # smoothed toward 1 Hz
    assert cover < 5.0  # reduced from full

def test_rate_equalizer_burst_clamps_cover_to_zero():
    from one_link import sphinx_native as sph

    eq = sph.RateEqualizer(target_total_hz=1.0)
    eq.set_half_life_sec(5.0)
    # 10 Hz burst — way over target.
    for i in range(30):
        eq.observe_real_emission(i * 100)
    assert eq.observed_real_rate() > 1.0
    assert eq.current_cover_rate() == 0.0


def test_rate_equalizer_validates_target():
    from one_link import sphinx_native as sph

    with pytest.raises(ValueError, match="positive"):
        sph.RateEqualizer(target_total_hz=0.0)
    with pytest.raises(ValueError, match="positive"):
        sph.RateEqualizer(target_total_hz=-1.0)


def test_rate_equalizer_set_half_life_validates():
    from one_link import sphinx_native as sph

    eq = sph.RateEqualizer(target_total_hz=1.0)
    eq.set_half_life_sec(10.0)
    with pytest.raises(ValueError, match="positive"):
        eq.set_half_life_sec(0.0)

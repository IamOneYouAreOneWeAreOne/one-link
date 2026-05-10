"""v0.20.7 — Verifiable Random Function on Ed25519.

A VRF gives unbiased pseudorandom output with a publicly-verifiable
proof. Use cases in One Link:
  - Unbiased DHT lookup-routing (mitigates eclipse attacks)
  - Fair onion-relay rotation (auditor verifies you didn't pre-pick)
  - Verifiable random sampling

These tests pin:
  - prove + verify round-trip for known inputs
  - Output is deterministic per (priv_seed, input)
  - Different inputs produce different outputs (avalanche)
  - Different priv_seeds produce different outputs for same input
  - verify rejects wrong public key, wrong output, wrong proof
  - verify rejects tampered output / proof bytes
  - public_key_from_priv_seed deterministic
"""
from __future__ import annotations

import os

import pytest

from one_link import vrf


def _gen_seed():
    return os.urandom(32)


def test_prove_verify_round_trip():
    seed = _gen_seed()
    pub = vrf.public_key_from_priv_seed(seed)
    inp = b"some input bytes"
    out = vrf.prove(priv_seed=seed, input_bytes=inp)
    assert len(out.output) == 32
    assert len(out.proof) == 96
    assert vrf.verify(
        public_key=pub, input_bytes=inp,
        output=out.output, proof=out.proof,
    )


def test_output_deterministic():
    seed = _gen_seed()
    inp = b"x"
    a = vrf.prove(priv_seed=seed, input_bytes=inp)
    b = vrf.prove(priv_seed=seed, input_bytes=inp)
    assert a.output == b.output


def test_proof_deterministic():
    """Same (seed, input) → same proof. The nonce derivation uses
    a deterministic hash of (priv_seed || input) per RFC 9381 §5.1
    so VRFs don't need a fresh randomness source — and aren't
    vulnerable to nonce reuse the way ECDSA is."""
    seed = _gen_seed()
    inp = b"deterministic-input"
    a = vrf.prove(priv_seed=seed, input_bytes=inp)
    b = vrf.prove(priv_seed=seed, input_bytes=inp)
    assert a.proof == b.proof


def test_output_avalanche_on_input():
    seed = _gen_seed()
    a = vrf.prove(priv_seed=seed, input_bytes=b"input-A")
    b = vrf.prove(priv_seed=seed, input_bytes=b"input-B")
    assert a.output != b.output


def test_output_changes_with_seed():
    inp = b"x"
    a = vrf.prove(priv_seed=_gen_seed(), input_bytes=inp)
    b = vrf.prove(priv_seed=_gen_seed(), input_bytes=inp)
    assert a.output != b.output


def test_public_key_deterministic():
    seed = _gen_seed()
    a = vrf.public_key_from_priv_seed(seed)
    b = vrf.public_key_from_priv_seed(seed)
    assert a == b
    assert len(a) == 32


def test_verify_rejects_wrong_pubkey():
    seed = _gen_seed()
    inp = b"x"
    out = vrf.prove(priv_seed=seed, input_bytes=inp)
    other_pub = vrf.public_key_from_priv_seed(_gen_seed())
    assert not vrf.verify(
        public_key=other_pub, input_bytes=inp,
        output=out.output, proof=out.proof,
    )


def test_verify_rejects_wrong_input():
    seed = _gen_seed()
    pub = vrf.public_key_from_priv_seed(seed)
    out = vrf.prove(priv_seed=seed, input_bytes=b"original")
    assert not vrf.verify(
        public_key=pub, input_bytes=b"different",
        output=out.output, proof=out.proof,
    )


def test_verify_rejects_tampered_output():
    seed = _gen_seed()
    pub = vrf.public_key_from_priv_seed(seed)
    out = vrf.prove(priv_seed=seed, input_bytes=b"x")
    bad = bytearray(out.output)
    bad[0] ^= 0xff
    assert not vrf.verify(
        public_key=pub, input_bytes=b"x",
        output=bytes(bad), proof=out.proof,
    )


def test_verify_rejects_tampered_proof():
    seed = _gen_seed()
    pub = vrf.public_key_from_priv_seed(seed)
    out = vrf.prove(priv_seed=seed, input_bytes=b"x")
    bad = bytearray(out.proof)
    bad[0] ^= 0xff
    assert not vrf.verify(
        public_key=pub, input_bytes=b"x",
        output=out.output, proof=bytes(bad),
    )


def test_verify_rejects_wrong_size_inputs():
    """Length checks at the verifier are an early-rejection guard."""
    assert not vrf.verify(
        public_key=b"\x00" * 31, input_bytes=b"x",
        output=b"\x00" * 32, proof=b"\x00" * 96,
    )
    assert not vrf.verify(
        public_key=b"\x00" * 32, input_bytes=b"x",
        output=b"\x00" * 31, proof=b"\x00" * 96,
    )
    assert not vrf.verify(
        public_key=b"\x00" * 32, input_bytes=b"x",
        output=b"\x00" * 32, proof=b"\x00" * 95,
    )


def test_invalid_seed_length_rejected():
    with pytest.raises(ValueError, match="32 bytes"):
        vrf.prove(priv_seed=b"\x00" * 16, input_bytes=b"x")
    with pytest.raises(ValueError, match="32 bytes"):
        vrf.public_key_from_priv_seed(b"\x00" * 16)


def test_uniformly_distributed_output():
    """Sanity: VRF output is pseudorandom, so it should pass a
    crude uniformity check on the high byte over many inputs."""
    seed = _gen_seed()
    high_bytes = []
    for i in range(256):
        out = vrf.prove(priv_seed=seed, input_bytes=str(i).encode())
        high_bytes.append(out.output[0])
    # We should see at least 100 distinct values out of 256 trials.
    # (A uniform distribution gives ~163 distinct on average; 100 is
    # a generous lower bound.)
    assert len(set(high_bytes)) >= 100


def test_use_case_unbiased_lookup_routing():
    """Realistic use: pick the closest-by-VRF-score node from a set
    of candidates. The node operating the VRF can prove to an
    auditor that they didn't favor a specific candidate; the
    candidates can verify the score is consistent across queries."""
    seed = _gen_seed()
    pub = vrf.public_key_from_priv_seed(seed)
    target = b"target-id-being-looked-up"
    # 5 candidates; score each via VRF.
    candidates = [
        ("alice", b"alice-id"),
        ("bob", b"bob-id"),
        ("carol", b"carol-id"),
        ("dave", b"dave-id"),
        ("eve", b"eve-id"),
    ]
    scored = []
    for name, cid in candidates:
        out = vrf.prove(priv_seed=seed, input_bytes=target + cid)
        scored.append((name, cid, out))
    # Pick the lowest-scoring (= "closest" by this metric).
    scored.sort(key=lambda t: t[2].output)
    winner = scored[0]
    # Auditor verifies the winning score.
    assert vrf.verify(
        public_key=pub, input_bytes=target + winner[1],
        output=winner[2].output, proof=winner[2].proof,
    )
    # Re-running with the same inputs gives the SAME ranking — the
    # selection is deterministic + auditable.
    rescored = []
    for name, cid in candidates:
        out = vrf.prove(priv_seed=seed, input_bytes=target + cid)
        rescored.append((name, cid, out))
    rescored.sort(key=lambda t: t[2].output)
    assert rescored[0][0] == winner[0]

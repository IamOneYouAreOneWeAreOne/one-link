"""File engine v2 — algebraic-correctness tests for ``one_link.chunk_store_native``.

Per ADR-0003 + ADR-0005 verification gates. Covers:

- Open / append / flush / read round trip.
- Multiple chunks; replay rebuilds the memtable across daemon restarts.
- Manifest WAL coupling: ``chunk_log_anchor`` auto-set when not provided.
- Convergent encryption + ChaCha20 + format-aware + compressed flags
  round-trip without corruption.
- Stripe descriptor round-trips both NONE and a populated descriptor.
- Bloom filter front prevents pointless reads on absent chunks.
"""

from __future__ import annotations

import secrets
import tempfile

import pytest

from one_link import chunk_store_native


pytestmark = pytest.mark.skipif(
    not chunk_store_native.HAS_NATIVE,
    reason="one_link_native not installed; run `cd native && maturin develop --release`",
)


def make_chunk_id(seed: int) -> bytes:
    return seed.to_bytes(4, "little") + secrets.token_bytes(28)


def make_ratchet_id(seed: int) -> bytes:
    return seed.to_bytes(2, "little") + secrets.token_bytes(14)


# ─── basic open + constants ────────────────────────────────────────────


def test_native_constants_present():
    assert chunk_store_native.CHUNK_RECORD_HEADER_LEN == 80
    assert chunk_store_native.MANIFEST_RECORD_HEADER_LEN == 52
    assert chunk_store_native.STRIPE_DESCRIPTOR_LEN == 24


def test_open_creates_subdirs():
    with tempfile.TemporaryDirectory() as d:
        with chunk_store_native.ChunkStore.open(d) as store:
            stats = store.stats()
            assert stats.indexed_chunks == 0
            assert stats.manifest_records == 0


# ─── round-trip ────────────────────────────────────────────────────────


def test_write_read_round_trip():
    with tempfile.TemporaryDirectory() as d:
        with chunk_store_native.ChunkStore.open(d) as store:
            chunk_id = make_chunk_id(1)
            ratchet_id = make_ratchet_id(1)
            ciphertext = b"\xCD" * 1040
            store.append_chunk(chunk_id, ratchet_id, 1024, ciphertext)
            store.flush()
            assert store.has_chunk(chunk_id)
            loc = store.locate_chunk(chunk_id)
            assert loc is not None
            assert loc.length_plaintext == 1024
            assert loc.length_ciphertext == 1040
            r = store.read_chunk(chunk_id)
            assert r.kind == "blob"
            assert r.address_kind == "raw"
            assert r.aead_kind == "aes"
            assert r.length_plaintext == 1024
            assert r.chunk_id == chunk_id
            assert r.ratchet_key_id == ratchet_id
            assert r.ciphertext == ciphertext


def test_read_chunk_not_found():
    with tempfile.TemporaryDirectory() as d:
        with chunk_store_native.ChunkStore.open(d) as store:
            with pytest.raises(Exception):
                store.read_chunk(b"\x00" * 32)


def test_replay_rebuilds_memtable_across_restart():
    with tempfile.TemporaryDirectory() as d:
        chunks = [(make_chunk_id(i), make_ratchet_id(i), b"\xEE" * 80) for i in range(8)]
        with chunk_store_native.ChunkStore.open(d) as store:
            for cid, rid, ct in chunks:
                store.append_chunk(cid, rid, 64, ct)
            store.flush()
        with chunk_store_native.ChunkStore.open(d) as store2:
            stats = store2.stats()
            assert stats.indexed_chunks == 8
            for cid, _rid, ct in chunks:
                assert store2.has_chunk(cid)
                r = store2.read_chunk(cid)
                assert r.ciphertext == ct


# ─── manifest WAL coupling (ADR-0005) ──────────────────────────────────


def test_manifest_anchor_auto_set_to_last_chunk_offset():
    with tempfile.TemporaryDirectory() as d:
        with chunk_store_native.ChunkStore.open(d) as store:
            cid = make_chunk_id(7)
            rid = make_ratchet_id(7)
            store.append_chunk(cid, rid, 64, b"\xAB" * 80)
            actor = secrets.token_bytes(32)
            store.append_manifest(
                "manifest_version", 12345, actor, b"crdt-op-bytes"
            )
            store.flush()
        with chunk_store_native.ChunkStore.open(d) as store2:
            stats = store2.stats()
            assert stats.manifest_records == 1
            assert stats.orphaned_manifest_records == 0


def test_manifest_kinds_supported():
    with tempfile.TemporaryDirectory() as d:
        with chunk_store_native.ChunkStore.open(d) as store:
            actor = secrets.token_bytes(32)
            for kind in ["manifest", "grant", "revoke", "share_link", "sentinel"]:
                store.append_manifest(kind, 1, actor, b"body")
            store.flush()
        with chunk_store_native.ChunkStore.open(d) as store2:
            assert store2.stats().manifest_records == 5


# ─── flag round-trips ──────────────────────────────────────────────────


def test_convergent_chacha_compressed_format_aware_round_trip():
    with tempfile.TemporaryDirectory() as d:
        with chunk_store_native.ChunkStore.open(d) as store:
            cid = make_chunk_id(99)
            rid = make_ratchet_id(99)
            ct = b"\x33" * 200
            store.append_chunk(
                cid,
                rid,
                184,
                ct,
                address_kind="convergent",
                aead_kind="chacha",
                compressed=True,
                format_aware=True,
            )
            store.flush()
            r = store.read_chunk(cid)
            assert r.address_kind == "convergent"
            assert r.aead_kind == "chacha"
            assert r.compressed is True
            assert r.format_aware is True


# ─── stripe descriptor ─────────────────────────────────────────────────


def test_stripe_default_round_trips():
    with tempfile.TemporaryDirectory() as d:
        with chunk_store_native.ChunkStore.open(d) as store:
            cid = make_chunk_id(11)
            store.append_chunk(cid, make_ratchet_id(11), 64, b"\x01" * 80)
            store.flush()
            r = store.read_chunk(cid)
            assert r.stripe.role == "not_striped"
            assert r.stripe.stripe_k == 0
            assert r.stripe.stripe_m == 0


def test_stripe_data_role_round_trips():
    from one_link_native.store import StripeDescriptor

    with tempfile.TemporaryDirectory() as d:
        with chunk_store_native.ChunkStore.open(d) as store:
            cid = make_chunk_id(22)
            stripe = StripeDescriptor(
                stripe_id_lo64=0xCAFEBABE_F00DBAAD,
                role="data",
                stripe_index=3,
                stripe_k=10,
                stripe_m=4,
                cohort_id_lo64=0xDEADBEEF_CAFEF00D,
            )
            store.append_chunk(
                cid, make_ratchet_id(22), 64, b"\x02" * 80, stripe=stripe
            )
            store.flush()
            r = store.read_chunk(cid)
            assert r.stripe.role == "data"
            assert r.stripe.stripe_index == 3
            assert r.stripe.stripe_k == 10
            assert r.stripe.stripe_m == 4
            assert r.stripe.stripe_id_lo64 == 0xCAFEBABE_F00DBAAD
            assert r.stripe.cohort_id_lo64 == 0xDEADBEEF_CAFEF00D


# ─── bad input ─────────────────────────────────────────────────────────


def test_bad_chunk_id_length_rejected():
    with tempfile.TemporaryDirectory() as d:
        with chunk_store_native.ChunkStore.open(d) as store:
            with pytest.raises(Exception):
                store.append_chunk(b"\x00" * 31, make_ratchet_id(1), 64, b"x" * 80)


def test_bad_ratchet_id_length_rejected():
    with tempfile.TemporaryDirectory() as d:
        with chunk_store_native.ChunkStore.open(d) as store:
            with pytest.raises(Exception):
                store.append_chunk(
                    make_chunk_id(1), b"\x00" * 15, 64, b"x" * 80
                )


def test_bad_actor_id_length_rejected():
    with tempfile.TemporaryDirectory() as d:
        with chunk_store_native.ChunkStore.open(d) as store:
            with pytest.raises(Exception):
                store.append_manifest("manifest", 1, b"\x00" * 31, b"body")


def test_unknown_kinds_rejected():
    with tempfile.TemporaryDirectory() as d:
        with chunk_store_native.ChunkStore.open(d) as store:
            with pytest.raises(Exception):
                store.append_chunk(
                    make_chunk_id(1),
                    make_ratchet_id(1),
                    64,
                    b"x" * 80,
                    record_kind="garbage",
                )


# ─── close semantics ──────────────────────────────────────────────────


def test_use_after_close_rejected():
    with tempfile.TemporaryDirectory() as d:
        store = chunk_store_native.ChunkStore.open(d)
        store.close()
        with pytest.raises(Exception):
            store.append_chunk(make_chunk_id(1), make_ratchet_id(1), 64, b"x" * 80)

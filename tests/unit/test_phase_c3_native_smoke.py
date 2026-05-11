"""Phase C-3 native modules smoke tests.

Verify the ``one_link_native.{capability, crdt, hwkey}`` Python bindings
load and round-trip basic operations. Light unit tests; the heavy
correctness invariants live in Rust (the 1M-iter lattice-laws gate,
the macaroon attenuation gate, the TOFU rotation-detection gate).
"""

from __future__ import annotations

import os

import pytest


def _native_available() -> bool:
    try:
        import one_link_native  # type: ignore[import-not-found] # noqa: F401

        return True
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native not installed (build via `cd native && maturin develop --release`)",
)


# --- ol_capability binding ------------------------------------------------


def test_capability_root_verify():
    from one_link_native import capability as cap

    root_key = b"\x42" * 32
    cap_id = b"\xCD" + b"\x00" * 31
    c = cap.Capability.root(cap_id, root_key)
    assert c.num_caveats() == 0
    # Empty context — root verifies.
    c.verify(root_key)


def test_capability_attenuate_and_verify():
    from one_link_native import capability as cap

    root_key = b"\x42" * 32
    cap_id = b"\xCD" + b"\x00" * 31
    c = (
        cap.Capability.root(cap_id, root_key)
        .attenuate_expires_at(1_000_000)
        .attenuate_path_prefix("/share/alice")
        .attenuate_operation_in(["read", "list"])
    )
    assert c.num_caveats() == 3
    # Within scope — accepts.
    c.verify(root_key, now_ms=500_000, path="/share/alice/x.pdf", operation="read")
    # Outside path — rejects.
    assert (
        c.accepts(root_key, now_ms=500_000, path="/share/bob/x.pdf", operation="read")
        is False
    )
    # Expired.
    assert (
        c.accepts(
            root_key, now_ms=9_999_999, path="/share/alice/x.pdf", operation="read"
        )
        is False
    )


def test_capability_wire_round_trip():
    from one_link_native import capability as cap

    root_key = os.urandom(32)
    cap_id = os.urandom(32)
    original = (
        cap.Capability.root(cap_id, root_key)
        .attenuate_expires_at(123)
        .attenuate_audit_tag("share-alice")
        .attenuate_peer(os.urandom(32))
    )
    wire = original.encode()
    decoded = cap.Capability.decode(wire)
    # Same cap_id and num_caveats; signature matches.
    assert decoded.cap_id() == original.cap_id()
    assert decoded.num_caveats() == original.num_caveats()
    assert decoded.signature() == original.signature()


def test_capability_wrong_root_rejects():
    from one_link_native import OlCapabilityError, capability as cap

    root_a = b"\x11" * 32
    root_b = b"\x22" * 32
    c = cap.Capability.root(b"\x01" * 32, root_a)
    with pytest.raises(OlCapabilityError):
        c.verify(root_b)


# --- ol_crdt binding ------------------------------------------------------


def test_folder_add_and_iter():
    from one_link_native import crdt

    alice = b"\x01" * 32
    fid = b"\xAA" * 32
    f = crdt.Folder()
    f.add_file(alice, fid, "report.pdf", 1024, 100)
    assert f.contains(fid) is True
    assert f.len() == 1
    entries = f.entries()
    assert len(entries) == 1
    assert entries[0][0] == fid
    assert entries[0][1] == "report.pdf"


def test_folder_merge_commutative():
    from one_link_native import crdt

    alice = b"\x01" * 32
    bob = b"\x02" * 32
    fid_a = b"\xAA" * 32
    fid_b = b"\xBB" * 32

    f1 = crdt.Folder()
    f1.add_file(alice, fid_a, "alice.bin", 1, 1)

    f2 = crdt.Folder()
    f2.add_file(bob, fid_b, "bob.bin", 2, 2)

    f12 = crdt.Folder()
    f12.add_file(alice, fid_a, "alice.bin", 1, 1)
    f12.merge(f2)

    f21 = crdt.Folder()
    f21.add_file(bob, fid_b, "bob.bin", 2, 2)
    f21.merge(f1)

    # Both should contain both files; merge order doesn't matter.
    assert f12.contains(fid_a) is True
    assert f12.contains(fid_b) is True
    assert f21.contains(fid_a) is True
    assert f21.contains(fid_b) is True
    assert f12.len() == f21.len()


def test_folder_add_wins_concurrent_remove():
    from one_link_native import crdt

    alice = b"\x01" * 32
    bob = b"\x02" * 32
    fid = b"\xCC" * 32

    a = crdt.Folder()
    a.add_file(alice, fid, "secret.pdf", 4096, 1)

    b = crdt.Folder()
    # Bob saw an earlier add and decided to remove.
    b.add_file(alice, fid, "secret.pdf", 4096, 1)
    b.remove_file(bob, fid)

    # Alice concurrently re-adds (fresh tag).
    a.add_file(alice, fid, "secret.pdf", 4096, 1)

    a.merge(b)
    assert a.contains(fid) is True


# --- ol_hwkey binding -----------------------------------------------------


def test_tofu_idempotent_and_stable():
    from one_link_native import hwkey

    s = hwkey.TofuStore(b"\x42" * 32)
    assert s.guarantee() == "TofuOnly"
    s.get_or_create("alice")
    pk1 = s.public_key("alice")
    pk2 = s.public_key("alice")
    assert pk1 == pk2


def test_tofu_rejects_rotated_key():
    from one_link_native import hwkey

    s = hwkey.TofuStore(b"\x42" * 32)
    s.get_or_create("alice")
    real_pk = s.public_key("alice")
    assert s.check_tofu("alice", real_pk) is True
    attacker = b"\xAA" * 32
    assert s.check_tofu("alice", attacker) is False

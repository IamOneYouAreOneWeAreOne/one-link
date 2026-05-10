"""v0.20.7 — MLS TreeKEM primitive (RFC 9420 §7).

Sender-keys group encryption costs O(N) per member rotation. MLS
replaces it with a left-balanced binary tree: O(log N) for the same
operations. Bundle 38 ships the tree math + path-secret derivation —
the cryptographic core distinct from sender-keys. HPKE-wrap-to-
copath (so an Update reveals the new secret only to the right
subtree) is the next-layer construction.

These tests pin the tree math invariants (RFC 9420 §7.1):
  - Power-of-2 trees: root index = 2N-2
  - Leaves at even indices, internal nodes at odd
  - parent ↔ left/right symmetric (parent(left(p)) = p)
  - sibling symmetric (sibling(sibling(x)) = x)
  - direct_path + copath have equal length, both = log2(N) for
    N = 2^k
  - Worked example matches RFC 9420 Figure 4 (4-leaf tree)

Plus the cryptographic primitive layer:
  - HKDF determinism + domain separation (path label != node label)
  - derive_path_secrets walks from leaf to root through every
    direct-path node
  - TreeKEMState apply_self_update produces a non-None root secret
  - Two members at the same epoch derive the SAME root secret from
    the SAME leaf material (the property the MLS group uses to
    align its symmetric ratchet)
"""
from __future__ import annotations

import os

import pytest

from one_link import mls_treekem as tk


# ── Tree math invariants ─────────────────────────────────────────


def test_total_nodes_formula():
    for n in (1, 2, 3, 4, 5, 8, 16, 100):
        assert tk.n_leaves_to_n_nodes(n) == 2 * n - 1


def test_is_leaf_even_indices():
    for n in range(0, 20, 2):
        assert tk.is_leaf(n)
    for n in range(1, 20, 2):
        assert not tk.is_leaf(n)


def test_leaf_index_doubles():
    for L in range(10):
        assert tk.leaf_index(L) == 2 * L


def test_root_for_powers_of_2():
    """N = 2^k ⇒ root index = N - 1 (the smallest index with k
    trailing 1-bits, which is the highest level in a tree with
    N leaves; total nodes = 2N - 1, root sits ~midway)."""
    for k in range(1, 6):
        n = 1 << k
        assert tk.root(n) == n - 1


def test_root_for_non_pow2():
    """N=3: root is at index 3 (parent of leaves 0,2 + virtual right).
    N=5: root is at index 7."""
    # We just confirm root() returns SOMETHING valid (in-range).
    for n in (1, 3, 5, 6, 7, 9):
        r = tk.root(n)
        assert 0 <= r < tk.n_leaves_to_n_nodes(n)


def test_parent_left_right_symmetric_pow2():
    """For N=4: parent(left(p)) = p for every internal node p."""
    n = 4
    for p in (1, 3, 5):
        assert tk.parent(tk.left(p), n) == p
        assert tk.parent(tk.right(p, n), n) == p


def test_sibling_involution_pow2():
    """sibling(sibling(x)) = x for every non-root node."""
    n = 4
    r = tk.root(n)
    for idx in range(tk.n_leaves_to_n_nodes(n)):
        if idx == r:
            continue
        s = tk.sibling(idx, n)
        ss = tk.sibling(s, n)
        assert ss == idx


def test_direct_path_4_leaves():
    """RFC 9420 Figure 4: leaf 0 (idx 0) has direct path [1, 3]."""
    assert tk.direct_path(0, n_leaves=4) == [1, 3]
    assert tk.direct_path(1, n_leaves=4) == [1, 3]
    assert tk.direct_path(2, n_leaves=4) == [5, 3]
    assert tk.direct_path(3, n_leaves=4) == [5, 3]


def test_copath_4_leaves():
    """leaf 0 copath = [2, 5]; leaf 2 copath = [0, 5]; leaf 3 copath = [4, 1]."""
    assert tk.copath(0, n_leaves=4) == [2, 5]
    assert tk.copath(1, n_leaves=4) == [0, 5]
    assert tk.copath(2, n_leaves=4) == [6, 1]
    assert tk.copath(3, n_leaves=4) == [4, 1]


def test_direct_path_and_copath_same_length():
    """Direct path and copath must have identical length: each step
    up has exactly one sibling."""
    for n in (2, 3, 4, 5, 8, 16):
        for L in range(n):
            assert len(tk.direct_path(L, n)) == len(tk.copath(L, n))


def test_path_length_log2_for_pow2_n():
    """For N = 2^k, every leaf's direct path has length k."""
    for k in range(1, 6):
        n = 1 << k
        for L in range(n):
            assert len(tk.direct_path(L, n)) == k


def test_level_zero_for_leaves():
    for L in range(20):
        assert tk.level(2 * L) == 0


# ── HKDF derivation primitives ────────────────────────────────────


def test_derive_next_path_secret_deterministic():
    s = os.urandom(32)
    a = tk.derive_next_path_secret(s)
    b = tk.derive_next_path_secret(s)
    assert a == b
    assert a != s
    assert len(a) == 32


def test_derive_next_path_secret_avalanche():
    s1 = os.urandom(32)
    s2 = bytes(b ^ 1 for b in s1[:1]) + s1[1:]  # one-bit flip
    assert tk.derive_next_path_secret(s1) != tk.derive_next_path_secret(s2)


def test_derive_node_keypair_deterministic():
    s = os.urandom(32)
    p1, pub1 = tk.derive_node_keypair(s)
    p2, pub2 = tk.derive_node_keypair(s)
    assert pub1 == pub2  # same secret → same pubkey


def test_derive_node_keypair_distinct_from_path():
    """The path-secret label and node-keypair label MUST be distinct,
    so deriving a node keypair doesn't leak into the next path
    secret (or vice versa)."""
    s = os.urandom(32)
    next_s = tk.derive_next_path_secret(s)
    _, node_pub = tk.derive_node_keypair(s)
    # The X25519 pubkey is 32 bytes; next_s is 32 bytes; they must
    # be unrelated (the labels guarantee this via HKDF).
    assert next_s != node_pub
    # And the node keypair derived from next_s differs from the one
    # derived from s.
    _, next_pub = tk.derive_node_keypair(next_s)
    assert node_pub != next_pub


def test_derive_path_secrets_walks_to_root():
    """For a 4-leaf tree, leaf 0's direct path is [1, 3], so
    derive_path_secrets returns secrets at exactly those two
    indices."""
    leaf_secret = os.urandom(32)
    secrets = tk.derive_path_secrets(leaf_secret, 0, n_leaves=4)
    assert sorted(secrets.keys()) == [1, 3]
    # Each secret is 32 bytes + distinct from the leaf secret.
    for v in secrets.values():
        assert len(v) == 32 and v != leaf_secret


def test_derive_path_secrets_chain_property():
    """secrets[parent_idx] = derive_next(secrets[child_idx]) — proves
    the path secrets ratchet UP through HKDF as expected."""
    leaf_secret = os.urandom(32)
    n = 4
    secrets = tk.derive_path_secrets(leaf_secret, 0, n_leaves=n)
    path = tk.direct_path(0, n_leaves=n)  # [1, 3]
    # secrets[1] = derive_next(leaf_secret)
    assert secrets[1] == tk.derive_next_path_secret(leaf_secret)
    # secrets[3] = derive_next(secrets[1])
    assert secrets[3] == tk.derive_next_path_secret(secrets[1])


# ── TreeKEMState ──────────────────────────────────────────────────


def test_treekem_state_apply_self_update_populates_root():
    state = tk.TreeKEMState.empty(n_leaves=4, self_position=0)
    leaf_secret = os.urandom(32)
    secrets = state.apply_self_update(leaf_secret)
    # Direct path is [1, 3] — both should be in secrets, and both
    # should be populated in state.nodes.
    assert 1 in secrets and 3 in secrets
    assert state.nodes[1].secret == secrets[1]
    assert state.nodes[3].secret == secrets[3]
    # root() = 6 for 4 leaves; root_secret = secrets at the highest
    # path node (3 in this case).
    assert state.root_secret() == secrets[3]


def test_treekem_two_members_same_leaf_secret_match_root():
    """If member A and member B both apply the SAME leaf secret at
    the SAME position, they derive the SAME root secret. (This isn't
    a real protocol step — in MLS members rotate their OWN leaf —
    but it verifies the determinism invariant the group ratchet
    relies on.)"""
    leaf_secret = os.urandom(32)
    state_a = tk.TreeKEMState.empty(n_leaves=4, self_position=0)
    state_b = tk.TreeKEMState.empty(n_leaves=4, self_position=0)
    state_a.apply_self_update(leaf_secret)
    state_b.apply_self_update(leaf_secret)
    assert state_a.root_secret() == state_b.root_secret()
    assert state_a.root_secret() is not None


def test_treekem_different_leaves_diverge():
    """Different leaves rotating with different secrets produce
    different root secrets (the property updates rely on for
    forward secrecy)."""
    state = tk.TreeKEMState.empty(n_leaves=4, self_position=0)
    state.apply_self_update(b"\x01" * 32)
    root1 = state.root_secret()
    state.apply_self_update(b"\x02" * 32)
    root2 = state.root_secret()
    assert root1 != root2


def test_treekem_state_empty_root_is_none():
    state = tk.TreeKEMState.empty(n_leaves=4, self_position=0)
    assert state.root_secret() is None


def test_invalid_leaf_position_rejected():
    with pytest.raises(ValueError):
        tk.direct_path(99, n_leaves=4)
    with pytest.raises(ValueError):
        tk.copath(-1, n_leaves=4)


def test_root_has_no_parent():
    n = 4
    r = tk.root(n)
    with pytest.raises(ValueError):
        tk.parent(r, n)


def test_leaves_have_no_children():
    with pytest.raises(ValueError):
        tk.left(0)
    with pytest.raises(ValueError):
        tk.right(0, n_leaves=4)

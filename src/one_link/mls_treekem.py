"""TreeKEM — MLS's asymmetric ratchet tree primitive (RFC 9420 §7).

Sender-keys group encryption (one_link.groups_crypto) costs O(N)
per state mutation: every member rotation re-derives N chain keys
and re-distributes them. Fine for small groups; quadratic-ish
scaling up to 100s of members.

MLS (Messaging Layer Security, RFC 9420, IETF 2023) replaces the
flat chain-key model with a **left-balanced binary tree** of
HKDF-derived secrets. Each leaf is one member's keypair; each
internal node is a secret derived from the leaves below it.
Updating one member's key requires only O(log N) work — the
new path secret ratchets from the affected leaf up to the root,
and the rest of the group consumes that ratchet via HPKE-wrapped
"copath" messages.

Bundle 38 ships the **tree math** + **path-secret derivation** —
the cryptographic core that's distinct from anything in
groups_crypto.py. The HPKE-wrapped copath messages (so an Update
proposal can be encrypted to the rest of the group without
revealing the new leaf secret to outsiders) is the next
construction layer; it sits on top of these primitives.

Tree layout (RFC 9420 §7.1)
---------------------------

A left-balanced binary tree with N leaves has 2*N-1 total nodes.
Nodes are addressed by their depth-first index:

  - Leaves are at EVEN indices: 0, 2, 4, 6, ...
  - Internal (parent) nodes are at ODD indices: 1, 3, 5, ...

For a 4-leaf tree::

       3 (root)
      / \
     1   5
    /|   |\
   0 2   4 6

The root sits at index 2*N-2 when N is a power of 2; for non-
power-of-2 N the tree is "left-balanced" — left subtree fills
first. ``left(p)``, ``right(p)``, ``parent(n)``, ``sibling(n)``
all compute via bit arithmetic without storing the tree
explicitly.

Path secrets (RFC 9420 §7.4)
----------------------------

A leaf member updates their key by:
  1. Sample a fresh leaf secret L.
  2. For each node in the direct path from leaf → root:
       node_secret_{k+1} = HKDF-Expand(node_secret_k, "path", 32)
       node_keypair_{k+1} = derive X25519 keypair from node_secret_{k+1}
  3. Each *copath* node (sibling of a direct-path node) needs the
     new node_secret of its parent. The leaf encrypts each new
     parent secret to the HPKE-public of the copath node's subtree,
     and broadcasts the encrypted bundle.

Test surface
------------

These primitives are pure functions over byte arrays + integers.
The test surface is:
  - Tree-math invariants (parent-of(leaf) = leaf+1; sibling
    symmetric; root-of-N = 2N-2 for N=2^k; etc.)
  - HKDF derivation determinism + domain separation
  - Path/copath enumeration matches the RFC 9420 worked example
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# Domain-separation labels for the HKDF tree-secret derivation.
# Distinct from every other HKDF info in the codebase so a leak of
# tree material doesn't compromise channel / group / identity keys.
TREE_LABEL_PATH = b"OL/mls/tree/path|v1"
TREE_LABEL_NODE = b"OL/mls/tree/node-key|v1"


# ── Tree math (RFC 9420 §7.1) ──────────────────────────────────────


def n_leaves_to_n_nodes(n_leaves: int) -> int:
    """Total node count in a left-balanced binary tree with
    ``n_leaves`` leaves: 2*N - 1."""
    if n_leaves <= 0:
        raise ValueError("n_leaves must be positive")
    return 2 * n_leaves - 1


def is_leaf(idx: int) -> bool:
    """Leaves sit at EVEN indices in the depth-first node ordering."""
    return idx % 2 == 0


def leaf_index(leaf_position: int) -> int:
    """Leaf at zero-based position L is at node index 2*L."""
    if leaf_position < 0:
        raise ValueError("leaf_position must be non-negative")
    return 2 * leaf_position


def level(idx: int) -> int:
    """Height of node ``idx`` above the leaves. Leaves are level 0;
    a parent of two leaves is level 1; the root grows with log2(N)."""
    if idx < 0:
        raise ValueError("idx must be non-negative")
    # Count trailing 1-bits in idx XOR (idx+1). Equivalent to the
    # position of the lowest unset bit. RFC 9420 §7.1 formulation.
    k = 0
    while ((idx >> k) & 1) == 1:
        k += 1
    return k


def parent(idx: int, n_leaves: int) -> int:
    """Parent node index. Root has no parent — raise."""
    n_nodes = n_leaves_to_n_nodes(n_leaves)
    if idx == root(n_leaves):
        raise ValueError(f"node {idx} is the root; no parent")
    if idx < 0 or idx >= n_nodes:
        raise ValueError(f"idx {idx} out of bounds for {n_leaves} leaves")
    lvl = level(idx)
    bit = 1 << (lvl + 1)
    candidate = (idx | (1 << lvl)) & ~bit
    # The candidate is correct on a power-of-2 tree; for non-pow2
    # the parent walks UP through "right edge" virtual nodes until
    # an actual node is found (RFC 9420 §7.1.2 "left-balanced").
    while candidate >= n_nodes:
        candidate = parent_pow2(candidate)
    return candidate


def parent_pow2(idx: int) -> int:
    """Parent calculation assuming an unrestricted full tree.
    Used internally by ``parent`` to walk past virtual nodes when
    n_leaves is not a power of 2."""
    lvl = level(idx)
    return (idx | (1 << lvl)) & ~(1 << (lvl + 1))


def left(idx: int) -> int:
    """Left child of an internal node."""
    if is_leaf(idx):
        raise ValueError(f"node {idx} is a leaf; no children")
    lvl = level(idx)
    return idx ^ (1 << (lvl - 1))  # flip the bit one below


def right(idx: int, n_leaves: int) -> int:
    """Right child of an internal node. Walks DOWN through left-
    children when the canonical right-child sits past the tree's
    actual node count (RFC 9420 §7.1.2 "left-balanced" rule)."""
    if is_leaf(idx):
        raise ValueError(f"node {idx} is a leaf; no children")
    lvl = level(idx)
    # RFC 9420: right(x) = x XOR (0x03 << (level(x) - 1))
    candidate = idx ^ (3 << (lvl - 1))
    n_nodes = n_leaves_to_n_nodes(n_leaves)
    while candidate >= n_nodes:
        candidate = left(candidate)
    return candidate


def sibling(idx: int, n_leaves: int) -> int:
    """Sibling under the same parent."""
    p = parent(idx, n_leaves)
    if left(p) == idx:
        return right(p, n_leaves)
    return left(p)


def root(n_leaves: int) -> int:
    """Index of the root of a left-balanced tree with ``n_leaves``
    leaves.

    Closed-form: root_idx = 2^ceil(log2(n_leaves)) - 1. Works for
    every n_leaves ≥ 1, including non-powers-of-2. The intuition:
    the root is the unique node at the highest occupied level k,
    and its index is the smallest k-trailing-1s integer = 2^(k+1)-1
    where k+1 = ceil(log2(n_leaves))."""
    if n_leaves <= 0:
        raise ValueError("n_leaves must be positive")
    if n_leaves == 1:
        return 0
    # ceil_log2(n_leaves)
    k = (n_leaves - 1).bit_length()
    return (1 << k) - 1


def direct_path(leaf_position: int, n_leaves: int) -> list[int]:
    """List of node indices from a leaf UP to (but not including)
    the root. Used during an Update to know which secrets the
    leaf member needs to derive."""
    idx = leaf_index(leaf_position)
    if idx >= n_leaves_to_n_nodes(n_leaves):
        raise ValueError(f"leaf_position {leaf_position} out of range")
    path = []
    r = root(n_leaves)
    while idx != r:
        idx = parent(idx, n_leaves)
        path.append(idx)
    return path


def copath(leaf_position: int, n_leaves: int) -> list[int]:
    """Siblings of every node on the direct path. The Update message
    encrypts each new path-secret to the recipients in the
    corresponding copath subtree."""
    idx = leaf_index(leaf_position)
    if idx >= n_leaves_to_n_nodes(n_leaves):
        raise ValueError(f"leaf_position {leaf_position} out of range")
    cop = []
    r = root(n_leaves)
    while idx != r:
        cop.append(sibling(idx, n_leaves))
        idx = parent(idx, n_leaves)
    return cop


# ── Path-secret derivation (RFC 9420 §7.4) ─────────────────────────


def derive_next_path_secret(secret: bytes) -> bytes:
    """Advance a path secret one step up the tree. RFC 9420 uses
    HKDF-Expand-Label with the ``path`` label."""
    if len(secret) != 32:
        raise ValueError("path secret must be 32 bytes")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=TREE_LABEL_PATH,
    ).derive(secret)


def derive_node_keypair(secret: bytes) -> tuple[X25519PrivateKey, bytes]:
    """Each node's KEM keypair is deterministic from its secret. The
    private key is HKDF-derived from the path secret with a distinct
    label so the same secret can derive both the next path secret
    AND a node keypair without one-way leakage between them."""
    if len(secret) != 32:
        raise ValueError("node secret must be 32 bytes")
    raw_priv = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=TREE_LABEL_NODE,
    ).derive(secret)
    priv = X25519PrivateKey.from_private_bytes(raw_priv)
    pub = priv.public_key().public_bytes_raw()
    return priv, pub


def derive_path_secrets(
    leaf_secret: bytes, leaf_position: int, n_leaves: int,
) -> dict[int, bytes]:
    """Walk from a leaf's fresh secret up to the root, deriving the
    path secret at each level. Returns ``{node_idx: secret}`` for
    every node on the direct path (NOT the root itself, which is
    derived from the highest direct-path node).

    The leaf member shares each path secret only with the subtree
    that should know it — implemented at the next layer via HPKE
    encryption to the copath node's public key. This module is the
    pure-key-derivation part."""
    if len(leaf_secret) != 32:
        raise ValueError("leaf_secret must be 32 bytes")
    path = direct_path(leaf_position, n_leaves)
    secrets: dict[int, bytes] = {}
    cur = leaf_secret
    for node_idx in path:
        cur = derive_next_path_secret(cur)
        secrets[node_idx] = cur
    return secrets


# ── TreeKEM state ──────────────────────────────────────────────────


@dataclass
class TreeNode:
    """Per-node tree state. ``secret`` is None for nodes the local
    member doesn't yet have the secret for (the parts of the tree
    other than its own direct path). ``pub`` is the X25519 public
    key for the node — known to every member after gossip."""
    secret: bytes | None = None
    pub: bytes | None = None


@dataclass
class TreeKEMState:
    """Per-member view of the tree. Initially populated by the
    Welcome message; each Update / Add / Remove proposal mutates it
    deterministically. The key invariant: every member's view of
    the public-key tree must be byte-identical, so adding a new
    member or rotating an existing one produces the same group
    secret on every device."""
    n_leaves: int
    self_position: int
    nodes: list[TreeNode]

    @classmethod
    def empty(cls, n_leaves: int, self_position: int) -> "TreeKEMState":
        n_nodes = n_leaves_to_n_nodes(n_leaves)
        return cls(
            n_leaves=n_leaves,
            self_position=self_position,
            nodes=[TreeNode() for _ in range(n_nodes)],
        )

    def apply_self_update(self, leaf_secret: bytes) -> dict[int, bytes]:
        """Local leaf rotates its key. Re-derives path secrets up
        to the root + computes new keypairs at each level. Returns
        the per-node secrets the caller can encrypt to copath
        recipients (the HPKE-wrap layer)."""
        path = direct_path(self.self_position, self.n_leaves)
        path_secrets = derive_path_secrets(
            leaf_secret, self.self_position, self.n_leaves,
        )
        # Update local state: leaf node + every direct-path node.
        leaf_idx = leaf_index(self.self_position)
        leaf_priv, leaf_pub = derive_node_keypair(leaf_secret)
        self.nodes[leaf_idx] = TreeNode(secret=leaf_secret, pub=leaf_pub)
        for node_idx in path:
            sec = path_secrets[node_idx]
            _, pub = derive_node_keypair(sec)
            self.nodes[node_idx] = TreeNode(secret=sec, pub=pub)
        return path_secrets

    def root_secret(self) -> bytes | None:
        """The derived secret at the root node. Equivalent to the
        group's "epoch secret" in MLS terms — every other group
        secret (sender chain keys, exporter secret, ...) ratchets
        from this. None when the local member doesn't have a
        complete view (e.g. mid-Welcome)."""
        r = root(self.n_leaves)
        return self.nodes[r].secret if self.nodes[r] else None

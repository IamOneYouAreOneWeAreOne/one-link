"""Kademlia DHT primitive — sovereign rendezvous without a server.

The current rendezvous (rendezvous_server.py) is a single coordination
point: every NAT-traversing peer registers there with its pubkey +
last-known endpoint, every peer that wants to find someone /lookups
the same server. The server is hardened (Bundle 2 closed 9 audit
findings against it) but it's still a SPOF — operationally, legally,
and in terms of "for the people" sovereignty: someone has to run it,
pay for it, and choose not to log.

Kademlia (Maymounkov + Mazières, 2002) replaces that single server
with a network of equal peers, each holding a slice of the routing
table. Lookups are iterative O(log N) hops; storage is replicated
to the K closest nodes; node failures are tolerated by the
redundancy. No central server, no operator, no logs in any one
place. The same algorithm that backs BitTorrent's mainline DHT
(currently ~30M peers) and Ethereum's discovery layer.

This module ships the **algorithm primitives**: NodeID, XOR distance,
KBuckets with LRU eviction, RoutingTable, iterative lookup. The
**transport** (UDP RPC for PING / STORE / FIND_NODE / FIND_VALUE)
is a separate ship — once the algorithm is solid, swapping in any
transport (UDP, WebRTC DataChannel, mixnet hop) becomes a contained
plumbing exercise.

Why ship the primitives separately? Two reasons:

  1. **Test surface**. The Kademlia algorithm has subtle invariants
     (XOR distance triangle inequality, bucket-split symmetry,
     lookup convergence guarantees) that need direct unit-test
     access. Tying tests to a network harness makes the failure
     modes "transport-flake" instead of "algorithm-bug" and slows
     the iteration loop.

  2. **Multi-transport future**. The same DHT algorithm wants to
     run over UDP today, WebRTC DataChannel for browser peers
     tomorrow, and a Tor-onion / I2P transport for the privacy-
     paranoid use case. Decoupling the algorithm from the wire
     keeps all three surfaces aligned.

References
----------

  - Maymounkov, P., & Mazières, D. (2002). Kademlia: A Peer-to-Peer
    Information System Based on the XOR Metric. IPTPS.
  - BEP-0005 (BitTorrent DHT) — production-tested variant.
  - libp2p kad-dht spec — modern interpretation with security
    refinements (S/Kademlia-style).
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Optional


# ── constants ──────────────────────────────────────────────────────


# 32-byte (256-bit) node IDs. Mirrors libp2p kad-dht; the legacy
# 160-bit Kademlia spec used SHA-1, which is no longer cryptographically
# strong. SHA-256 of an Ed25519 pubkey is the canonical derivation
# (matches one_link's existing 32-byte fingerprint shape).
NODE_ID_BITS = 256
NODE_ID_BYTES = 32

# Per-bucket cap. Maymounkov+Mazières recommended K=20; libp2p uses
# K=20; BitTorrent uses K=8. We match libp2p — large enough that
# random churn doesn't drop reachable nodes, small enough that the
# per-bucket store + lookup stays cheap.
DEFAULT_K = 20

# Concurrency parameter for iterative lookups. α=3 is the canonical
# choice (paper §3); larger α gets faster lookups at the cost of
# more wire traffic. We keep it tunable for transport experiments.
DEFAULT_ALPHA = 3


# ── NodeID + XOR distance ─────────────────────────────────────────


@dataclass(frozen=True, order=True)
class NodeID:
    """A 32-byte node identifier. Constructed from a pubkey (or any
    bytes) via SHA-256. Order is lexicographic so the dataclass
    works as a dict / set key; XOR distance is computed separately."""
    raw: bytes

    def __post_init__(self):
        if len(self.raw) != NODE_ID_BYTES:
            raise ValueError(
                f"NodeID must be {NODE_ID_BYTES} bytes, got {len(self.raw)}"
            )

    @classmethod
    def from_pubkey(cls, pubkey: bytes) -> "NodeID":
        return cls(raw=hashlib.sha256(pubkey).digest())

    @classmethod
    def random(cls) -> "NodeID":
        return cls(raw=secrets.token_bytes(NODE_ID_BYTES))

    def xor(self, other: "NodeID") -> int:
        """XOR distance as a non-negative integer (Kademlia metric)."""
        a = int.from_bytes(self.raw, "big")
        b = int.from_bytes(other.raw, "big")
        return a ^ b

    def common_prefix_length(self, other: "NodeID") -> int:
        """Number of leading bits the two IDs share. Used to map an
        ID into the right k-bucket: bucket index = NODE_ID_BITS - 1 -
        (common prefix length)."""
        x = self.xor(other)
        if x == 0:
            return NODE_ID_BITS
        # Position of the highest set bit (0-indexed from MSB).
        # Equivalent to floor(log2(x)) for x > 0.
        msb = x.bit_length() - 1
        return NODE_ID_BITS - 1 - msb

    def hex(self) -> str:
        return self.raw.hex()


# ── Contact (a peer's endpoint info as known to the routing table) ─


@dataclass(frozen=True)
class Contact:
    """One row in a k-bucket. ``id`` is the SHA-256 of the peer's
    pubkey; ``address`` is opaque to the algorithm (UDP "ip:port",
    WebRTC offer envelope, Tor onion address — whatever the
    transport layer expects)."""
    id: NodeID
    address: str
    # last_seen_ms is the LRU bucket-eviction order. Updated on
    # every successful contact (ping reply, FIND_NODE response,
    # incoming RPC). Highest = most recently seen.
    last_seen_ms: int = 0


# ── KBucket ────────────────────────────────────────────────────────


@dataclass
class KBucket:
    """One bucket of the routing table. Stores up to k contacts in
    LRU order; on overflow the LEAST recently seen is evicted only
    if a probe to it fails (Kademlia §2.2 "old contacts are kept").
    For this primitive we keep the simplification: LRU eviction
    without a probe, since the probe is a transport concern. The
    transport layer can intercept the eviction signal and skip it
    when the to-be-evicted contact is still alive."""
    contacts: list[Contact] = field(default_factory=list)
    k: int = DEFAULT_K

    def add(self, c: Contact) -> Optional[Contact]:
        """Add or refresh a contact. Returns the contact that was
        evicted if any (caller can re-insert if the probe finds it
        still alive)."""
        # If already present: refresh (move to LRU tail).
        for i, existing in enumerate(self.contacts):
            if existing.id == c.id:
                self.contacts.pop(i)
                self.contacts.append(c)
                return None
        # If room: append.
        if len(self.contacts) < self.k:
            self.contacts.append(c)
            return None
        # Bucket full: evict head (least-recently-seen).
        evicted = self.contacts.pop(0)
        self.contacts.append(c)
        return evicted

    def remove(self, node_id: NodeID) -> bool:
        for i, c in enumerate(self.contacts):
            if c.id == node_id:
                self.contacts.pop(i)
                return True
        return False

    def __iter__(self):
        return iter(self.contacts)

    def __len__(self):
        return len(self.contacts)


# ── RoutingTable ───────────────────────────────────────────────────


class RoutingTable:
    """Kademlia routing table: NODE_ID_BITS buckets, indexed by the
    common-prefix-length of (target ↔ self). Every contact lands in
    exactly one bucket; lookup walks buckets outward from the target's
    bucket to gather K closest contacts."""

    def __init__(self, self_id: NodeID, *, k: int = DEFAULT_K):
        self.self_id = self_id
        self.k = k
        self._buckets: list[KBucket] = [
            KBucket(k=k) for _ in range(NODE_ID_BITS)
        ]

    def _bucket_for(self, target_id: NodeID) -> int:
        idx = self.self_id.common_prefix_length(target_id)
        # common_prefix_length == NODE_ID_BITS only when target_id == self_id;
        # we never store ourselves, so clamp to last bucket if it
        # happens (defensive).
        if idx >= NODE_ID_BITS:
            return NODE_ID_BITS - 1
        return idx

    def add(self, contact: Contact) -> Optional[Contact]:
        if contact.id == self.self_id:
            return None  # never store ourselves
        return self._buckets[self._bucket_for(contact.id)].add(contact)

    def remove(self, node_id: NodeID) -> bool:
        if node_id == self.self_id:
            return False
        return self._buckets[self._bucket_for(node_id)].remove(node_id)

    def find_closest(
        self, target_id: NodeID, *, n: Optional[int] = None,
    ) -> list[Contact]:
        """Return up to ``n`` (default K) contacts ordered by
        increasing XOR distance from ``target_id``. The Kademlia
        FIND_NODE response shape."""
        if n is None:
            n = self.k
        all_contacts: list[Contact] = []
        for bucket in self._buckets:
            all_contacts.extend(bucket)
        all_contacts.sort(key=lambda c: c.id.xor(target_id))
        return all_contacts[:n]

    def __len__(self) -> int:
        return sum(len(b) for b in self._buckets)


# ── iterative lookup (network-agnostic core) ──────────────────────


@dataclass
class LookupResult:
    target_id: NodeID
    closest: list[Contact]
    queried: int


def iterative_lookup(
    *,
    self_id: NodeID,
    target_id: NodeID,
    table: RoutingTable,
    rpc_find_node,
    k: int = DEFAULT_K,
    alpha: int = DEFAULT_ALPHA,
    max_rounds: int = 20,
) -> LookupResult:
    """Run a Kademlia-style iterative FIND_NODE lookup.

    ``rpc_find_node(contact, target_id)`` is the transport hook —
    given a contact, return up to K contacts that contact knows
    closest to target_id. The caller wires this to UDP / WebRTC /
    whatever; the algorithm itself is transport-agnostic.

    The function returns the K closest contacts the search converged
    on. Convergence: a round completes without any newly-discovered
    contact being closer than the closest already-queried one.

    This is the synchronous-skeleton form. The async variant (used
    by the live transport) is structurally identical with
    ``rpc_find_node`` swapped to an awaitable. The algorithm
    invariants (shortlist monotonic-closeness, bounded round count)
    hold under either form."""
    queried: set[NodeID] = set()
    # Shortlist: known contacts ordered by XOR distance to target.
    shortlist: list[Contact] = list(table.find_closest(target_id, n=k))
    # Track the closest distance seen so we can detect convergence.
    if not shortlist:
        return LookupResult(
            target_id=target_id, closest=[], queried=0,
        )
    best_distance = shortlist[0].id.xor(target_id)

    for _ in range(max_rounds):
        # Pick α unqueried-and-closest contacts from the shortlist.
        candidates = [
            c for c in shortlist if c.id not in queried and c.id != self_id
        ][:alpha]
        if not candidates:
            break
        # Query each candidate; each returns its known-closest.
        new_contacts: list[Contact] = []
        for c in candidates:
            queried.add(c.id)
            try:
                rsp = rpc_find_node(c, target_id) or []
            except Exception:
                rsp = []
            for rc in rsp:
                if rc.id == self_id:
                    continue
                new_contacts.append(rc)
                # Add to our local routing table so future lookups
                # benefit from the discovery.
                table.add(rc)
        # Merge discovered into shortlist, dedupe, re-sort.
        seen_ids = {c.id for c in shortlist}
        for nc in new_contacts:
            if nc.id not in seen_ids:
                shortlist.append(nc)
                seen_ids.add(nc.id)
        shortlist.sort(key=lambda c: c.id.xor(target_id))
        shortlist = shortlist[:k]
        # Convergence check: did this round get strictly closer?
        cur_best = shortlist[0].id.xor(target_id)
        if cur_best >= best_distance and all(
            c.id in queried for c in shortlist[:alpha]
        ):
            break
        best_distance = min(best_distance, cur_best)
    return LookupResult(
        target_id=target_id,
        closest=shortlist,
        queried=len(queried),
    )

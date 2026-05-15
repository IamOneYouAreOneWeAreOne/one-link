"""Capability-grant store — live integration of Bundle 44 grants into
the daemon's capability-allowed checks.

Bundle 44 shipped the signed-grant primitive + tests. Bundle 56
wires it into a CapStore the Daemon owns + queries. Flow:

  1. Granter mints a grant via ``caps_grants.encode_grant`` and
     ships it to the subject (typically over their existing
     1-on-1 channel, or attached to a sealed-relay frame from
     Bundle 52).
  2. Subject's daemon calls ``CapStore.accept(grant_blob,
     expected_subject_pub=self_pub)``. This verifies the
     signature + freshness + expiry + replay, stores on success.
  3. When the daemon evaluates ``_capability_allowed(peer_fp,
     cap, scope=...)``, it checks BOTH the legacy binary
     pinned/unpinned state AND the CapStore. A peer with a valid
     grant is allowed even if not formally paired (the granter's
     signature attests authority).

The store auto-expires entries on every read AND on a periodic
prune; replay-by-nonce is bounded; revoked peers have all their
grants flushed atomically.

Threat caveats
--------------

  - **Granter trust**: a grant is only as trustworthy as the
    granter's pubkey. The CapStore verifies the signature but
    doesn't decide whether THE GRANTER themselves is trusted —
    that's the daemon's policy layer (typically: granter must
    be paired AND have authority over the resource).
  - **Audit-log replay**: grants log their nonce + timestamp on
    accept so the daemon can later reconstruct the authority
    chain for a given operation. Out of scope here; surface
    deferred.
"""
from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional

from one_link import caps_grants


@dataclass
class _StoredGrant:
    grant: caps_grants.CapabilityGrant
    accepted_ms: int


def _new_seen_nonces() -> "OrderedDict[bytes, None]":
    """Audit M11 May 2026: replay-defense container. Uses an
    ``OrderedDict`` so eviction-on-overflow drops the OLDEST nonce
    via ``popitem(last=False)``. The previous implementation used a
    plain ``set`` and ``set.pop()`` which evicts a RANDOM element,
    so an adversary that spam-submits valid grants could purge an
    honest peer's old nonce and then replay the original grant.
    The OrderedDict's insertion-order semantics make eviction
    deterministic and adversary-resistant.
    """
    return OrderedDict()


@dataclass
class CapStore:
    """Per-daemon active-grant store. Construct one at boot;
    daemon attaches it to itself + queries it from
    ``_capability_allowed``."""
    # Replay-defense map: every grant nonce we've ever accepted,
    # in insertion order. Bounded; OLDEST evicted when over cap
    # (audit M11). The mapping value is `None` — we only need the
    # key set with ordered semantics.
    seen_nonces: "OrderedDict[bytes, None]" = field(default_factory=_new_seen_nonces)
    max_seen_nonces: int = 100_000
    # Active grants keyed by (granter_pub, subject_pub, nonce).
    # Multiple grants can coexist for the same (granter, subject)
    # pair so we use the nonce as the disambiguator.
    _grants: dict[tuple[bytes, bytes, bytes], _StoredGrant] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self._grants)

    def accept(
        self,
        grant_blob: bytes,
        *,
        expected_subject_pub: bytes,
        expected_granter_pub: Optional[bytes] = None,
        now_ms: Optional[int] = None,
    ) -> caps_grants.CapabilityGrant:
        """Verify + store a grant. Returns the parsed grant on
        success. Raises ValueError on signature/freshness/replay
        failure."""
        verified = caps_grants.verify_grant(
            grant_blob,
            expected_subject_pub=expected_subject_pub,
            expected_granter_pub=expected_granter_pub,
            now_ms=now_ms,
            seen_nonces=self.seen_nonces,
        )
        # Audit M11 May 2026: bound the seen-nonces set with
        # OLDEST-first eviction (popitem(last=False)) so an
        # attacker can't grind a flood of legitimate grants to
        # purge an honest peer's old nonce and then replay it.
        if len(self.seen_nonces) > self.max_seen_nonces:
            # Drop ~10% to amortize.
            drop_n = self.max_seen_nonces // 10
            for _ in range(drop_n):
                try:
                    self.seen_nonces.popitem(last=False)
                except KeyError:
                    break
        if now_ms is None:
            now_ms = int(time.time() * 1000)
        key = (verified.granter_pub, verified.subject_pub, verified.nonce)
        self._grants[key] = _StoredGrant(grant=verified, accepted_ms=now_ms)
        return verified

    def prune_expired(self, *, now_ms: Optional[int] = None) -> int:
        """Drop grants whose ``not_after_ms`` has passed. Returns
        the count dropped. Cheap; safe to call on every check or
        periodically."""
        if now_ms is None:
            now_ms = int(time.time() * 1000)
        dead = [
            k for k, sg in self._grants.items()
            if now_ms > sg.grant.not_after_ms
        ]
        for k in dead:
            self._grants.pop(k, None)
        return len(dead)

    def revoke_subject(self, subject_pub: bytes) -> int:
        """Drop every grant directed at this subject. Used when a
        peer is explicitly revoked (audit-fix path)."""
        dead = [
            k for k in self._grants if k[1] == subject_pub
        ]
        for k in dead:
            self._grants.pop(k, None)
        return len(dead)

    def revoke_granter(self, granter_pub: bytes) -> int:
        """Drop every grant ISSUED BY this granter. Used when the
        granter's authority itself is revoked."""
        dead = [
            k for k in self._grants if k[0] == granter_pub
        ]
        for k in dead:
            self._grants.pop(k, None)
        return len(dead)

    def has_capability(
        self,
        *,
        granter_pub: bytes,
        subject_pub: bytes,
        capability: str,
        scope: Optional[bytes] = None,
        now_ms: Optional[int] = None,
    ) -> bool:
        """Return True iff the store has an active grant from
        ``granter_pub`` to ``subject_pub`` covering ``capability``
        within ``scope`` and not yet expired.

        Audit H12 May 2026 — strict exact-match scope semantics:
          - Query ``scope=None`` (caller didn't specify): match
            ONLY grants whose ``g.scope == b""`` (unrestricted).
          - Query ``scope=b"X"``: match ONLY grants whose
            ``g.scope == b"X"`` exactly.

        Previously a scope-restricted grant satisfied unscoped
        queries: a grant minted for ``b"folder-A"`` could authorize
        a request that never specified its scope (e.g. ``files:read``
        on folder-B). Now: a scoped grant is INVISIBLE to callers
        that don't pass its specific scope, and an unscoped query
        is invisible to scoped grants.
        """
        if now_ms is None:
            now_ms = int(time.time() * 1000)
        # Compute the effective query scope. ``None`` is mapped to
        # ``b""`` so the comparison below is a single exact-equality
        # check regardless of which way the caller passes "no scope".
        query_scope: bytes = b"" if scope is None else scope
        for k, sg in list(self._grants.items()):
            if k[0] != granter_pub or k[1] != subject_pub:
                continue
            g = sg.grant
            if now_ms < g.not_before_ms or now_ms > g.not_after_ms:
                # Inline expiry sweep so a stale entry doesn't keep
                # surviving through reads.
                if now_ms > g.not_after_ms:
                    self._grants.pop(k, None)
                continue
            if capability not in g.capabilities:
                continue
            # Strict-scope rule (audit H12): scopes must match exactly.
            if g.scope != query_scope:
                continue
            return True
        return False

    def list_grants_for(
        self, *, subject_pub: bytes,
        now_ms: Optional[int] = None,
    ) -> list[caps_grants.CapabilityGrant]:
        """Return every active grant addressed to ``subject_pub``,
        suppressing expired entries. Useful for audit / UI render."""
        if now_ms is None:
            now_ms = int(time.time() * 1000)
        out = []
        for k, sg in list(self._grants.items()):
            if k[1] != subject_pub:
                continue
            g = sg.grant
            if now_ms > g.not_after_ms:
                self._grants.pop(k, None)
                continue
            out.append(g)
        return out

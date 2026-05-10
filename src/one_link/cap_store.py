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
from dataclasses import dataclass, field
from typing import Optional

from one_link import caps_grants


@dataclass
class _StoredGrant:
    grant: caps_grants.CapabilityGrant
    accepted_ms: int


@dataclass
class CapStore:
    """Per-daemon active-grant store. Construct one at boot;
    daemon attaches it to itself + queries it from
    ``_capability_allowed``."""
    # Replay-defense set: every grant nonce we've ever accepted.
    # Bounded; oldest evicted when over cap.
    seen_nonces: set[bytes] = field(default_factory=set)
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
        # Bound the seen-nonces set.
        if len(self.seen_nonces) > self.max_seen_nonces:
            # Drop ~10% to amortize.
            drop_n = self.max_seen_nonces // 10
            for _ in range(drop_n):
                try:
                    self.seen_nonces.pop()
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
        within ``scope`` (when supplied) and not yet expired."""
        if now_ms is None:
            now_ms = int(time.time() * 1000)
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
            if scope is not None and g.scope != scope:
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

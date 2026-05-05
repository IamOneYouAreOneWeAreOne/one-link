"""Pairing: 6-digit SAS (Short Authentication String) for trust-on-first-use.

The user-facing flow:
  1. User clicks Pair on a discovered peer.
  2. Both daemons display the same 6-digit code, derived from BOTH peers'
     long-term Ed25519 public keys (deterministic — no ephemeral input).
  3. User on each side compares the codes verbally / visually and clicks
     "Match" or "Mismatch."
  4. When both sides confirm Match, both peers auto-pin each other.
     A code mismatch means a man-in-the-middle is intercepting the LAN —
     the user rejects.

After successful pairing, the peer is `pinned` permanently. Subsequent
launches reconnect silently with no UI prompts (the magic feel).

The SAS is derived as:
    h = BLAKE3(sorted_concat(pubkey_a, pubkey_b) || "OL-SAS-v1")
    sas = (first 4 bytes of h, big-endian) mod 1_000_000

Sorting the inputs ensures both sides compute the same value regardless
of who initiated.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import blake3


_SAS_INFO = b"OL-SAS-v1"


def compute_sas(my_pubkey: bytes, peer_pubkey: bytes) -> str:
    """Deterministic 6-digit code visible to both peers. Same code on both
    sides as long as both have each other's authenticated pubkeys."""
    if len(my_pubkey) != 32 or len(peer_pubkey) != 32:
        raise ValueError("pubkeys must be 32 bytes (Ed25519 raw)")
    pair = sorted([my_pubkey, peer_pubkey])
    h = blake3.blake3(pair[0] + pair[1] + _SAS_INFO).digest()
    n = int.from_bytes(h[:4], "big") % 1_000_000
    return f"{n:06d}"


def format_sas(sas: str) -> str:
    """Display form: '123 456' (easier to read aloud)."""
    s = sas.zfill(6)
    return f"{s[:3]} {s[3:]}"


class PairState(str, Enum):
    NONE = "none"            # never tried
    REQUESTED = "requested"  # we sent PAIR_REQUEST, awaiting peer's confirm
    INCOMING = "incoming"    # peer sent us PAIR_REQUEST, we haven't decided
    CONFIRMED = "confirmed"  # we said yes; awaiting peer's yes
    PAIRED = "paired"        # both sides confirmed → trust='pinned' set
    REJECTED = "rejected"    # user rejected the SAS — possible MITM


@dataclass
class PairContext:
    peer_fp: str
    sas: str
    state: PairState = PairState.NONE
    started_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    we_confirmed: bool = False
    they_confirmed: bool = False

    @property
    def both_confirmed(self) -> bool:
        return self.we_confirmed and self.they_confirmed


class PairingTracker:
    """In-memory pairing-attempt tracker. Persists nothing; trust state is
    persisted via state.set_peer_trust('pinned') once both sides confirm."""

    def __init__(self) -> None:
        self._by_peer: dict[str, PairContext] = {}

    def get(self, peer_fp: str) -> Optional[PairContext]:
        return self._by_peer.get(peer_fp)

    def begin(self, *, peer_fp: str, sas: str, incoming: bool) -> PairContext:
        ctx = PairContext(
            peer_fp=peer_fp,
            sas=sas,
            state=PairState.INCOMING if incoming else PairState.REQUESTED,
        )
        self._by_peer[peer_fp] = ctx
        return ctx

    def we_confirm(self, peer_fp: str) -> Optional[PairContext]:
        ctx = self._by_peer.get(peer_fp)
        if not ctx:
            return None
        ctx.we_confirmed = True
        if ctx.both_confirmed:
            ctx.state = PairState.PAIRED
        else:
            ctx.state = PairState.CONFIRMED
        return ctx

    def they_confirm(self, peer_fp: str) -> Optional[PairContext]:
        ctx = self._by_peer.get(peer_fp)
        if not ctx:
            return None
        ctx.they_confirmed = True
        if ctx.both_confirmed:
            ctx.state = PairState.PAIRED
        return ctx

    def reject(self, peer_fp: str) -> Optional[PairContext]:
        ctx = self._by_peer.get(peer_fp)
        if ctx:
            ctx.state = PairState.REJECTED
        return ctx

    def clear(self, peer_fp: str) -> None:
        self._by_peer.pop(peer_fp, None)

    def all(self) -> list[PairContext]:
        return list(self._by_peer.values())

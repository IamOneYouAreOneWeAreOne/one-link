"""Pairing: 8-digit SAS (Short Authentication String) for trust-on-first-use.

The user-facing flow:
  1. User clicks Pair on a discovered peer.
  2. Both daemons display the same 8-digit code, derived from BOTH peers'
     long-term Ed25519 public keys AND the encrypted-channel handshake
     transcript hash (a fresh per-session value bound to both sides'
     ephemerals + signatures).
  3. User on each side compares the codes verbally / visually and clicks
     "Match" or "Mismatch."
  4. When both sides confirm Match, both peers auto-pin each other.
     A code mismatch means a man-in-the-middle is intercepting the LAN —
     the user rejects.

After successful pairing, the peer is `pinned` permanently. Subsequent
launches reconnect silently with no UI prompts (the magic feel).

The SAS is derived as (v2, v0.20.7+):
    h = BLAKE3(transcript_hash || sorted_concat(pubkey_a, pubkey_b) || "OL-SAS-v2")
    sas = (first 5 bytes of h, big-endian) mod 100_000_000

Why the bump (security audit H11):

  v1 was a static function of the long-term pubkeys only — exactly
  20 bits of entropy (`% 1_000_000`). A LAN-active MITM grinding
  ~1M Ed25519 keypairs (under a minute on commodity hardware) could
  find a key whose v1 SAS-with-Alice matched a chosen target value;
  with offline grinding both sides of a two-sided substitution
  became feasible.

  v2 folds in the encrypted channel's transcript_hash — fresh per
  session, bound to both peers' ephemerals + signatures — so an
  attacker can no longer pre-compute a colliding key. They have to
  grind during the live pair window, against a code that's also
  longer (8 digits ≈ 26.6 bits, so ~100M Ed25519 ops per single
  collision instead of ~1M). 5-minute pairing TTL caps the live
  grind window. Birthday bound on 8 digits is comfortable for the
  trust ceremony.

Sorting the inputs ensures both sides compute the same value
regardless of who initiated. Both sides have the SAME transcript_hash
because the channel-handshake transcript is mirror-identical on
either end of the same TCP connection (audit fix #10 verified).

Backward compatibility (v1 fallback):

  If a caller invokes compute_sas without a transcript_hash (e.g. a
  pre-v0.20.7 peer that doesn't carry one through), the function
  falls back to the legacy 6-digit v1 SAS so the existing pair-flow
  doesn't break in the upgrade window. New users always get v2.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import blake3


_SAS_INFO_V1 = b"OL-SAS-v1"
_SAS_INFO_V2 = b"OL-SAS-v2"

# v0.20.7 (security audit H12): pair contexts auto-expire after 5
# minutes. Without this, a stale "Match" prompt that the user
# ignored at 10:00 stays armed forever; an attacker positioned
# later can ride the still-armed ctx into a confirm. The TTL is
# enforced at the daemon layer where the user-facing PAIR_REQUEST
# / PAIR_CONFIRM handlers live; the helper here exposes is_expired().
PAIR_CONTEXT_TTL_MS = 5 * 60 * 1000

# v0.20.7 (security audit M19): PairingTracker hard-cap. A LAN
# attacker who hops MAC / short_ids can otherwise grow the in-memory
# tracker without bound. 256 is generous (typical user has < 10
# devices); on overflow we evict the oldest insertion.
MAX_PAIR_CONTEXTS = 256


def compute_sas(
    my_pubkey: bytes,
    peer_pubkey: bytes,
    *,
    transcript_hash: Optional[bytes] = None,
) -> str:
    """Same code on both sides for the same channel handshake.

    With transcript_hash (v2): 8-digit code bound to the encrypted
    channel transcript so offline grinding cannot pre-compute a
    colliding key. With transcript_hash=None (v1 legacy): 6-digit
    code from pubkeys only, kept solely for compatibility with
    pre-v0.20.7 peers that did not carry the transcript through to
    the SAS-display call site.
    """
    if len(my_pubkey) != 32 or len(peer_pubkey) != 32:
        raise ValueError("pubkeys must be 32 bytes (Ed25519 raw)")
    pair = sorted([my_pubkey, peer_pubkey])
    if transcript_hash:
        h = blake3.blake3(
            bytes(transcript_hash) + pair[0] + pair[1] + _SAS_INFO_V2
        ).digest()
        n = int.from_bytes(h[:5], "big") % 100_000_000
        return f"{n:08d}"
    # Legacy fallback.
    h = blake3.blake3(pair[0] + pair[1] + _SAS_INFO_V1).digest()
    n = int.from_bytes(h[:4], "big") % 1_000_000
    return f"{n:06d}"


def format_sas(sas: str) -> str:
    """Display form: '12 345 678' for v2 (8 digits) or '123 456' for v1.
    Picking 3-digit groups for v2 keeps it easy to read aloud."""
    if len(sas) == 8:
        return f"{sas[:2]} {sas[2:5]} {sas[5:]}"
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
    # v0.20.7 (security audit M20): set when the per-peer trust state
    # at the moment we begin a fresh pair attempt was already
    # `rejected`. The daemon surfaces this in the WS pair_request
    # event so the UI can show a "previously blocked" warning before
    # the user clicks Match — closes the social-engineering re-pair
    # path where an attacker who was previously blocked simply asks
    # the user to re-add them and the trust=rejected → pinned flip
    # was silent.
    previously_rejected: bool = False
    # v0.20.7 (security audit H12): explicit TTL on the context so
    # the daemon can reject stale "Match" prompts.
    ttl_ms: int = field(default=PAIR_CONTEXT_TTL_MS)

    @property
    def both_confirmed(self) -> bool:
        return self.we_confirmed and self.they_confirmed

    def is_expired(self, *, now_ms: Optional[int] = None) -> bool:
        cutoff = (now_ms if now_ms is not None else int(time.time() * 1000))
        return cutoff - self.started_ms > self.ttl_ms


class PairingTracker:
    """In-memory pairing-attempt tracker. Persists nothing; trust state is
    persisted via state.set_peer_trust('pinned') once both sides confirm.

    v0.20.7 (security audit M19): bounded at MAX_PAIR_CONTEXTS via
    insertion-order LRU. Backed by OrderedDict so an oldest-first
    eviction is O(1). Expired contexts are evicted lazily on read
    (get / we_confirm / they_confirm) to keep an attacker who hops
    short_ids from indefinitely growing the dict."""

    def __init__(self) -> None:
        self._by_peer: "OrderedDict[str, PairContext]" = OrderedDict()

    def _maybe_evict_expired(self, peer_fp: str) -> None:
        ctx = self._by_peer.get(peer_fp)
        if ctx is not None and ctx.is_expired():
            self._by_peer.pop(peer_fp, None)

    def get(self, peer_fp: str) -> Optional[PairContext]:
        self._maybe_evict_expired(peer_fp)
        return self._by_peer.get(peer_fp)

    def begin(
        self,
        *,
        peer_fp: str,
        sas: str,
        incoming: bool,
        previously_rejected: bool = False,
    ) -> PairContext:
        ctx = PairContext(
            peer_fp=peer_fp,
            sas=sas,
            state=PairState.INCOMING if incoming else PairState.REQUESTED,
            previously_rejected=previously_rejected,
        )
        # Replace any stale ctx for this peer in-place; touch insertion
        # order so the new entry is youngest.
        self._by_peer.pop(peer_fp, None)
        self._by_peer[peer_fp] = ctx
        # v0.20.7 (security audit M19): hard cap. On overflow drop the
        # oldest entry. begin() being the only insertion point means
        # we can enforce here without scanning.
        while len(self._by_peer) > MAX_PAIR_CONTEXTS:
            self._by_peer.popitem(last=False)
        return ctx

    def we_confirm(self, peer_fp: str) -> Optional[PairContext]:
        self._maybe_evict_expired(peer_fp)
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
        self._maybe_evict_expired(peer_fp)
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

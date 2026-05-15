"""TrustLedger — per-daemon ledger of pinned peer master_vk keys.

Audit C2 closure surface: when a peer presents a master_vk we
haven't seen before — or one we have seen but it differs from the
pinned value — the daemon routes the decision through
:func:`identity_sas.evaluate_rotation` and acts on the
:class:`RotationDecision`:

  * First contact → record TOFU, allow_call=True, needs_reverify=True
    (UI will show SAS).
  * Same key → allow, skip SAS.
  * Different key + valid chain signature from prior key → allow
    with re-verify offer ("Mom updated her keys").
  * Different key + broken chain → **refuse** the call.

The ledger is in-memory by default. It exposes a clean
serialise/deserialise surface so the daemon's SQLite state layer
can persist it (the daemon's existing trust-store schema is the
target).

The actual signature verification (the ``verify_prior_signature``
callback in :func:`evaluate_rotation`) is plugged at construction
— production wires it to ``identity.verify``; tests substitute a
mock.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §7.1 (audit C2 closure)
"""

from __future__ import annotations

import logging
import threading
from dataclasses import asdict, dataclass, field
from typing import Callable, Optional

from one_link.identity_sas import (
    RotationDecision,
    TrustRecord,
    VerificationState,
    evaluate_rotation,
)

log = logging.getLogger(__name__)


# Signature-verify callable contract: takes hex pubkeys + sig bytes,
# returns True iff sig is a valid Ed25519 signature by ``prior_vk_hex``
# over the canonical "key rotation" transcript binding new_vk_hex.
VerifyPriorSignature = Callable[[str, str, bytes], bool]


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------

class TrustLedger:
    """In-memory ledger + thread-safe lookups.

    The daemon constructs ONE instance per identity (so a desktop
    + a phone, both running their own daemons, have independent
    ledgers — each is its own perspective on "who I trust"). Add
    a peer's pinned key with :meth:`record_pinned`; check an
    inbound observation with :meth:`check_inbound`.
    """

    def __init__(
        self,
        *,
        verify_prior_signature: VerifyPriorSignature,
    ) -> None:
        self._records: dict[str, TrustRecord] = {}
        self._lock = threading.Lock()
        self._verify = verify_prior_signature

    # ── Pinning + recording ──────────────────────────────────

    def record_pinned(
        self,
        *,
        peer_master_vk_hex: str,
        verified_at_ms: int,
        state: VerificationState = VerificationState.TRUSTED,
        previous_master_vk_hex: Optional[str] = None,
    ) -> None:
        """Add or update a pin. Idempotent: re-pinning the same key
        updates the timestamp but doesn't disturb other state."""
        with self._lock:
            self._records[peer_master_vk_hex] = TrustRecord(
                peer_master_vk_hex=peer_master_vk_hex,
                verified_at_ms=verified_at_ms,
                state=state,
                previous_master_vk_hex=previous_master_vk_hex,
            )

    def get(self, peer_master_vk_hex: str) -> Optional[TrustRecord]:
        with self._lock:
            return self._records.get(peer_master_vk_hex)

    def forget(self, peer_master_vk_hex: str) -> None:
        """Remove a pin (e.g., when the user explicitly revokes
        trust)."""
        with self._lock:
            self._records.pop(peer_master_vk_hex, None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    # ── Rotation check ───────────────────────────────────────

    def check_inbound(
        self,
        *,
        inbound_master_vk_hex: str,
        inbound_signature_from_prior: Optional[bytes],
        previous_pin_hex: Optional[str] = None,
    ) -> RotationDecision:
        """Decide what to do with an observed master_vk.

        Looks up the existing record for ``inbound_master_vk_hex``
        AND for ``previous_pin_hex`` (if the caller knows which
        prior key was pinned). Returns a :class:`RotationDecision`
        the caller acts on.

        The caller (typically the daemon's pairing/handshake code)
        is responsible for:
          - If ``decision.allow_call`` → proceed
          - If ``not decision.allow_call`` → refuse with the
            plain-language explanation
          - If ``decision.needs_reverify`` → surface the SAS UI
        """
        # If the inbound key IS already pinned, that's "same key"
        # — fast path.
        existing = self.get(inbound_master_vk_hex)
        if existing is not None:
            # Defer to evaluate_rotation for consistent decision
            # surface; passing existing=this-record yields the
            # "same key → TRUSTED" branch.
            return evaluate_rotation(
                inbound_master_vk_hex=inbound_master_vk_hex,
                inbound_signature_from_prior=inbound_signature_from_prior,
                existing=existing,
                verify_prior_signature=self._verify,
            )

        # The inbound key differs from anything we have pinned for
        # this peer. Was a different key previously pinned?
        prior = self.get(previous_pin_hex) if previous_pin_hex else None
        return evaluate_rotation(
            inbound_master_vk_hex=inbound_master_vk_hex,
            inbound_signature_from_prior=inbound_signature_from_prior,
            existing=prior,
            verify_prior_signature=self._verify,
        )

    def apply_decision(
        self,
        *,
        inbound_master_vk_hex: str,
        decision: RotationDecision,
        verified_at_ms: int,
        previous_pin_hex: Optional[str] = None,
    ) -> None:
        """If the decision allows the call AND establishes a new
        trust state, persist it.

        Called by the daemon after a successful first-contact SAS
        verification OR after the user re-verifies on rotation.
        Untrusted decisions (CHAIN_BROKEN) don't modify the ledger.
        """
        if not decision.allow_call:
            return
        if decision.new_state == VerificationState.KEY_ROTATED_CHAIN_BROKEN:
            return
        self.record_pinned(
            peer_master_vk_hex=inbound_master_vk_hex,
            verified_at_ms=verified_at_ms,
            state=decision.new_state,
            previous_master_vk_hex=previous_pin_hex,
        )

    # ── Persistence stubs ────────────────────────────────────

    def snapshot(self) -> list[dict]:
        """Return a JSON-friendly list of all records — the daemon's
        SQLite layer can persist this on shutdown / state sync."""
        with self._lock:
            return [
                {
                    "peer_master_vk_hex": r.peer_master_vk_hex,
                    "verified_at_ms": r.verified_at_ms,
                    "state": int(r.state),
                    "previous_master_vk_hex": r.previous_master_vk_hex,
                }
                for r in self._records.values()
            ]

    def restore(self, snapshot: list[dict]) -> None:
        """Load records from a snapshot. Overwrites existing
        entries. The daemon calls this on startup with whatever
        SQLite persisted."""
        with self._lock:
            for d in snapshot:
                try:
                    state = VerificationState(int(d.get("state", 0)))
                except (TypeError, ValueError):
                    state = VerificationState.UNVERIFIED
                vk_hex = d.get("peer_master_vk_hex")
                if not isinstance(vk_hex, str) or not vk_hex:
                    continue
                try:
                    verified_at_ms = int(d.get("verified_at_ms", 0))
                except (TypeError, ValueError):
                    verified_at_ms = 0
                self._records[vk_hex] = TrustRecord(
                    peer_master_vk_hex=vk_hex,
                    verified_at_ms=verified_at_ms,
                    state=state,
                    previous_master_vk_hex=d.get("previous_master_vk_hex"),
                )

    def clear(self) -> None:
        with self._lock:
            self._records.clear()

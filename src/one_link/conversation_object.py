"""Conversation-as-object capabilities.

Per LIVING_PRESENCE_ARCHITECTURE.md §7.3, conversations are
first-class objects with their own rights. Each conversation
carries a set of granted capabilities controlling what can be done
with it:

  - SUMMARIZE         — AI/operator can read and summarise the conversation
  - PERSIST_LOCALLY   — daemon may save it to disk past memory window
  - PERSIST_TO_ACE    — relational-memory substrate may absorb it
  - SHARE_EXCERPT     — participant may forward a snippet to a third party
  - INDEX_FOR_SEARCH  — searchable in future "find a conversation" UI
  - AUTO_TRANSCRIBE   — local captions generated for accessibility
  - AUTO_TRANSLATE    — translation available
  - RECORD            — recorded artifact may be created (gated by
                        :class:`RecordingConsent` for the live moment)

Default state: every capability is **not granted**. The conversation
"refuses by default." Each grant is a deliberate, audited action
by a participant that holds granting authority — either themselves
acting on their own data, or both parties for shared actions.

The capability tokens are macaroon-style: attenuable, revocable,
HMAC-chained. The actual macaroon implementation reuses the
existing ``ol_capability`` Rust crate; this module is the typed
adapter that the daemon + UI use to reason about conversation
rights.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §7.3
"""

from __future__ import annotations

import hashlib
import os
import threading
from dataclasses import dataclass, field, replace
from enum import IntEnum
from typing import Optional


# ---------------------------------------------------------------------------
# Capability vocabulary
# ---------------------------------------------------------------------------

class ConversationCap(IntEnum):
    """Rights a conversation may grant. Lower-numbered are more
    common; higher-numbered touch deeper integrations."""

    SUMMARIZE         = 0
    PERSIST_LOCALLY   = 1
    PERSIST_TO_ACE    = 2
    SHARE_EXCERPT     = 3
    INDEX_FOR_SEARCH  = 4
    AUTO_TRANSCRIBE   = 5
    AUTO_TRANSLATE    = 6
    RECORD            = 7


# Capabilities that require BOTH parties to consent before being
# valid. Asymmetric rights (PERSIST_LOCALLY on YOUR own copy) can
# be granted unilaterally; symmetric rights (RECORD the shared
# stream) cannot.
_REQUIRES_MUTUAL = frozenset({
    ConversationCap.RECORD,
    ConversationCap.SHARE_EXCERPT,
})


# Capabilities the conversation REFUSES by default — applying for
# them requires an explicit grant ceremony in the UI. All of them
# refuse by default; this set is the universe.
ALL_CAPS: frozenset[ConversationCap] = frozenset(ConversationCap)


# ---------------------------------------------------------------------------
# Grant token
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ConversationGrant:
    """One grant. Persistent through CRDT sync; revocable.

    ``granter_vk_hex`` is who granted it. For mutual caps, two
    grants from BOTH participants must be present before the cap
    counts as held.

    ``token`` is a 32-byte macaroon-chain ID. The actual macaroon
    structure lives in ``ol_capability``; this is the typed handle.
    """

    cap: ConversationCap
    granter_vk_hex: str
    granted_at_ms: int
    expires_at_ms: Optional[int] = None      # None = until revoked
    token: bytes = b""
    revoked: bool = False
    revoked_at_ms: Optional[int] = None

    def is_active_at(self, now_ms: int) -> bool:
        if self.revoked:
            return False
        if self.expires_at_ms is not None and now_ms >= self.expires_at_ms:
            return False
        return True


# ---------------------------------------------------------------------------
# Conversation rights state
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ConversationRights:
    """The full rights state for one conversation. Immutable
    snapshot. Updates produce a NEW instance via the helper methods.

    The ``grants`` tuple contains every grant the conversation has
    received (both active and revoked). Revoked grants are kept
    around so the audit trail is complete; queries filter by
    is_active_at."""

    conversation_id: str
    participants_vk_hex: frozenset[str]
    grants: tuple[ConversationGrant, ...] = ()

    # ── Queries ──────────────────────────────────────────────

    def holds_cap_at(self, cap: ConversationCap, *, now_ms: int) -> bool:
        """True iff the conversation currently holds ``cap``.

        For asymmetric caps: at least one active grant exists from
        any participant.
        For mutual caps: every participant has an active grant.
        """
        active_granters = {
            g.granter_vk_hex
            for g in self.grants
            if g.cap == cap and g.is_active_at(now_ms)
        }
        if cap in _REQUIRES_MUTUAL:
            return active_granters >= self.participants_vk_hex
        return bool(active_granters)

    def active_grants_for(
        self, cap: ConversationCap, *, now_ms: int,
    ) -> tuple[ConversationGrant, ...]:
        return tuple(
            g for g in self.grants
            if g.cap == cap and g.is_active_at(now_ms)
        )

    def all_active_caps_at(self, now_ms: int) -> frozenset[ConversationCap]:
        return frozenset(
            c for c in ConversationCap
            if self.holds_cap_at(c, now_ms=now_ms)
        )

    # ── Mutators (return new state) ──────────────────────────

    def with_grant(self, grant: ConversationGrant) -> "ConversationRights":
        """Append a grant. Doesn't validate signatures (caller's
        responsibility — the daemon checks the macaroon before
        invoking this)."""
        if grant.granter_vk_hex not in self.participants_vk_hex:
            raise ValueError(
                f"granter {grant.granter_vk_hex} is not a participant "
                f"of this conversation"
            )
        return replace(self, grants=self.grants + (grant,))

    def with_revoked(
        self,
        cap: ConversationCap,
        granter_vk_hex: str,
        *,
        revoked_at_ms: int,
    ) -> "ConversationRights":
        """Mark all matching grants as revoked.

        Revocation is unconditional: a granter may revoke their own
        previously-issued grant at any time.
        """
        new_grants = []
        for g in self.grants:
            if (
                g.cap == cap
                and g.granter_vk_hex == granter_vk_hex
                and not g.revoked
            ):
                new_grants.append(
                    replace(g, revoked=True, revoked_at_ms=revoked_at_ms)
                )
            else:
                new_grants.append(g)
        return replace(self, grants=tuple(new_grants))


# ---------------------------------------------------------------------------
# Decision API used by the daemon
# ---------------------------------------------------------------------------

class CapabilityDecision(IntEnum):
    """Result of checking whether a participant may perform an
    action on a conversation."""

    ALLOWED                 = 0
    REFUSED_NO_GRANT        = 1   # cap not granted by required parties
    REFUSED_EXPIRED         = 2   # grant existed but TTL elapsed
    REFUSED_REVOKED         = 3
    REFUSED_NOT_PARTICIPANT = 4   # actor is not in the conversation


@dataclass(frozen=True)
class DecisionResult:
    decision: CapabilityDecision
    explanation: str   # plain-language for the doctrine-compliant UI


def check_action(
    *,
    rights: ConversationRights,
    cap: ConversationCap,
    actor_vk_hex: str,
    now_ms: int,
) -> DecisionResult:
    """Decide whether ``actor_vk_hex`` may perform ``cap`` on the
    conversation right now. Returns a structured decision with a
    plain-language explanation — never an error code (doctrine
    §3.2.d)."""
    if actor_vk_hex not in rights.participants_vk_hex:
        return DecisionResult(
            decision=CapabilityDecision.REFUSED_NOT_PARTICIPANT,
            explanation="You are not part of this conversation.",
        )

    if rights.holds_cap_at(cap, now_ms=now_ms):
        return DecisionResult(
            decision=CapabilityDecision.ALLOWED,
            explanation=_human_action(cap) + " is allowed.",
        )

    # Figure out WHY it's refused.
    matching = tuple(g for g in rights.grants if g.cap == cap)
    if not matching:
        return DecisionResult(
            decision=CapabilityDecision.REFUSED_NO_GRANT,
            explanation=(
                f"This conversation does not allow {_human_action(cap)}. "
                f"Ask the other participant to grant it first."
            ),
        )
    # We have grants but they aren't active.
    if any(g.revoked for g in matching):
        return DecisionResult(
            decision=CapabilityDecision.REFUSED_REVOKED,
            explanation=(
                f"{_human_action(cap)} was revoked. Ask the granter to "
                f"grant it again to continue."
            ),
        )
    return DecisionResult(
        decision=CapabilityDecision.REFUSED_EXPIRED,
        explanation=(
            f"The grant for {_human_action(cap)} has expired. "
            f"Ask for a new one."
        ),
    )


def _human_action(cap: ConversationCap) -> str:
    """Plain-language verb. Doctrine §3.2.f, §3.9.a — never
    references error codes or internal capability names."""
    return {
        ConversationCap.SUMMARIZE:         "summarising the conversation",
        ConversationCap.PERSIST_LOCALLY:   "saving the conversation",
        ConversationCap.PERSIST_TO_ACE:    "adding it to your memory",
        ConversationCap.SHARE_EXCERPT:     "sharing a snippet",
        ConversationCap.INDEX_FOR_SEARCH:  "making it searchable",
        ConversationCap.AUTO_TRANSCRIBE:   "automatic captions",
        ConversationCap.AUTO_TRANSLATE:    "automatic translation",
        ConversationCap.RECORD:            "recording the conversation",
    }[cap]


# ---------------------------------------------------------------------------
# Grant helpers (HMAC-chained tokens)
# ---------------------------------------------------------------------------

def derive_grant_token(
    *,
    conversation_id: str,
    cap: ConversationCap,
    granter_vk_hex: str,
    granted_at_ms: int,
    chain_key: bytes,
) -> bytes:
    """Produce a deterministic 32-byte token for a grant.

    For Tier α-pre this is HMAC(chain_key, canonical(grant fields)).
    Production wiring uses the existing ``ol_capability`` macaroon
    chain — that crate's ``mint_macaroon`` returns the same shape.

    The token is opaque to the holder; the granter retains the
    chain_key and is the only party who can revoke without further
    signature."""
    if len(chain_key) != 32:
        raise ValueError("chain_key must be 32 bytes")
    h = hashlib.blake2b(key=chain_key, digest_size=32)
    h.update(b"ol-conv-grant-v1\x00")
    h.update(conversation_id.encode("utf-8"))
    h.update(bytes([int(cap) & 0xff]))
    h.update(granter_vk_hex.encode("ascii"))
    h.update(granted_at_ms.to_bytes(8, "big", signed=False))
    return h.digest()


def fresh_grant(
    *,
    conversation_id: str,
    cap: ConversationCap,
    granter_vk_hex: str,
    granted_at_ms: int,
    chain_key: bytes,
    expires_at_ms: Optional[int] = None,
) -> ConversationGrant:
    """Convenience builder for a fresh grant with a derived token."""
    token = derive_grant_token(
        conversation_id=conversation_id,
        cap=cap,
        granter_vk_hex=granter_vk_hex,
        granted_at_ms=granted_at_ms,
        chain_key=chain_key,
    )
    return ConversationGrant(
        cap=cap,
        granter_vk_hex=granter_vk_hex,
        granted_at_ms=granted_at_ms,
        expires_at_ms=expires_at_ms,
        token=token,
    )


# ---------------------------------------------------------------------------
# Conversation rights store
# ---------------------------------------------------------------------------

class ConversationRightsStore:
    """Per-daemon: maps conversation_id → ConversationRights.

    Thread-safe. The daemon's chat surface persists this to SQLite;
    this in-memory store is the working copy.
    """

    def __init__(self) -> None:
        self._by_conv: dict[str, ConversationRights] = {}
        self._lock = threading.Lock()

    def open(
        self,
        *,
        conversation_id: str,
        participants_vk_hex: frozenset[str],
    ) -> ConversationRights:
        with self._lock:
            existing = self._by_conv.get(conversation_id)
            if existing is not None:
                return existing
            rights = ConversationRights(
                conversation_id=conversation_id,
                participants_vk_hex=participants_vk_hex,
            )
            self._by_conv[conversation_id] = rights
            return rights

    def get(self, conversation_id: str) -> Optional[ConversationRights]:
        with self._lock:
            return self._by_conv.get(conversation_id)

    def replace(self, rights: ConversationRights) -> None:
        with self._lock:
            self._by_conv[rights.conversation_id] = rights

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_conv)


# ---------------------------------------------------------------------------
# UI labels (plain-language, doctrine-compliant)
# ---------------------------------------------------------------------------

def grant_request_label(cap: ConversationCap) -> str:
    """The text shown when a participant requests a grant. Calm
    language; never an error code."""
    return f"Allow {_human_action(cap)}?"


def grant_revoked_label(cap: ConversationCap) -> str:
    return f"You stopped allowing {_human_action(cap)}."

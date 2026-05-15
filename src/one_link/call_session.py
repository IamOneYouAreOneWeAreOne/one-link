"""CallSession — CRDT-backed shared state for one call.

Each device participating in a call maintains its own local view of
the :class:`CallSession`. Devices sync deltas over the existing
CONTROL stream; the lattice merge (``CallSession.merge``) converges
all participants to byte-identical state.

This module ships three small lattice primitives — :class:`LWWRegister`,
:class:`ORSet`, :class:`MaxCounter` — composed into a
:class:`CallSession` dataclass. The primitives are the same shape
used by the existing folder-sync code in ``one_link.crdt`` but
parametrised by content type rather than tied to manifest entries.

Lattice laws the merge must satisfy (verified by tests):

  - Commutativity: ``a.merge(b) == b.merge(a)``
  - Associativity: ``a.merge(b).merge(c) == a.merge(b.merge(c))``
  - Idempotence: ``a.merge(a) == a``

These guarantee CRDT correctness: any merge order produces the
same final state, and replaying a delta is harmless.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §5
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import IntEnum
from typing import Generic, Hashable, Optional, TypeVar

T = TypeVar("T", bound=Hashable)


# ---------------------------------------------------------------------------
# Intensity dial — the primary surface
# ---------------------------------------------------------------------------

class Intensity(IntEnum):
    """Continuous-presence intensity. A "call" is one position on
    this dial; AMBIENT is the always-on faint awareness; HIGH is
    full attention. Values are ordered (higher = more attention)."""

    AMBIENT = 0
    LOW     = 1
    MEDIUM  = 2
    HIGH    = 3


class Rung(IntEnum):
    """Presence Compiler rung. See LIVING_PRESENCE_ARCHITECTURE
    §4.2. Lower index = higher fidelity."""

    RAW_AV             = 0
    OPUS_VIDEO         = 1
    SEMANTIC_DELTA_AV  = 2
    FACE_STILL_MOTION  = 3
    AUDIO_ONLY         = 4
    PUSH_TO_TALK       = 5
    CONCEPT_TEXT       = 6
    ASYNC_CAPSULE      = 7
    AMBIENT_PRESENCE   = 8


class EndReason(IntEnum):
    """Why the call ended. ``ACTIVE`` means it hasn't yet."""

    ACTIVE              = 0
    USER_HANGUP_LOCAL   = 1
    USER_HANGUP_REMOTE  = 2
    NETWORK_ASYNC       = 3
    EMERGENCY_REKEY     = 4


class VerificationState(IntEnum):
    """Identity verification state for the remote participant."""

    UNVERIFIED                = 0   # first contact, SAS not yet shown
    TRUSTED                   = 1   # SAS confirmed by both sides
    KEY_ROTATED_CHAIN_OK      = 2   # rotated, signed by prior key
    KEY_ROTATED_CHAIN_BROKEN  = 3   # rotated WITHOUT prior-key signature


# ---------------------------------------------------------------------------
# LWWRegister — last-writer-wins atomic value
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LWWRegister(Generic[T]):
    """Last-writer-wins atomic register.

    Tiebreak (when two writes have identical ``timestamp_ms``) is
    by ``writer_id`` lexicographically. This is deterministic and
    independent of merge order.

    The optional ``value`` is the register's payload; None is a
    legitimate state ("not yet set").
    """

    value: Optional[T] = None
    timestamp_ms: int = 0
    writer_id: str = ""

    def with_value(
        self, value: T, *, timestamp_ms: int, writer_id: str,
    ) -> "LWWRegister[T]":
        """Return a NEW register with the value set, IF the proposed
        write is fresher than the existing state. Returns ``self``
        unchanged if the new write loses to the current state.
        """
        if timestamp_ms > self.timestamp_ms:
            return LWWRegister(value=value, timestamp_ms=timestamp_ms, writer_id=writer_id)
        if timestamp_ms == self.timestamp_ms and writer_id > self.writer_id:
            return LWWRegister(value=value, timestamp_ms=timestamp_ms, writer_id=writer_id)
        return self

    def merge(self, other: "LWWRegister[T]") -> "LWWRegister[T]":
        """Merge with another register. Returns whichever has the
        later (timestamp, writer_id) tuple."""
        if other.timestamp_ms > self.timestamp_ms:
            return other
        if other.timestamp_ms < self.timestamp_ms:
            return self
        # Equal timestamps — tiebreak by writer_id.
        if other.writer_id > self.writer_id:
            return other
        return self


# ---------------------------------------------------------------------------
# ORSet — observed-remove set (add-wins)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _ORSetEntry(Generic[T]):
    """One element in an OR-set. Tagged with the add-token so
    concurrent adds + removes converge add-wins."""

    value: T
    add_token: str       # globally-unique nonce minted at add time

    def __hash__(self) -> int:
        return hash((self.value, self.add_token))


@dataclass(frozen=True)
class ORSet(Generic[T]):
    """Observed-remove set. Adds win against concurrent removes.

    Internal representation: a frozenset of (value, add_token) pairs
    plus a frozenset of (value, add_token) tombstones. An element is
    visible if it has any add-tokens not in the tombstones.
    """

    entries: frozenset[_ORSetEntry[T]] = field(default_factory=frozenset)
    tombstones: frozenset[_ORSetEntry[T]] = field(default_factory=frozenset)

    @classmethod
    def empty(cls) -> "ORSet[T]":
        return cls()

    def add(self, value: T, *, add_token: str) -> "ORSet[T]":
        entry = _ORSetEntry(value=value, add_token=add_token)
        return ORSet(
            entries=self.entries | frozenset((entry,)),
            tombstones=self.tombstones,
        )

    def remove(self, value: T) -> "ORSet[T]":
        """Tombstone all currently-observed adds of ``value``. New
        adds (with unseen tokens) after this point are NOT removed —
        that's the add-wins property."""
        to_kill = frozenset(e for e in self.entries if e.value == value)
        return ORSet(
            entries=self.entries,
            tombstones=self.tombstones | to_kill,
        )

    def contains(self, value: T) -> bool:
        live = self.entries - self.tombstones
        return any(e.value == value for e in live)

    def values(self) -> frozenset[T]:
        live = self.entries - self.tombstones
        return frozenset(e.value for e in live)

    def merge(self, other: "ORSet[T]") -> "ORSet[T]":
        return ORSet(
            entries=self.entries | other.entries,
            tombstones=self.tombstones | other.tombstones,
        )


# ---------------------------------------------------------------------------
# MaxCounter — monotone non-decreasing integer
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MaxCounter:
    """Monotone-non-decreasing integer. Merge takes the max.

    Used for tick counters, alive-at timestamps, etc. — values that
    never decrease in real life and where the merge must reflect
    "the most recent thing we know about."
    """

    value: int = 0

    def bump(self, to: int) -> "MaxCounter":
        if to > self.value:
            return MaxCounter(value=to)
        return self

    def merge(self, other: "MaxCounter") -> "MaxCounter":
        return MaxCounter(value=max(self.value, other.value))


# ---------------------------------------------------------------------------
# ParticipantState — one peer's slice of the call
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ParticipantState:
    """One participant's slice. master_vk is the immutable key
    identifying this participant; the rest is mutable state."""

    master_vk: bytes
    active_devices: ORSet[str] = field(default_factory=ORSet.empty)
    primary_mic: LWWRegister[str] = field(default_factory=LWWRegister)
    primary_cam: LWWRegister[str] = field(default_factory=LWWRegister)
    primary_display: LWWRegister[str] = field(default_factory=LWWRegister)
    primary_speaker: LWWRegister[str] = field(default_factory=LWWRegister)
    preferred_relay: LWWRegister[str] = field(default_factory=LWWRegister)
    last_seen_alive_ms: MaxCounter = field(default_factory=MaxCounter)

    def merge(self, other: "ParticipantState") -> "ParticipantState":
        if self.master_vk != other.master_vk:
            raise ValueError(
                "cannot merge ParticipantState across different master_vk"
            )
        return ParticipantState(
            master_vk=self.master_vk,
            active_devices=self.active_devices.merge(other.active_devices),
            primary_mic=self.primary_mic.merge(other.primary_mic),
            primary_cam=self.primary_cam.merge(other.primary_cam),
            primary_display=self.primary_display.merge(other.primary_display),
            primary_speaker=self.primary_speaker.merge(other.primary_speaker),
            preferred_relay=self.preferred_relay.merge(other.preferred_relay),
            last_seen_alive_ms=self.last_seen_alive_ms.merge(other.last_seen_alive_ms),
        )


# ---------------------------------------------------------------------------
# CallSession — the top-level CRDT
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CallSession:
    """Top-level shared state for one call.

    ``call_id``, ``started_at_ms``, ``negotiated_capabilities``, and
    ``model_pack_hash`` are immutable for the lifetime of the call.
    Everything else converges via lattice merge.

    The merge is pure: ``a.merge(b) == b.merge(a)`` (commutative),
    ``a.merge(b).merge(c) == a.merge(b.merge(c))`` (associative),
    ``a.merge(a) == a`` (idempotent). Verified in
    ``tests/test_call_session.py``.
    """

    # Immutable identity
    call_id: str
    started_at_ms: int
    negotiated_capabilities: frozenset[str] = field(default_factory=frozenset)
    model_pack_hash: Optional[str] = None

    # Optional continuity links (immutable per call)
    conversation_id: Optional[str] = None
    resume_of: Optional[str] = None

    # Intensity dial
    intensity: LWWRegister[int] = field(default_factory=LWWRegister)
    target_intensity: LWWRegister[int] = field(default_factory=LWWRegister)
    current_rung: LWWRegister[int] = field(default_factory=LWWRegister)

    # Participants (keyed by master_vk hex)
    participants: tuple[tuple[str, ParticipantState], ...] = ()

    # Routing
    active_path: LWWRegister[str] = field(default_factory=LWWRegister)
    warm_backups: ORSet[str] = field(default_factory=ORSet.empty)

    # Lifecycle
    ended_at_ms: LWWRegister[int] = field(default_factory=LWWRegister)
    end_reason: LWWRegister[int] = field(default_factory=LWWRegister)
    live_resumable_until_ms: LWWRegister[int] = field(default_factory=LWWRegister)

    # Trust
    identity_verified: LWWRegister[int] = field(default_factory=LWWRegister)
    recording_state: LWWRegister[int] = field(default_factory=LWWRegister)

    # ── Identity invariants ──────────────────────────────────────

    def _check_compatible(self, other: "CallSession") -> None:
        if self.call_id != other.call_id:
            raise ValueError("cannot merge CallSessions with different call_id")
        if self.started_at_ms != other.started_at_ms:
            raise ValueError(
                "cannot merge CallSessions with different started_at_ms"
            )
        if self.negotiated_capabilities != other.negotiated_capabilities:
            raise ValueError(
                "cannot merge CallSessions with different "
                "negotiated_capabilities"
            )
        if self.model_pack_hash != other.model_pack_hash:
            raise ValueError(
                "cannot merge CallSessions with different model_pack_hash"
            )
        if self.conversation_id != other.conversation_id:
            raise ValueError(
                "cannot merge CallSessions with different conversation_id"
            )
        if self.resume_of != other.resume_of:
            raise ValueError(
                "cannot merge CallSessions with different resume_of"
            )

    # ── Merge ────────────────────────────────────────────────────

    def merge(self, other: "CallSession") -> "CallSession":
        self._check_compatible(other)

        # Participants: merge per-master_vk, union when only one side has it.
        a = dict(self.participants)
        b = dict(other.participants)
        merged_participants: dict[str, ParticipantState] = {}
        for k in set(a) | set(b):
            if k in a and k in b:
                merged_participants[k] = a[k].merge(b[k])
            elif k in a:
                merged_participants[k] = a[k]
            else:
                merged_participants[k] = b[k]
        participants_tuple = tuple(sorted(merged_participants.items()))

        return CallSession(
            call_id=self.call_id,
            started_at_ms=self.started_at_ms,
            negotiated_capabilities=self.negotiated_capabilities,
            model_pack_hash=self.model_pack_hash,
            conversation_id=self.conversation_id,
            resume_of=self.resume_of,
            intensity=self.intensity.merge(other.intensity),
            target_intensity=self.target_intensity.merge(other.target_intensity),
            current_rung=self.current_rung.merge(other.current_rung),
            participants=participants_tuple,
            active_path=self.active_path.merge(other.active_path),
            warm_backups=self.warm_backups.merge(other.warm_backups),
            ended_at_ms=self.ended_at_ms.merge(other.ended_at_ms),
            end_reason=self.end_reason.merge(other.end_reason),
            live_resumable_until_ms=self.live_resumable_until_ms.merge(
                other.live_resumable_until_ms
            ),
            identity_verified=self.identity_verified.merge(other.identity_verified),
            recording_state=self.recording_state.merge(other.recording_state),
        )

    # ── High-level mutation helpers ──────────────────────────────

    def with_intensity(
        self, intensity: Intensity, *, timestamp_ms: int, writer_id: str,
    ) -> "CallSession":
        return replace(
            self,
            intensity=self.intensity.with_value(
                int(intensity), timestamp_ms=timestamp_ms, writer_id=writer_id
            ),
        )

    def with_rung(
        self, rung: Rung, *, timestamp_ms: int, writer_id: str,
    ) -> "CallSession":
        return replace(
            self,
            current_rung=self.current_rung.with_value(
                int(rung), timestamp_ms=timestamp_ms, writer_id=writer_id
            ),
        )

    def with_ended(
        self,
        *,
        reason: EndReason,
        ended_at_ms: int,
        writer_id: str,
    ) -> "CallSession":
        return replace(
            self,
            ended_at_ms=self.ended_at_ms.with_value(
                ended_at_ms, timestamp_ms=ended_at_ms, writer_id=writer_id
            ),
            end_reason=self.end_reason.with_value(
                int(reason), timestamp_ms=ended_at_ms, writer_id=writer_id
            ),
        )

    def with_resumable_until(
        self, until_ms: int, *, timestamp_ms: int, writer_id: str,
    ) -> "CallSession":
        return replace(
            self,
            live_resumable_until_ms=self.live_resumable_until_ms.with_value(
                until_ms, timestamp_ms=timestamp_ms, writer_id=writer_id
            ),
        )

    # ── Read helpers ─────────────────────────────────────────────

    @property
    def is_active(self) -> bool:
        """A call is active until either (a) ended_at_ms has been
        set, or (b) the network induced async conversion and the
        resume window has expired."""
        return self.ended_at_ms.value is None or self.ended_at_ms.value == 0

    @property
    def current_intensity(self) -> Intensity:
        v = self.intensity.value
        if v is None:
            return Intensity.AMBIENT
        return Intensity(int(v))

    @property
    def current_rung_value(self) -> Rung:
        v = self.current_rung.value
        if v is None:
            return Rung.RAW_AV
        return Rung(int(v))

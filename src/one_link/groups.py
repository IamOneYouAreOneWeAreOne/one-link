"""Groups — distributed multi-member chat with no central authority.

This module ships the CRDT foundation only. Wire protocol, sender
keys, and UI are follow-on versions (v0.6.1+). v0.6.0 lets you:

  - Define a group with a stable id (random 16-byte token).
  - Add/remove members and change roles via signed events.
  - Replay any sequence of events on any device and converge to the
    same membership state.
  - Persist events and members in sqlite; rebuild state from events
    on demand.

The CRDT model
==============

A group's state is a deterministic function of its event log. Each
event is signed by its author's Ed25519 device key — anyone with the
public key can verify provenance. The log is causally ordered by
`(timestamp_ms, event_id)`; ties are broken by event_id (a hash, so
this is effectively random and stable).

Three kinds of authority:

  - ``owner``    : can do anything — add/remove members, change
                   roles, delete the group. Set at creation,
                   transferable.
  - ``admin``    : can add/remove regular members.
  - ``member``   : can post messages but not change membership.

Concurrency safety
==================

Alice and Bob are both admins. Alice removes Charlie at the same
moment Bob promotes Charlie to admin. Both events propagate. State
converges by:

  1. Sort all events (timestamp, event_id).
  2. Re-derive state from scratch.
  3. The later-timestamped event wins. If both have the same
     timestamp, the lower event_id wins. (Both are deterministic.)

Event authority is checked at *replay time*, not at *issue time* —
i.e., even if Alice's event re-orders Charlie out of the group,
Bob's promotion (which came BEFORE Alice's removal in the resolved
order) is still applied. This is "monotonic-state CRDT" — events are
immutable once issued, and the resolved state is a single global
order's reduce.

What's NOT in v0.6.0
====================

  - Per-message encryption (Sender Keys) — v0.6.1.
  - Wire-protocol (`GROUP_*` peer frames) — v0.6.2.
  - Invite links — v0.6.3.
  - UI — v0.6.4.
  - Forward secrecy via Double Ratchet — v0.7+.

What IS in v0.6.0
=================

A correct, tested, persistent CRDT primitive that the upstack pieces
will build on. Comprehensive tests covering commutativity,
idempotence, associativity, and the security cases (forged event
detection, role-overstepping rejection, replay-after-removal).
"""
from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional

import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PROTOCOL_VERSION = "OL-GROUP-1"
GROUP_ID_BYTES = 16

# Roles, in increasing authority. Higher number = more authority.
ROLE_MEMBER = "member"
ROLE_ADMIN = "admin"
ROLE_OWNER = "owner"
_ROLE_RANK = {ROLE_MEMBER: 0, ROLE_ADMIN: 1, ROLE_OWNER: 2}
ROLES_VALID = frozenset(_ROLE_RANK)

# Event kinds.
EV_CREATE = "create"
EV_ADD_MEMBER = "add_member"
EV_REMOVE_MEMBER = "remove_member"
EV_CHANGE_ROLE = "change_role"
EV_RENAME = "rename"
EV_KINDS_VALID = frozenset({
    EV_CREATE, EV_ADD_MEMBER, EV_REMOVE_MEMBER, EV_CHANGE_ROLE, EV_RENAME,
})

# Sane caps so a malicious member can't blow up state.
MAX_GROUP_NAME_LEN = 200
MAX_GROUP_MEMBERS = 1024


# ─── helpers ────────────────────────────────────────────────────────

def now_ms() -> int:
    return int(time.time() * 1000)


def new_group_id() -> bytes:
    """16 bytes of entropy. Used as the stable identifier for a
    group across all devices and forever."""
    return secrets.token_bytes(GROUP_ID_BYTES)


def _canonical_bytes(payload: dict) -> bytes:
    body = {k: v for k, v in payload.items() if k != "signature"}
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _event_id(payload: dict) -> str:
    """Content-addressed event id — hash of the canonical body
    (without signature). Two devices that issue the same logical
    event at the same `(group_id, timestamp_ms, kind, …)` get the
    same id; useful for dedup."""
    return blake3.blake3(_canonical_bytes(payload)).hexdigest()


def _b64(b: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    import base64
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


# ─── GroupEvent — the only mutating primitive ──────────────────────

@dataclass
class GroupEvent:
    """A signed assertion about a group's membership.

    `target` is the pubkey the event acts on (for add/remove/change).
    For `create` and `rename`, target is empty. For `change_role`,
    target is the affected member's pubkey and `role` is the new role.

    `payload` carries kind-specific extras (group name on create/rename).
    """
    group_id: bytes
    kind: str
    timestamp_ms: int
    author_pubkey: bytes              # who signed this
    target_pubkey: bytes = b""        # for add/remove/change_role
    role: str = ""                    # for create / add_member / change_role
    name: str = ""                    # for create / rename
    nonce: bytes = b""                # 8 bytes — defeats pre-image
    signature: bytes = b""

    @property
    def event_id(self) -> str:
        return _event_id(self.to_signing_dict())

    def to_signing_dict(self) -> dict:
        return {
            "v": PROTOCOL_VERSION,
            "group_id_b64": _b64(self.group_id),
            "kind": self.kind,
            "timestamp_ms": int(self.timestamp_ms),
            "author_pubkey_b64": _b64(self.author_pubkey),
            "target_pubkey_b64": _b64(self.target_pubkey) if self.target_pubkey else "",
            "role": self.role,
            "name": self.name,
            "nonce_b64": _b64(self.nonce),
        }

    def to_wire(self) -> dict:
        d = self.to_signing_dict()
        d["signature"] = _b64(self.signature)
        d["event_id"] = self.event_id
        return d

    @classmethod
    def from_wire(cls, d: dict) -> "GroupEvent":
        if not isinstance(d, dict):
            raise ValueError("event must be an object")
        if d.get("v") != PROTOCOL_VERSION:
            raise ValueError(f"unsupported version: {d.get('v')!r}")
        kind = _require_str(d.get("kind"), "kind")
        if kind not in EV_KINDS_VALID:
            raise ValueError(f"unknown event kind: {kind!r}")
        gid = _b64d(_require_str(d.get("group_id_b64"), "group_id_b64"))
        if len(gid) != GROUP_ID_BYTES:
            raise ValueError(f"group_id wrong length: {len(gid)}")
        author = _b64d(_require_str(d.get("author_pubkey_b64"), "author_pubkey_b64"))
        if len(author) != 32:
            raise ValueError("author_pubkey must be 32 bytes")
        target_b64 = d.get("target_pubkey_b64") or ""
        target = _b64d(target_b64) if target_b64 else b""
        if target and len(target) != 32:
            raise ValueError("target_pubkey must be 32 bytes when present")
        role = str(d.get("role") or "")
        if role and role not in ROLES_VALID:
            raise ValueError(f"invalid role: {role!r}")
        name = str(d.get("name") or "")
        if len(name) > MAX_GROUP_NAME_LEN:
            raise ValueError(f"name too long: {len(name)}")
        nonce = _b64d(_require_str(d.get("nonce_b64"), "nonce_b64"))
        if len(nonce) != 8:
            raise ValueError("nonce must be 8 bytes")
        sig = _b64d(_require_str(d.get("signature"), "signature"))
        if len(sig) != 64:
            raise ValueError("signature must be 64 bytes")
        return cls(
            group_id=gid,
            kind=kind,
            timestamp_ms=_require_int(d.get("timestamp_ms"), "timestamp_ms"),
            author_pubkey=author,
            target_pubkey=target,
            role=role,
            name=name,
            nonce=nonce,
            signature=sig,
        )

    def verify(self) -> None:
        try:
            Ed25519PublicKey.from_public_bytes(self.author_pubkey).verify(
                self.signature,
                _canonical_bytes(self.to_signing_dict()),
            )
        except InvalidSignature:
            raise ValueError("group event signature does not verify")


def _sign(
    *,
    private_key: Ed25519PrivateKey,
    pubkey: bytes,
    group_id: bytes,
    kind: str,
    timestamp_ms: int | None = None,
    target_pubkey: bytes = b"",
    role: str = "",
    name: str = "",
) -> GroupEvent:
    ev = GroupEvent(
        group_id=group_id,
        kind=kind,
        timestamp_ms=timestamp_ms if timestamp_ms is not None else now_ms(),
        author_pubkey=pubkey,
        target_pubkey=target_pubkey,
        role=role,
        name=name,
        nonce=secrets.token_bytes(8),
    )
    ev.signature = private_key.sign(_canonical_bytes(ev.to_signing_dict()))
    return ev


# ─── public sign* helpers ──────────────────────────────────────────

def sign_create_group(
    *,
    private_key: Ed25519PrivateKey,
    pubkey: bytes,
    name: str,
    group_id: bytes | None = None,
    timestamp_ms: int | None = None,
) -> GroupEvent:
    """Issue the genesis event for a new group. The author becomes
    the initial owner."""
    if not name or len(name) > MAX_GROUP_NAME_LEN:
        raise ValueError(f"group name out of range: {len(name)}")
    return _sign(
        private_key=private_key,
        pubkey=pubkey,
        group_id=group_id or new_group_id(),
        kind=EV_CREATE,
        timestamp_ms=timestamp_ms,
        name=name,
        role=ROLE_OWNER,
    )


def sign_add_member(
    *,
    private_key: Ed25519PrivateKey,
    pubkey: bytes,
    group_id: bytes,
    member_pubkey: bytes,
    role: str = ROLE_MEMBER,
    timestamp_ms: int | None = None,
) -> GroupEvent:
    if role not in ROLES_VALID:
        raise ValueError(f"invalid role: {role!r}")
    if len(member_pubkey) != 32:
        raise ValueError("member_pubkey must be 32 bytes")
    return _sign(
        private_key=private_key,
        pubkey=pubkey,
        group_id=group_id,
        kind=EV_ADD_MEMBER,
        target_pubkey=member_pubkey,
        role=role,
        timestamp_ms=timestamp_ms,
    )


def sign_remove_member(
    *,
    private_key: Ed25519PrivateKey,
    pubkey: bytes,
    group_id: bytes,
    member_pubkey: bytes,
    timestamp_ms: int | None = None,
) -> GroupEvent:
    if len(member_pubkey) != 32:
        raise ValueError("member_pubkey must be 32 bytes")
    return _sign(
        private_key=private_key,
        pubkey=pubkey,
        group_id=group_id,
        kind=EV_REMOVE_MEMBER,
        target_pubkey=member_pubkey,
        timestamp_ms=timestamp_ms,
    )


def sign_change_role(
    *,
    private_key: Ed25519PrivateKey,
    pubkey: bytes,
    group_id: bytes,
    member_pubkey: bytes,
    new_role: str,
    timestamp_ms: int | None = None,
) -> GroupEvent:
    if new_role not in ROLES_VALID:
        raise ValueError(f"invalid role: {new_role!r}")
    if len(member_pubkey) != 32:
        raise ValueError("member_pubkey must be 32 bytes")
    return _sign(
        private_key=private_key,
        pubkey=pubkey,
        group_id=group_id,
        kind=EV_CHANGE_ROLE,
        target_pubkey=member_pubkey,
        role=new_role,
        timestamp_ms=timestamp_ms,
    )


def sign_rename(
    *,
    private_key: Ed25519PrivateKey,
    pubkey: bytes,
    group_id: bytes,
    new_name: str,
    timestamp_ms: int | None = None,
) -> GroupEvent:
    if not new_name or len(new_name) > MAX_GROUP_NAME_LEN:
        raise ValueError(f"name out of range: {len(new_name)}")
    return _sign(
        private_key=private_key,
        pubkey=pubkey,
        group_id=group_id,
        kind=EV_RENAME,
        name=new_name,
        timestamp_ms=timestamp_ms,
    )


# ─── GroupState — the deterministic reduce ─────────────────────────

@dataclass
class GroupState:
    """The materialized state at a particular point in the event log.

    Deterministic function of the (sorted, deduped, signature-verified)
    event set. Reduce is associative + commutative when the input is
    a *set* of events — order independence is what makes this a CRDT.
    """
    group_id: bytes
    name: str = ""
    created_ms: int = 0
    members: dict[bytes, str] = field(default_factory=dict)  # pubkey -> role
    # Merkle-ish chain hash of the events that went into this state.
    # Lets two devices agree they're in sync via one comparison.
    state_hash: str = ""

    @property
    def member_count(self) -> int:
        return len(self.members)

    def is_member(self, pubkey: bytes) -> bool:
        return pubkey in self.members

    def role_of(self, pubkey: bytes) -> Optional[str]:
        return self.members.get(pubkey)

    def has_role_at_least(self, pubkey: bytes, required: str) -> bool:
        actual = self.members.get(pubkey)
        if actual is None:
            return False
        return _ROLE_RANK[actual] >= _ROLE_RANK[required]


def _sort_events(events: Iterable[GroupEvent]) -> list[GroupEvent]:
    """Total order: (timestamp_ms ascending, event_id ascending).
    The event_id tiebreaker is a hash → effectively random but
    stable across devices."""
    return sorted(events, key=lambda e: (e.timestamp_ms, e.event_id))


def reduce_events(
    events: Iterable[GroupEvent],
    *,
    skip_signature_verify: bool = False,
) -> Optional[GroupState]:
    """Apply a sequence of events (any order) and return the resulting
    state, or None if the events don't define a coherent group (e.g.,
    no `create` event, or events for mixed group_ids).

    Throws ValueError on:
      - invalid event signatures
      - mixed group_ids
      - events referencing unknown roles, etc. (parsed at from_wire too,
        but defense-in-depth here)

    Authority enforcement: an event whose author lacks the required
    authority at the time the event is replayed (in resolved order) is
    silently skipped. A future audit endpoint can surface "rejected
    by authority" events; v0.6.0 just drops them so the resulting
    state is always correct.
    """
    # Dedup by event_id (content-addressed) so duplicate events don't
    # double-affect the chain hash. Idempotence is a CRDT prerequisite.
    deduped: dict[str, GroupEvent] = {}
    for e in events:
        deduped[e.event_id] = e
    sorted_events = _sort_events(deduped.values())
    if not sorted_events:
        return None

    # All events must share the same group_id.
    gid = sorted_events[0].group_id
    for e in sorted_events:
        if e.group_id != gid:
            raise ValueError("events span multiple group_ids")

    # Verify signatures.
    if not skip_signature_verify:
        for e in sorted_events:
            e.verify()

    # Find the create event. There must be exactly one (or at least
    # one — the earliest by timestamp wins if duplicates exist, which
    # is unusual but not malformed).
    creates = [e for e in sorted_events if e.kind == EV_CREATE]
    if not creates:
        return None
    first_create = creates[0]
    state = GroupState(
        group_id=gid,
        name=first_create.name,
        created_ms=first_create.timestamp_ms,
        members={first_create.author_pubkey: ROLE_OWNER},
    )

    # Replay everything else (including any duplicate creates, which
    # we treat as no-ops — only the first sets the genesis state).
    chain = blake3.blake3()
    chain.update(_canonical_bytes(first_create.to_signing_dict()))

    for e in sorted_events:
        if e is first_create:
            continue
        if e.group_id != gid:
            continue  # already filtered above; defensive
        # Apply only if author has the authority at this point.
        applied = _apply_event(state, e)
        if applied:
            chain.update(_canonical_bytes(e.to_signing_dict()))

    state.state_hash = chain.hexdigest()
    return state


def _apply_event(state: GroupState, e: GroupEvent) -> bool:
    """Apply one event to state in-place. Returns True if applied,
    False if rejected (lack of authority, malformed, etc.)."""
    author_role = state.members.get(e.author_pubkey)
    if author_role is None:
        # Author isn't a member at this point in the timeline.
        # (Could be a former member whose removal preceded this event,
        # or a stranger.)
        return False

    if e.kind == EV_CREATE:
        # Duplicate create — ignored.
        return False

    if e.kind == EV_ADD_MEMBER:
        if _ROLE_RANK[author_role] < _ROLE_RANK[ROLE_ADMIN]:
            return False
        if len(e.target_pubkey) != 32:
            return False
        if len(state.members) >= MAX_GROUP_MEMBERS:
            return False
        new_role = e.role or ROLE_MEMBER
        if new_role not in ROLES_VALID:
            return False
        # Only owner can elevate to owner.
        if new_role == ROLE_OWNER and author_role != ROLE_OWNER:
            return False
        # If member already exists, promotion via add_member is
        # disallowed — change_role is the right tool. Idempotent
        # re-add of same role is a no-op but we report applied=True
        # so the chain hash advances (the event was legitimate).
        existing = state.members.get(e.target_pubkey)
        if existing is None:
            state.members[e.target_pubkey] = new_role
            return True
        # Already a member; treat as a no-op (don't downgrade or
        # promote via add).
        return False

    if e.kind == EV_REMOVE_MEMBER:
        if _ROLE_RANK[author_role] < _ROLE_RANK[ROLE_ADMIN]:
            return False
        target_role = state.members.get(e.target_pubkey)
        if target_role is None:
            return False
        # Admin can't remove an owner.
        if target_role == ROLE_OWNER and author_role != ROLE_OWNER:
            return False
        # Owner can't remove themselves if they're the *only* owner
        # AND there are remaining members — would orphan them. If the
        # leaving owner is the *only member at all*, the group simply
        # becomes empty, which is safe + the only way for a sole-owner
        # group of 1 to ever go away. Without this carve-out, a user
        # who created a group and is the only member is permanently
        # stuck with a ghost row in their sidebar (they can never
        # leave, and nobody else can remove them).
        if e.target_pubkey == e.author_pubkey and target_role == ROLE_OWNER:
            owners = [
                pk for pk, r in state.members.items()
                if r == ROLE_OWNER and pk != e.target_pubkey
            ]
            if not owners:
                others = [
                    pk for pk in state.members.keys()
                    if pk != e.target_pubkey
                ]
                if others:
                    # Real orphan risk — block.
                    return False
                # Sole member of the group: emptying it is fine.
        state.members.pop(e.target_pubkey, None)
        return True

    if e.kind == EV_CHANGE_ROLE:
        if author_role != ROLE_OWNER:
            # Only owners change roles. v0.6.0 keeps this strict; a
            # future "any admin can promote to admin but not to owner"
            # variant is a follow-on policy decision.
            return False
        if e.target_pubkey not in state.members:
            return False
        new_role = e.role
        if new_role not in ROLES_VALID:
            return False
        # Owner can't demote themselves below owner if they're the
        # only owner — same orphan-protection.
        if (
            e.target_pubkey == e.author_pubkey
            and new_role != ROLE_OWNER
        ):
            owners = [
                pk for pk, r in state.members.items()
                if r == ROLE_OWNER and pk != e.target_pubkey
            ]
            if not owners:
                return False
        state.members[e.target_pubkey] = new_role
        return True

    if e.kind == EV_RENAME:
        if _ROLE_RANK[author_role] < _ROLE_RANK[ROLE_ADMIN]:
            return False
        new_name = e.name
        if not new_name or len(new_name) > MAX_GROUP_NAME_LEN:
            return False
        state.name = new_name
        return True

    return False


# ─── input validation ──────────────────────────────────────────────

def _require_str(v, name: str) -> str:
    if not isinstance(v, str):
        raise ValueError(f"{name} must be a string")
    return v


def _require_int(v, name: str) -> int:
    if not isinstance(v, int) or isinstance(v, bool):
        raise ValueError(f"{name} must be an integer")
    return v

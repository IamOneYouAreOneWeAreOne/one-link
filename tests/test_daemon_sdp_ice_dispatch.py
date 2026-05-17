"""Daemon dispatch tests for SDP forwarding + CALL_ICE + TrustLedger.

The :func:`daemon._dispatch_living_presence_message` hook is the
boundary where the wire protocol meets the per-call CallManager. This
test file covers the three behaviours that exist *above* the FSM:

  - SDP offers / answers carried inside CALL_INVITE / CALL_ACCEPT are
    forwarded to the local browser as ``sdp_offer`` / ``sdp_answer``
    tail events (browser's RTCPeerConnection driver consumes those).
  - CALL_ICE wire messages are parsed + forwarded as
    ``ice_candidate`` tail events. No CallManager event is fired
    because ICE is media-layer state, not lifecycle state.
  - TrustLedger consultation on CALL_INVITE: a refused decision
    short-circuits before the CallManager is opened.
"""

from __future__ import annotations

import asyncio

import blake3
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.call_sdp_signaling import (
    CALL_ICE,
    CALL_INVITE_SDP_V1,
    SdpKind,
    SdpPayload,
    attach_answer_to_accept,
    attach_offer_to_invite,
    build_ice_message,
    end_of_candidates,
)
from one_link.call_signaling import CallPhase
from one_link.daemon import Daemon
from one_link.identity import Identity


# ---------------------------------------------------------------------------
# Test scaffolding
# ---------------------------------------------------------------------------

def _make_identity(name: str) -> Identity:
    seed = blake3.blake3(name.encode()).digest()[:32]
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fp = blake3.blake3(pub_bytes).hexdigest()
    return Identity(
        private=priv, public=priv.public_key(), public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname=name,
    )


class _FakePeerRecord:
    def __init__(self, ed_pub_hex: str) -> None:
        self.ed_pub_hex = ed_pub_hex
        self.trust = "pinned"


class _FakeState:
    def __init__(self, peer_pub_hex_by_fp: dict[str, str]) -> None:
        self._peers = {
            fp: _FakePeerRecord(pub) for fp, pub in peer_pub_hex_by_fp.items()
        }

    def get_peer(self, peer_fp: str):
        return self._peers.get(peer_fp)


class _FakeChannel:
    def __init__(self, peer_ed_pub: bytes, peer_short_id: str) -> None:
        self.peer_ed_pub = peer_ed_pub
        self.peer_short_id = peer_short_id
        self.peer_caps = {"features": ["chat"]}
        self.sent: list[bytes] = []

    async def send(self, payload: bytes) -> None:
        self.sent.append(payload)


SAMPLE_OFFER_SDP = (
    "v=0\r\n"
    "o=- 1 1 IN IP4 127.0.0.1\r\n"
    "s=-\r\n"
    "t=0 0\r\n"
    "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
    "a=mid:0\r\n"
)
SAMPLE_ANSWER_SDP = (
    "v=0\r\n"
    "o=- 2 2 IN IP4 127.0.0.1\r\n"
    "s=-\r\n"
    "t=0 0\r\n"
    "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
)


@pytest.fixture
def alice() -> Identity:
    return _make_identity("alice-sdp-dispatch")


@pytest.fixture
def mom() -> Identity:
    return _make_identity("mom-sdp-dispatch")


@pytest.fixture
def mom_daemon(mom: Identity, alice: Identity) -> Daemon:
    d = Daemon(me=mom)
    d.state = _FakeState({alice.fingerprint: alice.public_bytes.hex()})
    return d


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# SDP offer in CALL_INVITE
# ---------------------------------------------------------------------------

def test_call_invite_with_sdp_offer_emits_tail_event(
    mom_daemon: Daemon, alice: Identity,
) -> None:
    """Inbound CALL_INVITE carrying sdp_offer → daemon broadcasts an
    ``sdp_offer`` tail event so the browser can setRemoteDescription."""
    base = {
        "t": "CALL_INVITE",
        "id": "m1",
        "ts": 0,
        "from": alice.short_id,
        "call_id": "sdp-call-1",
    }
    msg = attach_offer_to_invite(base, sdp=SAMPLE_OFFER_SDP)
    tail: list[dict] = []
    mom_daemon._broadcast_tail = lambda ev: tail.append(ev)  # type: ignore
    channel = _FakeChannel(peer_ed_pub=alice.public_bytes, peer_short_id=alice.short_id)

    _run(mom_daemon._on_peer_message(channel, msg))

    offer_events = [e for e in tail if e.get("tail_kind") == "sdp_offer"]
    assert len(offer_events) == 1
    ev = offer_events[0]
    assert ev["call_id"] == "sdp-call-1"
    assert ev["sdp"] == SAMPLE_OFFER_SDP
    assert ev["sdp_kind"] == "offer"
    assert ev["peer_master_vk_hex"] == alice.fingerprint
    assert (
        mom_daemon._call_sdp_backfill["sdp-call-1"]["sdp_offer"]
        == SAMPLE_OFFER_SDP
    )


def test_call_invite_without_sdp_offer_emits_no_offer_event(
    mom_daemon: Daemon, alice: Identity,
) -> None:
    """A CALL_INVITE without an sdp_offer field (older client / audio-
    only fallback) must NOT generate a spurious empty sdp_offer event."""
    msg = {
        "t": "CALL_INVITE",
        "id": "m1",
        "ts": 0,
        "from": alice.short_id,
        "call_id": "sdp-call-2",
    }
    tail: list[dict] = []
    mom_daemon._broadcast_tail = lambda ev: tail.append(ev)  # type: ignore
    channel = _FakeChannel(peer_ed_pub=alice.public_bytes, peer_short_id=alice.short_id)

    _run(mom_daemon._on_peer_message(channel, msg))

    offer_events = [e for e in tail if e.get("tail_kind") == "sdp_offer"]
    assert offer_events == []


def test_call_invite_with_malformed_sdp_is_dropped_gracefully(
    mom_daemon: Daemon, alice: Identity,
) -> None:
    """A CALL_INVITE with garbage in sdp_offer must not crash the
    daemon. The lifecycle still advances (the FSM doesn't know about
    SDP), but no offer event fires."""
    msg = {
        "t": "CALL_INVITE",
        "id": "m1",
        "ts": 0,
        "from": alice.short_id,
        "call_id": "sdp-call-3",
        "sdp_offer": {"schema": 999, "kind": "offer", "sdp": "x"},
    }
    tail: list[dict] = []
    mom_daemon._broadcast_tail = lambda ev: tail.append(ev)  # type: ignore
    channel = _FakeChannel(peer_ed_pub=alice.public_bytes, peer_short_id=alice.short_id)

    _run(mom_daemon._on_peer_message(channel, msg))

    # No sdp_offer event because parsing failed.
    offer_events = [e for e in tail if e.get("tail_kind") == "sdp_offer"]
    assert offer_events == []
    # But the manager still opened — lifecycle decoupled from SDP.
    assert mom_daemon._call_registry.get("sdp-call-3") is not None


# ---------------------------------------------------------------------------
# SDP answer in CALL_ACCEPT
# ---------------------------------------------------------------------------

def test_call_accept_with_sdp_answer_emits_tail_event(
    mom_daemon: Daemon, alice: Identity, mom: Identity,
) -> None:
    """A pre-existing call receives CALL_ACCEPT with sdp_answer →
    broadcasts ``sdp_answer`` tail event."""
    from one_link.call_manager import ManagerEvent, ManagerEventKind

    mgr = mom_daemon._call_registry.open(
        call_id="sdp-call-4",
        peer_master_vk_hex=alice.fingerprint,
        local_role="originator",
        local_master_vk_hex=mom.fingerprint,
        started_at_ms=1_000,
    )
    mgr.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 1_000))

    base = {
        "t": "CALL_ACCEPT",
        "id": "m2",
        "ts": 0,
        "from": alice.short_id,
        "call_id": "sdp-call-4",
    }
    msg = attach_answer_to_accept(base, sdp=SAMPLE_ANSWER_SDP)
    tail: list[dict] = []
    mom_daemon._broadcast_tail = lambda ev: tail.append(ev)  # type: ignore
    channel = _FakeChannel(peer_ed_pub=alice.public_bytes, peer_short_id=alice.short_id)

    _run(mom_daemon._on_peer_message(channel, msg))

    answer_events = [e for e in tail if e.get("tail_kind") == "sdp_answer"]
    assert len(answer_events) == 1
    assert answer_events[0]["sdp"] == SAMPLE_ANSWER_SDP
    assert answer_events[0]["sdp_kind"] == "answer"
    assert (
        mom_daemon._call_sdp_backfill["sdp-call-4"]["sdp_answer"]
        == SAMPLE_ANSWER_SDP
    )
    assert mgr.phase == CallPhase.ACTIVE


# ---------------------------------------------------------------------------
# CALL_ICE → tail event
# ---------------------------------------------------------------------------

def test_call_ice_forwards_to_ui_tail(
    mom_daemon: Daemon, alice: Identity, mom: Identity,
) -> None:
    """A trickled ICE candidate arrives for a known call → tail event
    with the candidate so the browser can call addIceCandidate."""
    from one_link.call_manager import ManagerEvent, ManagerEventKind
    from one_link.call_sdp_signaling import IceCandidatePayload

    mgr = mom_daemon._call_registry.open(
        call_id="ice-call-1",
        peer_master_vk_hex=alice.fingerprint,
        local_role="recipient",
        local_master_vk_hex=mom.fingerprint,
        started_at_ms=1_000,
    )
    mgr.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_INVITE, 1_000))

    cand = IceCandidatePayload(
        schema=CALL_INVITE_SDP_V1,
        candidate="candidate:1 1 udp 1 1.2.3.4 1234 typ host",
        sdp_mid="0",
        sdp_m_line_index=0,
    )
    body = build_ice_message(call_id="ice-call-1", candidate=cand)
    msg = {
        "t": CALL_ICE,
        "id": "m3",
        "ts": 0,
        "from": alice.short_id,
        **body,
    }
    tail: list[dict] = []
    mom_daemon._broadcast_tail = lambda ev: tail.append(ev)  # type: ignore
    channel = _FakeChannel(peer_ed_pub=alice.public_bytes, peer_short_id=alice.short_id)

    _run(mom_daemon._on_peer_message(channel, msg))

    ice_events = [e for e in tail if e.get("tail_kind") == "ice_candidate"]
    assert len(ice_events) == 1
    ev = ice_events[0]
    assert ev["call_id"] == "ice-call-1"
    assert ev["candidate"].startswith("candidate:")
    assert ev["sdp_mid"] == "0"
    assert ev["sdp_m_line_index"] == 0
    assert ev["end_of_candidates"] is False


def test_call_ice_end_of_candidates_sentinel(
    mom_daemon: Daemon, alice: Identity, mom: Identity,
) -> None:
    """The end-of-candidates sentinel must propagate to the UI so the
    browser knows ICE gathering is complete."""
    from one_link.call_manager import ManagerEvent, ManagerEventKind

    mgr = mom_daemon._call_registry.open(
        call_id="ice-call-2",
        peer_master_vk_hex=alice.fingerprint,
        local_role="recipient",
        local_master_vk_hex=mom.fingerprint,
        started_at_ms=1_000,
    )
    mgr.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_INVITE, 1_000))

    body = end_of_candidates("ice-call-2")
    msg = {
        "t": CALL_ICE,
        "id": "m4",
        "ts": 0,
        "from": alice.short_id,
        **body,
    }
    tail: list[dict] = []
    mom_daemon._broadcast_tail = lambda ev: tail.append(ev)  # type: ignore
    channel = _FakeChannel(peer_ed_pub=alice.public_bytes, peer_short_id=alice.short_id)

    _run(mom_daemon._on_peer_message(channel, msg))

    ice_events = [e for e in tail if e.get("tail_kind") == "ice_candidate"]
    assert len(ice_events) == 1
    assert ice_events[0]["end_of_candidates"] is True


def test_call_ice_for_unknown_call_is_dropped(
    mom_daemon: Daemon, alice: Identity,
) -> None:
    """ICE for a call we don't know about (race / stale) → no event."""
    body = end_of_candidates("ghost-call")
    msg = {
        "t": CALL_ICE,
        "id": "m5",
        "ts": 0,
        "from": alice.short_id,
        **body,
    }
    tail: list[dict] = []
    mom_daemon._broadcast_tail = lambda ev: tail.append(ev)  # type: ignore
    channel = _FakeChannel(peer_ed_pub=alice.public_bytes, peer_short_id=alice.short_id)

    _run(mom_daemon._on_peer_message(channel, msg))

    ice_events = [e for e in tail if e.get("tail_kind") == "ice_candidate"]
    assert ice_events == []


def test_call_ice_malformed_is_dropped_gracefully(
    mom_daemon: Daemon, alice: Identity, mom: Identity,
) -> None:
    """Malformed CALL_ICE (e.g., garbage candidate field) must not
    crash the daemon."""
    from one_link.call_manager import ManagerEvent, ManagerEventKind

    mgr = mom_daemon._call_registry.open(
        call_id="ice-call-3",
        peer_master_vk_hex=alice.fingerprint,
        local_role="recipient",
        local_master_vk_hex=mom.fingerprint,
        started_at_ms=1_000,
    )
    mgr.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_INVITE, 1_000))

    msg = {
        "t": CALL_ICE,
        "id": "m6",
        "ts": 0,
        "from": alice.short_id,
        "call_id": "ice-call-3",
        "candidate": {"schema": 999, "candidate": 123},  # garbage
    }
    tail: list[dict] = []
    mom_daemon._broadcast_tail = lambda ev: tail.append(ev)  # type: ignore
    channel = _FakeChannel(peer_ed_pub=alice.public_bytes, peer_short_id=alice.short_id)

    # Must not raise.
    _run(mom_daemon._on_peer_message(channel, msg))

    ice_events = [e for e in tail if e.get("tail_kind") == "ice_candidate"]
    assert ice_events == []


# ---------------------------------------------------------------------------
# TrustLedger consultation (audit C2 closure)
# ---------------------------------------------------------------------------

def test_call_invite_first_contact_emits_sas_verification_required(
    mom_daemon: Daemon, alice: Identity,
) -> None:
    """First contact (peer not in ledger) → call ALLOWED + SAS prompt.
    The decision is TOFU UNVERIFIED so a needs_reverify event fires."""
    msg = {
        "t": "CALL_INVITE",
        "id": "m7",
        "ts": 0,
        "from": alice.short_id,
        "call_id": "tofu-call-1",
    }
    tail: list[dict] = []
    mom_daemon._broadcast_tail = lambda ev: tail.append(ev)  # type: ignore
    channel = _FakeChannel(peer_ed_pub=alice.public_bytes, peer_short_id=alice.short_id)

    _run(mom_daemon._on_peer_message(channel, msg))

    # Call NOT refused — first contact is allowed under TOFU.
    refused = [e for e in tail if e.get("tail_kind") == "call_refused"]
    assert refused == []
    # SAS prompt fired.
    sas_events = [
        e for e in tail if e.get("tail_kind") == "sas_verification_required"
    ]
    assert len(sas_events) == 1
    # Manager opened.
    assert mom_daemon._call_registry.get("tofu-call-1") is not None


def test_call_invite_refused_by_trust_ledger(
    mom_daemon: Daemon, alice: Identity, mom: Identity,
) -> None:
    """If the TrustLedger refuses the inbound master_vk (broken-chain
    rotation), the call must be refused with a plain-language tail
    event AND no CallManager opened."""
    # Pre-populate the ledger with a "previous" key under Alice's
    # short_id, then have a different inbound master_vk arrive.
    ledger = mom_daemon._get_trust_ledger()
    assert ledger is not None
    prior_vk_hex = "prior-pinned-vk-hex-deadbeef"
    ledger.record_pinned(
        peer_master_vk_hex=prior_vk_hex, verified_at_ms=1_000,
    )
    # Patch check_inbound to simulate "different key + broken chain".
    from one_link.identity_sas import (
        RotationDecision,
        VerificationState,
    )

    def _force_broken_chain(**_kw):
        return RotationDecision(
            new_state=VerificationState.KEY_ROTATED_CHAIN_BROKEN,
            allow_call=False,
            needs_reverify=False,
            explanation=(
                "This key looks different from before. Please verify in "
                "person before connecting."
            ),
        )
    ledger.check_inbound = _force_broken_chain  # type: ignore[method-assign]

    msg = {
        "t": "CALL_INVITE",
        "id": "m8",
        "ts": 0,
        "from": alice.short_id,
        "call_id": "rotated-call",
    }
    tail: list[dict] = []
    mom_daemon._broadcast_tail = lambda ev: tail.append(ev)  # type: ignore
    channel = _FakeChannel(peer_ed_pub=alice.public_bytes, peer_short_id=alice.short_id)

    _run(mom_daemon._on_peer_message(channel, msg))

    # The call is refused with a plain-language tail event.
    refused = [e for e in tail if e.get("tail_kind") == "call_refused"]
    assert len(refused) == 1
    msg_text = refused[0]["user_message"].lower()
    # Doctrine — no error codes / jargon in the user message.
    assert "error" not in msg_text
    assert "verify in person" in msg_text
    # No CallManager opened.
    assert mom_daemon._call_registry.get("rotated-call") is None


def test_trust_ledger_lazy_constructed_on_first_inbound(
    mom_daemon: Daemon,
) -> None:
    """The TrustLedger should not exist until the first inbound
    call (or first explicit access) requires it. Confirms the lazy
    init invariant — important so unrelated daemon tests don't pay
    the cost."""
    assert getattr(mom_daemon, "_trust_ledger_instance", None) is None
    ledger = mom_daemon._get_trust_ledger()
    assert ledger is not None
    # Second access returns the SAME instance (not a new one).
    again = mom_daemon._get_trust_ledger()
    assert ledger is again

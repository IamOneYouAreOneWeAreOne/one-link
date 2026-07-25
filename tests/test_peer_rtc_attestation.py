"""Tests for the Row 10 peer-RTC handshake attestation flow.

The peer-RTC manager sends `attest_challenge` over the data channel
when ``init_attestation()`` is invoked; on receiving a peer's
`attest_response` it verifies and updates ``BrowserPeer`` state.

These tests don't need a real WebRTC connection — they exercise the
manager's dispatch + handler methods directly with stubbed DC.
"""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace

import pytest

from one_link.confidential_native import (
    HAS_NATIVE,
    SealedMasterIdentity,
)
from one_link.peer_rtc import (
    PEER_DC_PROTOCOL_VERSION,
    BrowserPeer,
    BrowserPeerManager,
)

pytestmark = pytest.mark.skipif(
    not HAS_NATIVE,
    reason="one_link_native.confidential not built; run `maturin develop --release`",
)


class _StubDC:
    """Minimal RTCDataChannel stub. Records sent envelopes for
    assertion + lets tests inject responses."""

    def __init__(self) -> None:
        self.readyState = "open"
        self.sent: list[str] = []

    def send(self, data: str) -> None:
        self.sent.append(data)


def _make_daemon_with_sealed_master(
    me_public_bytes: bytes | None = None,
) -> object:
    """Build a minimal daemon-like object with sealed_master AND a
    fake daemon.me.public_bytes (audit C1 May 2026 — attest binds to
    the daemon's SDP Ed25519 pubkey)."""
    seed = bytes([0x42] * 32)
    sealed = SealedMasterIdentity.from_seed_bytes(seed)
    if me_public_bytes is None:
        me_public_bytes = bytes([0x99] * 32)
    me = SimpleNamespace(public_bytes=me_public_bytes)
    return SimpleNamespace(sealed_master=sealed, me=me)


def _make_peer(fp: str = "sha256:test") -> BrowserPeer:
    p = BrowserPeer(
        fingerprint=fp,
        pubkey_bytes=bytes([0xAB] * 32),
    )
    p.control_dc = _StubDC()
    p.bulk_dc = _StubDC()
    return p


# ── State + init_attestation ─────────────────────────────────────


def test_browser_peer_attestation_state_defaults_to_none():
    p = _make_peer()
    assert p.attestation_challenge is None
    assert p.attested_ms is None
    assert p.peer_master_vk is None


def test_init_attestation_sends_challenge_and_records_nonce():
    daemon = _make_daemon_with_sealed_master()
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer()
    ok = mgr.init_attestation(peer)
    assert ok is True
    # Nonce recorded on the peer.
    assert peer.attestation_challenge is not None
    assert len(peer.attestation_challenge) == 32
    # Challenge envelope sent on the control DC.
    assert len(peer.control_dc.sent) == 1
    sent = json.loads(peer.control_dc.sent[0])
    assert sent["t"] == "attest_challenge"
    assert sent["v"] == PEER_DC_PROTOCOL_VERSION
    assert (
        base64.b64decode(sent["challenge_b64"])
        == peer.attestation_challenge
    )


def test_init_attestation_overwrites_stale_challenge():
    daemon = _make_daemon_with_sealed_master()
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer()
    mgr.init_attestation(peer)
    first = peer.attestation_challenge
    mgr.init_attestation(peer)
    second = peer.attestation_challenge
    assert first != second


# ── attest_challenge → attest_response handling ───────────────────


@pytest.mark.asyncio
async def test_handle_attest_challenge_emits_response():
    daemon = _make_daemon_with_sealed_master()
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer()
    # Simulate the peer sending us a challenge.
    incoming_challenge = bytes([0xCC] * 32)
    envelope = {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "attest_challenge",
        "challenge_b64": base64.b64encode(incoming_challenge).decode("ascii"),
    }
    await mgr._handle_attest_challenge(peer, envelope)
    # Our response should have been queued on the control DC.
    assert any(
        "attest_response" in s for s in peer.control_dc.sent
    ), peer.control_dc.sent
    response = json.loads(peer.control_dc.sent[-1])
    assert response["t"] == "attest_response"
    assert response["v"] == PEER_DC_PROTOCOL_VERSION
    assert "doc" in response
    # The doc is a v=2 wire-dict shape (audit C1 May 2026 SDP-binding).
    assert response["doc"]["v"] == 2
    # And carries the issuer's SDP pubkey.
    assert "issuer_sdp_pubkey" in response["doc"]


@pytest.mark.asyncio
async def test_handle_attest_challenge_no_sealed_master_skips():
    daemon = SimpleNamespace(sealed_master=None)
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer()
    envelope = {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "attest_challenge",
        "challenge_b64": base64.b64encode(bytes([0] * 32)).decode("ascii"),
    }
    await mgr._handle_attest_challenge(peer, envelope)
    # Nothing sent.
    assert peer.control_dc.sent == []


# ── attest_response verification ─────────────────────────────────


@pytest.mark.asyncio
async def test_full_handshake_round_trip_two_peers():
    """Simulate both halves of an attestation handshake: peer A
    sends challenge to B, B responds, A verifies + marks B
    attested. Then the reverse direction."""
    # A's SDP Ed25519 pubkey and B's must each match what their
    # BrowserPeer record on the OTHER side shows as pubkey_bytes.
    a_sdp = bytes([0xA1] * 32)
    b_sdp = bytes([0xB1] * 32)
    daemon_a = _make_daemon_with_sealed_master(me_public_bytes=a_sdp)
    daemon_b = SimpleNamespace(
        sealed_master=SealedMasterIdentity.from_seed_bytes(bytes([0x55] * 32)),
        me=SimpleNamespace(public_bytes=b_sdp),
    )
    mgr_a = BrowserPeerManager(daemon_a)
    mgr_b = BrowserPeerManager(daemon_b)
    # Each side has a BrowserPeer for the other — pubkey_bytes is
    # what THAT side knows about the OTHER side's SDP identity.
    a_view_of_b = BrowserPeer(fingerprint="sha256:b", pubkey_bytes=b_sdp)
    a_view_of_b.control_dc = _StubDC()
    a_view_of_b.bulk_dc = _StubDC()
    b_view_of_a = BrowserPeer(fingerprint="sha256:a", pubkey_bytes=a_sdp)
    b_view_of_a.control_dc = _StubDC()
    b_view_of_a.bulk_dc = _StubDC()

    # 1. A initiates: sends challenge to B.
    mgr_a.init_attestation(a_view_of_b)
    a_challenge_env = json.loads(a_view_of_b.control_dc.sent[0])
    # 2. B receives A's challenge, responds with its doc.
    await mgr_b._handle_attest_challenge(b_view_of_a, a_challenge_env)
    b_response_env = json.loads(b_view_of_a.control_dc.sent[0])
    # 3. A receives B's response, verifies, updates state.
    await mgr_a._handle_attest_response(a_view_of_b, b_response_env)
    assert a_view_of_b.attested_ms is not None
    assert a_view_of_b.peer_master_vk == daemon_b.sealed_master.master_vk()
    # Challenge cleared after success.
    assert a_view_of_b.attestation_challenge is None


@pytest.mark.asyncio
async def test_handle_attest_response_without_prior_challenge_ignored():
    daemon = _make_daemon_with_sealed_master()
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer()
    # No init_attestation; peer.attestation_challenge stays None.
    envelope = {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "attest_response",
        "doc": {"v": 1, "provider_tag": 1},  # malformed but doesn't matter
    }
    await mgr._handle_attest_response(peer, envelope)
    assert peer.attested_ms is None
    assert peer.peer_master_vk is None


@pytest.mark.asyncio
async def test_handle_attest_response_with_wrong_challenge_rejected():
    """Set up a peer with a stale challenge, then send a response
    that was signed against a DIFFERENT challenge. Must NOT mark
    attested."""
    daemon = _make_daemon_with_sealed_master()
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer()
    # Plant a fake "expected" challenge.
    peer.attestation_challenge = bytes([0xAA] * 32)
    # Build a doc signed against a DIFFERENT challenge.
    from one_link.handshake_attestation import (
        AttestationWire,
        issue_for_challenge,
    )
    other_challenge = bytes([0xBB] * 32)
    # peer.pubkey_bytes is the SDP key the verifier expects; the doc
    # commits to it so the test still exercises the challenge-only
    # rejection path.
    doc = issue_for_challenge(daemon.sealed_master, other_challenge, peer.pubkey_bytes)
    wire = AttestationWire.from_doc(doc).to_wire_dict()
    envelope = {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "attest_response",
        "doc": wire,
    }
    await mgr._handle_attest_response(peer, envelope)
    # Verify failed; state untouched.
    assert peer.attested_ms is None
    assert peer.peer_master_vk is None
    # Challenge should still be present (cleared only on success).
    assert peer.attestation_challenge == bytes([0xAA] * 32)


@pytest.mark.asyncio
async def test_attest_response_with_wrong_sdp_pubkey_rejected():
    """Regression test for audit C1 (May 14 2026): an attestation doc
    bound to SDP-key X must be REJECTED by a verifier whose channel
    is talking to SDP-key Y. Closes the identity-confusion attack."""
    from one_link.handshake_attestation import AttestationWire, issue_for_challenge

    daemon = _make_daemon_with_sealed_master()
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer()  # peer.pubkey_bytes = 0xAB * 32
    challenge = mgr.init_attestation_returns_challenge_for_test(peer) if hasattr(
        mgr, "init_attestation_returns_challenge_for_test"
    ) else None
    if challenge is None:
        mgr.init_attestation(peer)
        challenge = peer.attestation_challenge
    # Issuer (us, but pretend) binds the doc to a DIFFERENT SDP pubkey
    # than what's on the peer record. Verifier should reject.
    wrong_sdp = bytes([0xCC] * 32)
    doc = issue_for_challenge(daemon.sealed_master, challenge, wrong_sdp)
    wire = AttestationWire.from_doc(doc).to_wire_dict()
    envelope = {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "attest_response",
        "doc": wire,
    }
    await mgr._handle_attest_response(peer, envelope)
    assert peer.attested_ms is None, "doc with wrong SDP pubkey must be rejected"
    assert peer.peer_master_vk is None


@pytest.mark.asyncio
async def test_attest_response_with_rotated_master_vk_refused():
    """Regression test for audit C2 (May 14 2026): once we've pinned
    a peer's master_vk on first attest, a later attestation with a
    DIFFERENT master_vk under the same SDP identity must be refused
    (TOFU). Otherwise an attacker who stole the SDP signing key can
    silently roll forward to a fresh master.
    """
    from one_link.handshake_attestation import AttestationWire, issue_for_challenge

    daemon = _make_daemon_with_sealed_master()
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer()
    # First attestation succeeds + pins master_vk.
    mgr.init_attestation(peer)
    challenge1 = peer.attestation_challenge
    doc1 = issue_for_challenge(daemon.sealed_master, challenge1, peer.pubkey_bytes)
    wire1 = AttestationWire.from_doc(doc1).to_wire_dict()
    await mgr._handle_attest_response(
        peer,
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "attest_response", "doc": wire1},
    )
    assert peer.attested_ms is not None
    pinned_vk = peer.peer_master_vk
    assert pinned_vk is not None

    # Reset the attested_ms to simulate re-attest flow (test fixture);
    # but leave peer_master_vk pinned. Attempt second attestation under
    # a DIFFERENT sealed master (different VK).
    other_master = SealedMasterIdentity.from_seed_bytes(bytes([0xFF] * 32))
    assert other_master.master_vk() != pinned_vk
    mgr.init_attestation(peer)
    challenge2 = peer.attestation_challenge
    doc2 = issue_for_challenge(other_master, challenge2, peer.pubkey_bytes)
    wire2 = AttestationWire.from_doc(doc2).to_wire_dict()
    await mgr._handle_attest_response(
        peer,
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "attest_response", "doc": wire2},
    )
    # Second attestation must NOT replace the pinned master_vk.
    assert peer.peer_master_vk == pinned_vk, "TOFU pin must be sticky"
    # And the peer should be torn down (closed flag set by _close_peer).
    assert peer.closed is True

"""v0.18.0 — Browser-as-peer WebRTC transport foundation.

This pins the first real browser peer transport layer. The browser
can create a signed offer, accept a signed answer, exchange signed ICE
candidates, and move control/bulk data over distinct DataChannels.
Manual copy/paste signaling is intentionally first-class so two
people can connect with zero signaling server.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def peer_html() -> str:
    return Path("src/one_link/web/peer.html").read_text(encoding="utf-8")


def _snippet(html: str, needle: str, size: int = 2400) -> str:
    idx = html.find(needle)
    assert idx >= 0, f"missing {needle!r}"
    return html[idx:idx + size]


def test_webrtc_card_present_and_hidden_until_identity(peer_html: str):
    assert 'id="webrtc-card"' in peer_html
    assert 'id="btn-webrtc-offer"' in peer_html
    assert 'id="btn-webrtc-accept"' in peer_html
    assert 'id="btn-webrtc-copy"' in peer_html
    tag_idx = peer_html.find('id="webrtc-card"')
    tag_start = peer_html.rfind("<div", 0, tag_idx)
    tag_end = peer_html.find(">", tag_idx)
    assert "hidden" in peer_html[tag_start:tag_end]


def test_webrtc_protocol_constants_pinned(peer_html: str):
    assert 'WRTC_PROTOCOL_VERSION = "OL-WRTC-1"' in peer_html
    assert "WRTC_SIGNAL_TTL_MS = 5 * 60 * 1000" in peer_html
    assert "WEBRTC_CONTROL_LABEL" in peer_html
    assert "WEBRTC_BULK_LABEL" in peer_html


def test_multi_org_stun_list_present(peer_html: str):
    snippet = _snippet(peer_html, "WEBRTC_STUN_SERVERS", 1200)
    for host in (
        "stun.l.google.com",
        "global.stun.twilio.com",
        "stun.cloudflare.com",
        "stun.nextcloud.com",
        "stun.sipgate.net",
        "stun.antisip.com",
    ):
        assert host in snippet


def test_peer_connection_uses_datachannels(peer_html: str):
    snippet = _snippet(peer_html, "function createPeerConnection", 5200)
    assert "new RTCPeerConnection" in snippet
    assert "iceServers: WEBRTC_STUN_SERVERS" in snippet
    assert "createDataChannel(WEBRTC_CONTROL_LABEL" in snippet
    assert "createDataChannel(WEBRTC_BULK_LABEL" in snippet
    assert "ordered: false" in snippet
    assert "maxRetransmits: 0" in snippet
    assert "pc.ondatachannel" in snippet


def test_webrtc_signals_are_signed_and_verified(peer_html: str):
    sign = _snippet(peer_html, "async function _signSignal", 1800)
    verify = _snippet(peer_html, "async function verifySignal", 2400)
    assert "sender_pubkey_b64" in sign
    assert "_canonicalJson(signing)" in sign
    assert "_signEd25519" in sign
    assert "signal expired" in verify
    assert "_verifyEd25519" in verify
    assert "signal signature does not verify" in verify


def test_offer_answer_ice_helpers_present(peer_html: str):
    for name in (
        "async function createOfferSignal",
        "async function acceptOfferSignal",
        "async function acceptAnswerSignal",
        "async function addIceSignal",
    ):
        assert name in peer_html
    offer = _snippet(peer_html, "async function createOfferSignal", 1400)
    assert "pc.createOffer" in offer
    assert 'type: "offer"' not in offer  # type is assigned by _signSignal
    answer = _snippet(peer_html, "async function acceptOfferSignal", 1700)
    assert "verifySignal(envelope, \"offer\")" in answer
    assert "pc.createAnswer" in answer
    ice = _snippet(peer_html, "async function addIceSignal", 900)
    assert "verifySignal(envelope, \"ice\")" in ice
    assert "addIceCandidate" in ice


def test_bulk_sender_has_backpressure(peer_html: str):
    snippet = _snippet(peer_html, "async function sendBulk", 1200)
    assert "WEBRTC_BULK_BUFFER_MAX_BYTES" in snippet
    assert "bufferedAmount" in snippet
    assert "onbufferedamountlow" in snippet
    assert "bulk channel not open" in snippet


def test_manual_signal_ui_wiring(peer_html: str):
    offer = _snippet(peer_html, '"#btn-webrtc-offer"', 1900)
    accept = _snippet(peer_html, '"#btn-webrtc-accept"', 2600)
    copy = _snippet(peer_html, '"#btn-webrtc-copy"', 1200)
    assert "createOfferSignal" in offer
    assert "_writeLocalSignal" in offer
    assert "acceptOfferSignal" in accept
    assert "acceptAnswerSignal" in accept
    assert "addIceSignal" in accept
    assert "navigator.clipboard.writeText" in copy


def test_webrtc_card_shown_after_identity(peer_html: str):
    snippet = _snippet(peer_html, "_renderIdentityCard = function", 700)
    assert "_showRdzCard()" in snippet
    assert "_showWebRtcCard()" in snippet


def test_test_surface_exposes_webrtc_helpers(peer_html: str):
    snippet = _snippet(peer_html, "window.__oneLinkPeer", 2400)
    for name in (
        "assertWebRtcAvailable",
        "createPeerConnection",
        "createOfferSignal",
        "acceptOfferSignal",
        "acceptAnswerSignal",
        "addIceSignal",
        "sendControl",
        "sendBulk",
        "verifySignal",
        "encodeSignal",
        "decodeSignal",
    ):
        assert name in snippet


def test_version_bumped_to_v0180(peer_html: str):
    assert 'version: "0.18.0"' in peer_html

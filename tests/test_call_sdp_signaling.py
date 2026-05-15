"""Tests for the SDP + ICE signaling extension.

The :mod:`call_sdp_signaling` module is the wire layer that carries
WebRTC SDP offers / answers + trickled ICE candidates on top of the
media-agnostic CallLifecycle FSM. These tests pin its round-trip
behaviour and refusal of malformed input — the daemon dispatch and
browser driver both rely on those invariants.
"""

from __future__ import annotations

import pytest

from one_link.call_sdp_signaling import (
    CALL_ICE,
    CALL_INVITE_SDP_V1,
    IceCandidatePayload,
    SdpKind,
    SdpPayload,
    attach_answer_to_accept,
    attach_offer_to_invite,
    build_ice_message,
    end_of_candidates,
    extract_answer,
    extract_offer,
    looks_like_sdp,
    parse_ice_message,
)


MINIMAL_OFFER_SDP = (
    "v=0\r\n"
    "o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n"
    "s=-\r\n"
    "t=0 0\r\n"
    "a=group:BUNDLE 0\r\n"
    "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
    "c=IN IP4 0.0.0.0\r\n"
    "a=mid:0\r\n"
)


MINIMAL_ANSWER_SDP = (
    "v=0\r\n"
    "o=- 4611731400430051337 2 IN IP4 127.0.0.1\r\n"
    "s=-\r\n"
    "t=0 0\r\n"
    "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
)


# ---------------------------------------------------------------------------
# SdpKind enum
# ---------------------------------------------------------------------------

def test_sdpkind_from_str_round_trip() -> None:
    for s in ("offer", "answer", "pranswer", "rollback"):
        assert SdpKind.from_str(s).to_str() == s


def test_sdpkind_from_str_case_insensitive() -> None:
    assert SdpKind.from_str("OFFER") == SdpKind.OFFER
    assert SdpKind.from_str("Answer") == SdpKind.ANSWER


def test_sdpkind_from_str_unknown_raises() -> None:
    with pytest.raises(KeyError):
        SdpKind.from_str("garbage")


# ---------------------------------------------------------------------------
# SdpPayload round-trip
# ---------------------------------------------------------------------------

def test_sdp_payload_offer_round_trip() -> None:
    p = SdpPayload(
        schema=CALL_INVITE_SDP_V1,
        kind=SdpKind.OFFER,
        sdp=MINIMAL_OFFER_SDP,
    )
    wire = p.to_wire()
    assert wire["schema"] == CALL_INVITE_SDP_V1
    assert wire["kind"] == "offer"
    assert wire["sdp"] == MINIMAL_OFFER_SDP

    back = SdpPayload.from_wire(wire)
    assert back == p


def test_sdp_payload_answer_round_trip() -> None:
    p = SdpPayload(
        schema=CALL_INVITE_SDP_V1,
        kind=SdpKind.ANSWER,
        sdp=MINIMAL_ANSWER_SDP,
    )
    back = SdpPayload.from_wire(p.to_wire())
    assert back.kind == SdpKind.ANSWER
    assert back.sdp == MINIMAL_ANSWER_SDP


# ---------------------------------------------------------------------------
# SdpPayload refusal
# ---------------------------------------------------------------------------

def test_sdp_payload_from_wire_rejects_non_dict() -> None:
    with pytest.raises(ValueError, match="must be a dict"):
        SdpPayload.from_wire("garbage")  # type: ignore[arg-type]


def test_sdp_payload_from_wire_rejects_wrong_schema() -> None:
    with pytest.raises(ValueError, match="unsupported sdp schema"):
        SdpPayload.from_wire(
            {"schema": 999, "kind": "offer", "sdp": MINIMAL_OFFER_SDP}
        )


def test_sdp_payload_from_wire_rejects_missing_kind() -> None:
    with pytest.raises(ValueError, match="sdp kind"):
        SdpPayload.from_wire(
            {"schema": CALL_INVITE_SDP_V1, "sdp": MINIMAL_OFFER_SDP}
        )


def test_sdp_payload_from_wire_rejects_unknown_kind() -> None:
    with pytest.raises(ValueError, match="unknown sdp kind"):
        SdpPayload.from_wire(
            {
                "schema": CALL_INVITE_SDP_V1,
                "kind": "bogus",
                "sdp": MINIMAL_OFFER_SDP,
            }
        )


def test_sdp_payload_from_wire_rejects_missing_body() -> None:
    with pytest.raises(ValueError, match="sdp body required"):
        SdpPayload.from_wire(
            {"schema": CALL_INVITE_SDP_V1, "kind": "offer"}
        )


def test_sdp_payload_from_wire_rejects_empty_body() -> None:
    with pytest.raises(ValueError, match="sdp body required"):
        SdpPayload.from_wire(
            {"schema": CALL_INVITE_SDP_V1, "kind": "offer", "sdp": ""}
        )


def test_sdp_payload_from_wire_rejects_oversize_body() -> None:
    huge = "v=0\r\n" + ("a" * (130 * 1024))
    with pytest.raises(ValueError, match="too large"):
        SdpPayload.from_wire(
            {"schema": CALL_INVITE_SDP_V1, "kind": "offer", "sdp": huge}
        )


def test_sdp_payload_from_wire_rejects_non_int_schema() -> None:
    with pytest.raises(ValueError, match="sdp schema"):
        SdpPayload.from_wire(
            {"schema": [], "kind": "offer", "sdp": MINIMAL_OFFER_SDP}
        )


# ---------------------------------------------------------------------------
# IceCandidatePayload round-trip
# ---------------------------------------------------------------------------

def test_ice_payload_round_trip() -> None:
    p = IceCandidatePayload(
        schema=CALL_INVITE_SDP_V1,
        candidate="candidate:842163049 1 udp 1677729535 192.0.2.1 54321 typ srflx",
        sdp_mid="0",
        sdp_m_line_index=0,
    )
    wire = p.to_wire()
    assert wire["candidate"].startswith("candidate:")
    assert wire["sdpMid"] == "0"
    assert wire["sdpMLineIndex"] == 0
    assert wire["endOfCandidates"] is False

    back = IceCandidatePayload.from_wire(wire)
    assert back == p


def test_ice_payload_end_of_candidates_sentinel() -> None:
    p = IceCandidatePayload(
        schema=CALL_INVITE_SDP_V1,
        candidate="",
        sdp_mid=None,
        sdp_m_line_index=None,
        end_of_candidates=True,
    )
    back = IceCandidatePayload.from_wire(p.to_wire())
    assert back.end_of_candidates is True
    assert back.candidate == ""


def test_ice_payload_allows_null_mid_and_index() -> None:
    back = IceCandidatePayload.from_wire(
        {
            "schema": CALL_INVITE_SDP_V1,
            "candidate": "candidate:1 1 udp 1 1.2.3.4 1234 typ host",
            "sdpMid": None,
            "sdpMLineIndex": None,
            "endOfCandidates": False,
        }
    )
    assert back.sdp_mid is None
    assert back.sdp_m_line_index is None


# ---------------------------------------------------------------------------
# IceCandidatePayload refusal
# ---------------------------------------------------------------------------

def test_ice_payload_from_wire_rejects_non_dict() -> None:
    with pytest.raises(ValueError, match="must be a dict"):
        IceCandidatePayload.from_wire("garbage")  # type: ignore[arg-type]


def test_ice_payload_from_wire_rejects_wrong_schema() -> None:
    with pytest.raises(ValueError, match="unsupported ice schema"):
        IceCandidatePayload.from_wire(
            {
                "schema": 999,
                "candidate": "candidate:1 1 udp 1 1.2.3.4 1234 typ host",
            }
        )


def test_ice_payload_from_wire_rejects_non_string_candidate() -> None:
    with pytest.raises(ValueError, match="candidate must be string"):
        IceCandidatePayload.from_wire(
            {"schema": CALL_INVITE_SDP_V1, "candidate": 123}
        )


def test_ice_payload_from_wire_rejects_oversize_candidate() -> None:
    huge = "candidate:" + ("a" * (5 * 1024))
    with pytest.raises(ValueError, match="ice candidate too large"):
        IceCandidatePayload.from_wire(
            {"schema": CALL_INVITE_SDP_V1, "candidate": huge}
        )


def test_ice_payload_from_wire_rejects_non_string_mid() -> None:
    with pytest.raises(ValueError, match="sdpMid"):
        IceCandidatePayload.from_wire(
            {
                "schema": CALL_INVITE_SDP_V1,
                "candidate": "candidate:1 1 udp 1 1.2.3.4 1234 typ host",
                "sdpMid": 42,
            }
        )


def test_ice_payload_from_wire_rejects_non_int_index() -> None:
    with pytest.raises(ValueError, match="sdpMLineIndex"):
        IceCandidatePayload.from_wire(
            {
                "schema": CALL_INVITE_SDP_V1,
                "candidate": "candidate:1 1 udp 1 1.2.3.4 1234 typ host",
                "sdpMLineIndex": "not-an-int",
            }
        )


def test_ice_payload_from_wire_rejects_out_of_range_index() -> None:
    with pytest.raises(ValueError, match="out of range"):
        IceCandidatePayload.from_wire(
            {
                "schema": CALL_INVITE_SDP_V1,
                "candidate": "candidate:1 1 udp 1 1.2.3.4 1234 typ host",
                "sdpMLineIndex": -1,
            }
        )
    with pytest.raises(ValueError, match="out of range"):
        IceCandidatePayload.from_wire(
            {
                "schema": CALL_INVITE_SDP_V1,
                "candidate": "candidate:1 1 udp 1 1.2.3.4 1234 typ host",
                "sdpMLineIndex": 9999,
            }
        )


# ---------------------------------------------------------------------------
# attach_offer_to_invite / extract_offer
# ---------------------------------------------------------------------------

def test_attach_and_extract_offer() -> None:
    invite = {"call_id": "abc", "from": "alice"}
    enriched = attach_offer_to_invite(invite, sdp=MINIMAL_OFFER_SDP)
    # Original dict not mutated.
    assert "sdp_offer" not in invite
    assert "sdp_offer" in enriched
    offer = extract_offer(enriched)
    assert offer is not None
    assert offer.kind == SdpKind.OFFER
    assert offer.sdp == MINIMAL_OFFER_SDP


def test_extract_offer_returns_none_when_absent() -> None:
    assert extract_offer({"call_id": "abc"}) is None


def test_extract_offer_raises_when_malformed() -> None:
    with pytest.raises(ValueError):
        extract_offer({"sdp_offer": {"schema": 999, "kind": "offer", "sdp": "x"}})


# ---------------------------------------------------------------------------
# attach_answer_to_accept / extract_answer
# ---------------------------------------------------------------------------

def test_attach_and_extract_answer() -> None:
    accept = {"call_id": "abc", "from": "bob"}
    enriched = attach_answer_to_accept(accept, sdp=MINIMAL_ANSWER_SDP)
    assert "sdp_answer" not in accept
    ans = extract_answer(enriched)
    assert ans is not None
    assert ans.kind == SdpKind.ANSWER
    assert ans.sdp == MINIMAL_ANSWER_SDP


def test_extract_answer_returns_none_when_absent() -> None:
    assert extract_answer({"call_id": "abc"}) is None


# ---------------------------------------------------------------------------
# CALL_ICE build / parse
# ---------------------------------------------------------------------------

def test_build_ice_message_round_trip() -> None:
    cand = IceCandidatePayload(
        schema=CALL_INVITE_SDP_V1,
        candidate="candidate:1 1 udp 1 1.2.3.4 1234 typ host",
        sdp_mid="0",
        sdp_m_line_index=0,
    )
    msg = build_ice_message(call_id="call-xyz", candidate=cand)
    assert msg["call_id"] == "call-xyz"
    call_id, back = parse_ice_message(msg)
    assert call_id == "call-xyz"
    assert back == cand


def test_parse_ice_message_rejects_missing_call_id() -> None:
    with pytest.raises(ValueError, match="missing call_id"):
        parse_ice_message({"candidate": {"schema": CALL_INVITE_SDP_V1, "candidate": "x"}})


def test_parse_ice_message_rejects_empty_call_id() -> None:
    with pytest.raises(ValueError, match="missing call_id"):
        parse_ice_message({"call_id": "", "candidate": {}})


def test_parse_ice_message_rejects_missing_candidate() -> None:
    with pytest.raises(ValueError, match="missing candidate"):
        parse_ice_message({"call_id": "xyz"})


def test_end_of_candidates_helper_round_trip() -> None:
    msg = end_of_candidates("call-xyz")
    call_id, cand = parse_ice_message(msg)
    assert call_id == "call-xyz"
    assert cand.end_of_candidates is True
    assert cand.candidate == ""


# ---------------------------------------------------------------------------
# looks_like_sdp structural check
# ---------------------------------------------------------------------------

def test_looks_like_sdp_accepts_real_offer() -> None:
    assert looks_like_sdp(MINIMAL_OFFER_SDP) is True


def test_looks_like_sdp_accepts_leading_whitespace() -> None:
    assert looks_like_sdp("   " + MINIMAL_OFFER_SDP) is True


def test_looks_like_sdp_rejects_non_sdp() -> None:
    assert looks_like_sdp("not sdp at all") is False
    assert looks_like_sdp("") is False
    assert looks_like_sdp("\x00\x01\x02") is False


def test_looks_like_sdp_rejects_no_media_line() -> None:
    # v=0 but no m=...
    s = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n"
    assert looks_like_sdp(s) is False


def test_looks_like_sdp_rejects_non_string() -> None:
    assert looks_like_sdp(None) is False  # type: ignore[arg-type]
    assert looks_like_sdp(123) is False  # type: ignore[arg-type]


def test_call_ice_constant_is_stable() -> None:
    """The wire-level message type string is part of the protocol —
    if this changes, older peers will silently drop the messages."""
    assert CALL_ICE == "CALL_ICE"

"""Audit C1 defense-in-depth: DTLS fingerprint cross-check.

Verifies that ``BrowserPeerManager.record_dtls_fingerprint`` extracts
the ``a=fingerprint:`` line from inbound SDP and tracks it against
the peer's Ed25519 pubkey. A silent rotation is recorded + logged
(WARN), not rejected — the envelope-signature gate upstream catches
real attacks; this is belt-and-suspenders.
"""

from __future__ import annotations

import logging

import pytest

from one_link.peer_rtc import BrowserPeerManager, _extract_dtls_fingerprint


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeDaemon:
    """Minimal stand-in: BrowserPeerManager.__init__ just stashes
    the daemon reference; it doesn't call into it during the DTLS
    check path."""

    pass


def _mk_manager() -> BrowserPeerManager:
    return BrowserPeerManager(daemon=_FakeDaemon())


SAMPLE_SDP_TEMPLATE = """v=0
o=- 4611731400430051336 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=fingerprint:sha-256 {FP}
a=setup:actpass
a=mid:0
"""


def _sdp_with_fp(fp_hex: str) -> str:
    return SAMPLE_SDP_TEMPLATE.replace("{FP}", fp_hex.upper())


PUBKEY_A = b"\x01" * 32
PUBKEY_B = b"\x02" * 32


# ---------------------------------------------------------------------------
# Extraction primitive
# ---------------------------------------------------------------------------

def test_extract_dtls_fingerprint_from_sdp() -> None:
    fp = _extract_dtls_fingerprint(
        _sdp_with_fp("AA:BB:CC:DD:EE:FF:11:22"),
    )
    assert fp == "sha-256:AA:BB:CC:DD:EE:FF:11:22"


def test_extract_returns_empty_when_no_fingerprint_line() -> None:
    sdp_no_fp = "v=0\no=- 1 1 IN IP4 0.0.0.0\ns=-\nt=0 0\n"
    assert _extract_dtls_fingerprint(sdp_no_fp) == ""


def test_extract_returns_empty_on_non_string() -> None:
    assert _extract_dtls_fingerprint(None) == ""  # type: ignore[arg-type]
    assert _extract_dtls_fingerprint(123) == ""   # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# First observation
# ---------------------------------------------------------------------------

def test_first_observation_recorded_returns_matches_true() -> None:
    mgr = _mk_manager()
    fp, matches = mgr.record_dtls_fingerprint(
        pubkey=PUBKEY_A,
        sdp=_sdp_with_fp("11:22:33:44:55"),
    )
    assert fp == "sha-256:11:22:33:44:55"
    assert matches is True


def test_first_observation_stored_for_future_lookup() -> None:
    mgr = _mk_manager()
    mgr.record_dtls_fingerprint(
        pubkey=PUBKEY_A,
        sdp=_sdp_with_fp("AB:CD:EF"),
    )
    assert mgr.get_recorded_dtls_fingerprint(PUBKEY_A) == "sha-256:AB:CD:EF"


# ---------------------------------------------------------------------------
# Re-observation
# ---------------------------------------------------------------------------

def test_same_fingerprint_re_observed_returns_true() -> None:
    mgr = _mk_manager()
    mgr.record_dtls_fingerprint(
        pubkey=PUBKEY_A,
        sdp=_sdp_with_fp("11:22"),
    )
    _, matches = mgr.record_dtls_fingerprint(
        pubkey=PUBKEY_A,
        sdp=_sdp_with_fp("11:22"),
    )
    assert matches is True


def test_changed_fingerprint_logs_warning_and_returns_false(
    caplog: pytest.LogCaptureFixture,
) -> None:
    mgr = _mk_manager()
    mgr.record_dtls_fingerprint(
        pubkey=PUBKEY_A,
        sdp=_sdp_with_fp("AA:AA:AA"),
    )
    with caplog.at_level(logging.WARNING, logger="one_link.peer_rtc"):
        fp, matches = mgr.record_dtls_fingerprint(
            pubkey=PUBKEY_A,
            sdp=_sdp_with_fp("BB:BB:BB"),
        )
    assert matches is False
    assert fp == "sha-256:BB:BB:BB"
    # The warning is structured + contains the peer pubkey prefix.
    msgs = [r.getMessage() for r in caplog.records]
    assert any("DTLS fingerprint changed" in m for m in msgs)


def test_changed_fingerprint_updates_stored_value() -> None:
    mgr = _mk_manager()
    mgr.record_dtls_fingerprint(
        pubkey=PUBKEY_A,
        sdp=_sdp_with_fp("AA:AA"),
    )
    mgr.record_dtls_fingerprint(
        pubkey=PUBKEY_A,
        sdp=_sdp_with_fp("BB:BB"),
    )
    # Latest is now stored.
    assert mgr.get_recorded_dtls_fingerprint(PUBKEY_A) == "sha-256:BB:BB"


# ---------------------------------------------------------------------------
# Per-pubkey isolation
# ---------------------------------------------------------------------------

def test_different_pubkeys_have_independent_history() -> None:
    """Alice's DTLS fp must not affect Bob's history."""
    mgr = _mk_manager()
    mgr.record_dtls_fingerprint(pubkey=PUBKEY_A, sdp=_sdp_with_fp("AA"))
    _, matches_b = mgr.record_dtls_fingerprint(
        pubkey=PUBKEY_B, sdp=_sdp_with_fp("BB"),
    )
    # Bob's first observation — not affected by Alice's prior record.
    assert matches_b is True
    assert mgr.get_recorded_dtls_fingerprint(PUBKEY_A) == "sha-256:AA"
    assert mgr.get_recorded_dtls_fingerprint(PUBKEY_B) == "sha-256:BB"


# ---------------------------------------------------------------------------
# Edge: SDP without fingerprint line
# ---------------------------------------------------------------------------

def test_sdp_without_fingerprint_does_not_raise() -> None:
    mgr = _mk_manager()
    fp, matches = mgr.record_dtls_fingerprint(
        pubkey=PUBKEY_A,
        sdp="v=0\no=- 1 1 IN IP4 0.0.0.0\ns=-\nt=0 0\n",
    )
    assert fp == ""
    # No fingerprint to check → first-seen-equivalent ("True" so the
    # caller doesn't take action).
    assert matches is True


def test_sdp_without_fingerprint_does_not_record() -> None:
    mgr = _mk_manager()
    mgr.record_dtls_fingerprint(
        pubkey=PUBKEY_A,
        sdp="v=0\no=- 1 1 IN IP4 0.0.0.0\ns=-\nt=0 0\n",
    )
    assert mgr.get_recorded_dtls_fingerprint(PUBKEY_A) is None


# ---------------------------------------------------------------------------
# Manager init guarantees
# ---------------------------------------------------------------------------

def test_manager_initialises_empty_dtls_map() -> None:
    mgr = _mk_manager()
    assert mgr.get_recorded_dtls_fingerprint(PUBKEY_A) is None
    assert mgr.get_recorded_dtls_fingerprint(PUBKEY_B) is None

"""v0.21.x plain-English copy gates.

Pins user-visible UI strings to plain-English replacements. The
audit found 19 friction points where engineer-jargon ("AES-GCM",
"OPFS", "PBKDF2", "Web Crypto", "SAS", "verification code")
leaked into copy normal users see. These tests pin the
replacements so a future refactor that re-introduces the jargon
fails CI before users see it.

We deliberately DON'T test the inverse ('the file contains no
'BLAKE3'') — those terms are legitimate inside code comments,
API parameter names, and crypto.subtle() calls. We assert on
the SPECIFIC user-visible strings that were jargony + are now
not.
"""
from __future__ import annotations

from pathlib import Path

import pytest


_PEER_HTML = Path(__file__).resolve().parents[1] / "src" / "one_link" / "web" / "peer.html"
_INDEX_HTML = Path(__file__).resolve().parents[1] / "src" / "one_link" / "web" / "index.html"
_SERVER_PY = Path(__file__).resolve().parents[1] / "src" / "one_link" / "server.py"


@pytest.fixture(scope="module")
def peer_html() -> str:
    return _PEER_HTML.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def server_src() -> str:
    return _SERVER_PY.read_text(encoding="utf-8")


# ── peer.html boot-error pill labels ────────────────────────────────


def test_boot_error_pill_no_jargon(peer_html):
    """The boot-error pills users see when their browser is too old
    must say plain-English labels, NOT 'no web crypto' / 'no opfs'.
    Users have no way to action 'no opfs'."""
    assert 'setPill("bad", "no web crypto")' not in peer_html, (
        "boot error pill 'no web crypto' is jargon; users can't "
        "action it. Should say 'browser too old'."
    )
    assert 'setPill("bad", "no opfs")' not in peer_html
    assert 'setPill("bad", "insecure context")' not in peer_html
    # Positive: the new labels are in.
    assert 'setPill("bad", "needs https")' in peer_html
    assert 'setPill("bad", "browser too old")' in peer_html


def test_boot_error_status_text_explains_what_to_do(peer_html):
    """When a boot error fires, the status text MUST tell the user
    what action to take ('update Safari', 'open the QR again on
    your laptop'), not just name the technical failure."""
    assert "Your browser is too old to run One Link safely" in peer_html, (
        "boot error message must lead with the plain-English problem "
        "before any browser-version list"
    )
    assert "Open the QR code on your laptop again and scan it" in peer_html
    # The original jargon-only sentences must be gone.
    assert "Browsers block Web Crypto on plain HTTP to a LAN address." not in peer_html
    assert "This browser doesn't expose Web Crypto." not in peer_html
    assert "This browser doesn't expose OPFS." not in peer_html


# ── peer.html SAS pairing ──────────────────────────────────────────


def test_sas_pairing_card_uses_plain_english_labels(peer_html):
    """The pairing-verification card was titled 'Verify the
    connection' with subheaders 'Verification code' + 'Visual art'
    + buttons 'Codes match' / 'Don't match'. Plain English: 'Confirm
    it's really you', 'Confirmation code', 'Picture', 'They match' /
    'They don't match'."""
    assert "<h2>Confirm it's really you</h2>" in peer_html
    assert ">Confirmation code<" in peer_html
    assert ">Picture<" in peer_html
    assert ">They match<" in peer_html
    assert ">They don't match<" in peer_html
    # Old jargon strings must be gone.
    assert "<h2>Verify the connection</h2>" not in peer_html
    assert ">Verification code<" not in peer_html
    assert ">Visual art<" not in peer_html
    # 'Codes match' button label gone (replaced with 'They match').
    assert ">Codes match<" not in peer_html


# ── peer.html passphrase + identity copy ───────────────────────────


def test_passphrase_help_text_does_not_leak_crypto_jargon(peer_html):
    """The 'Set passphrase' card help text used to read 'wrap this
    device's keypair with AES-GCM' - jargon. Now plain English."""
    assert "wrap this device's keypair with AES-GCM" not in peer_html, (
        "passphrase help leaks 'AES-GCM' jargon to the user; the "
        "fact that we use AES-GCM is an implementation detail"
    )
    # Positive: the new explanation uses 'encrypt' not 'wrap'.
    assert "Set a passphrase to encrypt this device's identity" in peer_html


def test_unlock_progress_text_does_not_say_pbkdf2(peer_html):
    """The unlock progress message said 'deriving key (PBKDF2 600k
    iterations)' - the user doesn't know what PBKDF2 is. Now
    plain English: 'Unlocking. This takes a second.'"""
    assert "PBKDF2" not in peer_html or not _contains_user_visible_pbkdf2(peer_html), (
        "PBKDF2 leaked into user-visible copy; should only appear "
        "in crypto.subtle() argument names + code comments"
    )
    assert "Unlocking. This takes a second." in peer_html


def _contains_user_visible_pbkdf2(html: str) -> bool:
    """PBKDF2 appears legitimately as a crypto.subtle() argument
    name and in code comments. It's a problem ONLY when it shows
    up in a setDiag()/text()/innerHTML call that ends up on screen.
    Check by looking for setDiag/innerHTML/textContent strings
    containing 'PBKDF2'."""
    import re
    for m in re.finditer(
        r'(?:setDiag|innerHTML|textContent|placeholder)\s*[=(]\s*[\'"`]([^\'"`]+)[\'"`]',
        html,
    ):
        if "PBKDF2" in m.group(1):
            return True
    return False


# ── peer.html generic status messages ──────────────────────────────


def test_autopair_status_explains_duration(peer_html):
    """The autopair status used to say 'Setting up secure link…' -
    generic, users don't know if it's stuck. Now sets a duration
    expectation."""
    assert ">Connecting to your laptop. This usually takes a few seconds.<" in peer_html
    assert ">Setting up secure link…<" not in peer_html


# ── iOS install page ──────────────────────────────────────────────


def test_ios_install_page_sets_30_second_expectation(server_src):
    """The iOS mobileconfig install page used to say 'You're seconds
    away. Two taps on iPhone' which lied about both the time + tap
    count. Now sets accurate expectations."""
    assert "About 30 seconds. We'll walk you through every tap." in server_src, (
        "iOS install page must set an accurate time expectation upfront"
    )
    assert "You're seconds away. Two taps on iPhone" not in server_src


def test_ios_install_page_has_per_step_troubleshooting(server_src):
    """Each install step needs an expandable 'stuck?' that explains
    the most-common failure mode. Without per-step recovery hints,
    a user who hits the wrong screen quits + the project loses
    that install."""
    install_idx = server_src.find("Tap to download")
    assert install_idx > 0, "iOS install page step 1 heading missing"
    # The 4 instances of <details> = the 4 step-level troubleshooting
    # expanders we ship.
    page_section = server_src[install_idx:install_idx + 6000]
    detail_count = page_section.count("<details")
    assert detail_count >= 4, (
        f"iOS install page should have a <details> troubleshooting "
        f"section under each of the 4 steps; found {detail_count}"
    )


def test_ios_install_page_explains_why_extra_step_3_exists(server_src):
    """The most-missed step is the trust-switch (step 3). The page
    must include a 'why this extra step?' explainer so users
    don't think they're being asked to do something weird."""
    assert "Why this extra step?" in server_src, (
        "iOS install step 3 lacks a 'why this extra step?' "
        "explainer; users skip it thinking it's redundant"
    )

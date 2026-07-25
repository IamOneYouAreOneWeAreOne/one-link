"""v0.20.3 — /peer UX scrub.

The user's complaint that drove the v0.20 arc: too many seams
visible. The default user opens /peer and sees identity card,
rendezvous card, manual signaling, SAS art, peer list — all
power-user surfaces with no scan-the-QR-and-be-done path.

This ship hides every technical card behind data-tier="advanced"
and shows ONE landing card by default: "Pair this device. On
your laptop, open Settings -> Devices -> Add a phone or laptop."

  Reach:  default-mode user sees clear instructions + nothing
          else. Power-user user can flip "Advanced surfaces"
          and access everything.
  Hide:   data-tier="advanced" CSS rule hides every tagged card
          unless html.show-advanced is on. Persisted via
          localStorage so a refresh keeps the toggle state.
  Async:  none (pure CSS + tiny JS toggle).
  Depth:  the auto-pair flow's _autopairHideManualCards now also
          hides the welcome card so a phone scanning a QR doesn't
          flash "scan a QR" copy at the user before fading into
          the connecting state.

Tests pin: welcome card markup + visibility default, advanced
toggle markup + persistence, every technical card carries
data-tier="advanced", auto-pair hides welcome too, CSS rules.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def peer_html() -> str:
    return Path("src/one_link/web/peer.html").read_text(encoding="utf-8")


def _open_tag_with_id(html: str, element_id: str) -> str:
    """Return the opening tag for the element with the given id."""
    needle = f'id="{element_id}"'
    idx = html.find(needle)
    if idx < 0:
        return ""
    open_start = html.rfind("<", 0, idx)
    open_end = html.find(">", idx)
    return html[open_start:open_end + 1]


# ───────── welcome card ─────────────────────────────────────────────


def test_welcome_card_present(peer_html: str):
    """The default landing surface. One card, clear instructions
    pointing at the desktop UI's pair-by-QR flow."""
    assert 'id="welcome-card"' in peer_html


def test_welcome_card_starts_hidden(peer_html: str):
    """Hidden in markup; the boot dispatch reveals it only when
    there's no ?pair= query (otherwise auto-pair takes over and
    the welcome card stays hidden)."""
    tag = _open_tag_with_id(peer_html, "welcome-card")
    assert "hidden" in tag


def test_welcome_card_explains_qr_flow(peer_html: str):
    """The copy MUST tell the user exactly where to find the QR
    on the laptop. 'Devices -> Add a phone or laptop -> Create device QR'.
    If the path moves, the test breaks loudly so we can update
    both surfaces."""
    idx = peer_html.find('id="welcome-card"')
    body = peer_html[idx:idx + 1500]
    assert "Devices" in body
    assert "Add a phone or laptop" in body
    assert "Create device QR" in body
    assert "QR" in body


def test_welcome_card_has_advanced_toggle(peer_html: str):
    """The 'Advanced surfaces' button is the only way out of
    welcome mode (without a pair query). Pin its presence."""
    idx = peer_html.find('id="welcome-card"')
    body = peer_html[idx:idx + 2000]
    assert 'id="btn-show-advanced"' in body


# ───────── data-tier="advanced" tagging ────────────────────────────


@pytest.mark.parametrize("card_id", [
    "identity-card",
    "status-card",
    "actions-card",
    "rdz-card",
    "webrtc-card",
    "pair-card",
    "peers-card",
    "chat-card",
])
def test_technical_cards_tagged_advanced(peer_html: str, card_id: str):
    """Every power-user card MUST carry data-tier="advanced" so
    the CSS rule hides it by default. Default users never see
    these surfaces unless they explicitly flip the toggle."""
    tag = _open_tag_with_id(peer_html, card_id)
    assert tag, f"missing element {card_id}"
    assert 'data-tier="advanced"' in tag


@pytest.mark.parametrize("card_id", [
    "welcome-card",
    "autopair-card",
    "daemon-roster-card",
    "daemon-chat-card",
    "identity-setup-card",
    "unlock-card",
])
def test_user_facing_cards_not_advanced(peer_html: str, card_id: str):
    """Cards that the default user MUST see (welcome, identity security gates,
    auto-pair, daemon roster + chat) MUST NOT carry data-tier="advanced".
    Otherwise they'd be invisible until the user flipped the
    toggle, defeating the whole UX scrub."""
    tag = _open_tag_with_id(peer_html, card_id)
    assert tag, f"missing element {card_id}"
    assert 'data-tier="advanced"' not in tag


# ───────── CSS reveal rule ─────────────────────────────────────────


def test_advanced_hidden_by_default_css(peer_html: str):
    """The CSS rule hiding [data-tier='advanced'] by default MUST
    be present. Without it, all the tagged cards would still
    render."""
    assert '[data-tier="advanced"] { display: none; }' in peer_html


def test_show_advanced_class_reveals(peer_html: str):
    """The .show-advanced class on <html> reveals every
    [data-tier='advanced'] element. display: revert lets each
    card use its natural display value (block, flex) rather than
    being forced to a single mode."""
    assert 'html.show-advanced [data-tier="advanced"] { display: revert; }' in peer_html


# ───────── advanced toggle JS ──────────────────────────────────────


def test_advanced_toggle_uses_localstorage(peer_html: str):
    """User's preference persists across reloads. Pin the key so
    a refactor doesn't quietly switch storage location."""
    assert 'ADV_KEY = "ol_peer.show_advanced"' in peer_html


def test_advanced_toggle_button_handler(peer_html: str):
    """Clicking the button flips html.show-advanced + persists +
    re-labels the button."""
    idx = peer_html.find('"#btn-show-advanced"')
    handler = peer_html.find("addEventListener", idx)
    snippet = peer_html[handler:handler + 800]
    assert 'classList.contains("show-advanced")' in snippet
    assert "_setShowAdvanced(!on)" in snippet


def test_advanced_state_restored_at_boot(peer_html: str):
    """If the user previously enabled advanced, restore that on
    page load BEFORE any cards render — otherwise the cards
    flash hidden then visible, looking buggy."""
    idx = peer_html.find('localStorage.getItem(ADV_KEY)')
    assert idx >= 0
    snippet = peer_html[idx:idx + 400]
    assert 'classList.add("show-advanced")' in snippet


def test_set_show_advanced_relabels_button(peer_html: str):
    """The button text alternates between 'Advanced surfaces' (off)
    and 'Hide advanced surfaces' (on). Pin both labels so the user
    sees the right action label for the current state."""
    snippet = peer_html[
        peer_html.find("function _setShowAdvanced"):
        peer_html.find("function _setShowAdvanced") + 1200
    ]
    assert "Advanced surfaces" in snippet
    assert "Hide advanced surfaces" in snippet


# ───────── boot dispatch updates ───────────────────────────────────


def test_boot_shows_welcome_when_no_pair_query(peer_html: str):
    """If _detectPairQuery returns null, _showWelcome (or just
    show($('#welcome-card'))) MUST fire. Without this, the page
    loads to a blank canvas — total UX failure."""
    idx = peer_html.find("const _pairQuery = _detectPairQuery();")
    snippet = peer_html[idx:idx + 5000]
    assert '_showOnly("#welcome-card")' in snippet
    # Welcome shows in the else branch (no pair query).
    else_idx = snippet.find("} else {")
    assert else_idx > 0
    after_else = snippet[else_idx:else_idx + 800]
    assert '_showOnly("#welcome-card")' in after_else


def test_autopair_also_hides_welcome_card(peer_html: str):
    """When auto-pair fires, welcome MUST be in the hide list so
    the user doesn't see 'scan a QR' copy briefly while the
    page transitions to connecting."""
    snippet = peer_html[
        peer_html.find("const _PHONE_TOP_LEVEL_CARDS"):
        peer_html.find("const _PHONE_TOP_LEVEL_CARDS") + 1800
    ]
    assert '#welcome-card' in snippet


# ───────── version pin ────────────────────────────────────────────


def test_peer_version_at_or_above_v0203(peer_html: str):
    """Forward-compat: pin shape, not literal."""
    import re
    m = re.search(r"version:\s*['\"](\d+)\.(\d+)\.(\d+)(?:-[A-Za-z0-9.]+)?['\"]", peer_html)
    assert m
    parts = tuple(int(p) for p in m.groups())
    assert parts >= (0, 20, 3)


def test_page_version_matches_package():
    from one_link import __version__
    html = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert f'PAGE_BUILT_FOR = "{__version__}"' in html

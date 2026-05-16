"""Tests for the May 15 2026 sovereignty preset layer.

Three tiers:
  - just_works (default): community STUN + update notifications + LAN
  - quiet: LAN only, zero outbound
  - off_grid: no mDNS either

Plus the resolver layer: explicit settings + env-vars win over the
preset default in that order.
"""
from __future__ import annotations

import json
from types import SimpleNamespace
from pathlib import Path

import pytest

from one_link import sovereignty as _sov


# ── Preset definitions ─────────────────────────────────────────────


def test_three_presets_exist():
    """The three named tiers are present and correctly keyed."""
    assert set(_sov.ALL_PRESETS.keys()) == {"just_works", "quiet", "off_grid"}


def test_default_preset_is_just_works():
    """Fresh install lands on 'Just Works' — usable cross-network out
    of the box, no corp accounts."""
    assert _sov.DEFAULT_PRESET_NAME == "just_works"


def test_just_works_uses_community_stun_not_big_three():
    """The community STUN list must NOT include Big-3 corporate
    servers. The whole point is avoiding those."""
    p = _sov.get_preset("just_works")
    joined = " ".join(p.stun_servers).lower()
    for forbidden in (
        "stun.l.google.com",       # Google
        "global.stun.twilio.com",  # Twilio
        "stun.cloudflare.com",     # Cloudflare
    ):
        assert forbidden not in joined, (
            f"just_works preset includes corp STUN {forbidden!r}; "
            f"only independent/community servers belong here"
        )
    # And it MUST include at least one server (otherwise the user
    # would silently lose cross-NAT pairing on the default).
    assert len(p.stun_servers) >= 1


def test_just_works_enables_update_notifications():
    assert _sov.get_preset("just_works").update_check_enabled is True


def test_just_works_keeps_mdns_on():
    assert _sov.get_preset("just_works").mdns_discovery_enabled is True


def test_quiet_is_lan_only():
    p = _sov.get_preset("quiet")
    assert p.update_check_enabled is False
    assert p.stun_servers == ()
    assert p.mdns_discovery_enabled is True   # LAN discovery still OK
    assert p.rendezvous_enabled is False


def test_off_grid_disables_even_mdns():
    p = _sov.get_preset("off_grid")
    assert p.update_check_enabled is False
    assert p.stun_servers == ()
    assert p.mdns_discovery_enabled is False  # Hard isolation
    assert p.rendezvous_enabled is False


def test_unknown_preset_falls_back_to_default():
    """Malformed user input MUST NOT crash the daemon."""
    assert _sov.get_preset("garbage").name == "just_works"
    assert _sov.get_preset("").name == "just_works"
    assert _sov.get_preset(None).name == "just_works"


def test_preset_get_is_case_insensitive():
    assert _sov.get_preset("Just_Works").name == "just_works"
    assert _sov.get_preset("JUST_WORKS").name == "just_works"


# ── Resolver order — setting > env > preset ────────────────────────


def test_update_check_explicit_setting_overrides_preset():
    """User can set state.update_check_enabled=0 on just_works to
    silence update notifications without switching presets."""
    on = _sov.resolve_update_check_enabled(
        state_setting="0",
        env_var=None,
        preset_name="just_works",
    )
    assert on is False
    # And vice versa: setting=1 on quiet enables it.
    on = _sov.resolve_update_check_enabled(
        state_setting="1",
        env_var=None,
        preset_name="quiet",
    )
    assert on is True


def test_update_check_env_var_overrides_preset():
    on = _sov.resolve_update_check_enabled(
        state_setting=None,
        env_var="0",
        preset_name="just_works",
    )
    assert on is False
    on = _sov.resolve_update_check_enabled(
        state_setting=None,
        env_var="1",
        preset_name="quiet",
    )
    assert on is True


def test_update_check_setting_beats_env():
    """If both setting and env are set, the explicit setting wins."""
    on = _sov.resolve_update_check_enabled(
        state_setting="0",
        env_var="1",
        preset_name="just_works",
    )
    assert on is False


def test_update_check_falls_through_to_preset_when_nothing_set():
    on = _sov.resolve_update_check_enabled(
        state_setting=None, env_var=None, preset_name="just_works",
    )
    assert on is True
    on = _sov.resolve_update_check_enabled(
        state_setting=None, env_var=None, preset_name="quiet",
    )
    assert on is False


def test_stun_setting_empty_string_is_explicit_opt_out():
    """state.stun_servers = "" must mean 'no STUN even though the
    preset would supply community ones' — this is the power-user
    escape hatch."""
    urls = _sov.resolve_stun_servers(
        state_setting="",        # explicit empty
        env_var=None,
        preset_name="just_works",
    )
    assert urls == ()


def test_stun_setting_none_means_use_preset_default():
    """state.stun_servers = None (unset) falls through to the preset.
    just_works preset = community STUN list."""
    urls = _sov.resolve_stun_servers(
        state_setting=None,
        env_var=None,
        preset_name="just_works",
    )
    assert len(urls) >= 1
    assert urls == _sov.JUST_WORKS.stun_servers


def test_stun_setting_overrides_preset_with_custom_list():
    urls = _sov.resolve_stun_servers(
        state_setting="stun:mybox.local:3478,stun:other:3478",
        env_var=None,
        preset_name="just_works",
    )
    assert urls == ("stun:mybox.local:3478", "stun:other:3478")


def test_stun_env_var_overrides_preset_when_setting_missing():
    urls = _sov.resolve_stun_servers(
        state_setting=None,
        env_var="stun:env-set:3478",
        preset_name="just_works",
    )
    assert urls == ("stun:env-set:3478",)


def test_stun_setting_beats_env_var():
    urls = _sov.resolve_stun_servers(
        state_setting="stun:from-setting:3478",
        env_var="stun:from-env:3478",
        preset_name="just_works",
    )
    assert urls == ("stun:from-setting:3478",)


def test_stun_resolver_dedups_and_strips_whitespace():
    urls = _sov.resolve_stun_servers(
        state_setting=" stun:a:1 , stun:a:1 ,  stun:b:2 ",
        env_var=None,
        preset_name="just_works",
    )
    assert urls == ("stun:a:1", "stun:b:2")


# ── current_preset_name state lookup ───────────────────────────────


def test_current_preset_name_with_no_state_returns_default():
    assert _sov.current_preset_name(None) == "just_works"


def test_current_preset_name_reads_setting():
    class FakeState:
        def __init__(self, val):
            self.val = val
        def get_setting(self, k):
            return self.val if k == "sovereignty_preset" else None

    assert _sov.current_preset_name(FakeState("quiet")) == "quiet"
    assert _sov.current_preset_name(FakeState("off_grid")) == "off_grid"
    # Unknown → default.
    assert _sov.current_preset_name(FakeState("bogus")) == "just_works"
    # None → default.
    assert _sov.current_preset_name(FakeState(None)) == "just_works"


def test_current_preset_name_state_failure_returns_default():
    """If state.get_setting raises, fall back to default — never crash."""
    class BrokenState:
        def get_setting(self, k):
            raise RuntimeError("disk fire")
    assert _sov.current_preset_name(BrokenState()) == "just_works"


# ── HTML / API contract surface (snapshot tests) ───────────────────


WEB_INDEX = (
    Path(__file__).resolve().parent.parent
    / "src" / "one_link" / "web" / "index.html"
)


def test_privacy_panel_overlay_present_in_html():
    html = WEB_INDEX.read_text(encoding="utf-8")
    # The overlay element exists.
    assert 'id="privacy-panel-overlay"' in html
    # The trigger button exists.
    assert 'id="btn-privacy"' in html
    # The JS entry point exists.
    assert "window.openPrivacyPanel = " in html
    # The Ctrl+Shift+P shortcut is wired.
    assert 'ev.ctrlKey && ev.shiftKey' in html
    # The 3 sovereignty endpoints are referenced.
    assert "/api/sovereignty/status" in html
    assert "/api/sovereignty/preset" in html
    assert "/api/sovereignty/outbound" in html


def test_privacy_panel_does_not_clutter_default_view():
    """Doctrine: privacy panel is HIDDEN by default. The overlay
    must start without the `.show` class so it doesn't paint until
    explicitly opened."""
    html = WEB_INDEX.read_text(encoding="utf-8")
    # Find the overlay div opening tag.
    idx = html.find('id="privacy-panel-overlay"')
    assert idx >= 0
    # Pull the div tag.
    div_open = html.rfind("<div", 0, idx)
    div_end = html.find(">", idx)
    div_tag = html[div_open:div_end + 1]
    assert "privacy-panel-overlay" in div_tag
    # The class list must NOT include 'show' in the static HTML.
    # The hidden-by-default style relies on `.show` being absent.
    assert " show" not in div_tag or 'class="privacy-panel-overlay"' in div_tag


def test_three_preset_cards_renderable_from_html_template():
    """The JS pulls preset data from /api/sovereignty/preset and
    renders one card per preset. Verify the JS handles each tier
    label (a regression here = a broken preset chooser)."""
    html = WEB_INDEX.read_text(encoding="utf-8")
    # The renderer references the preset data structure.
    assert "p.label" in html
    assert "p.description" in html
    assert "p.outbound_summary" in html

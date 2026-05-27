"""v0.21.x sovereignty preset wiring audit:

Pre-2026-05-27, 2 preset fields (mdns_discovery_enabled,
rendezvous_enabled) existed on the dataclass but no runtime code
checked them — off_grid mode silently broadcast over mDNS. 2 more
privacy-critical subsystems (TURN relay + mDNS rendezvous-URL
inheritance) were governed only by env vars + settings, not by
the preset.

These tests pin the wiring so a regression can't sneak back in.

For EACH preset field, we assert:
  1. The resolver function exists and returns the right value
     for explicit setting / unset (falls back to preset default).
  2. The consuming subsystem actually checks the resolver — verified
     by reading the source for the resolver-call site (rather than
     spinning up a full daemon for each test).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from one_link import sovereignty as sov


SRC_ROOT = Path(__file__).resolve().parents[1] / "src" / "one_link"


# ── all resolvers exist + match preset defaults ──────────────────


def test_resolver_exists_for_every_preset_field():
    for name in (
        "resolve_update_check_enabled",
        "resolve_stun_servers",
        "resolve_ui_session_persistence_enabled",
        "resolve_ui_session_labels_enabled",
        "resolve_mdns_discovery_enabled",
        "resolve_rendezvous_enabled",
        "resolve_turn_relay_enabled",
        "resolve_inherit_rendezvous_from_mdns_enabled",
    ):
        assert hasattr(sov, name), f"missing resolver: {name}"


@pytest.mark.parametrize("preset_name,expected", [
    ("just_works", True),
    ("quiet", True),
    ("off_grid", False),
])
def test_mdns_resolver_defaults_by_preset(preset_name, expected):
    assert sov.resolve_mdns_discovery_enabled(
        state_setting=None, preset_name=preset_name,
    ) is expected


@pytest.mark.parametrize("preset_name,expected", [
    ("just_works", False),
    ("quiet", False),
    ("off_grid", False),
])
def test_rendezvous_resolver_defaults_by_preset(preset_name, expected):
    """All current presets default rendezvous OFF — meaningful gate
    when the user has manually set rendezvous URLs (state.db) but
    then flipped to a stricter preset; the daemon must refuse to
    contact those URLs."""
    assert sov.resolve_rendezvous_enabled(
        state_setting=None, preset_name=preset_name,
    ) is expected


@pytest.mark.parametrize("preset_name,expected", [
    ("just_works", True),
    ("quiet", False),
    ("off_grid", False),
])
def test_turn_resolver_defaults_by_preset(preset_name, expected):
    """just_works keeps TURN ON (call rescue across hostile NATs);
    quiet + off_grid both OFF (no third-party relay traffic)."""
    assert sov.resolve_turn_relay_enabled(
        state_setting=None, preset_name=preset_name,
    ) is expected


@pytest.mark.parametrize("preset_name,expected", [
    ("just_works", True),
    ("quiet", False),
    ("off_grid", False),
])
def test_inherit_mdns_rendezvous_resolver_defaults(preset_name, expected):
    assert sov.resolve_inherit_rendezvous_from_mdns_enabled(
        state_setting=None, preset_name=preset_name,
    ) is expected


@pytest.mark.parametrize("name", ["just_works", "quiet", "off_grid"])
def test_explicit_setting_overrides_preset_for_all_new_resolvers(name):
    """For each new resolver: explicit 'true' wins over a preset
    that defaults False, and explicit 'false' wins over a preset
    that defaults True."""
    for resolver in (
        sov.resolve_mdns_discovery_enabled,
        sov.resolve_rendezvous_enabled,
        sov.resolve_turn_relay_enabled,
        sov.resolve_inherit_rendezvous_from_mdns_enabled,
    ):
        assert resolver(state_setting="true", preset_name=name) is True
        assert resolver(state_setting="false", preset_name=name) is False


# ── consumer wiring (source-level proof) ─────────────────────────


def _src(name: str) -> str:
    return (SRC_ROOT / name).read_text(encoding="utf-8")


def test_discovery_startup_calls_mdns_resolver():
    """daemon.py must call resolve_mdns_discovery_enabled before
    self.discovery.start() so off_grid actually means off_grid."""
    s = _src("daemon.py")
    assert "resolve_mdns_discovery_enabled" in s, (
        "daemon.py doesn't call the mdns resolver — Discovery.start "
        "would run unconditionally, breaking off_grid's no-broadcast "
        "promise"
    )
    # The resolver call must come BEFORE the .start() call.
    resolver_idx = s.find("resolve_mdns_discovery_enabled")
    start_idx = s.find("self.discovery.start()")
    assert 0 < resolver_idx < start_idx, (
        "mdns resolver must be checked BEFORE Discovery.start()"
    )


def test_rendezvous_startup_calls_resolver():
    s = _src("daemon.py")
    assert "resolve_rendezvous_enabled" in s, (
        "daemon.py doesn't call the rendezvous resolver — _start_"
        "rendezvous would honor URLs even in off_grid mode"
    )


def test_turn_config_calls_resolver():
    s = _src("server.py")
    assert "resolve_turn_relay_enabled" in s, (
        "server.py _resolved_turn_config doesn't call the TURN "
        "resolver — TURN relays would be loaded regardless of preset"
    )


def test_inherit_rendezvous_from_mdns_calls_resolver():
    s = _src("daemon.py")
    assert "resolve_inherit_rendezvous_from_mdns_enabled" in s, (
        "daemon.py _maybe_inherit_rendezvous_from_mdns doesn't call "
        "the resolver — quiet/off_grid would still adopt URLs from "
        "any LAN peer"
    )


# ── /api/sovereignty/status surfaces every new feature ──────────


def test_status_endpoint_surfaces_all_new_features():
    """Privacy panel reads /api/sovereignty/status to render the
    'What's turned on right now' rows. Every new preset field must
    appear in the features dict so the UI shows it."""
    s = _src("server.py")
    # Look at the api_sovereignty_status function specifically.
    idx = s.find("async def api_sovereignty_status(")
    assert idx > 0
    body = s[idx:idx + 12000]
    for feat_key in (
        '"mdns_discovery"',
        '"rendezvous"',
        '"turn_relay_preset"',
        '"inherit_rendezvous_from_mdns"',
        '"ui_session_persistence"',
        '"ui_session_labels"',
        '"update_check"',
        '"stun_servers"',
    ):
        assert feat_key in body, (
            f"api_sovereignty_status doesn't surface {feat_key} — "
            f"users can't see this in the Privacy panel"
        )


def test_preset_list_surfaces_all_new_fields():
    """The /api/sovereignty/preset endpoint returns the full preset
    bundle; new fields must be in it so UI cards can describe what
    each mode does for each subsystem."""
    s = _src("server.py")
    idx = s.find("async def api_sovereignty_preset_list(")
    assert idx > 0
    body = s[idx:idx + 5000]
    for field in (
        '"turn_relay_enabled"',
        '"inherit_rendezvous_from_mdns_enabled"',
        '"ui_session_persistence_enabled"',
        '"ui_session_labels_enabled"',
        '"mdns_discovery_enabled"',
        '"rendezvous_enabled"',
        '"update_check_enabled"',
        '"stun_servers"',
    ):
        assert field in body, (
            f"preset list doesn't surface {field}"
        )


# ── Privacy panel renders rows for the new features ─────────────


def test_privacy_panel_renders_turn_row():
    html = (
        SRC_ROOT / "web" / "index.html"
    ).read_text(encoding="utf-8")
    assert "turn_relay_preset" in html
    assert "Use TURN relay" in html


def test_privacy_panel_renders_inherit_rendezvous_row():
    html = (
        SRC_ROOT / "web" / "index.html"
    ).read_text(encoding="utf-8")
    assert "inherit_rendezvous_from_mdns" in html
    assert "Adopt rendezvous URLs" in html

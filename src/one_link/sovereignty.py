"""Sovereignty presets — three named tiers + the resolver layer.

May 15 2026.

One Link's promise is "no corps, no calls home, for the people." The
strict no-defaults posture (no STUN, no update-check, etc.) is
technically correct but makes cross-network pairing silently fail
for normal users. The 3-tier model below gives users a usable
default that's still corp-free, plus tighter modes for those who
want them.

Presets:

  - just_works: the default for fresh installs. Update-check ON.
    STUN ON via INDEPENDENT community-run servers (Nextcloud,
    Sipgate — never Google/Cloudflare/Twilio). LAN discovery ON.
    No corp accounts, no analytics, no cloud. Cross-network
    pairing works out of the box.

  - quiet: zero outbound to anything non-LAN. Update-check OFF.
    STUN OFF. LAN discovery ON. For users who'd rather pair
    manually or run their own STUN.

  - off_grid: the activist / high-threat profile. Adds: mDNS OFF
    (no broadcast peer discovery), manual pair only via paste-
    connection-string. Pure paranoia mode.

Each preset is defined as a dict of feature flags that the
respective subsystems read at runtime. Individual settings can
override the preset for power users — e.g. you can be on
just_works but blank out the STUN list, and the runtime honors
that override.

Read order:
  1. Explicit setting (state.settings.<key>) — always wins
  2. Env var override (where one is defined) — second priority
  3. Preset default — fallback

The audit endpoint surfaces which preset is active + which features
are overridden, so the user always knows what's happening.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


# ── Independent community STUN servers ─────────────────────────────
#
# We deliberately exclude the Big-3 (Google/Cloudflare/Twilio). The
# servers below are operated by community / privacy-focused orgs:
#
#   - Nextcloud  : private-cloud open-source project. Their STUN is
#                  a free community service; no logging policy posted
#                  publicly but the org's stated values align.
#   - Sipgate    : German VoIP telco. GDPR-strict, EU-jurisdiction.
#                  Their STUN is part of their public infrastructure
#                  for SIP clients.
#   - Antisip    : independent SIP operator.
#
# Operators who want to swap these for their own STUN can override
# via env var ONE_LINK_STUN_SERVERS or the ``stun_servers`` setting.
COMMUNITY_STUN_SERVERS = (
    "stun:stun.nextcloud.com:443",
    "stun:stun.sipgate.net:3478",
    "stun:stun.antisip.com:3478",
)


@dataclass(frozen=True)
class SovereigntyPreset:
    """Frozen feature-flag bundle for one preset tier."""

    name: str
    label: str
    description: str
    # Subsystems read these.
    update_check_enabled: bool
    stun_servers: tuple[str, ...]
    mdns_discovery_enabled: bool
    rendezvous_enabled: bool
    # v0.21.x persistent UI sessions (local-only, never sent over
    # the internet). Each preset picks a sensible default; user can
    # still override per-feature in the Privacy panel.
    #   just_works → both ON  (best UX)
    #   quiet      → persist ON, labels OFF (cookie survives but
    #                no browser fingerprint stored)
    #   off_grid   → both OFF (no cookies, no session table at all)
    ui_session_persistence_enabled: bool
    ui_session_labels_enabled: bool
    # v0.21.x sovereignty audit gaps. Pre-2026-05-27 these were
    # either silently always-on or governed only by env vars,
    # which meant off_grid mode silently broadcast over mDNS,
    # used TURN relays, and inherited rendezvous URLs from any
    # LAN peer. Each preset now gates them honestly.
    #
    # turn_relay_enabled — when False, the daemon refuses to load
    #   any TURN servers (state setting + env var both ignored).
    #   off_grid+quiet OFF; just_works ON (cross-NAT call rescue).
    # inherit_rendezvous_from_mdns_enabled — when False, the daemon
    #   ignores rendezvous URLs harvested from ambient LAN peers
    #   even if the inherit setting is on. off_grid OFF; everywhere
    #   else ON (this is how phones bootstrap onto your mesh).
    turn_relay_enabled: bool
    inherit_rendezvous_from_mdns_enabled: bool
    # UI hint — the chooser surfaces this as a one-line "what flows
    # outbound" summary so the user understands the trade.
    outbound_summary: str


JUST_WORKS = SovereigntyPreset(
    name="just_works",
    label="Just Works",
    description=(
        "Best for most people. Connecting your phone, laptop, and "
        "other computers works out of the box, even across different "
        "networks. You'll see a small note when a new version of One "
        "Link is available. No accounts, no profile, no tracking. "
        "Uses a tiny bit of public internet (small community-run "
        "servers, not Google or Microsoft) to help two devices find "
        "each other when they're on different networks."
    ),
    update_check_enabled=True,
    stun_servers=COMMUNITY_STUN_SERVERS,
    mdns_discovery_enabled=True,
    rendezvous_enabled=True,
    ui_session_persistence_enabled=True,
    ui_session_labels_enabled=True,
    turn_relay_enabled=True,
    inherit_rendezvous_from_mdns_enabled=True,
    outbound_summary=(
        "Uses small community servers (Nextcloud, Sipgate) only to "
        "help devices find each other. Checks for updates once every "
        "6 hours. Local Wi-Fi sharing on."
    ),
)

QUIET = SovereigntyPreset(
    name="quiet",
    label="Quiet",
    description=(
        "Only talks to other devices on your local Wi-Fi. Connecting "
        "across different networks (for example, your phone at a "
        "coffee shop to your laptop at home) will not work unless you "
        "set it up yourself. Update notifications are off. Browser "
        "labels in the sessions list are stripped (you'll see uuids "
        "only). Pick this for the strictest privacy without going "
        "completely offline."
    ),
    update_check_enabled=False,
    stun_servers=(),
    mdns_discovery_enabled=True,
    rendezvous_enabled=True,
    ui_session_persistence_enabled=True,
    ui_session_labels_enabled=False,
    turn_relay_enabled=False,
    inherit_rendezvous_from_mdns_enabled=False,
    outbound_summary=(
        "Local Wi-Fi only. No other outside connections."
    ),
)

OFF_GRID = SovereigntyPreset(
    name="off_grid",
    label="Off-grid",
    description=(
        "Your device makes no announcements and no outside "
        "connections at all. Pairing is manual only (you copy a code "
        "from one device to the other, in person). No persistent "
        "sign-in cookies — every daemon restart sends you back to "
        "opening from the tray. For people who need maximum privacy."
    ),
    update_check_enabled=False,
    stun_servers=(),
    mdns_discovery_enabled=False,
    rendezvous_enabled=False,
    ui_session_persistence_enabled=False,
    ui_session_labels_enabled=False,
    turn_relay_enabled=False,
    inherit_rendezvous_from_mdns_enabled=False,
    outbound_summary="Nothing. No connections, no broadcast.",
)


ALL_PRESETS: dict[str, SovereigntyPreset] = {
    "just_works": JUST_WORKS,
    "quiet": QUIET,
    "off_grid": OFF_GRID,
}

# The default for a fresh install. Picked so that "install and use"
# matches normal-person expectations. Strict modes are an opt-in.
DEFAULT_PRESET_NAME = "just_works"


def get_preset(name: Optional[str]) -> SovereigntyPreset:
    """Resolve a preset name to its definition. Unknown names fall
    back to the default — the only thing that matters is that the
    daemon NEVER crashes on a malformed setting."""
    if not name:
        return ALL_PRESETS[DEFAULT_PRESET_NAME]
    return ALL_PRESETS.get(name.strip().lower(), ALL_PRESETS[DEFAULT_PRESET_NAME])


def resolve_update_check_enabled(
    *,
    state_setting: Optional[str],
    env_var: Optional[str],
    preset_name: Optional[str],
) -> bool:
    """Read order for the update-check flag.

    1. ``state_setting`` (explicit user setting) wins if not None / not empty.
    2. ``env_var`` (operator override) wins if set.
    3. Preset default.
    """
    # 1. Explicit setting wins. Strings "0"/"false"/"no"/"off" are
    #    explicit OFF; "1"/"true"/"yes"/"on" are explicit ON.
    s = (state_setting or "").strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off"):
        return False
    # 2. Env var.
    e = (env_var or "").strip().lower()
    if e in ("1", "true", "yes", "on"):
        return True
    if e in ("0", "false", "no", "off"):
        return False
    # 3. Preset default.
    return get_preset(preset_name).update_check_enabled


def resolve_stun_servers(
    *,
    state_setting: Optional[str],
    env_var: Optional[str],
    preset_name: Optional[str],
) -> tuple[str, ...]:
    """Read order for the STUN server list.

    Setting + env var are comma-separated lists of stun:host:port
    URLs. Explicit empty string means "user wants NO stun even on a
    preset that defaults to community STUN" — honored.

    1. ``state_setting`` (if not None) wins — empty string = []
    2. ``env_var`` (if not None) wins next — empty string = []
    3. Preset default.
    """
    def _parse(raw: str) -> tuple[str, ...]:
        out = []
        seen: set[str] = set()
        for u in raw.split(","):
            u = u.strip()
            if u and u not in seen:
                out.append(u)
                seen.add(u)
        return tuple(out)

    # state_setting=None means "no override". Empty string means
    # "explicit opt-out of even the preset default."
    if state_setting is not None:
        return _parse(state_setting)
    if env_var is not None:
        return _parse(env_var)
    return get_preset(preset_name).stun_servers


def _resolve_bool_setting(
    *,
    state_setting: Optional[str],
    preset_value: bool,
) -> bool:
    """Shared explicit-setting-wins resolver for boolean flags. The
    user's explicit setting (true/false/etc.) overrides the preset;
    anything else falls back to the preset default."""
    s = (state_setting or "").strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off"):
        return False
    return preset_value


def resolve_ui_session_persistence_enabled(
    *,
    state_setting: Optional[str],
    preset_name: Optional[str],
) -> bool:
    """Should we mint persistent ol_session cookies? Explicit user
    setting (from the Privacy panel feature row) wins; otherwise
    falls back to the active preset's default. off_grid defaults
    OFF; just_works / quiet default ON."""
    return _resolve_bool_setting(
        state_setting=state_setting,
        preset_value=get_preset(preset_name).ui_session_persistence_enabled,
    )


def resolve_ui_session_labels_enabled(
    *,
    state_setting: Optional[str],
    preset_name: Optional[str],
) -> bool:
    """Should we store browser User-Agent labels on session rows?
    quiet + off_grid default OFF (no fingerprint); just_works
    defaults ON (readable Settings list)."""
    return _resolve_bool_setting(
        state_setting=state_setting,
        preset_value=get_preset(preset_name).ui_session_labels_enabled,
    )


def resolve_mdns_discovery_enabled(
    *,
    state_setting: Optional[str],
    preset_name: Optional[str],
) -> bool:
    """Should the daemon broadcast on mDNS (zeroconf) so other
    devices on the LAN can find it? off_grid OFF (the whole point);
    just_works + quiet ON. Explicit user setting wins."""
    return _resolve_bool_setting(
        state_setting=state_setting,
        preset_value=get_preset(preset_name).mdns_discovery_enabled,
    )


def resolve_rendezvous_enabled(
    *,
    state_setting: Optional[str],
    preset_name: Optional[str],
) -> bool:
    """Hard gate on rendezvous client startup. When False, even if
    rendezvous URLs are configured in state.db, the daemon will NOT
    contact them. All three current presets default OFF — rendezvous
    requires explicit user opt-in via a setting override anyway."""
    return _resolve_bool_setting(
        state_setting=state_setting,
        preset_value=get_preset(preset_name).rendezvous_enabled,
    )


def resolve_turn_relay_enabled(
    *,
    state_setting: Optional[str],
    preset_name: Optional[str],
) -> bool:
    """Should the daemon use TURN relays for cross-NAT call rescue?
    just_works ON (calls work even on hostile NATs); quiet OFF (no
    third-party relay traffic); off_grid OFF (no outbound at all).
    Explicit user setting wins."""
    return _resolve_bool_setting(
        state_setting=state_setting,
        preset_value=get_preset(preset_name).turn_relay_enabled,
    )


def resolve_inherit_rendezvous_from_mdns_enabled(
    *,
    state_setting: Optional[str],
    preset_name: Optional[str],
) -> bool:
    """Should the daemon adopt rendezvous URLs broadcast by other
    LAN peers via mDNS TXT records? This is how phones bootstrap
    onto an existing mesh, but it accepts URLs from any device on
    the same Wi-Fi — quiet + off_grid refuse to do this."""
    return _resolve_bool_setting(
        state_setting=state_setting,
        preset_value=get_preset(
            preset_name,
        ).inherit_rendezvous_from_mdns_enabled,
    )


def current_preset_name(state) -> str:
    """Reads the current preset name from state. Returns the
    default if unset."""
    if state is None:
        return DEFAULT_PRESET_NAME
    try:
        v = (state.get_setting("sovereignty_preset") or "").strip().lower()
    except Exception:
        return DEFAULT_PRESET_NAME
    if v not in ALL_PRESETS:
        return DEFAULT_PRESET_NAME
    return v

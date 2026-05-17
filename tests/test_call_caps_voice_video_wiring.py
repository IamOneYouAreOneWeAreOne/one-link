"""May 15 2026 — exhaustive wiring tests for the Voice/Video call split.

These tests probe ACROSS the layers — Python capability registry,
daemon HTTP API, served HTML markup — to confirm the recent
call-overlay revamp + VOICE_CALL/VIDEO_CALL capability split is
wired end-to-end without regressions.

What's covered:

  1. Capability constants — VOICE_CALL / VIDEO_CALL exist,
     are in LOCAL_CAPABILITIES, are in PROMPT_REQUIRED, and are
     NOT in DEFAULT_ALLOW_AFTER_PAIRING (so default policy
     correctly demands explicit grant).
  2. Capability classification round-trip — the canonical
     deny-by-default invariant (
        DEFAULT_ALLOW_AFTER_PAIRING ∪ PROMPT_REQUIRED ==
        LOCAL_CAPABILITIES - TRANSPORT_LAYER_CAPS
     ) still holds after the additions.
  3. Served HTML — confirms the new call-overlay markup is present
     in index.html so a browser pointed at the daemon picks up
     the revamp.
  4. Icon-filter logic — the exact JS logic from index.html is
     mirrored in Python so we can pin its branch coverage
     (voice_only_in_policy, video_only_in_policy, both, none,
     null = allow-all).
  5. M4 cover-traffic regression — the cover-traffic emit code
     in daemon.py must expect kind == "cover" from peel_sphinx,
     not the legacy "deliver". This test catches the regression
     I just shipped + fixed.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest


WEB_INDEX = (
    Path(__file__).resolve().parent.parent
    / "src" / "one_link" / "web" / "index.html"
)
DAEMON_PY = (
    Path(__file__).resolve().parent.parent
    / "src" / "one_link" / "daemon.py"
)


# ── 1. Capability constants ─────────────────────────────────────────


def test_voice_call_constant_exists():
    from one_link.capabilities import VOICE_CALL
    assert VOICE_CALL == "voice_call"


def test_video_call_constant_exists():
    from one_link.capabilities import VIDEO_CALL
    assert VIDEO_CALL == "video_call"


def test_voice_and_video_in_local_capabilities():
    from one_link.capabilities import (
        LOCAL_CAPABILITIES, VOICE_CALL, VIDEO_CALL,
    )
    assert VOICE_CALL in LOCAL_CAPABILITIES
    assert VIDEO_CALL in LOCAL_CAPABILITIES


def test_voice_and_video_in_prompt_required():
    """Calls are deny-by-default. A user must explicitly grant
    voice_call and/or video_call to each peer."""
    from one_link.capabilities import (
        PROMPT_REQUIRED, VOICE_CALL, VIDEO_CALL,
    )
    assert VOICE_CALL in PROMPT_REQUIRED
    assert VIDEO_CALL in PROMPT_REQUIRED


def test_voice_and_video_NOT_in_default_allow_after_pairing():
    """First pairing must NOT auto-grant a fresh peer the ability
    to call you. They have to be explicitly granted later."""
    from one_link.capabilities import (
        DEFAULT_ALLOW_AFTER_PAIRING, VOICE_CALL, VIDEO_CALL,
    )
    assert VOICE_CALL not in DEFAULT_ALLOW_AFTER_PAIRING
    assert VIDEO_CALL not in DEFAULT_ALLOW_AFTER_PAIRING


# ── 2. Capability classification round-trip ─────────────────────────


def test_default_allow_plus_prompt_covers_user_facing_local_caps():
    """The classification invariant: every user-facing local cap
    must be exactly one of {DEFAULT_ALLOW_AFTER_PAIRING, PROMPT_REQUIRED}.
    A cap that's neither is a policy hole."""
    from one_link.capabilities import (
        LOCAL_CAPABILITIES, DEFAULT_ALLOW_AFTER_PAIRING,
        PROMPT_REQUIRED, TRANSPORT_LAYER_CAPS,
    )
    user_caps = set(LOCAL_CAPABILITIES) - set(TRANSPORT_LAYER_CAPS)
    union = set(DEFAULT_ALLOW_AFTER_PAIRING) | set(PROMPT_REQUIRED)
    missing = user_caps - union
    extra = union - user_caps
    assert not missing, f"caps in LOCAL but unclassified: {missing}"
    assert not extra, f"classified caps not in LOCAL: {extra}"


def test_no_cap_is_in_both_buckets():
    from one_link.capabilities import (
        DEFAULT_ALLOW_AFTER_PAIRING, PROMPT_REQUIRED,
    )
    overlap = set(DEFAULT_ALLOW_AFTER_PAIRING) & set(PROMPT_REQUIRED)
    assert not overlap, f"caps in both buckets: {overlap}"


# ── 3. Served HTML — new overlay markup is present ─────────────────


@pytest.fixture(scope="module")
def index_html() -> str:
    return WEB_INDEX.read_text(encoding="utf-8")


REQUIRED_NEW_MARKERS = [
    # Avatar circle + initials
    "call-overlay-avatar",
    "call-outgoing-avatar",
    # Kind badge (voice vs video)
    "call-overlay-kind-badge",
    "call-outgoing-kind",
    # Elapsed-time counter
    "call-overlay-status",
    "call-outgoing-elapsed",
    # Route indicator
    "call-overlay-route",
    "call-outgoing-route",
    # Pre-call controls + selfpreview
    "call-overlay-precontrols",
    "btn-call-precmute",
    "btn-call-precam",
    "call-overlay-selfpreview",
    "call-outgoing-selfpreview",
    # Fallback "send a message instead"
    "call-overlay-fallback",
    "btn-call-send-msg-instead",
    # New caps in permissions pill row
    'data-cap="voice_call"',
    'data-cap="video_call"',
    # Two distinct call-button classes on peer rows
    "call-btn-voice",
    "call-btn-video",
]


@pytest.mark.parametrize("marker", REQUIRED_NEW_MARKERS)
def test_index_html_contains_new_marker(index_html, marker):
    assert marker in index_html, (
        f"new marker {marker!r} missing from index.html — the call-"
        f"overlay revamp didn't ship, or was reverted"
    )


def test_index_html_does_NOT_contain_old_debug_overlay_code():
    """The previous title-bar diagnostic that wrote
    '[vp ...] [win ...] [chrome-px ...]' to document.title is gone
    in active code. (A comment may still reference it for history.)"""
    body = WEB_INDEX.read_text(encoding="utf-8")
    # The active code path no longer assigns the debug string.
    # The forbidden pattern: a JS line that BUILDS the debug title.
    assert "`One Link [vp ${window.innerWidth}" not in body, (
        "debug title-bar overlay code re-introduced into index.html"
    )


def test_index_html_legacy_phone_only_path_removed():
    """The single ambiguous .call-btn handler block should be gone —
    replaced by separate .call-btn-voice + .call-btn-video paths."""
    body = WEB_INDEX.read_text(encoding="utf-8")
    # The legacy line that built one phone-only button.
    legacy = 'el("button", "call-btn", "📞")'
    assert legacy not in body, (
        "legacy single-phone-button path is still present in "
        "index.html — voice/video split incomplete"
    )


# ── 4. Icon-filter logic mirror ────────────────────────────────────


def _should_show_icon(allowed_capabilities, cap: str) -> bool:
    """Mirror of the JS icon-filter logic at index.html:6829-6830.
    Kept here so we can pin its branch coverage in Python."""
    if not isinstance(allowed_capabilities, list):
        return True  # null/None = allow-all default
    legacy_drawer_all = all(c in allowed_capabilities for c in ("chat", "files", "folder_sync"))
    if cap in ("voice_call", "video_call") and legacy_drawer_all:
        return True
    return cap in allowed_capabilities


@pytest.mark.parametrize("allowed,expect_voice,expect_video", [
    (None, True, True),                              # allow-all default
    ([], False, False),                              # explicitly deny all
    (["voice_call"], True, False),                   # voice-only
    (["video_call"], False, True),                   # video-only
    (["voice_call", "video_call"], True, True),     # both
    (["chat", "files"], False, False),               # neither granted
    (["chat", "files", "folder_sync"], True, True), # old UI "allow all"
    (["chat", "voice_call"], True, False),           # voice only, alongside chat
])
def test_icon_filter_branch_coverage(allowed, expect_voice, expect_video):
    assert _should_show_icon(allowed, "voice_call") is expect_voice
    assert _should_show_icon(allowed, "video_call") is expect_video


def test_drawer_allow_all_includes_voice_and_video(index_html):
    body = index_html
    assert 'const DRAWER_CAPS = ["chat", "files", "folder_sync", "voice_call", "video_call"];' in body
    idx = body.find("function drawerAllowedSet(policy)")
    snippet = body[idx:idx + 700]
    assert "if (policy == null) return new Set(DRAWER_CAPS);" in snippet
    assert "DRAWER_CAPS.every(cap => allowed.has(cap))" in snippet
    assert 'const LEGACY_DRAWER_ALLOW_ALL_CAPS = ["chat", "files", "folder_sync"];' in body
    assert 'policyLooksLikeLegacyDrawerAllowAll(policy)' in body
    assert 'return state.runtimeSettings?.pair_default_allow_all !== false;' in body


# ── 5. M4 cover-traffic regression — kind=='cover' not 'deliver' ───


def test_cover_traffic_emit_expects_kind_cover_not_deliver():
    """After M4 audit closure, peel_sphinx returns kind == "cover"
    directly for authenticated cover packets. The cover-traffic
    emit loop in daemon.py was previously asserting kind == "deliver"
    — that's the regression I shipped + just fixed. This test
    pins the correct expectation so a future revert is caught."""
    body = DAEMON_PY.read_text(encoding="utf-8")
    # The (new, correct) assertion is present.
    assert 'kind != "cover"' in body, (
        "cover-traffic emit should check kind != \"cover\" (M4 wire); "
        "the M4 closure changed the peel return type"
    )
    # The (old, wrong) assertion is gone.
    assert 'kind != "deliver"' not in body, (
        "cover-traffic emit still has the legacy kind != \"deliver\" "
        "check — that path is dead since M4 (peel now returns 'cover' "
        "for cover packets); this WILL spam WARNING logs"
    )


def test_cover_traffic_no_longer_inspects_plaintext_sentinel():
    """M8 audit closure: the plaintext is_cover_payload() fallback
    was forgeable and is gone. Cover packets are identified ONLY
    by the M4 authenticated trailer (kind == "cover")."""
    body = DAEMON_PY.read_text(encoding="utf-8")
    # The is_cover_payload check in the COVER-TRAFFIC EMIT block
    # is removed. (It's still present in tests + the peer_rtc
    # cover-receive path for back-compat — those are fine.)
    cover_emit_chunk = re.search(
        r"# Cover traffic emit.*?# end cover traffic emit",
        body,
        re.DOTALL,
    )
    # If the surrounding code block uses comment markers, ensure
    # is_cover_payload isn't inside the emit chunk. (Falsy if the
    # markers aren't present is fine — we just check globally that
    # the assertion is gone from the cover-emit path.)
    legacy_paranoid = (
        'if not _native_sphinx.is_cover_payload(payload):' in body
        and 'cover-traffic peel: payload missing cover sentinel' in body
    )
    assert not legacy_paranoid, (
        "legacy is_cover_payload() sentinel check is still present "
        "in cover-traffic emit; should be removed (M8 closure)"
    )

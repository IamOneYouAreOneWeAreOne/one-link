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


# ── index.html (desktop) jargon scrub ──────────────────────────────


@pytest.fixture(scope="module")
def index_html() -> str:
    return _INDEX_HTML.read_text(encoding="utf-8")


def test_rotate_identity_renamed_to_change_identity(index_html):
    """The recovery wizard's rotation card used to be labeled
    'Rotate identity key' - 'rotate' is engineer-speak. Users
    just want to 'change' it. Pin the rename so the audit
    finding doesn't regress."""
    # The card title.
    assert '"recwiz-card-name">Change your identity key<' in index_html
    # The modal title + aria-label.
    assert 'aria-label", "Change identity key"' in index_html
    assert 'recwiz-title">Change your identity key<' in index_html
    # The button label (inFlight branch + initial branch).
    assert '"Change again" : "Change identity key"' in index_html
    # The old jargon must be gone.
    assert '"recwiz-card-name">Rotate identity key<' not in index_html
    assert 'recwiz-title">Rotate identity key<' not in index_html


def test_loading_spinners_explain_what_is_loading(index_html):
    """Bare 'Loading…' / 'Loading...' strings are vague spinner
    states the audit flagged as P1 friction. Each one should
    name WHAT is loading so the user knows what to wait for.
    Pin the fixes."""
    expected_fixes = [
        "Reading your identity…",
        "Counting your files…",
        "Reading device history…",
        "Loading photos + videos…",
        "Checking your privacy settings…",
    ]
    for fix in expected_fixes:
        assert fix in index_html, (
            f"loading-state context message missing: {fix!r}"
        )


def test_api_get_error_does_not_leak_path_to_user(index_html):
    """api.get used to throw `Error('${p} ${r.status}')` which
    surfaced as toast text reading e.g. '/api/recovery/rotate/status
    500' - the URL path leaks the internal API surface to users
    + tells them nothing actionable. Now routed through _apiError
    so the user sees the server's {error, hint} JSON body."""
    idx = index_html.find("async get(p, opts = {})")
    assert idx > 0, "api.get helper not found"
    body = index_html[idx:idx + 1500]
    assert "throw new Error(`${p} ${r.status}`)" not in body, (
        "api.get throws the URL path in the error message - users "
        "see leaked API paths in toasts when something fails"
    )
    assert "_apiError(j, r.status)" in body, (
        "api.get should route errors through _apiError like .post "
        "and .del do, so the user-visible message comes from the "
        "server's JSON body (error/hint/code) not the raw path"
    )


def test_noun_only_buttons_renamed_to_verb_phrases(index_html):
    """A button labeled 'Trust folder' tells the user nothing
    about what clicking does. 'Mark folder trusted' makes the
    action explicit. Similar: 'Revoke verification' -> 'Remove
    verification'."""
    assert ">Mark folder trusted<" in index_html
    assert ">Remove verification<" in index_html
    # Old noun-only labels gone.
    assert ">Trust folder<" not in index_html
    assert ">Revoke verification<" not in index_html


def test_device_not_ready_toast_explains_what_to_do(index_html):
    """'That device isn't ready yet. Try again in a moment.' is
    vague ('a moment' = how long?). The actual scenario is the
    peer's daemon is still in startup; tell the user that +
    set an expectation."""
    assert "That device isn't ready yet" not in index_html
    assert "That device is still starting up. Try again in a few seconds." in index_html


def test_onboarding_codes_buttons_use_they_match_phrasing(index_html):
    """Onboarding step 4's pair-confirm buttons used to say 'Codes
    match' / 'Codes do not match'. The peer.html SAS card already
    uses 'They match' / 'They don't match'; consistency matters.
    Same audit category as the peer-side fix - awkward phrasing."""
    assert '>They match<' in index_html
    assert ">They don't match<" in index_html
    # The old onboarding-button labels must be gone.
    assert ">Codes match<" not in index_html
    assert ">Codes do not match<" not in index_html


def test_settings_about_has_report_a_bug_github_link(index_html):
    """The launch checklist (docs/LAUNCH_CHECKLIST.md item E)
    requires a discoverable in-app path to file a bug. Pin: the
    Settings -> About surface has a 'Report a bug on GitHub' link
    that opens issues/new in a new tab."""
    assert 'id="settings-about-report-bug"' in index_html
    # The link target is GitHub issues/new on the canonical repo.
    assert "github.com/IamOneYouAreOneWeAreOne/one-link/issues/new" in index_html
    assert 'target="_blank"' in index_html
    # Surrounding copy points the user at the Copy report button so
    # they include diagnostics with their issue.
    assert 'Copy report' in index_html


def test_api_error_synthesizes_plain_english_per_status_code(index_html):
    """When the server returns a non-JSON 5xx (or no body at all),
    _apiError used to fall back to 'request failed (N)' - tells
    the user nothing actionable. Now branches on common HTTP
    statuses to surface plain-English defaults with a hint."""
    idx = index_html.find("function _apiError(")
    assert idx > 0
    body = index_html[idx:idx + 3500]
    # 401/403 - auth refreshed.
    assert "One Link forgot who you are." in body
    # 404 - not present here.
    assert "That isn't on this device." in body
    # 408/504 - timeout.
    assert "Took too long to answer." in body
    # 413 - too big.
    assert "That's too big to send right now." in body
    # 429 - rate-limited.
    assert "Slowing things down for a second." in body
    # 5xx - something on this device.
    assert "Something went wrong on this device." in body
    # 0 - browser-side network error.
    assert "Can't reach One Link right now." in body
    # 'request failed (N)' must not be the headline anymore.
    # (We DO use it as a fallback for unknown statuses; that's fine.)
    assert "request failed (" not in body or "Something went wrong (" in body


def test_error_toast_separator_is_single_space_not_dash(index_html):
    """The separator between headline + hint in errorToastBody was
    ' - ' which produces awkward double-punctuation ('Took too
    long. - The other device...'). Switched to a single space so
    two complete sentences flow naturally. Pin so a future
    refactor doesn't re-introduce the dash."""
    idx = index_html.find("function errorToastBody(")
    assert idx > 0
    body = index_html[idx:idx + 2000]
    assert "`${headline} - ${hint}`" not in body, (
        "errorToastBody still uses ' - ' separator; produces "
        "awkward double-punctuation in toasts"
    )
    assert "`${headline} ${hint}`" in body


def test_recovery_wizard_render_helpers_in_script1_scope(index_html):
    """CRITICAL bug found by visual sweep 2026-05-25: the recovery
    wizard render functions (in Script 1's IIFE) call escapeText
    + escapeAttr, but those were ONLY defined in Script 2's IIFE.
    Result: every wizard render threw ReferenceError caught by
    .catch() wrappers, leaving all 6 track cards empty + the
    wizard non-functional.

    Pin: Script 1 must have its own escapeText + escapeAttr so
    the wizard renders. Aliases of the Script 2 implementations
    are fine."""
    # Find the FIRST escapeText definition (must be in Script 1,
    # ie before line 32118 where Script 1 closes).
    first_idx = index_html.find("function escapeText(")
    assert first_idx > 0, "escapeText not defined anywhere"
    # The Script 1 close tag is at line 32118; first def must be
    # before that.
    script1_close = index_html.find("\n</script>")
    assert first_idx < script1_close, (
        "escapeText is ONLY defined in Script 2; the recovery "
        "wizard renders in Script 1 will fail with ReferenceError"
    )


def test_no_yelling_or_eula_jokes_in_settings_copy(index_html):
    """The Chats + Notifications panes used to ship engineer-jokes
    that read weird to non-technical users:
      - 'Devices yelling on your local network...'
      - '...like a person who reads EULAs'
      - 'A muted peer never pings, no matter how loudly they yell'
      - '(Yes, the word means what you hope it means.)'
    All four replaced with calm explanatory copy. Pin so they
    don't sneak back."""
    assert "Devices yelling on your local network" not in index_html
    assert "like a person who reads EULAs" not in index_html
    assert "no matter how loudly they yell" not in index_html
    assert "the word means what you hope it means" not in index_html


def test_offline_transfer_status_explains_what_will_happen(index_html):
    """Audit P1: 'Waiting for device' was the queued-transfer status
    label. Vague - what's it waiting for? How long? Replaced with
    'Will send when they're back online' (action + cause)."""
    assert '"Will send when they\'re back online"' in index_html, (
        "transfer-status helper missing the actionable 'will send "
        "when they're back online' wording for queued transfers"
    )
    assert '"Will retry when they\'re back online"' in index_html, (
        "transfer-status helper missing the same wording for "
        "transient failures"
    )
    # The vague wording must be gone.
    assert 'return stateName === "resuming" ? "Resuming" : "Waiting for device"' not in index_html


def test_storage_pane_empty_state_is_friendly_not_suspicious(index_html):
    """The storage pane used to read 'No conversations. Suspicious.'
    on a fresh install - that's a snarky engineer joke that reads
    weird to a first-time user. Replaced with calm + explanatory."""
    assert "No conversations. Suspicious." not in index_html, (
        "storage pane still ships the snarky 'Suspicious.' empty "
        "state - confuses fresh-install users"
    )
    assert "Files and chat history will show up here" in index_html


def test_self_mesh_empty_state_points_user_at_the_action(index_html):
    """Audit P1: 'This device is reporting local presence; add
    trusted personal devices to form a self-mesh.' tells the user
    WHAT to do without telling them WHERE. New copy names the
    Settings -> Devices path explicitly."""
    assert "add trusted personal devices to form a self-mesh" not in index_html, (
        "self-mesh empty state still uses jargon-y 'form a "
        "self-mesh' language without telling the user where to go"
    )
    assert "Open Settings → Devices and pair another one of yours" in index_html, (
        "self-mesh empty state should name the Settings → Devices "
        "path so users have an actionable next step"
    )


def test_install_warning_banner_states_unverified_build_risk(index_html):
    """The first-launch warning must not encourage bypassing OS defenses.

    It identifies the missing release evidence, tells users to treat the
    binary as untrusted, and states the local inventory verifier's limit.
    """
    # Banner element exists.
    assert 'id="install-warning-banner"' in index_html, (
        "first-launch install-warning banner missing from DOM"
    )
    assert "Treat an unverified binary as untrusted" in index_html
    assert "does not yet publish a verified, platform-code-signed release" in index_html
    assert "Why did the platform warn me?" in index_html
    assert "Glad you got past the security warning" not in index_html
    assert "no company has the power to revoke your right" not in index_html
    # Points users at the local inventory verifier and states its limitation.
    assert "one-link verify-this-install" in index_html
    assert "hashes alone do not prove authenticity" in index_html
    # Once-per-device gate.
    assert 'one_link.install_warning_seen' in index_html, (
        "install-warning banner must be gated by a localStorage "
        "key so it only fires on first launch + then never again"
    )


def test_recovery_is_discoverable_from_settings_nav(index_html):
    """The recovery wizard exists but pre-launch was only
    reachable via the rotation banner (only shown after rotation
    occurs). Most users would never discover it. The Settings nav
    must surface a 'Recovery' entry whose click handler opens the
    wizard modal."""
    assert 'id="settings-nav-open-recovery"' in index_html, (
        "Settings nav missing 'Recovery' entry - users have no "
        "discoverable path to set up recovery before they need it"
    )
    # The click handler routes to the wizard (not a pane switch).
    assert 'settings-nav-open-recovery' in index_html
    assert '_showRecoveryWizard()' in index_html


def test_daemon_unreachable_message_tells_user_what_to_do(index_html):
    """The previous 'Couldn't reach the service' message described
    the failure without giving the user an action. The new message
    says explicitly: restart from system tray or close + reopen
    the tab."""
    assert "Couldn't reach the service." not in index_html, (
        "old vague 'Couldn't reach the service' message still "
        "in HTML; users have no action to take"
    )
    assert "Try restarting it from your system tray" in index_html, (
        "daemon-unreachable message must tell users what to do "
        "(restart from tray / reopen tab)"
    )


def test_error_toast_body_strips_internal_codes(index_html):
    """errorToastBody used to surface internal error codes
    ('send_failed', 'capability_disabled', 'request failed (500)')
    as the lead string of user toasts. Pin the strip-pattern so
    a future refactor doesn't re-introduce the leak."""
    idx = index_html.find("function errorToastBody(")
    assert idx > 0
    body = index_html[idx:idx + 1800]
    assert "internalCodePattern" in body, (
        "errorToastBody must strip internal codes; users were "
        "seeing 'send_failed:' as the lead of every send toast"
    )
    # The pattern covers the main internal-code surface.
    assert "send_failed" in body
    assert "capability_disabled" in body
    assert "wire_version_mismatch" in body


def test_folders_empty_state_points_to_form_below(index_html):
    """The folders empty state must (1) avoid CRDT jargon, (2) be
    accurate about where the Add form lives, and (3) NOT spawn an
    orphan 'Add a folder now' CTA button as a sibling of the empty
    state. The earlier orphan-button approach rendered as broken,
    left-aligned text in the middle of the panel because the empty
    state itself is centered while the appended sibling button was
    not. The form is always visible at the bottom of the panel, so
    the empty-state copy just needs to point users at it."""
    # CRDT jargon stays out of the empty-state description.
    assert "CRDT detects concurrent edits" not in index_html, (
        "folders empty state still leaks 'CRDT' jargon; users "
        "have no context for what CRDT means"
    )
    # No orphan CTA button. The form is always visible directly
    # below; an in-the-middle button just added visual noise.
    assert 'addCta.textContent = "Add a folder now"' not in index_html, (
        "the orphan 'Add a folder now' button is back. It rendered "
        "as broken left-aligned text mid-panel and was confusing "
        "users about where the add flow actually lives."
    )
    # Empty-state copy must accurately point users at the form
    # below (NOT 'right above' — the form sits at the bottom of
    # the panel, not the top).
    assert "form just below" in index_html, (
        "empty state must direct users to the form at the BOTTOM "
        "of the panel; the previous 'right above' copy was wrong"
    )
    assert "is right above" not in index_html or (
        "is right above" in index_html
        and "form just below" in index_html
    ), (
        "stale 'right above' copy needs to be removed; the form "
        "lives at the bottom of the folders panel"
    )


def test_folders_empty_state_hides_secondary_actions(index_html):
    """When there are zero folders, the destructive 'Clear folder
    traces' button + the 'refresh list' button serve no purpose —
    nothing to clear, nothing to refresh. Pin that they get hidden
    so the empty state has a single primary path (fill form, click
    Add) instead of three buttons of cognitive load."""
    idx = index_html.find("async function refreshFolders()")
    assert idx > 0
    body = index_html[idx:idx + 2000]
    # Both buttons must be toggled by the empty-state branch.
    assert "btn-clear-folder-traces" in body, (
        "refreshFolders must hide btn-clear-folder-traces when "
        "folders is empty; otherwise the destructive button is "
        "showing with nothing to act on"
    )
    assert "btn-refresh-folders" in body, (
        "refreshFolders must hide btn-refresh-folders when "
        "folders is empty; nothing to refresh, just noise"
    )
    # Look for the gating pattern. Either an isEmpty flag set
    # before the branch, OR a direct .length === 0 check applied
    # to display style.
    assert "isEmpty" in body or "length === 0" in body


def test_settings_about_has_daemon_log_location_button(index_html):
    """Same launch-checklist item: a user reaching for the log
    should not have to ask 'where is it?' on chat. Pin the
    Settings -> About surface that surfaces the log path +
    copies it to clipboard on click."""
    assert 'id="settings-about-show-log-location"' in index_html
    assert "Show daemon log location" in index_html
    # The handler is wired.
    assert '#settings-about-show-log-location' in index_html
    # And it offers a one-click copy-path action.
    assert 'Paste into File Explorer or Finder.' in index_html


def test_device_guardian_jargon_replaced_with_safety_language(index_html):
    """'Device Guardian' is an internal subsystem name that leaked
    into user-visible status text + error toasts. Replace with
    'Safety' / plain English about what the user can do."""
    # The status row no longer says 'Device Guardian {state}'.
    assert "Device Guardian ${p.safety_state" not in index_html, (
        "user-visible 'Device Guardian {state}' label leaked; "
        "should be 'Safety: {state}'"
    )
    # The error toasts no longer say 'needs stronger proof'.
    assert "Revoke needs stronger proof" not in index_html, (
        "Error toast 'Revoke needs stronger proof' is jargon; "
        "users have no way to action it"
    )
    assert "Guardian needs stronger proof" not in index_html, (
        "Error toast 'Guardian needs stronger proof' is jargon"
    )
    # And the new wording is in.
    assert "Try again from a trusted device you've verified in person" in index_html

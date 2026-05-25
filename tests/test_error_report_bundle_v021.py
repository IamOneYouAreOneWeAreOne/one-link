"""v0.21.x sanitized error-report bundle.

The trust-gate story for production: a user hits a bug, opens
Debug → 'Copy error report', and gets a JSON snippet they can
paste into a GitHub issue without leaking their fingerprint,
home-directory username, or LAN IP. Source-text gated so the
sanitization regexes can't be silently removed.
"""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def index_html() -> str:
    return (
        Path(__file__).resolve().parents[1] / "src" / "one_link" / "web" / "index.html"
    ).read_text(encoding="utf-8")


# ── UI surface ─────────────────────────────────────────────────────


def test_copy_error_report_button_present_in_debug_pane(index_html):
    """The Debug pane must surface a one-click 'Copy error report'
    button. Without it users have no in-app path to share a bug
    with maintainers; they'd have to find the log file on disk."""
    assert 'id="btn-debug-copy-report"' in index_html
    assert "Copy error report" in index_html


def test_copy_report_handler_redacts_64_hex_fingerprints(index_html):
    """The sanitizer MUST collapse 64-hex BLAKE3 fingerprints to a
    short prefix (so peer identities aren't leaked) but keep
    enough that two reports from the same install correlate to a
    debugger."""
    idx = index_html.find("function _sanitizeReportText(")
    assert idx > 0, "_sanitizeReportText helper missing"
    body = index_html[idx:idx + 2500]
    # The regex pattern.
    assert "[0-9a-fA-F]{64}" in body, (
        "sanitizer missing the 64-hex fingerprint redaction; "
        "user reports would leak full peer fingerprints"
    )


def test_copy_report_handler_redacts_windows_user_paths(index_html):
    """Windows paths like 'C:\\Users\\Josh\\...' leak the system
    username. The sanitizer must strip the prefix + keep only
    the basename so the bug-relevant tail survives."""
    idx = index_html.find("function _sanitizeReportText(")
    body = index_html[idx:idx + 2500]
    assert "A-Za-z]:\\\\" in body or "[A-Za-z]:\\\\\\\\" in body, (
        "sanitizer missing the Windows-path redaction; user "
        "reports would leak the user's home-directory username"
    )


def test_copy_report_handler_redacts_lan_ip_addresses(index_html):
    """Full LAN IPv4 addresses identify the user's network. The
    sanitizer keeps the first two octets (useful for 'are you on
    cellular vs WiFi' debugging) + masks the host octets."""
    idx = index_html.find("function _sanitizeReportText(")
    body = index_html[idx:idx + 2500]
    assert "\\d{1,3}\\.\\d{1,3}" in body, (
        "sanitizer missing IPv4 redaction"
    )


def test_report_includes_install_identity_for_correlation(index_html):
    """The shared report must include the install's version +
    source_fingerprint so a maintainer can tell at a glance which
    build the bug is from. Without this, every bug looks the
    same + reproduction is guesswork."""
    idx = index_html.find('id="btn-debug-copy-report"')
    # Locate the handler body.
    handler_idx = index_html.find(
        '#btn-debug-copy-report")?.addEventListener',
    )
    assert handler_idx > 0, "copy-report handler not wired"
    body = index_html[handler_idx:handler_idx + 4000]
    assert "/api/me" in body, (
        "report should include version + source_fingerprint via /api/me"
    )
    assert "source_fingerprint" in body
    assert "app_version" in body


def test_report_caps_event_count_so_huge_logs_dont_blow_clipboard(index_html):
    """Cap the bundle to N recent events. A daemon that's been
    running for weeks could have 10k debug entries; pasting that
    into a GitHub issue would be useless. Pin the cap."""
    handler_idx = index_html.find(
        '#btn-debug-copy-report")?.addEventListener',
    )
    body = index_html[handler_idx:handler_idx + 4000]
    assert ".slice(-50)" in body or ".slice(-100)" in body or ".slice(-200)" in body, (
        "copy-report handler must cap the included events to a "
        "reasonable tail; otherwise users paste 10MB of logs into "
        "every bug report"
    )


def test_report_uses_versioned_kind_field_for_forward_compat(index_html):
    """Including a `kind: 'one_link_error_report_v1'` discriminator
    lets future versions of the report schema coexist with v1
    consumers + lets a maintainer immediately recognize the shape."""
    handler_idx = index_html.find(
        '#btn-debug-copy-report")?.addEventListener',
    )
    body = index_html[handler_idx:handler_idx + 4000]
    assert "one_link_error_report_v1" in body, (
        "report must carry a versioned kind discriminator so "
        "v2 schemas can be distinguished without guessing"
    )


def test_report_writes_to_clipboard_not_a_local_file(index_html):
    """Report uses navigator.clipboard.writeText - one click,
    instant paste. Writing to disk would force the user to find
    the file. Pin the contract."""
    handler_idx = index_html.find(
        '#btn-debug-copy-report")?.addEventListener',
    )
    body = index_html[handler_idx:handler_idx + 4000]
    assert "navigator.clipboard.writeText" in body, (
        "copy-report handler must use clipboard API; writing to "
        "disk would break the one-click-paste UX"
    )

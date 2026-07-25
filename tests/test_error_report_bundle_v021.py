"""v0.21.x aggregate-only error-report bundle.

The trust-gate story for production: a user hits a bug, opens
Debug → 'Copy error report', and gets a JSON snippet they can
paste into a GitHub issue without leaking freeform log content,
fingerprints, paths, addresses, hostnames, or tokens. The report
maps events to a closed category/severity schema instead of trying
to regex-redact an open-ended string space.
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


def test_copy_report_uses_closed_aggregate_schema_not_freeform_redaction(index_html):
    summary_idx = index_html.find("function _diagnosticEventSummary(")
    assert summary_idx > 0, "aggregate diagnostic helper missing"
    summary = index_html[summary_idx : summary_idx + 1800]
    assert "by_severity" in summary
    assert "by_category" in summary
    for category in ("call", "transfer", "trust", "storage", "update", "network", "other"):
        assert f"{category}: 0" in summary

    handler_idx = index_html.find('#btn-debug-copy-report")?.addEventListener')
    handler = index_html[handler_idx : handler_idx + 2200]
    assert "event_summary: eventSummary" in handler
    for forbidden in (
        "message: e.message",
        "suggestion: e.suggestion",
        "context: e.context",
        "source: e.source",
        "code: e.code",
        "navigator.userAgent",
        "navigator.language",
        "generated_ms",
        "ts_ms",
    ):
        assert forbidden not in handler
    assert "_sanitizeReportText" not in index_html
    assert "_sanitizeReportContext" not in index_html


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
    body = index_html[handler_idx : handler_idx + 4000]
    assert "/api/me" in body, "report should include version + source_fingerprint via /api/me"
    assert "source_fingerprint" in body
    assert "app_version" in body


def test_report_caps_event_count_so_huge_logs_dont_blow_clipboard(index_html):
    """Cap the bundle to N recent events. A daemon that's been
    running for weeks could have 10k debug entries; pasting that
    into a GitHub issue would be useless. Pin the cap."""
    helper_idx = index_html.find("function _diagnosticEventSummary(")
    body = index_html[helper_idx : helper_idx + 1800]
    assert ".slice(-50)" in body, (
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
    body = index_html[handler_idx : handler_idx + 4000]
    assert "one_link_error_report_v2" in body, (
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
    body = index_html[handler_idx : handler_idx + 4000]
    assert "navigator.clipboard.writeText" in body, (
        "copy-report handler must use clipboard API; writing to "
        "disk would break the one-click-paste UX"
    )

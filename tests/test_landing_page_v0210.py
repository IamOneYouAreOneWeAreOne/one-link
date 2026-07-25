"""Fail-closed contracts for the public landing page.

Until a production tag has published complete verification evidence, the site
must not turn a mutable GitHub release into an install CTA. Release workflow
capability and release existence are deliberately separate facts.
"""

from __future__ import annotations

from pathlib import Path
import re


LANDING = Path(__file__).resolve().parent.parent / "docs" / "site" / "index.html"


def _html() -> str:
    return LANDING.read_text(encoding="utf-8")


def test_landing_page_exists_and_is_html():
    html = _html()
    assert "<!doctype html>" in html.lower()
    assert "<title>One Link" in html


def test_primary_cta_fails_closed_to_local_source_instructions():
    html = _html()
    assert 'id="download-primary"' in html
    assert 'href="#source-install"' in html
    assert 'data-release-state="unavailable"' in html
    assert "Production download unavailable" in html


def test_landing_page_states_current_release_evidence_gap():
    normalized = " ".join(_html().lower().split())
    for required in (
        "no verified production download is currently published",
        "only release is the mutable <code>auto-latest</code> prerelease",
        "rolling binaries and checksum files were refreshed on 2026-07-22",
        "no sigstore bundles",
        "published sbom",
        "provenance assets",
        "not an approved install source",
        "has not yet produced a production tag",
    ):
        assert required in normalized


def test_landing_page_never_resolves_or_links_mutable_release_downloads():
    html = _html().lower()
    for forbidden in (
        "/releases/latest",
        "/latest/download/",
        "api.github.com/repos/",
        "os_assets",
        "setlatestversionpill",
        "all downloads + signatures",
    ):
        assert forbidden not in html
    assert "fetch(" not in html


def test_source_evaluation_requires_reviewed_commit_and_frozen_lock():
    html = _html()
    assert 'id="source-install"' in html
    assert "git checkout &lt;reviewed-commit-sha&gt;" in html
    assert "uv sync --frozen" in html
    assert "development path, not a production installation" in html


def test_future_verification_is_conditional_and_exact_tag_bound():
    normalized = " ".join(_html().lower().split())
    assert "future release verification contract" in normalized
    assert "after an immutable <code>v*</code> tag successfully publishes" in normalized
    assert "verifier is tooling, not evidence" in normalized
    assert "never substitute <code>latest</code>" in normalized
    assert "scripts/verify-release.sh ./&lt;artifact&gt; vx.y.z" in normalized


def test_landing_page_does_not_claim_reproducible_or_production_ready():
    html = _html().lower()
    assert "reproducible builds</span>" not in html
    assert "production ready" not in html
    assert "production-ready" not in html


def test_landing_page_does_not_call_non_github_hosts():
    """No analytics, fonts, trackers, or dynamic release lookup."""
    html = _html()
    hosts = set(re.findall(r"https?://([^/\"'\s>]+)", html))
    allowed = {
        "github.com",
        "raw.githubusercontent.com",
        "IamOneYouAreOneWeAreOne.github.io",
        "www.gnu.org",
    }
    suspicious = {host for host in hosts if host not in allowed}
    assert not suspicious, f"landing page contacts non-approved host(s): {sorted(suspicious)}"


def test_landing_page_advertises_bounded_product_terms():
    normalized = " ".join(_html().lower().split())
    assert "peer-to-peer" in normalized
    assert "no required user account" in normalized
    assert "optional rendezvous and relay services" in normalized
    assert "end-to-end encrypted" in normalized


def test_landing_page_links_to_source_and_security_disclosure():
    html = _html()
    assert "github.com/IamOneYouAreOneWeAreOne/one-link" in html
    assert "SECURITY.md" in html

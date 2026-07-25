"""Source contracts that keep release/security documentation evidence-bound."""

from __future__ import annotations

from pathlib import Path


REPO = Path(__file__).resolve().parent.parent


def _read(relative: str) -> str:
    return (REPO / relative).read_text(encoding="utf-8")


def _normalized(relative: str) -> str:
    return " ".join(_read(relative).lower().split())


def test_public_entry_points_disclose_no_verified_production_release():
    assert "no verified production release" in _normalized("README.md")
    assert "no verified production release" in _normalized("SECURITY.md")
    assert "no verified production release" in _normalized("docs/SECURITY.md")
    assert "no verified production release" in _normalized("docs/TESTING.md")
    assert "no verified production download" in _normalized("docs/site/index.html")
    assert "current status (verified 2026-07-21): not satisfied" in _normalized(
        "docs/RELEASE_CHECKLIST.md"
    )


def test_release_evidence_gap_is_named_not_implied():
    for relative in (
        "README.md",
        "SECURITY.md",
        "docs/SECURITY.md",
        "docs/TESTING.md",
        "docs/RELEASE_CHECKLIST.md",
        "docs/site/index.html",
    ):
        text = _normalized(relative)
        assert "auto-latest" in text, relative
        assert "sigstore" in text, relative
        assert "sbom" in text, relative
        assert "provenance" in text, relative


def test_user_docs_do_not_link_mutable_latest_as_an_install_source():
    for relative in ("README.md", "docs/site/index.html"):
        text = _read(relative).lower()
        assert "/releases/latest" not in text
        assert "/latest/download/" not in text
        assert "api.github.com/repos/" not in text


def test_security_doc_labels_aspirational_supply_chain_controls():
    text = _normalized("docs/SECURITY.md")
    assert "roadmap, not current guarantees" in text
    assert "slsa-level certification" in text
    assert "threshold signing is a roadmap control" in text
    assert "whole-product byte-for-byte reproducibility is not claimed" in text
    assert "status:** ✅ defeated by structural threshold requirement" not in text
    assert "slsa-3 build provenance attestation published with every release" not in text
    assert "sbom (cyclonedx) auto-generated and published with every release" not in text


def test_release_checklist_distinguishes_required_controls_from_evidence():
    text = _normalized("docs/RELEASE_CHECKLIST.md")
    assert "future release decision" in text
    assert "presence is not evidence" in text
    assert "ruleset is a current blocker" in text
    assert "no production tag" in text
    assert "has completed `release.yml`" in text
    assert "must instead be covered by provenance" in text


def test_governance_labels_undeployed_maintainer_controls_as_targets():
    text = _normalized("docs/GOVERNANCE.md")
    assert "governance targets, not current release properties" in text
    assert "no enforced 2-of-n release authorization" in text
    assert "no `docs/maintainer_keys.md` file" in text
    assert "release signing — multi-maintainer threshold (target)" in text
    assert "no signed maintainer covenant is committed today" in text
    assert "no canonical signed warrant canary" in text
    assert "scheme:** ed25519 signatures. releases require" not in text


def test_release_checklist_names_actual_platform_coverage():
    text = _normalized("docs/RELEASE_CHECKLIST.md")
    assert "full pytest suite and playwright e2e run on linux + windows" in text
    assert "native picker smoke runs separately on linux + windows + macos" in text
    assert "macos does not currently run the full pytest suite" in text
    assert "runs on linux + windows + macos" not in text


def test_launch_checklist_separates_portable_zips_from_future_installers():
    text = _normalized("docs/LAUNCH_CHECKLIST.md")
    assert "architecture-labeled portable zip archives" in text
    assert "no production tag has completed that workflow yet" in text
    assert "does **not** include a windows installer" in text
    assert "future packaging gates (not current shipping claims)" in text
    assert "no windows installer currently ships" in text
    assert "no dmg or pkg currently ships" in text
    assert "no appimage currently ships" in text


def test_testing_docs_use_frozen_exact_commit_evidence_language():
    root_testing = _normalized("TESTING.md")
    detailed = _normalized("docs/TESTING.md")
    assert "uv sync --frozen" in root_testing
    assert "does not promise a fixed number or duration" in root_testing
    assert "configuration is an intended gate, not proof" in root_testing
    assert "workflow table above describes required mechanisms" in detailed
    assert "passing local subset" in detailed
    assert "reproducible builds, sigstore signing, artifact upload" not in detailed


def test_disclosure_policy_does_not_advertise_unpublished_pgp_key():
    text = _normalized("SECURITY.md")
    assert "no authenticated project pgp disclosure key is currently published" in text
    assert "iamoneyouareoneweareone.gpg" not in text


def test_verification_examples_are_placeholders_not_fictional_current_assets():
    readme = _read("README.md")
    site = _read("docs/site/index.html")
    assert "./<artifact> vX.Y.Z" in readme
    assert "./&lt;artifact&gt; vX.Y.Z" in site
    assert "v0.21.0-alpha" not in readme
    assert "v0.21.0-alpha" not in site

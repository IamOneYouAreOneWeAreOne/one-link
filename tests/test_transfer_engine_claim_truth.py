"""Regression checks for externally visible transfer-engine capability claims.

These tests intentionally validate documentation against the production code's
current scope. They prevent a generic primitive or a deferred codec from being
reported as a shipped control loop.
"""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_shipped_fountain_codec_is_reported_as_lt() -> None:
    changelog = _read("CHANGELOG.md")
    plan = _read("docs/FILE_ENGINE_V2_PLAN.md")
    implementation_manifest = _read("native/ol_fountain/Cargo.toml")

    assert "`ol_fountain` — LT (Luby Transform) fountain codes" in changelog
    assert "RaptorQ (RFC 6330) remains deferred" in changelog
    assert "| `ol_fountain` | shipped | LT (Luby Transform) codec" in plan
    assert "| LT fountain decode |" in plan
    assert "**Deferred and not shipped.** LT codes are the production codec." in plan
    assert "description = \"One Link file engine: LT fountain codes" in implementation_manifest

    false_shipped_claims = (
        "`ol_fountain` — RaptorQ fountain codes",
        "| `ol_fountain` | shipped | RaptorQ codec |",
        "| RaptorQ decode |",
        "├── ol_fountain/                    # Phase B: RaptorQ",
    )
    for claim in false_shipped_claims:
        assert claim not in changelog
        assert claim not in plan


def test_bandit_claims_match_route_only_production_wiring() -> None:
    crate_docs = _read("native/ol_bandit/src/lib.rs")
    plan = _read("docs/FILE_ENGINE_V2_PLAN.md")
    decision = _read("docs/decisions/0019-multi-armed-bandit.md")
    runtime = _read("src/one_link/transfer_brain.py")

    assert "production-active consumer today is **route selection only**" in crate_docs
    assert "future work; they are not implemented or production-active" in crate_docs
    assert "uses route names as arms" in plan
    assert "other proposed knob controllers are not production-active" in plan
    assert "| Route selection | candidate route names | **Production-active**" in decision
    assert "Deferred; no production control loop" in decision
    assert "No production `choose_knob()` API exists." in decision
    assert "class BanditRouteSelector:" in runtime
    assert "No bandit control" in runtime

    assert "one Bandit per (peer-pair, knob)" not in crate_docs
    assert "Ship `ol_bandit`: Beta-Bernoulli Thompson sampling, one Bandit" not in decision


"""v0.20.7 — /api/audit advertises the sovereignty primitive surface.

The audit endpoint is one of One Link's "no telemetry, no calls
home" verifications: it lists every network call the binary makes,
every protocol message it speaks, every outbound destination. Bundle
46 extends it to also list every sovereignty / privacy primitive
the binary ships, so an inspecting user can audit the surface
without grepping the source.

These tests pin:
  - The enumeration helper returns a non-empty list
  - Every entry has the required fields (module/name/status/summary/
    audit_ref)
  - Each module that's actually present in the build is reported as
    available (status != "unavailable")
  - Specific primitives (the ones added in Bundles 22-45) appear in
    the catalog
  - Status values are sane (one of: primitive / live / unavailable)
"""
from __future__ import annotations

import pytest

from one_link import server as srv_mod


def test_enumerator_returns_non_empty():
    out = srv_mod._enumerate_sovereign_primitives()
    assert isinstance(out, list)
    assert len(out) >= 15  # we shipped at least this many


def test_each_entry_has_required_fields():
    out = srv_mod._enumerate_sovereign_primitives()
    required = {"module", "name", "status", "summary", "audit_ref"}
    for entry in out:
        assert required.issubset(entry.keys()), entry


def test_status_values_are_sane():
    out = srv_mod._enumerate_sovereign_primitives()
    valid = {"primitive", "live", "unavailable"}
    for entry in out:
        assert entry["status"] in valid, entry


def test_critical_modules_advertised():
    """Spot-check the catalog includes the primitives we just shipped.
    A refactor that drops one of these from the catalog should
    surface in CI."""
    out = srv_mod._enumerate_sovereign_primitives()
    modules = {e["module"] for e in out}
    expected = {
        "one_link.path_pii",
        "one_link.social_recovery",
        "one_link.dht",
        "one_link.pq_hybrid",
        "one_link.mls_treekem",
        "one_link.sealed_sender",
        "one_link.onion",
        "one_link.traffic_shaper",
        "one_link.deletion_chain",
        "one_link.rdz_blind",
        "one_link.caps_grants",
        "one_link.identity_dag",
    }
    missing = expected - modules
    assert not missing, f"missing from audit catalog: {missing}"


def test_summaries_non_empty_and_reasonable():
    out = srv_mod._enumerate_sovereign_primitives()
    for entry in out:
        assert isinstance(entry["summary"], str)
        assert 10 < len(entry["summary"]) < 500, entry


def test_module_imports_succeed():
    """Every module listed in the catalog must actually import. If
    one's missing, the catalog reports "unavailable"; this test
    fails so we notice."""
    out = srv_mod._enumerate_sovereign_primitives()
    unavailable = [
        e for e in out if e["status"] == "unavailable"
    ]
    assert not unavailable, (
        f"some primitives are unavailable: "
        f"{[e['module'] for e in unavailable]}"
    )


def test_catalog_audit_refs_distinct_per_bundle():
    """audit_ref strings should be unique enough to identify the
    bundle that introduced the primitive — useful when reading
    /api/audit output to find the corresponding commit."""
    out = srv_mod._enumerate_sovereign_primitives()
    refs = [e["audit_ref"] for e in out]
    # We expect mostly unique refs; some primitives ship in the
    # same bundle (e.g. master_seed + mnemonic in B23). Soft check:
    assert len(set(refs)) >= len(refs) - 3

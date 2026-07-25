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

from pathlib import Path

from one_link import capabilities
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


def test_catalog_promotes_only_runtime_self_tested_security_paths():
    by_module = {
        entry["module"]: entry
        for entry in srv_mod._enumerate_sovereign_primitives()
    }

    pq = by_module["one_link.pq_hybrid"]
    assert pq["name"] == "Hybrid X25519 + ML-KEM-768 channel"
    pq_live = (
        capabilities.PQ_HYBRID_HANDSHAKE_V1
        in capabilities.advertised_capabilities()
    )
    assert pq["status"] == ("live" if pq_live else "primitive")
    if pq_live:
        assert "mutual key confirmation" in pq["summary"]
        assert "default downgrade refusal" in pq["summary"]
    else:
        assert "advertises no PQ channel" in pq["summary"]

    onion = by_module["one_link.onion"]
    assert "no live message/file route uses it" in onion["summary"]
    assert "not an anonymity guarantee" in onion["summary"]

    sealed = by_module["one_link.sealed_sender"]
    assert sealed["status"] == "live"
    assert "both identity-bearing channel first flights" in sealed["summary"]
    assert "not endpoint IP/timing/size metadata" in sealed["summary"]

    sealed_relay = by_module["one_link.sealed_relay"]
    assert sealed_relay["status"] == "live"
    assert "rotating pairwise route tags" in sealed_relay["summary"]
    assert "single relay still observes" in sealed_relay["summary"]

    shaper = by_module["one_link.traffic_shaper"]
    assert "runtime-gated Poisson scheduler" in shaper["summary"]
    assert "Real traffic is not shape-matched" in shaper["summary"]
    assert "not proven against timing or size correlation" in shaper["summary"]
    assert "defeat timing" not in shaper["summary"].lower()

    ratchet = by_module["one_link.double_ratchet"]
    assert ratchet["status"] == "live"
    assert "legacy peers remain on per-session AEAD" in ratchet["summary"]

    deletion = by_module["one_link.deletion_chain"]
    assert "does not prove that every remote copy was erased" in deletion["summary"]

    vrf_routing = by_module["one_link.dht_vrf_routing"]
    assert "no daemon integration" in vrf_routing["summary"]


def test_feature_truth_matrix_has_strict_unique_schema():
    rows = srv_mod._feature_truth_matrix()
    axes = {
        "primitive_proven",
        "daemon_wired",
        "ui_exposed",
        "soak_proven",
    }
    allowed = {"proven", "partial", "absent"}

    assert rows
    assert len({row["id"] for row in rows}) == len(rows)
    for row in rows:
        assert {
            "id", "name", "qualified", "evidence", "limitation", *axes,
        } <= row.keys()
        assert all(row[axis] in allowed for axis in axes)
        assert row["qualified"] is all(row[axis] == "proven" for axis in axes)
        assert row["evidence"]
        assert row["limitation"]


def test_feature_truth_does_not_promote_unwired_security_primitives():
    rows = {row["id"]: row for row in srv_mod._feature_truth_matrix()}

    for feature_id in ("mls", "onion"):
        assert rows[feature_id]["daemon_wired"] == "absent"
        assert rows[feature_id]["ui_exposed"] == "absent"
        assert rows[feature_id]["qualified"] is False
    assert rows["sealed_sender"]["daemon_wired"] == "partial"
    assert rows["sealed_sender"]["ui_exposed"] == "absent"
    assert rows["sealed_sender"]["runtime"]["status"] == "not_observed"
    assert rows["sealed_sender"]["qualified"] is False
    assert rows["cover_frames"]["daemon_wired"] == "partial"
    assert rows["cover_frames"]["runtime"]["status"] == "not_observed"
    assert rows["cover_frames"]["qualified"] is False
    pq_expected = (
        "proven"
        if capabilities.PQ_HYBRID_HANDSHAKE_V1
        in capabilities.advertised_capabilities()
        else "absent"
    )
    assert rows["pq_kem"]["daemon_wired"] == pq_expected
    assert rows["pq_kem"]["ui_exposed"] == "partial"
    assert rows["pq_kem"]["qualified"] is False
    assert "does not prove a physical scene" in rows["frame_provenance"]["limitation"]
    assert all(row["soak_proven"] != "proven" for row in rows.values())


def test_feature_truth_promotes_only_consistent_live_blinded_relay():
    class _BlindedDaemon:
        @staticmethod
        def relay_routing_runtime_truth():
            return {
                "pairwise_blinded_active": True,
                "legacy_identity_route_active": False,
                "destination_identity_exposure": (
                    "no_identity_public_key_on_relay_wire"
                ),
                "identity_bearing_channel_first_flight": (
                    "sealed_recipient_only_v1"
                ),
                "legacy_migration_override_enabled": False,
            }

    row = {
        item["id"]: item
        for item in srv_mod._feature_truth_matrix(_BlindedDaemon())
    }["sealed_sender"]
    assert row["daemon_wired"] == "proven"
    assert row["runtime"]["status"] == "pairwise_blinded_v2_active"
    assert row["runtime"]["pairwise_blinded_active"] is True
    assert row["qualified"] is False
    assert "not sender anonymity" in row["limitation"]


def test_feature_truth_fails_closed_for_legacy_or_inconsistent_relay():
    class _LegacyDaemon:
        @staticmethod
        def relay_routing_runtime_truth():
            return {
                "pairwise_blinded_active": True,
                "legacy_identity_route_active": True,
                "destination_identity_exposure": (
                    "destination_public_key_exposed_to_relay"
                ),
                "identity_bearing_channel_first_flight": "plaintext_identity_keys",
                "legacy_migration_override_enabled": True,
            }

    class _InconsistentDaemon:
        @staticmethod
        def relay_routing_runtime_truth():
            return {
                "pairwise_blinded_active": True,
                "legacy_identity_route_active": False,
                "destination_identity_exposure": "unknown",
                "identity_bearing_channel_first_flight": "unknown",
            }

    for daemon, status in (
        (_LegacyDaemon(), "legacy_identity_exposure_active"),
        (_InconsistentDaemon(), "inconsistent_report_failed_closed"),
    ):
        row = {
            item["id"]: item
            for item in srv_mod._feature_truth_matrix(daemon)
        }["sealed_sender"]
        assert row["daemon_wired"] == "partial"
        assert row["runtime"]["status"] == status
        assert row["qualified"] is False


def test_feature_truth_promotes_cover_frames_only_after_wire_observation():
    class _ObservedCoverDaemon:
        @staticmethod
        def cover_traffic_stats():
            return {
                "available": True,
                "running": True,
                "packets_sent": 3,
                "packets_received": 1,
            }

    row = {
        item["id"]: item
        for item in srv_mod._feature_truth_matrix(_ObservedCoverDaemon())
    }["cover_frames"]
    assert row["daemon_wired"] == "proven"
    assert row["runtime"] == {
        "status": "wire_frames_emitted",
        "available": True,
        "running": True,
        "packets_sent": 3,
        "packets_received": 1,
    }
    assert row["qualified"] is False
    assert "not proof of an anonymity system" in row["limitation"]


def test_feature_truth_does_not_call_receive_only_cover_emission_proven():
    class _ReceiveOnlyCoverDaemon:
        @staticmethod
        def cover_traffic_stats():
            return {
                "available": True,
                "running": True,
                "packets_sent": 0,
                "packets_received": 2,
            }

    row = {
        item["id"]: item
        for item in srv_mod._feature_truth_matrix(_ReceiveOnlyCoverDaemon())
    }["cover_frames"]
    assert row["daemon_wired"] == "partial"
    assert row["runtime"]["status"] == "wire_frames_received_only"
    assert row["qualified"] is False


def test_feature_truth_cover_frame_probe_fails_closed():
    class _InvalidCoverDaemon:
        @staticmethod
        def cover_traffic_stats():
            return {
                "available": True,
                "running": True,
                "packets_sent": "not-an-integer",
            }

    class _ExplodingCoverDaemon:
        @staticmethod
        def cover_traffic_stats():
            raise RuntimeError("probe unavailable")

    for daemon, status in (
        (_InvalidCoverDaemon(), "invalid_report_failed_closed"),
        (_ExplodingCoverDaemon(), "probe_failed_closed"),
    ):
        row = {
            item["id"]: item
            for item in srv_mod._feature_truth_matrix(daemon)
        }["cover_frames"]
        assert row["daemon_wired"] == "partial"
        assert row["runtime"]["status"] == status
        assert row["runtime"]["packets_sent"] == 0
        assert row["qualified"] is False


def test_feature_truth_native_rows_match_runtime_capability_advertisement():
    rows = {row["id"]: row for row in srv_mod._feature_truth_matrix()}
    runtime_caps = set(capabilities.advertised_capabilities())
    mapping = {
        "native_transfer": capabilities.NATIVE_TRANSFER_INDEXED_V1,
        "bloom_delta": capabilities.BLOOM_INIT_EXACT_V2,
        "quic": capabilities.QUIC_TRANSPORT_V1,
        "pq_kem": capabilities.PQ_HYBRID_HANDSHAKE_V1,
    }

    for feature_id, capability in mapping.items():
        expected = "proven" if capability in runtime_caps else "absent"
        assert rows[feature_id]["daemon_wired"] == expected


def test_feature_truth_promotes_linux_mount_only_from_consistent_runtime():
    class _LinuxFuseDaemon:
        @staticmethod
        def fuse_capabilities():
            return {
                "platform": "linux_ready",
                "ready": True,
                "backend": "fuse",
                "reason": "ready",
            }

    row = {
        item["id"]: item
        for item in srv_mod._feature_truth_matrix(_LinuxFuseDaemon())
    }["filesystem_mount"]

    assert row["primitive_proven"] == "proven"
    assert row["daemon_wired"] == "proven"
    assert row["ui_exposed"] == "partial"
    assert row["soak_proven"] == "partial"
    assert row["qualified"] is False
    assert row["runtime"] == {
        "status": "linux_fuse_ready",
        "platform": "linux_ready",
        "ready": True,
        "backend": "fuse",
        "reason": "ready",
    }


def test_feature_truth_filesystem_probe_fails_closed():
    class _InvalidFuseDaemon:
        @staticmethod
        def fuse_capabilities():
            return {
                "platform": "linux_ready",
                "ready": True,
                "backend": "none",
                "reason": "ready",
            }

    row = {
        item["id"]: item
        for item in srv_mod._feature_truth_matrix(_InvalidFuseDaemon())
    }["filesystem_mount"]

    assert row["daemon_wired"] == "partial"
    assert row["runtime"]["status"] == "inconsistent_report_failed_closed"
    assert row["runtime"]["ready"] is False
    assert row["qualified"] is False


def test_truth_dashboard_is_runtime_driven_and_fails_closed():
    html = (
        Path(__file__).parents[1] / "src" / "one_link" / "web" / "index.html"
    ).read_text(encoding="utf-8")

    assert 'api.get("/api/audit"' in html
    assert "audit?.feature_truth" in html
    assert "Runtime truth unavailable" in html
    assert "const TRUTH_MATRIX" not in html

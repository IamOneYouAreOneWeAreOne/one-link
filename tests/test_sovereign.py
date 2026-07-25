from __future__ import annotations

from one_link.sovereign import doctrine


def test_doctrine_is_direct_first_optional_infrastructure_and_open():
    d = doctrine()

    assert "no mandatory cloud" in d["principles"]
    assert "open-source distribution" in d["principles"]
    assert d["privacy_guarantees"]["external_telemetry"] is False
    assert d["privacy_guarantees"]["mandatory_relay"] is False
    assert d["privacy_guarantees"]["owner_ui_default_loopback"] is True
    assert d["privacy_guarantees"]["lan_pairing_surface_opt_in"] is True
    assert d["network_model"]["optional_rendezvous"] is True
    assert d["network_model"]["optional_encrypted_relay"] is True
    assert d["network_model"]["optional_update_check"] is True
    assert "serverless" not in d["mission"].lower()
    assert all(not c["central_service_required"] for c in d["capabilities"])
    assert all("serverless" not in c for c in d["capabilities"])
    assert any(c["name"] == "content_defined_dedup" for c in d["capabilities"])
    assert any(c["name"] == "merkle_drift_sync" for c in d["capabilities"])

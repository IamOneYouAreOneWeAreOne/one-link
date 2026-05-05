from __future__ import annotations

from one_link.sovereign import doctrine


def test_doctrine_is_serverless_and_open():
    d = doctrine()

    assert "no mandatory cloud" in d["principles"]
    assert "open-source distribution" in d["principles"]
    assert d["privacy_guarantees"]["external_telemetry"] is False
    assert d["privacy_guarantees"]["mandatory_relay"] is False
    assert all(c["serverless"] for c in d["capabilities"])
    assert any(c["name"] == "content_defined_dedup" for c in d["capabilities"])
    assert any(c["name"] == "merkle_drift_sync" for c in d["capabilities"])

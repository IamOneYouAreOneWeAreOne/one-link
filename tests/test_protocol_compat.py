from __future__ import annotations

from one_link.capabilities import CHAT, FILES, FILE_CDC, FOLDER_SYNC
from one_link.protocol_compat import Version, fallback_order, negotiate


def test_version_parse_accepts_partial_semver():
    assert Version.parse("0.8.4") == Version(0, 8, 4)
    assert Version.parse("1.2") == Version(1, 2, 0)
    assert Version.parse("2") == Version(2, 0, 0)
    assert Version.parse("not-a-version") is None


def test_same_major_with_cdc_uses_advanced_mode():
    res = negotiate(
        local_version="0.8.4",
        peer_version="0.7.3",
        local_capabilities=[CHAT, FILES, FILE_CDC],
        peer_capabilities=[CHAT, FILES, FILE_CDC],
    )
    assert res.compatible
    assert res.mode == "advanced"
    assert res.transfer_mode == "cdc"
    assert fallback_order(res)[:2] == ("file_cdc", "file_baseline")


def test_same_major_falls_back_to_baseline_file_mode():
    res = negotiate(
        local_version="0.8.4",
        peer_version="0.6.0",
        local_capabilities=[CHAT, FILES, FILE_CDC],
        peer_capabilities=[CHAT, FILES],
    )
    assert res.compatible
    assert res.mode == "baseline"
    assert res.transfer_mode == "baseline_file"
    assert "file_cdc" not in fallback_order(res)


def test_major_mismatch_is_explicit_incompatible():
    res = negotiate(
        local_version="1.0.0",
        peer_version="2.0.0",
        local_capabilities=[CHAT, FILES],
        peer_capabilities=[CHAT, FILES],
    )
    assert res.compatible is False
    assert res.mode == "incompatible_major"
    assert "major_version_mismatch" in res.reasons


def test_required_capability_must_be_common():
    res = negotiate(
        local_version="0.8.4",
        peer_version="0.8.4",
        local_capabilities=[CHAT, FILES, FOLDER_SYNC],
        peer_capabilities=[CHAT, FILES],
        required=[FOLDER_SYNC],
    )
    assert res.compatible is False
    assert res.mode == "missing_required"
    assert res.missing_required == (FOLDER_SYNC,)


def test_unknown_optional_capability_does_not_break_baseline():
    res = negotiate(
        local_version="0.8.4",
        peer_version="0.9.0",
        local_capabilities=[CHAT, FILES, "future_magic"],
        peer_capabilities=[CHAT, FILES, "newer_unknown"],
    )
    assert res.compatible
    assert res.common_capabilities == (CHAT, FILES)


def test_missing_peer_version_can_still_legacy_degrade():
    res = negotiate(
        local_version="0.8.4",
        peer_version=None,
        local_capabilities=[CHAT, FILES],
        peer_capabilities=[],
    )
    assert res.compatible
    assert res.mode == "legacy_unknown"
    assert "peer_version_unknown" in res.reasons

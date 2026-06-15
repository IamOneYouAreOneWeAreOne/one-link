from __future__ import annotations

from one_link.capabilities import (
    CHAT,
    FILES,
    FILE_CDC,
    FILE_COMPRESSION,
    FILE_RESUMABLE,
    FILE_SWARM,
    FOLDER_SYNC,
)
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


def test_swarm_resumable_cdc_is_strongest_but_keeps_fallbacks():
    res = negotiate(
        local_version="0.9.9",
        peer_version="0.9.8",
        local_capabilities=[
            CHAT, FILES, FILE_CDC, FILE_RESUMABLE, FILE_SWARM, FILE_COMPRESSION,
        ],
        peer_capabilities=[
            CHAT, FILES, FILE_CDC, FILE_RESUMABLE, FILE_SWARM, FILE_COMPRESSION,
        ],
    )
    assert res.compatible
    assert res.mode == "swarm_advanced"
    assert res.transfer_mode == "swarm_cdc"
    assert fallback_order(res)[:4] == (
        "file_swarm_cdc",
        "file_resumable_cdc",
        "file_cdc",
        "file_baseline",
    )


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


def test_app_major_mismatch_degrades_to_baseline_not_refused():
    """2026-06-04: an APP-version major difference must NOT sever
    interop — it degrades to the universal baseline so chat + basic
    file transfer always work. (Previously this returned
    compatible=False / incompatible_major, which would have turned a
    routine 1.0 release into a hard wall against every 0.x user.)"""
    res = negotiate(
        local_version="1.0.0",
        peer_version="2.0.0",
        local_capabilities=[CHAT, FILES, FILE_CDC],
        peer_capabilities=[CHAT, FILES, FILE_CDC],
    )
    assert res.compatible is True
    assert res.mode == "baseline_cross_major"
    assert "major_version_boundary" in res.reasons
    # Advanced framing (CDC) is conservatively disabled across the
    # boundary; only the baseline survives.
    assert "file_cdc" not in fallback_order(res)
    assert res.common_capabilities == (CHAT, FILES)


def test_same_wire_major_ignores_app_major_difference():
    """When both peers advertise the SAME wire protocol version, an
    app-version major difference is irrelevant — full advanced
    negotiation proceeds. This is the decoupling that lets the app
    bump to 1.0 (or 2.0) without downgrading transfers."""
    res = negotiate(
        local_version="2.0.0",
        peer_version="1.0.0",
        local_capabilities=[CHAT, FILES, FILE_CDC],
        peer_capabilities=[CHAT, FILES, FILE_CDC],
        local_wire_version="OL1.2",
        peer_wire_version="OL1.2",
    )
    assert res.compatible is True
    assert res.mode == "advanced"
    assert "major_version_boundary" not in res.reasons


def test_wire_major_boundary_degrades_to_baseline():
    """A genuine WIRE-protocol major boundary (frame shape may have
    changed) conservatively drops the pair to baseline rather than
    risking a corrupt advanced transfer — but still does NOT refuse."""
    res = negotiate(
        local_version="1.5.0",
        peer_version="1.5.0",
        local_capabilities=[CHAT, FILES, FILE_CDC],
        peer_capabilities=[CHAT, FILES, FILE_CDC],
        local_wire_version="OL2.0",
        peer_wire_version="OL1.2",
    )
    assert res.compatible is True
    assert res.mode == "baseline_cross_major"
    assert "file_cdc" not in fallback_order(res)


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

"""Cross-version wire-compatibility CONTRACT.

2026-06-04. One Link devices update independently, so paired devices can be on
different builds. These tests pin bounded compatibility invariants; they do not
prove arbitrary historical/future builds interoperate. If one fails, read
docs/WIRE_COMPATIBILITY.md before changing the contract.

The invariants:

  1. Current tested builds advertise baseline capabilities (chat + files).
     Shared names permit a baseline attempt but are not wire-equivalence proof.
  2. Capability negotiation does not hard-refuse on a version number alone;
     required capabilities and later protocol validation can still reject.
  3. The Double-Ratchet wire header is frozen at v1; a bump is a
     breaking wire change that MUST be gated behind a negotiated
     capability (see the doc), never shipped unilaterally.
  4. The CAPS frame carries the wire protocol version, and it parses.
  5. Unknown capabilities are ignored (forward-compat), not rejected.
"""
from __future__ import annotations

import pytest

from one_link import capabilities as caps
from one_link.protocol_compat import Version, negotiate


# ── 1. Baseline floor is always advertised ────────────────────────

def test_baseline_capabilities_always_advertised():
    """CHAT + FILES must always be in LOCAL_CAPABILITIES. They are the
    universal floor every build shares; remove either and two
    different versions could end up with zero common capability and
    be unable to talk at all."""
    assert caps.CHAT in caps.LOCAL_CAPABILITIES
    assert caps.FILES in caps.LOCAL_CAPABILITIES


def test_advertised_caps_include_core_features():
    """The daemon's advertised CAPS_FEATURES must be a superset of the
    core feature set. Renaming or dropping a core feature string
    silently disables that feature for any mixed-version pair (the
    cap simply stops appearing in the common set), which is exactly
    the kind of invisible interop regression this file guards."""
    from one_link.daemon import CAPS_FEATURES
    advertised = set(caps.normalize_caps(CAPS_FEATURES))
    core = {
        caps.CHAT,
        caps.FILES,
        caps.FILE_CDC,
        caps.FOLDER_SYNC,
        caps.DOUBLE_RATCHET_V1,
    }
    missing = core - advertised
    assert not missing, (
        f"core capabilities dropped from CAPS_FEATURES: {missing}. "
        "Removing/renaming a core cap breaks interop with builds that "
        "still expect it. See docs/WIRE_COMPATIBILITY.md."
    )


def test_preview_substrates_are_never_advertised_as_wire_capabilities():
    """A module or benchmark is not proof of an end-to-end media feature.

    Preview capabilities stay recognizable for forward compatibility, but a
    stable daemon must not promise them until the capture/wire/playout release
    gate is real.
    """
    from one_link.daemon import CAPS_FEATURES

    previews = set(caps.PREVIEW_CAPABILITIES)
    assert previews
    assert previews.isdisjoint(caps.LOCAL_CAPABILITIES)
    assert previews.isdisjoint(CAPS_FEATURES)
    assert previews.isdisjoint(caps.PROMPT_REQUIRED)


# ── 2. Version difference never hard-refuses ───────────────────────

def test_version_difference_alone_never_refuses():
    """Any two builds that share the baseline must negotiate as
    compatible, regardless of how far apart their versions are."""
    for lv, pv in [
        ("0.1.0", "9.9.9"),
        ("9.9.9", "0.1.0"),
        ("0.21.4", "0.21.4"),
        ("1.0.0", "0.21.0"),
    ]:
        res = negotiate(
            local_version=lv,
            peer_version=pv,
            local_capabilities=[caps.CHAT, caps.FILES, caps.FILE_CDC],
            peer_capabilities=[caps.CHAT, caps.FILES, caps.FILE_CDC],
        )
        assert res.compatible is True, f"{lv} vs {pv} wrongly refused"
        assert any(
            c in res.common_capabilities
            for c in (caps.CHAT, caps.FILES)
        )


def test_missing_peer_version_still_compatible():
    """A peer that advertises no version at all (very old build) must
    still degrade to a working legacy mode, not refuse."""
    res = negotiate(
        local_version="0.21.0",
        peer_version=None,
        local_capabilities=[caps.CHAT, caps.FILES],
        peer_capabilities=[caps.CHAT, caps.FILES],
    )
    assert res.compatible is True


def test_no_shared_capability_is_the_only_hard_incompatible():
    """The ONLY legitimate hard-incompatible is genuinely zero shared
    user capability (can't even chat). Everything else degrades."""
    res = negotiate(
        local_version="0.21.0",
        peer_version="0.21.0",
        local_capabilities=["some_exotic_cap"],
        peer_capabilities=["another_exotic_cap"],
    )
    assert res.compatible is False


# ── 3. Double-Ratchet wire header is frozen at v1 ──────────────────

def test_ratchet_header_frozen_at_v1():
    """The DR header version byte is the single hardest wire
    constraint: Header.decode() raises on any value != 1, so a peer
    that bumps it instantly hard-fails every older peer with
    'unsupported ratchet header version'. This test freezes it at 1.

    If you genuinely need to evolve the ratchet wire format, you may
    NOT just change this number. You must negotiate the new version
    via a CAPS feature (e.g. double_ratchet_v2) so two peers always
    pick a header version they BOTH understand, and keep accepting v1
    for at least one full release cycle. See docs/WIRE_COMPATIBILITY.md.
    """
    from one_link.double_ratchet import Header

    h = Header(v=1, flags=0, dh=b"\x00" * 32, pn=0, n=0)
    raw = h.encode()
    # v1 round-trips.
    assert Header.decode(raw).v == 1
    # A different version byte is rejected (the breaking-change wall).
    bumped = bytes([2]) + raw[1:]
    with pytest.raises(ValueError, match="unsupported ratchet header version"):
        Header.decode(bumped)


# ── 4. CAPS carries a parseable wire protocol version ──────────────

def test_protocol_version_is_present_and_parseable():
    from one_link.daemon import PROTOCOL_VERSION

    assert isinstance(PROTOCOL_VERSION, str) and PROTOCOL_VERSION
    wire = Version.parse_wire(PROTOCOL_VERSION)
    assert wire is not None, (
        f"PROTOCOL_VERSION {PROTOCOL_VERSION!r} must contain a parseable "
        "numeric wire version so negotiate() can key the major-boundary "
        "check off the wire, not the marketing app version"
    )
    # Pin the current wire major. Bumping this is a deliberate breaking
    # wire change — update the doc + provide a negotiated migration.
    assert wire.major == 1


# ── 5. Unknown capabilities are ignored, not rejected ──────────────

def test_unknown_capabilities_ignored():
    res = negotiate(
        local_version="0.21.0",
        peer_version="0.21.0",
        local_capabilities=[caps.CHAT, caps.FILES, "local_only_future_cap"],
        peer_capabilities=[caps.CHAT, caps.FILES, "peer_only_future_cap"],
    )
    assert res.compatible is True
    # The exotic caps simply don't appear in the common set.
    assert "local_only_future_cap" not in res.common_capabilities
    assert "peer_only_future_cap" not in res.common_capabilities
    assert caps.CHAT in res.common_capabilities
    assert caps.FILES in res.common_capabilities

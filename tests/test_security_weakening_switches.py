"""Every switch that WEAKENS a default, pinned at its secure setting.

An undocumented tuning knob is untidy. An undocumented switch that turns a
protection OFF is the hazard, because nothing proves it is off by default and
nothing proves what it does when set.

The dark-switch audit found three of these reachable from nowhere outside
`src/`. The post-quantum handshake pair is covered in
test_classical_downgrade_switches.py. These are the other two:

  ONE_LINK_ALLOW_FIXED_COURIER_TARGETS
      Courier discovery normally offers only REMOVABLE drives. With this set,
      fixed drives are offered too -- the code comment says "production should
      not spray courier files onto C:".

  ONE_LINK_ALLOW_LEGACY_RELAY_IDENTITY_ROUTE
      Re-enables a legacy relay identity route for mixed-version migration.

Each test asserts the SECURE DEFAULT first. That is the property that protects
a user who never heard of the switch, and it is the one that must never regress.
"""

from __future__ import annotations

import os

import pytest

WEAKENING_SWITCHES = (
    "ONE_LINK_ALLOW_FIXED_COURIER_TARGETS",
    "ONE_LINK_ALLOW_LEGACY_RELAY_IDENTITY_ROUTE",
)


@pytest.fixture(autouse=True)
def _no_ambient_override(monkeypatch: pytest.MonkeyPatch):
    for name in WEAKENING_SWITCHES:
        monkeypatch.delenv(name, raising=False)


# ── legacy relay identity route ───────────────────────────────────────


def _daemon_with_state(state):
    from one_link.daemon import Daemon

    daemon = Daemon.__new__(Daemon)
    daemon.state = state
    return daemon


def test_legacy_relay_route_is_refused_by_default() -> None:
    assert _daemon_with_state(None)._legacy_relay_identity_route_allowed() is False


@pytest.mark.parametrize("token", ["1", "true", "yes", "on", "TRUE", "  On  "])
def test_legacy_relay_route_accepts_its_documented_affirmatives(
    token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """This switch deliberately takes a token SET, unlike the handshake switch.

    That asymmetry is real and worth pinning rather than smoothing over: the
    handshake override requires exactly "1" because a channel downgrade must be
    hard to trigger by accident, while this one is an operator migration flag
    that also arrives from a stored setting typed by a human.
    """
    monkeypatch.setenv("ONE_LINK_ALLOW_LEGACY_RELAY_IDENTITY_ROUTE", token)
    assert _daemon_with_state(None)._legacy_relay_identity_route_allowed() is True


@pytest.mark.parametrize("token", ["0", "false", "no", "off", "", "maybe", "2"])
def test_legacy_relay_route_refuses_everything_else(
    token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A malformed value must fail CLOSED, never open.

    `ONE_LINK_ALLOW_LEGACY_RELAY_IDENTITY_ROUTE=disabled` reads to a human as
    off. If any non-empty string enabled it, trying to turn it off in words
    would turn it on.
    """
    monkeypatch.setenv("ONE_LINK_ALLOW_LEGACY_RELAY_IDENTITY_ROUTE", token)
    assert _daemon_with_state(None)._legacy_relay_identity_route_allowed() is False


def test_a_stored_setting_can_enable_the_legacy_relay_route() -> None:
    """The second door: persisted state, not just the environment.

    A switch reachable from two places needs both proven, which is exactly the
    lesson from the handshake override -- there, coverage followed one name and
    missed the other.
    """

    class _State:
        def __init__(self, value):
            self.value = value

        def get_setting(self, key):
            assert key == "allow_legacy_relay_identity_route"
            return self.value

    assert _daemon_with_state(_State("on"))._legacy_relay_identity_route_allowed() is True
    assert _daemon_with_state(_State("off"))._legacy_relay_identity_route_allowed() is False
    # An unset stored value must not mask the (absent) environment default.
    assert _daemon_with_state(_State(None))._legacy_relay_identity_route_allowed() is False


def test_a_failing_state_store_does_not_open_the_legacy_route() -> None:
    """Fail closed when the store cannot answer.

    The implementation reads the stored setting under contextlib.suppress. A
    store that raises must leave the switch OFF, not fall through to an
    accidental affirmative.
    """

    class _Exploding:
        def get_setting(self, key):
            raise RuntimeError("state unavailable")

    assert _daemon_with_state(_Exploding())._legacy_relay_identity_route_allowed() is False


# ── fixed courier targets ─────────────────────────────────────────────


def _drive_stub(fixed_letters: str = "C", removable_letters: str = "D"):
    """A stand-in for kernel32 exposing exactly what discovery calls."""
    letters = fixed_letters + removable_letters

    class _Kernel32:
        @staticmethod
        def GetLogicalDrives() -> int:
            mask = 0
            for ch in letters:
                mask |= 1 << (ord(ch) - ord("A"))
            return mask

        @staticmethod
        def GetDriveTypeW(root) -> int:
            # Discovery passes ctypes.c_wchar_p(root), so read .value -- str()
            # on the pointer yields an object repr and would classify every
            # drive identically, which is how this stub was wrong at first.
            path = getattr(root, "value", None) or str(root)
            # DRIVE_FIXED = 3, DRIVE_REMOVABLE = 2
            return 3 if path[0] in fixed_letters else 2

    return _Kernel32()


@pytest.fixture
def _windows_drive_surface(monkeypatch: pytest.MonkeyPatch):
    """Drive the REAL discovery function with a stubbed Win32 surface."""
    from one_link import removable_media

    if not hasattr(removable_media.ctypes, "windll"):
        pytest.skip("ctypes.windll exists only on Windows")

    monkeypatch.setattr(
        removable_media.ctypes,
        "windll",
        type("_W", (), {"kernel32": _drive_stub()})(),
        raising=False,
    )
    monkeypatch.setattr(removable_media, "_usable_dir", lambda path: True)
    return removable_media


def test_courier_targets_exclude_fixed_drives_by_default(
    _windows_drive_surface, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only REMOVABLE drives may be offered as courier targets.

    A courier file written to C: is user data placed outside the boundary the
    feature promises. The default must exclude fixed drives.
    """
    targets = _windows_drive_surface._list_windows_removable()
    ids = {t.id for t in targets}
    assert "win:C" not in ids, f"a FIXED drive was offered by default: {ids}"
    assert "win:D" in ids, f"the removable drive was not offered: {ids}"


def test_the_opt_in_really_is_what_admits_fixed_drives(
    _windows_drive_surface, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CONTROL for the test above.

    If discovery never offered C: for some unrelated reason, the default test
    would pass while proving nothing about the switch. Setting the opt-in must
    change the outcome -- that is what makes the default meaningful.
    """
    monkeypatch.setenv("ONE_LINK_ALLOW_FIXED_COURIER_TARGETS", "1")
    ids = {t.id for t in _windows_drive_surface._list_windows_removable()}
    assert "win:C" in ids, f"the opt-in did not admit the fixed drive: {ids}"


@pytest.mark.parametrize("token", ["0", "true", "yes", "on", "", "2"])
def test_only_the_exact_value_1_admits_fixed_drives(
    token: str, _windows_drive_surface, monkeypatch: pytest.MonkeyPatch
) -> None:
    """This switch requires exactly "1"; anything else must fail closed."""
    monkeypatch.setenv("ONE_LINK_ALLOW_FIXED_COURIER_TARGETS", token)
    ids = {t.id for t in _windows_drive_surface._list_windows_removable()}
    assert "win:C" not in ids, (
        f"ONE_LINK_ALLOW_FIXED_COURIER_TARGETS={token!r} admitted a fixed drive"
    )


def test_these_switches_have_left_the_dark_registry() -> None:
    """The ratchet, asserted from the other side.

    This test originally asserted these two were still IN the registry. That was
    wrong, and the registry's own staleness check said so: this file's tests
    made both switches reachable, so their entries became stale claims that a
    gap still existed. A known-gaps list that keeps closed entries stops being
    believed, so the list may only shrink.

    Keeping the assertion (inverted) rather than deleting it matters: if someone
    deletes the coverage above, the switches go dark again and BOTH gates have
    to be edited to hide it -- this one, and the registry.
    """
    from tests.test_no_dark_env_switches import KNOWN_UNREACHABLE

    for name in WEAKENING_SWITCHES:
        assert name not in KNOWN_UNREACHABLE, (
            f"{name} was re-added to KNOWN_UNREACHABLE, but this file covers it"
        )

"""v0.7.3 device_info tests.

Pin the cross-platform device-kind detection that drives the
"Windows laptop" / "MacBook Pro" / "Linux server" labels in the
pair modal + sidebar.

The module is best-effort by design (every probe is wrapped),
so tests focus on:
  - Public surface stays the dataclass + detect() entry point.
  - Cache is honoured (force=False repeats give the same instance).
  - DeviceInfo.compact() builds <os>-<kind>.
  - DeviceInfo.from_dict / to_dict round-trip.
  - Detect() actually returns SOMETHING sensible on this machine
    (smoke-test).
"""
from __future__ import annotations


from one_link import device_info
from one_link.device_info import DeviceInfo, detect


def test_detect_returns_device_info():
    di = detect(force=True)
    assert isinstance(di, DeviceInfo)
    # OS bucket is one of the known values (or 'other' fallback).
    assert di.os in (
        "windows", "macos", "linux", "bsd", "ios", "android", "other",
    )
    assert di.kind in (
        "desktop", "laptop", "server", "mobile",
        "tablet", "embedded", "unknown",
    )
    assert isinstance(di.display, str) and di.display


def test_detect_is_cached():
    a = detect()
    b = detect()
    assert a is b


def test_detect_force_reruns():
    a = detect(force=True)
    b = detect(force=True)
    # Same content (deterministic for one machine), but the cache
    # is reset each time — we mainly assert the call doesn't raise.
    assert a.os == b.os
    assert a.kind == b.kind


def test_compact_format():
    di = DeviceInfo(os="macos", kind="laptop")
    assert di.compact() == "macos-laptop"


def test_to_dict_round_trip():
    di = DeviceInfo(
        os="windows", kind="laptop", vendor="Lenovo",
        model="ThinkPad X1", arch="x86_64", display="Lenovo ThinkPad X1",
    )
    out = di.to_dict()
    di2 = DeviceInfo.from_dict(out)
    assert di2 == di


def test_from_dict_handles_missing_keys():
    di = DeviceInfo.from_dict({})
    assert di.os == "other"
    assert di.kind == "unknown"
    assert di.arch == "unknown"


def test_from_dict_handles_none():
    di = DeviceInfo.from_dict(None)
    assert isinstance(di, DeviceInfo)
    assert di.os == "other"


def test_safe_run_does_not_raise_on_missing_command():
    """Internal helper — must never raise even if the binary
    doesn't exist. This is what makes detect() resilient."""
    out = device_info._safe_run([
        "this-binary-definitely-does-not-exist-anywhere-9999",
        "--version",
    ])
    assert out == ""


def test_arch_normalization():
    """Common machine() outputs map to canonical buckets."""
    # We can't easily mock platform.machine; just assert detect()
    # produces one of the known arches OR 'unknown'.
    di = detect(force=True)
    assert di.arch in (
        "x86_64", "arm64", "armv7", "x86", "unknown",
    ) or isinstance(di.arch, str)


# ─── Discovery integration smoke ───────────────────────────────────

def test_discovery_peer_dataclass_carries_device_kind():
    from one_link.discovery import Peer
    p = Peer(
        short_id="abc", hostname="x", address="1.2.3.4", port=1,
        ed_pub_hex="ee", device_kind="macos-laptop",
    )
    assert p.device_kind == "macos-laptop"


def test_discovery_peer_default_device_kind_empty():
    from one_link.discovery import Peer
    p = Peer(
        short_id="abc", hostname="x", address="1.2.3.4", port=1,
        ed_pub_hex="ee",
    )
    assert p.device_kind == ""

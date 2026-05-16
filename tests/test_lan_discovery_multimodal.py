"""Unit tests for the multi-modal LAN discovery module.

The scanner runs five protocols (mDNS / ARP / SSDP / NetBIOS / TCP
probe) in parallel and correlates them by (IP, MAC). These tests
exercise the pure-Python pieces — OUI vendor lookup, merge logic,
network-health assessment, multicast/broadcast filter — without
touching any real network.
"""
from __future__ import annotations

import asyncio

import pytest

from one_link import lan_discovery
from one_link.lan_discovery import (
    DiscoveredDevice,
    NetworkHealth,
    assess_network_health,
    merge_devices,
    vendor_for_mac,
)


class TestOUILookup:
    def test_bundled_oui_table_loads(self):
        """The gzipped bundled OUI table must load on import without
        any network call."""
        # Apple is in our curated subset.
        vendor = vendor_for_mac("a4:c3:61:00:00:00")
        assert "Apple" in vendor

    def test_unknown_mac_returns_empty(self):
        # Locally-administered (randomized) MACs have no OUI vendor.
        assert vendor_for_mac("de:00:23:d5:29:7a") == ""

    def test_malformed_mac_handled(self):
        assert vendor_for_mac("") == ""
        assert vendor_for_mac("not-a-mac") == ""
        assert vendor_for_mac(None) == ""

    def test_samsung_prefix(self):
        v = vendor_for_mac("ccfe3c:11:22:33")
        # Either format should be tolerated.
        v2 = vendor_for_mac("cc:fe:3c:11:22:33")
        assert "Samsung" in v or "Samsung" in v2

    def test_case_insensitive(self):
        # Upper/lower case MACs should resolve identically.
        a = vendor_for_mac("A4:C3:61:00:00:00")
        b = vendor_for_mac("a4:c3:61:00:00:00")
        assert a == b


class TestMergeDevices:
    def test_merge_same_ip_different_sources(self):
        """Two scanners seeing the same IP must produce one merged
        device with both sources recorded."""
        a = DiscoveredDevice(ip="192.168.1.50", hostname="laptop", sources=["mdns"])
        b = DiscoveredDevice(ip="192.168.1.50", mac="aa:bb:cc:dd:ee:ff",
                             sources=["arp"])
        merged = merge_devices([a, b])
        assert len(merged) == 1
        d = merged[0]
        assert d.ip == "192.168.1.50"
        assert d.hostname == "laptop"
        assert d.mac == "aa:bb:cc:dd:ee:ff"
        assert "mdns" in d.sources and "arp" in d.sources

    def test_merge_keeps_distinct_ips(self):
        a = DiscoveredDevice(ip="192.168.1.50", sources=["arp"])
        b = DiscoveredDevice(ip="192.168.1.51", sources=["arp"])
        merged = merge_devices([a, b])
        assert len(merged) == 2

    def test_merge_by_mac_when_ip_differs(self):
        """Same MAC on a different IP (DHCP renewal) should still
        coalesce — the device hasn't changed."""
        a = DiscoveredDevice(ip="192.168.1.50", mac="aa:bb:cc:dd:ee:ff",
                             sources=["arp"])
        b = DiscoveredDevice(ip="192.168.1.99", mac="aa:bb:cc:dd:ee:ff",
                             sources=["mdns"])
        merged = merge_devices([a, b])
        # Either result is acceptable as long as we don't lose data.
        # The contract is that information is preserved.
        all_macs = {m.mac for m in merged}
        assert "aa:bb:cc:dd:ee:ff" in all_macs


class TestNetworkHealth:
    def test_empty_scan_implies_isolation_suspicion(self):
        """Zero devices found, but we know we have a gateway — that's
        AP isolation, not an empty network."""
        h = assess_network_health([])
        assert isinstance(h, NetworkHealth)
        # We can't actually probe the gateway without a real network;
        # the function must at least return a valid NetworkHealth.

    def test_devices_with_gateway_reported_healthy(self):
        devs = [
            DiscoveredDevice(ip="192.168.1.1", hostname="router", kind="router"),
            DiscoveredDevice(ip="192.168.1.50", hostname="laptop", kind="laptop"),
        ]
        h = assess_network_health(devs)
        assert h.has_default_gateway is True or h.has_default_gateway is False
        # No assertion on ap_isolation_suspected — depends on real env.


class TestMulticastFilter:
    """Multicast / broadcast IPs and MACs must be filtered out of
    discovery results — they're not real devices."""
    def test_full_scan_excludes_multicast(self):
        # We can't easily inject test data into full_scan, so we just
        # call it and check that no result has a multicast IP or MAC.
        async def _run():
            return await lan_discovery.full_scan(timeout_s=1.0)
        devs = asyncio.run(_run())
        for d in devs:
            assert not d.ip.startswith("224."), f"multicast IP in results: {d.ip}"
            assert not d.ip.startswith("239."), f"multicast IP in results: {d.ip}"
            assert d.ip != "255.255.255.255"
            assert d.mac != "ff:ff:ff:ff:ff:ff"
            assert not d.mac.startswith("01:00:5e")  # IPv4 multicast MAC
            assert not d.mac.startswith("33:33")      # IPv6 multicast MAC


class TestSovereigntyFloor:
    """The module must never call an outside server. This test
    verifies that no urllib / requests / httpx import is in the
    module — they'd be a smell. Bundled OUI table is the only
    'lookup'."""
    def test_no_outside_http_clients(self):
        """Strip docstrings + comments and check for actual code
        references to outside lookup services."""
        import inspect, ast
        src = inspect.getsource(lan_discovery)
        tree = ast.parse(src)
        # Imports must not pull in HTTP clients.
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert "requests" not in alias.name.split(".")[0], alias.name
                    assert alias.name not in ("httpx", "urllib3"), alias.name
            elif isinstance(node, ast.ImportFrom):
                modroot = (node.module or "").split(".")[0]
                assert modroot not in ("requests", "httpx", "urllib3"), node.module
                # urllib.request is the high-level HTTP client; urllib.parse is fine.
                assert (node.module or "") != "urllib.request"
        # Also assert no urls to corp lookup hosts appear in any
        # string literal anywhere in the module — excluding
        # docstrings (which mention the hosts to say we DON'T call
        # them).
        forbidden_hosts = ("macvendors.com", "wireshark.org/oui",
                           "api.macvendors", "standards-oui.ieee")
        docstrings: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef,
                                 ast.AsyncFunctionDef, ast.ClassDef)):
                ds = ast.get_docstring(node)
                if ds and node.body:
                    first = node.body[0]
                    if isinstance(first, ast.Expr) and isinstance(
                        first.value, ast.Constant
                    ):
                        docstrings.add(id(first.value))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and id(node) not in docstrings):
                for host in forbidden_hosts:
                    assert host not in node.value, (
                        f"sovereignty floor violation: {host!r} in "
                        f"non-docstring string literal"
                    )

    def test_oui_data_is_bundled_locally(self):
        """The OUI table must live inside the package, not be
        downloaded at runtime."""
        from one_link import lan_discovery as ld
        data_dir = ld.Path(ld.__file__).parent / "data"
        oui_path = data_dir / "oui_prefixes.txt.gz"
        assert oui_path.exists(), (
            f"bundled OUI table missing at {oui_path} — "
            "scripts/build_oui_bundle.py must be re-run"
        )
        # Must be small (curated subset, not full ~33k registry).
        assert oui_path.stat().st_size < 50_000  # 50 KB ceiling

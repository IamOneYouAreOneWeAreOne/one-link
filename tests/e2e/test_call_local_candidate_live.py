"""Real browser proof for call-media local ICE candidate augmentation.

The main owner UI has a WebRTC stack separate from ``peer.html``.  This test
loads the shipped page from a live daemon, disables every configured public
STUN server, gathers a real browser candidate, and executes the exact helper
used by authenticated ``send_ice_candidate`` call signaling.
"""

from __future__ import annotations

import ipaddress

import pytest
from playwright.sync_api import Page


@pytest.fixture(autouse=True)
def _no_public_browser_ice(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ONE_LINK_STUN_SERVERS", "")


def test_call_media_local_candidate_augmentation_uses_real_browser_ice(
    ui_page: Page,
    browser_name: str,
) -> None:
    ui_page.wait_for_function(
        "() => typeof window.__oneLinkCallTransport?.candidateLinesForSignal === 'function'",
        timeout=15_000,
    )
    result = ui_page.evaluate(
        r"""async () => {
          const response = await fetch('/api/peer-rtc/ice-config', {
            credentials: 'include',
            cache: 'no-store',
          });
          if (!response.ok) throw new Error(`ICE config failed: ${response.status}`);
          const config = await response.json();
          const addresses = window.__oneLinkCallTransport.localAddressesFromIceConfig(config);
          const pc = new RTCPeerConnection({
            iceServers: config.iceServers,
            bundlePolicy: 'max-bundle',
            rtcpMuxPolicy: 'require',
          });
          pc.createDataChannel('one-link-call-candidate-proof', { ordered: true });
          await pc.setLocalDescription(await pc.createOffer());
          await new Promise((resolve) => {
            if (pc.iceGatheringState === 'complete') {
              resolve();
              return;
            }
            const timer = setTimeout(resolve, 12_000);
            pc.addEventListener('icegatheringstatechange', () => {
              if (pc.iceGatheringState !== 'complete') return;
              clearTimeout(timer);
              resolve();
            });
          });
          const candidateLines = String(pc.localDescription?.sdp || '')
            .split(/\r?\n/)
            .filter((line) => line.startsWith('a=candidate:'));
          const mdns = candidateLines.filter((line) => {
            const parts = line.trim().split(/\s+/);
            return parts.length >= 8 && /\.local$/i.test(parts[4] || '') &&
              parts[6] === 'typ' && parts[7] === 'host';
          });
          const source = mdns[0] || candidateLines[0] || '';
          const augmented = window.__oneLinkCallTransport.candidateLinesForSignal(
            source,
            addresses,
          );
          const state = {
            iceServers: config.iceServers,
            localAddressDiscovery: config.local_address_discovery,
            addresses,
            gatheringState: pc.iceGatheringState,
            candidateLines,
            mdns,
            source,
            augmented,
          };
          pc.close();
          return state;
        }""",
    )

    assert result["gatheringState"] == "complete"
    assert result["iceServers"]
    assert len(result["iceServers"]) == 1
    assert result["iceServers"][0]["urls"].startswith("stun:127.0.0.1:")
    assist = result["localAddressDiscovery"]
    assert assist == {
        **assist,
        "enabled": True,
        "external": False,
        "scope": "same-device-or-lan",
    }
    assert result["addresses"]
    assert result["addresses"][0] == "127.0.0.1"
    assert result["candidateLines"]

    if browser_name == "firefox":
        assert result["mdns"], "Firefox proof must exercise a real randomized .local host"
    if result["mdns"]:
        assert result["augmented"][0] == result["source"]
        assert len(result["augmented"]) > 1
        original = result["source"].split()
        for candidate in result["augmented"][1:]:
            parts = candidate.split()
            assert parts[0].startswith("a=candidate:ol")
            assert ipaddress.ip_address(parts[4])
            assert parts[4] in result["addresses"]
            assert parts[1:4] == original[1:4]
            assert parts[5:] == original[5:]
    else:
        # Engines that expose a numeric host candidate already must keep it
        # byte-for-byte intact rather than synthesize a redundant route.
        assert result["augmented"] == [result["source"]]

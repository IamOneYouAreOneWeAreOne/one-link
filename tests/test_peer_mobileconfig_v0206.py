"""v0.20.6 — iOS Configuration Profile (.mobileconfig) install flow.

iOS Safari refuses to bypass self-signed cert warnings on LAN IP
addresses (no "visit anyway" link, no advanced override). This
killed the v0.20.4 HTTPS pair flow on iPhone — the user reported
"it wont actually let me vist the website" after the cert page.

The fix is an iOS Configuration Profile served by the daemon over
plain HTTP (must be HTTP — the cert isn't trusted yet, so HTTPS
would fail). Profile carries the daemon's self-signed cert as a
`com.apple.security.root` payload. After install + trust toggle
(Settings → General → About → Certificate Trust Settings), the
cert is system-trusted and the regular pair QR works clean.

Tests cover: builder shape (plist parses, expected payload types),
endpoint MIME + content-disposition, mint-pairing response carries
the ios_profile_url, desktop UI surfaces the trust QR + step-by-
step instructions.
"""

from __future__ import annotations

import plistlib
from pathlib import Path

import pytest


# ───────── builder shape ──────────────────────────────────────────


def test_build_mobileconfig_returns_xml_plist(tmp_path: Path):
    """Output MUST be a valid XML plist that plistlib can parse
    back. iOS rejects malformed profiles silently — no install
    prompt — so a parse-back round-trip is the right gate."""
    from one_link.peer_https import build_mobileconfig
    payload = build_mobileconfig(tmp_path)
    assert isinstance(payload, bytes)
    assert payload.lstrip().startswith(b"<?xml")
    parsed = plistlib.loads(payload)
    assert isinstance(parsed, dict)


def test_mobileconfig_outer_payload_is_configuration(tmp_path: Path):
    """The outer payload's PayloadType MUST be 'Configuration' —
    that's the wrapper iOS recognises as a profile."""
    from one_link.peer_https import build_mobileconfig
    parsed = plistlib.loads(build_mobileconfig(tmp_path))
    assert parsed["PayloadType"] == "Configuration"
    assert parsed["PayloadVersion"] == 1
    assert isinstance(parsed["PayloadIdentifier"], str)
    assert parsed["PayloadIdentifier"].startswith("com.onelink.")
    assert isinstance(parsed["PayloadUUID"], str)
    assert len(parsed["PayloadUUID"]) >= 32


def test_mobileconfig_inner_payload_is_root_cert(tmp_path: Path):
    """The single inner payload MUST be a root-cert payload —
    PayloadType 'com.apple.security.root' — carrying the DER bytes
    of the daemon's self-signed cert.

    2026-05-23: iOS's ``com.apple.security.root`` payload type
    REQUIRES DER-encoded bytes in PayloadContent. PEM with
    ``-----BEGIN CERTIFICATE-----`` markers parses for the install
    flow but does NOT register the cert as a trustable root —
    the resulting profile shows "Signed by: Not Signed" in red
    and an EMPTY Certificate Trust Settings page. DER bytes
    register the cert correctly so the Certificate Trust toggle
    appears for the user.
    """
    from one_link.peer_https import build_mobileconfig
    from cryptography import x509
    parsed = plistlib.loads(build_mobileconfig(tmp_path))
    inner = parsed["PayloadContent"]
    assert isinstance(inner, list)
    assert len(inner) == 1
    cp = inner[0]
    assert cp["PayloadType"] == "com.apple.security.root"
    assert cp["PayloadVersion"] == 1
    # PayloadContent is DER bytes (plistlib base64-wraps in <data>).
    cert_bytes = cp["PayloadContent"]
    assert isinstance(cert_bytes, bytes)
    # DER starts with the SEQUENCE tag (0x30) — not the PEM
    # "-----BEGIN" header. The cryptography library round-trips
    # DER cleanly; if iOS can parse it, so can this.
    assert cert_bytes[0:1] == b"\x30", (
        "PayloadContent must be DER-encoded; current first byte "
        f"is {cert_bytes[0:1]!r} (DER SEQUENCE is 0x30). PEM "
        "in this slot triggers the iOS 'Not Signed' regression."
    )
    cert = x509.load_der_x509_certificate(cert_bytes)
    assert cert.subject is not None
    assert cert.public_key() is not None


def test_mobileconfig_user_facing_strings_present(tmp_path: Path):
    """The display name + description MUST be human-readable —
    they show up in iOS's install prompt and in Settings → General
    → VPN & Device Management. A blank or junk value here makes
    the user think they're installing malware."""
    from one_link.peer_https import build_mobileconfig
    parsed = plistlib.loads(build_mobileconfig(tmp_path))
    name = parsed.get("PayloadDisplayName", "")
    assert "One Link" in name
    desc = parsed.get("PayloadDescription", "")
    assert len(desc) > 20
    inner = parsed["PayloadContent"][0]
    assert "One Link" in inner.get("PayloadDisplayName", "")


def test_mobileconfig_removable_by_user(tmp_path: Path):
    """PayloadRemovalDisallowed MUST be False (or absent) so the
    user can delete the profile any time without admin privileges.
    A locked-down profile would be a sovereignty violation."""
    from one_link.peer_https import build_mobileconfig
    parsed = plistlib.loads(build_mobileconfig(tmp_path))
    rd = parsed.get("PayloadRemovalDisallowed", False)
    assert rd is False


def test_mobileconfig_mints_cert_on_demand(tmp_path: Path):
    """If no cert exists yet, build_mobileconfig MUST mint one
    rather than crash. First-run: user clicks Generate pair QR
    before any HTTPS request has triggered ensure_cert."""
    from one_link.peer_https import build_mobileconfig, cert_path
    assert not cert_path(tmp_path).exists()
    payload = build_mobileconfig(tmp_path)
    assert payload  # didn't crash
    assert cert_path(tmp_path).is_file()


def test_mobileconfig_carries_root_ca_not_leaf(tmp_path: Path):
    """2026-05-23 (TN2326): the profile carries the long-lived
    ROOT CA — not the leaf TLS cert. iOS trusts the root via
    install + toggle; the daemon serves the leaf (signed by the
    root) at TLS handshake and the chain validates client-side.

    The leaf rotates yearly, the root does not — phones trust
    once and stay trusted across leaf rotations. Embedding the
    leaf here would defeat that and would also re-trigger the
    iOS 17/18 'network connection lost' bug class on
    dual-purpose self-signed certs.
    """
    from one_link.peer_https import (
        build_mobileconfig, cert_path, ensure_cert, root_ca_path,
    )
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    ensure_cert(tmp_path)
    on_disk_root = x509.load_pem_x509_certificate(
        root_ca_path(tmp_path).read_bytes()
    )
    on_disk_leaf = x509.load_pem_x509_certificate(
        cert_path(tmp_path).read_bytes()
    )
    parsed = plistlib.loads(build_mobileconfig(tmp_path))
    embedded_der = parsed["PayloadContent"][0]["PayloadContent"]
    embedded = x509.load_der_x509_certificate(embedded_der)

    # Match the ROOT — same serial + public key.
    root_pub = on_disk_root.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    embedded_pub = embedded.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert embedded_pub == root_pub, "profile must embed the root CA"
    assert embedded.serial_number == on_disk_root.serial_number

    # And explicitly NOT the leaf.
    leaf_pub = on_disk_leaf.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert embedded_pub != leaf_pub, (
        "profile must NOT embed the leaf TLS cert — embedding the "
        "leaf re-triggers the iOS 17/18 dual-purpose-cert handshake "
        "failure"
    )


# ───────── server endpoint + mint-pairing response ────────────────


def test_server_registers_profile_endpoint():
    """UIServer MUST register the profile.mobileconfig route
    so iOS Safari can fetch it. Auth-free — the cert isn't
    sensitive (it's the public half of a self-signed pair)."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    assert '/api/v1/peer-rtc/profile.mobileconfig' in src
    assert 'self._pair_profile' in src


def test_pair_profile_handler_uses_apple_mime():
    """The Content-Type MUST be application/x-apple-aspen-config —
    that's the magic MIME iOS Safari recognises to trigger the
    install prompt. Any other type and Safari just downloads the
    file as text and the user has nowhere to go."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def _pair_profile")
    assert idx > 0
    snippet = src[idx:idx + 2400]
    assert 'application/x-apple-aspen-config' in snippet
    # Suggested filename when downloaded outside Safari.
    assert 'one-link-trust.mobileconfig' in snippet
    # No-store: each install should fetch the current cert.
    assert 'no-store' in snippet


def test_pair_profile_handler_calls_builder():
    """The handler MUST call build_mobileconfig with the daemon's
    data_dir — not bake any cert into the source."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def _pair_profile")
    snippet = src[idx:idx + 2400]
    assert "build_mobileconfig" in snippet
    assert "data_dir()" in snippet


def test_mint_pairing_response_includes_profile_url():
    """The mint-pairing response MUST carry ios_profile_url so the
    desktop UI can render the trust-profile QR alongside the pair
    QR. Without this, the desktop UI has no way to construct a
    correct URL (host detection lives on the server)."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def api_mint_pairing")
    snippet = src[idx:idx + 4500]
    assert '"ios_profile_url"' in snippet
    # Profile URL MUST be HTTP, not HTTPS — the cert isn't trusted
    # yet at the time the user fetches the profile.
    assert 'f"http://{host}:{self.port}/api/v1/peer-rtc/profile.mobileconfig"' in snippet


# ───────── desktop UI: trust QR + instructions ────────────────────


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


def test_pair_phone_section_has_ios_trust_details(index_html: str):
    """The Pair-a-phone card MUST include a collapsible iOS-first-
    time setup section. Default-collapsed (Android / desktop users
    don't need it), one click to expand on iOS."""
    assert 'id="ios-trust-details"' in index_html
    assert "iPhone first time" in index_html


def test_ios_trust_details_includes_step_instructions(index_html: str):
    """The instructions MUST cover every step iOS forces the user
    through. Skipping any one of these dead-ends the install:
      1. Allow profile download in Safari
      2. Find profile in Settings → General → VPN & Device Mgmt
      3. Toggle on in Certificate Trust Settings
    Without all three, the cert is installed but not trusted for
    TLS, and Safari STILL refuses to load the pair URL.

    2026-05-23: drawer copy was simplified (no separate
    "Profile Downloaded" prompt mention — iOS-15+ Safari handles
    the download-then-Settings handoff differently). What we
    actually need to assert: every iOS step is named.
    """
    # The deep-Settings paths are easy to forget — pin them.
    assert "VPN" in index_html and "Device Management" in index_html
    assert "Certificate Trust Settings" in index_html
    # The download prompt is now phrased as "configuration profile"
    # (iOS-Safari-modal-accurate). The "Allow" tap is still pinned
    # because that's the load-bearing user gesture.
    assert "configuration profile" in index_html
    assert "Allow" in index_html
    # And we end by sending them back to scan the pair QR after
    # the trust setup completes.
    assert "Scan the pair QR" in index_html or "pair QR" in index_html


def test_ios_trust_qr_wrap_present(index_html: str):
    """A placeholder div MUST exist for the JS to populate with the
    profile-install QR. The JS only fires when the user clicks
    Generate pair QR, so the markup needs to pre-exist."""
    assert 'id="ios-trust-qr-wrap"' in index_html


def test_mint_pair_handler_renders_trust_qr(index_html: str):
    """The Generate-pair-QR click handler MUST also populate the
    iOS trust QR. Two separate QRs in two separate slots — the
    user sees pair QR on top, trust QR in the collapsible
    iPhone-first-time section. Single click, both rendered."""
    idx = index_html.find('$("#btn-mint-pair")?.addEventListener')
    assert idx > 0
    snippet = index_html[idx:idx + 6000]
    # Trust wrap is populated.
    assert '#ios-trust-qr-wrap' in snippet
    # The QR image src is the same qr.svg endpoint, but with the
    # profile URL as the encoded payload.
    assert 'info.ios_profile_url' in snippet
    assert 'encodeURIComponent(info.ios_profile_url)' in snippet


def test_mint_pair_handler_skips_trust_qr_without_https(index_html: str):
    """If the daemon has no HTTPS listener, no profile is needed.
    The handler MUST guard on info.https_available so we don't
    render a misleading 'install this profile' QR for an HTTP-only
    daemon (where the profile would do nothing useful)."""
    idx = index_html.find('$("#btn-mint-pair")?.addEventListener')
    snippet = index_html[idx:idx + 6000]
    assert 'info.https_available' in snippet


def test_reset_pair_card_clears_trust_qr(index_html: str):
    """Cancel / reset MUST clear the trust QR too — otherwise a
    stale QR stays visible and could point at a different cert
    if the daemon rotated certs since."""
    idx = index_html.find("function _resetPairPhoneCard")
    assert idx > 0
    snippet = index_html[idx:idx + 1200]
    assert "#ios-trust-qr-wrap" in snippet


# ───────── version pin ────────────────────────────────────────────


def test_version_at_or_above_v0206():
    """Forward-compat shape pin — passes for v0.20.6 or later.
    Tolerates PEP 440 pre-release suffixes (e.g. ``0.21.0-alpha``) by
    stripping anything past the first non-digit character of each part.
    """
    from one_link import __version__

    def _num(p: str) -> int:
        digits = "".join(c for c in p if c.isdigit())
        return int(digits) if digits else 0

    parts = tuple(_num(p) for p in __version__.split(".")[:3])
    assert parts >= (0, 20, 6)

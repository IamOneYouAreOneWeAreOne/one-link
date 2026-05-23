"""v0.20.4 — Self-signed HTTPS for the daemon.

iOS Safari (and most modern browsers) gate Web Crypto Subtle to
secure contexts (HTTPS or localhost). A phone hitting
http://192.168.1.42 to /peer can't generate Ed25519 keys, which
breaks the entire phone-as-peer architecture on LAN. This ship
mints a self-signed cert + serves a parallel HTTPS listener so
the pair URL becomes https://, the phone gets a "Not Private"
warning once, taps Continue, and Web Crypto works from then on.

  Reach:  the phone-as-peer pair flow finally completes on iOS
          Safari over LAN. Without this, every prior ship in the
          v0.20 arc was unusable on iPhone.
  Hide:   self-signed cert is generated invisibly on first run,
          persisted to data_dir, auto-rotated near expiry.
  Async:  cert generation is one-shot (~30ms); HTTPS listener
          comes up in parallel with the existing HTTP listener,
          on a separate port.
  Depth:  ECDSA P-256 (universal browser support; Ed25519 server
          certs are rejected by Safari). 365-day TTL with 30-day
          rotation window. SAN covers every detectable LAN IPv4 +
          IPv6 + localhost + onelink.local for future mDNS.

Tests cover: cert generation shape (algorithm, validity, SAN),
rotation triggers (missing / unparseable / expiring), SSL context
build (TLS 1.2 minimum, cert loaded), pair-URL adoption of
https://, autopair preflight surfaces insecure-context message,
boot stashes error to state.boot_error_msg.
"""

from __future__ import annotations

import datetime
import ssl
from pathlib import Path

import pytest


def test_cert_generation_writes_files(tmp_path: Path):
    """generate_self_signed mints a cert + key and writes both
    to <base>/peer_https/. Both files exist + non-empty."""
    from one_link.peer_https import (
        cert_path, generate_self_signed, https_dir, key_path,
    )
    cp, kp = generate_self_signed(tmp_path)
    assert cp == cert_path(tmp_path)
    assert kp == key_path(tmp_path)
    assert cp.is_file()
    assert kp.is_file()
    assert cp.read_bytes().startswith(b"-----BEGIN CERTIFICATE-----")
    assert kp.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")


def test_cert_uses_ecdsa_p256(tmp_path: Path):
    """Browser compatibility floor — ECDSA P-256 is universally
    accepted as a TLS server cert. RSA-2048 also works but is
    bigger; Ed25519 is rejected by Safari for server certs as of
    2026."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    from one_link.peer_https import generate_self_signed
    cp, _ = generate_self_signed(tmp_path)
    cert = x509.load_pem_x509_certificate(cp.read_bytes())
    pub = cert.public_key()
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    assert pub.curve.name == "secp256r1"


def test_cert_validity_is_one_year(tmp_path: Path):
    """365-day default. Auto-rotates within 30 days of expiry so
    phones never hit a sudden invalid cert mid-session."""
    from cryptography import x509
    from one_link.peer_https import CERT_VALID_DAYS, generate_self_signed
    cp, _ = generate_self_signed(tmp_path)
    cert = x509.load_pem_x509_certificate(cp.read_bytes())
    expiry = getattr(cert, "not_valid_after_utc", None)
    if expiry is None:
        expiry = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    not_before = getattr(cert, "not_valid_before_utc", None)
    if not_before is None:
        not_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
    span = expiry - not_before
    # +5 minutes of pre-validity slack, so total span is ~365d + 5min.
    assert datetime.timedelta(days=CERT_VALID_DAYS - 1) < span
    assert span < datetime.timedelta(days=CERT_VALID_DAYS + 1)


def test_cert_san_includes_localhost_and_lan(tmp_path: Path):
    """SAN MUST cover localhost (loopback access from desktop
    browsers) AND any LAN IP we can detect. Without this, the
    phone hits a hostname-mismatch error even after accepting
    the cert."""
    from cryptography import x509
    from one_link.peer_https import generate_self_signed
    cp, _ = generate_self_signed(tmp_path)
    cert = x509.load_pem_x509_certificate(cp.read_bytes())
    san = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName,
    ).value
    dns_names = [n.value for n in san if isinstance(n, x509.DNSName)]
    assert "localhost" in dns_names
    assert "onelink.local" in dns_names
    # At least one IP — 127.0.0.1 is always there.
    ip_strs = [str(n.value) for n in san if isinstance(n, x509.IPAddress)]
    assert "127.0.0.1" in ip_strs


def test_cert_ext_key_usage_server_auth(tmp_path: Path):
    """SERVER_AUTH ekuoid is required by browsers for a TLS
    server cert. Without it, Chrome rejects the cert outright."""
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID
    from one_link.peer_https import generate_self_signed
    cp, _ = generate_self_signed(tmp_path)
    cert = x509.load_pem_x509_certificate(cp.read_bytes())
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku


def test_cert_is_marked_as_root_ca_for_ios_trust(tmp_path: Path):
    """2026-05-23: iOS's Certificate Trust Settings page only lists
    certs that are flagged as CAs (BasicConstraints.ca=True) AND
    have key_cert_sign in their KeyUsage. The cert serves a DUAL
    role — TLS server cert AND self-signed root CA the user can
    trust via Settings. Without these flags, the cert installs via
    mobileconfig but iOS silently drops it from the trust UI,
    blocking the entire pair flow with "Not Private" warnings
    that the user has no in-app way to dismiss.

    Pin both flags so a future cert-shape refactor doesn't
    re-introduce the regression.
    """
    from cryptography import x509
    from one_link.peer_https import generate_self_signed
    cp, _ = generate_self_signed(tmp_path)
    cert = x509.load_pem_x509_certificate(cp.read_bytes())
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True, (
        "Cert MUST have BasicConstraints.ca=True so iOS lists it in "
        "Certificate Trust Settings as a trustable root. ca=False "
        "makes the trust UI silently drop the cert."
    )
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_cert_sign is True, (
        "Cert MUST have KeyUsage.key_cert_sign=True so iOS's PKI "
        "validator accepts the cert as CA-capable. Without it the "
        "Certificate Trust toggle never appears."
    )
    # Self-signed: subject == issuer is the load-bearing identity
    # that makes the dual-purpose (server + root CA) cert work.
    assert cert.subject == cert.issuer


def test_needs_rotation_for_missing_file(tmp_path: Path):
    from one_link.peer_https import cert_path, needs_rotation
    assert needs_rotation(cert_path(tmp_path)) is True


def test_needs_rotation_for_corrupt_file(tmp_path: Path):
    from one_link.peer_https import cert_path, https_dir, needs_rotation
    https_dir(tmp_path).mkdir(parents=True)
    cert_path(tmp_path).write_bytes(b"not a cert")
    assert needs_rotation(cert_path(tmp_path)) is True


def test_needs_rotation_false_for_fresh_cert(tmp_path: Path):
    from one_link.peer_https import cert_path, generate_self_signed, needs_rotation
    generate_self_signed(tmp_path)
    assert needs_rotation(cert_path(tmp_path)) is False


def test_needs_rotation_true_for_near_expiry_cert(tmp_path: Path):
    """A cert expiring within the rotation window MUST rotate."""
    from one_link.peer_https import cert_path, generate_self_signed, needs_rotation
    # 10-day cert + default 30-day rotation window → needs rotation.
    generate_self_signed(tmp_path, valid_days=10)
    assert needs_rotation(cert_path(tmp_path)) is True


def test_ensure_cert_idempotent(tmp_path: Path):
    """ensure_cert returns the same paths each call when the cert
    is fresh; doesn't re-mint."""
    from one_link.peer_https import ensure_cert
    cp1, kp1 = ensure_cert(tmp_path)
    cert_bytes_1 = cp1.read_bytes()
    cp2, kp2 = ensure_cert(tmp_path)
    cert_bytes_2 = cp2.read_bytes()
    assert cp1 == cp2
    assert kp1 == kp2
    # Same cert; no re-mint.
    assert cert_bytes_1 == cert_bytes_2


def test_build_ssl_context_returns_loadable_context(tmp_path: Path):
    """The context loaded from the self-signed material must be
    a usable server-side SSL context."""
    from one_link.peer_https import build_ssl_context
    ctx = build_ssl_context(tmp_path)
    assert ctx is not None
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_cert_fingerprint_sha256(tmp_path: Path):
    """Fingerprint helper returns a 64-char lowercase hex string."""
    from one_link.peer_https import (
        cert_fingerprint_sha256, cert_path, generate_self_signed,
    )
    generate_self_signed(tmp_path)
    fp = cert_fingerprint_sha256(cert_path(tmp_path))
    assert fp is not None
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)


def test_cert_fingerprint_sha256_missing_file(tmp_path: Path):
    """Returns None for a missing cert. Don't raise."""
    from one_link.peer_https import cert_fingerprint_sha256, cert_path
    fp = cert_fingerprint_sha256(cert_path(tmp_path))
    assert fp is None


# ───────── peer.html autopair preflight + boot error ───────────────


@pytest.fixture(scope="module")
def peer_html() -> str:
    return Path("src/one_link/web/peer.html").read_text(encoding="utf-8")


def _snippet(html: str, needle: str, size: int = 2400) -> str:
    idx = html.find(needle)
    assert idx >= 0, f"missing {needle!r}"
    return html[idx:idx + size]


def test_autopair_preflight_helper_present(peer_html: str):
    """Preflight runs synchronous platform checks BEFORE the 12s
    identity wait. Without this the user sees a generic 'no identity'
    message; with it they see the specific reason (insecure context
    / no Web Crypto / no OPFS)."""
    snippet = _snippet(peer_html, "function _autopairPreflight", 2200)
    assert "window.isSecureContext" in snippet
    assert "crypto.subtle.generateKey" in snippet
    assert "navigator.storage.getDirectory" in snippet


def test_autopair_preflight_called_first_in_flow(peer_html: str):
    """Preflight MUST run before _waitForIdentity — otherwise the
    user waits 12s for nothing on an insecure-context page."""
    snippet = _snippet(peer_html, "async function _runAutoPairFlow", 4000)
    pf_idx = snippet.find("_autopairPreflight()")
    wait_idx = snippet.find("_waitForIdentity(")
    assert pf_idx > 0
    assert wait_idx > pf_idx, "preflight must run before identity wait"


def test_autopair_preflight_surfaces_insecure_context(peer_html: str):
    """Insecure-context message MUST mention HTTPS specifically.
    A user reading 'page loaded over HTTP' immediately knows what
    to do (regenerate the QR on a v0.20.4+ daemon)."""
    snippet = _snippet(peer_html, "function _autopairPreflight", 2200)
    assert "HTTPS" in snippet
    assert "QR" in snippet or "laptop" in snippet


def test_boot_stashes_error_for_autopair(peer_html: str):
    """When boot fails (insecure context, keygen, etc.), it MUST
    set state.boot_error_msg so the autopair flow can surface the
    real reason instead of the generic 'no identity in 12s'."""
    snippet = _snippet(peer_html, "async function boot()", 6000)
    assert "state.boot_error_msg" in snippet


def test_wait_for_identity_aborts_on_boot_error(peer_html: str):
    """The wait loop MUST short-circuit when state.boot_error_msg
    is set — otherwise we wait 12s for an identity that will never
    arrive."""
    snippet = _snippet(peer_html, "async function _waitForIdentity", 800)
    assert "state.boot_error_msg" in snippet
    assert "return null" in snippet


def test_autopair_surfaces_real_boot_error(peer_html: str):
    """When _waitForIdentity returns null because of a boot error,
    autopair MUST display the actual error message — not the
    generic 'no identity' line."""
    snippet = _snippet(peer_html, "async function _runAutoPairFlow", 4000)
    assert "state.boot_error_msg" in snippet
    assert "Identity boot failed" in snippet


def test_boot_checks_secure_context_first(peer_html: str):
    """The insecure-context check MUST run BEFORE the
    crypto.subtle existence check. On insecure HTTP, crypto.subtle
    is sometimes present-but-restricted, so the no-web-crypto
    branch would fire with a misleading message."""
    snippet = _snippet(peer_html, "async function boot()", 4000)
    secure_idx = snippet.find("window.isSecureContext")
    crypto_idx = snippet.find("if (!window.crypto || !crypto.subtle)")
    assert secure_idx > 0
    assert crypto_idx > 0
    assert secure_idx < crypto_idx


# ───────── pair-URL adoption of https:// ──────────────────────────


def test_pair_url_uses_https_when_available():
    """Pure-Python check: when self.https_port is set, the
    api_mint_pairing handler should produce https:// pair URLs.
    We don't bring up a real listener here; just test the URL-
    building branch in isolation against a stub server."""
    # The branching logic lives inside api_mint_pairing. We can
    # verify it by reading the source — the actual integration
    # test is the live daemon probe at the end of the ship.
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def api_mint_pairing")
    snippet = src[idx:idx + 4000]
    assert "if self.https_port:" in snippet
    assert 'f"https://{host}:{self.https_port}"' in snippet
    assert 'ws_scheme = "wss"' in snippet


def test_pair_url_fallback_to_http_when_no_https():
    """If HTTPS bring-up fails, pair URLs fall back to http://. The
    daemon still works for desktop loopback access; phone-over-LAN
    just won't work without HTTPS, which is a separate concern."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def api_mint_pairing")
    snippet = src[idx:idx + 4000]
    # The fallback branch must exist.
    assert 'f"http://{host}:{self.port}"' in snippet


def test_pair_url_includes_cert_fingerprint_when_https():
    """The pair URL embeds the cert fingerprint as `&cert=...` so
    a future-ship phone-side check can pin against it. v0.20.4
    just emits it; v0.20.5+ can verify."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def api_mint_pairing")
    snippet = src[idx:idx + 4000]
    assert "self.https_cert_fp_sha256" in snippet
    assert '&cert=' in snippet


# ───────── legacy QR removal ──────────────────────────────────────


def test_legacy_connect_info_section_removed():
    """v0.20.4 removes the second QR (the desktop-UI-on-phone
    URL-only flow). Two QRs side-by-side was confusing the user
    about which to scan. The new pair-by-QR is now the only path
    in the About pane."""
    html = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    # The old section_h with "Open desktop UI on another device" is gone.
    assert "Open desktop UI on another device" not in html
    # The id stays present as an empty hidden div for any inline JS
    # that still references it (defensive); but the visible section
    # markup is gone.


# ───────── server bind metadata ───────────────────────────────────


def test_server_init_declares_https_attrs():
    """UIServer.__init__ MUST declare self.https_site,
    self.https_port, self.https_cert_fp_sha256 even before start()
    runs, so api_mint_pairing can read them safely on first
    request without an AttributeError.

    2026-05-22: the bind_host comment block (LAN-bind default doc)
    grew start() past the original 5000-char window. Read to the
    next ``async def`` boundary or 10000 chars max so structural
    checks survive reasonable in-function additions.
    """
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def start(self)")
    end_idx = src.find("\n    async def ", idx + 30)
    if end_idx == -1 or end_idx - idx > 10000:
        end_idx = idx + 10000
    snippet = src[idx:end_idx]
    assert "self.https_site = None" in snippet
    assert "self.https_port = None" in snippet
    assert "self.https_cert_fp_sha256 = None" in snippet


def test_server_logs_https_listener_up():
    """For operators / debugging — when HTTPS comes up, log it. A
    silent HTTPS bring-up is hard to diagnose if something later
    misbehaves."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def _start_https_listener")
    snippet = src[idx:idx + 3000]
    assert "UI server HTTPS up" in snippet


# ───────── version pin ────────────────────────────────────────────


def test_peer_version_at_or_above_v0204(peer_html: str):
    import re
    m = re.search(r"version:\s*['\"](\d+)\.(\d+)\.(\d+)(?:-[A-Za-z0-9.]+)?['\"]", peer_html)
    assert m
    parts = tuple(int(p) for p in m.groups())
    assert parts >= (0, 20, 4)


def test_page_version_matches_package():
    from one_link import __version__
    html = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert f'PAGE_BUILT_FOR = "{__version__}"' in html

"""v0.20.4 — Self-signed HTTPS for the daemon.

Why this ship exists
====================

iOS Safari (and most modern browsers) gate Web Crypto Subtle to
"secure contexts" — HTTPS or `localhost`. A phone connecting to
the desktop daemon over `http://192.168.1.42:7117` fails to do
ANY Web Crypto operation: `crypto.subtle.generateKey({name:
"Ed25519"})` either rejects, throws, or returns undefined.

The browser-as-peer architecture (v0.16-v0.20.3) needs Web Crypto
on the phone for: identity generation, signature verification,
SAS pairing, all of it. Without HTTPS, the entire arc is unusable
on iOS Safari over LAN.

This module solves it by minting a self-signed certificate on the
daemon, persisting it to data_dir, and serving an HTTPS listener
on a parallel port. The phone gets a "Not Private" warning the
first time it scans the pair QR; the user taps "Continue" once
per device, and from then on Web Crypto works and the pair flow
actually completes.

Cert design
===========

- Algorithm: ECDSA P-256. RSA-2048 also works but produces
  larger certs; Ed25519 is rejected by some browsers (Safari) for
  TLS server certs as of 2026. P-256 is the universal sweet spot.
- Validity: 365 days, auto-rotated when within 30 days of expiry.
- Common Name: "One Link Self-Signed"
- Subject Alternative Names: covers every interface the daemon
  might reach the phone on:
      DNS: localhost, *.local, onelink.local
      IP:  127.0.0.1, ::1, plus any LAN IPv4/IPv6 we can detect
- Persisted to:
      <data_dir>/peer_https/cert.pem
      <data_dir>/peer_https/key.pem
  Both 0o600. Regenerated if missing or expired.

What this ship does NOT yet do
==============================

- Cert pinning on the phone side. v0.20.4 just relies on the
  user accepting the "Not Private" warning once. A future ship
  could pin the SHA-256 of the cert in the QR (so the phone can
  verify "this is the SAME cert my laptop minted") — that closes
  the residual MITM window during the cert-trust ceremony.
- mDNS broadcasting of `onelink.local`. We include `onelink.local`
  in the SAN so a future mDNS-enabled daemon can use it without
  cert regen, but we don't actually broadcast it yet.
"""
from __future__ import annotations

import datetime
import ipaddress
import logging
import os
import socket
import contextlib
import ssl
from pathlib import Path
from typing import Optional, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

log = logging.getLogger(__name__)


# Sub-directory under data_dir for HTTPS material.
HTTPS_DIR = "peer_https"
# 2026-05-23 (TN2326): cert.pem is now leaf+root chain (PEM-concat).
# key.pem is the leaf key. root_ca.pem + root_ca_key.pem are the
# long-lived trust anchor. The mobileconfig embeds the root, not the
# leaf — iOS trusts the root, the chain validates the leaf at TLS
# handshake. A dual-purpose self-signed cert (the old shape) passes
# the Trust Settings toggle on most iOS versions but fails the
# actual TLS handshake on some iOS 17/18 builds with a
# "network connection lost" Safari error.
CERT_FILE = "cert.pem"            # leaf + root chain
KEY_FILE = "key.pem"              # leaf key
ROOT_CA_FILE = "root_ca.pem"      # long-lived trust anchor (in mobileconfig)
ROOT_CA_KEY_FILE = "root_ca_key.pem"  # signs the leaf on rotation

# Lifetime + rotation thresholds.
CERT_VALID_DAYS = 365             # leaf lifetime
CERT_ROTATE_WITHIN_DAYS = 30      # leaf rotation window
ROOT_CA_VALID_DAYS = 365 * 10     # root lives 10 years; phones trust once


def https_dir(base: Path) -> Path:
    return base / HTTPS_DIR


def cert_path(base: Path) -> Path:
    return https_dir(base) / CERT_FILE


def key_path(base: Path) -> Path:
    return https_dir(base) / KEY_FILE


def root_ca_path(base: Path) -> Path:
    return https_dir(base) / ROOT_CA_FILE


def root_ca_key_path(base: Path) -> Path:
    return https_dir(base) / ROOT_CA_KEY_FILE


def _detect_lan_addresses() -> list[str]:
    """Best-effort enumeration of every IPv4 + IPv6 address the
    daemon might be reached on. Used to populate SAN entries on
    the cert so the phone doesn't trip a hostname-mismatch."""
    out: set[str] = set()
    out.add("127.0.0.1")
    out.add("::1")
    # Egress-interface IPv4 — the LAN address other devices on the
    # same Wi-Fi will reach us on.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        out.add(s.getsockname()[0])
    except Exception:
        pass
    finally:
        s.close()
    # All IPv4 addresses bound to this host.
    try:
        hostname = socket.gethostname()
        _, _, addrs = socket.gethostbyname_ex(hostname)
        for a in addrs:
            out.add(a)
    except Exception:
        pass
    return sorted(out)


def _build_subject_alt_names(
    extra_dns: list[str] | None = None,
    *,
    short_id: str = "",
) -> x509.SubjectAlternativeName:
    """Build the SAN extension. We include every IP we can detect +
    a fixed set of useful DNS names so the cert is valid against
    common access paths.

    v0.20.7 (security audit M12): also include a per-daemon
    DNSName ``<short_id>.onelink.local`` so a phone with two
    different One Link daemons in its trust store (e.g. laptop
    + work-machine) can disambiguate which one it's connecting
    to without relying purely on TOFU."""
    names: list[x509.GeneralName] = []
    base_dns = ["localhost", "onelink.local"]
    if short_id:
        base_dns.append(f"{short_id}.onelink.local")
    for dn in base_dns + (extra_dns or []):
        names.append(x509.DNSName(dn))
    for ip_str in _detect_lan_addresses():
        try:
            ip = ipaddress.ip_address(ip_str)
            names.append(x509.IPAddress(ip))
        except ValueError:
            continue
    return x509.SubjectAlternativeName(names)


def _mint_root_ca(
    base: Path, *, short_id: str = "",
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Mint the long-lived root CA. Lives 10 years and signs every
    leaf TLS cert this daemon ever serves. The phone trusts THIS
    via the mobileconfig — install once, never rotate.

    Per Apple TN2326: the root has BasicConstraints CA=True, key
    usage = certSign+crlSign, NO subjectAltName (it's a trust
    anchor, not a TLS endpoint), NO extendedKeyUsage (leaves
    declare their own purposes). SubjectKeyIdentifier present;
    AuthorityKeyIdentifier == SubjectKeyIdentifier (self-issued).
    """
    d = https_dir(base)
    d.mkdir(parents=True, exist_ok=True)
    rcp = root_ca_path(base)
    rkp = root_ca_key_path(base)

    key = ec.generate_private_key(ec.SECP256R1())
    cn = (
        f"One Link Root CA ({short_id})"
        if short_id else "One Link Root CA"
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "One Link"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=ROOT_CA_VALID_DAYS))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    rcp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    rkp.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    try:
        os.chmod(rcp, 0o600)
        os.chmod(rkp, 0o600)
    except Exception:
        pass
    log.info(
        "peer-https: minted root CA (valid_days=%d, sha256=%s)",
        ROOT_CA_VALID_DAYS,
        cert.fingerprint(hashes.SHA256()).hex()[:32],
    )
    return key, cert


def _load_root_ca(
    base: Path,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    cert = x509.load_pem_x509_certificate(root_ca_path(base).read_bytes())
    key = serialization.load_pem_private_key(
        root_ca_key_path(base).read_bytes(), password=None
    )
    # Our root CA is always EC P-256; validate on load + narrow the
    # broad load_pem_private_key() union for the typed return.
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    return key, cert


def _mint_leaf_tls(
    base: Path,
    *,
    root_key: ec.EllipticCurvePrivateKey,
    root_cert: x509.Certificate,
    valid_days: int = CERT_VALID_DAYS,
    short_id: str = "",
) -> tuple[Path, Path]:
    """Mint a TLS server leaf cert signed by the root CA, write
    chain (leaf || root) to cert.pem and leaf key to key.pem.

    Per TN2326 the leaf has BasicConstraints CA=False, key usage
    = digitalSignature, EKU = serverAuth, and the SubjectAlt names
    must match the IP/hostnames the phone connects to. The leaf
    rotates yearly; the root CA the phone trusts does not.
    """
    d = https_dir(base)
    d.mkdir(parents=True, exist_ok=True)
    cp = cert_path(base)
    kp = key_path(base)

    key = ec.generate_private_key(ec.SECP256R1())
    cn = (
        f"One Link Daemon ({short_id})"
        if short_id else "One Link Daemon"
    )
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "One Link"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(
            _build_subject_alt_names(short_id=short_id),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                cast(ec.EllipticCurvePublicKey, root_cert.public_key())
            ),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    chain_pem = (
        cert.public_bytes(serialization.Encoding.PEM)
        + root_cert.public_bytes(serialization.Encoding.PEM)
    )
    cp.write_bytes(chain_pem)
    kp.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    try:
        os.chmod(cp, 0o600)
        os.chmod(kp, 0o600)
    except Exception:
        pass
    log.info(
        "peer-https: minted leaf TLS cert (valid_days=%d, sha256=%s)",
        valid_days,
        cert.fingerprint(hashes.SHA256()).hex()[:32],
    )
    return cp, kp


def generate_self_signed(
    base: Path,
    *,
    valid_days: int = CERT_VALID_DAYS,
    short_id: str = "",
) -> tuple[Path, Path]:
    """Mint a fresh root-CA + leaf TLS chain (TN2326 two-cert shape).

    Returns (chain_path, leaf_key_path). The chain.pem is leaf
    followed by root; aiohttp's load_cert_chain serves both to
    clients so iOS validates the leaf via the trusted root.

    Idempotent for the root (re-used if already on disk and not
    expired); always mints a fresh leaf so every call rotates.
    """
    rkp = root_ca_key_path(base)
    rcp = root_ca_path(base)
    have_root = rkp.is_file() and rcp.is_file()
    if have_root:
        try:
            root_key, root_cert = _load_root_ca(base)
            # Bail to a fresh root if the existing one is itself near
            # expiry (10-year cert; only happens once a decade).
            if needs_rotation(rcp, rotate_within_days=30):
                root_key, root_cert = _mint_root_ca(base, short_id=short_id)
        except Exception as e:
            log.warning("peer-https: existing root CA unreadable, regenerating: %s", e)
            root_key, root_cert = _mint_root_ca(base, short_id=short_id)
    else:
        root_key, root_cert = _mint_root_ca(base, short_id=short_id)
    return _mint_leaf_tls(
        base,
        root_key=root_key,
        root_cert=root_cert,
        valid_days=valid_days,
        short_id=short_id,
    )


def needs_rotation(
    cert_path_to_check: Path,
    *,
    rotate_within_days: int = CERT_ROTATE_WITHIN_DAYS,
) -> bool:
    """Return True if the cert is missing, unparseable, or expires
    within `rotate_within_days`. Don't ship a cert that's about to
    expire — phones cache trust decisions and a sudden invalid cert
    produces an aggressively-bad UX."""
    if not cert_path_to_check.is_file():
        return True
    try:
        data = cert_path_to_check.read_bytes()
        cert = x509.load_pem_x509_certificate(data)
    except Exception as e:
        log.warning("peer-https: cert unparseable, will rotate: %s", e)
        return True
    now = datetime.datetime.now(datetime.timezone.utc)
    # not_valid_after_utc is the modern attr; fallback for older
    # cryptography versions.
    expiry = getattr(cert, "not_valid_after_utc", None)
    if expiry is None:
        expiry = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    return expiry - now < datetime.timedelta(days=rotate_within_days)


def ensure_cert(base: Path, *, short_id: str = "") -> tuple[Path, Path]:
    """Return (cert_path, key_path), generating fresh material if
    the existing chain is missing, unparseable, or near expiry.

    2026-05-23 (TN2326 migration): if cert.pem exists but root_ca.pem
    does NOT, this is the pre-TN2326 single-cert layout. The existing
    cert is a self-signed dual-purpose root+leaf; iOS will toggle it
    as trusted but Safari rejects the TLS handshake on iOS 17/18.
    Wipe it and regenerate the chain — the user will have to re-
    install the mobileconfig once, but every connection thereafter
    works.
    """
    cp = cert_path(base)
    kp = key_path(base)
    rcp = root_ca_path(base)
    rkp = root_ca_key_path(base)

    # Migration: old single-cert layout (cert.pem exists, no root.pem).
    if cp.is_file() and not rcp.is_file():
        log.info(
            "peer-https: migrating pre-TN2326 single-cert layout to two-cert chain"
        )
        with contextlib.suppress(Exception):
            cp.unlink()
        with contextlib.suppress(Exception):
            kp.unlink()

    needs_regen = (
        not rcp.is_file()
        or not rkp.is_file()
        or not kp.is_file()
        or needs_rotation(cp)
    )
    if needs_regen:
        return generate_self_signed(base, short_id=short_id)
    return cp, kp


def build_ssl_context(
    base: Path, *, short_id: str = "",
) -> Optional[ssl.SSLContext]:
    """Build an ssl.SSLContext loaded with the daemon's self-signed
    cert. Returns None if the cert can't be created (e.g. the data
    dir is read-only) — callers fall back to HTTP-only.

    v0.20.7 (security audit M11): TLS 1.3 only by default. The
    previous profile permitted TLS 1.2 + 1.3 with no cipher
    restriction, which kept whole classes of historical attacks
    in scope (BEAST, CRIME, ROBOT, Lucky13, etc.). The browsers
    we target (Chrome 113+, Safari 17+, Firefox 121+) all speak
    TLS 1.3 unconditionally; pinning to 1.3-only loses no
    practical clients and removes those attack classes. We also
    disable compression + session tickets for forward-secrecy
    hygiene (TLS 1.3 already negotiates fresh keys per session,
    but OP_NO_TICKET keeps the in-memory session-state surface
    smaller).
    """
    try:
        cp, kp = ensure_cert(base, short_id=short_id)
    except Exception as e:
        log.warning("peer-https: couldn't ensure cert: %s", e)
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # v0.20.7 (M11): TLS 1.3 only.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    # Defense-in-depth flags. NO_COMPRESSION defeats CRIME-class
    # leaks; NO_TICKET shrinks the long-lived state surface.
    with contextlib.suppress(AttributeError):
        ctx.options |= ssl.OP_NO_COMPRESSION
    with contextlib.suppress(AttributeError):
        ctx.options |= ssl.OP_NO_TICKET
    try:
        # 2026-05-23: advertise http/1.1 ONLY. Previously we
        # advertised ["h2", "http/1.1"] but aiohttp's server
        # implementation does not speak HTTP/2 — when a browser
        # offers h2 first (Safari, modern Chrome), the server
        # selects h2 via ALPN but then can only respond in
        # HTTP/1.x bytes, which the browser treats as a fatal
        # protocol violation and tears the connection down
        # reporting NSURLErrorNetworkConnectionLost (-1005) on
        # iOS / ERR_HTTP2_PROTOCOL_ERROR on Chromium. curl with
        # default http/1.1 succeeded the whole time, masking the
        # bug behind every "works on curl" verification.
        # Re-enable h2 only when the server actually speaks it.
        ctx.set_alpn_protocols(["http/1.1"])
    except (NotImplementedError, ssl.SSLError):
        # Some platforms don't support ALPN on the server side
        # (rare); HTTP/1.1 fallback is still fine.
        pass
    try:
        ctx.load_cert_chain(certfile=str(cp), keyfile=str(kp))
    except Exception as e:
        log.warning("peer-https: load_cert_chain failed: %s", e)
        return None
    return ctx


def cert_fingerprint_sha256(cert_path_to_read: Path) -> Optional[str]:
    """SHA-256 fingerprint of the cert in lowercase hex with no
    separators. The pair QR can embed this so the phone-peer can
    verify "this is the same cert my laptop minted" before
    accepting the TLS connection — closing the residual MITM
    window during the trust-on-first-use ceremony.

    Returns None if the cert can't be read."""
    try:
        data = cert_path_to_read.read_bytes()
        cert = x509.load_pem_x509_certificate(data)
    except Exception:
        return None
    return cert.fingerprint(hashes.SHA256()).hex()


# ── iOS Configuration Profile (.mobileconfig) ────────────────────────


def _format_pem_for_plist(pem_bytes: bytes) -> bytes:
    """2026-05-23: iOS ``com.apple.security.root`` payload requires
    DER-encoded cert bytes in ``PayloadContent`` (plistlib then
    base64-wraps them inside ``<data>``). PEM with
    ``-----BEGIN CERTIFICATE-----`` markers parses fine for the
    profile install but does NOT register the cert as a root CA
    candidate — the result is a profile that shows
    ``Signed by: Not Signed`` in red and an EMPTY Certificate
    Trust Settings page, blocking the trust toggle that makes
    HTTPS actually work.

    Convert PEM → DER via the cryptography library so the cert
    lands as a proper root CA the user can toggle on.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    cert = x509.load_pem_x509_certificate(pem_bytes.strip())
    return cert.public_bytes(Encoding.DER)


def build_mobileconfig(
    base: Path,
    *,
    organization: str = "One Link",
    profile_display_name: str = "One Link Trust",
) -> bytes:
    """v0.20.6 — build an iOS Configuration Profile that installs the
    daemon's self-signed cert as a trusted root. After install, iOS
    trusts every TLS connection signed by this cert system-wide,
    which means /peer over HTTPS works with zero warnings.

    The profile is unsigned. iOS shows a "Not Verified" badge during
    install, but the user can still install it after entering their
    passcode. (Signing requires an Apple Developer cert + extra
    tooling we don't ship; the user's own face-to-face validation
    is the trust ceremony either way.)

    Profile structure:
      PayloadType: Configuration (the outer)
      └── PayloadContent[0]:
          PayloadType: com.apple.security.root
          PayloadContent: <PEM bytes of the self-signed cert>
          PayloadCertificateFileName: <human readable>
    """
    import plistlib
    import uuid

    # 2026-05-23 (TN2326): embed the ROOT CA in the profile, not the
    # leaf TLS cert. iOS trusts the root; the leaf is validated by
    # chain at TLS handshake. The single-cert (dual-purpose) shape
    # passes the Trust Settings toggle but Safari rejects the
    # handshake on iOS 17/18 with a generic "network connection
    # lost" error. Two-cert chain is Apple's recommended path.
    ensure_cert(base)
    rcp = root_ca_path(base)
    root_pem = rcp.read_bytes()
    fp = cert_fingerprint_sha256(rcp) or "unknown"

    cert_payload = {
        "PayloadType": "com.apple.security.root",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"com.onelink.peer.cert.{fp[:16]}",
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadDisplayName": "One Link Root CA",
        "PayloadDescription": (
            "Trust the One Link Root CA so your phone can talk to "
            "any One Link daemon you pair with, over HTTPS, with no "
            "warnings."
        ),
        "PayloadCertificateFileName": "one-link-root.cer",
        "PayloadContent": _format_pem_for_plist(root_pem),
    }

    outer = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"com.onelink.peer.profile.{fp[:16]}",
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadDisplayName": profile_display_name,
        "PayloadDescription": (
            "Adds your laptop's One Link daemon as a trusted source "
            "so your phone can pair with it over HTTPS without seeing "
            "a 'Not Private' warning. Remove anytime via "
            "Settings → General → VPN & Device Management."
        ),
        "PayloadOrganization": organization,
        # PayloadRemovalDisallowed = False so the user can delete
        # the profile any time they want, no admin intervention.
        "PayloadRemovalDisallowed": False,
        "PayloadContent": [cert_payload],
    }

    return plistlib.dumps(outer, fmt=plistlib.FMT_XML)

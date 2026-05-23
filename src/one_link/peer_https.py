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
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

log = logging.getLogger(__name__)


# Sub-directory under data_dir for HTTPS material.
HTTPS_DIR = "peer_https"
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

# Cert lifetime + rotation thresholds.
CERT_VALID_DAYS = 365
CERT_ROTATE_WITHIN_DAYS = 30


def https_dir(base: Path) -> Path:
    return base / HTTPS_DIR


def cert_path(base: Path) -> Path:
    return https_dir(base) / CERT_FILE


def key_path(base: Path) -> Path:
    return https_dir(base) / KEY_FILE


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


def generate_self_signed(
    base: Path,
    *,
    valid_days: int = CERT_VALID_DAYS,
    short_id: str = "",
) -> tuple[Path, Path]:
    """Mint a fresh ECDSA-P256 self-signed cert + key. Persists both
    to <base>/peer_https/{cert.pem,key.pem} with 0o600 perms.

    Returns (cert_path, key_path). Idempotent — call as many times
    as you want; each call writes a fresh cert.

    v0.20.7 (security audit M12): the cert subject now includes
    a per-daemon Common Name (``One Link Self-Signed (<short_id>)``)
    so a phone trust store containing certs from multiple daemons
    can identify which is which without inspecting fingerprints.
    The Ed25519 short_id is the identity hint (8 hex chars).
    """
    d = https_dir(base)
    d.mkdir(parents=True, exist_ok=True)
    cp = cert_path(base)
    kp = key_path(base)

    # ECDSA P-256 keypair.
    key = ec.generate_private_key(ec.SECP256R1())
    cn_text = (
        f"One Link Self-Signed ({short_id})"
        if short_id else
        "One Link Self-Signed"
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn_text),
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
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(
            _build_subject_alt_names(short_id=short_id),
            critical=False,
        )
        # 2026-05-23: mark the cert as a self-signed root CA. The cert
        # serves a DUAL purpose — it's both the TLS server cert (used
        # at handshake time) AND the root CA that the iOS device
        # trusts via Certificate Trust Settings. Without ca=True +
        # key_cert_sign=True, iOS installs the cert via mobileconfig
        # but does NOT recognise it as a root-CA candidate: the
        # Certificate Trust Settings page stays empty, the user
        # cannot toggle trust, and HTTPS still fails with "Not
        # Private." This is iOS Apple Root CA Trust documentation
        # behaviour — the certificate trust list is filtered to
        # CA-marked certs only.
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                # 2026-05-23: enable key_cert_sign so iOS treats this
                # as a trustable root. The cert self-signs itself
                # (subject == issuer), so this bit is consistent
                # with reality. Without it, iOS's PKI validator
                # rejects the cert as "not a CA" and silently drops
                # it from Certificate Trust Settings.
                #
                # crl_sign also enabled per Apple Developer Forums
                # guidance: "Certificate Sign, CRL Sign" together
                # are the canonical KeyUsage set for a CA-capable
                # cert. The CRL isn't actually consulted (we don't
                # publish one) but iOS's trust validator examines
                # the bit and the missing flag silently drops the
                # cert from the trust UI on some iOS 17+ versions.
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        # 2026-05-23: subjectKeyIdentifier + authorityKeyIdentifier
        # are required for iOS to index a self-signed root CA into
        # its trust UI. The Apple TN2326 and openssl docs both flag
        # these as load-bearing for CA recognition. Without them,
        # iOS installs the cert via mobileconfig but the cert never
        # surfaces in Settings > General > About > Certificate Trust
        # Settings — symptom-equivalent to the missing-CA-flag bug
        # but rooted in a different validator gate. For a self-signed
        # cert the two identifiers MUST match (issuer == subject).
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

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cp.write_bytes(cert_pem)
    kp.write_bytes(key_pem)
    # 0o600 — only the daemon-running user can read the private key.
    # Best-effort; non-POSIX filesystems may ignore the chmod.
    try:
        os.chmod(cp, 0o600)
        os.chmod(kp, 0o600)
    except Exception:
        pass
    log.info(
        "peer-https: minted self-signed cert (valid_days=%d, sha256=%s)",
        valid_days,
        cert.fingerprint(hashes.SHA256()).hex()[:32],
    )
    return cp, kp


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
    the existing cert is missing, unparseable, or near expiry."""
    cp = cert_path(base)
    kp = key_path(base)
    if needs_rotation(cp) or not kp.is_file():
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
        ctx.set_alpn_protocols(["h2", "http/1.1"])
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

    cp = cert_path(base)
    if not cp.is_file():
        # Mint on demand — same flow as ensure_cert.
        ensure_cert(base)
    cert_pem = cp.read_bytes()
    fp = cert_fingerprint_sha256(cp) or "unknown"

    cert_payload = {
        "PayloadType": "com.apple.security.root",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"com.onelink.peer.cert.{fp[:16]}",
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadDisplayName": "One Link Self-Signed CA",
        "PayloadDescription": (
            "Trust the One Link daemon's self-signed certificate so "
            "your phone can talk to it over HTTPS without warnings."
        ),
        "PayloadCertificateFileName": "one-link.cer",
        "PayloadContent": _format_pem_for_plist(cert_pem),
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

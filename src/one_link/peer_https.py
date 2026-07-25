"""Private, constrained HTTPS authority for the local daemon.

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

This module solves it with a per-install P-256 root and a proper TLS
leaf.  iOS installs the root through an explicitly removable profile;
the daemon serves the leaf and chain on a parallel TLS 1.3 listener.

Cert design
===========

- Algorithm: ECDSA P-256. RSA-2048 also works but produces
  larger certs; Ed25519 is rejected by some browsers (Safari) for
  TLS server certs as of 2026. P-256 is the universal sweet spot.
- The root has critical RFC 5280 NameConstraints.  It can issue only
  for localhost, the private ``onelink.local`` namespace, and the
  exact IP endpoints present when it is minted.  It is not a general
  web interception CA.
- The root signing authority is an authenticated LockBox envelope.
  The persisted file contains neither a cleartext PKCS#8 key nor an
  independently replaceable certificate/key pair.  On Windows the
  LockBox key is bound to the current user with DPAPI; passphrase and
  recoverable master-seed modes retain their normal LockBox semantics.
- The TLS leaf key must be available to OpenSSL and remains a strict
  owner-only file.  Compromise of that key can impersonate this daemon
  only; it cannot mint another certificate.
- Leaf validity is 365 days and rotates 30 days before expiry.  The
  root remains stable unless it expires or its exact endpoint scope no
  longer covers the daemon, in which case the profile must be reinstalled.
- Subject Alternative Names cover localhost, ``onelink.local``, the
  per-daemon ``<short-id>.onelink.local`` name, and detected LAN IPs.
- Persisted to:
      <data_dir>/peer_https/cert.pem
      <data_dir>/peer_https/key.pem
  Both 0o600. Regenerated if missing or expired.

The profile is still a manual local trust ceremony: on an unmanaged
iPhone, Apple requires the user to install the profile and separately
enable SSL trust in Certificate Trust Settings.  The profile and UI say
this directly and expose removal instructions.
"""

from __future__ import annotations

import datetime
import ipaddress
import logging
import os
import socket
import contextlib
import ssl
import struct
from pathlib import Path
from typing import Optional, cast

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from one_link.key_material import (
    KeyMaterialIntegrityError,
    atomic_create_bytes,
    atomic_replace_bytes,
    artifact_exists,
    read_bytes_if_exists,
)

log = logging.getLogger(__name__)


# Sub-directory under data_dir for HTTPS material.
HTTPS_DIR = "peer_https"
# cert.pem is the leaf+root chain (PEM-concat). key.pem is the leaf key.
# root_ca.pem is a public projection used by the mobileconfig.  The
# historically named root_ca_key.pem is now an authenticated LockBox
# authority envelope containing the matching root certificate and key as
# one transaction.  Keeping the old path permits an in-place, fail-closed
# migration from releases that stored a cleartext PKCS#8 key there.
CERT_FILE = "cert.pem"  # leaf + root chain
KEY_FILE = "key.pem"  # leaf key
ROOT_CA_FILE = "root_ca.pem"  # long-lived trust anchor (in mobileconfig)
ROOT_CA_KEY_FILE = "root_ca_key.pem"  # encrypted root authority envelope

_ROOT_AUTHORITY_MAGIC = b"OLTCAUTH\x01"
_ROOT_AUTHORITY_HEADER = struct.Struct(">9sII")
_ROOT_AUTHORITY_MAX_BYTES = 128 * 1024
_TLS_MATERIAL_MAX_BYTES = 256 * 1024

# Lifetime + rotation thresholds.
CERT_VALID_DAYS = 365  # leaf lifetime
CERT_ROTATE_WITHIN_DAYS = 30  # leaf rotation window
ROOT_CA_VALID_DAYS = 365 * 10  # root lives 10 years; phones trust once


class TLSAuthorityError(RuntimeError):
    """An existing TLS authority is incomplete, corrupt, or unauthentic."""


class TLSAuthorityRotationRequired(RuntimeError):
    """A valid authority must rotate to meet the current security policy."""


def _must_enforce_private_permissions() -> bool:
    """Return whether POSIX mode bits protect the generated key files.

    Windows protects these files with the account's ACL/default DACL and its
    ``chmod`` implementation only controls a read-only flag. On POSIX,
    failure to apply 0600 can expose a CA or leaf private key to another
    local account, so generation must fail closed.
    """

    return os.name != "nt"


def _restrict_private_files(*paths: Path) -> None:
    """Apply the documented 0600 mode, failing closed where meaningful."""

    for path in paths:
        if os.name == "nt":
            # chmod is only a read-only bit on Windows.  Apply the same
            # current-user ACL used by the identity and LockBox authorities.
            from one_link.identity import _restrict_windows_acl

            _restrict_windows_acl(path)
        try:
            os.chmod(path, 0o600)
        except OSError as exc:
            if _must_enforce_private_permissions():
                raise PermissionError(
                    f"could not restrict TLS key material permissions: {path}"
                ) from exc
            log.warning(
                "peer-https: platform could not apply mode 0600 to %s: %s",
                path,
                exc,
            )


def _write_private_bytes(path: Path, payload: bytes) -> None:
    """Write secret key bytes only after tightening an existing inode.

    ``Path.write_bytes`` creates files using the process umask and chmods
    later, leaving a small 0644 exposure window on common POSIX defaults.
    Open without truncation, enforce 0600, then replace the contents.
    """

    flags = os.O_WRONLY | os.O_CREAT
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(path, flags, 0o600)
    try:
        if _must_enforce_private_permissions():
            fchmod = getattr(os, "fchmod", None)
            if not callable(fchmod):
                raise PermissionError(f"could not restrict TLS key material permissions: {path}")
            try:
                fchmod(fd, 0o600)
            except OSError as exc:
                raise PermissionError(
                    f"could not restrict TLS key material permissions: {path}"
                ) from exc
        os.ftruncate(fd, 0)
        with os.fdopen(fd, "wb", closefd=False) as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
    finally:
        os.close(fd)


def _harden_private_path(path: Path) -> None:
    """Hardener callback for durable authority-file publication."""

    _restrict_private_files(path)


def _spki_bytes(key: object) -> bytes:
    public_bytes = getattr(key, "public_bytes", None)
    if not callable(public_bytes):
        raise TLSAuthorityError("TLS authority contains an unsupported public key")
    return public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _encode_root_authority(
    key: ec.EllipticCurvePrivateKey,
    cert: x509.Certificate,
) -> bytes:
    """Encode the matching root certificate/key into one strict record."""

    cert_der = cert.public_bytes(serialization.Encoding.DER)
    key_der = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    payload = (
        _ROOT_AUTHORITY_HEADER.pack(
            _ROOT_AUTHORITY_MAGIC,
            len(cert_der),
            len(key_der),
        )
        + cert_der
        + key_der
    )
    if len(payload) > _ROOT_AUTHORITY_MAX_BYTES:
        raise TLSAuthorityError("TLS root authority exceeds its size limit")
    return payload


def _decode_root_authority(
    payload: bytes,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Strictly decode a LockBox-authenticated root authority record."""

    if not isinstance(payload, bytes) or len(payload) < _ROOT_AUTHORITY_HEADER.size:
        raise TLSAuthorityError("TLS root authority record is truncated")
    if len(payload) > _ROOT_AUTHORITY_MAX_BYTES:
        raise TLSAuthorityError("TLS root authority record exceeds its size limit")
    magic, cert_len, key_len = _ROOT_AUTHORITY_HEADER.unpack_from(payload)
    if magic != _ROOT_AUTHORITY_MAGIC:
        raise TLSAuthorityError("TLS root authority record has an unknown version")
    if cert_len <= 0 or key_len <= 0:
        raise TLSAuthorityError("TLS root authority record contains an empty field")
    expected = _ROOT_AUTHORITY_HEADER.size + cert_len + key_len
    if expected != len(payload):
        raise TLSAuthorityError("TLS root authority record lengths are inconsistent")
    cert_start = _ROOT_AUTHORITY_HEADER.size
    key_start = cert_start + cert_len
    try:
        cert = x509.load_der_x509_certificate(payload[cert_start:key_start])
        loaded_key = serialization.load_der_private_key(
            payload[key_start:],
            password=None,
        )
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise TLSAuthorityError("TLS root authority record is not valid DER") from exc
    if not isinstance(loaded_key, ec.EllipticCurvePrivateKey):
        raise TLSAuthorityError("TLS root authority private key is not EC")
    return loaded_key, cert


def _wrap_root_authority(base: Path, payload: bytes) -> bytes:
    from one_link.lockbox import acquire_lockbox, is_wrapped

    wrapped = acquire_lockbox(base).wrap(payload)
    if not is_wrapped(wrapped):
        raise TLSAuthorityError("LockBox returned an invalid TLS authority envelope")
    return wrapped


def _unwrap_root_authority(base: Path, wrapped: bytes) -> bytes:
    from one_link.lockbox import LockBoxError, acquire_lockbox, is_wrapped

    if not is_wrapped(wrapped):
        raise TLSAuthorityError("TLS root authority is not LockBox-wrapped")
    try:
        return acquire_lockbox(base).unwrap(wrapped)
    except LockBoxError as exc:
        raise TLSAuthorityError("TLS root authority failed LockBox authentication") from exc


def _publish_private_authority(
    path: Path,
    payload: bytes,
    *,
    replace: bool,
) -> bool:
    """Durably publish one authenticated authority envelope."""

    def _validate(candidate: bytes) -> None:
        if candidate != payload:
            raise KeyMaterialIntegrityError("TLS authority read-back mismatch")

    if replace:
        atomic_replace_bytes(
            path,
            payload,
            label="TLS root authority",
            validate=_validate,
            harden_path=_harden_private_path,
        )
        return True
    return atomic_create_bytes(
        path,
        payload,
        label="TLS root authority",
        validate=_validate,
        harden_path=_harden_private_path,
    )


def _publish_root_projection(path: Path, cert: x509.Certificate) -> None:
    pem = cert.public_bytes(serialization.Encoding.PEM)

    def _validate(candidate: bytes) -> None:
        try:
            parsed = x509.load_pem_x509_certificate(candidate)
        except (ValueError, UnsupportedAlgorithm) as exc:
            raise KeyMaterialIntegrityError("TLS root certificate projection is invalid") from exc
        if parsed.fingerprint(hashes.SHA256()) != cert.fingerprint(hashes.SHA256()):
            raise KeyMaterialIntegrityError(
                "TLS root certificate projection does not match authority"
            )

    atomic_replace_bytes(
        path,
        pem,
        label="TLS root certificate projection",
        validate=_validate,
        harden_path=_harden_private_path,
    )


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
    except OSError as exc:
        log.debug("peer-https: egress LAN-address detection failed: %s", exc)
    finally:
        s.close()
    # All IPv4 addresses bound to this host.
    try:
        hostname = socket.gethostname()
        _, _, addrs = socket.gethostbyname_ex(hostname)
        for a in addrs:
            out.add(a)
    except OSError as exc:
        log.debug("peer-https: hostname LAN-address enumeration failed: %s", exc)
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


def _build_root_name_constraints() -> x509.NameConstraints:
    """Limit the installed CA to One Link names and current IP endpoints.

    RFC 5280 encodes IP constraints as an address plus mask.  A /32 or /128
    therefore grants exactly one address.  Endpoint changes deliberately
    rotate the root and require a fresh, visible trust ceremony instead of
    silently widening a phone-wide trust anchor.
    """

    permitted: list[x509.GeneralName] = [
        x509.DNSName("localhost"),
        # RFC 5280 DNS constraints permit this name and labels below it,
        # including the per-daemon <short-id>.onelink.local endpoint.
        x509.DNSName("onelink.local"),
    ]
    for ip_str in _detect_lan_addresses():
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        prefix = 32 if ip.version == 4 else 128
        permitted.append(x509.IPAddress(ipaddress.ip_network(f"{ip}/{prefix}")))
    return x509.NameConstraints(
        permitted_subtrees=permitted,
        excluded_subtrees=None,
    )


def _root_constraints_cover_current_endpoints(cert: x509.Certificate) -> bool:
    try:
        extension = cert.extensions.get_extension_for_class(x509.NameConstraints)
    except x509.ExtensionNotFound:
        return False
    if not extension.critical:
        return False
    constraints = extension.value
    if constraints.excluded_subtrees:
        return False
    permitted = constraints.permitted_subtrees or []
    dns_values = {
        name.value.lower().rstrip(".") for name in permitted if isinstance(name, x509.DNSName)
    }
    if not {"localhost", "onelink.local"}.issubset(dns_values):
        return False
    ip_networks = [
        name.value
        for name in permitted
        if isinstance(name, x509.IPAddress)
        and isinstance(
            name.value,
            (ipaddress.IPv4Network, ipaddress.IPv6Network),
        )
    ]
    for ip_str in _detect_lan_addresses():
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if not any(ip.version == network.version and ip in network for network in ip_networks):
            return False
    return True


def _validate_root_authority(
    key: ec.EllipticCurvePrivateKey,
    cert: x509.Certificate,
) -> None:
    """Validate every invariant before a root may sign a new leaf."""

    if not isinstance(key.curve, ec.SECP256R1):
        raise TLSAuthorityError("TLS root authority is not P-256")
    public_key = cert.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise TLSAuthorityError("TLS root certificate is not EC")
    if not isinstance(public_key.curve, ec.SECP256R1):
        raise TLSAuthorityError("TLS root certificate is not P-256")
    if _spki_bytes(key.public_key()) != _spki_bytes(public_key):
        raise TLSAuthorityError("TLS root certificate and private key do not match")
    if cert.subject != cert.issuer:
        raise TLSAuthorityError("TLS root certificate is not self-issued")
    signature_hash = cert.signature_hash_algorithm
    if signature_hash is None:
        raise TLSAuthorityError("TLS root certificate lacks a signature hash")
    try:
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(signature_hash),
        )
    except InvalidSignature as exc:
        raise TLSAuthorityError("TLS root certificate self-signature is invalid") from exc
    try:
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
    except x509.ExtensionNotFound as exc:
        raise TLSAuthorityError("TLS root certificate is missing a required extension") from exc
    if not basic.critical or not basic.value.ca or basic.value.path_length != 0:
        raise TLSAuthorityError("TLS root BasicConstraints are invalid")
    if not usage.critical or not usage.value.key_cert_sign or not usage.value.crl_sign:
        raise TLSAuthorityError("TLS root KeyUsage is invalid")
    if not _root_constraints_cover_current_endpoints(cert):
        raise TLSAuthorityRotationRequired(
            "TLS root is unconstrained or no longer covers current endpoints"
        )


def _certificate_needs_rotation(
    cert: x509.Certificate,
    *,
    rotate_within_days: int,
) -> bool:
    now = datetime.datetime.now(datetime.timezone.utc)
    expiry = getattr(cert, "not_valid_after_utc", None)
    if expiry is None:
        expiry = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    return expiry - now < datetime.timedelta(days=rotate_within_days)


def _leaf_san_covers_current_endpoints(
    leaf: x509.Certificate,
    *,
    short_id: str,
) -> bool:
    try:
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    dns = {name.value.lower().rstrip(".") for name in san if isinstance(name, x509.DNSName)}
    required_dns = {"localhost", "onelink.local"}
    if short_id:
        required_dns.add(f"{short_id}.onelink.local".lower())
    if not required_dns.issubset(dns):
        return False
    ips = {name.value for name in san if isinstance(name, x509.IPAddress)}
    for ip_str in _detect_lan_addresses():
        try:
            endpoint = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if endpoint not in ips:
            return False
    return True


def _validate_leaf_material(
    base: Path,
    *,
    root_cert: x509.Certificate,
    short_id: str,
) -> bool:
    """Validate persisted leaf files; return false only for safe regeneration.

    Access, reparse-point, and concurrent-replacement failures from the
    key-material reader propagate and fail closed.  Ordinary malformed or
    mismatched leaf bytes are non-authoritative and can be reminted beneath
    the still-authenticated root.
    """

    chain_pem = read_bytes_if_exists(
        cert_path(base),
        label="TLS leaf certificate chain",
        max_bytes=_TLS_MATERIAL_MAX_BYTES,
        harden_path=_harden_private_path,
    )
    key_pem = read_bytes_if_exists(
        key_path(base),
        label="TLS leaf private key",
        max_bytes=_TLS_MATERIAL_MAX_BYTES,
        harden_path=_harden_private_path,
    )
    if chain_pem is None or key_pem is None:
        return False
    try:
        certs = x509.load_pem_x509_certificates(chain_pem)
        loaded_key = serialization.load_pem_private_key(key_pem, password=None)
    except (TypeError, ValueError, UnsupportedAlgorithm):
        return False
    if len(certs) != 2 or not isinstance(loaded_key, ec.EllipticCurvePrivateKey):
        return False
    leaf, projected_root = certs
    leaf_public = leaf.public_key()
    if not isinstance(leaf_public, ec.EllipticCurvePublicKey):
        return False
    if not isinstance(leaf_public.curve, ec.SECP256R1):
        return False
    if not isinstance(loaded_key.curve, ec.SECP256R1):
        return False
    if _spki_bytes(loaded_key.public_key()) != _spki_bytes(leaf_public):
        return False
    if projected_root.fingerprint(hashes.SHA256()) != root_cert.fingerprint(hashes.SHA256()):
        return False
    if leaf.issuer != root_cert.subject:
        return False
    signature_hash = leaf.signature_hash_algorithm
    root_public = root_cert.public_key()
    if signature_hash is None or not isinstance(root_public, ec.EllipticCurvePublicKey):
        return False
    try:
        root_public.verify(
            leaf.signature,
            leaf.tbs_certificate_bytes,
            ec.ECDSA(signature_hash),
        )
        basic = leaf.extensions.get_extension_for_class(x509.BasicConstraints)
        usage = leaf.extensions.get_extension_for_class(x509.KeyUsage)
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except (InvalidSignature, x509.ExtensionNotFound):
        return False
    if not basic.critical or basic.value.ca:
        return False
    if not usage.critical or not usage.value.digital_signature:
        return False
    if usage.value.key_cert_sign or usage.value.crl_sign:
        return False
    if x509.ExtendedKeyUsageOID.SERVER_AUTH not in eku.value:
        return False
    if not _leaf_san_covers_current_endpoints(leaf, short_id=short_id):
        return False
    return not _certificate_needs_rotation(
        leaf,
        rotate_within_days=CERT_ROTATE_WITHIN_DAYS,
    )


def _publish_leaf_key(
    path: Path,
    payload: bytes,
    *,
    expected_public: ec.EllipticCurvePublicKey,
) -> None:
    def _validate(candidate: bytes) -> None:
        try:
            loaded = serialization.load_pem_private_key(candidate, password=None)
        except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
            raise KeyMaterialIntegrityError("TLS leaf key read-back is invalid") from exc
        if not isinstance(loaded, ec.EllipticCurvePrivateKey):
            raise KeyMaterialIntegrityError("TLS leaf key read-back is not EC")
        if _spki_bytes(loaded.public_key()) != _spki_bytes(expected_public):
            raise KeyMaterialIntegrityError("TLS leaf key read-back does not match")

    atomic_replace_bytes(
        path,
        payload,
        label="TLS leaf private key",
        validate=_validate,
        harden_path=_harden_private_path,
    )


def _publish_leaf_chain(
    path: Path,
    payload: bytes,
    *,
    leaf: x509.Certificate,
    root: x509.Certificate,
) -> None:
    def _validate(candidate: bytes) -> None:
        try:
            certs = x509.load_pem_x509_certificates(candidate)
        except (ValueError, UnsupportedAlgorithm) as exc:
            raise KeyMaterialIntegrityError("TLS leaf chain read-back is invalid") from exc
        if len(certs) != 2:
            raise KeyMaterialIntegrityError("TLS leaf chain read-back has wrong length")
        if certs[0].fingerprint(hashes.SHA256()) != leaf.fingerprint(hashes.SHA256()):
            raise KeyMaterialIntegrityError("TLS leaf chain read-back changed the leaf")
        if certs[1].fingerprint(hashes.SHA256()) != root.fingerprint(hashes.SHA256()):
            raise KeyMaterialIntegrityError("TLS leaf chain read-back changed the root")

    atomic_replace_bytes(
        path,
        payload,
        label="TLS leaf certificate chain",
        validate=_validate,
        harden_path=_harden_private_path,
    )


def _mint_root_ca(
    base: Path,
    *,
    short_id: str = "",
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Mint and transactionally publish a constrained root authority.

    Per Apple TN2326: the root has BasicConstraints CA=True, key
    usage = certSign+crlSign, no subjectAltName, and no EKU.  A
    critical NameConstraints extension prevents this manually trusted
    root from authenticating names outside One Link's local scope.

    The certificate and private key are serialized together, LockBox-
    wrapped, and atomically published before the public root projection.
    If publication races, the existing authenticated winner is loaded.
    """
    d = https_dir(base)
    d.mkdir(parents=True, exist_ok=True)
    rcp = root_ca_path(base)
    rkp = root_ca_key_path(base)

    key = ec.generate_private_key(ec.SECP256R1())
    cn = f"One Link Root CA ({short_id})" if short_id else "One Link Root CA"
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "One Link"),
        ]
    )
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
        .add_extension(
            _build_root_name_constraints(),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    _validate_root_authority(key, cert)

    encoded = _encode_root_authority(key, cert)
    wrapped = _wrap_root_authority(base, encoded)
    replacing = artifact_exists(rkp, label="TLS root authority")
    if not _publish_private_authority(rkp, wrapped, replace=replacing):
        # A concurrent first publisher won.  Never overwrite it with a
        # different authority; converge on the authenticated winner.
        return _load_root_ca(base)
    _publish_root_projection(rcp, cert)
    log.info(
        "peer-https: minted constrained root CA (valid_days=%d, sha256=%s, authority=lockbox)",
        ROOT_CA_VALID_DAYS,
        cert.fingerprint(hashes.SHA256()).hex()[:32],
    )
    return key, cert


def _load_root_ca(
    base: Path,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    rcp = root_ca_path(base)
    rkp = root_ca_key_path(base)
    authority_blob = read_bytes_if_exists(
        rkp,
        label="TLS root authority",
        max_bytes=_ROOT_AUTHORITY_MAX_BYTES,
        harden_path=_harden_private_path,
    )
    if authority_blob is None:
        raise TLSAuthorityError("TLS root authority is missing")

    from one_link.lockbox import is_wrapped

    if is_wrapped(authority_blob):
        key, cert = _decode_root_authority(_unwrap_root_authority(base, authority_blob))
    else:
        # One-time migration from the historical cleartext PKCS#8 key.  The
        # existing certificate is required and validated before replacement;
        # an incomplete/corrupt trust anchor is never treated as first boot.
        cert_pem = read_bytes_if_exists(
            rcp,
            label="TLS root certificate",
            max_bytes=_ROOT_AUTHORITY_MAX_BYTES,
            harden_path=_harden_private_path,
        )
        if cert_pem is None:
            raise TLSAuthorityError("legacy TLS root key exists without its certificate")
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
            loaded_key = serialization.load_pem_private_key(
                authority_blob,
                password=None,
            )
        except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
            raise TLSAuthorityError("legacy TLS root authority is invalid") from exc
        if not isinstance(loaded_key, ec.EllipticCurvePrivateKey):
            raise TLSAuthorityError("legacy TLS root private key is not EC")
        key = loaded_key

    _validate_root_authority(key, cert)

    expected_pem = cert.public_bytes(serialization.Encoding.PEM)
    projection = read_bytes_if_exists(
        rcp,
        label="TLS root certificate projection",
        max_bytes=_ROOT_AUTHORITY_MAX_BYTES,
        harden_path=_harden_private_path,
    )
    projection_matches = False
    if projection is not None:
        try:
            projected_cert = x509.load_pem_x509_certificate(projection)
            projection_matches = projected_cert.fingerprint(hashes.SHA256()) == cert.fingerprint(
                hashes.SHA256()
            )
        except (ValueError, UnsupportedAlgorithm):
            projection_matches = False
    if not projection_matches or projection != expected_pem:
        # The authenticated combined authority is the source of truth.  The
        # public PEM is a regenerable projection, not independent authority.
        _publish_root_projection(rcp, cert)

    if not is_wrapped(authority_blob):
        wrapped = _wrap_root_authority(base, _encode_root_authority(key, cert))
        _publish_private_authority(rkp, wrapped, replace=True)
        log.info("peer-https: migrated cleartext root key into LockBox authority")
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
    cn = f"One Link Daemon ({short_id})" if short_id else "One Link Daemon"
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "One Link"),
        ]
    )
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

    chain_pem = cert.public_bytes(serialization.Encoding.PEM) + root_cert.public_bytes(
        serialization.Encoding.PEM
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Publish the key first and chain second.  Each replacement is durable and
    # validated; a crash between them leaves a detectable mismatch that is
    # safely reminted under the unchanged authenticated root on next boot.
    _publish_leaf_key(
        kp,
        key_pem,
        expected_public=key.public_key(),
    )
    _publish_leaf_chain(
        cp,
        chain_pem,
        leaf=cert,
        root=root_cert,
    )
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

    Idempotent for a valid root authority; always mints a fresh leaf.
    Existing corrupt/partial authority fails closed.  Only a valid root
    that is expired, lacks NameConstraints, or no longer covers the
    current exact endpoints is deliberately rotated.
    """
    rkp = root_ca_key_path(base)
    rcp = root_ca_path(base)
    have_authority = artifact_exists(rkp, label="TLS root authority")
    have_projection = artifact_exists(rcp, label="TLS root certificate")
    if have_authority:
        try:
            root_key, root_cert = _load_root_ca(base)
        except TLSAuthorityRotationRequired as exc:
            log.warning(
                "peer-https: rotating valid root authority to satisfy policy: %s",
                exc,
            )
            root_key, root_cert = _mint_root_ca(base, short_id=short_id)
        else:
            # Root projection may have been repaired by _load_root_ca.
            if needs_rotation(rcp, rotate_within_days=30):
                root_key, root_cert = _mint_root_ca(base, short_id=short_id)
    elif have_projection:
        raise TLSAuthorityError("TLS root certificate exists without its signing authority")
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
    except FileNotFoundError:
        return True
    except (ValueError, UnsupportedAlgorithm) as e:
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
    Atomic publication replaces that non-authoritative leaf material
    with a two-certificate chain; the user must install the new profile.
    """
    cp = cert_path(base)
    kp = key_path(base)
    rcp = root_ca_path(base)
    rkp = root_ca_key_path(base)

    # root_ca.pem is a regenerable public projection of the authenticated
    # combined authority.  A missing projection is repaired by
    # generate_self_signed; a missing authority with a remaining projection
    # fails closed there instead of silently replacing phone trust.
    have_authority = artifact_exists(rkp, label="TLS root authority")
    have_projection = artifact_exists(rcp, label="TLS root certificate")
    if not have_authority or not have_projection:
        return generate_self_signed(base, short_id=short_id)
    # Validate authority even when the leaf is fresh.  This detects endpoint
    # scope changes, authority tampering, and projection replacement before
    # OpenSSL starts serving an invalid or over-broad chain.
    try:
        root_key, root_cert = _load_root_ca(base)
    except TLSAuthorityRotationRequired:
        return generate_self_signed(base, short_id=short_id)
    if not _validate_leaf_material(
        base,
        root_cert=root_cert,
        short_id=short_id,
    ):
        return _mint_leaf_tls(
            base,
            root_key=root_key,
            root_cert=root_cert,
            short_id=short_id,
        )
    return cp, kp


def build_ssl_context(
    base: Path,
    *,
    short_id: str = "",
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
    except (OSError, ValueError) as exc:
        log.warning(
            "peer-https: cannot derive certificate fingerprint from %s: %s",
            cert_path_to_read,
            exc,
        )
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
    """Build a removable iOS profile for this daemon's constrained root.

    After the user separately enables SSL trust, iOS accepts TLS leaves
    from this authority only for the exact local IP endpoints present at
    mint time, localhost, and the private One Link DNS namespace.  It is
    deliberately incapable of authenticating arbitrary public websites.

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
            "Trust only this laptop's constrained One Link authority "
            "for its local One Link names and current network addresses. "
            "It cannot authenticate arbitrary public websites."
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
            "Adds this laptop's endpoint-constrained One Link authority "
            "so your phone can pair over HTTPS. If the laptop's network "
            "address changes, install the newly generated profile. Remove "
            "anytime via "
            "Settings → General → VPN & Device Management."
        ),
        "PayloadOrganization": organization,
        # PayloadRemovalDisallowed = False so the user can delete
        # the profile any time they want, no admin intervention.
        "PayloadRemovalDisallowed": False,
        "PayloadContent": [cert_payload],
    }

    return plistlib.dumps(outer, fmt=plistlib.FMT_XML)

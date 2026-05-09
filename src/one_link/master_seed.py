"""Master seed — the single recoverable secret behind a daemon's
identity + at-rest data.

The 24-word BIP-39 mnemonic the user writes down on paper encodes
this seed exactly. Every other long-lived secret in the daemon
(Ed25519 identity private key, lockbox data root key, future
device-cluster shares) derives from it via HKDF-SHA256 with
domain-separated `info` strings. So a single recovery (typing
the 24 words on a fresh machine) re-creates the entire
cryptographic state of the original daemon.

Trust ground vs corporate substrate
-----------------------------------
The seed is stored on disk DPAPI-wrapped on Windows (same pattern
as lockbox.py — bound to the user's login credentials, which an
attacker can't unwrap without the user's password). On other
platforms the seed file is mode 0600 in the daemon's config dir.

The user's PAPER backup is the sovereignty layer: even a thief
who DPAPI-unwraps the seed in memory can't extract it from the
paper backup the user keeps in a drawer. The paper backup also
survives any platform substrate failure (hard drive death,
account lockout, OS reinstall).

Backward compatibility
----------------------
Daemons that pre-existed this module's introduction have separate
randomly-generated identity.key + DRK without a master seed.
``load_or_create_seed`` is opt-in for those daemons: it returns
the seed only when the seed file already exists. Identity.py and
lockbox.py check ``has_seed(data_dir)`` to decide whether to
derive their keys from the seed (new flow) or generate fresh
randomness (legacy flow). The "Initialize seed" CLI command lets
existing daemons migrate explicitly — a key-rotating action with
clear UX consequences.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


SEED_FILENAME = "master.seed"
SEED_LEN_BYTES = 32  # 256 bits — matches BIP-39 24-word entropy

# HKDF info strings. Domain-separated so a leak of one derived
# key doesn't compromise the others. Format follows the
# convention used elsewhere in the daemon: short ASCII labels
# with trailing pipe.
_INFO_DRK = b"OL/master/drk|v1"
_INFO_IDENTITY = b"OL/master/identity-ed25519|v1"
_INFO_CLUSTER_SEED = b"OL/master/cluster-seed|v1"


def _seed_path(data_dir: Path) -> Path:
    return Path(data_dir) / SEED_FILENAME


def has_seed(data_dir: Path) -> bool:
    """True iff a master seed has been provisioned for this install."""
    return _seed_path(data_dir).is_file()


def load_seed(data_dir: Path) -> Optional[bytes]:
    """Read the master seed off disk + DPAPI-unwrap on Windows.
    Returns None if no seed file exists or unwrap fails."""
    p = _seed_path(data_dir)
    if not p.is_file():
        return None
    try:
        blob = p.read_bytes()
    except OSError:
        return None
    if not blob:
        return None
    if os.name == "nt":
        from one_link.lockbox import _dpapi_unprotect
        unwrapped = _dpapi_unprotect(blob)
        if unwrapped is None or len(unwrapped) != SEED_LEN_BYTES:
            return None
        return unwrapped
    if len(blob) != SEED_LEN_BYTES:
        return None
    return blob


def store_seed(data_dir: Path, seed: bytes) -> None:
    """Persist the master seed to disk. Wraps with DPAPI on Windows
    (same scheme as lockbox.py); writes raw 32 bytes with mode 0600
    on POSIX. Atomic via temp + rename."""
    if not isinstance(seed, (bytes, bytearray)):
        raise TypeError("seed must be bytes")
    if len(seed) != SEED_LEN_BYTES:
        raise ValueError(f"seed must be {SEED_LEN_BYTES} bytes")
    p = _seed_path(data_dir)
    p.parent.mkdir(parents=True, exist_ok=True)

    out_bytes = bytes(seed)
    if os.name == "nt":
        from one_link.lockbox import _dpapi_protect
        wrapped = _dpapi_protect(out_bytes)
        if wrapped:
            out_bytes = wrapped

    tmp = p.with_name(p.name + ".tmp." + secrets.token_hex(4))
    # Windows: O_BINARY suppresses the default CRLF translation that
    # would corrupt DPAPI-wrapped blobs (a single 0x0a byte becomes
    # 0x0d 0x0a on disk). On POSIX O_BINARY isn't defined; the OR
    # is a no-op via getattr.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    flags |= getattr(os, "O_BINARY", 0)
    fd = os.open(str(tmp), flags, 0o600)
    try:
        os.write(fd, out_bytes)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, p)
    if os.name != "nt":
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass


def load_or_create_seed(data_dir: Path) -> tuple[bytes, bool]:
    """Return ``(seed, created)``. If a seed already exists on disk,
    load + return it with ``created=False``. Otherwise mint 32 fresh
    random bytes, persist them, and return ``(seed, True)``.

    First-launch callers use the ``created`` flag to decide whether
    to display the user's BIP-39 backup phrase ("WRITE THESE WORDS
    DOWN") on the way through. Subsequent launches see
    ``created=False`` and continue silently.
    """
    existing = load_seed(data_dir)
    if existing is not None:
        return existing, False
    seed = secrets.token_bytes(SEED_LEN_BYTES)
    store_seed(data_dir, seed)
    return seed, True


# ── derived keys ─────────────────────────────────────────────────


def derive_drk(seed: bytes) -> bytes:
    """Data root key for the lockbox. 32 bytes, AES-GCM-friendly."""
    if len(seed) != SEED_LEN_BYTES:
        raise ValueError("seed must be 32 bytes")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,  # the seed itself is the high-entropy IKM
        info=_INFO_DRK,
    ).derive(bytes(seed))


def derive_identity_priv(seed: bytes) -> Ed25519PrivateKey:
    """Ed25519 identity private key. The Ed25519 spec accepts any
    32-byte buffer as the private seed; HKDF gives us 32 bytes
    of pseudo-random material indistinguishable from os.urandom."""
    if len(seed) != SEED_LEN_BYTES:
        raise ValueError("seed must be 32 bytes")
    raw = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_INFO_IDENTITY,
    ).derive(bytes(seed))
    return Ed25519PrivateKey.from_private_bytes(raw)


def derive_cluster_seed(seed: bytes) -> bytes:
    """Per-install cluster seed used by future device-cluster
    Shamir splits. Distinct from the identity + DRK so a leak of
    cluster shares doesn't compromise the identity / lockbox key."""
    if len(seed) != SEED_LEN_BYTES:
        raise ValueError("seed must be 32 bytes")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_INFO_CLUSTER_SEED,
    ).derive(bytes(seed))

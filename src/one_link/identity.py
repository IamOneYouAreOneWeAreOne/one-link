"""Ed25519 device identity.

Each computer generates a long-term Ed25519 keypair on first run.
The public key's BLAKE3 fingerprint (first 8 hex chars) is the device ID
shown to the user. The private key never leaves disk.

Optional passphrase encryption-at-rest:
    Set the ONE_LINK_PASSPHRASE environment variable before launching the
    daemon and the private key file is wrapped with PKCS#8
    BestAvailableEncryption (currently AES-256 + PBKDF2). The same
    variable must be set on subsequent launches to decrypt.

    If you switch from unencrypted to encrypted, the existing file is
    transparently re-saved with encryption on next successful load.
"""

from __future__ import annotations

import os
import secrets
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import blake3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from one_link.paths import key_path

PASSPHRASE_ENV = "ONE_LINK_PASSPHRASE"


@dataclass(frozen=True)
class Identity:
    private: Ed25519PrivateKey
    public: Ed25519PublicKey
    public_bytes: bytes
    fingerprint: str
    short_id: str
    hostname: str

    def sign(self, data: bytes) -> bytes:
        return self.private.sign(data)


def _fingerprint(public_bytes: bytes) -> str:
    return blake3.blake3(public_bytes).hexdigest()


def _resolve_passphrase(passphrase: Optional[bytes | str]) -> Optional[bytes]:
    if passphrase is None:
        env = os.environ.get(PASSPHRASE_ENV)
        if env:
            return env.encode("utf-8")
        return None
    if isinstance(passphrase, str):
        return passphrase.encode("utf-8")
    return passphrase


def _restrict_windows_acl(p: Path) -> None:
    """v0.20.7 (security audit H3): tighten the file's Windows ACL to
    grant the current user full control and deny inheritance.

    `os.chmod` on Windows only flips the read-only attribute; it does
    nothing about access-control. The README's "user-only ACL on
    Windows" claim depended on `%APPDATA%` directory ACLs, which on a
    multi-admin / domain-joined box typically grant Administrators +
    SYSTEM read access. This routine uses the Win32 SetFileSecurity
    API via ctypes (no new dependency) to install an explicit
    discretionary ACL on the identity-key file: PROTECTED + a single
    ACE granting STANDARD_RIGHTS_ALL + GENERIC_ALL to the current
    user's SID. SYSTEM is intentionally omitted; if the OS needs
    SYSTEM access for backup it has to inherit from the parent dir
    (which we set DACL_PROTECTED on, breaking inheritance).

    Best-effort: any failure logs a debug message and falls back to
    the inherited parent-dir ACL. No raise, because the rest of the
    daemon must continue to function on stripped-down Windows
    (containers, embedded, bypassed system policies)."""
    if os.name != "nt":
        return
    try:
        import ctypes
        from ctypes import wintypes
    except Exception:
        return
    try:
        # Constants
        TOKEN_QUERY = 0x0008
        TokenUser = 1
        DACL_SECURITY_INFORMATION = 0x00000004
        PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
        SECURITY_DESCRIPTOR_REVISION = 1
        ACL_REVISION = 2
        STANDARD_RIGHTS_ALL = 0x001F0000
        GENERIC_ALL = 0x10000000
        FILE_ALL_ACCESS = 0x001F01FF

        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        # 1. Get current process token + the user SID.
        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)
        ):
            return
        try:
            size = wintypes.DWORD(0)
            advapi32.GetTokenInformation(
                token, TokenUser, None, 0, ctypes.byref(size)
            )
            buf = (ctypes.c_byte * size.value)()
            if not advapi32.GetTokenInformation(
                token, TokenUser, buf, size, ctypes.byref(size)
            ):
                return
            # TOKEN_USER struct: SID_AND_ATTRIBUTES { PSID Sid; DWORD Attributes }
            user_sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
            sid_len = advapi32.GetLengthSid(user_sid_ptr)
            if not sid_len:
                return
        finally:
            kernel32.CloseHandle(token)

        # 2. Build a security descriptor + DACL containing one ACE.
        sd = (ctypes.c_byte * 1024)()
        if not advapi32.InitializeSecurityDescriptor(
            sd, SECURITY_DESCRIPTOR_REVISION
        ):
            return
        # Allocate ACL: enough for the SD header (8) + one ACE
        # (8 + sid_len). Round up.
        acl_size = 8 + 8 + sid_len + 16
        acl = (ctypes.c_byte * acl_size)()
        if not advapi32.InitializeAcl(acl, acl_size, ACL_REVISION):
            return
        if not advapi32.AddAccessAllowedAce(
            acl, ACL_REVISION,
            FILE_ALL_ACCESS,
            user_sid_ptr,
        ):
            return
        if not advapi32.SetSecurityDescriptorDacl(sd, True, acl, False):
            return
        # 3. Apply to the file with PROTECTED so inheritance is broken.
        path_w = ctypes.c_wchar_p(str(p))
        if not advapi32.SetFileSecurityW(
            path_w,
            DACL_SECURITY_INFORMATION
            | PROTECTED_DACL_SECURITY_INFORMATION,
            sd,
        ):
            return
    except Exception:
        # Any reflection / API mismatch: drop quietly. The chmod
        # below is the best-effort fallback.
        return


def _save_key(p: Path, priv: Ed25519PrivateKey, passphrase: Optional[bytes]) -> None:
    """Atomically persist the Ed25519 identity key.

    v0.20.7 (security audit H19): the previous implementation was a
    direct ``p.write_bytes(pem)`` with no temp-file + fsync + rename
    discipline. A crash or power loss during the write left the user
    with a 0-byte / truncated identity.key, which on next boot caused
    the daemon to silently mint a fresh keypair, rotating the device
    fingerprint, breaking every pinned-trust relationship with paired
    peers, and orphaning all on-disk chunk-availability state.

    v0.20.7 (security audit H3): on Windows, also install an explicit
    user-only DACL via _restrict_windows_acl. `os.chmod(0o600)` only
    flips the read-only bit; the inherited %APPDATA% ACL on a multi-
    admin box can grant Administrators / Authenticated Users read
    access. Setting an explicit DACL with PROTECTED breaks the
    inheritance and grants only the current user's SID.

    The fix:
      1. Write PEM bytes to a unique sibling temp file.
      2. fsync the temp fd so bytes are durable.
      3. os.replace temp → final (atomic on POSIX + Windows NTFS).
      4. fsync the parent directory on POSIX so the rename is durable.
      5. chmod 0o600 (POSIX file-mode bits).
      6. Apply explicit user-only DACL on Windows (no-op on POSIX).
    """
    enc = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp." + secrets.token_hex(8))
    # Windows: O_BINARY suppresses CRLF translation on write so PEM
    # files round-trip byte-equal across save/load (PEM tolerates
    # mixed line endings, but `git diff` and reproducible-build
    # hashing don't). On POSIX O_BINARY isn't defined; the OR is
    # a no-op via getattr.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    flags |= getattr(os, "O_BINARY", 0)
    fd = os.open(str(tmp), flags, 0o600)
    try:
        os.write(fd, pem)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, p)
    if os.name != "nt":
        try:
            dfd = os.open(str(p.parent), os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except (OSError, AttributeError):
            pass
    try:
        os.chmod(p, 0o600)
    except (OSError, NotImplementedError):
        pass
    # v0.20.7 (security audit H3): Windows-only explicit DACL.
    # Best-effort; a failure here leaves the file under the
    # inherited %APPDATA% ACL — same defense as before this fix.
    _restrict_windows_acl(p)


def load_or_create(
    path: Optional[Path] = None,
    *,
    passphrase: Optional[bytes | str] = None,
) -> Identity:
    p = path or key_path()
    pw = _resolve_passphrase(passphrase)

    if p.exists():
        data = p.read_bytes()
        # Try the passphrase we have first; fall back to no-password to
        # support transparent migration unencrypted → encrypted.
        priv = None
        first_err: Optional[Exception] = None
        try:
            priv = serialization.load_pem_private_key(data, password=pw)
        except (TypeError, ValueError) as e:
            first_err = e
            try:
                priv = serialization.load_pem_private_key(data, password=None)
                # File was unencrypted on disk; if a passphrase is set now,
                # re-save encrypted for "transparent migration."
                if pw:
                    _save_key(p, priv, pw)
            except (TypeError, ValueError):
                pass
        if priv is None:
            # Encrypted but wrong/missing passphrase
            raise RuntimeError(
                f"identity key at {p} is encrypted; set {PASSPHRASE_ENV} "
                f"with the correct passphrase ({first_err})"
            )
        if not isinstance(priv, Ed25519PrivateKey):
            raise RuntimeError(f"unexpected key type at {p}: {type(priv).__name__}")
    else:
        # v0.20.7 (master-seed integration): if a master seed has
        # been provisioned (either via "one-link backup init" or
        # via "one-link backup restore"), derive the identity key
        # from that seed instead of minting fresh randomness. This
        # means a user who lost their laptop can type their 24-word
        # phrase on a new device and the identity is byte-identical
        # to the original — peers continue to recognize them.
        # Backward compat: daemons that pre-existed master_seed
        # have no seed file and fall through to the legacy
        # Ed25519PrivateKey.generate() path; those identities are
        # not BIP-39-recoverable, but they continue to work.
        priv = None
        try:
            from one_link import master_seed
            from one_link.paths import data_dir as _data_dir_fn
            seed = master_seed.load_seed(_data_dir_fn())
            if seed is not None:
                priv = master_seed.derive_identity_priv(seed)
        except Exception:
            priv = None
        if priv is None:
            priv = Ed25519PrivateKey.generate()
        _save_key(p, priv, pw)
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fp = _fingerprint(pub_bytes)
    return Identity(
        private=priv,
        public=pub,
        public_bytes=pub_bytes,
        fingerprint=fp,
        short_id=fp[:8],
        hostname=socket.gethostname(),
    )


def verify(public_bytes: bytes, signature: bytes, data: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, data)
        return True
    except Exception:
        return False


def fingerprint_of(public_bytes: bytes) -> str:
    return _fingerprint(public_bytes)

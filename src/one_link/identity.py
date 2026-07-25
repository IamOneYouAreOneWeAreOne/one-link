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

import contextlib
import logging
import os
import secrets
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn, Optional

# External audit 2026-05-18 ES-39 + ES-40: previously silent
# best-effort failures (os.chmod, directory fsync, Windows ACL apply)
# now log.warning so a misbehaving filesystem or stripped-down
# Windows policy doesn't quietly leave the identity key with weaker-
# than-expected at-rest permissions.
log = logging.getLogger(__name__)

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

    @property
    def wire_fingerprint(self) -> str:
        """Public protocol-wire fingerprint: ``sha256:<hex>``.

        The internal ``fingerprint`` is BLAKE3 (faster, used
        everywhere in audit logs and self-mesh state). But the
        browser-peer pairing protocol (peer_rtc + setup_device_invite)
        signs+verifies envelopes against a SHA-256 fingerprint —
        browsers expose SHA-256 in Web Crypto but not BLAKE3, so
        any fingerprint that crosses a wire to peer.html must be
        SHA-256 tagged. Cross-check in peer.html's
        _verifySignedDaemonAnswer reads exactly this format
        (``sha256:<hex>``) and refuses anything else as MITM-suspect.
        """
        import hashlib
        return "sha256:" + hashlib.sha256(self.public_bytes).hexdigest()

    def to_pkcs8_pem(self) -> str:
        """Serialise the private key as an unencrypted PKCS#8 PEM
        string. Used by the Wave 2c QUIC Identity bridge to hand
        the native ``ol_quic::Identity::from_pkcs8_pem`` the same
        Ed25519 key the daemon uses everywhere else, without ever
        sharing the in-memory ``Ed25519PrivateKey`` across the
        FFI boundary.
        """
        return self.private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")


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
    """Install and verify a protected, current-user-only Windows DACL.

    Key authority may not be returned after a best-effort ACL attempt.  Every
    Win32 function has an explicit pointer-width-safe signature, and the DACL
    is read back to prove that it is protected and contains exactly one allow
    ACE for the current user.  Any failure raises
    :class:`KeyMaterialProtectionError`; callers creating non-secret staging
    files already clean up and surface that failure, while secret publishers
    refuse to expose the newly generated authority.
    """
    if os.name != "nt":
        return
    import ctypes
    from ctypes import wintypes

    from one_link.key_material import KeyMaterialProtectionError

    token_query = 0x0008
    token_user_class = 1
    dacl_security_information = 0x00000004
    protected_dacl_security_information = 0x80000000
    security_descriptor_revision = 1
    acl_revision = 2
    file_all_access = 0x001F01FF
    se_dacl_protected = 0x1000
    acl_size_information_class = 2
    access_allowed_ace_type = 0
    se_file_object = 1

    class _SidAndAttributes(ctypes.Structure):
        _fields_ = [("sid", wintypes.LPVOID), ("attributes", wintypes.DWORD)]

    class _TokenUser(ctypes.Structure):
        _fields_ = [("user", _SidAndAttributes)]

    class _AclSizeInformation(ctypes.Structure):
        _fields_ = [
            ("ace_count", wintypes.DWORD),
            ("acl_bytes_in_use", wintypes.DWORD),
            ("acl_bytes_free", wintypes.DWORD),
        ]

    class _AceHeader(ctypes.Structure):
        _fields_ = [
            ("ace_type", wintypes.BYTE),
            ("ace_flags", wintypes.BYTE),
            ("ace_size", wintypes.WORD),
        ]

    class _AccessAllowedAce(ctypes.Structure):
        _fields_ = [
            ("header", _AceHeader),
            ("mask", wintypes.DWORD),
            ("sid_start", wintypes.DWORD),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.LPVOID]
    kernel32.LocalFree.restype = wintypes.LPVOID
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.GetLengthSid.argtypes = [wintypes.LPVOID]
    advapi32.GetLengthSid.restype = wintypes.DWORD
    advapi32.InitializeSecurityDescriptor.argtypes = [wintypes.LPVOID, wintypes.DWORD]
    advapi32.InitializeSecurityDescriptor.restype = wintypes.BOOL
    advapi32.InitializeAcl.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    advapi32.InitializeAcl.restype = wintypes.BOOL
    advapi32.AddAccessAllowedAce.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
    ]
    advapi32.AddAccessAllowedAce.restype = wintypes.BOOL
    advapi32.SetSecurityDescriptorDacl.argtypes = [
        wintypes.LPVOID,
        wintypes.BOOL,
        wintypes.LPVOID,
        wintypes.BOOL,
    ]
    advapi32.SetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.SetFileSecurityW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
    ]
    advapi32.SetFileSecurityW.restype = wintypes.BOOL
    advapi32.GetFileSecurityW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetFileSecurityW.restype = wintypes.BOOL
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetSecurityDescriptorControl.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.GetAclInformation.argtypes = [
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    advapi32.GetAclInformation.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.EqualSid.argtypes = [wintypes.LPVOID, wintypes.LPVOID]
    advapi32.EqualSid.restype = wintypes.BOOL

    def _fail(operation: str) -> NoReturn:
        code = int(ctypes.get_last_error())
        detail = ctypes.FormatError(code).strip() if code else "verification failed"
        raise KeyMaterialProtectionError(
            f"Windows private-ACL {operation} failed ({code}: {detail})"
        )

    def _fail_code(operation: str, code: int) -> NoReturn:
        detail = ctypes.FormatError(code).strip() if code else "verification failed"
        raise KeyMaterialProtectionError(
            f"Windows private-ACL {operation} failed ({code}: {detail})"
        )

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), token_query, ctypes.byref(token)
    ):
        _fail("OpenProcessToken")
    try:
        size = wintypes.DWORD()
        advapi32.GetTokenInformation(
            token, token_user_class, None, 0, ctypes.byref(size)
        )
        if size.value <= 0:
            _fail("GetTokenInformation(size)")
        token_info = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(
            token, token_user_class, token_info, size, ctypes.byref(size)
        ):
            _fail("GetTokenInformation")
        user_sid_ptr = ctypes.cast(
            token_info, ctypes.POINTER(_TokenUser)
        ).contents.user.sid
        sid_len = int(advapi32.GetLengthSid(user_sid_ptr))
        if sid_len <= 0:
            _fail("GetLengthSid")

        sd = ctypes.create_string_buffer(64)
        if not advapi32.InitializeSecurityDescriptor(sd, security_descriptor_revision):
            _fail("InitializeSecurityDescriptor")
        acl_size = 8 + 8 + sid_len + 16
        acl = ctypes.create_string_buffer(acl_size)
        if not advapi32.InitializeAcl(acl, acl_size, acl_revision):
            _fail("InitializeAcl")
        if not advapi32.AddAccessAllowedAce(
            acl, acl_revision, file_all_access, user_sid_ptr
        ):
            _fail("AddAccessAllowedAce")
        if not advapi32.SetSecurityDescriptorDacl(sd, True, acl, False):
            _fail("SetSecurityDescriptorDacl")
        if not advapi32.SetFileSecurityW(
            str(p),
            dacl_security_information | protected_dacl_security_information,
            sd,
        ):
            _fail("SetFileSecurityW")
        # SetNamedSecurityInfo is the authoritative inheritance-control API.
        # SetFileSecurity can canonicalize away SE_DACL_PROTECTED for a child
        # created inside an already non-inheriting private directory even
        # though the ACE list is safe; applying the explicit protection flag
        # here makes the persisted control bit itself unambiguous.
        named_status = int(
            advapi32.SetNamedSecurityInfoW(
                str(p),
                se_file_object,
                dacl_security_information | protected_dacl_security_information,
                None,
                None,
                acl,
                None,
            )
        )
        if named_status:
            _fail_code("SetNamedSecurityInfoW", named_status)

        readback_acl = wintypes.LPVOID()
        readback_sd = wintypes.LPVOID()
        status = int(
            advapi32.GetNamedSecurityInfoW(
                str(p),
                se_file_object,
                dacl_security_information,
                None,
                None,
                ctypes.byref(readback_acl),
                None,
                ctypes.byref(readback_sd),
            )
        )
        if status:
            _fail_code("GetNamedSecurityInfoW", status)
        try:
            control = wintypes.WORD()
            revision = wintypes.DWORD()
            if not advapi32.GetSecurityDescriptorControl(
                readback_sd, ctypes.byref(control), ctypes.byref(revision)
            ):
                _fail("GetSecurityDescriptorControl")
            if not (int(control.value) & se_dacl_protected):
                raise KeyMaterialProtectionError(
                    "Windows private-ACL DACL protection verification failed "
                    f"(control=0x{int(control.value):04x})"
                )
            if not readback_acl:
                _fail("DACL presence verification")
            acl_info = _AclSizeInformation()
            if not advapi32.GetAclInformation(
                readback_acl,
                ctypes.byref(acl_info),
                ctypes.sizeof(acl_info),
                acl_size_information_class,
            ):
                _fail("GetAclInformation")
            if int(acl_info.ace_count) != 1:
                _fail("DACL trustee-count verification")
            ace_ptr = wintypes.LPVOID()
            if not advapi32.GetAce(readback_acl, 0, ctypes.byref(ace_ptr)):
                _fail("GetAce")
            ace = ctypes.cast(ace_ptr, ctypes.POINTER(_AccessAllowedAce)).contents
            if (
                int(ace.header.ace_type) != access_allowed_ace_type
                or int(ace.header.ace_size) < ctypes.sizeof(_AccessAllowedAce)
                or int(ace.mask) != file_all_access
            ):
                _fail("DACL ACE verification")
            ace_address = ace_ptr.value
            if ace_address is None:
                _fail("DACL ACE address verification")
            ace_sid = ctypes.c_void_p(
                int(ace_address) + _AccessAllowedAce.sid_start.offset
            )
            if not advapi32.EqualSid(ace_sid, user_sid_ptr):
                _fail("DACL trustee verification")
        finally:
            if readback_sd:
                kernel32.LocalFree(readback_sd)
        log.debug("identity._restrict_windows_acl: verified user-only DACL on %s", p)
    finally:
        kernel32.CloseHandle(token)


def _zero_overwrite_file(p: Path) -> None:
    """Best-effort secure-overwrite for an existing file before it's
    replaced. Writes random bytes the same length as the original,
    fsyncs, then leaves the path in place for the caller's atomic-
    rename to clobber.

    This is the v0.21.x ES-3 mitigation for cleartext-PEM-on-COW-
    filesystem-residue. It cannot guarantee the original bytes are
    irrecoverable (SSDs / journaled / log-structured filesystems
    may have already mirrored the page to a different physical
    block), but it closes the simple-metadata-stays-readable hole
    that arises when ``os.replace`` releases the old inode without
    overwriting its contents.

    On any IO error this returns silently — the caller's atomic
    rename will still proceed, and not doing the overwrite is no
    worse than the pre-v0.21.x behaviour.
    """
    try:
        if not p.exists() or not p.is_file():
            return
        size = p.stat().st_size
        if size <= 0:
            return
        with open(p, "r+b", buffering=0) as f:
            # Two passes: first random (defeats simple sector-scanner
            # tools), then zeros (defeats "leftover entropy" heuristics).
            # Both fsync'd so the OS can't reorder them away.
            f.seek(0)
            f.write(os.urandom(size))
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
            f.seek(0)
            f.write(b"\x00" * size)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
    except OSError as e:
        log.warning(
            "identity._zero_overwrite_file: best-effort secure-erase "
            "failed for %s: %s. Continuing with atomic rename; the old "
            "cleartext bytes may survive in FS free space.",
            p, e,
        )


def _save_key(
    p: Path,
    priv: Ed25519PrivateKey,
    passphrase: Optional[bytes],
    *,
    replace: bool = True,
) -> None:
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
    from one_link.key_material import (
        KeyMaterialIntegrityError,
        atomic_create_bytes,
        atomic_replace_bytes,
    )

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
    expected = priv.private_bytes_raw()

    def _validate(blob: bytes) -> None:
        try:
            loaded = serialization.load_pem_private_key(blob, password=passphrase)
        except (TypeError, ValueError) as exc:
            raise KeyMaterialIntegrityError(
                "persisted identity key cannot be decoded with its requested protection"
            ) from exc
        if not isinstance(loaded, Ed25519PrivateKey):
            raise KeyMaterialIntegrityError(
                "persisted identity key has an unexpected key type"
            )
        if not secrets.compare_digest(loaded.private_bytes_raw(), expected):
            raise KeyMaterialIntegrityError(
                "persisted identity key does not match requested authority"
            )

    hardener = _restrict_windows_acl if os.name == "nt" else None
    if replace:
        atomic_replace_bytes(
            p,
            pem,
            label="identity key",
            validate=_validate,
            harden_path=hardener,
        )
        return
    if not atomic_create_bytes(
        p,
        pem,
        label="identity key",
        validate=_validate,
        harden_path=hardener,
    ):
        raise FileExistsError(f"identity key was concurrently created at {p}")


def _migrate_key_encryption(
    p: Path,
    priv: Ed25519PrivateKey,
    passphrase: bytes,
) -> None:
    """Atomically encrypt an existing PEM without pre-destroying authority.

    On POSIX an open descriptor retains the old inode across ``os.replace``;
    only after the encrypted replacement has passed read-back validation do
    we best-effort overwrite that unlinked inode.  On Windows an open handle
    can prevent the atomic replacement, so publication remains the priority
    and filesystem-level residue is left to BitLocker/secure storage.
    """

    retained_fd: int | None = None
    if os.name != "nt":
        flags = os.O_RDWR | int(getattr(os, "O_CLOEXEC", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        try:
            retained_fd = os.open(str(p), flags)
        except OSError:
            retained_fd = None
    try:
        _save_key(p, priv, passphrase)
        if retained_fd is None:
            return
        try:
            size = int(os.fstat(retained_fd).st_size)
            for fill in (None, b"\x00"):
                os.lseek(retained_fd, 0, os.SEEK_SET)
                remaining = size
                while remaining:
                    count = min(remaining, 65536)
                    payload = os.urandom(count) if fill is None else fill * count
                    offset = 0
                    while offset < len(payload):
                        wrote = os.write(retained_fd, payload[offset:])
                        if wrote <= 0:
                            raise OSError("short write erasing retired identity inode")
                        offset += wrote
                    remaining -= count
                os.fsync(retained_fd)
        except OSError as exc:
            log.warning(
                "identity migration published safely, but best-effort erasure "
                "of the retired cleartext inode failed: %s",
                exc,
            )
    finally:
        if retained_fd is not None:
            os.close(retained_fd)


def _load_existing_private_key(
    path: Path,
    *,
    passphrase: Optional[bytes | str] = None,
) -> Optional[Ed25519PrivateKey]:
    """Load an existing identity without creating or migrating it.

    Recovery and boot authority checks must be observational: a validation
    failure cannot be allowed to mint a replacement key or transparently
    rewrite the artifact being examined.  ``None`` therefore means only a
    proven-absent path; malformed, inaccessible, or wrongly protected keys
    raise.
    """
    from one_link.key_material import KeyMaterialIntegrityError, read_bytes_if_exists

    p = Path(path)
    blob = read_bytes_if_exists(
        p,
        label="identity key",
        max_bytes=1 << 20,
        harden_path=_restrict_windows_acl if os.name == "nt" else None,
    )
    if blob is None:
        return None
    pw = _resolve_passphrase(passphrase)
    errors: list[Exception] = []
    candidates: tuple[Optional[bytes], ...] = (pw, None) if pw else (None,)
    for candidate in candidates:
        try:
            loaded = serialization.load_pem_private_key(blob, password=candidate)
        except (TypeError, ValueError) as exc:
            errors.append(exc)
            continue
        if not isinstance(loaded, Ed25519PrivateKey):
            raise KeyMaterialIntegrityError(
                f"identity key at {p} is not an Ed25519 private key"
            )
        return loaded
    detail = errors[0] if errors else "unknown decode failure"
    raise KeyMaterialIntegrityError(
        f"identity key at {p} could not be decoded with the configured protection: "
        f"{detail}"
    )


def identity_file_matches_seed(
    path: Path,
    seed: bytes,
    *,
    passphrase: Optional[bytes | str] = None,
) -> Optional[bool]:
    """Return whether an on-disk identity is the one derived from ``seed``.

    ``None`` denotes a proven-absent identity.  This helper never creates or
    migrates key material, making it safe for phrase verification and daemon
    preflight checks.
    """
    from one_link import master_seed

    current = _load_existing_private_key(path, passphrase=passphrase)
    if current is None:
        return None
    expected = master_seed.derive_identity_priv(bytes(seed))
    return secrets.compare_digest(
        current.private_bytes_raw(),
        expected.private_bytes_raw(),
    )


def store_seed_derived_identity(
    path: Path,
    seed: bytes,
    *,
    passphrase: Optional[bytes | str] = None,
) -> Identity:
    """Atomically replace ``path`` with the identity derived from ``seed``.

    The caller owns the surrounding multi-artifact recovery journal.  This
    function provides the single-file atomic publication and exact read-back
    proof needed by that transaction.
    """
    from one_link import master_seed
    from one_link.key_material import KeyMaterialIntegrityError

    p = Path(path)
    pw = _resolve_passphrase(passphrase)
    private = master_seed.derive_identity_priv(bytes(seed))
    _save_key(p, private, pw, replace=True)
    matches = identity_file_matches_seed(p, bytes(seed), passphrase=pw)
    if matches is not True:
        raise KeyMaterialIntegrityError(
            "published identity does not match the recovered master seed"
        )
    public = private.public_key()
    public_bytes = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fp = _fingerprint(public_bytes)
    return Identity(
        private=private,
        public=public,
        public_bytes=public_bytes,
        fingerprint=fp,
        short_id=fp[:8],
        hostname=socket.gethostname(),
    )


def load_or_create(
    path: Optional[Path] = None,
    *,
    passphrase: Optional[bytes | str] = None,
) -> Identity:
    from one_link.key_material import read_bytes_if_exists, sync_existing_authority

    p = path or key_path()
    pw = _resolve_passphrase(passphrase)
    existing_bytes = read_bytes_if_exists(
        p,
        label="identity key",
        max_bytes=1 << 20,
        harden_path=_restrict_windows_acl if os.name == "nt" else None,
    )

    if existing_bytes is not None:
        data = existing_bytes
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
                # re-save encrypted for "transparent migration." The
                # narrowing-cast tells mypy the loaded key is Ed25519
                # (verified downstream by the caller); _save_key's
                # signature is intentionally tight.
                if pw:
                    if not isinstance(priv, Ed25519PrivateKey):
                        raise RuntimeError(
                            "key file must hold an Ed25519 private key"
                        )
                    # 2026-05-21 audit T1-K: file-lock the migration
                    # so two daemons starting at the same time don't
                    # race ``_zero_overwrite_file → _save_key``. If
                    # we lose the race (lock file already exists),
                    # the other process wins — we just re-load.
                    # Cross-platform via O_CREAT|O_EXCL.
                    lock_path = p.with_suffix(p.suffix + ".migrate.lock")
                    lock_fd = None
                    try:
                        try:
                            lock_fd = os.open(
                                str(lock_path),
                                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                                0o600,
                            )
                        except FileExistsError:
                            # Another process is migrating right now.
                            # Re-read the file in a moment and trust
                            # what they wrote. If their migration
                            # crashes mid-way we'll need a lock-file
                            # sweep, but a 5s-stale lock cleanup is
                            # outside this fix's scope.
                            pass
                        else:
                            # Build, fsync, decode, and key-compare the
                            # encrypted replacement before the atomic
                            # publish.  The old cleartext authority is never
                            # modified on a save/fsync/ACL/rename failure.
                            _migrate_key_encryption(p, priv, pw)
                    finally:
                        if lock_fd is not None:
                            with contextlib.suppress(Exception):
                                os.close(lock_fd)
                            with contextlib.suppress(Exception):
                                lock_path.unlink()
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
        from one_link import master_seed
        from one_link.paths import data_dir as _data_dir_fn

        seed = master_seed.load_seed(_data_dir_fn())
        if seed is not None:
            priv = master_seed.derive_identity_priv(seed)
        if priv is None:
            priv = Ed25519PrivateKey.generate()
        try:
            _save_key(p, priv, pw, replace=False)
        except FileExistsError:
            # A concurrent first boot won atomic no-replace publication.
            # Discard our candidate and load the durable winner; never return
            # ephemeral authority that differs from the on-disk identity.
            sync_existing_authority(p, label="identity key")
            return load_or_create(path=p, passphrase=passphrase)
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
    """Verify ``signature`` over ``data`` under ``public_bytes``.

    2026-05-21 audit (crypto agent): the previous bare ``except Exception``
    swallowed everything — InvalidSignature (the legitimate negative),
    but also ``ValueError`` from a malformed pubkey length and any
    library-internal exceptions. That meant a packing bug elsewhere
    (e.g. ``public_bytes`` of length != 32) silently looked like a
    signature-mismatch, which in ``channel.respond`` falls through
    from the v2 attempt to the v1 attempt and accepts the legacy
    HELLO sig. Narrow to ``InvalidSignature`` + ``ValueError`` (raised
    by ``from_public_bytes`` on length mismatch) only; surface
    anything else so the failure mode is loud, not a hidden downgrade.
    """
    from cryptography.exceptions import InvalidSignature
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, data)
        return True
    except (InvalidSignature, ValueError):
        return False


def fingerprint_of(public_bytes: bytes) -> str:
    return _fingerprint(public_bytes)

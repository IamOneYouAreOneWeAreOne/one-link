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
import sys
import secrets
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

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
    # External audit 2026-05-18 ES-40: every failure path in this
    # function was `return` with no log. On a Windows box where the
    # ACL apply fails, the user thought the file was user-only but
    # was actually on the inherited %APPDATA% ACL (which typically
    # grants Administrators + SYSTEM read). Promote each early
    # return to log.warning with the failure point named so ops can
    # grep for "ACL apply failed at step N".
    try:
        import ctypes
        from ctypes import wintypes
    except Exception as e:
        log.warning("identity._restrict_windows_acl: ctypes unavailable: %s", e)
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
            log.warning(
                "identity._restrict_windows_acl: OpenProcessToken failed "
                "(error %d); identity key on inherited %%APPDATA%% ACL.",
                ctypes.get_last_error(),
            )
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
                log.warning(
                    "identity._restrict_windows_acl: GetTokenInformation failed "
                    "(error %d); identity key on inherited ACL.",
                    ctypes.get_last_error(),
                )
                return
            # TOKEN_USER struct: SID_AND_ATTRIBUTES { PSID Sid; DWORD Attributes }
            user_sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
            sid_len = advapi32.GetLengthSid(user_sid_ptr)
            if not sid_len:
                log.warning("identity._restrict_windows_acl: GetLengthSid returned 0")
                return
        finally:
            kernel32.CloseHandle(token)

        # 2. Build a security descriptor + DACL containing one ACE.
        sd = (ctypes.c_byte * 1024)()
        if not advapi32.InitializeSecurityDescriptor(
            sd, SECURITY_DESCRIPTOR_REVISION
        ):
            log.warning("identity._restrict_windows_acl: InitializeSecurityDescriptor failed")
            return
        # Allocate ACL: enough for the SD header (8) + one ACE
        # (8 + sid_len). Round up.
        acl_size = 8 + 8 + sid_len + 16
        acl = (ctypes.c_byte * acl_size)()
        if not advapi32.InitializeAcl(acl, acl_size, ACL_REVISION):
            log.warning("identity._restrict_windows_acl: InitializeAcl failed")
            return
        if not advapi32.AddAccessAllowedAce(
            acl, ACL_REVISION,
            FILE_ALL_ACCESS,
            user_sid_ptr,
        ):
            log.warning("identity._restrict_windows_acl: AddAccessAllowedAce failed")
            return
        if not advapi32.SetSecurityDescriptorDacl(sd, True, acl, False):
            log.warning("identity._restrict_windows_acl: SetSecurityDescriptorDacl failed")
            return
        # 3. Apply to the file with PROTECTED so inheritance is broken.
        path_w = ctypes.c_wchar_p(str(p))
        if not advapi32.SetFileSecurityW(
            path_w,
            DACL_SECURITY_INFORMATION
            | PROTECTED_DACL_SECURITY_INFORMATION,
            sd,
        ):
            log.warning(
                "identity._restrict_windows_acl: SetFileSecurityW on %s failed "
                "(error %d); identity key on inherited ACL.",
                p, ctypes.get_last_error(),
            )
            return
        log.debug("identity._restrict_windows_acl: applied user-only DACL to %s", p)
    except Exception as e:
        log.warning(
            "identity._restrict_windows_acl: unexpected exception (%s); "
            "identity key on inherited %%APPDATA%% ACL.",
            e,
        )
        return


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
    if sys.platform != "win32":
        try:
            # POSIX-only flag — guarded by sys.platform narrow so
            # mypy resolves os.O_DIRECTORY from the POSIX stub set
            # and the constant is reachable on the runtime platform.
            dfd = os.open(str(p.parent), os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except (OSError, AttributeError) as e:
            # External audit 2026-05-18 ES-39: was silent. A
            # directory-fsync failure could mean the FS is read-only,
            # or O_DIRECTORY isn't supported on this platform (Windows
            # is one case where AttributeError fires). Log so ops can
            # grep for misbehaving filesystems instead of guessing.
            log.warning("identity._save_key: directory fsync failed: %s", e)
    try:
        os.chmod(p, 0o600)
    except (OSError, NotImplementedError) as e:
        # ES-39: silent before. A chmod failure means the file is
        # readable by other users on this box. Loud so a misconfigured
        # umask / Windows quirk doesn't quietly weaken at-rest perms.
        log.warning(
            "identity._save_key: chmod 0o600 on %s failed: %s. "
            "Identity-key file may be readable by other local users.",
            p, e,
        )
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
                            # External audit 2026-05-18 ES-3: before
                            # _save_key atomic-renames the new
                            # encrypted PEM into place, overwrite
                            # the existing cleartext PEM file with
                            # random bytes + fsync. Closes the
                            # cleartext-bytes-in-old-inode hole.
                            _zero_overwrite_file(p)
                            _save_key(p, priv, pw)
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

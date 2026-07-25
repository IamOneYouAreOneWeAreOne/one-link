"""Authenticated, bounded local control-channel protocol.

Loopback is a routing property, not an authorization boundary: any process
running as the logged-in user can connect to a localhost TCP port.  The One
Link control socket can send arbitrary local files, change peer trust, and
stop the daemon, so every request uses a mutually-authenticated challenge /
response exchange backed by a private per-install secret.

The server proves possession of the secret *before* a launcher trusts any
self-reported UI port.  The client then proves possession while binding its
request to both fresh nonces.  Captured requests cannot be replayed on a new
connection because the daemon chooses a new server nonce for every exchange.
All frames are newline-delimited JSON with explicit byte ceilings.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import os
import secrets
import socket
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from one_link.paths import data_dir


CONTROL_SECRET_FILE = "control.secret"
CONTROL_PROTOCOL_VERSION = 1
CONTROL_SECRET_BYTES = 32
CONTROL_NONCE_BYTES = 32
CONTROL_HANDSHAKE_MAX_BYTES = 4 * 1024
CONTROL_REQUEST_MAX_BYTES = 1024 * 1024
CONTROL_RESPONSE_MAX_BYTES = 8 * 1024 * 1024
CONTROL_HANDSHAKE_TIMEOUT_S = 3.0
CONTROL_RESPONSE_WRITE_TIMEOUT_S = 5.0
CONTROL_CLOSE_TIMEOUT_S = 1.0
CONTROL_MAX_CONCURRENT_CONNECTIONS = 64
CONTROL_TAIL_EVENT_MAX_BYTES = 1024 * 1024
CONTROL_TAIL_MAX_PENDING_BYTES = 2 * 1024 * 1024
CONTROL_TAIL_LIVENESS_POLL_S = 5.0

_SERVER_PROOF_DOMAIN = b"OL/control-ipc/server-proof/v1\0"
_CLIENT_PROOF_DOMAIN = b"OL/control-ipc/client-request/v1\0"
_RESPONSE_PROOF_DOMAIN = b"OL/control-ipc/server-response/v1\0"
_UI_INSTANCE_PROOF_DOMAIN = b"OL/ui-instance-proof/v1\0"


def _set_owner_only_fd(fd: int) -> None:
    """Apply POSIX owner-only mode without assuming ``os.fchmod`` on Windows."""
    fchmod = getattr(os, "fchmod", None)
    if not callable(fchmod):
        raise OSError("descriptor permission hardening is unavailable")
    fchmod(fd, 0o600)


class ControlProtocolError(RuntimeError):
    """A bounded control frame was malformed or incomplete."""


class ControlAuthenticationError(ControlProtocolError):
    """The peer failed mutual control-channel authentication."""


class ControlFrameTooLarge(ControlProtocolError):
    """A control frame exceeded its declared protocol ceiling."""


@dataclass(frozen=True)
class ControlExchange:
    """Cryptographic context shared by one request and its response."""

    client_nonce: str
    server_nonce: str
    request_bytes: bytes


def _secret_path(root: Path | None = None) -> Path:
    return Path(root) / CONTROL_SECRET_FILE if root is not None else data_dir() / CONTROL_SECRET_FILE


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _decode_b64u(value: str, *, expected_bytes: int, label: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise ControlAuthenticationError(f"invalid {label}")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise ControlAuthenticationError(f"invalid {label}") from exc
    if len(raw) != expected_bytes or _b64u(raw) != value:
        raise ControlAuthenticationError(f"invalid {label}")
    return raw


def _secret_bytes(secret: str) -> bytes:
    return _decode_b64u(
        secret,
        expected_bytes=CONTROL_SECRET_BYTES,
        label="control secret",
    )


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ControlProtocolError("control payload is not canonical JSON") from exc


def _constant_time_ascii_equal(supplied: Any, expected: str) -> bool:
    """Compare an untrusted JSON string without ``compare_digest`` type leaks."""

    if not isinstance(supplied, str) or len(supplied) != len(expected):
        return False
    try:
        supplied.encode("ascii")
    except UnicodeEncodeError:
        return False
    return hmac.compare_digest(supplied, expected)


def _mac(secret: str, domain: bytes, *parts: bytes) -> str:
    digest = hmac.new(_secret_bytes(secret), digestmod=hashlib.sha256)
    digest.update(domain)
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.hexdigest()


def _path_is_link_or_reparse(path_stat: os.stat_result) -> bool:
    attrs = int(getattr(path_stat, "st_file_attributes", 0) or 0)
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(path_stat.st_mode) or bool(attrs & reparse)


def _is_single_link_current_owner(path_stat: os.stat_result) -> bool:
    """Reject hard-link aliases and, on POSIX, foreign-owned credentials."""

    if int(getattr(path_stat, "st_nlink", 1)) != 1:
        return False
    get_euid = getattr(os, "geteuid", None)
    return get_euid is None or int(path_stat.st_uid) == int(get_euid())


def _restrict_secret_file(path: Path) -> None:
    if os.name == "nt":
        _restrict_windows_acl_strict(path)
        return
    os.chmod(path, 0o600)


def _restrict_windows_acl_strict(path: Path) -> None:
    """Install a protected, current-user-only DACL or raise.

    Identity-key ACL tightening elsewhere in the application is deliberately
    best effort for backwards compatibility.  The control credential has a
    stronger contract: publishing a privileged local API without knowing its
    authentication root is private would be a fail-open startup.  Use the
    Win32 security APIs directly and make every failure fatal to daemon start.
    """

    if os.name != "nt":
        return
    import ctypes
    from ctypes import wintypes

    token_query = 0x0008
    token_user_class = 1
    dacl_security_information = 0x00000004
    protected_dacl_security_information = 0x80000000
    security_descriptor_revision = 1
    acl_revision = 2
    file_all_access = 0x001F01FF

    class _SidAndAttributes(ctypes.Structure):
        _fields_ = [("sid", wintypes.LPVOID), ("attributes", wintypes.DWORD)]

    class _TokenUser(ctypes.Structure):
        _fields_ = [("user", _SidAndAttributes)]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
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

    def _raise_last_error(operation: str) -> None:
        code = int(ctypes.get_last_error())
        raise OSError(code, f"{operation} failed: {ctypes.FormatError(code)}")

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        token_query,
        ctypes.byref(token),
    ):
        _raise_last_error("OpenProcessToken")
    try:
        required = wintypes.DWORD()
        advapi32.GetTokenInformation(
            token,
            token_user_class,
            None,
            0,
            ctypes.byref(required),
        )
        if required.value <= 0:
            _raise_last_error("GetTokenInformation(size)")
        token_info = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            token,
            token_user_class,
            token_info,
            required,
            ctypes.byref(required),
        ):
            _raise_last_error("GetTokenInformation")
        sid = ctypes.cast(token_info, ctypes.POINTER(_TokenUser)).contents.user.sid
        sid_length = int(advapi32.GetLengthSid(sid))
        if sid_length <= 0:
            _raise_last_error("GetLengthSid")

        security_descriptor = ctypes.create_string_buffer(64)
        if not advapi32.InitializeSecurityDescriptor(
            security_descriptor,
            security_descriptor_revision,
        ):
            _raise_last_error("InitializeSecurityDescriptor")
        acl_size = 8 + 8 + sid_length + 16
        acl = ctypes.create_string_buffer(acl_size)
        if not advapi32.InitializeAcl(acl, acl_size, acl_revision):
            _raise_last_error("InitializeAcl")
        if not advapi32.AddAccessAllowedAce(
            acl,
            acl_revision,
            file_all_access,
            sid,
        ):
            _raise_last_error("AddAccessAllowedAce")
        if not advapi32.SetSecurityDescriptorDacl(
            security_descriptor,
            True,
            acl,
            False,
        ):
            _raise_last_error("SetSecurityDescriptorDacl")
        if not advapi32.SetFileSecurityW(
            str(path),
            dacl_security_information | protected_dacl_security_information,
            security_descriptor,
        ):
            _raise_last_error("SetFileSecurityW")
    finally:
        kernel32.CloseHandle(token)


def _read_secret_path(path: Path) -> str:
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise RuntimeError("control authentication secret missing") from exc
    if (
        _path_is_link_or_reparse(before)
        or not stat.S_ISREG(before.st_mode)
        or not _is_single_link_current_owner(before)
    ):
        raise RuntimeError("control authentication secret is not a regular private file")

    flags = os.O_RDONLY | int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(str(path), flags)
    except OSError as exc:
        raise RuntimeError("control authentication secret cannot be opened safely") from exc
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not _is_single_link_current_owner(opened)
        ):
            raise RuntimeError("control authentication secret changed type while opening")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError("control authentication secret changed while opening")
        raw = os.read(fd, 256)
        if os.read(fd, 1):
            raise RuntimeError("control authentication secret is oversized")
        if os.name != "nt":
            try:
                _set_owner_only_fd(fd)
            except OSError as exc:
                raise RuntimeError(
                    "control authentication secret permissions are unsafe"
                ) from exc
    finally:
        os.close(fd)

    try:
        secret = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RuntimeError("control authentication secret is corrupt") from exc
    if secret != secret.strip():
        raise RuntimeError("control authentication secret is not canonical")
    try:
        _secret_bytes(secret)
    except ControlAuthenticationError as exc:
        raise RuntimeError("control authentication secret is corrupt") from exc

    # Tighten legacy/umask-created files before returning the credential.
    try:
        if os.name == "nt":
            _restrict_secret_file(path)
    except OSError as exc:
        raise RuntimeError("control authentication secret permissions are unsafe") from exc
    try:
        after = os.lstat(path)
    except OSError as exc:
        raise RuntimeError("control authentication secret changed after opening") from exc
    if (
        _path_is_link_or_reparse(after)
        or not _is_single_link_current_owner(after)
        or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        raise RuntimeError("control authentication secret changed after opening")
    if os.name != "nt" and (after.st_mode & 0o077):
        raise RuntimeError("control authentication secret permissions are unsafe")
    return secret


def read_control_secret(root: Path | None = None) -> str:
    """Read and validate the existing per-install control secret.

    Clients never create this file.  Absence, corruption, unsafe type, or
    unsafe POSIX permissions fails closed instead of silently rotating away
    from a running daemon.
    """

    return _read_secret_path(_secret_path(root))


def read_private_bytes_strict(
    path: Path,
    *,
    max_bytes: int,
    label: str = "private file",
) -> bytes:
    """Read one bounded private regular file and re-assert owner-only access."""

    limit = int(max_bytes)
    if limit <= 0:
        raise ValueError("max_bytes must be positive")
    candidate = Path(path)
    before = os.lstat(candidate)
    if (
        _path_is_link_or_reparse(before)
        or not stat.S_ISREG(before.st_mode)
        or not _is_single_link_current_owner(before)
    ):
        raise RuntimeError(f"{label} is not a regular private file")
    flags = (
        os.O_RDONLY
        | int(getattr(os, "O_CLOEXEC", 0))
        | int(getattr(os, "O_BINARY", 0))
        | int(getattr(os, "O_NOFOLLOW", 0))
    )
    fd = os.open(str(candidate), flags)
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not _is_single_link_current_owner(opened)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise RuntimeError(f"{label} changed while opening")
        if os.name != "nt":
            _set_owner_only_fd(fd)
        raw = os.read(fd, limit + 1)
        if len(raw) > limit:
            raise RuntimeError(f"{label} exceeds byte limit")
    finally:
        os.close(fd)
    if os.name == "nt":
        _restrict_secret_file(candidate)
    after = os.lstat(candidate)
    if (
        _path_is_link_or_reparse(after)
        or not stat.S_ISREG(after.st_mode)
        or not _is_single_link_current_owner(after)
        or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        raise RuntimeError(f"{label} changed after opening")
    if os.name != "nt" and (after.st_mode & 0o077):
        raise RuntimeError(f"{label} permissions are unsafe")
    return raw


def write_private_bytes_strict(
    path: Path,
    payload: bytes,
    *,
    max_bytes: int,
    label: str = "private file",
) -> None:
    """Atomically replace ``path`` with owner-only bytes, never following it."""

    value = bytes(payload)
    limit = int(max_bytes)
    if limit <= 0 or len(value) > limit:
        raise ValueError(f"{label} exceeds byte limit")
    target = Path(path)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = target.with_name(
        f".{target.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | int(getattr(os, "O_CLOEXEC", 0))
        | int(getattr(os, "O_BINARY", 0))
        | int(getattr(os, "O_NOFOLLOW", 0))
    )
    fd: int | None = None
    try:
        fd = os.open(str(temporary), flags, 0o600)
        # Apply the protected Windows DACL while the file is still empty.
        _restrict_secret_file(temporary)
        written = 0
        while written < len(value):
            count = os.write(fd, value[written:])
            if count <= 0:
                raise OSError(f"short write while publishing {label}")
            written += count
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.replace(temporary, target)
        _restrict_secret_file(target)
        if os.name != "nt":
            directory_fd = os.open(str(target.parent), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        if read_private_bytes_strict(
            target,
            max_bytes=limit,
            label=label,
        ) != value:
            raise RuntimeError(f"{label} changed while publishing")
    except OSError as exc:
        raise RuntimeError(f"{label} could not be published privately") from exc
    finally:
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)
        with contextlib.suppress(OSError):
            temporary.unlink()


def load_or_create_control_secret(root: Path | None = None) -> str:
    """Load the control secret, creating it atomically on first daemon boot."""

    path = _secret_path(root)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        return _read_secret_path(path)

    secret = _b64u(secrets.token_bytes(CONTROL_SECRET_BYTES))
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | int(getattr(os, "O_CLOEXEC", 0))
        | int(getattr(os, "O_NOFOLLOW", 0))
    )
    fd: int | None = None
    try:
        try:
            fd = os.open(str(temporary), flags, 0o600)
            # On Windows, a newly-created file inherits its directory DACL.
            # Tighten the still-empty file before writing the credential so
            # there is never a readable-by-inheritance exposure window.  POSIX
            # already gets mode 0600 atomically from os.open; the explicit pass
            # also defends unusual umasks/filesystems and keeps one invariant.
            _restrict_secret_file(temporary)
            payload = secret.encode("ascii")
            written = 0
            while written < len(payload):
                count = os.write(fd, payload[written:])
                if count <= 0:
                    raise OSError(
                        "short write while creating control authentication secret"
                    )
                written += count
            os.fsync(fd)
            os.close(fd)
            fd = None
            if path.exists() or path.is_symlink():
                return _read_secret_path(path)
            os.replace(temporary, path)
            _restrict_secret_file(path)
            if os.name != "nt":
                directory_fd = os.open(str(path.parent), os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            return _read_secret_path(path)
        except OSError as exc:
            raise RuntimeError(
                "control authentication secret permissions are unsafe"
            ) from exc
    finally:
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)
        with contextlib.suppress(OSError):
            temporary.unlink()


def make_client_hello(*, client_nonce: str | None = None) -> tuple[dict[str, Any], str]:
    nonce = client_nonce or _b64u(secrets.token_bytes(CONTROL_NONCE_BYTES))
    _decode_b64u(nonce, expected_bytes=CONTROL_NONCE_BYTES, label="client nonce")
    return {"ipc_v": CONTROL_PROTOCOL_VERSION, "client_nonce": nonce}, nonce


def make_server_challenge(
    hello: Mapping[str, Any],
    secret: str,
    *,
    server_nonce: str | None = None,
) -> tuple[dict[str, Any], str, str]:
    if hello.get("ipc_v") != CONTROL_PROTOCOL_VERSION:
        raise ControlAuthenticationError("unsupported control protocol")
    client_nonce = str(hello.get("client_nonce") or "")
    _decode_b64u(client_nonce, expected_bytes=CONTROL_NONCE_BYTES, label="client nonce")
    chosen = server_nonce or _b64u(secrets.token_bytes(CONTROL_NONCE_BYTES))
    _decode_b64u(chosen, expected_bytes=CONTROL_NONCE_BYTES, label="server nonce")
    proof = _mac(
        secret,
        _SERVER_PROOF_DOMAIN,
        client_nonce.encode("ascii"),
        chosen.encode("ascii"),
    )
    return (
        {
            "ipc_v": CONTROL_PROTOCOL_VERSION,
            "client_nonce": client_nonce,
            "server_nonce": chosen,
            "server_proof": proof,
        },
        client_nonce,
        chosen,
    )


def verify_server_challenge(
    challenge: Mapping[str, Any],
    secret: str,
    *,
    client_nonce: str,
) -> str:
    if challenge.get("ipc_v") != CONTROL_PROTOCOL_VERSION:
        raise ControlAuthenticationError("daemon did not authenticate the control protocol")
    if not _constant_time_ascii_equal(challenge.get("client_nonce"), client_nonce):
        raise ControlAuthenticationError("daemon challenge is not bound to this client")
    server_nonce = str(challenge.get("server_nonce") or "")
    _decode_b64u(server_nonce, expected_bytes=CONTROL_NONCE_BYTES, label="server nonce")
    expected = _mac(
        secret,
        _SERVER_PROOF_DOMAIN,
        client_nonce.encode("ascii"),
        server_nonce.encode("ascii"),
    )
    supplied = challenge.get("server_proof")
    if not _constant_time_ascii_equal(supplied, expected):
        raise ControlAuthenticationError("daemon control identity proof failed")
    return server_nonce


def make_client_request(
    request: Mapping[str, Any],
    secret: str,
    *,
    client_nonce: str,
    server_nonce: str,
) -> tuple[dict[str, Any], ControlExchange]:
    if not isinstance(request, Mapping):
        raise ControlProtocolError("control request must be an object")
    body = dict(request)
    request_bytes = _canonical_json(body)
    if len(request_bytes) > CONTROL_REQUEST_MAX_BYTES:
        raise ControlFrameTooLarge("control request exceeds byte limit")
    proof = _mac(
        secret,
        _CLIENT_PROOF_DOMAIN,
        client_nonce.encode("ascii"),
        server_nonce.encode("ascii"),
        request_bytes,
    )
    exchange = ControlExchange(client_nonce, server_nonce, request_bytes)
    return (
        {
            "ipc_v": CONTROL_PROTOCOL_VERSION,
            "client_nonce": client_nonce,
            "server_nonce": server_nonce,
            "request": body,
            "client_proof": proof,
        },
        exchange,
    )


def verify_client_request(
    envelope: Mapping[str, Any],
    secret: str,
    *,
    client_nonce: str,
    server_nonce: str,
) -> tuple[dict[str, Any], ControlExchange]:
    if envelope.get("ipc_v") != CONTROL_PROTOCOL_VERSION:
        raise ControlAuthenticationError("unsupported control protocol")
    if not _constant_time_ascii_equal(envelope.get("client_nonce"), client_nonce):
        raise ControlAuthenticationError("client nonce mismatch")
    if not _constant_time_ascii_equal(envelope.get("server_nonce"), server_nonce):
        raise ControlAuthenticationError("server nonce mismatch")
    request = envelope.get("request")
    if not isinstance(request, dict):
        raise ControlProtocolError("control request must be an object")
    request_bytes = _canonical_json(request)
    if len(request_bytes) > CONTROL_REQUEST_MAX_BYTES:
        raise ControlFrameTooLarge("control request exceeds byte limit")
    expected = _mac(
        secret,
        _CLIENT_PROOF_DOMAIN,
        client_nonce.encode("ascii"),
        server_nonce.encode("ascii"),
        request_bytes,
    )
    supplied = envelope.get("client_proof")
    if not _constant_time_ascii_equal(supplied, expected):
        raise ControlAuthenticationError("client control identity proof failed")
    return request, ControlExchange(client_nonce, server_nonce, request_bytes)


def encode_server_response(
    response: Mapping[str, Any],
    secret: str,
    exchange: ControlExchange,
) -> bytes:
    def _signed_frame(body: dict[str, Any]) -> bytes:
        response_bytes = _canonical_json(body)
        proof = _mac(
            secret,
            _RESPONSE_PROOF_DOMAIN,
            exchange.client_nonce.encode("ascii"),
            exchange.server_nonce.encode("ascii"),
            exchange.request_bytes,
            response_bytes,
        )
        return _canonical_json(
            {
                "ipc_v": CONTROL_PROTOCOL_VERSION,
                "response": body,
                "server_proof": proof,
            }
        ) + b"\n"

    # The wire ceiling applies to the complete signed envelope, not merely to
    # the nested response object.  Testing only ``response_bytes`` leaves an
    # envelope-overhead edge where an otherwise in-limit response raises after
    # command execution and the client sees an unexplained EOF.  Build once,
    # then replace any over-limit result with a small authenticated error.
    frame = _signed_frame(dict(response))
    if len(frame) <= CONTROL_RESPONSE_MAX_BYTES:
        return frame
    fallback = _signed_frame(
        {"ok": False, "error": "control response exceeds byte limit"}
    )
    if len(fallback) > CONTROL_RESPONSE_MAX_BYTES:  # pragma: no cover - invariant
        raise ControlFrameTooLarge("signed control error exceeds byte limit")
    return fallback


def verify_server_response(
    envelope: Mapping[str, Any],
    secret: str,
    exchange: ControlExchange,
) -> dict[str, Any]:
    if envelope.get("ipc_v") != CONTROL_PROTOCOL_VERSION:
        raise ControlAuthenticationError("daemon returned an unauthenticated response")
    response = envelope.get("response")
    if not isinstance(response, dict):
        raise ControlProtocolError("daemon control response must be an object")
    response_bytes = _canonical_json(response)
    expected = _mac(
        secret,
        _RESPONSE_PROOF_DOMAIN,
        exchange.client_nonce.encode("ascii"),
        exchange.server_nonce.encode("ascii"),
        exchange.request_bytes,
        response_bytes,
    )
    supplied = envelope.get("server_proof")
    if not _constant_time_ascii_equal(supplied, expected):
        raise ControlAuthenticationError("daemon response identity proof failed")
    return response


def encode_json_line(value: Mapping[str, Any], *, max_bytes: int) -> bytes:
    frame = _canonical_json(dict(value)) + b"\n"
    if len(frame) > max_bytes:
        raise ControlFrameTooLarge("control frame exceeds byte limit")
    return frame


def recv_json_line(sock: socket.socket, *, max_bytes: int) -> dict[str, Any]:
    buf = bytearray()
    while True:
        remaining = max_bytes + 1 - len(buf)
        if remaining <= 0:
            raise ControlFrameTooLarge("control frame exceeds byte limit")
        chunk = sock.recv(min(65536, remaining))
        if not chunk:
            raise ControlProtocolError("control connection closed before a complete frame")
        newline = chunk.find(b"\n")
        if newline >= 0:
            if len(buf) + newline + 1 > max_bytes:
                raise ControlFrameTooLarge("control frame exceeds byte limit")
            buf.extend(chunk[:newline])
            if chunk[newline + 1 :]:
                raise ControlProtocolError("control peer pipelined an unexpected frame")
            break
        buf.extend(chunk)
        if len(buf) > max_bytes:
            raise ControlFrameTooLarge("control frame exceeds byte limit")
    try:
        value = json.loads(bytes(buf).decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ControlProtocolError("control peer returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise ControlProtocolError("control frame must be a JSON object")
    return value


def begin_authenticated_request(
    sock: socket.socket,
    request: Mapping[str, Any],
    *,
    secret: str | None = None,
) -> tuple[str, ControlExchange]:
    """Mutually authenticate ``sock``, send one request, and return context."""

    credential = secret if secret is not None else read_control_secret()
    hello, client_nonce = make_client_hello()
    sock.sendall(encode_json_line(hello, max_bytes=CONTROL_HANDSHAKE_MAX_BYTES))
    challenge = recv_json_line(sock, max_bytes=CONTROL_HANDSHAKE_MAX_BYTES)
    server_nonce = verify_server_challenge(
        challenge,
        credential,
        client_nonce=client_nonce,
    )
    envelope, exchange = make_client_request(
        request,
        credential,
        client_nonce=client_nonce,
        server_nonce=server_nonce,
    )
    sock.sendall(encode_json_line(envelope, max_bytes=CONTROL_REQUEST_MAX_BYTES))
    return credential, exchange


def receive_authenticated_response(
    sock: socket.socket,
    *,
    secret: str,
    exchange: ControlExchange,
) -> dict[str, Any]:
    envelope = recv_json_line(sock, max_bytes=CONTROL_RESPONSE_MAX_BYTES)
    return verify_server_response(envelope, secret, exchange)


def request_control(
    port: int,
    request: Mapping[str, Any],
    *,
    timeout: float = 5.0,
    secret: str | None = None,
) -> dict[str, Any]:
    """Perform one mutually-authenticated, bounded control round trip."""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(("127.0.0.1", int(port)))
        credential, exchange = begin_authenticated_request(sock, request, secret=secret)
        return receive_authenticated_response(sock, secret=credential, exchange=exchange)
    finally:
        sock.close()


def make_ui_instance_challenge() -> str:
    return _b64u(secrets.token_bytes(CONTROL_NONCE_BYTES))


def make_ui_instance_proof(
    secret: str,
    *,
    challenge: str,
    instance_id: str,
    pid: int,
    port: int,
    source_fingerprint: str,
) -> str:
    _decode_b64u(challenge, expected_bytes=CONTROL_NONCE_BYTES, label="UI proof challenge")
    values = (
        challenge,
        str(instance_id),
        str(int(pid)),
        str(int(port)),
        str(source_fingerprint),
    )
    return _mac(secret, _UI_INSTANCE_PROOF_DOMAIN, *(v.encode("utf-8") for v in values))


def verify_ui_instance_proof(
    proof: str,
    secret: str,
    *,
    challenge: str,
    instance_id: str,
    pid: int,
    port: int,
    source_fingerprint: str,
) -> bool:
    try:
        expected = make_ui_instance_proof(
            secret,
            challenge=challenge,
            instance_id=instance_id,
            pid=pid,
            port=port,
            source_fingerprint=source_fingerprint,
        )
    except (ControlProtocolError, ValueError, TypeError):
        return False
    return _constant_time_ascii_equal(proof, expected)

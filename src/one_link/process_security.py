"""Hardened process-launch primitives for production OS integrations.

One Link occasionally invokes a small, fixed set of operating-system tools
(file-manager launchers, PowerShell probes, ``netsh`` and similar helpers).
Calling those tools by basename makes the current directory and the caller's
``PATH`` part of the trust boundary.  A planted executable could therefore be
run before the genuine system binary.

This module keeps that boundary explicit:

* system tools are resolved only from fixed OS-owned directories;
* caller-supplied helpers must already be absolute, regular executables;
* child ``PATH`` values contain only the same trusted system directories;
* opener processes use list-form argv, closed standard handles, no shell, a
  trusted working directory, and a background waiter so exited children are
  reaped.

The functions intentionally raise on an unavailable or untrusted executable.
Callers that are best-effort probes may catch ``ProcessSecurityError`` or
``OSError`` and fall back without weakening resolution policy.
"""

from __future__ import annotations

import ctypes
import os
import stat
import subprocess
import sys
import threading
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePath
from typing import Final
from urllib.parse import urlsplit


class ProcessSecurityError(ValueError):
    """The requested process could not be launched under the trust policy."""


_POSIX_SYSTEM_DIRS: Final[tuple[Path, ...]] = (
    Path("/usr/bin"),
    Path("/bin"),
    Path("/usr/sbin"),
    Path("/sbin"),
)

# These tools live outside System32 on supported Windows installations.
_WINDOWS_RELATIVE_TO_ROOT: Final[dict[str, tuple[str, ...]]] = {
    "explorer.exe": ("explorer.exe",),
    "powershell.exe": ("System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
    "wmic.exe": ("System32", "wbem", "wmic.exe"),
}

_INJECTION_ENV_KEYS: Final[frozenset[str]] = frozenset({
    "BASH_ENV",
    "CDPATH",
    "DOTNET_STARTUP_HOOKS",
    "ENV",
    "GCONV_PATH",
    "NODE_OPTIONS",
    "OPENSSL_CONF",
    "OPENSSL_MODULES",
    "SHLIB_PATH",
    "SSLKEYLOGFILE",
    "ZDOTDIR",
    "__COMPAT_LAYER",
})

_INJECTION_ENV_PREFIXES: Final[tuple[str, ...]] = (
    "COR_",
    "DYLD_",
    "LD_",
    "PERL5",
    "PYTHON",
    "RUBY",
)

_CHILD_ENV_ALLOW_KEYS: Final[frozenset[str]] = frozenset({
    "ALLUSERSPROFILE",
    "APPDATA",
    "COMMONPROGRAMFILES",
    "COMMONPROGRAMFILES(X86)",
    "COMMONPROGRAMW6432",
    "DBUS_SESSION_BUS_ADDRESS",
    "DISPLAY",
    "HOME",
    "HOMEDRIVE",
    "HOMEPATH",
    "LANG",
    "LOCALAPPDATA",
    "LOGNAME",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMW6432",
    "SESSIONNAME",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USER",
    "USERDOMAIN",
    "USERNAME",
    "USERPROFILE",
    "WAYLAND_DISPLAY",
    "WINDIR",
    "XAUTHORITY",
    "XDG_CURRENT_DESKTOP",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_DESKTOP",
    "XDG_SESSION_TYPE",
})

_PROCESS_REAPER_SLOTS = threading.BoundedSemaphore(64)


def _platform_family(platform_name: str | None = None) -> str:
    value = (platform_name or sys.platform or os.name).strip().lower()
    if value in {"windows", "win32", "cygwin", "msys", "nt"}:
        return "windows"
    if value in {"darwin", "mac", "macos"}:
        return "darwin"
    return "posix"


def _windows_directory() -> Path:
    """Return the kernel-reported Windows directory, never ``%SystemRoot%``.

    Environment variables are deliberately not used: the process launcher is
    precisely where an attacker-controlled environment must not select an
    executable.  The fixed fallback is only for restricted test/compatibility
    environments where ``GetWindowsDirectoryW`` is unavailable.
    """

    if os.name == "nt":
        try:
            buffer = ctypes.create_unicode_buffer(32_768)
            length = int(ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer)))
            if 0 < length < len(buffer):
                candidate = Path(buffer.value)
                if candidate.is_absolute():
                    return candidate
        except (AttributeError, OSError, ValueError):
            pass
    return Path(r"C:\Windows")


def trusted_system_directories(*, platform_name: str | None = None) -> tuple[Path, ...]:
    """Return fixed directories eligible to contain invoked system tools."""

    family = _platform_family(platform_name)
    if family == "windows":
        root = _windows_directory()
        return (
            root / "System32",
            root / "System32" / "WindowsPowerShell" / "v1.0",
            root / "System32" / "wbem",
            root,
        )
    return _POSIX_SYSTEM_DIRS


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _validate_executable(path: Path, *, trusted_roots: Sequence[Path] | None) -> str:
    if not path.is_absolute():
        raise ProcessSecurityError("executable path must be absolute")
    try:
        resolved = path.resolve(strict=True)
        file_stat = resolved.stat()
    except OSError as exc:
        raise FileNotFoundError(f"executable is unavailable: {path}") from exc
    if not stat.S_ISREG(file_stat.st_mode):
        raise ProcessSecurityError(f"executable is not a regular file: {resolved}")
    if os.name != "nt":
        if not os.access(resolved, os.X_OK):
            raise ProcessSecurityError(f"file is not executable: {resolved}")
        if file_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ProcessSecurityError(
                f"executable is writable by group/others: {resolved}",
            )
    if trusted_roots is not None:
        roots: list[Path] = []
        for root in trusted_roots:
            try:
                roots.append(root.resolve(strict=True))
            except OSError:
                continue
        if not any(_is_relative_to(resolved, root) for root in roots):
            raise ProcessSecurityError(
                f"system executable escaped trusted OS directories: {resolved}",
            )
    return str(resolved)


def resolve_explicit_executable(executable: str | os.PathLike[str]) -> str:
    """Validate an explicitly selected absolute application/helper path."""

    path = Path(executable)
    if os.name == "nt" and path.suffix.lower() not in {".com", ".exe"}:
        # Windows can route .bat/.cmd through a command processor even when
        # ``shell=False``. Restrict this boundary to native executable images.
        raise ProcessSecurityError("Windows executable must be a .exe or .com image")
    return _validate_executable(path, trusted_roots=None)


def resolve_system_executable(name: str, *, platform_name: str | None = None) -> str:
    """Resolve a basename from fixed OS-owned directories only.

    ``PATH`` and the current working directory are never consulted.  Absolute
    paths belong in :func:`resolve_explicit_executable` so a caller cannot
    accidentally label an arbitrary program as a system tool.
    """

    if not isinstance(name, str) or not name.strip():
        raise ProcessSecurityError("system executable name is required")
    clean = name.strip()
    if PurePath(clean).name != clean or "/" in clean or "\\" in clean:
        raise ProcessSecurityError("system executable must be a bare filename")
    if (
        clean in {".", ".."}
        or len(clean) > 255
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in clean)
    ):
        raise ProcessSecurityError("invalid system executable name")

    family = _platform_family(platform_name)
    roots = trusted_system_directories(platform_name=platform_name)
    candidates: list[Path] = []
    if family == "windows":
        lowered = clean.lower()
        if not lowered.endswith(".exe"):
            lowered += ".exe"
        rel = _WINDOWS_RELATIVE_TO_ROOT.get(lowered)
        if rel is not None:
            candidates.append(_windows_directory().joinpath(*rel))
        else:
            # Windows system utilities used by One Link (taskkill, netsh,
            # route, arp, pnputil, cmd) are all in System32.
            candidates.append(_windows_directory() / "System32" / lowered)
    else:
        candidates.extend(root / clean for root in roots)

    errors: list[Exception] = []
    for candidate in candidates:
        try:
            return _validate_executable(candidate, trusted_roots=roots)
        except (OSError, ProcessSecurityError) as exc:
            errors.append(exc)
    detail = str(errors[-1]) if errors else "no eligible path"
    raise FileNotFoundError(f"trusted system executable {clean!r} not found ({detail})")


def resolve_argv(
    argv: Sequence[str],
    *,
    system_tool: bool,
    platform_name: str | None = None,
) -> list[str]:
    """Return list-form argv with an absolute, validated executable."""

    if not argv or not isinstance(argv[0], str) or not argv[0]:
        raise ProcessSecurityError("process argv requires an executable")
    if len(argv) > 4_096:
        raise ProcessSecurityError("process argv exceeds 4096 elements")
    if any(not isinstance(arg, str) or "\x00" in arg for arg in argv):
        raise ProcessSecurityError("process argv must contain NUL-free strings")
    if sum(len(arg) for arg in argv) > 1_048_576:
        raise ProcessSecurityError("process argv exceeds 1 MiB")
    executable = (
        resolve_system_executable(argv[0], platform_name=platform_name)
        if system_tool
        else resolve_explicit_executable(argv[0])
    )
    return [executable, *argv[1:]]


def trusted_process_env(
    *,
    platform_name: str | None = None,
    base: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Copy the environment while replacing ``PATH`` with trusted roots."""

    env = isolated_process_env(base=base)
    canonical_windows_keys = {
        "COMSPEC",
        "PATH",
        "PATHEXT",
        "PSMODULEPATH",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "WINDIR",
    }
    for key in tuple(env):
        if key.upper() in canonical_windows_keys:
            env.pop(key, None)
    env["PATH"] = os.pathsep.join(
        str(path) for path in trusted_system_directories(platform_name=platform_name)
    )
    if _platform_family(platform_name) == "windows":
        windows = _windows_directory()
        modules = windows / "System32" / "WindowsPowerShell" / "v1.0" / "Modules"
        env["SystemRoot"] = str(windows)
        env["WINDIR"] = str(windows)
        env["SystemDrive"] = windows.drive or "C:"
        env["COMSPEC"] = str(windows / "System32" / "cmd.exe")
        env["PATHEXT"] = ".COM;.EXE"
        env["PSModulePath"] = str(modules)
    return env


def isolated_process_env(
    *,
    base: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build a least-privilege GUI/system-tool environment.

    In particular this avoids handing cloud/API credentials from the daemon's
    parent environment to a browser, file manager, compiler, or OS probe.
    """

    source = os.environ if base is None else base
    env: dict[str, str] = {}
    for key, value in source.items():
        upper = key.upper()
        if (
            upper in _CHILD_ENV_ALLOW_KEYS
            or upper.startswith("LC_")
        ):
            env[key] = value
    return env


def sanitized_process_env(
    *,
    base: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Remove loader/interpreter variables that can inject child code."""

    env = dict(os.environ if base is None else base)
    for key in tuple(env):
        upper = key.upper()
        if upper in _INJECTION_ENV_KEYS or upper.startswith(_INJECTION_ENV_PREFIXES):
            env.pop(key, None)
    return env


def hidden_creationflags(*, detached: bool = False) -> int:
    """Windows flags that prevent console flashes and optional inheritance."""

    if os.name != "nt":
        return 0
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    if detached:
        flags |= getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
        flags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
    return int(flags)


def _reap_child(proc: subprocess.Popen[bytes]) -> None:
    """Wait outside the caller thread so short-lived GUI helpers do not zombie."""

    try:
        proc.wait()
    except (AttributeError, OSError, ValueError):
        pass
    finally:
        _PROCESS_REAPER_SLOTS.release()


def _launch_resolved_argv(
    argv: list[str],
    *,
    platform_name: str | None,
) -> subprocess.Popen[bytes]:
    if (
        not argv
        or not isinstance(argv[0], str)
        or not Path(argv[0]).is_absolute()
        or any(not isinstance(arg, str) or "\x00" in arg for arg in argv)
    ):
        raise ProcessSecurityError("resolved launcher argv is invalid")
    if not _PROCESS_REAPER_SLOTS.acquire(blocking=False):
        raise ProcessSecurityError("too many active OS launcher processes")
    proc: subprocess.Popen[bytes] | None = None
    try:
        family = _platform_family(platform_name)
        env = trusted_process_env(platform_name=platform_name)
        cwd = str(Path(argv[0]).parent)
        if family == "windows":
            proc = subprocess.Popen(  # noqa: S603
                argv,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                cwd=cwd,
                env=env,
                creationflags=hidden_creationflags(detached=True),
            )
        else:
            proc = subprocess.Popen(  # noqa: S603
                argv,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                cwd=cwd,
                env=env,
                start_new_session=True,
            )
        threading.Thread(
            target=_reap_child,
            args=(proc,),
            name="one-link-process-reaper",
            daemon=True,
        ).start()
    except BaseException:
        try:
            if proc is not None:
                stopped = False
                try:
                    proc.terminate()
                    proc.wait(timeout=2.0)
                    stopped = True
                except (AttributeError, OSError, ValueError, subprocess.TimeoutExpired):
                    pass
                if not stopped:
                    try:
                        proc.kill()
                    except (AttributeError, OSError, ValueError):
                        pass
                    try:
                        proc.wait(timeout=2.0)
                    except (
                        AttributeError,
                        OSError,
                        ValueError,
                        subprocess.TimeoutExpired,
                    ):
                        pass
        finally:
            _PROCESS_REAPER_SLOTS.release()
        raise
    assert proc is not None
    return proc


def launch_system_command(
    argv: Sequence[str],
    *,
    platform_name: str | None = None,
) -> subprocess.Popen[bytes]:
    """Launch a fixed system tool without inheriting a searchable ``PATH``."""

    safe_argv = resolve_argv(
        argv,
        system_tool=True,
        platform_name=platform_name,
    )
    return _launch_resolved_argv(
        safe_argv,
        platform_name=platform_name,
    )


def launch_explicit_command(
    argv: Sequence[str],
    *,
    platform_name: str | None = None,
) -> subprocess.Popen[bytes]:
    """Launch an absolute registered application/helper path safely."""

    safe_argv = resolve_argv(argv, system_tool=False, platform_name=platform_name)
    return _launch_resolved_argv(
        safe_argv,
        platform_name=platform_name,
    )


def launch_system_opener(
    target: str | os.PathLike[str],
    *,
    reveal: bool = False,
    platform_name: str | None = None,
) -> subprocess.Popen[bytes]:
    """Open or reveal an absolute local path with the trusted OS file manager."""

    target_path = Path(target)
    if not target_path.is_absolute():
        raise ProcessSecurityError("opener target must be an absolute path")
    # Resolve without requiring existence: a just-deleted inbox item should
    # fail in the OS launcher, not cause any fallback to a relative path.
    target_text = str(target_path.resolve(strict=False))
    family = _platform_family(platform_name)
    if family == "windows":
        executable = resolve_system_executable("explorer.exe", platform_name="windows")
        argv = [executable, f"/select,{target_text}"] if reveal else [executable, target_text]
    elif family == "darwin":
        executable = resolve_system_executable("open", platform_name="darwin")
        argv = [executable, "-R", target_text] if reveal else [executable, target_text]
    else:
        executable = resolve_system_executable("xdg-open", platform_name="posix")
        argv = [executable, str(Path(target_text).parent) if reveal else target_text]

    return _launch_resolved_argv(
        argv,
        platform_name=platform_name,
    )


def validate_loopback_url(url: str) -> str:
    """Return ``url`` after enforcing the local-control-surface boundary."""

    if not isinstance(url, str) or not 1 <= len(url) <= 8_192:
        raise ProcessSecurityError("browser URL length is invalid")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in url):
        raise ProcessSecurityError("browser URL contains a control character")
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ProcessSecurityError("browser URL has an invalid port") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or port is None
        or port <= 0
    ):
        raise ProcessSecurityError("browser URL must be loopback HTTP with an explicit port")
    return url


def launch_loopback_url(
    url: str,
    *,
    platform_name: str | None = None,
) -> subprocess.Popen[bytes] | None:
    """Open a strictly loopback HTTP URL without honoring ``$BROWSER``.

    Python's :mod:`webbrowser` intentionally executes commands configured in
    the ``BROWSER`` environment variable.  That flexibility is inappropriate
    for an authenticated local control surface, so One Link uses only the
    fixed OS browser launcher.
    """

    url = validate_loopback_url(url)

    family = _platform_family(platform_name)
    if family == "windows":
        # ShellExecute is Windows' default-browser API.  Strict parsing above
        # prevents this from becoming a generic file/protocol launcher.
        os.startfile(url, "open")  # type: ignore[attr-defined]  # nosec B606
        return None
    if family == "darwin":
        return launch_system_command(["open", url], platform_name="darwin")
    return launch_system_command(["xdg-open", url], platform_name="posix")


__all__ = [
    "ProcessSecurityError",
    "hidden_creationflags",
    "launch_explicit_command",
    "launch_loopback_url",
    "launch_system_command",
    "launch_system_opener",
    "isolated_process_env",
    "resolve_argv",
    "resolve_explicit_executable",
    "resolve_system_executable",
    "sanitized_process_env",
    "trusted_process_env",
    "trusted_system_directories",
    "validate_loopback_url",
]

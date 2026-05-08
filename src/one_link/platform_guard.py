"""Process-local platform probes that cannot hang One Link startup."""

from __future__ import annotations

import os


def install_windows_platform_fastpath() -> None:
    """Avoid Windows WMI during dependency imports.

    Python 3.14's ``platform.system()`` can route through WMI on Windows.
    If WMI is slow or wedged, importing libraries such as aiohttp, ifaddr,
    or zeroconf can hang before One Link publishes its control socket. One
    Link only needs the coarse OS family in those import-time checks, so a
    process-local fast path is safer and more honest for our use.
    """
    if os.name != "nt":
        return
    import platform

    if getattr(platform, "_one_link_fastpath_installed", False):
        return

    def _system() -> str:
        return "Windows"

    def _machine() -> str:
        arch = (
            os.environ.get("PROCESSOR_ARCHITECTURE")
            or os.environ.get("PROCESSOR_ARCHITEW6432")
            or ""
        ).lower()
        if arch in {"amd64", "x86_64", "x64"}:
            return "AMD64"
        if arch in {"arm64", "aarch64"}:
            return "ARM64"
        if arch in {"x86", "i386", "i686"}:
            return "x86"
        return arch or "AMD64"

    def _platform(*_args, **_kwargs) -> str:
        return f"Windows-{_machine()}"

    def _processor() -> str:
        return os.environ.get("PROCESSOR_IDENTIFIER") or _machine()

    platform.system = _system  # type: ignore[method-assign]
    platform.machine = _machine  # type: ignore[method-assign]
    platform.platform = _platform  # type: ignore[method-assign]
    platform.processor = _processor  # type: ignore[method-assign]
    platform._one_link_fastpath_installed = True  # type: ignore[attr-defined]

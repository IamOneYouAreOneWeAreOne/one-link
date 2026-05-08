"""Optional native CDC boundary scanner.

One Link's Python CDC implementation is intentionally simple and correct, but
the byte-by-byte rolling-hash scan is the current large-file bottleneck. This
module provides a tiny self-contained C scanner loaded through ``ctypes`` when
a local C compiler is available. If anything goes wrong, callers keep using the
Python path with identical chunk semantics.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Iterable

from platformdirs import user_cache_dir

from one_link.platform_guard import install_windows_platform_fastpath

install_windows_platform_fastpath()


_SOURCE = r"""
#include <stdint.h>
#include <stddef.h>

#if defined(_WIN32)
#define OL_EXPORT __declspec(dllexport)
#else
#define OL_EXPORT __attribute__((visibility("default")))
#endif

OL_EXPORT size_t ol_cdc_scan(
    const uint8_t *data,
    size_t len,
    uint64_t initial_rolling,
    uint64_t initial_chunk_len,
    uint64_t min_chunk,
    uint64_t max_chunk,
    uint64_t boundary_mask,
    const uint64_t *gear,
    uint64_t *cuts,
    size_t cuts_cap,
    uint64_t *final_rolling,
    uint64_t *final_chunk_len
) {
    uint64_t rolling = initial_rolling;
    uint64_t chunk_len = initial_chunk_len;
    size_t cut_count = 0;

    for (size_t i = 0; i < len; i++) {
        rolling = ((rolling << 1) + gear[data[i]]) & UINT64_MAX;
        chunk_len++;

        if (chunk_len >= min_chunk &&
            (chunk_len >= max_chunk || ((rolling & boundary_mask) == 0))) {
            if (cut_count < cuts_cap) {
                cuts[cut_count] = (uint64_t)(i + 1);
            }
            cut_count++;
            rolling = 0;
            chunk_len = 0;
        }
    }

    *final_rolling = rolling;
    *final_chunk_len = chunk_len;
    return cut_count;
}
"""


@dataclass(frozen=True)
class NativeCdcStatus:
    available: bool
    engine: str
    reason: str = ""
    library: str = ""


class NativeCdcScanner:
    """Compiled CDC scanner with Python-compatible boundary semantics."""

    def __init__(self, library: Path, gear: Iterable[int]) -> None:
        self.library = library
        self._dll = ctypes.CDLL(str(library))
        self._fn = self._dll.ol_cdc_scan
        self._fn.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(ctypes.c_uint64),
        ]
        self._fn.restype = ctypes.c_size_t
        self._gear = (ctypes.c_uint64 * 256)(*[int(x) & ((1 << 64) - 1) for x in gear])

    def scan(
        self,
        buf: bytearray,
        *,
        length: int,
        initial_rolling: int,
        initial_chunk_len: int,
        min_chunk: int,
        max_chunk: int,
        boundary_mask: int,
    ) -> tuple[list[int], int, int]:
        if length <= 0:
            return [], initial_rolling, initial_chunk_len
        data = (ctypes.c_uint8 * length).from_buffer(buf)
        cap = max(1, (length + max(1, min_chunk) - 1) // max(1, min_chunk) + 2)
        cuts = (ctypes.c_uint64 * cap)()
        final_rolling = ctypes.c_uint64(0)
        final_chunk_len = ctypes.c_uint64(0)
        n = self._fn(
            data,
            ctypes.c_size_t(length),
            ctypes.c_uint64(initial_rolling),
            ctypes.c_uint64(initial_chunk_len),
            ctypes.c_uint64(min_chunk),
            ctypes.c_uint64(max_chunk),
            ctypes.c_uint64(boundary_mask),
            self._gear,
            cuts,
            ctypes.c_size_t(cap),
            ctypes.byref(final_rolling),
            ctypes.byref(final_chunk_len),
        )
        if n > cap:
            # This should not happen with sane min/max settings. Returning a
            # hard failure lets the caller fall back to Python rather than
            # silently produce a partial manifest.
            raise RuntimeError(f"native CDC cut overflow: {n}>{cap}")
        return (
            [int(cuts[i]) for i in range(n)],
            int(final_rolling.value),
            int(final_chunk_len.value),
        )


_SCANNER: NativeCdcScanner | None = None
_STATUS: NativeCdcStatus | None = None


def native_cdc_status() -> NativeCdcStatus:
    scanner = get_native_cdc_scanner()
    if scanner is not None:
        return NativeCdcStatus(
            available=True,
            engine="ctypes-c",
            library=str(scanner.library),
        )
    return _STATUS or NativeCdcStatus(False, "python", "not initialized")


def get_native_cdc_scanner() -> NativeCdcScanner | None:
    global _SCANNER, _STATUS
    if os.environ.get("ONE_LINK_DISABLE_NATIVE_CDC"):
        _STATUS = NativeCdcStatus(False, "python", "disabled by ONE_LINK_DISABLE_NATIVE_CDC")
        return None
    if _SCANNER is not None:
        return _SCANNER
    if _STATUS is not None and not _STATUS.available:
        return None

    try:
        from .cdc import _GEAR

        lib = _ensure_library()
        _SCANNER = NativeCdcScanner(lib, _GEAR)
        _STATUS = NativeCdcStatus(True, "ctypes-c", library=str(lib))
        return _SCANNER
    except Exception as exc:
        _STATUS = NativeCdcStatus(False, "python", repr(exc))
        return None


def _ensure_library() -> Path:
    bundled = _bundled_library()
    if bundled is not None:
        return bundled

    # Keep the native build cache space-free. MSYS GCC can hand paths with
    # spaces to internal tools poorly on Windows, which makes compilation fail
    # without useful stderr.
    cache = Path(user_cache_dir("OneLink", "OneLink")) / "native"
    cache.mkdir(parents=True, exist_ok=True)
    digest = hashlib.blake2s(_SOURCE.encode("utf-8"), digest_size=8).hexdigest()
    suffix = ".dll" if os.name == "nt" else ".dylib" if platform.system() == "Darwin" else ".so"
    lib = cache / f"ol_native_cdc_{digest}{suffix}"
    if lib.is_file():
        return lib

    src = cache / f"ol_native_cdc_{digest}.c"
    src.write_text(_SOURCE, encoding="utf-8")
    compiler = _find_c_compiler()
    if compiler is None:
        raise RuntimeError("no C compiler found for native CDC")
    _compile(compiler, src, lib)
    return lib


def native_library_name() -> str:
    suffix = ".dll" if os.name == "nt" else ".dylib" if platform.system() == "Darwin" else ".so"
    return f"ol_native_cdc{suffix}"


def native_platform_tag() -> str:
    system = platform.system().lower() or "unknown"
    machine = platform.machine().lower().replace("amd64", "x86_64")
    return f"{system}-{machine}"


def _bundled_library() -> Path | None:
    rel = Path("native") / native_platform_tag() / native_library_name()

    # PyInstaller onefile extracts package data under sys._MEIPASS.
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        p = Path(meipass) / "one_link" / rel
        if p.is_file():
            return p

    try:
        candidate = resources.files("one_link").joinpath(str(rel).replace("\\", "/"))
        with resources.as_file(candidate) as p:
            if p.is_file():
                return p
    except Exception:
        pass

    return None


def _find_c_compiler() -> str | None:
    env = os.environ.get("CC")
    candidates = []
    if env:
        candidates.append(env)
    candidates.extend([
        "gcc",
        "clang",
        "cl",
        r"C:\msys64\ucrt64\bin\gcc.exe",
        r"C:\msys64\mingw64\bin\gcc.exe",
    ])
    for c in candidates:
        if "\\" in c or "/" in c:
            if Path(c).is_file():
                return c
        elif shutil.which(c):
            return c
    return None


def _compile(compiler: str, src: Path, lib: Path) -> None:
    name = Path(compiler).name.lower()
    env = dict(os.environ)
    compiler_dir = str(Path(compiler).parent)
    if compiler_dir and compiler_dir != ".":
        env["PATH"] = compiler_dir + os.pathsep + env.get("PATH", "")
    if name == "cl.exe" or name == "cl":
        cmd = [
            compiler,
            "/nologo",
            "/O2",
            "/LD",
            str(src),
            f"/Fe:{lib}",
        ]
    else:
        cmd = [
            compiler,
            "-O3",
            "-std=c99",
            "-shared",
            "-o",
            str(lib),
            str(src),
        ]
        if os.name != "nt":
            cmd.insert(3, "-fPIC")
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=env)
    if proc.returncode != 0 or not lib.is_file():
        stderr = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"native CDC compile failed: {stderr[:500]}")

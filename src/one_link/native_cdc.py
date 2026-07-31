"""Native CDC boundary scanner with a source-install fallback.

One Link's Python CDC implementation is intentionally simple and correct, but
the byte-by-byte rolling-hash scan is the current large-file bottleneck. This
module provides a tiny self-contained C scanner loaded through ``ctypes``.
Editable/source installs may compile locally and fall back to Python if native
initialization fails. Frozen stable artifacts are different: their bundled
library, exact SHA-256 sidecar, and ABI known vector are mandatory and failure
is fatal to the native feature/release gates.
"""

from __future__ import annotations

import contextlib
import ctypes
import hashlib
import logging
import os
import platform
import subprocess
import sys
import stat
from dataclasses import dataclass
from importlib import resources

log = logging.getLogger("one_link.native_cdc")
from pathlib import Path
from typing import Iterable

from platformdirs import user_cache_dir

from one_link.fault_observability import report_best_effort_failure
from one_link.platform_guard import install_windows_platform_fastpath
from one_link.process_security import (
    hidden_creationflags,
    resolve_explicit_executable,
    resolve_system_executable,
    trusted_process_env,
)

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


def validate_native_cdc_library(library: Path) -> None:
    """Load *library* and prove its exported scanner against a known vector.

    A successful ``ctypes.CDLL`` is not enough: an ABI-compatible but stale or
    malicious library can export ``ol_cdc_scan`` and still return incorrect
    boundaries.  This deterministic vector compares the native result to a
    small implementation of the canonical gear-hash state machine, including
    non-zero carry state across a buffer boundary.
    """
    from .cdc import _GEAR

    payload = bytearray(bytes(range(256)) * 17 + b"one-link-native-cdc-known-vector")
    initial_rolling = 0x0123_4567_89AB_CDEF
    initial_chunk_len = 29
    min_chunk = 64
    max_chunk = 257
    boundary_mask = 0x7F
    expected_cuts: list[int] = []
    rolling = initial_rolling
    chunk_len = initial_chunk_len
    for offset, value in enumerate(payload, start=1):
        rolling = ((rolling << 1) + int(_GEAR[value])) & ((1 << 64) - 1)
        chunk_len += 1
        if chunk_len >= min_chunk and (
            chunk_len >= max_chunk or (rolling & boundary_mask) == 0
        ):
            expected_cuts.append(offset)
            rolling = 0
            chunk_len = 0

    scanner = NativeCdcScanner(library, _GEAR)
    actual = scanner.scan(
        payload,
        length=len(payload),
        initial_rolling=initial_rolling,
        initial_chunk_len=initial_chunk_len,
        min_chunk=min_chunk,
        max_chunk=max_chunk,
        boundary_mask=boundary_mask,
    )
    expected = (expected_cuts, rolling, chunk_len)
    if actual != expected:
        raise RuntimeError(
            "native CDC known-vector mismatch: "
            f"actual={actual!r}, expected={expected!r}"
        )


def _is_link_like_path(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


def _frozen_bundle_roots() -> list[Path]:
    """Directories a frozen application legitimately owns, resolved."""

    roots: list[Path] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if isinstance(meipass, str) and meipass:
        with contextlib.suppress(OSError):
            roots.append(Path(meipass).resolve(strict=True))
    executable = getattr(sys, "executable", "") or ""
    if getattr(sys, "frozen", False) and executable:
        with contextlib.suppress(OSError):
            resolved = Path(executable).resolve(strict=True)
            # onedir: <root>/one-link; macOS .app: <root>.app/Contents/MacOS/one-link
            roots.append(resolved.parent)
            if len(resolved.parents) >= 3 and resolved.parents[1].name == "Contents":
                roots.append(resolved.parents[2])
    return roots


def _link_stays_inside_bundle(path: Path) -> bool:
    """True when a link and its target both live inside the frozen bundle."""

    roots = _frozen_bundle_roots()
    if not roots:
        return False
    try:
        target = path.resolve(strict=True)
        here = path.parent.resolve(strict=True)
    except OSError:
        return False

    def _contained(candidate: Path) -> bool:
        return any(candidate == root or root in candidate.parents for root in roots)

    return _contained(target) and _contained(here)


def _bundled_sidecar_path(library: Path) -> Path | None:
    """Locate the signed-hash sidecar in onedir and macOS BUNDLE layouts."""
    adjacent = library.with_suffix(library.suffix + ".sha256")
    if adjacent.is_file():
        return adjacent

    # PyInstaller places binaries in Contents/Frameworks but data files in
    # Contents/Resources.  ``sys._MEIPASS`` points at Frameworks for a macOS
    # app, so an adjacent-only lookup silently disabled verification there.
    executable = Path(sys.executable).resolve(strict=False)
    if (
        executable.parent.name == "MacOS"
        and executable.parent.parent.name == "Contents"
    ):
        resources_root = executable.parent.parent / "Resources"
        candidate = (
            resources_root
            / "one_link"
            / "native"
            / native_platform_tag()
            / (native_library_name() + ".sha256")
        )
        if candidate.is_file():
            return candidate
    return None


def _verify_bundled_library(p: Path) -> bool:
    """Verify the native CDC payload against its mandatory exact sidecar.

    The accepted format is exactly ``<lowercase 64-hex>  <basename>\n``.
    Frozen applications fail closed when either
    file is missing, link-like, malformed, or mismatched; editable/source
    installs may subsequently use their compiler fallback.
    """
    sidecar = _bundled_sidecar_path(p)
    if sidecar is None:
        return False
    # A link is refused unless it is PyInstaller's own intra-bundle mirror:
    # a macOS .app keeps Contents/Resources as links onto Contents/Frameworks,
    # so importlib.resources legitimately hands back a link-like path and a
    # blanket refusal made the frozen app reject its own verified library.
    # A link whose target escapes the bundle is still refused outright, and
    # the digest below is computed from the RESOLVED bytes either way.
    for candidate in (p, sidecar):
        if _is_link_like_path(candidate) and not _link_stays_inside_bundle(candidate):
            return False
    try:
        line = sidecar.read_text(encoding="ascii")
        actual = hashlib.sha256(p.read_bytes()).hexdigest().lower()
        expected_line = f"{actual}  {p.name}\n"
    except Exception as e:
        log.warning(
            "native CDC: integrity-check error for %s (%s); "
            "refusing bundled binary",
            p, e,
        )
        return False
    if line != expected_line:
        log.warning(
            "native CDC: integrity-check FAIL for %s; refusing bundled binary",
            p,
        )
        return False
    return True


def _ensure_library() -> Path:
    bundled = _bundled_library()
    if bundled is not None:
        if _verify_bundled_library(bundled):
            validate_native_cdc_library(bundled)
            return bundled
        if getattr(sys, "frozen", False):
            raise RuntimeError("bundled native CDC integrity verification failed")
    elif getattr(sys, "frozen", False):
        raise RuntimeError("frozen application is missing its native CDC library")

    # Keep the native build cache space-free. MSYS GCC can hand paths with
    # spaces to internal tools poorly on Windows, which makes compilation fail
    # without useful stderr.
    cache = Path(user_cache_dir("OneLink", "OneLink")) / "native"
    cache.mkdir(parents=True, exist_ok=True)
    digest = hashlib.blake2s(_SOURCE.encode("utf-8"), digest_size=8).hexdigest()
    suffix = ".dll" if os.name == "nt" else ".dylib" if platform.system() == "Darwin" else ".so"
    lib = cache / f"ol_native_cdc_{digest}{suffix}"
    if lib.is_file():
        try:
            validate_native_cdc_library(lib)
            return lib
        except Exception as exc:
            log.warning("native CDC: cached library failed ABI validation: %s", exc)
            lib.unlink(missing_ok=True)

    src = cache / f"ol_native_cdc_{digest}.c"
    src.write_text(_SOURCE, encoding="utf-8")
    compile_with_compiler_fallback(src, lib)
    return lib


def compile_with_compiler_fallback(src: Path, lib: Path) -> str:
    """Compile the CDC source trying EVERY usable compiler; return the winner.

    A driver that exists is not proof it can link (MSVC-target clang without
    a developer environment fails at LNK1181), and the accelerator being
    unavailable blocks the whole installer build -- so one unusable toolchain
    must not mask a working one sitting next to it.

    This is the ONE compile path for both the runtime self-build and
    scripts/build_native_cdc.py. The 636bc7c fallback originally lived only
    inside the runtime cache path, and the packaging script kept calling the
    first-hit search directly -- so CI kept dying at LNK1181 on runner images
    whose PATH surfaced clang first, exactly the failure the fix existed for.
    """

    candidates = _candidate_c_compilers()
    if not candidates:
        raise RuntimeError("no C compiler found for native CDC")
    failures: list[str] = []
    for index, compiler in enumerate(candidates):
        try:
            try:
                _compile(compiler, src, lib)
            except Exception as deterministic_exc:
                # The determinism switches are linker-flavour specific, and
                # which flavour a Windows clang drives cannot be told reliably
                # from its triple: a runner image rotated to a clang whose
                # -dumpmachine did not say "msvc" while it still invoked
                # lld-link, which then read `--image-base` as a GNU flag and
                # `0x180000000` as a FILE ("could not open '0x180000000'").
                # A pinned image base is a reproducibility nicety; a working
                # accelerator is the product. So retry the SAME compiler with
                # the flags dropped rather than guessing harder, and say so.
                lib.unlink(missing_ok=True)
                log.warning(
                    "native CDC: %s rejected the deterministic-link flags "
                    "(%s); retrying without them -- the library will build "
                    "but its preferred image base is not pinned",
                    Path(compiler).name,
                    type(deterministic_exc).__name__,
                )
                _compile(compiler, src, lib, deterministic_link=False)
            validate_native_cdc_library(lib)
        except Exception as exc:
            lib.unlink(missing_ok=True)
            failures.append(f"{Path(compiler).name}: {exc}")
            if index + 1 < len(candidates):
                log.warning(
                    "native CDC: %s could not produce a valid library (%s); "
                    "trying the next available compiler",
                    Path(compiler).name,
                    type(exc).__name__,
                )
                continue
            raise RuntimeError(
                "native CDC compile failed with every available compiler: "
                + "; ".join(failures)
            ) from exc
        return compiler
    raise RuntimeError("no C compiler found for native CDC")


def native_library_name() -> str:
    suffix = ".dll" if os.name == "nt" else ".dylib" if platform.system() == "Darwin" else ".so"
    return f"ol_native_cdc{suffix}"


def native_platform_tag() -> str:
    system = platform.system().lower() or "unknown"
    machine = platform.machine().lower().replace("amd64", "x86_64")
    return f"{system}-{machine}"


def _clang_targets_msvc(compiler: str) -> bool:
    """True iff this clang's default triple links through MSVC-style lld-link.

    A Windows clang can drive either linker flavor: an ``x86_64-pc-windows-
    msvc`` default (the upstream llvm.org installer, GitHub runners) invokes
    lld-link, which rejects GNU ld switches — it parses ``0x180000000`` as an
    input file — while a ``-gnu`` clang accepts them. Probing the triple is
    the only honest discriminator; on probe failure fall back to the GNU
    assumption, which matches this function's pre-probe behavior.
    """
    try:
        probe = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [compiler, "-dumpmachine"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return "msvc" in probe.stdout.strip().lower()


def _compile_command(
    compiler: str,
    src: Path,
    lib: Path,
    *,
    target_os_name: str | None = None,
    deterministic_link: bool = True,
) -> list[str]:
    """Build a deterministic native-CDC compiler command.

    GNU PE linkers otherwise stamp the current wall clock into the DLL header,
    making two ``SOURCE_DATE_EPOCH`` release builds differ despite identical
    source. MSVC (cl.exe or an MSVC-target clang) receives the corresponding
    reproducible-link switches for lld-link/link.exe instead.
    """
    os_name = os.name if target_os_name is None else target_os_name
    name = Path(compiler).name.lower()
    if name in {"cl.exe", "cl"}:
        return [
            compiler,
            "/nologo",
            "/O2",
            "/LD",
            str(src),
            f"/Fe:{lib}",
            "/link",
            "/Brepro",
        ]
    command = [
        compiler,
        "-O3",
        "-std=c99",
        "-shared",
        "-o",
        str(lib),
        str(src),
    ]
    if os_name == "nt":
        # NOTE the nesting: dropping the determinism flags must not fall
        # through to the POSIX branch and hand Windows a -fPIC it has no use
        # for. (Caught by test_determinism_flags_are_actually_dropped_on_retry
        # the first time this was written as one flat condition.)
        if not deterministic_link:
            pass
        elif "clang" in name and _clang_targets_msvc(compiler):
            # lld-link's reproducibility switches: /Brepro pins the PE
            # timestamp/checksum, /base fixes the preferred image base.
            command.insert(4, "-Wl,/Brepro")
            command.insert(5, "-Wl,/base:0x180000000")
        else:
            command.insert(4, "-Wl,--no-insert-timestamp")
            # GNU ld derives a DLL's default preferred image base from its
            # output path, which defeats byte-identical rebuilds in different
            # checkouts. Relocations/ASLR remain enabled; this only fixes the
            # preferred base.
            command.insert(5, "-Wl,--image-base,0x180000000")
    else:
        command.insert(3, "-fPIC")
    return command


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
    except (FileNotFoundError, OSError, TypeError, ValueError) as exc:
        report_best_effort_failure(
            log,
            "bundled_native_cdc_lookup",
            exc,
            level=logging.DEBUG,
        )

    return None


def _candidate_c_compilers() -> list[str]:
    """Every usable C compiler on this host, best first.

    Returning the whole list rather than the first hit is what makes the
    build survive a toolchain that is *present but not linkable*. An
    MSVC-target clang on a GitHub Windows runner is the live example: the
    driver exists, so a first-hit search commits to it, and then the link
    fails with LNK1181 because the MSVC library environment is only
    populated inside a developer shell. A GNU gcc sitting right there in
    MSYS2 would have linked fine. The caller tries these in order.

    ``ONE_LINK_CC`` -- then ``CC`` -- wins outright when set: an explicit
    operator choice must not be silently second-guessed.

    Two names, because ``CC`` is not ours alone. Anything else building C in
    the same environment reads it too: ``cc-rs`` honours it for the build
    scripts of ``ring``, ``zstd-sys`` and ``blake3``, so pointing ``CC`` at a
    GNU gcc to fix *this* compile hands GNU objects to an MSVC-target Rust
    link and breaks the native extension instead. ``ONE_LINK_CC`` pins the
    CDC compiler alone, which is what an operator on a Windows host with
    both toolchains actually wants.
    """
    env_compiler = str(
        os.environ.get("ONE_LINK_CC") or os.environ.get("CC") or ""
    ).strip()
    if env_compiler:
        try:
            if Path(env_compiler).is_absolute():
                return [resolve_explicit_executable(env_compiler)]
            # A bare CC name is accepted only when it names an OS-owned tool;
            # flags and relative paths are deliberately rejected.
            return [resolve_system_executable(env_compiler)]
        except (OSError, ValueError):
            return []

    found: list[str] = []

    def _add(path: str) -> None:
        if path not in found:
            found.append(path)

    for name in ("gcc", "clang", "cl"):
        try:
            _add(resolve_system_executable(name))
        except (OSError, ValueError):
            continue
    for candidate in (
        r"C:\msys64\ucrt64\bin\gcc.exe",
        r"C:\msys64\mingw64\bin\gcc.exe",
        r"C:\Program Files\LLVM\bin\clang.exe",
    ):
        try:
            _add(resolve_explicit_executable(candidate))
        except (OSError, ValueError):
            continue
    return found


def _find_c_compiler() -> str | None:
    """First usable compiler, or None. Kept for callers that want one name."""
    candidates = _candidate_c_compilers()
    return candidates[0] if candidates else None


def _compile(
    compiler: str, src: Path, lib: Path, *, deterministic_link: bool = True
) -> None:
    compiler = resolve_explicit_executable(compiler)
    env = trusted_process_env()
    compiler_dir = str(Path(compiler).parent)
    if compiler_dir and compiler_dir != ".":
        env["PATH"] = compiler_dir + os.pathsep + env["PATH"]
    cmd = _compile_command(
        compiler, src, lib, deterministic_link=deterministic_link
    )
    # 2026-06-04: 30s was too tight for a cold CI runner (first gcc
    # invocation on a fresh image, no warm caches) and intermittently
    # timed out, hard-failing the whole installer build. 120s gives
    # the cold path room while still bounding a genuinely hung compile.
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        cwd=compiler_dir,
        check=False,
        creationflags=hidden_creationflags(),
        shell=False,
    )
    if proc.returncode != 0 or not lib.is_file():
        stderr = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"native CDC compile failed: {stderr[:500]}")

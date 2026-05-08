"""Build the optional native CDC scanner for packaging.

The runtime can self-build into the user cache when a compiler exists, but
release binaries should not depend on the user's machine having GCC/clang/MSVC.
This script compiles the scanner into ``src/one_link/native/<platform>/`` so
setuptools/PyInstaller can bundle it.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def main() -> int:
    repo = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo / "src"))

    from one_link.native_cdc import (
        _SOURCE,
        _compile,
        _find_c_compiler,
        native_library_name,
        native_platform_tag,
    )

    ap = argparse.ArgumentParser()
    ap.add_argument("--required", action="store_true", help="fail if no native library can be built")
    ns = ap.parse_args()

    compiler = _find_c_compiler()
    if compiler is None:
        msg = "[native-cdc] no C compiler found; package will use Python fallback"
        print(msg)
        return 2 if ns.required else 0

    out_dir = repo / "src" / "one_link" / "native" / native_platform_tag()
    out_dir.mkdir(parents=True, exist_ok=True)
    src = out_dir / "ol_native_cdc.c"
    lib = out_dir / native_library_name()
    src.write_text(_SOURCE, encoding="utf-8")

    try:
        _compile(compiler, src, lib)
    except Exception as exc:
        print(f"[native-cdc] build failed with {compiler}: {exc}")
        return 1 if ns.required else 0

    size = lib.stat().st_size
    print(f"[native-cdc] built {lib} ({size:,} bytes) using {compiler}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

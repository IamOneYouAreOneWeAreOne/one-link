"""Build the optional native CDC scanner for packaging.

The runtime can self-build into the user cache when a compiler exists, but
release binaries should not depend on the user's machine having GCC/clang/MSVC.
By default this script compiles the scanner into
``src/one_link/native/<platform>/`` for backward compatibility. Packaging uses
``--output-dir`` to stage fresh release inputs under ``build/`` without
rewriting tracked package assets.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path


def main() -> int:
    repo = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo / "src"))

    from one_link.native_cdc import (
        _SOURCE,
        _candidate_c_compilers,
        compile_with_compiler_fallback,
        native_library_name,
        native_platform_tag,
    )

    ap = argparse.ArgumentParser()
    ap.add_argument("--required", action="store_true", help="fail if no native library can be built")
    ap.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help=(
            "directory that receives the generated C source, native library, "
            "and SHA-256 sidecar; defaults to the package's historical "
            "src/one_link/native/<platform> directory"
        ),
    )
    ns = ap.parse_args()

    # Presence check only -- selection happens inside the fallback ladder.
    # Importing the first-hit search here is what silently bypassed the
    # try-every-compiler fix and kept CI dying at LNK1181 on images whose
    # PATH surfaced an unlinkable MSVC-target clang first.
    if not _candidate_c_compilers():
        msg = "[native-cdc] no C compiler found; package will use Python fallback"
        print(msg)
        return 2 if ns.required else 0

    out_dir = (
        ns.output_dir.expanduser().resolve()
        if ns.output_dir is not None
        else repo / "src" / "one_link" / "native" / native_platform_tag()
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    src = out_dir / "ol_native_cdc.c"
    lib = out_dir / native_library_name()
    src.write_text(_SOURCE, encoding="utf-8")

    try:
        compiler = compile_with_compiler_fallback(src, lib)
    except Exception as exc:
        print(f"[native-cdc] build failed: {exc}")
        return 1 if ns.required else 0

    size = lib.stat().st_size
    digest = hashlib.sha256(lib.read_bytes()).hexdigest()
    lib.with_suffix(lib.suffix + ".sha256").write_text(
        f"{digest}  {lib.name}\n",
        encoding="ascii",
    )
    print(f"[native-cdc] built {lib} ({size:,} bytes) using {compiler}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

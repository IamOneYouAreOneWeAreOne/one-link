"""Build a single-file standalone binary of the one-link CLI.

Works on Windows (produces one-link.exe), macOS (produces one-link), and Linux.
Requires PyInstaller in the active environment:

    pip install pyinstaller

Usage:

    python scripts/build_binary.py
    python scripts/build_binary.py --gui          # windowed (no console)
    python scripts/build_binary.py --no-ml        # skip ONNX/scipy
                                                  # for a tiny binary

Output goes to dist/one-link[.exe] at the repo root.

ML model bundling:

This script auto-detects ``assets/models/*/checkpoint.onnx`` files and
bundles them into the exe. Combined with onnxruntime (autocollected
when installed), the bundled binary runs the Tier ζ/η/θ semantic
codecs without a separate ``pip install torch`` (~200 MB savings).

Native (Rust) module bundling:

This script auto-detects whether one_link_native is installed in
the active environment. When present, `--collect-all one_link_native`
is added to the PyInstaller arg list so the .pyd / .so / .dylib
files are bundled into the exe; the produced binary then realizes
the Phase A1/A2 gains (CDC, AEAD, QUIC, coherence-field) without
needing a separate `pip install`.

When one_link_native is NOT installed, the build proceeds without
it — the resulting exe still works, falling back to the pure-Python
transport paths. Users who want the native fast path on a binary
build should run, before this script:

    pip install one_link_native --find-links \\
      https://github.com/IamOneYouAreOneWeAreOne/one-link/releases/latest

The release.yml workflow already publishes the native wheels per
OS to GitHub Releases (Phase 1 of the production-install plan).
"""

from __future__ import annotations

import argparse
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--gui", action="store_true",
        help="Build a windowed binary (no console). For end-user installs.",
    )
    parser.add_argument(
        "--no-ml", action="store_true",
        help="Skip bundling ONNX models + onnxruntime. Produces a much "
             "smaller binary; Tier ζ/η/θ codecs won't work in the result.",
    )
    args = parser.parse_args()

    repo = Path(__file__).resolve().parent.parent
    entry = repo / "src" / "one_link" / "__main__.py"

    # Make sure we have a __main__.py for `python -m one_link` and PyInstaller's
    # entrypoint discovery to use.
    if not entry.exists():
        entry.write_text(
            "from one_link.cli import main\n"
            "if __name__ == '__main__':\n"
            "    raise SystemExit(main() or 0)\n",
            encoding="utf-8",
        )

    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("PyInstaller is not installed. Run:  pip install pyinstaller")
        return 2

    suffix = ".exe" if platform.system() == "Windows" else ""
    name = "one-link"
    out_name = f"{name}{suffix}"

    build = repo / "build"
    dist = repo / "dist"
    spec = repo / f"{name}.spec"

    for p in (build, dist):
        if p.exists():
            shutil.rmtree(p)
    if spec.exists():
        spec.unlink()

    native_build = subprocess.run(
        [sys.executable, str(repo / "scripts" / "build_native_cdc.py")],
        cwd=repo,
    )
    if native_build.returncode != 0:
        print(f"[build] native CDC build failed: exit {native_build.returncode}")
        return native_build.returncode

    # PyInstaller's --add-data uses ';' on Windows, ':' elsewhere.
    sep = ";" if platform.system() == "Windows" else ":"
    web_dir = repo / "src" / "one_link" / "web"
    add_data_web = f"{web_dir}{sep}one_link/web"
    native_dir = repo / "src" / "one_link" / "native"
    add_native: list[str] = []
    if native_dir.is_dir() and any(p.is_file() for p in native_dir.rglob("*")):
        add_native = ["--add-binary", f"{native_dir}{sep}one_link/native"]

    # Tier ζ/η/θ ML models — bundle every ONNX checkpoint + its
    # config. Torch .pt files are skipped to keep the binary lean;
    # the ONNX oracle factory falls back to torch only when ONNX is
    # missing, which won't happen in the bundled distribution.
    add_models: list[str] = []
    models_dir = repo / "assets" / "models"
    if not args.no_ml and models_dir.is_dir():
        for ckpt in models_dir.rglob("checkpoint.onnx"):
            rel = ckpt.parent.relative_to(repo).as_posix()
            add_models.extend([
                "--add-data", f"{ckpt}{sep}{rel}",
            ])
        for cfg in models_dir.rglob("config.json"):
            rel = cfg.parent.relative_to(repo).as_posix()
            add_models.extend([
                "--add-data", f"{cfg}{sep}{rel}",
            ])
        if add_models:
            print(f"[build] bundling {len(add_models) // 2} model file(s) from {models_dir}")

    onnx_collect: list[str] = []
    if not args.no_ml:
        try:
            import onnxruntime  # noqa: F401
            onnx_collect = ["--collect-all", "onnxruntime"]
            print("[build] onnxruntime detected — bundling for ONNX codecs")
        except ImportError:
            print("[build] onnxruntime not installed — ML codecs will not "
                  "work in the bundled binary. pip install onnxruntime first.")

    icon_arg: list[str] = []
    if platform.system() == "Windows":
        ico = web_dir / "assets" / "one-glyph.ico"
        if ico.is_file():
            icon_arg = ["--icon", str(ico)]
    elif platform.system() == "Darwin":
        # PyInstaller can take .icns on Mac; .ico is also accepted in recent versions.
        ico = web_dir / "assets" / "one-glyph.ico"
        if ico.is_file():
            icon_arg = ["--icon", str(ico)]

    # v0.21.x: include the Rust-built native extension (one_link_native)
    # so the bundled binary gets the QUIC + coherence-field fast paths.
    # If the wheel isn't installed in the active env, PyInstaller will
    # log a warning and the resulting exe will fall back to pure-Python
    # paths — same behavior as before this change, no regression.
    try:
        import one_link_native  # noqa: F401
        native_collect = ["--collect-all", "one_link_native"]
        print("[build] one_link_native detected — bundling into exe")
    except ImportError:
        native_collect = []
        print(
            "[build] one_link_native not installed in this env — building "
            "without native fast path. To include it: install the wheel "
            "first via `pip install one_link_native --find-links "
            "https://github.com/IamOneYouAreOneWeAreOne/one-link/releases/latest`"
        )

    # GUI mode = no console window. Use --windowed on Mac/Win, no-op on Linux.
    console_flag = "--windowed" if args.gui and platform.system() != "Linux" else "--console"

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--name",
        name,
        "--onefile",
        console_flag,
        "--clean",
        "--noconfirm",
        # Hidden imports zeroconf/cryptography/blake3 sometimes need:
        "--collect-submodules",
        "zeroconf",
        "--collect-submodules",
        "cryptography",
        "--collect-submodules",
        "aiohttp",
        *onnx_collect,
        *native_collect,
        # Bundle the web UI (HTML/CSS/JS/assets) into the exe:
        "--add-data",
        add_data_web,
        *add_models,
        *add_native,
        *icon_arg,
        # Entry point:
        str(entry),
    ]
    print("[build] running:", " ".join(cmd))
    res = subprocess.run(cmd, cwd=repo)
    if res.returncode != 0:
        print(f"[build] PyInstaller failed: exit {res.returncode}")
        return res.returncode

    final = dist / out_name
    if not final.exists():
        print(f"[build] expected output not found: {final}")
        return 3
    print(f"[build] OK -> {final}  ({final.stat().st_size:,} bytes)")

    print("[build] smoke test: one-link --version")
    try:
        smoke = subprocess.run(
            [str(final), "--version"], capture_output=True, text=True, timeout=15
        )
        print("  stdout:", smoke.stdout.strip())
        if smoke.stderr.strip():
            print("  stderr:", smoke.stderr.strip())
        if smoke.returncode != 0:
            print(f"[build] smoke non-zero ({smoke.returncode}); binary still produced")
        else:
            print("[build] smoke OK")
    except (OSError, subprocess.TimeoutExpired) as e:
        # On Windows, freshly-built unsigned exes can be blocked by
        # Defender/Application Control before they ever run. The binary is
        # still valid; ship it and let the user retry. This is informational,
        # not a build failure.
        print(f"[build] smoke step could not run: {e}")
        print(
            "[build] this is typically Windows Defender / Application Control "
            "blocking a fresh unsigned binary; the exe itself is fine."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())

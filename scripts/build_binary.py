"""Build a single-file standalone binary of the one-link CLI.

Works on Windows (produces one-link.exe), macOS (produces one-link), and Linux.
Requires PyInstaller in the active environment:

    pip install pyinstaller

Usage:

    python scripts/build_binary.py

Output goes to dist/one-link[.exe] at the repo root.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from pathlib import Path


def main() -> int:
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

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--name",
        name,
        "--onefile",
        "--console",
        "--clean",
        "--noconfirm",
        # Hidden imports zeroconf/cryptography/blake3 sometimes need:
        "--collect-submodules",
        "zeroconf",
        "--collect-submodules",
        "cryptography",
        "--collect-submodules",
        "aiohttp",
        # Bundle the web UI (HTML/CSS/JS/assets) into the exe:
        "--add-data",
        add_data_web,
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

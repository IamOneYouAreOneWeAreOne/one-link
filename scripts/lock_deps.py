"""Regenerate requirements.lock from pyproject.toml dependencies.

Wraps pip-compile (pip-tools) so a release can produce a fully-pinned
lockfile in one command. The lockfile is what CI feeds into pip-audit
for OSV scanning.

Usage:
    pip install -e ".[security]"
    python scripts/lock_deps.py            # writes requirements.lock
    python scripts/lock_deps.py --upgrade  # bump to latest within bounds
    python scripts/lock_deps.py --check    # fail if pyproject ahead of lock

The output is reproducible: same pyproject.toml on the same Python
version produces the same requirements.lock byte-for-byte. Different
Python versions can pick different transitive resolutions, so CI
should call this with the target Python.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _run(args: list[str]) -> int:
    print("$ " + " ".join(args))
    return subprocess.run(args, check=False).returncode


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--upgrade", action="store_true",
                   help="bump pinned versions to latest compatible")
    p.add_argument("--check", action="store_true",
                   help="fail if requirements.lock is out of date")
    args = p.parse_args(argv)
    root = _project_root()
    out = root / "requirements.lock"
    cmd = [
        sys.executable, "-m", "piptools", "compile",
        "--strip-extras",
        "--output-file", str(out),
        str(root / "pyproject.toml"),
    ]
    if args.upgrade:
        cmd.append("--upgrade")
    if args.check:
        # pip-compile has no stable --check flag across versions; emulate
        # by writing to a tempfile and diffing.
        tmp = root / "requirements.lock.tmp"
        cmd[cmd.index(str(out))] = str(tmp)
        rc = _run(cmd)
        if rc != 0:
            return rc
        a = out.read_bytes() if out.exists() else b""
        b = tmp.read_bytes()
        tmp.unlink(missing_ok=True)
        if a != b:
            print(
                "requirements.lock is out of date — regenerate with"
                " `python scripts/lock_deps.py`",
                file=sys.stderr,
            )
            return 1
        print("requirements.lock is up to date.")
        return 0
    return _run(cmd)


if __name__ == "__main__":
    raise SystemExit(main())

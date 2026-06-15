"""Generate a CycloneDX Software Bill of Materials for One Link.

Produces `dist/sbom.cdx.json` describing every Python dependency
that ships with the binary. CI uploads it as a release artifact so
downstream consumers can audit what they're running.

Usage:
    pip install -e ".[security]"
    python scripts/gen_sbom.py [--output dist/sbom.cdx.json]
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--output", default=None,
                   help="output path (default: dist/sbom.cdx.json)")
    p.add_argument("--from", dest="src", default="environment",
                   choices=["environment", "requirements"],
                   help="generate from current env or requirements.lock")
    args = p.parse_args(argv)
    root = _project_root()
    out = Path(args.output) if args.output else root / "dist" / "sbom.cdx.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    if args.src == "requirements":
        lock = root / "requirements.lock"
        if not lock.exists():
            print(
                "requirements.lock not present — run `python scripts/lock_deps.py`"
                " first or use `--from environment`.",
                file=sys.stderr,
            )
            return 2
        # 2026-06-04: the CycloneDX CLI flag is --output-file (alias -o),
        # not --outfile. The stale --outfile failed CI's SBOM step with
        # "unrecognized arguments: --outfile". Output format value is the
        # uppercase enum (JSON) the current cyclonedx_py expects.
        cmd = [
            sys.executable, "-m", "cyclonedx_py", "requirements",
            str(lock), "--output-format", "JSON",
            "--output-file", str(out),
        ]
    else:
        cmd = [
            sys.executable, "-m", "cyclonedx_py", "environment",
            "--output-format", "JSON", "--output-file", str(out),
        ]
    print("$ " + " ".join(cmd))
    rc = subprocess.run(cmd, check=False).returncode
    if rc == 0:
        print(f"SBOM written to {out}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
